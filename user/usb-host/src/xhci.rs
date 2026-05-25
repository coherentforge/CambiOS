// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! xHCI controller bring-up per xHCI 1.2 § 4.2 + § 5.
//!
//! B-i shipped capability-register parsing. B-ii added:
//!   - Operational + runtime register accessors
//!   - HCRESET sequence (§ 4.22.1)
//!   - DCBAA / command-ring / event-ring + ERST setup (§ 4.2)
//!   - USBCMD.RUN + HCH-clears assertion
//!
//! B-iii added port enumeration, the command/event flow (doorbell +
//! `wait_for_command_completion`), and the first commands (NoOp +
//! Enable Slot).
//!
//! B-iv adds Address Device — Input Context + Device Context + EP0
//! transfer ring allocation, DCBAA slot installation, and the Address
//! Device Command that transitions the slot to Addressed state.
//!
//! `XhciController` is the post-init handle: holds the MMIO base, the
//! parsed capabilities, the derived op + runtime virtual addresses, the
//! in-DMA ring buffers, and (post-Address Device) the per-slot
//! input/device context + EP0 transfer ring.

use cambios_libsys as sys;

use crate::descriptors::CcidEndpoints;
use crate::ring::{CommandRing, EventRing, Erst, TransferRing, Trb};

// ---------------------------------------------------------------------------
// Bound: poll iteration ceiling for HCRESET / RUN waits
// ---------------------------------------------------------------------------

/// SCAFFOLDING: poll iterations before declaring an xHCI state
/// transition timed out. Each iteration calls `sys::yield_now()` so
/// the wall-clock cost is roughly `iterations × scheduler-tick`
/// (~10 ms on our 100 Hz timer). 1000 iterations ≈ 10 s, well past
/// the few-millisecond budget the spec gives HCRST / RUN.
/// Why: a verifier can reason about bounded loops; an unbounded
/// `while !ready {}` cannot. The bound holds even under a
/// degenerate-slow CI host.
/// Replace when: real-hardware bring-up shows HCRESET completing
/// reliably under N iterations and we want to tighten the timeout
/// for faster failure detection.
const MAX_POLL_ITERATIONS: u32 = 1000;

/// SCAFFOLDING: number of device slots we enable in CONFIG.MaxSlotsEn.
/// xHCI 1.2 § 4.3.3 — must be ≤ HCSPARAMS1.MaxSlots (qemu-xhci reports
/// 64). v1-endgame: one YubiKey-class CCID device + a couple of HID
/// devices + headroom; 8 is comfortably above need.
/// Why: capped at boot via the CONFIG register; the controller refuses
/// to allocate more slots than this. Smaller is a verification win
/// (smaller DCBAA, smaller per-slot context working set).
/// Replace when: a workload needs simultaneous 9+ USB device
/// addresses (multi-YubiKey vault, USB fingerprint reader alongside
/// CCID, signed-carrier input device + keyboard + mouse + …).
pub const MAX_SLOTS_ENABLED: u8 = 8;

/// SCAFFOLDING: max bytes the driver will read for a single
/// configuration-descriptor blob (config + nested interface +
/// endpoint + class-specific descriptors). The USB 2.0 spec gives
/// `wTotalLength` 16 bits, so the protocol max is 65535; in practice
/// config descriptors for a CCID + a couple of HID-class devices stay
/// well under 256 bytes. 512 covers the v1-endgame device set with
/// 4-8× headroom while keeping the response buffer fitting in a
/// single 4 KiB DMA page along with the controller's transfer
/// metadata.
/// Why: bounded → verifier-tractable; smaller is a memory win
/// (per-enumeration, freed when the device is reconfigured).
/// Replace when: a target device's `wTotalLength` exceeds this cap
/// (would show up as a truncated read; the parser already validates
/// the blob fits its own internal length).
pub const MAX_CONFIG_DESCRIPTOR_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// Capability register block (xHCI 1.2 § 5.3)
// ---------------------------------------------------------------------------

/// Parsed xHCI capability register block. All fields are read once at
/// startup; the controller never updates this region.
///
/// `dead_code` is allowed because B-i logs only a subset of the fields;
/// `csz`, `cap_length`, `doorbell_offset`, and `runtime_offset` become
/// load-bearing in B-ii (operational-register bring-up) where they
/// locate the operational / doorbell / runtime register blocks and size
/// the device-context array.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct XhciCapabilities {
    /// CAPLENGTH (offset 0x00) — byte offset from MMIO base to the
    /// operational register block.
    pub cap_length: u8,
    /// HCIVERSION (offset 0x02) — BCD-encoded xHCI version (0x0100 = 1.0,
    /// 0x0110 = 1.1, 0x0120 = 1.2).
    pub hci_version: u16,
    /// HCSPARAMS1 [7:0] — maximum Device Slots the controller supports.
    pub max_slots: u8,
    /// HCSPARAMS1 [18:8] — maximum Interrupters the controller supports.
    pub max_intrs: u16,
    /// HCSPARAMS1 [31:24] — number of Root Hub ports.
    pub max_ports: u8,
    /// HCSPARAMS2 Max Scratchpad Bufs (hi[31:27] || lo[25:21]) —
    /// number of 4 KiB scratchpad pages the controller wants the
    /// driver to allocate and point DCBAA[0] at (xHCI 1.2 § 4.20).
    /// QEMU's qemu-xhci historically reported 0; if non-zero, the
    /// controller errors (USBSTS.HCE) on first command if DCBAA[0]
    /// is NULL.
    pub max_scratchpad_bufs: u32,
    /// HCCPARAMS1 [0] — AC64: controller supports 64-bit addressing.
    pub ac64: bool,
    /// HCCPARAMS1 [2] — CSZ: context size. False = 32-byte, True = 64-byte.
    pub csz: bool,
    /// DBOFF (offset 0x14) — byte offset from MMIO base to the Doorbell
    /// array. Low two bits are reserved and masked off.
    pub doorbell_offset: u32,
    /// RTSOFF (offset 0x18) — byte offset from MMIO base to the Runtime
    /// register block. Low five bits are reserved and masked off.
    pub runtime_offset: u32,
}

/// Read the capability register block from a mapped xHCI MMIO region.
///
/// `mmio_vaddr` must be the userspace virtual address returned by a
/// successful `sys::map_mmio` call against the xHCI controller's MMIO
/// BAR, and the mapped region must be at least 32 bytes long (covers
/// CAPLENGTH through HCCPARAMS2). Volatile reads are used so the
/// compiler cannot fold these accesses against any later state.
pub fn parse_capabilities(mmio_vaddr: u64) -> XhciCapabilities {
    // SAFETY: `mmio_vaddr` is the return value of a successful
    // `sys::map_mmio` call (checked at the call site in main.rs), which
    // maps at least one 4 KiB page covering the start of the xHCI BAR.
    // The capability block spans offsets 0x00..0x20 (32 bytes), well
    // inside that mapping. Volatile reads are device-safe — capability
    // registers are read-only, and the device performs no side effects
    // in response to capability-register accesses. The integer types
    // (u8/u16/u32) are naturally aligned at the offsets used here.
    unsafe {
        let base = mmio_vaddr as *const u8;
        // CAPLENGTH (low byte) + reserved + HCIVERSION (high 16 bits)
        // are packed in the dword at offset 0. QEMU's qemu-xhci only
        // honors 32-bit reads of this register; reading HCIVERSION as
        // a narrow u16 at offset 2 returns 0 (the QEMU MemoryRegion
        // dispatch routes byte-granularity accesses through a separate
        // handler that doesn't synthesize the version field). Read
        // the whole dword and extract — matches the spec's strict
        // "naturally aligned register-width access" guidance and
        // works across real hardware too.
        let cap_dword = core::ptr::read_volatile(base as *const u32);
        let cap_length = (cap_dword & 0xFF) as u8;
        let hci_version = ((cap_dword >> 16) & 0xFFFF) as u16;
        let hcsparams1 = core::ptr::read_volatile(base.add(4) as *const u32);
        let hcsparams2 = core::ptr::read_volatile(base.add(8) as *const u32);
        let hccparams1 = core::ptr::read_volatile(base.add(0x10) as *const u32);
        let dboff = core::ptr::read_volatile(base.add(0x14) as *const u32);
        let rtsoff = core::ptr::read_volatile(base.add(0x18) as *const u32);

        // HCSPARAMS2.MaxScratchpadBufs is split across [31:27] (hi)
        // and [25:21] (lo) per xHCI 1.2 § 5.3.4.
        let max_scratchpad_lo = (hcsparams2 >> 21) & 0x1F;
        let max_scratchpad_hi = (hcsparams2 >> 27) & 0x1F;
        let max_scratchpad_bufs = (max_scratchpad_hi << 5) | max_scratchpad_lo;

        XhciCapabilities {
            cap_length,
            hci_version,
            max_slots: (hcsparams1 & 0xFF) as u8,
            max_intrs: ((hcsparams1 >> 8) & 0x7FF) as u16,
            max_ports: ((hcsparams1 >> 24) & 0xFF) as u8,
            max_scratchpad_bufs,
            ac64: (hccparams1 & 0x1) != 0,
            csz: (hccparams1 & 0x4) != 0,
            doorbell_offset: dboff & !0x3,
            runtime_offset: rtsoff & !0x1F,
        }
    }
}

// ---------------------------------------------------------------------------
// Operational + runtime register offsets and bitfields (xHCI 1.2 § 5.4)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub mod regs {
    //! Register offsets are byte offsets from the operational base
    //! (MMIO + cap_length) or the runtime base (MMIO + runtime_offset).
    //!
    //! `dead_code` is allowed because the module exposes the full
    //! op + runtime + interrupter layout up front; B-ii uses a
    //! subset, B-iii + B-iv reach for IR_IMAN (interrupt-management)
    //! and CRCR_RCS (cycle-state-flip helpers) without a re-edit.

    // Operational register offsets
    pub const USBCMD: usize = 0x00;
    pub const USBSTS: usize = 0x04;
    pub const CRCR: usize = 0x18; // u64 (high+low halves; write high first)
    pub const DCBAAP: usize = 0x30; // u64
    pub const CONFIG: usize = 0x38;

    // PORTSC[i] = PORT_REGS_BASE + i * PORT_REG_STRIDE
    // (xHCI 1.2 § 5.4.8). Ports are 1-indexed in spec; index 0 here
    // = port 1 in spec.
    pub const PORT_REGS_BASE: usize = 0x400;
    pub const PORT_REG_STRIDE: usize = 0x10;
    pub const PORT_PORTSC: usize = 0x00; // relative to port base

    // USBCMD bits
    pub const USBCMD_RUN: u32 = 1 << 0;
    pub const USBCMD_HCRST: u32 = 1 << 1;

    // USBSTS bits (subset relevant to B-ii / B-iii)
    pub const USBSTS_HCH: u32 = 1 << 0; // Host Controller Halted
    pub const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

    // PORTSC bits (xHCI 1.2 § 5.4.8)
    pub const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
    pub const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
    pub const PORTSC_PR: u32 = 1 << 4; // Port Reset
    pub const PORTSC_PP: u32 = 1 << 9; // Port Power
    pub const PORTSC_SPEED_SHIFT: u32 = 10;
    pub const PORTSC_SPEED_MASK: u32 = 0xF << 10;
    pub const PORTSC_PRC: u32 = 1 << 21; // Port Reset Change

    // PORTSC RW1C status-change bits — must be masked off when
    // writing PORTSC so an unrelated write doesn't accidentally
    // clear a change bit the driver hasn't read yet.
    pub const PORTSC_RW1C_MASK: u32 =
        (1 << 17) | // CSC
        (1 << 18) | // PEC
        (1 << 19) | // WRC
        (1 << 20) | // OCC
        (1 << 21) | // PRC
        (1 << 22) | // PLC
        (1 << 23);  // CEC

    // CRCR bit 0: Ring Cycle State — written together with the ring
    // base pointer; the cycle bit must match the producer's initial
    // cycle bit (1 at fresh ring init). B-iii uses this for ring
    // wrap/abort transitions.
    pub const CRCR_RCS: u32 = 1 << 0;

    // Runtime register offsets
    pub const INTERRUPTER_0: usize = 0x20; // first interrupter base

    // Per-interrupter register offsets (relative to interrupter base).
    // IR_IMAN (Interrupt Management) is reached at B-iv when IRQ
    // delivery to userspace lands; kept here so the layout is
    // complete in one place.
    pub const IR_IMAN: usize = 0x00;
    pub const IR_ERSTSZ: usize = 0x08;
    pub const IR_ERSTBA: usize = 0x10; // u64 (high then low)
    pub const IR_ERDP: usize = 0x18; // u64 (high then low)

    // ERDP bit 3: Event Handler Busy (RW1C — writing 1 clears it).
    // Written along with the dequeue pointer when the driver has
    // caught up with the controller's event production.
    pub const ERDP_EHB: u32 = 1 << 3;
}

/// TRB type values used at command/event level (xHCI 1.2 § 6.4.6).
/// `pub` so main.rs can match on these without re-importing.
pub mod trb_type {
    pub const SETUP_STAGE: u8 = 2;
    pub const DATA_STAGE: u8 = 3;
    pub const STATUS_STAGE: u8 = 4;
    pub const ENABLE_SLOT_COMMAND: u8 = 9;
    pub const ADDRESS_DEVICE_COMMAND: u8 = 11;
    pub const EVALUATE_CONTEXT_COMMAND: u8 = 13;
    pub const NOOP_COMMAND: u8 = 23;
    pub const TRANSFER_EVENT: u8 = 32;
    pub const COMMAND_COMPLETION_EVENT: u8 = 33;
}

/// Command completion codes (xHCI 1.2 § 6.4.5).
#[allow(dead_code)]
pub mod completion_code {
    pub const SUCCESS: u8 = 1;
    pub const DATA_BUFFER_ERROR: u8 = 2;
    pub const BABBLE_DETECTED: u8 = 3;
    pub const USB_TRANSACTION_ERROR: u8 = 4;
    pub const TRB_ERROR: u8 = 5;
    pub const STALL_ERROR: u8 = 6;
    // others on demand
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Controller bring-up + B-iii command/event failure modes.
#[derive(Clone, Copy, Debug)]
pub enum XhciError {
    /// USBSTS.HCH never set after clearing R/S — controller failed to halt.
    HaltTimeout,
    /// USBCMD.HCRST never cleared after writing it — controller failed to reset.
    ResetTimeout,
    /// USBSTS.CNR never cleared after reset — controller stayed in not-ready.
    NotReadyTimeout,
    /// USBSTS.HCH never cleared after setting R/S — controller failed to run.
    RunTimeout,
    /// SYS_ALLOC_DMA failed during DCBAA / ring allocation.
    DmaAllocFailed,
    /// PORTSC.PRC never set after writing PR=1 — port reset stalled.
    PortResetTimeout,
    /// Command ring overflowed (would write into the Link TRB slot).
    /// Link-wrap is unimplemented — see `CommandRing::enqueue` for the
    /// trigger that turns this back into "implement wrap, don't fail."
    CommandRingFull,
    /// No matching Command Completion Event arrived within the poll budget.
    CommandTimeout,
    /// Command completed with a non-Success completion code.
    /// The inner `u8` carries the actual code (see `completion_code` module).
    CommandFailed(u8),
    /// Address Device called before Enable Slot — controller has no
    /// slot ID for the input/device context to live under.
    SlotNotEnabled,
    /// EP0 control transfer attempted before Address Device set up
    /// the slot's EP0 transfer ring + Device Context.
    EpNotReady,
    /// EP0 transfer ring overflowed (would write into the Link TRB slot).
    /// Link-wrap is unimplemented — see `TransferRing::enqueue`.
    TransferRingFull,
    /// No matching Transfer Event arrived within the poll budget.
    TransferTimeout,
    /// Transfer completed with a non-Success completion code.
    /// The inner `u8` carries the actual code (see `completion_code`).
    TransferFailed(u8),
}

// ---------------------------------------------------------------------------
// XhciController — owns MMIO bases + DMA-backed ring buffers
// ---------------------------------------------------------------------------

/// Post-init xHCI controller handle. Construct via
/// [`XhciController::bring_up`], which runs the full HCRESET → RUN
/// sequence and returns a handle with the DCBAA + rings live and
/// the controller running.
#[allow(dead_code)]
pub struct XhciController {
    pub mmio_vaddr: u64,
    pub cap: XhciCapabilities,
    /// `mmio_vaddr + cap.cap_length`.
    pub op_vaddr: u64,
    /// `mmio_vaddr + cap.runtime_offset`.
    pub runtime_vaddr: u64,
    /// Interrupter 0's register block (`runtime_vaddr + INTERRUPTER_0`).
    pub interrupter0_vaddr: u64,
    /// Doorbell array base (`mmio_vaddr + cap.doorbell_offset`).
    /// Doorbell 0 = Host Controller doorbell (command ring), doorbell
    /// `slot_id` = device doorbells for transfer rings.
    pub doorbell_vaddr: u64,
    /// Device Context Base Address Array (paddr written to DCBAAP;
    /// vaddr retained for slot-context installation in B-iii).
    pub dcbaa_paddr: u64,
    pub dcbaa_vaddr: u64,
    pub command_ring: CommandRing,
    pub event_ring: EventRing,
    pub erst: Erst,
    /// Slot ID returned by Enable Slot Command (B-iii). Threaded
    /// forward to B-iv's Address Device + B-v's GET_DESCRIPTOR.
    pub slot_id: Option<u8>,
    /// Input Context (xHCI 1.2 § 6.2.5) — scratch structure passed to
    /// Address Device and Configure Endpoint commands. Single-slot
    /// today; allocated lazily in `address_device`.
    /// Revisit when: multi-device discovery lands (B-vi) — these +
    /// the device context + EP0 ring belong in a slot-indexed table.
    pub input_context_paddr: Option<u64>,
    pub input_context_vaddr: Option<u64>,
    /// Device Context (xHCI 1.2 § 6.2.1) — controller writes here;
    /// installed in DCBAA at slot_id.
    pub device_context_paddr: Option<u64>,
    pub device_context_vaddr: Option<u64>,
    /// EP0 transfer ring — set up by Address Device, used by B-v
    /// GET_DESCRIPTOR control transfers.
    pub ep0_transfer_ring: Option<TransferRing>,
    /// Root hub port the slot lives on (0-indexed). Populated by
    /// `address_device`; reused by Configure Endpoint when the Input
    /// Context's Slot Context needs to be re-filled with current
    /// state (xHCI 1.2 § 4.6.6 requires A0=1 + Slot Context valid
    /// when adding endpoints that bump Context Entries).
    pub port_idx: Option<u8>,
    /// PORTSC speed field captured at port reset (1=FS, 3=HS,
    /// 4=SS, 5=SS+). Same purpose as `port_idx`.
    pub port_speed: Option<u8>,
    /// CCID bulk endpoint pair (IN + OUT) + their transfer rings,
    /// installed by Configure Endpoint. Consumed by B-vi.c's first
    /// bulk transfer.
    pub ccid_bulk: Option<CcidBulkRings>,
}

/// Per-slot bulk endpoint state for the CCID interface — DCIs +
/// transfer rings + Max Packet Sizes. Populated by
/// `configure_endpoint` once the endpoints are live.
#[allow(dead_code)]
pub struct CcidBulkRings {
    pub in_dci: u8,
    pub in_mps: u16,
    pub in_ring: TransferRing,
    pub out_dci: u8,
    pub out_mps: u16,
    pub out_ring: TransferRing,
}

impl XhciController {
    /// Reset the controller, set up DCBAA + rings, and run.
    pub fn bring_up(mmio_vaddr: u64, cap: XhciCapabilities) -> Result<Self, XhciError> {
        let op_vaddr = mmio_vaddr + cap.cap_length as u64;
        let runtime_vaddr = mmio_vaddr + cap.runtime_offset as u64;
        let interrupter0_vaddr = runtime_vaddr + regs::INTERRUPTER_0 as u64;
        let doorbell_vaddr = mmio_vaddr + cap.doorbell_offset as u64;

        // Step 1: HCRESET. Halt the controller first (clear R/S), wait
        // for HCH, then write HCRST, wait for it to clear, then wait
        // for CNR to clear.
        Self::reset(op_vaddr)?;

        // Step 2: configure number of enabled device slots.
        // SAFETY: op_vaddr is inside the MMIO BAR mapping (CONFIG at
        // offset 0x38 is well within the smallest legal BAR per spec).
        unsafe {
            let cur = core::ptr::read_volatile((op_vaddr + regs::CONFIG as u64) as *const u32);
            // CONFIG.MaxSlotsEn is bits [7:0]; preserve other bits.
            let new = (cur & !0xFF) | (MAX_SLOTS_ENABLED as u32);
            core::ptr::write_volatile((op_vaddr + regs::CONFIG as u64) as *mut u32, new);
        }

        // Step 3: allocate + install the Device Context Base Address
        // Array. Size = 8 bytes × (MaxSlots + 1) — slot 0 is the
        // Scratchpad Buffer Array pointer (per xHCI 1.2 § 6.1.1).
        // QEMU's xhci reports MaxScratchpadBufs = 0, so slot 0 stays
        // NULL. Scratchpad buffer allocation lands at B-iii.
        // Revisit when: HCSPARAMS2.MaxScratchpadBufs read shows
        // non-zero on the target controller (real-hardware bring-up
        // or qemu-xhci flag change).
        let (dcbaa_paddr, dcbaa_vaddr) = Self::alloc_dcbaa()?;
        Self::write_dcbaap(op_vaddr, dcbaa_paddr);

        // Step 4: allocate the command ring and install its base into
        // CRCR. The CRCR write must be high-dword-first then
        // low-dword (xHCI 1.2 § 4.6.1.2) — the low-dword write is the
        // trigger that latches the new ring; doing one 64-bit write
        // would race the controller's internal capture.
        let command_ring = CommandRing::new().ok_or(XhciError::DmaAllocFailed)?;
        Self::write_crcr(op_vaddr, command_ring.paddr, command_ring.cycle);

        // Step 5: allocate the event ring + ERST, install into
        // interrupter 0's runtime registers.
        let event_ring = EventRing::new().ok_or(XhciError::DmaAllocFailed)?;
        let erst = Erst::new(event_ring.paddr, event_ring.capacity_trbs())
            .ok_or(XhciError::DmaAllocFailed)?;
        Self::write_erstsz(interrupter0_vaddr, 1);
        Self::write_erstba(interrupter0_vaddr, erst.paddr);
        Self::write_erdp(interrupter0_vaddr, event_ring.paddr);

        // IMAN.IE = 1. We don't actually take interrupts (B-iv work),
        // but Linux's xhci-hcd does this at init and some controllers
        // tie event-write behavior to it. Cheap to set; no IRQ
        // delivery happens because the kernel doesn't route this
        // device IRQ to userspace yet.
        // SAFETY: interrupter0_vaddr inside MMIO mapping.
        unsafe {
            let p = interrupter0_vaddr + regs::IR_IMAN as u64;
            let cur = core::ptr::read_volatile(p as *const u32);
            core::ptr::write_volatile(p as *mut u32, cur | 0x2);
        }

        // Step 6: RUN. Set USBCMD.R/S, wait for USBSTS.HCH to clear.
        Self::run(op_vaddr)?;

        Ok(Self {
            mmio_vaddr,
            cap,
            op_vaddr,
            runtime_vaddr,
            interrupter0_vaddr,
            doorbell_vaddr,
            dcbaa_paddr,
            dcbaa_vaddr,
            command_ring,
            event_ring,
            erst,
            slot_id: None,
            input_context_paddr: None,
            input_context_vaddr: None,
            device_context_paddr: None,
            device_context_vaddr: None,
            ep0_transfer_ring: None,
            port_idx: None,
            port_speed: None,
            ccid_bulk: None,
        })
    }

    /// Read USBSTS as a single u32 — diagnostic helper for the success
    /// log; also used by callers verifying HCH/CNR state.
    pub fn read_usbsts(&self) -> u32 {
        // SAFETY: op_vaddr is inside the MMIO mapping; USBSTS at
        // offset 0x04 is naturally aligned and 4 bytes long.
        unsafe {
            core::ptr::read_volatile((self.op_vaddr + regs::USBSTS as u64) as *const u32)
        }
    }

    // -----------------------------------------------------------------
    // B-iii: port enumeration
    // -----------------------------------------------------------------

    /// Read PORTSC for the given 0-indexed port (spec port N+1).
    pub fn read_portsc(&self, port_idx: u8) -> u32 {
        let off = regs::PORT_REGS_BASE
            + (port_idx as usize) * regs::PORT_REG_STRIDE
            + regs::PORT_PORTSC;
        // SAFETY: op_vaddr inside MMIO mapping. PORTSC offsets are
        // bounded by `cap.max_ports`; callers iterate 0..max_ports.
        unsafe {
            core::ptr::read_volatile((self.op_vaddr + off as u64) as *const u32)
        }
    }

    /// Reset the port (set PR=1) and wait for PRC. After reset the
    /// port should report PED=1 and a stable Port Speed.
    pub fn reset_port(&self, port_idx: u8) -> Result<u32, XhciError> {
        let off = regs::PORT_REGS_BASE
            + (port_idx as usize) * regs::PORT_REG_STRIDE
            + regs::PORT_PORTSC;
        let portsc_addr = self.op_vaddr + off as u64;

        // Preserve non-RW1C control bits, mask off RW1C status-change
        // bits (writing 1 to a change bit clears it; we'd race the
        // controller's notification), then OR in PR=1.
        let cur = self.read_portsc(port_idx);
        let new = (cur & !regs::PORTSC_RW1C_MASK) | regs::PORTSC_PR;

        // SAFETY: portsc_addr inside MMIO mapping (bounded by max_ports).
        unsafe {
            core::ptr::write_volatile(portsc_addr as *mut u32, new);
        }

        // Wait for PRC (Port Reset Change) — the controller sets PRC
        // when its internal reset finishes. PED then transitions to 1.
        Self::poll_until(MAX_POLL_ITERATIONS, || {
            self.read_portsc(port_idx) & regs::PORTSC_PRC != 0
        })
        .ok_or(XhciError::PortResetTimeout)?;

        // Clear PRC (RW1C: write 1 to clear) so a future poll doesn't
        // see a stale change bit. Write current value with PRC set —
        // PRC is the only RW1C bit we want cleared right now.
        let cur2 = self.read_portsc(port_idx);
        let clear = (cur2 & !regs::PORTSC_RW1C_MASK) | regs::PORTSC_PRC;
        // SAFETY: as above.
        unsafe {
            core::ptr::write_volatile(portsc_addr as *mut u32, clear);
        }

        Ok(self.read_portsc(port_idx))
    }

    // -----------------------------------------------------------------
    // B-iii: command + event flow
    // -----------------------------------------------------------------

    /// Ring a doorbell. `target` = 0 for the Host Controller (command
    /// ring); `target` = `slot_id` for a device's transfer doorbells
    /// (used by B-iv onward).
    ///
    /// `value` packs DB Target [7:0] + DB Stream ID [31:16]. For the
    /// HC doorbell, write 0. For device doorbells, low byte = endpoint
    /// ID (1 = EP0).
    pub fn ring_doorbell(&self, target: u8, value: u32) {
        let off = (target as u64) * 4;
        // SAFETY: doorbell_vaddr is mmio_vaddr + cap.doorbell_offset;
        // the doorbell array spans (MaxSlots+1) × 4 bytes per xHCI
        // 1.2 § 5.6 and lives inside the BAR mapping.
        unsafe {
            core::ptr::write_volatile(
                (self.doorbell_vaddr + off) as *mut u32,
                value,
            );
        }
    }

    /// Enqueue a Command TRB, ring doorbell 0, wait for the matching
    /// Command Completion Event. Returns the completion event TRB so
    /// callers can extract command-specific fields (e.g. Slot ID).
    pub fn submit_command(&mut self, trb: Trb) -> Result<Trb, XhciError> {
        let cmd_paddr = self
            .command_ring
            .enqueue(trb)
            .ok_or(XhciError::CommandRingFull)?;

        // Ring HC doorbell (target=0, value=0) — wakes the command ring.
        self.ring_doorbell(0, 0);

        self.wait_for_command_completion(cmd_paddr)
    }

    /// Poll the event ring until a Command Completion Event arrives
    /// whose Command TRB Pointer matches `cmd_paddr`. Non-matching
    /// events (e.g. Port Status Change) are consumed + dropped. ERDP
    /// is updated when polling completes (or after each consumed
    /// event, whichever comes first — here we batch on completion).
    fn wait_for_command_completion(&mut self, cmd_paddr: u64) -> Result<Trb, XhciError> {
        for _ in 0..MAX_POLL_ITERATIONS {
            if let Some(event) = self.event_ring.poll_next() {
                let trb_type = ((event.control >> 10) & 0x3F) as u8;
                if trb_type == trb_type::COMMAND_COMPLETION_EVENT
                    && event.parameter == cmd_paddr
                {
                    self.write_erdp_to_current();
                    let code = (event.status >> 24) as u8;
                    if code == completion_code::SUCCESS {
                        return Ok(event);
                    } else {
                        return Err(XhciError::CommandFailed(code));
                    }
                }
                // Non-matching event (e.g. Port Status Change at
                // boot, or a stray PSC after our port reset)
                // consumed and dropped. ERDP is updated when we
                // return so the controller sees the consumption.
                continue;
            }
            sys::yield_now();
        }
        // Best-effort ERDP catch-up before returning the timeout, so
        // the controller sees whatever progress we made.
        self.write_erdp_to_current();
        Err(XhciError::CommandTimeout)
    }

    /// Update ERDP to point at the next-to-consume event ring slot,
    /// clearing EHB (RW1C: writing 1 clears). Idempotent.
    fn write_erdp_to_current(&self) {
        let p = self.interrupter0_vaddr + regs::IR_ERDP as u64;
        let dq = self.event_ring.dequeue_paddr();
        // Low dword = (dq & ~0xF) | EHB; high dword = dq >> 32. The
        // low 4 bits of ERDP are control fields (DESI[2:0], EHB[3]);
        // dq is page-aligned so its low 4 bits are zero, leaving just
        // EHB set. LO first then HI — Linux + QEMU expectation.
        let low = (dq as u32) | regs::ERDP_EHB;
        let high = (dq >> 32) as u32;
        // SAFETY: interrupter0_vaddr inside MMIO mapping.
        unsafe {
            core::ptr::write_volatile(p as *mut u32, low);
            core::ptr::write_volatile((p + 4) as *mut u32, high);
        }
    }

    // -----------------------------------------------------------------
    // B-iii: command shortcuts
    // -----------------------------------------------------------------

    /// Issue a NoOp Command (xHCI 1.2 § 6.4.3.7). Smoke-tests the
    /// command/event flow before commands with semantic side effects.
    pub fn noop_command(&mut self) -> Result<(), XhciError> {
        let trb = Trb {
            parameter: 0,
            status: 0,
            control: (trb_type::NOOP_COMMAND as u32) << 10,
        };
        self.submit_command(trb).map(|_| ())
    }

    /// Issue an Enable Slot Command (xHCI 1.2 § 6.4.3.2). Returns the
    /// Slot ID the controller allocated (1..=MaxSlotsEn). Slot Type
    /// is 0 (USB) for B-iii's CCID-shaped device; other slot types
    /// (Debug Capability, etc.) come from the Supported Protocol
    /// Extended Capability and land when needed.
    pub fn enable_slot(&mut self) -> Result<u8, XhciError> {
        let trb = Trb {
            parameter: 0,
            status: 0,
            // TRB Type = 9 (Enable Slot Command), Slot Type [20:16] = 0
            control: (trb_type::ENABLE_SLOT_COMMAND as u32) << 10,
        };
        let event = self.submit_command(trb)?;
        // Slot ID is in DWord 3 bits 24-31 of the completion event.
        let slot_id = ((event.control >> 24) & 0xFF) as u8;
        Ok(slot_id)
    }

    // -----------------------------------------------------------------
    // B-iv: Address Device
    // -----------------------------------------------------------------

    /// Set up the Input Context + Device Context + EP0 transfer ring
    /// for the slot allocated by Enable Slot, install the Device
    /// Context into DCBAA, and issue Address Device (xHCI 1.2 §
    /// 6.4.3.4). On success the slot transitions Enabled → Addressed
    /// and the controller has issued SET_ADDRESS over the bus.
    ///
    /// `port_idx` is 0-indexed (spec port = port_idx + 1).
    /// `speed` is the PORTSC Speed field value from the post-reset
    /// PORTSC read (1 = FS, 2 = LS, 3 = HS, 4 = SS, 5 = SS+).
    ///
    /// Returns the post-Address-Device Slot State from the device
    /// context (2 = Addressed on success). EP0 Max Packet Size is set
    /// to a speed-appropriate default (FS/LS = 8, HS = 64, SS/SS+ =
    /// 512); B-v's GET_DESCRIPTOR may refine via Evaluate Context if
    /// the device descriptor disagrees.
    pub fn address_device(&mut self, port_idx: u8, speed: u8) -> Result<u8, XhciError> {
        let slot_id = self.slot_id.ok_or(XhciError::SlotNotEnabled)?;

        // Allocate Input Context + Device Context (one page each).
        let (ic_paddr, ic_vaddr) = Self::alloc_zeroed_page()?;
        let (dc_paddr, dc_vaddr) = Self::alloc_zeroed_page()?;
        let ep0_ring = TransferRing::new().ok_or(XhciError::DmaAllocFailed)?;

        // Context size selector (xHCI 1.2 § 4.5.1): CSZ=0 → 32 B per
        // context, CSZ=1 → 64 B. Affects offsets in both Input Context
        // and Device Context. ICC + Slot + EP0 = 3 contexts; one page
        // (4 KiB) holds either 32 B × 33 = 1056 B or 64 B × 33 = 2112 B.
        let ctx_size: u64 = if self.cap.csz { 64 } else { 32 };

        // Fill Input Context. Layout (xHCI 1.2 § 6.2.5):
        //   offset 0           : Input Control Context (one ctx_size)
        //   offset ctx_size    : Slot Context (one ctx_size)
        //   offset 2*ctx_size  : EP0 Endpoint Context (one ctx_size)
        // SAFETY: ic_vaddr is the freshly allocated, zero-initialized
        // 4 KiB DMA page owned exclusively by this driver. All offsets
        // below stay within the first 3*ctx_size ≤ 192 bytes of the
        // page; u32 writes at 4-byte multiples of a 4 KiB-aligned base
        // are naturally aligned. Volatile writes ensure the controller
        // observes the populated context when the command TRB is
        // committed (the doorbell write in submit_command provides the
        // ordering barrier on the bus side).
        unsafe {
            // Input Control Context (xHCI 1.2 § 6.2.5.1):
            //   DWord 0: Drop Context flags D[31:2] (all zero — we add)
            //   DWord 1: Add Context flags A[31:0] — A0=Slot, A1=EP0
            let icc = ic_vaddr as *mut u32;
            core::ptr::write_volatile(icc.add(1), 0x3); // A0|A1

            // Slot Context (xHCI 1.2 § 6.2.2) at offset ctx_size.
            //   DWord 0: Route String [19:0]=0, Speed [23:20]=speed,
            //            Context Entries [31:27] = 1 (only EP0 valid)
            //   DWord 1: Root Hub Port Number [23:16] = port_idx + 1
            //   DWords 2,3: zero (TT info / device-address slot
            //               state filled by controller)
            let slot = (ic_vaddr + ctx_size) as *mut u32;
            let slot_dw0 =
                ((speed as u32 & 0xF) << 20) | (1u32 << 27);
            let slot_dw1 = ((port_idx as u32 + 1) & 0xFF) << 16;
            core::ptr::write_volatile(slot.add(0), slot_dw0);
            core::ptr::write_volatile(slot.add(1), slot_dw1);

            // EP0 Endpoint Context (xHCI 1.2 § 6.2.3) at offset
            // 2 * ctx_size.
            //   DWord 0: EP State [2:0]=0, all other fields 0
            //   DWord 1: CErr [2:1] = 3, EP Type [5:3] = 4 (Control),
            //            Max Packet Size [31:16] = speed-default
            //   DWords 2,3: TR Dequeue Pointer (LO|DCS=1, HI)
            //   DWord 4: Average TRB Length [15:0] = 8 (control EPs)
            let ep0 = (ic_vaddr + 2 * ctx_size) as *mut u32;
            let mps: u32 = match speed {
                3 => 64,            // High Speed
                4 | 5 => 512,       // SuperSpeed / SuperSpeedPlus
                _ => 8,             // FS / LS / unknown — safe minimum
            };
            let ep0_dw1 =
                (3u32 << 1) |       // CErr = 3
                (4u32 << 3) |       // EP Type = Control
                (mps << 16);
            let dq = ep0_ring.paddr | 0x1; // DCS = 1
            core::ptr::write_volatile(ep0.add(1), ep0_dw1);
            core::ptr::write_volatile(ep0.add(2), dq as u32);
            core::ptr::write_volatile(ep0.add(3), (dq >> 32) as u32);
            core::ptr::write_volatile(ep0.add(4), 8); // Avg TRB Len
        }

        // Install Device Context into DCBAA[slot_id]. DCBAA entries
        // are 8 bytes (u64 paddr) per xHCI 1.2 § 6.1.
        // SAFETY: dcbaa_vaddr is the freshly allocated, zeroed DMA
        // page owned by this driver. `slot_id` is bounded by
        // MAX_SLOTS_ENABLED (8); slot_id * 8 ≤ 64 bytes, well inside
        // the 4 KiB page. 8-byte write at a u64-aligned offset
        // (multiple of 8 from a 4 KiB-aligned base).
        unsafe {
            let slot_entry = (self.dcbaa_vaddr + (slot_id as u64) * 8) as *mut u64;
            core::ptr::write_volatile(slot_entry, dc_paddr);
        }

        // Submit Address Device command. BSR (Block Set Address
        // Request) [9] = 0 → controller issues SET_ADDRESS on the
        // bus. Slot ID in [31:24]. xHCI 1.2 § 6.4.3.4.
        let trb = Trb {
            parameter: ic_paddr,
            status: 0,
            control:
                ((trb_type::ADDRESS_DEVICE_COMMAND as u32) << 10)
                | ((slot_id as u32) << 24),
        };
        self.submit_command(trb)?;

        // Stash handles for downstream substages.
        self.input_context_paddr = Some(ic_paddr);
        self.input_context_vaddr = Some(ic_vaddr);
        self.device_context_paddr = Some(dc_paddr);
        self.device_context_vaddr = Some(dc_vaddr);
        self.ep0_transfer_ring = Some(ep0_ring);
        self.port_idx = Some(port_idx);
        self.port_speed = Some(speed);

        // Read back the Device Context's Slot Context DWord 3 to
        // report Slot State. Slot State is bits [31:27]. On success
        // it should be 2 (Addressed).
        // SAFETY: dc_vaddr is the freshly allocated DMA page; Slot
        // Context lives at offset 0 in the Device Context (xHCI 1.2
        // § 6.2.1). DWord 3 is 4 bytes at offset 12.
        let slot_state = unsafe {
            let dw3 = core::ptr::read_volatile((dc_vaddr + 12) as *const u32);
            ((dw3 >> 27) & 0x1F) as u8
        };
        Ok(slot_state)
    }

    // -----------------------------------------------------------------
    // EP0 control transfers + standard requests
    // -----------------------------------------------------------------

    /// Run a 3-TRB IN control transfer on EP0: Setup Stage → Data
    /// Stage (IN) → Status Stage (OUT, IOC=1). Returns once the
    /// matching Transfer Event arrives. The caller owns the response
    /// buffer at `buf_paddr` and reads it back via the mapped vaddr.
    ///
    /// `setup_packet` packs the 8-byte SETUP packet into a u64 in
    /// little-endian order (USB 2.0 § 9.3): byte 0 = bmRequestType,
    /// byte 1 = bRequest, bytes 2-3 = wValue, bytes 4-5 = wIndex,
    /// bytes 6-7 = wLength. xHCI 1.2 § 6.4.1.2.1 calls this the
    /// "TRB-resident" SETUP form, signalled by IDT=1 in the Setup
    /// Stage TRB.
    ///
    /// `length` is the Data Stage transfer length (≤ `wLength`).
    fn control_transfer_in(
        &mut self,
        setup_packet: u64,
        buf_paddr: u64,
        length: u16,
    ) -> Result<(), XhciError> {
        let slot_id = self.slot_id.ok_or(XhciError::EpNotReady)?;
        // The EP0 ring lives on `self`; take a brief move-out to enqueue
        // on it without mutably borrowing the whole controller for the
        // wait-for-event loop. Restored before return on every path.
        let mut ring = self.ep0_transfer_ring.take().ok_or(XhciError::EpNotReady)?;

        // Setup Stage TRB (xHCI 1.2 § 6.4.1.2.1).
        //   parameter : 8-byte SETUP packet (IDT means TRB-resident)
        //   status    : Interrupter Target [31:22]=0, TRB Transfer Length [16:0]=8
        //   control   : Cycle (filled by enqueue), IOC=0, IDT [6]=1,
        //               TRB Type [15:10]=2 (Setup Stage),
        //               TRT (Transfer Type) [17:16]=3 (IN Data Stage)
        let setup_trb = Trb {
            parameter: setup_packet,
            status: 8,
            control:
                (1u32 << 6)                                  // IDT
                | (3u32 << 16)                               // TRT = IN
                | ((trb_type::SETUP_STAGE as u32) << 10),
        };

        // Data Stage TRB (xHCI 1.2 § 6.4.1.2.2).
        //   parameter : buffer paddr (controller DMAs response here)
        //   status    : TRB Transfer Length = response buffer size
        //   control   : Cycle (enqueue), IOC=0, CH=0, DIR [16]=1 (IN),
        //               TRB Type [15:10]=3 (Data Stage)
        let data_trb = Trb {
            parameter: buf_paddr,
            status: length as u32,
            control:
                (1u32 << 16)                                 // DIR = IN
                | ((trb_type::DATA_STAGE as u32) << 10),
        };

        // Status Stage TRB (xHCI 1.2 § 6.4.1.2.3).
        //   parameter : 0 (no buffer)
        //   status    : 0
        //   control   : Cycle (enqueue), IOC [5]=1 (we want completion),
        //               DIR [16]=0 (OUT — opposite of IN Data Stage),
        //               TRB Type [15:10]=4 (Status Stage)
        // Only this TRB sets IOC, so the controller emits one
        // Transfer Event when the full 3-TRB sequence completes; the
        // event's TRB Pointer matches the Status TRB's paddr.
        let status_trb = Trb {
            parameter: 0,
            status: 0,
            control:
                (1u32 << 5)                                  // IOC
                | ((trb_type::STATUS_STAGE as u32) << 10),
        };

        let status_paddr = match (
            ring.enqueue(setup_trb),
            ring.enqueue(data_trb),
            ring.enqueue(status_trb),
        ) {
            (Some(_), Some(_), Some(p)) => p,
            _ => {
                self.ep0_transfer_ring = Some(ring);
                return Err(XhciError::TransferRingFull);
            }
        };

        // Restore the ring on self before the wait — wait_for_*
        // borrows the event ring through &mut self.
        self.ep0_transfer_ring = Some(ring);

        // Ring the device's EP0 doorbell. Target = slot_id; value =
        // endpoint ID (1 = DCI 1 = EP0 bidirectional control endpoint).
        // xHCI 1.2 § 6.4.5: doorbell value [7:0] = DB Target.
        self.ring_doorbell(slot_id, 1);

        // Wait for the matching Transfer Event. The Status TRB is the
        // only one with IOC=1, so we expect exactly one event whose
        // TRB pointer matches `status_paddr`.
        self.wait_for_transfer_event(status_paddr)?;
        Ok(())
    }

    /// Issue a GET_DESCRIPTOR(Device) on EP0 and return the 18-byte
    /// Device Descriptor per USB 2.0 § 9.6.1.
    ///
    /// Requires that `address_device` has run successfully (slot_id +
    /// ep0_transfer_ring populated). The caller compares the
    /// returned `bMaxPacketSize0` against the speed-default used in
    /// `address_device`; mismatch requires `evaluate_ep0_context`
    /// to be issued before subsequent EP0 transfers.
    pub fn get_descriptor_device(&mut self) -> Result<[u8; 18], XhciError> {
        // Per-transfer DMA buffer alloc (alloc_dma's granularity is
        // one page; we only read 18 bytes from it). EP0 control
        // transfers are infrequent; a buffer pool would be premature
        // optimization at this layer.
        // Revisit when: bulk IN/OUT endpoints land (B-vi) and the
        // per-transfer alloc count becomes a hot path.
        let (buf_paddr, buf_vaddr) = Self::alloc_zeroed_page()?;

        // SETUP packet for GET_DESCRIPTOR(Device):
        //   bmRequestType = 0x80 (D=IN | type=Standard | recipient=Device)
        //   bRequest      = 0x06 (GET_DESCRIPTOR)
        //   wValue        = 0x0100 (descriptor type 1=DEVICE, index 0)
        //   wIndex        = 0x0000 (language ID; 0 for device)
        //   wLength       = 0x0012 (18 bytes — device descriptor size)
        let setup_packet: u64 =
            0x80u64
            | (0x06u64 << 8)
            | (0x0100u64 << 16)
            | (0x0012u64 << 48);

        self.control_transfer_in(setup_packet, buf_paddr, 18)?;

        // Copy the 18-byte device descriptor out of the DMA buffer.
        // SAFETY: buf_vaddr is the page we allocated above (still
        // mapped, owned exclusively); the device descriptor fits in
        // 18 bytes well inside the page. Volatile reads make the
        // controller's writes visible.
        let mut desc = [0u8; 18];
        unsafe {
            let src = buf_vaddr as *const u8;
            for (i, slot) in desc.iter_mut().enumerate() {
                *slot = core::ptr::read_volatile(src.add(i));
            }
        }
        Ok(desc)
    }

    /// Issue GET_DESCRIPTOR(Configuration) on EP0 and copy the full
    /// nested blob (Configuration + Interface + Endpoint + class-
    /// specific descriptors) into `out`. Returns the number of bytes
    /// the device actually delivered.
    ///
    /// Two-pass per USB 2.0 § 9.4.3: first request reads 9 bytes
    /// (Configuration Descriptor only) to learn `wTotalLength`; the
    /// second request reads the full blob. `out` must be at least as
    /// large as the device's declared `wTotalLength`, capped at
    /// `MAX_CONFIG_DESCRIPTOR_SIZE`; oversized devices return
    /// `TransferFailed` so the caller knows to raise the cap.
    pub fn get_descriptor_configuration(
        &mut self,
        out: &mut [u8],
    ) -> Result<usize, XhciError> {
        if out.len() < 9 {
            return Err(XhciError::TransferRingFull); // out-of-band misuse signal
        }

        let (buf_paddr, buf_vaddr) = Self::alloc_zeroed_page()?;

        // Pass 1: read the Configuration Descriptor's 9 bytes to get
        // wTotalLength.
        //   bmRequestType = 0x80
        //   bRequest      = 0x06 (GET_DESCRIPTOR)
        //   wValue        = 0x0200 (descriptor type 2=CONFIGURATION, index 0)
        //   wIndex        = 0x0000
        //   wLength       = 0x0009
        let setup_short: u64 =
            0x80u64
            | (0x06u64 << 8)
            | (0x0200u64 << 16)
            | (0x0009u64 << 48);
        self.control_transfer_in(setup_short, buf_paddr, 9)?;

        // SAFETY: buf_vaddr is the page we allocated. The 9-byte
        // Configuration Descriptor lives at offset 0; bytes 2-3 hold
        // wTotalLength (little-endian).
        let total_length = unsafe {
            let src = buf_vaddr as *const u8;
            let lo = core::ptr::read_volatile(src.add(2));
            let hi = core::ptr::read_volatile(src.add(3));
            u16::from_le_bytes([lo, hi]) as usize
        };
        if total_length > MAX_CONFIG_DESCRIPTOR_SIZE || total_length > out.len() {
            return Err(XhciError::TransferFailed(0));
        }

        // Pass 2: read the full blob.
        //   wLength = total_length
        let setup_full: u64 =
            0x80u64
            | (0x06u64 << 8)
            | (0x0200u64 << 16)
            | ((total_length as u64) << 48);
        self.control_transfer_in(setup_full, buf_paddr, total_length as u16)?;

        // SAFETY: as above; the page is at least total_length bytes
        // wide because total_length ≤ MAX_CONFIG_DESCRIPTOR_SIZE
        // (512) << 4096.
        unsafe {
            let src = buf_vaddr as *const u8;
            for (i, slot) in out.iter_mut().take(total_length).enumerate() {
                *slot = core::ptr::read_volatile(src.add(i));
            }
        }
        Ok(total_length)
    }

    /// Issue an Evaluate Context Command to refresh EP0's Max Packet
    /// Size after GET_DESCRIPTOR(Device) revealed the device's actual
    /// `bMaxPacketSize0`. xHCI 1.2 § 4.6.7.
    ///
    /// Reuses the Input Context page allocated during `address_device`.
    /// Add Context flags: A1=1 (EP0), A0=0 (Slot Context untouched).
    /// Drop flags: all zero. The Slot Context region is left zeroed
    /// from `address_device`'s allocation; the controller ignores it
    /// when A0=0.
    pub fn evaluate_ep0_context(&mut self, new_mps: u16) -> Result<(), XhciError> {
        let slot_id = self.slot_id.ok_or(XhciError::EpNotReady)?;
        let ic_paddr = self.input_context_paddr.ok_or(XhciError::EpNotReady)?;
        let ic_vaddr = self.input_context_vaddr.ok_or(XhciError::EpNotReady)?;

        let ctx_size: u64 = if self.cap.csz { 64 } else { 32 };

        // Re-fill the Input Context. We zero the page first so the
        // previous Address Device payload doesn't leak into the
        // controller's read.
        // SAFETY: ic_vaddr is the page allocated by address_device;
        // we own it exclusively until the slot exits.
        unsafe {
            core::ptr::write_bytes(ic_vaddr as *mut u8, 0, 4096);

            // Input Control Context: A1 = 1 (EP0). A0 stays 0.
            let icc = ic_vaddr as *mut u32;
            core::ptr::write_volatile(icc.add(1), 0x2);

            // EP0 Endpoint Context: same shape as address_device's
            // fill but with the new MPS. CErr=3, EP Type=4 (Control),
            // TR Dequeue Pointer | DCS=1, Avg TRB Length = 8.
            let ep0_ring = self
                .ep0_transfer_ring
                .as_ref()
                .ok_or(XhciError::EpNotReady)?;
            let ep0 = (ic_vaddr + 2 * ctx_size) as *mut u32;
            let ep0_dw1 =
                (3u32 << 1)                  // CErr = 3
                | (4u32 << 3)                // EP Type = Control
                | ((new_mps as u32) << 16);
            let dq = ep0_ring.paddr | 0x1;
            core::ptr::write_volatile(ep0.add(1), ep0_dw1);
            core::ptr::write_volatile(ep0.add(2), dq as u32);
            core::ptr::write_volatile(ep0.add(3), (dq >> 32) as u32);
            core::ptr::write_volatile(ep0.add(4), 8); // Avg TRB Len
        }

        // Submit Evaluate Context Command. Same TRB layout as Address
        // Device — Input Context pointer + Slot ID — but TRB type 13.
        let trb = Trb {
            parameter: ic_paddr,
            status: 0,
            control:
                ((trb_type::EVALUATE_CONTEXT_COMMAND as u32) << 10)
                | ((slot_id as u32) << 24),
        };
        self.submit_command(trb)?;
        Ok(())
    }

    /// Run a 2-TRB control transfer on EP0 with no Data Stage (used
    /// for SET_CONFIGURATION + other "no payload" standard requests).
    /// xHCI 1.2 § 6.4.1.2: when TRT = 0 (No Data Stage), only Setup
    /// + Status TRBs are issued; the Status Stage direction is IN.
    fn control_transfer_no_data(
        &mut self,
        setup_packet: u64,
    ) -> Result<(), XhciError> {
        let slot_id = self.slot_id.ok_or(XhciError::EpNotReady)?;
        let mut ring = self.ep0_transfer_ring.take().ok_or(XhciError::EpNotReady)?;

        // Setup Stage TRB: IDT=1, TRT=0 (No Data Stage), Type=2.
        let setup_trb = Trb {
            parameter: setup_packet,
            status: 8,
            control:
                (1u32 << 6)                                  // IDT
                | ((trb_type::SETUP_STAGE as u32) << 10),
            // TRT = 0 (No Data Stage) is the implicit zero.
        };

        // Status Stage TRB: IOC=1, DIR=1 (IN — control transfers
        // without a Data Stage always Status-IN per USB 2.0 § 8.5.3),
        // Type=4.
        let status_trb = Trb {
            parameter: 0,
            status: 0,
            control:
                (1u32 << 5)                                  // IOC
                | (1u32 << 16)                               // DIR = IN
                | ((trb_type::STATUS_STAGE as u32) << 10),
        };

        let status_paddr = match (
            ring.enqueue(setup_trb),
            ring.enqueue(status_trb),
        ) {
            (Some(_), Some(p)) => p,
            _ => {
                self.ep0_transfer_ring = Some(ring);
                return Err(XhciError::TransferRingFull);
            }
        };

        self.ep0_transfer_ring = Some(ring);

        // Doorbell + wait for completion (Status TRB is the only one
        // with IOC=1, so the matching Transfer Event carries its paddr).
        self.ring_doorbell(slot_id, 1);
        self.wait_for_transfer_event(status_paddr)?;
        Ok(())
    }

    /// Issue a SET_CONFIGURATION standard request on EP0 (USB 2.0
    /// § 9.4.7). After this completes successfully the device is in
    /// the Configured state and the host can issue Configure
    /// Endpoint to bring up data endpoints.
    pub fn set_configuration(&mut self, config_value: u8) -> Result<(), XhciError> {
        // SETUP packet for SET_CONFIGURATION:
        //   bmRequestType = 0x00 (host-to-device, standard, recipient=device)
        //   bRequest      = 0x09 (SET_CONFIGURATION)
        //   wValue        = config_value
        //   wIndex        = 0
        //   wLength       = 0
        let setup_packet: u64 =
            0x00u64
            | (0x09u64 << 8)
            | ((config_value as u64) << 16);
        self.control_transfer_no_data(setup_packet)
    }

    // -----------------------------------------------------------------
    // Configure Endpoint + bulk transfer rings
    // -----------------------------------------------------------------

    /// Build an Input Context describing the CCID bulk IN + bulk OUT
    /// endpoint pair, issue Configure Endpoint (xHCI 1.2 § 4.6.6,
    /// TRB type 12), and allocate per-endpoint transfer rings. After
    /// this completes the slot transitions Addressed → Configured
    /// and the bulk endpoints can be driven via their doorbells.
    ///
    /// Returns the post-command Slot State from the Device Context
    /// for logging (3 = Configured on success per xHCI 1.2 § 6.2.2
    /// Slot State enum).
    pub fn configure_endpoint(&mut self, ccid: &CcidEndpoints) -> Result<u8, XhciError> {
        let slot_id = self.slot_id.ok_or(XhciError::EpNotReady)?;
        let ic_paddr = self.input_context_paddr.ok_or(XhciError::EpNotReady)?;
        let ic_vaddr = self.input_context_vaddr.ok_or(XhciError::EpNotReady)?;
        let dc_vaddr = self.device_context_vaddr.ok_or(XhciError::EpNotReady)?;
        let port_idx = self.port_idx.ok_or(XhciError::EpNotReady)?;
        let speed = self.port_speed.ok_or(XhciError::EpNotReady)?;

        // DCI mapping (xHCI 1.2 § 4.5.1): DCI = 2 * ep_num + dir_bit
        // (dir_bit = 1 for IN, 0 for OUT). Endpoint number is the
        // low 4 bits of bEndpointAddress.
        let in_ep_num = ccid.bulk_in.endpoint_number();
        let out_ep_num = ccid.bulk_out.endpoint_number();
        let in_dci = (in_ep_num as u32) * 2 + 1;
        let out_dci = (out_ep_num as u32) * 2;
        // Context Entries field in the Slot Context = max DCI used.
        let max_dci = core::cmp::max(in_dci, out_dci);

        let in_mps = ccid.bulk_in.max_packet_size_bytes();
        let out_mps = ccid.bulk_out.max_packet_size_bytes();

        // Allocate per-endpoint transfer rings before building the
        // Input Context (we need their paddrs for the TR Dequeue
        // Pointer fields).
        let in_ring = TransferRing::new().ok_or(XhciError::DmaAllocFailed)?;
        let out_ring = TransferRing::new().ok_or(XhciError::DmaAllocFailed)?;

        let ctx_size: u64 = if self.cap.csz { 64 } else { 32 };

        // Re-fill the Input Context. We zero the page so the
        // previous Address Device / Evaluate Context payload doesn't
        // leak into the controller's read.
        // SAFETY: ic_vaddr is the page allocated by address_device;
        // we own it exclusively until the slot exits. All offsets
        // below stay inside the 4 KiB page (Input Control + Slot +
        // up to DCI 31 endpoint contexts = 33 × ctx_size ≤ 2112 B).
        unsafe {
            core::ptr::write_bytes(ic_vaddr as *mut u8, 0, 4096);

            // Input Control Context (xHCI 1.2 § 6.2.5.1):
            //   DWord 0: Drop Context flags = 0
            //   DWord 1: Add Context flags — A0 (Slot, required when
            //            Context Entries changes), A<in_dci>, A<out_dci>
            let icc = ic_vaddr as *mut u32;
            let add_flags = 0x1u32 | (1u32 << in_dci) | (1u32 << out_dci);
            core::ptr::write_volatile(icc.add(1), add_flags);

            // Slot Context (xHCI 1.2 § 6.2.2) at offset ctx_size.
            // Re-populated from retained port_idx + port_speed; the
            // only field that changes vs. address_device is Context
            // Entries (1 → max_dci).
            let slot = (ic_vaddr + ctx_size) as *mut u32;
            let slot_dw0 =
                ((speed as u32 & 0xF) << 20)
                | ((max_dci & 0x1F) << 27);
            let slot_dw1 = ((port_idx as u32 + 1) & 0xFF) << 16;
            core::ptr::write_volatile(slot.add(0), slot_dw0);
            core::ptr::write_volatile(slot.add(1), slot_dw1);

            // Bulk IN Endpoint Context at offset (in_dci) * ctx_size.
            //   DWord 1: CErr=3, EP Type=6 (Bulk IN), MPS
            //   DWord 2-3: TR Dequeue Pointer | DCS=1
            //   DWord 4: Avg TRB Length = 1024 (bulk default per
            //            xHCI 1.2 § 4.14)
            let in_ep = (ic_vaddr + (in_dci as u64) * ctx_size) as *mut u32;
            let in_ep_dw1 =
                (3u32 << 1)                  // CErr = 3
                | (6u32 << 3)                // EP Type = Bulk IN
                | ((in_mps as u32) << 16);
            let in_dq = in_ring.paddr | 0x1;
            core::ptr::write_volatile(in_ep.add(1), in_ep_dw1);
            core::ptr::write_volatile(in_ep.add(2), in_dq as u32);
            core::ptr::write_volatile(in_ep.add(3), (in_dq >> 32) as u32);
            core::ptr::write_volatile(in_ep.add(4), 1024); // Avg TRB Len

            // Bulk OUT Endpoint Context at offset (out_dci) * ctx_size.
            //   EP Type = 2 (Bulk OUT)
            let out_ep = (ic_vaddr + (out_dci as u64) * ctx_size) as *mut u32;
            let out_ep_dw1 =
                (3u32 << 1)
                | (2u32 << 3)                // EP Type = Bulk OUT
                | ((out_mps as u32) << 16);
            let out_dq = out_ring.paddr | 0x1;
            core::ptr::write_volatile(out_ep.add(1), out_ep_dw1);
            core::ptr::write_volatile(out_ep.add(2), out_dq as u32);
            core::ptr::write_volatile(out_ep.add(3), (out_dq >> 32) as u32);
            core::ptr::write_volatile(out_ep.add(4), 1024);
        }

        // Configure Endpoint Command TRB (xHCI 1.2 § 6.4.3.5).
        //   parameter: Input Context paddr
        //   control  : Type=12, Slot ID [31:24], DC [9]=0 (configure,
        //              not deconfigure)
        let trb = Trb {
            parameter: ic_paddr,
            status: 0,
            control:
                (12u32 << 10)
                | ((slot_id as u32) << 24),
        };
        self.submit_command(trb)?;

        // Stash bulk ring state for downstream substages.
        self.ccid_bulk = Some(CcidBulkRings {
            in_dci: in_dci as u8,
            in_mps,
            in_ring,
            out_dci: out_dci as u8,
            out_mps,
            out_ring,
        });

        // Read back Slot State from the Device Context's Slot Context
        // (offset 0, DWord 3, bits [31:27]). Should be 3 (Configured).
        // SAFETY: dc_vaddr is the Device Context page allocated by
        // address_device; Slot Context lives at offset 0.
        let slot_state = unsafe {
            let dw3 = core::ptr::read_volatile((dc_vaddr + 12) as *const u32);
            ((dw3 >> 27) & 0x1F) as u8
        };
        Ok(slot_state)
    }

    /// Poll the event ring until a Transfer Event arrives whose TRB
    /// pointer matches `expected_trb_paddr`. Non-matching events
    /// (stray Port Status Change, Command Completion) are consumed
    /// and dropped. Same shape as `wait_for_command_completion` —
    /// duplication kept narrow for now.
    /// Revisit when: a third consumer of the event-ring poll loop
    /// appears (B-vi bulk transfers); refactor into
    /// `wait_for_event(predicate)` then.
    fn wait_for_transfer_event(
        &mut self,
        expected_trb_paddr: u64,
    ) -> Result<Trb, XhciError> {
        for _ in 0..MAX_POLL_ITERATIONS {
            if let Some(event) = self.event_ring.poll_next() {
                let trb_type_ = ((event.control >> 10) & 0x3F) as u8;
                if trb_type_ == trb_type::TRANSFER_EVENT
                    && event.parameter == expected_trb_paddr
                {
                    self.write_erdp_to_current();
                    let code = (event.status >> 24) as u8;
                    if code == completion_code::SUCCESS {
                        return Ok(event);
                    } else {
                        return Err(XhciError::TransferFailed(code));
                    }
                }
                continue;
            }
            sys::yield_now();
        }
        self.write_erdp_to_current();
        Err(XhciError::TransferTimeout)
    }

    /// Allocate one 4 KiB DMA page and zero it. Returns (paddr, vaddr).
    fn alloc_zeroed_page() -> Result<(u64, u64), XhciError> {
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut paddr);
        if ret < 0 {
            return Err(XhciError::DmaAllocFailed);
        }
        let vaddr = ret as u64;
        // SAFETY: alloc_dma returned a fresh 4 KiB region uniquely
        // owned by this process; zeroing initializes the entire page.
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, 4096);
        }
        Ok((paddr, vaddr))
    }

    // -----------------------------------------------------------------
    // Internal: register writes + bring-up steps
    // -----------------------------------------------------------------

    fn reset(op_vaddr: u64) -> Result<(), XhciError> {
        // Halt the controller first. The xHCI spec (§ 4.22.1.1) says
        // HCRST writes are only valid when HCHalted is set.
        // SAFETY: op_vaddr inside MMIO mapping; USBCMD/USBSTS at fixed
        // offsets within the smallest legal BAR.
        unsafe {
            let cur = core::ptr::read_volatile((op_vaddr + regs::USBCMD as u64) as *const u32);
            core::ptr::write_volatile(
                (op_vaddr + regs::USBCMD as u64) as *mut u32,
                cur & !regs::USBCMD_RUN,
            );
        }
        Self::poll_until(MAX_POLL_ITERATIONS, || {
            // SAFETY: as above.
            let sts = unsafe {
                core::ptr::read_volatile((op_vaddr + regs::USBSTS as u64) as *const u32)
            };
            sts & regs::USBSTS_HCH != 0
        })
        .ok_or(XhciError::HaltTimeout)?;

        // Write HCRST. Controller clears the bit when done.
        // SAFETY: as above.
        unsafe {
            core::ptr::write_volatile(
                (op_vaddr + regs::USBCMD as u64) as *mut u32,
                regs::USBCMD_HCRST,
            );
        }
        Self::poll_until(MAX_POLL_ITERATIONS, || {
            // SAFETY: as above.
            let cmd = unsafe {
                core::ptr::read_volatile((op_vaddr + regs::USBCMD as u64) as *const u32)
            };
            cmd & regs::USBCMD_HCRST == 0
        })
        .ok_or(XhciError::ResetTimeout)?;

        // Wait for Controller Not Ready to clear.
        Self::poll_until(MAX_POLL_ITERATIONS, || {
            // SAFETY: as above.
            let sts = unsafe {
                core::ptr::read_volatile((op_vaddr + regs::USBSTS as u64) as *const u32)
            };
            sts & regs::USBSTS_CNR == 0
        })
        .ok_or(XhciError::NotReadyTimeout)?;

        Ok(())
    }

    fn run(op_vaddr: u64) -> Result<(), XhciError> {
        // SAFETY: USBCMD inside MMIO mapping.
        unsafe {
            let cur = core::ptr::read_volatile((op_vaddr + regs::USBCMD as u64) as *const u32);
            core::ptr::write_volatile(
                (op_vaddr + regs::USBCMD as u64) as *mut u32,
                cur | regs::USBCMD_RUN,
            );
        }
        Self::poll_until(MAX_POLL_ITERATIONS, || {
            // SAFETY: as above.
            let sts = unsafe {
                core::ptr::read_volatile((op_vaddr + regs::USBSTS as u64) as *const u32)
            };
            sts & regs::USBSTS_HCH == 0
        })
        .ok_or(XhciError::RunTimeout)?;
        Ok(())
    }

    fn alloc_dcbaa() -> Result<(u64, u64), XhciError> {
        // One page is far more than the (MAX_SLOTS_ENABLED + 1) × 8 B
        // we actually need; alloc_dma's granularity is the page.
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut paddr);
        if ret < 0 {
            return Err(XhciError::DmaAllocFailed);
        }
        let vaddr = ret as u64;
        // SAFETY: alloc_dma returned a fresh 4 KiB region mapped at
        // `vaddr`; we own it exclusively until exit. Zeroing
        // initializes all DCBAA slot pointers to NULL — slot 0
        // (scratchpad pointer) stays NULL because qemu-xhci reports
        // MaxScratchpadBufs = 0; B-iii revisits if non-zero.
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, 4096);
        }
        Ok((paddr, vaddr))
    }

    fn write_dcbaap(op_vaddr: u64, paddr: u64) {
        // 64-bit MMIO register written as two 32-bit stores, LO first
        // then HI — matches Linux's `xhci_write_64` (lo_hi_writeq) and
        // QEMU's xhci dequeue-capture behavior (the dequeue/state
        // update happens on the HI write, using the captured LO).
        // SAFETY: op_vaddr inside MMIO mapping; DCBAAP at offset 0x30
        // (low) / 0x34 (high), both naturally aligned u32.
        unsafe {
            let p = op_vaddr + regs::DCBAAP as u64;
            core::ptr::write_volatile(p as *mut u32, paddr as u32);
            core::ptr::write_volatile((p + 4) as *mut u32, (paddr >> 32) as u32);
        }
    }

    fn write_crcr(op_vaddr: u64, ring_paddr: u64, cycle: u8) {
        // LO first then HI — matches Linux convention. The earlier
        // HI-first order silently failed under QEMU's qemu-xhci: the
        // controller would HCE on the first doorbell because its
        // internal cmd_ring.dequeue was still 0 (the LO write alone
        // doesn't latch the new pointer; the HI write is what triggers
        // the dequeue update using both captured values).
        // RCS = initial cycle bit (1 at fresh init). Low 6 bits of
        // ring_paddr are zero (DMA returns page-aligned, well past
        // 64-byte alignment).
        let low = (ring_paddr as u32) | ((cycle as u32) & 0x1);
        let high = (ring_paddr >> 32) as u32;
        // SAFETY: op_vaddr inside MMIO mapping.
        unsafe {
            let p = op_vaddr + regs::CRCR as u64;
            core::ptr::write_volatile(p as *mut u32, low);
            core::ptr::write_volatile((p + 4) as *mut u32, high);
        }
    }

    fn write_erstsz(interrupter_vaddr: u64, count: u32) {
        // SAFETY: interrupter_vaddr inside MMIO mapping.
        unsafe {
            core::ptr::write_volatile(
                (interrupter_vaddr + regs::IR_ERSTSZ as u64) as *mut u32,
                count,
            );
        }
    }

    fn write_erstba(interrupter_vaddr: u64, paddr: u64) {
        // LO first then HI — matches Linux + QEMU expectations.
        // SAFETY: interrupter_vaddr inside MMIO mapping.
        unsafe {
            let p = interrupter_vaddr + regs::IR_ERSTBA as u64;
            core::ptr::write_volatile(p as *mut u32, paddr as u32);
            core::ptr::write_volatile((p + 4) as *mut u32, (paddr >> 32) as u32);
        }
    }

    fn write_erdp(interrupter_vaddr: u64, paddr: u64) {
        // ERDP low-bits [3:0] = Dequeue ERST Segment Index (0), EHB
        // (bit 3) cleared. paddr is page-aligned so low bits are zero.
        // LO first then HI — matches Linux + QEMU expectations.
        // SAFETY: interrupter_vaddr inside MMIO mapping.
        unsafe {
            let p = interrupter_vaddr + regs::IR_ERDP as u64;
            core::ptr::write_volatile(p as *mut u32, paddr as u32);
            core::ptr::write_volatile((p + 4) as *mut u32, (paddr >> 32) as u32);
        }
    }

    /// Bounded poll for a condition. Calls `cond` up to `max` times,
    /// yielding between attempts. Returns `Some(())` if `cond` ever
    /// returned `true`; `None` if the iteration budget was exhausted.
    fn poll_until<F: FnMut() -> bool>(max: u32, mut cond: F) -> Option<()> {
        for _ in 0..max {
            if cond() {
                return Some(());
            }
            sys::yield_now();
        }
        None
    }
}
