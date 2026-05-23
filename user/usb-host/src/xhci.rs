// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! xHCI controller bring-up per xHCI 1.2 § 4.2 + § 5.
//!
//! B-i shipped capability-register parsing. B-ii adds:
//!   - Operational + runtime register accessors
//!   - HCRESET sequence (§ 4.22.1)
//!   - DCBAA / command-ring / event-ring + ERST setup (§ 4.2)
//!   - USBCMD.RUN + HCH-clears assertion
//!
//! `XhciController` is the post-init handle: holds the MMIO base, the
//! parsed capabilities, the derived op + runtime virtual addresses, and
//! the in-DMA ring buffers. B-iii commands flow through this handle.

use cambios_libsys as sys;

use crate::ring::{CommandRing, EventRing, Erst, Trb};

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
    pub const NOOP_COMMAND: u8 = 23;
    pub const ENABLE_SLOT_COMMAND: u8 = 9;
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
