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

use crate::ring::{CommandRing, EventRing, Erst};

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
        let hccparams1 = core::ptr::read_volatile(base.add(0x10) as *const u32);
        let dboff = core::ptr::read_volatile(base.add(0x14) as *const u32);
        let rtsoff = core::ptr::read_volatile(base.add(0x18) as *const u32);

        XhciCapabilities {
            cap_length,
            hci_version,
            max_slots: (hcsparams1 & 0xFF) as u8,
            max_intrs: ((hcsparams1 >> 8) & 0x7FF) as u16,
            max_ports: ((hcsparams1 >> 24) & 0xFF) as u8,
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

    // USBCMD bits
    pub const USBCMD_RUN: u32 = 1 << 0;
    pub const USBCMD_HCRST: u32 = 1 << 1;

    // USBSTS bits (subset relevant to B-ii)
    pub const USBSTS_HCH: u32 = 1 << 0; // Host Controller Halted
    pub const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

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
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Controller bring-up failure modes.
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
    /// Device Context Base Address Array (paddr written to DCBAAP;
    /// vaddr retained for slot-context installation in B-iii).
    pub dcbaa_paddr: u64,
    pub dcbaa_vaddr: u64,
    pub command_ring: CommandRing,
    pub event_ring: EventRing,
    pub erst: Erst,
}

impl XhciController {
    /// Reset the controller, set up DCBAA + rings, and run.
    pub fn bring_up(mmio_vaddr: u64, cap: XhciCapabilities) -> Result<Self, XhciError> {
        let op_vaddr = mmio_vaddr + cap.cap_length as u64;
        let runtime_vaddr = mmio_vaddr + cap.runtime_offset as u64;
        let interrupter0_vaddr = runtime_vaddr + regs::INTERRUPTER_0 as u64;

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

        // Step 6: RUN. Set USBCMD.R/S, wait for USBSTS.HCH to clear.
        Self::run(op_vaddr)?;

        Ok(Self {
            mmio_vaddr,
            cap,
            op_vaddr,
            runtime_vaddr,
            interrupter0_vaddr,
            dcbaa_paddr,
            dcbaa_vaddr,
            command_ring,
            event_ring,
            erst,
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
        // SAFETY: op_vaddr inside MMIO mapping; DCBAAP at offset 0x30
        // (low) / 0x34 (high), both naturally aligned u32. Two 32-bit
        // writes give the same effect as a single u64 write for this
        // register and avoid relying on the kernel's MMIO mapping to
        // serialize 8-byte stores.
        unsafe {
            let p = op_vaddr + regs::DCBAAP as u64;
            core::ptr::write_volatile((p + 4) as *mut u32, (paddr >> 32) as u32);
            core::ptr::write_volatile(p as *mut u32, paddr as u32);
        }
    }

    fn write_crcr(op_vaddr: u64, ring_paddr: u64, cycle: u8) {
        // CRCR low dword must be written LAST (xHCI 1.2 § 4.6.1.2).
        // RCS = initial cycle bit (1 at fresh init). Low 6 bits of
        // ring_paddr are zero (DMA returns page-aligned, well past
        // 64-byte alignment).
        let low = (ring_paddr as u32) | ((cycle as u32) & 0x1);
        let high = (ring_paddr >> 32) as u32;
        // SAFETY: op_vaddr inside MMIO mapping.
        unsafe {
            let p = op_vaddr + regs::CRCR as u64;
            core::ptr::write_volatile((p + 4) as *mut u32, high);
            core::ptr::write_volatile(p as *mut u32, low);
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
        // SAFETY: interrupter_vaddr inside MMIO mapping.
        unsafe {
            let p = interrupter_vaddr + regs::IR_ERSTBA as u64;
            core::ptr::write_volatile((p + 4) as *mut u32, (paddr >> 32) as u32);
            core::ptr::write_volatile(p as *mut u32, paddr as u32);
        }
    }

    fn write_erdp(interrupter_vaddr: u64, paddr: u64) {
        // ERDP low-bits [3:0] = Dequeue ERST Segment Index (0), EHB
        // (bit 3) cleared. paddr is page-aligned so low bits are zero.
        // SAFETY: interrupter_vaddr inside MMIO mapping.
        unsafe {
            let p = interrupter_vaddr + regs::IR_ERDP as u64;
            core::ptr::write_volatile((p + 4) as *mut u32, (paddr >> 32) as u32);
            core::ptr::write_volatile(p as *mut u32, paddr as u32);
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
