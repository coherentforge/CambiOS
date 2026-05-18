// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! xHCI capability register parsing per xHCI 1.2 § 5.3.
//!
//! The capability register block sits at the start of the xHCI MMIO BAR
//! and is read-only. It tells the driver where the operational, runtime,
//! and doorbell register regions live, how many slots / interrupters /
//! ports the controller supports, and whether 64-bit addressing is
//! available.
//!
//! B-i reads these registers and stops. Operational-register bring-up
//! (HCRESET, Run-Stop, DCBAA, command ring) lands in B-ii.

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
