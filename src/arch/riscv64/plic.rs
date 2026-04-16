// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! PLIC — Platform-Level Interrupt Controller (RISC-V)
//!
//! The PLIC is RISC-V's equivalent of x86's I/O APIC and AArch64's
//! GIC Distributor — a platform-wide MMIO unit that routes external
//! (device) interrupts to hart contexts. It is NOT used for timer
//! interrupts (CLINT handles those, mediated via SBI per ADR-013
//! Decision 4) or for inter-hart IPIs (also CLINT/SBI).
//!
//! QEMU `virt` layout (discovered from DTB at runtime, hardcoded
//! defaults here for Phase R-1):
//!
//!   Base address      0x0C00_0000
//!   Priority regs     base + 4 * source_id
//!   Pending regs      base + 0x1000
//!   Enable regs       base + 0x2000 + 0x80 * context_id
//!   Threshold         base + 0x20_0000 + 0x1000 * context_id
//!   Claim/Complete    base + 0x20_0004 + 0x1000 * context_id
//!
//! "Context" = (hart, privilege). On QEMU virt, hart 0 S-mode is
//! context 1 (hart 0 M-mode is context 0).
//!
//! ## Phase status
//!
//! Phase R-1: module exists, operations are stubs. Phase R-3 fleshes
//! them out once the trap handler can dispatch external interrupts.

/// Default PLIC base on QEMU virt. Real address comes from the DTB
/// in production — this default only applies if DTB parsing fails.
pub const PLIC_BASE_DEFAULT: u64 = 0x0C00_0000;

/// Initialize the PLIC for this hart's S-mode context. Phase R-3.
///
/// # Safety
/// Must be called from S-mode during boot, after MMIO mapping is
/// established for the PLIC region.
pub unsafe fn init() {
    // Phase R-3:
    // - Clear all source priorities (write 0 to each priority reg)
    // - Set S-mode context threshold to 0 (accept all priorities ≥ 1)
    // - Clear all enable bits (sources enabled per-driver via
    //   `enable_irq`)
}

/// Enable a specific interrupt source for this hart's S-mode
/// context. Phase R-3.
///
/// # Safety
/// Must be called from S-mode. `source_id` must be a valid IRQ line
/// for the platform (per DTB).
pub unsafe fn enable_irq(_source_id: u32) {
    // Phase R-3.
}

/// Read the PLIC claim register — returns the highest-priority
/// pending IRQ and marks it in-service. Returns 0 if nothing pending.
/// Phase R-3.
pub fn claim() -> u32 {
    0
}

/// Write the claim/complete register to signal IRQ handling is done.
/// Phase R-3.
pub fn complete(_source_id: u32) {
    // Phase R-3.
}
