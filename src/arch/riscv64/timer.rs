// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Timer — RISC-V (SBI-mediated, Phase R-3)
//!
//! Per [ADR-013](../../docs/adr/013-riscv64-architecture-support.md)
//! Decision 4, CambiOS uses the SBI Timer Extension rather than
//! programming CLINT directly. `sbi_set_timer(stime_value)` arms the
//! next per-hart timer interrupt; the `time` CSR (readable from
//! S-mode) gives the current tick count. Timer interrupts arrive with
//! `scause == 0x8000_0000_0000_0005` (bit 63 set → interrupt, cause 5
//! → S-mode timer).
//!
//! Phase R-1 only: module exists so `crate::arch::timer` resolves when
//! portable code imports it. `init()` / `rearm()` are Phase R-3.

/// Initialize the per-hart timer at `hz` Hz.
///
/// Phase R-3 will:
/// 1. Read `timebase-frequency` from DTB (stored in BootInfo or a
///    dedicated timer-info struct).
/// 2. Compute `reload = timebase_freq / hz`.
/// 3. Enable STIE bit in `sie` CSR.
/// 4. Call `rearm()` to schedule the first tick.
///
/// # Safety
/// Must be called once per hart, during boot, after `stvec` is
/// installed and `sstatus.SIE` is set.
pub unsafe fn init(_hz: u32) {
    // Phase R-3.
}

/// Arm the next timer interrupt via SBI. Phase R-3.
///
/// # Safety
/// Must be called from S-mode.
pub unsafe fn rearm() {
    // Phase R-3 will issue:
    //   let now: u64;
    //   core::arch::asm!("csrr {0}, time", out(reg) now);
    //   let deadline = now + RELOAD;
    //   sbi_set_timer(deadline);   // SBI extension 0x54494D45, function 0
}
