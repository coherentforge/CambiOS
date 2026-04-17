// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Timer — RISC-V (SBI-mediated, Phase R-3.c)
//!
//! Per [ADR-013](../../../docs/adr/013-riscv64-architecture-support.md)
//! Decision 4, CambiOS uses the SBI Timer Extension rather than
//! programming CLINT directly. `sbi_set_timer(stime_value)` arms the
//! next per-hart timer interrupt; the `time` CSR (readable from
//! S-mode) gives the current tick count. Timer interrupts arrive with
//! `scause == 0x8000_0000_0000_0005` (bit 63 set → interrupt, cause 5
//! → S-mode timer) and are dispatched via
//! [`super::trap::rust_trap_handler`].
//!
//! ## Reload math
//!
//! `time` increments at the platform base frequency read from the DTB
//! (`/cpus/timebase-frequency`, surfaced through
//! [`crate::boot::BootInfo::timer_base_frequency_hz`]). For a target
//! tick rate of `hz`:
//!
//! ```text
//! RELOAD = timebase_frequency_hz / hz
//! ```
//!
//! QEMU virt runs at 10 MHz timebase, so 100 Hz → RELOAD = 100_000
//! ticks per interval. Real RISC-V silicon typically uses 1–25 MHz.

use core::sync::atomic::{AtomicU64, Ordering};

use super::sbi;

// ============================================================================
// Configuration — set by `init`, read by `rearm` and the ISR path
// ============================================================================

/// Ticks of the `time` CSR per timer interrupt. 0 until `init` runs;
/// the trap handler treats a zero reload as "timer not armed yet" and
/// refuses to rearm.
static RELOAD: AtomicU64 = AtomicU64::new(0);

/// Monotonic tick counter. Updated by the trap handler on every S-mode
/// timer interrupt. Published via [`tick_count`] for debug/boot
/// diagnostic output.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Public API
// ============================================================================

/// Initialize the per-hart timer.
///
/// Reads the platform base frequency from [`crate::boot::info`] (which
/// was populated from the DTB by [`crate::boot::riscv::populate`]),
/// computes the reload value for the requested `hz`, enables the
/// S-mode timer interrupt enable bit (`sie.STIE`), and arms the first
/// interrupt. Does **not** set `sstatus.SIE` — that is the caller's
/// call (see [`super::trap::enable_interrupts`]).
///
/// Returns the effective reload so the caller can log it.
///
/// # Safety
/// - [`crate::boot::install`] must have run (so `boot::info()` works).
/// - Must be called with interrupts globally masked (`sstatus.SIE=0`).
/// - Must be called once per hart during boot, after the trap vector
///   is installed.
pub unsafe fn init(hz: u32) -> u64 {
    assert!(hz > 0, "timer::init called with hz=0");

    let base = crate::boot::info()
        .timer_base_frequency_hz
        .expect(
            "timer::init: DTB did not report /cpus/timebase-frequency — \
             CambiOS needs this to program the SBI timer",
        );

    let reload = (base as u64) / (hz as u64);
    assert!(
        reload > 0,
        "timer::init: base frequency {} Hz too low for target {} Hz",
        base,
        hz,
    );
    RELOAD.store(reload, Ordering::Release);

    // Enable S-mode timer interrupt (STIE in sie).
    // SAFETY: csrs is legal from S-mode; sets bit 5 of sie.
    unsafe {
        core::arch::asm!(
            "csrs sie, {0}",
            in(reg) 1u64 << 5,
            options(nostack, nomem, preserves_flags),
        );
    }

    // Arm the first interrupt.
    // SAFETY: reload is non-zero (asserted above) and we just published
    // it; sbi_set_timer is safe from S-mode.
    unsafe { rearm() };

    reload
}

/// Arm the next timer interrupt.
///
/// Called from the trap handler on every S-mode timer tick, and once
/// from [`init`] to prime the first interrupt.
///
/// # Safety
/// Must be called from S-mode. [`init`] must have published a non-zero
/// `RELOAD` (asserted in debug builds).
#[inline]
pub unsafe fn rearm() {
    let reload = RELOAD.load(Ordering::Acquire);
    debug_assert!(reload > 0, "riscv64 timer::rearm called before init");
    let deadline = sbi::read_time().wrapping_add(reload);
    // SAFETY: sbi::sbi_set_timer is safe from S-mode.
    unsafe { sbi::sbi_set_timer(deadline) };
}

/// Current tick count (monotonic, increments once per interrupt).
#[inline]
pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Acquire)
}

// ============================================================================
// Interrupt path — invoked from `super::trap::rust_trap_handler`
// ============================================================================

/// Called from the trap handler when a supervisor timer interrupt
/// fires. Rearms the timer, bumps the tick counter, and logs a
/// milestone line every 50 ticks (twice a second at 100 Hz) so the
/// Phase R-3.b+c milestone is observable on serial.
///
/// Phase R-3.f will replace the logging with a call into
/// `crate::scheduler::on_timer_isr` for preemption.
///
/// # Safety
/// ISR context — interrupts are masked; no allocation, no blocking.
/// Printing from an ISR is deliberately kept to milestone diagnostic
/// lines and will be removed in R-3.f when the scheduler takes over.
pub unsafe fn on_timer_interrupt() {
    // SAFETY: SBI call and rearm are safe from S-mode ISR context.
    unsafe { rearm() };

    let ticks = TICK_COUNT.fetch_add(1, Ordering::AcqRel) + 1;

    // R-3.b+c milestone cadence: log every half second at 100 Hz.
    // Removed when R-3.f wires the scheduler.
    if ticks % 50 == 0 {
        crate::println!(
            "[R-3 tick {}] sbi_set_timer live; time={}",
            ticks,
            sbi::read_time(),
        );
    }
}
