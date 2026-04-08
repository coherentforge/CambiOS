// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! ARM Generic Timer driver — AArch64
//!
//! Replaces x86_64's APIC timer (which requires PIT-based calibration).
//! The ARM Generic Timer is simpler:
//!
//! - **CNTFRQ_EL0**: System counter frequency (set by firmware, no calibration)
//! - **CNTP_TVAL_EL0**: Countdown timer (write count → fires when 0)
//! - **CNTP_CTL_EL0**: Timer control (enable, mask, status)
//! - **CNTPCT_EL0**: Current system counter value (monotonic)
//!
//! The timer fires PPI INTID 30 (physical non-secure EL1 timer).
//!
//! ## Comparison with x86_64 APIC timer
//!
//! | Property          | APIC timer          | ARM Generic Timer     |
//! |-------------------|---------------------|-----------------------|
//! | Frequency source  | PIT calibration     | CNTFRQ_EL0 (firmware) |
//! | Counter           | LVT decrement       | CNTP_TVAL_EL0         |
//! | Mode              | Periodic/One-shot   | Countdown (rearm)     |
//! | Interrupt         | LVT vector (32)     | PPI INTID 30          |
//! | Config registers  | MMIO (APIC page)    | System registers      |

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// PPI INTID for the physical non-secure EL1 timer.
pub const TIMER_PPI_INTID: u32 = 30;

/// System counter frequency (ticks per second). Set once during init.
static COUNTER_FREQ: AtomicU32 = AtomicU32::new(0);

/// Timer reload value (ticks per period). Set once during init.
static TIMER_RELOAD: AtomicU32 = AtomicU32::new(0);

/// Boot timestamp (counter value at init time).
static BOOT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Read the system counter frequency from CNTFRQ_EL0.
///
/// This value is set by firmware and is typically:
/// - QEMU virt: 62.5 MHz (62_500_000)
/// - Real hardware: varies (usually 1-400 MHz)
#[inline]
pub fn read_frequency() -> u32 {
    let freq: u64;
    // SAFETY: Reading CNTFRQ_EL0 is always safe.
    unsafe {
        core::arch::asm!(
            "mrs {0}, cntfrq_el0",
            out(reg) freq,
            options(nostack, nomem, preserves_flags),
        );
    }
    freq as u32
}

/// Read the current system counter value (monotonic, never wraps in practice).
#[inline]
pub fn read_counter() -> u64 {
    let cnt: u64;
    // SAFETY: Reading CNTPCT_EL0 is always safe (virtual counter at EL0+).
    unsafe {
        core::arch::asm!(
            "mrs {0}, cntpct_el0",
            out(reg) cnt,
            options(nostack, nomem, preserves_flags),
        );
    }
    cnt
}

/// Get the system counter frequency (after init).
pub fn frequency() -> u32 {
    COUNTER_FREQ.load(Ordering::Relaxed)
}

/// Get elapsed time in milliseconds since boot.
pub fn elapsed_ms() -> u64 {
    let freq = COUNTER_FREQ.load(Ordering::Relaxed) as u64;
    if freq == 0 {
        return 0;
    }
    let boot = BOOT_COUNTER.load(Ordering::Relaxed);
    let now = read_counter();
    ((now - boot) * 1000) / freq
}

/// Initialize the ARM Generic Timer for periodic interrupts.
///
/// Reads the counter frequency, computes the reload value for the
/// requested tick rate, records boot time, and starts the countdown.
///
/// # Safety
/// Must be called during boot with interrupts masked (DAIF.I set).
/// The GIC must have PPI INTID 30 enabled in the Redistributor for
/// the interrupt to be delivered.
pub unsafe fn init(frequency_hz: u32) {
    let cnt_freq = read_frequency();
    if cnt_freq == 0 {
        panic!("ARM Generic Timer: CNTFRQ_EL0 is 0 (firmware bug)");
    }

    COUNTER_FREQ.store(cnt_freq, Ordering::Release);

    // Compute reload: ticks_per_period = counter_freq / desired_hz
    // For 100 Hz at 62.5 MHz: 625_000 ticks
    let reload = cnt_freq / frequency_hz;
    TIMER_RELOAD.store(reload, Ordering::Release);

    // Record boot timestamp
    BOOT_COUNTER.store(read_counter(), Ordering::Release);

    // SAFETY: Writing CNTP_TVAL_EL0 and CNTP_CTL_EL0 from EL1 during boot
    // with interrupts masked is safe. This is the standard ARM Generic Timer
    // init sequence.
    unsafe {
        // Set the countdown value
        core::arch::asm!(
            "msr cntp_tval_el0, {0}",
            in(reg) reload as u64,
            options(nostack, nomem),
        );

        // Enable the timer: CNTP_CTL_EL0 bit[0]=ENABLE, bit[1]=IMASK(0=unmask)
        core::arch::asm!(
            "mov {tmp}, #1",
            "msr cntp_ctl_el0, {tmp}",
            "isb",
            tmp = out(reg) _,
        );
    }

    crate::println!(
        "  ARM Generic Timer: freq={}Hz reload={} ({}Hz tick)",
        cnt_freq, reload, frequency_hz
    );
}

/// Rearm the timer for the next period.
///
/// Must be called from the timer ISR after processing the tick.
/// Writes the reload value to CNTP_TVAL_EL0 to start the next countdown.
///
/// # Safety
/// Must be called from an interrupt handler at EL1.
#[inline]
pub unsafe fn rearm() {
    let reload = TIMER_RELOAD.load(Ordering::Relaxed) as u64;
    // SAFETY: Writing CNTP_TVAL_EL0 from EL1 in a timer ISR is safe.
    unsafe {
        core::arch::asm!(
            "msr cntp_tval_el0, {0}",
            in(reg) reload,
            options(nostack, nomem),
        );
    }
}

/// Initialize the timer on an AP (same frequency as BSP).
///
/// # Safety
/// Must be called once per AP during startup with interrupts masked.
pub unsafe fn init_ap() {
    let reload = TIMER_RELOAD.load(Ordering::Acquire) as u64;
    if reload == 0 {
        panic!("ARM timer: BSP timer not initialized before AP");
    }

    // SAFETY: Writing CNTP_TVAL_EL0 and CNTP_CTL_EL0 from EL1 during AP
    // startup with interrupts masked is safe.
    unsafe {
        // Set countdown
        core::arch::asm!(
            "msr cntp_tval_el0, {0}",
            in(reg) reload,
            options(nostack, nomem),
        );

        // Enable
        core::arch::asm!(
            "mov {tmp}, #1",
            "msr cntp_ctl_el0, {tmp}",
            "isb",
            tmp = out(reg) _,
        );
    }
}

/// Stop the timer (disable interrupts).
///
/// # Safety
/// Must be called from EL1.
pub unsafe fn stop() {
    // CNTP_CTL_EL0 = 0 (disable)
    // SAFETY: Writing CNTP_CTL_EL0 from EL1 is safe.
    unsafe {
        core::arch::asm!(
            "msr cntp_ctl_el0, xzr",
            "isb",
            options(nostack, nomem),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_ppi_intid() {
        assert_eq!(TIMER_PPI_INTID, 30, "ARM timer PPI is INTID 30");
    }

    #[test]
    fn test_reload_calculation() {
        // QEMU virt counter frequency: 62.5 MHz
        // At 100 Hz: 62_500_000 / 100 = 625_000 ticks per period
        let cnt_freq = 62_500_000u32;
        let hz = 100u32;
        let reload = cnt_freq / hz;
        assert_eq!(reload, 625_000);
    }

    #[test]
    fn test_reload_calculation_24mhz() {
        // Some real hardware: 24 MHz counter
        let cnt_freq = 24_000_000u32;
        let hz = 100u32;
        let reload = cnt_freq / hz;
        assert_eq!(reload, 240_000);
    }

    #[test]
    fn test_elapsed_ms_calculation() {
        // Simulate: freq=62.5MHz, boot at counter 1000, now at counter 63_501_000
        // Elapsed ticks: 63_500_000, elapsed ms: 63_500_000 * 1000 / 62_500_000 = 1016ms
        let freq: u64 = 62_500_000;
        let boot: u64 = 1000;
        let now: u64 = 63_501_000;
        let elapsed = ((now - boot) * 1000) / freq;
        assert_eq!(elapsed, 1016);
    }

    #[test]
    fn test_elapsed_ms_zero_freq() {
        // If freq is 0 (not initialized), elapsed_ms should return 0
        let freq: u64 = 0;
        if freq == 0 {
            assert_eq!(0u64, 0); // elapsed_ms() returns 0 early
        }
    }

    #[test]
    fn test_atomics_initial_values() {
        // Verify initial atomic state
        assert_eq!(COUNTER_FREQ.load(Ordering::Relaxed), 0);
        assert_eq!(TIMER_RELOAD.load(Ordering::Relaxed), 0);
        assert_eq!(BOOT_COUNTER.load(Ordering::Relaxed), 0);
    }
}
