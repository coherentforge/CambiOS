// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Typed boot-path error surface, per [ADR-021](../../../docs/adr/021-typed-boot-error-propagation.md).
//!
//! Every way boot can fail is a named variant of [`BootError`]. The
//! single [`boot_failed`] handler is the only code path that halts the
//! system on init failure — it matches exhaustively on every variant
//! and prints a compile-time-known diagnostic string. Callers above
//! the init layer (i.e., `kmain`) thread init functions with `?`:
//!
//! ```ignore
//! fn kmain() -> ! {
//!     if let Err(err) = kmain_init() {
//!         boot::boot_failed(err);
//!     }
//!     // … scheduler loop …
//! }
//!
//! fn kmain_init() -> Result<(), BootError> {
//!     boot::populate_info()?;
//!     interrupts::init()?;
//!     timer::init(TIMER_HZ)?;
//!     Ok(())
//! }
//! ```
//!
//! # Phase 021.A (this commit)
//!
//! Types only. No call sites consume them yet — migration of the
//! eleven `.expect()` / `panic!()` boot-path sites lands in phase
//! 021.B, subsystem-grouped. The existing panic handler still fires
//! on today's `.expect` calls; boot_failed is unreachable until
//! 021.B wires it in.
//!
//! # What goes here vs. the panic handler
//!
//! `boot_failed` is for *expected* init-time failures that the
//! typed return chain surfaces. The `#[panic_handler]` is defense-
//! in-depth for runtime panics outside the init path (which, if
//! ADR-021 succeeds, should be zero). The `[BOOT FAIL]` prefix on
//! `boot_failed`'s output distinguishes typed boot failures from
//! unexpected panics in the same serial log.

/// Every way boot can fail. Exhaustively matched in [`boot_failed`].
///
/// Flat rather than per-subsystem-subtype because eleven variants
/// do not justify the `BootError::Interrupts(InterruptError::…)`
/// indirection. A future variant count >20 or a variant carrying
/// meaningful context payload would argue for the split — see
/// ADR-021 § Open Problems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    // ── Bootloader contract (Limine on x86_64 / aarch64; boot stub on riscv64) ──

    /// The boot protocol did not provide the HHDM response.
    /// Site: `src/boot/limine.rs` Limine HHDM request unwrap.
    LimineHhdmMissing,

    /// The boot protocol did not provide the memory-map response.
    /// Site: `src/boot/limine.rs` Limine memory-map request unwrap.
    LimineMemoryMapMissing,

    // ── Interrupt controller init ──

    /// APIC detection or initialization failed.
    /// Site: `src/interrupts/mod.rs` `apic::detect_and_init()` expect.
    ApicInitFailed,

    /// APIC timer calibration computed a bus frequency of zero.
    /// Site: `src/arch/x86_64/apic.rs` calibration panic.
    ApicCalibrationFailed,

    /// PLIC initialization failed (DTB PLIC address range implausible).
    /// Site: `src/microkernel/main.rs` `plic::init(...)` expect on riscv64.
    PlicInitFailed,

    // ── Early-heap allocations during interrupt setup ──

    /// `Layout::from_size_align` failed for the double-fault IST stack.
    /// Site: `src/interrupts/mod.rs` IST stack layout expect.
    IstStackLayoutInvalid,

    /// Allocator returned null for the double-fault IST stack.
    /// Site: `src/interrupts/mod.rs` IST stack null-check panic.
    IstStackAllocFailed,

    // ── Platform timer ──

    /// Platform timer frequency unavailable.
    /// aarch64: CNTFRQ_EL0 read as zero.
    /// riscv64: DTB omitted `/cpus/timebase-frequency`.
    /// Sites: `src/arch/aarch64/timer.rs` CNTFRQ panic; `src/arch/riscv64/timer.rs` expect.
    TimerFrequencyMissing,

    /// Platform timer base frequency too low for the target HZ —
    /// reload divisor would compute as zero.
    /// Site: `src/arch/riscv64/timer.rs` `assert!(reload > 0)`.
    TimerFrequencyTooLow,

    /// Boot-sequence invariant violated: an AP came up and discovered
    /// the BSP had not finished its boot-time timer init.
    /// Site: `src/arch/aarch64/timer.rs` AP-side invariant panic.
    TimerInvariantViolation,
}

/// Halt the system on a typed boot-path failure.
///
/// Prints a compile-time-known diagnostic string per variant, then
/// halts permanently via [`crate::halt`]. No format-string machinery
/// is involved — every message is a `&'static str`.
///
/// The match is exhaustive; adding a new [`BootError`] variant forces
/// a new message at compile time.
pub fn boot_failed(err: BootError) -> ! {
    let msg = match err {
        BootError::LimineHhdmMissing =>
            "Limine did not provide the HHDM response",
        BootError::LimineMemoryMapMissing =>
            "Limine did not provide the memory-map response",
        BootError::ApicInitFailed =>
            "APIC initialization failed",
        BootError::ApicCalibrationFailed =>
            "APIC timer calibration failed (bus frequency zero)",
        BootError::PlicInitFailed =>
            "PLIC init failed (DTB PLIC address range implausible)",
        BootError::IstStackLayoutInvalid =>
            "IST stack layout computation failed",
        BootError::IstStackAllocFailed =>
            "IST stack allocator returned null",
        BootError::TimerFrequencyMissing =>
            "platform timer frequency unavailable",
        BootError::TimerFrequencyTooLow =>
            "platform timer base frequency too low for target HZ",
        BootError::TimerInvariantViolation =>
            "AP came up before BSP finished timer init",
    };
    crate::println!("[BOOT FAIL] {}", msg);
    crate::halt()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The boot_failed handler cannot be called in tests (it calls
    // crate::halt which is a divergent function). The tests below
    // verify the *type surface* and the exhaustive-match discipline.

    /// Every variant round-trips as its own discriminant — catches
    /// accidental duplicate assignments on `#[repr(...)]` bumps.
    #[test]
    fn variants_are_distinct() {
        let all = [
            BootError::LimineHhdmMissing,
            BootError::LimineMemoryMapMissing,
            BootError::ApicInitFailed,
            BootError::ApicCalibrationFailed,
            BootError::PlicInitFailed,
            BootError::IstStackLayoutInvalid,
            BootError::IstStackAllocFailed,
            BootError::TimerFrequencyMissing,
            BootError::TimerFrequencyTooLow,
            BootError::TimerInvariantViolation,
        ];
        // Every pair of variants must be distinct under Eq.
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    /// Each variant implements Debug (via derive) — smoke test that
    /// the formatter does not panic on any variant.
    #[test]
    fn debug_impl_is_non_empty_for_every_variant() {
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        for variant in [
            BootError::LimineHhdmMissing,
            BootError::LimineMemoryMapMissing,
            BootError::ApicInitFailed,
            BootError::ApicCalibrationFailed,
            BootError::PlicInitFailed,
            BootError::IstStackLayoutInvalid,
            BootError::IstStackAllocFailed,
            BootError::TimerFrequencyMissing,
            BootError::TimerFrequencyTooLow,
            BootError::TimerInvariantViolation,
        ] {
            buf.clear();
            write!(buf, "{:?}", variant).unwrap();
            assert!(!buf.is_empty());
        }
    }
}
