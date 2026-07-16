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

    // ── Boot manifest (ADR-018 — a present-but-invalid manifest is
    //    fatal: booting permissively on corrupt security configuration
    //    would be the vulnerability. An absent manifest module is NOT
    //    an error — the enforcement tables stay empty.) ──

    /// The manifest module's ARCSIG trailer is missing, unsupported,
    /// or its signature does not verify against the bootstrap pubkey.
    /// Site: `src/manifest.rs` `transcribe_manifest_module`.
    ManifestSignatureInvalid,

    /// The manifest blob failed the structural parse (bad magic /
    /// version / offsets / entry fields). The parse-error detail is
    /// printed at the site before this is returned.
    /// Site: `src/manifest.rs` `validate_payload`.
    ManifestMalformed,

    /// The manifest failed cross-record validation (duplicate module
    /// name or duplicate endpoint reservation).
    /// Site: `src/manifest.rs` `validate_payload`.
    ManifestInconsistent,

    /// Populating the enforcement tables failed (reservation or
    /// spawn-table install rejected a row). Unreachable after a clean
    /// `validate_unique` pass; kept so the tables' own invariants do
    /// not depend on their caller.
    /// Site: `src/manifest.rs` populate helpers.
    ManifestTranscriptionFailed,

    /// A manifest was transcribed but no boot module named
    /// `INIT_MODULE_NAME` is present. The manifest exists to be
    /// executed by init (ADR-018 § 4); a boot image shipping one
    /// without the other is broken, and continuing would silently
    /// leave the described services unsupervised.
    /// Site: `src/microkernel/main.rs` `load_boot_modules`.
    InitModuleMissing,

    /// Creating init as PID 1 failed after a manifest was transcribed
    /// (ELF load/verify, manifest-blob mapping, or capability setup).
    /// The step detail is printed at the site before this is returned.
    /// Site: `src/microkernel/main.rs` `create_init_process`.
    InitCreationFailed,
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
        BootError::ManifestSignatureInvalid =>
            "boot manifest ARCSIG trailer missing, unsupported, or signature invalid",
        BootError::ManifestMalformed =>
            "boot manifest blob failed structural parse",
        BootError::ManifestInconsistent =>
            "boot manifest failed cross-record validation (duplicate name/endpoint)",
        BootError::ManifestTranscriptionFailed =>
            "boot manifest transcription failed (table install rejected a row)",
        BootError::InitModuleMissing =>
            "boot manifest present but no init boot module — broken boot image",
        BootError::InitCreationFailed =>
            "creating init (PID 1) failed after manifest transcription",
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
    /// (The list drifted at the step-4 manifest variants; caught up
    /// with the step-7 init variants — keep it exhaustive.)
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
            BootError::ManifestSignatureInvalid,
            BootError::ManifestMalformed,
            BootError::ManifestInconsistent,
            BootError::ManifestTranscriptionFailed,
            BootError::InitModuleMissing,
            BootError::InitCreationFailed,
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
            BootError::ManifestSignatureInvalid,
            BootError::ManifestMalformed,
            BootError::ManifestInconsistent,
            BootError::ManifestTranscriptionFailed,
            BootError::InitModuleMissing,
            BootError::InitCreationFailed,
        ] {
            buf.clear();
            write!(buf, "{:?}", variant).unwrap();
            assert!(!buf.is_empty());
        }
    }
}
