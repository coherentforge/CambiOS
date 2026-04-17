// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! SBI (Supervisor Binary Interface) ecall wrappers.
//!
//! Per [ADR-013](../../../docs/adr/013-riscv64-architecture-support.md)
//! Decision 4, the kernel talks to M-mode firmware (OpenSBI in
//! QEMU / production silicon, eventually a CambiOS-native M-mode
//! firmware on project hardware) via the SBI ABI rather than
//! programming CLINT MMIO directly.
//!
//! This module is the single point where S-mode crosses into M-mode.
//! It hand-rolls the ecall inline-asm rather than pulling in the
//! `sbi` crate — a few tens of lines of code for the services we need
//! (timer, IPI in R-5, hart start/stop in R-5), matching the
//! verification-transparency posture applied elsewhere in arch.
//!
//! ## ABI
//!
//! - Extension ID in `a7`, function ID in `a6`.
//! - Arguments in `a0..a5`.
//! - Return: `a0 = error code` (0 = success), `a1 = value`.
//! - `ecall` from S-mode traps into M-mode. OpenSBI reads the
//!   registers, performs the service, writes results, and `mret`s back.
//!
//! Error codes are defined in the SBI v2.0 spec; we ignore them for
//! `sbi_set_timer` because the only failure mode on a conforming
//! implementation is "extension not supported" which we eliminate by
//! using the legacy extension.

// ============================================================================
// Extension / function IDs
// ============================================================================

/// Legacy SBI extension — "Set Timer" (EID 0x00, FID 0).
///
/// The v2.0 spec moved set-timer into the TIME extension
/// (EID = 0x54494D45, "TIME"), but the legacy call is still supported
/// by OpenSBI unconditionally and by every SBI implementation we
/// realistically target. The legacy call takes `stime_value` in `a0`;
/// the TIME extension call takes it split into `a0:a1` on RV32 but
/// also just `a0` on RV64 — so the legacy form is simpler and
/// behaviorally equivalent on our target.
///
/// If a future platform drops legacy compatibility, swap to EID =
/// 0x54494D45, FID = 0 here.
const SBI_LEGACY_SET_TIMER: u64 = 0x00;

// ============================================================================
// Public wrappers
// ============================================================================

/// Program the next supervisor-mode timer interrupt.
///
/// When the `time` CSR reaches `stime_value`, M-mode asserts the S-mode
/// timer interrupt (STIP in `mip` mirrored into `sip`). The S-mode
/// handler must re-arm to keep the timer firing.
///
/// # Safety
/// Must be called from S-mode. `stime_value` is in the same units as
/// the `time` CSR (platform `timebase-frequency`, read from the DTB
/// via [`crate::boot::BootInfo::timer_base_frequency_hz`] at init).
#[inline]
pub unsafe fn sbi_set_timer(stime_value: u64) {
    // SAFETY: ecall from S-mode to M-mode is always legal. The
    // clobber list covers the ABI-visible registers the call may
    // modify. `nostack` holds because ecall does not touch the stack
    // at our privilege level (M-mode firmware has its own stack).
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SBI_LEGACY_SET_TIMER,
            in("a0") stime_value,
            lateout("a0") _,
            lateout("a1") _,
            options(nostack),
        );
    }
}

/// Read the per-hart `time` CSR.
///
/// Monotonic at `timebase-frequency` Hz; the unit that
/// [`sbi_set_timer`] consumes.
#[inline]
pub fn read_time() -> u64 {
    let t: u64;
    // SAFETY: `csrr time` is a pure read, readable from S-mode
    // unconditionally (RISC-V priv-spec makes `time` a shadowed alias
    // of `mtime`).
    unsafe {
        core::arch::asm!(
            "csrr {0}, time",
            out(reg) t,
            options(nostack, nomem, preserves_flags),
        );
    }
    t
}
