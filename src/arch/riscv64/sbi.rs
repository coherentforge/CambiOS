// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

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

// ============================================================================
// HSM — Hart State Management extension (SBI v0.2+)
// ============================================================================
//
// Extension ID "HSM" = 0x48534D. Function 0 = hart_start.
// Signature: sbi_hart_start(hart_id, start_addr, opaque) -> SbiRet.
// On success, the target hart begins execution in S-mode at `start_addr`
// with paging disabled and interrupts masked. a0 receives `hart_id`,
// a1 receives `opaque`. This is the RISC-V AP-wakeup primitive — the
// replacement for Limine's MP `goto_address` on x86_64 / AArch64.

/// SBI HSM extension ID.
const SBI_EXT_HSM: u64 = 0x48534D;
/// HSM function: hart_start.
const SBI_HSM_HART_START: u64 = 0;

/// SBI Base extension — `probe_extension(eid)`. Returns 0 if the
/// extension is absent, non-zero if present. Used by R-5.b to decide
/// whether to use SBI-IPI-based TLB shootdown or a fallback.
const SBI_EXT_BASE: u64 = 0x10;
const SBI_BASE_PROBE_EXTENSION: u64 = 3;

/// Start a secondary hart at a physical address.
///
/// On success the target hart leaves its M-mode-parked state, runs
/// OpenSBI's HSM handoff code, and enters S-mode at `start_addr` with
/// `a0 = hart_id`, `a1 = opaque`, paging off, SIE masked. It is the
/// caller's responsibility to install a boot stub at `start_addr`
/// that sets up a stack, enables paging (same boot root as the BSP
/// or a per-AP root), and proceeds to per-hart Rust init.
///
/// Returns the SBI error code (0 on success). Non-fatal — the caller
/// logs and continues if a hart refuses to start.
///
/// # Safety
/// Must be called from S-mode. The `start_addr` must be a valid
/// physical address with executable code and `opaque` must be
/// meaningful to that code.
#[inline]
pub unsafe fn sbi_hart_start(hart_id: u64, start_addr_phys: u64, opaque: u64) -> i64 {
    let err: i64;
    // SAFETY: ecall to M-mode is always legal from S-mode. The SBI
    // call doesn't touch the S-mode stack. Clobber list covers the
    // ABI-visible registers the call may modify.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SBI_EXT_HSM,
            in("a6") SBI_HSM_HART_START,
            in("a0") hart_id,
            in("a1") start_addr_phys,
            in("a2") opaque,
            lateout("a0") err,
            lateout("a1") _,
            options(nostack),
        );
    }
    err
}

/// Probe whether an SBI extension is present.
///
/// Returns 0 if absent, non-zero if the M-mode firmware implements
/// the extension. R-5.b uses this for Svinval / TIME v2 detection.
#[inline]
pub fn sbi_probe_extension(eid: u64) -> i64 {
    let value: i64;
    // SAFETY: pure ecall, no stack access.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SBI_EXT_BASE,
            in("a6") SBI_BASE_PROBE_EXTENSION,
            in("a0") eid,
            lateout("a0") _,
            lateout("a1") value,
            options(nostack),
        );
    }
    value
}

// ============================================================================
// IPI extension (SBI v0.2+, EID "sPI" = 0x735049)
// ============================================================================
//
// `send_ipi(hart_mask, hart_mask_base)` signals SSIP on every hart
// whose bit is set in the mask. `hart_mask_base` shifts the mask —
// bit N of hart_mask means hart `hart_mask_base + N`. A value of
// `u64::MAX` for `hart_mask_base` broadcasts to *all* harts.
//
// Used by R-5.b's remote TLB shootdown: initiator sets the
// shootdown payload, calls `sbi_send_ipi(targets, 0)`, each target
// hart's trap vector catches the S-mode software interrupt and
// drains the payload via `sfence.vma`.

/// SBI IPI extension ID ("sPI" = 0x735049).
const SBI_EXT_IPI: u64 = 0x735049;
/// IPI function: send_ipi.
const SBI_IPI_SEND_IPI: u64 = 0;

/// Assert `sip.SSIP` on every hart whose bit is set in
/// `hart_mask << hart_mask_base`. Returns the SBI error code (0 on
/// success; typically 0 even when some harts in the mask are stopped
/// or nonexistent — the firmware silently skips them).
///
/// # Safety
/// Must be called from S-mode. Targets will take a trap on the
/// S-mode software interrupt vector (`scause` = `1 << 63 | 1`); the
/// caller is responsible for ensuring those harts have
/// [`sstatus.SIE`] + `sie.SSIE` enabled and a handler ready to
/// consume the shootdown payload.
#[inline]
pub unsafe fn sbi_send_ipi(hart_mask: u64, hart_mask_base: u64) -> i64 {
    let err: i64;
    // SAFETY: ecall to M-mode is always legal from S-mode.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SBI_EXT_IPI,
            in("a6") SBI_IPI_SEND_IPI,
            in("a0") hart_mask,
            in("a1") hart_mask_base,
            lateout("a0") err,
            lateout("a1") _,
            options(nostack),
        );
    }
    err
}

/// Convenience: SBI IPI extension ID (exported so `tlb::init` can
/// probe it at boot and fall back gracefully if absent).
pub const IPI_EXTENSION_ID: u64 = SBI_EXT_IPI;
