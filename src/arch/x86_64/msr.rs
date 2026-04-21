// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Model-Specific Register (MSR) access for x86_64
//!
//! Provides a single shared implementation of `rdmsr`/`wrmsr` to replace
//! the three copies previously duplicated across `apic.rs`, `percpu.rs`,
//! and `syscall.rs`.
//!
//! # Safety model
//! Reading/writing an MSR is inherently privileged (ring 0) and the MSR
//! index must be valid. The unsafe boundary is at `read()` and `write()`.

/// Read a Model-Specific Register.
///
/// # Safety
/// - Must be called at ring 0 (kernel mode).
/// - `msr` must be a valid MSR index for this CPU.
#[inline(always)]
pub unsafe fn read(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: Caller guarantees ring 0 and valid MSR index.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Write a Model-Specific Register.
///
/// # Safety
/// - Must be called at ring 0 (kernel mode).
/// - `msr` must be a valid MSR index for this CPU.
/// - `value` must be appropriate for the target MSR.
#[inline(always)]
pub unsafe fn write(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    // SAFETY: Caller guarantees ring 0, valid MSR index, and appropriate value.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
}
