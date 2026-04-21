// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Syscall entry — AArch64
//!
//! AArch64 uses the SVC instruction (Supervisor Call) for syscalls, which
//! triggers a synchronous exception routed through VBAR_EL1. The exception
//! handler reads ESR_EL1 to verify the SVC class (EC=0b010101), extracts
//! arguments from x0-x5, and dispatches to the kernel syscall handler.
//!
//! ## Register convention (Linux-compatible)
//! | Register | Purpose        |
//! |----------|----------------|
//! | x8       | Syscall number |
//! | x0-x5    | Arguments      |
//! | x0       | Return value   |
//!
//! ## Exception vector routing
//! SVC from EL0 lands in VBAR_EL1 + 0x400 (Lower EL, AArch64, Synchronous).
//! The vector table is defined in `mod.rs`; this module provides the init
//! function that installs it.

/// Install the exception vector table at VBAR_EL1.
///
/// The vector table (`exception_vector_table`) is defined in `mod.rs`
/// via `global_asm!`. This function writes its address to VBAR_EL1.
///
/// # Safety
/// Must be called during boot with interrupts masked (DAIF.I set).
/// The exception_vector_table symbol must be properly aligned (2048 bytes)
/// and contain valid exception vectors.
pub unsafe fn init() {
    extern "C" {
        // Defined in src/arch/aarch64/mod.rs via global_asm!
        static exception_vector_table: u8;
    }

    // SAFETY: exception_vector_table is a properly aligned (.balign 2048)
    // static symbol defined in mod.rs via global_asm!. Writing VBAR_EL1
    // from EL1 during boot is safe.
    unsafe {
        let vbar = &exception_vector_table as *const u8 as u64;

        core::arch::asm!(
            "msr vbar_el1, {0}",
            "isb",
            in(reg) vbar,
            options(nostack),
        );
    }
}
