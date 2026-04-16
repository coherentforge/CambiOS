// Copyright (C) 2024-2026 Jason Ricca - All rights reserved.

//! Syscall entry — RISC-V (S-mode)
//!
//! Unlike x86_64 (SYSCALL/SYSRET + LSTAR MSR) and AArch64 (SVC +
//! VBAR_EL1), RISC-V has a single trap entry point configured via
//! `stvec`. All synchronous exceptions and interrupts route through
//! it; `scause` distinguishes them.
//!
//! A syscall from U-mode is an `ecall` instruction, which traps into
//! S-mode with `scause == 8` ("Environment call from U-mode"). Arg
//! registers (Linux RISC-V ABI): `a7 = syscall number`, `a0..a5 =
//! arguments`, `a0 = return value`.
//!
//! The actual dispatch code lives in `mod.rs` as part of the trap
//! handler; this module provides the initialization routine that
//! installs the vector at `stvec`.
//!
//! ## Phase R-1
//!
//! `init()` is currently a no-op. In Phase R-3 it will write `stvec`
//! with the address of the trap handler defined in `mod.rs`.

/// Install the S-mode trap vector (Phase R-3).
///
/// # Safety
/// Must be called during early boot with interrupts masked (SIE=0 in
/// sstatus) and after the trap handler is loaded at its link-time
/// address.
pub unsafe fn init() {
    // Phase R-3 will write the trap handler address to `stvec`:
    //
    //   extern "C" { static trap_vector: u8; }
    //   let addr = &trap_vector as *const u8 as u64;
    //   core::arch::asm!("csrw stvec, {0}", in(reg) addr, options(nostack));
    //
    // MODE field (low 2 bits) = 0 (direct — single-entry dispatch).
    //
    // Until Phase R-3 the kernel's trap surface is empty; taking an
    // unexpected trap during Phase R-1 boot puts the hart into a
    // tight loop at stvec==0 which QEMU reports clearly in its trace.
}
