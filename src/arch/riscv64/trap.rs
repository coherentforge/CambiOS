// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! RISC-V S-mode trap vector.
//!
//! Single entry point for all exceptions and interrupts, installed at
//! `stvec` with MODE=0 (direct). `scause` distinguishes what happened.
//!
//! ## Phase R-3.b+c scope: kernel-mode entry only
//!
//! This first landing handles traps **from S-mode only** — the timer
//! interrupt firing while the kernel idle-loops in `wfi`. That is the
//! only trap source in the current milestone (no user code until R-4,
//! no PLIC-routed device IRQs until R-3.d). Because every trap here
//! comes from the kernel, we skip the `sscratch`/`tp` swap dance that
//! U-mode entry requires — `tp` is already the kernel per-CPU pointer,
//! `sp` is already the kernel stack.
//!
//! When Phase R-4 lands user code, this vector grows a front-end that:
//!   1. Tests `sstatus.SPP` (bit 8) to detect U→S entry.
//!   2. Swaps `tp` with `sscratch` on U→S to get the kernel per-CPU ptr.
//!   3. Loads kernel `sp` from `tp + PerCpu::kernel_stack_top_offset`.
//!   4. Reverses the swap on S→U return.
//!
//! The body below never touches `sscratch` and never assumes a swap has
//! happened. That means until R-4 extends it, a trap from U-mode would
//! corrupt the kernel stack — so until the R-4 front-end is in, nothing
//! may enter U-mode. The kernel stays in S-mode end-to-end.
//!
//! ## Trap frame layout
//!
//! Matches [`super::SavedContext`] exactly:
//!
//! ```text
//!   0..256  gpr[0..32]   (x0 slot unused; saved order follows index)
//! 256..264  sepc
//! 264..272  sstatus
//! ```
//!
//! Allocated as 288 bytes on the stack (272 rounded to 16-byte align)
//! per [`super::ISR_FRAME_SIZE`].
//!
//! ## Why naked assembly?
//!
//! The first instruction must save a register or use a register before
//! clobbering it. Any Rust function prologue allocates stack / saves
//! callee-saved regs — it clobbers registers we haven't saved yet.
//! `global_asm!` gives us a pure-asm entry point we can point `stvec`
//! at directly. The Rust handler is called from the asm with a fully
//! populated [`super::SavedContext`] on the kernel stack.

use super::SavedContext;

// ============================================================================
// Trap vector assembly — single kernel-mode entry
// ============================================================================

// Exported symbol: `_riscv_trap_vector`.
//
// Path: allocate 288B trap frame on current sp, save x1 + x3..x31 at
// their natural offsets (x0 is hardwired zero; skipped), compute and
// save original sp, capture sepc + sstatus, call rust_trap_handler,
// then restore everything (including sp last) and sret.
core::arch::global_asm!(
    r#"
    .section .text.trap
    .globl _riscv_trap_vector
    .align 4
_riscv_trap_vector:
    // Allocate SavedContext (288 bytes, 16-byte aligned).
    addi sp, sp, -288

    // Save x1 (ra) and x3..x31 at their natural offsets.
    // x0 is hardwired zero; its slot at offset 0 is never touched.
    // x2 (sp) is handled specially below (we need its pre-trap value).
    sd x1,   8(sp)
    sd x3,  24(sp)
    sd x4,  32(sp)
    sd x5,  40(sp)
    sd x6,  48(sp)
    sd x7,  56(sp)
    sd x8,  64(sp)
    sd x9,  72(sp)
    sd x10, 80(sp)
    sd x11, 88(sp)
    sd x12, 96(sp)
    sd x13, 104(sp)
    sd x14, 112(sp)
    sd x15, 120(sp)
    sd x16, 128(sp)
    sd x17, 136(sp)
    sd x18, 144(sp)
    sd x19, 152(sp)
    sd x20, 160(sp)
    sd x21, 168(sp)
    sd x22, 176(sp)
    sd x23, 184(sp)
    sd x24, 192(sp)
    sd x25, 200(sp)
    sd x26, 208(sp)
    sd x27, 216(sp)
    sd x28, 224(sp)
    sd x29, 232(sp)
    sd x30, 240(sp)
    sd x31, 248(sp)

    // Save pre-trap sp at gpr[2] offset (= current sp + 288).
    // t0 (x5) was just saved, so we can freely use it.
    addi t0, sp, 288
    sd t0, 16(sp)

    // Capture sepc + sstatus.
    csrr t0, sepc
    sd t0, 256(sp)
    csrr t0, sstatus
    sd t0, 264(sp)

    // Call _riscv_rust_trap_handler(saved_ctx, scause, stval).
    // a0 = &SavedContext (current sp).
    // a1 = scause, a2 = stval.
    // The handler may mutate the frame (for future ERET changes).
    mv   a0, sp
    csrr a1, scause
    csrr a2, stval
    call _riscv_rust_trap_handler

    // Restore sepc + sstatus first (they may have been updated by the
    // handler to redirect the return).
    ld t0, 264(sp)
    csrw sstatus, t0
    ld t0, 256(sp)
    csrw sepc, t0

    // Restore x1 + x3..x31. Skip x2 (sp); we restore it last.
    ld x1,   8(sp)
    ld x3,  24(sp)
    ld x4,  32(sp)
    ld x5,  40(sp)
    ld x6,  48(sp)
    ld x7,  56(sp)
    ld x8,  64(sp)
    ld x9,  72(sp)
    ld x10, 80(sp)
    ld x11, 88(sp)
    ld x12, 96(sp)
    ld x13, 104(sp)
    ld x14, 112(sp)
    ld x15, 120(sp)
    ld x16, 128(sp)
    ld x17, 136(sp)
    ld x18, 144(sp)
    ld x19, 152(sp)
    ld x20, 160(sp)
    ld x21, 168(sp)
    ld x22, 176(sp)
    ld x23, 184(sp)
    ld x24, 192(sp)
    ld x25, 200(sp)
    ld x26, 208(sp)
    ld x27, 216(sp)
    ld x28, 224(sp)
    ld x29, 232(sp)
    ld x30, 240(sp)
    ld x31, 248(sp)

    // Restore sp last: loads the saved pre-trap sp from 16(sp), which
    // equals (current sp + 288), effectively deallocating the frame.
    ld sp, 16(sp)

    sret
    "#
);

// ============================================================================
// Rust trap handler
// ============================================================================

/// Scause bit 63 — set for interrupts, clear for synchronous exceptions.
const SCAUSE_INTERRUPT: u64 = 1 << 63;

/// Mask for the cause code (low 63 bits of scause).
const SCAUSE_CODE_MASK: u64 = (1 << 63) - 1;

/// Interrupt cause code — supervisor timer.
const IRQ_TIMER: u64 = 5;

/// Interrupt cause code — supervisor external (PLIC, wired in R-3.d).
const IRQ_EXTERNAL: u64 = 9;

/// Interrupt cause code — supervisor software (IPI, wired in R-5).
const IRQ_SOFTWARE: u64 = 1;

/// Rust-level trap dispatcher. Called from `_riscv_trap_vector` with a
/// populated [`SavedContext`] on the kernel stack.
///
/// The symbol name is RISC-V-prefixed to keep it out of collision
/// range if another arch backend later defines its own
/// `rust_trap_handler`. The asm `call` in the vector matches.
///
/// # Safety
/// - Only the trap vector may call this. The assembly guarantees
///   `saved` points to a live SavedContext, `scause` and `stval` are
///   the CSR values read at trap entry.
/// - Interrupts are masked on S-mode trap entry (sstatus.SIE is
///   cleared by hardware on entry; restored from SPIE on sret).
#[no_mangle]
pub unsafe extern "C" fn _riscv_rust_trap_handler(
    saved: *mut SavedContext,
    scause: u64,
    stval: u64,
) {
    let is_interrupt = scause & SCAUSE_INTERRUPT != 0;
    let code = scause & SCAUSE_CODE_MASK;

    if is_interrupt {
        match code {
            IRQ_TIMER => {
                // Clear the pending bit by re-arming; SBI's set_timer
                // implicitly clears STIP once the deadline moves past
                // the current `time`.
                //
                // SAFETY: sbi::sbi_set_timer is safe to call from
                // S-mode with interrupts masked (we're in an ISR).
                unsafe { super::timer::on_timer_interrupt(); }
            }
            IRQ_EXTERNAL => {
                // PLIC-routed device IRQ. `dispatch_pending` drains
                // every pending source: claim → router lookup (or
                // R-3.d inline UART fallback) → complete.
                //
                // SAFETY: trap handler runs with interrupts masked;
                // the PLIC driver is safe to call from ISR context
                // (its only lock — `crate::INTERRUPT_ROUTER` — is
                // acquired via try_lock).
                let _ = stval; // stval is zero for external IRQs.
                unsafe { super::plic::dispatch_pending(); }
            }
            IRQ_SOFTWARE => {
                // IPI. R-5 will handle cross-hart wake / TLB shootdown.
                panic!("riscv64: S-mode software interrupt (IPI) not wired until R-5");
            }
            other => panic!("riscv64: unexpected S-mode interrupt cause={}", other),
        }
    } else {
        // Synchronous exception. Everything listed below is a kernel
        // bug at this stage (R-3.b+c milestone): user code isn't
        // running yet, so ECALL-from-U is impossible, and any page
        // fault or illegal instruction signals a kernel problem.
        // SAFETY: `saved` was populated by the trap vector before
        // this function was called; the pointer is valid for the
        // duration of the handler and the memory is not aliased.
        let sepc = unsafe { (*saved).sepc };
        match code {
            0 => panic!("riscv64 fault: instruction address misaligned @ sepc={:#x}", sepc),
            1 => panic!("riscv64 fault: instruction access fault @ sepc={:#x}", sepc),
            2 => panic!("riscv64 fault: illegal instruction @ sepc={:#x} stval={:#x}", sepc, stval),
            3 => panic!("riscv64 fault: breakpoint @ sepc={:#x}", sepc),
            4 => panic!("riscv64 fault: load address misaligned @ sepc={:#x} stval={:#x}", sepc, stval),
            5 => panic!("riscv64 fault: load access fault @ sepc={:#x} stval={:#x}", sepc, stval),
            6 => panic!("riscv64 fault: store/AMO address misaligned @ sepc={:#x} stval={:#x}", sepc, stval),
            7 => panic!("riscv64 fault: store/AMO access fault @ sepc={:#x} stval={:#x}", sepc, stval),
            8 => panic!("riscv64 fault: ECALL from U-mode — user syscalls not wired until R-4"),
            9 => panic!("riscv64 fault: ECALL from S-mode — kernel ecalls must go through sbi wrappers"),
            12 => panic!("riscv64 fault: instruction page fault @ sepc={:#x} stval={:#x}", sepc, stval),
            13 => panic!("riscv64 fault: load page fault @ sepc={:#x} stval={:#x}", sepc, stval),
            15 => panic!("riscv64 fault: store/AMO page fault @ sepc={:#x} stval={:#x}", sepc, stval),
            other => panic!("riscv64 fault: unknown exception code {} @ sepc={:#x} stval={:#x}", other, sepc, stval),
        }
    }
}

// ============================================================================
// Install / uninstall
// ============================================================================

extern "C" {
    /// Address of the trap vector defined in global_asm above.
    static _riscv_trap_vector: u8;
}

/// Install the S-mode trap vector by writing its address to `stvec`
/// with MODE = 0 (direct dispatch — the single vector handles all
/// causes; unlike MODE=1 Vectored which would bank interrupts by cause).
///
/// # Safety
/// Must be called during early boot with SIE = 0 in sstatus. After
/// this returns, traps may land on our handler; the caller must ensure
/// the per-hart state the handler reads (kernel stack under sp, no
/// user code yet) is coherent before enabling interrupts.
pub unsafe fn install() {
    // Take the address of the linker symbol. Cast through *const u8
    // to avoid a "reference to extern static" warning.
    let addr = (&raw const _riscv_trap_vector) as u64;
    // MODE bits [1:0] must be 0 (direct). The address is 4-byte
    // aligned by construction (global_asm `.align 4`).
    debug_assert_eq!(addr & 0b11, 0, "riscv64: stvec base must be 4-byte aligned");

    // SAFETY: csrw stvec from S-mode is always legal. The written
    // value is a valid kernel VA pointing at our vector.
    unsafe {
        core::arch::asm!(
            "csrw stvec, {0}",
            in(reg) addr,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Enable S-mode interrupts globally by setting `sstatus.SIE`.
///
/// The timer enable bit (`sie.STIE`) and external-interrupt enable
/// bit (`sie.SEIE`) are set separately by the timer and PLIC drivers.
///
/// # Safety
/// Must be called after `install()` has written `stvec`, and after all
/// per-hart state the trap handler reads is initialized. Calling this
/// before the per-CPU data is set up would leave the handler reading
/// stale / null values on the first tick.
pub unsafe fn enable_interrupts() {
    // Set SSTATUS.SIE (bit 1).
    // SAFETY: csrs is a read-modify-write CSR op; legal from S-mode.
    unsafe {
        core::arch::asm!(
            "csrs sstatus, {0}",
            in(reg) 1u64 << 1,
            options(nostack, nomem, preserves_flags),
        );
    }
}
