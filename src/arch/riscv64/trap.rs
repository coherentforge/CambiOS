// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! RISC-V S-mode trap vector.
//!
//! Single entry point for all exceptions and interrupts, installed at
//! `stvec` with MODE=0 (direct). `scause` distinguishes what happened.
//!
//! ## Phase R-4.a scope: U↔S-capable vector
//!
//! Handles traps from both S-mode (kernel preemption, kernel-side
//! breakpoints) and U-mode (`ecall` syscalls, page faults from user
//! code, device IRQs arriving while user runs). The split is driven
//! by the `sscratch` ↔ `tp` swap convention:
//!
//! - While the kernel executes: `tp` = kernel PerCpu pointer,
//!   `sscratch` = 0 (sentinel).
//! - While user executes: `tp` = user's thread pointer,
//!   `sscratch` = kernel PerCpu pointer (pre-set on the sret-to-U
//!   return path).
//!
//! Entry sequence: `csrrw tp, sscratch, tp` atomically swaps the two.
//! If the *new* `tp` is non-zero, we came from user (we now hold the
//! kernel PerCpu); otherwise we came from kernel and swap back.
//!
//! On U→S entry the vector additionally:
//!   1. Stashes the user `sp` into `PerCpu.user_sp_scratch` (offset 40).
//!   2. Loads the kernel stack from `PerCpu.kernel_stack_top` (off 24).
//!   3. Saves the user's original `tp` (now in `sscratch`) into the
//!      SavedContext's gpr[4] slot.
//!   4. Saves the user's `sp` (from the PerCpu scratch slot) into gpr[2].
//!
//! On S→U return the vector additionally:
//!   1. Sets `sscratch` back to the kernel PerCpu pointer so the next
//!      U→S trap picks up the swap.
//!   2. Restores the user's `tp` from the SavedContext.
//!
//! S→S (kernel preempted by kernel-mode timer) behaves identically to
//! R-3's original kernel-only vector: no PerCpu reads, no sscratch
//! writes beyond the initial swap/swap-back pair, the full frame is
//! allocated on the *current* sp.
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
// Entry:
//   csrrw tp, sscratch, tp     — atomic swap
//   if new tp != 0 → from U-mode (tp now = kernel PerCpu)
//   if new tp == 0 → from S-mode (sscratch now holds kernel PerCpu; swap back)
//
// Both paths converge on the save/dispatch tail after laying the
// 288-byte SavedContext on the kernel sp, with gpr[2]=sp and
// gpr[4]=tp filled from the correct source (original kernel values
// on S-entry, PerCpu scratch + sscratch on U-entry).
//
// Exit: branches on the NEW sstatus.SPP — SPP=1 restores for sret to
// S; SPP=0 writes sscratch = kernel_tp (so the next U→S trap's swap
// lands tp = kernel PerCpu) and restores including tp/sp from the
// user-valued frame.
core::arch::global_asm!(
    r#"
    .section .text.trap
    .globl _riscv_trap_vector
    .align 4
_riscv_trap_vector:
    // === Entry: swap tp ↔ sscratch, branch on origin ===
    csrrw tp, sscratch, tp
    bnez tp, 10f                    // tp != 0 → came from U-mode

    // From S-mode: pre-trap sscratch was 0 (kernel invariant), so the
    // swap put tp=0 and sscratch=kernel_tp. Restore via a second swap.
    csrrw tp, sscratch, tp          // tp = kernel_tp, sscratch = 0
    addi sp, sp, -288               // allocate SavedContext on kernel sp
    sd x1,   8(sp)
    sd x3,  24(sp)
    sd x4,  32(sp)                  // tp (kernel_tp; matches running kernel)
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
    addi t0, sp, 288                // pre-trap kernel sp
    sd t0, 16(sp)                   // gpr[2] = pre-trap sp
    j 20f

10:
    // From U-mode: post-swap tp = kernel PerCpu, sscratch = user_tp.
    // Stash user sp, load kernel stack, allocate frame.
    sd sp, 40(tp)                   // PerCpu.user_sp_scratch = user_sp
    ld sp, 24(tp)                   // sp = PerCpu.kernel_stack_top
    addi sp, sp, -288
    sd x1,   8(sp)
    sd x3,  24(sp)
    // x4 (tp) is currently kernel_tp; the user's tp is in sscratch.
    // Skip `sd x4` here — gpr[4] is written from sscratch below so
    // the frame carries user_tp for the sret-to-U restore path.
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
    ld t0, 40(tp)                   // t0 = user_sp (from PerCpu scratch)
    sd t0, 16(sp)                   // gpr[2] = user_sp
    csrr t0, sscratch               // t0 = user_tp
    sd t0, 32(sp)                   // gpr[4] = user_tp

20:
    // === Shared: save sepc + sstatus, dispatch ===
    csrr t0, sepc
    sd t0, 256(sp)
    csrr t0, sstatus
    sd t0, 264(sp)

    mv   a0, sp
    csrr a1, scause
    csrr a2, stval
    call _riscv_rust_trap_handler
    mv   sp, a0                     // handler may have swapped frames

    // Restore sepc + sstatus first.
    ld t0, 264(sp)
    csrw sstatus, t0
    ld t1, 256(sp)
    csrw sepc, t1

    // Branch on the NEW sstatus.SPP (bit 8) for return mode.
    andi t1, t0, 0x100
    beqz t1, 30f                    // SPP == 0 → return to U-mode

    // === Restore for sret to S-mode ===
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
    ld sp, 16(sp)
    sret

30:
    // === Restore for sret to U-mode ===
    // Current tp = kernel_tp (handler didn't touch it); stash it in
    // sscratch so the NEXT U→S trap's swap drops kernel_tp into tp.
    csrw sscratch, tp
    ld x1,   8(sp)
    ld x3,  24(sp)
    ld x4,  32(sp)                  // tp = user_tp (from frame)
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
    ld sp, 16(sp)                   // sp = user_sp (from frame)
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
/// ## Return value
///
/// Returns the SavedContext pointer (as a `u64`) the trap vector
/// should restore from. For synchronous exceptions and non-switching
/// interrupt ticks this is always the input `saved`. For a preempting
/// timer tick it's the *next* task's SavedContext — the scheduler
/// returned a different stack pointer via [`timer_isr_inner`] and we
/// propagate it all the way back to the asm's `mv sp, a0; sret` pair.
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
) -> u64 {
    let is_interrupt = scause & SCAUSE_INTERRUPT != 0;
    let code = scause & SCAUSE_CODE_MASK;

    if is_interrupt {
        match code {
            IRQ_TIMER => {
                // Rearm the timer and run the portable scheduler's
                // tick. Returns the SavedContext pointer to restore
                // from (same as input for non-switching ticks, a
                // different stack for preemptive context switch).
                // ISR context with interrupts masked; the handler
                // rearms SBI and acquires scheduler locks via
                // try_lock per the portable contract.
                return super::timer_isr_inner(saved as u64);
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
                // R-5.b: SBI-delivered S-mode software interrupt.
                // Currently the only producer is `tlb::broadcast_
                // shootdown` on other harts — drain the payload +
                // clear sip.SSIP + ACK.
                //
                // SAFETY: ISR context; `handle_ipi` runs the sfence
                // and atomic counter update the initiator is
                // waiting on. Further IPI uses (cross-hart wake
                // for scheduler load-balancing) would land here in
                // additional arms, discriminated by a payload tag.
                unsafe { super::tlb::handle_ipi(); }
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
            8 => {
                // ECALL from U-mode — the R-4 syscall entry point.
                // The Rust-side handler extracts a7/a0..a5 from the
                // SavedContext, dispatches, writes the return value
                // back to a0, and bumps sepc past the 4-byte ecall
                // so sret resumes at the next user instruction.
                // SAFETY: ISR context; `saved` was populated by the
                // trap vector's U→S entry path.
                return unsafe { super::syscall::ecall_handler_inner(saved as u64) };
            }
            9 => panic!("riscv64 fault: ECALL from S-mode — kernel ecalls must go through sbi wrappers"),
            12 => panic!("riscv64 fault: instruction page fault @ sepc={:#x} stval={:#x}", sepc, stval),
            13 => panic!("riscv64 fault: load page fault @ sepc={:#x} stval={:#x}", sepc, stval),
            15 => panic!("riscv64 fault: store/AMO page fault @ sepc={:#x} stval={:#x}", sepc, stval),
            other => panic!("riscv64 fault: unknown exception code {} @ sepc={:#x} stval={:#x}", other, sepc, stval),
        }
    }

    // External IRQs fall through to here after `dispatch_pending` —
    // no context swap, restore from the same frame we arrived on.
    // (Every exception arm panics; the IRQ_TIMER arm returned early.)
    saved as u64
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
    // Enable sie.SSIE (bit 1) alongside SIE so the hart takes SBI
    // IPIs. Per-source enables for timer (sie.STIE) and external
    // (sie.SEIE) are set by `timer::init` and `plic::init`
    // respectively; SSIE lives here because it's the generic
    // "cross-hart wake / TLB shootdown" enable and not tied to a
    // specific driver. `sie.SSIE` = bit 1.
    // SAFETY: csrs is a read-modify-write CSR op; legal from S-mode.
    unsafe {
        core::arch::asm!(
            "csrs sie, {0}",
            "csrs sstatus, {1}",
            in(reg) 1u64 << 1,              // sie.SSIE
            in(reg) 1u64 << 1,              // sstatus.SIE
            options(nostack, nomem, preserves_flags),
        );
    }
}
