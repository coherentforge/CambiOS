// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! RISC-V S-mode trap vector.
//!
//! Single entry point for all exceptions and interrupts, installed at
//! `stvec` with MODE=0 (direct). `scause` distinguishes what happened.
//!
//! ## U↔S-capable vector scope
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
//!   2. Moves the user's `tp` out of `sscratch` and writes the sentinel 0
//!      back, in one instruction (`csrrw sp, sscratch, zero`), then parks
//!      it in `PerCpu.user_tp_scratch` (offset 48). Before the swap only
//!      step 1's store runs; a trap there would re-enter with the
//!      program's `tp` as its anchor (ADR-040 § 9).
//!   3. Loads the kernel stack from `PerCpu.kernel_stack_top` (off 24).
//!   4. Copies the user's `sp` and `tp` from the PerCpu scratch slots into
//!      the SavedContext's gpr[2] and gpr[4].
//!
//! Both branches tell the Rust handler which one ran; the handler checks
//! it against the frame's captured `sstatus.SPP`, which the hardware
//! wrote at the trap, and halts with a typed report if the two disagree
//! (`entry_branch::check`).
//!
//! On S→U return the vector additionally:
//!   1. Sets `sscratch` back to the kernel PerCpu pointer so the next
//!      U→S trap picks up the swap.
//!   2. Restores the user's `tp` from the SavedContext.
//!
//! S→S (kernel preempted by kernel-mode timer) behaves identically to
//! R-3's original kernel-only vector: no PerCpu reads, no sscratch
//! writes beyond the initial swap/swap-back pair, the full frame is
//! allocated on the *current* sp. The frame's gpr[4] is saved but never
//! restored: the S-mode exit keeps `tp` as it is, this hart's `PerCpu`,
//! so a kernel context resumed on another hart (a migrated task) does
//! not bring the saving hart's pointer with it (ADR-040 § 9).
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
use crate::arch::riscv64_entry_branch::{self as entry_branch, EntryBranch};

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
    li a3, 0                        // entry branch: supervisor (x13 saved above)
    j 20f

10:
    // From U-mode: post-swap tp = this hart's PerCpu, sscratch = the
    // program's tp. Until the csrrw below, a trap would re-enter here with
    // the program's tp as its anchor, so one store through tp is all that
    // runs first (ADR-040 § 9).
    sd sp, 40(tp)                   // PerCpu.user_sp_scratch = user_sp
    csrrw sp, sscratch, zero        // sp = user_tp, sscratch = 0 (sentinel)
    // A trap from here on takes the S-mode branch. sp holds the program's
    // tp until the load below, so both instructions address only through tp.
    sd sp, 48(tp)                   // PerCpu.user_tp_scratch = user_tp
    ld sp, 24(tp)                   // sp = PerCpu.kernel_stack_top
    addi sp, sp, -288
    sd x1,   8(sp)
    sd x3,  24(sp)
    // x4 (tp) is currently kernel_tp; the user's tp is in
    // PerCpu.user_tp_scratch. Skip `sd x4` here: gpr[4] is written from
    // that slot below so the frame carries user_tp for the sret-to-U path.
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
    ld t0, 48(tp)                   // t0 = user_tp (from PerCpu scratch)
    sd t0, 32(sp)                   // gpr[4] = user_tp
    li a3, 1                        // entry branch: user (x13 saved above)

20:
    // === Shared: save sepc + sstatus, dispatch ===
    csrr t0, sepc
    sd t0, 256(sp)
    csrr t0, sstatus
    sd t0, 264(sp)

    mv   a0, sp
    csrr a1, scause
    csrr a2, stval
    // a3 = the entry branch, set by each branch above
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
    // tp is not loaded from the frame: it already holds this hart's
    // PerCpu, and the frame's copy is the hart the context was saved on
    // (ADR-040 § 9).
    ld x1,   8(sp)
    ld x3,  24(sp)
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

/// HARDWARE: `scause` bit 63, set for interrupts, clear for synchronous
/// exceptions (riscv-privileged, "Supervisor Cause Register").
const SCAUSE_INTERRUPT: u64 = 1 << 63;

/// HARDWARE: the cause code, the low 63 bits of `scause` (same register).
const SCAUSE_CODE_MASK: u64 = (1 << 63) - 1;

/// HARDWARE: interrupt cause code 5, supervisor timer (riscv-privileged,
/// `scause` interrupt codes).
const IRQ_TIMER: u64 = 5;

/// HARDWARE: interrupt cause code 9, supervisor external (the PLIC).
const IRQ_EXTERNAL: u64 = 9;

/// HARDWARE: interrupt cause code 1, supervisor software (the IPI).
const IRQ_SOFTWARE: u64 = 1;

// ============================================================================
// TrapError — typed boundary for unrecoverable S-mode traps
// ============================================================================

/// Classes of S-mode trap the dispatcher can hit but can't recover from.
///
/// Per `riscv-privileged` § "Supervisor Cause Register" — synchronous
/// exception codes (`scause` low bits, `INTERRUPT` bit clear) plus the
/// "interrupt arrived with an unexpected cause code" tail. Each variant
/// carries the SEPC + STVAL captured at trap entry so [`report_and_halt`]
/// can produce a structured fault dump without re-reading the CSRs.
///
/// Replaces the `panic!()` chain that used to live in
/// [`_riscv_rust_trap_handler`]. CLAUDE.md's no-panic-in-kernel rule
/// applies here even though the terminal action is identical (print +
/// halt) — a typed boundary lets a future audit hook, host-style test
/// harness, or per-process kill-rather-than-halt path attach without
/// touching every fault arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapError {
    InstructionMisaligned { sepc: u64 },
    InstructionAccessFault { sepc: u64 },
    IllegalInstruction { sepc: u64, stval: u64 },
    Breakpoint { sepc: u64 },
    LoadMisaligned { sepc: u64, stval: u64 },
    LoadAccessFault { sepc: u64, stval: u64 },
    StoreMisaligned { sepc: u64, stval: u64 },
    StoreAccessFault { sepc: u64, stval: u64 },
    /// `ECALL` from S-mode — kernel ecalls must go through the `sbi::*`
    /// wrappers, never raw `ecall` in Rust code. If we see this it's
    /// almost certainly a bug in a wrapper or hand-rolled assembly.
    SModeEcall { sepc: u64 },
    InstructionPageFault { sepc: u64, stval: u64 },
    LoadPageFault { sepc: u64, stval: u64 },
    StorePageFault { sepc: u64, stval: u64 },
    /// Synchronous exception with a `scause` code we don't model
    /// (reserved or future RISC-V revision). Carries the raw code so the
    /// fault dump can name it even though we have no structural handler.
    UnknownException { code: u64, sepc: u64, stval: u64 },
    /// Interrupt with a cause code we don't model (the IRQ_TIMER /
    /// IRQ_EXTERNAL / IRQ_SOFTWARE arms above didn't claim it). Code is
    /// the low 63 bits of `scause`.
    UnexpectedInterrupt { code: u64 },
    /// The trap vector's `sscratch` test and `sstatus.SPP` disagree about
    /// which mode the trap came from (ADR-040 § 9), so the frame was
    /// built from the wrong per-CPU anchor and nothing in it is trusted.
    /// `branch` is what the vector reported (`None`: a value it never
    /// passes), `origin` what SPP says.
    EntryBranchMismatch {
        branch: Option<EntryBranch>,
        origin: EntryBranch,
        sstatus: u64,
        sepc: u64,
    },
}

/// Map a U-mode `scause` code onto the portable fault vocabulary
/// (ADR-019 § Decision 2). Page faults (12/13/15) and illegal
/// instruction (2) have common-set names; access faults, misaligned
/// accesses, breakpoints and reserved codes keep their raw code.
pub(super) fn user_fault_kind(code: u64) -> crate::reap::FaultKind {
    match code {
        12 | 13 | 15 => crate::reap::FaultKind::PageFault,
        2 => crate::reap::FaultKind::InvalidOpcode,
        other => crate::reap::FaultKind::ArchSpecific(other as u8),
    }
}

/// Reap the current task for a U-mode fault and never return (ADR-019
/// § Decision 6). We are on the hart's kernel stack (the trap vector
/// swapped `tp`/`sp` on U→S entry) with the full frame saved, so
/// re-enabling S-mode interrupts here is the same posture the ecall
/// path takes — and it is required: the reap spins on cross-hart
/// TLB-shootdown IPIs that a masked hart could neither send nor answer.
/// `sepc`/`stval` were captured at entry, before any nested trap.
fn reap_user_fault(code: u64, sepc: u64, stval: u64) -> ! {
    let kind = user_fault_kind(code);
    crate::println!(
        "  [Fault] U-mode scause={} {:?} stval={:#x} sepc={:#x}",
        code, kind, stval, sepc
    );
    // SAFETY: setting sstatus.SIE on a valid kernel stack with the trap
    // frame fully saved; interrupts were masked only by trap entry.
    unsafe {
        core::arch::asm!("csrsi sstatus, 2", options(nomem, nostack));
    }
    if !crate::reap::reap_faulting_current(kind, stval, sepc) {
        // A U-mode fault with no current process is a broken kernel
        // invariant; sret would re-fault at hardware speed.
        report_and_halt(classify_sync_fault(code, sepc, stval));
    }
    // The task is Terminated and will never be re-scheduled.
    loop {
        // SAFETY: kernel stack, no scheduler lock held.
        unsafe { crate::arch::yield_save_and_switch(); }
    }
}

/// Classify a synchronous exception (scause's INTERRUPT bit clear) into
/// a [`TrapError`]. Pure function over the trap-time CSR snapshot — host-
/// testable and free of side effects, so the typed boundary above can be
/// exercised without spinning up a RISC-V kernel.
///
/// Returns `Some(TrapError::SModeEcall)` for code 9 (the only S-mode
/// ecall the kernel ever sees in this dispatcher; ECALL-from-U is the
/// syscall path and is handled separately upstream of this function).
/// Returns `Some(UnknownException { ... })` for any reserved/unmodeled
/// code.
pub(super) fn classify_sync_fault(code: u64, sepc: u64, stval: u64) -> TrapError {
    match code {
        0 => TrapError::InstructionMisaligned { sepc },
        1 => TrapError::InstructionAccessFault { sepc },
        2 => TrapError::IllegalInstruction { sepc, stval },
        3 => TrapError::Breakpoint { sepc },
        4 => TrapError::LoadMisaligned { sepc, stval },
        5 => TrapError::LoadAccessFault { sepc, stval },
        6 => TrapError::StoreMisaligned { sepc, stval },
        7 => TrapError::StoreAccessFault { sepc, stval },
        9 => TrapError::SModeEcall { sepc },
        12 => TrapError::InstructionPageFault { sepc, stval },
        13 => TrapError::LoadPageFault { sepc, stval },
        15 => TrapError::StorePageFault { sepc, stval },
        other => TrapError::UnknownException { code: other, sepc, stval },
    }
}

/// Print a structured fault dump on the serial console and halt the
/// hart. Replaces the previous `panic!()` chain — same observable
/// behavior (operator sees a fault report and the system stops), but
/// the variant is typed and the call site is a single function the
/// audit / debug / test layer can hook later.
fn report_and_halt(err: TrapError) -> ! {
    crate::println!("\n!! RISC-V S-MODE TRAP — KERNEL FAULT !!");
    match err {
        TrapError::InstructionMisaligned { sepc } => {
            crate::println!("  cause: instruction address misaligned");
            crate::println!("  sepc:  {:#x}", sepc);
        }
        TrapError::InstructionAccessFault { sepc } => {
            crate::println!("  cause: instruction access fault");
            crate::println!("  sepc:  {:#x}", sepc);
        }
        TrapError::IllegalInstruction { sepc, stval } => {
            crate::println!("  cause: illegal instruction");
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}  (offending instruction word)", stval);
        }
        TrapError::Breakpoint { sepc } => {
            crate::println!("  cause: breakpoint (ebreak)");
            crate::println!("  sepc:  {:#x}", sepc);
        }
        TrapError::LoadMisaligned { sepc, stval } => {
            crate::println!("  cause: load address misaligned");
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}  (faulting load address)", stval);
        }
        TrapError::LoadAccessFault { sepc, stval } => {
            crate::println!("  cause: load access fault");
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}  (faulting load address)", stval);
        }
        TrapError::StoreMisaligned { sepc, stval } => {
            crate::println!("  cause: store/AMO address misaligned");
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}  (faulting store address)", stval);
        }
        TrapError::StoreAccessFault { sepc, stval } => {
            crate::println!("  cause: store/AMO access fault");
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}  (faulting store address)", stval);
        }
        TrapError::SModeEcall { sepc } => {
            crate::println!(
                "  cause: ECALL from S-mode \
                 — kernel ecalls must go through sbi::* wrappers"
            );
            crate::println!("  sepc:  {:#x}", sepc);
        }
        TrapError::InstructionPageFault { sepc, stval } => {
            crate::println!("  cause: instruction page fault");
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}  (faulting fetch address)", stval);
        }
        TrapError::LoadPageFault { sepc, stval } => {
            crate::println!("  cause: load page fault");
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}  (faulting load address)", stval);
        }
        TrapError::StorePageFault { sepc, stval } => {
            crate::println!("  cause: store/AMO page fault");
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}  (faulting store address)", stval);
        }
        TrapError::UnknownException { code, sepc, stval } => {
            crate::println!("  cause: unknown synchronous exception code {}", code);
            crate::println!("  sepc:  {:#x}", sepc);
            crate::println!("  stval: {:#x}", stval);
        }
        TrapError::UnexpectedInterrupt { code } => {
            crate::println!("  cause: unexpected S-mode interrupt code {}", code);
        }
        TrapError::EntryBranchMismatch { branch, origin, sstatus, sepc } => {
            crate::println!(
                "  cause: trap vector took the {:?} branch for a trap from {:?} \
                 (sscratch invariant broken, ADR-040 § 9)",
                branch, origin
            );
            crate::println!("  sstatus: {:#x}", sstatus);
            crate::println!("  sepc:  {:#x}", sepc);
        }
    }
    crate::halt();
}

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
///   the CSR values read at trap entry, and `entry_branch` is 0 from its
///   S-mode branch or 1 from its U-mode branch.
/// - Interrupts are masked on S-mode trap entry (sstatus.SIE is
///   cleared by hardware on entry; restored from SPIE on sret).
#[no_mangle]
pub unsafe extern "C" fn _riscv_rust_trap_handler(
    saved: *mut SavedContext,
    scause: u64,
    stval: u64,
    entry_branch: u64,
) -> u64 {
    // SAFETY: `saved` was populated by the trap vector before this
    // function was called; the pointer is valid for the duration of the
    // handler and the memory is not aliased.
    let sepc = unsafe { (*saved).sepc };
    // SAFETY: same object as the read above; sstatus is a plain u64 in
    // the saved frame.
    let sstatus = unsafe { (*saved).sstatus };
    // Before any dispatch: an interrupt is exactly the trap that arrived
    // through the wrong branch when the invariant broke. The check reads
    // the frame's captured sstatus, not the live CSR.
    if let Err(entry_branch::Mismatch { branch, origin }) = entry_branch::check(entry_branch, sstatus) {
        report_and_halt(TrapError::EntryBranchMismatch { branch, origin, sstatus, sepc });
    }

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
                // inline UART fallback) → complete.
                //
                // SAFETY: trap handler runs with interrupts masked;
                // the PLIC driver is safe to call from ISR context
                // (its only lock — `crate::INTERRUPT_ROUTER` — is
                // acquired via try_lock).
                let _ = stval; // stval is zero for external IRQs.
                // SAFETY: see the SAFETY block above — restated here so
                // the comment is contiguous with the unsafe call site.
                unsafe { super::plic::dispatch_pending(); }
            }
            IRQ_SOFTWARE => {
                // SBI-delivered S-mode software interrupt.
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
            other => report_and_halt(TrapError::UnexpectedInterrupt { code: other }),
        }
    } else {
        // Synchronous exception. Two user-originated arms are
        // recoverable: ECALL-from-U (the syscall path) and any other
        // fault taken in U-mode (the process is reaped, ADR-019). A
        // fault taken in S-mode is a kernel bug and halts.
        let from_user = EntryBranch::from_sstatus(sstatus) == EntryBranch::User;
        // ECALL from U-mode is the only recoverable arm — handle it
        // before classify_sync_fault, which would otherwise have to
        // model the syscall path.
        if code == 8 {
            // ECALL from U-mode — the syscall entry point.
            // The Rust-side handler extracts a7/a0..a5 from the
            // SavedContext, dispatches, writes the return value back
            // to a0, and bumps sepc past the 4-byte ecall so sret
            // resumes at the next user instruction.
            // SAFETY: ISR context; `saved` was populated by the
            // trap vector's U→S entry path.
            return unsafe { super::syscall::ecall_handler_inner(saved as u64) };
        }
        if from_user {
            reap_user_fault(code, sepc, stval);
        }
        report_and_halt(classify_sync_fault(code, sepc, stval));
    }

    // External IRQs fall through to here after `dispatch_pending` —
    // no context swap, restore from the same frame we arrived on.
    // (Every exception arm either tail-returns from
    // `ecall_handler_inner` or diverges through `report_and_halt`;
    // the IRQ_TIMER arm returned early.)
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
