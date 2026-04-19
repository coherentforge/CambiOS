// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Architecture-specific code (riscv64gc)
//!
//! Third architecture backend, targeting RISC-V S-mode with OpenSBI in
//! M-mode. See [ADR-013](../../docs/adr/013-riscv64-architecture-support.md)
//! for the load-bearing decisions (bootloader, DTB parsing, Sv48 paging,
//! SBI timer, PLIC, `tp`/`sscratch` per-CPU).
//!
//! ## x86_64 / AArch64 / RISC-V mapping
//!
//! | x86_64             | AArch64            | RISC-V (S-mode)              |
//! |--------------------|--------------------|------------------------------|
//! | GDT + TSS          | EL1/EL0 (no segs)  | S/U (no segs, SPP in sstatus) |
//! | IDT                | VBAR_EL1           | stvec (single vector)         |
//! | SYSCALL/SYSRET     | SVC / ERET         | ecall / sret                  |
//! | Local APIC timer   | Generic Timer      | SBI `sbi_set_timer`           |
//! | I/O APIC           | GIC Distributor    | PLIC                          |
//! | CR3 (PML4)         | TTBR0_EL1          | satp (Sv48)                   |
//! | IRETQ              | ERET               | SRET                          |
//! | HLT                | WFI                | WFI                           |
//! | GS base (per-CPU)  | TPIDR_EL1          | `tp` register + `sscratch`    |
//! | TLB shootdown IPI  | TLBI broadcast     | SBI IPI + local sfence.vma    |
//!
//! ## Phase status
//!
//! Phase R-1 lands the skeleton: SavedContext layout, stub context
//! primitives (panic until Phase R-3), percpu via `tp` register, trap
//! vector install stub, minimal PLIC/TLB wrappers. Context switching
//! proper, timer ticks, and U-mode entry come in Phase R-3 / R-4. See
//! the plan file at `/Users/jasonricca/.claude/plans/
//! melodic-tumbling-muffin.md`.

pub mod entry;
pub mod paging;
pub mod percpu;
pub mod plic;
pub mod sbi;
pub mod syscall;
pub mod timer;
pub mod tlb;
pub mod trap;

/// Read the current hart's S-mode interrupt-enable state.
///
/// Returns `true` if S-mode interrupts are enabled (SSTATUS.SIE set).
/// Used by portable `debug_assert!` at call sites that require interrupts
/// masked — see CLAUDE.md § Timer / Preemptive Scheduling.
#[cfg(target_os = "none")]
#[inline]
pub fn interrupts_enabled() -> bool {
    let sstatus: u64;
    // SAFETY: csrr is a pure read of sstatus; nomem + preserves_flags hold.
    unsafe {
        core::arch::asm!(
            "csrr {0}, sstatus",
            out(reg) sstatus,
            options(nomem, preserves_flags),
        );
    }
    (sstatus & (1 << 1)) != 0 // SSTATUS.SIE
}

/// Host-test stub (same rationale as the x86_64 version).
#[cfg(not(target_os = "none"))]
#[inline]
pub fn interrupts_enabled() -> bool {
    false
}

/// GDT compatibility shim.
///
/// RISC-V has no segment selectors — privilege is managed via modes
/// (U/S/M). These constants exist so that `loader/mod.rs` can construct
/// a `SavedContext` without per-field cfg-gating. Mirrors the AArch64
/// shim at `src/arch/aarch64/mod.rs::gdt`.
pub mod gdt {
    /// User code "selector" — placeholder (U-mode has no segment)
    pub const USER_CS: u16 = 0;
    /// User stack "selector" — placeholder
    pub const USER_SS: u16 = 0;
    /// Kernel code "selector" — placeholder (S-mode has no segment)
    pub const KERNEL_CS: u16 = 0;
    /// Kernel stack "selector" — placeholder
    pub const KERNEL_SS: u16 = 0;

    /// Initialize S-mode configuration.
    ///
    /// On RISC-V there are no segment descriptors; privilege is a CSR
    /// bit. This is a no-op — OpenSBI hands us a S-mode context and the
    /// boot stub sets up paging (`satp`) plus the trap vector (`stvec`)
    /// before `kmain`.
    ///
    /// # Safety
    /// Must be called during early boot with interrupts masked.
    pub unsafe fn init() {
        // No-op on RISC-V.
    }

    /// Per-CPU init. No segment state per hart on RISC-V.
    ///
    /// # Safety
    /// Must be called once per AP during early init.
    pub unsafe fn init_for_cpu(_cpu_index: usize) {
        // No-op on RISC-V.
    }

    /// Store the kernel stack top in the current hart's PerCpu entry.
    ///
    /// The trap handler reads this field on U→S entry to switch off the
    /// user stack. The access is `tp`-relative (PerCpu lives in the
    /// struct pointed to by `tp`), matching how AArch64 does this
    /// TPIDR_EL1-relatively.
    ///
    /// # Safety
    /// - `tp` must already hold a valid `*mut PerCpu` (set via
    ///   [`percpu::init_bsp`] / [`percpu::init_ap`]).
    /// - Called from S-mode with interrupts masked.
    pub unsafe fn set_kernel_stack(stack_top: u64) {
        // PerCpu.kernel_stack_top is at offset 24 (same shape as
        // AArch64's PerCpu). On RISC-V we reach it through `tp`, not
        // TPIDR_EL1.
        //
        // SAFETY: `tp` was initialized by percpu::init_bsp. The pointed
        // memory is a valid `PerCpu` and this CPU has exclusive access
        // during context switch (interrupts masked).
        unsafe {
            core::arch::asm!(
                "sd {val}, 24(tp)",
                val = in(reg) stack_top,
                options(nostack, preserves_flags),
            );
        }
    }
}

use crate::scheduler::CpuContext;

// ============================================================================
// Explicit context switch primitives (global_asm)
// ============================================================================
//
// RISC-V AAPCS:
//   a0..a7 = args, a0..a1 = return values, ra = x1 (return address),
//   sp = x2 (stack pointer).
//   Callee-saved: s0..s11 (x8/x9/x18..x27).
//   Caller-saved: t0..t6 (x5..x7/x28..x31), a0..a7 (x10..x17), ra (x1).
//
// CpuContext field offsets (#[repr(C)] — guaranteed sequential):
//   s0=0,  s1=8,  s2=16, s3=24, s4=32, s5=40, s6=48, s7=56,
//   s8=64, s9=72, s10=80, s11=88,
//   ra=96, sp=104, pc=112, sstatus=120

extern "C" {
    /// Save current context to a CpuContext. Returns normally: the
    /// caller sees `context_save` as a function call that's cheap and
    /// leaves every architectural state observable via `ctx`. When a
    /// later `context_restore(ctx)` fires, execution resumes at the
    /// instruction after *this* call (because `pc = ra` is written
    /// during save).
    pub fn context_save(ctx: *mut CpuContext);

    /// Restore all callee-saved regs from a CpuContext and jump to its
    /// saved PC. Does not return.
    pub fn context_restore(ctx: *const CpuContext) -> !;

    /// Save the current context into `current_ctx`, restore from
    /// `next_ctx`, and jump to the next PC. Does not return from the
    /// current invocation.
    pub fn context_switch(
        current_ctx: *mut CpuContext,
        next_ctx: *const CpuContext,
    ) -> !;
}

core::arch::global_asm!(
    // =================================================================
    // context_save(ctx: *mut CpuContext)
    // a0 = ctx
    //
    // Writes the callee-saved set + ra + sp + sstatus into ctx, then
    // returns. Saves `ra` into both `ctx.ra` (offset 96) and `ctx.pc`
    // (offset 112) — so a later context_restore branches back to the
    // instruction after the `call context_save` that reached us.
    // =================================================================
    ".global context_save",
    "context_save:",
    "sd s0,   0(a0)",
    "sd s1,   8(a0)",
    "sd s2,  16(a0)",
    "sd s3,  24(a0)",
    "sd s4,  32(a0)",
    "sd s5,  40(a0)",
    "sd s6,  48(a0)",
    "sd s7,  56(a0)",
    "sd s8,  64(a0)",
    "sd s9,  72(a0)",
    "sd s10, 80(a0)",
    "sd s11, 88(a0)",
    "sd ra,  96(a0)",          // ra
    "sd sp, 104(a0)",          // sp
    "sd ra, 112(a0)",          // pc := ra (resume-after-call PC)
    "csrr t0, sstatus",
    "sd t0, 120(a0)",
    "ret",

    // =================================================================
    // context_restore(ctx: *const CpuContext) -> !
    // a0 = ctx. Does not return.
    // =================================================================
    ".global context_restore",
    "context_restore:",
    "ld s0,   0(a0)",
    "ld s1,   8(a0)",
    "ld s2,  16(a0)",
    "ld s3,  24(a0)",
    "ld s4,  32(a0)",
    "ld s5,  40(a0)",
    "ld s6,  48(a0)",
    "ld s7,  56(a0)",
    "ld s8,  64(a0)",
    "ld s9,  72(a0)",
    "ld s10, 80(a0)",
    "ld s11, 88(a0)",
    "ld ra,  96(a0)",
    "ld sp, 104(a0)",
    "ld t0, 112(a0)",          // saved PC
    "ld t1, 120(a0)",          // saved sstatus
    "csrw sstatus, t1",
    "jr t0",                   // branch to saved PC

    // =================================================================
    // context_switch(current: *mut CpuContext, next: *const CpuContext)
    // a0 = current, a1 = next. Does not return.
    // =================================================================
    ".global context_switch",
    "context_switch:",
    // --- Save current task (a0) ---
    "sd s0,   0(a0)",
    "sd s1,   8(a0)",
    "sd s2,  16(a0)",
    "sd s3,  24(a0)",
    "sd s4,  32(a0)",
    "sd s5,  40(a0)",
    "sd s6,  48(a0)",
    "sd s7,  56(a0)",
    "sd s8,  64(a0)",
    "sd s9,  72(a0)",
    "sd s10, 80(a0)",
    "sd s11, 88(a0)",
    "sd ra,  96(a0)",
    "sd sp, 104(a0)",
    "sd ra, 112(a0)",          // pc = ra
    "csrr t0, sstatus",
    "sd t0, 120(a0)",
    // --- Restore next task (a1) ---
    "ld s0,   0(a1)",
    "ld s1,   8(a1)",
    "ld s2,  16(a1)",
    "ld s3,  24(a1)",
    "ld s4,  32(a1)",
    "ld s5,  40(a1)",
    "ld s6,  48(a1)",
    "ld s7,  56(a1)",
    "ld s8,  64(a1)",
    "ld s9,  72(a1)",
    "ld s10, 80(a1)",
    "ld s11, 88(a1)",
    "ld ra,  96(a1)",
    "ld sp, 104(a1)",
    "ld t0, 112(a1)",
    "ld t1, 120(a1)",
    "csrw sstatus, t1",
    "jr t0",
);

// ============================================================================
// SavedContext — trap frame built on S-mode trap entry
// ============================================================================

/// Full register snapshot captured on trap entry.
///
/// The RISC-V trap handler (in Phase R-3) saves all 32 GPRs plus
/// `sepc` and `sstatus` into this struct on the kernel stack, then
/// passes its SP to the portable scheduler. On trap exit the same
/// struct is restored and `sret` returns to user or kernel mode.
///
/// Layout (byte offsets used by assembly in Phase R-3):
/// ```text
///   0..256  gpr[0..32]   (x0..x31 — x0 hardwired zero, slot unused)
/// 256..264  sepc
/// 264..272  sstatus
/// ```
/// Total size: 272 bytes (happens to match AArch64's SavedContext
/// exactly — the two architectures both save 32 GPRs plus two CSRs).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SavedContext {
    /// x0..x31. x0 is hardwired zero; its slot is kept only to make
    /// indexing uniform with register numbers. The trap handler never
    /// writes or reads gpr[0].
    pub gpr: [u64; 32],
    /// Saved PC (sepc CSR value at trap entry).
    pub sepc: u64,
    /// Saved status (sstatus CSR value at trap entry — encodes previous
    /// privilege via SPP and previous interrupt enable via SPIE).
    pub sstatus: u64,
}

/// Size in bytes of the trap frame pushed on the kernel stack.
///
/// Used by `loader/mod.rs` to compute `kstack_top - ISR_FRAME_SIZE`
/// for the initial trap frame of a newly loaded process. Matches the
/// AArch64 value (288 bytes — 272 rounded up to 16-byte alignment).
pub const ISR_FRAME_SIZE: u64 = 288;

// ============================================================================
// Voluntary context switch — synthetic trap frame + sret
// ============================================================================
//
// Mirrors the AArch64 `yield_save_and_switch` pattern. When a kernel
// path needs to voluntarily yield (blocking on IPC, the caller in a
// syscall handler, etc.), the entry below:
//
//   1. Masks SIE so the save runs atomically with respect to the timer.
//   2. Allocates a 288-byte `SavedContext` on the kernel stack —
//      identical layout to what the trap vector pushes.
//   3. Saves x1..x31 at offsets 8..248; original sp at offset 16.
//   4. Stores a synthetic sepc = `.Lyield_resume` (address of the code
//      that runs post-sret) and a synthetic sstatus with SPP=1 +
//      SPIE=1 (so sret returns to S-mode with interrupts re-enabled).
//   5. Calls `yield_inner` with the SavedContext pointer; it returns
//      the SP of the possibly-different SavedContext to resume from.
//   6. Restores sepc/sstatus + all GPRs + sp, then `sret` — which
//      pops the synthetic trap frame and lands at `.Lyield_resume`.
//   7. At the resume label, the caller's pre-yield `ra` is back in
//      x1 (restored from the SavedContext), so `ret` branches back to
//      the kernel path that called `yield_save_and_switch`.
//
// The synthetic-frame trick keeps the voluntary and preempted paths
// walking the exact same restore code. `yield_inner` performs the same
// arch-side post-switch as the timer ISR (satp + kernel-stack update).

extern "C" {
    /// Voluntary context switch.
    ///
    /// Saves all registers into a SavedContext on the kernel stack,
    /// calls `yield_inner` (which consults the scheduler for the next
    /// task), and resumes via `sret`. Returns to the caller when the
    /// calling task is re-scheduled.
    ///
    /// # Safety
    /// Must be called on the kernel stack with the scheduler live.
    /// Must not be called with a scheduler lock held — `yield_inner`
    /// acquires the scheduler itself.
    pub fn yield_save_and_switch();
}

core::arch::global_asm!(
    ".global yield_save_and_switch",
    "yield_save_and_switch:",

    // ---- Mask SIE for atomic save ----
    "csrci sstatus, 2",            // clear SIE (bit 1)

    // ---- Allocate SavedContext (288 bytes, 16-aligned) ----
    "addi sp, sp, -288",

    // ---- Save x1 + x3..x31 (skip x0; save sp separately) ----
    "sd x1,   8(sp)",
    "sd x3,  24(sp)",
    "sd x4,  32(sp)",
    "sd x5,  40(sp)",
    "sd x6,  48(sp)",
    "sd x7,  56(sp)",
    "sd x8,  64(sp)",
    "sd x9,  72(sp)",
    "sd x10, 80(sp)",
    "sd x11, 88(sp)",
    "sd x12, 96(sp)",
    "sd x13, 104(sp)",
    "sd x14, 112(sp)",
    "sd x15, 120(sp)",
    "sd x16, 128(sp)",
    "sd x17, 136(sp)",
    "sd x18, 144(sp)",
    "sd x19, 152(sp)",
    "sd x20, 160(sp)",
    "sd x21, 168(sp)",
    "sd x22, 176(sp)",
    "sd x23, 184(sp)",
    "sd x24, 192(sp)",
    "sd x25, 200(sp)",
    "sd x26, 208(sp)",
    "sd x27, 216(sp)",
    "sd x28, 224(sp)",
    "sd x29, 232(sp)",
    "sd x30, 240(sp)",
    "sd x31, 248(sp)",

    // ---- Save original sp (pre-yield = sp + 288) ----
    "addi t0, sp, 288",
    "sd t0, 16(sp)",

    // ---- Synthetic sepc = .Lyield_resume ----
    "la t0, .Lyield_resume",
    "sd t0, 256(sp)",

    // ---- Synthetic sstatus: SPP=1 (bit 8) + SPIE=1 (bit 5). On sret:
    //      sstatus.SIE = saved.SPIE = 1 → interrupts re-enabled
    //      mode      = saved.SPP  = S → lands in kernel at resume label
    "csrr t0, sstatus",
    "ori t0, t0, 0x120",           // (1<<8) | (1<<5) = 0x120
    "sd t0, 264(sp)",

    // ---- Call Rust scheduler glue ----
    "mv a0, sp",
    "call yield_inner",
    // a0 = new SP (same or different task's SavedContext)

    // ---- Restore from (possibly new) SavedContext ----
    "mv sp, a0",

    // Restore sepc + sstatus.
    "ld t0, 264(sp)",
    "csrw sstatus, t0",
    "ld t0, 256(sp)",
    "csrw sepc, t0",

    // Restore x1 + x3..x31 (skip x2 — sp restored last).
    "ld x1,   8(sp)",
    "ld x3,  24(sp)",
    "ld x4,  32(sp)",
    "ld x5,  40(sp)",
    "ld x6,  48(sp)",
    "ld x7,  56(sp)",
    "ld x8,  64(sp)",
    "ld x9,  72(sp)",
    "ld x10, 80(sp)",
    "ld x11, 88(sp)",
    "ld x12, 96(sp)",
    "ld x13, 104(sp)",
    "ld x14, 112(sp)",
    "ld x15, 120(sp)",
    "ld x16, 128(sp)",
    "ld x17, 136(sp)",
    "ld x18, 144(sp)",
    "ld x19, 152(sp)",
    "ld x20, 160(sp)",
    "ld x21, 168(sp)",
    "ld x22, 176(sp)",
    "ld x23, 184(sp)",
    "ld x24, 192(sp)",
    "ld x25, 200(sp)",
    "ld x26, 208(sp)",
    "ld x27, 216(sp)",
    "ld x28, 224(sp)",
    "ld x29, 232(sp)",
    "ld x30, 240(sp)",
    "ld x31, 248(sp)",

    // Restore sp last (pops the frame).
    "ld sp, 16(sp)",

    "sret",                        // land at .Lyield_resume in S-mode, SIE=1

    // ---- Resume point for yielded tasks ----
    // sret restored PC = here. x1 (ra) holds the caller's pre-yield
    // return address — `ret` branches back into the kernel.
    ".Lyield_resume:",
    "ret",
);

/// Rust handler for the timer ISR.
///
/// Called from `_riscv_rust_trap_handler`'s `IRQ_TIMER` arm with a
/// pointer to the preempted task's SavedContext on the kernel stack.
/// Rearms the SBI timer, runs the portable `scheduler::on_timer_isr`,
/// applies the arch-side per-hart updates the scheduler requests,
/// and returns the SavedContext pointer the trap vector should
/// restore from. Identical in shape to AArch64's `timer_isr_inner`
/// (minus GIC EOI — RISC-V timer IRQs clear implicitly on re-arm).
///
/// # Safety
/// ISR context — interrupts masked, trap frame valid on kernel stack.
#[no_mangle]
extern "C" fn timer_isr_inner(current_sp: u64) -> u64 {
    // Rearm the SBI timer first. SBI's set_timer implicitly clears
    // STIP once the deadline moves past the current `time`, so this
    // both drops the pending bit and programs the next tick.
    //
    // SAFETY: ISR context — SBI ecall is legal from S-mode.
    unsafe { timer::rearm(); }

    let (new_sp, hint) = crate::scheduler::on_timer_isr(current_sp);

    // Apply arch-side per-hart state updates the scheduler recorded.
    // Same shape as `yield_inner` below — if the scheduler switched
    // to a task owned by a different process, update the kernel
    // stack pointer and the satp page-table root.
    if let Some(hint) = hint {
        if hint.kernel_stack_top != 0 {
            // SAFETY: ISR context; hint.kernel_stack_top is the next
            // task's kernel stack, validated by the scheduler.
            unsafe { gdt::set_kernel_stack(hint.kernel_stack_top); }
        }
        if hint.page_table_root != 0 {
            // SAFETY: satp read/write is legal from S-mode; the
            // hint's page-table root came from the scheduler.
            unsafe {
                let current_satp: u64;
                core::arch::asm!(
                    "csrr {0}, satp",
                    out(reg) current_satp,
                    options(nostack, nomem, preserves_flags),
                );
                let current_root = (current_satp & ((1u64 << 44) - 1)) << 12;
                if current_root != hint.page_table_root {
                    let ppn = hint.page_table_root >> 12;
                    let new_satp = (9u64 << 60) | ppn; // Sv48 mode = 9
                    core::arch::asm!(
                        "csrw satp, {0}",
                        "sfence.vma zero, zero",
                        in(reg) new_satp,
                        options(nostack),
                    );
                }
            }
        }
    }

    new_sp
}

/// Rust handler for voluntary context switch.
///
/// Called from the `yield_save_and_switch` assembly with a pointer to
/// the caller's SavedContext on the kernel stack. Asks the scheduler
/// which task to resume next and applies arch-side per-hart state
/// updates (kernel stack + satp) before returning the SP of the
/// target task's SavedContext.
#[no_mangle]
extern "C" fn yield_inner(current_sp: u64) -> u64 {
    let (new_sp, hint) = crate::scheduler::on_voluntary_yield(current_sp);

    // Apply arch-side per-hart state updates the scheduler recorded.
    // Matches the AArch64 `yield_inner` shape — if the scheduler
    // switched to a task owned by a different process, we update the
    // kernel stack pointer and the satp page-table root.
    if let Some(hint) = hint {
        if hint.kernel_stack_top != 0 {
            // SAFETY: interrupts are masked (csrci in the trampoline).
            // `hint.kernel_stack_top` is the next task's kernel stack.
            unsafe { gdt::set_kernel_stack(hint.kernel_stack_top); }
        }
        if hint.page_table_root != 0 {
            // SAFETY: satp read/write is always legal from S-mode. The
            // new root phys was validated by the scheduler; we issue
            // sfence.vma to drop stale TLB entries.
            unsafe {
                let current_satp: u64;
                core::arch::asm!(
                    "csrr {0}, satp",
                    out(reg) current_satp,
                    options(nostack, nomem, preserves_flags),
                );
                // satp encodes MODE[63:60] | ASID[59:44] | PPN[43:0].
                // We compare PPN * 4 KiB against hint.page_table_root.
                let current_root = (current_satp & ((1u64 << 44) - 1)) << 12;
                if current_root != hint.page_table_root {
                    // Build new satp: MODE = Sv48 (9), ASID=0 for now,
                    // PPN = hint.page_table_root >> 12.
                    let ppn = hint.page_table_root >> 12;
                    let new_satp = (9u64 << 60) | ppn;
                    // SAFETY: new_satp targets a valid Sv48 root table
                    // from the scheduler; sfence.vma is mandatory per
                    // the priv spec after changing satp.
                    core::arch::asm!(
                        "csrw satp, {0}",
                        "sfence.vma zero, zero",
                        in(reg) new_satp,
                        options(nostack),
                    );
                }
            }
        }
    }

    new_sp
}

/// Park the current hart until the next interrupt.
///
/// Masks S-mode interrupts, sets SP to the per-CPU kernel stack, then
/// loops on `wfi`. The interrupt handler will resume scheduling when
/// the next timer tick fires (Phase R-3 onward).
///
/// For Phase R-1 this is simply `wfi` in a loop — no scheduling yet.
///
/// # Safety
/// `kernel_stack_top` must point to the top of a valid kernel stack for
/// this hart, or zero if no stack switch is desired.
pub fn halt_until_preempted(_kernel_stack_top: u64) -> ! {
    loop {
        // SAFETY: wfi is always legal from S-mode. It blocks until a
        // pending interrupt is observed; if interrupts are masked we
        // still wake on pending bits but the trap does not fire.
        unsafe {
            core::arch::asm!("wfi", options(nostack, nomem, preserves_flags));
        }
    }
}

// ============================================================================
// Switch-context coordination (used by loader/scheduler)
// ============================================================================

/// Stashed pointer to an on-stack SavedContext, set by the yield path
/// when it needs the scheduler to inspect the current trap frame.
/// Mirrors the AArch64 SWITCH_CONTEXT_PTR pattern. Phase R-3 wires it
/// through the trap handler.
static SWITCH_CONTEXT_PTR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn set_switch_context(ctx: *const SavedContext) {
    SWITCH_CONTEXT_PTR.store(ctx as u64, core::sync::atomic::Ordering::Release);
}

pub fn clear_switch_context() {
    SWITCH_CONTEXT_PTR.store(0, core::sync::atomic::Ordering::Release);
}

pub fn get_switch_context() -> u64 {
    SWITCH_CONTEXT_PTR.load(core::sync::atomic::Ordering::Acquire)
}

/// Copy register state from a SavedContext (trap frame) into the
/// scheduler's CpuContext (callee-saved view).
///
/// Maps the RISC-V ABI register numbers to the `CpuContext` field
/// names: `s0..s11` come from `gpr[8..9, 18..27]`, `ra` from `gpr[1]`,
/// `sp` from `gpr[2]`, `pc` from `sepc`.
pub fn saved_to_cpu_context(saved: &SavedContext, cpu: &mut CpuContext) {
    cpu.s0  = saved.gpr[8];
    cpu.s1  = saved.gpr[9];
    cpu.s2  = saved.gpr[18];
    cpu.s3  = saved.gpr[19];
    cpu.s4  = saved.gpr[20];
    cpu.s5  = saved.gpr[21];
    cpu.s6  = saved.gpr[22];
    cpu.s7  = saved.gpr[23];
    cpu.s8  = saved.gpr[24];
    cpu.s9  = saved.gpr[25];
    cpu.s10 = saved.gpr[26];
    cpu.s11 = saved.gpr[27];
    cpu.ra  = saved.gpr[1];
    cpu.sp  = saved.gpr[2];
    cpu.pc  = saved.sepc;
    cpu.sstatus = saved.sstatus;
}

/// Copy register state from the scheduler's CpuContext into a
/// SavedContext (trap frame).
///
/// Zeros caller-saved registers (a0..a7, t0..t6) — they are not
/// preserved across voluntary yields and must not leak values across
/// task resumes. Fills callee-saved slots + ra/sp/sepc/sstatus.
pub fn cpu_to_saved_context(cpu: &CpuContext, saved: &mut SavedContext) {
    // Zero every GPR slot first; we then overwrite the callee-saved
    // subset. This keeps caller-saved regs from leaking values that
    // belonged to a different task.
    for slot in saved.gpr.iter_mut() {
        *slot = 0;
    }
    saved.gpr[1]  = cpu.ra;
    saved.gpr[2]  = cpu.sp;
    saved.gpr[8]  = cpu.s0;
    saved.gpr[9]  = cpu.s1;
    saved.gpr[18] = cpu.s2;
    saved.gpr[19] = cpu.s3;
    saved.gpr[20] = cpu.s4;
    saved.gpr[21] = cpu.s5;
    saved.gpr[22] = cpu.s6;
    saved.gpr[23] = cpu.s7;
    saved.gpr[24] = cpu.s8;
    saved.gpr[25] = cpu.s9;
    saved.gpr[26] = cpu.s10;
    saved.gpr[27] = cpu.s11;
    saved.sepc    = cpu.pc;
    saved.sstatus = cpu.sstatus;
}
