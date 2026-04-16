// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Architecture-specific code (AArch64)
//!
//! Implements CPU-specific primitives for ARMv8-A (AArch64 execution state).
//!
//! ## Context Switch Architecture
//!
//! Two context switch paths exist (mirroring x86_64):
//!
//! 1. **Explicit switch** (`context_switch`): Voluntary yields and blocking.
//!    Saves callee-saved registers (x19-x30, SP, LR) via `stp` pairs,
//!    restores from next task, `ret` to next task's LR.
//!
//! 2. **Interrupt-driven switch** (`timer_isr_stub`): Preemption via exception.
//!    Exception vector saves all 31 GP registers + ELR_EL1 + SPSR_EL1 + SP_EL0
//!    into SavedContext, calls Rust handler, restores from (potentially different)
//!    context, `eret` to resume.
//!
//! ## AArch64 ↔ x86_64 mapping
//!
//! | x86_64             | AArch64                | Notes                       |
//! |--------------------|------------------------|-----------------------------|
//! | GDT + TSS          | EL1/EL0 configuration  | Exception levels, not segs  |
//! | IDT                | VBAR_EL1 vector table   | 4 entries × 4 types         |
//! | SYSCALL/SYSRET     | SVC / ERET             | Synchronous exception       |
//! | Local APIC         | GICv3 redistributor    | Per-CPU interrupt ctrl      |
//! | I/O APIC           | GICv3 distributor      | Shared interrupt routing    |
//! | CR3 (PML4)         | TTBR0_EL1 / TTBR1_EL1 | User / kernel page tables   |
//! | IRETQ              | ERET                   | Return from exception       |
//! | HLT                | WFI                    | Wait for interrupt          |
//! | GS base (percpu)   | TPIDR_EL1              | Per-CPU data pointer        |
//! | TLB shootdown IPI  | TLBI broadcast         | Hardware-assisted on v8.4+  |

pub mod gic;
pub mod paging;
pub mod percpu;
pub mod syscall;
pub mod timer;
pub mod tlb;

/// Read the current CPU's IRQ-enable state.
///
/// Returns `true` if IRQs are unmasked (DAIF.I *clear*). Used by portable
/// `debug_assert!` at call sites that require interrupts masked — see
/// CLAUDE.md § Timer / Preemptive Scheduling.
#[cfg(target_os = "none")]
#[inline]
pub fn interrupts_enabled() -> bool {
    let daif: u64;
    // SAFETY: mrs is a pure read of DAIF; nomem + preserves_flags hold.
    unsafe {
        core::arch::asm!(
            "mrs {0}, daif",
            out(reg) daif,
            options(nomem, preserves_flags),
        );
    }
    (daif & (1 << 7)) == 0 // DAIF.I; clear = IRQs enabled
}

/// Host-test stub (same rationale as the x86_64 version).
#[cfg(not(target_os = "none"))]
#[inline]
pub fn interrupts_enabled() -> bool {
    false
}

/// GDT compatibility shim.
///
/// AArch64 has no segment selectors — privilege is managed via exception
/// levels (EL0 = user, EL1 = kernel). These constants exist so that
/// `loader/mod.rs` can construct SavedContext without per-field cfg-gating.
pub mod gdt {
    /// User code "selector" — placeholder (EL0)
    pub const USER_CS: u16 = 0;
    /// User stack "selector" — placeholder (EL0)
    pub const USER_SS: u16 = 0;
    /// Kernel code "selector" — placeholder (EL1)
    pub const KERNEL_CS: u16 = 0;
    /// Kernel stack "selector" — placeholder (EL1)
    pub const KERNEL_SS: u16 = 0;

    /// Initialize EL1 configuration (AArch64 equivalent of loading a GDT).
    ///
    /// On AArch64, privilege is managed via exception levels, not segment
    /// selectors. This is a no-op — Limine already sets up EL1 for us.
    ///
    /// # Safety
    /// Must be called during early boot with interrupts masked.
    pub unsafe fn init() {
        // No-op on AArch64 — EL1/EL0 configuration is handled by Limine
        // and exception vector table installation (syscall::init).
    }

    /// Per-CPU init (AArch64 equivalent of loading a per-CPU GDT+TSS).
    ///
    /// On AArch64, there are no per-CPU segment descriptors. Per-CPU
    /// kernel stacks are set via SP_EL1 at context switch time.
    ///
    /// # Safety
    /// Must be called once per AP during early init.
    pub unsafe fn init_for_cpu(_cpu_index: usize) {
        // No-op on AArch64
    }

    /// Set the kernel stack pointer for exception return.
    ///
    /// On AArch64, this writes SP_EL1 so the exception entry from EL0
    /// lands on the correct kernel stack.
    ///
    /// # Safety
    /// Must be called from EL1 with interrupts masked (DAIF.I set).
    pub unsafe fn set_kernel_stack(stack_top: u64) {
        // Store the kernel stack top in PerCpu (offset 24 from TPIDR_EL1).
        // The timer ISR stub sets SP_EL1 from PerCpu in its restore path,
        // right before ERET, so the next exception entry uses this stack.
        //
        // We do NOT modify SP_EL1 here because the ISR is running on
        // SP_EL1 — writing it mid-ISR would corrupt the active stack.
        //
        // SAFETY: TPIDR_EL1 is initialized. Called with interrupts masked.
        unsafe {
            core::arch::asm!(
                "mrs {tmp}, tpidr_el1",
                "str {val}, [{tmp}, #24]",   // PerCpu.kernel_stack_top
                tmp = out(reg) _,
                val = in(reg) stack_top,
                options(nostack),
            );
        }
    }
}

use crate::scheduler::CpuContext;
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Explicit context switch primitives (global_asm)
// ============================================================================
//
// AArch64 AAPCS64 calling convention:
//   x0 = first arg, x1 = second arg, return via ret (branches to x30/LR)
//
// Callee-saved: x19-x28, x29 (FP), x30 (LR)
// Caller-saved: x0-x18
//
// CpuContext field offsets (#[repr(C)] — guaranteed sequential layout):
//   x19=0, x20=8, x21=16, x22=24, x23=32, x24=40, x25=48, x26=56,
//   x27=64, x28=72, x29(fp)=80, x30(lr)=88, sp=96, pc=104, pstate=112

extern "C" {
    /// Save current context to a CpuContext structure. Returns normally.
    ///
    /// Captures callee-saved registers (x19-x30), SP (via `mov`),
    /// LR as the return PC, and NZCV flags via `mrs`. When restored,
    /// execution resumes at the instruction after this call.
    pub fn context_save(ctx: *mut CpuContext);

    /// Restore all registers from a CpuContext and jump to saved PC.
    /// Does NOT return.
    pub fn context_restore(ctx: *const CpuContext) -> !;

    /// Save current context, then restore and jump to next task.
    /// Does not return from current invocation.
    pub fn context_switch(current_ctx: *mut CpuContext, next_ctx: *const CpuContext) -> !;
}

core::arch::global_asm!(
    // =================================================================
    // context_save(ctx: *mut CpuContext)
    // AAPCS64: x0 = ctx
    // =================================================================
    ".global context_save",
    "context_save:",
    // Callee-saved pairs (x19..x28)
    "stp x19, x20, [x0, #0]",
    "stp x21, x22, [x0, #16]",
    "stp x23, x24, [x0, #32]",
    "stp x25, x26, [x0, #48]",
    "stp x27, x28, [x0, #64]",
    // Frame pointer + link register
    "stp x29, x30, [x0, #80]",
    // SP — can't stp SP directly, move to temp first
    "mov x2, sp",
    "str x2, [x0, #96]",
    // PC = return address (LR holds where we'll return to)
    "str x30, [x0, #104]",
    // PSTATE (NZCV only — DAIF is managed by exception entry/exit)
    "mrs x2, nzcv",
    "str x2, [x0, #112]",
    "ret",

    // =================================================================
    // context_restore(ctx: *const CpuContext)
    // AAPCS64: x0 = ctx.  Does not return.
    // =================================================================
    ".global context_restore",
    "context_restore:",
    // Restore callee-saved pairs
    "ldp x19, x20, [x0, #0]",
    "ldp x21, x22, [x0, #16]",
    "ldp x23, x24, [x0, #32]",
    "ldp x25, x26, [x0, #48]",
    "ldp x27, x28, [x0, #64]",
    "ldp x29, x30, [x0, #80]",
    // Restore SP
    "ldr x2, [x0, #96]",
    "mov sp, x2",
    // Restore NZCV
    "ldr x2, [x0, #112]",
    "msr nzcv, x2",
    // Branch to saved PC (stored at offset 104)
    "ldr x2, [x0, #104]",
    "br x2",

    // =================================================================
    // context_switch(current: *mut CpuContext, next: *const CpuContext)
    // AAPCS64: x0 = current, x1 = next.  Does not return.
    // =================================================================
    ".global context_switch",
    "context_switch:",
    // --- Save current task (x0) ---
    "stp x19, x20, [x0, #0]",
    "stp x21, x22, [x0, #16]",
    "stp x23, x24, [x0, #32]",
    "stp x25, x26, [x0, #48]",
    "stp x27, x28, [x0, #64]",
    "stp x29, x30, [x0, #80]",
    "mov x2, sp",
    "str x2, [x0, #96]",
    "str x30, [x0, #104]",     // PC = LR = return address
    "mrs x2, nzcv",
    "str x2, [x0, #112]",
    // --- Restore next task (x1) ---
    "ldp x19, x20, [x1, #0]",
    "ldp x21, x22, [x1, #16]",
    "ldp x23, x24, [x1, #32]",
    "ldp x25, x26, [x1, #48]",
    "ldp x27, x28, [x1, #64]",
    "ldp x29, x30, [x1, #80]",
    "ldr x2, [x1, #96]",
    "mov sp, x2",
    "ldr x2, [x1, #112]",
    "msr nzcv, x2",
    "ldr x2, [x1, #104]",     // PC
    "br x2",
);

// ============================================================================
// SavedContext — full register frame for interrupt-driven context switches
// ============================================================================

/// Full register state saved on exception entry (timer IRQ, SVC, etc.).
///
/// When an exception fires from EL0 or EL1, the ISR stub saves all 31 GP
/// registers plus the system registers the CPU doesn't automatically save.
///
/// ## Layout (offsets for assembly)
/// ```text
/// x0=0, x1=8, x2=16, ..., x30=240
/// elr_el1=248, spsr_el1=256, sp_el0=264
/// ```
/// Total size: 272 bytes (34 × 8), 16-byte aligned.
#[repr(C)]
pub struct SavedContext {
    /// General purpose registers x0-x30 (31 registers)
    pub gpr: [u64; 31],
    /// Exception Link Register — return PC
    pub elr_el1: u64,
    /// Saved Program Status Register — PSTATE at exception entry
    pub spsr_el1: u64,
    /// User stack pointer (only meaningful when exception from EL0)
    pub sp_el0: u64,
}

// ============================================================================
// Switch context pointer (architecture-independent logic)
// ============================================================================

/// Pointer to the next task's SavedContext for interrupt-driven switching.
/// 0 = no context switch pending.
static SWITCH_CONTEXT_PTR: AtomicU64 = AtomicU64::new(0);

/// Set the context pointer for the next exception return.
pub fn set_switch_context(ctx: *const SavedContext) {
    SWITCH_CONTEXT_PTR.store(ctx as u64, Ordering::Release);
}

/// Clear the context switch pointer (no switch pending).
pub fn clear_switch_context() {
    SWITCH_CONTEXT_PTR.store(0, Ordering::Release);
}

/// Get the pending context switch pointer (0 = no switch).
pub fn get_switch_context() -> u64 {
    SWITCH_CONTEXT_PTR.load(Ordering::Acquire)
}

// ============================================================================
// Context conversion helpers
// ============================================================================

/// Copy a SavedContext into a CpuContext (for scheduler task tracking).
///
/// Maps the full interrupt frame to the callee-saved subset that the
/// scheduler tracks.
pub fn saved_to_cpu_context(saved: &SavedContext, cpu: &mut CpuContext) {
    // Callee-saved: x19-x28
    cpu.x19 = saved.gpr[19];
    cpu.x20 = saved.gpr[20];
    cpu.x21 = saved.gpr[21];
    cpu.x22 = saved.gpr[22];
    cpu.x23 = saved.gpr[23];
    cpu.x24 = saved.gpr[24];
    cpu.x25 = saved.gpr[25];
    cpu.x26 = saved.gpr[26];
    cpu.x27 = saved.gpr[27];
    cpu.x28 = saved.gpr[28];
    cpu.x29 = saved.gpr[29]; // FP
    cpu.x30 = saved.gpr[30]; // LR
    cpu.sp = saved.sp_el0;
    cpu.pc = saved.elr_el1;
    cpu.pstate = saved.spsr_el1;
}

/// Copy a CpuContext into a SavedContext (for restoring on exception return).
///
/// Fills callee-saved registers; caller-saved registers (x0-x18) are zeroed.
pub fn cpu_to_saved_context(cpu: &CpuContext, saved: &mut SavedContext) {
    // Zero caller-saved registers
    for i in 0..19 {
        saved.gpr[i] = 0;
    }
    // Callee-saved: x19-x28
    saved.gpr[19] = cpu.x19;
    saved.gpr[20] = cpu.x20;
    saved.gpr[21] = cpu.x21;
    saved.gpr[22] = cpu.x22;
    saved.gpr[23] = cpu.x23;
    saved.gpr[24] = cpu.x24;
    saved.gpr[25] = cpu.x25;
    saved.gpr[26] = cpu.x26;
    saved.gpr[27] = cpu.x27;
    saved.gpr[28] = cpu.x28;
    saved.gpr[29] = cpu.x29;
    saved.gpr[30] = cpu.x30;
    saved.elr_el1 = cpu.pc;
    saved.spsr_el1 = cpu.pstate;
    saved.sp_el0 = cpu.sp;
}

// ============================================================================
// Timer ISR stub — exception vector entry for preemptive context switching
// ============================================================================
//
// AArch64 exception vector table has 16 entries (4 types × 4 sources).
// We install this at VBAR_EL1. Each entry is 32 instructions (128 bytes).
// The timer IRQ comes through the IRQ vector from the current EL (EL1)
// using SP_EL0 or SP_EL1 depending on SPSel.

core::arch::global_asm!(
    // =================================================================
    // Exception vector table — installed at VBAR_EL1
    //
    // Layout: 4 groups × 4 vectors × 128 bytes = 2048 bytes
    // Group 0: Current EL, SP_EL0 (not used — we use SP_EL1 in kernel)
    // Group 1: Current EL, SP_ELx (kernel interrupted itself)
    // Group 2: Lower EL, AArch64 (user→kernel)
    // Group 3: Lower EL, AArch32 (not supported)
    // =================================================================
    ".balign 2048",
    ".global exception_vector_table",
    "exception_vector_table:",

    // --- Group 0: Current EL with SP_EL0 (kernel, SPSel was 0) ---
    // Exception entry forces SPSel=1, so SP = SP_EL1 on entry.
    // set_kernel_stack() keeps SP_EL1 = kernel stack via SPSel toggle.
    // Synchronous (e.g., kernel data abort)
    ".balign 128",
    "b sync_el1_stub",
    // IRQ — timer IRQ from kernel idle loop
    ".balign 128",
    "b timer_isr_stub",
    // FIQ
    ".balign 128",
    "b unhandled_exception",
    // SError
    ".balign 128",
    "b unhandled_exception",

    // --- Group 1: Current EL with SP_ELx (kernel, SPSel was 1) ---
    // Same handlers — SP_EL1 is valid in both cases.
    // Synchronous
    ".balign 128",
    "b sync_el1_stub",
    // IRQ
    ".balign 128",
    "b timer_isr_stub",
    // FIQ
    ".balign 128",
    "b unhandled_exception",
    // SError
    ".balign 128",
    "b unhandled_exception",

    // --- Group 2: Lower EL, AArch64 (user → kernel) ---
    // SP_EL1 = kernel stack (set by set_kernel_stack on last ctx switch).
    // Synchronous (SVC, data abort, instruction abort from EL0)
    ".balign 128",
    "b sync_el0_stub",
    // IRQ — timer IRQ while user task running
    ".balign 128",
    "b timer_isr_stub",
    // FIQ
    ".balign 128",
    "b unhandled_exception",
    // SError
    ".balign 128",
    "b unhandled_exception",

    // --- Group 3: Lower EL, AArch32 (not supported) ---
    ".balign 128",
    "b unhandled_exception",
    ".balign 128",
    "b unhandled_exception",
    ".balign 128",
    "b unhandled_exception",
    ".balign 128",
    "b unhandled_exception",

    // =================================================================
    // unhandled_exception: spin forever (placeholder)
    // =================================================================
    "unhandled_exception:",
    "wfi",
    "b unhandled_exception",

    // =================================================================
    // timer_isr_stub: save all registers → call Rust → restore → eret
    //
    // On entry: exception forced SPSel=1, SP = SP_EL1 = kernel stack
    // (set by set_kernel_stack via SPSel toggle on each context switch).
    //
    // SP_EL0 holds either:
    //   - The kernel stack (if exception from EL1 — Group 0/1)
    //   - The user stack (if exception from EL0 — Group 2)
    //
    // We save SP_EL0 into SavedContext via SPSel toggle (QEMU traps
    // mrs/msr SP_EL0). On ERET, SPSR restores SPSel and the correct
    // SP_EL0 is written back via the same toggle.
    // =================================================================
    ".global timer_isr_stub",
    "timer_isr_stub:",
    // --- Save SP_EL0 and x0 to kernel stack before allocating frame ---
    // Push x0 to SP_EL1 (current SP), then read SP_EL0 via SPSel toggle.
    "str x0,  [sp, #-16]!",   // push x0 (pre-decrement SP_EL1)
    "msr spsel, #0",           // SP = SP_EL0
    "mov x0, sp",              // x0 = SP_EL0 value
    "msr spsel, #1",           // SP = SP_EL1 (back to kernel stack)
    "str x0,  [sp, #8]",      // save SP_EL0 next to x0
    "ldr x0,  [sp], #16",     // restore x0, pop (SP_EL1 back to original)
    // Now: SP = SP_EL1 = kernel stack, SP_EL0 saved at [SP_EL1 - 8]

    // Allocate SavedContext (288 bytes, 16-aligned)
    "sub sp, sp, #288",
    // Save x0-x30
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "str x30,      [sp, #240]",
    // Save system registers
    "mrs x2, elr_el1",
    "mrs x3, spsr_el1",
    // Load saved SP_EL0 from temp area above frame (old_SP - 8 = sp + 280).
    // Store it in the SavedContext's sp_el0 field at offset 264 so that
    // context switches read it from the canonical location.
    "ldr x4, [sp, #280]",     // saved SP_EL0 from temp push area
    "str x2, [sp, #248]",     // elr_el1
    "str x3, [sp, #256]",     // spsr_el1
    "str x4, [sp, #264]",     // sp_el0 (canonical location in SavedContext)
    // Adjust SP to hide the temp push area (frame is self-contained)
    // (Not needed — the 16 bytes above the frame are invisible to Rust)

    // Call Rust handler: x0 = pointer to SavedContext on kernel stack
    "mov x0, sp",
    "bl timer_isr_inner",
    // x0 = new SP (same or different task's SavedContext)
    "mov sp, x0",

    // Restore system registers from (potentially different) SavedContext
    "ldr x2, [sp, #248]",     // elr_el1
    "ldr x3, [sp, #256]",     // spsr_el1
    "ldr x4, [sp, #264]",     // sp_el0
    "msr elr_el1, x2",
    "msr spsr_el1, x3",
    // Restore SP_EL0 via SPSel toggle (QEMU traps msr sp_el0)
    "msr spsel, #0",           // SP = SP_EL0
    "mov sp, x4",              // SP_EL0 = saved value
    "msr spsel, #1",           // SP = SP_EL1 (back to SavedContext)

    // Restore x0-x30
    "ldp x0,  x1,  [sp, #0]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x20, x21, [sp, #160]",
    "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]",
    "ldp x26, x27, [sp, #208]",
    "ldp x28, x29, [sp, #224]",
    "ldr x30,      [sp, #240]",
    // Deallocate SavedContext frame
    "add sp, sp, #288",
    // Return from exception
    "eret",
);

// ============================================================================
// Synchronous exception stubs — fault dispatching
// ============================================================================

core::arch::global_asm!(
    // =================================================================
    // sync_el0_stub: Synchronous exception from EL0 (user mode)
    //
    // Dispatches based on ESR_EL1 Exception Class:
    //   EC=0x15: SVC (syscall) → svc_handler_inner
    //   EC=0x20: Instruction Abort from lower EL → fault_el0_inner
    //   EC=0x24: Data Abort from lower EL → fault_el0_inner
    //   Other: → fault_el0_inner (generic fault)
    //
    // Uses the same SavedContext frame layout as svc_entry_stub.
    // =================================================================
    ".global sync_el0_stub",
    "sync_el0_stub:",
    // Exception from EL0: CPU forced SPSel=1, SP = SP_EL1 = kernel stack.
    // SP_EL0 = user stack (must be saved).
    //
    // Read user SP_EL0 via SPSel toggle, save it alongside x0 above the
    // frame, then allocate the SavedContext and save everything.
    "str x0,  [sp, #-16]!",   // push x0 (pre-decrement SP_EL1)
    "msr spsel, #0",           // SP = SP_EL0 (user stack)
    "mov x0, sp",              // x0 = user SP_EL0
    "msr spsel, #1",           // SP = SP_EL1 (back to kernel stack)
    "str x0,  [sp, #8]",      // save user SP_EL0 next to saved x0
    "ldr x0,  [sp], #16",     // restore x0, pop temp area

    // Allocate SavedContext (288 bytes)
    "sub sp, sp, #288",
    // Save x0-x30
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "str x30,      [sp, #240]",
    // Save system registers
    "mrs x2, elr_el1",
    "mrs x3, spsr_el1",
    "ldr x4, [sp, #280]",     // Load saved user SP_EL0 (at old_SP - 8 = sp + 280)
    "str x2, [sp, #248]",
    "str x3, [sp, #256]",
    "str x4, [sp, #264]",
    // Read ESR_EL1 to determine exception class
    "mrs x1, esr_el1",
    "lsr x2, x1, #26",          // EC = bits [31:26]
    // Check if SVC (EC=0x15)
    "cmp x2, #0x15",
    "b.eq sync_el0_is_svc",
    // Not SVC — call fault handler: x0 = saved SP, x1 = ESR
    "mov x0, sp",
    "bl fault_el0_inner",
    "b sync_el0_restore",
    // SVC path
    "sync_el0_is_svc:",
    "mov x0, sp",
    "bl svc_handler_inner",
    // Write return value into saved x0 slot
    "str x0, [sp, #0]",
    // Restore and eret (shared path)
    "sync_el0_restore:",
    "ldr x2, [sp, #248]",
    "ldr x3, [sp, #256]",
    "ldr x4, [sp, #264]",
    "msr elr_el1, x2",
    "msr spsr_el1, x3",
    // Restore user SP_EL0 via SPSel toggle
    "msr spsel, #0",           // SP = SP_EL0
    "mov sp, x4",              // SP_EL0 = saved user stack
    "msr spsel, #1",           // SP = SP_EL1 (back to SavedContext)
    // Restore x0-x30
    "ldp x0,  x1,  [sp, #0]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x20, x21, [sp, #160]",
    "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]",
    "ldp x26, x27, [sp, #208]",
    "ldp x28, x29, [sp, #224]",
    "ldr x30,      [sp, #240]",
    "add sp, sp, #288",
    "eret",

    // =================================================================
    // sync_el1_stub: Synchronous exception from EL1 (kernel mode)
    //
    // Kernel data abort / instruction abort. Saves minimal context for
    // diagnostics, calls Rust handler which panics with full info.
    // =================================================================
    ".global sync_el1_stub",
    "sync_el1_stub:",
    // Exception entry forces SPSel=1. Switch back to SPSel=0 to use
    // SP_EL0 (the kernel stack that was active before the fault).
    "msr spsel, #0",
    // Save a few registers for the Rust handler arguments
    "stp x29, x30, [sp, #-16]!",
    // x0 = ESR_EL1, x1 = FAR_EL1, x2 = ELR_EL1
    "mrs x0, esr_el1",
    "mrs x1, far_el1",
    "mrs x2, elr_el1",
    "bl fault_el1_inner",
    // fault_el1_inner should not return, but if it does:
    "ldp x29, x30, [sp], #16",
    "eret",
);

/// Rust handler for synchronous exceptions from EL0 (user mode).
///
/// Called for data aborts, instruction aborts, and other non-SVC synchronous
/// exceptions from user space. Terminates the faulting task.
///
/// ## ESR_EL1 Exception Classes
/// - `0x20`: Instruction Abort from lower EL
/// - `0x24`: Data Abort from lower EL
/// - Other: unexpected synchronous exception
#[unsafe(no_mangle)]
extern "C" fn fault_el0_inner(saved_sp: u64, esr: u64) {
    let ec = (esr >> 26) & 0x3F;

    // Read the faulting address from FAR_EL1
    let far: u64;
    // SAFETY: Reading FAR_EL1 at EL1 after a synchronous exception is always valid.
    unsafe {
        core::arch::asm!(
            "mrs {0}, far_el1",
            out(reg) far,
            options(nostack, nomem),
        );
    }

    // Read ELR_EL1 (faulting PC) from the saved frame
    let frame = saved_sp as *const u64;
    // SAFETY: saved_sp points to SavedContext; ELR_EL1 is at offset 248 (index 31).
    let elr = unsafe { core::ptr::read_volatile(frame.add(31)) };

    let ec_name = match ec {
        0x20 => "Instruction Abort (EL0)",
        0x21 => "Instruction Abort (EL1)",
        0x24 => "Data Abort (EL0)",
        0x25 => "Data Abort (EL1)",
        _ => "Synchronous Exception",
    };

    // ISS (Instruction Specific Syndrome) for data/instruction aborts
    let iss = esr & 0x1FFFFFF;
    let is_write = (iss >> 6) & 1 == 1; // WnR bit for data aborts
    let dfsc = iss & 0x3F; // Data Fault Status Code
    let access = if ec == 0x20 { "execute" } else if is_write { "write" } else { "read" };

    let fault_type = match dfsc & 0x3C {
        0x04 => "translation fault",
        0x08 => "access flag fault",
        0x0C => "permission fault",
        _ => "other fault",
    };

    if let Some(task_id) = crate::terminate_current_task() {
        crate::println!(
            "  [Fault] Task {} killed: {} {} {} at {:#x} (PC={:#x}, DFSC={:#x})",
            task_id.0, ec_name, fault_type, access, far, elr, dfsc
        );
        // Yield away immediately. The task is Terminated and will never be
        // re-scheduled, so this loop does not return. Without this, the
        // exception return (eret) goes back to the faulting PC and the
        // task re-faults at hardware speed until the next timer tick.
        loop {
            // SAFETY: We are on the kernel stack, scheduler lock is not held.
            unsafe { crate::arch::yield_save_and_switch(); }
        }
    } else {
        crate::println!(
            "  [Fault] {} at {:#x} (PC={:#x}) but no current task",
            ec_name, far, elr
        );
    }
}

/// Rust handler for synchronous exceptions from EL1 (kernel mode).
///
/// Kernel-mode faults are unrecoverable — print diagnostics and halt.
#[unsafe(no_mangle)]
extern "C" fn fault_el1_inner(esr: u64, far: u64, elr: u64) {
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x1FFFFFF;
    let dfsc = iss & 0x3F;
    let is_write = (iss >> 6) & 1 == 1;

    let ec_name = match ec {
        0x20 => "Instruction Abort (EL0→EL1)",
        0x21 => "Instruction Abort (EL1)",
        0x24 => "Data Abort (EL0→EL1)",
        0x25 => "Data Abort (EL1)",
        0x00 => "Unknown",
        0x15 => "SVC (unexpected in EL1 sync)",
        0x2F => "SError",
        _ => "Other Synchronous Exception",
    };

    let access = if ec == 0x20 || ec == 0x21 { "execute" } else if is_write { "write" } else { "read" };

    crate::println!(
        "\n!!! KERNEL FAULT !!!\n  Type: {} (EC={:#x})\n  Address: {:#x}\n  PC: {:#x}\n  Access: {}\n  DFSC: {:#x}\n  ESR: {:#x}",
        ec_name, ec, far, elr, access, dfsc, esr
    );
    crate::halt();
}

// ============================================================================
// SavedContext field indices (for pointer-offset access)
// ============================================================================

/// Index of ELR_EL1 in SavedContext (gpr[0..31] then elr_el1 at index 31).
const SAVED_CTX_ELR_INDEX: usize = 31;
/// Index of SPSR_EL1 in SavedContext (index 32).
const SAVED_CTX_SPSR_INDEX: usize = 32;
/// Index of SP_EL0 in SavedContext (index 33).
const SAVED_CTX_SP_EL0_INDEX: usize = 33;

/// PL011 UART physical base address (QEMU virt machine).
const PL011_PHYS: u64 = 0x0900_0000;

/// Debug diagnostic: log the first few context switches via raw PL011 UART.
///
/// Only compiled in debug builds. Reads ELR and SP_EL0 from the new task's
/// SavedContext and prints them as hex. Bypasses the serial lock because
/// this runs inside the timer ISR with interrupts masked.
#[cfg(debug_assertions)]
fn debug_log_context_switch(current_sp: u64, new_sp: u64) {
    /// Maximum number of context switches to log before going silent.
    const MAX_DEBUG_SWITCHES: u32 = 5;

    if new_sp == current_sp {
        return;
    }

    static DBG_N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let n = DBG_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n >= MAX_DEBUG_SWITCHES {
        return;
    }

    let ctx = new_sp as *const u64;
    // SAFETY: new_sp points to a valid SavedContext on a kernel stack.
    // The SavedContext has 34 u64 fields (gpr[31], elr, spsr, sp_el0),
    // so indices 31..33 are within bounds.
    let elr = unsafe { *ctx.add(SAVED_CTX_ELR_INDEX) };
    let sp_el0 = unsafe { *ctx.add(SAVED_CTX_SP_EL0_INDEX) };

    let hhdm = crate::hhdm_offset();
    // SAFETY: PL011 UART is mapped into the HHDM at early boot via
    // early_map_mmio(). write_volatile is used because the UART data
    // register is a memory-mapped I/O port.
    let uart = (PL011_PHYS + hhdm) as *mut u32;

    /// Write a byte string to PL011 UART.
    ///
    /// # Safety
    /// `uart` must point to a valid, mapped PL011 data register.
    unsafe fn uart_write_bytes(uart: *mut u32, bytes: &[u8]) {
        for &b in bytes {
            // SAFETY: caller guarantees `uart` points to a valid, mapped PL011 data register.
            unsafe { core::ptr::write_volatile(uart, b as u32) };
        }
    }

    /// Write a u64 value as 16-digit lowercase hex to PL011 UART.
    ///
    /// # Safety
    /// `uart` must point to a valid, mapped PL011 data register.
    unsafe fn uart_write_hex64(uart: *mut u32, val: u64) {
        for i in (0..16).rev() {
            let nibble = ((val >> (i * 4)) & 0xF) as u8;
            let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
            // SAFETY: caller guarantees `uart` points to a valid, mapped PL011 data register.
            unsafe { core::ptr::write_volatile(uart, ch as u32) };
        }
    }

    // SAFETY: UART is mapped (see above). Called from ISR with interrupts masked.
    unsafe {
        uart_write_bytes(uart, b"\n[SW] ");
        uart_write_hex64(uart, sp_el0);
        uart_write_bytes(uart, b" elr=");
        uart_write_hex64(uart, elr);
        uart_write_bytes(uart, b"\n");
    }
}

/// Rust handler called from the timer ISR stub.
///
/// Receives the current task's saved SP (pointing to SavedContext on stack).
/// Returns the SP to restore from — same value if no switch, or a different
/// task's SavedContext SP if a context switch is needed.
///
/// Delegates portable tick/schedule logic to `scheduler::on_timer_isr()`,
/// then performs AArch64-specific post-switch work (SP_EL1, TTBR0_EL1, GIC EOI).
#[unsafe(no_mangle)]
extern "C" fn timer_isr_inner(current_sp: u64) -> u64 {
    let (new_sp, hint) = crate::scheduler::on_timer_isr(current_sp);

    // Debug diagnostic: log first few context switches (debug builds only).
    #[cfg(debug_assertions)]
    debug_log_context_switch(current_sp, new_sp);

    // AArch64-specific post-switch: update kernel stack and TTBR0 (page table)
    if let Some(ref hint) = hint {
        if hint.kernel_stack_top != 0 {
            // SAFETY: Called from IRQ handler at EL1 with interrupts masked.
            // hint.kernel_stack_top is the top of the next task's kernel stack.
            unsafe { gdt::set_kernel_stack(hint.kernel_stack_top); }
        }
        if hint.page_table_root != 0 {
            // SAFETY: Reading TTBR0_EL1 is always safe at EL1.
            // Writing TTBR0_EL1 switches the user address space; the
            // hint.page_table_root was validated by the scheduler.
            unsafe {
                let current_ttbr0: u64;
                core::arch::asm!(
                    "mrs {0}, ttbr0_el1",
                    out(reg) current_ttbr0,
                    options(nostack, nomem),
                );
                if current_ttbr0 != hint.page_table_root {
                    // SAFETY: hint.page_table_root is a valid user page table
                    // physical address. After writing TTBR0_EL1, we must
                    // invalidate TLB entries to flush stale translations from
                    // the previous address space. Without this, the CPU may
                    // use cached translations and fault on valid pages.
                    core::arch::asm!(
                        "msr ttbr0_el1, {0}",
                        "isb",
                        "tlbi vmalle1",     // Invalidate all EL0/EL1 TLB entries
                        "dsb ish",          // Ensure TLB invalidation completes
                        "isb",              // Synchronize context
                        in(reg) hint.page_table_root,
                        options(nostack),
                    );
                }
            }
        }
    }

    // Acknowledge the interrupt (read ICC_IAR1_EL1 to get INTID).
    // GICv3 requires acknowledge before EOI — without this, the interrupt
    // stays active and the GIC won't deliver the next one.
    // SAFETY: We are in an IRQ handler at EL1.
    let intid = unsafe { gic::acknowledge_irq() };

    // Rearm the timer for the next period (ARM Generic Timer is one-shot countdown)
    // SAFETY: We are in a timer IRQ handler at EL1.
    unsafe {
        timer::rearm();
    }

    // Send End-of-Interrupt to GIC (uses the INTID from acknowledge_irq)
    // SAFETY: We are in an IRQ handler after acknowledge_irq().
    unsafe {
        gic::write_eoi();
    }

    // Spurious interrupt (INTID 1023): return without context switch
    if intid >= 1020 {
        return current_sp;
    }

    new_sp
}

// ============================================================================
// SVC handler (syscall from EL0)
// ============================================================================

/// Rust handler for SVC (syscall) from EL0.
///
/// Called from `sync_el0_stub` after ESR_EL1 EC=0x15 was verified.
/// `saved_sp` points to the SavedContext frame on the kernel stack.
/// Returns the syscall result value (written into saved x0 by assembly).
///
/// # AArch64 syscall register convention (Linux-compatible)
///
/// | Register | Role                                        |
/// |----------|---------------------------------------------|
/// | x8       | Syscall number                              |
/// | x0-x5    | Arguments 1-6                               |
/// | x0       | Return value (output)                       |
#[unsafe(no_mangle)]
extern "C" fn svc_handler_inner(saved_sp: u64) -> u64 {
    // SAFETY: saved_sp points to the SavedContext built by sync_el0_stub.
    // The frame has gpr[0..31] at offsets 0..248, elr_el1 at 248,
    // spsr_el1 at 256, sp_el0 at 264.
    let frame = saved_sp as *const u64;

    // SAFETY: frame points to the SavedContext with 31 u64 GPRs starting at
    // offset 0. x8 is at index 8, x0-x5 at indices 0-5.
    let syscall_num = unsafe { core::ptr::read_volatile(frame.add(8)) };  // x8
    let arg1 = unsafe { core::ptr::read_volatile(frame.add(0)) };         // x0
    let arg2 = unsafe { core::ptr::read_volatile(frame.add(1)) };         // x1
    let arg3 = unsafe { core::ptr::read_volatile(frame.add(2)) };         // x2
    let arg4 = unsafe { core::ptr::read_volatile(frame.add(3)) };         // x3
    let arg5 = unsafe { core::ptr::read_volatile(frame.add(4)) };         // x4
    let arg6 = unsafe { core::ptr::read_volatile(frame.add(5)) };         // x5

    use crate::syscalls::{SyscallArgs, SyscallError};
    use crate::syscalls::dispatcher::{SyscallContext, SyscallDispatcher};
    use crate::ipc::ProcessId;

    // Look up the calling task and its metadata from the per-CPU scheduler
    let (task_id, process_id, cr3) = {
        let sched = crate::local_scheduler().lock();
        match sched.as_ref().and_then(|s| {
            let tid = s.current_task()?;
            let task = s.current_task_ref()?;
            let pid = task.process_id.unwrap_or(ProcessId::new(tid.0 as u32, 0));
            Some((tid, pid, task.cr3))
        }) {
            Some(info) => info,
            None => return SyscallError::InvalidArg as i64 as u64,
        }
    };

    let ctx = SyscallContext {
        process_id,
        task_id,
        cr3,
        caller_principal: None, // resolved in dispatch()
    };

    let args = SyscallArgs::new(arg1, arg2, arg3, arg4, arg5, arg6);

    // SYS_EXIT is handled by handle_exit(), which loops on
    // yield_save_and_switch() and never returns. Other blocking syscalls
    // (recv_msg, wait_irq) yield internally and return when woken.
    let result = match SyscallDispatcher::dispatch(syscall_num, args, ctx) {
        Ok(val) => val as i64,
        Err(e) => e.as_i64(),
    };

    result as u64
}

/// Halt with interrupts enabled until preempted by the timer ISR.
///
/// Switches to the given kernel stack before enabling interrupts.
/// The SVC handler may run on the user stack (SP_EL0). If the timer ISR's
/// TTBR0 switch ran on the user stack, the page table change would remap
/// the stack to different physical memory. The kernel stack is in the
/// HHDM, which is mapped identically across all page tables.
///
/// # Safety
/// `kernel_stack_top` must be a valid, mapped kernel stack address (HHDM).
/// The scheduler lock must NOT be held.
pub fn halt_until_preempted(kernel_stack_top: u64) -> ! {
    // SAFETY: Caller guarantees kernel_stack_top is valid HHDM-mapped memory.
    // Switching SP and unmasking IRQs is safe because the timer ISR will
    // eventually preempt us, and the kernel stack is in the HHDM (identity-
    // mapped across all page tables).
    unsafe {
        core::arch::asm!(
            "mov sp, {kstack}",
            "2:",
            "msr daifclr, #2",
            "wfi",
            "b 2b",
            kstack = in(reg) kernel_stack_top,
            options(noreturn),
        );
    }
}

// ============================================================================
// Voluntary context switch — yield_save_and_switch
// ============================================================================
//
// Assembly trampoline for voluntary context switching from syscall handlers.
//
// Builds a synthetic SavedContext (identical layout to the timer ISR's) on the
// kernel stack, calls yield_inner (Rust) to save it and schedule the next task,
// then restores from the (potentially different) SavedContext and does eret.
//
// When the yielding task is later re-scheduled (by the timer ISR or another
// yield_save_and_switch), eret goes to .Lyield_resume, which re-enables
// interrupts and returns to the syscall handler that called us.
//
// Stack layout after the sub (SavedContext, low → high):
//   [sp+0]     x0               ← SP points here (arg to yield_inner)
//   [sp+8]     x1
//   ...
//   [sp+240]   x30
//   [sp+248]   elr_el1          = .Lyield_resume
//   [sp+256]   spsr_el1         = EL1h + DAIF.I masked
//   [sp+264]   sp_el0           = saved user SP
//
// Total frame: 288 bytes (272 payload + 16 padding for alignment).

extern "C" {
    /// Voluntary context switch.
    ///
    /// Saves all registers as a SavedContext on the kernel stack, calls the
    /// scheduler to pick the next task, and restores from the next task's
    /// SavedContext via eret. When the calling task is later re-scheduled,
    /// this function returns normally to its caller.
    ///
    /// # Safety
    /// Must be called on the kernel stack (SP_EL1, not user stack). The caller
    /// must not hold the scheduler lock. Interrupts may be enabled or disabled
    /// on entry — they are masked during the save/switch and re-enabled at
    /// resume.
    pub fn yield_save_and_switch();
}

core::arch::global_asm!(
    ".global yield_save_and_switch",
    "yield_save_and_switch:",

    // ---- Mask IRQs for atomic save ----
    "msr daifset, #2",

    // ---- Read SP_EL0 via SPSel toggle ----
    // Save x0 temporarily on the kernel stack, read SP_EL0, restore x0.
    // We use the SPSel toggle because QEMU traps mrs/msr SP_EL0 directly.
    "str x0,  [sp, #-16]!",       // push x0 (pre-decrement SP_EL1)
    "msr spsel, #0",               // SP = SP_EL0
    "mov x0, sp",                  // x0 = SP_EL0 value
    "msr spsel, #1",               // SP = SP_EL1 (back to kernel stack)
    "str x0,  [sp, #8]",          // save SP_EL0 next to x0
    "ldr x0,  [sp], #16",         // restore x0, pop temp area

    // ---- Allocate SavedContext (288 bytes, 16-aligned) ----
    "sub sp, sp, #288",

    // ---- Save x0-x30 ----
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "str x30,      [sp, #240]",

    // ---- Save synthetic system registers ----
    // ELR_EL1 = .Lyield_resume (where eret will return to)
    "adr x2, .Lyield_resume",
    "str x2, [sp, #248]",          // elr_el1

    // SPSR_EL1 = EL1h (0x5) + IRQ masked (bit 7) + FIQ masked (bit 6)
    // D and A left unmasked for normal kernel operation.
    // Resume label will unmask I.
    "mov x2, #0xC5",
    "str x2, [sp, #256]",          // spsr_el1

    // SP_EL0 from temp save area above the frame (entry_sp - 8 = sp + 280)
    "ldr x2, [sp, #280]",
    "str x2, [sp, #264]",          // sp_el0

    // ---- Call Rust scheduler ----
    // x0 = pointer to SavedContext (identical layout to timer ISR's)
    "mov x0, sp",
    "bl yield_inner",
    // x0 = new SP (same or different task's SavedContext)

    // ---- Restore from (potentially new) SavedContext ----
    "mov sp, x0",

    // Restore system registers
    "ldr x2, [sp, #248]",          // elr_el1
    "ldr x3, [sp, #256]",          // spsr_el1
    "ldr x4, [sp, #264]",          // sp_el0
    "msr elr_el1, x2",
    "msr spsr_el1, x3",
    // Restore SP_EL0 via SPSel toggle (same technique as timer_isr_stub)
    "msr spsel, #0",               // SP = SP_EL0
    "mov sp, x4",                  // SP_EL0 = saved value
    "msr spsel, #1",               // SP = SP_EL1 (back to SavedContext)

    // Restore x0-x30
    "ldp x0,  x1,  [sp, #0]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x20, x21, [sp, #160]",
    "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]",
    "ldp x26, x27, [sp, #208]",
    "ldp x28, x29, [sp, #224]",
    "ldr x30,      [sp, #240]",
    // Deallocate SavedContext frame
    "add sp, sp, #288",
    // Return from exception — eret restores PC and PSTATE from ELR/SPSR
    "eret",

    // ---- Resume point for yielded tasks ----
    // eret restores: PC = here, PSTATE = EL1h + DAIF.I masked.
    // Re-enable interrupts (handler was running with IRQs enabled before yield).
    ".Lyield_resume:",
    "msr daifclr, #2",             // unmask IRQs
    "ret",                          // return to caller of yield_save_and_switch
);

/// Rust handler for voluntary context switch.
///
/// Called from `yield_save_and_switch` assembly. Receives the current task's
/// SavedContext SP, saves it, calls schedule(), and returns the next task's
/// SavedContext SP. Performs AArch64-specific post-switch (SP_EL1, TTBR0_EL1).
///
/// Does NOT send GIC EOI — this is a voluntary switch, not a hardware interrupt.
#[unsafe(no_mangle)]
extern "C" fn yield_inner(current_sp: u64) -> u64 {
    let (new_sp, hint) = crate::scheduler::on_voluntary_yield(current_sp);

    // AArch64-specific post-switch: update kernel stack and TTBR0 (page table)
    // (same as timer_isr_inner, minus GIC acknowledge/EOI and timer rearm)
    if let Some(hint) = hint {
        if hint.kernel_stack_top != 0 {
            // SAFETY: Called with interrupts masked (daifset in trampoline).
            // hint.kernel_stack_top is the next task's kernel stack top.
            unsafe { gdt::set_kernel_stack(hint.kernel_stack_top); }
        }
        if hint.page_table_root != 0 {
            // SAFETY: Reading TTBR0_EL1 is always safe at EL1. Writing
            // TTBR0_EL1 switches user page tables; hint.page_table_root
            // was validated by the scheduler. Interrupts are disabled.
            unsafe {
                let current_ttbr0: u64;
                core::arch::asm!(
                    "mrs {0}, ttbr0_el1",
                    out(reg) current_ttbr0,
                    options(nostack, nomem),
                );
                if current_ttbr0 != hint.page_table_root {
                    // SAFETY: hint.page_table_root is a valid user page table
                    // physical address. TLB invalidation required after switch.
                    core::arch::asm!(
                        "msr ttbr0_el1, {0}",
                        "isb",
                        "tlbi vmalle1",
                        "dsb ish",
                        "isb",
                        in(reg) hint.page_table_root,
                        options(nostack),
                    );
                }
            }
        }
    }

    new_sp
}
