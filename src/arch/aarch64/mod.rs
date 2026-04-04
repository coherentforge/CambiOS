//! Architecture-specific code (AArch64)
//!
//! Scaffold module matching the x86_64 public API so that portable code
//! (scheduler, loader, syscalls) compiles on both targets. All functions
//! are stubs that `todo!()` at runtime — this is compile-only scaffolding.
//!
//! ## AArch64 equivalents of x86_64 concepts
//!
//! | x86_64             | AArch64                | Notes                       |
//! |--------------------|------------------------|-----------------------------|
//! | GDT + TSS          | EL1/EL0 configuration  | Exception levels, not segs  |
//! | IDT                | VBAR_EL1 vector table   | 4 entries × 4 types         |
//! | SYSCALL/SYSRET     | SVC / ERET             | Synchronous exception       |
//! | Local APIC         | GICv3 redistributor    | Per-CPU interrupt ctrl      |
//! | I/O APIC           | GICv3 distributor      | Shared interrupt routing     |
//! | CR3 (PML4)         | TTBR0_EL1 / TTBR1_EL1 | User / kernel page tables   |
//! | IRETQ              | ERET                   | Return from exception       |
//! | HLT                | WFI                    | Wait for interrupt          |
//! | GS base (percpu)   | TPIDR_EL1              | Per-CPU data pointer        |
//! | TLB shootdown IPI  | TLBI broadcast         | Hardware-assisted on v8.4+  |

// Submodule stubs — AArch64 equivalents of x86_64 peripherals
pub mod gic;
pub mod percpu;
pub mod syscall;
pub mod tlb;

/// GDT compatibility shim.
///
/// AArch64 has no GDT — privilege is managed via exception levels (EL0/EL1).
/// These constants exist so that `loader/mod.rs` compiles without cfg-gating
/// every SavedContext construction site.
pub mod gdt {
    /// User code "selector" — placeholder (AArch64 uses EL0)
    pub const USER_CS: u16 = 0;
    /// User stack "selector" — placeholder (AArch64 uses EL0)
    pub const USER_SS: u16 = 0;
    /// Kernel code "selector" — placeholder (AArch64 uses EL1)
    pub const KERNEL_CS: u16 = 0;
    /// Kernel stack "selector" — placeholder (AArch64 uses EL1)
    pub const KERNEL_SS: u16 = 0;

    /// Set the kernel stack pointer for exception return.
    ///
    /// On AArch64, this would configure SP_EL1 or the exception stack.
    ///
    /// # Safety
    /// Must be called from EL1 with interrupts masked.
    pub unsafe fn set_kernel_stack(_stack_top: u64) {
        todo!("AArch64: configure SP_EL1 for kernel stack")
    }
}

use crate::scheduler::CpuContext;
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Context switch primitives (stubs — will be AArch64 assembly)
// ============================================================================

/// Save current CPU context.
///
/// AArch64 implementation will use `stp` to save x19-x30 (callee-saved),
/// `mrs` to read SP, LR, and NZCV flags.
///
/// # Safety
/// `ctx` must point to valid, writeable memory for a `CpuContext`.
pub unsafe fn context_save(_ctx: *mut CpuContext) {
    todo!("AArch64: save x19-x30, sp, lr, nzcv")
}

/// Restore CPU context and resume execution. Does not return.
///
/// AArch64 implementation will use `ldp` to restore x19-x30,
/// `msr` to set SP/ELR_EL1/SPSR_EL1, then `eret`.
///
/// # Safety
/// `ctx` must point to a valid, previously saved `CpuContext`.
pub unsafe fn context_restore(_ctx: *const CpuContext) -> ! {
    todo!("AArch64: restore x19-x30, sp, lr, eret")
}

/// Save current context, restore next context, resume next. Does not return.
///
/// AArch64 equivalent of save + restore in a single sequence.
///
/// # Safety
/// Both pointers must be valid. `current_ctx` must be writable.
pub unsafe fn context_switch(_current_ctx: *mut CpuContext, _next_ctx: *const CpuContext) -> ! {
    todo!("AArch64: save current, restore next, eret")
}

// ============================================================================
// SavedContext — interrupt frame for preemptive switching
// ============================================================================

/// Saved register state for interrupt-driven context switches.
///
/// Field names match x86_64 for compile compatibility with portable code
/// (loader, scheduler). On AArch64, the real implementation will store:
///
/// | Field (x86 name) | AArch64 mapping        |
/// |-------------------|------------------------|
/// | r15..rax (15 GP)  | x0-x30 (31 GP)         |
/// | rip               | ELR_EL1 (return PC)    |
/// | cs                | unused (0)             |
/// | rflags            | SPSR_EL1 (saved PSTATE)|
/// | rsp               | SP_EL0 (user stack)    |
/// | ss                | unused (0)             |
///
/// When the real AArch64 context switch is implemented, this struct will
/// be replaced with a proper 31-register layout.
#[repr(C)]
pub struct SavedContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
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
pub fn saved_to_cpu_context(saved: &SavedContext, cpu: &mut CpuContext) {
    cpu.rax = saved.rax;
    cpu.rbx = saved.rbx;
    cpu.rcx = saved.rcx;
    cpu.rdx = saved.rdx;
    cpu.rsi = saved.rsi;
    cpu.rdi = saved.rdi;
    cpu.rbp = saved.rbp;
    cpu.r8 = saved.r8;
    cpu.r9 = saved.r9;
    cpu.r10 = saved.r10;
    cpu.r11 = saved.r11;
    cpu.r12 = saved.r12;
    cpu.r13 = saved.r13;
    cpu.r14 = saved.r14;
    cpu.r15 = saved.r15;
    cpu.rip = saved.rip;
    cpu.rsp = saved.rsp;
    cpu.rflags = saved.rflags;
}

/// Copy a CpuContext into a SavedContext (for restoring on exception return).
pub fn cpu_to_saved_context(cpu: &CpuContext, saved: &mut SavedContext) {
    saved.rax = cpu.rax;
    saved.rbx = cpu.rbx;
    saved.rcx = cpu.rcx;
    saved.rdx = cpu.rdx;
    saved.rsi = cpu.rsi;
    saved.rdi = cpu.rdi;
    saved.rbp = cpu.rbp;
    saved.r8 = cpu.r8;
    saved.r9 = cpu.r9;
    saved.r10 = cpu.r10;
    saved.r11 = cpu.r11;
    saved.r12 = cpu.r12;
    saved.r13 = cpu.r13;
    saved.r14 = cpu.r14;
    saved.r15 = cpu.r15;
    saved.rip = cpu.rip;
    saved.rsp = cpu.rsp;
    saved.rflags = cpu.rflags;
    saved.cs = 0;
    saved.ss = 0;
}
