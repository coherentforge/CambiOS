//! Architecture-specific code (x86-64)
//!
//! Implements CPU-specific primitives like context switching,
//! register manipulation, and interrupt control.
//!
//! ## Context Switch Architecture
//!
//! Two context switch paths exist:
//!
//! 1. **Explicit switch** (`context_switch`): Used for voluntary yields and blocking.
//!    Saves all registers, jumps to target task. Never returns.
//!
//! 2. **Interrupt-driven switch** (`timer_isr_stub`): Used for preemption.
//!    Assembly ISR stub saves full register state to the current task's `SavedContext`,
//!    calls a Rust handler that may swap the context pointer, then restores from
//!    the (potentially different) context and does `iretq`.

pub mod spinlock;

use crate::scheduler::CpuContext;
use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

/// Save current CPU context to a CpuContext structure
///
/// Captures all general-purpose registers and control registers.
/// This is called from the scheduler to preserve task state during
/// context switches.
#[inline(never)]
pub unsafe fn context_save(ctx: *mut CpuContext) {
    // Get return address (will become RIP when we context switch back)
    let rip: u64;
    asm!("mov {}, [rsp]", out(reg) rip);
    
    // Get current stack pointer (after return address)
    let rsp: u64;
    asm!("lea {}, [rsp + 8]", out(reg) rsp);
    
    // Read RFLAGS
    let rflags: u64;
    asm!("pushfq; pop {}", out(reg) rflags);
    
    // Save all GP registers to memory locations
    // Using memory addressing instead of register constraints to avoid LLVM limitations
    asm!(
        "mov [{ctx}], rax",
        "mov [{ctx} + 8], rbx",
        "mov [{ctx} + 16], rcx",
        "mov [{ctx} + 24], rdx",
        "mov [{ctx} + 32], rsi",
        "mov [{ctx} + 40], rdi",
        "mov [{ctx} + 48], rbp",
        "mov [{ctx} + 56], r8",
        "mov [{ctx} + 64], r9",
        "mov [{ctx} + 72], r10",
        "mov [{ctx} + 80], r11",
        "mov [{ctx} + 88], r12",
        "mov [{ctx} + 96], r13",
        "mov [{ctx} + 104], r14",
        "mov [{ctx} + 112], r15",
        ctx = in(reg) ctx,
    );
    
    // Save control registers
    ptr::write(&mut (*ctx).rip, rip);
    ptr::write(&mut (*ctx).rsp, rsp);
    ptr::write(&mut (*ctx).rflags, rflags);
}

/// Restore CPU context from a CpuContext structure and jump to saved RIP
///
/// Loads all general-purpose registers and control registers from
/// a saved context, then jumps to the saved instruction pointer.
/// This function does NOT return normally.
#[inline(never)]
pub unsafe fn context_restore(ctx: *const CpuContext) -> ! {
    let new_rsp = (*ctx).rsp;
    let new_rip = (*ctx).rip;
    let new_rflags = (*ctx).rflags;
    
    // Restore all GP registers from memory at ctx
    asm!(
        "mov rax, [{ctx}]",
        "mov rbx, [{ctx} + 8]",
        "mov rcx, [{ctx} + 16]",
        "mov rdx, [{ctx} + 24]",
        "mov rsi, [{ctx} + 32]",
        "mov rdi, [{ctx} + 40]",
        "mov rbp, [{ctx} + 48]",
        "mov r8, [{ctx} + 56]",
        "mov r9, [{ctx} + 64]",
        "mov r10, [{ctx} + 72]",
        "mov r11, [{ctx} + 80]",
        "mov r12, [{ctx} + 88]",
        "mov r13, [{ctx} + 96]",
        "mov r14, [{ctx} + 104]",
        "mov r15, [{ctx} + 112]",
        ctx = in(reg) ctx,
    );
    
    // Set up stack, restore flags, and jump to RIP
    asm!(
        "mov rsp, {rsp}",
        "push {rflags}",
        "popfq",
        "jmp {rip}",
        rsp = in(reg) new_rsp,
        rflags = in(reg) new_rflags,
        rip = in(reg) new_rip,
        options(noreturn)
    );
}

/// Perform atomic context switch from current to next task
///
/// Saves current task's context, then restores and jumps to next task.
#[inline(never)]
pub unsafe fn context_switch(current_ctx: *mut CpuContext, next_ctx: *const CpuContext) -> ! {
    // Save current task
    context_save(current_ctx);
    // Jump to next task
    context_restore(next_ctx);
}

// ============================================================================
// Interrupt-driven context switching
// ============================================================================

/// Saved register state for interrupt context switches
///
/// When the timer ISR fires, the CPU pushes SS, RSP, RFLAGS, CS, RIP onto the
/// interrupted task's stack. The ISR stub then pushes all GP registers.
/// This struct represents that saved state, laid out to match the push order.
#[repr(C)]
pub struct SavedContext {
    // Pushed by ISR stub (in reverse order of push)
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
    // Pushed by CPU on interrupt entry
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Pointer to the current task's SavedContext on its kernel stack.
/// The timer ISR handler sets this to point to a different task's context
/// when a context switch is needed.
///
/// Accessed from assembly — must be a fixed address.
/// 0 = no context switch pending (restore from same stack).
static SWITCH_CONTEXT_PTR: AtomicU64 = AtomicU64::new(0);

/// Set the context pointer for the next iretq
///
/// Called by the Rust timer handler when a context switch is needed.
/// The assembly ISR stub reads this to decide where to restore from.
pub fn set_switch_context(ctx: *const SavedContext) {
    SWITCH_CONTEXT_PTR.store(ctx as u64, Ordering::Release);
}

/// Clear the context switch pointer (no switch pending)
pub fn clear_switch_context() {
    SWITCH_CONTEXT_PTR.store(0, Ordering::Release);
}

/// Get the pending context switch pointer (0 = no switch)
pub fn get_switch_context() -> u64 {
    SWITCH_CONTEXT_PTR.load(Ordering::Acquire)
}

/// Copy a SavedContext into a CpuContext (for scheduler task tracking)
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

/// Copy a CpuContext into a SavedContext (for restoring on iretq)
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
    saved.cs = 0x08;  // Kernel code segment
    saved.ss = 0x10;  // Kernel data segment
}