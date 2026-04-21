// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

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

pub mod apic;
pub mod gdt;
pub mod ioapic;
pub mod msr;
pub mod percpu;
pub mod portio;
pub mod syscall;
pub mod tlb;

use crate::scheduler::CpuContext;
use core::sync::atomic::{AtomicU64, Ordering};

/// Read the current CPU's interrupt-enable state.
///
/// Returns `true` if maskable interrupts are enabled (RFLAGS.IF set).
/// Used by portable `debug_assert!` at call sites that require interrupts
/// masked — see CLAUDE.md § Timer / Preemptive Scheduling for the
/// blocking pattern.
#[cfg(target_os = "none")]
#[inline]
pub fn interrupts_enabled() -> bool {
    let rflags: u64;
    // SAFETY: pushfq/pop is a pure read of RFLAGS; nomem + preserves_flags
    // tell the compiler no memory or flags side-effects occur.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            out(reg) rflags,
            options(nomem, preserves_flags),
        );
    }
    (rflags & (1 << 9)) != 0 // RFLAGS.IF
}

/// Host-test stub. On `x86_64-apple-darwin` the kernel interrupt model
/// doesn't apply; return `false` so `debug_assert!(!interrupts_enabled())`
/// passes silently under `cargo test --lib`.
#[cfg(not(target_os = "none"))]
#[inline]
pub fn interrupts_enabled() -> bool {
    false
}

// ============================================================================
// Explicit context switch primitives (global_asm — no compiler interference)
// ============================================================================
//
// These are pure assembly, called via the SysV x86-64 C ABI:
//   rdi = first arg, rsi = second arg, return via ret
//
// CpuContext field offsets (#[repr(C)] — guaranteed sequential layout):
//   rax=0, rbx=8, rcx=16, rdx=24, rsi=32, rdi=40, rbp=48,
//   r8=56, r9=64, r10=72, r11=80, r12=88, r13=96, r14=104, r15=112,
//   rip=120, rsp=128, rflags=136

extern "C" {
    /// Save current context to a CpuContext structure. Returns normally.
    ///
    /// Captures callee-saved registers (rbx, rbp, r12-r15), RIP (return
    /// address), RSP (caller's stack pointer), and RFLAGS. Caller-saved
    /// registers (rax, rcx, rdx, rsi, rdi, r8-r11) are zeroed in the
    /// struct since they're not preserved across function calls.
    ///
    /// When this saved context is later restored via `context_restore`,
    /// execution resumes at the instruction after the `context_save` call.
    pub fn context_save(ctx: *mut CpuContext);

    /// Restore all registers from a CpuContext and jump to saved RIP.
    ///
    /// Does NOT return. Switches RSP to the saved stack, restores all 15
    /// GPRs and RFLAGS, then `ret`s to the saved RIP.
    pub fn context_restore(ctx: *const CpuContext) -> !;

    /// Save current context, then restore and jump to next context.
    ///
    /// Equivalent to `context_save(current)` + `context_restore(next)` but
    /// as a single assembly sequence with no compiler-managed code between.
    /// Does not return from the current invocation. When the saved task is
    /// later restored (by another `context_switch` or `context_restore`),
    /// this function appears to return normally to its caller.
    pub fn context_switch(current_ctx: *mut CpuContext, next_ctx: *const CpuContext) -> !;
}

#[cfg(not(any(fuzzing, test)))]
core::arch::global_asm!(
    // =================================================================
    // context_save(ctx: *mut CpuContext)
    // SysV ABI: rdi = ctx
    // =================================================================
    ".global context_save",
    "context_save:",
    // Callee-saved GPRs — the only ones meaningful in a function body
    "mov [rdi + 8], rbx",
    "mov [rdi + 48], rbp",
    "mov [rdi + 88], r12",
    "mov [rdi + 96], r13",
    "mov [rdi + 104], r14",
    "mov [rdi + 112], r15",
    // RIP = return address sitting on the stack (pushed by `call`)
    "mov rax, [rsp]",
    "mov [rdi + 120], rax",
    // RSP = caller's stack pointer (after `ret` pops the return address)
    "lea rax, [rsp + 8]",
    "mov [rdi + 128], rax",
    // RFLAGS (pushfq/pop is balanced — net stack effect zero)
    "pushfq",
    "pop rax",
    "mov [rdi + 136], rax",
    // Zero caller-saved slots (not preserved by the calling convention)
    "xor eax, eax",
    "mov [rdi], rax",
    "mov [rdi + 16], rax",
    "mov [rdi + 24], rax",
    "mov [rdi + 32], rax",
    "mov [rdi + 40], rax",
    "mov [rdi + 56], rax",
    "mov [rdi + 64], rax",
    "mov [rdi + 72], rax",
    "mov [rdi + 80], rax",
    "ret",

    // =================================================================
    // context_restore(ctx: *const CpuContext)
    // SysV ABI: rdi = ctx.  Does not return.
    //
    // Strategy: switch RSP first, stage rip+rflags on the new stack,
    // restore all GPRs (rdi last since it's our base pointer), popfq, ret.
    // =================================================================
    ".global context_restore",
    "context_restore:",
    "mov rsp, [rdi + 128]",       // Switch to target stack
    "mov rax, [rdi + 120]",       // rip
    "push rax",                    // [rsp] = target rip (for ret)
    "mov rax, [rdi + 136]",       // rflags
    "push rax",                    // [rsp] = rflags, [rsp+8] = rip
    // Restore all 15 GPRs.  rdi is restored last because it holds ctx.
    "mov rax, [rdi]",
    "mov rbx, [rdi + 8]",
    "mov rcx, [rdi + 16]",
    "mov rdx, [rdi + 24]",
    "mov rsi, [rdi + 32]",
    // rdi restored below
    "mov rbp, [rdi + 48]",
    "mov r8,  [rdi + 56]",
    "mov r9,  [rdi + 64]",
    "mov r10, [rdi + 72]",
    "mov r11, [rdi + 80]",
    "mov r12, [rdi + 88]",
    "mov r13, [rdi + 96]",
    "mov r14, [rdi + 104]",
    "mov r15, [rdi + 112]",
    "mov rdi, [rdi + 40]",        // Destroys base pointer — must be last
    "popfq",                       // Restore RFLAGS
    "ret",                         // Pop rip, jump to target

    // =================================================================
    // context_switch(current: *mut CpuContext, next: *const CpuContext)
    // SysV ABI: rdi = current, rsi = next.  Does not return.
    // =================================================================
    ".global context_switch",
    "context_switch:",
    // --- Save current task (rdi) ---
    "mov [rdi + 8], rbx",
    "mov [rdi + 48], rbp",
    "mov [rdi + 88], r12",
    "mov [rdi + 96], r13",
    "mov [rdi + 104], r14",
    "mov [rdi + 112], r15",
    "mov rax, [rsp]",
    "mov [rdi + 120], rax",
    "lea rax, [rsp + 8]",
    "mov [rdi + 128], rax",
    "pushfq",
    "pop rax",
    "mov [rdi + 136], rax",
    // --- Restore next task (rsi) ---
    "mov rsp, [rsi + 128]",
    "mov rax, [rsi + 120]",
    "push rax",
    "mov rax, [rsi + 136]",
    "push rax",
    "mov rax, [rsi]",
    "mov rbx, [rsi + 8]",
    "mov rcx, [rsi + 16]",
    "mov rdx, [rsi + 24]",
    "mov rdi, [rsi + 40]",
    "mov rbp, [rsi + 48]",
    "mov r8,  [rsi + 56]",
    "mov r9,  [rsi + 64]",
    "mov r10, [rsi + 72]",
    "mov r11, [rsi + 80]",
    "mov r12, [rsi + 88]",
    "mov r13, [rsi + 96]",
    "mov r14, [rsi + 104]",
    "mov r15, [rsi + 112]",
    "mov rsi, [rsi + 32]",        // Destroys base pointer — must be last
    "popfq",
    "ret",
);

// ============================================================================
// Interrupt-driven context switching
// ============================================================================

/// Saved register state for interrupt context switches.
///
/// When the timer ISR fires, the CPU pushes SS, RSP, RFLAGS, CS, RIP.
/// The ISR stub then pushes rax, rbx, ... r15 (each `push` decrements RSP).
///
/// Fields are ordered by ascending memory address.  The last register pushed
/// (r15) ends up at the lowest address, so it's the first field.  The CPU-
/// pushed frame (rip, cs, rflags, rsp, ss) is at the highest addresses.
#[repr(C)]
pub struct SavedContext {
    // GP registers — last pushed is at the lowest address
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
    saved.cs = gdt::KERNEL_CS as u64;
    saved.ss = gdt::KERNEL_SS as u64;
}

// ============================================================================
// Timer ISR stub — naked assembly for preemptive context switching
// ============================================================================
//
// When the PIT timer fires (vector 32), the CPU pushes SS, RSP, RFLAGS, CS, RIP.
// This stub pushes all 15 GPRs to create a full SavedContext on the current stack,
// calls the Rust handler which may decide to switch tasks, then restores registers
// from the (potentially different) SavedContext and returns via iretq.

#[cfg(not(any(fuzzing, test)))]
core::arch::global_asm!(
    ".global timer_isr_stub",
    "timer_isr_stub:",
    // Save all GPRs to form SavedContext (struct fields: r15..rax at offsets 0..112)
    "push rax",
    "push rbx",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push rbp",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // RSP now points to SavedContext. Pass as first arg to Rust handler.
    "mov rdi, rsp",
    "cld",                      // Clear DF per ABI before calling C function
    "call timer_isr_inner",
    // RAX = new RSP (same task or different task's SavedContext)
    "mov rsp, rax",
    // Restore GPRs from (potentially new) SavedContext
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rax",
    // Return to (potentially new) task — pops RIP, CS, RFLAGS, RSP, SS
    "iretq",
);

/// Rust handler called from the timer ISR stub.
///
/// Receives the current task's saved RSP (pointing to SavedContext on its stack).
/// Returns the RSP to restore from — same value if no switch, or a different
/// task's SavedContext RSP if a context switch is needed.
///
/// Delegates portable tick/schedule logic to `scheduler::on_timer_isr()`,
/// then performs x86-specific post-switch work (TSS, CR3, PIC EOI).
#[unsafe(no_mangle)]
extern "C" fn timer_isr_inner(current_rsp: u64) -> u64 {
    let (new_rsp, hint) = crate::scheduler::on_timer_isr(current_rsp);

    // x86-specific post-switch: update TSS and CR3
    if let Some(hint) = hint {
        if hint.kernel_stack_top != 0 {
            // SAFETY: Called from the timer ISR with interrupts disabled.
            // hint.kernel_stack_top is the top of the next task's kernel stack,
            // written during task creation (alloc_task_stack / create_user_task).
            unsafe { crate::arch::gdt::set_kernel_stack(hint.kernel_stack_top); }
        }
        if hint.page_table_root != 0 {
            let current_cr3: u64;
            // SAFETY: Reading CR3 is always safe at ring 0 with interrupts disabled.
            unsafe {
                core::arch::asm!(
                    "mov {}, cr3",
                    out(reg) current_cr3,
                    options(nostack, nomem),
                );
            }
            if current_cr3 != hint.page_table_root {
                // SAFETY: hint.page_table_root is the physical address of a valid
                // PML4 set up by create_process_page_table(). Writing CR3 flushes
                // the TLB and switches address spaces. Kernel mappings (upper half)
                // are shared across all page tables.
                unsafe {
                    core::arch::asm!(
                        "mov cr3, {}",
                        in(reg) hint.page_table_root,
                        options(nostack, preserves_flags),
                    );
                }
            }
        }
    }

    // Send End-of-Interrupt to APIC (MUST happen before iretq)
    // SAFETY: We are in a hardware interrupt handler (vector 32 = timer).
    // SAFETY: APIC is initialized before interrupts are enabled.
    // Writing to the EOI register signals completion of this interrupt.
    unsafe {
        apic::write_eoi();
    }

    new_rsp
}

/// Halt with interrupts enabled until preempted by the timer ISR.
///
/// Used by AArch64 SVC handler for SYS_EXIT (x86_64 now uses
/// `yield_save_and_switch` instead). Kept for AArch64 compatibility.
///
/// # Safety
/// `kernel_stack_top` must be a valid, mapped kernel stack address (HHDM).
/// The scheduler lock must NOT be held.
pub fn halt_until_preempted(kernel_stack_top: u64) -> ! {
    // SAFETY: We switch RSP to a valid kernel stack, then enable interrupts
    // and halt. The timer ISR fires within 10ms (100Hz), detects the
    // Terminated current_task, and context-switches to a Ready task. The
    // ISR's iretq goes to the new task — this code is never resumed.
    //
    // The `noreturn` option tells the compiler this never returns, matching
    // the `-> !` return type.
    unsafe {
        core::arch::asm!(
            "mov rsp, {kstack}",
            "2:",
            "sti",
            "hlt",
            "jmp 2b",
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
// current kernel stack, calls yield_inner (Rust) to save it and schedule the
// next task, then restores from the (potentially different) SavedContext and
// does iretq.
//
// When the yielding task is later re-scheduled (by the timer ISR or another
// yield_save_and_switch), iretq goes to .Lyield_resume, which re-enables
// interrupts and returns to the syscall handler that called us.
//
// Stack layout after the push sequence (SavedContext, low → high):
//   [rsp+0]   r15          ← RSP points here (arg to yield_inner)
//   [rsp+8]   r14
//   ...
//   [rsp+112] rax
//   [rsp+120] rip          = .Lyield_resume
//   [rsp+128] cs           = current CS (KERNEL_CS)
//   [rsp+136] rflags       (IF=0, saved under cli)
//   [rsp+144] rsp          = entry RSP (caller's stack with return address)
//   [rsp+152] ss           = current SS (KERNEL_SS)

extern "C" {
    /// Voluntary context switch.
    ///
    /// Saves all registers as a SavedContext on the kernel stack, calls the
    /// scheduler to pick the next task, and restores from the next task's
    /// SavedContext via iretq. When the calling task is later re-scheduled,
    /// this function returns normally to its caller.
    ///
    /// # Safety
    /// Must be called on the kernel stack (not user stack). The caller must
    /// not hold the scheduler lock. Interrupts may be enabled or disabled on
    /// entry — they are disabled during the save/switch and re-enabled at
    /// resume.
    pub fn yield_save_and_switch();
}

#[cfg(not(any(fuzzing, test)))]
core::arch::global_asm!(
    ".global yield_save_and_switch",
    "yield_save_and_switch:",

    // ---- Disable interrupts for atomic save ----
    "cli",

    // ---- Build synthetic iretq frame (same layout as CPU interrupt entry) ----
    // Order: SS, RSP, RFLAGS, CS, RIP (high address → low address on stack)
    "mov rax, ss",
    "push rax",                 // SS

    "lea rax, [rsp + 8]",      // Entry RSP (before SS push; points to return addr)
    "push rax",                 // RSP

    "pushfq",                   // RFLAGS (IF=0 since cli)

    "mov rax, cs",
    "push rax",                 // CS (KERNEL_CS)

    "lea rax, [rip + .Lyield_resume]",
    "push rax",                 // RIP = .Lyield_resume

    // ---- Push all GPRs (same order as timer_isr_stub) ----
    // RAX was clobbered above — its value is irrelevant (caller-saved).
    "push rax",                 // RAX (clobbered, but SavedContext needs the slot)
    "push rbx",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push rbp",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push r12",
    "push r13",
    "push r14",
    "push r15",

    // ---- Call Rust scheduler ----
    // RSP → SavedContext (identical layout to timer ISR's)
    "mov rdi, rsp",
    "cld",
    "call yield_inner",
    // RAX = new_rsp (same or different task's SavedContext)

    // ---- Restore from (potentially new) SavedContext ----
    "mov rsp, rax",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rax",
    "iretq",

    // ---- Resume point for yielded tasks ----
    // iretq restores: RIP=here, CS=KERNEL_CS, RFLAGS(IF=0), RSP, SS.
    // Re-enable interrupts (handler was running with sti before yield).
    ".Lyield_resume:",
    "sti",
    "ret",                      // Return to caller of yield_save_and_switch
);

// ============================================================================
// Asm symbol stubs — satisfy linker for non-kernel targets (fuzz + host test)
// ============================================================================
//
// These replace global_asm! symbols on builds that don't / can't link the
// real bare-metal asm: cargo-fuzz (sets --cfg fuzzing) and host unit tests
// (cfg(test) on the x86_64-apple-darwin target — the asm directives are
// ELF-flavored and Mach-O linker doesn't resolve `_yield_save_and_switch`).
//
// Fuzz targets exercise pure-logic modules (ELF parser, capability,
// allocator) and never call these. Host syscall-dispatcher tests exercise
// validation paths that exit before reaching any asm primitive. In both
// cases the linker just needs the symbols to exist.

#[cfg(any(fuzzing, test))]
mod fuzz_asm_stubs {
    use crate::scheduler::CpuContext;

    #[unsafe(no_mangle)]
    pub extern "C" fn context_save(_ctx: *mut CpuContext) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn context_restore(_ctx: *const CpuContext) -> ! {
        unreachable!("context_restore called outside kernel target")
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn context_switch(
        _current_ctx: *mut CpuContext,
        _next_ctx: *const CpuContext,
    ) -> ! {
        unreachable!("context_switch called outside kernel target")
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn timer_isr_stub() {}

    #[unsafe(no_mangle)]
    pub extern "C" fn yield_save_and_switch() {}

    #[unsafe(no_mangle)]
    pub extern "C" fn gdt_reload_segments() {}

    #[unsafe(no_mangle)]
    pub extern "C" fn syscall_entry() {}
}

/// Rust handler for voluntary context switch.
///
/// Called from `yield_save_and_switch` assembly. Receives the current task's
/// SavedContext RSP, saves it, calls schedule(), and returns the next task's
/// SavedContext RSP. Performs platform-specific post-switch (TSS, CR3).
///
/// Does NOT send APIC EOI — this is a voluntary switch, not a hardware interrupt.
#[unsafe(no_mangle)]
extern "C" fn yield_inner(current_rsp: u64) -> u64 {
    let (new_rsp, hint) = crate::scheduler::on_voluntary_yield(current_rsp);

    // Platform-specific post-switch: update TSS.RSP0 and CR3
    // (same as timer_isr_inner, minus EOI)
    if let Some(hint) = hint {
        if hint.kernel_stack_top != 0 {
            // SAFETY: Called with interrupts disabled (cli in trampoline).
            // hint.kernel_stack_top is the next task's kernel stack top.
            unsafe { gdt::set_kernel_stack(hint.kernel_stack_top); }
        }
        if hint.page_table_root != 0 {
            let current_cr3: u64;
            // SAFETY: Reading CR3 is always safe at ring 0 with interrupts disabled.
            unsafe {
                core::arch::asm!(
                    "mov {}, cr3",
                    out(reg) current_cr3,
                    options(nostack, nomem),
                );
            }
            if current_cr3 != hint.page_table_root {
                // SAFETY: hint.page_table_root is a valid PML4 physical address
                // from create_process_page_table(). Kernel half is shared.
                unsafe {
                    core::arch::asm!(
                        "mov cr3, {}",
                        in(reg) hint.page_table_root,
                        options(nostack, preserves_flags),
                    );
                }
            }
        }
    }

    new_rsp
}