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

    // Per-CPU timer-ISR tick bump. Portable SMP diagnostic — see
    // `crate::PER_CPU_TIMER_TICKS` doc. SAFETY: GS base points at
    // this CPU's PerCpu block by the time the timer ISR fires (set
    // by init_ap / init_bsp before APIC is unmasked).
    let cpu = unsafe { percpu::current_percpu().cpu_id() } as usize;
    if cpu < crate::MAX_CPUS {
        crate::PER_CPU_TIMER_TICKS[cpu]
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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
/// DIAGNOSTIC (temporary — lazy-spawn iretq GPF investigation).
/// Armed by `handle_spawn` with a countdown; each voluntary yield that
/// actually switches tasks decrements and dumps the iretq frame + the
/// task we just resumed to. Bounded so we see the full spawn→first-run
/// chain without flooding forever. REMOVE once the bug is fixed.
pub(crate) static TRACE_SPAWN_YIELD: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

#[unsafe(no_mangle)]
extern "C" fn yield_inner(current_rsp: u64) -> u64 {
    let (mut new_rsp, mut hint) = crate::scheduler::on_voluntary_yield(current_rsp);

    // DIAGNOSTIC (temporary — lazy-spawn iretq GPF investigation).
    // Dumps the iretq frame values the new task is about to pop when a
    // real switch happens AND the trace counter is non-zero. REMOVE
    // once the bug is fixed.
    if new_rsp != current_rsp && new_rsp != 0 {
        let prev = TRACE_SPAWN_YIELD
            .fetch_update(
                core::sync::atomic::Ordering::Relaxed,
                core::sync::atomic::Ordering::Relaxed,
                |v| if v > 0 { Some(v - 1) } else { None },
            )
            .unwrap_or(0);
        if prev > 0 {
            // Peek current_task + its table state from the scheduler
            // (lock was released by on_voluntary_yield). May race on
            // SMP but good enough for diagnostic identification.
            let (
                resumed_task_id,
                task_state,
                task_saved_rsp,
                task_kstack_top,
                task_in_rq,
                task_proc,
                task_home_cpu,
            ) = {
                let g = crate::local_scheduler().lock();
                let sched = g.as_ref();
                let tid = sched.and_then(|s| s.current_task());
                let task = tid.and_then(|t| sched.and_then(|s| s.get_task_pub(t)));
                (
                    tid.map(|t| t.0 as i32).unwrap_or(-1),
                    task.map(|t| t.state),
                    task.map(|t| t.saved_rsp).unwrap_or(0),
                    task.map(|t| t.kernel_stack_top).unwrap_or(0),
                    task.map(|t| t.in_ready_queue).unwrap_or(false),
                    task.and_then(|t| t.process_id).map(|p| p.slot() as i32).unwrap_or(-1),
                    task.map(|t| t.home_cpu as i32).unwrap_or(-1),
                )
            };
            // SAFETY: GS base points at this CPU's PerCpu block once
            // init_bsp/init_ap has run, which is well before any yield
            // can occur.
            let current_cpu = unsafe { percpu::current_percpu().cpu_id() as i32 };
            crate::println!(
                "[YIELD #{}] cur_rsp={:#x} new_rsp={:#x} resumed_task={} proc={} home_cpu={} cur_cpu={}",
                prev, current_rsp, new_rsp,
                resumed_task_id, task_proc, task_home_cpu, current_cpu
            );
            crate::println!(
                "[YIELD #{}] task: state={:?} saved_rsp={:#x} kstack_top={:#x} in_rq={}",
                prev, task_state, task_saved_rsp, task_kstack_top, task_in_rq
            );
            // Peek GPRs (first 4 u64s of SavedContext: r15, r14, r13, r12)
            // and top-of-stack (4 u64s just below kstack_top) to tell
            // "whole stack zeroed" from "only iretq frame zeroed".
            // SAFETY: saved_rsp and kstack_top are within the new task's
            // kernel-heap-backed stack allocation.
            unsafe {
                let p = new_rsp as *const u64;
                crate::println!(
                    "[YIELD #{}] gprs@saved_rsp: r15={:#x} r14={:#x} r13={:#x} r12={:#x}",
                    prev, *p, *p.add(1), *p.add(2), *p.add(3)
                );
                let top = (task_kstack_top.saturating_sub(32)) as *const u64;
                if task_kstack_top != 0 {
                    crate::println!(
                        "[YIELD #{}] ktop-32..ktop: {:#x} {:#x} {:#x} {:#x}",
                        prev, *top, *top.add(1), *top.add(2), *top.add(3)
                    );
                }
            }
            // Scan the resumed task's full 32 KB kernel stack per u64
            // (no stride). KERNEL_STACK_SIZE = 32 * 1024. First 32
            // non-zero u64s printed; total count reported.
            if task_kstack_top != 0 {
                const KSTACK_BYTES: usize = 32 * 1024;
                let kbase = task_kstack_top.saturating_sub(KSTACK_BYTES as u64);
                // SAFETY: kbase..kstack_top spans the task's kernel-stack
                // allocation, HHDM-mapped and readable.
                unsafe {
                    crate::println!("[YIELD #{}] kstack scan (every non-zero u64):", prev);
                    let mut reported = 0usize;
                    let mut total_nonzero = 0usize;
                    for off in (0..KSTACK_BYTES).step_by(8) {
                        let p = (kbase + off as u64) as *const u64;
                        let v = *p;
                        if v != 0 {
                            total_nonzero += 1;
                            if reported < 32 {
                                crate::println!(
                                    "  offset {:>5}: {:#018x}",
                                    off, v
                                );
                                reported += 1;
                            }
                        }
                    }
                    if total_nonzero == 0 {
                        crate::println!("  (entire 32 KB is zero)");
                    } else if total_nonzero > reported {
                        crate::println!(
                            "  ... and {} more non-zero (total {})",
                            total_nonzero - reported, total_nonzero
                        );
                    }
                }
            }
            // Dump ALL tasks' kstack_top + saved_rsp + state + schedule_count.
            {
                let g = crate::local_scheduler().lock();
                if let Some(sched) = g.as_ref() {
                    crate::println!("[YIELD #{}] all tasks:", prev);
                    for tid_raw in 0..16u32 {
                        let tid = crate::scheduler::TaskId(tid_raw);
                        if let Some(t) = sched.get_task_pub(tid) {
                            let proc = t.process_id.map(|p| p.slot() as i32).unwrap_or(-1);
                            crate::println!(
                                "  tid={} proc={} state={:?} sched_cnt={} saved_rsp={:#x} kstack_top={:#x}",
                                tid_raw, proc, t.state, t.schedule_count,
                                t.saved_rsp, t.kernel_stack_top
                            );
                        }
                    }
                }
            }
            // Raw 256-byte hex window starting 32 bytes BELOW saved_rsp.
            // Spans: [saved_rsp-32 .. saved_rsp+224), covering the
            // 160-byte SavedContext and 32 bytes on either side.
            // SAFETY: addresses are within task's kernel-stack allocation.
            unsafe {
                let base = new_rsp.saturating_sub(32);
                crate::println!(
                    "[YIELD #{}] raw window @ saved_rsp-32 = {:#x}:",
                    prev, base
                );
                for line in 0..8 {
                    let off = line * 32;
                    let p = (base + off as u64) as *const u64;
                    crate::println!(
                        "  +{:>3}: {:#018x} {:#018x} {:#018x} {:#018x}",
                        off, *p, *p.add(1), *p.add(2), *p.add(3)
                    );
                }
            }
            // Also dump the just-spawned task's (most recent slot) state
            // so we can compare kernel-stack extents for overlap.
            let (peer_id, peer_state, peer_saved_rsp, peer_kstack_top, peer_proc) = {
                let g = crate::local_scheduler().lock();
                let sched = g.as_ref();
                // Scan task table for the highest-numbered non-idle task
                // (most recently allocated slot).
                let mut best: Option<(u32, crate::scheduler::TaskState, u64, u64, i32)> = None;
                if let Some(s) = sched {
                    for tid_raw in 1..256u32 {
                        let tid = crate::scheduler::TaskId(tid_raw);
                        if let Some(t) = s.get_task_pub(tid) {
                            let p = t.process_id.map(|p| p.slot() as i32).unwrap_or(-1);
                            best = Some((tid_raw, t.state, t.saved_rsp, t.kernel_stack_top, p));
                        }
                    }
                }
                match best {
                    Some((i, s, r, k, p)) => (i as i32, Some(s), r, k, p),
                    None => (-1, None, 0, 0, -1),
                }
            };
            crate::println!(
                "[YIELD #{}] latest_task: id={} proc={} state={:?} saved_rsp={:#x} kstack_top={:#x}",
                prev, peer_id, peer_proc, peer_state, peer_saved_rsp, peer_kstack_top
            );
            if let Some(ref h) = hint {
                crate::println!(
                    "[YIELD #{}] hint: kstack_top={:#x} cr3={:#x}",
                    prev, h.kernel_stack_top, h.page_table_root
                );
            }
            // Peek the iretq frame sitting at new_rsp + 120 (5 u64s).
            // SAFETY: new_rsp is inside a kernel-stack allocation;
            // 40 bytes at +120 are inside it.
            unsafe {
                let p = (new_rsp + 120) as *const u64;
                crate::println!(
                    "[YIELD #{}] iretq frame: rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}",
                    prev, *p, *p.add(1), *p.add(2), *p.add(3), *p.add(4)
                );
            }
        }
    }

    // BYPASS (temporary — lazy-spawn iretq GPF investigation).
    // Always-on safety net: if the task we're about to iretq into has
    // a zeroed iretq frame (null selector CS=0 = guaranteed #GP),
    // rewrite its SavedContext with a fresh initial frame so it resumes
    // at its user-space entry point rather than #GP'ing the kernel.
    // Mirrors the SavedContext that load_elf_process writes at process
    // load (src/loader/mod.rs:594-608). The task restarts from _start,
    // losing in-flight state but keeping the service alive (virtio-input
    // re-handshakes and keyboard input continues working). REMOVE once
    // the underlying memory-stomper is found and fixed.
    if new_rsp != current_rsp && new_rsp != 0 {
        let frame_is_zero = unsafe {
            let p = (new_rsp + 120) as *const u64;
            // CS=0 is the definitive null-selector test; RIP=0 alone could
            // theoretically (but not really) be valid.
            *p.add(1) == 0 && *p == 0
        };
        if frame_is_zero {
            // task.context.rip preserves the entry_point passed at
            // Task::new_with_stack — nothing writes task.context after
            // construction (verified 2026-04-23), so it's a stable
            // source for the restart target.
            let (task_id, entry_point, rflags_snapshot, sched_cnt) = {
                let g = crate::local_scheduler().lock();
                g.as_ref()
                    .and_then(|s| {
                        s.current_task_ref().map(|t| {
                            (t.id.0, t.context.rip, t.rflags_snapshot, t.schedule_count)
                        })
                    })
                    .unwrap_or((u32::MAX, 0, 0, 0))
            };
            // DIAGNOSTIC (stomper hunt). rflags_snapshot is read back
            // at each saved_rsp write. If it's non-zero and the
            // current *(new_rsp+136) is zero, the save was valid and
            // the stomp happened between write and now. If it's zero,
            // either the save wrote zeros itself or we never saved
            // for this task.
            let current_rflags = unsafe { *((new_rsp + 136) as *const u64) };
            crate::println!(
                "[STOMP-DIAG] tid={} sched_cnt={} rflags_at_save={:#x} rflags_now={:#x}",
                task_id, sched_cnt, rflags_snapshot, current_rflags
            );
            if entry_point != 0 {
                crate::println!(
                    "[BYPASS] zero iretq frame at new_rsp={:#x} tid={} — restart @ entry={:#x}",
                    new_rsp, task_id, entry_point
                );
                // SAFETY: new_rsp is the resumed task's saved_rsp, which
                // points at a 160-byte SavedContext region within its
                // kernel stack. The current iretq frame there is zeroed
                // (by the still-unknown stomper); writing a fresh initial
                // SavedContext is strictly safer than letting iretq run.
                // hint still carries the task's kernel_stack_top + cr3
                // from on_voluntary_yield, so ring-3 entry finds the
                // right address space.
                unsafe {
                    core::ptr::write(
                        new_rsp as *mut SavedContext,
                        SavedContext {
                            r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0,
                            r9: 0, r8: 0, rbp: 0, rdi: 0, rsi: 0, rdx: 0,
                            rcx: 0, rbx: 0, rax: 0,
                            rip: entry_point,
                            cs: gdt::USER_CS as u64,
                            rflags: 0x202, // IF set
                            rsp: 0x80_0000, // DEFAULT_STACK_TOP from loader
                            ss: gdt::USER_SS as u64,
                        },
                    );
                }
            } else {
                // entry_point should never be zero for a loaded task —
                // fall back to the old block-and-reschedule behavior so
                // the kernel doesn't iretq into a null frame.
                crate::println!(
                    "[BYPASS] zero iretq frame at new_rsp={:#x} tid={} entry=0 — blocking",
                    new_rsp, task_id
                );
                let mut g = crate::local_scheduler().lock();
                if let Some(sched) = g.as_mut() {
                    if let Some(tid) = sched.current_task() {
                        if let Some(task) = sched.get_task_mut_pub(tid) {
                            task.state = crate::scheduler::TaskState::Blocked;
                            task.block_reason =
                                Some(crate::scheduler::BlockReason::BootGate);
                        }
                    }
                    if let Ok(_) = sched.schedule() {
                        if let Some(task) = sched.current_task_ref() {
                            let cr3 = if task.cr3 != 0 {
                                task.cr3
                            } else {
                                crate::kernel_cr3()
                            };
                            new_rsp = task.saved_rsp;
                            hint = Some(crate::scheduler::ContextSwitchHint {
                                kernel_stack_top: task.kernel_stack_top,
                                page_table_root: cr3,
                            });
                        }
                    }
                }
            }
        }
    }

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