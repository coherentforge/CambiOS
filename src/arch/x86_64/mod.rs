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
//! 2. **Interrupt-driven switch** (the trap entry in [`trap`], ADR-040 § 3):
//!    every vector's stub and the common entry save the full register state
//!    as a `SavedContext` on the current stack, `interrupts::x86_trap` may
//!    return another task's context (the timer and reschedule vectors), and
//!    the common exit restores whichever context it returned and does `iretq`.
//!    `yield_save_and_switch` builds the same shape and leaves the same way.

pub mod apic;
pub mod gdt;
pub mod ioapic;
pub mod msr;
pub mod percpu;
pub mod portio;
pub mod syscall;
pub mod tlb;
pub mod trap;

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

/// Save the current interrupt state and disable maskable interrupts.
///
/// Returns an opaque token (the pre-`cli` RFLAGS) to pass to
/// [`irq_restore`]. The single masking primitive behind [`IrqSpinlock`];
/// pair every call with exactly one `irq_restore`.
#[cfg(target_os = "none")]
#[inline]
pub fn irq_save_disable() -> usize {
    let rflags: u64;
    // SAFETY: pushfq/pop is a balanced read of RFLAGS (net-zero stack); cli
    // disables maskable interrupts at ring 0. nomem: no memory operands.
    // preserves_flags is sound — cli touches IF, not the status flags.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) rflags,
            options(nomem, preserves_flags),
        );
    }
    rflags as usize
}

/// Restore the interrupt state captured by [`irq_save_disable`].
///
/// Re-enables interrupts only if they were enabled when the token was
/// taken (RFLAGS.IF set), so nested holds never prematurely unmask.
#[cfg(target_os = "none")]
#[inline]
pub fn irq_restore(token: usize) {
    if token & (1 << 9) != 0 {
        // SAFETY: sti re-enables maskable interrupts at ring 0; only reached
        // when IF was set at save time, so this restores rather than newly
        // enables. Local to this CPU.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    }
}

/// Host-test stubs (same rationale as `interrupts_enabled`): no privileged
/// interrupt-state instructions under `cargo test --lib`.
#[cfg(not(target_os = "none"))]
#[inline]
pub fn irq_save_disable() -> usize {
    0
}

#[cfg(not(target_os = "none"))]
#[inline]
pub fn irq_restore(_token: usize) {}

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

/// Saved register state for interrupt context switches (ADR-040 § 3).
///
/// On a trap the CPU pushes SS, RSP, RFLAGS, CS, RIP and, for some vectors,
/// an error code; the vector's stub pushes a 0 where it did not, then the
/// vector number; the common entry pushes rax, rbx, ... r15 (each `push`
/// decrements RSP). `yield_save_and_switch` and the loader build the same
/// shape, so the common exit can resume any saved context.
///
/// Fields are ordered by ascending memory address. The last register pushed
/// (r15) ends up at the lowest address, so it's the first field. The CPU-
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
    /// The vector the trap stub pushed, or [`SavedContext::NO_VECTOR`] for
    /// a context no trap produced (a yield, a new task's first entry).
    pub vector: u64,
    /// The CPU's error code for the vector, or 0 where it pushes none.
    pub error_code: u64,
    // Pushed by CPU on interrupt entry
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl SavedContext {
    /// ARCHITECTURAL: the `vector` of a saved context that no trap produced
    /// (`yield_save_and_switch`'s synthetic frame, a new task's first
    /// frame). Not a vector number: those are 0-255. The yield assembly
    /// pushes it as `push -1`.
    pub const NO_VECTOR: u64 = u64::MAX;
}

// The trap entry, the common exit and `yield_save_and_switch` address these
// slots by offset; the stub's 16-byte alignment at the call into Rust needs
// the size to be a multiple of 16 (ADR-040 § 3).
const _: () = assert!(core::mem::offset_of!(SavedContext, rax) == 112);
const _: () = assert!(core::mem::offset_of!(SavedContext, vector) == 120);
const _: () = assert!(core::mem::offset_of!(SavedContext, error_code) == 128);
const _: () = assert!(core::mem::offset_of!(SavedContext, rip) == 136);
const _: () = assert!(core::mem::offset_of!(SavedContext, ss) == 168);
const _: () = assert!(core::mem::size_of::<SavedContext>() == 176);
const _: () = assert!(core::mem::size_of::<SavedContext>().is_multiple_of(16));

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

/// ARCHITECTURAL: IPI vector for the cross-CPU reschedule kick. Sits
/// just below the TLB-shootdown IPI (0xFE) and the spurious vector
/// (0xFF), above every device vector the I/O APIC hands out (33..56).
pub const RESCHED_VECTOR: u8 = 0xFD;

/// Reschedule-IPI handler, called from `interrupts::x86_trap` on the CPU
/// that was kicked. Reschedules if this CPU was idle (or its current task
/// is no longer Running), applies the switch hint, and acknowledges the IPI.
/// Takes and returns the stack pointer of a `SavedContext`, like the timer.
pub(crate) fn resched_isr_inner(current_rsp: u64) -> u64 {
    let (new_rsp, hint) = crate::scheduler::on_resched_ipi(current_rsp);
    crate::RESCHED_KICKS_HANDLED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if new_rsp != current_rsp {
        crate::RESCHED_KICKS_SWITCHED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    if let Some(hint) = hint {
        apply_switch_hint(&hint);
    }
    // SAFETY: we are in the APIC-delivered reschedule IPI handler; the
    // APIC was initialized before any IPI could be sent.
    unsafe {
        apic::write_eoi();
    }
    new_rsp
}

/// Time-stamp counter, for boot-phase timing before any timer exists.
/// Raw cycles; the kernel never converts, it prints deltas.
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC reads a counter and writes EDX:EAX; no memory or
    // flags are touched. CR4.TSD is clear (ring 0 regardless).
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// Kick `cpu` so a task just woken onto its scheduler runs now rather
/// than at that CPU's next timer tick. No-op for the calling CPU, for
/// a CPU index past the online count, and before the APs are up (the
/// APIC is not necessarily initialized then). Must be called with no
/// scheduler lock held: the target's handler `try_lock`s its scheduler
/// and a held lock turns the kick into a no-op.
pub fn kick_cpu(cpu: usize) {
    if crate::online_cpu_count() <= 1 || cpu >= crate::online_cpu_count() {
        return;
    }
    // SAFETY: GS base is initialized on every CPU that can run kernel
    // code once the APs are online, which the gate above requires.
    let me = unsafe { percpu::current_cpu_id() } as usize;
    if cpu == me {
        return;
    }
    let Some(apic_id) = percpu::apic_id_of(cpu) else { return };
    // Deferred: x2APIC (wider than 8-bit) destination ids get no kick
    // and ride the timer tick; the IPI primitive is xAPIC-only today.
    // Revisit when: a target boots with more than 255 logical CPUs or
    // firmware leaves x2APIC mode on.
    let Ok(dest) = u8::try_from(apic_id) else { return };
    crate::RESCHED_KICKS_SENT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    x86_64::instructions::interrupts::without_interrupts(|| {
        // SAFETY: APIC initialized (APs online); RESCHED_VECTOR is in
        // the shared IDT every CPU loaded; interrupts are masked around
        // the two ICR writes so no handler on this CPU can interleave.
        unsafe { apic::send_ipi(dest, RESCHED_VECTOR) };
    });
}

/// Timer handler (vector 32), called from `interrupts::x86_trap`.
///
/// Receives the current task's saved RSP (pointing to SavedContext on its stack).
/// Returns the RSP to restore from — same value if no switch, or a different
/// task's SavedContext RSP if a context switch is needed.
///
/// Delegates portable tick/schedule logic to `scheduler::on_timer_isr()`,
/// then performs x86-specific post-switch work (TSS, CR3, APIC EOI).
pub(crate) fn timer_isr_inner(current_rsp: u64) -> u64 {
    let (new_rsp, hint) = crate::scheduler::on_timer_isr(current_rsp);

    // x86-specific post-switch: update TSS and CR3
    if let Some(hint) = hint {
        apply_switch_hint(&hint);
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

/// x86-specific post-switch work shared by every ISR that may switch
/// tasks: point the TSS at the next task's kernel stack and load its
/// page-table root if it differs from the current one.
fn apply_switch_hint(hint: &crate::scheduler::ContextSwitchHint) {
    if hint.kernel_stack_top != 0 {
        // SAFETY: Called from an ISR with interrupts disabled.
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
// Builds a synthetic SavedContext (the trap entry's layout, ADR-040 § 3) on
// the current kernel stack, calls yield_inner (Rust) to save it and schedule
// the next task, then leaves through the common trap exit, which restores
// from the (potentially different) SavedContext and does iretq.
//
// When the yielding task is later re-scheduled (by the timer or another
// yield_save_and_switch), iretq goes to .Lyield_resume, which re-enables
// interrupts and returns to the syscall handler that called us.
//
// The frame is placed as the CPU places one: RSP is first aligned down to
// 16 bytes, and the frame's saved RSP is the unaligned entry value, so the
// resumed `ret` finds the return address. 22 words then leave RSP aligned
// at `call yield_inner`, as the SysV ABI requires (the previous frame, 20
// words from an entry RSP 8 bytes off alignment, called it misaligned).
//
// Stack layout after the push sequence (SavedContext, low → high):
//   [rsp+0]   r15          ← RSP points here (arg to yield_inner)
//   [rsp+8]   r14
//   ...
//   [rsp+112] rax
//   [rsp+120] vector       = SavedContext::NO_VECTOR (no trap produced it)
//   [rsp+128] error_code   = 0
//   [rsp+136] rip          = .Lyield_resume
//   [rsp+144] cs           = current CS (KERNEL_CS)
//   [rsp+152] rflags       (IF=0, saved under cli)
//   [rsp+160] rsp          = entry RSP (caller's stack with return address)
//   [rsp+168] ss           = current SS (KERNEL_SS)

extern "C" {
    /// Voluntary context switch.
    ///
    /// Saves all registers as a SavedContext on the kernel stack, calls the
    /// scheduler to pick the next task, and restores from the next task's
    /// SavedContext via the common trap exit. When the calling task is
    /// later re-scheduled, this function returns normally to its caller.
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

    // ---- Place the frame as the CPU would ----
    // r11 and rax are scratch: caller-saved, so their values need not
    // survive, though their slots are still filled below.
    "mov r11, rsp",             // entry RSP (points at our return address)
    "and rsp, -16",

    // ---- Synthetic iretq frame: SS, RSP, RFLAGS, CS, RIP ----
    "mov rax, ss",
    "push rax",                 // SS
    "push r11",                 // RSP = entry RSP
    "pushfq",                   // RFLAGS (IF=0 since cli)
    "mov rax, cs",
    "push rax",                 // CS (KERNEL_CS)
    "lea rax, [rip + .Lyield_resume]",
    "push rax",                 // RIP = .Lyield_resume

    // ---- The trap entry's error-code and vector slots ----
    "push 0",                   // error_code
    "push -1",                  // vector = SavedContext::NO_VECTOR

    // ---- Push all GPRs (same order as the trap entry) ----
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

    // ---- Call Rust scheduler ----
    "mov rdi, rsp",
    "cld",
    "call yield_inner",
    // RAX = new_rsp (same or different task's SavedContext)

    // ---- Restore from (potentially new) SavedContext ----
    "mov rsp, rax",
    "jmp x86_trap_restore",

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

    /// The trap stub table (`trap::X86_TRAP_STUB_TABLE`): host builds read
    /// nothing from it, the linker only needs the symbol.
    #[unsafe(no_mangle)]
    pub static X86_TRAP_STUB_TABLE: [u64; super::trap::IDT_ENTRIES] = [0; super::trap::IDT_ENTRIES];

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