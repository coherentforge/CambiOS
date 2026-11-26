// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! SYSCALL/SYSRET fast system call entry path
//!
//! When a process executes the `syscall` instruction:
//!   1. CPU saves RIP → RCX, RFLAGS → R11
//!   2. CS/SS loaded from STAR MSR (kernel selectors)
//!   3. RIP loaded from LSTAR MSR (→ `syscall_entry`)
//!   4. RFLAGS masked by SFMASK: TF, IF, DF, IOPL, NT and AC cleared
//!      ([ADR-040] § 5), so none of the caller's values for them reaches
//!      ring 0 (interrupts are disabled on entry)
//!
//! The stub saves caller state, builds a SyscallFrame, calls `syscall_handler_inner`,
//! and returns via `sysretq`. Only ring 3 executes `syscall`; there is no
//! ring-0 return path. A saved return address that is not canonical in the
//! lower half is never returned to: the caller is reaped instead
//! (`syscall_bad_return`), because Intel CPUs raise the resulting #GP in
//! ring 0 on the caller's stack (CVE-2012-0217).
//!
//! [ADR-040]: ../../../docs/adr/040-trap-entry-discipline.md
//!
//! ## Register convention
//!
//! | Register | Role                                          |
//! |----------|-----------------------------------------------|
//! | RAX      | Syscall number (input), return value (output) |
//! | RDI      | arg1                                          |
//! | RSI      | arg2                                          |
//! | RDX      | arg3                                          |
//! | R10      | arg4  (NOT RCX — `syscall` clobbers RCX)      |
//! | R8       | arg5                                          |
//! | R9       | arg6                                          |
//! | RCX      | (clobbered: user RIP saved here by CPU)       |
//! | R11      | (clobbered: user RFLAGS saved here by CPU)    |

use super::gdt;

// ============================================================================
// MSR addresses
// ============================================================================

const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;

/// EFER: System Call Extensions enable
const EFER_SCE: u64 = 1 << 0;

/// HARDWARE: the RFLAGS bits SFMASK clears on `syscall` entry (Intel SDM
/// Vol. 1 § 3.4.3): TF (bit 8), IF (9), DF (10), IOPL (12-13), NT (14), AC
/// (18). ADR-040 § 5: a set TF would single-step the first kernel
/// instruction on the caller's stack; NT would make the kernel's next
/// `iretq` fault; AC would switch SMAP off in the kernel; DF must be clear
/// for Rust code (the stub also runs `cld`); IF stays clear until the stub
/// is on the kernel stack. `sysretq` restores the caller's flags from R11.
const SFMASK_FLAGS: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (3 << 12) | (1 << 14) | (1 << 18);

const _: () = assert!(SFMASK_FLAGS == 0x47700);

// ============================================================================
// Syscall frame passed to the Rust handler
// ============================================================================

/// Frame built on the kernel stack by the assembly stub.
///
/// Layout must match the push order in `syscall_entry`.
#[repr(C)]
pub struct SyscallFrame {
    pub number: u64, // RAX
    pub arg1: u64,   // RDI
    pub arg2: u64,   // RSI
    pub arg3: u64,   // RDX
    pub arg4: u64,   // R10
    pub arg5: u64,   // R8
    pub arg6: u64,   // R9
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the SYSCALL/SYSRET mechanism.
///
/// Configures STAR (segment selectors), LSTAR (entry point), and SFMASK
/// (interrupt masking), then enables the SCE bit in EFER.
///
/// # Safety
/// Must be called during single-threaded init after the GDT is loaded
/// and before any task executes `syscall`.
pub unsafe fn init() {
    // STAR MSR: segment selectors for SYSCALL and SYSRET
    //
    //   Bits 47:32 = SYSCALL target:
    //     CS = STAR[47:32]        = 0x08 (KERNEL_CS)
    //     SS = STAR[47:32] + 8    = 0x10 (KERNEL_SS)
    //
    //   Bits 63:48 = SYSRET base:
    //     SS = STAR[63:48] + 8  | 3 = 0x1B (USER_SS)
    //     CS = STAR[63:48] + 16 | 3 = 0x23 (USER_CS)  [64-bit mode]
    let star = ((gdt::KERNEL_SS as u64) << 48) | ((gdt::KERNEL_CS as u64) << 32);
    // SAFETY: MSR_STAR is a valid MSR. Caller ensures single-threaded init at ring 0.
    unsafe { super::msr::write(MSR_STAR, star) };

    // LSTAR: target RIP for SYSCALL instruction
    extern "C" {
        fn syscall_entry();
    }
    // SAFETY: MSR_LSTAR is a valid MSR. syscall_entry is our global_asm entry point.
    unsafe { super::msr::write(MSR_LSTAR, syscall_entry as *const () as u64) };

    // SFMASK: RFLAGS bits to CLEAR on SYSCALL entry (SFMASK_FLAGS).
    // SAFETY: MSR_SFMASK is a valid MSR.
    unsafe { super::msr::write(MSR_SFMASK, SFMASK_FLAGS) };

    // Enable System Call Extensions in EFER
    // SAFETY: MSR_EFER is a valid MSR.
    let efer = unsafe { super::msr::read(MSR_EFER) };
    // SAFETY: Writing EFER with SCE bit set is valid at ring 0.
    unsafe { super::msr::write(MSR_EFER, efer | EFER_SCE) };
}

// ============================================================================
// Assembly stub
// ============================================================================
//
// Entry: syscall has set RCX=user_rip, R11=user_rflags, RAX=syscall_number
//        Args in RDI, RSI, RDX, R10, R8, R9   (R10 replaces RCX for arg4)
//        Interrupts disabled (SFMASK cleared IF)
//        RSP = user stack (SYSCALL does not switch stacks)
//        GS base = the program's (ADR-040 § 2)
//
// The stub first executes `swapgs` (GS base becomes this CPU's PerCpu),
// then switches RSP from the user stack to the per-CPU kernel
// stack (read from gs:[PERCPU_KERNEL_RSP0]). The user RSP is saved via the
// per-CPU scratch slot (gs:[PERCPU_USER_RSP_SCRATCH]) and pushed onto the
// kernel stack for restoration on return.
//
// Interrupts are enabled (sti) after the kernel stack switch so the handler
// is preemptible by the timer ISR. Interrupts are disabled (cli) before the
// return path to prevent an ISR between the kernel→user RSP switch and sysretq.
//
// Exit: RAX = return value.
//       sysretq (CS=USER_CS, SS=USER_SS, RIP=RCX, RFLAGS=R11). Only ring 3
//       executes `syscall`, so there is no other way back.
//       Before that, the saved RCX must be canonical in the lower half
//       (bits 63:47 clear). A `syscall` in the last user page saves
//       RCX = 0x8000_0000_0000, and `sysretq` with it raises #GP in ring 0
//       on the user's RSP on Intel CPUs (CVE-2012-0217). Such a caller is
//       reaped instead (`syscall_bad_return`, ADR-040 § 5): its return
//       address is outside user space, so no correct program gets here.
//
// Kernel stack layout after entry (high address first):
//   user_rsp          ← pushed from gs:[PERCPU_USER_RSP_SCRATCH]
//   RCX (user RIP)
//   R11 (user RFLAGS)
//   RBX, RBP, R12-R15 (callee-saved)
//   SyscallFrame      ← RSP points here when handler is called

#[cfg(not(any(fuzzing, test)))]
core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",

    // ---- Kernel GS (ADR-040 § 2) ----
    // Only ring 3 executes `syscall`, so GS base is the program's here and
    // IA32_KERNEL_GS_BASE holds this CPU's PerCpu: swap them, always. A
    // program can change its own GS base (`mov gs` with a user selector
    // loads base 0), so nothing before this instruction may read GS.
    "swapgs",

    // ---- Switch to kernel stack ----
    "mov gs:[32], rsp",     // Save user RSP to PerCpu.user_rsp_scratch
    "mov rsp, gs:[24]",     // Load kernel RSP from PerCpu.kernel_rsp0

    // ---- Push user RSP onto kernel stack ----
    "push qword ptr gs:[32]",  // user RSP (for restoration on return)

    // ---- Save user return state ----
    "push rcx",             // user RIP  (restored before return)
    "push r11",             // user RFLAGS

    // ---- Save callee-saved registers (SysV ABI) ----
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",

    // ---- Build SyscallFrame on the stack ----
    // Layout: [number, arg1, arg2, arg3, arg4, arg5, arg6]
    "push r9",              // arg6
    "push r8",              // arg5
    "push r10",             // arg4
    "push rdx",             // arg3
    "push rsi",             // arg2
    "push rdi",             // arg1
    "push rax",             // syscall number

    // ---- Enable interrupts ----
    // Safe now: we're on the kernel stack, so timer ISR saves/restores
    // correctly. Handler is preemptible — yield and blocking work.
    "sti",

    // ---- Call Rust handler ----
    // extern "C" fn syscall_handler_inner(*const SyscallFrame) -> i64
    "mov rdi, rsp",         // pointer to SyscallFrame
    "cld",                  // Clear DF per SysV ABI before C call
    "call syscall_handler_inner",
    // RAX now holds the return value

    // ---- The return address must be canonical in the lower half ----
    // [rsp + 112] is the saved RCX (user RIP): the 7-word SyscallFrame,
    // then r15, r14, r13, r12, rbp, rbx, r11. Interrupts are still on, as
    // the reap needs.
    "mov rcx, [rsp + 112]",
    "shr rcx, 47",
    "jnz .Lsyscall_bad_return",

    // ---- Disable interrupts for return path ----
    // Prevents timer ISR from firing between RSP switch and sysretq,
    // which would push an ISR frame onto the user stack.
    "cli",

    // ---- Clean up SyscallFrame ----
    "add rsp, 56",          // 7 fields × 8 bytes

    // ---- Restore callee-saved registers ----
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",

    // ---- Restore user return state ----
    "pop r11",              // user RFLAGS
    "pop rcx",              // user RIP

    // ---- Restore user RSP ----
    // After this, RSP is back on the user stack. Interrupts are disabled
    // (cli above) so no ISR frame can be pushed onto the user stack.
    "pop rsp",              // user RSP (safe: sysretq doesn't touch stack)

    // ---- Return to ring 3: the program's GS back, then sysretq ----
    // Adjacent, interrupts off: nothing between them can fault (an NMI or
    // #MC here takes the paranoid entry, which reads GS base itself).
    "swapgs",
    "sysretq",

    // ---- A return address outside user space: reap, never return ----
    // Still on the kernel stack with every register pushed; RSP is as it
    // was at the call above, so the call below is aligned.
    ".Lsyscall_bad_return:",
    "mov rdi, [rsp + 112]",
    "call syscall_bad_return",
    "ud2",                  // syscall_bad_return does not return
);

/// The caller of a syscall whose saved return address (RCX) is not
/// canonical in the lower half: reap it instead of returning (ADR-040 § 5).
///
/// Called from `syscall_entry` on the caller's kernel stack with interrupts
/// enabled, after its syscall ran. Recorded as a general-protection fault at
/// that address, the fault `sysretq` would have raised on the way back.
#[unsafe(no_mangle)]
extern "C" fn syscall_bad_return(return_rip: u64) -> ! {
    crate::println!(
        "  [syscall] return address {:#x} is outside user space; reaping the caller",
        return_rip
    );
    crate::interrupts::exceptions::reap_user_fault(
        crate::reap::FaultKind::GeneralProtection,
        return_rip,
        return_rip,
    )
}

// ============================================================================
// Rust syscall handler (called from assembly stub)
// ============================================================================

/// Rust-side syscall handler dispatched from the assembly entry stub.
///
/// Receives a pointer to `SyscallFrame` on the kernel stack and returns
/// the result in RAX (i64: positive = success value, negative = error).
///
/// The handler runs on the kernel stack with interrupts enabled (sti in the
/// assembly stub). Blocking, yielding, and exit are handled inside the
/// individual dispatch handlers via `yield_save_and_switch()` — this
/// function simply dispatches and returns.
#[unsafe(no_mangle)]
extern "C" fn syscall_handler_inner(frame: *const SyscallFrame) -> i64 {
    // SAFETY: frame points to the SyscallFrame built on the kernel stack by
    // syscall_entry. We are on the kernel stack with interrupts enabled.
    let frame = unsafe { &*frame };

    use crate::syscalls::{SyscallArgs, SyscallError};
    use crate::syscalls::dispatcher::{SyscallContext, SyscallDispatcher};
    use crate::ipc::ProcessId;

    // Look up the calling task and its metadata from the scheduler
    let (task_id, process_id, cr3) = {
        let sched = crate::local_scheduler().lock();
        match sched.as_ref().and_then(|s| {
            let tid = s.current_task()?;
            let task = s.current_task_ref()?;
            let pid = task.process_id.unwrap_or(ProcessId::new(tid.slot(), 0));
            Some((tid, pid, task.cr3))
        }) {
            Some(info) => info,
            None => return SyscallError::InvalidArg.as_i64(),
        }
    };

    let ctx = SyscallContext {
        process_id,
        task_id,
        cr3,
        caller_principal: None, // resolved in dispatch()
    };

    let args = SyscallArgs::new(
        frame.arg1, frame.arg2, frame.arg3,
        frame.arg4, frame.arg5, frame.arg6,
    );

    match SyscallDispatcher::dispatch(frame.number, args, ctx) {
        Ok(val) => val as i64,
        Err(e) => e.as_i64(),
    }
}

// suspend_to_kernel_stack removed — superseded by yield_save_and_switch.
// Blocking handlers now call yield_save_and_switch() directly, which saves
// context via a synthetic iretq frame and calls the scheduler.
