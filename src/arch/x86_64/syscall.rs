// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! SYSCALL/SYSRET fast system call entry path
//!
//! When a process executes the `syscall` instruction:
//!   1. CPU saves RIP → RCX, RFLAGS → R11
//!   2. CS/SS loaded from STAR MSR (kernel selectors)
//!   3. RIP loaded from LSTAR MSR (→ `syscall_entry`)
//!   4. RFLAGS masked by SFMASK (clears IF — interrupts disabled on entry)
//!
//! The stub saves caller state, builds a SyscallFrame, calls `syscall_handler_inner`,
//! and returns via `sysretq` (ring 3 caller) or `jmp rcx` (ring 0 caller).
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
    // SAFETY: All MSR reads/writes below target valid MSRs on x86_64 CPUs.
    // Caller ensures single-threaded init after GDT is loaded, at ring 0.
    unsafe {
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
        super::msr::write(MSR_STAR, star);

        // LSTAR: target RIP for SYSCALL instruction
        extern "C" {
            fn syscall_entry();
        }
        super::msr::write(MSR_LSTAR, syscall_entry as *const () as u64);

        // SFMASK: RFLAGS bits to CLEAR on SYSCALL entry
        // 0x200 = IF — disable interrupts until the handler explicitly re-enables them
        super::msr::write(MSR_SFMASK, 0x200);

        // Enable System Call Extensions in EFER
        let efer = super::msr::read(MSR_EFER);
        super::msr::write(MSR_EFER, efer | EFER_SCE);
    }
}

// ============================================================================
// Assembly stub
// ============================================================================
//
// Entry: syscall has set RCX=user_rip, R11=user_rflags, RAX=syscall_number
//        Args in RDI, RSI, RDX, R10, R8, R9   (R10 replaces RCX for arg4)
//        Interrupts disabled (SFMASK cleared IF)
//
// Exit: RAX = return value.
//       For ring 3 callers → sysretq (CS=USER_CS, SS=USER_SS, RIP=RCX, RFLAGS=R11)
//       For ring 0 callers → restore RFLAGS from R11, jmp to RCX

core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",

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

    // ---- Call Rust handler ----
    // extern "C" fn syscall_handler_inner(*const SyscallFrame) -> i64
    "mov rdi, rsp",         // pointer to SyscallFrame
    "cld",                  // Clear DF per SysV ABI before C call
    "call syscall_handler_inner",
    // RAX now holds the return value

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

    // ---- Return path ----
    // Bit 47 of return RIP distinguishes kernel (high-half) from user (low-half).
    // Ring 3: sysretq sets CS/SS to user selectors with RPL=3.
    // Ring 0: manual RFLAGS restore + jmp (sysretq would force ring 3).
    "bt rcx, 47",
    "jc 2f",                // jump if kernel address

    // User return path
    "sysretq",

    // Kernel return path (for ring 0 testing)
    "2:",
    "push r11",
    "popfq",                // restore RFLAGS (re-enables IF if it was set)
    "jmp rcx",              // jump to saved RIP
);

// ============================================================================
// Rust syscall handler (called from assembly stub)
// ============================================================================

/// Rust-side syscall handler dispatched from the assembly entry stub.
///
/// Receives a pointer to `SyscallFrame` on the kernel stack and returns
/// the result in RAX (i64: positive = success value, negative = error).
#[unsafe(no_mangle)]
extern "C" fn syscall_handler_inner(frame: *const SyscallFrame) -> i64 {
    // SAFETY: frame points to the SyscallFrame we just built on the stack in
    // syscall_entry, and we are in a single-threaded context (interrupts disabled).
    let frame = unsafe { &*frame };

    use crate::syscalls::{SyscallArgs, SyscallError};
    use crate::syscalls::dispatcher::{SyscallContext, SyscallDispatcher};
    use crate::ipc::ProcessId;

    // Look up the calling task and its metadata from the scheduler
    let (task_id, process_id, cr3, kernel_stack_top) = {
        let sched = crate::local_scheduler().lock();
        match sched.as_ref().and_then(|s| {
            let tid = s.current_task()?;
            let task = s.current_task_ref()?;
            let pid = task.process_id.unwrap_or(ProcessId(tid.0 as u32));
            Some((tid, pid, task.cr3, task.kernel_stack_top))
        }) {
            Some(info) => info,
            None => return SyscallError::InvalidArg.as_i64(),
        }
    };

    let ctx = SyscallContext {
        process_id,
        task_id,
        cr3,
    };

    let args = SyscallArgs::new(
        frame.arg1, frame.arg2, frame.arg3,
        frame.arg4, frame.arg5, frame.arg6,
    );

    match SyscallDispatcher::dispatch(frame.number, args, &ctx) {
        Ok(val) => {
            // SYS_EXIT (0): task is Terminated — halt on kernel stack.
            if frame.number == 0 {
                super::halt_until_preempted(kernel_stack_top);
            }

            // Check if the dispatcher blocked this task (e.g., recv_msg with
            // empty queue). If so, save the user-return state to the kernel
            // stack and halt — the timer ISR switches away, and when the task
            // is woken later, iretq returns it to user space with RAX=0.
            // If the dispatcher blocked this task (e.g., recv_msg with empty
            // queue), save user-return state to the kernel stack and halt.
            // The timer ISR detects the Blocked task and context-switches away.
            // When woken later, iretq restores to user space with RAX=val.
            if val == 0 && kernel_stack_top != 0 {
                let is_blocked = {
                    let sched = crate::local_scheduler().lock();
                    sched.as_ref().and_then(|s| {
                        s.current_task_ref().map(|t| {
                            t.state == crate::scheduler::TaskState::Blocked
                        })
                    }).unwrap_or(false)
                };
                if is_blocked {
                    suspend_to_kernel_stack(frame, kernel_stack_top, task_id, val as u64);
                }
            }

            val as i64
        }
        Err(e) => e.as_i64(),
    }
}

/// Save the user-return state to the kernel stack and halt.
///
/// Called when a syscall blocks the current task (e.g., recv_msg with empty
/// queue). Builds a SavedContext on the task's kernel stack that, when
/// restored by the timer ISR's iretq, returns to user space as if the
/// syscall returned `return_value`.
///
/// The SYSCALL entry stub pushed registers onto the user stack in this order
/// (high address to low): RCX(user RIP), R11(user RFLAGS), RBX, RBP,
/// R12-R15, then the SyscallFrame (R9, R8, R10, RDX, RSI, RDI, RAX).
/// The `frame` pointer points to the SyscallFrame (lowest address).
fn suspend_to_kernel_stack(
    frame: &SyscallFrame,
    kernel_stack_top: u64,
    task_id: crate::scheduler::TaskId,
    return_value: u64,
) -> ! {
    use super::SavedContext;
    use super::gdt;
    use core::mem::size_of;

    let frame_base = frame as *const SyscallFrame as u64;

    // Read callee-saved registers and user return state from the SYSCALL
    // frame on the user stack. Layout above the SyscallFrame (7 fields):
    //   +56: R15, +64: R14, +72: R13, +80: R12, +88: RBP, +96: RBX,
    //   +104: R11 (user RFLAGS), +112: RCX (user RIP)
    // SAFETY: These addresses are within the SYSCALL frame pushed by
    // syscall_entry, on the current (user) stack, still accessible.
    let (r15, r14, r13, r12, rbp, rbx, user_rflags, user_rip, user_rsp) = unsafe {
        (
            *((frame_base + 56) as *const u64),
            *((frame_base + 64) as *const u64),
            *((frame_base + 72) as *const u64),
            *((frame_base + 80) as *const u64),
            *((frame_base + 88) as *const u64),
            *((frame_base + 96) as *const u64),
            *((frame_base + 104) as *const u64),  // R11 = user RFLAGS
            *((frame_base + 112) as *const u64),  // RCX = user RIP
            frame_base + 120,                      // user RSP (above all pushes)
        )
    };

    // Build SavedContext on the kernel stack (same position as the initial
    // dispatch context — kstack_top - sizeof(SavedContext)).
    let saved_ctx_addr = kernel_stack_top - size_of::<SavedContext>() as u64;

    // SAFETY: saved_ctx_addr is within the task's kernel stack (heap-allocated,
    // in HHDM space). The SavedContext will be restored by the timer ISR's
    // iretq, returning to user space at user_rip with RAX=return_value.
    unsafe {
        core::ptr::write(saved_ctx_addr as *mut SavedContext, SavedContext {
            r15, r14, r13, r12,
            r11: 0, r10: 0, r9: 0, r8: 0,
            rbp,
            rdi: 0, rsi: 0, rdx: 0, rcx: 0,
            rbx,
            rax: return_value,
            rip: user_rip,
            cs: gdt::USER_CS as u64,
            rflags: user_rflags,
            rsp: user_rsp,
            ss: gdt::USER_SS as u64,
        });
    }

    // Update saved_rsp in the scheduler so the ISR dispatches from here
    {
        let mut sched_guard = crate::local_scheduler().lock();
        if let Some(sched) = sched_guard.as_mut() {
            if let Some(task) = sched.get_task_mut_pub(task_id) {
                task.saved_rsp = saved_ctx_addr;
            }
        }
    }

    // Halt BELOW the SavedContext on the kernel stack. The timer ISR will
    // push its own 160-byte frame downward from RSP — if we halted at
    // kernel_stack_top, that frame would overwrite our synthetic context.
    // Halting at saved_ctx_addr puts the ISR frame below the context.
    super::halt_until_preempted(saved_ctx_addr);
}
