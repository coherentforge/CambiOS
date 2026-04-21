// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Syscall entry — RISC-V (S-mode)
//!
//! RISC-V syscalls ride the `ecall` instruction: from U-mode it traps
//! into S-mode with `scause == 8`. Our trap vector ([`super::trap`])
//! catches it, saves the full user SavedContext, and delegates to
//! [`ecall_handler_inner`] here. The handler extracts the Linux-style
//! ABI registers (a7 = syscall number, a0..a5 = args), calls the
//! portable `SyscallDispatcher::dispatch`, writes the return value
//! back into `gpr[10]` (a0), and advances `sepc` by 4 so `sret`
//! resumes at the instruction after the `ecall`.
//!
//! ## Register convention (Linux-compatible)
//!
//! | Register | Role                    |
//! |----------|-------------------------|
//! | a7 (x17) | Syscall number          |
//! | a0..a5   | Arguments 1..6          |
//! | a0 (x10) | Return value (output)   |
//!
//! Negative i64 return values signal `SyscallError` variants per
//! `SyscallError::as_i64`; user-space libsys wrappers flip the sign
//! bit to detect errors.
//!
//! ## Why this lives here
//!
//! `trap.rs` owns the vector asm + `_riscv_rust_trap_handler`; this
//! file owns the U-mode-specific syscall decoding + return
//! bookkeeping so future expansion (signal delivery, syscall
//! restart on EINTR, etc.) has a dedicated landing spot without
//! growing the generic trap dispatcher.

use super::SavedContext;
use crate::ipc::ProcessId;
use crate::syscalls::dispatcher::{SyscallContext, SyscallDispatcher};
use crate::syscalls::{SyscallArgs, SyscallError};

/// Handle `ecall` from U-mode.
///
/// Called from [`super::trap::_riscv_rust_trap_handler`]'s cause-8
/// arm. Reads syscall registers from the caller's SavedContext on the
/// kernel stack, dispatches, writes `a0` with the result, and bumps
/// `sepc` past the `ecall` instruction.
///
/// Returns the SavedContext pointer unchanged — no context switch
/// happens on the syscall path; the calling task resumes at
/// `sepc + 4` via `sret`.
///
/// # Safety
/// - Only the RISC-V trap vector may call this.
/// - `saved_sp` must point at a valid SavedContext built by the
///   vector's U→S entry path (sscratch/tp swap complete, user regs
///   captured, sepc/sstatus stored at offsets 256/264).
#[no_mangle]
pub unsafe extern "C" fn ecall_handler_inner(saved_sp: u64) -> u64 {
    // SAFETY: saved_sp is a kernel VA pointing at a live SavedContext.
    // gpr[..] occupies offsets 0..256 (32 × u64). Access as indexed
    // u64 pointer.
    let frame = saved_sp as *mut u64;

    // SAFETY: bounds below are < 32 (gpr slots); pointer math stays
    // within the 256-byte gpr region.
    let (syscall_num, arg1, arg2, arg3, arg4, arg5, arg6) = unsafe {
        (
            core::ptr::read_volatile(frame.add(17)), // a7 = syscall num
            core::ptr::read_volatile(frame.add(10)), // a0
            core::ptr::read_volatile(frame.add(11)), // a1
            core::ptr::read_volatile(frame.add(12)), // a2
            core::ptr::read_volatile(frame.add(13)), // a3
            core::ptr::read_volatile(frame.add(14)), // a4
            core::ptr::read_volatile(frame.add(15)), // a5
        )
    };

    // Resolve (task, process, cr3) from the current hart's scheduler.
    // Identical shape to AArch64's `svc_handler_inner`.
    let ctx_result = {
        let sched = crate::local_scheduler().lock();
        sched.as_ref().and_then(|s| {
            let tid = s.current_task()?;
            let task = s.current_task_ref()?;
            let pid = task.process_id.unwrap_or(ProcessId::new(tid.0, 0));
            Some((tid, pid, task.cr3))
        })
    };
    let (task_id, process_id, cr3) = match ctx_result {
        Some(info) => info,
        None => {
            // Write error to a0, skip past the ecall, keep the same
            // frame — we never had enough context to dispatch.
            let err = SyscallError::InvalidArg.as_i64() as u64;
            // SAFETY: `frame` points at the SavedContext built by the trap
            // vector (same invariant as the gpr reads at line 64). Offsets
            // 10 (a0) and 32 (sepc) lie within the 33-slot context
            // (gpr[0..32] + sepc at slot 32), so `frame.add(n)` stays in
            // bounds.
            unsafe {
                core::ptr::write_volatile(frame.add(10), err);
                let sepc = core::ptr::read_volatile(frame.add(32)); // offset 256
                core::ptr::write_volatile(frame.add(32), sepc.wrapping_add(4));
            }
            return saved_sp;
        }
    };

    let ctx = SyscallContext {
        process_id,
        task_id,
        cr3,
        caller_principal: None, // resolved inside dispatch()
    };
    let args = SyscallArgs::new(arg1, arg2, arg3, arg4, arg5, arg6);

    // Dispatch. `SYS_EXIT` doesn't return (handler loops on
    // yield_save_and_switch); other blocking syscalls yield
    // internally and resume here once woken. In all normal cases
    // we land below with a result to write back.
    let result = match SyscallDispatcher::dispatch(syscall_num, args, ctx) {
        Ok(v) => v as i64,
        Err(e) => e.as_i64(),
    };

    // Write a0 = return value; advance sepc past the ecall (4 bytes).
    // SAFETY: same as above — frame gpr[10] and sepc slot are valid.
    unsafe {
        core::ptr::write_volatile(frame.add(10), result as u64);
        let sepc = core::ptr::read_volatile(frame.add(32)); // offset 256
        core::ptr::write_volatile(frame.add(32), sepc.wrapping_add(4));
    }

    saved_sp
}

/// Unused — the trap vector (`super::trap::install`) is already what
/// installs `stvec`. Kept as a compile-time placeholder so code that
/// was wired against the R-1 stub compiles without churn. Safe to
/// delete in R-5 once the multi-hart AP path replaces trap-install
/// with a per-hart variant.
///
/// # Safety
/// No-op; kept for API parity with `arch::aarch64::syscall::init`.
#[allow(dead_code)]
pub unsafe fn init() {
    // trap::install already does the stvec write. No-op here.
    let _ = core::mem::size_of::<SavedContext>();
}
