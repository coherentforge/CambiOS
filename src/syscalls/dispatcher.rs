//! Syscall dispatcher and handlers
//!
//! Routes syscalls from userspace to appropriate kernel handlers.
//! Enforces capability checks and manages process state.

use crate::syscalls::{SyscallNumber, SyscallArgs, SyscallResult, SyscallError};
use crate::scheduler::TaskId;
use crate::ipc::ProcessId;

/// Syscall handler context
/// 
/// Passed to each syscall handler to give it access to kernel state.
/// In a full system, this would be protected by the privilege level boundary.
pub struct SyscallContext {
    /// Calling process ID
    pub process_id: ProcessId,
    /// Calling task ID
    pub task_id: TaskId,
}

/// Dispatcher that routes syscalls to handlers
pub struct SyscallDispatcher;

impl SyscallDispatcher {
    /// Dispatch a syscall to its handler
    /// 
    /// This is the main entry point called when userspace invokes a syscall.
    /// Returns the syscall result (typically stored in RAX by caller).
    pub fn dispatch(
        syscall_num: u64,
        args: SyscallArgs,
        ctx: &SyscallContext,
    ) -> SyscallResult {
        let num = match SyscallNumber::from_u64(syscall_num) {
            Some(n) => n,
            None => return Err(SyscallError::Enosys),
        };

        match num {
            SyscallNumber::Exit => Self::handle_exit(args, ctx),
            SyscallNumber::Write => Self::handle_write(args, ctx),
            SyscallNumber::Read => Self::handle_read(args, ctx),
            SyscallNumber::Allocate => Self::handle_allocate(args, ctx),
            SyscallNumber::Free => Self::handle_free(args, ctx),
            SyscallNumber::WaitIrq => Self::handle_wait_irq(args, ctx),
            SyscallNumber::RegisterEndpoint => Self::handle_register_endpoint(args, ctx),
            SyscallNumber::Yield => Self::handle_yield(args, ctx),
            SyscallNumber::GetPid => Self::handle_get_pid(args, ctx),
            SyscallNumber::GetTime => Self::handle_get_time(args, ctx),
        }
    }

    /// SYS_EXIT: Terminate process
    fn handle_exit(args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        let exit_code = args.arg1_u32();
        crate::println!("  [Syscall] EXIT code={}", exit_code);
        
        // TODO: Actually terminate the process
        Ok(0)
    }

    /// SYS_WRITE: Send data through endpoint
    fn handle_write(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let _endpoint_id = args.arg1_u32();
        let _buffer = args.arg2_ptr::<u8>();
        let len = args.arg_usize(3);

        crate::println!(
            "  [Syscall] WRITE pid={:?} endpoint={} len={}",
            ctx.process_id, _endpoint_id, len
        );

        // TODO: Validate buffer, write through IPC with capability check
        Ok(len as u64)
    }

    /// SYS_READ: Receive data from endpoint
    fn handle_read(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let _endpoint_id = args.arg1_u32();
        let _buffer = args.arg2_mut_ptr::<u8>();
        let len = args.arg_usize(3);

        crate::println!(
            "  [Syscall] READ pid={:?} endpoint={} buflen={}",
            ctx.process_id, _endpoint_id, len
        );

        // TODO: Validate buffer, read from IPC with capability check
        Ok(0) // bytes read
    }

    /// SYS_ALLOCATE: Allocate memory for process
    fn handle_allocate(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let size = args.arg_usize(1);
        let _flags = args.arg1_u32(); // unused for now

        crate::println!(
            "  [Syscall] ALLOCATE pid={:?} size={}",
            ctx.process_id, size
        );

        // TODO: Allocate from process heap
        Ok(0x1000) // dummy address
    }

    /// SYS_FREE: Free allocated memory
    fn handle_free(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let ptr = args.arg1 as usize;
        let size = args.arg_usize(2);

        crate::println!(
            "  [Syscall] FREE pid={:?} ptr={:#x} size={}",
            ctx.process_id, ptr, size
        );

        // TODO: Validate and free the memory
        Ok(0)
    }

    /// SYS_WAIT_IRQ: Wait for specific interrupt
    fn handle_wait_irq(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let irq_num = args.arg1_u32();

        crate::println!(
            "  [Syscall] WAIT_IRQ pid={:?} irq={}",
            ctx.process_id, irq_num
        );

        // TODO: Check if process has capability for this IRQ
        // Then block until interrupt fires
        Ok(0)
    }

    /// SYS_REGISTER_ENDPOINT: Register message endpoint
    fn handle_register_endpoint(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();
        let _flags = args.arg2_u32();

        crate::println!(
            "  [Syscall] REGISTER_ENDPOINT pid={:?} ep={}",
            ctx.process_id, endpoint_id
        );

        // TODO: Allocate endpoint, grant capability to process
        Ok(0)
    }

    /// SYS_YIELD: Voluntarily yield CPU
    fn handle_yield(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        crate::println!("  [Syscall] YIELD");
        
        // TODO: Trigger context switch
        Ok(0)
    }

    /// SYS_GET_PID: Get current process ID
    fn handle_get_pid(_args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        Ok(ctx.process_id.0 as u64)
    }

    /// SYS_GET_TIME: Get system time in ticks
    fn handle_get_time(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        let ticks = crate::scheduler::Timer::get_ticks();
        Ok(ticks)
    }
}
