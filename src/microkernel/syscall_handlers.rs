//! Syscall handler implementations
//!
//! Real implementations for syscalls that need access to kernel state.
//! These run in privileged mode and have access to the scheduler, IPC manager, etc.

use arcos_core::syscalls::{SyscallNumber, SyscallArgs, SyscallError};
use arcos_core::ipc::{ProcessId, EndpointId, Message, CapabilityRights};
use arcos_core::scheduler::{TaskId, BlockReason};

/// Result type for syscall implementations
pub type SyscallResult = Result<i64, SyscallError>;

/// Handle SYS_GET_PID - return process ID (already in dispatcher)
pub fn handle_get_pid(process_id: ProcessId) -> SyscallResult {
    Ok(process_id.0 as i64)
}

/// Handle SYS_GET_TIME - return system ticks (already in dispatcher)
pub fn handle_get_time() -> SyscallResult {
    let ticks = arcos_core::scheduler::Timer::get_ticks();
    Ok(ticks as i64)
}

/// Handle SYS_YIELD - yield CPU to scheduler
pub fn handle_yield(current_task: TaskId, scheduler: &mut Option<&mut super::super::scheduler::Scheduler>) -> SyscallResult {
    // If we have the scheduler, put current task back in ready queue
    // Next scheduler tick will select a different task
    if let Some(sched) = scheduler {
        // TODO: Signal that this task is ready to be preempted
        // For now, just acknowledge
    }
    Ok(0)
}

/// Handle SYS_EXIT - terminate process  
pub fn handle_exit(exit_code: u32, process_id: ProcessId, task_id: TaskId) -> SyscallResult {
    crate::println!("[Syscall] EXIT pid={:?} task={:?} code={}", process_id, task_id, exit_code);
    // TODO: Mark task as terminated, add to cleanup queue
    Ok(exit_code as i64)
}

/// Handle SYS_ALLOCATE - allocate memory
pub fn handle_allocate(size: usize, _flags: u32, process_id: ProcessId) -> SyscallResult {
    if size == 0 || size > 1024 * 1024 {  // Max 1MB per allocation
        return Err(SyscallError::InvalidArg);
    }
    
    crate::println!("[Syscall] ALLOCATE pid={:?} size={}", process_id, size);
    
    // TODO: Use a real heap allocator (for now return dummy address)
    // In a full system, would maintain per-process heaps
    let addr = 0x10000 + (process_id.0 * 0x10000) as u64;  // Simple offset per process
    Ok(addr as i64)
}

/// Handle SYS_FREE - free memory
pub fn handle_free(ptr: u64, size: usize, process_id: ProcessId) -> SyscallResult {
    if ptr == 0 || size == 0 {
        return Err(SyscallError::InvalidArg);
    }
    
    crate::println!("[Syscall] FREE pid={:?} ptr={:#x} size={}", process_id, ptr, size);
    
    // TODO: Validate and deallocate
    Ok(0)
}

/// Handle SYS_WRITE - send data through endpoint with capability check
pub fn handle_write(
    process_id: ProcessId,
    endpoint_id: u32,
    _buffer: *const u8,
    len: usize,
    ipc_mgr: &arcos_core::ipc::IpcManager,
    cap_mgr: &arcos_core::ipc::capability::CapabilityManager,
) -> SyscallResult {
    // Check capability
    let endpoint = EndpointId(endpoint_id);
    cap_mgr.verify_access(
        process_id,
        endpoint,
        CapabilityRights::SEND_ONLY,
    ).map_err(|_| SyscallError::PermissionDenied)?;
    
    crate::println!("[Syscall] WRITE pid={:?} ep={} len={}", process_id, endpoint_id, len);
    
    // TODO: Actually copy buffer and queue message
    Ok(len as i64)
}

/// Handle SYS_READ - receive data from endpoint with capability check  
pub fn handle_read(
    process_id: ProcessId,
    endpoint_id: u32,
    _buffer: *mut u8,
    max_len: usize,
    ipc_mgr: &arcos_core::ipc::IpcManager,
    cap_mgr: &arcos_core::ipc::capability::CapabilityManager,
) -> SyscallResult {
    // Check capability
    let endpoint = EndpointId(endpoint_id);
    cap_mgr.verify_access(
        process_id,
        endpoint,
        CapabilityRights::RECV_ONLY,
    ).map_err(|_| SyscallError::PermissionDenied)?;
    
    crate::println!("[Syscall] READ pid={:?} ep={} maxlen={}", process_id, endpoint_id, max_len);
    
    // TODO: Actually dequeue message and copy to buffer
    Ok(0)
}

/// Handle SYS_REGISTER_ENDPOINT - register a message endpoint
pub fn handle_register_endpoint(
    process_id: ProcessId,
    endpoint_id: u32,
    _flags: u32,
    cap_mgr: &mut arcos_core::ipc::capability::CapabilityManager,
) -> SyscallResult {
    let endpoint = EndpointId(endpoint_id);
    
    // Grant full RWD capabilities on this endpoint to the process
    cap_mgr.grant_capability(
        process_id,
        endpoint,
        CapabilityRights::FULL,
    ).map_err(|_| SyscallError::InvalidArg)?;
    
    crate::println!("[Syscall] REGISTER_ENDPOINT pid={:?} ep={}", process_id, endpoint_id);
    Ok(0)
}

/// Handle SYS_WAIT_IRQ - wait for interrupt
pub fn handle_wait_irq(
    process_id: ProcessId,
    task_id: TaskId,
    irq_num: u32,
) -> SyscallResult {
    crate::println!("[Syscall] WAIT_IRQ pid={:?} task={:?} irq={}", process_id, task_id, irq_num);
    
    // TODO: Register task as handler for this IRQ, block until it fires
    Ok(0)
}
