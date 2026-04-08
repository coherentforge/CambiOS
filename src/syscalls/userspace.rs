// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Userspace syscall library
//!
//! Provides convenient wrapper functions for drivers to invoke syscalls.
//! These functions should be used by userspace process code to request kernel services.

use crate::syscalls::SyscallArgs;

/// Write data to an endpoint
///
/// # Arguments
/// - `endpoint_id`: Target endpoint ID
/// - `buffer`: Pointer to data to send
/// - `len`: Number of bytes to send
///
/// # Returns
/// Number of bytes sent, or negative error code
///
/// # Example
/// ```ignore
/// let data = b"Hello";
/// let n = sys_write(10, data.as_ptr(), data.len());
/// if n > 0 {
///     println!("Sent {} bytes", n);
/// }
/// ```
pub fn sys_write(endpoint_id: u32, buffer: *const u8, len: usize) -> i64 {
    // In a real system, this would invoke `syscall` instruction
    // For now, we use a direct call (requires being in same address space)
    //
    // Real implementation:
    // asm!(
    //     "mov rax, 1",           // SYS_WRITE
    //     "mov rdi, rdi",         // endpoint_id
    //     "mov rsi, rsi",         // buffer
    //     "mov rdx, rdx",         // len
    //     "syscall",
    //     out("rax") ret,
    //     in("rdi") endpoint_id,
    //     in("rsi") buffer,
    //     in("rdx") len,
    // );
    
    let _args = SyscallArgs::new(
        endpoint_id as u64,
        buffer as u64,
        len as u64,
        0, 0, 0,
    );
    
    // TODO: Call kernel syscall handler
    -1  // For now, always fails
}

/// Read data from an endpoint
///
/// # Arguments
/// - `endpoint_id`: Source endpoint ID
/// - `buffer`: Pointer to receive buffer
/// - `max_len`: Maximum bytes to read
///
/// # Returns
/// Number of bytes read, or negative error code
///
/// # Example
/// ```ignore
/// let mut buf = [0u8; 256];
/// let n = sys_read(10, buf.as_mut_ptr(), buf.len());
/// if n > 0 {
///     println!("Received {} bytes", n);
/// }
/// ```
pub fn sys_read(endpoint_id: u32, buffer: *mut u8, max_len: usize) -> i64 {
    let _args = SyscallArgs::new(
        endpoint_id as u64,
        buffer as u64,
        max_len as u64,
        0, 0, 0,
    );
    
    // TODO: Call kernel syscall handler
    -1  // For now, always fails
}

/// Allocate memory for the process
///
/// # Arguments
/// - `size`: Number of bytes to allocate
/// - `flags`: Allocation flags (reserved for future use)
///
/// # Returns
/// Pointer to allocated memory, or 0 on failure
///
/// # Example
/// ```ignore
/// let ptr = sys_allocate(4096, 0);
/// if ptr != 0 {
///     let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, 4096) };
///     buf.fill(0);
/// }
/// ```
pub fn sys_allocate(size: usize, flags: u32) -> u64 {
    let _args = SyscallArgs::new(
        size as u64,
        flags as u64,
        0, 0, 0, 0,
    );
    
    // TODO: Call kernel syscall handler
    0  // For now, always fails
}

/// Free previously allocated memory
///
/// # Arguments
/// - `ptr`: Pointer to free
/// - `size`: Size of allocation (must match original allocation)
///
/// # Returns
/// 0 on success, negative error code on failure
///
/// # Example
/// ```ignore
/// let ptr = sys_allocate(4096, 0);
/// if ptr != 0 {
///     sys_free(ptr, 4096);
/// }
/// ```
pub fn sys_free(ptr: u64, size: usize) -> i64 {
    let _args = SyscallArgs::new(
        ptr,
        size as u64,
        0, 0, 0, 0,
    );
    
    // TODO: Call kernel syscall handler
    -1  // For now, always fails
}

/// Wait for a specific interrupt to fire
///
/// # Arguments
/// - `irq_number`: IRQ number to wait for
///
/// # Returns
/// 0 on success, negative error code on failure
///
/// # Example
/// ```ignore
/// // Register this task to handle keyboard interrupts
/// sys_wait_irq(1);  // Wait for IRQ 1 (keyboard)
/// // Driver is blocked until keyboard interrupt fires
/// ```
pub fn sys_wait_irq(irq_number: u32) -> i64 {
    let _args = SyscallArgs::new(irq_number as u64, 0, 0, 0, 0, 0);
    
    // TODO: Call kernel syscall handler
    -1  // For now, always fails
}

/// Register a message endpoint for this process
///
/// # Arguments
/// - `endpoint_id`: Endpoint to register
/// - `flags`: Endpoint flags (reserved)
///
/// # Returns
/// 0 on success, negative error code on failure
///
/// # Example
/// ```ignore
/// sys_register_endpoint(10, 0)?;  // Register endpoint 10
/// ```
pub fn sys_register_endpoint(endpoint_id: u32, flags: u32) -> i64 {
    let _args = SyscallArgs::new(
        endpoint_id as u64,
        flags as u64,
        0, 0, 0, 0,
    );
    
    // TODO: Call kernel syscall handler
    -1  // For now, always fails
}

/// Yield CPU to scheduler (voluntary context switch)
///
/// # Example
/// ```ignore
/// sys_yield();  // Let another task run
/// ```
pub fn sys_yield() -> i64 {
    let _args = SyscallArgs::new(0, 0, 0, 0, 0, 0);
    
    // TODO: Call kernel syscall handler
    0
}

/// Get current process ID
///
/// # Returns
/// Process ID of calling task
///
/// # Example
/// ```ignore
/// let pid = sys_get_pid();
/// println!("I am process {}", pid);
/// ```
pub fn sys_get_pid() -> u32 {
    // TODO: Call kernel syscall handler
    0
}

/// Get current system time (in ticks)
///
/// # Returns
/// System time in scheduler ticks
///
/// # Example
/// ```ignore
/// let t0 = sys_get_time();
/// do_work();
/// let t1 = sys_get_time();
/// println!("Took {} ticks", t1 - t0);
/// ```
pub fn sys_get_time() -> u64 {
    // TODO: Call kernel syscall handler
    0
}

/// Exit the process with exit code
///
/// # Arguments
/// - `exit_code`: Exit code to return
///
/// # Note
/// This function never returns; it terminates the calling process.
///
/// # Example
/// ```ignore
/// if error {
///     sys_exit(1);
/// }
/// ```
pub fn sys_exit(exit_code: u32) -> ! {
    let _args = SyscallArgs::new(exit_code as u64, 0, 0, 0, 0, 0);
    
    // TODO: Call kernel syscall handler
    loop { }  // Should not reach here
}
