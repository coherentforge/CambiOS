# ArcOS Syscalls

This document describes the syscall interface that userspace processes (drivers, services) use to request kernel services.

## Overview

Syscalls are the interface between userspace and the microkernel. When a driver needs kernel assistance (memory allocation, IPC, interrupts), it invokes a syscall.

## ABI: x86-64 System V Convention

All syscalls follow the x86-64 System V ABI:

| Register | Purpose |
|----------|---------|
| RAX | Syscall number (input), return value (output) |
| RDI | First argument |
| RSI | Second argument |
| RDX | Third argument |
| RCX | Fourth argument |
| R8  | Fifth argument |
| R9  | Sixth argument |

Return values:
- **Positive/zero**: Success (often a count, pointer, or resource ID)
- **Negative**: Error code (see SyscallError enum)

## Syscall Reference

### SYS_EXIT (0)

Terminate the calling process.

```c
void sys_exit(int exit_code);
```

**Arguments:**
- `exit_code` (RDI): Exit code (typically 0 for success)

**Returns:** Never returns; process is terminated

**Errors:** None (always terminates)

**Example:**
```rust
if error {
    sys_exit(1);
}
```

---

### SYS_WRITE (1)

Send data through a message endpoint.

```c
ssize_t sys_write(uint32_t endpoint_id, const void *buffer, size_t len);
```

**Arguments:**
- `endpoint_id` (RDI): Target endpoint ID
- `buffer` (RSI): Pointer to data to send
- `len` (RDX): Number of bytes to send

**Returns:**
- ≥0: Number of bytes written
- <0: Error code (EACCES, ENOENT, etc.)

**Errors:**
- `PermissionDenied (-2)`: No SEND capability on endpoint
- `EndpointNotFound (-4)`: Endpoint doesn't exist

**Example:**
```rust
let data = b"Hello, driver!";
let n = sys_write(SERIAL_ENDPOINT, data.as_ptr(), data.len());
if n < 0 {
    println!("Write failed: {}", n);
}
```

---

### SYS_READ (2)

Receive data from a message endpoint.

```c
ssize_t sys_read(uint32_t endpoint_id, void *buffer, size_t max_len);
```

**Arguments:**
- `endpoint_id` (RDI): Source endpoint ID
- `buffer` (RSI): Pointer to receive buffer
- `max_len` (RDX): Maximum bytes to read

**Returns:**
- ≥0: Number of bytes read (0 if queue empty, blocks if capability allows)
- <0: Error code

**Errors:**
- `PermissionDenied (-2)`: No RECEIVE capability on endpoint
- `EndpointNotFound (-4)`: Endpoint doesn't exist
- `WouldBlock (-5)`: Non-blocking read, no data available

**Example:**
```rust
let mut buf = [0u8; 256];
let n = sys_read(SERIAL_ENDPOINT, &mut buf as *mut _ as *mut u8, buf.len());
if n > 0 {
    println!("Read {} bytes", n);
}
```

---

### SYS_ALLOCATE (3)

Allocate memory for the process.

```c
void* sys_allocate(size_t size, uint32_t flags);
```

**Arguments:**
- `size` (RDI): Number of bytes to allocate
- `flags` (RSI): Allocation flags (reserved, pass 0)

**Returns:**
- Non-zero: Virtual address of allocated memory
- 0: Allocation failed

**Errors:** (implicit in return value)
- Out of memory
- Invalid size

**Example:**
```rust
let ptr = sys_allocate(4096, 0);
if ptr != 0 {
    let buf = unsafe {
        core::slice::from_raw_parts_mut(ptr as *mut u8, 4096)
    };
    buf.fill(0);
}
```

---

### SYS_FREE (4)

Free previously allocated memory.

```c
int sys_free(void* ptr, size_t size);
```

**Arguments:**
- `ptr` (RDI): Pointer to free
- `size` (RSI): Size of allocation (must match original)

**Returns:**
- 0: Success
- <0: Error code

**Errors:**
- `InvalidArg (-1)`: Invalid pointer or size mismatch

**Example:**
```rust
sys_free(ptr, 4096)?;
```

---

### SYS_WAIT_IRQ (5)

Wait for a specific hardware interrupt to fire.

```c
int sys_wait_irq(uint32_t irq_number);
```

**Arguments:**
- `irq_number` (RDI): IRQ number to wait for (0-15 for PC)

**Returns:**
- 0: Interrupt fired
- <0: Error code

**Errors:**
- `PermissionDenied (-2)`: Process not authorized for this IRQ
- `InvalidArg (-1)`: Invalid IRQ number

**Example:**
```rust
// Register keyboard driver for IRQ 1
sys_wait_irq(1);  // Blocks until keyboard interrupt
// ... handle interrupt ...
sys_wait_irq(1);  // Wait for next interrupt
```

---

### SYS_REGISTER_ENDPOINT (6)

Register a new message endpoint for this process.

```c
int sys_register_endpoint(uint32_t endpoint_id, uint32_t flags);
```

**Arguments:**
- `endpoint_id` (RDI): Endpoint number to register
- `flags` (RSI): Flags (reserved, pass 0)

**Returns:**
- 0: Success
- <0: Error code

**Errors:**
- `InvalidArg (-1)`: Endpoint already registered
- `PermissionDenied (-2)`: Not allowed to register this endpoint

**Example:**
```rust
sys_register_endpoint(10, 0)?;  // Register endpoint 10
// Now this process can send/receive on endpoint 10
```

---

### SYS_YIELD (7)

Voluntarily yield the CPU to the scheduler.

```c
int sys_yield(void);
```

**Arguments:** None

**Returns:** 0 (always succeeds)

**Example:**
```rust
// Let another task run
sys_yield();
```

---

### SYS_GET_PID (8)

Get the current process ID.

```c
uint32_t sys_get_pid(void);
```

**Arguments:** None

**Returns:** Process ID of calling process

**Example:**
```rust
let my_pid = sys_get_pid();
println!("I am process {}", my_pid);
```

---

### SYS_GET_TIME (9)

Get the current system time in scheduler ticks.

```c
uint64_t sys_get_time(void);
```

**Arguments:** None

**Returns:** System time in ticks (monotonic increasing)

**Example:**
```rust
let t0 = sys_get_time();
do_work();
let t1 = sys_get_time();
println!("Took {} ticks", t1 - t0);
```

---

## Error Codes

All error-returning syscalls use negative return values:

| Error | Value | Meaning |
|-------|-------|---------|
| Success | 0 | Operation succeeded |
| InvalidArg | -1 | Invalid argument |
| PermissionDenied | -2 | Insufficient capabilities |
| OutOfMemory | -3 | No memory available |
| EndpointNotFound | -4 | Endpoint doesn't exist |
| WouldBlock | -5 | Operation would block (future) |
| Interrupted | -6 | Interrupted by signal (future) |
| Enosys | -38 | Unknown syscall |

## Capability-Based Access Control

All IPC syscalls (`sys_write`, `sys_read`, `sys_register_endpoint`) are subject to capability checks.

- **SYS_WRITE**: Requires SEND capability on target endpoint
- **SYS_READ**: Requires RECEIVE capability on source endpoint
- **SYS_REGISTER_ENDPOINT**: Requires special privilege (only kernel can grant)

The kernel's capability manager (see [../src/ipc/capability.rs](../src/ipc/capability.rs)) controls which processes can communicate.

## Usage Patterns

### Simple Driver: Keyboard Handler

```rust
// Initialize
sys_register_endpoint(10, 0)?;

// Main loop
loop {
    // Wait for keyboard interrupt
    sys_wait_irq(1);
    
    // Read keyboard data
    let mut buf = [0u8; 256];
    let n = sys_read(10, &mut buf, buf.len())?;
    
    // Process keyboard event
    handle_keyboard(&buf[..n as usize]);
}
```

### Message-Passing Service

```rust
// Register endpoints
sys_register_endpoint(20, 0)?;  // Incoming requests
sys_register_endpoint(21, 0)?;  // Outgoing responses

// Main loop
loop {
    // Wait for request
    let mut req = [0u8; 256];
    let n = sys_read(20, &mut req, req.len())?;
    
    // Process and generate response
    let response = process_request(&req[..n]);
    
    // Send response
    sys_write(21, response.as_ptr(), response.len())?;
}
```

## Known Limitations

Current implementation is **stub/placeholder**:
- Syscalls log but don't fully implement behavior
- Direct IPC through global structures (not via `syscall` instruction)
- No actual system call traps to privileged mode
- Memory allocation returns dummy addresses

This will be replaced with full implementation as ArcOS development continues.

## Future Enhancements

- [ ] Non-blocking I/O syscalls
- [ ] Signal handling (SYS_SIGNAL, SYS_SIGACTION)
- [ ] Memory protection (SYS_MPROTECT, SYS_MMAP)
- [ ] Process creation (SYS_FORK, SYS_EXEC)
- [ ] Device I/O (SYS_IOCTL)
- [ ] Timing (SYS_NANOSLEEP, SYS_CLOCK_GETTIME)
