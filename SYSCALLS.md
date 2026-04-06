# ArcOS Syscalls

This document describes the syscall interface that userspace processes (drivers, services) use to request kernel services. All 18 syscalls are fully implemented in [`src/syscalls/dispatcher.rs`](src/syscalls/dispatcher.rs).

## Overview

Syscalls are the interface between userspace and the microkernel. When a driver or service needs kernel assistance (memory allocation, IPC, interrupts, identity, object storage), it invokes a syscall. Every syscall passes through a zero-trust interceptor pre-check before dispatch.

User-space buffer access is performed via page-table walks through the process's page table root (CR3 on x86_64, TTBR0 on AArch64) using the HHDM. Buffers are capped at 4KB per syscall.

## ABI

### x86_64 — SYSCALL/SYSRET

The `syscall` instruction traps into the kernel. Entry point: [`src/arch/x86_64/syscall.rs`](src/arch/x86_64/syscall.rs).

| Register | Purpose |
|----------|---------|
| RAX | Syscall number (input), return value (output) |
| RDI | First argument |
| RSI | Second argument |
| RDX | Third argument |
| RCX | Fourth argument (clobbered by `syscall` — saved/restored by kernel) |
| R8  | Fifth argument |
| R9  | Sixth argument |

### AArch64 — SVC

The `svc #0` instruction generates a synchronous exception routed via VBAR_EL1. Entry point: [`src/arch/aarch64/syscall.rs`](src/arch/aarch64/syscall.rs). The exception handler verifies ESR_EL1 EC=0x15 (SVC from AArch64).

| Register | Purpose |
|----------|---------|
| x8 | Syscall number |
| x0-x5 | Arguments |
| x0 | Return value |

### Return Convention

- **Positive/zero**: Success (count, pointer, resource ID, or 0 for void-like calls)
- **Negative**: Error code (see [Error Codes](#error-codes))

---

## Syscall Reference

### SYS_EXIT (0)

Terminate the calling task. Marks the task as `Terminated` in the per-CPU scheduler. The next timer tick will context-switch away.

```
void sys_exit(int exit_code);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| exit_code | RDI / x0 | Exit code (0 = success) |

**Returns:** Technically returns the exit code, but the task is terminated and will not execute further.

---

### SYS_WRITE (1)

Send data through an IPC endpoint. The kernel reads the user buffer via page-table walk, builds an IPC `Message` with `sender_principal` stamped by the kernel (unforgeable), and enqueues it after capability + interceptor checks.

```
ssize_t sys_write(uint32_t endpoint_id, const void *buffer, size_t len);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| endpoint_id | RDI / x0 | Target endpoint ID |
| buffer | RSI / x1 | Pointer to data to send |
| len | RDX / x2 | Bytes to send (max 256) |

**Returns:** Bytes written on success.

**Errors:** `PermissionDenied` (no SEND capability), `InvalidArg` (bad buffer/len)

---

### SYS_READ (2)

Receive data from an IPC endpoint. Dequeues a message after capability + interceptor checks, then writes the payload to the user buffer.

```
ssize_t sys_read(uint32_t endpoint_id, void *buffer, size_t max_len);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| endpoint_id | RDI / x0 | Source endpoint ID |
| buffer | RSI / x1 | Receive buffer |
| max_len | RDX / x2 | Max bytes to read (max 256) |

**Returns:** Bytes read (0 if queue empty).

**Errors:** `PermissionDenied` (no RECEIVE capability), `InvalidArg` (bad buffer/len)

---

### SYS_ALLOCATE (3)

Allocate memory for the calling process. Assigns a virtual region via the process VMA tracker, allocates physical frames (per-CPU cache fast path), zeroes them, and maps into the process page table.

Includes full rollback on OOM: unmaps already-mapped pages, frees frames, removes VMA entry.

```
void* sys_allocate(size_t size, uint32_t flags);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| size | RDI / x0 | Bytes to allocate (max 1MB) |
| flags | RSI / x1 | Reserved (pass 0) |

**Returns:** User virtual address of allocation, or 0 on failure.

**Errors:** `InvalidArg` (size 0, >1MB, or kernel task), `OutOfMemory`

---

### SYS_FREE (4)

Free previously allocated memory. Looks up the allocation in the process VMA tracker, unmaps all pages, returns frames to the per-CPU cache, removes the VMA entry.

```
int sys_free(void* ptr, size_t size);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| ptr | RDI / x0 | Virtual address to free |
| size | RSI / x1 | Ignored (VMA tracks actual size) |

**Returns:** 0 on success.

**Errors:** `InvalidArg` (null pointer, kernel address, unknown VMA)

---

### SYS_WAIT_IRQ (5)

Block until a specific hardware interrupt fires. Registers the calling task as the handler for the IRQ, pins the task to the current CPU, routes the IRQ to that CPU (I/O APIC on x86_64, GIC SPI enable on AArch64), and blocks the task.

```
int sys_wait_irq(uint32_t irq_number);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| irq_number | RDI / x0 | IRQ number (0-223) |

**Returns:** 0 when the interrupt fires.

**Errors:** `InvalidArg` (IRQ >= 224 or block failed)

---

### SYS_REGISTER_ENDPOINT (6)

Register a message endpoint and grant the calling process full capabilities (send/recv/delegate) on it.

```
int sys_register_endpoint(uint32_t endpoint_id, uint32_t flags);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| endpoint_id | RDI / x0 | Endpoint to register |
| flags | RSI / x1 | Reserved (pass 0) |

**Returns:** 0 on success.

**Errors:** `EndpointNotFound` (id >= MAX_ENDPOINTS), `PermissionDenied`

---

### SYS_YIELD (7)

Voluntarily yield the CPU. Sets the calling task Ready with zero time remaining, causing the scheduler to pick another task on the next timer tick.

```
int sys_yield(void);
```

**Returns:** 0 (always succeeds).

---

### SYS_GET_PID (8)

Get the current process ID.

```
uint32_t sys_get_pid(void);
```

**Returns:** Process ID of the calling task.

---

### SYS_GET_TIME (9)

Get the current system time in scheduler ticks (monotonically increasing, 100Hz).

```
uint64_t sys_get_time(void);
```

**Returns:** Tick count.

---

### SYS_PRINT (10)

Print a user-provided string to the kernel serial console. Reads the buffer via page-table walk. Intended for debugging.

```
ssize_t sys_print(const void *buffer, size_t len);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| buffer | RDI / x0 | String buffer (user vaddr) |
| len | RSI / x1 | Bytes to print (max 256) |

**Returns:** Bytes printed.

**Errors:** `InvalidArg` (len 0 or >256, bad buffer)

---

### SYS_BIND_PRINCIPAL (11)

Bind a cryptographic Principal (32-byte Ed25519 public key) to a process. **Restricted:** only callable by a process whose own Principal matches the bootstrap Principal.

```
int sys_bind_principal(uint32_t process_id, const void *pubkey, uint32_t pubkey_len);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| process_id | RDI / x0 | Target process to bind |
| pubkey | RSI / x1 | 32-byte public key (user vaddr) |
| pubkey_len | RDX / x2 | Must be 32 |

**Returns:** 0 on success.

**Errors:** `InvalidArg` (len != 32), `PermissionDenied` (caller is not bootstrap Principal)

---

### SYS_GET_PRINCIPAL (12)

Read the calling process's bound Principal (32-byte public key).

```
int sys_get_principal(void *out_buf, uint32_t buf_len);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| out_buf | RDI / x0 | Output buffer (user vaddr) |
| buf_len | RSI / x1 | Must be >= 32 |

**Returns:** 32 on success (bytes written).

**Errors:** `InvalidArg` (buf_len < 32, no Principal bound)

---

### SYS_RECV_MSG (13)

Receive an IPC message with sender identity metadata. Unlike `SYS_READ`, the response includes the sender's Principal and originating endpoint.

```
ssize_t sys_recv_msg(uint32_t endpoint_id, void *buf, size_t buf_len);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| endpoint_id | RDI / x0 | Endpoint to receive from |
| buf | RSI / x1 | Output buffer (user vaddr) |
| buf_len | RDX / x2 | Buffer size (must be >= 36) |

**Response layout:**
```
[sender_principal: 32 bytes][from_endpoint: 4 bytes LE][payload: N bytes]
```

**Returns:** Total bytes written (>= 36), or 0 if no message.

**Errors:** `InvalidArg` (buf_len < 36), `PermissionDenied` (no RECEIVE capability)

---

### SYS_OBJ_PUT (14)

Store an ArcObject in the kernel object store. The caller's Principal becomes both author and owner. Content is hashed (FNV-1a, Phase 0) and stored.

```
ssize_t sys_obj_put(const void *content, size_t content_len, void *out_hash);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| content | RDI / x0 | Object content (user vaddr) |
| content_len | RSI / x1 | Content size (1-4096 bytes) |
| out_hash | RDX / x2 | 32-byte output for content hash |

**Returns:** 0 on success.

**Errors:** `InvalidArg` (empty/oversized content, kernel task), `PermissionDenied` (no Principal bound), `OutOfMemory` (store at capacity — 256 objects max)

---

### SYS_OBJ_GET (15)

Retrieve object content by its 32-byte content hash.

```
ssize_t sys_obj_get(const void *hash, void *out_buf, size_t out_buf_len);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| hash | RDI / x0 | 32-byte content hash (user vaddr) |
| out_buf | RSI / x1 | Output buffer |
| out_buf_len | RDX / x2 | Buffer size |

**Returns:** Bytes written (may be less than content if buffer is smaller).

**Errors:** `InvalidArg` (bad buffer, kernel task), `EndpointNotFound` (hash not in store — reuses error code)

---

### SYS_OBJ_DELETE (16)

Delete an object from the store. **Ownership enforced:** only the object's owner can delete it.

```
ssize_t sys_obj_delete(const void *hash);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| hash | RDI / x0 | 32-byte content hash (user vaddr) |

**Returns:** 0 on success.

**Errors:** `InvalidArg` (kernel task), `PermissionDenied` (caller is not owner or has no Principal), `EndpointNotFound` (hash not in store)

---

### SYS_OBJ_LIST (17)

List all object hashes in the store. Writes packed 32-byte hashes to the user buffer.

```
ssize_t sys_obj_list(void *out_buf, size_t out_buf_len);
```

| Arg | Register (x86/arm) | Description |
|-----|---------------------|-------------|
| out_buf | RDI / x0 | Output buffer for packed hashes |
| out_buf_len | RSI / x1 | Buffer size (must be >= 32) |

**Returns:** Number of objects listed (not bytes — each is 32 bytes).

**Errors:** `InvalidArg` (kernel task, buffer < 32 bytes)

---

## Error Codes

| Error | Value | Meaning |
|-------|-------|---------|
| Success | 0 | Operation succeeded |
| InvalidArg | -1 | Invalid argument (bad pointer, size, etc.) |
| PermissionDenied | -2 | Insufficient capabilities or identity check failed |
| OutOfMemory | -3 | No memory or store capacity available |
| EndpointNotFound | -4 | Endpoint or object hash doesn't exist |
| WouldBlock | -5 | Non-blocking operation, no data available |
| Interrupted | -6 | Interrupted by signal (reserved) |
| Enosys | -38 | Unknown syscall number |

## Capability-Based Access Control

All IPC syscalls are subject to capability checks via [`src/ipc/capability.rs`](src/ipc/capability.rs):

- **SYS_WRITE / SYS_READ / SYS_RECV_MSG**: Require SEND or RECEIVE capability on the endpoint
- **SYS_REGISTER_ENDPOINT**: Grants FULL capability (send/recv/delegate) to the caller

Additionally, the zero-trust interceptor ([`src/ipc/interceptor.rs`](src/ipc/interceptor.rs)) runs a pre-dispatch policy check on every syscall and enforces send/recv hooks on IPC operations.

## Identity-Aware IPC

IPC messages carry an unforgeable `sender_principal` field, stamped by the kernel in `send_message_with_capability()`. This enables receiver-side identity verification without trusting the sender's self-reported identity. `SYS_RECV_MSG` exposes this metadata to userspace.

The bootstrap Principal (deterministic seed in Phase 0, real entropy planned for Phase 1) is bound to kernel processes at boot and is the only identity authorized to call `SYS_BIND_PRINCIPAL`.

## Usage Patterns

### FS Service (real example — [`user/fs-service/`](user/fs-service/))

The filesystem service runs on endpoint 16 and demonstrates the full syscall surface:

```rust
// Register endpoint and enter service loop
sys_register_endpoint(16, 0);

loop {
    // Identity-aware receive
    let n = sys_recv_msg(16, buf, buf_len);
    if n == 0 { sys_yield(); continue; }

    // Parse: [principal:32][endpoint:4][command|payload]
    let sender = &buf[0..32];
    let cmd = buf[36];

    match cmd {
        CMD_PUT => {
            let hash = sys_obj_put(&buf[37..], content_len, &mut hash_buf);
            sys_write(from_endpoint, &response, resp_len);
        }
        CMD_GET => {
            let n = sys_obj_get(&hash, &mut content_buf, buf_len);
            sys_write(from_endpoint, &content_buf[..n], n);
        }
        CMD_DELETE => {
            sys_obj_delete(&hash);  // Ownership enforced by kernel
        }
        CMD_LIST => {
            let count = sys_obj_list(&mut list_buf, list_buf_len);
            sys_write(from_endpoint, &list_buf, count * 32);
        }
    }
}
```

### Device Driver Pattern

```rust
// Register endpoint for driver communication
sys_register_endpoint(DRIVER_ENDPOINT, 0);

loop {
    // Block until hardware interrupt fires
    // (pins task to CPU, routes IRQ via I/O APIC or GIC)
    sys_wait_irq(IRQ_NUMBER);

    // Handle interrupt, send data to consumers
    let data = read_device_registers();
    sys_write(DRIVER_ENDPOINT, &data, data.len());
}
```

## Future Enhancements

- AArch64 user-space syscall wrappers (fs-service currently x86_64 only)
- `SYS_MPROTECT` — change page permissions on existing mappings
- `SYS_SPAWN` — create a new process from an ELF image
- `SYS_NANOSLEEP` / `SYS_CLOCK_GETTIME` — wall-clock time
- Blake3 content hashing + Ed25519 signature verification (Phase 1B)
