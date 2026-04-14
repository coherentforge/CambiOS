// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS user-space syscall library
//!
//! Safe wrappers around architecture-specific syscall instructions. This is
//! the ONLY crate in user-space that contains `unsafe` code. All other
//! user-space crates should use `#![forbid(unsafe_code)]` and call these
//! safe functions.
//!
//! ## Architecture conventions
//!
//! | Arch    | Instruction | Syscall # | Args       | Return |
//! |---------|-------------|-----------|------------|--------|
//! | x86_64  | `syscall`   | RAX       | RDI..R9    | RAX    |
//! | AArch64 | `svc #0`    | x8        | x0..x5     | x0     |

#![no_std]

// Syscall numbers (must match kernel src/syscalls/mod.rs)
const SYS_EXIT: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_REGISTER_ENDPOINT: u64 = 6;
const SYS_YIELD: u64 = 7;
const SYS_GET_PID: u64 = 8;
const SYS_PRINT: u64 = 10;
const SYS_RECV_MSG: u64 = 13;
const SYS_OBJ_PUT: u64 = 14;
const SYS_OBJ_GET: u64 = 15;
const SYS_OBJ_DELETE: u64 = 16;
const SYS_OBJ_LIST: u64 = 17;
const SYS_CLAIM_BOOTSTRAP_KEY: u64 = 18;
const SYS_OBJ_PUT_SIGNED: u64 = 19;

// ============================================================================
// Raw syscall primitives — the ONLY unsafe code in user-space
// ============================================================================

// ----------------------------------------------------------------------------
// x86_64: SYSCALL instruction
// ----------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn syscall_raw3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: Invokes the kernel syscall handler via the SYSCALL instruction.
    // The kernel validates all arguments.
    //
    // Clobbers: The CPU clobbers RCX (saved RIP) and R11 (saved RFLAGS).
    // The kernel syscall stub does NOT restore RDI, RSI, RDX, R8, R9, R10
    // (they are caller-saved in the SysV ABI and discarded when the
    // SyscallFrame is cleaned up with `add rsp, 56`).
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            inlateout("rdi") arg1 => _,
            inlateout("rsi") arg2 => _,
            inlateout("rdx") arg3 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn syscall_raw4(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    // SAFETY: Same as syscall_raw3. RCX carries the 4th argument in our ABI,
    // but is still clobbered on return (CPU writes saved RIP there).
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            inlateout("rdi") arg1 => _,
            inlateout("rsi") arg2 => _,
            inlateout("rdx") arg3 => _,
            inlateout("rcx") arg4 => _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ----------------------------------------------------------------------------
// AArch64: SVC #0 instruction
// ----------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn syscall_raw3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: Invokes the kernel SVC handler via `svc #0`.
    // The kernel validates all arguments.
    //
    // AArch64 convention: x8 = syscall number, x0-x5 = args, x0 = return.
    // The SVC exception saves/restores all registers via the exception
    // vector stub (sync_el0_stub), so only x0 is modified on return
    // (the stub writes the return value into the saved x0 slot).
    //
    // Clobbers: x0 (return value). x1-x7 and x8 are restored by the kernel's
    // exception return path, but we mark them clobbered defensively since
    // the kernel could change its ABI without breaking us.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x0") arg1 as i64 => ret,
            inlateout("x1") arg2 => _,
            inlateout("x2") arg3 => _,
            inlateout("x8") num => _,
            // x3-x7 not used but may be clobbered by future kernel changes
            lateout("x3") _,
            lateout("x4") _,
            lateout("x5") _,
            lateout("x6") _,
            lateout("x7") _,
            // x9-x15 are caller-saved (corruptible) in AAPCS64
            lateout("x9") _,
            lateout("x10") _,
            lateout("x11") _,
            lateout("x12") _,
            lateout("x13") _,
            lateout("x14") _,
            lateout("x15") _,
            // x16-x17 are intra-procedure-call scratch
            lateout("x16") _,
            lateout("x17") _,
            // x18 is platform register (caller-saved)
            lateout("x18") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn syscall_raw4(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    // SAFETY: Same as syscall_raw3. x3 carries the 4th argument.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x0") arg1 as i64 => ret,
            inlateout("x1") arg2 => _,
            inlateout("x2") arg3 => _,
            inlateout("x3") arg4 => _,
            inlateout("x8") num => _,
            lateout("x4") _,
            lateout("x5") _,
            lateout("x6") _,
            lateout("x7") _,
            lateout("x9") _,
            lateout("x10") _,
            lateout("x11") _,
            lateout("x12") _,
            lateout("x13") _,
            lateout("x14") _,
            lateout("x15") _,
            lateout("x16") _,
            lateout("x17") _,
            lateout("x18") _,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// Safe public API
// ============================================================================

pub fn exit(code: u32) -> ! {
    syscall_raw3(SYS_EXIT, code as u64, 0, 0);
    loop {}
}

pub fn print(msg: &[u8]) {
    syscall_raw3(SYS_PRINT, msg.as_ptr() as u64, msg.len() as u64, 0);
}

/// Log an error message. Currently prints to the kernel console.
///
/// Future: will also emit an audit event (kernel audit ring) so a log
/// viewer can surface errors without them stepping on the user's display.
/// Services should prefer this over `print` for error conditions — it
/// gives us a single hook to evolve into "silent success, visible failure".
pub fn log_error(tag: &[u8], msg: &[u8]) {
    // Assemble a single [TAG] ERROR: msg line to keep output contiguous.
    let mut buf = [0u8; 256];
    let mut n = 0;
    let push = |buf: &mut [u8], n: &mut usize, bytes: &[u8]| {
        let space = buf.len().saturating_sub(*n);
        let take = core::cmp::min(space, bytes.len());
        buf[*n..*n + take].copy_from_slice(&bytes[..take]);
        *n += take;
    };
    push(&mut buf, &mut n, b"[");
    push(&mut buf, &mut n, tag);
    push(&mut buf, &mut n, b"] ERROR: ");
    push(&mut buf, &mut n, msg);
    if n < buf.len() {
        buf[n] = b'\n';
        n += 1;
    }
    print(&buf[..n]);
}

pub fn register_endpoint(endpoint_id: u32) -> i64 {
    syscall_raw3(SYS_REGISTER_ENDPOINT, endpoint_id as u64, 0, 0)
}

pub fn yield_now() {
    syscall_raw3(SYS_YIELD, 0, 0, 0);
}

pub fn get_pid() -> u32 {
    syscall_raw3(SYS_GET_PID, 0, 0, 0) as u32
}

/// Send IPC message (Write syscall).
pub fn write(endpoint: u32, buf: &[u8]) -> i64 {
    syscall_raw3(SYS_WRITE, endpoint as u64, buf.as_ptr() as u64, buf.len() as u64)
}

/// Receive IPC message with sender identity.
/// Returns total bytes in buf, or 0 if no message, or negative error.
/// buf layout: [sender_principal:32][from_endpoint:4][payload:N]
pub fn recv_msg(endpoint: u32, buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_RECV_MSG, endpoint as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// Store object. Writes 32-byte hash to out_hash. Returns 0 or negative error.
pub fn obj_put(content: &[u8], out_hash: &mut [u8; 32]) -> i64 {
    syscall_raw3(SYS_OBJ_PUT, content.as_ptr() as u64, content.len() as u64, out_hash.as_mut_ptr() as u64)
}

/// Get object content by hash. Returns bytes read or negative error.
pub fn obj_get(hash: &[u8; 32], out_buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_OBJ_GET, hash.as_ptr() as u64, out_buf.as_mut_ptr() as u64, out_buf.len() as u64)
}

/// Delete object by hash. Returns 0 or negative error.
pub fn obj_delete(hash: &[u8; 32]) -> i64 {
    syscall_raw3(SYS_OBJ_DELETE, hash.as_ptr() as u64, 0, 0)
}

/// List object hashes. Returns count of objects.
pub fn obj_list(out_buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_OBJ_LIST, out_buf.as_mut_ptr() as u64, out_buf.len() as u64, 0)
}

/// Store a pre-signed object. Kernel verifies the signature.
pub fn obj_put_signed(content: &[u8], sig: &[u8; 64], out_hash: &mut [u8; 32]) -> i64 {
    syscall_raw4(
        SYS_OBJ_PUT_SIGNED,
        content.as_ptr() as u64,
        content.len() as u64,
        sig.as_ptr() as u64,
        out_hash.as_mut_ptr() as u64,
    )
}

/// Claim the bootstrap secret key from the kernel (one-shot).
/// Returns 64 on success, negative error on failure.
pub fn claim_bootstrap_key(out_sk: &mut [u8; 64]) -> i64 {
    syscall_raw3(SYS_CLAIM_BOOTSTRAP_KEY, out_sk.as_mut_ptr() as u64, 0, 0)
}

// ============================================================================
// Identity types — the userspace half of "no ID, no participation"
// ============================================================================

/// A 32-byte Ed25519 public key representing a process identity.
/// The zero value is invalid (anonymous / unidentified).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Principal([u8; 32]);

impl Principal {
    /// The zero Principal — sentinel for "no identity."
    pub const ANONYMOUS: Self = Self([0u8; 32]);

    /// Returns `true` if this is the zero (anonymous) Principal.
    pub fn is_anonymous(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// The raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An IPC message whose sender identity has been verified as non-anonymous.
///
/// This type **cannot** be constructed without a valid (non-zero) Principal.
/// If the kernel does not stamp principals on IPC messages (e.g., a stripped
/// fork), `recv_verified()` always returns `None` and the service is inert.
///
/// This is the userspace half of the "identity is load-bearing" invariant.
/// The kernel half is the identity gate in the syscall dispatcher.
pub struct VerifiedMessage<'a> {
    sender: Principal,
    from_endpoint: u32,
    payload: &'a [u8],
}

impl<'a> VerifiedMessage<'a> {
    /// The sender's verified Principal (guaranteed non-anonymous).
    pub fn sender(&self) -> &Principal {
        &self.sender
    }

    /// The endpoint the message was sent from.
    pub fn from_endpoint(&self) -> u32 {
        self.from_endpoint
    }

    /// The payload bytes (after the 36-byte header).
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    /// Split the payload into (command_byte, data) if non-empty.
    pub fn command(&self) -> Option<(u8, &[u8])> {
        self.payload.split_first().map(|(&cmd, rest)| (cmd, rest))
    }
}

/// Receive and verify an IPC message on `endpoint`.
///
/// `buf` should be at least 292 bytes for full 256-byte payloads
/// (36-byte header + 256 payload). Smaller buffers work but truncate.
///
/// Returns `Some(VerifiedMessage)` only if a message is available AND the
/// sender has a non-anonymous (non-zero) Principal. Returns `None` if:
/// - No message available (queue empty)
/// - Message too short (< 37 bytes: 32 principal + 4 endpoint + 1 payload)
/// - Sender principal is anonymous (all zeros)
///
/// This is the **only** way to obtain a `VerifiedMessage`. Services that
/// use this function structurally cannot operate on a kernel that does not
/// stamp sender identity on IPC messages.
pub fn recv_verified<'a>(endpoint: u32, buf: &'a mut [u8]) -> Option<VerifiedMessage<'a>> {
    let n = recv_msg(endpoint, buf);
    if n <= 0 {
        return None;
    }
    let total = n as usize;
    // 32 principal + 4 endpoint + 1 minimum payload byte
    if total < 37 || total > buf.len() {
        return None;
    }

    let mut principal_bytes = [0u8; 32];
    principal_bytes.copy_from_slice(&buf[0..32]);
    let principal = Principal(principal_bytes);

    // THE STRUCTURAL CHECK: no principal, no message, no service.
    if principal.is_anonymous() {
        return None;
    }

    let from_endpoint = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);

    Some(VerifiedMessage {
        sender: principal,
        from_endpoint,
        payload: &buf[36..total],
    })
}

// ============================================================================
// Device / DMA syscalls
// ============================================================================

const SYS_MAP_MMIO: u64 = 20;
const SYS_ALLOC_DMA: u64 = 21;
const SYS_DEVICE_INFO: u64 = 22;
const SYS_PORT_IO: u64 = 23;

/// Map device MMIO into this process's address space.
/// Returns user-space virtual address, or negative error.
pub fn map_mmio(phys_addr: u64, num_pages: u32) -> i64 {
    syscall_raw3(SYS_MAP_MMIO, phys_addr, num_pages as u64, 0)
}

/// Allocate physically contiguous DMA-capable pages with guard pages.
/// Returns user-space virtual address. Physical address written to `out_paddr`.
pub fn alloc_dma(num_pages: u32, out_paddr: &mut u64) -> i64 {
    syscall_raw3(SYS_ALLOC_DMA, num_pages as u64, 0, out_paddr as *mut u64 as u64)
}

/// Query PCI device info by index.
/// Writes a 108-byte device descriptor to `out_buf`.
/// Returns 0 on success, negative error if index is out of range.
pub fn device_info(index: u32, out_buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_DEVICE_INFO, index as u64, out_buf.as_mut_ptr() as u64, out_buf.len() as u64)
}

/// Perform kernel-validated port I/O on a PCI device I/O BAR.
/// The kernel rejects ports not within a discovered PCI I/O BAR.
///
/// `flags` bit 0: direction (0=read, 1=write)
/// `flags` bits 2:1: width (0=byte, 1=word, 2=dword)
pub fn port_io(port: u16, value: u32, flags: u32) -> i64 {
    syscall_raw3(SYS_PORT_IO, port as u64, value as u64, flags as u64)
}

/// Read a byte from a PCI device I/O port.
pub fn port_read8(port: u16) -> Result<u8, i64> {
    let r = port_io(port, 0, 0b000); // read, byte
    if r < 0 { Err(r) } else { Ok(r as u8) }
}

/// Write a byte to a PCI device I/O port.
pub fn port_write8(port: u16, value: u8) -> Result<(), i64> {
    let r = port_io(port, value as u32, 0b001); // write, byte
    if r < 0 { Err(r) } else { Ok(()) }
}

/// Read a 16-bit word from a PCI device I/O port.
pub fn port_read16(port: u16) -> Result<u16, i64> {
    let r = port_io(port, 0, 0b010); // read, word
    if r < 0 { Err(r) } else { Ok(r as u16) }
}

/// Write a 16-bit word to a PCI device I/O port.
pub fn port_write16(port: u16, value: u16) -> Result<(), i64> {
    let r = port_io(port, value as u32, 0b011); // write, word
    if r < 0 { Err(r) } else { Ok(()) }
}

/// Read a 32-bit dword from a PCI device I/O port.
pub fn port_read32(port: u16) -> Result<u32, i64> {
    let r = port_io(port, 0, 0b100); // read, dword
    if r < 0 { Err(r) } else { Ok(r as u32) }
}

/// Write a 32-bit dword to a PCI device I/O port.
pub fn port_write32(port: u16, value: u32) -> Result<(), i64> {
    let r = port_io(port, value, 0b101); // write, dword
    if r < 0 { Err(r) } else { Ok(()) }
}

// ============================================================================
// Shell / interactive syscalls
// ============================================================================

const SYS_CONSOLE_READ: u64 = 24;
const SYS_SPAWN: u64 = 25;
const SYS_WAIT_TASK: u64 = 26;
const SYS_GET_TIME: u64 = 9;

/// Read bytes from the serial console (non-blocking).
/// Returns the number of bytes read (0 if no data available).
pub fn console_read(buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_CONSOLE_READ, buf.as_mut_ptr() as u64, buf.len() as u64, 0)
}

/// Spawn a boot module by name. Returns the new task ID, or negative error.
pub fn spawn(name: &[u8]) -> i64 {
    syscall_raw3(SYS_SPAWN, name.as_ptr() as u64, name.len() as u64, 0)
}

/// Block until the specified child task exits. Returns the child's exit code.
pub fn wait_task(task_id: u32) -> i64 {
    syscall_raw3(SYS_WAIT_TASK, task_id as u64, 0, 0)
}

/// Get system time in ticks.
pub fn get_time() -> u64 {
    syscall_raw3(SYS_GET_TIME, 0, 0, 0) as u64
}

// ============================================================================
// Phase 3.2d.iv: Shared-memory channel syscalls (ADR-005)
// ============================================================================

const SYS_CHANNEL_CREATE: u64 = 28;
const SYS_CHANNEL_ATTACH: u64 = 29;
const SYS_CHANNEL_CLOSE: u64 = 30;
const SYS_CHANNEL_REVOKE: u64 = 31;
const SYS_CHANNEL_INFO: u64 = 32;

/// Create a shared-memory channel.
///
/// `size_pages`: number of 4 KiB pages (1..=4096).
/// `peer_principal`: 32-byte Ed25519 public key of the intended peer.
/// `role`: 0 = Producer (creator writes), 1 = Consumer (creator reads),
///         2 = Bidirectional (both sides write).
/// `out_vaddr`: receives the creator's virtual address of the shared region.
///
/// Returns the ChannelId (>= 0) on success, or a negative error code.
/// Requires the `CreateChannel` system capability.
pub fn channel_create(
    size_pages: u32,
    peer_principal: &[u8; 32],
    role: u32,
    out_vaddr: &mut u64,
) -> i64 {
    syscall_raw4(
        SYS_CHANNEL_CREATE,
        size_pages as u64,
        peer_principal.as_ptr() as u64,
        role as u64,
        out_vaddr as *mut u64 as u64,
    )
}

/// Attach to an existing channel as the named peer.
///
/// The kernel verifies the caller's Principal matches the peer_principal
/// specified at create time. Returns the user-space virtual address of
/// the shared region on success, or a negative error code.
pub fn channel_attach(channel_id: u64) -> i64 {
    syscall_raw3(SYS_CHANNEL_ATTACH, channel_id, 0, 0)
}

/// Close a channel. Both sides' mappings are removed.
///
/// Only the creator or peer may call this. Returns 0 on success.
pub fn channel_close(channel_id: u64) -> i64 {
    syscall_raw3(SYS_CHANNEL_CLOSE, channel_id, 0, 0)
}

/// Force-revoke a channel (bootstrap/policy authority required).
///
/// Returns 0 on success.
pub fn channel_revoke(channel_id: u64) -> i64 {
    syscall_raw3(SYS_CHANNEL_REVOKE, channel_id, 0, 0)
}

/// Query channel metadata.
///
/// Writes a 46-byte descriptor to `out_buf`. Returns 0 on success.
pub fn channel_info(channel_id: u64, out_buf: &mut [u8]) -> i64 {
    syscall_raw3(
        SYS_CHANNEL_INFO,
        channel_id,
        out_buf.as_mut_ptr() as u64,
        out_buf.len() as u64,
    )
}

// ============================================================================
// Audit infrastructure (Phase 3.3, ADR-007)
// ============================================================================

const SYS_AUDIT_ATTACH: u64 = 33;
const SYS_AUDIT_INFO: u64 = 34;

/// Attach as the audit ring consumer.
///
/// Maps the kernel's audit ring pages read-only into this process's
/// address space. Returns the user-space virtual address on success,
/// or a negative error code.
///
/// Restricted to the bootstrap Principal.
pub fn audit_attach() -> i64 {
    syscall_raw3(SYS_AUDIT_ATTACH, 0, 0, 0)
}

/// Read audit ring statistics into `out_buf`.
///
/// `out_buf` must be at least 48 bytes. Returns 0 on success.
pub fn audit_info(out_buf: &mut [u8]) -> i64 {
    syscall_raw3(
        SYS_AUDIT_INFO,
        out_buf.as_mut_ptr() as u64,
        out_buf.len() as u64,
        0,
    )
}
