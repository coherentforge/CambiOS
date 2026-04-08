// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! ArcOS user-space syscall library
//!
//! Safe wrappers around x86_64 SYSCALL instruction. This is the ONLY crate
//! in user-space that contains `unsafe` code. All other user-space crates
//! should use `#![forbid(unsafe_code)]` and call these safe functions.

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

#[inline(always)]
fn syscall_raw3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: Invokes the kernel syscall handler via the SYSCALL instruction.
    // The kernel validates all arguments. rcx and r11 are clobbered by the
    // CPU (saved RIP and RFLAGS respectively).
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn syscall_raw4(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    // SAFETY: Same as syscall_raw3. rcx carries the 4th argument in our ABI.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            inlateout("rcx") arg4 => _,
            lateout("r11") _,
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
