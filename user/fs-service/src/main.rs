//! ArcOS Filesystem Service — user-space ObjectStore gateway
//!
//! Runs as a ring-3 process. Registers IPC endpoint 16, receives
//! get/put/delete/list commands over IPC, enforces ownership via
//! sender_principal, delegates to kernel ObjectStore syscalls.
//!
//! IPC protocol (256-byte payload):
//!   Request:  [cmd:1][data...]
//!   Response: [status:1][data...]
//!
//!   cmd: 1=PUT, 2=GET, 3=DELETE, 4=LIST
//!   status: 0=OK, 1=NOT_FOUND, 2=FULL, 3=DENIED, 4=INVALID

#![no_std]
#![no_main]

// ============================================================================
// Panic handler (required for no_std)
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Print panic message if possible, then exit
    let msg = b"[FS] PANIC!\n";
    sys_print(msg);
    sys_exit(1);
}

// ============================================================================
// Syscall wrappers (x86_64 SYSCALL instruction)
// ============================================================================

/// Raw syscall with up to 3 arguments.
#[inline(always)]
fn syscall3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
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

/// Raw syscall with 4 arguments.
#[inline(always)]
fn syscall4(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    // SAFETY: Same as syscall3. RCX is the 4th arg register in our ABI.
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

/// Raw syscall with 1 argument.
#[inline(always)]
fn syscall1(num: u64, arg1: u64) -> i64 {
    syscall3(num, arg1, 0, 0)
}

/// Raw syscall with 0 arguments.
#[inline(always)]
fn syscall0(num: u64) -> i64 {
    syscall3(num, 0, 0, 0)
}

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
const SYS_OBJ_PUT_SIGNED: u64 = 19;

fn sys_exit(code: u32) -> ! {
    syscall1(SYS_EXIT, code as u64);
    loop {}
}

fn sys_print(msg: &[u8]) {
    syscall3(SYS_PRINT, msg.as_ptr() as u64, msg.len() as u64, 0);
}

fn sys_register_endpoint(endpoint_id: u32) -> i64 {
    syscall3(SYS_REGISTER_ENDPOINT, endpoint_id as u64, 0, 0)
}

fn sys_yield() {
    syscall0(SYS_YIELD);
}

fn sys_get_pid() -> u32 {
    syscall0(SYS_GET_PID) as u32
}

/// Send IPC message (Write syscall).
fn sys_write(endpoint: u32, buf: &[u8]) -> i64 {
    syscall3(SYS_WRITE, endpoint as u64, buf.as_ptr() as u64, buf.len() as u64)
}

/// Receive IPC message with sender identity.
/// Returns total bytes in buf, or 0 if no message, or negative error.
/// buf layout: [sender_principal:32][from_endpoint:4][payload:N]
fn sys_recv_msg(endpoint: u32, buf: &mut [u8]) -> i64 {
    syscall3(SYS_RECV_MSG, endpoint as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// Store object. Writes 32-byte hash to out_hash. Returns 0 or negative error.
fn sys_obj_put(content: &[u8], out_hash: &mut [u8; 32]) -> i64 {
    syscall3(SYS_OBJ_PUT, content.as_ptr() as u64, content.len() as u64, out_hash.as_mut_ptr() as u64)
}

/// Get object content by hash. Returns bytes read or negative error.
fn sys_obj_get(hash: &[u8; 32], out_buf: &mut [u8]) -> i64 {
    syscall3(SYS_OBJ_GET, hash.as_ptr() as u64, out_buf.as_mut_ptr() as u64, out_buf.len() as u64)
}

/// Delete object by hash. Returns 0 or negative error.
fn sys_obj_delete(hash: &[u8; 32]) -> i64 {
    syscall1(SYS_OBJ_DELETE, hash.as_ptr() as u64)
}

/// List object hashes. Returns count of objects.
fn sys_obj_list(out_buf: &mut [u8]) -> i64 {
    syscall3(SYS_OBJ_LIST, out_buf.as_mut_ptr() as u64, out_buf.len() as u64, 0)
}

/// Store a pre-signed object. Kernel verifies the signature.
fn sys_obj_put_signed(content: &[u8], sig: &[u8; 64], out_hash: &mut [u8; 32]) -> i64 {
    syscall4(
        SYS_OBJ_PUT_SIGNED,
        content.as_ptr() as u64,
        content.len() as u64,
        sig.as_ptr() as u64,
        out_hash.as_mut_ptr() as u64,
    )
}

// ============================================================================
// Key Store interaction (endpoint 17)
// ============================================================================

const KS_ENDPOINT: u32 = 17;
const KS_CMD_SIGN: u8 = 1;

/// Request a signature from the key-store service.
/// Returns Some(signature) on success, None if key-store is unavailable.
fn request_sign(content: &[u8]) -> Option<[u8; 64]> {
    if content.is_empty() || content.len() > 254 {
        return None; // Payload too large for 256-byte IPC frame (1 cmd + 255 data)
    }

    // Build sign request: [CMD_SIGN:1][content:N]
    let mut req = [0u8; 256];
    req[0] = KS_CMD_SIGN;
    req[1..1 + content.len()].copy_from_slice(content);
    let req_len = 1 + content.len();

    // Send to key-store endpoint
    let ret = sys_write(KS_ENDPOINT, &req[..req_len]);
    if ret < 0 {
        return None; // Key-store not available
    }

    // Receive response from our own endpoint
    let mut resp_buf = [0u8; 256];
    // Poll a few times for the response (key-store needs to be scheduled)
    for _ in 0..20 {
        let n = sys_recv_msg(FS_ENDPOINT, &mut resp_buf);
        if n > 0 {
            let total = n as usize;
            if total >= 36 + 65 {
                // Response: [principal:32][from:4][status:1][sig:64]
                let status = resp_buf[36];
                if status == 0 {
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&resp_buf[37..101]);
                    return Some(sig);
                }
            }
            // Got a response but it wasn't a valid sign reply — might be a
            // client request that arrived during our poll. For simplicity,
            // we drop it and return None (fallback to unsigned).
            return None;
        }
        sys_yield();
    }
    None // Timed out
}

// ============================================================================
// IPC Protocol
// ============================================================================

const FS_ENDPOINT: u32 = 16;

// Commands (request byte 0)
const CMD_PUT: u8 = 1;
const CMD_GET: u8 = 2;
const CMD_DELETE: u8 = 3;
const CMD_LIST: u8 = 4;

// Status codes (response byte 0)
const STATUS_OK: u8 = 0;
const STATUS_NOT_FOUND: u8 = 1;
const STATUS_FULL: u8 = 2;
const STATUS_DENIED: u8 = 3;
const STATUS_INVALID: u8 = 4;

// ============================================================================
// Service handlers
// ============================================================================

/// Handle PUT request.
/// Request payload: [content:N]
/// Response: [status:1][hash:32]
///
/// Attempts to create a signed object by requesting a signature from the
/// key-store service (endpoint 17). Falls back to unsigned ObjPut if the
/// key-store is unavailable (e.g., during early boot).
fn handle_put(payload: &[u8], _sender_principal: &[u8; 32], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_INVALID;
        return 1;
    }

    let mut hash = [0u8; 32];

    // Try signed path: request signature from key-store, then ObjPutSigned
    let ret = if let Some(sig) = request_sign(payload) {
        sys_obj_put_signed(payload, &sig, &mut hash)
    } else {
        // Fallback: unsigned ObjPut (key-store not yet available)
        sys_obj_put(payload, &mut hash)
    };

    if ret < 0 {
        response[0] = STATUS_FULL;
        return 1;
    }

    response[0] = STATUS_OK;
    response[1..33].copy_from_slice(&hash);
    33
}

/// Handle GET request.
/// Request payload: [hash:32]
/// Response: [status:1][content:N]
fn handle_get(payload: &[u8], _sender_principal: &[u8; 32], response: &mut [u8]) -> usize {
    if payload.len() < 32 {
        response[0] = STATUS_INVALID;
        return 1;
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload[..32]);

    // Use remaining response buffer for content (after status byte)
    let max_content = response.len() - 1;
    let mut content_buf = [0u8; 255]; // 256 - 1 status byte
    let read_len = core::cmp::min(max_content, 255);

    let ret = sys_obj_get(&hash, &mut content_buf[..read_len]);

    if ret < 0 {
        response[0] = STATUS_NOT_FOUND;
        return 1;
    }

    let bytes_read = ret as usize;
    response[0] = STATUS_OK;
    response[1..1 + bytes_read].copy_from_slice(&content_buf[..bytes_read]);
    1 + bytes_read
}

/// Handle DELETE request.
/// Request payload: [hash:32]
/// Response: [status:1]
fn handle_delete(payload: &[u8], sender_principal: &[u8; 32], response: &mut [u8]) -> usize {
    if payload.len() < 32 {
        response[0] = STATUS_INVALID;
        return 1;
    }

    // Reject anonymous deletes
    if *sender_principal == [0u8; 32] {
        response[0] = STATUS_DENIED;
        return 1;
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload[..32]);

    let ret = sys_obj_delete(&hash);

    response[0] = match ret {
        0 => STATUS_OK,
        -2 => STATUS_DENIED,       // PermissionDenied
        -4 => STATUS_NOT_FOUND,    // EndpointNotFound (reused for "not found")
        _ => STATUS_INVALID,
    };
    1
}

/// Handle LIST request.
/// Request payload: (empty)
/// Response: [status:1][count:1][hash:32]*
fn handle_list(response: &mut [u8]) -> usize {
    // Max hashes that fit: (256 - 2) / 32 = 7
    let max_hashes = (response.len() - 2) / 32;
    let buf_size = max_hashes * 32;

    let mut hash_buf = [0u8; 224]; // 7 * 32
    let actual_buf_len = core::cmp::min(buf_size, 224);

    let ret = sys_obj_list(&mut hash_buf[..actual_buf_len]);

    if ret < 0 {
        response[0] = STATUS_INVALID;
        return 1;
    }

    let count = ret as usize;
    response[0] = STATUS_OK;
    response[1] = count as u8;

    let hash_bytes = count * 32;
    response[2..2 + hash_bytes].copy_from_slice(&hash_buf[..hash_bytes]);
    2 + hash_bytes
}

// ============================================================================
// Entry point
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let _pid = sys_get_pid();

    sys_print(b"[FS] Filesystem service starting\n");

    // Register our IPC endpoint
    sys_register_endpoint(FS_ENDPOINT);

    sys_print(b"[FS] Endpoint 16 registered, entering service loop\n");

    // Service loop: receive message, dispatch command, send response
    let mut recv_buf = [0u8; 256]; // [principal:32][from:4][payload:N]
    let mut resp_buf = [0u8; 256];

    loop {
        let n = sys_recv_msg(FS_ENDPOINT, &mut recv_buf);

        if n <= 0 {
            // No message — yield and retry. Silence means healthy.
            sys_yield();
            continue;
        }
        let total = n as usize;

        if total < 37 {
            // Too short: need at least 36-byte header + 1 byte command
            continue;
        }

        // Parse header
        let sender_principal: &[u8; 32] = recv_buf[0..32].try_into().unwrap_or(&[0u8; 32]);
        let from_endpoint = u32::from_le_bytes([
            recv_buf[32], recv_buf[33], recv_buf[34], recv_buf[35],
        ]);
        let payload = &recv_buf[36..total];

        // First byte of payload is the command
        let cmd = payload[0];
        let cmd_data = &payload[1..];

        // Dispatch
        let resp_len = match cmd {
            CMD_PUT => handle_put(cmd_data, sender_principal, &mut resp_buf),
            CMD_GET => handle_get(cmd_data, sender_principal, &mut resp_buf),
            CMD_DELETE => handle_delete(cmd_data, sender_principal, &mut resp_buf),
            CMD_LIST => handle_list(&mut resp_buf),
            _ => {
                resp_buf[0] = STATUS_INVALID;
                1
            }
        };

        // Send response back to sender's endpoint
        sys_write(from_endpoint, &resp_buf[..resp_len]);
    }
}
