// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS Filesystem Service — user-space ObjectStore gateway
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
#![deny(unsafe_code)]

use arcos_libsys as sys;

// ============================================================================
// Panic handler (required for no_std)
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[FS] PANIC!\n");
    sys::exit(1);
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
    let ret = sys::write(KS_ENDPOINT, &req[..req_len]);
    if ret < 0 {
        return None; // Key-store not available
    }

    // Receive response from our own endpoint
    let mut resp_buf = [0u8; 256];
    // Poll a few times for the response (key-store needs to be scheduled)
    for _ in 0..20 {
        let n = sys::recv_msg(FS_ENDPOINT, &mut resp_buf);
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
        sys::yield_now();
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
/// Requires a signature from the key-store service (endpoint 17).
/// No unsigned fallback — identity is load-bearing.
fn handle_put(payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_INVALID;
        return 1;
    }

    // Require signature from key-store. No fallback — unsigned puts are
    // not permitted. If key-store is unavailable, the object cannot be stored.
    let sig = match request_sign(payload) {
        Some(sig) => sig,
        None => {
            response[0] = STATUS_DENIED;
            return 1;
        }
    };

    let mut hash = [0u8; 32];
    let ret = sys::obj_put_signed(payload, &sig, &mut hash);

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
fn handle_get(payload: &[u8], response: &mut [u8]) -> usize {
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

    let ret = sys::obj_get(&hash, &mut content_buf[..read_len]);

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
///
/// Anonymous check removed: recv_verified guarantees the sender has a
/// non-zero Principal. If the kernel doesn't stamp principals, the
/// message is never delivered to this handler.
fn handle_delete(payload: &[u8], response: &mut [u8]) -> usize {
    if payload.len() < 32 {
        response[0] = STATUS_INVALID;
        return 1;
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload[..32]);

    let ret = sys::obj_delete(&hash);

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

    let ret = sys::obj_list(&mut hash_buf[..actual_buf_len]);

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

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let _pid = sys::get_pid();

    // Register our IPC endpoint
    sys::register_endpoint(FS_ENDPOINT);

    sys::print(b"[FS] ready on endpoint 16\n");

    // Service loop: receive verified message, dispatch command, send response.
    // recv_verified rejects anonymous senders — if the kernel doesn't stamp
    // principals, this loop processes nothing. Identity is load-bearing.
    let mut recv_buf = [0u8; 256];
    let mut resp_buf = [0u8; 256];

    loop {
        let msg = match sys::recv_verified(FS_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };

        let (cmd, cmd_data) = match msg.command() {
            Some(pair) => pair,
            None => continue,
        };

        let resp_len = match cmd {
            CMD_PUT => handle_put(cmd_data, &mut resp_buf),
            CMD_GET => handle_get(cmd_data, &mut resp_buf),
            CMD_DELETE => handle_delete(cmd_data, &mut resp_buf),
            CMD_LIST => handle_list(&mut resp_buf),
            _ => {
                resp_buf[0] = STATUS_INVALID;
                1
            }
        };

        sys::write(msg.from_endpoint(), &resp_buf[..resp_len]);
    }
}
