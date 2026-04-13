// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS Policy Service — user-space authorization decisions (Phase 3.4)
//!
//! Receives syscall policy queries from the kernel on endpoint 22,
//! evaluates against per-process syscall profiles, and sends Allow/Deny
//! decisions back on endpoint 23.
//!
//! v0: returns Allow for all queries (establishes architectural slot
//! without changing behavior). Phase 3.4b adds real per-process
//! syscall allowlists.
//!
//! IPC protocol (256-byte payload):
//!   Query (kernel → policy-service):
//!     [sender_principal:32][from_endpoint:4][query_id:8][caller_pid:4][syscall_num:4][caller_principal:32]
//!   Response (policy-service → kernel):
//!     [query_id:8][decision:1]   (0 = Allow, 1 = Deny)

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libsys as sys;

// ============================================================================
// Panic handler (required for no_std)
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[POLICY] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// Constants
// ============================================================================

/// IPC endpoint where the kernel sends policy queries.
const POLICY_QUERY_ENDPOINT: u32 = 22;

/// IPC endpoint where the kernel intercepts our responses.
const POLICY_RESP_ENDPOINT: u32 = 23;

/// Minimum payload size for a valid query.
/// IPC header (36 bytes) + query payload (48 bytes) = 84 bytes total.
const MIN_QUERY_SIZE: usize = 36 + 48;

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[POLICY] Policy service starting\n");

    // Register our query endpoint
    sys::register_endpoint(POLICY_QUERY_ENDPOINT);

    sys::print(b"[POLICY] Endpoint 22 registered, entering query loop\n");

    // Service loop: recv_verified rejects anonymous senders.
    let mut recv_buf = [0u8; 256];

    loop {
        let msg = match sys::recv_verified(POLICY_QUERY_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };

        // Query payload must be at least 48 bytes (query_id + pid + syscall + principal)
        let payload = msg.payload();
        if payload.len() < 48 {
            continue;
        }

        // Extract query_id (first 8 bytes of query payload)
        let query_id_bytes: [u8; 8] = match payload[0..8].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let _query_id = u64::from_le_bytes(query_id_bytes);

        // v0: always Allow. Phase 3.4b will add per-process profile lookup here.
        // The query also contains caller_pid (bytes 8..12), syscall_num (12..16),
        // and caller_principal (16..48), which Phase 3.4b will use.

        // Build response: [query_id:8][decision:1]
        let mut resp = [0u8; 9];
        resp[0..8].copy_from_slice(&query_id_bytes);
        resp[8] = 0; // 0 = Allow

        // Send response to the policy response endpoint (kernel intercepts this)
        sys::write(POLICY_RESP_ENDPOINT, &resp);
    }
}
