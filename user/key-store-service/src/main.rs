// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! ArcOS Key Store Service — user-space Ed25519 signing service
//!
//! When a bootstrap secret key is available in the kernel (legacy seed mode),
//! claims it at boot and signs on behalf of callers. When no secret key is
//! available (hardware-backed YubiKey mode), enters degraded mode: responds
//! to sign requests with STATUS_ERROR so callers fall back to unsigned storage.
//!
//! Degraded mode is the expected state when the bootstrap signing key lives
//! on external hardware (YubiKey). Full signing resumes when the USB HID
//! stack enables runtime communication with the hardware key store.
//!
//! Runs as a ring-3 process. Registers IPC endpoint 17, receives
//! sign and get-public-key requests over IPC.
//!
//! IPC protocol (256-byte payload):
//!   Request:  [cmd:1][data...]
//!   Response: [status:1][data...]
//!
//!   cmd: 1=SIGN, 2=GET_PUBKEY
//!   status: 0=OK, 1=ERROR

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libsys as sys;

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[KS] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// IPC Protocol
// ============================================================================

const KS_ENDPOINT: u32 = 17;

const CMD_SIGN: u8 = 1;
const CMD_GET_PUBKEY: u8 = 2;

const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;

// ============================================================================
// Key state (stack-local, no static mut needed)
// ============================================================================

struct KeyState {
    secret_key: [u8; 64],
    public_key: [u8; 32],
    initialized: bool,
}

impl KeyState {
    fn new() -> Self {
        Self {
            secret_key: [0u8; 64],
            public_key: [0u8; 32],
            initialized: false,
        }
    }
}

// ============================================================================
// Signing
// ============================================================================

/// Sign content using the stored secret key.
/// Returns a 64-byte Ed25519 signature.
fn sign(keys: &KeyState, content: &[u8]) -> [u8; 64] {
    let ed_sk = ed25519_compact::SecretKey::new(keys.secret_key);
    let sig = ed_sk.sign(content, None);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ============================================================================
// Service handlers
// ============================================================================

fn handle_sign(keys: &KeyState, payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_ERROR;
        return 1;
    }

    if !keys.initialized {
        response[0] = STATUS_ERROR;
        return 1;
    }

    let sig = sign(keys, payload);
    response[0] = STATUS_OK;
    response[1..65].copy_from_slice(&sig);
    65
}

fn handle_get_pubkey(keys: &KeyState, response: &mut [u8]) -> usize {
    if !keys.initialized {
        response[0] = STATUS_ERROR;
        return 1;
    }

    response[0] = STATUS_OK;
    response[1..33].copy_from_slice(&keys.public_key);
    33
}

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[KS] Key store service starting\n");

    // Step 1: Try to claim the bootstrap secret key from the kernel.
    // In hardware-backed mode (YubiKey), no secret key exists in the kernel
    // and this call returns an error. The service enters degraded mode:
    // it still registers its endpoint and responds to requests, but all
    // sign operations return STATUS_ERROR until runtime hardware key
    // access is available (USB HID stack).
    let mut keys = KeyState::new();
    let mut sk = [0u8; 64];
    let ret = sys::claim_bootstrap_key(&mut sk);
    if ret < 0 {
        sys::print(b"[KS] No kernel secret key available (hardware-backed mode)\n");
        sys::print(b"[KS] Entering degraded mode - signing unavailable\n");
        // keys.initialized stays false — sign requests will return ERROR
    } else {
        // Legacy seed mode: store the key in process memory
        keys.secret_key.copy_from_slice(&sk);
        keys.public_key.copy_from_slice(&sk[32..64]);
        keys.initialized = true;

        // Zero the stack copy
        for b in sk.iter_mut() {
            *b = 0;
        }

        sys::print(b"[KS] Bootstrap key claimed, kernel copy zeroed\n");
    }

    // Step 2: Register our IPC endpoint
    sys::register_endpoint(KS_ENDPOINT);
    sys::print(b"[KS] Endpoint 17 registered, entering service loop\n");

    // Step 3: Service loop
    let mut recv_buf = [0u8; 256];
    let mut resp_buf = [0u8; 256];

    loop {
        let n = sys::recv_msg(KS_ENDPOINT, &mut recv_buf);

        if n <= 0 {
            sys::yield_now();
            continue;
        }
        let total = n as usize;

        if total < 37 {
            // Too short: need at least 36-byte header + 1 byte command
            continue;
        }

        // Parse header: [sender_principal:32][from_endpoint:4][payload:N]
        let from_endpoint = u32::from_le_bytes([
            recv_buf[32], recv_buf[33], recv_buf[34], recv_buf[35],
        ]);
        let payload = &recv_buf[36..total];

        let cmd = payload[0];
        let cmd_data = &payload[1..];

        let resp_len = match cmd {
            CMD_SIGN => handle_sign(&keys, cmd_data, &mut resp_buf),
            CMD_GET_PUBKEY => handle_get_pubkey(&keys, &mut resp_buf),
            _ => {
                resp_buf[0] = STATUS_ERROR;
                1
            }
        };

        sys::write(from_endpoint, &resp_buf[..resp_len]);
    }
}
