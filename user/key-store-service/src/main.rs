// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Key Store Service — user-space PIV-backed identity service
//!
//! Runs as a ring-3 process on IPC endpoint 17. Dispatches `CMD_PIV_*`
//! requests through whichever PIV backend was selected at build time:
//! `SwPivBackend` under `--features dev-piv`, `InertPivBackend` (always
//! `NotPresent`) otherwise. Stream B's `CcidPivBackend` becomes a third
//! arm when it lands.
//!
//! IPC protocol (256-byte payload):
//!   Request:  [cmd:1][data...]
//!   Response: [status:1][data...]
//!
//! Commands and status codes live in `cambios_libsys::keystore`.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use cambios_key_store_service::piv::{
    dispatch::dispatch_piv_command, ActiveBackend,
};
use cambios_key_store_service::vault::init::init_vault;
use cambios_libsys as sys;
use cambios_libsys::keystore::{
    CMD_PIV_ATTEST, CMD_PIV_DECRYPT, CMD_PIV_GET_PUBKEY, CMD_PIV_HEALTH,
    CMD_PIV_LIST_SLOTS, CMD_PIV_SIGN, CMD_PIV_VERIFY_PIN,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[KS] PANIC!\n");
    sys::exit(1);
}

const KS_ENDPOINT: u32 = 17;
const STATUS_ERROR: u8 = 1;

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Register our IPC endpoint.
    sys::register_endpoint(KS_ENDPOINT);

    // Instantiate the active PIV backend. Cfg-driven: under
    // `--features dev-piv` this is `SwPivBackend`; otherwise the
    // always-NotPresent `InertPivBackend` stand-in. Stream B's
    // `CcidPivBackend` will become a third arm here.
    // Revisit when: stream B's `CcidPivBackend` lands and
    // `init_piv_backend` gains a third arm.
    let mut piv_backend = match init_piv_backend() {
        Some(b) => Some(b),
        None => {
            sys::print(b"[KS] WARNING: PIV backend init failed; CMD_PIV_* will return Generic\n");
            None
        }
    };

    // Vault directory (ADR-033). v1 single-entry: bootstrap AID → active
    // backend's KeyHandle. The IPC primitives that consume it land in
    // later 1C stages; today the binding exists so the directory is
    // ready when bind_for_spawn / sign_with / decrypt_with arrive.
    let mut bootstrap_aid = [0u8; 32];
    let rc = sys::get_principal(&mut bootstrap_aid);
    let _vault = if rc == 32 {
        sys::print(b"[KS] vault initialized (1 entry, bootstrap)\n");
        Some(init_vault(bootstrap_aid))
    } else {
        sys::print(b"[KS] WARNING: get_principal failed; vault not initialized\n");
        None
    };

    sys::print(b"[KS] ready on endpoint 17\n");
    sys::module_ready();

    // Step 4: Service loop — recv_verified rejects anonymous senders.
    let mut recv_buf = [0u8; 256];
    let mut resp_buf = [0u8; 256];

    loop {
        let msg = match sys::recv_verified(KS_ENDPOINT, &mut recv_buf) {
            Some(msg) => msg,
            None => {
                sys::yield_now();
                continue;
            }
        };

        let (cmd, _cmd_data) = match msg.command() {
            Some(pair) => pair,
            None => continue,
        };

        let resp_len = match cmd {
            // PIV commands route through dispatch_piv_command, which
            // takes the full payload (cmd byte included).
            CMD_PIV_HEALTH
            | CMD_PIV_VERIFY_PIN
            | CMD_PIV_LIST_SLOTS
            | CMD_PIV_GET_PUBKEY
            | CMD_PIV_SIGN
            | CMD_PIV_DECRYPT
            | CMD_PIV_ATTEST => match piv_backend.as_mut() {
                Some(backend) => {
                    dispatch_piv_command(backend, msg.payload(), &mut resp_buf)
                }
                None => {
                    resp_buf[0] = STATUS_ERROR;
                    1
                }
            },
            _ => {
                resp_buf[0] = STATUS_ERROR;
                1
            }
        };

        sys::write(msg.from_endpoint(), &resp_buf[..resp_len]);
    }
}

/// Initialize the active PIV backend at startup. Returns `None` if
/// the dev-piv DPIV bundle is malformed (only possible under
/// `--features dev-piv`); default builds always succeed.
#[cfg(feature = "dev-piv")]
fn init_piv_backend() -> Option<ActiveBackend> {
    match ActiveBackend::from_compiled_in() {
        Ok(b) => Some(b),
        Err(_) => None,
    }
}

#[cfg(not(feature = "dev-piv"))]
fn init_piv_backend() -> Option<ActiveBackend> {
    Some(ActiveBackend::new())
}
