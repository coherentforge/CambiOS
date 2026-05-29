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
    dispatch::dispatch_piv_command, ActiveBackend, PivBackend,
};
use cambios_key_store_service::vault::{init::init_vault, BindSource, Vault};
use cambios_libsys as sys;
use cambios_libsys::keystore::{
    PivError, CMD_PIV_ATTEST, CMD_PIV_DECRYPT, CMD_PIV_GET_PUBKEY,
    CMD_PIV_HEALTH, CMD_PIV_LIST_SLOTS, CMD_PIV_SIGN, CMD_PIV_VERIFY_PIN,
};
use cambios_libsys::vault::{
    decode_bind_for_spawn_request, decode_decrypt_with_request,
    decode_sign_with_request, encode_bind_for_spawn_response,
    encode_decrypt_with_response,
    encode_error_response as encode_vault_error_response,
    encode_sign_with_response, VaultError, CMD_VAULT_BIND_FOR_SPAWN,
    CMD_VAULT_DECRYPT_WITH, CMD_VAULT_SIGN_WITH, MAX_VAULT_PLAINTEXT_LEN,
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
    let vault = if rc == 32 {
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

            // Vault primitives per ADR-033 § 2.
            CMD_VAULT_BIND_FOR_SPAWN => match vault.as_ref() {
                Some(v) => match decode_bind_for_spawn_request(msg.payload()) {
                    Ok(context) => {
                        let caller_aid = msg.sender().as_bytes();
                        match v.bind_for_spawn(caller_aid, context) {
                            Ok(result) => {
                                if result.source == BindSource::BootstrapFallback {
                                    log_vault_fallback(context);
                                }
                                encode_bind_for_spawn_response(&result.aid, &mut resp_buf)
                                    .unwrap_or(0)
                            }
                            Err(e) => encode_vault_error_response(e, &mut resp_buf)
                                .unwrap_or(0),
                        }
                    }
                    Err(_) => encode_vault_error_response(
                        VaultError::InvalidPayload,
                        &mut resp_buf,
                    )
                    .unwrap_or(0),
                },
                None => encode_vault_error_response(
                    VaultError::BackendError,
                    &mut resp_buf,
                )
                .unwrap_or(0),
            },

            CMD_VAULT_SIGN_WITH => match (vault.as_ref(), piv_backend.as_ref()) {
                (Some(v), Some(b)) => handle_vault_sign(
                    v,
                    b,
                    msg.sender().as_bytes(),
                    msg.payload(),
                    &mut resp_buf,
                ),
                _ => encode_vault_error_response(
                    VaultError::BackendError,
                    &mut resp_buf,
                )
                .unwrap_or(0),
            },

            CMD_VAULT_DECRYPT_WITH => match (vault.as_ref(), piv_backend.as_ref()) {
                (Some(v), Some(b)) => handle_vault_decrypt(
                    v,
                    b,
                    msg.sender().as_bytes(),
                    msg.payload(),
                    &mut resp_buf,
                ),
                _ => encode_vault_error_response(
                    VaultError::BackendError,
                    &mut resp_buf,
                )
                .unwrap_or(0),
            },

            _ => {
                resp_buf[0] = STATUS_ERROR;
                1
            }
        };

        sys::write(msg.from_endpoint(), &resp_buf[..resp_len]);
    }
}

/// Emit a structured `[VAULT][FALLBACK]` line on every context-miss
/// bind_for_spawn. Surfaces silent fallback-to-bootstrap so callers
/// leaning on the v1 single-Principal practice become greppable in
/// boot logs — see D4 in `notes/phase-1c-vault-overview.md`.
/// Revisit when: a userspace audit-emit primitive lands and a second
/// consumer with line-of-sight to the AI-watcher ring justifies
/// promoting this from `sys::print` to kernel audit-ring emission.
fn log_vault_fallback(context: &[u8]) {
    sys::print(b"[VAULT][FALLBACK] context=");
    if context.is_empty() {
        sys::print(b"<empty>");
    } else {
        sys::print(context);
    }
    sys::print(b" -> bootstrap\n");
}

/// Translate a `PivError` raised by the backend into a `VaultError`
/// surfaced to the vault caller. The vault wire surface is intentionally
/// narrower than PIV's — auth-/transport-class failures collapse to
/// `TokenAbsent` because the wire protocol gives the caller no way to
/// drive PIN entry or re-seat the card; `SlotEmpty` collapses to
/// `AidNotFound` because the AID has no usable key; everything else is
/// `BackendError`.
fn piv_to_vault_error(e: PivError) -> VaultError {
    match e {
        PivError::NotPresent
        | PivError::AuthRequired
        | PivError::PinLocked
        | PivError::CardTransport => VaultError::TokenAbsent,
        PivError::SlotEmpty => VaultError::AidNotFound,
        PivError::Generic
        | PivError::WrongAlgorithm
        | PivError::WireFormat
        | PivError::Ipc => VaultError::BackendError,
    }
}

/// Dispatch handler for `CMD_VAULT_SIGN_WITH`. Pure-ish: drives the
/// vault directory + active PIV backend, writes wire bytes into
/// `resp`. No syscalls, no globals. Returns bytes written.
fn handle_vault_sign(
    vault: &Vault,
    backend: &ActiveBackend,
    caller_aid: &[u8; 32],
    request: &[u8],
    resp: &mut [u8],
) -> usize {
    let (target_aid, msg_bytes) = match decode_sign_with_request(request) {
        Ok(parts) => parts,
        Err(_) => {
            return encode_vault_error_response(VaultError::InvalidPayload, resp)
                .unwrap_or(0);
        }
    };
    let slot = match vault.resolve_sign(caller_aid, target_aid) {
        Ok(s) => s,
        Err(e) => return encode_vault_error_response(e, resp).unwrap_or(0),
    };
    match backend.sign(slot, msg_bytes) {
        Ok(sig) => encode_sign_with_response(&sig, resp).unwrap_or(0),
        Err(e) => {
            encode_vault_error_response(piv_to_vault_error(e), resp).unwrap_or(0)
        }
    }
}

/// Dispatch handler for `CMD_VAULT_DECRYPT_WITH`. Same shape as
/// `handle_vault_sign`; uses the `decrypt_slot` and an intermediate
/// plaintext buffer sized to the vault's `MAX_VAULT_PLAINTEXT_LEN`
/// ceiling.
fn handle_vault_decrypt(
    vault: &Vault,
    backend: &ActiveBackend,
    caller_aid: &[u8; 32],
    request: &[u8],
    resp: &mut [u8],
) -> usize {
    let (target_aid, ciphertext) = match decode_decrypt_with_request(request) {
        Ok(parts) => parts,
        Err(_) => {
            return encode_vault_error_response(VaultError::InvalidPayload, resp)
                .unwrap_or(0);
        }
    };
    let slot = match vault.resolve_decrypt(caller_aid, target_aid) {
        Ok(s) => s,
        Err(e) => return encode_vault_error_response(e, resp).unwrap_or(0),
    };
    let mut plaintext = [0u8; MAX_VAULT_PLAINTEXT_LEN];
    match backend.decrypt(slot, ciphertext, &mut plaintext) {
        Ok(pt_len) => encode_decrypt_with_response(&plaintext[..pt_len], resp)
            .unwrap_or(0),
        Err(e) => {
            encode_vault_error_response(piv_to_vault_error(e), resp).unwrap_or(0)
        }
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
