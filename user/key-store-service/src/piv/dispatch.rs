// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! IPC command dispatch for PIV commands.
//!
//! Pure function: takes a request payload and a backend, writes the
//! response payload bytes into a caller-provided buffer, returns the
//! number of bytes written. No syscalls, no IPC, no globals. Designed
//! to be host-testable end-to-end with any `PivBackend` implementation.
//!
//! The service's main loop (`src/main.rs`) reads an IPC message via
//! `recv_verified`, hands the verified payload to this function with a
//! response buffer, then writes the produced response bytes back via
//! `sys::write` to the caller's reply endpoint. Identity gating
//! happens at `recv_verified` (anonymous senders are dropped before
//! reaching here); no extra Principal checks inside dispatch.
//!
//! Audit emission on sign/decrypt key-use is **deferred** per
//! Convention 9 — see the per-arm `Revisit when:` markers below.

use super::PivBackend;
use cambios_libsys::keystore::{
    CMD_PIV_ATTEST, CMD_PIV_DECRYPT, CMD_PIV_GET_PUBKEY, CMD_PIV_HEALTH, CMD_PIV_LIST_SLOTS,
    CMD_PIV_SIGN, CMD_PIV_VERIFY_PIN, PivError, PivStatus, decode_attest_request,
    decode_decrypt_request, decode_get_pubkey_request, decode_health_request,
    decode_list_slots_request, decode_sign_request, decode_verify_pin_request,
    encode_attest_response, encode_decrypt_response, encode_error_response,
    encode_get_pubkey_response, encode_health_response, encode_list_slots_response,
    encode_sign_response, encode_verify_pin_ok_response,
};

/// Translate a backend `PivError` to the wire `PivStatus` byte.
/// Local-only error variants (`WireFormat`, `Ipc`) collapse to
/// `Generic` on the wire.
fn error_to_status(err: PivError) -> PivStatus {
    match err {
        PivError::Generic | PivError::WireFormat | PivError::Ipc => PivStatus::Generic,
        PivError::NotPresent => PivStatus::NotPresent,
        PivError::AuthRequired => PivStatus::AuthRequired,
        PivError::SlotEmpty => PivStatus::SlotEmpty,
        PivError::WrongAlgorithm => PivStatus::WrongAlgorithm,
        PivError::PinLocked => PivStatus::PinLocked,
        PivError::CardTransport => PivStatus::CardTransport,
    }
}

/// Write a single-byte error status into the response buffer.
/// Returns the bytes written (always 1, or 0 if `response` is empty).
fn write_error(status: PivStatus, response: &mut [u8]) -> usize {
    encode_error_response(status, response).unwrap_or(0)
}

/// Dispatch a single PIV command. Returns the number of bytes written
/// to `response`. Caller is responsible for forwarding those bytes
/// back to the IPC sender.
///
/// `request` is the full request payload starting with the command byte
/// (i.e., the bytes a `recv_verified` payload accessor returns, minus
/// the verified IPC envelope). `response` must be at least 256 bytes —
/// the IPC payload ceiling — to accommodate the largest response.
pub fn dispatch_piv_command<B: PivBackend>(
    backend: &mut B,
    request: &[u8],
    response: &mut [u8],
) -> usize {
    if request.is_empty() || response.is_empty() {
        // Cannot produce even a status byte; drop silently. The IPC
        // layer above is the only thing that could surface this.
        return 0;
    }
    let cmd = request[0];

    match cmd {
        CMD_PIV_HEALTH => match decode_health_request(request) {
            Ok(()) => {
                let state = backend.health();
                encode_health_response(state, response).unwrap_or(0)
            }
            Err(_) => write_error(PivStatus::Generic, response),
        },

        CMD_PIV_VERIFY_PIN => match decode_verify_pin_request(request) {
            Ok(pin) => match backend.verify_pin(pin) {
                Ok(()) => encode_verify_pin_ok_response(response).unwrap_or(0),
                Err(e) => write_error(error_to_status(e), response),
            },
            Err(_) => write_error(PivStatus::Generic, response),
        },

        CMD_PIV_LIST_SLOTS => match decode_list_slots_request(request) {
            Ok(()) => {
                let list = backend.list_slots();
                encode_list_slots_response(&list, response).unwrap_or(0)
            }
            Err(_) => write_error(PivStatus::Generic, response),
        },

        CMD_PIV_GET_PUBKEY => match decode_get_pubkey_request(request) {
            Ok(slot) => match backend.get_pubkey(slot) {
                Ok(pubkey) => encode_get_pubkey_response(&pubkey, response).unwrap_or(0),
                Err(e) => write_error(error_to_status(e), response),
            },
            Err(_) => write_error(PivStatus::Generic, response),
        },

        CMD_PIV_SIGN => match decode_sign_request(request) {
            Ok((slot, msg)) => {
                // Deferred: audit-emit on key-use per ADR-007.
                // Revisit when: userspace audit-emit syscall lands OR
                // audit-tail subscribes to key-store events.
                match backend.sign(slot, msg) {
                    Ok(sig) => encode_sign_response(&sig, response).unwrap_or(0),
                    Err(e) => write_error(error_to_status(e), response),
                }
            }
            Err(_) => write_error(PivStatus::Generic, response),
        },

        CMD_PIV_DECRYPT => match decode_decrypt_request(request) {
            Ok((slot, wrapped)) => {
                // Deferred: audit-emit on key-use per ADR-007.
                // Revisit when: userspace audit-emit syscall lands OR
                // audit-tail subscribes to key-store events.
                let mut shared = [0u8; 32];
                match backend.decrypt(slot, wrapped, &mut shared) {
                    Ok(n) => encode_decrypt_response(&shared[..n], response).unwrap_or(0),
                    Err(e) => write_error(error_to_status(e), response),
                }
            }
            Err(_) => write_error(PivStatus::Generic, response),
        },

        CMD_PIV_ATTEST => match decode_attest_request(request) {
            Ok(slot) => {
                let mut cert = [0u8; cambios_libsys::keystore::MAX_ATTEST_INLINE];
                match backend.attest(slot, &mut cert) {
                    Ok(n) => encode_attest_response(&cert[..n], response).unwrap_or(0),
                    Err(e) => write_error(error_to_status(e), response),
                }
            }
            Err(_) => write_error(PivStatus::Generic, response),
        },

        _ => write_error(PivStatus::Generic, response),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piv::inert::InertPivBackend;
    use cambios_libsys::keystore::*;

    // ------------------------------------------------------------------
    // InertPivBackend: every command returns NotPresent (uniform "no
    // card" surface).
    // ------------------------------------------------------------------

    fn dispatch_inert(request: &[u8]) -> ([u8; 256], usize) {
        let mut backend = InertPivBackend::new();
        let mut response = [0u8; 256];
        let n = dispatch_piv_command(&mut backend, request, &mut response);
        (response, n)
    }

    #[test]
    fn inert_health_reports_not_present() {
        let mut req = [0u8; 256];
        let req_len = encode_health_request(&mut req).unwrap();
        let (response, n) = dispatch_inert(&req[..req_len]);
        // Health is the one command that returns Ok even when the card
        // is absent — the wire is "Ok, state=NotPresent" so the client
        // can distinguish "card missing" from "transport error".
        let state = decode_health_response(&response[..n]).unwrap();
        assert_eq!(state, PivHealthState::NotPresent);
    }

    #[test]
    fn inert_verify_pin_rejected() {
        let mut req = [0u8; 256];
        let req_len = encode_verify_pin_request(b"123456", &mut req).unwrap();
        let (response, n) = dispatch_inert(&req[..req_len]);
        match decode_verify_pin_response(&response[..n]) {
            Err(PivError::NotPresent) => {}
            other => panic!("expected NotPresent, got {:?}", other),
        }
    }

    #[test]
    fn inert_list_slots_empty() {
        let mut req = [0u8; 256];
        let req_len = encode_list_slots_request(&mut req).unwrap();
        let (response, n) = dispatch_inert(&req[..req_len]);
        let list = decode_list_slots_response(&response[..n]).unwrap();
        assert_eq!(list.count, 0);
    }

    #[test]
    fn inert_get_pubkey_not_present() {
        let mut req = [0u8; 256];
        let req_len = encode_get_pubkey_request(PivSlot::Signature, &mut req).unwrap();
        let (response, n) = dispatch_inert(&req[..req_len]);
        match decode_get_pubkey_response(&response[..n]) {
            Err(PivError::NotPresent) => {}
            other => panic!("expected NotPresent, got {:?}", other),
        }
    }

    #[test]
    fn inert_sign_not_present() {
        let mut req = [0u8; 256];
        let req_len = encode_sign_request(PivSlot::Signature, b"msg", &mut req).unwrap();
        let (response, n) = dispatch_inert(&req[..req_len]);
        match decode_sign_response(&response[..n]) {
            Err(PivError::NotPresent) => {}
            other => panic!("expected NotPresent, got {:?}", other),
        }
    }

    #[test]
    fn inert_decrypt_not_present() {
        let mut req = [0u8; 256];
        let req_len =
            encode_decrypt_request(PivSlot::KeyManagement, &[0u8; 32], &mut req).unwrap();
        let (response, n) = dispatch_inert(&req[..req_len]);
        let mut out = [0u8; 32];
        match decode_decrypt_response(&response[..n], &mut out) {
            Err(PivError::NotPresent) => {}
            other => panic!("expected NotPresent, got {:?}", other),
        }
    }

    #[test]
    fn inert_attest_not_present() {
        let mut req = [0u8; 256];
        let req_len = encode_attest_request(PivSlot::Signature, &mut req).unwrap();
        let (response, n) = dispatch_inert(&req[..req_len]);
        let mut out = [0u8; 256];
        match decode_attest_response(&response[..n], &mut out) {
            Err(PivError::NotPresent) => {}
            other => panic!("expected NotPresent, got {:?}", other),
        }
    }

    #[test]
    fn unknown_command_returns_generic_error() {
        let mut backend = InertPivBackend::new();
        let mut response = [0u8; 256];
        let n = dispatch_piv_command(&mut backend, &[0xFE], &mut response);
        assert_eq!(n, 1);
        assert_eq!(response[0], PivStatus::Generic as u8);
    }

    #[test]
    fn malformed_request_returns_generic_error() {
        let mut backend = InertPivBackend::new();
        let mut response = [0u8; 256];
        // CMD_PIV_GET_PUBKEY without slot byte — request too short.
        let n = dispatch_piv_command(&mut backend, &[CMD_PIV_GET_PUBKEY], &mut response);
        assert_eq!(n, 1);
        assert_eq!(response[0], PivStatus::Generic as u8);
    }

    #[test]
    fn empty_request_writes_nothing() {
        let mut backend = InertPivBackend::new();
        let mut response = [0u8; 256];
        let n = dispatch_piv_command(&mut backend, &[], &mut response);
        assert_eq!(n, 0);
    }

    // ------------------------------------------------------------------
    // SwPivBackend: real crypto operations through the IPC contract.
    // ------------------------------------------------------------------

    #[cfg(feature = "dev-piv")]
    mod with_sw_backend {
        use super::*;
        use crate::piv::sw::SwPivBackend;

        fn fresh_sw() -> SwPivBackend {
            SwPivBackend::from_compiled_in().expect("DPIV bundle should parse")
        }

        fn verified_sw() -> SwPivBackend {
            let mut b = fresh_sw();
            b.verify_pin(b"123456").expect("DEV_PIN should verify");
            b
        }

        #[test]
        fn sw_health_initially_auth_required() {
            let mut backend = fresh_sw();
            let mut req = [0u8; 256];
            let req_len = encode_health_request(&mut req).unwrap();
            let mut resp = [0u8; 256];
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            assert_eq!(
                decode_health_response(&resp[..n]).unwrap(),
                PivHealthState::AuthRequired
            );
        }

        #[test]
        fn sw_verify_pin_then_sign() {
            let mut backend = fresh_sw();
            let mut req = [0u8; 256];
            let mut resp = [0u8; 256];

            // Verify PIN via dispatch.
            let req_len = encode_verify_pin_request(b"123456", &mut req).unwrap();
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            decode_verify_pin_response(&resp[..n]).expect("verify pin ok");

            // Sign via dispatch.
            let msg = b"audit-tail hello";
            let req_len = encode_sign_request(PivSlot::Signature, msg, &mut req).unwrap();
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            let sig = decode_sign_response(&resp[..n]).expect("sign ok");

            // Independently verify under the slot-9C pubkey.
            let req_len =
                encode_get_pubkey_request(PivSlot::Signature, &mut req).unwrap();
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            let pubkey = decode_get_pubkey_response(&resp[..n]).expect("get_pubkey ok");
            let pk_obj = ed25519_compact::PublicKey::from_slice(pubkey.as_slice())
                .expect("pubkey parse");
            let sig_obj = ed25519_compact::Signature::from_slice(&sig.0)
                .expect("sig parse");
            pk_obj.verify(msg, &sig_obj).expect("signature must verify");
        }

        #[test]
        fn sw_sign_before_pin_returns_auth_required() {
            let mut backend = fresh_sw();
            let mut req = [0u8; 256];
            let req_len = encode_sign_request(PivSlot::Signature, b"m", &mut req).unwrap();
            let mut resp = [0u8; 256];
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            match decode_sign_response(&resp[..n]) {
                Err(PivError::AuthRequired) => {}
                other => panic!("expected AuthRequired, got {:?}", other),
            }
        }

        #[test]
        fn sw_decrypt_roundtrip_through_dispatch() {
            let mut backend = verified_sw();
            let mut req = [0u8; 256];
            let mut resp = [0u8; 256];

            // Get the slot-9D X25519 pubkey via dispatch.
            let req_len = encode_get_pubkey_request(PivSlot::KeyManagement, &mut req)
                .unwrap();
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            let backend_pk =
                decode_get_pubkey_response(&resp[..n]).expect("get_pubkey 9D");
            let backend_x_pk =
                ed25519_compact::x25519::PublicKey::from_slice(backend_pk.as_slice())
                    .unwrap();

            // Independent ephemeral keypair (fixed seed for repro).
            let eph_seed = ed25519_compact::Seed::new([0x11u8; 32]);
            let eph_ed = ed25519_compact::KeyPair::from_seed(eph_seed);
            let eph_x = ed25519_compact::x25519::KeyPair::from_ed25519(&eph_ed).unwrap();
            let sender_shared = backend_x_pk.dh(&eph_x.sk).unwrap();

            // Backend's ECDH via dispatch.
            let req_len =
                encode_decrypt_request(PivSlot::KeyManagement, eph_x.pk.as_ref(), &mut req)
                    .unwrap();
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            let mut out = [0u8; 32];
            let pt_len =
                decode_decrypt_response(&resp[..n], &mut out).expect("decrypt ok");
            assert_eq!(pt_len, 32);
            assert_eq!(out, *sender_shared.as_ref());
        }

        #[test]
        fn sw_pin_lockout_surfaces_through_dispatch() {
            let mut backend = fresh_sw();
            let mut req = [0u8; 256];
            let mut resp = [0u8; 256];

            // Three wrong PINs → lockout.
            for _ in 0..3 {
                let req_len = encode_verify_pin_request(b"wrong", &mut req).unwrap();
                let _ = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            }

            // Correct PIN now fails — locked.
            let req_len = encode_verify_pin_request(b"123456", &mut req).unwrap();
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            match decode_verify_pin_response(&resp[..n]) {
                Err(PivError::PinLocked) => {}
                other => panic!("expected PinLocked, got {:?}", other),
            }

            // Health surfaces NotReady.
            let req_len = encode_health_request(&mut req).unwrap();
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            assert_eq!(
                decode_health_response(&resp[..n]).unwrap(),
                PivHealthState::NotReady
            );
        }

        #[test]
        fn sw_list_slots_through_dispatch_reports_four() {
            let mut backend = fresh_sw();
            let mut req = [0u8; 256];
            let req_len = encode_list_slots_request(&mut req).unwrap();
            let mut resp = [0u8; 256];
            let n = dispatch_piv_command(&mut backend, &req[..req_len], &mut resp);
            let list = decode_list_slots_response(&resp[..n]).unwrap();
            assert_eq!(list.count, 4);
            // 9C signing slot is populated.
            assert!(list.as_slice().iter().any(|info| info.slot == PivSlot::Signature
                && info.populated));
        }
    }
}
