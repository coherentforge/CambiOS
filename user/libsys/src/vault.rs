// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! Multi-Principal vault IPC wire codec.
//!
//! Shares endpoint 17 with the PIV protocol in [`crate::keystore`] but
//! defines a distinct command family — opcodes 10..=15 are reserved for
//! vault primitives per ADR-033. The vault layer translates AID-keyed
//! requests into PIV slot operations on the server side; clients should
//! prefer vault primitives over direct `CMD_PIV_*` calls when an AID is
//! the natural identifier of the key being used.
//!
//! Wire format mirrors the PIV protocol:
//!   Request:  `[cmd:1][body...]`
//!   Response: `[status:1][body...]`
//!
//! Status discriminants do not collide with `PivStatus` — vault statuses
//! occupy 0x10..=0x1F so a single shared codec can distinguish which
//! protocol the response belongs to without an extra envelope tag.

// ============================================================================
// Command IDs
// ============================================================================

/// `bind_for_spawn(context: &[u8]) → AID`. Parent processes consult the
/// vault before invoking `SYS_SPAWN` to learn which AID the child should
/// be bound to. Per ADR-033 § 2; phase 1C stage B.
pub const CMD_VAULT_BIND_FOR_SPAWN: u8 = 10;

// Reserved for additive vault growth: 11..=15.
//   11 = CMD_VAULT_SIGN_WITH    (1C-C)
//   12 = CMD_VAULT_DECRYPT_WITH (1C-C)

// ============================================================================
// Bounds
// ============================================================================

/// Maximum context-label byte length on the wire. Matches the
/// server-side `MAX_CONTEXT_LABEL_LEN` in `user/key-store-service`'s
/// vault module — both sides hard-code 32, which the 256-byte IPC
/// payload comfortably accommodates.
pub const MAX_CONTEXT_LABEL_LEN: usize = 32;

// ============================================================================
// Wire status byte
// ============================================================================

/// Wire status byte. Discriminants live in 0x10..=0x1F so they do not
/// collide with `PivStatus` (0x00..=0x07) — see module docs.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VaultStatus {
    Ok = 0x10,
    NotAuthorized = 0x11,
    AidNotFound = 0x12,
    TokenAbsent = 0x13,
    ContextNotFound = 0x14,
    BackendError = 0x15,
    InvalidPayload = 0x16,
}

impl VaultStatus {
    pub fn from_byte(b: u8) -> Option<VaultStatus> {
        match b {
            0x10 => Some(VaultStatus::Ok),
            0x11 => Some(VaultStatus::NotAuthorized),
            0x12 => Some(VaultStatus::AidNotFound),
            0x13 => Some(VaultStatus::TokenAbsent),
            0x14 => Some(VaultStatus::ContextNotFound),
            0x15 => Some(VaultStatus::BackendError),
            0x16 => Some(VaultStatus::InvalidPayload),
            _ => None,
        }
    }
}

// ============================================================================
// User-facing error type
// ============================================================================

/// Client-side error. Wire-status variants share discriminant values
/// with `VaultStatus`; local-only variants live above 0x80 to keep
/// them out of any wire codec.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VaultError {
    NotAuthorized = 0x11,
    AidNotFound = 0x12,
    TokenAbsent = 0x13,
    ContextNotFound = 0x14,
    BackendError = 0x15,
    InvalidPayload = 0x16,
    /// Local: response/request did not match the expected wire format.
    WireFormat = 0xFE,
    /// Local: IPC syscall (write or recv_msg) returned an error.
    Ipc = 0xFF,
}

impl VaultError {
    /// Map a non-Ok wire status to the matching error variant.
    /// Returns `None` if `status == VaultStatus::Ok`.
    pub fn from_status(status: VaultStatus) -> Option<VaultError> {
        match status {
            VaultStatus::Ok => None,
            VaultStatus::NotAuthorized => Some(VaultError::NotAuthorized),
            VaultStatus::AidNotFound => Some(VaultError::AidNotFound),
            VaultStatus::TokenAbsent => Some(VaultError::TokenAbsent),
            VaultStatus::ContextNotFound => Some(VaultError::ContextNotFound),
            VaultStatus::BackendError => Some(VaultError::BackendError),
            VaultStatus::InvalidPayload => Some(VaultError::InvalidPayload),
        }
    }

    /// Map an error back to its wire status byte. Used by the server to
    /// encode error responses from a server-side `VaultError`.
    pub fn to_status(&self) -> Option<VaultStatus> {
        match self {
            VaultError::NotAuthorized => Some(VaultStatus::NotAuthorized),
            VaultError::AidNotFound => Some(VaultStatus::AidNotFound),
            VaultError::TokenAbsent => Some(VaultStatus::TokenAbsent),
            VaultError::ContextNotFound => Some(VaultStatus::ContextNotFound),
            VaultError::BackendError => Some(VaultStatus::BackendError),
            VaultError::InvalidPayload => Some(VaultStatus::InvalidPayload),
            VaultError::WireFormat | VaultError::Ipc => None,
        }
    }
}

// ============================================================================
// Encoders — REQUESTS (client-side build)
// ============================================================================

/// Encode a `bind_for_spawn` request: `[cmd:1][context_len:1][context:N]`.
pub fn encode_bind_for_spawn_request(
    context: &[u8],
    out: &mut [u8],
) -> Result<usize, VaultError> {
    if context.len() > MAX_CONTEXT_LABEL_LEN {
        return Err(VaultError::WireFormat);
    }
    let total = 2 + context.len();
    if out.len() < total {
        return Err(VaultError::WireFormat);
    }
    out[0] = CMD_VAULT_BIND_FOR_SPAWN;
    out[1] = context.len() as u8;
    out[2..total].copy_from_slice(context);
    Ok(total)
}

// ============================================================================
// Decoders — REQUESTS (server-side parse)
// ============================================================================

/// Decode a `bind_for_spawn` request, returning a slice borrowing the
/// context-label bytes from `buf`.
pub fn decode_bind_for_spawn_request(buf: &[u8]) -> Result<&[u8], VaultError> {
    if buf.len() < 2 || buf[0] != CMD_VAULT_BIND_FOR_SPAWN {
        return Err(VaultError::WireFormat);
    }
    let ctx_len = buf[1] as usize;
    if ctx_len > MAX_CONTEXT_LABEL_LEN || buf.len() != 2 + ctx_len {
        return Err(VaultError::WireFormat);
    }
    Ok(&buf[2..2 + ctx_len])
}

// ============================================================================
// Encoders — RESPONSES (server-side build)
// ============================================================================

/// Encode an error response: `[status:1]`. Caller must supply a
/// status-mappable `VaultError` (not `WireFormat` or `Ipc`).
pub fn encode_error_response(
    err: VaultError,
    out: &mut [u8],
) -> Result<usize, VaultError> {
    let status = err.to_status().ok_or(VaultError::WireFormat)?;
    if out.is_empty() {
        return Err(VaultError::WireFormat);
    }
    out[0] = status as u8;
    Ok(1)
}

/// Encode a `bind_for_spawn` OK response: `[status:1][aid:32]`.
pub fn encode_bind_for_spawn_response(
    aid: &[u8; 32],
    out: &mut [u8],
) -> Result<usize, VaultError> {
    if out.len() < 33 {
        return Err(VaultError::WireFormat);
    }
    out[0] = VaultStatus::Ok as u8;
    out[1..33].copy_from_slice(aid);
    Ok(33)
}

// ============================================================================
// Decoders — RESPONSES (client-side parse)
// ============================================================================

/// Decode a `bind_for_spawn` response. Returns the AID on success, or
/// the wire-mapped `VaultError` on any non-Ok status.
pub fn decode_bind_for_spawn_response(buf: &[u8]) -> Result<[u8; 32], VaultError> {
    if buf.is_empty() {
        return Err(VaultError::WireFormat);
    }
    let status = VaultStatus::from_byte(buf[0]).ok_or(VaultError::WireFormat)?;
    if let Some(err) = VaultError::from_status(status) {
        return Err(err);
    }
    if buf.len() != 33 {
        return Err(VaultError::WireFormat);
    }
    let mut aid = [0u8; 32];
    aid.copy_from_slice(&buf[1..33]);
    Ok(aid)
}

// ============================================================================
// IPC wrappers — invoke key-store-service over endpoint 17
// ============================================================================

use crate::keystore::KEY_STORE_ENDPOINT;

/// Ask the vault which AID a newly-spawned child should be bound to.
///
/// `context` is an opaque byte string the parent uses to identify the
/// spawn context (e.g. `b"work"`, `b"social"`); the vault looks it up
/// in its `context_map`. If the context is not bound, the v1 vault
/// falls back to the bootstrap AID and emits a `[VAULT][FALLBACK]` log
/// line on its side — the client sees the bootstrap AID returned with
/// `VaultStatus::Ok`.
///
/// `reply_endpoint` must be an endpoint the caller has already
/// registered via `SYS_REGISTER_ENDPOINT`. The kernel routes the
/// vault's reply there via the `REPLY_ENDPOINT` registry.
pub fn vault_bind_for_spawn(
    reply_endpoint: u32,
    context: &[u8],
) -> Result<[u8; 32], VaultError> {
    let mut req = [0u8; 64];
    let req_len = encode_bind_for_spawn_request(context, &mut req)?;

    let rc = crate::write(KEY_STORE_ENDPOINT, &req[..req_len]);
    if rc < 0 {
        return Err(VaultError::Ipc);
    }

    let mut buf = [0u8; 256];
    let n = crate::recv_msg(reply_endpoint, &mut buf);
    if n < 36 {
        return Err(VaultError::Ipc);
    }
    let n = n as usize;
    decode_bind_for_spawn_response(&buf[36..n])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_context() {
        let mut req = [0u8; 64];
        let req_len = encode_bind_for_spawn_request(b"", &mut req).unwrap();
        assert_eq!(req_len, 2);
        let ctx = decode_bind_for_spawn_request(&req[..req_len]).unwrap();
        assert!(ctx.is_empty());
    }

    #[test]
    fn round_trip_short_context() {
        let mut req = [0u8; 64];
        let req_len =
            encode_bind_for_spawn_request(b"social", &mut req).unwrap();
        assert_eq!(req_len, 8);
        let ctx = decode_bind_for_spawn_request(&req[..req_len]).unwrap();
        assert_eq!(ctx, b"social");
    }

    #[test]
    fn round_trip_max_length_context() {
        let label = [b'x'; MAX_CONTEXT_LABEL_LEN];
        let mut req = [0u8; 64];
        let req_len =
            encode_bind_for_spawn_request(&label, &mut req).unwrap();
        assert_eq!(req_len, 2 + MAX_CONTEXT_LABEL_LEN);
        let ctx = decode_bind_for_spawn_request(&req[..req_len]).unwrap();
        assert_eq!(ctx, &label);
    }

    #[test]
    fn encode_rejects_overlong_context() {
        let label = [b'x'; MAX_CONTEXT_LABEL_LEN + 1];
        let mut req = [0u8; 64];
        assert_eq!(
            encode_bind_for_spawn_request(&label, &mut req),
            Err(VaultError::WireFormat)
        );
    }

    #[test]
    fn encode_rejects_undersized_buffer() {
        let mut tiny = [0u8; 1];
        assert_eq!(
            encode_bind_for_spawn_request(b"x", &mut tiny),
            Err(VaultError::WireFormat)
        );
    }

    #[test]
    fn decode_rejects_wrong_opcode() {
        let buf = [0x99, 0, b'x'];
        assert_eq!(
            decode_bind_for_spawn_request(&buf),
            Err(VaultError::WireFormat)
        );
    }

    #[test]
    fn decode_rejects_overlong_declared_length() {
        let mut buf = [0u8; 3];
        buf[0] = CMD_VAULT_BIND_FOR_SPAWN;
        buf[1] = (MAX_CONTEXT_LABEL_LEN + 1) as u8;
        assert_eq!(
            decode_bind_for_spawn_request(&buf),
            Err(VaultError::WireFormat)
        );
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let buf = [CMD_VAULT_BIND_FOR_SPAWN, 5, b'x'];
        assert_eq!(
            decode_bind_for_spawn_request(&buf),
            Err(VaultError::WireFormat)
        );
    }

    #[test]
    fn response_round_trip_ok() {
        let aid = [0xAA; 32];
        let mut resp = [0u8; 64];
        let n = encode_bind_for_spawn_response(&aid, &mut resp).unwrap();
        assert_eq!(n, 33);
        let decoded = decode_bind_for_spawn_response(&resp[..n]).unwrap();
        assert_eq!(decoded, aid);
    }

    #[test]
    fn response_round_trip_each_error_variant() {
        for err in [
            VaultError::NotAuthorized,
            VaultError::AidNotFound,
            VaultError::TokenAbsent,
            VaultError::ContextNotFound,
            VaultError::BackendError,
            VaultError::InvalidPayload,
        ] {
            let mut resp = [0u8; 64];
            let n = encode_error_response(err, &mut resp).unwrap();
            assert_eq!(n, 1);
            assert_eq!(decode_bind_for_spawn_response(&resp[..n]), Err(err));
        }
    }

    #[test]
    fn encode_error_rejects_local_only_variants() {
        let mut resp = [0u8; 64];
        assert_eq!(
            encode_error_response(VaultError::WireFormat, &mut resp),
            Err(VaultError::WireFormat)
        );
        assert_eq!(
            encode_error_response(VaultError::Ipc, &mut resp),
            Err(VaultError::WireFormat)
        );
    }

    #[test]
    fn decode_response_rejects_truncated() {
        assert_eq!(
            decode_bind_for_spawn_response(&[]),
            Err(VaultError::WireFormat)
        );
        let truncated_ok = [VaultStatus::Ok as u8, 0xAA, 0xAA];
        assert_eq!(
            decode_bind_for_spawn_response(&truncated_ok),
            Err(VaultError::WireFormat)
        );
    }

    #[test]
    fn decode_response_rejects_unknown_status() {
        let buf = [0xFF];
        assert_eq!(
            decode_bind_for_spawn_response(&buf),
            Err(VaultError::WireFormat)
        );
    }

    #[test]
    fn status_byte_round_trip() {
        for s in [
            VaultStatus::Ok,
            VaultStatus::NotAuthorized,
            VaultStatus::AidNotFound,
            VaultStatus::TokenAbsent,
            VaultStatus::ContextNotFound,
            VaultStatus::BackendError,
            VaultStatus::InvalidPayload,
        ] {
            assert_eq!(VaultStatus::from_byte(s as u8), Some(s));
        }
    }
}
