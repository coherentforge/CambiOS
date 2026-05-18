// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! Key-store-service IPC wire codec.
//!
//! This module owns the wire format for the key-store-service PIV protocol
//! (endpoint 17). It is **codec only**: pure encode/decode functions that
//! build and parse the 256-byte IPC payload. No syscalls, no IPC, no state.
//!
//! The IPC wrapper functions (`piv_sign`, `piv_decrypt`, etc. that actually
//! invoke `sys::write` + `sys::recv_msg`) land in a follow-on substage when
//! the key-store-service handler side ships. Until then this module exists
//! so the server-side software-PIV backend and any future client both
//! share one source of truth for the byte layout.
//!
//! See `notes/yubikey-stream-a-handoff.md` and [ADR-032] for the design
//! rationale.
//!
//! [ADR-032]: ../../../docs/adr/032-full-disk-encryption-below-substrate.md
//!
//! ## Wire format
//!
//! Every request:  `[cmd:1][body...]`
//! Every response: `[status:1][body...]`
//!
//! `status` is the byte representation of `PivStatus` (0x00 = Ok, others
//! map to `PivError` variants). All multi-byte ints are little-endian.

// ============================================================================
// Endpoint + command IDs
// ============================================================================

/// IPC endpoint registered by `user/key-store-service`.
pub const KEY_STORE_ENDPOINT: u32 = 17;

// Legacy commands (kept working for degraded seed-mode bootstrap).
pub const CMD_SIGN: u8 = 1;
pub const CMD_GET_PUBKEY: u8 = 2;

// PIV commands (this contract).
pub const CMD_PIV_HEALTH: u8 = 3;
pub const CMD_PIV_VERIFY_PIN: u8 = 4;
pub const CMD_PIV_LIST_SLOTS: u8 = 5;
pub const CMD_PIV_GET_PUBKEY: u8 = 6;
pub const CMD_PIV_SIGN: u8 = 7;
pub const CMD_PIV_DECRYPT: u8 = 8;
pub const CMD_PIV_ATTEST: u8 = 9;

// Reserved-for-additive-growth range: 10..=31. Wire format freezes
// after the first real-hardware deployment.

/// SCAFFOLDING: Maximum number of PIV slots reported by CMD_PIV_LIST_SLOTS.
/// Why: v1 uses 4 standard PIV slots (0x9A/0x9C/0x9D/0x9E). 8 = headroom
/// for retired-key slots (0x82..=0x95 per NIST SP 800-73-4) if a future
/// rotation flow surfaces.
/// Replace when: a deployment lists more than 4 active slots in practice.
pub const MAX_PIV_SLOTS: usize = 8;

/// Maximum PIN byte length on the wire. PIV PINs are typically 6-8 ASCII
/// digits; 32 bytes covers PUKs and any future longer-PIN policy with
/// room to spare.
pub const MAX_PIN_LEN: usize = 32;

/// Maximum signed-message byte length on the wire. The 256-byte IPC
/// payload minus the request header (cmd=1, slot=1, msg_len=2) and a
/// safety margin.
pub const MAX_SIGN_MSG_LEN: usize = 250;

/// Maximum wrapped-key byte length on the wire. Matches the FDE volume
/// header slot table's `wrapped_key` field per ADR-032 § 4.
pub const MAX_WRAPPED_KEY_LEN: usize = 220;

/// Maximum unwrapped output length. AES-256 master keys are 32 bytes;
/// the 252-byte ceiling leaves room for future larger-key flows without
/// a wire-format break.
pub const MAX_PLAINTEXT_LEN: usize = 252;

/// Maximum public-key byte length. Ed25519/X25519 = 32, ECC P-256
/// uncompressed = 65, ECC P-384 uncompressed = 97. 96 covers
/// Ed25519/X25519/P-256 with headroom; P-384 (if it ever enters scope)
/// would require bumping this bound and growing the `PivPubkey.bytes`
/// buffer (additive change, no wire-format break — the wire `len` byte
/// already addresses up to 252).
pub const MAX_PUBKEY_LEN: usize = 96;

/// Maximum attestation-certificate byte length on the wire. PIV slot
/// attestation X.509 certs are typically ~700 bytes — larger than fits
/// in one 256-byte IPC payload. The CMD_PIV_ATTEST response format
/// reserves the field as truncated-for-v1; a future revision will
/// switch to channel-based bulk delivery (ADR-005 channel substrate).
/// Until then, callers receive up to 250 bytes and the response carries
/// the full length so callers can detect truncation.
pub const MAX_ATTEST_INLINE: usize = 250;

// ============================================================================
// Wire status byte
// ============================================================================

/// Wire status byte. Sent by the server as the first byte of every
/// response. `Ok` = 0x00 means "decode the response body"; any other
/// value maps to a `PivError` and the response body is undefined.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PivStatus {
    Ok = 0x00,
    Generic = 0x01,
    NotPresent = 0x02,
    AuthRequired = 0x03,
    SlotEmpty = 0x04,
    WrongAlgorithm = 0x05,
    PinLocked = 0x06,
    CardTransport = 0x07,
}

impl PivStatus {
    pub fn from_byte(b: u8) -> Option<PivStatus> {
        match b {
            0x00 => Some(PivStatus::Ok),
            0x01 => Some(PivStatus::Generic),
            0x02 => Some(PivStatus::NotPresent),
            0x03 => Some(PivStatus::AuthRequired),
            0x04 => Some(PivStatus::SlotEmpty),
            0x05 => Some(PivStatus::WrongAlgorithm),
            0x06 => Some(PivStatus::PinLocked),
            0x07 => Some(PivStatus::CardTransport),
            _ => None,
        }
    }
}

// ============================================================================
// User-facing error type
// ============================================================================

/// Client-side error type. Combines server-reported wire statuses with
/// local failures (wire-format parse error, IPC syscall failure).
///
/// Layout note: the wire-status variants intentionally share discriminant
/// values with `PivStatus` so server-side encoding can use either type
/// interchangeably; the local-only variants use values outside 0x00..=0x7F
/// to avoid wire collision.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PivError {
    Generic = 0x01,
    NotPresent = 0x02,
    AuthRequired = 0x03,
    SlotEmpty = 0x04,
    WrongAlgorithm = 0x05,
    PinLocked = 0x06,
    CardTransport = 0x07,
    /// Local: response/request did not match the expected wire format.
    WireFormat = 0xFE,
    /// Local: IPC syscall (write or recv_msg) returned an error. Reserved
    /// for the IPC-wrapper substage; the codec layer never emits this.
    Ipc = 0xFF,
}

impl PivError {
    /// Map a non-Ok wire status to the corresponding error variant.
    /// Returns `None` if `status == PivStatus::Ok`.
    pub fn from_status(status: PivStatus) -> Option<PivError> {
        match status {
            PivStatus::Ok => None,
            PivStatus::Generic => Some(PivError::Generic),
            PivStatus::NotPresent => Some(PivError::NotPresent),
            PivStatus::AuthRequired => Some(PivError::AuthRequired),
            PivStatus::SlotEmpty => Some(PivError::SlotEmpty),
            PivStatus::WrongAlgorithm => Some(PivError::WrongAlgorithm),
            PivStatus::PinLocked => Some(PivError::PinLocked),
            PivStatus::CardTransport => Some(PivError::CardTransport),
        }
    }
}

// ============================================================================
// PIV slot + algorithm enums (typed wrappers over wire bytes)
// ============================================================================

/// PIV key slots used by CambiOS. Discriminant values match NIST SP
/// 800-73-4 native slot IDs; the wire carries a raw `u8` so retired-key
/// slots (0x82..=0x95) remain forward-addressable without a wire break.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PivSlot {
    Authentication = 0x9A,
    Signature = 0x9C,
    KeyManagement = 0x9D,
    CardAuthentication = 0x9E,
}

impl PivSlot {
    pub fn from_byte(b: u8) -> Option<PivSlot> {
        match b {
            0x9A => Some(PivSlot::Authentication),
            0x9C => Some(PivSlot::Signature),
            0x9D => Some(PivSlot::KeyManagement),
            0x9E => Some(PivSlot::CardAuthentication),
            _ => None,
        }
    }
}

/// Cryptographic algorithm IDs. Discriminants match the NIST PIV
/// algorithm registry so kernel + userspace + tooling all agree on one
/// table.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PivAlgo {
    EccP256 = 0x14,
    Ed25519 = 0x22,
    X25519 = 0x42,
}

impl PivAlgo {
    pub fn from_byte(b: u8) -> Option<PivAlgo> {
        match b {
            0x14 => Some(PivAlgo::EccP256),
            0x22 => Some(PivAlgo::Ed25519),
            0x42 => Some(PivAlgo::X25519),
            _ => None,
        }
    }
}

/// PIV chip health state.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PivHealthState {
    NotPresent = 0,
    Ready = 1,
    NotReady = 2,
    AuthRequired = 3,
}

impl PivHealthState {
    pub fn from_byte(b: u8) -> Option<PivHealthState> {
        match b {
            0 => Some(PivHealthState::NotPresent),
            1 => Some(PivHealthState::Ready),
            2 => Some(PivHealthState::NotReady),
            3 => Some(PivHealthState::AuthRequired),
            _ => None,
        }
    }
}

// ============================================================================
// Typed payload structs
// ============================================================================

/// Ed25519 signature, fixed 64 bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Ed25519Signature(pub [u8; 64]);

/// Public key returned by CMD_PIV_GET_PUBKEY. The first `len` bytes of
/// `bytes` are meaningful; the remainder are zero-padded.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PivPubkey {
    pub algo: PivAlgo,
    pub len: u8,
    pub bytes: [u8; MAX_PUBKEY_LEN],
}

impl PivPubkey {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Per-slot metadata reported by CMD_PIV_LIST_SLOTS.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PivSlotInfo {
    pub slot: PivSlot,
    pub algo: PivAlgo,
    pub populated: bool,
}

/// Slot enumeration result. First `count` entries are meaningful.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PivSlotList {
    pub count: u8,
    pub entries: [PivSlotInfo; MAX_PIV_SLOTS],
}

impl PivSlotList {
    pub fn as_slice(&self) -> &[PivSlotInfo] {
        &self.entries[..self.count as usize]
    }
}

// ============================================================================
// Encoders — REQUESTS (client → server)
// ============================================================================
//
// Each `encode_*_request` writes the request bytes into `out` and returns
// the number of bytes written. Returns `Err(PivError::WireFormat)` if
// `out` is too small for the request OR an input exceeds its documented
// maximum (PIN > 32, msg > 250, wrapped > 220).

pub fn encode_health_request(out: &mut [u8]) -> Result<usize, PivError> {
    if out.is_empty() {
        return Err(PivError::WireFormat);
    }
    out[0] = CMD_PIV_HEALTH;
    Ok(1)
}

pub fn encode_verify_pin_request(pin: &[u8], out: &mut [u8]) -> Result<usize, PivError> {
    if pin.len() > MAX_PIN_LEN {
        return Err(PivError::WireFormat);
    }
    let total = 2 + pin.len();
    if out.len() < total {
        return Err(PivError::WireFormat);
    }
    out[0] = CMD_PIV_VERIFY_PIN;
    out[1] = pin.len() as u8;
    out[2..total].copy_from_slice(pin);
    Ok(total)
}

pub fn encode_list_slots_request(out: &mut [u8]) -> Result<usize, PivError> {
    if out.is_empty() {
        return Err(PivError::WireFormat);
    }
    out[0] = CMD_PIV_LIST_SLOTS;
    Ok(1)
}

pub fn encode_get_pubkey_request(slot: PivSlot, out: &mut [u8]) -> Result<usize, PivError> {
    if out.len() < 2 {
        return Err(PivError::WireFormat);
    }
    out[0] = CMD_PIV_GET_PUBKEY;
    out[1] = slot as u8;
    Ok(2)
}

pub fn encode_sign_request(slot: PivSlot, msg: &[u8], out: &mut [u8]) -> Result<usize, PivError> {
    if msg.len() > MAX_SIGN_MSG_LEN {
        return Err(PivError::WireFormat);
    }
    let total = 4 + msg.len();
    if out.len() < total {
        return Err(PivError::WireFormat);
    }
    out[0] = CMD_PIV_SIGN;
    out[1] = slot as u8;
    let len_bytes = (msg.len() as u16).to_le_bytes();
    out[2] = len_bytes[0];
    out[3] = len_bytes[1];
    out[4..total].copy_from_slice(msg);
    Ok(total)
}

pub fn encode_decrypt_request(
    slot: PivSlot,
    wrapped: &[u8],
    out: &mut [u8],
) -> Result<usize, PivError> {
    if wrapped.len() > MAX_WRAPPED_KEY_LEN {
        return Err(PivError::WireFormat);
    }
    let total = 4 + wrapped.len();
    if out.len() < total {
        return Err(PivError::WireFormat);
    }
    out[0] = CMD_PIV_DECRYPT;
    out[1] = slot as u8;
    let len_bytes = (wrapped.len() as u16).to_le_bytes();
    out[2] = len_bytes[0];
    out[3] = len_bytes[1];
    out[4..total].copy_from_slice(wrapped);
    Ok(total)
}

pub fn encode_attest_request(slot: PivSlot, out: &mut [u8]) -> Result<usize, PivError> {
    if out.len() < 2 {
        return Err(PivError::WireFormat);
    }
    out[0] = CMD_PIV_ATTEST;
    out[1] = slot as u8;
    Ok(2)
}

// ============================================================================
// Decoders — REQUESTS (server-side parse)
// ============================================================================

pub fn decode_health_request(buf: &[u8]) -> Result<(), PivError> {
    if buf.len() != 1 || buf[0] != CMD_PIV_HEALTH {
        return Err(PivError::WireFormat);
    }
    Ok(())
}

/// Returns a slice borrowing the PIN bytes from `buf`.
pub fn decode_verify_pin_request(buf: &[u8]) -> Result<&[u8], PivError> {
    if buf.len() < 2 || buf[0] != CMD_PIV_VERIFY_PIN {
        return Err(PivError::WireFormat);
    }
    let pin_len = buf[1] as usize;
    if pin_len > MAX_PIN_LEN || buf.len() != 2 + pin_len {
        return Err(PivError::WireFormat);
    }
    Ok(&buf[2..2 + pin_len])
}

pub fn decode_list_slots_request(buf: &[u8]) -> Result<(), PivError> {
    if buf.len() != 1 || buf[0] != CMD_PIV_LIST_SLOTS {
        return Err(PivError::WireFormat);
    }
    Ok(())
}

pub fn decode_get_pubkey_request(buf: &[u8]) -> Result<PivSlot, PivError> {
    if buf.len() != 2 || buf[0] != CMD_PIV_GET_PUBKEY {
        return Err(PivError::WireFormat);
    }
    PivSlot::from_byte(buf[1]).ok_or(PivError::WireFormat)
}

pub fn decode_sign_request(buf: &[u8]) -> Result<(PivSlot, &[u8]), PivError> {
    if buf.len() < 4 || buf[0] != CMD_PIV_SIGN {
        return Err(PivError::WireFormat);
    }
    let slot = PivSlot::from_byte(buf[1]).ok_or(PivError::WireFormat)?;
    let msg_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if msg_len > MAX_SIGN_MSG_LEN || buf.len() != 4 + msg_len {
        return Err(PivError::WireFormat);
    }
    Ok((slot, &buf[4..4 + msg_len]))
}

pub fn decode_decrypt_request(buf: &[u8]) -> Result<(PivSlot, &[u8]), PivError> {
    if buf.len() < 4 || buf[0] != CMD_PIV_DECRYPT {
        return Err(PivError::WireFormat);
    }
    let slot = PivSlot::from_byte(buf[1]).ok_or(PivError::WireFormat)?;
    let wrapped_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if wrapped_len > MAX_WRAPPED_KEY_LEN || buf.len() != 4 + wrapped_len {
        return Err(PivError::WireFormat);
    }
    Ok((slot, &buf[4..4 + wrapped_len]))
}

pub fn decode_attest_request(buf: &[u8]) -> Result<PivSlot, PivError> {
    if buf.len() != 2 || buf[0] != CMD_PIV_ATTEST {
        return Err(PivError::WireFormat);
    }
    PivSlot::from_byte(buf[1]).ok_or(PivError::WireFormat)
}

// ============================================================================
// Encoders — RESPONSES (server → client)
// ============================================================================

/// Common shape for error responses: single `status` byte.
pub fn encode_error_response(status: PivStatus, out: &mut [u8]) -> Result<usize, PivError> {
    if out.is_empty() || status == PivStatus::Ok {
        return Err(PivError::WireFormat);
    }
    out[0] = status as u8;
    Ok(1)
}

pub fn encode_health_response(
    state: PivHealthState,
    out: &mut [u8],
) -> Result<usize, PivError> {
    if out.len() < 2 {
        return Err(PivError::WireFormat);
    }
    out[0] = PivStatus::Ok as u8;
    out[1] = state as u8;
    Ok(2)
}

pub fn encode_verify_pin_ok_response(out: &mut [u8]) -> Result<usize, PivError> {
    if out.is_empty() {
        return Err(PivError::WireFormat);
    }
    out[0] = PivStatus::Ok as u8;
    Ok(1)
}

pub fn encode_list_slots_response(
    list: &PivSlotList,
    out: &mut [u8],
) -> Result<usize, PivError> {
    if list.count as usize > MAX_PIV_SLOTS {
        return Err(PivError::WireFormat);
    }
    let total = 2 + (list.count as usize) * 3;
    if out.len() < total {
        return Err(PivError::WireFormat);
    }
    out[0] = PivStatus::Ok as u8;
    out[1] = list.count;
    for (i, info) in list.entries.iter().take(list.count as usize).enumerate() {
        let base = 2 + i * 3;
        out[base] = info.slot as u8;
        out[base + 1] = info.algo as u8;
        out[base + 2] = if info.populated { 1 } else { 0 };
    }
    Ok(total)
}

pub fn encode_get_pubkey_response(
    pubkey: &PivPubkey,
    out: &mut [u8],
) -> Result<usize, PivError> {
    let pk_len = pubkey.len as usize;
    if pk_len > MAX_PUBKEY_LEN {
        return Err(PivError::WireFormat);
    }
    let total = 3 + pk_len;
    if out.len() < total {
        return Err(PivError::WireFormat);
    }
    out[0] = PivStatus::Ok as u8;
    out[1] = pubkey.algo as u8;
    out[2] = pubkey.len;
    out[3..total].copy_from_slice(&pubkey.bytes[..pk_len]);
    Ok(total)
}

pub fn encode_sign_response(sig: &Ed25519Signature, out: &mut [u8]) -> Result<usize, PivError> {
    if out.len() < 2 + 64 {
        return Err(PivError::WireFormat);
    }
    out[0] = PivStatus::Ok as u8;
    out[1] = 64;
    out[2..2 + 64].copy_from_slice(&sig.0);
    Ok(2 + 64)
}

pub fn encode_decrypt_response(plaintext: &[u8], out: &mut [u8]) -> Result<usize, PivError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(PivError::WireFormat);
    }
    let total = 3 + plaintext.len();
    if out.len() < total {
        return Err(PivError::WireFormat);
    }
    out[0] = PivStatus::Ok as u8;
    let len_bytes = (plaintext.len() as u16).to_le_bytes();
    out[1] = len_bytes[0];
    out[2] = len_bytes[1];
    out[3..total].copy_from_slice(plaintext);
    Ok(total)
}

pub fn encode_attest_response(cert: &[u8], out: &mut [u8]) -> Result<usize, PivError> {
    if cert.len() > MAX_ATTEST_INLINE {
        return Err(PivError::WireFormat);
    }
    let total = 3 + cert.len();
    if out.len() < total {
        return Err(PivError::WireFormat);
    }
    out[0] = PivStatus::Ok as u8;
    let len_bytes = (cert.len() as u16).to_le_bytes();
    out[1] = len_bytes[0];
    out[2] = len_bytes[1];
    out[3..total].copy_from_slice(cert);
    Ok(total)
}

// ============================================================================
// Decoders — RESPONSES (client-side parse)
// ============================================================================
//
// Each `decode_*_response` reads the status byte first. If non-Ok, returns
// the mapped `PivError`. Otherwise parses the body.

fn read_status(buf: &[u8]) -> Result<(), PivError> {
    if buf.is_empty() {
        return Err(PivError::WireFormat);
    }
    let status = PivStatus::from_byte(buf[0]).ok_or(PivError::WireFormat)?;
    match PivError::from_status(status) {
        None => Ok(()),
        Some(err) => Err(err),
    }
}

pub fn decode_health_response(buf: &[u8]) -> Result<PivHealthState, PivError> {
    read_status(buf)?;
    if buf.len() != 2 {
        return Err(PivError::WireFormat);
    }
    PivHealthState::from_byte(buf[1]).ok_or(PivError::WireFormat)
}

pub fn decode_verify_pin_response(buf: &[u8]) -> Result<(), PivError> {
    read_status(buf)?;
    if buf.len() != 1 {
        return Err(PivError::WireFormat);
    }
    Ok(())
}

pub fn decode_list_slots_response(buf: &[u8]) -> Result<PivSlotList, PivError> {
    read_status(buf)?;
    if buf.len() < 2 {
        return Err(PivError::WireFormat);
    }
    let count = buf[1];
    if count as usize > MAX_PIV_SLOTS {
        return Err(PivError::WireFormat);
    }
    let expected = 2 + (count as usize) * 3;
    if buf.len() != expected {
        return Err(PivError::WireFormat);
    }
    let mut list = PivSlotList {
        count,
        entries: [PivSlotInfo {
            slot: PivSlot::Authentication,
            algo: PivAlgo::Ed25519,
            populated: false,
        }; MAX_PIV_SLOTS],
    };
    for i in 0..count as usize {
        let base = 2 + i * 3;
        let slot = PivSlot::from_byte(buf[base]).ok_or(PivError::WireFormat)?;
        let algo = PivAlgo::from_byte(buf[base + 1]).ok_or(PivError::WireFormat)?;
        let populated = match buf[base + 2] {
            0 => false,
            1 => true,
            _ => return Err(PivError::WireFormat),
        };
        list.entries[i] = PivSlotInfo { slot, algo, populated };
    }
    Ok(list)
}

pub fn decode_get_pubkey_response(buf: &[u8]) -> Result<PivPubkey, PivError> {
    read_status(buf)?;
    if buf.len() < 3 {
        return Err(PivError::WireFormat);
    }
    let algo = PivAlgo::from_byte(buf[1]).ok_or(PivError::WireFormat)?;
    let pk_len = buf[2] as usize;
    if pk_len > MAX_PUBKEY_LEN || buf.len() != 3 + pk_len {
        return Err(PivError::WireFormat);
    }
    let mut pubkey = PivPubkey {
        algo,
        len: pk_len as u8,
        bytes: [0u8; MAX_PUBKEY_LEN],
    };
    pubkey.bytes[..pk_len].copy_from_slice(&buf[3..3 + pk_len]);
    Ok(pubkey)
}

pub fn decode_sign_response(buf: &[u8]) -> Result<Ed25519Signature, PivError> {
    read_status(buf)?;
    if buf.len() != 2 + 64 || buf[1] != 64 {
        return Err(PivError::WireFormat);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&buf[2..2 + 64]);
    Ok(Ed25519Signature(sig))
}

/// Decode CMD_PIV_DECRYPT response into a caller-provided buffer.
/// Returns the number of plaintext bytes written.
pub fn decode_decrypt_response(buf: &[u8], out: &mut [u8]) -> Result<usize, PivError> {
    read_status(buf)?;
    if buf.len() < 3 {
        return Err(PivError::WireFormat);
    }
    let pt_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
    if pt_len > MAX_PLAINTEXT_LEN || buf.len() != 3 + pt_len {
        return Err(PivError::WireFormat);
    }
    if out.len() < pt_len {
        return Err(PivError::WireFormat);
    }
    out[..pt_len].copy_from_slice(&buf[3..3 + pt_len]);
    Ok(pt_len)
}

/// Decode CMD_PIV_ATTEST response into a caller-provided buffer.
/// Returns the number of certificate bytes written.
pub fn decode_attest_response(buf: &[u8], out: &mut [u8]) -> Result<usize, PivError> {
    read_status(buf)?;
    if buf.len() < 3 {
        return Err(PivError::WireFormat);
    }
    let cert_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
    if cert_len > MAX_ATTEST_INLINE || buf.len() != 3 + cert_len {
        return Err(PivError::WireFormat);
    }
    if out.len() < cert_len {
        return Err(PivError::WireFormat);
    }
    out[..cert_len].copy_from_slice(&buf[3..3 + cert_len]);
    Ok(cert_len)
}

// ============================================================================
// IPC wrappers — compose codec + sys::write + sys::recv_msg
// ============================================================================
//
// These are convenience wrappers around the codec. Each:
//   1. Encodes the request into a stack-local 256-byte buffer.
//   2. Writes it to `KEY_STORE_ENDPOINT` (17) via `sys::write`.
//   3. Blocks on `sys::recv_msg(reply_endpoint, …)` for the response.
//   4. Strips the 36-byte `[sender_principal:32][from_endpoint:4]`
//      header that the kernel prepends to incoming messages.
//   5. Decodes the response payload, returning either the typed result
//      or a mapped `PivError`.
//
// **Caller contract:** the caller MUST have called
// `sys::register_endpoint(reply_endpoint)` before invoking any of
// these. The reply endpoint is the queue the wrapper drains for the
// response — typically the caller's first registered endpoint, also
// reflected in the kernel's `REPLY_ENDPOINT` table per CLAUDE.md §
// "IPC reply-endpoint registry". Different callers should not share
// a reply endpoint (cross-talk hazard).
//
// **Threading:** these block. A service-loop process cannot call them
// from the same task that is `recv_verified`-ing on the same endpoint
// without orchestration — both calls would race on the same queue.
//
// Audit-emit on key-use is deferred per Convention 9 — see
// `user/key-store-service/src/piv/dispatch.rs`. The deferral applies
// equally to the client side (sign / decrypt wrappers); when the
// userspace audit-emit syscall lands, both sides gain an emit point.
// Revisit when: userspace audit-emit syscall lands OR audit-tail
// subscribes to key-store events.

/// Bytes of IPC envelope prepended to every received message.
const IPC_ENVELOPE_BYTES: usize = 32 + 4;

fn recv_response<'a>(
    reply_endpoint: u32,
    buf: &'a mut [u8; 256],
) -> Result<&'a [u8], PivError> {
    let n = crate::recv_msg(reply_endpoint, buf);
    if n < 0 {
        return Err(PivError::Ipc);
    }
    let total = n as usize;
    if total < IPC_ENVELOPE_BYTES {
        return Err(PivError::Ipc);
    }
    Ok(&buf[IPC_ENVELOPE_BYTES..total])
}

fn send_request(req: &[u8]) -> Result<(), PivError> {
    if crate::write(KEY_STORE_ENDPOINT, req) < 0 {
        Err(PivError::Ipc)
    } else {
        Ok(())
    }
}

/// Query the key-store's PIV health. Does not require PIN.
pub fn piv_health(reply_endpoint: u32) -> Result<PivHealthState, PivError> {
    let mut req = [0u8; 256];
    let req_len = encode_health_request(&mut req)?;
    send_request(&req[..req_len])?;
    let mut resp = [0u8; 256];
    let payload = recv_response(reply_endpoint, &mut resp)?;
    decode_health_response(payload)
}

/// Verify the PIN. On success, subsequent sign / decrypt operations
/// are unlocked for the lifetime of the key-store-service process.
pub fn piv_verify_pin(reply_endpoint: u32, pin: &[u8]) -> Result<(), PivError> {
    let mut req = [0u8; 256];
    let req_len = encode_verify_pin_request(pin, &mut req)?;
    send_request(&req[..req_len])?;
    let mut resp = [0u8; 256];
    let payload = recv_response(reply_endpoint, &mut resp)?;
    decode_verify_pin_response(payload)
}

/// Enumerate the configured PIV slots and their algorithms. Does not
/// require PIN.
pub fn piv_list_slots(reply_endpoint: u32) -> Result<PivSlotList, PivError> {
    let mut req = [0u8; 256];
    let req_len = encode_list_slots_request(&mut req)?;
    send_request(&req[..req_len])?;
    let mut resp = [0u8; 256];
    let payload = recv_response(reply_endpoint, &mut resp)?;
    decode_list_slots_response(payload)
}

/// Read the public key in `slot`. Does not require PIN (PIV pubkeys
/// are readable without auth).
pub fn piv_get_pubkey(
    reply_endpoint: u32,
    slot: PivSlot,
) -> Result<PivPubkey, PivError> {
    let mut req = [0u8; 256];
    let req_len = encode_get_pubkey_request(slot, &mut req)?;
    send_request(&req[..req_len])?;
    let mut resp = [0u8; 256];
    let payload = recv_response(reply_endpoint, &mut resp)?;
    decode_get_pubkey_response(payload)
}

/// Sign `msg` with the private key in `slot`. Requires prior
/// `piv_verify_pin`. Returns a 64-byte Ed25519 signature.
pub fn piv_sign(
    reply_endpoint: u32,
    slot: PivSlot,
    msg: &[u8],
) -> Result<Ed25519Signature, PivError> {
    let mut req = [0u8; 256];
    let req_len = encode_sign_request(slot, msg, &mut req)?;
    send_request(&req[..req_len])?;
    let mut resp = [0u8; 256];
    let payload = recv_response(reply_endpoint, &mut resp)?;
    decode_sign_response(payload)
}

/// Decrypt / ECDH with the private key in `slot`. For slot 9D
/// (KeyManagement) `wrapped` is the caller's ephemeral X25519 public
/// key; the response is the 32-byte ECDH shared secret. Writes up to
/// `out.len()` bytes; returns the actual byte count.
pub fn piv_decrypt(
    reply_endpoint: u32,
    slot: PivSlot,
    wrapped: &[u8],
    out: &mut [u8],
) -> Result<usize, PivError> {
    let mut req = [0u8; 256];
    let req_len = encode_decrypt_request(slot, wrapped, &mut req)?;
    send_request(&req[..req_len])?;
    let mut resp = [0u8; 256];
    let payload = recv_response(reply_endpoint, &mut resp)?;
    decode_decrypt_response(payload, out)
}

/// Read the on-card attestation certificate for `slot`. The software
/// backend returns `SlotEmpty`; `CcidPivBackend` (stream B) will
/// return the YubiKey-signed X.509 cert.
pub fn piv_attest(
    reply_endpoint: u32,
    slot: PivSlot,
    out: &mut [u8],
) -> Result<usize, PivError> {
    let mut req = [0u8; 256];
    let req_len = encode_attest_request(slot, &mut req)?;
    send_request(&req[..req_len])?;
    let mut resp = [0u8; 256];
    let payload = recv_response(reply_endpoint, &mut resp)?;
    decode_attest_response(payload, out)
}

// ============================================================================
// Tests — wire-format round-trips
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_roundtrip() {
        let mut req = [0u8; 256];
        let n = encode_health_request(&mut req).unwrap();
        assert_eq!(n, 1);
        decode_health_request(&req[..n]).unwrap();

        let mut resp = [0u8; 256];
        let n = encode_health_response(PivHealthState::Ready, &mut resp).unwrap();
        assert_eq!(n, 2);
        let state = decode_health_response(&resp[..n]).unwrap();
        assert_eq!(state, PivHealthState::Ready);
    }

    #[test]
    fn health_response_all_states() {
        for state in [
            PivHealthState::NotPresent,
            PivHealthState::Ready,
            PivHealthState::NotReady,
            PivHealthState::AuthRequired,
        ] {
            let mut buf = [0u8; 256];
            let n = encode_health_response(state, &mut buf).unwrap();
            assert_eq!(decode_health_response(&buf[..n]).unwrap(), state);
        }
    }

    #[test]
    fn verify_pin_roundtrip() {
        let pin = b"123456";
        let mut req = [0u8; 256];
        let n = encode_verify_pin_request(pin, &mut req).unwrap();
        assert_eq!(n, 2 + pin.len());
        let decoded = decode_verify_pin_request(&req[..n]).unwrap();
        assert_eq!(decoded, pin);

        let mut resp = [0u8; 256];
        let n = encode_verify_pin_ok_response(&mut resp).unwrap();
        decode_verify_pin_response(&resp[..n]).unwrap();
    }

    #[test]
    fn verify_pin_max_len() {
        let pin = [0xABu8; MAX_PIN_LEN];
        let mut req = [0u8; 256];
        let n = encode_verify_pin_request(&pin, &mut req).unwrap();
        let decoded = decode_verify_pin_request(&req[..n]).unwrap();
        assert_eq!(decoded, &pin);
    }

    #[test]
    fn verify_pin_oversize_rejected() {
        let pin = [0u8; MAX_PIN_LEN + 1];
        let mut req = [0u8; 256];
        assert_eq!(
            encode_verify_pin_request(&pin, &mut req),
            Err(PivError::WireFormat)
        );
    }

    #[test]
    fn list_slots_roundtrip_empty() {
        let mut req = [0u8; 256];
        let n = encode_list_slots_request(&mut req).unwrap();
        decode_list_slots_request(&req[..n]).unwrap();

        let list = PivSlotList {
            count: 0,
            entries: [PivSlotInfo {
                slot: PivSlot::Authentication,
                algo: PivAlgo::Ed25519,
                populated: false,
            }; MAX_PIV_SLOTS],
        };
        let mut resp = [0u8; 256];
        let n = encode_list_slots_response(&list, &mut resp).unwrap();
        let decoded = decode_list_slots_response(&resp[..n]).unwrap();
        assert_eq!(decoded.count, 0);
    }

    #[test]
    fn list_slots_roundtrip_four_standard() {
        let mut list = PivSlotList {
            count: 4,
            entries: [PivSlotInfo {
                slot: PivSlot::Authentication,
                algo: PivAlgo::Ed25519,
                populated: false,
            }; MAX_PIV_SLOTS],
        };
        list.entries[0] = PivSlotInfo {
            slot: PivSlot::Authentication,
            algo: PivAlgo::EccP256,
            populated: false,
        };
        list.entries[1] = PivSlotInfo {
            slot: PivSlot::Signature,
            algo: PivAlgo::Ed25519,
            populated: true,
        };
        list.entries[2] = PivSlotInfo {
            slot: PivSlot::KeyManagement,
            algo: PivAlgo::X25519,
            populated: true,
        };
        list.entries[3] = PivSlotInfo {
            slot: PivSlot::CardAuthentication,
            algo: PivAlgo::EccP256,
            populated: false,
        };

        let mut buf = [0u8; 256];
        let n = encode_list_slots_response(&list, &mut buf).unwrap();
        let decoded = decode_list_slots_response(&buf[..n]).unwrap();
        assert_eq!(decoded.count, 4);
        assert_eq!(decoded.as_slice(), list.as_slice());
    }

    #[test]
    fn get_pubkey_roundtrip_ed25519() {
        let mut req = [0u8; 256];
        let n = encode_get_pubkey_request(PivSlot::Signature, &mut req).unwrap();
        assert_eq!(decode_get_pubkey_request(&req[..n]).unwrap(), PivSlot::Signature);

        let mut bytes = [0u8; MAX_PUBKEY_LEN];
        for (i, b) in bytes.iter_mut().take(32).enumerate() {
            *b = i as u8;
        }
        let pubkey = PivPubkey {
            algo: PivAlgo::Ed25519,
            len: 32,
            bytes,
        };
        let mut resp = [0u8; 256];
        let n = encode_get_pubkey_response(&pubkey, &mut resp).unwrap();
        let decoded = decode_get_pubkey_response(&resp[..n]).unwrap();
        assert_eq!(decoded.algo, PivAlgo::Ed25519);
        assert_eq!(decoded.len, 32);
        assert_eq!(decoded.as_slice(), &bytes[..32]);
    }

    #[test]
    fn get_pubkey_roundtrip_ecc_p256_uncompressed() {
        let mut bytes = [0u8; MAX_PUBKEY_LEN];
        for (i, b) in bytes.iter_mut().take(65).enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let pubkey = PivPubkey {
            algo: PivAlgo::EccP256,
            len: 65,
            bytes,
        };
        let mut buf = [0u8; 256];
        let n = encode_get_pubkey_response(&pubkey, &mut buf).unwrap();
        let decoded = decode_get_pubkey_response(&buf[..n]).unwrap();
        assert_eq!(decoded.algo, PivAlgo::EccP256);
        assert_eq!(decoded.len, 65);
        assert_eq!(decoded.as_slice(), &bytes[..65]);
    }

    #[test]
    fn sign_roundtrip() {
        let msg = b"hello world";
        let mut req = [0u8; 256];
        let n = encode_sign_request(PivSlot::Signature, msg, &mut req).unwrap();
        let (slot, decoded_msg) = decode_sign_request(&req[..n]).unwrap();
        assert_eq!(slot, PivSlot::Signature);
        assert_eq!(decoded_msg, msg);

        let mut sig_bytes = [0u8; 64];
        for (i, b) in sig_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let sig = Ed25519Signature(sig_bytes);
        let mut resp = [0u8; 256];
        let n = encode_sign_response(&sig, &mut resp).unwrap();
        let decoded_sig = decode_sign_response(&resp[..n]).unwrap();
        assert_eq!(decoded_sig.0, sig_bytes);
    }

    #[test]
    fn sign_max_msg_len() {
        let msg = [0xAAu8; MAX_SIGN_MSG_LEN];
        let mut req = [0u8; 256];
        let n = encode_sign_request(PivSlot::Signature, &msg, &mut req).unwrap();
        let (_, decoded) = decode_sign_request(&req[..n]).unwrap();
        assert_eq!(decoded.len(), MAX_SIGN_MSG_LEN);
    }

    #[test]
    fn sign_oversize_rejected() {
        let msg = [0u8; MAX_SIGN_MSG_LEN + 1];
        let mut req = [0u8; 256];
        assert_eq!(
            encode_sign_request(PivSlot::Signature, &msg, &mut req),
            Err(PivError::WireFormat)
        );
    }

    #[test]
    fn decrypt_roundtrip() {
        let wrapped = [0x42u8; 200];
        let mut req = [0u8; 256];
        let n = encode_decrypt_request(PivSlot::KeyManagement, &wrapped, &mut req).unwrap();
        let (slot, decoded_wrapped) = decode_decrypt_request(&req[..n]).unwrap();
        assert_eq!(slot, PivSlot::KeyManagement);
        assert_eq!(decoded_wrapped, &wrapped);

        let plaintext = [0u8; 32];
        let mut resp = [0u8; 256];
        let n = encode_decrypt_response(&plaintext, &mut resp).unwrap();
        let mut out = [0u8; 32];
        let pt_len = decode_decrypt_response(&resp[..n], &mut out).unwrap();
        assert_eq!(pt_len, 32);
        assert_eq!(out, plaintext);
    }

    #[test]
    fn decrypt_max_wrapped_len() {
        let wrapped = [0u8; MAX_WRAPPED_KEY_LEN];
        let mut req = [0u8; 256];
        let n = encode_decrypt_request(PivSlot::KeyManagement, &wrapped, &mut req).unwrap();
        let (_, decoded) = decode_decrypt_request(&req[..n]).unwrap();
        assert_eq!(decoded.len(), MAX_WRAPPED_KEY_LEN);
    }

    #[test]
    fn attest_roundtrip() {
        let mut req = [0u8; 256];
        let n = encode_attest_request(PivSlot::Signature, &mut req).unwrap();
        assert_eq!(decode_attest_request(&req[..n]).unwrap(), PivSlot::Signature);

        let cert = [0xCEu8; 200];
        let mut resp = [0u8; 256];
        let n = encode_attest_response(&cert, &mut resp).unwrap();
        let mut out = [0u8; 200];
        let cert_len = decode_attest_response(&resp[..n], &mut out).unwrap();
        assert_eq!(cert_len, 200);
        assert_eq!(out, cert);
    }

    #[test]
    fn error_response_for_each_status() {
        for status in [
            PivStatus::Generic,
            PivStatus::NotPresent,
            PivStatus::AuthRequired,
            PivStatus::SlotEmpty,
            PivStatus::WrongAlgorithm,
            PivStatus::PinLocked,
            PivStatus::CardTransport,
        ] {
            let mut resp = [0u8; 256];
            let n = encode_error_response(status, &mut resp).unwrap();
            assert_eq!(n, 1);
            // Any response-decoder should surface the matching PivError.
            let err = decode_health_response(&resp[..n]).unwrap_err();
            let expected = PivError::from_status(status).unwrap();
            assert_eq!(err, expected);
        }
    }

    #[test]
    fn error_response_rejects_ok_status() {
        let mut resp = [0u8; 256];
        assert_eq!(
            encode_error_response(PivStatus::Ok, &mut resp),
            Err(PivError::WireFormat)
        );
    }

    #[test]
    fn slot_byte_roundtrip() {
        for slot in [
            PivSlot::Authentication,
            PivSlot::Signature,
            PivSlot::KeyManagement,
            PivSlot::CardAuthentication,
        ] {
            assert_eq!(PivSlot::from_byte(slot as u8), Some(slot));
        }
        assert_eq!(PivSlot::from_byte(0x00), None);
        assert_eq!(PivSlot::from_byte(0x9B), None);
    }

    #[test]
    fn algo_byte_roundtrip() {
        for algo in [PivAlgo::EccP256, PivAlgo::Ed25519, PivAlgo::X25519] {
            assert_eq!(PivAlgo::from_byte(algo as u8), Some(algo));
        }
        assert_eq!(PivAlgo::from_byte(0xFF), None);
    }

    #[test]
    fn status_byte_roundtrip() {
        for status in [
            PivStatus::Ok,
            PivStatus::Generic,
            PivStatus::NotPresent,
            PivStatus::AuthRequired,
            PivStatus::SlotEmpty,
            PivStatus::WrongAlgorithm,
            PivStatus::PinLocked,
            PivStatus::CardTransport,
        ] {
            assert_eq!(PivStatus::from_byte(status as u8), Some(status));
        }
        assert_eq!(PivStatus::from_byte(0x08), None);
    }

    #[test]
    fn truncated_response_rejected() {
        let truncated = [0x00u8]; // Ok status but no body
        assert!(matches!(
            decode_health_response(&truncated),
            Err(PivError::WireFormat)
        ));
        assert!(matches!(
            decode_sign_response(&truncated),
            Err(PivError::WireFormat)
        ));
    }

    #[test]
    fn malformed_request_rejected() {
        // Wrong cmd byte.
        assert!(matches!(
            decode_sign_request(&[0xFF, 0x9C, 0, 0]),
            Err(PivError::WireFormat)
        ));
        // Length mismatch.
        assert!(matches!(
            decode_sign_request(&[CMD_PIV_SIGN, 0x9C, 5, 0, 1, 2, 3]),
            Err(PivError::WireFormat)
        ));
        // Invalid slot byte.
        assert!(matches!(
            decode_get_pubkey_request(&[CMD_PIV_GET_PUBKEY, 0x00]),
            Err(PivError::WireFormat)
        ));
    }
}
