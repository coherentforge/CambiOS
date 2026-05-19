// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Volume header signature verification — kernel-side wrapper over
//! `cambios-fde-proto`.
//!
//! The byte-layout constants, fixed-prefix parser, slot-table
//! parser, slot enums, and `SlotEntry` struct all live in
//! `cambios-fde-proto` so userspace consumers (`fde-mount`,
//! `format-volume`, the shell `fde-test` command) can share one
//! source of truth without duplication.
//!
//! What stays kernel-side: `verify_header`, which composes
//! `parse` with an ed25519 signature check against the
//! kernel-baked bootstrap pubkey via `crate::crypto::verify`.
//! Userspace doesn't have access to the baked pubkey or the
//! `crate::crypto` shim, so this layer is the kernel's
//! responsibility.

pub use cambios_fde_proto::{
    HeaderError, OFF_SLOT_TABLE, SIGNATURE_BYTES, SLOT_BYTES, SLOT_OFF_CLASS,
    SLOT_OFF_PRINCIPAL, SLOT_OFF_TYPE, SLOT_OFF_WRAPPED_KEY, SLOT_OFF_WRAPPED_LEN,
    SLOT_WRAPPED_KEY_MAX, SlotClass, SlotEntry, SlotType, VolumeHeader, find_first_live_yubikey,
    parse, parse_slot_table, HEADER_FIXED_PREFIX, HEADER_MAX_LEN, HEADER_MIN_LEN,
    MAX_VOLUME_SLOTS, OFF_CIPHER_ID, OFF_FORMAT_GEN, OFF_HEADER_LEN, OFF_KDF_ID,
    OFF_KDF_PARAMS, OFF_MAGIC, OFF_MASTER_ROT, OFF_RESERVED, OFF_RESERVED_FLAGS,
    OFF_SLOT_COUNT, OFF_VOLUME_UUID, VOLUME_MAGIC,
};

use crate::crypto::{PublicKeyRef, SignatureAlgo, SignatureRef, verify};

/// Parse + signature-verify a complete volume header against the
/// kernel-baked bootstrap pubkey. Returns the parsed header on
/// success or the first failing invariant.
///
/// Checks (in order):
///   1. Parse the fixed prefix (delegates to `cambios_fde_proto::parse`).
///   2. `bytes.len() == header.header_length` (the signature lives
///      at `header_length-64..header_length`).
///   3. `volume_uuid == bootstrap_pubkey` (the AID-as-bootstrap-pubkey
///      invariant per ADR-032 § 3).
///   4. Ed25519 signature at `[header_length-64..header_length]`
///      verifies under `bootstrap_pubkey` over `[0..header_length-64]`.
pub fn verify_header(
    bytes: &[u8],
    bootstrap_pubkey: &[u8; 32],
) -> Result<VolumeHeader, HeaderError> {
    let header = parse(bytes)?;
    let header_length = header.header_length as usize;
    if bytes.len() != header_length {
        return Err(HeaderError::BadHeaderLength);
    }
    if header.volume_uuid != *bootstrap_pubkey {
        return Err(HeaderError::VolumeUuidMismatch);
    }
    let sig_offset = header_length - SIGNATURE_BYTES;
    let signed_content = &bytes[..sig_offset];
    let mut sig_bytes = [0u8; SIGNATURE_BYTES];
    sig_bytes.copy_from_slice(&bytes[sig_offset..header_length]);

    if !verify(
        SignatureAlgo::Ed25519,
        PublicKeyRef::Ed25519(bootstrap_pubkey),
        signed_content,
        SignatureRef::Ed25519(&sig_bytes),
    ) {
        return Err(HeaderError::SignatureInvalid);
    }
    Ok(header)
}

// ============================================================================
// Tests — signature verification only. Parse + slot-table tests live
// in `cambios-fde-proto/src/lib.rs` since they don't depend on the
// kernel's `crate::crypto::verify`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    fn make_keypair(seed_byte: u8) -> KeyPair {
        KeyPair::from_seed(Seed::new([seed_byte; 32]))
    }

    /// Build a minimal valid header (0 slots, no padding), sign it
    /// with the given keypair, and embed its pubkey as the volume_uuid.
    fn build_signed_header(kp: &KeyPair) -> ([u8; HEADER_MIN_LEN], [u8; 32]) {
        let mut buf = [0u8; HEADER_MIN_LEN];
        let pk_bytes = {
            let mut b = [0u8; 32];
            b.copy_from_slice(kp.pk.as_ref());
            b
        };

        buf[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(VOLUME_MAGIC);
        buf[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
            .copy_from_slice(&(HEADER_MIN_LEN as u32).to_le_bytes());
        buf[OFF_CIPHER_ID..OFF_CIPHER_ID + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_VOLUME_UUID..OFF_VOLUME_UUID + 32].copy_from_slice(&pk_bytes);
        buf[OFF_FORMAT_GEN..OFF_FORMAT_GEN + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_KDF_ID..OFF_KDF_ID + 4].copy_from_slice(&1u32.to_le_bytes());

        let sig_offset = HEADER_MIN_LEN - SIGNATURE_BYTES;
        let signed = &buf[..sig_offset];
        let sig = kp.sk.sign(signed, None);
        buf[sig_offset..HEADER_MIN_LEN].copy_from_slice(sig.as_ref());

        (buf, pk_bytes)
    }

    #[test]
    fn verify_minimal_header_under_correct_pubkey() {
        let kp = make_keypair(0x02);
        let (buf, pk) = build_signed_header(&kp);
        let header = verify_header(&buf, &pk).expect("verify");
        assert_eq!(header.volume_uuid, pk);
    }

    #[test]
    fn verify_rejects_tampered_content() {
        let kp = make_keypair(0x03);
        let (mut buf, pk) = build_signed_header(&kp);
        buf[OFF_CIPHER_ID] ^= 0xFF;
        assert_eq!(verify_header(&buf, &pk), Err(HeaderError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let kp = make_keypair(0x04);
        let (mut buf, pk) = build_signed_header(&kp);
        let sig_offset = HEADER_MIN_LEN - SIGNATURE_BYTES;
        buf[sig_offset] ^= 0xFF;
        assert_eq!(verify_header(&buf, &pk), Err(HeaderError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let signing_kp = make_keypair(0x05);
        let (buf, _signing_pk) = build_signed_header(&signing_kp);
        let wrong_pk = [0xAAu8; 32];
        assert_eq!(verify_header(&buf, &wrong_pk), Err(HeaderError::VolumeUuidMismatch));
    }

    #[test]
    fn verify_rejects_mismatched_aid_with_correct_signing_key() {
        let signing_kp = make_keypair(0x06);
        let (mut buf, pk) = build_signed_header(&signing_kp);
        buf[OFF_VOLUME_UUID] ^= 0xFF;
        let sig_offset = HEADER_MIN_LEN - SIGNATURE_BYTES;
        let signed = &buf[..sig_offset];
        let fresh_sig = signing_kp.sk.sign(signed, None);
        buf[sig_offset..HEADER_MIN_LEN].copy_from_slice(fresh_sig.as_ref());
        assert_eq!(verify_header(&buf, &pk), Err(HeaderError::VolumeUuidMismatch));
    }

    #[test]
    fn verify_rejects_under_min_length() {
        let buf = [0u8; HEADER_MIN_LEN - 1];
        let pk = [0u8; 32];
        assert_eq!(verify_header(&buf, &pk), Err(HeaderError::BadLength));
    }

    #[test]
    fn verify_rejects_header_length_field_disagreeing_with_buffer() {
        let kp = make_keypair(0x0B);
        let (mut buf, pk) = build_signed_header(&kp);
        let lying = (HEADER_MIN_LEN as u32) + 8;
        buf[OFF_HEADER_LEN..OFF_HEADER_LEN + 4].copy_from_slice(&lying.to_le_bytes());
        assert_eq!(
            verify_header(&buf, &pk),
            Err(HeaderError::BadHeaderLength)
        );
    }

    #[test]
    fn verify_accepts_padded_header_with_one_slot() {
        let kp = make_keypair(0x0C);
        const TOTAL: usize = 512;
        let mut buf = [0u8; TOTAL];
        let pk_bytes = {
            let mut b = [0u8; 32];
            b.copy_from_slice(kp.pk.as_ref());
            b
        };

        buf[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(VOLUME_MAGIC);
        buf[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
            .copy_from_slice(&(TOTAL as u32).to_le_bytes());
        buf[OFF_CIPHER_ID..OFF_CIPHER_ID + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_VOLUME_UUID..OFF_VOLUME_UUID + 32].copy_from_slice(&pk_bytes);
        buf[OFF_FORMAT_GEN..OFF_FORMAT_GEN + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_KDF_ID..OFF_KDF_ID + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_SLOT_COUNT..OFF_SLOT_COUNT + 4].copy_from_slice(&1u32.to_le_bytes());

        let sig_offset = TOTAL - SIGNATURE_BYTES;
        let sig = kp.sk.sign(&buf[..sig_offset], None);
        buf[sig_offset..TOTAL].copy_from_slice(sig.as_ref());

        let header = verify_header(&buf, &pk_bytes).expect("verify");
        assert_eq!(header.slot_count, 1);
        assert_eq!(header.header_length as usize, TOTAL);
    }
}
