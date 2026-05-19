// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! FDE volume header on-disk format — ADR-032 § 4 + § 5 slot table.
//!
//! Source-of-truth for the byte layout of CambiOS encrypted volume
//! headers. Pure types + parsers; no I/O, no globals, no signature
//! verification (that lives in the kernel because it depends on the
//! baked bootstrap pubkey and the kernel's `crate::crypto::verify`
//! shim). Consumers:
//!
//! - Kernel `src/fs/crypto/header.rs` — wraps the parsers with
//!   `verify_header` for the `SYS_VERIFY_VOLUME_HEADER` syscall
//!   handler.
//! - Userspace `user/fde-mount/` boot module (stream A A-v.a) —
//!   reads the header from raw disk, walks the slot table, finds
//!   the live YubiKey slot.
//! - Userspace `user/shell` `fde-test` command — builds a header
//!   for the sign+verify round-trip demo.
//! - Host tool `tools/format-volume` (stream A A-v.e) — writes
//!   fresh signed headers.
//!
//! Three categories of code:
//! 1. **Constants** — magic, byte offsets, lengths, MAX_VOLUME_SLOTS.
//! 2. **`parse(bytes) -> Result<VolumeHeader, HeaderError>`** —
//!    fixed-prefix parser. Validates magic + `header_length` bounds
//!    + `slot_count <= MAX_VOLUME_SLOTS`. Returns the parsed prefix.
//!    Does **not** match `bytes.len()` against `header.header_length`
//!    (the kernel's `verify_header` does that, since it's the
//!    invariant before signature verify).
//! 3. **`parse_slot_table(bytes, slot_count) -> Result<[Option
//!    <SlotEntry>; MAX_VOLUME_SLOTS], HeaderError>`** — walks the
//!    slot region after the fixed prefix.
//! 4. **`find_first_live_yubikey(&slots) -> Option<&SlotEntry>`** —
//!    selection helper for fde-mount.

#![no_std]
#![deny(unsafe_code)]

// ============================================================================
// Constants
// ============================================================================

pub const VOLUME_MAGIC: &[u8; 8] = b"ARCVOL01";

pub const OFF_MAGIC: usize = 0;
pub const OFF_HEADER_LEN: usize = 8;
pub const OFF_CIPHER_ID: usize = 12;
pub const OFF_VOLUME_UUID: usize = 16;
pub const OFF_FORMAT_GEN: usize = 48;
pub const OFF_KDF_ID: usize = 52;
pub const OFF_KDF_PARAMS: usize = 56;
pub const OFF_SLOT_COUNT: usize = 88;
pub const OFF_MASTER_ROT: usize = 92;
pub const OFF_RESERVED_FLAGS: usize = 96;
pub const OFF_RESERVED: usize = 100;
pub const OFF_SLOT_TABLE: usize = 112;

/// HARDWARE: byte count for one slot per ADR-032 § 4 slot table.
pub const SLOT_BYTES: usize = 256;

/// HARDWARE: Ed25519 signature length.
pub const SIGNATURE_BYTES: usize = 64;

/// HARDWARE: fixed-prefix length before the slot table per ADR-032 § 4.
pub const HEADER_FIXED_PREFIX: usize = 112;

/// SCAFFOLDING: maximum volume slot count per ADR-032 § 4.
/// Why: v1 deployments use 1-3 YubiKey live slots + 1-2 Argon2id
/// recovery slots; 16 = headroom for future N-of-1 unlock with
/// multiple authorized YubiKeys. Memory cost: 4 KiB per header.
/// Replace when: a deployment surfaces > 4 active live slots in practice.
pub const MAX_VOLUME_SLOTS: usize = 16;

/// HARDWARE: smallest legal header byte length (zero-slot edge case).
pub const HEADER_MIN_LEN: usize = HEADER_FIXED_PREFIX + SIGNATURE_BYTES;

/// HARDWARE: largest legal header byte length (max slots, no padding).
pub const HEADER_MAX_LEN: usize =
    HEADER_FIXED_PREFIX + MAX_VOLUME_SLOTS * SLOT_BYTES + SIGNATURE_BYTES;

/// HARDWARE: maximum byte length for a slot's `wrapped_key` field per
/// ADR-032 § 4 slot table layout. Sized to cover PIV-wrapped AES-256
/// envelopes + slot header bytes (`220 = SLOT_BYTES - 36`).
pub const SLOT_WRAPPED_KEY_MAX: usize = 220;

/// Slot byte offsets within a single 256-byte entry. Names mirror
/// ADR-032 § 4 slot table column headers.
pub const SLOT_OFF_TYPE: usize = 0;
pub const SLOT_OFF_CLASS: usize = 1;
pub const SLOT_OFF_WRAPPED_LEN: usize = 2;
pub const SLOT_OFF_PRINCIPAL: usize = 4;
pub const SLOT_OFF_WRAPPED_KEY: usize = 36;

// ============================================================================
// Error type
// ============================================================================

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HeaderError {
    /// Buffer length < HEADER_MIN_LEN.
    BadLength,
    /// First 8 bytes != "ARCVOL01".
    BadMagic,
    /// header_length field out of [HEADER_MIN_LEN, HEADER_MAX_LEN], or
    /// disagrees with the caller-supplied buffer length.
    BadHeaderLength,
    /// slot_count > MAX_VOLUME_SLOTS.
    SlotCountExceeds,
    /// volume_uuid bytes don't match the bootstrap pubkey. ADR-032 §
    /// 3 invariant: format-time AID equals bootstrap pubkey bytes.
    /// **Kernel-side only** (the proto-level parser does not have the
    /// bootstrap pubkey); emitted by `verify_header` in the kernel.
    VolumeUuidMismatch,
    /// Ed25519 signature did not verify under bootstrap_pubkey.
    /// **Kernel-side only**; emitted by `verify_header` in the kernel.
    SignatureInvalid,
    /// A slot entry's `slot_type` byte is not in {0x00 empty, 0x01
    /// YubiKey, 0x02 Argon2id-passphrase}.
    BadSlotType,
    /// A slot entry's `slot_class` byte is not in {0x00 live, 0x01
    /// recovery}.
    BadSlotClass,
    /// A slot entry's `wrapped_key_len` exceeds `SLOT_WRAPPED_KEY_MAX`.
    BadWrappedKeyLen,
}

// ============================================================================
// Parsed header view
// ============================================================================

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct VolumeHeader {
    pub header_length: u32,
    pub cipher_id: u32,
    pub volume_uuid: [u8; 32],
    pub format_generation: u32,
    pub kdf_id: u32,
    pub slot_count: u32,
    pub master_rotation_progress: u32,
}

// ============================================================================
// Parse
// ============================================================================

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Parse the fixed-prefix fields. Validates magic, header_length
/// range, and slot_count bound. Does **not** verify the signature
/// (see kernel's `verify_header`) and does **not** require the
/// buffer length to equal `header_length`.
pub fn parse(bytes: &[u8]) -> Result<VolumeHeader, HeaderError> {
    if bytes.len() < HEADER_MIN_LEN {
        return Err(HeaderError::BadLength);
    }
    if &bytes[OFF_MAGIC..OFF_MAGIC + 8] != VOLUME_MAGIC {
        return Err(HeaderError::BadMagic);
    }
    let header_length = read_u32_le(bytes, OFF_HEADER_LEN);
    if (header_length as usize) < HEADER_MIN_LEN
        || (header_length as usize) > HEADER_MAX_LEN
    {
        return Err(HeaderError::BadHeaderLength);
    }
    let slot_count = read_u32_le(bytes, OFF_SLOT_COUNT);
    if (slot_count as usize) > MAX_VOLUME_SLOTS {
        return Err(HeaderError::SlotCountExceeds);
    }
    let mut volume_uuid = [0u8; 32];
    volume_uuid.copy_from_slice(&bytes[OFF_VOLUME_UUID..OFF_VOLUME_UUID + 32]);
    Ok(VolumeHeader {
        header_length,
        cipher_id: read_u32_le(bytes, OFF_CIPHER_ID),
        volume_uuid,
        format_generation: read_u32_le(bytes, OFF_FORMAT_GEN),
        kdf_id: read_u32_le(bytes, OFF_KDF_ID),
        slot_count,
        master_rotation_progress: read_u32_le(bytes, OFF_MASTER_ROT),
    })
}

// ============================================================================
// Slot table (ADR-032 § 4 slot layout)
// ============================================================================

/// Slot type byte at slot offset 0. Discriminants match ADR-032 § 4.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SlotType {
    Empty = 0x00,
    YubiKey = 0x01,
    Argon2idPassphrase = 0x02,
}

impl SlotType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Empty),
            0x01 => Some(Self::YubiKey),
            0x02 => Some(Self::Argon2idPassphrase),
            _ => None,
        }
    }
}

/// Slot class byte at slot offset 1. Discriminants match ADR-032 § 5.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SlotClass {
    /// Normal-unlock live slot. N-of-1 unlock via any live YubiKey.
    Live = 0x00,
    /// Single-use recovery slot. Triggers credential rotation per
    /// ADR-032 § 5 on use.
    Recovery = 0x01,
}

impl SlotClass {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Live),
            0x01 => Some(Self::Recovery),
            _ => None,
        }
    }
}

/// Parsed slot table entry.
#[derive(Copy, Clone, Debug)]
pub struct SlotEntry {
    pub slot_type: SlotType,
    pub slot_class: SlotClass,
    pub wrapped_key_len: u16,
    pub slot_principal: [u8; 32],
    pub wrapped_key: [u8; SLOT_WRAPPED_KEY_MAX],
}

impl SlotEntry {
    /// The meaningful prefix of `wrapped_key`. Trailing bytes past
    /// `wrapped_key_len` are zero-padded per ADR-032 § 4.
    pub fn wrapped_key_bytes(&self) -> &[u8] {
        &self.wrapped_key[..self.wrapped_key_len as usize]
    }

    /// True iff this slot is a normal-unlock YubiKey slot — the
    /// shape `fde-mount` walks the table looking for.
    pub fn is_live_yubikey(&self) -> bool {
        self.slot_type == SlotType::YubiKey && self.slot_class == SlotClass::Live
    }
}

/// Parse `slot_count` entries from the slot table region of a volume
/// header. Returns a fixed-size array with the first `slot_count`
/// entries populated as `Some`, the rest `None`.
pub fn parse_slot_table(
    bytes: &[u8],
    slot_count: usize,
) -> Result<[Option<SlotEntry>; MAX_VOLUME_SLOTS], HeaderError> {
    if slot_count > MAX_VOLUME_SLOTS {
        return Err(HeaderError::SlotCountExceeds);
    }
    let required_end = OFF_SLOT_TABLE + slot_count * SLOT_BYTES;
    if bytes.len() < required_end {
        return Err(HeaderError::BadHeaderLength);
    }
    let mut slots: [Option<SlotEntry>; MAX_VOLUME_SLOTS] = [None; MAX_VOLUME_SLOTS];
    for i in 0..slot_count {
        let base = OFF_SLOT_TABLE + i * SLOT_BYTES;
        let slot_bytes = &bytes[base..base + SLOT_BYTES];
        let slot_type = SlotType::from_byte(slot_bytes[SLOT_OFF_TYPE])
            .ok_or(HeaderError::BadSlotType)?;
        let slot_class = SlotClass::from_byte(slot_bytes[SLOT_OFF_CLASS])
            .ok_or(HeaderError::BadSlotClass)?;
        let wrapped_key_len = u16::from_le_bytes([
            slot_bytes[SLOT_OFF_WRAPPED_LEN],
            slot_bytes[SLOT_OFF_WRAPPED_LEN + 1],
        ]);
        if wrapped_key_len as usize > SLOT_WRAPPED_KEY_MAX {
            return Err(HeaderError::BadWrappedKeyLen);
        }
        let mut slot_principal = [0u8; 32];
        slot_principal
            .copy_from_slice(&slot_bytes[SLOT_OFF_PRINCIPAL..SLOT_OFF_PRINCIPAL + 32]);
        let mut wrapped_key = [0u8; SLOT_WRAPPED_KEY_MAX];
        wrapped_key.copy_from_slice(
            &slot_bytes[SLOT_OFF_WRAPPED_KEY..SLOT_OFF_WRAPPED_KEY + SLOT_WRAPPED_KEY_MAX],
        );
        slots[i] = Some(SlotEntry {
            slot_type,
            slot_class,
            wrapped_key_len,
            slot_principal,
            wrapped_key,
        });
    }
    Ok(slots)
}

/// Find the first slot in the table that is a live-class YubiKey
/// entry — the unlock target fde-mount walks to.
pub fn find_first_live_yubikey(
    slots: &[Option<SlotEntry>; MAX_VOLUME_SLOTS],
) -> Option<&SlotEntry> {
    slots
        .iter()
        .filter_map(|s| s.as_ref())
        .find(|s| s.is_live_yubikey())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn write_minimal_prefix(buf: &mut [u8], pubkey: &[u8; 32], total: u32, slot_count: u32) {
        buf[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(VOLUME_MAGIC);
        buf[OFF_HEADER_LEN..OFF_HEADER_LEN + 4].copy_from_slice(&total.to_le_bytes());
        buf[OFF_CIPHER_ID..OFF_CIPHER_ID + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_VOLUME_UUID..OFF_VOLUME_UUID + 32].copy_from_slice(pubkey);
        buf[OFF_FORMAT_GEN..OFF_FORMAT_GEN + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_KDF_ID..OFF_KDF_ID + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_SLOT_COUNT..OFF_SLOT_COUNT + 4].copy_from_slice(&slot_count.to_le_bytes());
    }

    fn build_slot_bytes(
        slot_type: SlotType,
        slot_class: SlotClass,
        wrapped_key: &[u8],
        slot_principal: &[u8; 32],
    ) -> [u8; SLOT_BYTES] {
        let mut buf = [0u8; SLOT_BYTES];
        buf[SLOT_OFF_TYPE] = slot_type as u8;
        buf[SLOT_OFF_CLASS] = slot_class as u8;
        let wlen = wrapped_key.len() as u16;
        buf[SLOT_OFF_WRAPPED_LEN..SLOT_OFF_WRAPPED_LEN + 2]
            .copy_from_slice(&wlen.to_le_bytes());
        buf[SLOT_OFF_PRINCIPAL..SLOT_OFF_PRINCIPAL + 32].copy_from_slice(slot_principal);
        buf[SLOT_OFF_WRAPPED_KEY..SLOT_OFF_WRAPPED_KEY + wrapped_key.len()]
            .copy_from_slice(wrapped_key);
        buf
    }

    fn assert_parse_slot_err(bytes: &[u8], slot_count: usize, expected: HeaderError) {
        // `parse_slot_table`'s Ok variant is an array of SlotEntry,
        // which doesn't derive PartialEq (the [u8; 220] field). Match
        // on the result rather than `assert_eq!`.
        match parse_slot_table(bytes, slot_count) {
            Ok(_) => panic!("expected {:?}, got Ok", expected),
            Err(e) => assert_eq!(e, expected),
        }
    }

    #[test]
    fn parse_minimal_prefix() {
        let mut buf = [0u8; HEADER_MIN_LEN];
        let pk = [0x42u8; 32];
        write_minimal_prefix(&mut buf, &pk, HEADER_MIN_LEN as u32, 0);
        let header = parse(&buf).expect("parse");
        assert_eq!(header.header_length as usize, HEADER_MIN_LEN);
        assert_eq!(header.cipher_id, 1);
        assert_eq!(header.volume_uuid, pk);
        assert_eq!(header.slot_count, 0);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let buf = [0u8; HEADER_MIN_LEN - 1];
        assert_eq!(parse(&buf), Err(HeaderError::BadLength));
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut buf = [0u8; HEADER_MIN_LEN];
        let pk = [0u8; 32];
        write_minimal_prefix(&mut buf, &pk, HEADER_MIN_LEN as u32, 0);
        buf[0] = b'X';
        assert_eq!(parse(&buf), Err(HeaderError::BadMagic));
    }

    #[test]
    fn parse_rejects_header_length_below_min() {
        let mut buf = [0u8; HEADER_MIN_LEN];
        let pk = [0u8; 32];
        write_minimal_prefix(&mut buf, &pk, 100, 0);
        assert_eq!(parse(&buf), Err(HeaderError::BadHeaderLength));
    }

    #[test]
    fn parse_rejects_header_length_above_max() {
        let mut buf = [0u8; HEADER_MIN_LEN];
        let pk = [0u8; 32];
        write_minimal_prefix(&mut buf, &pk, (HEADER_MAX_LEN as u32) + 1, 0);
        assert_eq!(parse(&buf), Err(HeaderError::BadHeaderLength));
    }

    #[test]
    fn parse_rejects_slot_count_overflow() {
        let mut buf = [0u8; HEADER_MIN_LEN];
        let pk = [0u8; 32];
        write_minimal_prefix(
            &mut buf,
            &pk,
            HEADER_MIN_LEN as u32,
            (MAX_VOLUME_SLOTS as u32) + 1,
        );
        assert_eq!(parse(&buf), Err(HeaderError::SlotCountExceeds));
    }

    #[test]
    fn parse_slot_table_zero_slots_returns_all_none() {
        let buf = [0u8; HEADER_MIN_LEN];
        let slots = parse_slot_table(&buf, 0).expect("parse");
        for slot in slots.iter() {
            assert!(slot.is_none());
        }
    }

    #[test]
    fn parse_slot_table_one_live_yubikey() {
        let slot_principal = [0xAAu8; 32];
        let wrapped = [0xCCu8; 80];
        let slot_blob = build_slot_bytes(
            SlotType::YubiKey,
            SlotClass::Live,
            &wrapped,
            &slot_principal,
        );
        let mut buf = [0u8; HEADER_FIXED_PREFIX + SLOT_BYTES + SIGNATURE_BYTES];
        buf[OFF_SLOT_TABLE..OFF_SLOT_TABLE + SLOT_BYTES].copy_from_slice(&slot_blob);

        let slots = parse_slot_table(&buf, 1).expect("parse");
        let s0 = slots[0].as_ref().expect("slot 0 populated");
        assert_eq!(s0.slot_type, SlotType::YubiKey);
        assert_eq!(s0.slot_class, SlotClass::Live);
        assert_eq!(s0.wrapped_key_len as usize, wrapped.len());
        assert_eq!(s0.slot_principal, slot_principal);
        assert_eq!(s0.wrapped_key_bytes(), &wrapped);
        assert!(slots[1].is_none());
    }

    #[test]
    fn parse_slot_table_three_mixed_slots() {
        let live_yk = build_slot_bytes(
            SlotType::YubiKey,
            SlotClass::Live,
            &[1u8; 80],
            &[0x11u8; 32],
        );
        let recovery_argon = build_slot_bytes(
            SlotType::Argon2idPassphrase,
            SlotClass::Recovery,
            &[2u8; 48],
            &[0u8; 32],
        );
        let empty = build_slot_bytes(SlotType::Empty, SlotClass::Live, &[], &[0u8; 32]);
        let mut buf = [0u8; HEADER_FIXED_PREFIX + 3 * SLOT_BYTES + SIGNATURE_BYTES];
        buf[OFF_SLOT_TABLE..OFF_SLOT_TABLE + SLOT_BYTES].copy_from_slice(&live_yk);
        buf[OFF_SLOT_TABLE + SLOT_BYTES..OFF_SLOT_TABLE + 2 * SLOT_BYTES]
            .copy_from_slice(&recovery_argon);
        buf[OFF_SLOT_TABLE + 2 * SLOT_BYTES..OFF_SLOT_TABLE + 3 * SLOT_BYTES]
            .copy_from_slice(&empty);

        let slots = parse_slot_table(&buf, 3).expect("parse");
        assert_eq!(slots[0].as_ref().unwrap().slot_type, SlotType::YubiKey);
        assert_eq!(slots[0].as_ref().unwrap().slot_class, SlotClass::Live);
        assert_eq!(
            slots[1].as_ref().unwrap().slot_type,
            SlotType::Argon2idPassphrase
        );
        assert_eq!(slots[1].as_ref().unwrap().slot_class, SlotClass::Recovery);
        assert_eq!(slots[2].as_ref().unwrap().slot_type, SlotType::Empty);
        assert!(slots[3].is_none());
    }

    #[test]
    fn parse_slot_table_rejects_slot_count_overflow() {
        let buf = [0u8; HEADER_MIN_LEN];
        assert_parse_slot_err(&buf, MAX_VOLUME_SLOTS + 1, HeaderError::SlotCountExceeds);
    }

    #[test]
    fn parse_slot_table_rejects_truncated_bytes() {
        let buf = [0u8; OFF_SLOT_TABLE + SLOT_BYTES - 1];
        assert_parse_slot_err(&buf, 1, HeaderError::BadHeaderLength);
    }

    #[test]
    fn parse_slot_table_rejects_bad_slot_type() {
        let mut buf = [0u8; OFF_SLOT_TABLE + SLOT_BYTES];
        buf[OFF_SLOT_TABLE + SLOT_OFF_TYPE] = 0x99;
        assert_parse_slot_err(&buf, 1, HeaderError::BadSlotType);
    }

    #[test]
    fn parse_slot_table_rejects_bad_slot_class() {
        let mut buf = [0u8; OFF_SLOT_TABLE + SLOT_BYTES];
        buf[OFF_SLOT_TABLE + SLOT_OFF_TYPE] = SlotType::YubiKey as u8;
        buf[OFF_SLOT_TABLE + SLOT_OFF_CLASS] = 0x99;
        assert_parse_slot_err(&buf, 1, HeaderError::BadSlotClass);
    }

    #[test]
    fn parse_slot_table_rejects_oversize_wrapped_key_len() {
        let mut buf = [0u8; OFF_SLOT_TABLE + SLOT_BYTES];
        buf[OFF_SLOT_TABLE + SLOT_OFF_TYPE] = SlotType::YubiKey as u8;
        buf[OFF_SLOT_TABLE + SLOT_OFF_CLASS] = SlotClass::Live as u8;
        let oversize = (SLOT_WRAPPED_KEY_MAX as u16) + 1;
        buf[OFF_SLOT_TABLE + SLOT_OFF_WRAPPED_LEN
            ..OFF_SLOT_TABLE + SLOT_OFF_WRAPPED_LEN + 2]
            .copy_from_slice(&oversize.to_le_bytes());
        assert_parse_slot_err(&buf, 1, HeaderError::BadWrappedKeyLen);
    }

    #[test]
    fn parse_slot_table_max_wrapped_key_len_accepted() {
        let mut buf = [0u8; OFF_SLOT_TABLE + SLOT_BYTES];
        buf[OFF_SLOT_TABLE + SLOT_OFF_TYPE] = SlotType::YubiKey as u8;
        buf[OFF_SLOT_TABLE + SLOT_OFF_CLASS] = SlotClass::Live as u8;
        let max_len = SLOT_WRAPPED_KEY_MAX as u16;
        buf[OFF_SLOT_TABLE + SLOT_OFF_WRAPPED_LEN
            ..OFF_SLOT_TABLE + SLOT_OFF_WRAPPED_LEN + 2]
            .copy_from_slice(&max_len.to_le_bytes());
        let slots = parse_slot_table(&buf, 1).expect("parse");
        assert_eq!(slots[0].as_ref().unwrap().wrapped_key_len, max_len);
    }

    #[test]
    fn find_first_live_yubikey_empty_table_returns_none() {
        let slots: [Option<SlotEntry>; MAX_VOLUME_SLOTS] = [None; MAX_VOLUME_SLOTS];
        assert!(find_first_live_yubikey(&slots).is_none());
    }

    #[test]
    fn find_first_live_yubikey_skips_recovery_and_argon2id() {
        let mut slots: [Option<SlotEntry>; MAX_VOLUME_SLOTS] = [None; MAX_VOLUME_SLOTS];
        slots[0] = Some(SlotEntry {
            slot_type: SlotType::Argon2idPassphrase,
            slot_class: SlotClass::Recovery,
            wrapped_key_len: 0,
            slot_principal: [0u8; 32],
            wrapped_key: [0u8; SLOT_WRAPPED_KEY_MAX],
        });
        slots[1] = Some(SlotEntry {
            slot_type: SlotType::YubiKey,
            slot_class: SlotClass::Recovery,
            wrapped_key_len: 0,
            slot_principal: [0xBBu8; 32],
            wrapped_key: [0u8; SLOT_WRAPPED_KEY_MAX],
        });
        slots[2] = Some(SlotEntry {
            slot_type: SlotType::YubiKey,
            slot_class: SlotClass::Live,
            wrapped_key_len: 0,
            slot_principal: [0xCCu8; 32],
            wrapped_key: [0u8; SLOT_WRAPPED_KEY_MAX],
        });
        let live = find_first_live_yubikey(&slots).expect("live yk present");
        assert_eq!(live.slot_principal, [0xCCu8; 32]);
    }

    #[test]
    fn find_first_live_yubikey_returns_first_when_multiple() {
        let mut slots: [Option<SlotEntry>; MAX_VOLUME_SLOTS] = [None; MAX_VOLUME_SLOTS];
        slots[0] = Some(SlotEntry {
            slot_type: SlotType::YubiKey,
            slot_class: SlotClass::Live,
            wrapped_key_len: 0,
            slot_principal: [0x11u8; 32],
            wrapped_key: [0u8; SLOT_WRAPPED_KEY_MAX],
        });
        slots[1] = Some(SlotEntry {
            slot_type: SlotType::YubiKey,
            slot_class: SlotClass::Live,
            wrapped_key_len: 0,
            slot_principal: [0x22u8; 32],
            wrapped_key: [0u8; SLOT_WRAPPED_KEY_MAX],
        });
        let live = find_first_live_yubikey(&slots).expect("first live yk");
        assert_eq!(live.slot_principal, [0x11u8; 32]);
    }

    #[test]
    fn is_live_yubikey_matrix() {
        let mut s = SlotEntry {
            slot_type: SlotType::YubiKey,
            slot_class: SlotClass::Live,
            wrapped_key_len: 0,
            slot_principal: [0u8; 32],
            wrapped_key: [0u8; SLOT_WRAPPED_KEY_MAX],
        };
        assert!(s.is_live_yubikey());
        s.slot_class = SlotClass::Recovery;
        assert!(!s.is_live_yubikey());
        s.slot_class = SlotClass::Live;
        s.slot_type = SlotType::Argon2idPassphrase;
        assert!(!s.is_live_yubikey());
        s.slot_type = SlotType::Empty;
        assert!(!s.is_live_yubikey());
    }

    #[test]
    fn slot_type_byte_roundtrip() {
        for st in [SlotType::Empty, SlotType::YubiKey, SlotType::Argon2idPassphrase] {
            assert_eq!(SlotType::from_byte(st as u8), Some(st));
        }
        assert_eq!(SlotType::from_byte(0x99), None);
    }

    #[test]
    fn slot_class_byte_roundtrip() {
        for sc in [SlotClass::Live, SlotClass::Recovery] {
            assert_eq!(SlotClass::from_byte(sc as u8), Some(sc));
        }
        assert_eq!(SlotClass::from_byte(0x99), None);
    }
}
