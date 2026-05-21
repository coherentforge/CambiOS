// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Block-device encryption layer — XTS-AES-256 per
//! [ADR-032](../../../../docs/adr/032-full-disk-encryption-below-substrate.md) § 2.
//!
//! [`EncryptedBlockDevice<B>`] is the substrate's view of an
//! at-rest-encrypted disk. It wraps any inner `B: BlockDevice` and
//! transparently encrypts on `write_block` / decrypts on `read_block`
//! using XTS-AES-256 with the LBA as the per-sector tweak. The
//! transform is length-preserving (4 KiB in → 4 KiB out) so substrate
//! bookkeeping (bitmap math, journal record offsets) is unchanged.
//!
//! ## Construction
//!
//! Held by the kernel's storage singleton once the volume is mounted.
//! Boot sequence per ADR-032 § Architecture:
//!
//!   1. `fde-mount` boot module unlocks the master key via PIV
//!      (stream A A-v.a).
//!   2. `SYS_INSTALL_MASTER_KEY` (A-v.d) hands the 64-byte master
//!      to the kernel; the kernel constructs
//!      `EncryptedBlockDevice<VirtioBlkDevice>` and installs it as
//!      STORAGE's data device.
//!   3. All substrate I/O flows through the wrapper from that point
//!      forward. The header region (LBA 0..=3) is read raw via
//!      `SYS_READ_VOLUME_HEADER` and is never routed through this
//!      wrapper.
//!
//! ## Cipher details (NIST SP 800-38E + IEEE 1619-2007)
//!
//! - **Master key** is 64 bytes — the concatenated `K1 || K2`. K1
//!   encrypts data; K2 generates the per-sector tweak from the LBA.
//!   Both are AES-256 keys per [ADR-032 § 2](../../../../docs/adr/032-full-disk-encryption-below-substrate.md#2-cipher-xts-aes-256-uniform-v1).
//! - **Sector size** is `BLOCK_SIZE = 4096`; each sector holds 256
//!   × 128-bit AES blocks. The tweak advances by one GF(2^128)
//!   multiplication per inner block.
//! - **Per-sector tweak** is `AES(K2, LBA as 128-bit LE)` — the LBA
//!   sits in the low 8 bytes; the high 8 bytes are zero. Standard
//!   XTS convention; identical to dm-crypt / FileVault encoding.
//! - **GF(2^128) reduction polynomial**: x^128 + x^7 + x^2 + x + 1
//!   (`0x87` after the shift). Implemented inline in
//!   [`advance_tweak`].
//!
//! ## Security caveats
//!
//! - XTS confidentiality only; **no per-block integrity**. An
//!   attacker with offline write access to the disk can flip
//!   ciphertext bits and the OS cannot detect the modification
//!   on read. This is the standard FDE integrity gap (dm-crypt,
//!   FileVault, BitLocker-without-XTS-with-diffuser have the
//!   same property). ADR-032 § 6 enumerates the threat model and
//!   per-layer mitigations (CambiObject Blake3, substrate journal
//!   MAC).
//! - **Software AES** via [`super::aes_soft`] is cache-timing-leak
//!   prone for a co-located attacker. Hardware-AES backends
//!   (AES-NI, ARMv8 Crypto Extensions) are a future cfg-gated
//!   swap; see `aes_soft` module rustdoc.
//!
//! ## Lock ordering
//!
//! `EncryptedBlockDevice` introduces **no new lock**. It holds an
//! inner `B: BlockDevice` and forwards every operation; the kernel
//! callers serialize access at the same OBJECT_STORE / POSIX_STORE
//! layer that already serializes the raw `B`. See CLAUDE.md "Lock
//! Ordering" for the surrounding context.

extern crate alloc;

use super::aes_soft::{AES_BLOCK_LEN, AES256_KEY_LEN, Aes256};
use crate::fs::block::{BLOCK_SIZE, Block, BlockDevice, BlockError};

/// HARDWARE: XTS-AES-256 master key length — `K1 || K2`, two
/// AES-256 keys per NIST SP 800-38E. Mirrors
/// `cambios_fde_proto::FDE_MASTER_KEY_LEN`; defined locally so
/// kernel code doesn't need to thread proto-crate imports.
pub const XTS_MASTER_KEY_LEN: usize = 2 * AES256_KEY_LEN;

/// HARDWARE: XTS inner-block size, fixed by AES (128 bits).
const XTS_INNER_BLOCK_LEN: usize = AES_BLOCK_LEN;

/// HARDWARE: number of 128-bit XTS inner blocks per 4 KiB sector.
/// Derived from `BLOCK_SIZE / XTS_INNER_BLOCK_LEN` = 4096 / 16 = 256.
/// Constant rather than runtime division because every encrypt /
/// decrypt loop is bounded by it (Formal Verification rule:
/// "Bounded iteration").
const XTS_BLOCKS_PER_SECTOR: usize = BLOCK_SIZE / XTS_INNER_BLOCK_LEN;

// Static check: confirm BLOCK_SIZE divides evenly.
const _: () = assert!(BLOCK_SIZE % XTS_INNER_BLOCK_LEN == 0);
const _: () = assert!(XTS_BLOCKS_PER_SECTOR == 256);

/// XTS-AES-256 cipher state — the two AES-256 instances K1 (data)
/// and K2 (tweak) per NIST SP 800-38E.
///
/// Construction splits the 64-byte master into `master[..32]` =
/// K1, `master[32..]` = K2 directly with no KDF derivation (the
/// master IS the cipher keying; see ADR-032 § Divergence
/// 2026-05-20 for the rationale and the 32-byte interim spec this
/// replaces).
pub struct XtsAes256 {
    k1: Aes256,
    k2: Aes256,
}

impl XtsAes256 {
    /// Build a fresh XTS-AES-256 cipher from a 64-byte master key.
    ///
    /// The master is `K1 || K2`; K1 (master[..32]) encrypts data,
    /// K2 (master[32..]) generates per-sector tweaks. NIST
    /// SP 800-38E § 5.1 requires K1 ≠ K2 — caller is responsible
    /// for ensuring this property (in practice, a 64-byte random
    /// master will have distinct halves with probability ~1).
    pub fn new(master: &[u8; XTS_MASTER_KEY_LEN]) -> Self {
        let mut k1_bytes = [0u8; AES256_KEY_LEN];
        let mut k2_bytes = [0u8; AES256_KEY_LEN];
        k1_bytes.copy_from_slice(&master[..AES256_KEY_LEN]);
        k2_bytes.copy_from_slice(&master[AES256_KEY_LEN..]);
        Self {
            k1: Aes256::new(&k1_bytes),
            k2: Aes256::new(&k2_bytes),
        }
    }

    /// Encrypt one full sector in place. `lba` is the data-unit
    /// sequence number used as the XTS tweak per NIST SP 800-38E
    /// § 5.3. Sector size is fixed at [`BLOCK_SIZE`] (4 KiB).
    pub fn encrypt_sector(&self, sector: &mut Block, lba: u64) {
        // Compute initial tweak T_0 = AES_K2(LBA as 128-bit LE).
        let mut tweak = initial_tweak_bytes(lba);
        self.k2.encrypt_block(&mut tweak);

        for chunk in sector.chunks_exact_mut(XTS_INNER_BLOCK_LEN) {
            let block: &mut [u8; XTS_INNER_BLOCK_LEN] = chunk
                .try_into()
                .expect("chunks_exact_mut yields XTS_INNER_BLOCK_LEN slices");

            // C_j = AES_K1(P_j XOR T_j) XOR T_j
            xts_xor_inplace(&mut *block, &tweak);
            self.k1.encrypt_block(&mut *block);
            xts_xor_inplace(&mut *block, &tweak);

            // T_(j+1) = T_j * alpha mod (x^128 + x^7 + x^2 + x + 1)
            advance_tweak(&mut tweak);
        }
    }

    /// Decrypt one full sector in place. Inverse of
    /// [`encrypt_sector`]. The tweak stream is identical to
    /// encryption (it only depends on `lba` + K2); only the inner
    /// AES operation is inverted.
    pub fn decrypt_sector(&self, sector: &mut Block, lba: u64) {
        let mut tweak = initial_tweak_bytes(lba);
        self.k2.encrypt_block(&mut tweak);

        for chunk in sector.chunks_exact_mut(XTS_INNER_BLOCK_LEN) {
            let block: &mut [u8; XTS_INNER_BLOCK_LEN] = chunk
                .try_into()
                .expect("chunks_exact_mut yields XTS_INNER_BLOCK_LEN slices");

            // P_j = AES_K1^(-1)(C_j XOR T_j) XOR T_j
            xts_xor_inplace(&mut *block, &tweak);
            self.k1.decrypt_block(&mut *block);
            xts_xor_inplace(&mut *block, &tweak);

            advance_tweak(&mut tweak);
        }
    }
}

/// Encode the LBA as a 128-bit little-endian value — low 8 bytes
/// = LBA, high 8 bytes = 0. The K2 encryption of this value
/// produces the per-sector initial tweak T_0.
#[inline(always)]
fn initial_tweak_bytes(lba: u64) -> [u8; XTS_INNER_BLOCK_LEN] {
    let mut bytes = [0u8; XTS_INNER_BLOCK_LEN];
    bytes[..8].copy_from_slice(&lba.to_le_bytes());
    bytes
}

/// 16-byte in-place XOR. Hot path on the data side; keep
/// `#[inline(always)]` so loops in `encrypt_sector` / `decrypt_sector`
/// don't pay a function-call boundary per inner block.
#[inline(always)]
fn xts_xor_inplace(dst: &mut [u8; XTS_INNER_BLOCK_LEN], src: &[u8; XTS_INNER_BLOCK_LEN]) {
    for i in 0..XTS_INNER_BLOCK_LEN {
        dst[i] ^= src[i];
    }
}

/// GF(2^128) multiplication by α (the primitive element `x`) —
/// shift left by 1 bit, with reduction by `x^128 + x^7 + x^2 + x + 1`
/// when the high bit was set. Standard XTS tweak advance per
/// IEEE 1619-2007 § 5.2.
///
/// Byte layout: tweak is stored as 16 LE bytes; bit 0 of byte 0 is
/// the LSB, bit 7 of byte 15 is the MSB.
#[inline(always)]
fn advance_tweak(t: &mut [u8; XTS_INNER_BLOCK_LEN]) {
    let high_bit_was_set = (t[XTS_INNER_BLOCK_LEN - 1] >> 7) & 1;

    // Shift left by 1, carrying from each byte's high bit into the
    // next byte's low bit.
    for i in (1..XTS_INNER_BLOCK_LEN).rev() {
        t[i] = (t[i] << 1) | (t[i - 1] >> 7);
    }
    t[0] <<= 1;

    if high_bit_was_set != 0 {
        // x^128 ≡ x^7 + x^2 + x + 1 (mod the AES reduction poly)
        // = 0x87 in our LE byte 0.
        t[0] ^= 0x87;
    }
}

// ============================================================================
// EncryptedBlockDevice<B> — transparent BlockDevice wrapper
// ============================================================================

/// Transparent encryption wrapper for any [`BlockDevice`].
///
/// Reads decrypt; writes encrypt. The wrapper is length-preserving
/// (`capacity_blocks` and the per-block byte count are unchanged
/// from the inner device).
///
/// Substrate-visible behavior is identical to an unencrypted
/// `BlockDevice`; the only operational difference is the latency
/// cost of XTS-AES per I/O. With software AES on x86_64-unknown-none
/// today, that cost is ~10-20× hardware AES — acceptable for v1
/// since the data path is virtio-blk over IPC and the IPC + virtqueue
/// overheads dominate. Per-arch hardware-AES swap is future work
/// (see [`super::aes_soft`] rustdoc).
pub struct EncryptedBlockDevice<B: BlockDevice> {
    inner: B,
    cipher: XtsAes256,
}

impl<B: BlockDevice> EncryptedBlockDevice<B> {
    /// Wrap `inner` with XTS-AES-256 using `master_key` as `K1 || K2`.
    ///
    /// The caller retains responsibility for `master_key` zeroize on
    /// drop; this constructor materializes the AES round-key
    /// schedules and the original 64 bytes can be zeroed by the
    /// caller after this call returns. The expanded schedules inside
    /// `cipher` live for the lifetime of `self`.
    pub fn new(inner: B, master_key: &[u8; XTS_MASTER_KEY_LEN]) -> Self {
        Self {
            inner,
            cipher: XtsAes256::new(master_key),
        }
    }

    /// Borrow the underlying `BlockDevice`. Useful for diagnostics
    /// (capacity inspection, flush-state queries) where the
    /// encrypted layer is transparent.
    pub fn inner(&self) -> &B {
        &self.inner
    }
}

impl<B: BlockDevice> BlockDevice for EncryptedBlockDevice<B> {
    fn capacity_blocks(&self) -> u64 {
        self.inner.capacity_blocks()
    }

    fn read_block(&mut self, lba: u64, buf: &mut Block) -> Result<(), BlockError> {
        self.inner.read_block(lba, buf)?;
        // Buf now holds ciphertext. Decrypt in place.
        self.cipher.decrypt_sector(buf, lba);
        Ok(())
    }

    fn write_block(&mut self, lba: u64, buf: &Block) -> Result<(), BlockError> {
        // Caller's plaintext is `&Block` (immutable); we need a
        // local scratch sector for the ciphertext to hand to inner.
        // Kernel boot stack is 256 KiB; 4 KiB scratch per call is
        // well within budget.
        let mut scratch: Block = *buf;
        self.cipher.encrypt_sector(&mut scratch, lba);
        self.inner.write_block(lba, &scratch)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.inner.flush()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::block::MemBlockDevice;

    // --- XTS primitive ---

    fn master_key_pattern() -> [u8; XTS_MASTER_KEY_LEN] {
        // Non-trivial 64-byte master: each half (K1, K2) is
        // distinct, and neither is all-zero or repeating-byte
        // (catches index-off-by-one bugs that uniform keys would
        // mask).
        let mut master = [0u8; XTS_MASTER_KEY_LEN];
        for (i, b) in master.iter_mut().enumerate() {
            *b = (((i * 17) ^ 0xa5).wrapping_add(if i >= 32 { 0x40 } else { 0 })) as u8;
        }
        master
    }

    fn plaintext_pattern() -> Block {
        let mut pt = [0u8; BLOCK_SIZE];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = ((i * 13) ^ 0x3c) as u8;
        }
        pt
    }

    #[test]
    fn encrypt_decrypt_sector_roundtrip() {
        let cipher = XtsAes256::new(&master_key_pattern());
        let original = plaintext_pattern();
        let mut sector = original;

        cipher.encrypt_sector(&mut sector, 42);
        // Sanity: ciphertext differs from plaintext.
        assert_ne!(sector, original, "encrypted sector matches plaintext");

        cipher.decrypt_sector(&mut sector, 42);
        assert_eq!(sector, original, "decrypt did not invert encrypt");
    }

    #[test]
    fn distinct_lbas_produce_distinct_ciphertext() {
        // XTS's defining property: the same plaintext at different
        // LBAs encrypts to different ciphertext (because the tweak
        // depends on LBA). If this fails, the tweak isn't being
        // mixed in correctly.
        let cipher = XtsAes256::new(&master_key_pattern());
        let plaintext = plaintext_pattern();

        let mut sector_lba_0 = plaintext;
        let mut sector_lba_1 = plaintext;
        let mut sector_lba_high = plaintext;

        cipher.encrypt_sector(&mut sector_lba_0, 0);
        cipher.encrypt_sector(&mut sector_lba_1, 1);
        cipher.encrypt_sector(&mut sector_lba_high, 0x1234_5678_9abc_def0);

        assert_ne!(sector_lba_0, sector_lba_1, "LBA 0 == LBA 1 ciphertext");
        assert_ne!(sector_lba_0, sector_lba_high, "LBA 0 == LBA high ciphertext");
        assert_ne!(sector_lba_1, sector_lba_high, "LBA 1 == LBA high ciphertext");
    }

    #[test]
    fn distinct_keys_produce_distinct_ciphertext() {
        let plaintext = plaintext_pattern();
        let mut master_a = [0xaau8; XTS_MASTER_KEY_LEN];
        let mut master_b = [0xbbu8; XTS_MASTER_KEY_LEN];
        // Differentiate halves so K1 ≠ K2 internally.
        master_a[AES256_KEY_LEN] = 0xa1;
        master_b[AES256_KEY_LEN] = 0xb1;

        let cipher_a = XtsAes256::new(&master_a);
        let cipher_b = XtsAes256::new(&master_b);

        let mut sector_a = plaintext;
        let mut sector_b = plaintext;
        cipher_a.encrypt_sector(&mut sector_a, 0);
        cipher_b.encrypt_sector(&mut sector_b, 0);

        assert_ne!(sector_a, sector_b);
    }

    #[test]
    fn length_preserving_4096_in_4096_out() {
        let cipher = XtsAes256::new(&master_key_pattern());
        let mut sector = plaintext_pattern();
        cipher.encrypt_sector(&mut sector, 0);
        assert_eq!(sector.len(), BLOCK_SIZE);
    }

    // --- advance_tweak (GF(2^128) multiply by α) ---

    #[test]
    fn advance_tweak_no_overflow() {
        // T = [0x01, 0, ..., 0] → shift left → [0x02, 0, ..., 0]
        let mut t = [0u8; XTS_INNER_BLOCK_LEN];
        t[0] = 0x01;
        advance_tweak(&mut t);
        let mut expected = [0u8; XTS_INNER_BLOCK_LEN];
        expected[0] = 0x02;
        assert_eq!(t, expected);
    }

    #[test]
    fn advance_tweak_carry_between_bytes() {
        // T = [0x80, 0, ..., 0] → shift left → [0x00, 0x01, 0, ..., 0]
        // (the high bit of byte 0 carries into bit 0 of byte 1).
        let mut t = [0u8; XTS_INNER_BLOCK_LEN];
        t[0] = 0x80;
        advance_tweak(&mut t);
        let mut expected = [0u8; XTS_INNER_BLOCK_LEN];
        expected[1] = 0x01;
        assert_eq!(t, expected);
    }

    #[test]
    fn advance_tweak_reduction_on_high_bit() {
        // T = [0, 0, ..., 0x80] (bit 127 set) → shift left would
        // overflow into bit 128; the reduction XORs 0x87 into byte 0.
        // Result: [0x87, 0, ..., 0].
        let mut t = [0u8; XTS_INNER_BLOCK_LEN];
        t[XTS_INNER_BLOCK_LEN - 1] = 0x80;
        advance_tweak(&mut t);
        let mut expected = [0u8; XTS_INNER_BLOCK_LEN];
        expected[0] = 0x87;
        assert_eq!(t, expected);
    }

    #[test]
    fn advance_tweak_all_ones_reduction() {
        // T = all-ones (every bit set). Shift left → all-but-bit-0
        // shifted in; high-bit-was-set so reduction XORs 0x87.
        //
        // Sequence: original bit pattern is 0xff repeated.
        // After shift: byte 0 = 0xfe (low bit cleared since no
        // input bit fed in); bytes 1..15 = 0xff (because every byte
        // is shifted left + carries the high bit of the previous,
        // both of which are 1 → high carry, then OR with 1 = 0xff).
        // Wait — byte 0 was 0xff, shifts to 0xfe; high bit was 1
        // so reduction XORs 0x87 → byte 0 = 0xfe XOR 0x87 = 0x79.
        let mut t = [0xffu8; XTS_INNER_BLOCK_LEN];
        advance_tweak(&mut t);
        assert_eq!(t[0], 0x79, "byte 0 after shift+reduce of all-ones");
        // Bytes 1..15: each was 0xff, becomes (0xff << 1) | (0xff >> 7)
        // = 0xfe | 0x01 = 0xff.
        for i in 1..XTS_INNER_BLOCK_LEN {
            assert_eq!(t[i], 0xff, "byte {i} should stay 0xff after shift+carry");
        }
    }

    // --- EncryptedBlockDevice<MemBlockDevice> integration ---

    #[test]
    fn encrypted_device_roundtrip_via_mem() {
        // Write plaintext through the encrypted layer; read it
        // back; verify it matches the original. The on-disk bytes
        // in the underlying MemBlockDevice should NOT match the
        // plaintext (i.e., encryption actually happened).
        let mem = MemBlockDevice::new(16);
        let mut dev = EncryptedBlockDevice::new(mem, &master_key_pattern());

        let plaintext = plaintext_pattern();
        let lba = 7u64;

        dev.write_block(lba, &plaintext).unwrap();

        // Verify what's actually on disk is not the plaintext.
        let mut raw_from_inner = [0u8; BLOCK_SIZE];
        dev.inner.read_block(lba, &mut raw_from_inner).unwrap();
        assert_ne!(
            raw_from_inner, plaintext,
            "inner device holds plaintext — encryption didn't happen",
        );

        // Read through the encrypted layer — should decrypt back
        // to the original plaintext.
        let mut read_back = [0u8; BLOCK_SIZE];
        dev.read_block(lba, &mut read_back).unwrap();
        assert_eq!(read_back, plaintext, "decrypt-on-read didn't recover plaintext");
    }

    #[test]
    fn encrypted_device_distinct_lbas_have_distinct_ciphertext_on_disk() {
        let mem = MemBlockDevice::new(16);
        let mut dev = EncryptedBlockDevice::new(mem, &master_key_pattern());

        let plaintext = plaintext_pattern();
        dev.write_block(3, &plaintext).unwrap();
        dev.write_block(4, &plaintext).unwrap();

        let mut raw_3 = [0u8; BLOCK_SIZE];
        let mut raw_4 = [0u8; BLOCK_SIZE];
        dev.inner.read_block(3, &mut raw_3).unwrap();
        dev.inner.read_block(4, &mut raw_4).unwrap();
        assert_ne!(
            raw_3, raw_4,
            "same plaintext at different LBAs produced identical ciphertext",
        );
    }

    #[test]
    fn encrypted_device_preserves_capacity() {
        let cap = 128u64;
        let mem = MemBlockDevice::new(cap);
        let dev = EncryptedBlockDevice::new(mem, &master_key_pattern());
        assert_eq!(dev.capacity_blocks(), cap);
    }

    #[test]
    fn encrypted_device_flush_delegates() {
        let mem = MemBlockDevice::new(4);
        let mut dev = EncryptedBlockDevice::new(mem, &master_key_pattern());
        assert_eq!(dev.flush(), Ok(()));
    }

    #[test]
    fn encrypted_device_rejects_out_of_bounds_lba() {
        let mem = MemBlockDevice::new(4);
        let mut dev = EncryptedBlockDevice::new(mem, &master_key_pattern());
        let plaintext = plaintext_pattern();
        // Inner MemBlockDevice has 4 blocks; LBA 4 is out of bounds.
        assert_eq!(
            dev.write_block(4, &plaintext),
            Err(BlockError::OutOfBounds),
        );
        let mut buf = [0u8; BLOCK_SIZE];
        assert_eq!(dev.read_block(4, &mut buf), Err(BlockError::OutOfBounds));
    }

    /// Self-vector regression fingerprint.
    ///
    /// Locks in a Blake3 fingerprint of the ciphertext produced for
    /// a fixed (master, LBA, plaintext) triple. Catches accidental
    /// impl drift across commits.
    ///
    /// External cross-check via IEEE 1619-2007 Annex B vectors is
    /// the eventual goal:
    /// Replace when: `make run` boots end-to-end under
    /// `--features dev-piv` and fde-mount logs successful decrypt
    /// of a real disk's data extent — the full chain (format-volume
    /// writes ciphertext at LBA k under the same master, fde-mount
    /// unwraps it, kernel mounts the EncryptedBlockDevice with that
    /// master) uses this same XTS-AES-256 impl; an end-to-end boot
    /// is the load-bearing observational ground truth. At that
    /// point this regression fingerprint can be replaced with the
    /// matching IEEE 1619 vector.
    #[test]
    fn self_vector_blake3_fingerprint_stable() {
        let cipher = XtsAes256::new(&master_key_pattern());
        let mut sector = plaintext_pattern();
        cipher.encrypt_sector(&mut sector, 0xdeadbeef);

        let fp = blake3::hash(&sector);
        let fp_bytes: [u8; 32] = *fp.as_bytes();

        // First 8 bytes of the fingerprint — locking in current
        // impl as the regression baseline. If this test starts
        // failing on a future commit, either (a) the cipher impl
        // changed (regression — investigate) or (b) the
        // fingerprint was intentionally updated alongside the
        // change (rotate the constant).
        let actual_prefix: [u8; 8] = [
            fp_bytes[0], fp_bytes[1], fp_bytes[2], fp_bytes[3],
            fp_bytes[4], fp_bytes[5], fp_bytes[6], fp_bytes[7],
        ];

        // This constant is whatever our impl currently produces —
        // a stake in the ground, refreshed when external
        // validation lands.
        let recorded_prefix: [u8; 8] = SELF_VECTOR_FP_PREFIX;
        assert_eq!(
            actual_prefix, recorded_prefix,
            "XTS self-vector fingerprint changed — \
             investigate cipher impl drift",
        );
    }

    /// HARDWARE: Blake3 fingerprint prefix of our XTS-AES-256 impl's
    /// output for the locked (master_key_pattern, LBA=0xdeadbeef,
    /// plaintext_pattern) triple. Acts as a self-vector regression
    /// fingerprint; replaced on intentional impl change, otherwise
    /// stable.
    const SELF_VECTOR_FP_PREFIX: [u8; 8] = SELF_VECTOR_FP_PREFIX_VALUE;

    // Captured 2026-05-21 from the impl as initially landed.
    // Cross-validation against IEEE 1619-2007 Annex B vectors
    // deferred per the Convention 9 trigger on
    // `self_vector_blake3_fingerprint_stable` rustdoc.
    const SELF_VECTOR_FP_PREFIX_VALUE: [u8; 8] =
        [0x56, 0x92, 0xf1, 0x13, 0x36, 0xe0, 0x02, 0xe5];
}
