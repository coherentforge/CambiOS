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
        self.encrypt_data_unit(sector, initial_tweak_bytes(lba));
    }

    /// Decrypt one full sector in place. Inverse of
    /// [`encrypt_sector`]. The tweak stream is identical to
    /// encryption (it only depends on `lba` + K2); only the inner
    /// AES operation is inverted.
    pub fn decrypt_sector(&self, sector: &mut Block, lba: u64) {
        self.decrypt_data_unit(sector, initial_tweak_bytes(lba));
    }

    /// Encrypt a single XTS data unit of arbitrary size in place,
    /// taking the raw 16-byte tweak directly per NIST SP 800-38E
    /// § 5.3.1 (`i` parameter). Buffer length must be a non-zero
    /// multiple of [`XTS_INNER_BLOCK_LEN`] (16). Used by the
    /// substrate's [`encrypt_sector`] (with `tweak =
    /// initial_tweak_bytes(lba)`) and by NIST CAVP KAT tests
    /// (with arbitrary tweaks and data-unit sizes from the
    /// XTSGenAES256 vector set).
    ///
    /// Panics if `buf.len()` is zero or not a multiple of 16 —
    /// callers above the substrate already guarantee whole-block
    /// sizes; the panic is a development-time assertion, not a
    /// runtime check on attacker-controlled input.
    pub fn encrypt_data_unit(&self, buf: &mut [u8], tweak: [u8; XTS_INNER_BLOCK_LEN]) {
        assert!(
            !buf.is_empty() && buf.len() % XTS_INNER_BLOCK_LEN == 0,
            "XTS data-unit length must be a non-zero multiple of AES block size"
        );

        // Compute initial tweak T_0 = AES_K2(tweak).
        let mut t = tweak;
        self.k2.encrypt_block(&mut t);

        for chunk in buf.chunks_exact_mut(XTS_INNER_BLOCK_LEN) {
            let block: &mut [u8; XTS_INNER_BLOCK_LEN] = chunk
                .try_into()
                .expect("chunks_exact_mut yields XTS_INNER_BLOCK_LEN slices");

            // C_j = AES_K1(P_j XOR T_j) XOR T_j
            xts_xor_inplace(&mut *block, &t);
            self.k1.encrypt_block(&mut *block);
            xts_xor_inplace(&mut *block, &t);

            // T_(j+1) = T_j * alpha mod (x^128 + x^7 + x^2 + x + 1)
            advance_tweak(&mut t);
        }
    }

    /// Decrypt a single XTS data unit of arbitrary size in place.
    /// Inverse of [`encrypt_data_unit`]; same shape, K1 inverse
    /// applied in place of K1 forward.
    pub fn decrypt_data_unit(&self, buf: &mut [u8], tweak: [u8; XTS_INNER_BLOCK_LEN]) {
        assert!(
            !buf.is_empty() && buf.len() % XTS_INNER_BLOCK_LEN == 0,
            "XTS data-unit length must be a non-zero multiple of AES block size"
        );

        let mut t = tweak;
        self.k2.encrypt_block(&mut t);

        for chunk in buf.chunks_exact_mut(XTS_INNER_BLOCK_LEN) {
            let block: &mut [u8; XTS_INNER_BLOCK_LEN] = chunk
                .try_into()
                .expect("chunks_exact_mut yields XTS_INNER_BLOCK_LEN slices");

            // P_j = AES_K1^(-1)(C_j XOR T_j) XOR T_j
            xts_xor_inplace(&mut *block, &t);
            self.k1.decrypt_block(&mut *block);
            xts_xor_inplace(&mut *block, &t);

            advance_tweak(&mut t);
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

    // ----------------------------------------------------------------
    // NIST CAVP XTSGenAES256 Known-Answer Tests
    // ----------------------------------------------------------------
    //
    // Source: NIST CAVP XTSTestVectors archive, file XTSGenAES256.rsp.
    // CAVS 11.0, generated 2011-03-01. Same numerical vectors that
    // every FIPS-validated XTS-AES-256 implementation tests against
    // (a re-publication of IEEE Std 1619-2007 Annex B; the vectors
    // are deterministic outputs of the math and not copyrightable).
    //
    // CAVP wire format → our API mapping:
    //   `Key`           (128 hex chars = 64 bytes) → master = K1 || K2
    //   `i`             (32 hex chars = 16 bytes)  → tweak: [u8; 16]
    //   `DataUnitLen`   (256 bits)                  → buf.len() = 32
    //   `PT` / `CT`     (64 hex chars = 32 bytes)   → plaintext / expected ciphertext
    //
    // Two vectors covered: COUNT=1 and COUNT=2, each tested in both
    // encrypt and decrypt direction (four total assertions per vector
    // beyond the obvious roundtrip).

    /// NIST CAVS 11.0 XTSGen AES-256, COUNT = 1, DataUnitLen = 256 bits.
    const CAVP_C1_MASTER: [u8; XTS_MASTER_KEY_LEN] = [
        // K1: 1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7c
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e,
        0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47, 0x14,
        0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7,
        0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a, 0x0e, 0x7c,
        // K2: d6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08
        0xd6, 0xe1, 0x3f, 0xfd, 0xf2, 0x41, 0x8d, 0x8d,
        0x19, 0x11, 0xc0, 0x04, 0xcd, 0xa5, 0x8d, 0xa3,
        0xd6, 0x19, 0xb7, 0xe2, 0xb9, 0x14, 0x1e, 0x58,
        0x31, 0x8e, 0xea, 0x39, 0x2c, 0xf4, 0x1b, 0x08,
    ];
    /// CAVP COUNT=1 `i`: adf8d92627464ad2f0428e84a9f87564
    const CAVP_C1_TWEAK: [u8; XTS_INNER_BLOCK_LEN] = [
        0xad, 0xf8, 0xd9, 0x26, 0x27, 0x46, 0x4a, 0xd2,
        0xf0, 0x42, 0x8e, 0x84, 0xa9, 0xf8, 0x75, 0x64,
    ];
    /// CAVP COUNT=1 `PT`: 2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e
    const CAVP_C1_PT: [u8; 32] = [
        0x2e, 0xed, 0xea, 0x52, 0xcd, 0x82, 0x15, 0xe1,
        0xac, 0xc6, 0x47, 0xe8, 0x10, 0xbb, 0xc3, 0x64,
        0x2e, 0x87, 0x28, 0x7f, 0x8d, 0x2e, 0x57, 0xe3,
        0x6c, 0x0a, 0x24, 0xfb, 0xc1, 0x2a, 0x20, 0x2e,
    ];
    /// CAVP COUNT=1 `CT`: cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db
    const CAVP_C1_CT: [u8; 32] = [
        0xcb, 0xaa, 0xd0, 0xe2, 0xf6, 0xce, 0xa3, 0xf5,
        0x0b, 0x37, 0xf9, 0x34, 0xd4, 0x6a, 0x9b, 0x13,
        0x0b, 0x9d, 0x54, 0xf0, 0x7e, 0x34, 0xf3, 0x6a,
        0xf7, 0x93, 0xe8, 0x6f, 0x73, 0xc6, 0xd7, 0xdb,
    ];

    /// NIST CAVS 11.0 XTSGen AES-256, COUNT = 2, DataUnitLen = 256 bits.
    const CAVP_C2_MASTER: [u8; XTS_MASTER_KEY_LEN] = [
        // K1: e149be00177d76b7c1d85bcbb6b5054ee10b9f51cd73f59e0840628b9e7d854e
        0xe1, 0x49, 0xbe, 0x00, 0x17, 0x7d, 0x76, 0xb7,
        0xc1, 0xd8, 0x5b, 0xcb, 0xb6, 0xb5, 0x05, 0x4e,
        0xe1, 0x0b, 0x9f, 0x51, 0xcd, 0x73, 0xf5, 0x9e,
        0x08, 0x40, 0x62, 0x8b, 0x9e, 0x7d, 0x85, 0x4e,
        // K2: 2e1c0ab0537186a2a7c314bbc5eb23b6876a26bcdbf9e6b758d1cae053c2f278
        0x2e, 0x1c, 0x0a, 0xb0, 0x53, 0x71, 0x86, 0xa2,
        0xa7, 0xc3, 0x14, 0xbb, 0xc5, 0xeb, 0x23, 0xb6,
        0x87, 0x6a, 0x26, 0xbc, 0xdb, 0xf9, 0xe6, 0xb7,
        0x58, 0xd1, 0xca, 0xe0, 0x53, 0xc2, 0xf2, 0x78,
    ];
    /// CAVP COUNT=2 `i`: 0ea18818fab95289b1caab4e61349501
    const CAVP_C2_TWEAK: [u8; XTS_INNER_BLOCK_LEN] = [
        0x0e, 0xa1, 0x88, 0x18, 0xfa, 0xb9, 0x52, 0x89,
        0xb1, 0xca, 0xab, 0x4e, 0x61, 0x34, 0x95, 0x01,
    ];
    /// CAVP COUNT=2 `PT`: f5f101d8e3a7681b1ddb21bd2826b24e32990bca49b39291b5369a9bca277d75
    const CAVP_C2_PT: [u8; 32] = [
        0xf5, 0xf1, 0x01, 0xd8, 0xe3, 0xa7, 0x68, 0x1b,
        0x1d, 0xdb, 0x21, 0xbd, 0x28, 0x26, 0xb2, 0x4e,
        0x32, 0x99, 0x0b, 0xca, 0x49, 0xb3, 0x92, 0x91,
        0xb5, 0x36, 0x9a, 0x9b, 0xca, 0x27, 0x7d, 0x75,
    ];
    /// CAVP COUNT=2 `CT`: 5bf2479393cc673306fbb15e72600598e33d4d8a470727ce098730fd80afa959
    const CAVP_C2_CT: [u8; 32] = [
        0x5b, 0xf2, 0x47, 0x93, 0x93, 0xcc, 0x67, 0x33,
        0x06, 0xfb, 0xb1, 0x5e, 0x72, 0x60, 0x05, 0x98,
        0xe3, 0x3d, 0x4d, 0x8a, 0x47, 0x07, 0x27, 0xce,
        0x09, 0x87, 0x30, 0xfd, 0x80, 0xaf, 0xa9, 0x59,
    ];

    #[test]
    fn nist_cavp_xtsgen_aes256_count1_encrypt() {
        let cipher = XtsAes256::new(&CAVP_C1_MASTER);
        let mut buf = CAVP_C1_PT;
        cipher.encrypt_data_unit(&mut buf, CAVP_C1_TWEAK);
        assert_eq!(buf, CAVP_C1_CT, "NIST CAVP XTSGenAES256 COUNT=1 encrypt mismatch");
    }

    #[test]
    fn nist_cavp_xtsgen_aes256_count1_decrypt() {
        let cipher = XtsAes256::new(&CAVP_C1_MASTER);
        let mut buf = CAVP_C1_CT;
        cipher.decrypt_data_unit(&mut buf, CAVP_C1_TWEAK);
        assert_eq!(buf, CAVP_C1_PT, "NIST CAVP XTSGenAES256 COUNT=1 decrypt mismatch");
    }

    #[test]
    fn nist_cavp_xtsgen_aes256_count2_encrypt() {
        let cipher = XtsAes256::new(&CAVP_C2_MASTER);
        let mut buf = CAVP_C2_PT;
        cipher.encrypt_data_unit(&mut buf, CAVP_C2_TWEAK);
        assert_eq!(buf, CAVP_C2_CT, "NIST CAVP XTSGenAES256 COUNT=2 encrypt mismatch");
    }

    #[test]
    fn nist_cavp_xtsgen_aes256_count2_decrypt() {
        let cipher = XtsAes256::new(&CAVP_C2_MASTER);
        let mut buf = CAVP_C2_CT;
        cipher.decrypt_data_unit(&mut buf, CAVP_C2_TWEAK);
        assert_eq!(buf, CAVP_C2_PT, "NIST CAVP XTSGenAES256 COUNT=2 decrypt mismatch");
    }

    /// NIST CAVS 11.0 XTSGen AES-256, COUNT = 499, DataUnitLen = 384 bits.
    /// Listed in the .rsp file's [DECRYPT] section — same math, just
    /// NIST's documentation convention. 48-byte data unit = 3 inner
    /// blocks, exercising two advance_tweak transitions per direction.
    const CAVP_C499_MASTER: [u8; XTS_MASTER_KEY_LEN] = [
        // K1: 22a0a371842832d8706388e94533f3df997d749f48503a1ad38dad9791ce14fe
        0x22, 0xa0, 0xa3, 0x71, 0x84, 0x28, 0x32, 0xd8,
        0x70, 0x63, 0x88, 0xe9, 0x45, 0x33, 0xf3, 0xdf,
        0x99, 0x7d, 0x74, 0x9f, 0x48, 0x50, 0x3a, 0x1a,
        0xd3, 0x8d, 0xad, 0x97, 0x91, 0xce, 0x14, 0xfe,
        // K2: 9ccaa3f3ab5c7546fd019bdf997cb3abd6cb22edece35349237ebe289708ce9d
        0x9c, 0xca, 0xa3, 0xf3, 0xab, 0x5c, 0x75, 0x46,
        0xfd, 0x01, 0x9b, 0xdf, 0x99, 0x7c, 0xb3, 0xab,
        0xd6, 0xcb, 0x22, 0xed, 0xec, 0xe3, 0x53, 0x49,
        0x23, 0x7e, 0xbe, 0x28, 0x97, 0x08, 0xce, 0x9d,
    ];
    /// CAVP COUNT=499 `i`: 01d23862799e6295c0041bbaec5109a7
    const CAVP_C499_TWEAK: [u8; XTS_INNER_BLOCK_LEN] = [
        0x01, 0xd2, 0x38, 0x62, 0x79, 0x9e, 0x62, 0x95,
        0xc0, 0x04, 0x1b, 0xba, 0xec, 0x51, 0x09, 0xa7,
    ];
    /// CAVP COUNT=499 `PT`: 6169b219ca37a2f7ccd2d8581d621d3c1bff888dac080364f2b9c702d01a9574b55bc4f045bfa04d1851e58c21ea7f55
    const CAVP_C499_PT: [u8; 48] = [
        0x61, 0x69, 0xb2, 0x19, 0xca, 0x37, 0xa2, 0xf7,
        0xcc, 0xd2, 0xd8, 0x58, 0x1d, 0x62, 0x1d, 0x3c,
        0x1b, 0xff, 0x88, 0x8d, 0xac, 0x08, 0x03, 0x64,
        0xf2, 0xb9, 0xc7, 0x02, 0xd0, 0x1a, 0x95, 0x74,
        0xb5, 0x5b, 0xc4, 0xf0, 0x45, 0xbf, 0xa0, 0x4d,
        0x18, 0x51, 0xe5, 0x8c, 0x21, 0xea, 0x7f, 0x55,
    ];
    /// CAVP COUNT=499 `CT`: 0e2b93cc892b22b5dbba9d32f50aeafe9de0ee66dffccaa6063679be69dd606c7d71a446333f9e5c36755896f4d8e16f
    const CAVP_C499_CT: [u8; 48] = [
        0x0e, 0x2b, 0x93, 0xcc, 0x89, 0x2b, 0x22, 0xb5,
        0xdb, 0xba, 0x9d, 0x32, 0xf5, 0x0a, 0xea, 0xfe,
        0x9d, 0xe0, 0xee, 0x66, 0xdf, 0xfc, 0xca, 0xa6,
        0x06, 0x36, 0x79, 0xbe, 0x69, 0xdd, 0x60, 0x6c,
        0x7d, 0x71, 0xa4, 0x46, 0x33, 0x3f, 0x9e, 0x5c,
        0x36, 0x75, 0x58, 0x96, 0xf4, 0xd8, 0xe1, 0x6f,
    ];

    /// NIST CAVS 11.0 XTSGen AES-256, COUNT = 500, DataUnitLen = 384 bits.
    const CAVP_C500_MASTER: [u8; XTS_MASTER_KEY_LEN] = [
        // K1: 88dfd7c83cb121968feb417520555b36c0f63b662570eac12ea96cbe188ad5b1
        0x88, 0xdf, 0xd7, 0xc8, 0x3c, 0xb1, 0x21, 0x96,
        0x8f, 0xeb, 0x41, 0x75, 0x20, 0x55, 0x5b, 0x36,
        0xc0, 0xf6, 0x3b, 0x66, 0x25, 0x70, 0xea, 0xc1,
        0x2e, 0xa9, 0x6c, 0xbe, 0x18, 0x8a, 0xd5, 0xb1,
        // K2: a44db23ac6470316cba0041cadf248f6d9a7713f454e663f3e3987585cebbf96
        0xa4, 0x4d, 0xb2, 0x3a, 0xc6, 0x47, 0x03, 0x16,
        0xcb, 0xa0, 0x04, 0x1c, 0xad, 0xf2, 0x48, 0xf6,
        0xd9, 0xa7, 0x71, 0x3f, 0x45, 0x4e, 0x66, 0x3f,
        0x3e, 0x39, 0x87, 0x58, 0x5c, 0xeb, 0xbf, 0x96,
    ];
    /// CAVP COUNT=500 `i`: 0ee84632b838dd528f1d96c76439805c
    const CAVP_C500_TWEAK: [u8; XTS_INNER_BLOCK_LEN] = [
        0x0e, 0xe8, 0x46, 0x32, 0xb8, 0x38, 0xdd, 0x52,
        0x8f, 0x1d, 0x96, 0xc7, 0x64, 0x39, 0x80, 0x5c,
    ];
    /// CAVP COUNT=500 `PT`: ec36551c70efcdf85de7a39988978263ad261e83996dad219a0058e02187384f2d0754ff9cfa000bec448fafd2cfa738
    const CAVP_C500_PT: [u8; 48] = [
        0xec, 0x36, 0x55, 0x1c, 0x70, 0xef, 0xcd, 0xf8,
        0x5d, 0xe7, 0xa3, 0x99, 0x88, 0x97, 0x82, 0x63,
        0xad, 0x26, 0x1e, 0x83, 0x99, 0x6d, 0xad, 0x21,
        0x9a, 0x00, 0x58, 0xe0, 0x21, 0x87, 0x38, 0x4f,
        0x2d, 0x07, 0x54, 0xff, 0x9c, 0xfa, 0x00, 0x0b,
        0xec, 0x44, 0x8f, 0xaf, 0xd2, 0xcf, 0xa7, 0x38,
    ];
    /// CAVP COUNT=500 `CT`: a55d533c9c5885562b92d4582ea69db8e2ba9c0b967a9f0167700b043525a47bafe7d630774eaf4a1dc9fbcf94a1fda4
    const CAVP_C500_CT: [u8; 48] = [
        0xa5, 0x5d, 0x53, 0x3c, 0x9c, 0x58, 0x85, 0x56,
        0x2b, 0x92, 0xd4, 0x58, 0x2e, 0xa6, 0x9d, 0xb8,
        0xe2, 0xba, 0x9c, 0x0b, 0x96, 0x7a, 0x9f, 0x01,
        0x67, 0x70, 0x0b, 0x04, 0x35, 0x25, 0xa4, 0x7b,
        0xaf, 0xe7, 0xd6, 0x30, 0x77, 0x4e, 0xaf, 0x4a,
        0x1d, 0xc9, 0xfb, 0xcf, 0x94, 0xa1, 0xfd, 0xa4,
    ];

    #[test]
    fn nist_cavp_xtsgen_aes256_count499_encrypt_48byte() {
        let cipher = XtsAes256::new(&CAVP_C499_MASTER);
        let mut buf = CAVP_C499_PT;
        cipher.encrypt_data_unit(&mut buf, CAVP_C499_TWEAK);
        assert_eq!(buf, CAVP_C499_CT, "NIST CAVP XTSGenAES256 COUNT=499 encrypt mismatch");
    }

    #[test]
    fn nist_cavp_xtsgen_aes256_count499_decrypt_48byte() {
        let cipher = XtsAes256::new(&CAVP_C499_MASTER);
        let mut buf = CAVP_C499_CT;
        cipher.decrypt_data_unit(&mut buf, CAVP_C499_TWEAK);
        assert_eq!(buf, CAVP_C499_PT, "NIST CAVP XTSGenAES256 COUNT=499 decrypt mismatch");
    }

    #[test]
    fn nist_cavp_xtsgen_aes256_count500_encrypt_48byte() {
        let cipher = XtsAes256::new(&CAVP_C500_MASTER);
        let mut buf = CAVP_C500_PT;
        cipher.encrypt_data_unit(&mut buf, CAVP_C500_TWEAK);
        assert_eq!(buf, CAVP_C500_CT, "NIST CAVP XTSGenAES256 COUNT=500 encrypt mismatch");
    }

    #[test]
    fn nist_cavp_xtsgen_aes256_count500_decrypt_48byte() {
        let cipher = XtsAes256::new(&CAVP_C500_MASTER);
        let mut buf = CAVP_C500_CT;
        cipher.decrypt_data_unit(&mut buf, CAVP_C500_TWEAK);
        assert_eq!(buf, CAVP_C500_PT, "NIST CAVP XTSGenAES256 COUNT=500 decrypt mismatch");
    }

    #[test]
    fn encrypt_sector_matches_encrypt_data_unit_with_lba_tweak() {
        // Internal consistency: the existing `encrypt_sector(buf, lba)`
        // path is exactly `encrypt_data_unit(buf, initial_tweak_bytes(lba))`.
        // This test pins the equivalence so the refactor that introduced
        // `encrypt_data_unit` can't silently diverge `encrypt_sector` later.
        let cipher = XtsAes256::new(&master_key_pattern());
        let mut a = plaintext_pattern();
        let mut b = plaintext_pattern();

        let lba = 0xdeadbeefu64;
        cipher.encrypt_sector(&mut a, lba);

        let mut tweak_bytes = [0u8; XTS_INNER_BLOCK_LEN];
        tweak_bytes[..8].copy_from_slice(&lba.to_le_bytes());
        cipher.encrypt_data_unit(&mut b, tweak_bytes);

        assert_eq!(a, b);
    }
}
