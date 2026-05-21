// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Pure-Rust AES-256 software implementation (FIPS-197).
//!
//! Block-cipher primitive for [ADR-032](../../../../docs/adr/032-full-disk-encryption-below-substrate.md)
//! § 2's XTS-AES-256 FDE cipher. Consumed by
//! [`super::encrypted_device::EncryptedBlockDevice`]; no other
//! callers today.
//!
//! ## Why vendored
//!
//! RustCrypto's `aes` 0.8.x crate hits LLVM lowering errors
//! (`"Do not know how to split the result of this operator!"`) on
//! `x86_64-unknown-none` with our pinned `nightly-2026-02-07`
//! toolchain. Its transitive deps (`cpufeatures`, `constant_time_eq`
//! 0.4) carry the same fragility. Vendoring a minimal pure-Rust
//! AES-256 — no SIMD, no intrinsics, no cpufeatures runtime
//! detection, no transitive crypto deps — moves the build surface
//! from "everything RustCrypto + LLVM + cpufeatures do" to "`u8`,
//! `u32`, and `^` ops on three target arches." Vastly smaller LLVM
//! exposure; statically analyzable; Verus-friendly for future
//! formal verification (Convention 1).
//!
//! Future replacement: swap to `aes::Aes256` (or hardware-accelerated
//! per-arch backends — AES-NI on x86_64, ARMv8 Crypto Extensions on
//! aarch64) once RustCrypto's bare-metal codegen story stabilizes,
//! tracked behind the same `Aes256::encrypt_block`/`decrypt_block`
//! API this module exposes. cipher_id stays 0x01; the wire format
//! is independent of the AES implementation.
//!
//! ## Security caveats
//!
//! - **Table-based S-box.** This implementation uses the standard
//!   FIPS-197 S-box and InvS-box as constant tables (256 bytes
//!   each). Table lookups indexed by secret data leak through the
//!   CPU cache; a co-located attacker with cache-observation
//!   capability can recover key bits. On x86_64 + AArch64 we target
//!   hardware AES (AES-NI, ARMv8 Crypto Extensions) as the long-term
//!   data-path implementation — both are constant-time. On RISC-V
//!   boards without Zk* extensions, software AES is the
//!   implementation and cache-timing is a documented gap per
//!   ADR-032 § 2 ("slower but uniform"). For v1, the threat model
//!   centers on offline disk theft, not local cache adversaries;
//!   the gap is acknowledged but not load-bearing.
//! - **No constant-time guarantee** beyond the trivial sense (the
//!   *control flow* is constant — only the cache trace varies).
//! - **No zeroize on Drop.** The caller (the `EncryptedBlockDevice`
//!   wrapper) holds the round-keys for the lifetime of the volume
//!   mount; mount-side zeroize is the caller's responsibility.
//!
//! ## Reference
//!
//! FIPS PUB 197, *Advanced Encryption Standard (AES)*, November
//! 2001 (NIST). Public domain — US government work. Test vectors
//! in `tests` mod are FIPS-197 Appendix C.3 (the canonical
//! AES-256 example).

/// HARDWARE: AES block size in bytes — fixed at 128 bits by
/// FIPS-197 § 2, independent of key length.
pub const AES_BLOCK_LEN: usize = 16;

/// HARDWARE: AES-256 key length in bytes per FIPS-197 § 5.
pub const AES256_KEY_LEN: usize = 32;

/// HARDWARE: AES-256 number of rounds per FIPS-197 Table 2 (`Nr` = 14).
const AES256_ROUNDS: usize = 14;

/// HARDWARE: AES-256 round-key buffer size — `(Nr+1) * Nb * 4` bytes
/// = 15 × 16 = 240 bytes. The KeyExpansion routine fills this buffer
/// with one 16-byte round key per round, starting at offset 0.
const AES256_ROUND_KEYS_LEN: usize = (AES256_ROUNDS + 1) * AES_BLOCK_LEN;

/// FIPS-197 Figure 7 forward S-box. Substitutes each byte during
/// `SubBytes`. The table is the affine transformation of the
/// multiplicative inverse in GF(2^8) — pre-computed since deriving
/// it at runtime would be wasteful.
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// FIPS-197 Figure 14 inverse S-box. Used in `InvSubBytes` during
/// decryption.
#[rustfmt::skip]
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// FIPS-197 § 5.2 round-constants for KeyExpansion. Only the first
/// 7 are needed for AES-256 (the expansion loop walks indices
/// 8..60 of the round-key word array; `i/Nk` ranges 1..=7).
const RCON: [u8; 8] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

/// Multiplication by 2 in GF(2^8) — the `xtime` operation of
/// FIPS-197 § 4.2.1. Used by `MixColumns` and the GF-element
/// derivations 3·x, 9·x, 11·x, 13·x, 14·x.
#[inline(always)]
fn xtime(b: u8) -> u8 {
    // (b << 1) XOR (0x1b if bit 7 was set, else 0)
    // 0x1b is the AES reduction polynomial.
    let shifted = b << 1;
    let mask = (b >> 7).wrapping_mul(0x1b);
    shifted ^ mask
}

/// AES-256 cipher instance — holds the 240-byte expanded round-key
/// schedule. Construct via `Aes256::new(&key)`, then call
/// `encrypt_block` / `decrypt_block` per 16-byte block.
pub struct Aes256 {
    /// Round keys 0..14, each 16 bytes (4 × 4-byte words).
    /// FIPS-197 KeyExpansion fills this in `new`.
    round_keys: [u8; AES256_ROUND_KEYS_LEN],
}

impl Aes256 {
    /// Expand a 32-byte AES-256 key into the 240-byte round-key
    /// schedule per FIPS-197 § 5.2 (Algorithm 1).
    pub fn new(key: &[u8; AES256_KEY_LEN]) -> Self {
        let mut round_keys = [0u8; AES256_ROUND_KEYS_LEN];

        // The first Nk × 4 = 32 bytes of the round-key buffer are
        // a copy of the user key — FIPS-197 § 5.2 spec.
        round_keys[..AES256_KEY_LEN].copy_from_slice(key);

        // Generate words 8..60 (4 bytes per word, 60 - 8 = 52
        // words; 52 × 4 = 208 bytes; total 32 + 208 = 240 bytes).
        //
        // i_word indexes 32-bit words; byte offset = i_word * 4.
        // Nk = 8 for AES-256.

        /// HARDWARE: FIPS-197 Table 2 — AES-256 key length in 32-bit
        /// words (`Nk` = 8). Derived from `AES256_KEY_LEN / 4` purely
        /// as a readability convenience; the value is fixed by FIPS-197.
        const NK: usize = AES256_KEY_LEN / 4;
        /// HARDWARE: FIPS-197 Table 2 — total round-key buffer in
        /// 32-bit words for AES-256 (`(Nr+1) * Nb` = 15 × 4 = 60).
        /// Derived from `AES256_ROUND_KEYS_LEN / 4`; fixed by FIPS-197.
        const TOTAL_WORDS: usize = AES256_ROUND_KEYS_LEN / 4;

        for i_word in NK..TOTAL_WORDS {
            let prev_off = (i_word - 1) * 4;
            let mut temp = [
                round_keys[prev_off],
                round_keys[prev_off + 1],
                round_keys[prev_off + 2],
                round_keys[prev_off + 3],
            ];

            if i_word % NK == 0 {
                // RotWord: cyclic left rotation by 1 byte
                temp = [temp[1], temp[2], temp[3], temp[0]];
                // SubWord: per-byte S-box
                temp = [
                    SBOX[temp[0] as usize],
                    SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                ];
                // XOR Rcon (a single byte applied to byte 0).
                // i_word/NK is in 1..=7 for AES-256.
                temp[0] ^= RCON[i_word / NK];
            } else if i_word % NK == 4 {
                // AES-256-only: extra SubWord every Nk/2 = 4 words.
                temp = [
                    SBOX[temp[0] as usize],
                    SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                ];
            }

            // w[i] = w[i-Nk] XOR temp
            let dst_off = i_word * 4;
            let src_off = (i_word - NK) * 4;
            round_keys[dst_off] = round_keys[src_off] ^ temp[0];
            round_keys[dst_off + 1] = round_keys[src_off + 1] ^ temp[1];
            round_keys[dst_off + 2] = round_keys[src_off + 2] ^ temp[2];
            round_keys[dst_off + 3] = round_keys[src_off + 3] ^ temp[3];
        }

        Self { round_keys }
    }

    /// Encrypt one 16-byte block in place. FIPS-197 § 5.1
    /// (Algorithm 5): initial AddRoundKey, then Nr-1 full rounds,
    /// then one final round without MixColumns.
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        // Round 0: AddRoundKey only.
        add_round_key(block, &self.round_keys[0..AES_BLOCK_LEN]);

        // Rounds 1..Nr-1: SubBytes, ShiftRows, MixColumns, AddRoundKey.
        for round in 1..AES256_ROUNDS {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            let rk_off = round * AES_BLOCK_LEN;
            add_round_key(block, &self.round_keys[rk_off..rk_off + AES_BLOCK_LEN]);
        }

        // Final round (Nr): SubBytes, ShiftRows, AddRoundKey
        // (no MixColumns, per FIPS-197 § 5.1).
        sub_bytes(block);
        shift_rows(block);
        let rk_off = AES256_ROUNDS * AES_BLOCK_LEN;
        add_round_key(block, &self.round_keys[rk_off..rk_off + AES_BLOCK_LEN]);
    }

    /// Decrypt one 16-byte block in place. FIPS-197 § 5.3
    /// (Algorithm 6): inverse of `encrypt_block`.
    pub fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        // Inverse round 0: AddRoundKey with the *last* round key.
        let rk_off = AES256_ROUNDS * AES_BLOCK_LEN;
        add_round_key(block, &self.round_keys[rk_off..rk_off + AES_BLOCK_LEN]);

        // Inverse rounds Nr-1 down to 1: InvShiftRows, InvSubBytes,
        // AddRoundKey, InvMixColumns.
        for round in (1..AES256_ROUNDS).rev() {
            inv_shift_rows(block);
            inv_sub_bytes(block);
            let rk_off = round * AES_BLOCK_LEN;
            add_round_key(block, &self.round_keys[rk_off..rk_off + AES_BLOCK_LEN]);
            inv_mix_columns(block);
        }

        // Final inverse round: InvShiftRows, InvSubBytes, AddRoundKey
        // (no InvMixColumns).
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, &self.round_keys[0..AES_BLOCK_LEN]);
    }
}

// ============================================================================
// Round primitives — FIPS-197 § 5.1 (encrypt) / § 5.3 (decrypt)
// ============================================================================
//
// All operate on a 16-byte block laid out column-major: byte i is
// state[r=i%4][c=i/4]. The ShiftRows / MixColumns indices below
// follow that convention.

#[inline(always)]
fn add_round_key(block: &mut [u8; AES_BLOCK_LEN], round_key: &[u8]) {
    // FIPS-197 § 5.1.4: state XOR round_key, byte-wise.
    for i in 0..AES_BLOCK_LEN {
        block[i] ^= round_key[i];
    }
}

#[inline(always)]
fn sub_bytes(block: &mut [u8; AES_BLOCK_LEN]) {
    // FIPS-197 § 5.1.1: per-byte S-box substitution.
    for b in block.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

#[inline(always)]
fn inv_sub_bytes(block: &mut [u8; AES_BLOCK_LEN]) {
    for b in block.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

#[inline(always)]
fn shift_rows(block: &mut [u8; AES_BLOCK_LEN]) {
    // FIPS-197 § 5.1.2: row r is rotated left by r positions.
    // Column-major byte layout: state[r][c] = block[r + 4*c].
    //
    // Row 0: no change.
    // Row 1: 1, 5, 9, 13  → 5, 9, 13, 1
    let t = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = t;
    // Row 2: 2, 6, 10, 14 → 10, 14, 2, 6 (rotate by 2)
    block.swap(2, 10);
    block.swap(6, 14);
    // Row 3: 3, 7, 11, 15 → 15, 3, 7, 11 (rotate left by 3 = right by 1)
    let t = block[3];
    block[3] = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = t;
}

#[inline(always)]
fn inv_shift_rows(block: &mut [u8; AES_BLOCK_LEN]) {
    // Inverse: rotate row r right by r positions.
    // Row 0: no change.
    // Row 1: rotate right by 1 (= rotate left by 3)
    let t = block[13];
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = t;
    // Row 2: rotate by 2 (self-inverse with shift_rows row 2)
    block.swap(2, 10);
    block.swap(6, 14);
    // Row 3: rotate right by 3 (= rotate left by 1)
    let t = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = block[3];
    block[3] = t;
}

#[inline(always)]
fn mix_columns(block: &mut [u8; AES_BLOCK_LEN]) {
    // FIPS-197 § 5.1.3: each column is treated as a polynomial over
    // GF(2^8) and multiplied modulo (x^4 + 1) by 3x^3 + x^2 + x + 2.
    //
    // For each column [s0, s1, s2, s3]:
    //   s'0 = 2·s0 ⊕ 3·s1 ⊕   s2 ⊕   s3
    //   s'1 =   s0 ⊕ 2·s1 ⊕ 3·s2 ⊕   s3
    //   s'2 =   s0 ⊕   s1 ⊕ 2·s2 ⊕ 3·s3
    //   s'3 = 3·s0 ⊕   s1 ⊕   s2 ⊕ 2·s3
    //
    // 3·x = xtime(x) XOR x; 2·x = xtime(x).
    for c in 0..4 {
        let off = c * 4;
        let s0 = block[off];
        let s1 = block[off + 1];
        let s2 = block[off + 2];
        let s3 = block[off + 3];
        let t = s0 ^ s1 ^ s2 ^ s3;
        block[off] ^= t ^ xtime(s0 ^ s1);
        block[off + 1] ^= t ^ xtime(s1 ^ s2);
        block[off + 2] ^= t ^ xtime(s2 ^ s3);
        block[off + 3] ^= t ^ xtime(s3 ^ s0);
    }
}

#[inline(always)]
fn inv_mix_columns(block: &mut [u8; AES_BLOCK_LEN]) {
    // FIPS-197 § 5.3.3: inverse column transform using
    // multiplication by 11x^3 + 13x^2 + 9x + 14.
    //
    // For each column: derive 9·x, 11·x, 13·x, 14·x via repeated
    // xtime — see FIPS-197 § 4.2.1 worked example.
    for c in 0..4 {
        let off = c * 4;
        let s0 = block[off];
        let s1 = block[off + 1];
        let s2 = block[off + 2];
        let s3 = block[off + 3];

        // Precompute multiples in GF(2^8).
        let x2_s0 = xtime(s0);
        let x4_s0 = xtime(x2_s0);
        let x8_s0 = xtime(x4_s0);
        let x9_s0 = x8_s0 ^ s0;
        let x11_s0 = x8_s0 ^ x2_s0 ^ s0;
        let x13_s0 = x8_s0 ^ x4_s0 ^ s0;
        let x14_s0 = x8_s0 ^ x4_s0 ^ x2_s0;

        let x2_s1 = xtime(s1);
        let x4_s1 = xtime(x2_s1);
        let x8_s1 = xtime(x4_s1);
        let x9_s1 = x8_s1 ^ s1;
        let x11_s1 = x8_s1 ^ x2_s1 ^ s1;
        let x13_s1 = x8_s1 ^ x4_s1 ^ s1;
        let x14_s1 = x8_s1 ^ x4_s1 ^ x2_s1;

        let x2_s2 = xtime(s2);
        let x4_s2 = xtime(x2_s2);
        let x8_s2 = xtime(x4_s2);
        let x9_s2 = x8_s2 ^ s2;
        let x11_s2 = x8_s2 ^ x2_s2 ^ s2;
        let x13_s2 = x8_s2 ^ x4_s2 ^ s2;
        let x14_s2 = x8_s2 ^ x4_s2 ^ x2_s2;

        let x2_s3 = xtime(s3);
        let x4_s3 = xtime(x2_s3);
        let x8_s3 = xtime(x4_s3);
        let x9_s3 = x8_s3 ^ s3;
        let x11_s3 = x8_s3 ^ x2_s3 ^ s3;
        let x13_s3 = x8_s3 ^ x4_s3 ^ s3;
        let x14_s3 = x8_s3 ^ x4_s3 ^ x2_s3;

        block[off] = x14_s0 ^ x11_s1 ^ x13_s2 ^ x9_s3;
        block[off + 1] = x9_s0 ^ x14_s1 ^ x11_s2 ^ x13_s3;
        block[off + 2] = x13_s0 ^ x9_s1 ^ x14_s2 ^ x11_s3;
        block[off + 3] = x11_s0 ^ x13_s1 ^ x9_s2 ^ x14_s3;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 Appendix C.3 — canonical AES-256 example.
    /// Plaintext: 00112233445566778899aabbccddeeff
    /// Key:       000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    /// Ciphertext: 8ea2b7ca516745bfeafc49904b496089
    const FIPS_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const FIPS_PT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const FIPS_CT: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];

    #[test]
    fn fips197_appendix_c3_encrypt() {
        let cipher = Aes256::new(&FIPS_KEY);
        let mut block = FIPS_PT;
        cipher.encrypt_block(&mut block);
        assert_eq!(block, FIPS_CT, "FIPS-197 § C.3 encrypt mismatch");
    }

    #[test]
    fn fips197_appendix_c3_decrypt() {
        let cipher = Aes256::new(&FIPS_KEY);
        let mut block = FIPS_CT;
        cipher.decrypt_block(&mut block);
        assert_eq!(block, FIPS_PT, "FIPS-197 § C.3 decrypt mismatch");
    }

    #[test]
    fn encrypt_decrypt_roundtrip_all_zeros() {
        let key = [0u8; 32];
        let cipher = Aes256::new(&key);
        let plaintext = [0u8; 16];
        let mut block = plaintext;
        cipher.encrypt_block(&mut block);
        // After encrypt, block should not equal plaintext (sanity).
        assert_ne!(block, plaintext);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_random_pattern() {
        // Non-trivial key and plaintext to catch index-off-by-one
        // bugs that the all-zero case would hide.
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = ((i * 17) ^ 0xa5) as u8;
        }
        let mut plaintext = [0u8; 16];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = ((i * 13) ^ 0x3c) as u8;
        }
        let cipher = Aes256::new(&key);
        let mut block = plaintext;
        cipher.encrypt_block(&mut block);
        assert_ne!(block, plaintext);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn xtime_matches_fips197_section_4_2_1() {
        // FIPS-197 § 4.2.1 worked example: xtime(0x57) = 0xae,
        // xtime(0xae) = 0x47, xtime(0x47) = 0x8e, xtime(0x8e) = 0x07.
        assert_eq!(xtime(0x57), 0xae);
        assert_eq!(xtime(0xae), 0x47);
        assert_eq!(xtime(0x47), 0x8e);
        assert_eq!(xtime(0x8e), 0x07);
    }

    #[test]
    fn sbox_is_involutive_via_inv_sbox() {
        // S(InvS(x)) == x and InvS(S(x)) == x for all 256 bytes.
        for x in 0..=255u8 {
            assert_eq!(SBOX[INV_SBOX[x as usize] as usize], x);
            assert_eq!(INV_SBOX[SBOX[x as usize] as usize], x);
        }
    }

    #[test]
    fn key_expansion_first_round_matches_input_key() {
        // FIPS-197 § 5.2 specifies the first Nk words of the round
        // key buffer equal the user key verbatim.
        let cipher = Aes256::new(&FIPS_KEY);
        assert_eq!(&cipher.round_keys[..32], &FIPS_KEY[..]);
    }

    #[test]
    fn distinct_keys_produce_distinct_ciphertexts() {
        let key_a = [0xaau8; 32];
        let key_b = [0xbbu8; 32];
        let pt = [0u8; 16];
        let cipher_a = Aes256::new(&key_a);
        let cipher_b = Aes256::new(&key_b);
        let mut block_a = pt;
        let mut block_b = pt;
        cipher_a.encrypt_block(&mut block_a);
        cipher_b.encrypt_block(&mut block_b);
        assert_ne!(block_a, block_b);
    }
}
