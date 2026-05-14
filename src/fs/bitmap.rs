// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Block-allocation bitmap.
//!
//! Per [ADR-029 § Decision 1](../../docs/adr/029-posix-file-storage-model.md)
//! the bitmap region tracks which data blocks are in use. The bitmap
//! is shared between the POSIX backend (immediately) and the
//! CambiObject backend (post-[ADR-010 § Divergence 3](../../docs/adr/010-persistent-object-store-on-disk-format.md));
//! every bitmap mutation is journaled per the journal-owned-bitmap
//! invariant.
//!
//! This module is the pure data-structure layer. It does not own a
//! lock, does not perform device I/O, and does not interact with the
//! journal. The kernel-side instance with locking + journaling lands
//! in ADR-029 step 5C (POSIX integration) and step 5D (CambiObject
//! integration).
//!
//! ## Bit convention
//!
//! `1 = free`, `0 = occupied`. Matches the `FreeMap` convention in
//! `crate::fs::disk` so allocator-style "find first free" becomes a
//! single `trailing_zeros` over each word.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::fs::block::{Block, BLOCK_SIZE};

/// Errors from bitmap operations. Typed per CLAUDE.md "no panics in
/// non-test kernel code" — out-of-bounds indices surface as
/// `Result::Err` rather than a debug_assert panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapError {
    /// Block index >= capacity.
    OutOfBounds,
    /// Encoded buffer size doesn't match the bitmap's word count
    /// (`capacity.div_ceil(64) * 8` bytes).
    EncodingSizeMismatch,
    /// On-disk bitmap has bits set past the declared capacity. The
    /// canonical-form invariant (matching ADR-029 § Divergence 1's
    /// stance for inodes) requires unused trailing bits to be zero.
    NonZeroPadding,
}

/// In-memory block-allocation bitmap. Bit `i` represents data block
/// `i`; `1 = free`, `0 = occupied`.
///
/// Owned by the kernel-instance behind `BLOCK_BITMAP_LOCK` at lock-
/// hierarchy position 12 (per [ADR-029 § Decision 4](../../docs/adr/029-posix-file-storage-model.md));
/// the lock instance lives in `src/lib.rs` and is introduced in
/// step 5C. This module exposes the unsynchronized data structure;
/// the lock wrapper is one level up.
///
/// `Debug + PartialEq + Eq` derived to support `assert_eq!` on
/// `Result<BlockBitmap, BitmapError>` in tests and the
/// canonical-form claim ("same logical bitmap → same bytes").
#[derive(Debug, PartialEq, Eq)]
pub struct BlockBitmap {
    /// One bit per block. `words[i]` covers blocks `i*64 .. (i+1)*64`,
    /// little-endian within each word: bit 0 of `words[i]` is block
    /// `i*64`.
    words: Vec<u64>,
    /// Number of valid bits (i.e., the number of blocks the bitmap
    /// represents). Bits past this in the last partial word are
    /// always zero (canonical form).
    capacity: u64,
}

impl BlockBitmap {
    /// Create a bitmap with the given capacity (in blocks) where every
    /// block starts free. Bits past `capacity` in the last word are
    /// zeroed so `first_free` cannot accidentally return an
    /// out-of-range index.
    pub fn new_all_free(capacity: u64) -> Self {
        let word_count = capacity.div_ceil(64) as usize;
        let mut words = vec![u64::MAX; word_count];
        // Zero unused trailing bits in the last word.
        let last_word_bits = capacity % 64;
        if last_word_bits != 0 && word_count > 0 {
            let mask = (1u64 << last_word_bits) - 1;
            words[word_count - 1] &= mask;
        }
        Self { words, capacity }
    }

    /// Total number of blocks tracked.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Returns `true` if `block` is free and within range.
    pub fn is_free(&self, block: u64) -> bool {
        if block >= self.capacity {
            return false;
        }
        let (w, b) = ((block / 64) as usize, block % 64);
        (self.words[w] >> b) & 1 == 1
    }

    /// Returns `true` if `block` is in range AND occupied. Out-of-
    /// range indices return `false` (callers should bounds-check
    /// before relying on this).
    pub fn is_occupied(&self, block: u64) -> bool {
        if block >= self.capacity {
            return false;
        }
        !self.is_free(block)
    }

    /// Mark `block` as occupied. Returns `OutOfBounds` if the index is
    /// past capacity.
    pub fn mark_occupied(&mut self, block: u64) -> Result<(), BitmapError> {
        if block >= self.capacity {
            return Err(BitmapError::OutOfBounds);
        }
        let (w, b) = ((block / 64) as usize, block % 64);
        self.words[w] &= !(1u64 << b);
        Ok(())
    }

    /// Mark `block` as free. Returns `OutOfBounds` if the index is
    /// past capacity.
    pub fn mark_free(&mut self, block: u64) -> Result<(), BitmapError> {
        if block >= self.capacity {
            return Err(BitmapError::OutOfBounds);
        }
        let (w, b) = ((block / 64) as usize, block % 64);
        self.words[w] |= 1u64 << b;
        Ok(())
    }

    /// Find the lowest-indexed free block. `None` if all blocks are
    /// occupied.
    pub fn first_free(&self) -> Option<u64> {
        for (i, &w) in self.words.iter().enumerate() {
            if w != 0 {
                let bit = w.trailing_zeros() as u64;
                let block = (i as u64) * 64 + bit;
                if block < self.capacity {
                    return Some(block);
                }
            }
        }
        None
    }

    /// Find the lowest-indexed run of `count` consecutive free blocks.
    /// `None` if no such run exists.
    ///
    /// Used by extent-based allocation: when a write needs an extent
    /// of `n` contiguous blocks, this scans for the first run of `n`
    /// free bits. Bounded iteration over `capacity` bits;
    /// verifier-friendly upper bound.
    pub fn find_first_free_run(&self, count: u64) -> Option<u64> {
        if count == 0 || count > self.capacity {
            return None;
        }
        let mut run_start: Option<u64> = None;
        let mut run_len: u64 = 0;
        for block in 0..self.capacity {
            if self.is_free(block) {
                if run_start.is_none() {
                    run_start = Some(block);
                    run_len = 1;
                } else {
                    run_len += 1;
                }
                if run_len == count {
                    return run_start;
                }
            } else {
                run_start = None;
                run_len = 0;
            }
        }
        None
    }

    /// Count of currently-free blocks. Linear scan; intended for
    /// telemetry and tests, not allocator hot path.
    pub fn free_count(&self) -> u64 {
        let mut total = 0u64;
        for &w in &self.words {
            total += w.count_ones() as u64;
        }
        total
    }

    /// Encoded size in bytes. Equal to `capacity.div_ceil(64) * 8`.
    pub fn encoded_bytes(&self) -> usize {
        self.words.len() * 8
    }

    /// Number of blocks needed to store the encoded bitmap. Equal to
    /// `encoded_bytes().div_ceil(BLOCK_SIZE)`.
    pub fn region_blocks(&self) -> u64 {
        (self.encoded_bytes() as u64).div_ceil(BLOCK_SIZE as u64)
    }

    /// Encode the bitmap into `buf`, a byte slice sized to exactly
    /// `encoded_bytes()`. Words are written little-endian, back to
    /// back.
    pub fn encode(&self, buf: &mut [u8]) -> Result<(), BitmapError> {
        if buf.len() != self.encoded_bytes() {
            return Err(BitmapError::EncodingSizeMismatch);
        }
        for (i, &w) in self.words.iter().enumerate() {
            let base = i * 8;
            buf[base..base + 8].copy_from_slice(&w.to_le_bytes());
        }
        Ok(())
    }

    /// Decode a bitmap from a byte slice, validating the canonical-
    /// form invariant (bits past `capacity` must be zero).
    pub fn decode(buf: &[u8], capacity: u64) -> Result<Self, BitmapError> {
        let word_count = capacity.div_ceil(64) as usize;
        let expected = word_count * 8;
        if buf.len() != expected {
            return Err(BitmapError::EncodingSizeMismatch);
        }
        let mut words = Vec::with_capacity(word_count);
        for i in 0..word_count {
            let base = i * 8;
            let w = u64::from_le_bytes([
                buf[base], buf[base + 1], buf[base + 2], buf[base + 3],
                buf[base + 4], buf[base + 5], buf[base + 6], buf[base + 7],
            ]);
            words.push(w);
        }
        // Canonical form: bits past capacity in the last word must be zero.
        let last_word_bits = capacity % 64;
        if last_word_bits != 0 && word_count > 0 {
            let mask = (1u64 << last_word_bits) - 1;
            if words[word_count - 1] & !mask != 0 {
                return Err(BitmapError::NonZeroPadding);
            }
        }
        Ok(Self { words, capacity })
    }
}

/// Convenience helper: encode a bitmap into a sequence of full block-
/// sized buffers, zero-padding the final block if `encoded_bytes` is
/// not a multiple of `BLOCK_SIZE`. Returns the blocks; the caller
/// writes them to the bitmap region at consecutive LBAs.
///
/// Pure function over the bitmap's bytes — no device I/O.
pub fn encode_to_blocks(bitmap: &BlockBitmap) -> Result<Vec<Block>, BitmapError> {
    let mut bytes = vec![0u8; bitmap.encoded_bytes()];
    bitmap.encode(&mut bytes)?;
    let region_blocks = bitmap.region_blocks() as usize;
    let mut blocks = vec![[0u8; BLOCK_SIZE]; region_blocks];
    for (i, block) in blocks.iter_mut().enumerate() {
        let start = i * BLOCK_SIZE;
        let end = core::cmp::min(start + BLOCK_SIZE, bytes.len());
        if end > start {
            block[..end - start].copy_from_slice(&bytes[start..end]);
        }
    }
    Ok(blocks)
}

/// Convenience helper: decode a bitmap from a sequence of block-sized
/// buffers. The reverse of [`encode_to_blocks`]. The buffers must be
/// in the same order they were written.
pub fn decode_from_blocks(blocks: &[Block], capacity: u64) -> Result<BlockBitmap, BitmapError> {
    let expected_bytes = capacity.div_ceil(64) as usize * 8;
    let expected_region_blocks = (expected_bytes as u64).div_ceil(BLOCK_SIZE as u64) as usize;
    if blocks.len() != expected_region_blocks {
        return Err(BitmapError::EncodingSizeMismatch);
    }
    let mut bytes = vec![0u8; expected_bytes];
    let mut written = 0usize;
    for block in blocks {
        let remaining = expected_bytes - written;
        let take = core::cmp::min(BLOCK_SIZE, remaining);
        if take > 0 {
            bytes[written..written + take].copy_from_slice(&block[..take]);
        }
        written += take;
    }
    // Canonical form: bytes past expected_bytes in the final partial
    // block must be zero. Check the source blocks directly.
    let unused_in_last_block = expected_region_blocks * BLOCK_SIZE - expected_bytes;
    if unused_in_last_block > 0 {
        let last = &blocks[expected_region_blocks - 1];
        if last[BLOCK_SIZE - unused_in_last_block..].iter().any(|&b| b != 0) {
            return Err(BitmapError::NonZeroPadding);
        }
    }
    BlockBitmap::decode(&bytes, capacity)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_all_free_is_all_free() {
        let bm = BlockBitmap::new_all_free(100);
        assert_eq!(bm.capacity(), 100);
        assert_eq!(bm.free_count(), 100);
        for i in 0..100 {
            assert!(bm.is_free(i));
            assert!(!bm.is_occupied(i));
        }
    }

    #[test]
    fn mark_occupied_then_free() {
        let mut bm = BlockBitmap::new_all_free(64);
        bm.mark_occupied(10).unwrap();
        assert!(!bm.is_free(10));
        assert!(bm.is_occupied(10));
        assert_eq!(bm.free_count(), 63);
        bm.mark_free(10).unwrap();
        assert!(bm.is_free(10));
        assert_eq!(bm.free_count(), 64);
    }

    #[test]
    fn out_of_bounds_returns_error() {
        let mut bm = BlockBitmap::new_all_free(64);
        assert_eq!(bm.mark_occupied(64), Err(BitmapError::OutOfBounds));
        assert_eq!(bm.mark_free(64), Err(BitmapError::OutOfBounds));
        assert_eq!(bm.mark_occupied(u64::MAX), Err(BitmapError::OutOfBounds));
    }

    #[test]
    fn is_free_handles_out_of_bounds() {
        let bm = BlockBitmap::new_all_free(64);
        assert!(!bm.is_free(64));
        assert!(!bm.is_free(u64::MAX));
        assert!(!bm.is_occupied(64));
    }

    #[test]
    fn first_free_finds_lowest_index() {
        let mut bm = BlockBitmap::new_all_free(128);
        assert_eq!(bm.first_free(), Some(0));
        bm.mark_occupied(0).unwrap();
        bm.mark_occupied(1).unwrap();
        bm.mark_occupied(2).unwrap();
        assert_eq!(bm.first_free(), Some(3));
        // Occupy across a word boundary.
        for i in 3..70 {
            bm.mark_occupied(i).unwrap();
        }
        assert_eq!(bm.first_free(), Some(70));
    }

    #[test]
    fn first_free_returns_none_when_full() {
        let mut bm = BlockBitmap::new_all_free(64);
        for i in 0..64 {
            bm.mark_occupied(i).unwrap();
        }
        assert_eq!(bm.first_free(), None);
    }

    #[test]
    fn first_free_respects_capacity_not_word_alignment() {
        // Capacity = 70 means bits [64..70] are valid; bits [70..128]
        // in the second word must be zero (canonical form) so
        // first_free returns 64, not 70.
        let bm = BlockBitmap::new_all_free(70);
        for i in 0..70 {
            assert!(bm.is_free(i));
        }
        // Mark all bits in [0..64] occupied; first_free is now 64.
        let mut bm = bm;
        for i in 0..64 {
            bm.mark_occupied(i).unwrap();
        }
        assert_eq!(bm.first_free(), Some(64));
        // Mark all valid bits occupied; first_free is None.
        for i in 64..70 {
            bm.mark_occupied(i).unwrap();
        }
        assert_eq!(bm.first_free(), None);
    }

    #[test]
    fn find_first_free_run_basic() {
        let mut bm = BlockBitmap::new_all_free(64);
        assert_eq!(bm.find_first_free_run(1), Some(0));
        assert_eq!(bm.find_first_free_run(5), Some(0));
        assert_eq!(bm.find_first_free_run(64), Some(0));
        assert_eq!(bm.find_first_free_run(65), None);
        // Block out the run at 0..3; next run starts at 3.
        bm.mark_occupied(0).unwrap();
        bm.mark_occupied(1).unwrap();
        bm.mark_occupied(2).unwrap();
        assert_eq!(bm.find_first_free_run(5), Some(3));
    }

    #[test]
    fn find_first_free_run_skips_broken_runs() {
        let mut bm = BlockBitmap::new_all_free(64);
        bm.mark_occupied(5).unwrap();
        // [0..5] is a run of 5; [6..64] is a run of 58. Run of 4
        // fits at 0; run of 5 also fits at 0 (just barely); run of
        // 6 doesn't fit until block 6.
        assert_eq!(bm.find_first_free_run(4), Some(0));
        assert_eq!(bm.find_first_free_run(5), Some(0));
        assert_eq!(bm.find_first_free_run(6), Some(6));
    }

    #[test]
    fn find_first_free_run_returns_none_when_no_run_fits() {
        let mut bm = BlockBitmap::new_all_free(10);
        bm.mark_occupied(5).unwrap();
        // Best run is 5 (blocks 0..5 or 6..10); 6 doesn't fit.
        assert_eq!(bm.find_first_free_run(5), Some(0));
        assert_eq!(bm.find_first_free_run(6), None);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut bm = BlockBitmap::new_all_free(200);
        bm.mark_occupied(0).unwrap();
        bm.mark_occupied(63).unwrap();
        bm.mark_occupied(64).unwrap();
        bm.mark_occupied(199).unwrap();

        let mut buf = vec![0u8; bm.encoded_bytes()];
        bm.encode(&mut buf).unwrap();
        let decoded = BlockBitmap::decode(&buf, 200).unwrap();
        assert_eq!(decoded.capacity(), 200);
        assert_eq!(decoded.free_count(), bm.free_count());
        for i in 0..200 {
            assert_eq!(decoded.is_free(i), bm.is_free(i));
        }
    }

    #[test]
    fn encode_size_mismatch_rejected() {
        let bm = BlockBitmap::new_all_free(100);
        let mut buf = vec![0u8; 1]; // wrong size
        assert_eq!(bm.encode(&mut buf), Err(BitmapError::EncodingSizeMismatch));
    }

    #[test]
    fn decode_size_mismatch_rejected() {
        let buf = vec![0u8; 7];
        assert_eq!(
            BlockBitmap::decode(&buf, 64),
            Err(BitmapError::EncodingSizeMismatch),
        );
    }

    #[test]
    fn decode_rejects_padding_bits() {
        // Capacity = 65 means bits [65..128] in word[1] must be zero
        // (canonical form). Hand-craft a buffer where bit 100
        // (word 1, bit 36) is set despite being outside the valid
        // range, and confirm decode rejects.
        let mut buf = vec![0u8; 16];
        // word[0] = all ones (every bit valid; bits 0..64).
        for byte in buf.iter_mut().take(8) {
            *byte = 0xFF;
        }
        // word[1] starts as all zeros; set bit 100 only.
        // 100 - 64 = 36. Byte 4 within word 1, bit 4 within that byte.
        buf[8 + 4] |= 1 << 4;
        let result = BlockBitmap::decode(&buf, 65);
        assert_eq!(result, Err(BitmapError::NonZeroPadding));
    }

    #[test]
    fn encode_to_blocks_roundtrip_partial_block() {
        // 200 bits = 25 bytes; fits in one 4 KiB block.
        let mut bm = BlockBitmap::new_all_free(200);
        bm.mark_occupied(0).unwrap();
        bm.mark_occupied(199).unwrap();
        let blocks = encode_to_blocks(&bm).unwrap();
        assert_eq!(blocks.len(), 1);
        let decoded = decode_from_blocks(&blocks, 200).unwrap();
        for i in 0..200 {
            assert_eq!(decoded.is_free(i), bm.is_free(i));
        }
    }

    #[test]
    fn encode_to_blocks_roundtrip_multiple_blocks() {
        // 1B blocks ÷ 64 bits/word = 16M words = 128 MiB = 32k blocks
        // of bitmap. Use a smaller but multi-block case: 50000 blocks
        // → ~6.25 KiB → 2 blocks.
        let cap = 50_000u64;
        let mut bm = BlockBitmap::new_all_free(cap);
        bm.mark_occupied(0).unwrap();
        bm.mark_occupied(40_000).unwrap();
        bm.mark_occupied(cap - 1).unwrap();
        let blocks = encode_to_blocks(&bm).unwrap();
        assert!(blocks.len() >= 2);
        let decoded = decode_from_blocks(&blocks, cap).unwrap();
        assert_eq!(decoded.free_count(), bm.free_count());
        assert!(decoded.is_occupied(0));
        assert!(decoded.is_occupied(40_000));
        assert!(decoded.is_occupied(cap - 1));
    }

    #[test]
    fn decode_from_blocks_rejects_unused_padding() {
        let bm = BlockBitmap::new_all_free(200);
        let mut blocks = encode_to_blocks(&bm).unwrap();
        // Last block has unused bytes past the encoded bitmap;
        // poke one.
        let last = blocks.last_mut().unwrap();
        last[BLOCK_SIZE - 1] = 0xFF;
        let result = decode_from_blocks(&blocks, 200);
        assert_eq!(result, Err(BitmapError::NonZeroPadding));
    }
}
