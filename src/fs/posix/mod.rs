// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! POSIX file storage backend.
//!
//! On-disk format specified by [ADR-029](../../../docs/adr/029-posix-file-storage-model.md);
//! this module is the reference reader/writer of that format. Sibling
//! to [`crate::fs::disk`] (the CambiObject backend); both are generic
//! over the [`crate::fs::block::BlockDevice`] trait so the format is
//! exercisable against `MemBlockDevice` in unit tests and against
//! `VirtioBlkDevice` at runtime.
//!
//! ## Structure
//!
//! - [`PosixFsBackend<B>`] — generic backend. Owns a `B: BlockDevice`
//!   and the in-memory mount state (currently just the superblock; the
//!   inode index lands in commit 4B, the block-allocation bitmap in
//!   ADR-029 step 5).
//! - Encoding helpers (`encode_superblock`, `classify_superblock`) are
//!   pure functions over byte buffers — host-testable.
//! - Same enum-dispatch posture as [ADR-003 § Divergence](../../../docs/adr/003-content-addressed-storage-and-identity.md);
//!   no trait objects in the hot path. The kernel-side global
//!   integration (path resolver, lock-hierarchy insertion) lands at
//!   ADR-029 § Migration Path step 10; this commit ships the backend
//!   as standalone-testable only.
//!
//! ## Canonical on-disk form
//!
//! Per ADR-029 § Divergence 1 (added alongside commit 4B), encoders
//! AND decoders enforce strict zero-fill on reserved bytes within
//! every block they write or read. Same logical record → same on-disk
//! bytes → same `header_checksum`. Future format extensions that use
//! reserved bytes are version bumps, not backward-compatible additions.

extern crate alloc;

use crate::fs::block::{Block, BlockDevice, BlockError, BLOCK_SIZE};

// ============================================================================
// Format identification
// ============================================================================

/// ARCHITECTURAL: superblock magic for the POSIX backend on-disk
/// format. Changing this is a new format family, not a version bump.
/// Mirrors `ARCOBJ_MAGIC` in the CambiObject backend (ADR-010).
pub const ARCPOSX_MAGIC: [u8; 8] = *b"ARCPOSX1";

/// ARCHITECTURAL: inode-header magic for an occupied slot. Absence (any
/// other 8 bytes, including all zeros) means the slot is free.
/// Commit point for inode-allocation visibility in v1 (the inode is
/// allocated iff the header magic equals this constant).
pub const ARCINOD_MAGIC_OCCUPIED: [u8; 8] = *b"ARCINOD1";

/// ARCHITECTURAL: POSIX on-disk format version. Mount rejects unknown
/// versions. Version 2 lands when the inode header layout grows
/// (PQ signature tail, ACL extension blocks, additional metadata).
pub const FORMAT_VERSION: u32 = 1;

// ============================================================================
// Region geometry
// ============================================================================
//
// LBA 0..1    Superblock                            (2 blocks = 8 KiB)
// LBA 2..     Inode region                          (capacity_inodes × 2 blocks)
//              inode i starts at LBA 2 + 2*i
// LBA k..     Block-allocation bitmap               (sized for capacity_blocks)
// LBA m..     Journal region                        (JOURNAL_BYTES)
// LBA n..     Data region                           (capacity_blocks × 1)
//
// Bitmap / journal / data regions are step-5+ scope; their LBAs are
// computed and stored in the superblock at format time so future
// mount logic doesn't need to re-derive layout from scratch.

/// ARCHITECTURAL: superblock header block LBA. ADR-029 § Decision 1.
pub const SUPERBLOCK_HEADER_LBA: u64 = 0;

/// ARCHITECTURAL: superblock reserved block LBA (zero-filled in v1;
/// reserved for ML-DSA signature tail per ADR-029 § Decision 1).
pub const SUPERBLOCK_RESERVED_LBA: u64 = 1;

/// ARCHITECTURAL: first inode header LBA. Inode `i` lives at
/// `INODE_REGION_LBA + BLOCKS_PER_INODE * i` per ADR-029 § Decision 1.
pub const INODE_REGION_LBA: u64 = 2;

/// ARCHITECTURAL: stride per inode (header block + reserved tail block)
/// per ADR-029 § Decision 1.
pub const BLOCKS_PER_INODE: u64 = 2;

/// SCAFFOLDING: 16 MiB metadata journal per ADR-029 § Decision 5.
/// Why: fixed-size circular log; ~1M records at § Decision 5 sizes
///      with checkpoint cadence (every 4 KiB or 100 ticks) bounding
///      steady-state usage well below capacity.
/// Replace when: observed flush-stall behavior under sustained
///      metadata churn per ADR-029 § Open Questions ("Journal
///      compaction strategy").
pub const JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// ARCHITECTURAL: journal region size in blocks (derived from
/// `JOURNAL_BYTES` and `BLOCK_SIZE`; tracks `JOURNAL_BYTES`).
pub const JOURNAL_BLOCKS: u64 = JOURNAL_BYTES / BLOCK_SIZE as u64;

/// SCAFFOLDING: declared-inode-capacity ceiling. Mount rejects above.
/// Why: per ADR-029 § Architecture — Win-compat endgame is low
///      millions of files per personal machine; 4M gives ~4× headroom.
///      On-disk cost at full capacity is 32 GiB inode region (well
///      above any v1 deployment).
/// Replace when: a deployment legitimately wants >4M inodes; bound
///      rises or per-tier policy carries a tier-specific ceiling
///      (analogous to ADR-008 / ADR-009).
pub const MAX_INODES_ON_DISK: u64 = 4_194_304;

/// SCAFFOLDING: declared-block-capacity ceiling. Mount rejects above.
/// Why: per ADR-029 § Architecture — 1B blocks × 4 KiB = 4 TiB max
///      partition. Bitmap region at full capacity is 1 GiB (a
///      fraction of the data region).
/// Replace when: a v1+ deployment wants >4 TiB per partition;
///      tiered/sparse bitmap representations land first.
pub const MAX_BLOCKS_ON_DISK: u64 = 1_073_741_824;

// ============================================================================
// Superblock layout (header block, LBA 0)
// ============================================================================
//
// On-disk byte offsets in the 4096-byte header block. Order matches
// ADR-029 § Decision 1's layout description. Reserved bytes between
// the last field and the checksum (offsets SB_LAST_FIELD_END..
// SB_OFF_CHECKSUM) are strictly zero per § Divergence 1.

const SB_OFF_MAGIC: usize = 0;
const SB_OFF_VERSION: usize = 8;
const SB_OFF_CAPACITY_INODES: usize = 12;
const SB_OFF_CAPACITY_BLOCKS: usize = 20;
const SB_OFF_INODE_REGION_LBA: usize = 28;
const SB_OFF_BITMAP_REGION_LBA: usize = 36;
const SB_OFF_JOURNAL_REGION_LBA: usize = 44;
const SB_OFF_DATA_REGION_LBA: usize = 52;
const SB_OFF_JOURNAL_CAPACITY_BYTES: usize = 60;
const SB_OFF_LAST_CHECKPOINT_OFFSET: usize = 68;
const SB_OFF_GENERATION: usize = 76;
const SB_OFF_CREATED_AT: usize = 84;
const SB_LAST_FIELD_END: usize = 92;
const SB_OFF_CHECKSUM: usize = BLOCK_SIZE - 8;
const SB_CHECKSUM_COVER_END: usize = SB_OFF_CHECKSUM;

// ============================================================================
// Pure helpers
// ============================================================================

/// First 8 bytes of `blake3(data)`. Same shape as the CambiObject
/// backend's header_checksum (accidental-corruption detection only;
/// adversarial integrity is out of scope for POSIX-shape working
/// state per ADR-029 § Threat Model).
fn checksum8(data: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&blake3::hash(data).as_bytes()[0..8]);
    out
}

// Constant-offset little-endian readers; same shape and rationale as
// the helpers in `crate::fs::disk` (no panics, no unwrap, every offset
// statically below BLOCK_SIZE).

#[inline]
const fn read_u32_le(buf: &Block, offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
    ])
}

#[inline]
const fn read_u64_le(buf: &Block, offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
        buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7],
    ])
}

/// LBA of the header block for inode `slot`. ADR-029 § Decision 1:
/// inode `i` starts at `INODE_REGION_LBA + BLOCKS_PER_INODE * i`.
#[inline]
pub const fn inode_header_lba(slot: u64) -> u64 {
    INODE_REGION_LBA + BLOCKS_PER_INODE * slot
}

// ============================================================================
// Superblock encode / decode
// ============================================================================

/// In-memory superblock representation. On-disk magic + checksum are
/// not carried — they are reconstituted at encode time and validated
/// at decode time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    pub capacity_inodes: u64,
    pub capacity_blocks: u64,
    pub inode_region_lba: u64,
    pub bitmap_region_lba: u64,
    pub journal_region_lba: u64,
    pub data_region_lba: u64,
    pub journal_capacity_bytes: u64,
    pub last_checkpoint_offset: u64,
    pub generation: u64,
    pub created_at: u64,
}

/// Result of inspecting a candidate superblock block. Mirrors the
/// `SuperblockState` discriminant from `crate::fs::disk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuperblockState {
    /// Header block is all zeros — disk is blank, format on first use.
    Blank,
    /// Header block parsed cleanly: magic + version + checksum + strict
    /// zero-padding on reserved bytes all hold.
    Valid(Superblock),
    /// Header block is non-zero but does not pass validation. Mount
    /// refuses to proceed; the disk is either a different format or
    /// has been damaged.
    Corrupt,
}

/// Encode the superblock header block. Caller writes the result to
/// `SUPERBLOCK_HEADER_LBA`; the reserved block (`SUPERBLOCK_RESERVED_LBA`)
/// must be written separately as all-zeros.
pub fn encode_superblock(buf: &mut Block, sb: &Superblock) {
    buf.fill(0);
    buf[SB_OFF_MAGIC..SB_OFF_MAGIC + 8].copy_from_slice(&ARCPOSX_MAGIC);
    buf[SB_OFF_VERSION..SB_OFF_VERSION + 4]
        .copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf[SB_OFF_CAPACITY_INODES..SB_OFF_CAPACITY_INODES + 8]
        .copy_from_slice(&sb.capacity_inodes.to_le_bytes());
    buf[SB_OFF_CAPACITY_BLOCKS..SB_OFF_CAPACITY_BLOCKS + 8]
        .copy_from_slice(&sb.capacity_blocks.to_le_bytes());
    buf[SB_OFF_INODE_REGION_LBA..SB_OFF_INODE_REGION_LBA + 8]
        .copy_from_slice(&sb.inode_region_lba.to_le_bytes());
    buf[SB_OFF_BITMAP_REGION_LBA..SB_OFF_BITMAP_REGION_LBA + 8]
        .copy_from_slice(&sb.bitmap_region_lba.to_le_bytes());
    buf[SB_OFF_JOURNAL_REGION_LBA..SB_OFF_JOURNAL_REGION_LBA + 8]
        .copy_from_slice(&sb.journal_region_lba.to_le_bytes());
    buf[SB_OFF_DATA_REGION_LBA..SB_OFF_DATA_REGION_LBA + 8]
        .copy_from_slice(&sb.data_region_lba.to_le_bytes());
    buf[SB_OFF_JOURNAL_CAPACITY_BYTES..SB_OFF_JOURNAL_CAPACITY_BYTES + 8]
        .copy_from_slice(&sb.journal_capacity_bytes.to_le_bytes());
    buf[SB_OFF_LAST_CHECKPOINT_OFFSET..SB_OFF_LAST_CHECKPOINT_OFFSET + 8]
        .copy_from_slice(&sb.last_checkpoint_offset.to_le_bytes());
    buf[SB_OFF_GENERATION..SB_OFF_GENERATION + 8]
        .copy_from_slice(&sb.generation.to_le_bytes());
    buf[SB_OFF_CREATED_AT..SB_OFF_CREATED_AT + 8]
        .copy_from_slice(&sb.created_at.to_le_bytes());
    // Bytes SB_LAST_FIELD_END..SB_OFF_CHECKSUM are already zero from
    // the `buf.fill(0)` above; the canonical-form invariant holds.
    let cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
    buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8].copy_from_slice(&cs);
}

/// Classify a candidate superblock header block. Returns `Blank` on
/// all-zero magic, `Corrupt` on any validation failure (wrong magic,
/// checksum mismatch, non-zero reserved bytes), `Valid(...)` on full
/// canonical-form pass.
pub fn classify_superblock(buf: &Block) -> SuperblockState {
    // Blank detection: all-zero magic. On a freshly-provisioned disk
    // every byte is zero, including the checksum field; we treat that
    // as the "format on first use" signal.
    let magic = &buf[SB_OFF_MAGIC..SB_OFF_MAGIC + 8];
    if magic.iter().all(|&b| b == 0) {
        return SuperblockState::Blank;
    }
    if magic != ARCPOSX_MAGIC {
        return SuperblockState::Corrupt;
    }
    // Strict zero-fill on reserved bytes (canonical-form invariant).
    if buf[SB_LAST_FIELD_END..SB_OFF_CHECKSUM].iter().any(|&b| b != 0) {
        return SuperblockState::Corrupt;
    }
    // Checksum validation.
    let expected_cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
    let on_disk_cs = &buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8];
    if on_disk_cs != expected_cs {
        return SuperblockState::Corrupt;
    }
    let version = read_u32_le(buf, SB_OFF_VERSION);
    if version != FORMAT_VERSION {
        return SuperblockState::Corrupt;
    }
    SuperblockState::Valid(Superblock {
        capacity_inodes: read_u64_le(buf, SB_OFF_CAPACITY_INODES),
        capacity_blocks: read_u64_le(buf, SB_OFF_CAPACITY_BLOCKS),
        inode_region_lba: read_u64_le(buf, SB_OFF_INODE_REGION_LBA),
        bitmap_region_lba: read_u64_le(buf, SB_OFF_BITMAP_REGION_LBA),
        journal_region_lba: read_u64_le(buf, SB_OFF_JOURNAL_REGION_LBA),
        data_region_lba: read_u64_le(buf, SB_OFF_DATA_REGION_LBA),
        journal_capacity_bytes: read_u64_le(buf, SB_OFF_JOURNAL_CAPACITY_BYTES),
        last_checkpoint_offset: read_u64_le(buf, SB_OFF_LAST_CHECKPOINT_OFFSET),
        generation: read_u64_le(buf, SB_OFF_GENERATION),
        created_at: read_u64_le(buf, SB_OFF_CREATED_AT),
    })
}

// ============================================================================
// Errors
// ============================================================================

/// POSIX backend error type. Returned by `PosixFsBackend` methods.
/// Wraps `BlockError` for transport-layer failures; carries typed
/// variants for format-level invariants per ADR-029.
///
/// Inode-format errors (the typed variants enumerated in commit 4B)
/// surface as `FsError::InodeFormat`. Step 4 only exposes the
/// non-inode variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// Underlying block device reported an error.
    BlockError(BlockError),
    /// Superblock failed validation (wrong magic, checksum mismatch,
    /// non-zero reserved bytes, unknown version, declared capacities
    /// exceeding `MAX_INODES_ON_DISK` / `MAX_BLOCKS_ON_DISK`).
    InvalidSuperblock,
    /// Device is too small to hold even the superblock plus a single
    /// inode-and-bitmap region.
    DeviceTooSmall,
    /// `format()` called with `desired_capacity_inodes == 0`.
    InvalidCapacity,
}

impl From<BlockError> for FsError {
    fn from(e: BlockError) -> Self {
        FsError::BlockError(e)
    }
}

// ============================================================================
// PosixFsBackend
// ============================================================================

/// POSIX file storage backend. Generic over `B: BlockDevice` so the
/// format is exercisable against `MemBlockDevice` in tests and against
/// `VirtioBlkDevice` at runtime.
///
/// Commit 4A holds only the superblock; the inode index lands in
/// commit 4B and the block-allocation bitmap in ADR-029 step 5.
pub struct PosixFsBackend<B: BlockDevice> {
    device: B,
    superblock: Superblock,
}

impl<B: BlockDevice> PosixFsBackend<B> {
    /// Open an existing backend, or format a blank device. Returns
    /// `InvalidSuperblock` on a populated-but-corrupt disk; this is
    /// the kernel's signal that the operator must intervene
    /// (re-format with `format()`, or attach a known-good replacement).
    pub fn open_or_format(
        mut device: B,
        desired_capacity_inodes: u64,
        desired_capacity_blocks: u64,
        created_at: u64,
    ) -> Result<Self, FsError> {
        let mut sb_buf = [0u8; BLOCK_SIZE];
        device.read_block(SUPERBLOCK_HEADER_LBA, &mut sb_buf)?;

        match classify_superblock(&sb_buf) {
            SuperblockState::Blank => Self::format(
                device,
                desired_capacity_inodes,
                desired_capacity_blocks,
                created_at,
            ),
            SuperblockState::Valid(sb) => Self::mount(device, sb),
            SuperblockState::Corrupt => Err(FsError::InvalidSuperblock),
        }
    }

    /// Format a fresh backend onto `device`. Writes the superblock
    /// header + reserved block; the inode region is left zero (which
    /// for our format means "all inodes free" since the magic check
    /// is the occupancy signal).
    ///
    /// Bitmap, journal, and data regions are sized at format time but
    /// not initialized — they're zero-filled when format runs against
    /// a blank device, and the allocator / journal logic (step 5) will
    /// treat the zero state as "all free / empty journal" on mount.
    pub fn format(
        mut device: B,
        desired_capacity_inodes: u64,
        desired_capacity_blocks: u64,
        created_at: u64,
    ) -> Result<Self, FsError> {
        if desired_capacity_inodes == 0 || desired_capacity_blocks == 0 {
            return Err(FsError::InvalidCapacity);
        }
        if desired_capacity_inodes > MAX_INODES_ON_DISK
            || desired_capacity_blocks > MAX_BLOCKS_ON_DISK
        {
            return Err(FsError::InvalidCapacity);
        }

        let dev_blocks = device.capacity_blocks();
        // Minimum sanity: room for the 2-block superblock plus at
        // least the requested inode region plus the journal plus one
        // bitmap block plus the data region. Computed below; we re-
        // check after sizing because clamping the capacity may make
        // an otherwise-too-small device fit.
        let bitmap_bits = desired_capacity_blocks;
        let bitmap_blocks = bitmap_bits.div_ceil(8 * BLOCK_SIZE as u64);
        let inode_region_blocks = desired_capacity_inodes * BLOCKS_PER_INODE;

        let inode_region_lba = INODE_REGION_LBA;
        let bitmap_region_lba = inode_region_lba + inode_region_blocks;
        let journal_region_lba = bitmap_region_lba + bitmap_blocks;
        let data_region_lba = journal_region_lba + JOURNAL_BLOCKS;

        let required_blocks = data_region_lba + desired_capacity_blocks;
        if dev_blocks < required_blocks {
            return Err(FsError::DeviceTooSmall);
        }

        let sb = Superblock {
            capacity_inodes: desired_capacity_inodes,
            capacity_blocks: desired_capacity_blocks,
            inode_region_lba,
            bitmap_region_lba,
            journal_region_lba,
            data_region_lba,
            journal_capacity_bytes: JOURNAL_BYTES,
            last_checkpoint_offset: 0,
            generation: 1,
            created_at,
        };

        let mut sb_buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut sb_buf, &sb);
        device.write_block(SUPERBLOCK_HEADER_LBA, &sb_buf)?;

        // Reserved block is always all-zero in v1. On a freshly-
        // provisioned disk it already is; on reformat we overwrite to
        // re-establish the canonical-form invariant.
        let zero_block = [0u8; BLOCK_SIZE];
        device.write_block(SUPERBLOCK_RESERVED_LBA, &zero_block)?;

        device.flush()?;

        Ok(Self { device, superblock: sb })
    }

    /// Mount an existing backend. Validates the declared geometry
    /// against the device's actual size and bumps the superblock
    /// generation counter (the same anti-stale-snapshot convention
    /// used by the CambiObject backend per ADR-010).
    fn mount(mut device: B, sb: Superblock) -> Result<Self, FsError> {
        if sb.capacity_inodes == 0
            || sb.capacity_inodes > MAX_INODES_ON_DISK
            || sb.capacity_blocks == 0
            || sb.capacity_blocks > MAX_BLOCKS_ON_DISK
        {
            return Err(FsError::InvalidSuperblock);
        }
        if sb.inode_region_lba != INODE_REGION_LBA {
            return Err(FsError::InvalidSuperblock);
        }
        // Sanity-check region ordering; corrupt geometry rejected.
        if !(sb.inode_region_lba < sb.bitmap_region_lba
            && sb.bitmap_region_lba < sb.journal_region_lba
            && sb.journal_region_lba < sb.data_region_lba)
        {
            return Err(FsError::InvalidSuperblock);
        }
        let required_blocks = sb.data_region_lba + sb.capacity_blocks;
        if device.capacity_blocks() < required_blocks {
            return Err(FsError::InvalidSuperblock);
        }

        // Bump generation so stale media swaps are detectable. The
        // step-5 journal-replay path will sit between this generation
        // bump and the inode-region scan (commit 4B).
        let next_sb = Superblock {
            generation: sb.generation.wrapping_add(1),
            ..sb
        };
        let mut sb_buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut sb_buf, &next_sb);
        device.write_block(SUPERBLOCK_HEADER_LBA, &sb_buf)?;
        device.flush()?;

        Ok(Self { device, superblock: next_sb })
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Consume the backend and return the underlying device. Test-only
    /// escape hatch for reboot-cycle tests (mirrors `DiskObjectStore::into_device`).
    #[cfg(test)]
    pub fn into_device(self) -> B {
        self.device
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::block::MemBlockDevice;

    /// Geometry suitable for the small in-memory devices the tests use:
    /// 4 inodes, 32 blocks of data. Total device blocks needed:
    /// 2 (superblock) + 4 * 2 (inodes) + bitmap (1) + journal (JOURNAL_BLOCKS)
    /// + 32 (data) = JOURNAL_BLOCKS + 43.
    fn test_dev_blocks() -> u64 {
        JOURNAL_BLOCKS + 43
    }

    fn fresh_backend() -> PosixFsBackend<MemBlockDevice> {
        let device = MemBlockDevice::new(test_dev_blocks());
        PosixFsBackend::open_or_format(device, 4, 32, 12345).unwrap()
    }

    #[test]
    fn superblock_roundtrip() {
        let sb = Superblock {
            capacity_inodes: 4,
            capacity_blocks: 32,
            inode_region_lba: 2,
            bitmap_region_lba: 10,
            journal_region_lba: 11,
            data_region_lba: 11 + JOURNAL_BLOCKS,
            journal_capacity_bytes: JOURNAL_BYTES,
            last_checkpoint_offset: 0,
            generation: 1,
            created_at: 999,
        };
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, &sb);
        match classify_superblock(&buf) {
            SuperblockState::Valid(decoded) => assert_eq!(decoded, sb),
            other => panic!("expected Valid, got {:?}", other),
        }
    }

    #[test]
    fn superblock_blank_is_detected() {
        let buf = [0u8; BLOCK_SIZE];
        assert_eq!(classify_superblock(&buf), SuperblockState::Blank);
    }

    #[test]
    fn superblock_wrong_magic_is_corrupt() {
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..8].copy_from_slice(b"NOTARCFS");
        assert_eq!(classify_superblock(&buf), SuperblockState::Corrupt);
    }

    #[test]
    fn superblock_bad_checksum_is_corrupt() {
        let sb = Superblock {
            capacity_inodes: 4,
            capacity_blocks: 32,
            inode_region_lba: 2,
            bitmap_region_lba: 10,
            journal_region_lba: 11,
            data_region_lba: 11 + JOURNAL_BLOCKS,
            journal_capacity_bytes: JOURNAL_BYTES,
            last_checkpoint_offset: 0,
            generation: 1,
            created_at: 999,
        };
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, &sb);
        // Flip a byte in the checksum.
        buf[SB_OFF_CHECKSUM] ^= 0xFF;
        assert_eq!(classify_superblock(&buf), SuperblockState::Corrupt);
    }

    #[test]
    fn superblock_nonzero_reserved_is_corrupt() {
        // Encode a valid superblock, then poke a byte in the reserved
        // region and recompute the checksum so the only failure mode is
        // the strict-zero-padding check.
        let sb = Superblock {
            capacity_inodes: 4,
            capacity_blocks: 32,
            inode_region_lba: 2,
            bitmap_region_lba: 10,
            journal_region_lba: 11,
            data_region_lba: 11 + JOURNAL_BLOCKS,
            journal_capacity_bytes: JOURNAL_BYTES,
            last_checkpoint_offset: 0,
            generation: 1,
            created_at: 999,
        };
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, &sb);
        // Place a non-zero byte deep in the reserved region.
        buf[SB_LAST_FIELD_END + 100] = 0x42;
        // Recompute the checksum so the only violated invariant is the
        // reserved-zero rule.
        let cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
        buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(classify_superblock(&buf), SuperblockState::Corrupt);
    }

    #[test]
    fn superblock_wrong_version_is_corrupt() {
        let sb = Superblock {
            capacity_inodes: 4,
            capacity_blocks: 32,
            inode_region_lba: 2,
            bitmap_region_lba: 10,
            journal_region_lba: 11,
            data_region_lba: 11 + JOURNAL_BLOCKS,
            journal_capacity_bytes: JOURNAL_BYTES,
            last_checkpoint_offset: 0,
            generation: 1,
            created_at: 999,
        };
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, &sb);
        // Overwrite the version field with a future version and recompute
        // the checksum.
        buf[SB_OFF_VERSION..SB_OFF_VERSION + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        let cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
        buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(classify_superblock(&buf), SuperblockState::Corrupt);
    }

    #[test]
    fn format_then_mount_roundtrip() {
        let mut backend = fresh_backend();
        let sb_before = *backend.superblock();
        let dev = backend.into_device();
        // Re-open: should mount, bump generation, succeed.
        let backend2 = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        let sb_after = *backend2.superblock();
        // All fields preserved except generation, which is bumped.
        assert_eq!(sb_after.capacity_inodes, sb_before.capacity_inodes);
        assert_eq!(sb_after.capacity_blocks, sb_before.capacity_blocks);
        assert_eq!(sb_after.created_at, sb_before.created_at);
        assert_eq!(sb_after.generation, sb_before.generation + 1);
    }

    #[test]
    fn format_rejects_too_small_device() {
        let small_dev = MemBlockDevice::new(4);
        let result = PosixFsBackend::open_or_format(small_dev, 4, 32, 0);
        assert!(matches!(result, Err(FsError::DeviceTooSmall)));
    }

    #[test]
    fn format_rejects_zero_capacity() {
        let dev = MemBlockDevice::new(test_dev_blocks());
        let result = PosixFsBackend::format(dev, 0, 32, 0);
        assert!(matches!(result, Err(FsError::InvalidCapacity)));
    }

    #[test]
    fn open_or_format_rejects_corrupt_disk() {
        let mut dev = MemBlockDevice::new(test_dev_blocks());
        // Write garbage at LBA 0 — non-zero magic that isn't ARCPOSX_MAGIC.
        let mut bad = [0u8; BLOCK_SIZE];
        bad[..8].copy_from_slice(b"DEADBEEF");
        dev.write_block(SUPERBLOCK_HEADER_LBA, &bad).unwrap();
        let result = PosixFsBackend::open_or_format(dev, 4, 32, 0);
        assert!(matches!(result, Err(FsError::InvalidSuperblock)));
    }

    #[test]
    fn inode_header_lba_geometry() {
        // Slot 0 starts at LBA 2; subsequent slots at +2.
        assert_eq!(inode_header_lba(0), 2);
        assert_eq!(inode_header_lba(1), 4);
        assert_eq!(inode_header_lba(2), 6);
        assert_eq!(inode_header_lba(1000), 2 + 2 * 1000);
    }
}
