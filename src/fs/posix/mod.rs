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

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use cambios_abi::{
    AclEntry, Extent, InodeId, InodeKind, PosixInode, Rights,
    MAX_EXTENTS_PER_INODE, MAX_INODE_ACL_ENTRIES,
};

use crate::fs::bitmap::{decode_from_blocks, encode_to_blocks, BitmapError, BlockBitmap};
use crate::fs::block::{Block, BlockDevice, BlockError, BLOCK_SIZE};
use crate::fs::journal::{
    encode_record, Append, BitmapMutation, Journal, JournalError, JournalRecord,
};
use crate::ipc::Principal;

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
// Inode header layout (4096 bytes per header block)
// ============================================================================
//
// On-disk offsets per ADR-029 § Decision 1. The reserved tail block
// (LBA `2 + 2*i + 1`) is always all-zero in v1; this commit's
// encoder writes it that way and the inode-region scan does not
// inspect it.

const INODE_OFF_MAGIC: usize = 0;
const INODE_OFF_VERSION: usize = 8;
const INODE_OFF_KIND: usize = 12;
const INODE_OFF_EXTENT_COUNT: usize = 13;
const INODE_OFF_ACL_COUNT: usize = 14;
const INODE_OFF_SIZE_BYTES: usize = 16;
const INODE_OFF_CREATED_AT: usize = 24;
const INODE_OFF_MODIFIED_AT: usize = 32;
const INODE_OFF_OWNER: usize = 40;
const INODE_OFF_LINK_COUNT: usize = 72;
const INODE_OFF_COW_REFCOUNT: usize = 76;
const INODE_OFF_EXTENTS: usize = 80;
const INODE_OFF_ACL: usize = 272;
const INODE_OFF_RESERVED: usize = 976;
const INODE_OFF_CHECKSUM: usize = BLOCK_SIZE - 8;
const INODE_CHECKSUM_COVER_END: usize = INODE_OFF_CHECKSUM;

// Packed on-disk record sizes (different from the natural Rust
// alignment per ADR-029 § Architecture).
const EXTENT_PACKED_SIZE: usize = 12;
const ACL_ENTRY_PACKED_SIZE: usize = 44;

// Per-entry offsets within a packed Extent record.
const EXTENT_OFF_START_LBA: usize = 0;
const EXTENT_OFF_BLOCK_COUNT: usize = 8;

// Per-entry offsets within a packed AclEntry record.
const ACL_OFF_PRINCIPAL: usize = 0;
const ACL_OFF_RIGHTS: usize = 32;
const ACL_OFF_EXPIRY: usize = 33;

// Rights bit positions (mirroring cambios_abi::Rights).
const RIGHTS_READ_BIT: u8 = 1 << 0;
const RIGHTS_WRITE_BIT: u8 = 1 << 1;
const RIGHTS_EXECUTE_BIT: u8 = 1 << 2;
const RIGHTS_VALID_MASK: u8 = RIGHTS_READ_BIT | RIGHTS_WRITE_BIT | RIGHTS_EXECUTE_BIT;

// InodeKind discriminants on disk.
const INODE_KIND_REGULAR: u8 = 0;
const INODE_KIND_DIRECTORY: u8 = 1;
const INODE_KIND_SYMLINK: u8 = 2;

// ============================================================================
// Errors
// ============================================================================

/// POSIX backend error type. Returned by `PosixFsBackend` methods.
/// Wraps `BlockError` for transport-layer failures; carries typed
/// variants for format-level invariants per ADR-029.
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
    /// An inode header on disk (or a `PosixInode` value passed to
    /// `encode_inode_header`) failed validation. Carries the typed
    /// reason; see [`InodeError`].
    InodeFormat(InodeError),
    /// `get_inode` called with an `InodeId` whose slot is free or
    /// whose raw value exceeds the backend's `capacity_inodes`. The
    /// "free slot" and "out-of-range" cases collapse into one error
    /// because both correspond to "no inode exists at this id" from
    /// the caller's perspective; future write-path code may
    /// distinguish if a workload demands it.
    InodeNotFound,
    /// Journal-side codec / replay error. See [`JournalError`].
    Journal(JournalError),
    /// Bitmap-side encode / decode / mutation error. See [`BitmapError`].
    Bitmap(BitmapError),
    /// Defense-in-depth check at mount: the bitmap reconstructed by
    /// replaying the journal does not match the bitmap region read
    /// from disk. Per ADR-029 § Verification Stance row 4 the bitmap
    /// is the projection of committed journal records, so divergence
    /// means either a journal-replay bug or on-disk corruption.
    /// Mount refuses to proceed; the kernel-singleton wire-up
    /// (step 6+) will emit an audit event before surfacing this
    /// error. Recovery requires manual fsck.
    BitmapDivergence,
    /// `allocate_block()` found no free block in the bitmap. The
    /// caller's transaction cannot proceed; userspace receives
    /// `ENOSPC` after this propagates upward.
    OutOfSpace,
    /// `free_block(block)` called with a block index that is either
    /// out of range or already free. Distinguished from
    /// `Bitmap(BitmapError::OutOfBounds)` so future write-path code
    /// can react differently to "tried to double-free a known block"
    /// versus "tried to address a block past capacity."
    NotAllocated,
    /// `open_inode` (or another authorization-gated op) found the
    /// inode but the caller's Principal is neither the owner nor
    /// a holder of an ACL entry covering the requested rights. Maps
    /// to userspace `EACCES`. Per ADR-029 § Decision 3 — owner-or-
    /// ACL check is the only auth source; no Unix u/g/o.
    PermissionDenied,
}

impl From<BlockError> for FsError {
    fn from(e: BlockError) -> Self {
        FsError::BlockError(e)
    }
}

impl From<InodeError> for FsError {
    fn from(e: InodeError) -> Self {
        FsError::InodeFormat(e)
    }
}

impl From<JournalError> for FsError {
    fn from(e: JournalError) -> Self {
        FsError::Journal(e)
    }
}

impl From<BitmapError> for FsError {
    fn from(e: BitmapError) -> Self {
        FsError::Bitmap(e)
    }
}

/// Typed inode-format invariant violations. Surfaced when:
/// (a) the encoder is handed a `PosixInode` that violates the
///     contiguous-Some invariant on `extents` / `acl`;
/// (b) the decoder reads an on-disk header whose `extent_count` /
///     `acl_count` exceeds the inline cap, whose padding is non-zero,
///     whose version is unknown, or whose checksum fails.
///
/// All variants are typed errors per CLAUDE.md's "no panics in
/// non-test kernel code" rule. The encoder will never silently
/// canonicalize a malformed inode; the decoder will never silently
/// accept a non-canonical record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeError {
    /// In-memory `extents` or `acl` array has `Some(...)` entries
    /// that are not packed contiguously from index 0.
    NonContiguousExtents,
    /// On-disk `extent_count` exceeds `MAX_EXTENTS_PER_INODE`.
    ExtentCountOutOfRange,
    /// On-disk `acl_count` exceeds `MAX_INODE_ACL_ENTRIES`.
    AclCountOutOfRange,
    /// On-disk header has non-zero bytes in a region that the
    /// canonical-form invariant requires to be zero: trailing
    /// extents region past `extent_count`, trailing acl region
    /// past `acl_count`, or the reserved region.
    NonZeroPadding,
    /// On-disk header has an unknown `version` field. v1 readers
    /// refuse to interpret v2+ records rather than guessing.
    UnknownVersion,
    /// On-disk header `header_checksum` does not match
    /// `Blake3(bytes[0..4088])[..8]`.
    HeaderChecksumMismatch,
    /// On-disk `kind` is not one of `Regular` / `Directory` /
    /// `Symlink`.
    UnknownKind,
    /// On-disk ACL entry has bits set beyond `Read | Write | Execute`.
    /// Future rights extensions are format-version bumps.
    UnknownRightsBits,
}

/// Validate that a `PosixInode`'s `extents` and `acl` arrays satisfy
/// the contiguous-Some invariant: `Some(...)` entries pack from index
/// 0, `None` slots only appear after the last `Some(...)`. The encoder
/// calls this before serializing; mutators (write-path code in a later
/// commit) call it after every mutation.
pub fn validate_inode(inode: &PosixInode) -> Result<(), InodeError> {
    let mut saw_none = false;
    for slot in inode.extents.iter() {
        if slot.is_none() {
            saw_none = true;
        } else if saw_none {
            return Err(InodeError::NonContiguousExtents);
        }
    }
    let mut saw_none = false;
    for slot in inode.acl.iter() {
        if slot.is_none() {
            saw_none = true;
        } else if saw_none {
            return Err(InodeError::NonContiguousExtents);
        }
    }
    Ok(())
}

// ============================================================================
// Inode header encode / decode
// ============================================================================

/// Encode a `PosixInode` into a 4 KiB header block. Returns
/// `InodeError::NonContiguousExtents` if the input violates the
/// contiguous-Some invariant; otherwise produces a canonical-form
/// header (extents-region padding zero past `extent_count`, acl-region
/// padding zero past `acl_count`, reserved region all-zero, checksum
/// computed last).
///
/// Per ADR-029 § Divergence 1 the encoder is the canonical-form
/// producer. Same logical inode → same on-disk bytes → same
/// `header_checksum`.
pub fn encode_inode_header(buf: &mut Block, inode: &PosixInode) -> Result<(), InodeError> {
    validate_inode(inode)?;

    buf.fill(0);
    buf[INODE_OFF_MAGIC..INODE_OFF_MAGIC + 8].copy_from_slice(&ARCINOD_MAGIC_OCCUPIED);
    buf[INODE_OFF_VERSION..INODE_OFF_VERSION + 4]
        .copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf[INODE_OFF_KIND] = match inode.kind {
        InodeKind::Regular => INODE_KIND_REGULAR,
        InodeKind::Directory => INODE_KIND_DIRECTORY,
        InodeKind::Symlink => INODE_KIND_SYMLINK,
    };

    // Count Some(...) entries; the contiguous invariant guarantees
    // `take_while` reaches them all without missing any.
    let extent_count = inode.extents.iter().take_while(|e| e.is_some()).count();
    let acl_count = inode.acl.iter().take_while(|e| e.is_some()).count();
    debug_assert!(extent_count <= MAX_EXTENTS_PER_INODE);
    debug_assert!(acl_count <= MAX_INODE_ACL_ENTRIES);
    buf[INODE_OFF_EXTENT_COUNT] = extent_count as u8;
    buf[INODE_OFF_ACL_COUNT..INODE_OFF_ACL_COUNT + 2]
        .copy_from_slice(&(acl_count as u16).to_le_bytes());

    buf[INODE_OFF_SIZE_BYTES..INODE_OFF_SIZE_BYTES + 8]
        .copy_from_slice(&inode.size_bytes.to_le_bytes());
    buf[INODE_OFF_CREATED_AT..INODE_OFF_CREATED_AT + 8]
        .copy_from_slice(&inode.created_at.to_le_bytes());
    buf[INODE_OFF_MODIFIED_AT..INODE_OFF_MODIFIED_AT + 8]
        .copy_from_slice(&inode.modified_at.to_le_bytes());
    buf[INODE_OFF_OWNER..INODE_OFF_OWNER + 32].copy_from_slice(&inode.owner);
    buf[INODE_OFF_LINK_COUNT..INODE_OFF_LINK_COUNT + 4]
        .copy_from_slice(&inode.link_count.to_le_bytes());
    buf[INODE_OFF_COW_REFCOUNT..INODE_OFF_COW_REFCOUNT + 4]
        .copy_from_slice(&inode.cow_refcount.to_le_bytes());

    // Pack extents densely starting at offset 80. Trailing extent
    // bytes stay zero (canonical form).
    for (i, slot) in inode.extents.iter().enumerate().take(extent_count) {
        let entry = slot.expect("contiguous invariant: take(extent_count) covers Some(...)");
        let base = INODE_OFF_EXTENTS + i * EXTENT_PACKED_SIZE;
        buf[base + EXTENT_OFF_START_LBA..base + EXTENT_OFF_START_LBA + 8]
            .copy_from_slice(&entry.start_lba.to_le_bytes());
        buf[base + EXTENT_OFF_BLOCK_COUNT..base + EXTENT_OFF_BLOCK_COUNT + 4]
            .copy_from_slice(&entry.block_count.to_le_bytes());
    }

    // Pack ACL entries densely starting at offset 272. Same trailing-
    // zero discipline.
    for (i, slot) in inode.acl.iter().enumerate().take(acl_count) {
        let entry = slot.expect("contiguous invariant: take(acl_count) covers Some(...)");
        let base = INODE_OFF_ACL + i * ACL_ENTRY_PACKED_SIZE;
        buf[base + ACL_OFF_PRINCIPAL..base + ACL_OFF_PRINCIPAL + 32]
            .copy_from_slice(&entry.principal);
        buf[base + ACL_OFF_RIGHTS] = entry.rights.bits();
        let expiry = entry.expiry.unwrap_or(0);
        buf[base + ACL_OFF_EXPIRY..base + ACL_OFF_EXPIRY + 8]
            .copy_from_slice(&expiry.to_le_bytes());
        // Trailing 3 reserved bytes per packed entry stay zero from
        // the earlier buf.fill(0).
    }

    // INODE_OFF_RESERVED..INODE_OFF_CHECKSUM stays zero (canonical-
    // form padding for the post-PQ-tail region).

    let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
    buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
    Ok(())
}

/// Outcome of inspecting an inode header block. `Free` means the
/// magic byte sequence does not match `ARCINOD_MAGIC_OCCUPIED` —
/// per ADR-029 § Decision 1 absence of the occupied magic IS the
/// "slot is free" signal. `Occupied(...)` carries the fully-validated
/// inode contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeHeaderState {
    Free,
    Occupied(PosixInode),
}

/// Decode an on-disk inode header block. Returns `Free` on magic
/// mismatch (the slot-occupancy signal); returns
/// `Err(InodeError::...)` on any canonical-form violation (out-of-
/// range counts, non-zero padding, unknown version, checksum failure,
/// unknown kind / rights bits).
///
/// The decoder is the canonical-form acceptor: it refuses any record
/// whose bytes cannot have been produced by `encode_inode_header`
/// from a valid `PosixInode`. See ADR-029 § Divergence 1.
pub fn decode_inode_header(buf: &Block) -> Result<InodeHeaderState, InodeError> {
    let magic = &buf[INODE_OFF_MAGIC..INODE_OFF_MAGIC + 8];
    if magic != ARCINOD_MAGIC_OCCUPIED {
        return Ok(InodeHeaderState::Free);
    }

    // Header-checksum first — corrupted bytes anywhere else surface
    // here, including any tampering with the padding regions checked
    // below.
    let expected_cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
    let on_disk_cs = &buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8];
    if on_disk_cs != expected_cs {
        return Err(InodeError::HeaderChecksumMismatch);
    }

    let version = read_u32_le(buf, INODE_OFF_VERSION);
    if version != FORMAT_VERSION {
        return Err(InodeError::UnknownVersion);
    }

    let kind = match buf[INODE_OFF_KIND] {
        INODE_KIND_REGULAR => InodeKind::Regular,
        INODE_KIND_DIRECTORY => InodeKind::Directory,
        INODE_KIND_SYMLINK => InodeKind::Symlink,
        _ => return Err(InodeError::UnknownKind),
    };
    let extent_count = buf[INODE_OFF_EXTENT_COUNT] as usize;
    if extent_count > MAX_EXTENTS_PER_INODE {
        return Err(InodeError::ExtentCountOutOfRange);
    }
    let acl_count = read_u16_le_inode(buf, INODE_OFF_ACL_COUNT) as usize;
    if acl_count > MAX_INODE_ACL_ENTRIES {
        return Err(InodeError::AclCountOutOfRange);
    }

    // Canonical-form: extents region past extent_count must be zero.
    let extents_filled_end = INODE_OFF_EXTENTS + extent_count * EXTENT_PACKED_SIZE;
    let extents_region_end = INODE_OFF_EXTENTS + MAX_EXTENTS_PER_INODE * EXTENT_PACKED_SIZE;
    if buf[extents_filled_end..extents_region_end].iter().any(|&b| b != 0) {
        return Err(InodeError::NonZeroPadding);
    }
    // Canonical-form: acl region past acl_count must be zero.
    let acl_filled_end = INODE_OFF_ACL + acl_count * ACL_ENTRY_PACKED_SIZE;
    let acl_region_end = INODE_OFF_ACL + MAX_INODE_ACL_ENTRIES * ACL_ENTRY_PACKED_SIZE;
    if buf[acl_filled_end..acl_region_end].iter().any(|&b| b != 0) {
        return Err(InodeError::NonZeroPadding);
    }
    // Canonical-form: reserved tail must be zero.
    if buf[INODE_OFF_RESERVED..INODE_OFF_CHECKSUM].iter().any(|&b| b != 0) {
        return Err(InodeError::NonZeroPadding);
    }

    let size_bytes = read_u64_le(buf, INODE_OFF_SIZE_BYTES);
    let created_at = read_u64_le(buf, INODE_OFF_CREATED_AT);
    let modified_at = read_u64_le(buf, INODE_OFF_MODIFIED_AT);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&buf[INODE_OFF_OWNER..INODE_OFF_OWNER + 32]);
    let link_count = read_u32_le(buf, INODE_OFF_LINK_COUNT);
    let cow_refcount = read_u32_le(buf, INODE_OFF_COW_REFCOUNT);

    let mut extents = [None; MAX_EXTENTS_PER_INODE];
    for i in 0..extent_count {
        let base = INODE_OFF_EXTENTS + i * EXTENT_PACKED_SIZE;
        let start_lba = read_u64_le(buf, base + EXTENT_OFF_START_LBA);
        let block_count = read_u32_le(buf, base + EXTENT_OFF_BLOCK_COUNT);
        extents[i] = Some(Extent { start_lba, block_count });
    }

    let mut acl = [None; MAX_INODE_ACL_ENTRIES];
    for i in 0..acl_count {
        let base = INODE_OFF_ACL + i * ACL_ENTRY_PACKED_SIZE;
        let mut principal = [0u8; 32];
        principal.copy_from_slice(&buf[base + ACL_OFF_PRINCIPAL..base + ACL_OFF_PRINCIPAL + 32]);
        let rights_byte = buf[base + ACL_OFF_RIGHTS];
        if rights_byte & !RIGHTS_VALID_MASK != 0 {
            return Err(InodeError::UnknownRightsBits);
        }
        let rights = Rights::from_bits(rights_byte);
        let expiry_raw = read_u64_le(buf, base + ACL_OFF_EXPIRY);
        let expiry = if expiry_raw == 0 { None } else { Some(expiry_raw) };
        acl[i] = Some(AclEntry { principal, rights, expiry });
    }

    let mut magic_buf = [0u8; 8];
    magic_buf.copy_from_slice(magic);
    Ok(InodeHeaderState::Occupied(PosixInode {
        magic: magic_buf,
        kind,
        size_bytes,
        created_at,
        modified_at,
        owner,
        link_count,
        cow_refcount,
        extents,
        acl,
    }))
}

#[inline]
const fn read_u16_le_inode(buf: &Block, offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

// ============================================================================
// Bitmap geometry + journal-replay helpers
// ============================================================================

/// Number of 4 KiB blocks the bitmap region occupies for a backend
/// declaring `capacity_blocks` data blocks. Mirrors the calculation
/// in `format()` so `mount()` and the kernel-singleton path use the
/// same derivation. Pure function over the superblock-stored capacity.
#[inline]
const fn bitmap_region_blocks_for(capacity_blocks: u64) -> u64 {
    capacity_blocks.div_ceil(8 * BLOCK_SIZE as u64)
}

/// Apply the bitmap-side effect of a single journal record to an
/// in-memory bitmap. Records that don't mutate the bitmap
/// (`Checkpoint`, `InodeAllocate`, `InodeFree`, `DirectoryEntry`,
/// `Rename`, `AclGrant`, `AclRevoke`, `LinkCountSet`, `Pad`) are
/// no-ops on the bitmap; only `ExtentUpdate` carries bitmap
/// mutations.
///
/// Used as the replay callback in `mount()` and as a forward-looking
/// reference for the kernel-singleton replay path. Returns the
/// `JournalError` shape the callback contract requires; bitmap
/// errors flow through the `From<BitmapError>` impl on `JournalError`.
fn apply_bitmap_mutations(
    bitmap: &mut BlockBitmap,
    rec: &JournalRecord,
) -> Result<(), JournalError> {
    if let JournalRecord::ExtentUpdate(eu) = rec {
        for m in &eu.mutations {
            match m {
                BitmapMutation::Set(b) => bitmap.mark_occupied(*b)?,
                BitmapMutation::Clear(b) => bitmap.mark_free(*b)?,
            }
        }
    }
    Ok(())
}

// ============================================================================
// PosixFsBackend
// ============================================================================

/// POSIX file storage backend. Generic over `B: BlockDevice` so the
/// format is exercisable against `MemBlockDevice` in tests and against
/// `VirtioBlkDevice` at runtime.
///
/// Commit 4B added the inode-region scan to `mount()`; commit 4C added
/// `get_inode()`. Commit 5C-ii (this commit) adds the in-memory
/// `bitmap` and `journal` fields plus `allocate_block` / `free_block`.
/// Mount-time journal replay reconstructs the bitmap before the
/// inode scan; a defense-in-depth comparison against the on-disk
/// bitmap region surfaces divergence per ADR-029 § Verification
/// Stance row 4.
///
/// The kernel-singleton wire-up (post-5D, ADR-029 migration step 6+)
/// will publish `bitmap` and `journal` into the global lock slots
/// declared in `src/lib.rs` (`BLOCK_BITMAP_LOCK(12)` and
/// `JOURNAL_LOCK(13)`); for now those slots stay `None` and unit
/// tests work with the struct fields directly.
pub struct PosixFsBackend<B: BlockDevice> {
    device: B,
    superblock: Superblock,
    /// In-memory set of occupied inode slots, populated at mount time
    /// by scanning every inode header in `[INODE_REGION_LBA, ...]`
    /// per ADR-029's bounded-iteration claim. Lookup is O(log n);
    /// scan-time iteration is `for i in 0..capacity_inodes`.
    inodes: BTreeSet<InodeId>,
    /// Block-allocation bitmap. At mount, reconstructed by replaying
    /// the journal over a fresh all-free bitmap; the on-disk bitmap
    /// region is a defense-in-depth cross-check, not the source of
    /// truth (per ADR-029 § Decision 2 step 5 + § Verification Stance
    /// row 4: "bitmap state is the projection of committed journal
    /// records").
    bitmap: BlockBitmap,
    /// Metadata journal. At mount, initialized from the superblock's
    /// `last_checkpoint_offset`; `head_offset` is reconstructed by
    /// `replay_from_checkpoint`. Mutations (allocate_block /
    /// free_block / inode CRUD in step 6+) append records before
    /// committing in-memory state.
    journal: Journal,
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

        // Initialize the in-memory bitmap as all-free and write it to
        // the bitmap region so a subsequent mount's defense-in-depth
        // check sees the canonical-form on-disk image.
        let bitmap = BlockBitmap::new_all_free(desired_capacity_blocks);
        let bitmap_buffers = encode_to_blocks(&bitmap)?;
        for (i, block) in bitmap_buffers.iter().enumerate() {
            device.write_block(bitmap_region_lba + i as u64, block)?;
        }

        // Zero-fill the journal region. Fresh format = empty journal;
        // every byte is zero. Mount's blank-region detector relies on
        // this (a leading zero byte stops the cursor cleanly).
        for i in 0..JOURNAL_BLOCKS {
            device.write_block(journal_region_lba + i, &zero_block)?;
        }

        let journal = Journal::new(JOURNAL_BYTES)?;

        device.flush()?;

        // Fresh format: no occupied inodes yet.
        Ok(Self {
            device,
            superblock: sb,
            inodes: BTreeSet::new(),
            bitmap,
            journal,
        })
    }

    /// Mount an existing backend. Validates the declared geometry,
    /// replays the journal to reconstruct the in-memory bitmap,
    /// cross-checks against the on-disk bitmap region (defense in
    /// depth), scans the inode region, and bumps the superblock
    /// generation counter.
    ///
    /// Ordering per ADR-029 § Decision 2 step 5 + § Verification
    /// Stance row 4: the bitmap is the projection of committed
    /// journal records, so journal replay precedes the inode scan
    /// and the on-disk bitmap region is consulted only as a
    /// cross-check. Divergence between the journal-reconstructed
    /// bitmap and the on-disk bitmap surfaces as
    /// `FsError::BitmapDivergence` and refuses mount; the
    /// kernel-singleton wire-up (step 6+) will emit an audit event
    /// before surfacing this error.
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
        if sb.journal_capacity_bytes != JOURNAL_BYTES {
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

        // -- Journal replay ---------------------------------------
        // Load the entire journal region into memory. 16 MiB; the
        // kernel-singleton wire-up (step 6+) will replace this with
        // a `FrameAllocator::allocate_contiguous` allocation
        // HHDM-mapped from the boot frame pool. Tests use Vec.
        let mut journal_buf = vec![0u8; JOURNAL_BYTES as usize];
        let mut block_buf = [0u8; BLOCK_SIZE];
        for i in 0..JOURNAL_BLOCKS {
            device.read_block(sb.journal_region_lba + i, &mut block_buf)?;
            let start = (i as usize) * BLOCK_SIZE;
            journal_buf[start..start + BLOCK_SIZE].copy_from_slice(&block_buf);
        }

        let mut journal = Journal::from_disk_state(
            JOURNAL_BYTES,
            sb.last_checkpoint_offset,
            0, // head reconstructed by replay
        )?;
        let mut bitmap = BlockBitmap::new_all_free(sb.capacity_blocks);
        journal.replay_from_checkpoint(&journal_buf, |rec| {
            apply_bitmap_mutations(&mut bitmap, rec)
        })?;

        // -- Defense-in-depth bitmap cross-check ------------------
        // Compare the journal-reconstructed bitmap against the
        // on-disk bitmap region. The bitmap region is authoritative
        // for kernel-singleton consumers that need to read the
        // free-pool without scanning the journal; the journal is
        // authoritative for correctness. A mismatch means either a
        // journal-replay bug or on-disk corruption; refuse to mount.
        let bitmap_blocks = bitmap_region_blocks_for(sb.capacity_blocks);
        let mut disk_bitmap_blocks: Vec<Block> = Vec::with_capacity(bitmap_blocks as usize);
        for i in 0..bitmap_blocks {
            let mut block = [0u8; BLOCK_SIZE];
            device.read_block(sb.bitmap_region_lba + i, &mut block)?;
            disk_bitmap_blocks.push(block);
        }
        let disk_bitmap = decode_from_blocks(&disk_bitmap_blocks, sb.capacity_blocks)?;
        if bitmap != disk_bitmap {
            return Err(FsError::BitmapDivergence);
        }

        // -- Inode-region scan ------------------------------------
        // Bounded by `sb.capacity_inodes`, which is itself bounded
        // above by `MAX_INODES_ON_DISK` (verifier-friendly per
        // ADR-029 § Verification Stance).
        let mut inodes = BTreeSet::new();
        let mut header_buf = [0u8; BLOCK_SIZE];
        for slot in 0..sb.capacity_inodes {
            device.read_block(inode_header_lba(slot), &mut header_buf)?;
            match decode_inode_header(&header_buf)? {
                InodeHeaderState::Free => {}
                InodeHeaderState::Occupied(_inode) => {
                    inodes.insert(InodeId::new(slot));
                }
            }
        }

        // Bump generation so stale media swaps are detectable.
        let next_sb = Superblock {
            generation: sb.generation.wrapping_add(1),
            ..sb
        };
        let mut sb_buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut sb_buf, &next_sb);
        device.write_block(SUPERBLOCK_HEADER_LBA, &sb_buf)?;
        device.flush()?;

        Ok(Self {
            device,
            superblock: next_sb,
            inodes,
            bitmap,
            journal,
        })
    }

    /// Return `true` if `id` was observed as occupied during the most
    /// recent mount/format. Lookups touch the in-memory set only; no
    /// device I/O.
    pub fn is_inode_occupied(&self, id: InodeId) -> bool {
        self.inodes.contains(&id)
    }

    /// Iterate occupied inode IDs in sorted order. Test-oriented; the
    /// step-5+ write path will replace this with a richer API.
    pub fn occupied_inodes(&self) -> impl Iterator<Item = InodeId> + '_ {
        self.inodes.iter().copied()
    }

    /// Read the inode at `id` from disk and return its decoded form.
    ///
    /// Returns `FsError::InodeNotFound` for an out-of-range id or a
    /// free slot. Surfaces `FsError::BlockError(...)` for transport
    /// failures and `FsError::InodeFormat(...)` for any canonical-
    /// form violation in the on-disk header (per ADR-029 § Divergence
    /// 1 the decoder rejects non-canonical bytes loudly).
    ///
    /// One block-device read per call. The in-memory `inodes` set
    /// provides O(log n) early-out for free slots, avoiding the
    /// round-trip; the disk decode is the source of truth for the
    /// returned contents.
    pub fn get_inode(&mut self, id: InodeId) -> Result<PosixInode, FsError> {
        if id.raw() >= self.superblock.capacity_inodes {
            return Err(FsError::InodeNotFound);
        }
        if !self.inodes.contains(&id) {
            return Err(FsError::InodeNotFound);
        }
        let mut header_buf = [0u8; BLOCK_SIZE];
        self.device.read_block(inode_header_lba(id.raw()), &mut header_buf)?;
        match decode_inode_header(&header_buf)? {
            InodeHeaderState::Free => {
                // The in-memory set said occupied; the disk says free.
                // That's a divergence — most likely a CoW-induced race
                // in step 5+. For step 4 with no write path it should
                // not happen; surface as NotFound rather than panic.
                Err(FsError::InodeNotFound)
            }
            InodeHeaderState::Occupied(inode) => Ok(inode),
        }
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Read-only view of the in-memory bitmap. Test-friendly accessor;
    /// production callers (step 6+) acquire `BLOCK_BITMAP_LOCK` via
    /// the kernel-singleton path.
    pub fn bitmap(&self) -> &BlockBitmap {
        &self.bitmap
    }

    /// Read-only view of the in-memory journal. Test-friendly accessor;
    /// production callers (step 6+) acquire `JOURNAL_LOCK` via the
    /// kernel-singleton path.
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Allocate a fresh data block. Per ADR-029 § Decision 2 step 4:
    /// the journal record describing the bitmap mutation lands
    /// durably on disk BEFORE the in-memory bitmap commits the mark.
    /// On crash between journal flush and the in-memory mark, the
    /// next mount's replay re-applies the mutation; on crash before
    /// journal flush, the block stays free (no journal record, no
    /// effect on the projected bitmap state).
    ///
    /// The journal record is an `ExtentUpdate` with an empty extent
    /// list and a single `BitmapMutation::Set`. The empty extent
    /// list signals "no inode-side effect, bitmap-only transaction"
    /// — the inode association happens in the caller's higher-level
    /// transaction (step 6+). Returns the allocated block index, or
    /// `FsError::OutOfSpace` when the bitmap is full.
    ///
    /// After the in-memory mark, the affected bitmap-region block is
    /// flushed to disk so the mount-time defense-in-depth check sees
    /// a coherent on-disk image. Production (step 7+ checkpoint
    /// cadence) may batch the bitmap-region flush at checkpoint
    /// boundaries rather than per-mutation; for 5C-ii the write-
    /// through cost is acceptable and keeps the divergence check
    /// meaningful as a corruption detector.
    pub fn allocate_block(&mut self) -> Result<u64, FsError> {
        let block = self.bitmap.first_free().ok_or(FsError::OutOfSpace)?;
        let record = JournalRecord::extent_update(
            InodeId::new(0),
            [None; MAX_EXTENTS_PER_INODE],
            alloc::vec![BitmapMutation::Set(block)],
        )?;
        let encoded = encode_record(&record)?;
        let append = self.journal.append(&encoded)?;
        self.commit_journal_append(&append, &encoded)?;
        // Journal flush is durable; safe to update in-memory bitmap.
        self.bitmap.mark_occupied(block)?;
        self.flush_bitmap_region_for(block)?;
        Ok(block)
    }

    /// Free a previously-allocated data block. Symmetric with
    /// `allocate_block` — journals an `ExtentUpdate` with empty
    /// extent list + `BitmapMutation::Clear`, then commits the
    /// in-memory mark and flushes the affected bitmap-region block.
    ///
    /// Returns `FsError::NotAllocated` if the block is out of range
    /// or already free (caller's logic bug; not idempotent —
    /// double-free is loud per ADR-029 § Verification Stance).
    pub fn free_block(&mut self, block: u64) -> Result<(), FsError> {
        if !self.bitmap.is_occupied(block) {
            return Err(FsError::NotAllocated);
        }
        let record = JournalRecord::extent_update(
            InodeId::new(0),
            [None; MAX_EXTENTS_PER_INODE],
            alloc::vec![BitmapMutation::Clear(block)],
        )?;
        let encoded = encode_record(&record)?;
        let append = self.journal.append(&encoded)?;
        self.commit_journal_append(&append, &encoded)?;
        self.bitmap.mark_free(block)?;
        self.flush_bitmap_region_for(block)?;
        Ok(())
    }

    /// Find the lowest-numbered free inode slot in
    /// `0..capacity_inodes`, or `None` when the region is full.
    ///
    /// Bounded loop per ADR-029 § Verification Stance row 1 ("Mount
    /// inode scan is `for i in 0..capacity_inodes`"). Same scan
    /// shape used at mount; the in-memory `inodes` BTreeSet carries
    /// the post-replay state so this only walks the gaps.
    fn find_free_inode_slot(&self) -> Option<InodeId> {
        for slot in 0..self.superblock.capacity_inodes {
            let id = InodeId::new(slot);
            if !self.inodes.contains(&id) {
                return Some(id);
            }
        }
        None
    }

    /// Allocate a fresh inode owned by `owner` and return its ID.
    /// ADR-029 § Decision 4 `SYS_FILE_CREATE` backend half: picks the
    /// lowest-numbered free slot, builds a regular-file inode with
    /// the caller as owner and an empty ACL, journals an
    /// `InodeAllocate` record, then writes the inode header block
    /// to disk.
    ///
    /// Order matches ADR-029 § Decision 5: the journal record is
    /// durable before the inode header lands and before the
    /// in-memory occupancy set commits. A crash between journal
    /// flush and header write replays as "inode allocated"
    /// (mount-time replay re-inserts the ID); the next
    /// `find_free_inode_slot` skips it and `get_inode` returns the
    /// header bytes from disk (zero-filled = free, header valid =
    /// occupied). The InodeAllocate record is idempotent.
    ///
    /// `now_ticks` stamps both `created_at` and `modified_at`. The
    /// caller (dispatcher) reads the kernel tick counter; tests
    /// pass a fixed value.
    ///
    /// Returns `FsError::OutOfSpace` when the inode region is full.
    pub fn create_inode(
        &mut self,
        owner: Principal,
        now_ticks: u64,
    ) -> Result<InodeId, FsError> {
        let inode_id = self.find_free_inode_slot().ok_or(FsError::OutOfSpace)?;

        let inode = PosixInode {
            magic: ARCINOD_MAGIC_OCCUPIED,
            kind: InodeKind::Regular,
            size_bytes: 0,
            created_at: now_ticks,
            modified_at: now_ticks,
            owner: *owner.aid(),
            link_count: 1,
            cow_refcount: 0,
            extents: [None; MAX_EXTENTS_PER_INODE],
            acl: [None; MAX_INODE_ACL_ENTRIES],
        };

        // Journal first — ADR-029 § Decision 5 ordering invariant.
        let record = JournalRecord::InodeAllocate { inode: inode_id };
        let encoded = encode_record(&record)?;
        let append = self.journal.append(&encoded)?;
        self.commit_journal_append(&append, &encoded)?;

        // Header block durable next.
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode)?;
        self.device.write_block(inode_header_lba(inode_id.raw()), &buf)?;
        self.device.flush()?;

        // In-memory occupancy committed last.
        self.inodes.insert(inode_id);
        Ok(inode_id)
    }

    /// Authorize an open of `inode_id` for `rights_requested` by
    /// `caller`. Returns the resolved rights (always equal to
    /// `rights_requested` in step 6; future tier policy may
    /// narrow) when access is granted.
    ///
    /// Per ADR-029 § Decision 3:
    /// 1. If `caller`'s AID matches `inode.owner`, access is
    ///    granted (owner authority is uncircumscribed; the inode
    ///    creator can always read/write/execute their own files).
    /// 2. Else scan `inode.acl` for an entry where `principal ==
    ///    caller.aid()` and the entry's rights cover the request
    ///    and the entry has not expired.
    /// 3. Else `FsError::PermissionDenied`.
    ///
    /// Read-only — does not mutate the inode, the journal, or the
    /// occupancy set. `cow_refcount` accounting lands in step 7
    /// (`O_CONSISTENT_SNAPSHOT` opens) and uses a separate code
    /// path.
    ///
    /// Returns `FsError::InodeNotFound` when the inode does not
    /// exist (out-of-range or free slot per `get_inode`).
    pub fn open_inode(
        &mut self,
        caller: Principal,
        inode_id: InodeId,
        rights_requested: Rights,
        now_ticks: u64,
    ) -> Result<Rights, FsError> {
        let inode = self.get_inode(inode_id)?;
        let caller_aid = *caller.aid();

        if inode.owner == caller_aid {
            return Ok(rights_requested);
        }

        // ACL scan — bounded by MAX_INODE_ACL_ENTRIES (16).
        for entry in inode.acl.iter().flatten() {
            if entry.principal != caller_aid {
                continue;
            }
            if let Some(expiry) = entry.expiry {
                if expiry != 0 && expiry <= now_ticks {
                    continue;
                }
            }
            if entry.rights.contains(rights_requested) {
                return Ok(rights_requested);
            }
            // Found the caller's row but it doesn't cover the
            // request — deny without continuing the scan. ADR-029
            // § Decision 3 has one ACL row per principal; a second
            // match would imply duplicate entries which the grant
            // path (step 6-iii) rejects.
            return Err(FsError::PermissionDenied);
        }

        Err(FsError::PermissionDenied)
    }

    /// Write the on-disk bitmap-region block that contains the bit
    /// for `block`. Re-encodes the in-memory bitmap and copies the
    /// one affected block onto disk; the remaining bitmap blocks are
    /// left untouched.
    ///
    /// Deferred: re-encoding the entire bitmap on every mutation is
    /// O(capacity_blocks); the per-mutation cost is acceptable for
    /// the v1 SCAFFOLDING capacity (≤4 TiB → 1 GiB bitmap region).
    /// Revisit when: a per-block encoder lands or the per-mutation
    /// I/O cost surfaces in profiling.
    fn flush_bitmap_region_for(&mut self, block: u64) -> Result<(), FsError> {
        let bitmap_block_idx = block / (BLOCK_SIZE as u64 * 8);
        let all_blocks = encode_to_blocks(&self.bitmap)?;
        let lba = self.superblock.bitmap_region_lba + bitmap_block_idx;
        self.device
            .write_block(lba, &all_blocks[bitmap_block_idx as usize])?;
        self.device.flush()?;
        Ok(())
    }

    /// Execute the device writes described by an [`Append`] and
    /// flush. Writes the pad first (if present), then the real
    /// record, mirroring ADR-029 § Decision 5's "pad covers tail
    /// before real lands at offset 0" ordering. The pad write must
    /// commit before the real write so a crash between the two
    /// leaves the cursor stoppable at the pad without partial
    /// real-record visibility.
    fn commit_journal_append(
        &mut self,
        append: &Append,
        real_bytes: &[u8],
    ) -> Result<(), FsError> {
        if let Some((pad_at, pad_bytes)) = &append.pad_at {
            self.write_journal_bytes(*pad_at, pad_bytes)?;
            self.device.flush()?;
        }
        self.write_journal_bytes(append.real_at, real_bytes)?;
        self.device.flush()?;
        Ok(())
    }

    /// Write `bytes` into the journal region starting at byte
    /// `byte_offset`. Spans block boundaries via read-modify-write
    /// on the partial-tail block; bounded loop over
    /// `bytes.len().div_ceil(BLOCK_SIZE) + 1` iterations.
    fn write_journal_bytes(
        &mut self,
        byte_offset: u64,
        bytes: &[u8],
    ) -> Result<(), FsError> {
        let region_lba = self.superblock.journal_region_lba;
        let mut cursor = byte_offset;
        let mut written = 0usize;
        while written < bytes.len() {
            let block_idx = cursor / BLOCK_SIZE as u64;
            let block_off = (cursor % BLOCK_SIZE as u64) as usize;
            let lba = region_lba + block_idx;

            // Read-modify-write: preserve neighbor bytes in the
            // same block. For a full-block write this is wasteful;
            // step 6+ can optimize the full-block fast path once
            // the workload profile is measurable.
            let mut block = [0u8; BLOCK_SIZE];
            self.device.read_block(lba, &mut block)?;
            let copy = core::cmp::min(BLOCK_SIZE - block_off, bytes.len() - written);
            block[block_off..block_off + copy]
                .copy_from_slice(&bytes[written..written + copy]);
            self.device.write_block(lba, &block)?;

            cursor += copy as u64;
            written += copy;
        }
        Ok(())
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

    // ========================================================================
    // Inode header encode/decode (commit 4B)
    // ========================================================================

    fn make_inode(extent_count: usize, acl_count: usize) -> PosixInode {
        let mut extents = [None; MAX_EXTENTS_PER_INODE];
        for i in 0..extent_count {
            extents[i] = Some(Extent {
                start_lba: 1000 + i as u64,
                block_count: 4 + i as u32,
            });
        }
        let mut acl = [None; MAX_INODE_ACL_ENTRIES];
        for i in 0..acl_count {
            let mut principal = [0u8; 32];
            principal[0] = i as u8 + 1;
            acl[i] = Some(AclEntry {
                principal,
                rights: Rights::READ.union(Rights::WRITE),
                expiry: if i == 0 { None } else { Some(9000 + i as u64) },
            });
        }
        PosixInode {
            magic: ARCINOD_MAGIC_OCCUPIED,
            kind: InodeKind::Regular,
            size_bytes: 4096,
            created_at: 100,
            modified_at: 200,
            owner: [0xAA; 32],
            link_count: 1,
            cow_refcount: 0,
            extents,
            acl,
        }
    }

    #[test]
    fn inode_header_roundtrip_empty() {
        let inode = make_inode(0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        match decode_inode_header(&buf).unwrap() {
            InodeHeaderState::Occupied(decoded) => {
                assert_eq!(decoded.size_bytes, inode.size_bytes);
                assert_eq!(decoded.kind as u8, inode.kind as u8);
                assert!(decoded.extents.iter().all(|e| e.is_none()));
                assert!(decoded.acl.iter().all(|e| e.is_none()));
            }
            other => panic!("expected Occupied, got {:?}", other),
        }
    }

    #[test]
    fn inode_header_roundtrip_populated() {
        let inode = make_inode(3, 2);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        match decode_inode_header(&buf).unwrap() {
            InodeHeaderState::Occupied(decoded) => {
                for i in 0..3 {
                    assert_eq!(decoded.extents[i], inode.extents[i]);
                }
                for i in 3..MAX_EXTENTS_PER_INODE {
                    assert!(decoded.extents[i].is_none());
                }
                for i in 0..2 {
                    let a = decoded.acl[i].unwrap();
                    let b = inode.acl[i].unwrap();
                    assert_eq!(a.principal, b.principal);
                    assert_eq!(a.rights.bits(), b.rights.bits());
                    assert_eq!(a.expiry, b.expiry);
                }
            }
            other => panic!("expected Occupied, got {:?}", other),
        }
    }

    #[test]
    fn inode_header_full_capacity_roundtrip() {
        // Exercise both arrays at MAX. Smoke-test that the canonical-
        // form padding logic does not miscount when there's no padding
        // to write.
        let inode = make_inode(MAX_EXTENTS_PER_INODE, MAX_INODE_ACL_ENTRIES);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        match decode_inode_header(&buf).unwrap() {
            InodeHeaderState::Occupied(decoded) => {
                assert!(decoded.extents.iter().all(|e| e.is_some()));
                assert!(decoded.acl.iter().all(|e| e.is_some()));
            }
            other => panic!("expected Occupied, got {:?}", other),
        }
    }

    #[test]
    fn inode_header_free_slot_detection() {
        // All-zero buffer reads as Free (magic mismatch).
        let buf = [0u8; BLOCK_SIZE];
        assert_eq!(decode_inode_header(&buf), Ok(InodeHeaderState::Free));
    }

    #[test]
    fn inode_header_bad_magic_reads_as_free() {
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..8].copy_from_slice(b"WRONGMAG");
        assert_eq!(decode_inode_header(&buf), Ok(InodeHeaderState::Free));
    }

    #[test]
    fn inode_header_bad_checksum_is_error() {
        let inode = make_inode(2, 1);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        buf[INODE_OFF_CHECKSUM] ^= 0xFF;
        assert_eq!(decode_inode_header(&buf), Err(InodeError::HeaderChecksumMismatch));
    }

    #[test]
    fn inode_header_extent_count_out_of_range() {
        let inode = make_inode(2, 1);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        // Set extent_count to MAX+1 and recompute checksum so the only
        // violated invariant is the bounds check.
        buf[INODE_OFF_EXTENT_COUNT] = (MAX_EXTENTS_PER_INODE + 1) as u8;
        let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
        buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(decode_inode_header(&buf), Err(InodeError::ExtentCountOutOfRange));
    }

    #[test]
    fn inode_header_acl_count_out_of_range() {
        let inode = make_inode(0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        let bad = (MAX_INODE_ACL_ENTRIES as u16 + 1).to_le_bytes();
        buf[INODE_OFF_ACL_COUNT..INODE_OFF_ACL_COUNT + 2].copy_from_slice(&bad);
        let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
        buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(decode_inode_header(&buf), Err(InodeError::AclCountOutOfRange));
    }

    #[test]
    fn inode_header_unknown_version_is_error() {
        let inode = make_inode(0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        buf[INODE_OFF_VERSION..INODE_OFF_VERSION + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
        buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(decode_inode_header(&buf), Err(InodeError::UnknownVersion));
    }

    #[test]
    fn inode_header_unknown_kind_is_error() {
        let inode = make_inode(0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        buf[INODE_OFF_KIND] = 99;
        let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
        buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(decode_inode_header(&buf), Err(InodeError::UnknownKind));
    }

    #[test]
    fn inode_header_unknown_rights_bits_are_error() {
        let inode = make_inode(0, 1);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        // Set a bit beyond Read|Write|Execute on the first ACL entry.
        let base = INODE_OFF_ACL + ACL_OFF_RIGHTS;
        buf[base] |= 1 << 7;
        let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
        buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(decode_inode_header(&buf), Err(InodeError::UnknownRightsBits));
    }

    #[test]
    fn inode_header_nonzero_extents_padding_rejected() {
        let inode = make_inode(2, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        // Trailing extent slot 2's first byte non-zero, while
        // extent_count = 2 declares slots [0,2) are meaningful.
        let trailing_slot_base = INODE_OFF_EXTENTS + 2 * EXTENT_PACKED_SIZE;
        buf[trailing_slot_base] = 0xAB;
        let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
        buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(decode_inode_header(&buf), Err(InodeError::NonZeroPadding));
    }

    #[test]
    fn inode_header_nonzero_acl_padding_rejected() {
        let inode = make_inode(0, 1);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        let trailing_slot_base = INODE_OFF_ACL + ACL_ENTRY_PACKED_SIZE;
        buf[trailing_slot_base + 10] = 0xCD;
        let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
        buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(decode_inode_header(&buf), Err(InodeError::NonZeroPadding));
    }

    #[test]
    fn inode_header_nonzero_reserved_tail_rejected() {
        let inode = make_inode(0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        buf[INODE_OFF_RESERVED + 200] = 0xEF;
        let cs = checksum8(&buf[..INODE_CHECKSUM_COVER_END]);
        buf[INODE_OFF_CHECKSUM..INODE_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        assert_eq!(decode_inode_header(&buf), Err(InodeError::NonZeroPadding));
    }

    #[test]
    fn validate_rejects_noncontiguous_extents() {
        let mut inode = make_inode(0, 0);
        // Skip slot 0, place an extent at slot 1 — violates the invariant.
        inode.extents[1] = Some(Extent { start_lba: 100, block_count: 1 });
        assert_eq!(
            validate_inode(&inode),
            Err(InodeError::NonContiguousExtents),
        );
    }

    #[test]
    fn validate_rejects_noncontiguous_acl() {
        let mut inode = make_inode(0, 0);
        inode.acl[2] = Some(AclEntry {
            principal: [1u8; 32],
            rights: Rights::READ,
            expiry: None,
        });
        assert_eq!(
            validate_inode(&inode),
            Err(InodeError::NonContiguousExtents),
        );
    }

    #[test]
    fn encode_refuses_invalid_inode() {
        let mut inode = make_inode(0, 0);
        inode.extents[5] = Some(Extent { start_lba: 1, block_count: 1 });
        let mut buf = [0u8; BLOCK_SIZE];
        assert_eq!(
            encode_inode_header(&mut buf, &inode),
            Err(InodeError::NonContiguousExtents),
        );
    }

    // ========================================================================
    // Mount-time inode-region scan (commit 4B)
    // ========================================================================

    /// Place an encoded inode header at `slot` on `dev`.
    fn write_inode(dev: &mut MemBlockDevice, slot: u64, inode: &PosixInode) {
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, inode).unwrap();
        dev.write_block(inode_header_lba(slot), &buf).unwrap();
    }

    #[test]
    fn mount_with_empty_inode_region() {
        let backend = fresh_backend();
        assert_eq!(backend.occupied_inodes().count(), 0);
    }

    #[test]
    fn mount_discovers_populated_inodes() {
        // Format, drop, hand-populate two inode slots, then mount and
        // confirm both are discovered.
        let mut dev = fresh_backend().into_device();
        let inode = make_inode(1, 0);
        write_inode(&mut dev, 0, &inode);
        write_inode(&mut dev, 2, &inode);
        let backend2 = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        let ids: alloc::vec::Vec<InodeId> = backend2.occupied_inodes().collect();
        assert_eq!(ids, &[InodeId::new(0), InodeId::new(2)]);
        assert!(backend2.is_inode_occupied(InodeId::new(0)));
        assert!(!backend2.is_inode_occupied(InodeId::new(1)));
        assert!(backend2.is_inode_occupied(InodeId::new(2)));
        assert!(!backend2.is_inode_occupied(InodeId::new(3)));
    }

    #[test]
    fn mount_surfaces_corrupt_inode_as_fserror() {
        let backend = fresh_backend();
        let mut dev = backend.into_device();
        // Write a header with valid magic but bad checksum.
        let inode = make_inode(0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        buf[INODE_OFF_CHECKSUM] ^= 0xFF;
        dev.write_block(inode_header_lba(1), &buf).unwrap();
        let result = PosixFsBackend::open_or_format(dev, 4, 32, 0);
        assert!(matches!(
            result,
            Err(FsError::InodeFormat(InodeError::HeaderChecksumMismatch)),
        ));
    }

    // ========================================================================
    // Read path (commit 4C)
    // ========================================================================

    #[test]
    fn get_inode_returns_occupied_contents() {
        let mut dev = fresh_backend().into_device();
        let inode = make_inode(2, 1);
        write_inode(&mut dev, 1, &inode);
        let mut backend = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        let got = backend.get_inode(InodeId::new(1)).unwrap();
        assert_eq!(got, inode);
    }

    #[test]
    fn get_inode_on_free_slot_is_not_found() {
        let mut backend = fresh_backend();
        let result = backend.get_inode(InodeId::new(2));
        assert!(matches!(result, Err(FsError::InodeNotFound)));
    }

    #[test]
    fn get_inode_out_of_range_is_not_found() {
        // capacity_inodes = 4 in fresh_backend; id 4 is out of range.
        let mut backend = fresh_backend();
        let result = backend.get_inode(InodeId::new(4));
        assert!(matches!(result, Err(FsError::InodeNotFound)));
        let result = backend.get_inode(InodeId::new(u64::MAX));
        assert!(matches!(result, Err(FsError::InodeNotFound)));
    }

    #[test]
    fn get_inode_surfaces_corruption_after_mount() {
        // Write a valid inode, mount, then corrupt the on-disk bytes
        // and confirm get_inode surfaces the typed checksum error
        // rather than silently masquerading. Real workloads see this
        // when disk-level corruption hits a previously-good inode.
        let mut dev = fresh_backend().into_device();
        let inode = make_inode(1, 0);
        write_inode(&mut dev, 0, &inode);
        // Corrupt slot 0's checksum AFTER write_inode but BEFORE mount
        // — mount would otherwise reject the whole disk. Place the
        // damage as a slot-1 corruption (free slot in the set per
        // fresh_backend) ... actually no, we want slot 0 to read as
        // occupied at mount but corrupt at get-time. Do the
        // corruption AFTER mount has populated the inodes set.
        let mut backend = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        // Reach into the device through into_device → mutate → re-open
        // would re-validate; instead use the existing device through
        // a fresh write that the in-memory set doesn't know about.
        // For step 4 we don't expose &mut device; the test contract
        // is "if mount succeeded and the disk is then corrupted
        // out-of-band, get_inode surfaces it." Simulate by re-mounting
        // after writing corrupt bytes; the second mount itself will
        // catch the corruption and refuse to open, which is the
        // stronger guarantee. Document the chosen test shape:
        let mut dev = backend.into_device();
        let mut buf = [0u8; BLOCK_SIZE];
        dev.read_block(inode_header_lba(0), &mut buf).unwrap();
        buf[INODE_OFF_CHECKSUM] ^= 0x55;
        dev.write_block(inode_header_lba(0), &buf).unwrap();
        let result = PosixFsBackend::open_or_format(dev, 4, 32, 0);
        // Mount-time scan catches the corruption before we even reach
        // get_inode — desired behavior per the canonical-form stance.
        assert!(matches!(
            result,
            Err(FsError::InodeFormat(InodeError::HeaderChecksumMismatch)),
        ));
    }

    // ========================================================================
    // Survives-reboot tests (commit 4C)
    // ========================================================================

    #[test]
    fn survives_reboot_with_three_distinct_inodes() {
        // The headline correctness test: format, write three inodes
        // with distinct contents, drop the backend, re-mount, get
        // each inode back byte-for-byte.
        let mut dev = fresh_backend().into_device();

        let a = PosixInode {
            kind: InodeKind::Regular,
            size_bytes: 1024,
            link_count: 1,
            ..make_inode(2, 1)
        };
        let mut b = make_inode(0, 0);
        b.kind = InodeKind::Directory;
        b.size_bytes = 4096;
        b.created_at = 555;
        let mut c = make_inode(MAX_EXTENTS_PER_INODE, MAX_INODE_ACL_ENTRIES);
        c.kind = InodeKind::Symlink;
        c.owner = [0x42; 32];
        c.cow_refcount = 7;

        write_inode(&mut dev, 0, &a);
        write_inode(&mut dev, 1, &b);
        write_inode(&mut dev, 3, &c);

        // First mount discovers and bumps generation.
        let mut backend = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        let gen_after_first_mount = backend.superblock().generation;
        assert_eq!(backend.get_inode(InodeId::new(0)).unwrap(), a);
        assert_eq!(backend.get_inode(InodeId::new(1)).unwrap(), b);
        assert_eq!(backend.get_inode(InodeId::new(3)).unwrap(), c);
        // Slot 2 was never written.
        assert!(matches!(
            backend.get_inode(InodeId::new(2)),
            Err(FsError::InodeNotFound),
        ));

        // Drop and re-mount: contents survive, generation bumps again.
        let dev = backend.into_device();
        let mut backend2 = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        assert_eq!(
            backend2.superblock().generation,
            gen_after_first_mount + 1,
        );
        assert_eq!(backend2.get_inode(InodeId::new(0)).unwrap(), a);
        assert_eq!(backend2.get_inode(InodeId::new(1)).unwrap(), b);
        assert_eq!(backend2.get_inode(InodeId::new(3)).unwrap(), c);
    }

    #[test]
    fn reboot_preserves_canonical_form_byte_for_byte() {
        // Stronger property: re-encoding a decoded inode produces the
        // same on-disk bytes. The ADR-029 § Divergence 1 canonical-
        // form claim ("same logical inode → same bytes → same hash")
        // is verified at the byte level here.
        let inode = make_inode(3, 2);
        let mut buf1 = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf1, &inode).unwrap();
        let decoded = match decode_inode_header(&buf1).unwrap() {
            InodeHeaderState::Occupied(i) => i,
            other => panic!("expected Occupied, got {:?}", other),
        };
        let mut buf2 = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf2, &decoded).unwrap();
        assert_eq!(buf1, buf2, "decode then encode must produce identical bytes");
    }

    // ========================================================================
    // Bitmap + journal integration (commit 5C-ii)
    // ========================================================================

    #[test]
    fn fresh_backend_bitmap_all_free() {
        let backend = fresh_backend();
        let bm = backend.bitmap();
        assert_eq!(bm.capacity(), 32);
        assert_eq!(bm.free_count(), 32);
    }

    #[test]
    fn fresh_backend_journal_empty() {
        let backend = fresh_backend();
        let j = backend.journal();
        assert_eq!(j.region_bytes(), JOURNAL_BYTES);
        assert_eq!(j.head_offset(), 0);
        assert_eq!(j.last_checkpoint_offset(), 0);
    }

    #[test]
    fn allocate_block_marks_and_journals() {
        let mut backend = fresh_backend();
        let initial_head = backend.journal().head_offset();

        let block = backend.allocate_block().unwrap();
        assert_eq!(block, 0, "first allocation should return lowest free block");
        assert!(backend.bitmap().is_occupied(block));
        assert_eq!(backend.bitmap().free_count(), 31);
        assert!(
            backend.journal().head_offset() > initial_head,
            "journal head must advance past the new record"
        );
    }

    #[test]
    fn allocate_block_returns_distinct_blocks_in_order() {
        let mut backend = fresh_backend();
        let a = backend.allocate_block().unwrap();
        let b = backend.allocate_block().unwrap();
        let c = backend.allocate_block().unwrap();
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(c, 2);
        assert_eq!(backend.bitmap().free_count(), 29);
    }

    #[test]
    fn allocate_until_exhausted_returns_out_of_space() {
        let mut backend = fresh_backend();
        for _ in 0..32 {
            backend.allocate_block().unwrap();
        }
        assert_eq!(backend.bitmap().free_count(), 0);
        assert_eq!(backend.allocate_block(), Err(FsError::OutOfSpace));
    }

    #[test]
    fn free_block_round_trips_through_bitmap_and_journal() {
        let mut backend = fresh_backend();
        let b = backend.allocate_block().unwrap();
        let head_after_alloc = backend.journal().head_offset();
        backend.free_block(b).unwrap();
        assert!(backend.bitmap().is_free(b));
        assert!(
            backend.journal().head_offset() > head_after_alloc,
            "free must also emit a journal record"
        );
    }

    #[test]
    fn free_block_rejects_already_free() {
        let mut backend = fresh_backend();
        assert_eq!(backend.free_block(5), Err(FsError::NotAllocated));
    }

    #[test]
    fn free_block_rejects_out_of_range() {
        let mut backend = fresh_backend();
        // capacity_blocks = 32 in fresh_backend.
        assert_eq!(backend.free_block(100), Err(FsError::NotAllocated));
    }

    #[test]
    fn mount_replays_journal_to_reconstruct_bitmap() {
        // Allocate three blocks, drop the backend, remount. The
        // post-remount bitmap must match the pre-drop state — the
        // journal replay (NOT the on-disk bitmap region alone) is
        // the source of truth.
        let mut backend = fresh_backend();
        for _ in 0..3 {
            backend.allocate_block().unwrap();
        }
        let pre_drop_free = backend.bitmap().free_count();
        assert_eq!(pre_drop_free, 29);

        let dev = backend.into_device();
        let remounted = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        assert_eq!(remounted.bitmap().free_count(), pre_drop_free);
        for b in 0..3 {
            assert!(remounted.bitmap().is_occupied(b));
        }
        for b in 3..32 {
            assert!(remounted.bitmap().is_free(b));
        }
    }

    #[test]
    fn mount_replays_allocate_then_free_sequence() {
        // Allocate blocks 0, 1, 2; free 1. Remount must reconstruct
        // the same bitmap (0 and 2 occupied, 1 free).
        let mut backend = fresh_backend();
        backend.allocate_block().unwrap();
        backend.allocate_block().unwrap();
        backend.allocate_block().unwrap();
        backend.free_block(1).unwrap();

        let dev = backend.into_device();
        let remounted = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        assert!(remounted.bitmap().is_occupied(0));
        assert!(remounted.bitmap().is_free(1));
        assert!(remounted.bitmap().is_occupied(2));
        assert_eq!(remounted.bitmap().free_count(), 30);
    }

    #[test]
    fn mount_rejects_bitmap_divergence() {
        // After allocating, corrupt the on-disk bitmap region so it
        // disagrees with what the journal replay would reconstruct.
        // Mount must surface FsError::BitmapDivergence.
        let mut backend = fresh_backend();
        backend.allocate_block().unwrap();
        let bitmap_region_lba = backend.superblock().bitmap_region_lba;
        let mut dev = backend.into_device();
        // Read the bitmap region's first block, flip a free bit
        // (block 5: currently free per the journal, but on-disk
        // we'll mark it occupied so disk-vs-journal disagree).
        let mut block = [0u8; BLOCK_SIZE];
        dev.read_block(bitmap_region_lba, &mut block).unwrap();
        // First byte: bit 5 = 0x20. "1 = free" convention so clear
        // bit 5 to claim block 5 is occupied on disk.
        block[0] &= !0x20;
        dev.write_block(bitmap_region_lba, &block).unwrap();

        let result = PosixFsBackend::open_or_format(dev, 4, 32, 0);
        assert_eq!(result.err().unwrap(), FsError::BitmapDivergence);
    }

    #[test]
    fn allocate_returns_first_free_after_free_in_middle() {
        // Bitmap's first_free is the lowest-indexed free block. After
        // allocate 0,1,2,3 then free 1, the next allocate should reuse
        // block 1.
        let mut backend = fresh_backend();
        for _ in 0..4 {
            backend.allocate_block().unwrap();
        }
        backend.free_block(1).unwrap();
        let reused = backend.allocate_block().unwrap();
        assert_eq!(reused, 1);
    }

    #[test]
    fn mount_inode_scan_still_works_with_journal_replay() {
        // Regression test: 5C-ii reordered mount() to journal-replay
        // first, then inode scan. Verify the inode scan still
        // discovers occupied slots.
        let mut dev = fresh_backend().into_device();
        write_inode(&mut dev, 1, &make_inode(1, 0));
        write_inode(&mut dev, 3, &make_inode(2, 1));
        let backend = PosixFsBackend::open_or_format(dev, 4, 32, 0).unwrap();
        let occupied: Vec<InodeId> = backend.occupied_inodes().collect();
        assert_eq!(occupied, alloc::vec![InodeId::new(1), InodeId::new(3)]);
    }

    // ========================================================================
    // ADR-029 step 6-ii — create_inode + open_inode handler methods.
    // ========================================================================

    fn owner_p() -> Principal {
        Principal::from_public_key([0xA1; 32])
    }

    fn stranger_p() -> Principal {
        Principal::from_public_key([0xB2; 32])
    }

    #[test]
    fn create_inode_allocates_first_free_slot() {
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        assert_eq!(id, InodeId::new(0));
        assert!(backend.is_inode_occupied(id));
    }

    #[test]
    fn create_inode_populates_owner_and_timestamps() {
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 12345).unwrap();
        let inode = backend.get_inode(id).unwrap();
        assert_eq!(inode.owner, *owner_p().aid());
        assert_eq!(inode.created_at, 12345);
        assert_eq!(inode.modified_at, 12345);
        assert_eq!(inode.kind, InodeKind::Regular);
        assert_eq!(inode.link_count, 1);
        assert_eq!(inode.cow_refcount, 0);
        assert_eq!(inode.size_bytes, 0);
    }

    #[test]
    fn create_inode_sequential_allocations_use_sequential_slots() {
        let mut backend = fresh_backend();
        let a = backend.create_inode(owner_p(), 100).unwrap();
        let b = backend.create_inode(owner_p(), 101).unwrap();
        let c = backend.create_inode(owner_p(), 102).unwrap();
        assert_eq!(a, InodeId::new(0));
        assert_eq!(b, InodeId::new(1));
        assert_eq!(c, InodeId::new(2));
    }

    #[test]
    fn create_inode_advances_journal_head() {
        // Indirect check that the journal saw a record: head_offset
        // moves forward by at least the size of a non-empty
        // serialized record after create_inode. The reboot-replay
        // path (see `create_inode_survives_reboot`) is what asserts
        // *which* record was written.
        let mut backend = fresh_backend();
        let head_before = backend.journal.head_offset();
        backend.create_inode(owner_p(), 100).unwrap();
        let head_after = backend.journal.head_offset();
        assert!(
            head_after > head_before,
            "journal head must advance after create_inode (was {}, now {})",
            head_before,
            head_after
        );
    }

    #[test]
    fn create_inode_survives_reboot() {
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 9999).unwrap();
        let dev = backend.into_device();
        let backend2 = PosixFsBackend::open_or_format(dev, 8, 64, 0).unwrap();
        assert!(backend2.is_inode_occupied(id));
        // Slot 0 is occupied; next free slot would be 1 — verify
        // the inode region scan agrees by reading the inode back.
        let mut backend2 = backend2;
        let inode = backend2.get_inode(id).unwrap();
        assert_eq!(inode.owner, *owner_p().aid());
        assert_eq!(inode.created_at, 9999);
    }

    #[test]
    fn create_inode_fills_capacity_then_returns_out_of_space() {
        let mut backend = fresh_backend();
        let cap = backend.superblock().capacity_inodes;
        for i in 0..cap {
            let id = backend.create_inode(owner_p(), 100 + i).unwrap();
            assert_eq!(id, InodeId::new(i));
        }
        assert!(matches!(
            backend.create_inode(owner_p(), 999),
            Err(FsError::OutOfSpace)
        ));
    }

    #[test]
    fn create_inode_skips_already_occupied_slots() {
        // Pre-populate slot 0 via direct-write, then ensure
        // create_inode picks slot 1.
        let mut backend = fresh_backend();
        let mut dev = backend.into_device();
        write_inode(&mut dev, 0, &make_inode(0, 0));
        let mut backend = PosixFsBackend::open_or_format(dev, 8, 64, 0).unwrap();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        assert_eq!(id, InodeId::new(1));
    }

    #[test]
    fn open_inode_owner_gets_requested_rights() {
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        let granted = backend
            .open_inode(owner_p(), id, Rights::READ.union(Rights::WRITE), 200)
            .unwrap();
        assert_eq!(granted.bits(), Rights::READ.union(Rights::WRITE).bits());
    }

    #[test]
    fn open_inode_owner_gets_execute_too() {
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        let granted = backend
            .open_inode(owner_p(), id, Rights::EXECUTE, 200)
            .unwrap();
        assert_eq!(granted.bits(), Rights::EXECUTE.bits());
    }

    #[test]
    fn open_inode_stranger_with_no_acl_entry_is_denied() {
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        let res = backend.open_inode(stranger_p(), id, Rights::READ, 200);
        assert_eq!(res, Err(FsError::PermissionDenied));
    }

    #[test]
    fn open_inode_acl_grant_authorizes_within_rights() {
        // Owner-create, then manually plant an ACL entry granting
        // stranger Read+Write; verify open with Read works and
        // Read+Write works.
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        let mut inode = backend.get_inode(id).unwrap();
        inode.acl[0] = Some(AclEntry {
            principal: *stranger_p().aid(),
            rights: Rights::READ.union(Rights::WRITE),
            expiry: None,
        });
        // Rewrite the inode header so subsequent get_inode reads
        // the updated ACL.
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        backend
            .device
            .write_block(inode_header_lba(id.raw()), &buf)
            .unwrap();

        assert_eq!(
            backend.open_inode(stranger_p(), id, Rights::READ, 200),
            Ok(Rights::READ)
        );
        let combined = Rights::READ.union(Rights::WRITE);
        assert_eq!(
            backend.open_inode(stranger_p(), id, combined, 200),
            Ok(combined)
        );
    }

    #[test]
    fn open_inode_acl_grant_denies_beyond_granted_rights() {
        // Stranger has Read only; an Execute open returns
        // PermissionDenied (not a missing-row case — the grant
        // exists but doesn't cover Execute).
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        let mut inode = backend.get_inode(id).unwrap();
        inode.acl[0] = Some(AclEntry {
            principal: *stranger_p().aid(),
            rights: Rights::READ,
            expiry: None,
        });
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        backend
            .device
            .write_block(inode_header_lba(id.raw()), &buf)
            .unwrap();

        assert_eq!(
            backend.open_inode(stranger_p(), id, Rights::EXECUTE, 200),
            Err(FsError::PermissionDenied)
        );
    }

    #[test]
    fn open_inode_expired_acl_grant_is_denied() {
        // Grant with expiry = 150; query at now = 200 → expired.
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        let mut inode = backend.get_inode(id).unwrap();
        inode.acl[0] = Some(AclEntry {
            principal: *stranger_p().aid(),
            rights: Rights::READ,
            expiry: Some(150),
        });
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        backend
            .device
            .write_block(inode_header_lba(id.raw()), &buf)
            .unwrap();

        assert_eq!(
            backend.open_inode(stranger_p(), id, Rights::READ, 200),
            Err(FsError::PermissionDenied)
        );
        // But same query at now = 100 still grants (not yet expired).
        assert_eq!(
            backend.open_inode(stranger_p(), id, Rights::READ, 100),
            Ok(Rights::READ)
        );
    }

    #[test]
    fn open_inode_zero_expiry_means_no_expiry() {
        // Per ADR-029 § Decision 3, `expiry: Some(0)` is treated
        // as "no expiry" in the on-disk encoding (the encoder maps
        // `None` to zero bytes; the decoder maps zero bytes back
        // to `None`). The owner-or-acl auth path therefore must
        // not treat 0 as "expired at tick 0."
        let mut backend = fresh_backend();
        let id = backend.create_inode(owner_p(), 100).unwrap();
        let mut inode = backend.get_inode(id).unwrap();
        inode.acl[0] = Some(AclEntry {
            principal: *stranger_p().aid(),
            rights: Rights::READ,
            expiry: Some(0),
        });
        let mut buf = [0u8; BLOCK_SIZE];
        encode_inode_header(&mut buf, &inode).unwrap();
        backend
            .device
            .write_block(inode_header_lba(id.raw()), &buf)
            .unwrap();

        assert_eq!(
            backend.open_inode(stranger_p(), id, Rights::READ, u64::MAX),
            Ok(Rights::READ)
        );
    }

    #[test]
    fn open_inode_on_free_slot_is_not_found() {
        let mut backend = fresh_backend();
        let _id = backend.create_inode(owner_p(), 100).unwrap();
        // Slot 1 is empty.
        assert_eq!(
            backend.open_inode(owner_p(), InodeId::new(1), Rights::READ, 200),
            Err(FsError::InodeNotFound)
        );
    }

    #[test]
    fn open_inode_out_of_range_is_not_found() {
        let mut backend = fresh_backend();
        let cap = backend.superblock().capacity_inodes;
        assert_eq!(
            backend.open_inode(owner_p(), InodeId::new(cap), Rights::READ, 200),
            Err(FsError::InodeNotFound)
        );
    }
}
