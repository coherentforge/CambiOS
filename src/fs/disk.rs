// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Persistent, disk-backed `ObjectStore`.
//!
//! The on-disk format is specified in ADR-010. This module is the reference
//! reader/writer of that format. It is generic over any `BlockDevice` — the
//! same code path is exercised by unit tests against `MemBlockDevice` and
//! at runtime against `VirtioBlkDevice`.
//!
//! ## Structure
//!
//! - `DiskObjectStore<B>` — generic store. Owns a `B: BlockDevice` and the
//!   in-memory indices (`hash -> slot`, per-slot free bit). No trait objects
//!   anywhere on the path: `OBJECT_STORE` in `lib.rs` holds an
//!   `ObjectStoreBackend` enum that dispatches via match arms (ADR-003 §
//!   Divergence), so backend selection is monomorphized at compile time.
//! - Encoding helpers (`encode_superblock`, `encode_record_header`, ...) are
//!   pure functions over byte buffers — testable on host without a device.
//! - All numeric bounds (`MAX_OBJECTS_ON_DISK`, `MAX_CONTENT_BYTES_ON_DISK`)
//!   are documented in docs/ASSUMPTIONS.md per Development Convention 8.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use cambios_abi::Extent;

use crate::fs::bitmap::{decode_from_blocks, encode_to_blocks, BlockBitmap};
use crate::fs::block::{Block, BlockDevice, BlockError, BLOCK_SIZE};
use crate::fs::journal::{Journal, JournalRecord};
use crate::fs::{
    content_hash, CambiObject, ObjectCapSet, ObjectMeta, ObjectRights, ObjectStore,
    SignatureAlgo, SignatureBytes, StoreError, MAX_OBJECT_CAPS,
};
use crate::ipc::Principal;

// ============================================================================
// Format constants
// ============================================================================

/// ARCHITECTURAL: superblock magic. Wire fact; changing it is a new format
/// family, not a version bump.
pub const ARCOBJ_MAGIC: [u8; 8] = *b"ARCOBJ00";

/// ARCHITECTURAL: v1 record-header magic for an occupied slot. Absence
/// (or any other 8-byte value) = free / never-written. Content for v1
/// records lives inline in the slot's second block (LBA `2 + 2*i`).
pub const ARCOREC_MAGIC_OCCUPIED: [u8; 8] = *b"ARCOREC1";

/// ARCHITECTURAL: v2 record-header magic per
/// [ADR-010 § Divergence 3](../../docs/adr/010-persistent-object-store-on-disk-format.md).
/// v2 records carry a 16-entry extent array at offset 568..760; content
/// data lives in the shared data region, not inline. Mount distinguishes
/// v1 vs v2 records by this magic byte sequence; v1 records remain
/// readable forever per the Divergence's no-migration commitment.
pub const ARCOREC_MAGIC_V2: [u8; 8] = *b"ARCOREC2";

/// ARCHITECTURAL: current format version. Mount rejects unknown versions.
/// Version 2 lands per [ADR-010 § Divergence 3](../../docs/adr/010-persistent-object-store-on-disk-format.md)
/// with the shared block-allocation bitmap, the metadata journal,
/// and the multi-block content layout. v1 disks are rejected at
/// mount; new puts default to v2 records (per § Divergence 3 "New
/// puts default to v2 once this Divergence lands"). v1 *records*
/// remain decodable forever on v2 disks via magic-byte dispatch.
pub const FORMAT_VERSION: u32 = 2;

/// ARCHITECTURAL: maximum data-region extents per v2 CambiObject record.
/// Matches `cambios_abi::MAX_EXTENTS_PER_INODE` (= 16) so journal records
/// (`ExtentUpdate`, shared between POSIX and CambiObject) carry one
/// canonical extent-array shape. ADR-010 § Divergence 3 fixes 192 bytes
/// (offset 568..760) for the extent array at 12 bytes per entry.
pub const MAX_EXTENTS_PER_CAMBIOBJECT: usize = cambios_abi::MAX_EXTENTS_PER_INODE;

/// SCAFFOLDING: maximum number of object slots this implementation supports.
/// Why: v1 workload is human-scale (identity attestations, small documents,
///      social log entries). With the ~25%-of-bound rule, we expect ~1000
///      objects in realistic v1 use; 4096 gives ~4x headroom.
///      Memory cost: 4096 entries × (~48 bytes per BTreeMap entry + 1 bit
///      free-map) ≈ 200 KiB against the 4 MiB kernel heap.
/// Replace when: social log or SSB federation cause object counts to
///      approach ~1000; bump to 16384 or 65536, verify heap budget,
///      update docs/ASSUMPTIONS.md.
pub const MAX_OBJECTS_ON_DISK: u64 = 4096;

/// SCAFFOLDING: maximum content length per object on disk. For v1
/// records this is the inline content block (one `BLOCK_SIZE` per
/// slot). For v2 records (post-ADR-010 § Divergence 3) the content
/// can span up to `MAX_EXTENTS_PER_CAMBIOBJECT × MAX_EXTENT_BLOCKS`
/// blocks; this constant is the v1 cap and stays here for v1 record
/// validation.
pub const MAX_CONTENT_BYTES_ON_DISK: usize = BLOCK_SIZE;

/// SCAFFOLDING: maximum data-region blocks the v2 superblock can
/// declare. The bitmap region grows linearly with this value
/// (`MAX_DATA_BLOCKS_ON_DISK / 32768` blocks). 1B blocks × 4 KiB
/// per block = 4 TiB of addressable v2 content; matches POSIX's
/// `MAX_BLOCKS_ON_DISK` so cross-backend reasoning carries.
/// Replace when: a v1+ deployment wants >4 TiB CambiObject region;
/// tiered/sparse bitmap representations land first.
pub const MAX_DATA_BLOCKS_ON_DISK: u64 = 1_073_741_824;

// Superblock field offsets (LBA 0). v2 superblock per
// ADR-010 § Divergence 3: the fixed-field region grows to declare
// the bitmap, journal, and data regions. v1 superblocks (version=1)
// are rejected at mount; new disks are formatted as v2.
const SB_OFF_MAGIC: usize = 0;
const SB_OFF_VERSION: usize = 8;
const SB_OFF_CAPACITY_SLOTS: usize = 12;
const SB_OFF_CAPACITY_DATA_BLOCKS: usize = 20;
const SB_OFF_BITMAP_REGION_LBA: usize = 28;
const SB_OFF_JOURNAL_REGION_LBA: usize = 36;
const SB_OFF_DATA_REGION_LBA: usize = 44;
const SB_OFF_JOURNAL_CAPACITY_BYTES: usize = 52;
const SB_OFF_LAST_CHECKPOINT_OFFSET: usize = 60;
const SB_OFF_GENERATION: usize = 68;
const SB_OFF_CREATED_AT: usize = 76;
const SB_LAST_FIELD_END: usize = 84;
const SB_OFF_CHECKSUM: usize = 4088;
const SB_CHECKSUM_COVER_END: usize = 4088;

/// ARCHITECTURAL: journal region size in bytes. Matches POSIX backend's
/// `JOURNAL_BYTES` per ADR-029 § Decision 5 — both backends use the
/// same 16 MiB circular log. The shared journal record format (see
/// `src/fs/journal.rs`) is what makes cross-backend allocation
/// transactions possible.
pub const JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// ARCHITECTURAL: journal region size in blocks. Derived from
/// `JOURNAL_BYTES` and `BLOCK_SIZE`.
pub const JOURNAL_BLOCKS: u64 = JOURNAL_BYTES / BLOCK_SIZE as u64;

// Record-header field offsets (LBA 1 + 2*slot)
const HDR_OFF_MAGIC: usize = 0;
const HDR_OFF_CONTENT_LEN: usize = 8;
const HDR_OFF_CONTENT_HASH: usize = 12;
const HDR_OFF_AUTHOR: usize = 44;
const HDR_OFF_OWNER: usize = 76;
const HDR_OFF_SIG_ALGO: usize = 108;
const HDR_OFF_LINEAGE_PRESENT: usize = 109;
const HDR_OFF_CAP_COUNT: usize = 110;
const HDR_OFF_CREATED_AT: usize = 112;
const HDR_OFF_SIGNATURE: usize = 120;
const HDR_OFF_LINEAGE: usize = 184;
const HDR_OFF_CAPS: usize = 216;
const HDR_OFF_CHECKSUM: usize = 4088;
const HDR_CHECKSUM_COVER_END: usize = 4088;

// Cap entry layout (44 bytes each)
const CAP_ENTRY_SIZE: usize = 44;
const CAP_OFF_PRINCIPAL: usize = 0;
const CAP_OFF_EXPIRY: usize = 32;
const CAP_OFF_RIGHTS: usize = 40;
// rights bits
const CAP_RIGHT_READ: u8 = 0b0001;
const CAP_RIGHT_WRITE: u8 = 0b0010;
const CAP_RIGHT_EXECUTE: u8 = 0b0100;

// v2 record-header extent array layout (ADR-010 § Divergence 3).
// Extents start where v1's reserved region begins, occupy 192 bytes
// (16 × 12), and leave the remaining reserved bytes for ML-DSA + future
// extensions.
const HDR_V2_OFF_EXTENTS: usize = 568;
const EXTENT_PACKED_SIZE: usize = 12;
const HDR_V2_EXTENTS_BYTES: usize = MAX_EXTENTS_PER_CAMBIOBJECT * EXTENT_PACKED_SIZE;
const HDR_V2_OFF_EXTENT_REGION_END: usize = HDR_V2_OFF_EXTENTS + HDR_V2_EXTENTS_BYTES;
const EXTENT_OFF_START_LBA: usize = 0;
const EXTENT_OFF_BLOCK_COUNT: usize = 8;

// LBA helpers
const SUPERBLOCK_LBA: u64 = 0;
#[inline]
fn header_lba(slot: u64) -> u64 {
    1 + 2 * slot
}
#[inline]
fn content_lba(slot: u64) -> u64 {
    2 + 2 * slot
}

/// Number of bitmap-region blocks required to track `capacity_data_blocks`
/// bits. Mirrors `bitmap_region_blocks_for` in `crate::fs::posix` so
/// both backends compute the same shape from the same input.
#[inline]
const fn bitmap_region_blocks_for(capacity_data_blocks: u64) -> u64 {
    capacity_data_blocks.div_ceil(8 * BLOCK_SIZE as u64)
}

/// Total blocks required to hold a v2 disk with the given geometry:
/// superblock (1) + slot region (`2*capacity_slots`) + bitmap region
/// (`bitmap_region_blocks_for(capacity_data_blocks)`) + journal region
/// (`JOURNAL_BLOCKS`) + data region (`capacity_data_blocks`).
#[inline]
fn total_blocks_for_capacity(capacity_slots: u64, capacity_data_blocks: u64) -> u64 {
    1 + 2 * capacity_slots
        + bitmap_region_blocks_for(capacity_data_blocks)
        + JOURNAL_BLOCKS
        + capacity_data_blocks
}

/// Blake3 truncated to 8 bytes, used as a torn-write detector on disk
/// headers. The cryptographic strength matters less than determinism;
/// we already pull in `blake3` for content addressing, so reusing it
/// avoids adding a CRC dependency.
fn checksum8(data: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&blake3::hash(data).as_bytes()[0..8]);
    out
}

// ============================================================================
// Free-slot bitmap
// ============================================================================

/// Bit-packed free-slot tracker. One bit per slot: `1 = free`, `0 = occupied`.
/// Kept in memory only; the disk format is stateless w.r.t. free-tracking
/// (mount scans record magics).
struct FreeMap {
    bits: Vec<u64>,
    len: u64,
}

impl FreeMap {
    fn new(len: u64) -> Self {
        let words = len.div_ceil(64) as usize;
        Self {
            bits: vec![u64::MAX; words],
            len,
        }
    }

    fn mark_occupied(&mut self, i: u64) {
        debug_assert!(i < self.len);
        let (w, b) = ((i / 64) as usize, i % 64);
        self.bits[w] &= !(1u64 << b);
    }

    fn mark_free(&mut self, i: u64) {
        debug_assert!(i < self.len);
        let (w, b) = ((i / 64) as usize, i % 64);
        self.bits[w] |= 1u64 << b;
    }

    fn first_free(&self) -> Option<u64> {
        for (w_idx, &w) in self.bits.iter().enumerate() {
            if w != 0 {
                let b = w.trailing_zeros() as u64;
                let i = (w_idx as u64) * 64 + b;
                if i < self.len {
                    return Some(i);
                }
            }
        }
        None
    }
}

// ============================================================================
// Superblock encoding
// ============================================================================

/// Encode the v2 superblock. Caller writes the result to LBA 0. The
/// `Superblock` struct carries the geometry; the encoder writes it to
/// the fixed offsets defined above and appends the Blake3 checksum.
fn encode_superblock(buf: &mut Block, sb: &Superblock) {
    buf.fill(0);
    buf[SB_OFF_MAGIC..SB_OFF_MAGIC + 8].copy_from_slice(&ARCOBJ_MAGIC);
    buf[SB_OFF_VERSION..SB_OFF_VERSION + 4].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf[SB_OFF_CAPACITY_SLOTS..SB_OFF_CAPACITY_SLOTS + 8]
        .copy_from_slice(&sb.capacity_slots.to_le_bytes());
    buf[SB_OFF_CAPACITY_DATA_BLOCKS..SB_OFF_CAPACITY_DATA_BLOCKS + 8]
        .copy_from_slice(&sb.capacity_data_blocks.to_le_bytes());
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
    buf[SB_OFF_GENERATION..SB_OFF_GENERATION + 8].copy_from_slice(&sb.generation.to_le_bytes());
    buf[SB_OFF_CREATED_AT..SB_OFF_CREATED_AT + 8].copy_from_slice(&sb.created_at.to_le_bytes());
    // SB_LAST_FIELD_END..SB_OFF_CHECKSUM stays zero from buf.fill(0).
    let cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
    buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8].copy_from_slice(&cs);
}

/// In-memory representation of the v2 superblock. Carries the full
/// geometry; encoder reconstitutes the on-disk magic + checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Superblock {
    capacity_slots: u64,
    capacity_data_blocks: u64,
    bitmap_region_lba: u64,
    journal_region_lba: u64,
    data_region_lba: u64,
    journal_capacity_bytes: u64,
    last_checkpoint_offset: u64,
    generation: u64,
    created_at: u64,
}

// ────────────────────────────────────────────────────────────────────────
// Fixed-size little-endian readers.
//
// The on-disk format places multi-byte fields at constant offsets within
// a `Block` (`[u8; 4096]`). The natural Rust idiom is
// `slice.try_into().unwrap()` to convert a `&[u8]` slice into a fixed
// `[u8; N]` for `from_le_bytes` — but the unwrap is a panic the
// compiler cannot statically eliminate from the slice path. These
// helpers use literal byte indexing into the array, which monomorphizes
// to constant-folded bounds checks at every call site (every offset
// here is a `const usize` well below `BLOCK_SIZE = 4096`), and so are
// provably panic-free per CLAUDE.md's "no panics in non-test kernel
// code" rule.
// ────────────────────────────────────────────────────────────────────────

#[inline]
const fn read_u16_le(buf: &Block, offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

#[inline]
const fn read_u32_le(buf: &Block, offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

#[inline]
const fn read_u64_le(buf: &Block, offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuperblockState {
    Blank,
    Valid(Superblock),
    /// Magic matches, version doesn't. v1 disks land here under v2 code.
    UnknownVersion(u32),
    Corrupt,
}

fn classify_superblock(buf: &Block) -> SuperblockState {
    // Blank disk detection: all zeros in the magic field and checksum field.
    let magic = &buf[SB_OFF_MAGIC..SB_OFF_MAGIC + 8];
    if magic.iter().all(|&b| b == 0) {
        return SuperblockState::Blank;
    }
    if magic != ARCOBJ_MAGIC {
        return SuperblockState::Corrupt;
    }
    let expected_cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
    let on_disk_cs = &buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8];
    if on_disk_cs != expected_cs {
        return SuperblockState::Corrupt;
    }
    let version = read_u32_le(buf, SB_OFF_VERSION);
    if version != FORMAT_VERSION {
        return SuperblockState::UnknownVersion(version);
    }
    let capacity_slots = read_u64_le(buf, SB_OFF_CAPACITY_SLOTS);
    let capacity_data_blocks = read_u64_le(buf, SB_OFF_CAPACITY_DATA_BLOCKS);
    let bitmap_region_lba = read_u64_le(buf, SB_OFF_BITMAP_REGION_LBA);
    let journal_region_lba = read_u64_le(buf, SB_OFF_JOURNAL_REGION_LBA);
    let data_region_lba = read_u64_le(buf, SB_OFF_DATA_REGION_LBA);
    let journal_capacity_bytes = read_u64_le(buf, SB_OFF_JOURNAL_CAPACITY_BYTES);
    let last_checkpoint_offset = read_u64_le(buf, SB_OFF_LAST_CHECKPOINT_OFFSET);
    let generation = read_u64_le(buf, SB_OFF_GENERATION);
    let created_at = read_u64_le(buf, SB_OFF_CREATED_AT);
    SuperblockState::Valid(Superblock {
        capacity_slots,
        capacity_data_blocks,
        bitmap_region_lba,
        journal_region_lba,
        data_region_lba,
        journal_capacity_bytes,
        last_checkpoint_offset,
        generation,
        created_at,
    })
}

// ============================================================================
// Record encoding / decoding
// ============================================================================

fn encode_record_header(buf: &mut Block, obj: &CambiObject) -> Result<(), StoreError> {
    if obj.content.len() > MAX_CONTENT_BYTES_ON_DISK {
        return Err(StoreError::InvalidObject);
    }
    if obj.capabilities.len() > MAX_OBJECT_CAPS {
        return Err(StoreError::InvalidObject);
    }

    buf.fill(0);
    buf[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8].copy_from_slice(&ARCOREC_MAGIC_OCCUPIED);
    buf[HDR_OFF_CONTENT_LEN..HDR_OFF_CONTENT_LEN + 4]
        .copy_from_slice(&(obj.content.len() as u32).to_le_bytes());
    buf[HDR_OFF_CONTENT_HASH..HDR_OFF_CONTENT_HASH + 32].copy_from_slice(&obj.content_hash);
    buf[HDR_OFF_AUTHOR..HDR_OFF_AUTHOR + 32].copy_from_slice(&obj.author);
    buf[HDR_OFF_OWNER..HDR_OFF_OWNER + 32].copy_from_slice(&obj.owner);
    buf[HDR_OFF_SIG_ALGO] = obj.sig_algo as u8;
    buf[HDR_OFF_LINEAGE_PRESENT] = if obj.lineage.is_some() { 1 } else { 0 };
    buf[HDR_OFF_CAP_COUNT..HDR_OFF_CAP_COUNT + 2]
        .copy_from_slice(&(obj.capabilities.len() as u16).to_le_bytes());
    buf[HDR_OFF_CREATED_AT..HDR_OFF_CREATED_AT + 8].copy_from_slice(&obj.created_at.to_le_bytes());
    buf[HDR_OFF_SIGNATURE..HDR_OFF_SIGNATURE + 64].copy_from_slice(&obj.signature.data);
    if let Some(lineage) = obj.lineage {
        buf[HDR_OFF_LINEAGE..HDR_OFF_LINEAGE + 32].copy_from_slice(&lineage);
    }

    for (i, cap) in obj.capabilities.iter().enumerate() {
        let base = HDR_OFF_CAPS + i * CAP_ENTRY_SIZE;
        buf[base + CAP_OFF_PRINCIPAL..base + CAP_OFF_PRINCIPAL + 32]
            .copy_from_slice(cap.principal.aid());
        let expiry = cap.expiry.unwrap_or(0);
        buf[base + CAP_OFF_EXPIRY..base + CAP_OFF_EXPIRY + 8]
            .copy_from_slice(&expiry.to_le_bytes());
        let mut rights = 0u8;
        if cap.rights.read {
            rights |= CAP_RIGHT_READ;
        }
        if cap.rights.write {
            rights |= CAP_RIGHT_WRITE;
        }
        if cap.rights.execute {
            rights |= CAP_RIGHT_EXECUTE;
        }
        buf[base + CAP_OFF_RIGHTS] = rights;
    }

    let cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
    buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8].copy_from_slice(&cs);
    Ok(())
}

fn encode_content_block(buf: &mut Block, content: &[u8]) {
    buf.fill(0);
    buf[..content.len()].copy_from_slice(content);
}

/// Parsed record-header. `None` means "slot is free" (not an error).
struct HeaderDecoded {
    content_len: u32,
    content_hash: [u8; 32],
    author: [u8; 32],
    owner: [u8; 32],
    sig_algo: SignatureAlgo,
    lineage: Option<[u8; 32]>,
    cap_count: u16,
    created_at: u64,
    signature: SignatureBytes,
    capabilities: ObjectCapSet,
}

fn decode_record_header(buf: &Block) -> Result<Option<HeaderDecoded>, StoreError> {
    let magic = &buf[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8];
    if magic != ARCOREC_MAGIC_OCCUPIED {
        return Ok(None);
    }
    let expected_cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
    if buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8] != expected_cs {
        // Torn write / corruption. Treat as free per ADR-010 mount protocol.
        return Ok(None);
    }

    let content_len = read_u32_le(buf, HDR_OFF_CONTENT_LEN);
    if content_len as usize > MAX_CONTENT_BYTES_ON_DISK {
        return Err(StoreError::InvalidObject);
    }

    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&buf[HDR_OFF_CONTENT_HASH..HDR_OFF_CONTENT_HASH + 32]);
    let mut author = [0u8; 32];
    author.copy_from_slice(&buf[HDR_OFF_AUTHOR..HDR_OFF_AUTHOR + 32]);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&buf[HDR_OFF_OWNER..HDR_OFF_OWNER + 32]);

    let sig_algo = match buf[HDR_OFF_SIG_ALGO] {
        0 => SignatureAlgo::Ed25519,
        1 => SignatureAlgo::MlDsa65,
        _ => return Err(StoreError::InvalidObject),
    };
    let lineage = if buf[HDR_OFF_LINEAGE_PRESENT] == 1 {
        let mut l = [0u8; 32];
        l.copy_from_slice(&buf[HDR_OFF_LINEAGE..HDR_OFF_LINEAGE + 32]);
        Some(l)
    } else {
        None
    };
    let cap_count = read_u16_le(buf, HDR_OFF_CAP_COUNT);
    if cap_count as usize > MAX_OBJECT_CAPS {
        return Err(StoreError::InvalidObject);
    }
    let created_at = read_u64_le(buf, HDR_OFF_CREATED_AT);

    let mut signature = SignatureBytes::EMPTY;
    signature
        .data
        .copy_from_slice(&buf[HDR_OFF_SIGNATURE..HDR_OFF_SIGNATURE + 64]);

    let mut caps = ObjectCapSet::new();
    for i in 0..cap_count as usize {
        let base = HDR_OFF_CAPS + i * CAP_ENTRY_SIZE;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[base + CAP_OFF_PRINCIPAL..base + CAP_OFF_PRINCIPAL + 32]);
        let expiry_raw = read_u64_le(buf, base + CAP_OFF_EXPIRY);
        let expiry = if expiry_raw == 0 { None } else { Some(expiry_raw) };
        let rights_bits = buf[base + CAP_OFF_RIGHTS];
        let rights = ObjectRights {
            read: rights_bits & CAP_RIGHT_READ != 0,
            write: rights_bits & CAP_RIGHT_WRITE != 0,
            execute: rights_bits & CAP_RIGHT_EXECUTE != 0,
        };
        caps.grant(Principal::from_public_key(pk), rights, expiry)
            .map_err(|_| StoreError::InvalidObject)?;
    }

    Ok(Some(HeaderDecoded {
        content_len,
        content_hash,
        author,
        owner,
        sig_algo,
        lineage,
        cap_count,
        created_at,
        signature,
        capabilities: caps,
    }))
}

fn rebuild_cambi_object(header: HeaderDecoded, content_block: &Block) -> Result<CambiObject, StoreError> {
    let content_len = header.content_len as usize;
    let content = content_block[..content_len].to_vec();
    let computed = content_hash(&content);
    if computed != header.content_hash {
        return Err(StoreError::InvalidObject);
    }
    Ok(CambiObject {
        content_hash: header.content_hash,
        author: header.author,
        owner: header.owner,
        sig_algo: header.sig_algo,
        signature: header.signature,
        capabilities: header.capabilities,
        lineage: header.lineage,
        created_at: header.created_at,
        content,
    })
}

// ============================================================================
// Format-time geometry + journal-replay helpers
// ============================================================================

/// Geometry picked by `open_or_format` when it has to format a blank
/// device. `desired_capacity_slots` is clamped by both the device size
/// and `MAX_OBJECTS_ON_DISK`; `capacity_data_blocks` fills the
/// remaining device space (minus the bitmap, journal, and a small
/// headroom block).
struct FormatGeometry {
    capacity_slots: u64,
    capacity_data_blocks: u64,
}

fn pick_format_geometry(
    dev_blocks: u64,
    desired_capacity_slots: u64,
) -> Result<FormatGeometry, StoreError> {
    if dev_blocks < 1 + 2 + 1 + JOURNAL_BLOCKS + 1 {
        return Err(StoreError::InvalidObject);
    }
    let capacity_slots = desired_capacity_slots.min(MAX_OBJECTS_ON_DISK).max(1);
    let used_by_slots = 1 + 2 * capacity_slots + JOURNAL_BLOCKS;
    if used_by_slots + 2 > dev_blocks {
        // Need at least 1 bitmap block + 1 data block remaining.
        return Err(StoreError::InvalidObject);
    }
    // Remaining blocks split between bitmap and data. Each bitmap
    // block tracks 32768 data blocks, so the bitmap overhead is
    // ~1/32769 of the data region — tiny. We approximate by
    // reserving `ceil(remaining / 32769)` for the bitmap and the
    // rest for data, then verify the total fits.
    let remaining = dev_blocks - used_by_slots;
    let mut data_blocks = remaining - 1; // reserve at least 1 bitmap block
    let bitmap_blocks = bitmap_region_blocks_for(data_blocks);
    if used_by_slots + bitmap_blocks + data_blocks > dev_blocks {
        // Shrink data_blocks by the bitmap overhead and re-check.
        let overhead = used_by_slots + bitmap_blocks + data_blocks - dev_blocks;
        data_blocks = data_blocks.saturating_sub(overhead);
    }
    if data_blocks == 0 {
        return Err(StoreError::InvalidObject);
    }
    Ok(FormatGeometry {
        capacity_slots,
        capacity_data_blocks: data_blocks.min(MAX_DATA_BLOCKS_ON_DISK),
    })
}

/// Apply the bitmap-side effect of a single journal record to an
/// in-memory bitmap. Records that don't mutate the bitmap are no-ops;
/// only `ExtentUpdate` carries bitmap mutations. Mirrors
/// `crate::fs::posix::apply_bitmap_mutations` — both backends use the
/// same record-shape so cross-backend journal records (which the
/// step 6+ kernel singleton will see) apply consistently regardless
/// of which side created them.
fn apply_bitmap_mutations(
    bitmap: &mut BlockBitmap,
    rec: &JournalRecord,
) -> Result<(), crate::fs::journal::JournalError> {
    if let JournalRecord::ExtentUpdate(eu) = rec {
        for m in &eu.mutations {
            match m {
                crate::fs::journal::BitmapMutation::Set(b) => bitmap.mark_occupied(*b)?,
                crate::fs::journal::BitmapMutation::Clear(b) => bitmap.mark_free(*b)?,
            }
        }
    }
    Ok(())
}

// ============================================================================
// v2 record codec (ADR-010 § Divergence 3)
// ============================================================================
//
// v2 records share the v1 fixed-field layout (offsets 0..568) so the
// content-addressing, signature, ACL, and lineage semantics are
// byte-identical between versions. v2 adds a 16-entry extent array at
// offset 568..760 (192 bytes) replacing the leading 192 bytes of v1's
// reserved region. The remaining 3328 bytes (760..4088) stay reserved
// for the future ML-DSA signature tail.
//
// Content for v2 records lives in the shared data region pointed to by
// the extent array; the slot's second block changes role from "content"
// to "reserved tail" (zero-filled in v1, ML-DSA-bound). Mount
// distinguishes versions by the leading 8-byte magic — `ARCOREC1` for
// v1, `ARCOREC2` for v2; anything else reads as a free slot.
//
// 5D-i lands the pure-function codec. The mount-side dispatch in
// `decode_record_header` that recognizes `ARCOREC2` lands in 5D-iii
// alongside the v2-aware get/put path; until then, decode_record_header
// continues to treat v2 magic as a free slot.

/// Decoded v2 record header. Mirrors `HeaderDecoded` (v1) plus the
/// extent array. `extents` carries the on-disk extents packed
/// contiguously from index 0; trailing slots are `None`. `content_len`
/// is the total length across all extents (not bounded by `BLOCK_SIZE`
/// the way v1 is).
struct HeaderDecodedV2 {
    content_len: u32,
    content_hash: [u8; 32],
    author: [u8; 32],
    owner: [u8; 32],
    sig_algo: SignatureAlgo,
    lineage: Option<[u8; 32]>,
    cap_count: u16,
    created_at: u64,
    signature: SignatureBytes,
    capabilities: ObjectCapSet,
    extents: [Option<Extent>; MAX_EXTENTS_PER_CAMBIOBJECT],
}

/// Validate that an extents array satisfies the contiguous-Some
/// invariant — `Some(_)` entries pack from index 0 and the first
/// `None` (if any) is followed by `None`s only. Mirrors
/// `crate::fs::posix::validate_inode`'s posture on extent arrays so
/// the on-disk canonical-form invariant is identical across backends.
fn validate_extents(
    extents: &[Option<Extent>; MAX_EXTENTS_PER_CAMBIOBJECT],
) -> Result<(), StoreError> {
    let mut saw_none = false;
    for slot in extents.iter() {
        if slot.is_none() {
            saw_none = true;
        } else if saw_none {
            return Err(StoreError::InvalidObject);
        }
    }
    Ok(())
}

/// Encode a v2 record header. `obj` supplies the shared fields
/// (content_hash, author, owner, signature, capabilities, lineage,
/// created_at); `content_len` is taken from `obj.content.len()` for
/// callers that pass the in-memory object. `extents` is the
/// caller-built array of (start_lba, block_count) pairs describing
/// where the content bytes live in the shared data region.
///
/// Caller invariants: `extents` must satisfy contiguous-Some (else
/// `InvalidObject`); `obj.capabilities.len() ≤ MAX_OBJECT_CAPS`.
/// The encoder is the canonical-form producer — trailing extent
/// slots are zero, the post-extent reserved region (760..4088) is
/// zero, the checksum is computed last.
fn encode_record_header_v2(
    buf: &mut Block,
    obj: &CambiObject,
    extents: &[Option<Extent>; MAX_EXTENTS_PER_CAMBIOBJECT],
) -> Result<(), StoreError> {
    if obj.capabilities.len() > MAX_OBJECT_CAPS {
        return Err(StoreError::InvalidObject);
    }
    validate_extents(extents)?;

    buf.fill(0);
    buf[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8].copy_from_slice(&ARCOREC_MAGIC_V2);
    buf[HDR_OFF_CONTENT_LEN..HDR_OFF_CONTENT_LEN + 4]
        .copy_from_slice(&(obj.content.len() as u32).to_le_bytes());
    buf[HDR_OFF_CONTENT_HASH..HDR_OFF_CONTENT_HASH + 32].copy_from_slice(&obj.content_hash);
    buf[HDR_OFF_AUTHOR..HDR_OFF_AUTHOR + 32].copy_from_slice(&obj.author);
    buf[HDR_OFF_OWNER..HDR_OFF_OWNER + 32].copy_from_slice(&obj.owner);
    buf[HDR_OFF_SIG_ALGO] = obj.sig_algo as u8;
    buf[HDR_OFF_LINEAGE_PRESENT] = if obj.lineage.is_some() { 1 } else { 0 };
    buf[HDR_OFF_CAP_COUNT..HDR_OFF_CAP_COUNT + 2]
        .copy_from_slice(&(obj.capabilities.len() as u16).to_le_bytes());
    buf[HDR_OFF_CREATED_AT..HDR_OFF_CREATED_AT + 8].copy_from_slice(&obj.created_at.to_le_bytes());
    buf[HDR_OFF_SIGNATURE..HDR_OFF_SIGNATURE + 64].copy_from_slice(&obj.signature.data);
    if let Some(lineage) = obj.lineage {
        buf[HDR_OFF_LINEAGE..HDR_OFF_LINEAGE + 32].copy_from_slice(&lineage);
    }

    for (i, cap) in obj.capabilities.iter().enumerate() {
        let base = HDR_OFF_CAPS + i * CAP_ENTRY_SIZE;
        buf[base + CAP_OFF_PRINCIPAL..base + CAP_OFF_PRINCIPAL + 32]
            .copy_from_slice(cap.principal.aid());
        let expiry = cap.expiry.unwrap_or(0);
        buf[base + CAP_OFF_EXPIRY..base + CAP_OFF_EXPIRY + 8]
            .copy_from_slice(&expiry.to_le_bytes());
        let mut rights = 0u8;
        if cap.rights.read {
            rights |= CAP_RIGHT_READ;
        }
        if cap.rights.write {
            rights |= CAP_RIGHT_WRITE;
        }
        if cap.rights.execute {
            rights |= CAP_RIGHT_EXECUTE;
        }
        buf[base + CAP_OFF_RIGHTS] = rights;
    }

    // Extents: 16 × 12 bytes starting at HDR_V2_OFF_EXTENTS. Unused
    // slots stay zero (canonical form). buf.fill(0) above already
    // zeroed the entire block, so trailing entries are correct by
    // construction.
    for (i, slot) in extents.iter().enumerate() {
        if let Some(extent) = slot {
            let base = HDR_V2_OFF_EXTENTS + i * EXTENT_PACKED_SIZE;
            buf[base + EXTENT_OFF_START_LBA..base + EXTENT_OFF_START_LBA + 8]
                .copy_from_slice(&extent.start_lba.to_le_bytes());
            buf[base + EXTENT_OFF_BLOCK_COUNT..base + EXTENT_OFF_BLOCK_COUNT + 4]
                .copy_from_slice(&extent.block_count.to_le_bytes());
        }
    }

    let cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
    buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8].copy_from_slice(&cs);
    Ok(())
}

/// Decode a v2 record header. `None` means "not a v2 record" (magic
/// mismatch or torn-write checksum failure — caller treats as free,
/// matching the v1 mount protocol). `Err` means "v2 magic + valid
/// checksum but malformed payload" (canonical-form violation, unknown
/// kind/version, out-of-range counts).
///
/// Per ADR-029 § Divergence 1's strict-canonical posture (adopted here
/// for v2 records): trailing extent slots past the last `Some(_)` must
/// be zero, the post-extent reserved region (760..4088) must be zero,
/// and extents must satisfy contiguous-Some on decode.
fn decode_record_header_v2(buf: &Block) -> Result<Option<HeaderDecodedV2>, StoreError> {
    let magic = &buf[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8];
    if magic != ARCOREC_MAGIC_V2 {
        return Ok(None);
    }
    let expected_cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
    if buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8] != expected_cs {
        // Torn write at this slot. Same posture as v1: treat as free.
        return Ok(None);
    }

    let content_len = read_u32_le(buf, HDR_OFF_CONTENT_LEN);
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&buf[HDR_OFF_CONTENT_HASH..HDR_OFF_CONTENT_HASH + 32]);
    let mut author = [0u8; 32];
    author.copy_from_slice(&buf[HDR_OFF_AUTHOR..HDR_OFF_AUTHOR + 32]);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&buf[HDR_OFF_OWNER..HDR_OFF_OWNER + 32]);

    let sig_algo = match buf[HDR_OFF_SIG_ALGO] {
        0 => SignatureAlgo::Ed25519,
        1 => SignatureAlgo::MlDsa65,
        _ => return Err(StoreError::InvalidObject),
    };
    let lineage = if buf[HDR_OFF_LINEAGE_PRESENT] == 1 {
        let mut l = [0u8; 32];
        l.copy_from_slice(&buf[HDR_OFF_LINEAGE..HDR_OFF_LINEAGE + 32]);
        Some(l)
    } else {
        None
    };
    let cap_count = read_u16_le(buf, HDR_OFF_CAP_COUNT);
    if cap_count as usize > MAX_OBJECT_CAPS {
        return Err(StoreError::InvalidObject);
    }
    let created_at = read_u64_le(buf, HDR_OFF_CREATED_AT);

    let mut signature = SignatureBytes::EMPTY;
    signature
        .data
        .copy_from_slice(&buf[HDR_OFF_SIGNATURE..HDR_OFF_SIGNATURE + 64]);

    let mut caps = ObjectCapSet::new();
    for i in 0..cap_count as usize {
        let base = HDR_OFF_CAPS + i * CAP_ENTRY_SIZE;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[base + CAP_OFF_PRINCIPAL..base + CAP_OFF_PRINCIPAL + 32]);
        let expiry_raw = read_u64_le(buf, base + CAP_OFF_EXPIRY);
        let expiry = if expiry_raw == 0 { None } else { Some(expiry_raw) };
        let rights_bits = buf[base + CAP_OFF_RIGHTS];
        let rights = ObjectRights {
            read: rights_bits & CAP_RIGHT_READ != 0,
            write: rights_bits & CAP_RIGHT_WRITE != 0,
            execute: rights_bits & CAP_RIGHT_EXECUTE != 0,
        };
        caps.grant(Principal::from_public_key(pk), rights, expiry)
            .map_err(|_| StoreError::InvalidObject)?;
    }

    // Decode extents. An entry is "present" iff `(start_lba != 0) ||
    // (block_count != 0)`. start_lba == 0 is impossible for a real
    // extent (block 0 is the superblock) so this serves as the
    // sentinel.
    let mut extents: [Option<Extent>; MAX_EXTENTS_PER_CAMBIOBJECT] =
        [None; MAX_EXTENTS_PER_CAMBIOBJECT];
    let mut saw_none = false;
    for i in 0..MAX_EXTENTS_PER_CAMBIOBJECT {
        let base = HDR_V2_OFF_EXTENTS + i * EXTENT_PACKED_SIZE;
        let start_lba = read_u64_le(buf, base + EXTENT_OFF_START_LBA);
        let block_count = read_u32_le(buf, base + EXTENT_OFF_BLOCK_COUNT);
        if start_lba == 0 && block_count == 0 {
            saw_none = true;
        } else if saw_none {
            // Contiguous-Some violated: a real extent follows a
            // sentinel. Canonical-form rejection per ADR-029
            // § Divergence 1.
            return Err(StoreError::InvalidObject);
        } else if block_count == 0 {
            // Half-sentinel: start_lba != 0 but block_count == 0.
            // Not a valid extent.
            return Err(StoreError::InvalidObject);
        } else {
            extents[i] = Some(Extent {
                start_lba,
                block_count,
            });
        }
    }

    // Canonical-form: the post-extent reserved region must be zero.
    // Bytes [HDR_V2_OFF_EXTENT_REGION_END .. HDR_OFF_CHECKSUM).
    if buf[HDR_V2_OFF_EXTENT_REGION_END..HDR_OFF_CHECKSUM]
        .iter()
        .any(|&b| b != 0)
    {
        return Err(StoreError::InvalidObject);
    }

    Ok(Some(HeaderDecodedV2 {
        content_len,
        content_hash,
        author,
        owner,
        sig_algo,
        lineage,
        cap_count,
        created_at,
        signature,
        capabilities: caps,
        extents,
    }))
}

// ============================================================================
// DiskObjectStore
// ============================================================================

/// Error-bridging helper.
fn block_err_to_store(_e: BlockError) -> StoreError {
    // All block-device errors surface as InvalidObject at the ObjectStore
    // boundary. We don't distinguish "disk full" from "disk unplugged" here;
    // a richer error taxonomy lands if/when callers need to act on it.
    StoreError::InvalidObject
}

pub struct DiskObjectStore<B: BlockDevice> {
    device: B,
    superblock: Superblock,
    index: BTreeMap<[u8; 32], u64>,
    free: FreeMap,
    count: usize,
    /// Shared block-allocation bitmap per ADR-010 § Divergence 3. v2
    /// records (post-5D-iii) allocate content blocks here; v1 records
    /// (legacy puts) bypass it. For 5D-ii the bitmap is initialized
    /// all-free at format time, reconstructed by journal replay at
    /// mount, and not yet mutated by put — that integration is 5D-iii.
    bitmap: BlockBitmap,
    /// Shared metadata journal per ADR-029 § Decision 5. Initialized
    /// empty at format; reconstructed from the on-disk region at mount.
    /// 5D-iii populates put/delete with journal-append flows.
    journal: Journal,
}

impl<B: BlockDevice> DiskObjectStore<B> {
    /// Open an existing v2 store, format a blank device as v2, or fail
    /// if the device looks corrupt or carries a different format
    /// version. v2 disks gain bitmap + journal + data regions per
    /// ADR-010 § Divergence 3; this entry point picks reasonable
    /// region sizes that fill the device (the kernel boot path and
    /// most tests use this default sizing).
    pub fn open_or_format(
        mut device: B,
        desired_capacity_slots: u64,
    ) -> Result<Self, StoreError> {
        let mut sb_buf = [0u8; BLOCK_SIZE];
        device
            .read_block(SUPERBLOCK_LBA, &mut sb_buf)
            .map_err(block_err_to_store)?;

        match classify_superblock(&sb_buf) {
            // Blank = superblock region is all zeros. On any newly-
            // provisioned storage (fresh qemu-img, freshly-erased SSD,
            // mkfs-like tool) the record headers are also guaranteed
            // zero — which for our format means they already read as
            // "free" (magic != ARCOREC_MAGIC_OCCUPIED). Skip the
            // per-slot zero-write loop; writing zeros over zeros is a
            // no-op that costs `capacity_slots` IPC round-trips.
            SuperblockState::Blank => {
                let geometry = pick_format_geometry(
                    device.capacity_blocks(),
                    desired_capacity_slots,
                )?;
                Self::format(
                    device,
                    geometry.capacity_slots,
                    geometry.capacity_data_blocks,
                    0,
                    false,
                )
            }
            SuperblockState::Valid(sb) => Self::mount(device, sb),
            // v1 disks (pre-Divergence-3) and any other unknown
            // version land here. Recovery requires an explicit
            // migration utility (out of scope for 5D); mount refuses.
            SuperblockState::UnknownVersion(_) => Err(StoreError::InvalidObject),
            SuperblockState::Corrupt => Err(StoreError::InvalidObject),
        }
    }

    /// Format the device as a fresh v2 disk. Existing data is discarded.
    ///
    /// `desired_capacity_slots` and `desired_capacity_data_blocks` are
    /// clamped to fit the device and the `MAX_OBJECTS_ON_DISK` /
    /// `MAX_DATA_BLOCKS_ON_DISK` SCAFFOLDING bounds. `erase_headers =
    /// true` zeros every record header slot — use when re-formatting
    /// a disk with unknown prior contents; `false` trusts that the
    /// underlying storage is already zero-initialized.
    pub fn format(
        mut device: B,
        desired_capacity_slots: u64,
        desired_capacity_data_blocks: u64,
        created_at: u64,
        erase_headers: bool,
    ) -> Result<Self, StoreError> {
        let dev_blocks = device.capacity_blocks();
        // v2 disks need superblock + at least one slot + bitmap (1) +
        // journal (JOURNAL_BLOCKS) + one data block. The journal
        // region dominates: any device smaller than `JOURNAL_BLOCKS +
        // 4` cannot host a v2 layout.
        let min_required = 1 + 2 + 1 + JOURNAL_BLOCKS + 1;
        if dev_blocks < min_required {
            return Err(StoreError::InvalidObject);
        }
        let capacity_slots = desired_capacity_slots
            .min(MAX_OBJECTS_ON_DISK)
            .max(1);
        let capacity_data_blocks = desired_capacity_data_blocks
            .min(MAX_DATA_BLOCKS_ON_DISK)
            .max(1);
        if total_blocks_for_capacity(capacity_slots, capacity_data_blocks) > dev_blocks {
            return Err(StoreError::InvalidObject);
        }

        // Compute region offsets.
        let bitmap_region_lba = 1 + 2 * capacity_slots;
        let bitmap_blocks = bitmap_region_blocks_for(capacity_data_blocks);
        let journal_region_lba = bitmap_region_lba + bitmap_blocks;
        let data_region_lba = journal_region_lba + JOURNAL_BLOCKS;

        let sb = Superblock {
            capacity_slots,
            capacity_data_blocks,
            bitmap_region_lba,
            journal_region_lba,
            data_region_lba,
            journal_capacity_bytes: JOURNAL_BYTES,
            last_checkpoint_offset: 0,
            generation: 1,
            created_at,
        };

        // Write superblock with generation = 1 (fresh format).
        let mut sb_buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut sb_buf, &sb);
        device
            .write_block(SUPERBLOCK_LBA, &sb_buf)
            .map_err(block_err_to_store)?;

        if erase_headers {
            // Zero every record header so leftover bytes can't masquerade
            // as occupied records. Content blocks are left as-is — they
            // are only read if a header points to them, which never
            // happens after zeroing.
            let zero_block = [0u8; BLOCK_SIZE];
            for slot in 0..capacity_slots {
                device
                    .write_block(header_lba(slot), &zero_block)
                    .map_err(block_err_to_store)?;
            }
        }

        // Initialize the in-memory bitmap as all-free and write it to
        // the bitmap region so a subsequent mount's defense-in-depth
        // check sees the canonical-form on-disk image (mirrors
        // PosixFsBackend::format).
        let bitmap = BlockBitmap::new_all_free(capacity_data_blocks);
        let bitmap_buffers = encode_to_blocks(&bitmap).map_err(|_| StoreError::InvalidObject)?;
        for (i, block) in bitmap_buffers.iter().enumerate() {
            device
                .write_block(bitmap_region_lba + i as u64, block)
                .map_err(block_err_to_store)?;
        }

        // Zero-fill the journal region. Fresh format = empty journal;
        // mount's blank-region detector relies on a zero leading byte
        // to stop the replay cursor cleanly.
        let zero_block = [0u8; BLOCK_SIZE];
        for i in 0..JOURNAL_BLOCKS {
            device
                .write_block(journal_region_lba + i, &zero_block)
                .map_err(block_err_to_store)?;
        }

        let journal = Journal::new(JOURNAL_BYTES).map_err(|_| StoreError::InvalidObject)?;

        device.flush().map_err(block_err_to_store)?;

        Ok(Self {
            device,
            superblock: sb,
            index: BTreeMap::new(),
            free: FreeMap::new(capacity_slots),
            count: 0,
            bitmap,
            journal,
        })
    }

    /// Mount an existing v2 store. Geometry validation → journal
    /// replay (reconstructing the bitmap) → defense-in-depth bitmap
    /// cross-check → slot-table scan → generation bump.
    ///
    /// Ordering mirrors `PosixFsBackend::mount` for the same reason:
    /// per ADR-029 § Verification Stance row 4 the bitmap is the
    /// projection of committed journal records, and the on-disk
    /// bitmap is a defense-in-depth cross-check rather than the
    /// source of truth.
    fn mount(mut device: B, sb: Superblock) -> Result<Self, StoreError> {
        if sb.capacity_slots == 0
            || sb.capacity_slots > MAX_OBJECTS_ON_DISK
            || sb.capacity_data_blocks == 0
            || sb.capacity_data_blocks > MAX_DATA_BLOCKS_ON_DISK
        {
            return Err(StoreError::InvalidObject);
        }
        if sb.journal_capacity_bytes != JOURNAL_BYTES {
            return Err(StoreError::InvalidObject);
        }
        // Sanity-check region ordering; corrupt geometry rejected.
        let expected_bitmap_lba = 1 + 2 * sb.capacity_slots;
        let expected_journal_lba =
            expected_bitmap_lba + bitmap_region_blocks_for(sb.capacity_data_blocks);
        let expected_data_lba = expected_journal_lba + JOURNAL_BLOCKS;
        if sb.bitmap_region_lba != expected_bitmap_lba
            || sb.journal_region_lba != expected_journal_lba
            || sb.data_region_lba != expected_data_lba
        {
            return Err(StoreError::InvalidObject);
        }
        if device.capacity_blocks()
            < total_blocks_for_capacity(sb.capacity_slots, sb.capacity_data_blocks)
        {
            return Err(StoreError::InvalidObject);
        }

        // -- Journal replay -----------------------------------------
        let mut journal_buf = vec![0u8; JOURNAL_BYTES as usize];
        let mut block_buf = [0u8; BLOCK_SIZE];
        for i in 0..JOURNAL_BLOCKS {
            device
                .read_block(sb.journal_region_lba + i, &mut block_buf)
                .map_err(block_err_to_store)?;
            let start = (i as usize) * BLOCK_SIZE;
            journal_buf[start..start + BLOCK_SIZE].copy_from_slice(&block_buf);
        }
        let mut journal = Journal::from_disk_state(
            JOURNAL_BYTES,
            sb.last_checkpoint_offset,
            0,
        )
        .map_err(|_| StoreError::InvalidObject)?;
        let mut bitmap = BlockBitmap::new_all_free(sb.capacity_data_blocks);
        journal
            .replay_from_checkpoint(&journal_buf, |rec| {
                apply_bitmap_mutations(&mut bitmap, rec)
            })
            .map_err(|_| StoreError::InvalidObject)?;

        // -- Defense-in-depth bitmap cross-check --------------------
        let bitmap_blocks = bitmap_region_blocks_for(sb.capacity_data_blocks);
        let mut disk_bitmap_blocks: Vec<Block> = Vec::with_capacity(bitmap_blocks as usize);
        for i in 0..bitmap_blocks {
            let mut block = [0u8; BLOCK_SIZE];
            device
                .read_block(sb.bitmap_region_lba + i, &mut block)
                .map_err(block_err_to_store)?;
            disk_bitmap_blocks.push(block);
        }
        let disk_bitmap = decode_from_blocks(&disk_bitmap_blocks, sb.capacity_data_blocks)
            .map_err(|_| StoreError::InvalidObject)?;
        if bitmap != disk_bitmap {
            return Err(StoreError::InvalidObject);
        }

        // -- Slot-table scan ----------------------------------------
        let mut index = BTreeMap::new();
        let mut free = FreeMap::new(sb.capacity_slots);
        let mut count = 0usize;

        let mut header_buf = [0u8; BLOCK_SIZE];
        for slot in 0..sb.capacity_slots {
            device
                .read_block(header_lba(slot), &mut header_buf)
                .map_err(block_err_to_store)?;
            if let Some(hdr) = decode_record_header(&header_buf)? {
                // Dedup safety: if two slots claim the same content hash,
                // only the first registers — the later occurrence is orphaned
                // and will be reclaimed on next put (its slot is treated as
                // occupied, but the index never points at it).
                if index.insert(hdr.content_hash, slot).is_none() {
                    free.mark_occupied(slot);
                    count += 1;
                }
            }
        }

        // Bump generation on successful mount so stale snapshots are
        // detectable. Write-back the superblock.
        let next_sb = Superblock {
            generation: sb.generation.wrapping_add(1),
            ..sb
        };
        let mut sb_buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut sb_buf, &next_sb);
        device
            .write_block(SUPERBLOCK_LBA, &sb_buf)
            .map_err(block_err_to_store)?;
        device.flush().map_err(block_err_to_store)?;

        Ok(Self {
            device,
            superblock: next_sb,
            index,
            free,
            count,
            bitmap,
            journal,
        })
    }

    /// Consume the store and return the underlying device. Test-only
    /// escape hatch used by the reboot-cycle tests.
    #[cfg(test)]
    pub fn into_device(self) -> B {
        self.device
    }

    pub fn capacity_slots(&self) -> u64 {
        self.superblock.capacity_slots
    }

    /// Total data-region blocks declared by the superblock. Used by the
    /// kernel-singleton wire-up and by tests that need to sanity-check
    /// the disk geometry.
    pub fn capacity_data_blocks(&self) -> u64 {
        self.superblock.capacity_data_blocks
    }

    /// Read-only view of the in-memory bitmap. Test-friendly accessor;
    /// production callers (5D-iii integration + kernel-singleton wire-up)
    /// acquire `BLOCK_BITMAP_LOCK` via the global slot.
    pub fn bitmap(&self) -> &BlockBitmap {
        &self.bitmap
    }

    /// Read-only view of the in-memory journal. Same posture as
    /// [`Self::bitmap`].
    pub fn journal(&self) -> &Journal {
        &self.journal
    }
}

impl<B: BlockDevice> ObjectStore for DiskObjectStore<B> {
    fn get(&mut self, hash: &[u8; 32]) -> Result<CambiObject, StoreError> {
        let slot = *self.index.get(hash).ok_or(StoreError::NotFound)?;

        let mut header_buf = [0u8; BLOCK_SIZE];
        self.device
            .read_block(header_lba(slot), &mut header_buf)
            .map_err(block_err_to_store)?;
        let header = decode_record_header(&header_buf)?.ok_or(StoreError::NotFound)?;

        // Sanity: the slot's on-disk hash must match the index key.
        if &header.content_hash != hash {
            return Err(StoreError::InvalidObject);
        }

        let mut content_buf = [0u8; BLOCK_SIZE];
        self.device
            .read_block(content_lba(slot), &mut content_buf)
            .map_err(block_err_to_store)?;

        rebuild_cambi_object(header, &content_buf)
    }

    fn put(&mut self, object: CambiObject) -> Result<[u8; 32], StoreError> {
        let computed = content_hash(&object.content);
        if computed != object.content_hash {
            return Err(StoreError::InvalidObject);
        }
        if object.content.len() > MAX_CONTENT_BYTES_ON_DISK {
            return Err(StoreError::CapacityExceeded);
        }
        if self.index.contains_key(&object.content_hash) {
            return Ok(object.content_hash);
        }

        let slot = self.free.first_free().ok_or(StoreError::CapacityExceeded)?;

        // Step 1: write content block.
        let mut content_buf = [0u8; BLOCK_SIZE];
        encode_content_block(&mut content_buf, &object.content);
        self.device
            .write_block(content_lba(slot), &content_buf)
            .map_err(block_err_to_store)?;
        self.device.flush().map_err(block_err_to_store)?;

        // Step 2: write header block (commit point).
        let mut header_buf = [0u8; BLOCK_SIZE];
        encode_record_header(&mut header_buf, &object)?;
        self.device
            .write_block(header_lba(slot), &header_buf)
            .map_err(block_err_to_store)?;
        self.device.flush().map_err(block_err_to_store)?;

        // Step 3: update in-memory index.
        self.index.insert(object.content_hash, slot);
        self.free.mark_occupied(slot);
        self.count += 1;
        Ok(object.content_hash)
    }

    fn delete(&mut self, hash: &[u8; 32]) -> Result<(), StoreError> {
        let slot = self.index.remove(hash).ok_or(StoreError::NotFound)?;

        // Overwrite the header block with zeros. Content block is left as-is
        // per ADR-010 (unlink semantics, not secure erase).
        let zero_block = [0u8; BLOCK_SIZE];
        self.device
            .write_block(header_lba(slot), &zero_block)
            .map_err(block_err_to_store)?;
        self.device.flush().map_err(block_err_to_store)?;

        self.free.mark_free(slot);
        self.count -= 1;
        Ok(())
    }

    fn list(&mut self) -> Result<Vec<([u8; 32], ObjectMeta)>, StoreError> {
        // ObjectMeta is stubbed — consumers that need author/owner/created_at
        // call `get`. The index carries hashes; pairing each with a zero
        // ObjectMeta preserves the trait signature at zero I/O cost.
        let mut out = Vec::with_capacity(self.index.len());
        for &hash in self.index.keys() {
            out.push((
                hash,
                ObjectMeta {
                    owner: [0u8; 32],
                    author: [0u8; 32],
                    created_at: 0,
                    content_len: 0,
                },
            ));
        }
        Ok(out)
    }

    fn count(&self) -> usize {
        self.count
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::block::MemBlockDevice;
    use crate::fs::keypair_from_seed;

    // Capacity sized so tests cover both "fill the store" and "reboot with
    // known state" scenarios without eating test-runner memory. v2 disks
    // include the 16 MiB journal region (`JOURNAL_BLOCKS`) plus a small
    // bitmap + data region.
    const TEST_CAP: u64 = 8;
    const TEST_DATA_BLOCKS: u64 = 32;
    const TEST_DEV_BLOCKS: u64 = 1 + 2 * TEST_CAP + 1 + JOURNAL_BLOCKS + TEST_DATA_BLOCKS;

    fn fresh_store() -> DiskObjectStore<MemBlockDevice> {
        let dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap()
    }

    /// Build a synthetic v2 superblock with reasonable defaults so tests
    /// can exercise `encode_superblock` / `classify_superblock` without
    /// reaching into the full backend.
    fn test_superblock(capacity_slots: u64, generation: u64) -> Superblock {
        let bitmap_region_lba = 1 + 2 * capacity_slots;
        let bitmap_blocks = bitmap_region_blocks_for(TEST_DATA_BLOCKS);
        let journal_region_lba = bitmap_region_lba + bitmap_blocks;
        let data_region_lba = journal_region_lba + JOURNAL_BLOCKS;
        Superblock {
            capacity_slots,
            capacity_data_blocks: TEST_DATA_BLOCKS,
            bitmap_region_lba,
            journal_region_lba,
            data_region_lba,
            journal_capacity_bytes: JOURNAL_BYTES,
            last_checkpoint_offset: 0,
            generation,
            created_at: 0,
        }
    }

    fn make_object(author_seed: u8, content: &[u8]) -> CambiObject {
        let author = Principal::from_public_key([author_seed; 32]);
        CambiObject::new(author, content.to_vec(), 42)
    }

    // ------------------- Encoding helpers (pure) -------------------

    #[test]
    fn superblock_roundtrip() {
        let sb = test_superblock(128, 7);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, &sb);
        match classify_superblock(&buf) {
            SuperblockState::Valid(decoded) => assert_eq!(decoded, sb),
            other => panic!("expected Valid, got {:?}", other),
        }
    }

    #[test]
    fn superblock_blank_detected() {
        let buf = [0u8; BLOCK_SIZE];
        assert_eq!(classify_superblock(&buf), SuperblockState::Blank);
    }

    #[test]
    fn superblock_wrong_magic_is_corrupt() {
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..8].copy_from_slice(b"NOTARCOB");
        assert_eq!(classify_superblock(&buf), SuperblockState::Corrupt);
    }

    #[test]
    fn superblock_bad_checksum_is_corrupt() {
        let sb = test_superblock(TEST_CAP, 1);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, &sb);
        buf[100] ^= 0xFF; // flip a middle byte, checksum now wrong
        assert_eq!(classify_superblock(&buf), SuperblockState::Corrupt);
    }

    #[test]
    fn superblock_v1_disk_rejected_as_unknown_version() {
        // Craft a v1-shaped superblock (version=1) so the dispatcher
        // recognizes the magic but rejects the version. The exact v1
        // field layout doesn't matter; only the magic + version byte
        // matter to classify_superblock.
        let mut buf = [0u8; BLOCK_SIZE];
        buf[SB_OFF_MAGIC..SB_OFF_MAGIC + 8].copy_from_slice(&ARCOBJ_MAGIC);
        buf[SB_OFF_VERSION..SB_OFF_VERSION + 4].copy_from_slice(&1u32.to_le_bytes());
        let cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
        buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        match classify_superblock(&buf) {
            SuperblockState::UnknownVersion(v) => assert_eq!(v, 1),
            other => panic!("expected UnknownVersion, got {:?}", other),
        }
    }

    #[test]
    fn record_header_roundtrip() {
        let obj = make_object(9, b"persistent world");
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header(&mut buf, &obj).unwrap();
        let hdr = decode_record_header(&buf).unwrap().expect("should decode");
        assert_eq!(hdr.content_hash, obj.content_hash);
        assert_eq!(hdr.author, obj.author);
        assert_eq!(hdr.owner, obj.owner);
        assert_eq!(hdr.content_len, obj.content.len() as u32);
        assert_eq!(hdr.cap_count, 0);
        assert_eq!(hdr.lineage, None);
    }

    #[test]
    fn record_header_bad_magic_is_free_slot() {
        let mut buf = [0u8; BLOCK_SIZE];
        // all zeros → free
        assert!(decode_record_header(&buf).unwrap().is_none());
        buf[0..8].copy_from_slice(b"OTHERMAG");
        assert!(decode_record_header(&buf).unwrap().is_none());
    }

    #[test]
    fn record_header_bad_checksum_reads_as_free() {
        let obj = make_object(1, b"torn");
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header(&mut buf, &obj).unwrap();
        buf[500] ^= 0x01; // corrupt the middle of the header
        // Per ADR-010 mount protocol: treat as free.
        assert!(decode_record_header(&buf).unwrap().is_none());
    }

    #[test]
    fn record_header_rejects_oversized_content() {
        let author = Principal::from_public_key([1u8; 32]);
        let big = alloc::vec![0u8; MAX_CONTENT_BYTES_ON_DISK + 1];
        let obj = CambiObject::new(author, big, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        assert_eq!(
            encode_record_header(&mut buf, &obj),
            Err(StoreError::InvalidObject)
        );
    }

    // ------------------- FreeMap -------------------

    #[test]
    fn free_map_initial_all_free() {
        let fm = FreeMap::new(10);
        assert_eq!(fm.first_free(), Some(0));
    }

    #[test]
    fn free_map_mark_occupied_advances_first_free() {
        let mut fm = FreeMap::new(4);
        fm.mark_occupied(0);
        assert_eq!(fm.first_free(), Some(1));
        fm.mark_occupied(1);
        fm.mark_occupied(2);
        fm.mark_occupied(3);
        assert_eq!(fm.first_free(), None);
    }

    #[test]
    fn free_map_mark_free_restores_slot() {
        let mut fm = FreeMap::new(4);
        fm.mark_occupied(0);
        fm.mark_occupied(1);
        assert_eq!(fm.first_free(), Some(2));
        fm.mark_free(0);
        assert_eq!(fm.first_free(), Some(0));
    }

    // ------------------- End-to-end on MemBlockDevice -------------------

    #[test]
    fn format_then_put_get() {
        let mut store = fresh_store();
        let obj = make_object(2, b"alpha");
        let hash = store.put(obj.clone()).unwrap();
        assert_eq!(hash, obj.content_hash);
        assert_eq!(store.count(), 1);

        let retrieved = store.get(&hash).unwrap();
        assert_eq!(retrieved.content, b"alpha");
        assert_eq!(retrieved.author, obj.author);
        assert_eq!(retrieved.owner, obj.owner);
        assert_eq!(retrieved.content_hash, obj.content_hash);
    }

    #[test]
    fn put_idempotent() {
        let mut store = fresh_store();
        let obj = make_object(1, b"same");
        let h1 = store.put(obj.clone()).unwrap();
        let h2 = store.put(obj.clone()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn get_not_found() {
        let mut store = fresh_store();
        let fake = [0xFFu8; 32];
        assert_eq!(store.get(&fake), Err(StoreError::NotFound));
    }

    #[test]
    fn put_invalid_content_hash() {
        let mut store = fresh_store();
        let mut obj = make_object(1, b"legitimate");
        obj.content_hash = [0u8; 32];
        assert_eq!(store.put(obj), Err(StoreError::InvalidObject));
    }

    #[test]
    fn put_content_too_large() {
        let mut store = fresh_store();
        let author = Principal::from_public_key([1u8; 32]);
        let big = alloc::vec![42u8; MAX_CONTENT_BYTES_ON_DISK + 1];
        let obj = CambiObject::new(author, big, 0);
        assert_eq!(store.put(obj), Err(StoreError::CapacityExceeded));
    }

    #[test]
    fn delete_removes_and_frees_slot() {
        let mut store = fresh_store();
        let obj = make_object(1, b"ephemeral");
        let hash = store.put(obj).unwrap();
        assert_eq!(store.count(), 1);
        store.delete(&hash).unwrap();
        assert_eq!(store.count(), 0);
        assert_eq!(store.get(&hash), Err(StoreError::NotFound));

        // Slot is free; we can put again up to capacity.
        let obj2 = make_object(1, b"reused");
        store.put(obj2).unwrap();
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn delete_not_found() {
        let mut store = fresh_store();
        let fake = [0xAAu8; 32];
        assert_eq!(store.delete(&fake), Err(StoreError::NotFound));
    }

    #[test]
    fn capacity_exhaustion() {
        let mut store = fresh_store();
        for i in 0..TEST_CAP as u8 {
            let content = alloc::format!("object-{}", i);
            let obj = make_object(1, content.as_bytes());
            store.put(obj).unwrap();
        }
        assert_eq!(store.count() as u64, TEST_CAP);
        let overflow = make_object(1, b"overflow");
        assert_eq!(store.put(overflow), Err(StoreError::CapacityExceeded));
    }

    #[test]
    fn list_returns_all_hashes() {
        let mut store = fresh_store();
        let a = make_object(1, b"a");
        let b = make_object(1, b"b");
        let c = make_object(1, b"c");
        let ha = store.put(a).unwrap();
        let hb = store.put(b).unwrap();
        let hc = store.put(c).unwrap();

        let listing = store.list().unwrap();
        let hashes: Vec<_> = listing.iter().map(|(h, _)| *h).collect();
        assert!(hashes.contains(&ha));
        assert!(hashes.contains(&hb));
        assert!(hashes.contains(&hc));
        assert_eq!(listing.len(), 3);
    }

    // ------------------- Reboot cycle (the headline test) -------------------

    #[test]
    fn survives_reboot_with_multiple_objects() {
        let dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        let mut store = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();

        let obj_a = make_object(1, b"persistent-alpha");
        let obj_b = make_object(2, b"persistent-beta");
        let obj_c = make_object(3, b"persistent-gamma");
        let ha = store.put(obj_a.clone()).unwrap();
        let hb = store.put(obj_b.clone()).unwrap();
        let hc = store.put(obj_c.clone()).unwrap();
        assert_eq!(store.count(), 3);

        // Simulate reboot: hand the device back, drop the store, remount.
        let dev = store.into_device();
        let mut store2 = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();

        assert_eq!(store2.count(), 3);
        let got_a = store2.get(&ha).unwrap();
        let got_b = store2.get(&hb).unwrap();
        let got_c = store2.get(&hc).unwrap();
        assert_eq!(got_a.content, b"persistent-alpha");
        assert_eq!(got_b.content, b"persistent-beta");
        assert_eq!(got_c.content, b"persistent-gamma");
        assert_eq!(got_a.author, obj_a.author);
        assert_eq!(got_b.author, obj_b.author);
        assert_eq!(got_c.author, obj_c.author);
    }

    #[test]
    fn reboot_preserves_signed_object() {
        let (pk, sk) = keypair_from_seed(&[7u8; 32]);
        let author = Principal::from_public_key(pk);
        let content = b"signed-persistence".to_vec();
        let mut obj = CambiObject::new(author, content.clone(), 100);
        obj.signature = crate::fs::sign_content(&sk, &content);

        let dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        let mut store = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        let hash = store.put(obj.clone()).unwrap();

        let dev = store.into_device();
        let mut store2 = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        let retrieved = store2.get(&hash).unwrap();

        // Signature must round-trip exactly and still verify.
        assert_eq!(retrieved.signature.data, obj.signature.data);
        assert!(crate::fs::verify_signature(
            &retrieved.owner,
            &retrieved.content,
            &retrieved.signature
        ));
    }

    #[test]
    fn reboot_after_delete_shows_object_gone() {
        let dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        let mut store = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();

        let keep = make_object(1, b"kept");
        let drop = make_object(2, b"dropped");
        let keep_hash = store.put(keep).unwrap();
        let drop_hash = store.put(drop).unwrap();
        store.delete(&drop_hash).unwrap();

        let dev = store.into_device();
        let mut store2 = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        assert_eq!(store2.count(), 1);
        assert!(store2.get(&keep_hash).is_ok());
        assert_eq!(store2.get(&drop_hash), Err(StoreError::NotFound));
    }

    #[test]
    fn reboot_with_full_store_preserves_all_slots() {
        let dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        let mut store = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        let mut hashes = Vec::new();
        for i in 0..TEST_CAP as u8 {
            let content = alloc::format!("slot-{}", i);
            let obj = make_object(i + 1, content.as_bytes());
            hashes.push(store.put(obj).unwrap());
        }

        let dev = store.into_device();
        let mut store2 = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        assert_eq!(store2.count() as u64, TEST_CAP);
        for (i, h) in hashes.iter().enumerate() {
            let got = store2.get(h).unwrap();
            let expected = alloc::format!("slot-{}", i);
            assert_eq!(got.content, expected.as_bytes());
        }
    }

    #[test]
    fn reboot_bumps_generation_counter() {
        let dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        let store = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        let gen_first_mount = store.superblock.generation;

        let dev = store.into_device();
        let store2 = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        assert!(store2.superblock.generation > gen_first_mount);
    }

    // ------------------- Corruption paths -------------------

    #[test]
    fn mount_rejects_corrupt_superblock() {
        let mut dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        // Write a plausible-but-corrupt superblock: right magic, wrong checksum.
        let sb = test_superblock(TEST_CAP, 1);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, &sb);
        buf[100] ^= 0x01;
        dev.write_block(SUPERBLOCK_LBA, &buf).unwrap();
        assert_eq!(
            DiskObjectStore::open_or_format(dev, TEST_CAP).err(),
            Some(StoreError::InvalidObject)
        );
    }

    #[test]
    fn torn_header_is_invisible_after_mount() {
        // Put one good object, then corrupt its header checksum in place.
        // After remount, that slot should read as empty (per ADR-010).
        let dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        let mut store = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        let obj = make_object(1, b"to-be-torn");
        let hash = store.put(obj).unwrap();

        let mut dev = store.into_device();
        let mut header_buf = [0u8; BLOCK_SIZE];
        dev.read_block(header_lba(0), &mut header_buf).unwrap();
        header_buf[500] ^= 0xAA;
        dev.write_block(header_lba(0), &header_buf).unwrap();

        let mut store2 = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        assert_eq!(store2.count(), 0);
        assert_eq!(store2.get(&hash), Err(StoreError::NotFound));
    }

    #[test]
    fn slot_with_orphan_content_but_no_header_is_reusable() {
        // Simulate the crash window in the put protocol: content block
        // written + flushed, then power loss before the header write.
        // Expected behavior on next mount: slot is free (no header magic),
        // orphan content bytes are invisible, next put reuses the slot.
        let mut dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        // Format first so the superblock is valid.
        {
            let store = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
            dev = store.into_device();
        }
        // Hand-write an orphan content block into slot 0's content LBA.
        let orphan = [0x5Au8; BLOCK_SIZE];
        dev.write_block(content_lba(0), &orphan).unwrap();
        // No header write — slot 0's header is still zero.

        let mut store = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        assert_eq!(store.count(), 0);

        // Next put should reuse slot 0 (the FreeMap had it free) and
        // overwrite the orphan content.
        let obj = make_object(1, b"fresh");
        let hash = store.put(obj).unwrap();
        let got = store.get(&hash).unwrap();
        assert_eq!(got.content, b"fresh");
    }

    #[test]
    fn open_on_undersized_device_fails() {
        // Device smaller than 3 blocks cannot even hold superblock + one slot.
        let dev = MemBlockDevice::new(2);
        assert_eq!(
            DiskObjectStore::open_or_format(dev, 1).err(),
            Some(StoreError::InvalidObject)
        );
    }

    #[test]
    fn header_lba_math() {
        assert_eq!(header_lba(0), 1);
        assert_eq!(content_lba(0), 2);
        assert_eq!(header_lba(5), 11);
        assert_eq!(content_lba(5), 12);
        // v2 disk total: 1 sb + 2*slots + bitmap_blocks + journal + data.
        // For slots=10, data=64: bitmap = ceil(64 / 32768) = 1.
        // Total = 1 + 20 + 1 + JOURNAL_BLOCKS + 64 = JOURNAL_BLOCKS + 86.
        assert_eq!(
            total_blocks_for_capacity(10, 64),
            1 + 20 + 1 + JOURNAL_BLOCKS + 64,
        );
    }

    // ========================================================================
    // v2 record header codec (commit 5D-i, ADR-010 § Divergence 3)
    // ========================================================================

    fn empty_extents() -> [Option<Extent>; MAX_EXTENTS_PER_CAMBIOBJECT] {
        [None; MAX_EXTENTS_PER_CAMBIOBJECT]
    }

    fn make_v2_extents(count: usize) -> [Option<Extent>; MAX_EXTENTS_PER_CAMBIOBJECT] {
        let mut e = empty_extents();
        for i in 0..count {
            e[i] = Some(Extent {
                start_lba: 1000 + i as u64,
                block_count: 1 + i as u32,
            });
        }
        e
    }

    #[test]
    fn v2_record_roundtrip_no_extents() {
        let obj = make_object(7, b"v2 with no allocated content");
        let extents = empty_extents();
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        let hdr = decode_record_header_v2(&buf).unwrap().expect("v2 decode");
        assert_eq!(hdr.content_hash, obj.content_hash);
        assert_eq!(hdr.author, obj.author);
        assert_eq!(hdr.owner, obj.owner);
        assert_eq!(hdr.content_len, obj.content.len() as u32);
        assert!(hdr.extents.iter().all(|e| e.is_none()));
    }

    #[test]
    fn v2_record_roundtrip_populated_extents() {
        let obj = make_object(1, b"v2 with three extents");
        let extents = make_v2_extents(3);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        let hdr = decode_record_header_v2(&buf).unwrap().expect("v2 decode");
        for i in 0..3 {
            assert_eq!(hdr.extents[i], extents[i]);
        }
        for i in 3..MAX_EXTENTS_PER_CAMBIOBJECT {
            assert!(hdr.extents[i].is_none());
        }
    }

    #[test]
    fn v2_record_roundtrip_full_capacity_extents() {
        let obj = make_object(2, b"v2 full extents");
        let extents = make_v2_extents(MAX_EXTENTS_PER_CAMBIOBJECT);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        let hdr = decode_record_header_v2(&buf).unwrap().expect("v2 decode");
        for i in 0..MAX_EXTENTS_PER_CAMBIOBJECT {
            assert_eq!(hdr.extents[i], extents[i]);
        }
    }

    #[test]
    fn v2_encode_rejects_non_contiguous_extents() {
        let obj = make_object(1, b"x");
        let mut extents = empty_extents();
        // Skip slot 0, populate slot 1 — violates contiguous-Some.
        extents[1] = Some(Extent {
            start_lba: 100,
            block_count: 1,
        });
        let mut buf = [0u8; BLOCK_SIZE];
        assert_eq!(
            encode_record_header_v2(&mut buf, &obj, &extents),
            Err(StoreError::InvalidObject),
        );
    }

    #[test]
    fn v2_decode_rejects_non_contiguous_extents() {
        // Hand-craft a buffer where extent slot 0 is sentinel and
        // slot 1 is a real extent. Recompute checksum so the only
        // violation is the contiguous-Some invariant.
        let obj = make_object(1, b"y");
        let extents = empty_extents();
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        // Poke a real extent into slot 1, leaving slot 0 zero.
        let base = HDR_V2_OFF_EXTENTS + EXTENT_PACKED_SIZE;
        buf[base..base + 8].copy_from_slice(&500u64.to_le_bytes());
        buf[base + 8..base + 12].copy_from_slice(&2u32.to_le_bytes());
        let cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
        buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        match decode_record_header_v2(&buf) {
            Err(StoreError::InvalidObject) => {}
            other => panic!("expected InvalidObject, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn v2_decode_rejects_half_sentinel_extent() {
        // start_lba != 0 but block_count == 0 — neither a real extent
        // nor a sentinel. Canonical-form rejection.
        let obj = make_object(1, b"z");
        let extents = empty_extents();
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        let base = HDR_V2_OFF_EXTENTS;
        buf[base..base + 8].copy_from_slice(&100u64.to_le_bytes());
        // block_count stays 0.
        let cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
        buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        match decode_record_header_v2(&buf) {
            Err(StoreError::InvalidObject) => {}
            other => panic!("expected InvalidObject, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn v2_decode_rejects_nonzero_reserved_tail() {
        let obj = make_object(1, b"q");
        let extents = make_v2_extents(2);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        // Poke a byte in the post-extent reserved region.
        buf[HDR_V2_OFF_EXTENT_REGION_END + 100] = 0x42;
        let cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
        buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        match decode_record_header_v2(&buf) {
            Err(StoreError::InvalidObject) => {}
            other => panic!("expected InvalidObject, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn v2_decode_bad_magic_returns_none() {
        // v1 magic on a buffer should not be picked up by v2 decoder.
        let obj = make_object(3, b"v1");
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header(&mut buf, &obj).unwrap();
        assert!(decode_record_header_v2(&buf).unwrap().is_none());
    }

    #[test]
    fn v2_decode_bad_checksum_reads_as_free() {
        let obj = make_object(4, b"torn");
        let extents = make_v2_extents(1);
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        buf[500] ^= 0xFF;
        // Torn-write posture: not an error, just "treat as free."
        assert!(decode_record_header_v2(&buf).unwrap().is_none());
    }

    #[test]
    fn v2_decode_rejects_unknown_sig_algo() {
        let obj = make_object(5, b"x");
        let extents = empty_extents();
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        buf[HDR_OFF_SIG_ALGO] = 99;
        let cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
        buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        match decode_record_header_v2(&buf) {
            Err(StoreError::InvalidObject) => {}
            other => panic!("expected InvalidObject, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn v2_decode_rejects_cap_count_overflow() {
        let obj = make_object(6, b"x");
        let extents = empty_extents();
        let mut buf = [0u8; BLOCK_SIZE];
        encode_record_header_v2(&mut buf, &obj, &extents).unwrap();
        let bad = (MAX_OBJECT_CAPS as u16 + 1).to_le_bytes();
        buf[HDR_OFF_CAP_COUNT..HDR_OFF_CAP_COUNT + 2].copy_from_slice(&bad);
        let cs = checksum8(&buf[..HDR_CHECKSUM_COVER_END]);
        buf[HDR_OFF_CHECKSUM..HDR_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        match decode_record_header_v2(&buf) {
            Err(StoreError::InvalidObject) => {}
            other => panic!("expected InvalidObject, got {:?}", other.is_ok()),
        }
    }

    // ========================================================================
    // v2 superblock + disk geometry (commit 5D-ii)
    // ========================================================================

    #[test]
    fn fresh_v2_store_bitmap_all_free() {
        let store = fresh_store();
        let bm = store.bitmap();
        assert_eq!(bm.capacity(), TEST_DATA_BLOCKS);
        assert_eq!(bm.free_count(), TEST_DATA_BLOCKS);
    }

    #[test]
    fn fresh_v2_store_journal_empty() {
        let store = fresh_store();
        let j = store.journal();
        assert_eq!(j.region_bytes(), JOURNAL_BYTES);
        assert_eq!(j.head_offset(), 0);
        assert_eq!(j.last_checkpoint_offset(), 0);
    }

    #[test]
    fn fresh_v2_store_geometry_consistent() {
        let store = fresh_store();
        let sb = &store.superblock;
        assert_eq!(sb.capacity_slots, TEST_CAP);
        assert_eq!(sb.capacity_data_blocks, TEST_DATA_BLOCKS);
        assert_eq!(sb.bitmap_region_lba, 1 + 2 * TEST_CAP);
        assert_eq!(
            sb.journal_region_lba,
            sb.bitmap_region_lba + bitmap_region_blocks_for(TEST_DATA_BLOCKS),
        );
        assert_eq!(sb.data_region_lba, sb.journal_region_lba + JOURNAL_BLOCKS);
        assert_eq!(sb.journal_capacity_bytes, JOURNAL_BYTES);
    }

    #[test]
    fn mount_rejects_bitmap_divergence() {
        // Format then corrupt the on-disk bitmap: claim block 5 is
        // occupied on disk while the journal (still empty) reconstructs
        // an all-free bitmap. Mount must surface the divergence.
        let mut store = fresh_store();
        let bitmap_lba = store.superblock.bitmap_region_lba;
        // Take ownership of the device through into_device.
        let mut dev = store.into_device();
        let mut block = [0u8; BLOCK_SIZE];
        dev.read_block(bitmap_lba, &mut block).unwrap();
        // bit 5 of byte 0 = 0x20. Bitmap convention is `1 = free`,
        // so clear bit 5 to claim block 5 is occupied on disk.
        block[0] &= !0x20;
        dev.write_block(bitmap_lba, &block).unwrap();

        let result = DiskObjectStore::open_or_format(dev, TEST_CAP);
        assert_eq!(result.err(), Some(StoreError::InvalidObject));
    }

    #[test]
    fn mount_rejects_unknown_version_superblock() {
        // Synthesize a v1-shaped superblock and confirm
        // open_or_format rejects it (matches the
        // SuperblockState::UnknownVersion path).
        let mut dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        let mut buf = [0u8; BLOCK_SIZE];
        buf[SB_OFF_MAGIC..SB_OFF_MAGIC + 8].copy_from_slice(&ARCOBJ_MAGIC);
        buf[SB_OFF_VERSION..SB_OFF_VERSION + 4].copy_from_slice(&1u32.to_le_bytes());
        let cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
        buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8].copy_from_slice(&cs);
        dev.write_block(SUPERBLOCK_LBA, &buf).unwrap();
        let result = DiskObjectStore::open_or_format(dev, TEST_CAP);
        assert_eq!(result.err(), Some(StoreError::InvalidObject));
    }

    #[test]
    fn v2_and_v1_magic_distinct_on_disk() {
        // Encoding the same logical object as v1 vs v2 produces
        // distinct first 8 bytes — the magic byte sequence is the
        // dispatch signal at decode time.
        let obj = make_object(8, b"distinct");
        let mut v1_buf = [0u8; BLOCK_SIZE];
        let mut v2_buf = [0u8; BLOCK_SIZE];
        encode_record_header(&mut v1_buf, &obj).unwrap();
        encode_record_header_v2(&mut v2_buf, &obj, &empty_extents()).unwrap();
        assert_eq!(&v1_buf[..8], b"ARCOREC1");
        assert_eq!(&v2_buf[..8], b"ARCOREC2");
        assert_ne!(&v1_buf[..8], &v2_buf[..8]);
    }
}
