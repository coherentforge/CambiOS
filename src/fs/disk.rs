// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Persistent, disk-backed `ObjectStore`.
//!
//! The on-disk format is specified in ADR-010. This module is the reference
//! reader/writer of that format. It is generic over any `BlockDevice` — the
//! same code path is exercised by unit tests against `MemBlockDevice` and
//! (in Phase 4a.iii) at runtime against `VirtioBlkDevice`.
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

use crate::fs::block::{Block, BlockDevice, BlockError, BLOCK_SIZE};
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

/// ARCHITECTURAL: record-header magic for an occupied slot. Absence = free.
pub const ARCOREC_MAGIC_OCCUPIED: [u8; 8] = *b"ARCOREC1";

/// ARCHITECTURAL: current format version. Mount rejects unknown versions.
/// Version 2 lands when ML-DSA signatures or multi-block content arrives.
pub const FORMAT_VERSION: u32 = 1;

/// SCAFFOLDING: maximum number of object slots this implementation supports.
/// Why: v1 workload is human-scale (identity attestations, small documents,
///      social log entries). With the ~25%-of-bound rule, we expect ~1000
///      objects in realistic v1 use; 4096 gives ~4x headroom.
///      Memory cost: 4096 entries × (~48 bytes per BTreeMap entry + 1 bit
///      free-map) ≈ 200 KiB against the 4 MiB kernel heap.
/// Replace when: Phase 5 (social log) or Phase 7 (SSB federation) cause
///      object counts to approach ~1000; bump to 16384 or 65536, verify
///      heap budget, update docs/ASSUMPTIONS.md.
pub const MAX_OBJECTS_ON_DISK: u64 = 4096;

/// SCAFFOLDING: maximum content length per object on disk. Matches
/// `BLOCK_SIZE` — one block per content. Raised to multi-block content when
/// Phase 4b lands channel-based bulk IPC and the format goes to version 2.
pub const MAX_CONTENT_BYTES_ON_DISK: usize = BLOCK_SIZE;

// Superblock field offsets (LBA 0)
const SB_OFF_MAGIC: usize = 0;
const SB_OFF_VERSION: usize = 8;
const SB_OFF_CAPACITY: usize = 12;
const SB_OFF_GENERATION: usize = 20;
const SB_OFF_CREATED_AT: usize = 28;
const SB_OFF_CHECKSUM: usize = 4088;
const SB_CHECKSUM_COVER_END: usize = 4088;

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
#[inline]
fn total_blocks_for_capacity(capacity_slots: u64) -> u64 {
    1 + 2 * capacity_slots
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

fn encode_superblock(
    buf: &mut Block,
    capacity_slots: u64,
    generation: u64,
    created_at: u64,
) {
    buf.fill(0);
    buf[SB_OFF_MAGIC..SB_OFF_MAGIC + 8].copy_from_slice(&ARCOBJ_MAGIC);
    buf[SB_OFF_VERSION..SB_OFF_VERSION + 4].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf[SB_OFF_CAPACITY..SB_OFF_CAPACITY + 8].copy_from_slice(&capacity_slots.to_le_bytes());
    buf[SB_OFF_GENERATION..SB_OFF_GENERATION + 8].copy_from_slice(&generation.to_le_bytes());
    buf[SB_OFF_CREATED_AT..SB_OFF_CREATED_AT + 8].copy_from_slice(&created_at.to_le_bytes());
    let cs = checksum8(&buf[..SB_CHECKSUM_COVER_END]);
    buf[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 8].copy_from_slice(&cs);
}

struct SuperblockFields {
    capacity_slots: u64,
    generation: u64,
    version: u32,
    // created_at is read but not consumed today; keep for future use.
    #[allow(dead_code)]
    created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuperblockState {
    Blank,
    Valid(SuperblockSnapshot),
    Corrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SuperblockSnapshot {
    capacity_slots: u64,
    generation: u64,
    version: u32,
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
    let version = u32::from_le_bytes(
        buf[SB_OFF_VERSION..SB_OFF_VERSION + 4].try_into().unwrap(),
    );
    let capacity_slots = u64::from_le_bytes(
        buf[SB_OFF_CAPACITY..SB_OFF_CAPACITY + 8].try_into().unwrap(),
    );
    let generation = u64::from_le_bytes(
        buf[SB_OFF_GENERATION..SB_OFF_GENERATION + 8].try_into().unwrap(),
    );
    SuperblockState::Valid(SuperblockSnapshot {
        capacity_slots,
        generation,
        version,
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
            .copy_from_slice(&cap.principal.public_key);
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

    let content_len = u32::from_le_bytes(
        buf[HDR_OFF_CONTENT_LEN..HDR_OFF_CONTENT_LEN + 4]
            .try_into()
            .unwrap(),
    );
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
    let cap_count = u16::from_le_bytes(
        buf[HDR_OFF_CAP_COUNT..HDR_OFF_CAP_COUNT + 2]
            .try_into()
            .unwrap(),
    );
    if cap_count as usize > MAX_OBJECT_CAPS {
        return Err(StoreError::InvalidObject);
    }
    let created_at = u64::from_le_bytes(
        buf[HDR_OFF_CREATED_AT..HDR_OFF_CREATED_AT + 8]
            .try_into()
            .unwrap(),
    );

    let mut signature = SignatureBytes::EMPTY;
    signature
        .data
        .copy_from_slice(&buf[HDR_OFF_SIGNATURE..HDR_OFF_SIGNATURE + 64]);

    let mut caps = ObjectCapSet::new();
    for i in 0..cap_count as usize {
        let base = HDR_OFF_CAPS + i * CAP_ENTRY_SIZE;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[base + CAP_OFF_PRINCIPAL..base + CAP_OFF_PRINCIPAL + 32]);
        let expiry_raw = u64::from_le_bytes(
            buf[base + CAP_OFF_EXPIRY..base + CAP_OFF_EXPIRY + 8]
                .try_into()
                .unwrap(),
        );
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
    capacity_slots: u64,
    index: BTreeMap<[u8; 32], u64>,
    free: FreeMap,
    count: usize,
    #[allow(dead_code)]
    generation: u64,
}

impl<B: BlockDevice> DiskObjectStore<B> {
    /// Open an existing store, or format a blank device, or fail if the
    /// device looks corrupt. On format, `desired_capacity_slots` is the
    /// slot count written to the new superblock — clamped by device
    /// capacity and the `MAX_OBJECTS_ON_DISK` SCAFFOLDING bound.
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
            SuperblockState::Blank => Self::format(device, desired_capacity_slots, 0, false),
            SuperblockState::Valid(snap) => {
                if snap.version != FORMAT_VERSION {
                    return Err(StoreError::InvalidObject);
                }
                Self::mount(device, snap)
            }
            SuperblockState::Corrupt => Err(StoreError::InvalidObject),
        }
    }

    /// Format the device. Existing data is discarded.
    ///
    /// `erase_headers = true` zeros every record header slot — use when
    /// re-formatting a disk with unknown prior contents (explicit user
    /// erase, or reformat of a previously-valid store). `false` trusts
    /// that the underlying storage is already zero-initialized, which is
    /// the common case for first-boot on freshly-provisioned media.
    pub fn format(
        mut device: B,
        desired_capacity_slots: u64,
        created_at: u64,
        erase_headers: bool,
    ) -> Result<Self, StoreError> {
        let dev_blocks = device.capacity_blocks();
        if dev_blocks < 3 {
            // Must hold superblock + at least one slot (2 blocks).
            return Err(StoreError::InvalidObject);
        }
        let max_by_device = (dev_blocks - 1) / 2;
        let capacity_slots = desired_capacity_slots
            .min(max_by_device)
            .min(MAX_OBJECTS_ON_DISK);
        if capacity_slots == 0 {
            return Err(StoreError::InvalidObject);
        }

        // Write superblock with generation = 1 (fresh format).
        let mut sb_buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut sb_buf, capacity_slots, 1, created_at);
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
        device.flush().map_err(block_err_to_store)?;

        Ok(Self {
            device,
            capacity_slots,
            index: BTreeMap::new(),
            free: FreeMap::new(capacity_slots),
            count: 0,
            generation: 1,
        })
    }

    fn mount(mut device: B, snap: SuperblockSnapshot) -> Result<Self, StoreError> {
        let capacity_slots = snap.capacity_slots;
        if capacity_slots == 0 || capacity_slots > MAX_OBJECTS_ON_DISK {
            return Err(StoreError::InvalidObject);
        }
        // Check the device actually has space for this declared capacity.
        if device.capacity_blocks() < total_blocks_for_capacity(capacity_slots) {
            return Err(StoreError::InvalidObject);
        }

        let mut index = BTreeMap::new();
        let mut free = FreeMap::new(capacity_slots);
        let mut count = 0usize;

        let mut header_buf = [0u8; BLOCK_SIZE];
        for slot in 0..capacity_slots {
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
        let next_generation = snap.generation.wrapping_add(1);
        let mut sb_buf = [0u8; BLOCK_SIZE];
        // Preserve original created_at by re-reading the superblock block;
        // encode_superblock rewrites every field so we need to supply it.
        device
            .read_block(SUPERBLOCK_LBA, &mut sb_buf)
            .map_err(block_err_to_store)?;
        let created_at = u64::from_le_bytes(
            sb_buf[SB_OFF_CREATED_AT..SB_OFF_CREATED_AT + 8]
                .try_into()
                .unwrap(),
        );
        encode_superblock(&mut sb_buf, capacity_slots, next_generation, created_at);
        device
            .write_block(SUPERBLOCK_LBA, &sb_buf)
            .map_err(block_err_to_store)?;
        device.flush().map_err(block_err_to_store)?;

        Ok(Self {
            device,
            capacity_slots,
            index,
            free,
            count,
            generation: next_generation,
        })
    }

    /// Consume the store and return the underlying device. Test-only
    /// escape hatch used by the reboot-cycle tests.
    #[cfg(test)]
    pub fn into_device(self) -> B {
        self.device
    }

    pub fn capacity_slots(&self) -> u64 {
        self.capacity_slots
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
    // known state" scenarios without eating test-runner memory.
    const TEST_CAP: u64 = 8;
    const TEST_DEV_BLOCKS: u64 = 1 + 2 * TEST_CAP;

    fn fresh_store() -> DiskObjectStore<MemBlockDevice> {
        let dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap()
    }

    fn make_object(author_seed: u8, content: &[u8]) -> CambiObject {
        let author = Principal::from_public_key([author_seed; 32]);
        CambiObject::new(author, content.to_vec(), 42)
    }

    // ------------------- Encoding helpers (pure) -------------------

    #[test]
    fn superblock_roundtrip() {
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, 128, 7, 0xDEAD_BEEF);
        match classify_superblock(&buf) {
            SuperblockState::Valid(snap) => {
                assert_eq!(snap.capacity_slots, 128);
                assert_eq!(snap.generation, 7);
                assert_eq!(snap.version, FORMAT_VERSION);
            }
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
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, 64, 1, 0);
        buf[100] ^= 0xFF; // flip a middle byte, checksum now wrong
        assert_eq!(classify_superblock(&buf), SuperblockState::Corrupt);
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
        let gen_first_mount = store.generation;

        let dev = store.into_device();
        let store2 = DiskObjectStore::open_or_format(dev, TEST_CAP).unwrap();
        assert!(store2.generation > gen_first_mount);
    }

    // ------------------- Corruption paths -------------------

    #[test]
    fn mount_rejects_corrupt_superblock() {
        let mut dev = MemBlockDevice::new(TEST_DEV_BLOCKS);
        // Write a plausible-but-corrupt superblock: right magic, wrong checksum.
        let mut buf = [0u8; BLOCK_SIZE];
        encode_superblock(&mut buf, TEST_CAP, 1, 0);
        buf[60] ^= 0x01;
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
        assert_eq!(total_blocks_for_capacity(10), 21);
    }
}
