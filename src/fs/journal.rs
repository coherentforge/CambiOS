// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Metadata journal record types.
//!
//! Per [ADR-029 § Decision 5](../../docs/adr/029-posix-file-storage-model.md),
//! the journal is a fixed-size circular log that carries metadata
//! transactions. Each record describes a single *metadata
//! transaction* — atomic at replay (either the entire record applies
//! on replay or none of it does). Every bitmap mutation, every inode
//! extent-list change, every directory entry insertion / deletion,
//! every rename, every ACL grant / revoke, every link_count change —
//! all flow through journal records.
//!
//! Data writes (the bytes inside a content block) are NOT journaled.
//! Their visibility is gated by the inode extent list, which IS
//! journaled atomically with the bitmap mutation that justified the
//! new block. The invariant per ADR-029 § Decision 5: *anything that
//! affects which blocks are reachable is journaled; anything that
//! affects what bytes are in a block is not.*
//!
//! ## Scope of this module (step 5A)
//!
//! Step 5A lands the record-shape data structures only:
//! [`JournalRecord`], the per-variant payload structs, [`JournalError`],
//! and pure helpers for constructing well-formed records. Encode /
//! decode helpers and the circular-log structure with replay loop
//! land in step 5B. The integration with the POSIX backend lands in
//! step 5C; the cross-backend usage by the CambiObject backend lands
//! in step 5D (per [ADR-010 § Divergence 3](../../docs/adr/010-persistent-object-store-on-disk-format.md)).

extern crate alloc;

use alloc::vec::Vec;

use cambios_abi::{InodeId, MAX_EXTENTS_PER_INODE, Rights};

use crate::fs::bitmap::BitmapError;

/// SCAFFOLDING: bitmap mutations per `ExtentUpdate` record (ADR-029
/// § Decision 5).
/// Why: worst-case CoW commit is 1 bitmap-set + `MAX_EXTENTS_PER_INODE`
///      bitmap-clears (replacing every existing extent). 32 gives
///      ~2× headroom.
/// Replace when: a batch primitive (batch-rename, batch-unlink)
///      requires more mutations per transaction.
pub const MAX_BITMAP_MUTATIONS_PER_RECORD: usize = 32;

/// SCAFFOLDING: maximum directory entries packed into a single
/// `DirectoryEntry` journal record. v1 directory operations
/// (mkdir / unlink / rename) touch at most a few entries; 8 gives
/// ~3× headroom over typical and bounds the per-record size.
/// Replace when: a bulk-directory primitive (e.g., batch-import,
/// directory-tree clone) requires more entries per record.
pub const MAX_DIRENTS_PER_RECORD: usize = 8;

/// Typed error surface for journal-record construction, encoding,
/// decoding, and (in 5C) replay. Variants are added as the journal
/// grows; this set covers step 5A construction errors plus 5B
/// codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    /// Wraps a bitmap-side error so callers can propagate uniformly
    /// when a bitmap operation fails as part of journal-record
    /// construction or replay.
    Bitmap(BitmapError),
    /// `ExtentUpdate + BitmapMutation` record carries more than
    /// `MAX_BITMAP_MUTATIONS_PER_RECORD` bitmap operations.
    TooManyMutations,
    /// `ExtentUpdate + BitmapMutation` record's `new_extents` array
    /// violates the contiguous-Some invariant (matching the inode
    /// validation per `validate_inode` in `crate::fs::posix`).
    NonContiguousExtents,
    /// `DirectoryEntry` record carries more entries than
    /// `MAX_DIRENTS_PER_RECORD`.
    TooManyDirents,
    /// Encoded payload exceeds the 16-bit `payload_size` field. None
    /// of the ADR-029 record kinds approach this bound; the check
    /// exists to make corruption impossible to silently encode.
    PayloadTooLarge,
    /// Decode reached the end of the byte buffer before reading a
    /// complete record (header + payload + checksum).
    BufferTooShort,
    /// On-disk record header carries an unknown `kind` discriminant.
    UnknownKind,
    /// On-disk record header carries an unknown `version` byte.
    UnknownVersion,
    /// On-disk record's Blake3 checksum doesn't match the preceding
    /// bytes. Distinct from on-disk inode `HeaderChecksumMismatch`
    /// because callers (replay) react differently — a torn write at
    /// the journal head is normal, not an error to surface upward.
    ChecksumMismatch,
    /// On-disk record's payload bytes don't match the variant's
    /// expected internal structure (wrong size, bad enum discriminant,
    /// non-zero reserved bytes).
    MalformedPayload,
}

impl From<BitmapError> for JournalError {
    fn from(e: BitmapError) -> Self {
        JournalError::Bitmap(e)
    }
}

/// A single bitmap mutation: set bit (block now allocated) or clear
/// bit (block now free). Bundled inside an `ExtentUpdate +
/// BitmapMutation` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapMutation {
    /// Block transitions from free → occupied.
    Set(u64),
    /// Block transitions from occupied → free.
    Clear(u64),
}

/// A directory entry as it appears inside a `DirectoryEntry` record.
/// Name bytes live alongside in a separate payload buffer (encoded
/// in step 5B); the record carries the child inode and the offset/
/// length into the name buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirentRef {
    pub child: InodeId,
    /// Offset of this entry's name bytes within the record's name
    /// buffer.
    pub name_offset: u32,
    /// Length of this entry's name in bytes.
    pub name_len: u16,
}

/// Operation performed on a directory entry. Per ADR-029
/// § Decision 5: insert / delete / rewrite. Rewrite covers in-place
/// rename-without-cross-directory cases (e.g., `chmod`-style flag
/// updates if directories ever carry per-entry flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirentOp {
    Insert,
    Delete,
    Rewrite,
}

/// One directory-entry change recorded in a journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirentChange {
    pub op: DirentOp,
    pub directory: InodeId,
    pub entry: DirentRef,
}

/// Payload of an `ExtentUpdate + BitmapMutation` journal record. The
/// inode's extent list transitions from its previous state to
/// `new_extents`; the bitmap mutations describe the bits flipped to
/// justify the transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentUpdate {
    pub inode: InodeId,
    /// New extent list. Must satisfy the contiguous-Some invariant
    /// (Some entries packed from index 0).
    pub new_extents: [Option<cambios_abi::Extent>; MAX_EXTENTS_PER_INODE],
    /// Bitmap bits set / cleared. Bounded by
    /// `MAX_BITMAP_MUTATIONS_PER_RECORD`.
    pub mutations: Vec<BitmapMutation>,
}

/// Payload of a `Rename` record — covers both directory-entry
/// changes (source delete, destination insert) atomically. The
/// kernel never journals one without the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenamePayload {
    pub source_dir: InodeId,
    pub source: DirentRef,
    pub dest_dir: InodeId,
    pub dest: DirentRef,
}

/// Payload of an `AclGrant` or `AclRevoke` record. ACL ops live as
/// their own record kind (not bundled with `ExtentUpdate`) because
/// they touch inode metadata without bitmap or extent activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclChange {
    pub inode: InodeId,
    pub principal: [u8; 32],
    /// `Some(rights)` for grant; `None` for revoke. (Revoke ignores
    /// the rights field; the principal alone identifies the row to
    /// remove.)
    pub rights: Option<Rights>,
    /// `0` for "no expiry" per the disk-layer convention.
    pub expiry: u64,
}

/// Payload of a `LinkCount Set` record. ADR-029 § Decision 5 spec:
/// "Records the new absolute `link_count` value (not a delta), so
/// the record is idempotent under repeated replay. Relative-mutation
/// records (delta semantics) would break the journal-replay
/// idempotency invariant."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkCountSet {
    pub inode: InodeId,
    pub new_value: u32,
}

/// Top-level journal record. Matches ADR-029 § Decision 5's
/// enumeration of record kinds. Each variant is a separate atomic
/// transaction at replay; the journal applies each in order.
///
/// `Checkpoint` is the bookkeeping marker — replay starts after the
/// most recent checkpoint and the kernel advances the superblock's
/// `last_checkpoint_offset` at cadence (every 4 KiB of journal
/// records or every 100 ticks per ADR-029 § Decision 5).
///
/// All variants are designed to be **idempotent** under repeated
/// replay: re-applying the same record produces the same state.
/// The journal-replay idempotency invariant (ADR-029 § Verification
/// Stance row 3) is a structural property of the enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecord {
    /// Allocate a fresh inode at the given slot.
    InodeAllocate { inode: InodeId },
    /// Free an inode at the given slot. Replay sets the on-disk
    /// magic to "free"; the inode region is the projection of these
    /// events.
    InodeFree { inode: InodeId },
    /// CoW commit step per ADR-029 § Decision 2. Inode extent list
    /// updates, bitmap mutations, and the matching durability marker
    /// bundle into one record.
    ExtentUpdate(ExtentUpdate),
    /// Directory contents change (mkdir / unlink within a directory,
    /// link / readdir-affecting ops). Up to `MAX_DIRENTS_PER_RECORD`
    /// entries per record.
    DirectoryEntry { changes: Vec<DirentChange> },
    /// Atomic rename — source delete + destination insert in one
    /// record. The kernel never journals one without the other; the
    /// invariant is on the record, not on caller discipline.
    Rename(RenamePayload),
    /// ACL grant: adds or replaces a `(principal, rights, expiry)`
    /// row on an inode's ACL.
    AclGrant(AclChange),
    /// ACL revoke: removes a principal's row from an inode's ACL.
    /// The `rights` field of the carried `AclChange` is `None` for
    /// revokes.
    AclRevoke(AclChange),
    /// Idempotent link-count set per ADR-029 § Decision 5 (absolute
    /// value, not a delta).
    LinkCountSet(LinkCountSet),
    /// Checkpoint marker — emitted at cadence per ADR-029 § Decision
    /// 5. Records preceding the most recent checkpoint have been
    /// flushed to their respective on-disk regions; mount-time
    /// replay starts from the checkpoint and applies later records.
    Checkpoint { tick: u64 },
}

// ============================================================================
// Construction helpers (validate the bounded-size invariants)
// ============================================================================

impl JournalRecord {
    /// Construct an `ExtentUpdate` record, validating the bounded-
    /// size and contiguous-Some invariants. Returns `JournalError`
    /// if the inputs are malformed.
    pub fn extent_update(
        inode: InodeId,
        new_extents: [Option<cambios_abi::Extent>; MAX_EXTENTS_PER_INODE],
        mutations: Vec<BitmapMutation>,
    ) -> Result<Self, JournalError> {
        if mutations.len() > MAX_BITMAP_MUTATIONS_PER_RECORD {
            return Err(JournalError::TooManyMutations);
        }
        // Contiguous-Some invariant on new_extents.
        let mut saw_none = false;
        for slot in new_extents.iter() {
            if slot.is_none() {
                saw_none = true;
            } else if saw_none {
                return Err(JournalError::NonContiguousExtents);
            }
        }
        Ok(JournalRecord::ExtentUpdate(ExtentUpdate {
            inode,
            new_extents,
            mutations,
        }))
    }

    /// Construct a `DirectoryEntry` record, validating the bounded-
    /// size invariant.
    pub fn directory_entry(changes: Vec<DirentChange>) -> Result<Self, JournalError> {
        if changes.len() > MAX_DIRENTS_PER_RECORD {
            return Err(JournalError::TooManyDirents);
        }
        Ok(JournalRecord::DirectoryEntry { changes })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cambios_abi::Extent;

    fn empty_extents() -> [Option<Extent>; MAX_EXTENTS_PER_INODE] {
        [None; MAX_EXTENTS_PER_INODE]
    }

    #[test]
    fn extent_update_accepts_empty() {
        let rec = JournalRecord::extent_update(
            InodeId::new(0),
            empty_extents(),
            alloc::vec::Vec::new(),
        )
        .unwrap();
        assert!(matches!(rec, JournalRecord::ExtentUpdate(_)));
    }

    #[test]
    fn extent_update_accepts_contiguous_extents() {
        let mut extents = empty_extents();
        extents[0] = Some(Extent { start_lba: 100, block_count: 4 });
        extents[1] = Some(Extent { start_lba: 200, block_count: 2 });
        let rec = JournalRecord::extent_update(
            InodeId::new(0),
            extents,
            alloc::vec![BitmapMutation::Set(100), BitmapMutation::Set(200)],
        )
        .unwrap();
        match rec {
            JournalRecord::ExtentUpdate(eu) => {
                assert_eq!(eu.mutations.len(), 2);
                assert_eq!(eu.new_extents[0].unwrap().start_lba, 100);
                assert_eq!(eu.new_extents[1].unwrap().start_lba, 200);
                assert!(eu.new_extents[2].is_none());
            }
            _ => panic!("expected ExtentUpdate"),
        }
    }

    #[test]
    fn extent_update_rejects_noncontiguous() {
        let mut extents = empty_extents();
        // Skip slot 0; place at slot 1. Violates contiguous-Some.
        extents[1] = Some(Extent { start_lba: 100, block_count: 1 });
        let result = JournalRecord::extent_update(
            InodeId::new(0),
            extents,
            alloc::vec::Vec::new(),
        );
        assert_eq!(result, Err(JournalError::NonContiguousExtents));
    }

    #[test]
    fn extent_update_rejects_too_many_mutations() {
        let mut mutations = alloc::vec::Vec::new();
        for i in 0..=MAX_BITMAP_MUTATIONS_PER_RECORD {
            mutations.push(BitmapMutation::Set(i as u64));
        }
        let result = JournalRecord::extent_update(
            InodeId::new(0),
            empty_extents(),
            mutations,
        );
        assert_eq!(result, Err(JournalError::TooManyMutations));
    }

    #[test]
    fn directory_entry_accepts_empty() {
        let rec = JournalRecord::directory_entry(alloc::vec::Vec::new()).unwrap();
        match rec {
            JournalRecord::DirectoryEntry { changes } => assert!(changes.is_empty()),
            _ => panic!("expected DirectoryEntry"),
        }
    }

    #[test]
    fn directory_entry_rejects_too_many() {
        let mut changes = alloc::vec::Vec::new();
        for i in 0..=MAX_DIRENTS_PER_RECORD {
            changes.push(DirentChange {
                op: DirentOp::Insert,
                directory: InodeId::new(0),
                entry: DirentRef {
                    child: InodeId::new(i as u64),
                    name_offset: 0,
                    name_len: 1,
                },
            });
        }
        let result = JournalRecord::directory_entry(changes);
        assert_eq!(result, Err(JournalError::TooManyDirents));
    }

    #[test]
    fn record_variant_equality() {
        // Round-trip property: clone + Eq holds for every variant.
        // Smoke-test for the PartialEq derives.
        let a = JournalRecord::InodeAllocate { inode: InodeId::new(7) };
        let b = JournalRecord::InodeAllocate { inode: InodeId::new(7) };
        assert_eq!(a, b);
        let c = JournalRecord::InodeFree { inode: InodeId::new(7) };
        assert_ne!(a, c);
    }

    #[test]
    fn checkpoint_record_constructs() {
        let cp = JournalRecord::Checkpoint { tick: 12345 };
        match cp {
            JournalRecord::Checkpoint { tick } => assert_eq!(tick, 12345),
            _ => panic!("expected Checkpoint"),
        }
    }

    #[test]
    fn link_count_set_constructs() {
        let lc = JournalRecord::LinkCountSet(LinkCountSet {
            inode: InodeId::new(3),
            new_value: 5,
        });
        match lc {
            JournalRecord::LinkCountSet(payload) => {
                assert_eq!(payload.inode.raw(), 3);
                assert_eq!(payload.new_value, 5);
            }
            _ => panic!("expected LinkCountSet"),
        }
    }

    #[test]
    fn acl_grant_carries_rights() {
        let grant = JournalRecord::AclGrant(AclChange {
            inode: InodeId::new(1),
            principal: [0xAA; 32],
            rights: Some(Rights::READ.union(Rights::WRITE)),
            expiry: 0,
        });
        match grant {
            JournalRecord::AclGrant(c) => {
                assert!(c.rights.is_some());
                assert!(c.rights.unwrap().contains(Rights::READ));
            }
            _ => panic!("expected AclGrant"),
        }
    }

    #[test]
    fn acl_revoke_has_no_rights() {
        let revoke = JournalRecord::AclRevoke(AclChange {
            inode: InodeId::new(1),
            principal: [0xBB; 32],
            rights: None,
            expiry: 0,
        });
        match revoke {
            JournalRecord::AclRevoke(c) => assert!(c.rights.is_none()),
            _ => panic!("expected AclRevoke"),
        }
    }

    #[test]
    fn bitmap_error_converts_to_journal_error() {
        let je: JournalError = BitmapError::OutOfBounds.into();
        assert_eq!(je, JournalError::Bitmap(BitmapError::OutOfBounds));
    }

    // ========================================================================
    // Encode/decode roundtrips (commit 5B)
    // ========================================================================

    fn roundtrip(rec: JournalRecord) {
        let encoded = super::encode_record(&rec).expect("encode");
        let (decoded, consumed) = super::decode_record(&encoded).expect("decode");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, rec);
    }

    #[test]
    fn roundtrip_inode_allocate() {
        roundtrip(JournalRecord::InodeAllocate { inode: InodeId::new(42) });
    }

    #[test]
    fn roundtrip_inode_free() {
        roundtrip(JournalRecord::InodeFree { inode: InodeId::new(u64::MAX) });
    }

    #[test]
    fn roundtrip_extent_update_empty() {
        let rec = JournalRecord::extent_update(
            InodeId::new(7),
            empty_extents(),
            alloc::vec::Vec::new(),
        )
        .unwrap();
        roundtrip(rec);
    }

    #[test]
    fn roundtrip_extent_update_populated() {
        let mut extents = empty_extents();
        extents[0] = Some(Extent { start_lba: 1024, block_count: 4 });
        extents[1] = Some(Extent { start_lba: 2048, block_count: 8 });
        extents[2] = Some(Extent { start_lba: 4096, block_count: 16 });
        let mutations = alloc::vec![
            BitmapMutation::Set(1024),
            BitmapMutation::Set(2048),
            BitmapMutation::Clear(512),
        ];
        let rec = JournalRecord::extent_update(InodeId::new(11), extents, mutations).unwrap();
        roundtrip(rec);
    }

    #[test]
    fn roundtrip_directory_entry() {
        let rec = JournalRecord::directory_entry(alloc::vec![
            DirentChange {
                op: DirentOp::Insert,
                directory: InodeId::new(0),
                entry: DirentRef {
                    child: InodeId::new(5),
                    name_offset: 0,
                    name_len: 4,
                },
            },
            DirentChange {
                op: DirentOp::Delete,
                directory: InodeId::new(0),
                entry: DirentRef {
                    child: InodeId::new(6),
                    name_offset: 4,
                    name_len: 7,
                },
            },
        ])
        .unwrap();
        roundtrip(rec);
    }

    #[test]
    fn roundtrip_rename() {
        roundtrip(JournalRecord::Rename(RenamePayload {
            source_dir: InodeId::new(1),
            source: DirentRef {
                child: InodeId::new(10),
                name_offset: 0,
                name_len: 8,
            },
            dest_dir: InodeId::new(2),
            dest: DirentRef {
                child: InodeId::new(10),
                name_offset: 8,
                name_len: 12,
            },
        }));
    }

    #[test]
    fn roundtrip_acl_grant() {
        roundtrip(JournalRecord::AclGrant(AclChange {
            inode: InodeId::new(33),
            principal: [0xAB; 32],
            rights: Some(Rights::READ.union(Rights::WRITE)),
            expiry: 1_000_000,
        }));
    }

    #[test]
    fn roundtrip_acl_grant_no_expiry() {
        roundtrip(JournalRecord::AclGrant(AclChange {
            inode: InodeId::new(33),
            principal: [0xCD; 32],
            rights: Some(Rights::EXECUTE),
            expiry: 0,
        }));
    }

    #[test]
    fn roundtrip_acl_revoke() {
        roundtrip(JournalRecord::AclRevoke(AclChange {
            inode: InodeId::new(33),
            principal: [0xEF; 32],
            rights: None,
            expiry: 0,
        }));
    }

    #[test]
    fn roundtrip_link_count_set() {
        roundtrip(JournalRecord::LinkCountSet(LinkCountSet {
            inode: InodeId::new(99),
            new_value: 17,
        }));
    }

    #[test]
    fn roundtrip_checkpoint() {
        roundtrip(JournalRecord::Checkpoint { tick: 123_456_789 });
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        let mut buf = super::encode_record(&JournalRecord::InodeAllocate {
            inode: InodeId::new(1),
        })
        .unwrap();
        buf[0] = 0x42; // unknown kind
        // Recompute checksum so the kind is the only violation.
        let cs = super::checksum8(&buf[..buf.len() - 8]);
        let end = buf.len();
        buf[end - 8..].copy_from_slice(&cs);
        let result = super::decode_record(&buf);
        assert_eq!(result, Err(JournalError::UnknownKind));
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut buf = super::encode_record(&JournalRecord::InodeAllocate {
            inode: InodeId::new(1),
        })
        .unwrap();
        buf[1] = 99; // unknown version
        let cs = super::checksum8(&buf[..buf.len() - 8]);
        let end = buf.len();
        buf[end - 8..].copy_from_slice(&cs);
        let result = super::decode_record(&buf);
        assert_eq!(result, Err(JournalError::UnknownVersion));
    }

    #[test]
    fn decode_rejects_checksum_mismatch() {
        let mut buf = super::encode_record(&JournalRecord::InodeAllocate {
            inode: InodeId::new(1),
        })
        .unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 0xFF;
        let result = super::decode_record(&buf);
        assert_eq!(result, Err(JournalError::ChecksumMismatch));
    }

    #[test]
    fn decode_rejects_buffer_too_short() {
        let buf = [0u8; 5];
        let result = super::decode_record(&buf);
        assert_eq!(result, Err(JournalError::BufferTooShort));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut buf = super::encode_record(&JournalRecord::InodeAllocate {
            inode: InodeId::new(1),
        })
        .unwrap();
        // Drop the last 3 bytes; the declared payload_size now exceeds
        // available bytes.
        buf.truncate(buf.len() - 3);
        let result = super::decode_record(&buf);
        assert_eq!(result, Err(JournalError::BufferTooShort));
    }

    #[test]
    fn decode_extent_update_rejects_non_zero_reserved() {
        let mut extents = empty_extents();
        extents[0] = Some(Extent { start_lba: 100, block_count: 1 });
        let rec = JournalRecord::extent_update(
            InodeId::new(0),
            extents,
            alloc::vec::Vec::new(),
        )
        .unwrap();
        let mut buf = super::encode_record(&rec).unwrap();
        // Reserved bytes 11..16 of the payload — payload starts at
        // offset RECORD_HEADER_BYTES = 4. So reserved is at buf[15..20].
        buf[16] = 0xFF; // poke a reserved byte
        let cs = super::checksum8(&buf[..buf.len() - 8]);
        let end = buf.len();
        buf[end - 8..].copy_from_slice(&cs);
        let result = super::decode_record(&buf);
        assert_eq!(result, Err(JournalError::MalformedPayload));
    }

    // ========================================================================
    // Cursor + replay (commit 5B)
    // ========================================================================

    #[test]
    fn cursor_yields_records_in_order() {
        let a = JournalRecord::InodeAllocate { inode: InodeId::new(1) };
        let b = JournalRecord::Checkpoint { tick: 42 };
        let c = JournalRecord::InodeFree { inode: InodeId::new(1) };
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&super::encode_record(&a).unwrap());
        buf.extend_from_slice(&super::encode_record(&b).unwrap());
        buf.extend_from_slice(&super::encode_record(&c).unwrap());
        // Trailing blank space (zeros) should stop the cursor cleanly.
        buf.extend_from_slice(&[0u8; 32]);

        let mut cursor = super::JournalRecordCursor::new(&buf, 0);
        let r1 = cursor.next().unwrap().unwrap();
        let r2 = cursor.next().unwrap().unwrap();
        let r3 = cursor.next().unwrap().unwrap();
        assert_eq!(r1, a);
        assert_eq!(r2, b);
        assert_eq!(r3, c);
        assert!(cursor.next().is_none());
    }

    #[test]
    fn cursor_stops_at_blank_region() {
        let a = JournalRecord::InodeAllocate { inode: InodeId::new(1) };
        let mut buf = super::encode_record(&a).unwrap();
        buf.extend_from_slice(&[0u8; 64]); // blank
        let mut cursor = super::JournalRecordCursor::new(&buf, 0);
        assert_eq!(cursor.next().unwrap().unwrap(), a);
        assert!(cursor.next().is_none());
        assert_eq!(cursor.offset(), super::encode_record(&a).unwrap().len());
    }

    #[test]
    fn cursor_surfaces_torn_write() {
        let a = JournalRecord::InodeAllocate { inode: InodeId::new(1) };
        let b = JournalRecord::Checkpoint { tick: 5 };
        let mut buf = super::encode_record(&a).unwrap();
        let mut b_bytes = super::encode_record(&b).unwrap();
        // Corrupt the second record's checksum to simulate a torn
        // write at the head.
        let len = b_bytes.len();
        b_bytes[len - 1] ^= 0xFF;
        buf.extend_from_slice(&b_bytes);

        let mut cursor = super::JournalRecordCursor::new(&buf, 0);
        let r1 = cursor.next().unwrap().unwrap();
        assert_eq!(r1, a);
        let r2_err = cursor.next().unwrap().unwrap_err();
        assert_eq!(r2_err, JournalError::ChecksumMismatch);
        // After an error, the cursor stops.
        assert!(cursor.next().is_none());
    }

    #[test]
    fn replay_records_calls_callback_per_record() {
        let records = alloc::vec![
            JournalRecord::InodeAllocate { inode: InodeId::new(1) },
            JournalRecord::InodeAllocate { inode: InodeId::new(2) },
            JournalRecord::Checkpoint { tick: 100 },
            JournalRecord::InodeFree { inode: InodeId::new(1) },
        ];
        let mut buf = alloc::vec::Vec::new();
        for r in &records {
            buf.extend_from_slice(&super::encode_record(r).unwrap());
        }

        let mut seen = alloc::vec::Vec::new();
        let end = super::replay_records(&buf, 0, |r| {
            seen.push(r.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, records);
        assert_eq!(end, buf.len());
    }

    #[test]
    fn replay_records_stops_at_torn_write() {
        let a = JournalRecord::InodeAllocate { inode: InodeId::new(1) };
        let b = JournalRecord::Checkpoint { tick: 5 };
        let a_bytes = super::encode_record(&a).unwrap();
        let a_len = a_bytes.len();
        let mut buf = a_bytes;
        let mut b_bytes = super::encode_record(&b).unwrap();
        let b_len = b_bytes.len();
        b_bytes[b_len - 1] ^= 0xFF;
        buf.extend_from_slice(&b_bytes);

        let mut seen = alloc::vec::Vec::new();
        let result = super::replay_records(&buf, 0, |r| {
            seen.push(r.clone());
            Ok(())
        });
        assert_eq!(result, Err(JournalError::ChecksumMismatch));
        // The first record was applied before the failure surfaced.
        assert_eq!(seen, alloc::vec![a]);
        // The torn record starts at offset a_len.
        let _ = a_len; // bound by-value
    }

    #[test]
    fn replay_records_from_checkpoint_offset() {
        // Verify the cursor can start mid-buffer (post-checkpoint
        // replay pattern). Build A, Checkpoint, B; start replay
        // after A.
        let a = JournalRecord::InodeAllocate { inode: InodeId::new(1) };
        let cp = JournalRecord::Checkpoint { tick: 42 };
        let b = JournalRecord::InodeFree { inode: InodeId::new(1) };
        let a_bytes = super::encode_record(&a).unwrap();
        let cp_bytes = super::encode_record(&cp).unwrap();
        let b_bytes = super::encode_record(&b).unwrap();
        let mut buf = a_bytes.clone();
        buf.extend_from_slice(&cp_bytes);
        buf.extend_from_slice(&b_bytes);

        let mut seen = alloc::vec::Vec::new();
        super::replay_records(&buf, a_bytes.len(), |r| {
            seen.push(r.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, alloc::vec![cp, b]);
    }

    #[test]
    fn replay_records_propagates_callback_error() {
        let records = alloc::vec![
            JournalRecord::InodeAllocate { inode: InodeId::new(1) },
            JournalRecord::InodeAllocate { inode: InodeId::new(2) },
        ];
        let mut buf = alloc::vec::Vec::new();
        for r in &records {
            buf.extend_from_slice(&super::encode_record(r).unwrap());
        }
        let result = super::replay_records(&buf, 0, |_| {
            Err(JournalError::MalformedPayload)
        });
        assert_eq!(result, Err(JournalError::MalformedPayload));
    }
}

// ============================================================================
// On-disk record codec
// ============================================================================
//
// Wire format per record (byte-packed, little-endian, all multi-byte
// fields LE):
//
//   0..1   kind discriminant (u8)
//   1..2   record-format version (u8; v1 = 1)
//   2..4   payload_size (u16 LE)
//   4..(4+payload_size)   payload
//   ((4+payload_size)..(12+payload_size))   blake3(buf[0..]).bytes[0..8]
//
// Total record size = 4 + payload_size + 8 = payload_size + 12 bytes.
//
// `payload_size` is bounded by the per-variant max payload — every
// kind has a static upper bound (verifier-friendly). The 16-bit cap
// of 65535 is far above any kind's max; `JournalError::PayloadTooLarge`
// is a defense-in-depth check, not a routine outcome.

/// ARCHITECTURAL: record-header byte length (kind + version +
/// payload_size). Changing this is a new record-format version.
pub const RECORD_HEADER_BYTES: usize = 4;

/// ARCHITECTURAL: per-record checksum byte length (Blake3, first 8
/// bytes). Matches the inode-header and superblock-header checksum
/// convention. Changing this is a new record-format version.
pub const RECORD_CHECKSUM_BYTES: usize = 8;

/// ARCHITECTURAL: record-format version. Mount rejects unknown
/// versions; v2 lands when a record kind grows or the header layout
/// changes.
pub const RECORD_FORMAT_VERSION: u8 = 1;

// Kind discriminants. Non-zero so a blank journal region (all 0x00)
// never accidentally decodes as a valid record. Values match the
// JournalRecord variant order; `Checkpoint` and `Pad` use distinct
// high values to make them obvious at hex-dump time.
const KIND_INODE_ALLOCATE: u8 = 0x01;
const KIND_INODE_FREE: u8 = 0x02;
const KIND_EXTENT_UPDATE: u8 = 0x03;
const KIND_DIRECTORY_ENTRY: u8 = 0x04;
const KIND_RENAME: u8 = 0x05;
const KIND_ACL_GRANT: u8 = 0x06;
const KIND_ACL_REVOKE: u8 = 0x07;
const KIND_LINK_COUNT_SET: u8 = 0x08;
const KIND_CHECKPOINT: u8 = 0xFE;
/// Reserved for pad records that fill the tail of the journal region
/// when a record won't fit before wrap-around. Step 5C writes these.
pub const KIND_PAD: u8 = 0xFF;

// DirentOp on-disk discriminants.
const DIRENT_OP_INSERT: u8 = 0;
const DIRENT_OP_DELETE: u8 = 1;
const DIRENT_OP_REWRITE: u8 = 2;

/// First 8 bytes of `blake3(data)`. Same shape as the inode-header
/// checksum in `crate::fs::posix` and the CambiObject-header checksum
/// in `crate::fs::disk`.
fn checksum8(data: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&blake3::hash(data).as_bytes()[0..8]);
    out
}

/// Encode one journal record to bytes. Output is a self-contained
/// `Vec<u8>` of `RECORD_HEADER_BYTES + payload_size +
/// RECORD_CHECKSUM_BYTES` bytes, suitable for appending to a
/// journal region.
pub fn encode_record(rec: &JournalRecord) -> Result<Vec<u8>, JournalError> {
    let mut payload: Vec<u8> = Vec::new();
    let kind = encode_payload(rec, &mut payload)?;
    let payload_size: u16 = payload
        .len()
        .try_into()
        .map_err(|_| JournalError::PayloadTooLarge)?;

    let mut record = Vec::with_capacity(RECORD_HEADER_BYTES + payload.len() + RECORD_CHECKSUM_BYTES);
    record.push(kind);
    record.push(RECORD_FORMAT_VERSION);
    record.extend_from_slice(&payload_size.to_le_bytes());
    record.extend_from_slice(&payload);
    let cs = checksum8(&record);
    record.extend_from_slice(&cs);
    Ok(record)
}

fn encode_payload(rec: &JournalRecord, out: &mut Vec<u8>) -> Result<u8, JournalError> {
    match rec {
        JournalRecord::InodeAllocate { inode } => {
            out.extend_from_slice(&inode.raw().to_le_bytes());
            Ok(KIND_INODE_ALLOCATE)
        }
        JournalRecord::InodeFree { inode } => {
            out.extend_from_slice(&inode.raw().to_le_bytes());
            Ok(KIND_INODE_FREE)
        }
        JournalRecord::ExtentUpdate(eu) => {
            if eu.mutations.len() > MAX_BITMAP_MUTATIONS_PER_RECORD {
                return Err(JournalError::TooManyMutations);
            }
            // Validate contiguous-Some on encode side as well (the
            // construction helper also validates, but a hand-built
            // record could still arrive here invalid).
            let mut saw_none = false;
            for slot in eu.new_extents.iter() {
                if slot.is_none() {
                    saw_none = true;
                } else if saw_none {
                    return Err(JournalError::NonContiguousExtents);
                }
            }
            let extent_count: u8 = eu
                .new_extents
                .iter()
                .take_while(|s| s.is_some())
                .count()
                .try_into()
                .map_err(|_| JournalError::PayloadTooLarge)?;
            let mutation_count: u16 = eu.mutations.len() as u16;

            out.extend_from_slice(&eu.inode.raw().to_le_bytes());
            out.push(extent_count);
            out.extend_from_slice(&mutation_count.to_le_bytes());
            out.extend_from_slice(&[0u8; 5]); // reserved, 5 bytes for 8-byte alignment
            for slot in eu.new_extents.iter().take(extent_count as usize) {
                let extent = slot.expect("contiguous-Some invariant");
                out.extend_from_slice(&extent.start_lba.to_le_bytes());
                out.extend_from_slice(&extent.block_count.to_le_bytes());
            }
            for m in eu.mutations.iter() {
                match m {
                    BitmapMutation::Set(block) => {
                        out.push(0);
                        out.extend_from_slice(&block.to_le_bytes());
                    }
                    BitmapMutation::Clear(block) => {
                        out.push(1);
                        out.extend_from_slice(&block.to_le_bytes());
                    }
                }
            }
            Ok(KIND_EXTENT_UPDATE)
        }
        JournalRecord::DirectoryEntry { changes } => {
            if changes.len() > MAX_DIRENTS_PER_RECORD {
                return Err(JournalError::TooManyDirents);
            }
            // The in-memory `DirentRef` records offset+len into the
            // record's name buffer but does not carry the names
            // themselves; encoding here emits `name_buf_len = 0` and
            // no name bytes. ADR-029 step 5C extends this when the
            // directory write path is wired (the names live on the
            // syscall-side caller and get appended at journal-append
            // time).
            let change_count: u8 = changes
                .len()
                .try_into()
                .map_err(|_| JournalError::PayloadTooLarge)?;
            let name_buf_len: u32 = 0;
            out.push(change_count);
            out.extend_from_slice(&[0u8; 3]); // reserved
            out.extend_from_slice(&name_buf_len.to_le_bytes());
            for ch in changes.iter() {
                let op_byte = match ch.op {
                    DirentOp::Insert => DIRENT_OP_INSERT,
                    DirentOp::Delete => DIRENT_OP_DELETE,
                    DirentOp::Rewrite => DIRENT_OP_REWRITE,
                };
                out.push(op_byte);
                out.extend_from_slice(&[0u8; 7]); // reserved
                out.extend_from_slice(&ch.directory.raw().to_le_bytes());
                out.extend_from_slice(&ch.entry.child.raw().to_le_bytes());
                out.extend_from_slice(&ch.entry.name_offset.to_le_bytes());
                out.extend_from_slice(&ch.entry.name_len.to_le_bytes());
                out.extend_from_slice(&[0u8; 2]); // reserved
            }
            Ok(KIND_DIRECTORY_ENTRY)
        }
        JournalRecord::Rename(rp) => {
            out.extend_from_slice(&rp.source_dir.raw().to_le_bytes());
            out.extend_from_slice(&rp.source.child.raw().to_le_bytes());
            out.extend_from_slice(&rp.source.name_offset.to_le_bytes());
            out.extend_from_slice(&rp.source.name_len.to_le_bytes());
            out.extend_from_slice(&[0u8; 2]); // reserved
            out.extend_from_slice(&rp.dest_dir.raw().to_le_bytes());
            out.extend_from_slice(&rp.dest.child.raw().to_le_bytes());
            out.extend_from_slice(&rp.dest.name_offset.to_le_bytes());
            out.extend_from_slice(&rp.dest.name_len.to_le_bytes());
            out.extend_from_slice(&[0u8; 2]); // reserved
            // name_buf_len = 0 in 5B per the DirectoryEntry note above.
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&[0u8; 4]); // reserved
            Ok(KIND_RENAME)
        }
        JournalRecord::AclGrant(c) => {
            encode_acl_change(c, true, out);
            Ok(KIND_ACL_GRANT)
        }
        JournalRecord::AclRevoke(c) => {
            encode_acl_change(c, false, out);
            Ok(KIND_ACL_REVOKE)
        }
        JournalRecord::LinkCountSet(lc) => {
            out.extend_from_slice(&lc.inode.raw().to_le_bytes());
            out.extend_from_slice(&lc.new_value.to_le_bytes());
            out.extend_from_slice(&[0u8; 4]); // reserved
            Ok(KIND_LINK_COUNT_SET)
        }
        JournalRecord::Checkpoint { tick } => {
            out.extend_from_slice(&tick.to_le_bytes());
            Ok(KIND_CHECKPOINT)
        }
    }
}

fn encode_acl_change(c: &AclChange, is_grant: bool, out: &mut Vec<u8>) {
    out.extend_from_slice(&c.inode.raw().to_le_bytes());
    out.extend_from_slice(&c.principal);
    out.extend_from_slice(&c.expiry.to_le_bytes());
    let rights_byte = if is_grant {
        c.rights.map(|r| r.bits()).unwrap_or(0)
    } else {
        0
    };
    out.push(rights_byte);
    out.push(if is_grant { 1 } else { 0 });
    out.extend_from_slice(&[0u8; 6]); // reserved
}

/// Decode one journal record from the start of `buf`. Returns the
/// decoded record and the number of bytes consumed (header + payload
/// + checksum). The caller advances its cursor by the returned byte
/// count to read the next record.
///
/// Errors:
/// - `BufferTooShort` — buffer is smaller than the declared record.
/// - `UnknownKind` — kind byte doesn't match any defined variant.
/// - `UnknownVersion` — version byte isn't `RECORD_FORMAT_VERSION`.
/// - `ChecksumMismatch` — Blake3 checksum doesn't match. Callers can
///   distinguish "torn write at journal head" from "corruption" by
///   the surrounding context (replay stops at the first checksum
///   mismatch and treats earlier records as committed).
/// - `MalformedPayload` — payload bytes don't match the variant's
///   expected internal structure.
pub fn decode_record(buf: &[u8]) -> Result<(JournalRecord, usize), JournalError> {
    if buf.len() < RECORD_HEADER_BYTES + RECORD_CHECKSUM_BYTES {
        return Err(JournalError::BufferTooShort);
    }
    let kind = buf[0];
    let version = buf[1];
    if version != RECORD_FORMAT_VERSION {
        return Err(JournalError::UnknownVersion);
    }
    let payload_size = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    let total = RECORD_HEADER_BYTES + payload_size + RECORD_CHECKSUM_BYTES;
    if buf.len() < total {
        return Err(JournalError::BufferTooShort);
    }
    // Validate checksum before interpreting the payload.
    let expected_cs = checksum8(&buf[..RECORD_HEADER_BYTES + payload_size]);
    let on_disk_cs = &buf[RECORD_HEADER_BYTES + payload_size..total];
    if on_disk_cs != expected_cs {
        return Err(JournalError::ChecksumMismatch);
    }
    let payload = &buf[RECORD_HEADER_BYTES..RECORD_HEADER_BYTES + payload_size];
    let rec = decode_payload(kind, payload)?;
    Ok((rec, total))
}

fn decode_payload(kind: u8, payload: &[u8]) -> Result<JournalRecord, JournalError> {
    match kind {
        KIND_INODE_ALLOCATE => {
            if payload.len() != 8 {
                return Err(JournalError::MalformedPayload);
            }
            let inode = InodeId::new(u64::from_le_bytes(payload[0..8].try_into().unwrap()));
            Ok(JournalRecord::InodeAllocate { inode })
        }
        KIND_INODE_FREE => {
            if payload.len() != 8 {
                return Err(JournalError::MalformedPayload);
            }
            let inode = InodeId::new(u64::from_le_bytes(payload[0..8].try_into().unwrap()));
            Ok(JournalRecord::InodeFree { inode })
        }
        KIND_EXTENT_UPDATE => decode_extent_update(payload),
        KIND_DIRECTORY_ENTRY => decode_directory_entry(payload),
        KIND_RENAME => decode_rename(payload),
        KIND_ACL_GRANT => decode_acl_change(payload, true).map(JournalRecord::AclGrant),
        KIND_ACL_REVOKE => decode_acl_change(payload, false).map(JournalRecord::AclRevoke),
        KIND_LINK_COUNT_SET => decode_link_count_set(payload),
        KIND_CHECKPOINT => {
            if payload.len() != 8 {
                return Err(JournalError::MalformedPayload);
            }
            let tick = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            Ok(JournalRecord::Checkpoint { tick })
        }
        _ => Err(JournalError::UnknownKind),
    }
}

fn decode_extent_update(payload: &[u8]) -> Result<JournalRecord, JournalError> {
    if payload.len() < 16 {
        return Err(JournalError::MalformedPayload);
    }
    let inode = InodeId::new(u64::from_le_bytes(payload[0..8].try_into().unwrap()));
    let extent_count = payload[8] as usize;
    let mutation_count = u16::from_le_bytes([payload[9], payload[10]]) as usize;
    // Reserved bytes 11..16 must be zero (canonical form).
    if payload[11..16].iter().any(|&b| b != 0) {
        return Err(JournalError::MalformedPayload);
    }
    if extent_count > MAX_EXTENTS_PER_INODE {
        return Err(JournalError::MalformedPayload);
    }
    if mutation_count > MAX_BITMAP_MUTATIONS_PER_RECORD {
        return Err(JournalError::TooManyMutations);
    }
    let expected_size = 16 + extent_count * 12 + mutation_count * 9;
    if payload.len() != expected_size {
        return Err(JournalError::MalformedPayload);
    }

    let mut new_extents = [None; MAX_EXTENTS_PER_INODE];
    for i in 0..extent_count {
        let base = 16 + i * 12;
        let start_lba = u64::from_le_bytes(payload[base..base + 8].try_into().unwrap());
        let block_count = u32::from_le_bytes(payload[base + 8..base + 12].try_into().unwrap());
        new_extents[i] = Some(cambios_abi::Extent { start_lba, block_count });
    }

    let mut mutations = Vec::with_capacity(mutation_count);
    let mutations_base = 16 + extent_count * 12;
    for i in 0..mutation_count {
        let base = mutations_base + i * 9;
        let block = u64::from_le_bytes(payload[base + 1..base + 9].try_into().unwrap());
        let m = match payload[base] {
            0 => BitmapMutation::Set(block),
            1 => BitmapMutation::Clear(block),
            _ => return Err(JournalError::MalformedPayload),
        };
        mutations.push(m);
    }

    Ok(JournalRecord::ExtentUpdate(ExtentUpdate {
        inode,
        new_extents,
        mutations,
    }))
}

fn decode_directory_entry(payload: &[u8]) -> Result<JournalRecord, JournalError> {
    if payload.len() < 8 {
        return Err(JournalError::MalformedPayload);
    }
    let change_count = payload[0] as usize;
    if payload[1..4].iter().any(|&b| b != 0) {
        return Err(JournalError::MalformedPayload);
    }
    let name_buf_len = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
    if change_count > MAX_DIRENTS_PER_RECORD {
        return Err(JournalError::TooManyDirents);
    }
    let expected_size = 8 + change_count * 32 + name_buf_len;
    if payload.len() != expected_size {
        return Err(JournalError::MalformedPayload);
    }

    let mut changes = Vec::with_capacity(change_count);
    for i in 0..change_count {
        let base = 8 + i * 32;
        let op = match payload[base] {
            DIRENT_OP_INSERT => DirentOp::Insert,
            DIRENT_OP_DELETE => DirentOp::Delete,
            DIRENT_OP_REWRITE => DirentOp::Rewrite,
            _ => return Err(JournalError::MalformedPayload),
        };
        if payload[base + 1..base + 8].iter().any(|&b| b != 0) {
            return Err(JournalError::MalformedPayload);
        }
        let directory =
            InodeId::new(u64::from_le_bytes(payload[base + 8..base + 16].try_into().unwrap()));
        let child =
            InodeId::new(u64::from_le_bytes(payload[base + 16..base + 24].try_into().unwrap()));
        let name_offset = u32::from_le_bytes(payload[base + 24..base + 28].try_into().unwrap());
        let name_len = u16::from_le_bytes(payload[base + 28..base + 30].try_into().unwrap());
        if payload[base + 30..base + 32].iter().any(|&b| b != 0) {
            return Err(JournalError::MalformedPayload);
        }
        changes.push(DirentChange {
            op,
            directory,
            entry: DirentRef {
                child,
                name_offset,
                name_len,
            },
        });
    }
    // Name buffer bytes are accepted as-is. 5C will populate them when
    // the directory write path lands; until then they're zero-length.
    Ok(JournalRecord::DirectoryEntry { changes })
}

fn decode_rename(payload: &[u8]) -> Result<JournalRecord, JournalError> {
    if payload.len() < 56 {
        return Err(JournalError::MalformedPayload);
    }
    let source_dir = InodeId::new(u64::from_le_bytes(payload[0..8].try_into().unwrap()));
    let source_child = InodeId::new(u64::from_le_bytes(payload[8..16].try_into().unwrap()));
    let source_name_offset = u32::from_le_bytes(payload[16..20].try_into().unwrap());
    let source_name_len = u16::from_le_bytes(payload[20..22].try_into().unwrap());
    if payload[22..24].iter().any(|&b| b != 0) {
        return Err(JournalError::MalformedPayload);
    }
    let dest_dir = InodeId::new(u64::from_le_bytes(payload[24..32].try_into().unwrap()));
    let dest_child = InodeId::new(u64::from_le_bytes(payload[32..40].try_into().unwrap()));
    let dest_name_offset = u32::from_le_bytes(payload[40..44].try_into().unwrap());
    let dest_name_len = u16::from_le_bytes(payload[44..46].try_into().unwrap());
    if payload[46..48].iter().any(|&b| b != 0) {
        return Err(JournalError::MalformedPayload);
    }
    let name_buf_len = u32::from_le_bytes(payload[48..52].try_into().unwrap()) as usize;
    if payload[52..56].iter().any(|&b| b != 0) {
        return Err(JournalError::MalformedPayload);
    }
    let expected_size = 56 + name_buf_len;
    if payload.len() != expected_size {
        return Err(JournalError::MalformedPayload);
    }
    Ok(JournalRecord::Rename(RenamePayload {
        source_dir,
        source: DirentRef {
            child: source_child,
            name_offset: source_name_offset,
            name_len: source_name_len,
        },
        dest_dir,
        dest: DirentRef {
            child: dest_child,
            name_offset: dest_name_offset,
            name_len: dest_name_len,
        },
    }))
}

fn decode_acl_change(payload: &[u8], is_grant: bool) -> Result<AclChange, JournalError> {
    if payload.len() != 56 {
        return Err(JournalError::MalformedPayload);
    }
    let inode = InodeId::new(u64::from_le_bytes(payload[0..8].try_into().unwrap()));
    let mut principal = [0u8; 32];
    principal.copy_from_slice(&payload[8..40]);
    let expiry = u64::from_le_bytes(payload[40..48].try_into().unwrap());
    let rights_byte = payload[48];
    let rights_present = payload[49];
    if payload[50..56].iter().any(|&b| b != 0) {
        return Err(JournalError::MalformedPayload);
    }
    let rights = match (is_grant, rights_present) {
        (true, 1) => Some(Rights::from_bits(rights_byte)),
        (false, 0) => {
            if rights_byte != 0 {
                return Err(JournalError::MalformedPayload);
            }
            None
        }
        _ => return Err(JournalError::MalformedPayload),
    };
    Ok(AclChange {
        inode,
        principal,
        rights,
        expiry,
    })
}

fn decode_link_count_set(payload: &[u8]) -> Result<JournalRecord, JournalError> {
    if payload.len() != 16 {
        return Err(JournalError::MalformedPayload);
    }
    let inode = InodeId::new(u64::from_le_bytes(payload[0..8].try_into().unwrap()));
    let new_value = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    if payload[12..16].iter().any(|&b| b != 0) {
        return Err(JournalError::MalformedPayload);
    }
    Ok(JournalRecord::LinkCountSet(LinkCountSet { inode, new_value }))
}

// ============================================================================
// Linear cursor over a byte slice
// ============================================================================

/// Iterator-style reader over a contiguous byte slice of journal
/// records. Yields `(JournalRecord, byte_offset_after)` pairs in
/// sequence, stopping at the first decode error (which for replay
/// purposes typically means "torn write at journal head — earlier
/// records are committed, later bytes are not interpretable").
///
/// This cursor does NOT handle wrap-around; the circular-log
/// wrapper that detects journal-end and re-cursors from offset 0
/// lands in step 5C alongside the kernel-side `Journal` struct.
pub struct JournalRecordCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    stopped: bool,
}

impl<'a> JournalRecordCursor<'a> {
    /// Construct a cursor that starts reading from `start_offset`
    /// within `bytes`.
    pub fn new(bytes: &'a [u8], start_offset: usize) -> Self {
        Self {
            bytes,
            offset: start_offset,
            stopped: false,
        }
    }

    /// Current byte offset within the slice. After the cursor stops,
    /// this is the offset of the first unconsumed byte.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl Iterator for JournalRecordCursor<'_> {
    type Item = Result<JournalRecord, JournalError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped || self.offset >= self.bytes.len() {
            return None;
        }
        let remaining = &self.bytes[self.offset..];
        // A leading zero byte means we've reached blank journal space
        // (kind discriminant 0 is reserved). Stop without erroring.
        if remaining[0] == 0 {
            self.stopped = true;
            return None;
        }
        match decode_record(remaining) {
            Ok((rec, consumed)) => {
                self.offset += consumed;
                Some(Ok(rec))
            }
            Err(e) => {
                self.stopped = true;
                Some(Err(e))
            }
        }
    }
}

/// Replay all records starting at `start_offset` in `bytes`, calling
/// `callback` for each. Returns the byte offset where iteration
/// stopped — i.e., the offset of the first un-applied byte (either
/// blank space, a torn write, or the end of the buffer).
///
/// `callback` receives each record by reference; the closure's
/// return value (`Result<(), E>`) bubbles up. A returned `Err` halts
/// replay; the offset returned in that case is the start of the
/// failing record so the caller can inspect.
///
/// Decoded-but-malformed records ARE surfaced as
/// `Err(JournalError::...)` — the caller decides whether to stop or
/// continue. Step 5C's mount path stops at the first decode error
/// (torn write at head); other callers may choose differently.
pub fn replay_records<F>(
    bytes: &[u8],
    start_offset: usize,
    mut callback: F,
) -> Result<usize, JournalError>
where
    F: FnMut(&JournalRecord) -> Result<(), JournalError>,
{
    let mut cursor = JournalRecordCursor::new(bytes, start_offset);
    let mut last_committed = start_offset;
    while let Some(item) = cursor.next() {
        let rec = item?;
        callback(&rec)?;
        last_committed = cursor.offset();
    }
    Ok(last_committed)
}
