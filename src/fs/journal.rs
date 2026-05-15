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
    /// Wrap-around padding emitted by the circular-log writer when a
    /// record would not fit before the journal-region end (per
    /// ADR-029 § Decision 5 wrap semantics, implemented in step 5C).
    /// `total_bytes` is the pad's complete on-disk byte length
    /// (`RECORD_HEADER_BYTES + payload + RECORD_CHECKSUM_BYTES`) and
    /// equals the byte distance from the pad's start offset to the
    /// journal region end.
    ///
    /// Pads carry no semantic state; replay treats them as a
    /// "wrap to offset 0" signal (see
    /// [`Journal::replay_from_checkpoint`]). The payload bytes are
    /// strict-canonical zero per ADR-029 § Divergence 1.
    Pad { total_bytes: u32 },
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

    // ========================================================================
    // KIND_PAD codec (commit 5C-i)
    // ========================================================================

    #[test]
    fn roundtrip_pad_minimum_size() {
        // Smallest possible pad: header + zero-byte payload + checksum.
        let rec = JournalRecord::Pad {
            total_bytes: (super::RECORD_HEADER_BYTES + super::RECORD_CHECKSUM_BYTES) as u32,
        };
        let encoded = super::encode_record(&rec).unwrap();
        assert_eq!(encoded.len(), super::RECORD_HEADER_BYTES + super::RECORD_CHECKSUM_BYTES);
        let (decoded, consumed) = super::decode_record(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, rec);
    }

    #[test]
    fn roundtrip_pad_typical_size() {
        // ~500-byte pad — representative of the gap left when an
        // ExtentUpdate-sized record won't fit before region end.
        let rec = JournalRecord::Pad { total_bytes: 500 };
        let encoded = super::encode_record(&rec).unwrap();
        assert_eq!(encoded.len(), 500);
        let (decoded, _) = super::decode_record(&encoded).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn decode_pad_rejects_nonzero_payload() {
        let rec = JournalRecord::Pad { total_bytes: 50 };
        let mut encoded = super::encode_record(&rec).unwrap();
        // Poke a non-zero byte into the payload (strict canonical
        // form violation).
        encoded[super::RECORD_HEADER_BYTES + 10] = 0x42;
        let cs = super::checksum8(&encoded[..encoded.len() - 8]);
        let end = encoded.len();
        encoded[end - 8..].copy_from_slice(&cs);
        let result = super::decode_record(&encoded);
        assert_eq!(result, Err(JournalError::MalformedPayload));
    }

    #[test]
    fn encode_pad_rejects_below_minimum() {
        let rec = JournalRecord::Pad {
            total_bytes: (super::RECORD_HEADER_BYTES + super::RECORD_CHECKSUM_BYTES - 1) as u32,
        };
        let result = super::encode_record(&rec);
        assert_eq!(result, Err(JournalError::MalformedPayload));
    }

    // ========================================================================
    // Journal struct: append + wrap-around (commit 5C-i)
    // ========================================================================

    /// Journal region large enough for several typical-sized records.
    const SMALL_REGION_BYTES: u64 = 256;

    fn small_journal() -> super::Journal {
        super::Journal::new(SMALL_REGION_BYTES).unwrap()
    }

    #[test]
    fn journal_new_fresh_state() {
        let j = small_journal();
        assert_eq!(j.region_bytes(), SMALL_REGION_BYTES);
        assert_eq!(j.head_offset(), 0);
        assert_eq!(j.last_checkpoint_offset(), 0);
    }

    #[test]
    fn journal_new_rejects_tiny_region() {
        let result = super::Journal::new(1);
        assert_eq!(result, Err(JournalError::PayloadTooLarge));
    }

    #[test]
    fn journal_append_no_wrap_advances_head() {
        let mut j = small_journal();
        let rec = JournalRecord::InodeAllocate { inode: InodeId::new(7) };
        let encoded = super::encode_record(&rec).unwrap();
        let len = encoded.len() as u64;

        let result = j.append(&encoded).unwrap();
        assert_eq!(result.pad_at, None);
        assert_eq!(result.real_at, 0);
        assert_eq!(j.head_offset(), len);

        // Second append continues from head.
        let result2 = j.append(&encoded).unwrap();
        assert_eq!(result2.pad_at, None);
        assert_eq!(result2.real_at, len);
        assert_eq!(j.head_offset(), 2 * len);
    }

    #[test]
    fn journal_append_rejects_oversized_record() {
        let mut j = super::Journal::new(40).unwrap();
        // A 100-byte fake "record" can't fit in a 40-byte region.
        let fake = alloc::vec![0x01u8; 100]; // kind=0x01 (InodeAllocate)
        let result = j.append(&fake);
        assert_eq!(result, Err(JournalError::PayloadTooLarge));
    }

    #[test]
    fn journal_append_rejects_pad_input() {
        let mut j = small_journal();
        let pad_bytes = super::encode_record(&JournalRecord::Pad { total_bytes: 20 }).unwrap();
        let result = j.append(&pad_bytes);
        assert_eq!(result, Err(JournalError::MalformedPayload));
    }

    #[test]
    fn journal_append_rejects_empty_record() {
        let mut j = small_journal();
        let result = j.append(&[]);
        assert_eq!(result, Err(JournalError::MalformedPayload));
    }

    #[test]
    fn journal_append_wraps_when_record_does_not_fit() {
        // Construct a journal sized so the second InodeAllocate
        // record would overflow if no wrap occurred.
        let rec = JournalRecord::InodeAllocate { inode: InodeId::new(1) };
        let encoded = super::encode_record(&rec).unwrap();
        let len = encoded.len() as u64;
        // Region holds exactly one record plus a sub-minimum gap,
        // forcing the second append to wrap.
        let region = len + (super::RECORD_HEADER_BYTES + super::RECORD_CHECKSUM_BYTES) as u64;
        let mut j = super::Journal::new(region).unwrap();

        // First append: fits at offset 0.
        let r1 = j.append(&encoded).unwrap();
        assert_eq!(r1.pad_at, None);
        assert_eq!(r1.real_at, 0);
        let head_after_first = j.head_offset();
        assert_eq!(head_after_first, len);

        // Second append: wraps. Pad covers [head_after_first, region),
        // real lands at offset 0.
        let r2 = j.append(&encoded).unwrap();
        let (pad_at, pad_bytes) = r2.pad_at.expect("expected wrap");
        assert_eq!(pad_at, head_after_first);
        assert_eq!(pad_bytes.len() as u64, region - head_after_first);
        assert_eq!(r2.real_at, 0);
        assert_eq!(j.head_offset(), len);

        // Verify the emitted pad decodes as KIND_PAD with canonical form.
        let (pad_rec, _) = super::decode_record(&pad_bytes).unwrap();
        match pad_rec {
            JournalRecord::Pad { total_bytes } => {
                assert_eq!(total_bytes as u64, region - head_after_first);
            }
            _ => panic!("expected Pad, got {:?}", pad_rec),
        }
    }

    #[test]
    fn journal_append_wraps_when_remaining_below_min_pad() {
        // After the first record, remaining = region - len. To force
        // the second append to wrap via the "sub-pad gap" rule (not
        // because the record overflows), arrange:
        //   record_len <= remaining
        //   remaining - record_len < min_pad
        // i.e., remaining ∈ [record_len, record_len + min_pad).
        let rec = JournalRecord::InodeAllocate { inode: InodeId::new(1) };
        let encoded = super::encode_record(&rec).unwrap();
        let len = encoded.len() as u64;
        let min_pad = (super::RECORD_HEADER_BYTES + super::RECORD_CHECKSUM_BYTES) as u64;
        // After append 1, head = len. Pick region so remaining is in
        // [len, len + min_pad): region - len = len + 5, i.e.
        // region = 2*len + 5. Sub-pad gap = 5 < min_pad.
        let region = 2 * len + 5;
        let mut j = super::Journal::new(region).unwrap();

        let r1 = j.append(&encoded).unwrap();
        assert_eq!(r1.pad_at, None);
        assert_eq!(j.head_offset(), len);

        // Second append: would fit arithmetically (remaining = len + 5
        // >= len = record_len) but leaves a sub-pad gap of 5 bytes, so
        // the wrap rule fires.
        let r2 = j.append(&encoded).unwrap();
        assert!(r2.pad_at.is_some(), "expected sub-pad-gap wrap");
        let (pad_at, pad_bytes) = r2.pad_at.as_ref().unwrap();
        assert_eq!(*pad_at, len);
        assert_eq!(pad_bytes.len() as u64, region - len);
        assert_eq!(r2.real_at, 0);
    }

    // ========================================================================
    // Journal::replay_from_checkpoint (commit 5C-i)
    // ========================================================================

    /// Simulate disk by tracking the bytes the caller would have
    /// written. Returns a `Vec<u8>` of size `region_bytes` populated
    /// from a sequence of records appended via `Journal::append`.
    fn simulate_writes(j: &mut super::Journal, records: &[JournalRecord]) -> alloc::vec::Vec<u8> {
        let mut disk = alloc::vec![0u8; j.region_bytes() as usize];
        for r in records {
            let encoded = super::encode_record(r).unwrap();
            let app = j.append(&encoded).unwrap();
            if let Some((pad_at, pad_bytes)) = app.pad_at {
                let start = pad_at as usize;
                disk[start..start + pad_bytes.len()].copy_from_slice(&pad_bytes);
            }
            let start = app.real_at as usize;
            disk[start..start + encoded.len()].copy_from_slice(&encoded);
        }
        disk
    }

    #[test]
    fn replay_from_checkpoint_no_wrap() {
        let records = alloc::vec![
            JournalRecord::InodeAllocate { inode: InodeId::new(1) },
            JournalRecord::InodeAllocate { inode: InodeId::new(2) },
            JournalRecord::Checkpoint { tick: 10 },
            JournalRecord::InodeFree { inode: InodeId::new(1) },
        ];
        let mut writer = small_journal();
        let disk = simulate_writes(&mut writer, &records);
        let writer_head = writer.head_offset();

        let mut replayer = small_journal();
        let mut seen = alloc::vec::Vec::new();
        replayer
            .replay_from_checkpoint(&disk, |r| {
                seen.push(r.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, records);
        assert_eq!(replayer.head_offset(), writer_head);
    }

    #[test]
    fn replay_from_checkpoint_starts_after_checkpoint() {
        let pre_cp = alloc::vec![
            JournalRecord::InodeAllocate { inode: InodeId::new(1) },
            JournalRecord::InodeAllocate { inode: InodeId::new(2) },
        ];
        let post_cp = alloc::vec![
            JournalRecord::InodeFree { inode: InodeId::new(1) },
            JournalRecord::InodeAllocate { inode: InodeId::new(3) },
        ];

        // Build the journal: pre_cp records, then Checkpoint, then
        // post_cp records. Note the checkpoint's byte offset.
        let mut writer = small_journal();
        let mut disk = alloc::vec![0u8; writer.region_bytes() as usize];
        let mut write = |w: &mut super::Journal, d: &mut [u8], r: &JournalRecord| {
            let encoded = super::encode_record(r).unwrap();
            let app = w.append(&encoded).unwrap();
            if let Some((pad_at, pad_bytes)) = app.pad_at {
                d[pad_at as usize..pad_at as usize + pad_bytes.len()]
                    .copy_from_slice(&pad_bytes);
            }
            d[app.real_at as usize..app.real_at as usize + encoded.len()]
                .copy_from_slice(&encoded);
        };
        for r in &pre_cp {
            write(&mut writer, &mut disk, r);
        }
        // Capture the checkpoint's byte position: it's the head right
        // before we append the checkpoint record. Set the replayer's
        // last_checkpoint_offset to the offset AFTER the checkpoint
        // record, so post-checkpoint replay starts there.
        write(&mut writer, &mut disk, &JournalRecord::Checkpoint { tick: 100 });
        let cp_end = writer.head_offset();
        for r in &post_cp {
            write(&mut writer, &mut disk, r);
        }

        // Replay starting from cp_end: should see only post_cp records.
        let mut replayer = super::Journal::from_disk_state(
            SMALL_REGION_BYTES,
            cp_end,
            0, // head will be overwritten by replay
        )
        .unwrap();
        let mut seen = alloc::vec::Vec::new();
        replayer
            .replay_from_checkpoint(&disk, |r| {
                seen.push(r.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, post_cp);
        assert_eq!(replayer.head_offset(), writer.head_offset());
    }

    #[test]
    fn replay_from_checkpoint_handles_wrap() {
        // Single-wrap scenario with checkpoint > 0 (the realistic
        // case — bound by the ADR-029 § Decision 5 checkpoint
        // cadence). Pre-wrap byte order on disk after the writes:
        //   [post-cp records overwriting pre-cp][Cp][post-cp records][Pad]
        //
        // Replay from cp_end (offset after the Checkpoint record)
        // walks pre-wrap [cp_end..end-of-region] → hits Pad → wraps
        // to 0 → walks [0..cp_end] → wrap-stop at cp_end. Callback
        // sees the post-cp records in byte order, plus the Cp marker
        // (idempotent re-application per ADR-029 § Verification
        // Stance row 3).
        let inode = |id: u64| JournalRecord::InodeAllocate { inode: InodeId::new(id) };
        let encoded_len = super::encode_record(&inode(1)).unwrap().len() as u64;
        let min_pad = (super::RECORD_HEADER_BYTES + super::RECORD_CHECKSUM_BYTES) as u64;
        // Region sized so:
        //   appends A(20), Cp(20), B(20) all fit cleanly (head=60).
        //   append C(20) wraps because remaining=12 < record_len=20.
        // The wrap thus occurs AFTER cp_end is captured (cp_end=40).
        // region = 3*encoded_len + min_pad = 72.
        let region = 3 * encoded_len + min_pad;

        let mut writer = super::Journal::new(region).unwrap();
        let mut disk = alloc::vec![0u8; region as usize];
        let mut commit = |w: &mut super::Journal, d: &mut [u8], r: &JournalRecord| {
            let encoded = super::encode_record(r).unwrap();
            let app = w.append(&encoded).unwrap();
            if let Some((pad_at, pad_bytes)) = app.pad_at {
                d[pad_at as usize..pad_at as usize + pad_bytes.len()]
                    .copy_from_slice(&pad_bytes);
            }
            d[app.real_at as usize..app.real_at as usize + encoded.len()]
                .copy_from_slice(&encoded);
        };

        // Pre-checkpoint write: record A.
        commit(&mut writer, &mut disk, &inode(1)); // A
        commit(&mut writer, &mut disk, &JournalRecord::Checkpoint { tick: 100 });
        let cp_end = writer.head_offset();
        // Post-checkpoint writes: B fits, C wraps and overwrites A.
        commit(&mut writer, &mut disk, &inode(2)); // B
        commit(&mut writer, &mut disk, &inode(3)); // C (wraps)
        // Wrap must have occurred for this test to exercise the wrap path.
        assert!(writer.head_offset() < cp_end, "test setup must force a wrap");

        let mut replayer = super::Journal::from_disk_state(region, cp_end, 0).unwrap();
        let mut seen = alloc::vec::Vec::new();
        replayer
            .replay_from_checkpoint(&disk, |r| {
                seen.push(r.clone());
                Ok(())
            })
            .unwrap();
        // Expected callback order:
        //   pre-wrap [cp_end..end-of-region]: B
        //   post-wrap [0..cp_end]: C (overwrote A at offset 0), Cp marker
        let expected = alloc::vec![
            inode(2), // B
            inode(3), // C
            JournalRecord::Checkpoint { tick: 100 }, // Cp re-applied (idempotent)
        ];
        assert_eq!(seen, expected);
    }

    #[test]
    fn replay_from_checkpoint_rejects_wrong_region_size() {
        let mut j = small_journal();
        let disk = alloc::vec![0u8; (SMALL_REGION_BYTES + 1) as usize];
        let result = j.replay_from_checkpoint(&disk, |_| Ok(()));
        assert_eq!(result, Err(JournalError::MalformedPayload));
    }

    #[test]
    fn replay_from_checkpoint_propagates_callback_error() {
        let mut writer = small_journal();
        let disk = simulate_writes(
            &mut writer,
            &[JournalRecord::InodeAllocate { inode: InodeId::new(1) }],
        );
        let mut replayer = small_journal();
        let result = replayer.replay_from_checkpoint(&disk, |_| {
            Err(JournalError::MalformedPayload)
        });
        assert_eq!(result, Err(JournalError::MalformedPayload));
    }

    #[test]
    fn note_checkpoint_advances_replay_origin() {
        let mut j = small_journal();
        let rec = JournalRecord::InodeAllocate { inode: InodeId::new(1) };
        let encoded = super::encode_record(&rec).unwrap();
        j.append(&encoded).unwrap();
        let head = j.head_offset();
        j.note_checkpoint();
        assert_eq!(j.last_checkpoint_offset(), head);
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
        JournalRecord::Pad { total_bytes } => {
            let total = *total_bytes as usize;
            if total < RECORD_HEADER_BYTES + RECORD_CHECKSUM_BYTES {
                return Err(JournalError::MalformedPayload);
            }
            let payload_size = total - RECORD_HEADER_BYTES - RECORD_CHECKSUM_BYTES;
            if payload_size > u16::MAX as usize {
                return Err(JournalError::PayloadTooLarge);
            }
            // Pad payload is `payload_size` zero bytes; strict-canonical
            // form on decode requires this (ADR-029 § Divergence 1).
            out.resize(out.len() + payload_size, 0);
            Ok(KIND_PAD)
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
        KIND_PAD => {
            // Strict canonical form: pad payload must be all-zero
            // (ADR-029 § Divergence 1). The total byte length of the
            // pad on disk equals header + payload + checksum.
            if payload.iter().any(|&b| b != 0) {
                return Err(JournalError::MalformedPayload);
            }
            let total_bytes =
                (RECORD_HEADER_BYTES + payload.len() + RECORD_CHECKSUM_BYTES) as u32;
            Ok(JournalRecord::Pad { total_bytes })
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

// ============================================================================
// Circular-log journal (step 5C)
// ============================================================================
//
// The pure-function codec above describes a single record. The
// `Journal` struct below is the circular-log writer: it owns the
// region geometry (`region_bytes`, `head_offset`, `last_checkpoint_offset`)
// and emits the byte-stream layout for the caller to write to disk.
//
// `Journal` does NOT perform device I/O. It returns an `Append`
// describing what bytes to write where; the caller (e.g.,
// `PosixFsBackend`) does the block-level writes and the
// post-write flush. This keeps the journal layer host-testable
// against an in-memory byte buffer and confines kernel-side I/O
// to the backend wrapper (ADR-029 § Verification Stance).
//
// Wrap semantics per ADR-029 § Decision 5: when a record would not
// fit before the journal-region end, `append` emits a `KIND_PAD`
// record covering the tail and reports `real_at = 0` for the
// caller to write the real record at the region start. The pad's
// payload is strict-canonical zero per ADR-029 § Divergence 1.

/// Locations the caller must write to commit an `append`. The
/// caller writes `pad_at` first (if present), then `real_at`. The
/// `Journal` struct has already advanced `head_offset` to the
/// post-write position; the caller MUST perform both writes before
/// the next `append` or `head_offset` will not match on-disk state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Append {
    /// `Some((byte_offset, pad_bytes))` when the record would not
    /// fit before the journal-region end. The pad is a full
    /// `KIND_PAD` record covering `[byte_offset, region_bytes)`.
    pub pad_at: Option<(u64, Vec<u8>)>,
    /// Byte offset where the caller writes the real record. Equals
    /// `0` after a wrap, otherwise the pre-call `head_offset`.
    pub real_at: u64,
}

/// Circular-log journal writer. Owns the region geometry and head
/// position; does not own disk I/O.
///
/// Constructed at mount time via [`Journal::new`] (fresh format)
/// or [`Journal::from_disk_state`] (post-replay). The
/// [`Journal::replay_from_checkpoint`] helper reconstructs the
/// in-memory `head_offset` from on-disk records before the
/// backend completes mount.
///
/// Owned by the kernel-instance behind `JOURNAL_LOCK` at lock-
/// hierarchy position 13 (per ADR-029 § Divergence 2, landing in
/// step 5C). This module exposes the unsynchronized struct; the
/// lock wrapper is one level up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    /// Total bytes in the journal region. Constant after construction;
    /// matches the superblock's `journal_capacity_bytes`.
    region_bytes: u64,
    /// Byte offset of the next-write position within the region.
    /// `0 <= head_offset < region_bytes`. Maintained such that
    /// `region_bytes - head_offset` is either 0 (head snapped to
    /// region end, next append wraps) or `>= RECORD_HEADER_BYTES +
    /// RECORD_CHECKSUM_BYTES` (room for at least a minimum pad).
    head_offset: u64,
    /// Byte offset of the most-recent committed checkpoint. Replay
    /// starts here on mount. Equal to `0` for a freshly-formatted
    /// journal.
    last_checkpoint_offset: u64,
}

/// ARCHITECTURAL: minimum on-disk size of any journal record.
/// Mechanically equals `RECORD_HEADER_BYTES + RECORD_CHECKSUM_BYTES`;
/// derived from two ARCHITECTURAL constants and inherits their
/// invariance. Centralizes the bound for the sub-pad-gap rule in
/// `Journal::append` so every successful append leaves room for at
/// least a minimum pad on the subsequent wrap.
const MIN_RECORD_BYTES: u64 = (RECORD_HEADER_BYTES + RECORD_CHECKSUM_BYTES) as u64;

impl Journal {
    /// Construct a fresh journal for a region of `region_bytes`
    /// bytes. Head and checkpoint both start at offset 0.
    /// `region_bytes` must be at least `MIN_RECORD_BYTES`; smaller
    /// regions cannot fit any record.
    pub fn new(region_bytes: u64) -> Result<Self, JournalError> {
        if region_bytes < MIN_RECORD_BYTES {
            return Err(JournalError::PayloadTooLarge);
        }
        Ok(Self {
            region_bytes,
            head_offset: 0,
            last_checkpoint_offset: 0,
        })
    }

    /// Construct a journal from on-disk state. The superblock's
    /// `last_checkpoint_offset` is the source of `cp_offset`;
    /// `head_offset` is the position the replay loop stopped at
    /// (returned by [`Journal::replay_from_checkpoint`]).
    pub fn from_disk_state(
        region_bytes: u64,
        last_checkpoint_offset: u64,
        head_offset: u64,
    ) -> Result<Self, JournalError> {
        if region_bytes < MIN_RECORD_BYTES {
            return Err(JournalError::PayloadTooLarge);
        }
        if head_offset >= region_bytes || last_checkpoint_offset >= region_bytes {
            return Err(JournalError::MalformedPayload);
        }
        Ok(Self {
            region_bytes,
            head_offset,
            last_checkpoint_offset,
        })
    }

    /// Total bytes in the journal region.
    pub fn region_bytes(&self) -> u64 {
        self.region_bytes
    }

    /// Current head byte offset (next-write position).
    pub fn head_offset(&self) -> u64 {
        self.head_offset
    }

    /// Most-recent committed checkpoint byte offset.
    pub fn last_checkpoint_offset(&self) -> u64 {
        self.last_checkpoint_offset
    }

    /// Append the pre-encoded `record_bytes` to the journal. Returns
    /// an [`Append`] describing the byte locations the caller must
    /// write. Updates `head_offset` to the post-write position; the
    /// caller MUST perform the indicated writes before the next
    /// `append` call.
    ///
    /// Wrap behavior: when the record would not fit before the
    /// region end, a `KIND_PAD` record covering the entire tail is
    /// emitted as `pad_at`, and `real_at` is `0`. The caller writes
    /// the pad first, then the real record, then flushes.
    ///
    /// Errors:
    /// - `MalformedPayload`: `record_bytes` is empty or is itself a
    ///   `KIND_PAD` record (pads are emitted internally only).
    /// - `PayloadTooLarge`: record exceeds the region size.
    pub fn append(&mut self, record_bytes: &[u8]) -> Result<Append, JournalError> {
        if record_bytes.is_empty() {
            return Err(JournalError::MalformedPayload);
        }
        if record_bytes[0] == KIND_PAD {
            return Err(JournalError::MalformedPayload);
        }
        let record_len = record_bytes.len() as u64;
        if record_len > self.region_bytes {
            return Err(JournalError::PayloadTooLarge);
        }
        let remaining = self.region_bytes - self.head_offset;
        // Fit without wrap iff the record fits AND either exactly
        // fills the remainder or leaves at least a minimum-pad-sized
        // gap. The latter ensures the next wrap can emit a pad.
        let fits_without_wrap = record_len <= remaining
            && (record_len == remaining || remaining - record_len >= MIN_RECORD_BYTES);

        if !fits_without_wrap {
            // Wrap: emit pad covering [head, region_end), write real
            // record at offset 0.
            let pad_record = encode_record(&JournalRecord::Pad {
                total_bytes: remaining
                    .try_into()
                    .map_err(|_| JournalError::PayloadTooLarge)?,
            })?;
            debug_assert_eq!(pad_record.len() as u64, remaining);
            let pad_at = self.head_offset;
            self.head_offset = record_len;
            if self.head_offset == self.region_bytes {
                self.head_offset = 0;
            }
            return Ok(Append {
                pad_at: Some((pad_at, pad_record)),
                real_at: 0,
            });
        }
        let real_at = self.head_offset;
        self.head_offset += record_len;
        if self.head_offset == self.region_bytes {
            self.head_offset = 0;
        }
        Ok(Append { pad_at: None, real_at })
    }

    /// Advance `last_checkpoint_offset` to the current head. The
    /// caller is responsible for having durably written a
    /// `Checkpoint` record at the old head before invoking this
    /// (ADR-029 § Decision 5 ordering: append the checkpoint, then
    /// update the superblock).
    pub fn note_checkpoint(&mut self) {
        self.last_checkpoint_offset = self.head_offset;
    }

    /// Replay the journal records starting from
    /// `last_checkpoint_offset`, calling `callback` for each
    /// non-pad record. Handles a single wrap-around: when a
    /// `JournalRecord::Pad` is encountered, replay re-cursors from
    /// offset 0 and continues. After the second cursor stops
    /// (blank region or torn write), `head_offset` is set to that
    /// position.
    ///
    /// Per the ADR-029 § Verification Stance row 4 ("bitmap state
    /// is the projection of committed journal records"), this is
    /// the source of truth for reconstructing post-checkpoint
    /// in-memory state at mount.
    ///
    /// Errors propagate from the callback or from the cursor's
    /// decode path. A `ChecksumMismatch` or `BufferTooShort` from
    /// the cursor is surfaced as `Err`; callers that want to treat
    /// torn writes as "stop here, no error" should match on the
    /// returned error.
    ///
    /// Multi-wrap recovery (two pads in a single replay) is not
    /// supported in v1 — replay stops at the second pad.
    /// Revisit when: a production workload's metadata-churn rate
    /// approaches the journal-wrap cadence between mounts.
    ///
    /// Wrap-stop semantics: when the post-wrap cursor reaches
    /// `last_checkpoint_offset`, replay stops. This prevents
    /// re-applying pre-checkpoint stale records that the post-wrap
    /// writes did not fully overwrite (the bytes at
    /// `[head_offset..last_checkpoint_offset]` are stale-pre-wrap
    /// records left over from the previous revolution). For
    /// `last_checkpoint_offset == 0` the wrap-stop is suppressed —
    /// the journal is "all post-checkpoint" by definition, and the
    /// "second pad = stop" rule alone bounds iteration.
    pub fn replay_from_checkpoint<F>(
        &mut self,
        region_bytes: &[u8],
        mut callback: F,
    ) -> Result<(), JournalError>
    where
        F: FnMut(&JournalRecord) -> Result<(), JournalError>,
    {
        if region_bytes.len() as u64 != self.region_bytes {
            return Err(JournalError::MalformedPayload);
        }
        let start = self.last_checkpoint_offset as usize;
        let mut cursor = JournalRecordCursor::new(region_bytes, start);
        let mut wrapped = false;

        loop {
            // Wrap-stop: post-wrap cursor must not walk back into
            // pre-checkpoint territory. Suppressed when cp == 0
            // (no pre-checkpoint region exists).
            if wrapped
                && self.last_checkpoint_offset != 0
                && cursor.offset() as u64 >= self.last_checkpoint_offset
            {
                break;
            }
            match cursor.next() {
                None => break,
                Some(Err(e)) => return Err(e),
                Some(Ok(JournalRecord::Pad { .. })) => {
                    if wrapped {
                        // Second pad in a single replay = multi-wrap;
                        // v1 stops here (see method doc).
                        break;
                    }
                    wrapped = true;
                    cursor = JournalRecordCursor::new(region_bytes, 0);
                }
                Some(Ok(rec)) => {
                    callback(&rec)?;
                }
            }
        }
        self.head_offset = cursor.offset() as u64;
        if self.head_offset == self.region_bytes {
            self.head_offset = 0;
        }
        Ok(())
    }
}
