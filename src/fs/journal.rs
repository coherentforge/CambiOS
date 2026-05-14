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

/// Typed error surface for journal-record construction and (in
/// step 5B) encoding / decoding / replay. Variants are added as
/// the journal grows; step 5A only needs the construction-side
/// errors.
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
}
