# ADR-029: POSIX File Storage Model

- **Status:** Proposed
- **Date:** 2026-05-12
- **Depends on:** [ADR-028](028-three-storage-models.md) (Three Storage Models - the kernel-API discipline this ADR provides the POSIX backend for), [ADR-010](010-persistent-object-store-on-disk-format.md) (CambiObject on-disk format - the template this ADR's format mirrors, and which adopts the shared extent allocator via a Divergence appendix), [storage-planning.md](../storage-planning.md) (the synthesis)
- **Related:** [ADR-003](003-content-addressed-storage-and-identity.md) (CambiObject + ObjectStore - the peer backend), [ADR-005](005-ipc-primitives-control-and-bulk.md) (channels - posix-fs-service uses control IPC like fs-service), [ADR-016](016-win-compat-api-ai-boundary.md) (Win32 layer - primary downstream consumer), [ADR-018](018-init-process-and-boot-manifest.md) (boot manifest - system-global REGALO aliases land here), [ADR-027](027-service-clusters.md) (clusters scope POSIX-file namespaces alongside CambiObjects; multi-Principal access routes through cluster delegation rather than wide inline ACL)
- **Supersedes:** N/A
- **Context:** [ADR-028](028-three-storage-models.md) committed to three co-equal storage models and three seam syscalls but deferred the POSIX backend's on-disk format, recovery model, ACL semantics, atomic-rename mechanics, syscall surface, MAX_REGALO_PER_PROCESS sizing, and per-inode CoW strategy to this ADR. The CambiObject backend ([ADR-003](003-content-addressed-storage-and-identity.md) + [ADR-010](010-persistent-object-store-on-disk-format.md)) already specifies how a content-addressed signed-object store is built; this ADR specifies how a mutable path-keyed file store is built alongside it. Where the two backends touch (shared block-allocation bitmap, CAMBIO transactions, REGALO alias table), this ADR is the source of truth and ADR-010 will gain a Divergence appendix adopting the extent allocator.

## Problem

ADR-028 named the model and the kernel-API contract; this ADR has to deliver the storage substrate. Four gaps motivate the design, all of which fall out of "what does mutable byte-at-a-path mean at the kernel layer in CambiOS."

### Gap 1 - No mutable backend exists; everything currently goes through ObjectStore

`src/fs/` today holds `block.rs`, `disk.rs`, `lazy_disk.rs`, `mod.rs`, `ram.rs`, `virtio_blk_device.rs` - all of it implements the content-addressed `ObjectStore` trait. There is no `file_open` syscall, no inode concept, no path resolver beyond the per-fs-service path-to-hash index. ADR-028's `FileDescriptor` returns no bytes until this ADR specifies what backs it.

### Gap 2 - CAMBIO's snapshot-consistency claim has no implementation

ADR-028's threat-model row 3 says "CAMBIO obtains a snapshot-consistent view of the source at open time (per-inode COW per ADR-029); the bytes hashed are the bytes as of CAMBIO open. Concurrent writes during the seal go to new blocks via COW." That claim is load-bearing - it replaces the unworkable "global backend lock for 2.3 hours during a 4 TiB seal." But ADR-028 deferred the COW strategy itself. This ADR specifies the per-inode CoW mechanism that makes the snapshot-consistency claim true: refcounted extents, frozen-view handles, write-redirect semantics.

### Gap 3 - POSIX permissions do not map to Principal identity

POSIX inherits Unix u/g/o. CambiOS identity is Principal-keyed (32-byte AID per ADR-025). The two models do not compose - a "uid=1001" has no meaning when every process is identified by a 32-byte AID and capabilities are granted Principal-to-Principal. Forcing u/g/o into the POSIX backend forces a kernel-side UID-to-Principal translation table, which is exactly the kind of opaque cross-domain mapping the CambiOS threat model avoids (every binding becomes a thing that can be wrong, stale, or forged, and the kernel becomes a translation authority for an identity scheme it doesn't natively understand). Drop u/g/o; carry Principal-keyed ACL on every inode; translate at the legacy-shim boundary.

### Gap 4 - Recovery model has to handle concurrent writers + mutability + crash

ADR-010 chose no-journal-with-header-magic-commit for CambiObjects because objects are write-once. Mutable files can't use the same shape: a partial write leaves the inode in some intermediate state that header-magic alone can't disambiguate. The recovery story for POSIX backend has to handle: crash mid-write (data partially written, metadata not yet committed), crash mid-metadata-update (extent list change pending), crash during rename (one inode pointing at two paths or zero paths). Three plausible shapes (full journal, full CoW, hybrid); this ADR picks one.

## The Reframe

> The POSIX backend is a path-keyed mutable storage model with its own on-disk format, its own Principal-keyed ACL, and its own recovery story. It is a peer to the ObjectStore, not an extension. CAMBIO and REGALO are the only seams between the two; everything else is POSIX-native. The backend supports inodes (so POSIX hard links and atomic rename work as users expect), contiguous extents (≤16 per inode, shared block-allocation bitmap with the CambiObject backend via an ADR-010 Divergence), and per-inode copy-on-write (so CAMBIO snapshot-consistency holds without a global lock). The recovery model is hybrid: a metadata journal covers all changes that affect which blocks are reachable (inode allocations, extent-list updates, directory-entry mutations, ACL grants, bitmap allocations and frees); data writes (the bytes inside a block) are not journaled because their visibility is gated by the extent list, which is journaled atomically with the bitmap mutation that justifies it.

The reframe matches ADR-010's "no internal pointers" goal where possible: extents are header-resident, not chased through indirection blocks. The reframe diverges from ADR-010 where mutability forces it: a journal exists (it cannot not exist for crash-safe metadata updates to mutable files), but it is bounded and the recovery path is a bounded loop. The pattern is structurally close to ext4's stripped-down "writeback" journal mode with extent-tree replaced by a header-resident bounded extent array.

## Decision

Five commitments. They are co-dependent: each makes the others coherent.

### 1. On-disk format - inode-based, header-resident extents, 8 KiB superblock and inode block

The disk is a contiguous array of 4 KiB blocks (LBAs). Layout:

```
LBA 0..1    Superblock                          (2 blocks = 8 KiB)
LBA 2..    Inode region                         (capacity_inodes * 2 blocks each)
            inode i starts at LBA 2 + 2*i
            inode i = header block + reserved block
LBA k..    Block-allocation bitmap              (capacity_blocks / 8 / BLOCK_SIZE blocks)
LBA m..    Journal region                       (JOURNAL_BYTES = 16 MiB)
LBA n..    Data region                          (capacity_blocks * 1 block each)
```

The superblock declares region offsets, `capacity_inodes`, `capacity_blocks`, format version, and a generation counter (bumped at each mount). 8 KiB matches the path Option 1 from ADR-028's redline discussion: one header block for fields, one reserved block for future PQ signature tail and other extensions. Mount rejects unknown format versions.

**Inode (header block, 4096 bytes)**:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `magic` | `"ARCINOD1"` = occupied. Any other value = free/never-written. The `ARC*` prefix is the CambiOS-wide magic-prefix convention; the registry lands in ASSUMPTIONS.md when the third backend introduces its own prefixes. |
| 8 | 4 | `version` | u32 LE. Currently `1`. |
| 12 | 1 | `kind` | `0 = Regular`, `1 = Directory`, `2 = Symlink`. |
| 13 | 1 | `extent_count` | u8. Number of active entries in `extents`, ≤ `MAX_EXTENTS_PER_INODE = 16`. |
| 14 | 2 | `acl_count` | u16 LE. Number of active entries in `acl`, ≤ `MAX_INODE_ACL_ENTRIES = 16`. |
| 16 | 8 | `size_bytes` | u64 LE. Logical file size. |
| 24 | 8 | `created_at` | u64 LE. Monotonic ticks at create time. |
| 32 | 8 | `modified_at` | u64 LE. Monotonic ticks at last write. |
| 40 | 32 | `owner` | Owner Principal (AID). |
| 72 | 4 | `link_count` | u32 LE. Number of hard links pointing at this inode. |
| 76 | 4 | `cow_refcount` | u32 LE. Number of frozen-view handles holding this inode's extents. The u32 width is the on-disk architectural ceiling; the v1 SCAFFOLDING practical bound is `MAX_FROZEN_VIEWS_PER_INODE = 1024` (see Decision 2). |
| 80 | 192 | `extents` | 16 entries × 12 bytes each (on-disk packed): `(start_lba: u64, block_count: u32)`. The kernel uses explicit byte reads, not `repr(C)` reinterpretation, because Rust's natural alignment of `(u64, u32)` is 16 bytes; the on-disk packing is 12. |
| 272 | 704 | `acl` | 16 entries × 44 bytes each: `(principal: [u8;32], rights: u8, expiry: u64, reserved: [u8;3])`. Inline cap of 16 by construction; multi-Principal access routes through ADR-027 cluster delegation, not through stuffing more entries into the inode. |
| 976 | 3104 | *reserved* | Zero-filled. Future symlink target inline, ACL extension, or PQ tail. |
| 4088 | 8 | `header_checksum` | Blake3 of bytes [0..4088], first 8 bytes. Detects accidental corruption only; adversarial integrity is out of scope for the POSIX backend (CAMBIO covers it for content that needs cryptographic provenance). |

**Reserved block** (LBA `2 + 2*i + 1`, 4096 bytes): zero-filled in v1; reserved for ML-DSA signature tail when PQ signing lands. Symmetric with ADR-010's reserved-tail allocation.

**Directory contents.** A directory inode's data extents hold a serialized list of `(name_len: u16, child_inode: u32, name_bytes)` records, packed without padding. `readdir` iterates the records; `mkdir`/`unlink`/`rename` rewrite affected records under journal protection (see Decision 5).

**Symlink target** is stored inline in the inode's first extent slot (target string up to `MAX_SYMLINK_LEN = 4 KiB - inode_overhead`); no data blocks needed.

**Shared block-allocation bitmap with the CambiObject backend.** Both backends allocate from the same on-disk bitmap region. The bitmap is read-only at mount time except via the journal (see Decision 5): every bitmap mutation is journaled in the POSIX journal, regardless of which backend triggered the allocation. The CambiObject backend, when it adopts this format via an ADR-010 Divergence appendix, will route its allocations through the same journal record type. The bitmap lock (`BLOCK_BITMAP_LOCK`) sits at hierarchy position 12, below both backends' top-level locks (see Decision 4).

**`MAX_INODES_ON_DISK`, `MAX_EXTENTS_PER_INODE`, `MAX_INODE_ACL_ENTRIES`, `MAX_FROZEN_VIEWS_PER_INODE`** are all SCAFFOLDING per Convention 8. Sizing rationale in § Architecture.

### 2. Per-inode copy-on-write - snapshot-consistency, concurrent writes, and the recovery substrate

When a writer modifies a block at offset O in inode I, the write does not overwrite the existing data block. Instead:

1. The writer allocates a fresh data block B' from the block-allocation bitmap (in-memory; not yet durable).
2. The writer writes new bytes to B' (data block durably on disk; not yet visible to anyone because no extent points at it).
3. The writer updates the in-memory inode extent list to point at B' instead of the old block B.
4. The writer appends a single journal record covering **both** (a) the bitmap-mutation (B' is now allocated, B is now free if cow_refcount on its extent permits) **and** (b) the inode extent-list update. The record is durable on journal flush.
5. After journal commit, the old block B's extent refcount is decremented; when it reaches zero, the kernel immediately journals a `BitmapMutation` record clearing B's bit, returning B to the free pool. The bitmap clear is never deferred to a coincidental future write that happens to touch B's bitmap word.

If a crash occurs between step 2 and step 4, B' is on disk but unreferenced and unallocated: the bitmap still shows B' free, no inode points at it, and the next allocation overwrites it. No orphan, no scan needed, no recovery action required.

This is the standard CoW shape with one critical detail: **bitmap mutations are journaled as part of the same record that updates the extent list**. The atomicity is at the journal record level; there is no torn-allocation window. Anything that affects which blocks are reachable (allocations, frees, extent-list changes) is journaled; the data write to B' itself is not journaled (its visibility is gated by the extent-list, which is). See Decision 5 for the full journal record specification.

Three properties fall out:

- **Concurrent reads see consistent bytes.** A reader holding a frozen view of inode I sees the extent list at the moment the view was opened. The writer's CoW does not modify those extents - it allocates new ones and updates the in-memory list. The reader's frozen view continues to point at the old (still-allocated, refcount > 0) blocks.
- **CAMBIO snapshot-consistency holds without locks.** CAMBIO's seal opens a frozen view of the source inode at start of seal; the cow_refcount on that inode is bumped. The seal reads through the frozen extent list. Concurrent writers do CoW, increment their own refcounts on new blocks, update the live extent list. When CAMBIO completes, it drops the frozen view; cow_refcount decrements; any blocks now unreferenced are freed via journaled bitmap-clear records. The seal never holds a global lock; concurrent writes never block.
- **Crash recovery is bounded.** A crash between step 2 (data write durable) and step 4 (journal record durable) leaves the new block B' written to disk but with no journal record claiming it. On replay, the bitmap stays unchanged (no record updates it); B' looks free; B is still allocated to inode I via its old extent. The pre-write state is preserved. B' is reusable on next allocation. No orphan.

**Frozen view handle**: a kernel-resident `FrozenInodeView { inode_id, frozen_extents, cow_refcount_ref }`. Held by CAMBIO syscall handlers and by any `FileDescriptor` opened with explicit `O_CONSISTENT_SNAPSHOT` mode (see Decision 4). Normal `FileDescriptor` opens do not create frozen views - they read from the live extent list, which is sufficient for POSIX semantics (POSIX `read` is allowed to interleave with concurrent writes).

**`MAX_FROZEN_VIEWS_PER_INODE = 1024`** (SCAFFOLDING). Memory cost per frozen view is ~256 bytes (inode id + extent list copy + bookkeeping); 1024 × 256 B = 256 KiB per inode at saturation, negligible. v1 endgame: a backup tool snapshotting working trees might hold a few hundred concurrent frozen views during a snapshot pass; 1024 gives 4× headroom. The on-disk `cow_refcount: u32` field has architectural headroom (4 billion) for future workloads with very high concurrency; raising the SCAFFOLDING bound is a one-line change in `ASSUMPTIONS.md`. When the per-inode bound is hit, CAMBIO open returns `EBUSY`.

### 3. Principal-keyed ACL - no Unix u/g/o

The inode's `owner` field is a 32-byte Principal AID. The inode's `acl` array holds up to 16 entries of `(Principal, Rights, expiry)`. `Rights` is a bitfield (bit 0 = Read, bit 1 = Write, bit 2 = Execute). Permission checks at every POSIX syscall:

1. The kernel reads the calling process's bound Principal P from the cap record.
2. If P matches `inode.owner`, the syscall is permitted (owner always has full rights on its own files).
3. Otherwise, scan `inode.acl` for an entry where `principal == P`. If found and the entry's `rights` bits include the operation's required bits and `expiry == 0 || expiry > now`, permitted. Else `EACCES`.

No "group" concept and no "other" concept; the equivalents are downstream of this ADR:

- **Multi-Principal access (a team, a service group, a shared project directory) routes through ADR-027 cluster delegation, not through stuffing more entries into the inode.** The inline 16-entry ACL is for the owner plus a handful of explicit individual grants (a contractor, a one-off share, a delegated agent). Workloads that require dozens or hundreds of accessing Principals create a service cluster, grant access at the cluster level, and let cluster membership confer the cap. This is the architectural answer to "what if I have 100 collaborators on a project" - it is not "ACL extension blocks," because that defeats the bounded-iteration verification claim and introduces an unbounded auxiliary store.
- **Public files (read-anywhere) are unusual in the CambiOS model.** If a genuinely-shared system object is needed (a signed system DLL, common config), the boot manifest installs a REGALO mount of a CambiObject and the CambiObject's ACL carries the wide-Read grant. POSIX inodes do not have a "world-readable" bit.

**Legacy UID translation lives entirely in userspace, in the calling process's libposix shim.** The shim runs as part of the process's address space (not in the kernel). It maintains a per-process UID→Principal table (populated at process startup from the sandbox manifest, or via libposix-internal allocation). When a POSIX program calls `chown(path, uid, gid)`, the shim resolves `uid → Principal` in its own table and then issues `SYS_ACL_GRANT(path, principal, rights)`. The kernel sees only the Principal; the kernel has no UID concept and no UID-to-Principal map of its own. The threat-model property this preserves: the worst case of a misbehaving shim is "the shim presents the wrong Principal to the kernel," which the kernel rejects via the existing identity gate (the syscall is rejected if the Principal doesn't have the required cap). The shim is never a translation authority on behalf of the kernel.

**Reverse direction (Principal → uid_t for stat readback).** A POSIX program that calls `stat(path)` expects `uid_t` in the returned `struct stat`. The libposix shim synthesizes a `uid_t` from the Principal (a stable deterministic hash, an ephemeral per-process allocation, or a cross-run stable scheme the shim's own state file maintains). The kernel exposes the Principal; the shim is free to choose any synthesis scheme that works for its consumers. The choice belongs in the future libposix design doc, not in this ADR.

**ACL operations** are exposed as POSIX-shaped extension syscalls (`acl_grant`, `acl_revoke`, `acl_list`) rather than overloading `chmod` - `chmod`-shape u/g/o bits would be lossy on the way back out to legacy code.

### 4. POSIX syscall surface + posix-fs-service gateway + lock-hierarchy placement

Twenty new syscalls cover the POSIX-shaped surface. They fall into three groups: file and directory operations (51-65), metadata (66-67), and ACL (68-70).

| Number | Name | Identity-required | Notes |
|---|---|---|---|
| 51 | `SYS_FILE_OPEN` | yes | Returns `FileDescriptor`. Flags include `O_RDONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_CONSISTENT_SNAPSHOT` (opens a frozen view per Decision 2). |
| 52 | `SYS_FILE_CREATE` | yes | Equivalent to `O_CREAT \| O_EXCL`. Returns `FileDescriptor`. |
| 53 | `SYS_FILE_CLOSE` | yes | Drops the descriptor; if a frozen view, decrements cow_refcount. |
| 54 | `SYS_FILE_READ` | yes | Bounded by `MAX_FILE_IO_BYTES_PER_CALL = 1 MiB` SCAFFOLDING. Subsequent calls iterate. |
| 55 | `SYS_FILE_WRITE` | yes | Same bound. Triggers CoW per Decision 2 if the write modifies an existing block. |
| 56 | `SYS_FILE_SEEK` | yes | Updates the descriptor's offset. |
| 57 | `SYS_FILE_TRUNCATE` | yes | Updates `size_bytes`; frees extents beyond the new size (refcount-checked). |
| 58 | `SYS_FILE_RENAME` | yes | Atomic per Decision 5 (single journal entry). Source and destination must be in the same backend (no cross-backend rename); cross-backend returns `EXDEV`. |
| 59 | `SYS_FILE_UNLINK` | yes | Decrements link_count; if zero and no open descriptors, frees the inode. |
| 60 | `SYS_FILE_LINK` | yes | Creates a new directory entry pointing at an existing inode; increments link_count. |
| 61 | `SYS_FILE_SYMLINK` | yes | Creates a Symlink inode whose first extent holds the target string. |
| 62 | `SYS_MKDIR` | yes | Allocates a Directory inode; initializes empty directory contents. |
| 63 | `SYS_RMDIR` | yes | Frees a Directory inode iff it has no entries. |
| 64 | `SYS_OPENDIR` | yes | Returns a directory descriptor (a `FileDescriptor` flavor with `backing = Directory`). |
| 65 | `SYS_READDIR` | yes | Iterates entries in a directory descriptor. |
| 66 | `SYS_STAT` | yes | Returns a `FileMetadata` struct (kind, size, owner, mtime, ctime, link_count). |
| 67 | `SYS_FSYNC` | yes | Forces journal flush and data CoW commits to durable storage. |
| 68 | `SYS_ACL_GRANT` | yes | Adds a `(Principal, Rights, expiry)` row to an inode's ACL; owner-only. Returns `ENOSPC` if the inline ACL is full (multi-Principal workloads should route through ADR-027 cluster delegation per Decision 3). |
| 69 | `SYS_ACL_REVOKE` | yes | Removes a row by Principal; owner-only. |
| 70 | `SYS_ACL_LIST` | yes | Returns the ACL contents for inspection. |

Numbers 51-70 reserved (ADR-022's wallclock and ADR-027's cluster syscalls already occupied 41-47; ADR-028 reserves 48-50).

**`posix-fs-service`** is a new boot module at endpoint 18 (the next free endpoint after the existing services). Same pattern as fs-service: kernel exposes the syscalls; posix-fs-service runs the policy layer for sandboxed callers (win-compat sandboxes, audit, future userland services that want path-shape access without direct kernel calls). Per-sandbox path-namespace mappings (`C:\` → `/var/win-compat/<sandbox>/c-drive/`) live in the shim, not in the kernel.

**REGALO cap behavior at limit.** When a process holds `MAX_REGALO_PER_PROCESS = 16384` aliases and calls `SYS_REGALO` to add another, the kernel returns `ENOMEM`. Userspace chooses the fallback: LRU-evict via `SYS_REGALO_REVOKE`, refuse to spawn the consumer at boot-manifest load time, fail open with a runtime error to the legacy app, or any other policy. The kernel does not make the choice.

**`POSIX_STORE` enters the lock hierarchy at position 11, above `OBJECT_STORE(10)`. `BLOCK_BITMAP_LOCK` enters at position 12, below both backends.**

```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
CLUSTER_MANAGER(5) → CHANNEL_MANAGER(6) → PROCESS_TABLE(7) →
FRAME_ALLOCATOR(8) → INTERRUPT_ROUTER(9) → OBJECT_STORE(10) →
POSIX_STORE(11) → BLOCK_BITMAP_LOCK(12)
```

CAMBIO acquires `OBJECT_STORE → POSIX_STORE → BLOCK_BITMAP_LOCK` in canonical order. POSIX-only operations acquire `POSIX_STORE → BLOCK_BITMAP_LOCK` (skipping OBJECT_STORE). The CambiObject backend, when it adopts the shared bitmap via the ADR-010 Divergence appendix, acquires `OBJECT_STORE → BLOCK_BITMAP_LOCK` (skipping POSIX_STORE). The shared `BLOCK_BITMAP_LOCK` is always acquired last; it never acquires anything above itself. REGALO operations touch `PROCESS_TABLE(7)` for the per-process alias table and do not touch `POSIX_STORE` or below - REGALO does not materialize an inode, just a path-to-hash entry.

**Sub-locks within POSIX_STORE** (POSIX-internal, never promoted to the top-level hierarchy):

- `INODE_LOCK[i]` - per-inode lock, acquired for any inode modification. Lock ordering across inodes is by ID ascending, to prevent rename deadlocks (rename touches two inodes).
- `JOURNAL_LOCK` - serializes journal record appends; brief, held only during the append.

### 5. Path-namespace integration + hybrid recovery (metadata journal + data CoW)

**Path resolver** (callable from any path-shaped syscall) implements the exhaustive match from ADR-028 § Decision 2:

```rust
fn resolve(path: &str, caller: Principal, op: Operation) -> Result<ResolvedHandle, Error> {
    // Step 1 - write attempt under /co/* is rejected before backend lookup.
    // Fires regardless of whether the path is a valid canonical hash;
    // a file_open for write on /co/<anything> returns EROFS without ever
    // resolving to a backend.
    if path.starts_with("/co/") && op.is_write_or_create() {
        return Err(EROFS);
    }
    // Step 2 - /co/<hex-hash> canonical mount → ObjectView via cap check.
    // Only fires on read operations; writes were caught in Step 1.
    if let Some(hash) = parse_canonical_mount(path) {
        return cap_check_and_return_object_view(hash, caller);
    }
    // Step 3 - REGALO alias hit → ObjectView via per-process REGALO table.
    if let Some(hash) = regalo_lookup(path, caller.pid()) {
        return cap_check_and_return_object_view(hash, caller);
    }
    // Step 4 - POSIX inode resolution by walking directory tree from root.
    // Path-walk depth is bounded by MAX_PATH_DEPTH = 64 SCAFFOLDING.
    posix_inode_lookup(path, caller, op)
}
```

The match is closed; no fifth outcome. Step 1 fires on any write or create attempt under `/co/*` regardless of whether the path is a valid canonical hash, ensuring `file_open` for write at `/co/...` returns `EROFS` without backend lookup and never returns a successful open. Step 2 fires only on reads; writes were caught earlier. Steps 2-3 return `FileDescriptor` with `backing = ObjectView { hash, source }` per ADR-028's `FileBacking` enum; step 4 returns `FileDescriptor` with `backing = Posix`.

**Reverse-ACL enumeration** (`opendir("/co/")`) iterates the per-Principal index entries for the calling Principal and returns hashes. Population events per ADR-028 § Decision 2 rule 4 (initial put, ACL grant, cap-transfer via IPC capability machinery, removed on revoke). The reverse-ACL index lives on the CambiObject side per ADR-010 - this ADR's `/co/` resolver consults it; this ADR does not own it.

**Recovery: hybrid metadata journal + data CoW.**

The journal is a fixed-size circular log in a dedicated disk region (size: `JOURNAL_BYTES = 16 MiB`, SCAFFOLDING). Each journal record covers one *metadata transaction*. Records are atomic: either the entire record applies on replay or none of it does.

Journal record kinds:

- **InodeAllocate / InodeFree** - inode lifecycle.
- **ExtentUpdate + BitmapMutation** - the CoW commit step from Decision 2, bundled atomically. Records the inode whose extent list changes, the new extent list, and the bitmap bits flipped (set for newly-allocated blocks, cleared for blocks now unreferenced). This bundling is what makes Decision 2 step 4 work; bitmap mutations are never separable from the extent-list changes that justify them.
- **DirectoryEntry insert/delete/rewrite** - directory contents.
- **Rename** - covers both directory-entry changes (source delete, destination insert) atomically.
- **ACL grant / revoke** - inode ACL changes.
- **LinkCount Set** - hard-link bookkeeping. Records the new absolute `link_count` value (not a delta), so the record is idempotent under repeated replay. Relative-mutation records (delta semantics) would break the journal-replay idempotency invariant.

Records are appended on operation completion; the operation is only acknowledged to userspace after the journal record is durable (single fsync of the journal region). On mount, the recovery loop replays uncommitted records from the journal's last checkpoint forward:

```
for record in journal_records_since_last_checkpoint() {
    if record.is_committed_marker() { mark_replay_complete(); break; }
    apply_metadata_change(record);  // idempotent
}
```

Idempotency is the constraint that makes the replay loop bounded and correct: every metadata change is expressible as "set field F of object O to value V" (or "flip bit B of bitmap"), which is idempotent under repeated application. Data writes (CoW block writes) do not appear in the journal at all - they write directly to the data region, and their visibility is gated by the inode's extent list (which is journaled together with the bitmap-bit-set that the extent points at). A crash mid-data-write leaves the data on disk but unreferenced; the next allocation will overwrite it.

**The invariant: anything that affects which blocks are reachable is journaled; anything that affects what bytes are in a block is not.** This collapses the recovery story to "replay journal records, find committed state of reachability metadata, ignore unreferenced data blocks."

**Checkpoint cadence.** Every 4 KiB of journal records, or every 100 ticks (1 second), whichever comes first, the kernel writes a checkpoint marker and updates the superblock to reflect the new replay-start point. Bounded journal growth; bounded recovery time. **Cadence cost note:** 4 KiB cadence on a 16 MiB journal produces up to 4096 superblock writes per journal wrap. On NVMe / SSD (the v1 target hardware - Dell 3630 and targeted cloud peers), this is sub-millisecond per write. On a spinning disk, the superblock write rate would dominate and the cadence would need relaxing; not a v1 blocker because v1 hardware is flash-only.

**The hybrid model bounds verification surface:**

- Journal replay is a bounded loop over a bounded region.
- Each metadata change is a small, identifiable enum variant - finite state, exhaustive match.
- Data writes have no transactional semantics at the kernel level - they are just "write to block, journal extent+bitmap update atomically" - so there is no torn-write recovery for data; the worst case is unreferenced bytes on disk that get overwritten on next allocation.
- The journal is fixed-size and circular; it cannot grow unbounded.
- The bitmap is consulted from journal records only (no out-of-band bitmap mutations), so the worst-case orphan-block-scan never runs: bitmap state is always the projection of committed journal records.

**MAX_REGALO_PER_PROCESS = 16384** (SCAFFOLDING). Win-compat dependency closure: system32 holds ~3500 files baseline, a non-trivial Windows app (QuickBooks, AutoCAD) adds 5K-15K DLLs + config + registry-backed manifests. 16K covers the high end of observed dependency closures with the 25%-utilization rule giving 4× headroom. Memory cost per process: ~1 MiB (16K × ~64 bytes per REGALO entry). Replace when an observed Windows-app workload exceeds the bound. Behavior at the cap is specified in Decision 4 (`SYS_REGALO` returns `ENOMEM`; userspace chooses the fallback policy).

## Architecture

### Kernel state

```rust
// In a new src/fs/posix/mod.rs:
pub struct PosixFsBackend {
    pub superblock: Superblock,
    pub inodes: PosixInodeTable,
    pub block_bitmap: BlockBitmap,   // governed by BLOCK_BITMAP_LOCK
    pub journal: Journal,
    pub frozen_views: FrozenViewTable,
}

pub struct Superblock {
    pub magic: [u8; 8],         // "ARCPOSX1"
    pub version: u32,
    pub capacity_inodes: u64,
    pub capacity_blocks: u64,
    // Region offsets, in on-disk layout order.
    pub inode_region_lba: u64,
    pub bitmap_region_lba: u64,
    pub journal_region_lba: u64,
    pub data_region_lba: u64,
    // Journal state.
    pub journal_capacity_bytes: u64,
    pub last_checkpoint_offset: u64,
    // Bookkeeping.
    pub generation: u64,
    pub created_at: u64,
}

pub struct PosixInode {
    pub magic: [u8; 8],         // "ARCINOD1"
    pub kind: InodeKind,         // Regular | Directory | Symlink
    pub size_bytes: u64,
    pub created_at: u64,
    pub modified_at: u64,
    pub owner: Principal,
    pub link_count: u32,
    pub cow_refcount: u32,
    pub extents: [Option<Extent>; MAX_EXTENTS_PER_INODE],
    pub acl: [Option<AclEntry>; MAX_INODE_ACL_ENTRIES],
}

pub struct Extent {
    pub start_lba: u64,
    pub block_count: u32,
}

pub struct AclEntry {
    pub principal: Principal,
    pub rights: Rights,        // bitfield: Read | Write | Execute
    pub expiry: Option<u64>,
}

pub struct FrozenInodeView {
    pub inode_id: InodeId,
    pub frozen_extents: [Option<Extent>; MAX_EXTENTS_PER_INODE],
    pub view_id: u32,
    pub created_at: u64,
}
```

The `ObjectStore` trait's enum-dispatch pattern from [ADR-003 § Divergence](003-content-addressed-storage-and-identity.md#divergence) is mirrored here. A new `PosixFsBackend` is the kernel-side singleton; no polymorphic trait, no `dyn` dispatch on the hot path.

**On-disk vs in-memory layout.** The Rust `Extent { start_lba: u64, block_count: u32 }` naturally aligns to 16 bytes (the `u64` field's 8-byte alignment dominates). The on-disk format packs to 12 bytes per record. The kernel uses explicit byte reads (via the `byteorder` or equivalent crate) rather than `mem::transmute` or `repr(C, packed)` reinterpretation, both for the extent records and for any other size-asymmetric on-disk structure. Future readers should not be surprised that `mem::size_of::<Extent>() == 16` while the on-disk record is 12 bytes.

### Bounded iteration claims (for verification)

- **Mount inode scan** is `for i in 0..capacity_inodes`. `capacity_inodes` is declared in the superblock and bounded by `MAX_INODES_ON_DISK` SCAFFOLDING (sized to the Win-compat endgame: tens of thousands of files per app × possibly tens of apps = low millions on a personal machine; set `MAX_INODES_ON_DISK = 4_194_304` = 4M for v1).
- **Block-bitmap scan at mount** is a defense-in-depth check. The journal-owned-bitmap invariant (verified independently per the Verification Stance) guarantees the bitmap must match the projection of replayed journal records; the scan catches the case where a journal-replay bug or a corrupted journal record produced an inconsistent state. On mismatch the kernel refuses to complete mount (no read-write access), emits an audit event, and requires manual recovery via a future fsck tool. Set `MAX_BLOCKS_ON_DISK = 1_073_741_824` (1B blocks = 4 TiB disk).
- **Journal replay** is `for record in journal_since_checkpoint()`, bounded by `JOURNAL_BYTES / MIN_RECORD_SIZE`.
- **Path resolution depth** bounded by `MAX_PATH_DEPTH = 64` SCAFFOLDING; prevents arbitrary `/.././.././..` walking.

Every SCAFFOLDING bound carries the Convention 8 doc comment and lands in [ASSUMPTIONS.md](../ASSUMPTIONS.md) when the implementation lands.

### CAMBIO interaction (cross-backend transaction)

CAMBIO acquires `OBJECT_STORE → POSIX_STORE → BLOCK_BITMAP_LOCK` in canonical order, opens a `FrozenInodeView` of the source POSIX inode (incrementing its cow_refcount), reads bytes streaming through the frozen extent list, computes Blake3, runs the signing flow against the calling Principal's key-store binding, installs the resulting CambiObject via `ObjectStoreBackend::put`. On success: drops the frozen view (decrements cow_refcount); on `AndDelete` flag: also unlinks the source. The transaction is atomic-or-fail at the syscall boundary - either both the CambiObject install and the optional unlink commit, or neither does (the journal record for the unlink is appended only after the CambiObject's hash is durable in the ObjectStore).

### Capability checks

| POSIX operation | Cap chain |
|---|---|
| File open (read) | ACL.Read for caller's Principal on inode |
| File open (write) | ACL.Write |
| File create | ACL.Write on parent directory |
| Directory listing | ACL.Read on directory inode |
| Rename | ACL.Write on source's parent dir + ACL.Write on dest's parent dir |
| Unlink | ACL.Write on parent directory |
| Stat | ACL.Read on inode (or implicit if caller owns it) |
| ACL grant / revoke | Caller is inode.owner |

No new `CapabilityKind`. Permission is sourced from the inode's per-Principal ACL.

## Threat Model

### What this ADR protects against

| Threat | Mitigation |
|---|---|
| Concurrent CAMBIO + write produces an inconsistent hash | Per-inode CoW (Decision 2): CAMBIO reads the frozen extent list; concurrent writes go to new blocks; hash is over the consistent snapshot |
| Crash mid-write produces a corrupt file | Data writes are CoW (new block); inode extent list updates are journaled atomically alongside the bitmap mutation that allocated the new block; mount-time replay reverts uncommitted updates; no orphan blocks exist because bitmap state is always the projection of committed journal records |
| Crash mid-rename produces an inode pointing at two paths or zero paths | Rename is a single journal record that covers both directory-entry changes; replay applies the record atomically or not at all |
| ACL escalation by directly editing the inode | Inode writes go through `POSIX_STORE`-locked code paths; no syscall lets userspace write inode header bytes directly. ACL grant/revoke is owner-only and journaled |
| Path-walk traversal exploits (../../../../etc/passwd) | Path resolver enforces `MAX_PATH_DEPTH` per Decision 5; symlink resolution depth is also bounded |
| Hard-link unlink-after-open race | `link_count` is decremented on unlink but inode is not freed until `link_count == 0 && open_descriptor_count == 0`; matches POSIX semantics |
| Cross-backend rename (POSIX file → CambiObject path) | `SYS_FILE_RENAME` rejects with `EXDEV` if source and destination resolve to different backends; only CAMBIO crosses the seam |
| /co/* write attempt by a buggy or malicious POSIX consumer | Path resolver rejects writes under `/co/*` in step 1 of the resolve match per Decision 5 (before any backend is touched) |
| Forged kernel-side UID-Principal binding | No kernel-side binding exists. UID translation is shim-side userspace state per Decision 3; the worst case of a misbehaving shim is "wrong Principal presented to the kernel," which the kernel rejects via the identity gate |

### What this ADR does NOT protect against

| Risk | Mitigation |
|---|---|
| Disk-level corruption (bitrot, controller error, adversarial physical access) | Out of scope. Higher-layer concern; per-block content hashing for the POSIX backend is deferred (CambiObject side is content-addressed and adversarial-integrity-protected by design; POSIX side is for working state where the threat model is accidental corruption only). The 8-byte Blake3 header checksum on inodes detects accidental corruption but is not adversarial-strength. |
| Side-channel between two Principals via the shared block-allocation bitmap | An attacker observing block-allocation patterns may infer write activity by an unrelated Principal. Out of scope; the bitmap is shared by construction and bitmap-allocation patterns are global state. Future hardening could partition the bitmap per Principal; not in v1. |
| Symlink-following into the canonical /co/ namespace by a confused POSIX consumer | Symlinks under POSIX paths can target `/co/<hash>` paths; resolution passes through the canonical mount logic (read-only). Write attempts via a symlink still hit step 1 of resolve and fail. Acceptable. |
| Time-of-check / time-of-use between path resolve and inode operation | POSIX has this inherently; CambiOS does not solve it at the syscall boundary. Sandboxed callers per win-compat operate on their own per-sandbox subtree where the attacker has no concurrent access. |
| Large-file write or CAMBIO fails with `EFRAGMENTED` on an aged disk | The 16-extent cap per inode (Decision 1) creates an upper bound on file fragmentation; aged disks with many allocate-delete-reallocate cycles may exceed it. v1 has no defragmenter; the failing syscall returns `EFRAGMENTED` and the user must invoke a future out-of-band compaction tool. Open Questions names this deferred. Not silent corruption; explicit failure mode. |

### Impact on existing threats

- [ADR-003](003-content-addressed-storage-and-identity.md)'s integrity model: unaffected. CambiObjects retain Blake3 + Ed25519 verification on retrieval. CAMBIO writes the caller's Principal into the CambiObject's `author` field (transcription per [ADR-026](026-identity-transcription-at-the-kernel-ring.md)).
- [ADR-005](005-ipc-primitives-control-and-bulk.md)'s channel model: unaffected. posix-fs-service uses the standard control-IPC pattern.
- [ADR-027](027-service-clusters.md)'s cluster-scoped cap inventories: compose with this ADR. A cluster member's POSIX file ACLs are part of its cap inventory; cluster revoke removes the member's ACL entries from inodes the cluster owns. Multi-Principal access patterns route through cluster delegation rather than wide inline ACL (Decision 3).

## Verification Stance

The kernel surface is the verification target. Six distinct claims:

- **On-disk format exhaustiveness.** Mount's inode-region scan is a bounded `for i in 0..capacity_inodes` loop; every iteration matches `magic == "ARCINOD1"` (occupied) or anything-else (free). No "other" case. Kani harness target: "every inode in the table is exactly one of {Free, Occupied} after mount."
- **Per-inode CoW correctness.** A frozen view's `frozen_extents` is set at view-open time and immutable for the view's lifetime. Concurrent writers do not modify those extents; they allocate new extents and update the inode's live extent list. Kani target: "after a write to inode I with view V open, V's frozen_extents are byte-identical to V's frozen_extents before the write."
- **Journal replay idempotency.** Every journal record's apply function is idempotent. Kani target: "for any sequence of journal records R1, R2, ..., Rn, applying them once produces the same state as applying R1, ..., Rk, R1, ..., Rn for any 1 ≤ k ≤ n."
- **Journal-owned-bitmap invariant.** Every bitmap mutation appears in a journal record. Kani target: "for every block B with bitmap-bit set, there exists a committed journal record (ExtentUpdate or InodeAllocate) whose payload includes B." Equivalently: there are no orphan blocks, because the bitmap is the projection of committed journal records.
- **ACL check correctness.** Every POSIX syscall handler resolves the calling Principal's rights via owner-check-or-acl-lookup, exhaustively. Kani target: "no path through the handlers reaches a backend mutation without an ACL check returning Permitted for the required rights."
- **Path resolution exhaustiveness.** The resolve function's match (write-rejection-under-canonical / canonical / REGALO / POSIX inode) is closed; every input path produces exactly one of those outcomes. The Kani target is shared with ADR-028's path-namespace exhaustiveness claim — single harness, one verification target across both ADRs rather than duplicated work.

The verification surface delta vs. existing kernel: substantial - a full new backend, the journal, the CoW state machine, the path resolver, twenty new syscall handlers, the ACL check on each. Larger than ADR-027's cluster manager. The bound-everything-by-SCAFFOLDING discipline (Convention 8) is what makes it tractable: every loop has a stated upper bound, every state machine has finite states, no unbounded data structures.

## Why Not Other Options

### Option A: Use ext4 (or similar mature filesystem) verbatim

Adopt the ext4 on-disk format. Userspace tools (mkfs, fsck, debugfs) work out of the box.

**Why considered.** Decades of production hardening. Existing tools. Wide deployment surface area.

**Why rejected.** Ext4's metadata model is intricate: extent trees with B-tree indirection, htree-indexed directories, journal modes (writeback / ordered / journal), several feature-flag combinations. The verification surface is enormous. CambiOS targets formal verification of every kernel subsystem; an ext4-shaped backend would dominate the verification budget. The CambiOS POSIX backend trades feature parity for tractability: bounded extents, fixed-size inode table, hybrid journal, no b-trees. ext4's compatibility benefit is gated on supporting ext4 partitions from outside CambiOS, which is not a v1 requirement.

### Option B: Full CoW with snapshot trees (btrfs / zfs shape)

Every metadata change copies the affected inode and walks up to a new superblock root. Snapshots are trivially supported by retaining old roots.

**Why considered.** Crash recovery is trivial: load the last-known-good superblock. Snapshots are free. The CoW model already needed for CAMBIO snapshot-consistency would generalize.

**Why rejected.** The verification burden of full CoW is specifically expensive: every metadata write becomes a tree mutation that has to be proved to terminate and converge on a consistent root, and free-space-after-snapshot accounting (when can a block be returned to the free list after snapshots have been retired) is a non-trivial state machine in its own right. The hybrid model's verification target is bounded-replay-loop-over-fixed-ring with per-record idempotence - a much cleaner Kani target. Data CoW alone (without tree mutation) gives the snapshot-consistency property CAMBIO needs via `FrozenInodeView`, without paying for a tree of inodes or kernel-side snapshot management.

ADR-010's no-journal choice is correct for write-once content-addressed objects; it is not transferable to mutable POSIX semantics, which is why this ADR diverges. The journal does not reverse ADR-010's stance, it answers a different problem.

### Option C: Make POSIX backend a thin layer over CambiObject

Every POSIX write produces a new CambiObject; the inode's "current bytes" are a hash pointer that updates on write.

**Why considered.** One backend instead of two. Versioning is free. Audit trail is automatic.

**Why rejected.** This is exactly the failure mode the synthesis (storage-planning.md) excluded - "forcing those workloads through content-addressing has real cost." Every write triggers rehash; version explosion in the ObjectStore; the win-compat working state alone would generate gigabytes of CambiObject versions per session. Two co-equal backends, not one as a degraded form of the other.

### Option D: Defer POSIX backend; ship CAMBIO-only via a tmpfs-equivalent

POSIX paths resolve to RAM-only inodes (lost on reboot); persistence is only via CAMBIO.

**Why considered.** Smaller initial implementation. Persistence problem becomes a userspace problem (REGALO mount your CAMBIOed objects at boot from the manifest).

**Why rejected.** Win-compat target apps (QuickBooks, AutoCAD, LabVIEW) write working state continuously; losing it on reboot is unacceptable. Native CambiOS workflows (document editing, build systems) also need persistent mutable storage. The deferred-persistence path forces every consumer of the POSIX model to also be a consumer of CAMBIO + REGALO, which collapses the synthesis's two-backend model into one with extra steps.

### Option E: Split this ADR into two (backend on-disk format, then API surface)

ADR-029a covers format, CoW, recovery. ADR-029b covers syscalls, path resolver, posix-fs-service. Smaller ADRs are easier to redline.

**Why considered.** Each half is independently decideable. Half-size redline iterations.

**Why rejected.** The format and the API surface are tightly coupled - the syscall arguments reference inode IDs, extent shapes, ACL entries; the path resolver references the directory entry format. Splitting forces forward references in 029a to 029b's syscall numbers and resolver shape, and vice versa. The synthesis's "one POSIX File Storage Model ADR" call is the right shape; this ADR keeps that boundary.

## Migration Path

Documentation + reservation first, implementation in dependency order. This ADR's implementation chain is the longest of the storage stack.

1. **Land this ADR as `Proposed`.** No code touched. The format, CoW model, ACL semantics, syscall surface, lock placement, and path resolver shape are now citeable.
2. **`cambios-abi` syscall reservations.** Reserve numbers 51-70 for the POSIX syscall family. Reservation only; no handlers - same posture as ADR-022 / ADR-028.
3. **`PosixInode`, `Extent`, `AclEntry`, `FrozenInodeView` types added to `cambios-abi`.** Opaque newtypes around kernel-issued IDs (e.g., `InodeId`); no public field access. No behavior change.
4. **PosixFsBackend skeleton + on-disk format reader.** Implements Mount (superblock parse, inode scan, journal replay) but no write path. Tests for the format on a synthetic disk image.
5. **Block-bitmap allocator + journal record format + `BLOCK_BITMAP_LOCK` introduction + ADR-010 Divergence appendix.** Both backends adopt the shared journal record format simultaneously; sub-lock established at hierarchy position 12. The ADR-010 Divergence lands here (not later) because the journal-owned-bitmap invariant requires the CambiObject backend's allocation path to route through the shared journal from the moment the shared bitmap exists; deferring the Divergence would create a window where the invariant is partially broken.
6. **Inode CRUD + ACL operations.** `SYS_FILE_CREATE`, `SYS_FILE_OPEN` (read), `SYS_STAT`, `SYS_ACL_GRANT/REVOKE/LIST`. Journal records cover the metadata changes.
7. **Data path + CoW.** `SYS_FILE_READ`, `SYS_FILE_WRITE`, `SYS_FILE_SEEK`, `SYS_FILE_TRUNCATE`, `SYS_FSYNC`. Per-inode CoW with refcounted extents. FrozenInodeView introduced.
8. **Directory operations.** `SYS_MKDIR`, `SYS_RMDIR`, `SYS_OPENDIR`, `SYS_READDIR`, `SYS_FILE_LINK`, `SYS_FILE_UNLINK`, `SYS_FILE_SYMLINK`.
9. **Atomic rename.** `SYS_FILE_RENAME` with the single-journal-record transaction.
10. **Path resolver + canonical mount + REGALO alias table.** ADR-028's migration step 7 lands here, sharing this ADR's resolver code.
11. **CAMBIO handler.** ADR-028's migration step 6 lands here; depends on FrozenInodeView (step 7 above) and ObjectStore (existing).
12. **posix-fs-service.** Userspace boot module at endpoint 18; ACL policy layer; per-sandbox path-namespace mappings for win-compat. If a v1 workload demands cluster-scoped file access at this point, an ADR-027 Divergence appendix lands here adding storage-ACL grants to the cluster cap-delegation set (see Open Questions / Deferred).
13. **ADR-003 Divergence appendix.** Per ADR-028 migration step 9.
14. **win-compat.md edit pass** per ADR-028 migration step 10.

Each step independently bisectable. Steps 1-3 are pre-implementation; steps 4-14 chain through actual code.

## Cross-References

- **[ADR-028](028-three-storage-models.md)** - The kernel-API discipline this ADR provides the POSIX backend for.
- **[ADR-010](010-persistent-object-store-on-disk-format.md)** - The CambiObject on-disk format; gets a Divergence appendix adopting this ADR's shared block-allocation bitmap + journal record format.
- **[storage-planning.md](../storage-planning.md)** - The synthesis the model split comes from.
- **[ADR-003](003-content-addressed-storage-and-identity.md)** - The CambiObject backend; peer of this ADR's POSIX backend.
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** - Channel substrate posix-fs-service uses for control IPC.
- **[ADR-016](016-win-compat-api-ai-boundary.md)** - Win32 layer; primary downstream consumer of the POSIX backend via the win-compat shim's UID-to-Principal translation.
- **[ADR-018](018-init-process-and-boot-manifest.md)** - Boot manifest installs system-global REGALO aliases that this ADR's resolver consults.
- **[ADR-025](025-principal-as-aid.md)** - Principal as 32-byte AID; the identity primitive this ADR's ACL is keyed on.
- **[ADR-026](026-identity-transcription-at-the-kernel-ring.md)** - Kernel transcribes Principal values, does not interpret them - this ADR's ACL check is a Principal-equality match, consistent with the transcription invariant.
- **[ADR-027](027-service-clusters.md)** - Clusters scope POSIX file ACLs alongside CambiObjects; multi-Principal access patterns route through cluster delegation per Decision 3.

## See Also in CLAUDE.md

When this ADR's implementation lands, the following CLAUDE.md sections must be updated:

- **§ "Lock Ordering"** - insert `POSIX_STORE(11)` and `BLOCK_BITMAP_LOCK(12)` below `OBJECT_STORE(10)`. Update the `IrqSpinlock` annotations and the comment in `src/lib.rs`. Document the acquisition pattern: CAMBIO does `OBJECT_STORE → POSIX_STORE → BLOCK_BITMAP_LOCK`; POSIX-only ops do `POSIX_STORE → BLOCK_BITMAP_LOCK`; CambiObject-only ops (after the ADR-010 Divergence) do `OBJECT_STORE → BLOCK_BITMAP_LOCK`.
- **§ "Required Reading by Subsystem"** - add a row for "POSIX file storage / mutable backend / atomic rename" pointing at this ADR, storage-planning.md, ADR-028.
- **§ "Syscall Numbers"** - add `SYS_FILE_OPEN` through `SYS_ACL_LIST` (51-70) when handlers land.
- **§ "Design Documents"** - already updated when ADR-028 landed; no additional entries needed.

## Open Questions / Deferred

> **Deferred decision.** Whether `SYS_FSYNC` is per-fd or whole-backend. Per-fd is the POSIX-faithful semantics; whole-backend is simpler but penalizes the common case. Lean per-fd. **Revisit when:** the first workload demands the simpler semantics, or per-fd fsync proves too expensive under the chosen journal flush strategy.

> **Deferred decision.** Whether the POSIX backend supports extended attributes (xattrs). POSIX-shape code occasionally relies on them (selinux, posix capabilities, mac extensions). v1 ships without xattrs; ACL entries cover the security-relevant subset. **Revisit when:** a target application's behavior depends on xattr presence (e.g., a specific Windows-app's compatibility shim).

> **Deferred decision.** Whether boot-manifest-installed REGALO aliases are system-global (resolvable for any Principal) or per-Principal (resolvable only for Principals the manifest names). Lean per-Principal scoping for security, with a "public" tier for genuinely shared system objects (signed system DLLs, common config). **Revisit when:** ADR-018 grows a section on global-alias semantics.

> **Deferred decision.** Cross-backend hardlinks. Currently `SYS_FILE_LINK` rejects across-backend with `EXDEV`. A future workload (versioned working-tree pointing at signed manifest entries via hardlink-shaped reference) might want cross-backend reference, which collapses into REGALO. **Revisit when:** the workload appears; the reframe would probably be "model this as REGALO + a per-inode 'pinned-via-link' marker" rather than literal hardlink.

> **Deferred decision.** Journal compaction strategy under sustained metadata churn. v1 uses a fixed-size circular journal with checkpoint markers every 4 KiB. A workload that churns metadata faster than 4 KiB / 100 ticks could starve the checkpoint cadence and force a flush stall. v1 ships with the simple cadence; instrumentation will tell us if it's a real problem. **Revisit when:** observed flush-stall behavior in a production-scale workload.

> **Deferred decision.** Principal → uid_t synthesis scheme in libposix (for `stat()` readback). The libposix shim must synthesize some `uid_t` from the Principal it sees in the kernel-returned `FileMetadata`. Options include stable deterministic hash, ephemeral per-process allocation, or cross-run stable mapping via libposix's own state file. The kernel exposes the Principal; the shim chooses. **Revisit when:** the libposix design doc is drafted.

> **Deferred decision.** ACL extension blocks (for inodes that legitimately need >16 ACL entries without going through cluster delegation). v1 does not support this; the architectural answer for multi-Principal access is cluster delegation per Decision 3. **Revisit when:** a workload appears where cluster delegation is structurally wrong for the access pattern (the natural example would be public commentary on a shared document, but ADR-027 clusters may handle that case adequately).

> **Deferred decision (cross-ADR).** ADR-027 currently specifies cluster cap-delegation for IPC and channel rights (Channel-create, channel-attach pre-authorization, endpoint send/recv, optional `ClusterRevoke`). Decision 3 of this ADR asserts that multi-Principal POSIX file access routes through the same delegation mechanism, but ADR-027 has not yet been extended with storage-ACL grant types in its per-role cap set. This ADR forecasts an ADR-027 Divergence appendix that adds `(file_acl_grant: ACL.Read | ACL.Write)` to the cluster manifest's per-role policy. **Revisit when:** the first workload that requires cluster-scoped file access appears; ADR-027 Divergence appendix lands at that point, and this ADR's migration step 12 (posix-fs-service) is the natural trigger.

> **Deferred decision.** Defragmenter / compaction tool for the data region. The 16-extent cap on inode extents creates a real failure mode (`EFRAGMENTED` on `SYS_FILE_WRITE` or `SYS_CAMBIO`) on aged disks that have exceeded the cap through repeated allocate-delete-reallocate cycles. v1 ships without a defrag pass; recovery is currently "user invokes the future out-of-band compaction tool," which is unspecified. **Revisit when:** the first observed `EFRAGMENTED` failure in a production workload, or proactively before v1 ships if disk-stress testing surfaces it.

> **Deferred decision.** POSIX advisory file locking (`fcntl(F_SETLK)`, `flock`, `lockf`). Many POSIX consumers - SQLite, Postgres, application-level mutual exclusion via lockfiles - depend on advisory locking; v1 does not implement it. The libposix shim stubs calls or returns `ENOSYS`. **Revisit when:** the first win-compat target app fails because of missing file-locking semantics (likely the first database-backed Windows app: QuickBooks, an embedded-SQLite app). The natural shape is a per-inode lock-record list plus two new syscalls (`SYS_FILE_LOCK`, `SYS_FILE_UNLOCK`); fits as an ADR-029 Divergence appendix rather than a separate ADR.

> **Deferred decision.** Memory-mapped files (`mmap`) and how they compose with per-inode CoW (Decision 2). A writer that mmaps a page and stores into it does per-byte writes that bypass `SYS_FILE_WRITE`, which means the CoW + journal mechanism does not fire. v1 has no mmap support; libposix calls return `ENOSYS`. The composition is non-trivial: page-fault-triggered CoW with a journal record at first-dirtying of each mapped page is the likely shape, but it interacts with the FrozenInodeView mechanism in ways that need explicit design. **Revisit when:** mmap support is in scope (compilers, debuggers, language runtimes, databases, GPU drivers, X-shared-memory all want it; deferred until a v1 workload demands it). Probably warrants its own ADR rather than a Divergence appendix, given the CoW interaction surface.

> **Deferred decision.** Sparse files, `fallocate`-style preallocation, and explicit holes. The current extent-based format represents contiguous runs of data only; it has no way to express "block N is logically zero, no allocation." VM disk images, Postgres WAL preallocation, large logfiles with skipped regions, and any app using `posix_fallocate` use sparse semantics. v1 does not support sparse files; a 1 TB sparse file would actually allocate 1 TB of blocks. **Revisit when:** Postgres or a comparable database lands as a v1 target; the natural extension is a per-extent `is_hole` flag plus `SYS_FILE_FALLOCATE`. Fits as an ADR-029 Divergence appendix.

> **Deferred decision.** File-change notifications (POSIX inotify, Windows `ReadDirectoryChangesW`). Many native apps and language tooling (Cargo file watchers, language servers, build systems, IDEs) watch directories for changes. v1 emits audit events on file mutations but does not expose a userspace notification channel suitable for polling-replacement. **Revisit when:** the first userspace consumer needs change-detection without polling; the natural mechanism is a per-watcher subscription channel (riding on ADR-005 channels) that emits ChannelManager-routed events on inode-modified, dir-entry-added, dir-entry-removed.

> **Deferred decision.** Behavior of a long-lived `FileDescriptor` when the inode's ACL changes (the owner revokes the descriptor-holder's Principal-keyed entry). v1 adopts standard POSIX semantics: permissions are checked at `file_open` time, not on every operation, so the descriptor remains valid for its declared rights. Cluster revoke per ADR-027 handles cluster-scoped cap teardown; individual ACL revoke on a held FD does not propagate. **Revisit when:** a Stream-containment use case (NDA review, content protection) requires guarantees stronger than "cluster revoke is the only way to invalidate held descriptors." The natural extension is per-inode generation counters checked on each `SYS_FILE_READ`/`_WRITE`, paid for by a per-op cap-check on a hot path.
