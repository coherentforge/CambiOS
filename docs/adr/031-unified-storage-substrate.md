# ADR-031: Unified Storage Substrate

- **Status:** Proposed
- **Date:** 2026-05-17
- **Depends on:** [ADR-010](010-persistent-object-store-on-disk-format.md) (CambiObject metadata layer; record format adopts the extent-into-substrate shape via the body edit that lands alongside this ADR), [ADR-029](029-posix-file-storage-model.md) (POSIX metadata layer; inode region defers substrate ownership to this ADR via the body edit that lands alongside)
- **Related:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (channel substrate the seam syscalls ride on; orthogonal to storage substrate but the lock-ordering peer), [ADR-028](028-three-storage-models.md) (the three-models policy that this ADR is the implementation substrate for), [ADR-003](003-content-addressed-storage-and-identity.md) (CambiObject semantics; substrate is content-blind, identity is metadata-layer)
- **Supersedes:** N/A.
- **Context:** ADR-010 ratifies the CambiObject on-disk format; ADR-029 ratifies the POSIX file backend on-disk format. Both backends allocate blocks, journal metadata mutations, and hold a bitmap of allocated blocks. ADR-029 § Decision 1 originally declared "Shared block-allocation bitmap with the CambiObject backend" as the design intent, but the 5C-iii landing shipped per-backend `bitmap` and `journal` struct fields as a staging step — the codecs and lock-hierarchy positions were unified, but the *instances* stayed per-backend pending the kernel-singleton wire-up. This ADR closes that gap by making the shared substrate first-class: one superblock, one bitmap, one journal, one data region, with two metadata layers (CambiObject slot region, POSIX inode region) as views.

## Problem

Two backends, two substrates is the wrong shape for three load-bearing reasons:

### 1. CAMBIO at scale cannot afford to copy bytes

The synthesis ([storage-planning.md](../storage-planning.md)) names CAMBIO as the seam that converts a POSIX-mutable file into a sealed CambiObject. The v1 endgame target — Win-compat shims running QuickBooks-class workloads, document editors checkpointing working state, build systems sealing artifacts — produces multi-MB to multi-GB seals at workload rates. If CAMBIO is "read POSIX backend's bytes, allocate a CambiObject backend's bytes, copy across," the seal cost scales with the source size. With one shared data region and refcounted extents, CAMBIO becomes a pure metadata operation: copy the POSIX inode's extent list into a fresh CambiObject slot header, bump `cow_refcount` on the shared blocks, journal the transaction atomically. Zero byte copies regardless of file size.

### 2. Two bitmaps require their own coordination correctness claim

The "bitmap is the projection of committed journal records" verification claim ([ADR-029](029-posix-file-storage-model.md) § Verification Stance row 4) is a per-bitmap claim. With two backends each holding their own bitmap, the system gains an extra correctness obligation: "the two bitmaps never disagree on who owns block N." That obligation has no clean formulation when each backend allocates from its own partition. The two-substrate design either falls back to two partitions with disjoint LBA ranges (no shared block can exist; CAMBIO must copy per #1) or carries a cross-substrate-coordination invariant whose verification surface is its own state machine.

### 3. Substrate decisions deferred per-step accumulate sawtooth

The 5C/5D staging built bitmap + journal codecs at per-backend granularity because the singleton wire-up was deferred from 5C-ii to "step 6+." At step 6 planning the deferral re-fired ("kernel-heap-vs-journal mismatch"); at step 7 planning the deferral surfaces the shared-substrate question for real. Each deferral was locally rational; together they shipped code that step 7 has to rework. The substrate question has to be answered before more code lands on top of the per-backend assumption. Per [CLAUDE.md § "Build with the End in Mind"](../../CLAUDE.md), the sawtooth check rejects "ship the per-backend version, refactor later" as a v1-shape plan.

## Decision

A single unified substrate underneath both metadata layers.

### 1. Global superblock declaring all regions

At LBA 0..3 (one 16 KiB superblock spanning four blocks; aligned for future signature tail) lives the unified superblock. Magic: `CAMBIOFS\0` (8 bytes). Declares format version, capacity in blocks, region offsets for the bitmap, journal, POSIX inode region, CambiObject slot region, and shared data region. Generation counter bumped at mount. Single source of truth for layout; replaces the per-backend superblocks in ADR-010 and ADR-029.

```
LBA 0..3       Global superblock (16 KiB)
LBA 4..        Block-allocation bitmap (capacity_blocks / 8 / BLOCK_SIZE blocks)
LBA k..        Metadata journal (JOURNAL_BYTES = 16 MiB)
LBA m..        POSIX inode region (capacity_inodes × 2 blocks per inode)
LBA n..        CambiObject slot region (capacity_objects × 2 blocks per slot)
LBA p..        Shared data region (the only place file/object content bytes live)
```

POSIX inodes carry extent lists pointing into the shared data region (unchanged from ADR-029 § Decision 1). CambiObject slot headers carry extent lists pointing into the shared data region (new — ADR-010 v3, replaces inline content). Both metadata layers reference the same byte storage; neither owns it directly.

### 2. Shared block-allocation bitmap

One bitmap. Both backends call `STORAGE::allocate_block()` and `STORAGE::free_block()` through `BLOCK_BITMAP_LOCK(12)` (position established by ADR-029 § Divergence 2 in commit 5C-iii). The bitmap's bit-B-is-set-iff-block-B-is-allocated invariant holds globally across both metadata layers. Any block has at most one extent (in one metadata layer) claiming it; cross-backend stomping is structurally prevented by the single allocation path.

### 3. Shared metadata journal

One log at `JOURNAL_LOCK(13)`. Records carry an existing `JournalRecord` variant plus a 1-byte backend tag (`BACKEND_POSIX = 0x01`, `BACKEND_CAMBIO = 0x02`, `BACKEND_SHARED = 0x00` for substrate-only mutations like raw `ExtentUpdate` against `InodeId::new(0)`). Replay routes each record to the right metadata layer based on the tag. The "anything that affects which blocks are reachable is journaled; anything that affects what bytes are in a block is not" invariant (ADR-029 § Decision 5) holds globally.

Journal record kinds, by backend tag at replay:

- `InodeAllocate / InodeFree / DirectoryEntry / Rename / AclGrant / AclRevoke / LinkCountSet` — POSIX inode-layer; tag = `BACKEND_POSIX`.
- `CambioRecordPut / CambioRecordDelete` (new kinds, added with the ADR-010 v3 body edit) — CambiObject slot-layer; tag = `BACKEND_CAMBIO`.
- `ExtentUpdate` — substrate-level; tag identifies which metadata layer owns the extents being updated. CAMBIO transactions emit two `ExtentUpdate` records (one per backend tag) in one transaction.

### 4. Shared data region

The only place content bytes live. Both metadata layers' extent lists point here. Refcounting is owned by the substrate: `STORAGE::bump_extent_refcount(block)` / `STORAGE::drop_extent_refcount(block)`. When refcount reaches zero, `free_block` journals the bitmap clear. CAMBIO bumps the source POSIX inode's extents' refcounts and writes a CambiObject slot header pointing at the same blocks — the blocks now have two references (POSIX inode + CambiObject slot), each owning a refcount.

The refcount table itself is bounded SCAFFOLDING per CLAUDE.md Convention 8: `MAX_REFCOUNTED_EXTENTS` blocks tracked concurrently. Replace when CAMBIO concurrency at scale demands more than the bound (extrapolation: a backup tool snapshotting a 4 TiB working tree might hold up to 4 TiB / typical-extent-size frozen views; 1M extents is the 25%-rule headroom over that workload).

### 5. Per-backend metadata regions

POSIX inode region: ADR-029 § Decision 1's inode format (8 KiB per inode = header + reserved). Unchanged.

CambiObject slot region: ADR-010 v3's metadata-only slot header (magic + version + lineage + owner + signature + extent list). Content extracted to data region. Smaller per-slot than v2; same slot-region region-offset role.

## Architecture

`src/fs/storage/` module. Owns:

- The unified `Superblock` struct.
- The `BlockBitmap` instance (one, mutated only through `STORAGE::allocate_block` / `::free_block`).
- The `Journal` instance (one).
- The `ExtentRefcountTable` (one).
- `format(device, capacity_blocks, capacity_inodes, capacity_objects, now_ticks) -> STORAGE`.
- `mount(device) -> STORAGE` — runs journal replay, defense-in-depth bitmap cross-check, then reads the two metadata-region headers.

Kernel-runtime singleton: `pub static STORAGE: Spinlock<Option<StorageSubstrate<VirtioBlkDevice>>>` at `src/lib.rs`. Lock-hierarchy position: not a new top-level lock. Already covered by `BLOCK_BITMAP_LOCK(12)` and `JOURNAL_LOCK(13)`; `STORAGE` is the holder of those instances. Acquisition pattern:

- `BLOCK_BITMAP_LOCK(12)` for allocation primitives.
- `JOURNAL_LOCK(13)` for journal append + flush.
- `POSIX_STORE(11)` and `OBJECT_STORE(10)` are the metadata-layer locks; backends acquire their own top-level lock, then descend through `BLOCK_BITMAP_LOCK → JOURNAL_LOCK` for substrate operations.

Per-backend metadata layers (`PosixFsBackend`, `DiskObjectStore`) become *views* over `STORAGE`: they own their metadata-region state (inode-occupancy BTreeSet for POSIX, slot-header cache for CambiObject) but not bitmap or journal. Per-instance `bitmap` and `journal` struct fields disappear. Allocation and journaling route through `STORAGE`.

## Threat Model

### What this ADR protects against

| Threat | Mitigation |
|---|---|
| Cross-backend block reuse | One bitmap = one allocation path. A block allocated to a POSIX inode cannot be re-allocated to a CambiObject slot while the inode still holds an extent referencing it; the bitmap shows it as occupied regardless of which backend allocated it. |
| Crash mid-CAMBIO leaves the source inode without bumped refcount and the destination CambiObject orphaned | CAMBIO emits one journal transaction containing both the inode-side `ExtentUpdate` (refcount bump) and the slot-side `CambioRecordPut`; replay applies the full transaction or none of it. |
| Bitmap diverges between backends | Cannot occur structurally; there is one bitmap. |
| Journal replay races between backends | One journal, one replay loop; backend-tag routes each record. |

### What this ADR does NOT protect against

| Risk | Mitigation |
|---|---|
| Substrate-level corruption surfaces in both backends simultaneously | Accepted. The cost of unification is that a bitmap or journal bug affects both metadata layers. The verification claim per § Verification Stance below is the planned mitigation. |
| Disk-level physical corruption (bitrot, controller error) | Out of scope per ADR-029. Higher-layer concern. |

## Verification Stance

One substrate = one set of claims. The bitmap is the projection of committed journal records (proven once, applies to both metadata layers). Journal replay is a bounded loop over a fixed-size circular log (proven once). Bitmap-mutation idempotence is a property of the journal record format (proven once). All three claims are now substrate-level, not per-backend; the verification surface shrinks rather than grows when the second metadata layer lands.

Each metadata layer retains its own per-layer claims (POSIX inode format exhaustiveness, CambiObject record format exhaustiveness, per-layer ACL/auth check correctness). Those are unchanged from ADR-010 and ADR-029.

## Why Not Other Options

### Option A: Two separate substrates per backend (the 5C/5D shape)

Each backend owns its own bitmap, journal, and data region at its own LBA range.

**Why considered.** Simpler refactor from the current code; loose coupling between backends; bug in one's allocation path doesn't corrupt the other's view.

**Why rejected.** CAMBIO cannot be zero-copy without a cross-substrate reference scheme (which has its own verification surface); two bitmaps are two state machines to verify; the "shared bitmap" claim in ADR-029 § Decision 1 stays aspirational forever.

### Option B: POSIX as a thin layer over CambiObject (or the reverse)

POSIX inodes are stored as CambiObjects; every write produces a new CambiObject; the inode's "current bytes" is a hash pointer that updates on write.

**Why considered.** One backend instead of two.

**Why rejected.** Already rejected in ADR-029 § Why Not Other Options Option C ("forcing those workloads through content-addressing has real cost; version explosion; signing-overhead per write"). This ADR doesn't reopen that decision.

### Option C: Two backends, two substrates, two on-disk partitions with disjoint LBA ranges

Each backend gets its own region of the disk; no overlap; CAMBIO performs a byte copy across partition boundaries.

**Why considered.** Clean isolation; backwards-compatible with current per-backend codecs.

**Why rejected.** Per Option A's rejection — CAMBIO is structurally byte-copy, which collides with the v1-endgame scale target.

## Migration Path

1. **This ADR lands as Proposed.** Citations point to it from ADR-010 (Divergence preserving v2 in-line content format) and ADR-029 (Divergence preserving per-backend bitmap+journal staging).
2. **[ADR-010](010-persistent-object-store-on-disk-format.md) body edit lands** (v3 metadata-only slot header + extent list into shared data region; Divergence appendix preserves v2 format).
3. **[ADR-029](029-posix-file-storage-model.md) body edit lands** (substrate defers to ADR-031; Divergence appendix preserves the 5C-iii per-backend bitmap+journal staging).
4. **`src/fs/storage/` module lands**. Owns the unified superblock + bitmap + journal + extent refcount table. Format + mount paths.
5. **POSIX backend ports to substrate.** `PosixFsBackend` drops its `bitmap` and `journal` fields; calls route through `STORAGE`.
6. **CambiObject backend ports to v3.** `DiskObjectStore` writes v3 slot headers (metadata-only) over the shared data region.
7. **Dispatcher wire-up + libsys wrappers.** POSIX syscalls (53-72) get real handlers; CambiObject syscalls re-route through new substrate path.
8. **CoW + data path** (= original ADR-029 step 7). `SYS_FILE_READ/WRITE/SEEK/TRUNCATE/FSYNC`, `FrozenInodeView`, `cow_refcount` accounting. CAMBIO falls out as a pure metadata operation.

Each step independently bisectable.

## Cross-References

- **[ADR-010](010-persistent-object-store-on-disk-format.md)** — CambiObject metadata layer; v3 record format defined there; body edit lands alongside this ADR.
- **[ADR-028](028-three-storage-models.md)** — the three-models policy this ADR is the substrate for.
- **[ADR-029](029-posix-file-storage-model.md)** — POSIX metadata layer; body edit lands alongside this ADR.
- **[ADR-003](003-content-addressed-storage-and-identity.md)** — CambiObject semantics (content-addressing + identity stamping); substrate is content-blind, identity lives in the metadata layer.
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** — channel substrate the seam syscalls (CAMBIO, REGALO, STREAM per ADR-028 + ADR-030) ride on; orthogonal to storage substrate but lock-ordering peer.

## See Also in CLAUDE.md

When this ADR's implementation lands, the following CLAUDE.md sections update:

- **§ "Lock Ordering"** — note that `BLOCK_BITMAP_LOCK(12)` and `JOURNAL_LOCK(13)` instances are now owned by `STORAGE`, not by either metadata backend.
- **§ "Required Reading by Subsystem"** — add a row for "Unified storage substrate (bitmap, journal, data region)" pointing at this ADR.
- **§ "Design Documents"** — no new entry; this ADR is the design doc.

## Open Questions / Deferred

> **Deferred decision.** Extent refcount table on-disk persistence. v1 reconstructs the refcount table at mount time by scanning both metadata regions' extent lists. Scan cost is `O(capacity_inodes + capacity_objects)` blocks, bounded but linear. **Revisit when:** mount time exceeds a workload-driven threshold or a per-mount-incremental refcount snapshot becomes worth the on-disk cost.

> **Deferred decision.** Cross-backend transaction ordering beyond CAMBIO. ADR-028's three seams (CAMBIO, REGALO, STREAM) are the only cross-backend operations specified today. **Revisit when:** a fourth cross-backend operation is proposed.

> **Deferred decision.** Per-tier substrate sizing. The `capacity_inodes`, `capacity_objects`, `capacity_blocks` ratios are SCAFFOLDING choices. v1 picks balanced defaults; tier policy ([ADR-008](008-boot-time-sized-object-tables.md)/[ADR-009](009-purpose-tiers-scope.md)) may want to skew per workload. **Revisit when:** the first tier-specific workload demonstrates skew beyond defaults.
