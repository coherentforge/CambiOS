# ADR-010: Persistent ObjectStore — on-disk format

- **Status:** Accepted
- **Date:** 2026-04-14
- **Depends on:** [ADR-003](003-content-addressed-storage-and-identity.md) (Content-Addressed Storage), [ADR-004](004-cryptographic-integrity.md) (Blake3 + Ed25519)
- **Related:** [identity.md](../identity.md), [FS-and-ID-design-plan.md](../FS-and-ID-design-plan.md), [ADR-005](005-ipc-primitives-control-and-bulk.md)
- **Supersedes:** N/A

## Context

Phase 4 replaces the Phase 0 `RamObjectStore` with a disk-backed implementation behind the same `ObjectStore` trait. This ADR fixes the *on-disk format* that the disk-backed store reads and writes. It does not fix the transport (kernel vs fs-service, virtio-blk vs NVMe) — those are Phase 4a.iii and Phase 4b decisions. Once the format lands, it is the wire format between any pair of CambiOS instances that share storage, and between a given instance and its past self across reboot. Changing it is an ADR-level event.

The format's goals, in priority order:

1. **Crash consistency without a journal.** Power loss at any point leaves every object in either its pre-commit or post-commit state. No torn writes become valid records. A separate write-ahead log would be simpler to reason about in the abstract, but doubles the write amplification and adds a journal-replay code path that is itself a verification target. A record-commit-via-header-write design reaches the same consistency guarantees with one fewer moving part.
2. **Bounded iteration at mount.** Mount reconstructs the in-memory index by scanning every record slot once. The slot count is declared at format time and bounded by a compile-time constant, so iteration is a single for-loop with a statically-known bound — exactly the shape formal verification tools expect.
3. **No internal pointers.** Records do not reference other records by offset. Corruption localizes to one slot. Defragmentation is not a thing — there is nothing to defrag.
4. **Content-addressed deduplication preserved.** Same content hash → same slot. `put` is idempotent at the format level, matching the `ObjectStore` trait contract.
5. **Forward-compatible with ML-DSA signatures.** The record header reserves space for a 3293-byte post-quantum signature. The current Ed25519 signature field occupies the first 64 bytes; the remainder is reserved. The format version gate (`version: u32`) lets future records declare a different signature encoding without breaking old readers.

## Decision

### Layout

The disk is a contiguous array of 4 KiB blocks (LBAs). Block size matches the x86_64 page size and divides every common physical sector size cleanly; see `src/fs/block.rs` and ASSUMPTIONS.md for the `BLOCK_SIZE` rationale.

```
LBA 0       Superblock                         (1 block)
LBA 1..     Record slots, each slot = 2 blocks
            slot i starts at LBA 1 + 2*i
            slot i = header block + content block
```

The superblock declares the total slot capacity. There is no on-disk free-map: a slot is free iff its header block magic is not `ARCOREC1`. Mount scans every slot's header block; occupied headers are validated and added to the in-memory index. The O(n) scan is the price paid for dropping the free-map and making recovery stateless.

### Superblock (LBA 0, 4096 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `magic` | ASCII `"ARCOBJ00"` — format-family tag |
| 8 | 4 | `version` | u32 LE. Current = `1`. Mount rejects unknown versions. |
| 12 | 8 | `capacity_slots` | u64 LE. Declared at format time. Slots past `capacity_slots` must be unused. |
| 20 | 8 | `generation` | u64 LE. Bumped on every successful mount. Used to detect stale media swap (snapshot/rollback outside the OS). |
| 28 | 8 | `created_at` | u64 LE. Monotonic ticks at format time. |
| 36 | 4052 | *reserved* | Zero-filled. |
| 4088 | 8 | `checksum` | Blake3 hash of bytes `[0..4088]`, first 8 bytes. Validates the superblock itself. |

### Record (slot i: LBAs `1 + 2*i` and `2 + 2*i`)

**Header block** (LBA `1 + 2*i`, 4096 bytes):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `magic` | `"ARCOREC1"` = occupied. Any other value = free/never-written. |
| 8 | 4 | `content_len` | u32 LE. Length of content bytes. Must be `≤ BLOCK_SIZE`. |
| 12 | 32 | `content_hash` | Blake3(content). Primary identity. |
| 44 | 32 | `author` | Ed25519 public key. |
| 76 | 32 | `owner` | Ed25519 public key. |
| 108 | 1 | `sig_algo` | `0 = Ed25519`, `1 = ML-DSA-65` (reserved, Phase 4b+). |
| 109 | 1 | `lineage_present` | `0 = no lineage`, `1 = lineage field valid`. |
| 110 | 2 | `cap_count` | u16 LE. Number of active entries in `caps`, ≤ `MAX_OBJECT_CAPS`. |
| 112 | 8 | `created_at` | u64 LE. Monotonic ticks at put time. |
| 120 | 64 | `signature` | Ed25519 signature over `content`. ML-DSA migration reuses this field's *start*; the tail moves into `sig_tail` in a future version. |
| 184 | 32 | `lineage` | Parent content hash. Zero if `!lineage_present`. |
| 216 | 352 | `caps` | `MAX_OBJECT_CAPS = 8` entries × 44 bytes each. |
| 568 | 3520 | *reserved* | Zero-filled. Future ML-DSA signature tail lives here. |
| 4088 | 8 | `header_checksum` | Blake3 hash of bytes `[0..4088]`, first 8 bytes. |

Each `caps` entry (44 bytes):

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | `principal` |
| 32 | 8 | `expiry` (u64 LE, `0 = no expiry`) |
| 40 | 1 | `rights` (bit 0 = read, bit 1 = write, bit 2 = execute) |
| 41 | 3 | *reserved* (zero) |

**Content block** (LBA `2 + 2*i`, 4096 bytes):

| Offset | Size | Field |
|---|---|---|
| 0 | `content_len` | `content` bytes |
| `content_len` | `4096 - content_len` | Zero padding |

Content integrity is verified at read time by recomputing `blake3(content[..content_len])` and comparing against `header.content_hash`. No separate content checksum — `content_hash` *is* the checksum, and it's what the `ObjectStore` trait identifies the object by.

### Write protocol (commit by header magic)

**`put(obj)`**:

1. If `content_hash` is already in the in-memory index → return its hash (idempotent).
2. Allocate a free slot: first index `i` where the cached slot state is `Free`. Slot state is tracked in a small bit-vector alongside the hash → slot index map; no on-disk free-map.
3. Prepare the content block in a local 4 KiB buffer: `content[..content_len]` followed by zero padding.
4. `block_device.write_block(content_lba, &content_buf)`.
5. `block_device.flush()`.
6. Prepare the header block: `magic = "ARCOREC1"`, all metadata fields, `header_checksum = blake3(bytes[0..4088])[0..8]`.
7. `block_device.write_block(header_lba, &header_buf)`.
8. `block_device.flush()`.

The header write at step 7 is the *commit point*. Crash between 4 and 7 leaves the content block populated but the header reads as "free" — the slot is re-allocatable and the orphan content is overwritten on next use. Crash after 7 is a committed record.

**`delete(hash)`**:

1. Look up the slot.
2. Overwrite the header block with all zeros (magic is now not `ARCOREC1` → slot reads as free).
3. `block_device.flush()`.

The content block is left intact. This is not a secure erase — it is the microkernel equivalent of `unlink(2)`. Secure erase is a separate operation (not part of Phase 4a); any future secure-erase path writes the content block with a pattern before zeroing the header.

### Mount protocol

1. `block_device.read_block(0, &mut superblock_buf)`.
2. Verify `magic == "ARCOBJ00"` and `checksum` matches Blake3 of bytes `[0..4088]`.
3. If the device is blank (all zeros), call `format()` — write a fresh superblock and declare `capacity_slots` based on device capacity.
4. For slot `i` in `0..capacity_slots`:
   - `block_device.read_block(1 + 2*i, &mut header_buf)`.
   - If `magic != "ARCOREC1"` → slot is free, continue.
   - Verify `header_checksum` matches Blake3 of bytes `[0..4088]`. Mismatch → log and treat slot as free (the record was in flight at crash). Do *not* add to index.
   - Parse fields, add `(content_hash, i)` to the index.
5. Bump `generation` in the superblock, rewrite, flush.

Mount is idempotent: running it twice on the same consistent disk produces the same index.

### What is explicitly not in scope for this ADR

- **Garbage collection of orphan content blocks** (crashed puts that wrote content but not the header). These slots are allocatable again, and the next `put` to that slot overwrites the orphan. Explicit GC is not needed for correctness.
- **On-disk free-map.** The header-magic check replaces it.
- **Write-ahead log.** Not needed given the header-commit design.
- **Multi-block content.** `content_len ≤ BLOCK_SIZE` is a SCAFFOLDING limit, sized to match the current syscall ceiling. Phase 4b's channel-based bulk IPC protocol will raise this; the format gets a new `version = 2` at that point and records declare their content extent explicitly.
- **Encryption at rest.** ObjectStore stores already-signed objects — integrity is checked on every read. Confidentiality at rest is a higher-layer concern and out of scope.
- **Snapshots / CoW.** Not needed for v1; deferred indefinitely.

## Why not a write-ahead log?

The alternative is the classic journal: every mutation appends to a log; commit is a log record flush; periodic checkpoint copies the log into the main format. Considered and rejected for v1 because:

- **Write amplification.** Each `put` becomes two writes (log + data) instead of two writes (content + header) of the same size. The journal's write cost dominates when writes are small and numerous — which is exactly the CambiObject workload.
- **Replay is a verification target.** Log replay is a state machine that must be proved to restore every consistent state from every possible crash trace. The header-commit design's recovery is a single scan with a single invariant (`magic == "ARCOREC1"` → committed; else → free).
- **Throughput is not a v1 concern.** At 100 Hz audit events, a few user-space services, and human-scale object puts, the format is never write-bound. When it does become write-bound (video, AI model caches), the workload lives on the Phase 4b channel-based bulk path, not this kernel-side format.

A log can be added in a future version without breaking this format: old records remain valid, new records are staged through the log. That migration is not pre-planned but is not precluded either.

## Bounded iteration claim (for verification)

Mount's record scan is a `for i in 0..capacity_slots` loop. `capacity_slots` is declared in the superblock and bounded by `MAX_OBJECTS_ON_DISK` (SCAFFOLDING, documented in ASSUMPTIONS.md). No inner unbounded loop — each iteration does exactly one `read_block` + checksum check + optional index insertion. This satisfies the "no unbounded loops in kernel paths" rule in CLAUDE.md.

`put`'s free-slot scan is also bounded by `capacity_slots`. `delete`'s index lookup is a BTreeMap operation (O(log n)) with n ≤ `capacity_slots`.

## Cross-references

- `src/fs/block.rs` — `BlockDevice` trait, `MemBlockDevice`, `BLOCK_SIZE`.
- `src/fs/disk.rs` — `DiskObjectStore` (the reference reader/writer of this format).
- `src/fs/mod.rs` — `ObjectStore` trait, `CambiObject`, `SignatureBytes`.
- `ASSUMPTIONS.md` — `BLOCK_SIZE`, `MAX_OBJECTS_ON_DISK`, `MAX_CONTENT_BYTES_ON_DISK`, `ARCOBJ_MAGIC`, `ARCOREC_MAGIC_OCCUPIED`.
- [FS-and-ID-design-plan.md § Phase 4](../FS-and-ID-design-plan.md) — design intent for persistent storage.

## Divergence

Two things landed during Phase 4a.iii that deviate from the plan originally sketched alongside this ADR. Capturing them here so the ADR doesn't silently become fiction.

### 1. Plan/execute/commit decomposition not implemented

The plan called for decomposing `DiskObjectStore::{get,put,delete}` into `plan_*` (in-memory bookkeeping under `OBJECT_STORE`), `execute_*` (I/O lock-free), and `commit_*` (reacquire and update indices), motivated by concern about a hierarchy violation when a disk-backed `BlockDevice` call acquires `IPC_MANAGER` (lock position 3) while `OBJECT_STORE` (position 9) is held.

On closer inspection the concern doesn't materialize for the Phase 4a.iii wiring: the kernel-side `VirtioBlkDevice` uses `SHARDED_IPC` (per-endpoint shard locks, outside the main hierarchy) rather than `IPC_MANAGER`. The other lock the path acquires is `PER_CPU_SCHEDULER` (position 1) — which is per-CPU, never held by code that also acquires `OBJECT_STORE`, so the circular-wait that hierarchy rules prevent cannot form. Holding `OBJECT_STORE` across disk I/O is therefore safe; concurrent `SYS_OBJ_*` callers spin-wait on `OBJECT_STORE` until the holder's I/O completes, which is the serialization the single virtio-blk virtqueue imposes anyway.

The plan/execute surface on `ObjectStore` / `DiskObjectStore` was never added. The single-phase `get` / `put` / `delete` / `list` methods from Phase 4a.i remain the full trait. If a future backend shows a real hierarchy conflict (e.g. an `IPC_MANAGER`-using adapter), the decomposition can land then.

### 2. Kernel↔driver wait is poll-with-yield, not block+wake

The first implementation of `VirtioBlkDevice::call` mirrored the `src/policy/mod.rs` policy-router pattern: build the request, send via `SHARDED_IPC`, `block_local_task(BlockReason::MessageWait(25))`, `yield_save_and_switch`, resume on wake, dequeue the reply. The matching wake — a `wake_message_waiters(25)` invoked from the `handle_write` endpoint-25 intercept — empirically stalled the **virtio-blk driver's own self-test FLUSH**: the driver's virtqueue submit (unrelated to the wake code path) blocked for the full 200-yield timeout. Root cause was not conclusively characterized; the interaction between the cross-CPU `try_lock(PER_CPU_SCHEDULER)` in the wake loop and the driver's virtqueue `pop_used` polling is the most plausible candidate, but the investigation was not productive.

The fix adopted: `VirtioBlkDevice::call` polls `SHARDED_IPC.recv_message(25)` with cooperative `yield_save_and_switch` between attempts, up to `MAX_WAIT_ITERATIONS`. Uncontended case costs one yield round-trip vs the block+wake design. The kernel's caller task eventually hits idle, QEMU's TCG event loop advances the virtio-blk request, the driver replies, the reply lands in `SHARDED_IPC.shard[25]` via the `handle_write` intercept (which now does NOT call `wake_message_waiters`), and the kernel's next poll iteration finds it.

Documented here because future work (e.g. switching to interrupt-driven virtio-blk completion — the right long-term fix — or reusing this kernel↔user IPC pattern for other drivers) will need to revisit the decision. The `handle_write` intercept's `// NO scheduler wake —` comment names this ADR.

### 3. Shared block-allocation bitmap + journaled allocations + multi-block content (forecast for ADR-029 step 5)

- **Date:** 2026-05-12
- **Trigger:** [ADR-029](029-posix-file-storage-model.md) Decision 1 and Decision 5 establish a shared block-allocation bitmap and a journal-owned-bitmap invariant: every bitmap mutation, regardless of which backend triggered it, is journaled in the POSIX journal. For ADR-010 to remain coherent with this invariant, the CambiObject backend's allocation path must route through the shared journal. Without this Divergence, the invariant has a CambiObject-side hole, and ADR-029's Verification Stance claim "bitmap state is the projection of committed journal records" is false.

This Divergence is forecast (not yet implemented). It lands concurrently with [ADR-029](029-posix-file-storage-model.md) migration step 5 - the simultaneous landing is what keeps the journal-owned-bitmap invariant whole from the moment the shared bitmap exists. Listed in the ADR before code so future readers reach for ADR-010 and find the planned trajectory rather than re-deriving it from ADR-029's migration path.

#### What changes

1. **Allocation routing.** CambiObject `put` operations no longer perform direct on-disk bitmap mutations for content-block allocation. The allocation is recorded in a journal record of type `ExtentUpdate + BitmapMutation` (per ADR-029 Decision 5), atomically with the CambiObject record's header commit. Until the journal record is durable, the bitmap is in-memory-only and the allocation is not visible on disk. The `BLOCK_BITMAP_LOCK` (hierarchy position 12 per ADR-029) governs the in-memory bitmap; the CambiObject backend acquires `OBJECT_STORE → BLOCK_BITMAP_LOCK` for allocation operations.

2. **Multi-block content layout.** The `content_len <= BLOCK_SIZE` SCAFFOLDING constraint from "What is explicitly not in scope" is lifted. CambiObject records gain a header-resident bounded-extent array (up to 16 extents per object, each `(start_lba: u64, block_count: u32)`, matching ADR-029's inode extent shape). Content data blocks live in the shared data region and are referenced by the extent array, replacing the single per-slot content block.

3. **Layout restructuring.** v1's slot pattern was "header block + content block, slot stride = 2 blocks." For v2 records, the slot stride remains 2 blocks but the second block changes role from "content" to "reserved tail" (zero-filled in v1, reserved for the ML-DSA signature tail when PQ signing lands - matching ADR-029's inode layout). The header block's existing 3520-byte reserved region is partitioned: 192 bytes (offset 568..760) for the extent array, 3328 bytes (760..4088) retained for ML-DSA + future extensions. Actual content bytes live in the shared data region per the extent array. Mount distinguishes v1 records (`version = 1`, content in slot's second block) from v2 records (`version = 2`, content via extents) and reads both indefinitely.

4. **Format version handling.** New puts default to v2 once this Divergence lands. v1 records remain readable forever; because CambiObjects are immutable, there is no "next write that updates the record" - v1 records stay v1 unless an explicit migration utility runs. A migration tool for storage-density reasons may land later but is not a v1 requirement.

#### What does not change

- **CambiObject identity.** Content-addressed, signed-by-owner, immutable author, transferable owner, lineage chain - all preserved.
- **Signature verification.** Blake3 + Ed25519 verification on every read, preserved unchanged.
- **ACL model.** `ObjectCapSet` (up to 8 entries) per ADR-003 unchanged.
- **Magic-byte commit pattern.** `ARCOREC1` magic at offset 0 still distinguishes occupied vs. free records. The header still commits via the existing pattern; what is new is the *allocation* of data blocks under that header, which now flows through the shared journal.
- **No-write-after-put semantics.** CambiObjects remain immutable. The extent array is determined at put time and never mutates.
- **Plan/execute/commit decomposition.** Still not implemented (per Divergence 1). Shared-bitmap allocation does not change this; the existing single-phase `put` continues to suffice, with the journal record now bundling extent-list + bitmap mutations as ADR-029 Decision 5 specifies.

#### Sequencing

Forecast for landing with [ADR-029](029-posix-file-storage-model.md) migration step 5. Until that step lands, ADR-010 v1's `content_len <= BLOCK_SIZE` constraint and direct bitmap writes remain in force. The CambiObject backend's allocation path crosses over to journaled bitmap mutations as a single coordinated change with the POSIX backend's step-5 implementation; the same commit (or commit pair) lands both backends' allocation routing through the shared journal.

#### Why a Divergence rather than a superseding ADR

The CambiObject model, the on-disk record's existing fields, the magic-byte commit pattern, and the signature verification are ADR-010's core decisions and remain unchanged. What changes is the *allocation mechanism* (now journaled), the *content layout* (extent-based multi-block), and the *slot composition* (header block + reserved tail; content in shared data region). A Divergence appendix captures the implementation-shape change without rewriting the immutable decision text. A superseding ADR would imply ADR-010's decisions are being walked back, which they are not.
