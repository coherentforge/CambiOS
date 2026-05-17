# ADR-010: Persistent ObjectStore — on-disk format

- **Status:** Accepted
- **Date:** 2026-04-14 (original ADR landing); body rewritten 2026-05-17 alongside ADR-031 ratification
- **Depends on:** [ADR-003](003-content-addressed-storage-and-identity.md) (Content-Addressed Storage), [ADR-004](004-cryptographic-integrity.md) (Blake3 + Ed25519), [ADR-031](031-unified-storage-substrate.md) (shared bitmap + journal + data region that this metadata layer rides on)
- **Related:** [identity.md](../identity.md), [FS-and-ID-design-plan.md](../FS-and-ID-design-plan.md), [ADR-005](005-ipc-primitives-control-and-bulk.md), [ADR-029](029-posix-file-storage-model.md) (peer metadata layer over the same substrate)
- **Supersedes:** N/A

## Context

ADR-010 specifies the on-disk format for **CambiObject metadata** — the slot region that the `ObjectStore` trait reads and writes. The substrate underneath (block-allocation bitmap, metadata journal, shared data region) is owned by [ADR-031](031-unified-storage-substrate.md). This ADR is the metadata layer; ADR-031 is the substrate they sit over.

The split is load-bearing: CambiObject records and POSIX inodes ([ADR-029](029-posix-file-storage-model.md)) are two metadata layers over one substrate. Content bytes live exactly once, in the substrate's shared data region; both metadata layers' extent lists point at them. CAMBIO (the seam syscall that seals a POSIX file as a signed CambiObject per [ADR-028](028-three-storage-models.md)) is therefore a pure metadata operation — copy the POSIX inode's extent list into a fresh CambiObject slot, sign, journal atomically — with no byte copy. Once the format and substrate land, the format is the wire format between any pair of CambiOS instances that share storage, and between a given instance and its past self across reboot. Changing it is an ADR-level event.

The format's goals, in priority order:

1. **Metadata-layer separation.** CambiObject records carry identity (author, owner), integrity (Blake3 + Ed25519 signature), cap inventory, lineage, and an extent list. They don't carry content bytes; those live in the substrate's shared data region. The metadata is the verification target; the substrate handles bytes.
2. **Bounded iteration at mount.** Slot-region scan reconstructs the in-memory occupancy view over `capacity_objects` slots — a single `for` loop with a statically-known bound, matching the formal-verification shape.
3. **No internal pointers between records.** Records do not reference other records by offset. Corruption localizes to one slot. Defragmentation is not a thing.
4. **Content-addressed deduplication preserved.** Same content hash → same slot. `put` is idempotent at the format level, matching the `ObjectStore` trait contract.
5. **Forward-compatible with ML-DSA signatures.** The record header reserves space for a post-quantum signature tail. The current Ed25519 signature occupies the first 64 bytes of the `signature` field; the remainder of the slot's reserved tail block is held for ML-DSA migration.

## Decision

### Layout (slot region)

The disk is a contiguous array of 4 KiB blocks. ADR-031's global superblock at LBA 0..3 declares all region offsets; this ADR concerns the **slot region**, declared by the superblock's `cambio_slot_region_lba` and `capacity_objects` fields:

```
LBA cambio_slot_region_lba..   CambiObject slots, each slot = 2 blocks
                               slot i = header block + reserved tail block
                               slot i header at cambio_slot_region_lba + 2*i
                               slot i reserved tail at cambio_slot_region_lba + 2*i + 1
```

A slot is free iff its header block magic is not `ARCOREC2`. Mount scans every slot's header block; occupied headers are validated and added to the in-memory index. Content bytes are not in the slot region — they live in the substrate's shared data region (per [ADR-031](031-unified-storage-substrate.md)) and are referenced by the header's extent array. Slot count and slot-region offset are bounded by `MAX_OBJECTS_ON_DISK` (SCAFFOLDING, [docs/ASSUMPTIONS.md](../ASSUMPTIONS.md)).

### Record (slot i)

**Header block** (LBA `cambio_slot_region_lba + 2*i`, 4096 bytes):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `magic` | `"ARCOREC2"` = occupied. Any other value = free/never-written. `ARCOREC1` (v1) is recognized by `get` magic-dispatch for backward read; new puts always produce `ARCOREC2`. |
| 8 | 4 | `content_len` | u32 LE. Length of content bytes addressed by the extent array. |
| 12 | 32 | `content_hash` | Blake3(content). Primary identity. |
| 44 | 32 | `author` | Ed25519 public key. |
| 76 | 32 | `owner` | Ed25519 public key. |
| 108 | 1 | `sig_algo` | `0 = Ed25519`, `1 = ML-DSA-65` (reserved). |
| 109 | 1 | `lineage_present` | `0 = no lineage`, `1 = lineage field valid`. |
| 110 | 2 | `cap_count` | u16 LE. Number of active entries in `caps`, ≤ `MAX_OBJECT_CAPS`. |
| 112 | 8 | `created_at` | u64 LE. Monotonic ticks at put time. |
| 120 | 64 | `signature` | Ed25519 signature over `content`. ML-DSA migration extends into the reserved region. |
| 184 | 32 | `lineage` | Parent content hash. Zero if `!lineage_present`. |
| 216 | 352 | `caps` | `MAX_OBJECT_CAPS = 8` entries × 44 bytes each. |
| 568 | 192 | `extents` | 16 entries × 12 bytes packed: `(start_lba: u64, block_count: u32)`. Points into the substrate's shared data region per [ADR-031](031-unified-storage-substrate.md). |
| 760 | 3328 | *reserved* | Zero-filled. Future ML-DSA signature tail lives here. |
| 4088 | 8 | `header_checksum` | Blake3 hash of bytes `[0..4088]`, first 8 bytes. |

Each `caps` entry (44 bytes):

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | `principal` |
| 32 | 8 | `expiry` (u64 LE, `0 = no expiry`) |
| 40 | 1 | `rights` (bit 0 = read, bit 1 = write, bit 2 = execute) |
| 41 | 3 | *reserved* (zero) |

**Reserved tail block** (LBA `cambio_slot_region_lba + 2*i + 1`, 4096 bytes): zero-filled. Reserved for ML-DSA signature tail when PQ signing lands. Symmetric with [ADR-029](029-posix-file-storage-model.md)'s POSIX inode reserved-tail allocation.

Content integrity is verified at read time by reading content through the extent array and recomputing `blake3(content[..content_len])` against `header.content_hash`. No separate content checksum — `content_hash` *is* the checksum, and it's what the `ObjectStore` trait identifies the object by.

### Write protocol (substrate-anchored)

**`put(obj)`**:

1. If `content_hash` is already in the in-memory index → return its hash (idempotent).
2. Allocate a free slot: first index `i` where the cached slot state is `Free`. Slot state is tracked in a bit-vector alongside the hash → slot index map; no on-disk slot-free-map.
3. Allocate data-region extents via `STORAGE::allocate_block` (one call per extent; up to `MAX_EXTENTS_PER_CAMBIOBJECT = 16`). Each call journals a substrate-tagged `ExtentUpdate + BitmapMutation::Set` record per [ADR-031](031-unified-storage-substrate.md) § Decision 3.
4. Write content bytes through the allocated extents (`block_device.write_block` for each block, `block_device.flush()` after).
5. Build the header in a 4 KiB buffer: magic = `ARCOREC2`, metadata fields, extent array from step 3, `header_checksum = blake3(bytes[0..4088])[0..8]`.
6. Journal a `CambioRecordPut` record (backend-tag = `BACKEND_CAMBIO`) covering the slot index + header bytes. Per ADR-031 § Decision 3, this is the commit point for the slot-layer mutation.
7. `block_device.write_block(slot_header_lba, &header_buf)`.
8. `block_device.flush()`.

The journal record at step 6 is the *commit point*. Crash between 3 and 6 leaves data-region blocks allocated in the bitmap (journal replay re-applies the bitmap-set) but no slot points at them; the next mount's defense-in-depth cross-check surfaces the orphaned blocks via the [ADR-031](031-unified-storage-substrate.md) substrate replay. Crash between 6 and 7 replays the `CambioRecordPut` record on next mount, which carries the slot index + header bytes; the substrate-layer replay reconstructs the slot header from the journal record. Crash after 8 is a fully-committed record.

**`delete(hash)`**:

1. Look up the slot.
2. Journal a `CambioRecordDelete` record (backend-tag = `BACKEND_CAMBIO`) carrying the slot index.
3. Journal `BitmapMutation::Clear` for each block referenced by the deleted record's extent array (via `STORAGE::free_block`). The journal records and the `CambioRecordDelete` are bundled into one transaction per [ADR-031](031-unified-storage-substrate.md) § Decision 3.
4. Overwrite the slot header block with zeros (magic is now not `ARCOREC2` → slot reads as free).
5. `block_device.flush()`.

The data-region blocks become free per substrate accounting. This is not a secure erase; it is the microkernel equivalent of `unlink(2)`. Secure erase is a separate operation; any future secure-erase path overwrites the data extents with a pattern before clearing the bitmap.

### Mount protocol

ADR-031's `STORAGE::mount` runs first: parse global superblock, journal-replay, defense-in-depth bitmap cross-check. After STORAGE is mounted:

1. For slot `i` in `0..capacity_objects`:
   - `block_device.read_block(cambio_slot_region_lba + 2*i, &mut header_buf)`.
   - If `magic` is neither `ARCOREC1` (v1, magic-dispatched for read) nor `ARCOREC2` → slot is free, continue.
   - Verify `header_checksum` matches Blake3 of bytes `[0..4088]`. Mismatch → log and treat slot as free (the record was in flight at crash). Do *not* add to index.
   - Parse fields, add `(content_hash, i)` to the index.

Mount is idempotent: running it twice on the same consistent disk produces the same index.

### What is explicitly not in scope for this ADR

- **Garbage collection of orphan data-region blocks** (crashed puts that allocated extents but didn't commit the slot). Substrate replay surfaces these; explicit GC is a substrate concern, not metadata-layer.
- **On-disk slot-free-map.** The header-magic check replaces it.
- **Encryption at rest.** ObjectStore stores already-signed objects — integrity is checked on every read. Confidentiality at rest is provided by the FDE layer below the substrate (forthcoming ADR; not in this ADR's scope). At-rest integrity at the block layer is *not* provided — CambiObject Blake3 verification covers CambiObject content; POSIX-namespace content has no block-level adversarial-integrity check (see ADR-029's threat model).
- **Snapshots / CoW.** CoW lives in [ADR-029](029-posix-file-storage-model.md) § Decision 2 (POSIX-side) and the CAMBIO seam (cross-backend). CambiObjects are immutable; no per-record CoW is needed.

## Bounded iteration claim (for verification)

Mount's slot scan is a `for i in 0..capacity_objects` loop. `capacity_objects` is declared in ADR-031's superblock and bounded by `MAX_OBJECTS_ON_DISK` (SCAFFOLDING, see [docs/ASSUMPTIONS.md](../ASSUMPTIONS.md)). No inner unbounded loop — each iteration does exactly one `read_block` + checksum check + optional index insertion. This satisfies the "no unbounded loops in kernel paths" rule in CLAUDE.md.

`put`'s free-slot scan is also bounded by `capacity_objects`. `delete`'s index lookup is a BTreeMap operation (O(log n)) with n ≤ `capacity_objects`. Substrate-level claims (bitmap-is-projection-of-journal, bounded journal replay) live in [ADR-031](031-unified-storage-substrate.md) § Verification Stance.

## Cross-references

- [`src/fs/block.rs`](../../src/fs/block.rs) — `BlockDevice` trait, `MemBlockDevice`, `BLOCK_SIZE`.
- [`src/fs/disk.rs`](../../src/fs/disk.rs) — `DiskObjectStore` (the reference reader/writer of this format).
- [`src/fs/mod.rs`](../../src/fs/mod.rs) — `ObjectStore` trait, `CambiObject`, `SignatureBytes`.
- [`src/fs/storage/`](../../src/fs/storage/) (when ADR-031 lands) — the substrate module that owns bitmap + journal + data region.
- [docs/ASSUMPTIONS.md](../ASSUMPTIONS.md) — `BLOCK_SIZE`, `MAX_OBJECTS_ON_DISK`, `MAX_CONTENT_BYTES_ON_DISK`, `ARCOREC_MAGIC_OCCUPIED`, `MAX_EXTENTS_PER_CAMBIOBJECT`.
- [ADR-031](031-unified-storage-substrate.md) — the substrate this metadata layer rides on.
- [ADR-029](029-posix-file-storage-model.md) — peer metadata layer (POSIX inodes) over the same substrate.
- [FS-and-ID-design-plan.md § Phase 4](../FS-and-ID-design-plan.md) — historical design intent for persistent storage.

## Divergence

### 1. Plan/execute/commit decomposition not implemented

The plan called for decomposing `DiskObjectStore::{get,put,delete}` into `plan_*` (in-memory bookkeeping under `OBJECT_STORE`), `execute_*` (I/O lock-free), and `commit_*` (reacquire and update indices), motivated by concern about a hierarchy violation when a disk-backed `BlockDevice` call acquires `IPC_MANAGER` (lock position 3) while `OBJECT_STORE` (position 10) is held.

On closer inspection the concern doesn't materialize for the Phase 4a.iii wiring: the kernel-side `VirtioBlkDevice` uses `SHARDED_IPC` (per-endpoint shard locks, outside the main hierarchy) rather than `IPC_MANAGER`. The other lock the path acquires is `PER_CPU_SCHEDULER` (position 1) — which is per-CPU, never held by code that also acquires `OBJECT_STORE`, so the circular-wait that hierarchy rules prevent cannot form. Holding `OBJECT_STORE` across disk I/O is therefore safe; concurrent `SYS_OBJ_*` callers spin-wait on `OBJECT_STORE` until the holder's I/O completes, which is the serialization the single virtio-blk virtqueue imposes anyway.

The plan/execute surface on `ObjectStore` / `DiskObjectStore` was never added. The single-phase `get` / `put` / `delete` / `list` methods from Phase 4a.i remain the full trait. If a future backend shows a real hierarchy conflict (e.g. an `IPC_MANAGER`-using adapter), the decomposition can land then.

### 2. Kernel↔driver wait is poll-with-yield, not block+wake

The first implementation of `VirtioBlkDevice::call` mirrored the `src/policy/mod.rs` policy-router pattern: build the request, send via `SHARDED_IPC`, `block_local_task(BlockReason::MessageWait(25))`, `yield_save_and_switch`, resume on wake, dequeue the reply. The matching wake — a `wake_message_waiters(25)` invoked from the `handle_write` endpoint-25 intercept — empirically stalled the **virtio-blk driver's own self-test FLUSH**: the driver's virtqueue submit (unrelated to the wake code path) blocked for the full 200-yield timeout. Root cause was not conclusively characterized; the interaction between the cross-CPU `try_lock(PER_CPU_SCHEDULER)` in the wake loop and the driver's virtqueue `pop_used` polling is the most plausible candidate, but the investigation was not productive.

The fix adopted: `VirtioBlkDevice::call` polls `SHARDED_IPC.recv_message(25)` with cooperative `yield_save_and_switch` between attempts, up to `MAX_WAIT_ITERATIONS`. Uncontended case costs one yield round-trip vs the block+wake design. The kernel's caller task eventually hits idle, QEMU's TCG event loop advances the virtio-blk request, the driver replies, the reply lands in `SHARDED_IPC.shard[25]` via the `handle_write` intercept (which now does NOT call `wake_message_waiters`), and the kernel's next poll iteration finds it.

Documented here because future work (e.g. switching to interrupt-driven virtio-blk completion — the right long-term fix — or reusing this kernel↔user IPC pattern for other drivers) will need to revisit the decision. The `handle_write` intercept's `// NO scheduler wake —` comment names this ADR.

### 3. Shared block-allocation bitmap + journaled allocations + multi-block content (per-backend staging)

- **Date forecast:** 2026-05-12
- **Date landed:** 2026-05-16

The 5D commit chain (commits 0ea9c45..9c83ba3) landed v2 records with multi-block content via extents into a per-backend data region, plus per-backend `bitmap: BlockBitmap` and `journal: Journal` struct fields on `DiskObjectStore`. The "shared block-allocation bitmap" wording in this ADR's body, and in [ADR-029](029-posix-file-storage-model.md) § Decision 1, was load-bearing aspirationally — the codecs and record format anticipated shared substrate, but the *instances* of bitmap and journal stayed per-backend pending the kernel-singleton wire-up.

**This Divergence is now historical.** The current body describes v2 records over the shared substrate per ADR-031, which is superseded by [Divergence 4](#4-shared-substrate-per-adr-031) below. This entry is retained for the trajectory: v2 record format was specified here (Divergence 3) and substrate-ratified there (Divergence 4).

The original Divergence 3 wording's "What changes" had four items: (1) allocation routing through the shared journal, (2) multi-block content via extents, (3) layout restructuring with reserved tail and extent array, (4) format-version handling via magic-byte dispatch. Items 2-4 are unchanged in the current body. Item 1 (allocation routing) is the part [Divergence 4](#4-shared-substrate-per-adr-031) makes literal via ADR-031.

The original Divergence 3 also carried a "Known implementation drift: crash-safety atomicity" note (write order content → header → journal could orphan data blocks on crash). That gap is closed by ADR-031's `CambioRecordPut` journal-record-as-commit-point pattern (per the rewritten Write protocol in this body).

### 4. Shared substrate per ADR-031

- **Date:** 2026-05-17
- **Trigger:** [ADR-031](031-unified-storage-substrate.md) ratification of the unified storage substrate.

#### What changes (relative to Divergence 3)

Divergence 3 (5D, 2026-05-16) shipped v2 records with per-backend bitmap and journal. The "shared block-allocation bitmap" claim it made was load-bearing aspirationally but per-backend in practice — `DiskObjectStore` carried `bitmap: BlockBitmap` and `journal: Journal` struct fields.

This Divergence makes the substrate first-class per ADR-031. `DiskObjectStore` drops the `bitmap` and `journal` fields; allocations route through `STORAGE` (the substrate singleton). v2 record format (`ARCOREC2` magic, header + reserved tail + extents into data region) is unchanged byte-for-byte; what changes is *which* data region the extents point into (now the shared data region per ADR-031, previously the per-backend data region) and *how* allocation is journaled (now substrate-tagged through `STORAGE`).

The write-protocol body section above describes the substrate-anchored flow. The `CambioRecordPut` and `CambioRecordDelete` journal record kinds (new with this Divergence) are added to the journal record enum per ADR-031 § Decision 3.

#### What does not change

v2 record format byte layout (offsets, sizes, field semantics); content addressing (Blake3); signature model (Ed25519); ObjectRights bitfield; lineage; ARCSIG trailer behavior; magic-byte commit pattern; CambiObject immutability.

#### Why

ADR-031 closes the per-vs-shared-substrate gap by making one substrate underneath both metadata layers (CambiObject + POSIX). The CambiObject backend's v2 records become metadata-only views over the shared substrate. The plus side: zero-copy CAMBIO (per ADR-031 § Problem), one verification surface for bitmap-is-projection-of-journal (per ADR-031 § Verification Stance), and the journal-record-as-commit-point pattern closes Divergence 3's "Known implementation drift" gap.

#### What does not migrate

No conversion tool. v2 disks formatted by 5D code that used the per-backend substrate exist only in dev environments; reformatting under ADR-031's new global superblock is acceptable per the pre-user-period rule (see CLAUDE.md § "Build with the End in Mind"). A `DiskObjectStore::mount` that encounters a 5D-shaped per-backend superblock returns `FormatVersion` error; `format` produces the ADR-031 substrate-shaped layout.
