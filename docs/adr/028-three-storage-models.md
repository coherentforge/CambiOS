# ADR-028: Three Storage Models: Kernel-API Type Discipline and Seam Syscalls

- **Status:** Proposed
- **Date:** 2026-05-11
- **Depends on:** [ADR-003](003-content-addressed-storage-and-identity.md) (CambiObject + ObjectStore - the native storage model this ADR adds two co-equal models alongside), [storage-planning.md](../storage-planning.md) (the synthesis this ADR ratifies)
- **Related:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (channel substrate the Stream model rides on), [ADR-010](010-persistent-object-store-on-disk-format.md) (CambiObject on-disk format; the POSIX backend's follow-on takes the same shape under ADR-029), [ADR-016](016-win-compat-api-ai-boundary.md) (primary downstream consumer of the POSIX model), [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (the cap-shape duality this ADR generalizes from caps to storage), [ADR-027](027-service-clusters.md) (clusters can scope POSIX-file namespaces and Stream caps just as they scope CambiObjects; cluster-scoped sandboxing is the deployment-level companion to Stream's cap-level containment)
- **Supersedes:** N/A - [ADR-003](003-content-addressed-storage-and-identity.md) gets a Divergence appendix when this ADR ratifies (narrowing the "files are not bytes-at-a-path" claim without altering the CambiObject model).
- **Context:** [storage-planning.md](../storage-planning.md) (2026-05-09) named three first-class CambiOS storage models - CambiObject (immutable, content-addressed, signed), POSIX file (mutable, path-named), and Stream (transient, capability-bounded flow) - and the three seams that cross between them: CAMBIO (file → object), REGALO (object → file-view, read-only), STREAM ({object, file} → flow). The synthesis ratified the framing. This ADR commits to the kernel-API shape that makes the model split structural rather than conventional: three distinct kernel handle types, three new seam syscalls, and a path-namespace convention that visually signals which world a consumer is in. On-disk format for the POSIX backend is deferred to ADR-029; the full Stream cap shape is deferred to ADR-030.

## Problem

The synthesis names three models and three seams but does not specify the kernel API. Without API-level type discipline, the architecture-aware-duality property leaks: a polymorphic "file" handle that accepts both objects and POSIX files re-introduces the same conflation pressure the synthesis explicitly excluded. Three concrete gaps motivate this ADR.

### Gap 1 - Handle polymorphism would erase the model boundary

Today `ObjectStore` is the only storage trait in [src/fs/mod.rs](../../src/fs/mod.rs). When the POSIX backend lands, a tempting first move is a parent trait (`Storage`) with `Object` and `File` as implementations. That move is the failure mode the synthesis already excluded - once a kernel API accepts a `Storage` handle, callers stop knowing whether the bytes underneath them are immutable, mutable, or transient, and the structural property collapses into a runtime check. The fix is no polymorphic trait at all. Three handle types, three syscall surfaces.

### Gap 2 - Path resolution must be honest about which world it crossed into

A legacy or POSIX-shaped consumer reaches storage by `open()`-ing a path. If both POSIX files and CambiObject views live under `/`, nothing in the path signals which model the consumer just bound to. A buggy app that expects writes to land in a POSIX file but actually opens a REGALO mount sees EROFS-on-write; a security-sensitive app that expects a sealed-content read but actually opened a mutable file sees the wrong invariants. The path-namespace must carry the diagnostic.

### Gap 3 - Seam operations need explicit syscalls, not implicit promotion

The synthesis is emphatic: seams are never implicit. CAMBIO is a workflow event, not a side-effect of a mutable write. REGALO is an explicit mount, not a transparent fallback when an object is referenced by path. STREAM is an explicit open with cap-shape bounds, not the kernel "detecting that no persistence is needed." Three new syscalls. Each carries its own preconditions, capability checks, and outcomes.

## The Reframe

> A storage handle in CambiOS is one of three distinct kernel-API types: an **ObjectHandle** (CambiObject), a **FileDescriptor** (POSIX file), or a **StreamEndpoint** (Stream). The kernel never returns a handle that could be any of these depending on what the caller did later. The type at the API surface is the type at the storage layer, decided at the syscall that produced the handle. The seams between models - CAMBIO, REGALO, STREAM - are the only kernel-mediated crossings, each with its own syscall, its own preconditions, and its own atomic-or-fail semantics. There is no polymorphic "file" syscall surface and no implicit-promotion path between models.

The reframe is the cap-shape duality from [ADR-026](026-identity-transcription-at-the-kernel-ring.md) generalized one level up. Cap handles inside the kernel are `(endpoint, rights)`; rich external envelopes live at the boundary. Storage handles inside the kernel are typed; rich path-shaped or content-addressed external views live at the boundary, mediated by REGALO and the canonical CambiObject mount. The kernel is mechanical in both cases; userspace and documentation translate at the seams.

## Decision

Five commitments. They are co-dependent: each makes the others coherent.

### 1. Three distinct kernel handle types - no polymorphic trait

```rust
/// CambiObject handle. Returned by ObjPut / ObjGet / ObjList.
/// Backed by ObjectStoreBackend per ADR-003 § Divergence.
pub struct ObjectHandle { hash: [u8; 32], rights: ObjectRights, generation: u32 }

/// POSIX file descriptor. Returned by file_open / file_create.
/// Backed by the POSIX file backend per ADR-029 OR by a CambiObject view (REGALO / canonical mount).
pub struct FileDescriptor { fd: u32, rights: FileRights, backing: FileBacking, generation: u32 }

/// Stream endpoint. Returned by SYS_STREAM (this ADR § 3).
/// Backed by the channel substrate per ADR-005, with cap-shape bounds per ADR-030.
pub struct StreamEndpoint { stream_id: u32, role: StreamRole, generation: u32 }

/// FileDescriptor backing. Resolved at file_open time; static for handle lifetime.
/// v1 shape the Kani harness targets; final layout owned by ADR-029.
pub enum FileBacking {
    /// Mutable POSIX file in the POSIX file backend (ADR-029).
    Posix,
    /// Immutable CambiObject view; bytes resolved via ObjectStoreBackend::get on read.
    ObjectView { hash: [u8; 32], source: ViewSource },
}

pub enum ViewSource {
    /// Reached via the /co/<hex-hash> canonical mount.
    Canonical,
    /// Reached via a REGALO alias.
    Regalo(RegaloId),
}
```

There is no `Storage` trait that abstracts over the three. There is no kernel API that accepts "any storage handle." The three types live in three separate modules (`fs::object`, `fs::posix`, `fs::stream`); the corresponding syscalls dispatch from three separate `SyscallNumber` ranges; the corresponding capability checks live in three separate code paths.

Conflation between *models* is structurally absent at the kernel boundary because no syscall returns "a handle whose underlying model could be either object or stream depending on later behavior." The added complexity carries structural load.

**`FileDescriptor` admits two storage backings.** The `backing` field records whether the descriptor points at a mutable POSIX file or at an immutable CambiObject view (from REGALO or the canonical `/co/<hash>` mount). The handle type stays uniform across both, and the contract (path-keyed, writes may fail) is uniform - analogous to how POSIX `O_RDONLY` admits both writable filesystems and read-only mounts under one descriptor type. The variation is in *backing storage*, not in *handle type or contract*. Writes against an immutable backing terminate uniformly in `EROFS` (or its CambiOS analog) before any backend operation runs. This is consistent with the type discipline because the *model* a developer is reasoning about (POSIX-shape, path-keyed, possibly read-only) does not vary; only the backend supplying bytes does. See § Architecture / Userspace module structure for the developer-experience elaboration.

This commitment retains [ADR-003 § Divergence](003-content-addressed-storage-and-identity.md#divergence)'s enum-dispatch posture for the `ObjectStore` trait *within* the object subsystem (`ObjectStoreBackend` matches over `Ram` / `LazyDisk` backends). That trait remains the specification for what every CambiObject backend must implement. It does *not* grow to admit POSIX files or Stream sources.

### 2. Path-namespace convention

The path namespace tells a consumer which world they are in. Four rules:

- **Canonical CambiObject mount: `/co/<hex-hash>`.** Every CambiObject the calling process has read-cap on is reachable at this path without prior REGALO. The path-resolver recognizes the `/co/` prefix, parses the hex hash, looks up the object in the ObjectStore backend, and serves a read-only file-view of the content. The path is deterministic, content-derived, and visually diagnostic - a `/co/` prefix means "you are reading a sealed object."
- **REGALO mounts are user-chosen aliases.** A successful REGALO call binds an object hash to a path (e.g., `/etc/policy`, `C:\Program Files\App\App.exe`). Resolution at that path serves the same read-only file-view as the canonical mount. The kernel records the alias in a per-process REGALO table; a read-only enumeration (`SYS_REGALO_LIST`) shows backing hashes for every active alias the caller owns.
- **`/co/*` is structurally read-only at the path layer.** No POSIX write operation (`file_create`, `file_write`, `file_rename`, `file_unlink`, `mkdir` under the prefix) succeeds - the resolver rejects writes outright before any backend is touched. REGALO aliases cannot target paths under `/co/*` (REGALO maps user-chosen paths *to* objects, never *into* the canonical namespace). New `/co/<hash>` paths become resolvable only as a consequence of CambiObject creation via `SYS_OBJ_PUT` (per ADR-003) or `SYS_CAMBIO` (per § 3 of this ADR); those syscalls operate on the ObjectStore directly and are not path-writes. The rule is enforced at the path-resolver, not by per-syscall checks - no future syscall can quietly re-open a write path under the prefix without an explicit ADR change.
- **Enumeration is process-local, sourced from the existing per-Principal reverse-ACL index.** A process bound to Principal P sees in `/co/` (e.g., `opendir("/co/")`) only object hashes where `(P, Read)` appears in the ObjectStore's existing per-Principal reverse-ACL index - the same structure already required for cap-revocation lookups. There is no separate "known-hashes" table; this ADR adds no new state for enumeration. The index is populated by every operation that establishes a `(Principal, rights)` row in an object's ACL - the initial put (author gets the row at creation), owner-driven ACL grants, and cap-transfer via IPC capability machinery - and rows are removed on revoke. IPC *payload bytes* are not parsed for hash discovery (the kernel never interprets IPC content per [ADR-005](005-ipc-primitives-control-and-bulk.md)); the index entry that lets a recipient see a hash is created by the cap-transfer operation itself, not by the recipient's observation of an IPC payload that happens to contain the hash. A process that has never had a hash promoted into its cap set cannot discover that hash via path enumeration. The side-channel defenses (known-plaintext correlation, activity inference, lineage-topology mapping) hold because hash existence becomes visible only through explicit cap operations. Global enumeration (the list of every CambiObject on the system) requires a future `CapabilityKind::EnumerateObjects`, deferred until audit-tail / backup workloads demand it; v1 ships without that cap.

The canonical `/co/<hex-hash>` mount and REGALO produce the same read-only file-view of the same object; they differ in stability and naming. Use the canonical mount when you have the hash and want path-shaped access without committing to a name (one-shot reads, hash-aware tools). Use REGALO when you want the object reachable at a stable human-readable path (win-compat installs DLLs at `C:\...` paths via REGALO; native services may REGALO config objects at `/etc/...` for legacy tools).

POSIX paths that are neither `/co/...` nor an active REGALO alias resolve to POSIX files (per ADR-029's backend). The three resolution outcomes are exhaustive: canonical object mount, REGALO alias, or POSIX file. The path resolver returns a `FileDescriptor` in every case; the descriptor's `backing` tag records which of the three the resolution landed on (read-only CambiObject view for the first two, mutable POSIX for the third). Hash-keyed object access returns `ObjectHandle` via the object API; that path is independent of the path-resolver.

### 3. Three new seam syscalls

Reserve the next three syscall numbers (current reservations end at 47 per [ADR-027 § Divergence](027-service-clusters.md#divergence); next free is 48). "Identity-required: yes" in the table below means the caller must be Principal-bound per [ADR-025](025-principal-as-aid.md) before invoking the syscall; the kernel reads `sender_principal` from the calling task's capability record. The convention is inherited from ADR-027's syscall table.

| Number | Name | Identity-required | Inputs | Outputs | Caps consumed |
|---|---|---|---|---|---|
| 48 | `SYS_CAMBIO` | yes | `FileDescriptor` (source POSIX file), optional `Principal` (delegated signing identity, defaults to caller), optional `lineage: [u8; 32]` (parent object hash), optional flag `AndDelete` | `[u8; 32]` content hash | Read on source file; sign-as-Principal (implicit via Principal binding); CreateObject |
| 49 | `SYS_REGALO` | yes | `[u8; 32]` object hash, path string (user-chosen alias) | mount handle `RegaloId` (revocable) | Read on object; path-namespace write under per-process mount root |
| 50 | `SYS_STREAM` | yes | Source spec `StreamSource::{Object([u8;32]), File(FileDescriptor)}`, `peer_principal`, cap-shape `StreamCapShape` (defined by ADR-030) | `StreamEndpoint` (sender side) + channel ID for the peer to attach | Read on source; channel-create rights; cap-shape bound enforcement |

Each handler is a single atomic transaction at the kernel ABI level (atomic-or-fail from the caller's perspective). CAMBIO obtains a snapshot-consistent view of the source, hashes and signs streaming over that view, installs a `CambiObject` via the existing `ObjectStoreBackend::put` path. REGALO writes one row into the REGALO alias table. STREAM creates a channel record per [ADR-005](005-ipc-primitives-control-and-bulk.md) with a `StreamCapShape` attached, returning the producer-side endpoint to the caller and queuing the consumer-side handle for `SYS_CHANNEL_ATTACH` by the peer.

**Multi-block CAMBIO.** CAMBIO operates on POSIX source files of arbitrary size up to `MAX_CAMBIO_CONTENT_BYTES = 4 TiB` (SCAFFOLDING - sized to cover the v1 endgame: documents, ELF binaries, AI model snapshots, full-length 4K video, VM disk images, low-TB database files; replace when a workload legitimately exceeds 4 TiB per single sealed record). The kernel-side hash + sign + install transaction reads streaming over a snapshot-consistent view of the source. The resulting CambiObject's on-disk multi-block layout - extent allocation, header restructuring to accommodate both extents and the post-quantum signature reservation, recovery semantics - and the locking strategy that makes the snapshot view possible (per-inode copy-on-write or equivalent) are specified by ADR-029 (the POSIX file backend, which shares an extent-allocator with the CambiObject backend) and an ADR-010 successor admitting multi-block content. ADR-028 commits to the *size capability* and the *snapshot-consistency guarantee* at the seam syscall; the on-disk shape and locking strategy are downstream.

No new `CapabilityKind` variants. The seam syscalls compose existing capabilities (read-on-source, sign-as-Principal, CreateObject, channel-create). The atomic-or-fail semantics are what make these syscalls rather than userspace compositions; see § Why Not Other Options.

### 4. Type discipline propagated through syscall return values, not runtime tags

The kernel returns a typed handle. Userspace cannot construct an `ObjectHandle` from a `FileDescriptor` or vice versa; the constructors are kernel-only (the userspace types are opaque newtypes around kernel-issued IDs, with no public field access). A syscall that expects `ObjectHandle` rejects `FileDescriptor` at parameter decode (a separate syscall-argument trait per type, with no `From` impls bridging them). At the verification target, the handle-type discipline is a structural property of the `SyscallArguments` enum *for code that uses the API as published* - closed-world, exhaustively matched, monomorphized. Defeating the discipline requires opting out (via `unsafe` or transmute), at which point the user code is no longer using the API; see § Threat Model "does NOT protect against" row 1.

This is the same shape [ADR-024](024-syscall-abi-crate.md) gives the syscall ABI generally. The `cambios-abi` crate carries the three handle types; the kernel imports them; userspace clients import them; no party gets to invent a fourth.

### 5. The asymmetry - no inverse seams

Three explicit non-existences ratify what storage-planning.md called "one asymmetry":

- **No DEMOTE** (CambiObject → POSIX file). Once sealed, no unsigning. Working from a CambiObject means COPY-OUT: read the bytes via the canonical mount or a REGALO alias, write them into a new POSIX file. The original CambiObject remains intact and content-addressable; the new POSIX file carries the bytes but not the seal.
- **No CAPTURE through the Stream cap** (Stream → CambiObject or POSIX file). A receiver of a Stream cannot re-emit the consumed bytes *through that Stream's cap* to either storage model. The Stream cap itself does not admit persistence; the dispatch table has no DEMOTE or CAPTURE entry against a `StreamEndpoint`, and no `From` impl bridges StreamEndpoint to either other handle type.

    The Stream cap does *not*, however, constrain the receiver's *other* caps. A receiver that independently holds write caps on POSIX files, or CAMBIO rights against its own work, can write the consumed bytes to those targets - those are separate caps doing separate operations. Full "bytes never persist anywhere" containment (the NDA review, medical imaging, signed-input, content-protection use case) requires composing the Stream cap with **deployment-level sandboxing**: the receiver is a process whose cap inventory at launch excludes all other persistence surfaces (no POSIX write caps anywhere, no CreateObject, no CAMBIO rights). Stream's structural property gives the cap-level guarantee ("bytes through this cap do not become addressable through this cap"); sandboxing gives the deployment-level guarantee ("bytes never become addressable anywhere because the receiver has nowhere to put them"). The two compose: a Stream cap held by a process with no write caps anywhere can consume but cannot persist. The sandbox half is downstream of [ADR-027](027-service-clusters.md) (cluster-scoped cap inventories) and the win-compat sandboxed-Principal model ([docs/win-compat.md](../win-compat.md)).

- **No implicit promotion of any kind.** The three seams (CAMBIO, REGALO, STREAM) are the only kernel-mediated transitions between models. The kernel never "detects that a POSIX file looks ready to seal," never "promotes a CambiObject to writable because the user pressed Edit," never "promotes a Stream to addressable storage because the cap shape was relaxed."

The implementation enforces this by simply *not implementing* the inverse syscalls - no DEMOTE or CAPTURE entry in the dispatch table, no `From` impls between the three handle types. Stream's IPC-layer ephemerality, win-compat's working-state-vs-sealed-record distinction, and the per-model audit and verification posture all rely on this asymmetry being structural, not conventional - in concert with the deployment-level sandboxing described above where the full containment guarantee is required.

## Architecture

### Userspace module structure

A typical developer touches one of three modules, scoped to their use case:

| Module | Developer use case | Handle type | Syscalls in scope | Userspace service |
|---|---|---|---|---|
| **libobj** | Sealed-object workflows: audit consumers, key-store, native CambiOS services, anything signing or content-addressing | `ObjectHandle` | `SYS_OBJ_PUT/GET/DELETE/LIST` (per ADR-003), `SYS_CAMBIO`, `SYS_REGALO` | fs-service (endpoint 16) |
| **libposix** | Mutable-files-at-paths workflows: Windows-compat apps, POSIX legacy code, scratch and working state | `FileDescriptor` | `file_open/read/write/close/rename/unlink/mkdir/...` | new posix-fs-service (endpoint per ADR-029) |
| **libstream** | Transient-flow workflows: rendering pipelines, sensor flow, NDA review, content protection | `StreamEndpoint` | `SYS_STREAM`, `SYS_CHANNEL_ATTACH` (per ADR-005) | direct kernel; no userspace gateway |

A developer typically links one module per use case. A win-compat sandbox links libposix and never sees CambiObjects directly. A native audit consumer links libobj. A signed-video renderer links libstream. Cross-linking is possible but the typical app does not need it.

**Stream skips a userspace gateway** because cap-shape enforcement is kernel-side (where the channel substrate already lives per ADR-005) and is the only *policy* concern in the Stream model. Higher-level coordination services - stream-brokers for multiplexing, naming, discovery, retransmit - can exist as ordinary userspace processes consuming the Stream API; they are not part of the Stream substrate and are out of scope for this ADR. The other two modules have userspace gateways (fs-service, posix-fs-service) because those gateways do policy work on top of kernel mechanism; Stream has no analogous policy layer above its cap shape.

**CAMBIO and REGALO live in libobj.** They are object-flavored operations even when their input or output crosses to the POSIX side:

- **CAMBIO** takes a `FileDescriptor` and produces an `ObjectHandle`. The developer doing the seal is reasoning about objects ("I want a sealed record of this working file").
- **REGALO** takes an `ObjectHandle` and publishes it as a POSIX path. The developer doing the publish is reasoning about objects ("I want this sealed binary to appear at `C:\Program Files\App\App.exe` so legacy code can `open()` it").

A libposix-only consumer who later does `file_open("C:\Program Files\App\App.exe")` on a REGALO-mounted path does not know or care that REGALO published it. They receive a `FileDescriptor` (with `backing = ObjectView` set by the kernel resolver), they read bytes, they are done. Writes return EROFS because the backing storage cannot accept writes. The type contract of `FileDescriptor` (POSIX-shape, possibly read-only) holds uniformly; the runtime backing varies but the type semantics do not.

This is **not** the polymorphism the synthesis excluded. The forbidden polymorphism was "a Handle whose underlying *model* could be anything depending on later behavior." What `FileDescriptor` admits is two *backings* (mutable POSIX file, immutable CambiObject view) under a single path-shaped contract, with write-failure as a uniform behavior when the backing is immutable. The API a developer calls tells them what shape they are working with: `file_open` → `FileDescriptor`, `SYS_OBJ_GET` → `ObjectHandle`, `SYS_STREAM` → `StreamEndpoint`. No syscall ever returns "a Handle whose type depends on later behavior."

### Kernel state additions

```rust
// In a new src/fs/regalo.rs:
pub struct RegaloTable {
    /// REGALO alias table. Per-process namespace.
    aliases: [Option<RegaloEntry>; MAX_REGALO_PER_PROCESS],
    count: u32,
}

pub struct RegaloEntry {
    pub id: RegaloId,
    pub object_hash: [u8; 32],
    pub path: PathBuf,
    pub creator_pid: ProcessId,
    pub created_at_tick: u64,
}
```

`MAX_REGALO_PER_PROCESS` is SCAFFOLDING per [Convention 8](../../CLAUDE.md#development-conventions). The bound is set at "high thousands to low tens of thousands" to cover a Windows-app dependency closure (system32 alone is ~3500 files, plus app-bundled DLLs and registry-backed configuration; a non-trivial app's REGALO needs are in the 5K-15K range). The exact number is deferred to ADR-029, where it lands alongside the POSIX backend's other SCAFFOLDING bounds and is measured against an observed Win-compat closure rather than estimated. ADR-028 commits to "per-process REGALO table is bounded"; the bound is downstream.

The canonical `/co/<hex-hash>` resolver is not a table - it parses the path component, hex-decodes the hash, and dispatches to `ObjectStoreBackend::get` with the calling process's read-cap check. **Enumeration of `/co/`** (e.g., `opendir("/co/")`) is sourced from the ObjectStore's existing per-Principal reverse-ACL index per § Decision 2: the resolver returns hashes where the calling process's Principal appears with `Read` rights in that index. The reverse-ACL index is already needed for cap-revocation lookups; this ADR adds no new state. IPC payloads are not parsed for hash discovery, and population of the index is owner-driven (ACL grants), so the side-channel defenses (correlation, activity, lineage) hold.

`StreamEndpoint` state lives in a new `StreamTable` parallel to the `ChannelManager`, with role-typed entries (Producer / Consumer / Bidirectional, matching channel role shape per [ADR-005](005-ipc-primitives-control-and-bulk.md)). The cap-shape bounds attached to each StreamEndpoint are specified by ADR-030.

### Lock ordering

No new top-level locks. The new state lives at existing or near-existing positions:

- **REGALO table**: per-process state, governed by the existing `PROCESS_TABLE` lock at acquisition time. Reads under read-locked process state; writes under the process-table lock.
- **Stream table**: integrates with `CHANNEL_MANAGER` (lock position 6 per [ADR-027 § Lock ordering](027-service-clusters.md#lock-ordering)) since Stream rides on channels. A Stream's lifecycle is bookkeeping over channel records, not a new lock domain.

This avoids a re-renumbering of the lock hierarchy and keeps the ADR's surface area small. **CAMBIO does not hold a global POSIX-backend lock for the duration of a seal**; it uses per-inode COW (or equivalent finer-grained mechanism per ADR-029) to obtain a snapshot-consistent view of the source and runs the hash + sign + install streaming over that view. Concurrent POSIX operations elsewhere in the backend are unaffected; concurrent writes to the source go to new blocks via COW. The locking strategy is ADR-029's commitment; ADR-028 requires only that the strategy supports snapshot-consistency without blocking the rest of the backend.

### Capability checks

| Seam | Cap chain |
|---|---|
| CAMBIO | `Read(FileDescriptor)` on source → `BindPrincipal`-implied sign-as-self → `CreateObject` (or via `OBJ_PUT` capability per ADR-003) |
| REGALO | `Read(ObjectHandle)` on object → namespace-write-in-own-process-root (implicit) → returns revocable `RegaloId` |
| STREAM | `Read(source)` (object or file) → `ChannelCreate` (per ADR-005) → `StreamCapShape` enforced bounds (per ADR-030) |

No new `CapabilityKind`. The composition is the discipline.

### Existing syscalls preserved

Object syscalls per [ADR-003](003-content-addressed-storage-and-identity.md) (`SYS_OBJ_PUT`, `SYS_OBJ_GET`, `SYS_OBJ_DELETE`, `SYS_OBJ_LIST`) remain the canonical CambiObject API. They are not deprecated.

**`SYS_OBJ_PUT` and `SYS_CAMBIO` are not redundant** - they share a destination (the ObjectStore) but differ in input shape and signing flow:

- **`SYS_OBJ_PUT`** takes a pre-assembled `CambiObject` struct from a userspace buffer, with a pre-obtained signature (typically retrieved via key-store IPC before the call). Used by services producing objects from in-memory data: audit-log records, key-store records, IPC-message archives, small synthesized objects. The caller owns assembly and signing; the kernel just stores.
- **`SYS_CAMBIO`** takes a `FileDescriptor` and runs the kernel-side streaming-seal transaction: read source bytes (from a snapshot-consistent view), compute Blake3, run the signing flow against the caller's Principal-to-key-store binding, install. Used for sealing existing POSIX files where the bytes are too large to buffer in userspace or where the workflow event ("save-as-final," "ship," "commit document") is the right framing. The kernel owns reading, hashing, and atomic-or-fail commit.

Pick by input shape: in-memory data → OBJ_PUT; existing POSIX file → CAMBIO. The two paths produce identical CambiObjects in the store; REGALO and STREAM accept any object hash regardless of which syscall produced it. New code that already knows it wants an `ObjectHandle` directly should call OBJ_PUT / GET / DELETE / LIST rather than going through REGALO + path resolution. REGALO exists for the path-shaped consumer; it is not the only object access path.

POSIX syscalls (`file_open`, `file_read`, `file_write`, `file_close`, `file_rename`, etc.) are defined by ADR-029. This ADR commits to their existence and to their type discipline (they return `FileDescriptor`, not `Handle`), not to their full enumeration.

## Threat Model

### What this ADR protects against

| Threat | Mitigation |
|---|---|
| Polymorphism attack: a caller passes an `ObjectHandle` to a syscall expecting `FileDescriptor` (or vice versa) | Typed at kernel API decode; rejected with `InvalidHandle` before any storage operation runs |
| Conflation in user code: a process treats a REGALO mount as if it were a writable POSIX file and discovers the mistake at runtime | Writes structurally rejected with EROFS or its CambiOS analog before any backend operation runs; the diagnostic is immediate, not subtle |
| CAMBIO with a tampered source: the caller has read on a POSIX file that's concurrently being written | CAMBIO obtains a snapshot-consistent view of the source at open time (per-inode COW per ADR-029); the bytes hashed are the bytes as of CAMBIO open. Concurrent writes during the seal are admitted (they go to new blocks via COW) and do not affect the hash. The seal does not block other POSIX-backend operations; only the snapshot-setup is locking, bounded by setup cost rather than seal duration |
| Path-namespace deception: a caller resolves `/co/<hash>` expecting a sealed object and gets something else | The `/co/` prefix is reserved and read-only at the path-resolver level per § Decision 2. POSIX paths cannot create / write / rename / unlink under `/co/`. REGALO cannot alias into `/co/<hash>` paths. The only operations that change which `/co/<hash>` paths resolve are CambiObject creation/deletion through ObjectStore syscalls |
| Forged handle: caller passes an `ObjectHandle` it never received | The handle carries a kernel-issued generation counter; stale or fabricated handles are rejected at use |
| REGALO alias hijack: one process REGALOs `/etc/policy`, another process REGALOs the same path | REGALO aliases live in *per-process* namespace tables. Two processes can independently alias the same path string to different (or same) object hashes; there is no cross-process aliasing without explicit IPC. System-global aliases land via the boot manifest per ADR-018, not via per-process REGALO |
| Stream side-channel via IPC-borne hashes (an attacker sends fabricated hashes to a victim hoping to populate the victim's `/co/` enumeration) | The reverse-ACL index that backs `/co/` enumeration is populated only by explicit ACL grant operations on the object owner's side. The kernel never interprets IPC payloads for hashes. Fabricated hashes in an IPC payload are ignored; the victim's enumeration is unaffected |

### What this ADR does NOT protect against

| Risk | Mitigation |
|---|---|
| User-code conflation despite the type discipline (e.g., a thin wrapper that unwraps to a u64 ID and recombines as a different type) | The handle types are opaque newtypes at the userspace API surface. Defeating that requires `unsafe` (or transmute), at which point the user code has opted out of the discipline. Same posture as ADR-024's syscall ABI. |
| Side-channel between models via shared backing storage (e.g., a CambiObject and a POSIX file share a page in the page cache; an attacker correlates) | Out of scope for this ADR. The page-cache integrity model is a separate concern handled by the per-backend memory hygiene. |
| The POSIX backend's on-disk format being weaker than the CambiObject format's | ADR-029's verification target. Not this ADR's gap. |
| Stream cap-shape leakage (a receiver buffers beyond the cap, or rewinds beyond the cap-shape window) | ADR-030's verification target. This ADR commits to the existence of `StreamCapShape` and its enforcement at the kernel boundary; ADR-030 specifies the structure. |
| Stream receiver persists consumed bytes via independent write caps (the receiver has Stream + a write cap on `/tmp/log`; it copies the bytes out) | Out of scope for the Stream cap itself per § Decision 5. Full "bytes never persist anywhere" containment requires the receiver to be a sandboxed process whose cap inventory excludes other persistence surfaces. The cap-level guarantee composes with deployment-level sandboxing (ADR-027 / win-compat); ADR-028 commits to the cap-level half. |

### Impact on existing threats

- [ADR-003](003-content-addressed-storage-and-identity.md)'s integrity model continues to apply unchanged for the CambiObject side. Signature verification on retrieval, immutable author, transferable owner - none altered.
- [ADR-005](005-ipc-primitives-control-and-bulk.md)'s channel threat model continues to apply for Stream's substrate. The Stream cap shape is an *additional* invariant the kernel enforces on top of channel semantics; nothing in ADR-005 weakens.
- [ADR-026](026-identity-transcription-at-the-kernel-ring.md)'s transcription invariant: seam syscalls do not interpret identity beyond what the cap-promotion boundary already does. CAMBIO writes the caller's Principal into the object's `author` field; that is a *transcription* of the kernel-bound Principal, not interpretation.

## Verification Stance

The kernel-API surface is the verification target. Two distinct discipline claims, separately verifiable:

- **Handle-type discipline (static).** The API surface returns one of three handle types, decided at the syscall that produced the handle (`ObjectHandle`, `FileDescriptor`, `StreamEndpoint`). The `SyscallArguments` enum is closed-world; every syscall arm matches a specific subset of handle types. Kani harness target: "no syscall decode path accepts both `ObjectHandle` and `FileDescriptor` for the same parameter slot." This is a static property - no runtime tag-check selects among the three handle types; defeating it requires opting out of the API (`unsafe` / transmute).
- **Storage-backing discipline within `FileDescriptor` (resolved at open).** The descriptor's `backing` field (POSIX-mutable vs. CambiObject-view-readonly) is resolved at `file_open` time by the path resolver and held in the descriptor record for the lifetime of the handle; subsequent operations branch on the backing tag without re-resolving. The contract (path-keyed, writes may fail uniformly when backing is immutable) is uniform across backings. Kani harness target: "write operations against a descriptor with `backing = ObjectView` terminate in `EROFS` before any backend operation runs."
- **Seam atomicity:** Each seam syscall acquires its required locks in canonical order, runs the operation, releases. CAMBIO's per-inode COW (ADR-029) keeps the lock duration bounded by snapshot-setup cost; the hash + sign + install streaming over the snapshot view runs without holding a global lock. REGALO touches only `PROCESS_TABLE`. STREAM touches `CHANNEL_MANAGER` per ADR-005's existing posture.
- **Path-namespace exhaustiveness:** The path resolver's match is `Canonical(/co/...) | RegaloAlias | PosixPath`, exhaustively. Every resolution returns `FileDescriptor` with `backing` set. `/co/*` write attempts terminate in a single rejection arm before any backend lookup.
- **Bounded iteration:** REGALO alias lookup is bounded by `MAX_REGALO_PER_PROCESS` (per-process bound deferred to ADR-029). Canonical resolution is constant-time (hex-decode + ObjectStore get). Reverse-ACL enumeration is bounded by the calling Principal's cap count. Stream channel-create is bounded per ADR-005.
- **Existing CambiObject syscalls:** Unaffected. The proofs for `SYS_OBJ_PUT` etc. carry over without modification.

The verification surface delta vs. existing kernel: roughly the size of three new syscall handlers plus the REGALO table operations. Smaller than ADR-027's cluster manager. The handle-type discipline at the API is a *static* property - it falls out of the syscall ABI's structure with no runtime check beyond decode. The storage-backing discipline within `FileDescriptor` is *resolved* at `file_open` and *static thereafter* for the lifetime of the handle.

## Why Not Other Options

### Option A: Polymorphic file handle (one type, runtime-tagged)

A `Handle` enum with `Object(ObjectHandle) | File(FileDescriptor) | Stream(StreamEndpoint)` variants, accepted by a unified syscall surface. Userspace decides at call site which variant to wrap.

**Why considered.** Ergonomic for legacy code paths. A POSIX library that wants to abstract over "a thing you can read bytes from" gets a single type.

**Why rejected.** Defeats the synthesis's "kernel makes conflation impossible" principle. Runtime-tagged polymorphism across *models* is exactly the userspace-convention shape the synthesis excluded. Once the kernel accepts a `Handle`, every caller's bug is now a runtime check rather than a compile-time miss. Verification cost rises: every syscall that takes `Handle` must reason about all three variants. [ADR-026](026-identity-transcription-at-the-kernel-ring.md)'s cap-shape duality already paid for this lesson; this ADR does not undo it for storage. Note: `FileDescriptor`'s two backings are *not* this kind of polymorphism - the *model* is uniform (POSIX-shape, path-keyed); only the storage backend varies, and the contract is uniform across backings.

### Option B: Defer this ADR; specify type discipline inside ADR-029 and ADR-030

ADR-029 specifies the POSIX backend including its handle type. ADR-030 specifies Stream including its endpoint type. A separate ADR for the type discipline is redundant.

**Why considered.** Less ADR overhead. Each backend ADR is self-contained.

**Why rejected.** Type discipline is the cross-cutting decision. If 029 and 030 each implicitly make it without a shared baseline, drift is inevitable - one ADR might allow a polymorphic shim, the other might not, and the synthesis's structural property is lost. This ADR is the place to ratify the cross-cutting commitment so 029 and 030 build on a shared foundation.

### Option C: Skip seam syscalls; let userspace compose them out of existing primitives

CAMBIO in userspace: read bytes from POSIX, compute Blake3, call `SYS_OBJ_PUT`. REGALO in userspace: maintain a per-process map of paths → object hashes, intercept opens. STREAM in userspace: open a channel, send bytes, never persist on receiver side.

**Why considered.** Cycles-outside-the-ring heuristic. Kernel adds no new syscalls, no new state.

**Why rejected.** Atomicity. A userspace CAMBIO has a window between "I read the bytes" and "I sealed them" during which the source file may be mutated; the hash written into the CambiObject does not match the bytes any concurrent reader would have seen, and there is no userspace mechanism for snapshot-consistency. A userspace REGALO cannot intercept `open()` at the kernel - every consumer would have to opt into the userspace interceptor, which is exactly the userspace-convention model the synthesis excluded. A userspace STREAM cannot enforce cap-shape bounds (rewind, buffer, fan-out) - the kernel must be on the path. The atomicity and the kernel-boundary enforcement are why these are syscalls, not userspace conventions.

### Option D: Defer Stream entirely; ship objects + POSIX in v1, add Stream later

Two-model v1 (CambiObject + POSIX). Stream becomes a future ADR when an actual workload demands ephemerality.

**Why considered.** Stream's downstream consumers are mostly future workloads (rendering pipelines, signed-carrier input, NDA review). v1 might not need it.

**Why rejected.** [ADR-014 § Divergence 2026-04-20](014-compositor-scanout-driver-protocol.md) already shows a v1 rendering pipeline that double-copies pixels through `SYS_VIRTIO_MODERN_CAPS`. That pipeline is structurally a Stream - sealed object on the compositor side, ephemeral pixel flow to the scanout driver. v1 ships without naming the pattern; ADR-028 names it. The kernel side may stay minimal (the channel substrate already exists per ADR-005); ADR-030 fills in the cap-shape structure when the consumer demands it. Naming the model now is cheap; retrofitting after the rendering pipeline has solidified is not.

### Option E: Stream-only mode as a kernel-enforced process posture

A "Stream-only mode" syscall (e.g., `SYS_ENTER_STREAM_ONLY_MODE`) puts the calling process in a posture where it cannot acquire any new write caps for the rest of its lifetime; existing write caps become inactive. Combined with a Stream cap, this would deliver the full containment property kernel-side rather than requiring deployment-level sandboxing.

**Why considered.** Removes the deployment-level dependency on sandboxing patterns. A consumer process can opt into containment unilaterally.

**Why rejected (v1).** The existing deployment-side machinery is sufficient. [ADR-027](027-service-clusters.md) and the win-compat sandboxed-Principal model ([docs/win-compat.md](../win-compat.md)) already restrict member cap inventories at launch; a v1 NDA-review consumer, a medical viewer, a content-protected media player are all deployable as sandboxed receivers whose launch-time cap inventory excludes other persistence surfaces. The kernel-enforced mode is additive complexity (a new process-posture state machine with its own activation, deactivation, and interaction-with-existing-caps semantics, plus the verification cost of those new transitions) that we don't need yet. The composition of Stream cap + sandboxed receiver delivers the same containment property using primitives already specified. **Not foreclosed**: if a future workload demands kernel-enforced Stream-only mode without a viable deployment-side path, that lands as an additive ADR without invalidating ADR-028's commitments.

## Migration Path

Documentation + reservation first, implementation per follow-on ADRs.

1. **Land this ADR as `Proposed`.** No code touched. The three-handle-type, three-seam-syscall, path-namespace-convention shape is now citeable for any storage work that wants to "leave room" for the model split.
2. **`cambios-abi` syscall reservations.** Reserve numbers 48–50 for `SYS_CAMBIO` / `SYS_REGALO` / `SYS_STREAM`. Reservation only; no handlers - same posture as [ADR-022](022-wall-clock-time.md)'s wallclock reservation.
3. **`ObjectHandle`, `FileDescriptor`, `StreamEndpoint` types added to `cambios-abi`.** Opaque newtypes around kernel-issued IDs with no public field access. `FileDescriptor` carries a `backing: FileBacking` tag. No behavior change; preparing the type discipline.
4. **ADR-029 lands** (POSIX file backend on-disk format + handler surface + per-inode COW for CAMBIO snapshot-consistency + REGALO size bound). FileDescriptor gets a backend.
5. **ADR-030 lands** (Stream cap shape). StreamEndpoint gets cap-shape bounds.
6. **CAMBIO handler.** Touches both backends - sequenced after ADR-029.
7. **REGALO handler + canonical `/co/<hash>` path resolver + `/co/*` write-rejection arm + reverse-ACL-index-backed enumeration.** Sequenced after ADR-029 (the path resolver lives in the POSIX path-namespace surface). The enumeration surface (`opendir("/co/")` returning ACL-filtered hashes) is sourced from the existing per-Principal reverse-ACL index in ObjectStore; population events listed in § Decision 2 rule 4.
8. **STREAM handler.** Sequenced after ADR-030.
9. **ADR-003 Divergence appendix.** Lands when the implementation chain (steps 6–8) is in place; cites this ADR and the synthesis. Narrows the "files are not bytes-at-a-path" claim without altering the CambiObject model definition.
10. **win-compat.md edit** per storage-planning.md's "editorial emergence" framing. Working state lives in POSIX files; sealed records via CAMBIO; the virtual registry rebased on POSIX with explicit CAMBIO points. Sequenced with or after step 9.

Each step independently bisectable. Steps 1–3 are cheap and pre-implementation. Steps 4–10 chain through the follow-on ADRs.

## Cross-References

- **[storage-planning.md](../storage-planning.md)** - The synthesis this ADR ratifies. Three models, three seams, one asymmetry.
- **[ADR-003](003-content-addressed-storage-and-identity.md)** - CambiObject and the native ObjectStore. Gets a Divergence appendix at step 9 of the migration path.
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** - Channel substrate; STREAM rides on channels.
- **[ADR-010](010-persistent-object-store-on-disk-format.md)** - CambiObject on-disk format; the template for ADR-029's POSIX backend.
- **[ADR-024](024-syscall-abi-crate.md)** - `cambios-abi` carries the three handle types and the seam syscall numbers.
- **[ADR-026](026-identity-transcription-at-the-kernel-ring.md)** - Cap-shape duality; this ADR generalizes the same shape from caps to storage.
- **[ADR-027](027-service-clusters.md)** - Clusters scope member cap inventories; the deployment-level companion to Stream's cap-level containment.
- **[docs/win-compat.md](../win-compat.md)** - Primary downstream consumer of the POSIX model; sandboxed-Principal pattern composes with Stream containment. Gets an editorial-emergence edit at step 10.
- **[docs/ASSUMPTIONS.md](../ASSUMPTIONS.md)** - Receives a row for `MAX_REGALO_PER_PROCESS` when ADR-029 lands the measured bound.

## See Also in CLAUDE.md

When this ADR's implementation lands, the following CLAUDE.md sections must be updated:

- **§ "Required Reading by Subsystem"** - add a row for "Storage models / object / POSIX file / stream" pointing at storage-planning.md, this ADR, ADR-029, ADR-030.
- **§ "Syscall Numbers"** - add `SYS_CAMBIO` (48), `SYS_REGALO` (49), `SYS_STREAM` (50) when handlers land. Per-syscall behavior notes go under the same convention as existing entries.
- **§ "Design Documents"** - add storage-planning.md to the list once this ADR is `Proposed` (the synthesis is no longer an isolated draft; it's the design context for a ratified ADR chain).

## Open Questions / Deferred

> **Deferred decision.** The signing flow for `SYS_OBJ_PUT` vs `SYS_CAMBIO` is asymmetric under the post-ADR-025 identity model. `OBJ_PUT` assumes the caller has obtained a signature externally (typically via key-store IPC); `CAMBIO` runs the signing transaction kernel-side via the caller's Principal-to-key-store binding. The architectural question - whether the kernel should mediate key-store interaction for both paths, or whether `OBJ_PUT` should retain its userspace-signing posture - depends on whether the key-store integration lives in kernel or stays as user-IPC. If the signing flow later unifies (e.g., key-store integration moves kernel-side for both syscalls), `SYS_CAMBIO` remains useful for the streaming-over-large-files case that `SYS_OBJ_PUT` structurally cannot serve (userspace buffer assembly). The two syscalls' distinguishing rationale is not entirely load-bearing on the signing-flow question; the input-shape difference is independent. **Revisit when:** the multi-Principal vault ADR (referenced in identity-synthesis.md) specifies the key-store integration shape, or ADR-029 makes the signing flow load-bearing for the POSIX backend's `author` / `owner` semantics.

> **Deferred decision.** Whether to introduce a `CapabilityKind::EnumerateObjects` for processes that legitimately need the global hash list (audit-tail per [ADR-023](023-audit-consumer-capability.md), a future backup-service, maintenance tools). v1 ships without this cap; every process gets process-local enumeration only, with no escape hatch. **Revisit when:** ADR-023's audit consumer capability is extended to ObjectStore enumeration, or a backup-service ADR lands.

> **Deferred decision.** Whether CAMBIO supports a `delegated_signing_principal` parameter (sign as a Principal other than the caller, with the caller holding a vault-issued delegation token). v1 leans current-Principal default with an explicit override option matching storage-planning.md § Open Questions. **Revisit when:** the multi-Principal vault ADR (referenced in identity-synthesis.md) lands and specifies the delegation envelope.

> **Deferred decision.** Whether `SYS_REGALO_REVOKE` is a separate syscall or piggybacks on the existing `SYS_REVOKE_CAPABILITY` against the `RegaloId`. v1 leans piggyback (no new syscall), but the question depends on whether `RegaloId` becomes a `CapabilityHandle` per the deferred handle-table refactor. **Revisit when:** the post-v1 capability handle-table work lands.

> **Deferred decision.** Whether a kernel-enforced "Stream-only mode" (`SYS_ENTER_STREAM_ONLY_MODE` or equivalent) is needed for use cases that cannot rely on deployment-level sandboxing. v1 uses Stream cap + sandboxed receiver composition for full containment per § Decision 5; the kernel-side mode is forecast as an additive ADR if a workload demands it. **Revisit when:** a v1 workload legitimately needs kernel-enforced containment without deployment-level sandboxing as a viable option.
