# CambiOS Storage Synthesis: Three Co-Equal Models 

This document is the design context under which CambiOS's storage layer defines three first-class data shapes - a) immutable content-addressed objects, b) mutable path-named files, and c) transient capability-bounded streams - such that they are defined and subsequently implemented clearly. It is not a decision record. It is the framing the follow-on ADRs cite when they pick specific mechanisms for each model and the seams between them.

- **Status:** Design context for follow-on ADRs (Three Storage Models, POSIX File Storage Model, Stream Cap Variant). Forward-looking. No code lands from this document directly.
- **Date:** 2026-05-09
- **Depends on:** [ADR-003](adr/003-content-addressed-storage-and-identity.md) (CambiObject + ObjectStore), [ADR-005](adr/005-ipc-primitives-control-and-bulk.md) (channel substrate Stream rides on), [ADR-010](adr/010-persistent-object-store-on-disk-format.md) (CambiObject on-disk format)
- **Related:** [identity-synthesis.md](identity-synthesis.md) (the analogous duality move for identity), [ADR-016](adr/016-win-compat-api-ai-boundary.md), [ADR-027](adr/027-service-clusters.md), [win-compat.md](win-compat.md), [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md)

## Synthesis Principle

[ADR-003](adr/003-content-addressed-storage-and-identity.md) introduced CambiObject as the native CambiOS storage unit and set the bar by saying "files are not bytes-at-a-path." That formulation got the native shape right and the framing wrong. Some workloads genuinely need mutable byte-at-a-path semantics: in-progress documents, databases, journals, and the working state of legacy applications loaded under the win-compat layer. Forcing those workloads through content-addressing has real cost - rehash on every write, version explosion, audit-replay storage that nobody asked for. Forcing them through a translation shim leaks the shim's bugs into every workload that crosses it.

The synthesis: CambiOS admits three first-class storage models, distinguished by data semantics, not by application origin.

- **CambiObject** - immutable, content-addressed, Principal-stamped, signed. Holder can re-derive the exact bytes from the hash, anywhere, anytime.
- **POSIX file** - mutable, path-named, byte-editable. Holder with write cap mutates bytes at a path; with read cap, reads what is there now.
- **Stream** - non-storage data flow with no recipient-side persistence. Holder consumes; cap shape determines bounds and whether they may persist what they consumed.

The three are co-equal native models, not "CambiObject native + POSIX compat shim." Three models, three seams, one asymmetry. That phrase is the spine of every follow-on ADR.

The principle, in three words: **architecture-aware duality, not userspace convention.** Git, IPFS, and ostree have shown the object-vs-file duality in userspace for years. What CambiOS does differently is build the awareness into the OS so the split is a first-class structural property and conflation is impossible at the system boundary, not just discouraged at the documentation boundary.

## Three Models

### CambiObject

Unchanged from [ADR-003](adr/003-content-addressed-storage-and-identity.md). 32-byte content hash as identity. Immutable `author`, transferable `owner`, signature over content, capability set, optional lineage. Content-addressed, signed-by-owner, deduplicated by construction. Use cases: code (signed ELF binaries, ARCSIG-trailed), credentials, audit records, archived documents, sealed records, manifests - anything whose bytes are the identity.

### POSIX file

A new co-equal storage model: bytes at a path that change over time. Use cases: working state, in-progress documents, databases, journals, log buffers, scratch space, anything a Windows or POSIX consumer expects to mutate by path. The model carries the standard path-namespace operations (open, read, write, seek, truncate, rename, unlink, mkdir, opendir/readdir, atomic rename for safe replace). The kernel API is a separate type from the CambiObject handle, not a polymorphic file descriptor.

The POSIX model is not a degraded CambiObject. It is a different storage shape with its own backend, its own audit story, and its own recovery model. The follow-on ADR specifies the on-disk format, the namespace structure, the ACL model, the atomic-rename semantics, and the syscall surface.

### Stream

A non-storage data flow primitive. Bytes traverse from sender to one or more receivers; the kernel does not persist the bytes, and the receiver's cap shape determines whether the receiver may. Implemented atop the [ADR-005](adr/005-ipc-primitives-control-and-bulk.md) channel substrate as a cap variant, not as a fourth substrate. The channel carries the bytes; the Stream cap shape carries the ephemerality invariant.

Use cases: rendering pipelines (sealed object → ephemeral pixel flow → display), sensor flows (signed-carrier input → authenticator → consumed), real-time telemetry where retention is a privacy concern, NDA-bound document review, any workload where the architectural property "the recipient consumed but cannot re-address" is desirable. Streaming-media playback under content protection is one application of the same primitive, not the headline.

The Stream cap is not a single bit. The cap shape carries explicit knobs (full structure deferred to the follow-on ADR; sketched here only to fix the shape):

- `consume` - required for any Stream cap.
- `rewind_window: bytes` - 0 = pure forward-only; >0 = bounded backward seek. The bound is the integrity boundary.
- `buffer_max: bytes` - kernel-enforced ceiling on receiver-side buffering. Unbounded buffer = receiver has effectively captured.
- `fan_out_count: u32` - max simultaneous receivers, controlled at create time.
- `lifetime_bytes` and/or `lifetime_duration` - total throughput before the stream is forced closed.

If any of these are receiver-discretion rather than cap-bound, the property leaks. Stream's containment is a cap-shape invariant, not a runtime check.

## Three Seams

The transitions between models. Always explicit, never implicit. Each seam is a syscall (or a small family) that performs one boundary crossing with documented preconditions, capability checks, and outcomes.

1. **CAMBIO** - POSIX file → CambiObject. Hash the file's current bytes, sign with the caller's Principal (or an explicitly-named delegated Principal), wrap in a CambiObject, store. Workflow event (save-as-final, commit, ship), never implicit. The original file remains; CAMBIO is not move.
2. **REGALO** - CambiObject → POSIX file view, read-only. The mechanism exists because CambiObjects are content-addressed and legacy or POSIX-shaped consumers (the Win32 PE loader, native tools that take filenames, anything that calls `open()`) only know how to read from paths. REGALO is the translation point: the path is the user-visible shape, the content hash is the kernel-visible identity, the view binds them. Read-only is structural - the underlying storage is immutable - not a separate permission layer the user later flips. POSIX-shaped ACLs on the view control *who may see and read the path*; write is absent because the storage cannot accept writes.
3. **STREAM** - {CambiObject, POSIX file} → Stream. Open a stream cap pointing at a source, with the bound knobs above. Sender's cap-set determines what bounds it may impose; receiver's cap shape determines what bounds it must obey.

POSIX-internal operations like copy-at-point-in-time (the thing an earlier draft called SNAPSHOT) are POSIX features alongside read / write / rename / unlink, not seams. They stay inside the POSIX model and do not cross to CambiObject or Stream.

What is not a seam:

- **No DEMOTE.** Once sealed, no unsigning. To work from a CambiObject, COPY-OUT into a new POSIX file. COPY-OUT is just REGALO-and-then-cp, composed; the original CambiObject remains intact and addressable.
- **No transparent capture from Stream.** A receiver of a Stream cannot re-emit the consumed bytes as a CambiObject or POSIX file under that cap. If the receiver also holds a write cap on a separate POSIX file or a Principal authorized to CAMBIO, that is a different cap doing a different operation; from the Stream's view, the bytes flow through and go nowhere. The asymmetry is the architecture.

## The Stream Asymmetry

Stream is one-way by construction. The seam to open a Stream from {object, file} exists; a seam closing one back into CambiObject or POSIX storage does not. A receiver holding a Stream cap with no rewind, no buffer-beyond-cap, no fan-out beyond the cap's count, no lifetime beyond the cap's bound, and no cap-shape route back into storage has consumed bytes that the IPC layer never gave them addressable form to. That is the architectural property: **IPC-layer ephemerality, capability-enforced**.

The primary use cases are integrity and privacy primitives:

- Medical imaging that should not leave the viewer process.
- Financial dashboards that should not be screenshot-able by the rendering process.
- Legal documents flowing under NDA review.
- Biometric data flowing from sensor to authenticator.
- Pre-decryption signed-carrier input flows from trusted-tier hardware.

Streaming-media playback under content protection is one application of the same primitive. The framing throughout this synthesis is ephemerality first; content protection is a downstream use.

## Keeping the Three Apart

Once three models exist, the failure mode is conflation: code or documentation that pretends a POSIX file is a CambiObject (by hashing on every write), pretends a CambiObject is a POSIX file (by treating mutable copies as if they were the original), or pretends a Stream is one of the storage models (by silently buffering "for convenience"). Once conflation enters the codebase, the architecture's properties leak.

What keeps the split honest is layered:

1. **Distinct types at the kernel API.** Object handle, file descriptor, and stream endpoint are different kernel types with different syscall surfaces. No polymorphic "file" handle. The seam syscalls (CAMBIO / REGALO / STREAM) are explicit boundary crossings, never implicit.
2. **Two distinct storage backends, not one abstracted trait.** Block-level mutable backend for POSIX. Content-addressed log-structured backend for CambiObjects (per [ADR-010](adr/010-persistent-object-store-on-disk-format.md)). No `Storage` trait that hides which is which. Stream has no backend by definition.
3. **Path-namespace tells the user which world they are in.** Mount points or prefix conventions visibly distinguish CambiObject views (e.g., `/co/<oid>` or similar) from ordinary POSIX paths. Conflation is visually diagnostic.
4. **Vocabulary discipline in code and docs.** "Object" for CambiObject, "file" for POSIX, "stream" for transient. Code names refuse to collapse them; documentation refuses to use "file" interchangeably.
5. **The user/dev manual reflects the architecture, not the other way around.** The manual chapter does not say "please don't conflate these." It says "here is why the kernel makes conflation impossible, here is how to choose."

The result: the system itself is architecturally aware of the split. Developers and applications see the distinction as a first-class structural property. Conflation is structurally prevented at the kernel boundary, not discouraged by convention.

## How This Changes Existing Documents

### ADR-003

The line "Files are not bytes-at-a-path; they are content-addressed signed objects with an immutable author, a transferable owner, and a cryptographic signature tying content to controller" is correct as a description of the CambiObject *model* and overreaches as a description of all CambiOS storage. The follow-on ADR (Three Storage Models) supersedes the universal claim. CambiObject remains the canonical native model for content-addressed signed storage. The synthesis adds the POSIX file model alongside it, and the comment in [src/fs/mod.rs](../src/fs/mod.rs) ("Not a traditional block-device filesystem. Every backing store... implements this trait.") narrows in scope: the `ObjectStore` trait specifies the CambiObject backend; the POSIX-file backend is its own trait, not a variant under it.

When the follow-on ADR ratifies, ADR-003 gets a Divergence appendix citing both this synthesis and the new ADR. The appendix narrows the scope of the universal-claim line without altering the CambiObject model definition.

### ADR-010

The current persistent on-disk format is the CambiObject format. POSIX files need their own on-disk format. Different region of disk (separate slot range or separate volume), different commit semantics (block-level mutable, journaled or copy-on-write, the choice belongs to the follow-on ADR), different recovery story (POSIX recovery is "what was in flight at crash" - a richer question than "is this header committed"). The follow-on ADR for the POSIX File Storage Model takes the same shape as ADR-010: format declaration, write protocol, mount/recovery protocol, bounded-iteration claim for verification.

### win-compat.md

Currently states that file writes from sandboxed apps create CambiObjects with `author = sandboxed Principal, owner = parent Principal`. Under the synthesis, that is true for **CAMBIO**'d content: the explicit save-final-version action that produces a sealed record. The default write path - working state, in-progress documents, scratch, the things a Windows app expects to rewrite in place - lands in POSIX file storage under a per-sandbox path namespace, owned by the parent Principal, accessed by the sandboxed Principal. CAMBIO is the workflow event that produces the CambiObject; the legacy app does not know it happened.

This is a meaningful change to the virtual-filesystem section. Most of `C:\Users\<user>\Documents\` is POSIX-shaped during the working session and CAMBIOs to CambiObject only when the user signals they are done (save-and-close, "ship," etc.). The synthesis follow-on ADR specifies the trigger semantics; win-compat.md gets edited directly when the synthesis ratifies. With no implementing code citing the doc and no commits referencing it as a frozen baseline, the change is editorial emergence rather than a divergence appendix.

The virtual registry (HKLM, HKCU, HKCR) is squarely a POSIX-style mutable workload, not a CambiObject-backed KV store. Registry writes happen constantly, mostly never matter, and occasionally produce a state worth sealing (license activation, configuration finalization). The follow-on ADR rebases the virtual registry on the POSIX file model with explicit CAMBIO points for the cases where a registry change is actually a record.

## Mapping Table

| Concept | CambiObject | POSIX file | Stream |
|---|---|---|---|
| Identity | content hash | path | endpoint + session |
| Mutability | immutable | mutable | flow (no persistence) |
| Author / Owner | both intrinsic to object | external attributes (process Principal at write) | sender Principal at create; recipient cap-bounded |
| Provenance | signed lineage chain | journal at best | none beyond sender Principal stamping |
| Storage backend | content-addressed log-structured | block-level mutable | none |
| Kernel handle type | object handle | file descriptor | stream endpoint |
| Audit story | every version distinct, replay exact | logged operations, no byte history | flow trace; cap-bounded retention |
| Verification posture | cryptographic, anywhere | replay-from-journal, local | trust the cap shape |
| Canonical use cases | code, credentials, audit, archives, signed records, manifests | scratch, drafts, databases, journals, working trees, registry | rendering, sensor flow, NDA review, ephemeral consumption (content protection is one application) |

## Structural Wins

1. **The CambiObject model keeps its formal-verification properties.** No new abstraction over storage backends; CambiObjects are still content-addressed, signed, and bounded per [ADR-003](adr/003-content-addressed-storage-and-identity.md) / [ADR-010](adr/010-persistent-object-store-on-disk-format.md). The POSIX backend is a separate verification target with its own invariants, not a polymorphic extension that erodes the object model's clarity.
2. **The win-compat layer becomes architecturally honest.** Working state lives where its semantics actually fit. CAMBIO is the explicit "this matters now" event, which is closer to the user's mental model anyway. Most of what a Windows app writes was never a record; the synthesis stops treating it as one.
3. **Stream's one-way property is a structural consequence, not a feature.** No new policy layer. The cap shape says what it says, and the ephemerality follows. Verifier-friendly, marketing-honest.
4. **Three independent verification efforts.** CambiObject model (already underway). POSIX storage model (own ADR, own format, own bounded recovery). Stream cap-shape invariants (algebraic, cap-set check). Each layer is a separate target.
5. **The user/dev manual is a translation of the architecture.** The chapter on storage explains three models, three seams, one asymmetry. The kernel makes conflation impossible; the manual says so.

## ADR Slots This Document Opens

Three follow-on ADRs cite this synthesis as design context. Drafting order, dependency-respecting:

1. **Three Storage Models.** Cites this doc plus [ADR-003](adr/003-content-addressed-storage-and-identity.md). Ratifies the three-model split, the three seams, the asymmetry. Specifies the kernel-API type discipline (object handle vs file descriptor vs stream endpoint), the path-namespace convention that visually distinguishes the views, and the syscall surface for the seams (CAMBIO, REGALO, STREAM). Defers the POSIX backend's on-disk format and the Stream cap shape's full structure to ADRs (2) and (3).
2. **POSIX File Storage Model.** Cites this doc plus [ADR-010](adr/010-persistent-object-store-on-disk-format.md). Specifies the on-disk format for the mutable backend, the namespace structure, the ACL model and how it relates to the CambiObject ACL, atomic-rename semantics, and the recovery / fsck model. Same shape as ADR-010 (declarations + protocols + bounded-iteration claims).
3. **Stream as Cap Variant on Channels.** Cites this doc plus [ADR-005](adr/005-ipc-primitives-control-and-bulk.md). Specifies the Stream cap shape (`consume`, `rewind_window`, `buffer_max`, `fan_out_count`, `lifetime_*`), how those knobs are checked at send/receive, the kernel-side invariants the channel substrate enforces, and how the cap composes with the existing channel role/peer model. Defers cap-shape's user-facing wrapping (e.g., a content-presentation library that handles "open this signed video for viewing only") to userspace.

An edit pass on win-compat.md (working state in POSIX, CAMBIO for sealed records, registry rebased on POSIX) lands when ADR (1) ratifies. Because the doc has no implementing code yet, this is editorial emergence rather than a divergence appendix on a frozen plan.

Each ADR is small, focused, and decideable in isolation. Each one adds a layer the prior ones did not have to commit to.

## Open Questions Carried Forward

These resolve in the follow-on ADRs.

- **Directory-tree presentation.** Live working trees are POSIX namespaces (path → mutable file). Archival or sharable trees are CambiObject manifests (a Merkle tree of names → content hashes). Same content can present either way depending on whether the user is in a workflow or in an archive. ADR (1) decides whether the kernel exposes both presentations or only the POSIX one (with archival presentation being a userspace-composed view).
- **CAMBIO signing identity.** Does CAMBIO auto-bind `author = current Principal`, or accept an explicit signing identity (e.g., a delegated key from the user's vault)? Lean current-Principal default with an explicit override option. Decision in ADR (1).
- **Mount-point semantics for `/co/<oid>` and equivalents.** Kernel-namespace primitive or userspace fs-shim composition? Lean userspace shim - the kernel exposes (object handle, mount path) primitives, the shim composes them. Decision in ADR (1).
- **Stream lifetime across process restart.** Does a Stream survive past the recipient-side process exit, or is the cap session-scoped? Lean session-scoped; carry-across-restart is an explicit feature, not the default. Decision in ADR (3).
- **Receiver multiplicity.** Is a Stream cap one-shot (single receiver) or attachable from multiple receivers up to `fan_out_count`? Decision in ADR (3).
- **fs-service surface.** The current [user/fs-service](../user/fs-service) gates the ObjectStore. Does it grow a sibling for POSIX storage, or is there a separate `posix-fs-service` crate? Lean separate crate - one service, one storage model, clean separation matches the architecture. Sequenced after ADR (1) and (2).
- **CAMBIO atomicity.** When CAMBIO seals a POSIX file, does the file remain at the path (the POSIX side is unchanged), or is it deleted (a destructive seal)? Lean non-destructive default with an explicit "and-delete" variant for the workflow case where the working file was scratch all along. Decision in ADR (1).

## Cross-References

- [identity-synthesis.md](identity-synthesis.md): the analogous duality move for identity, same architectural shape.
- [ADR-003](adr/003-content-addressed-storage-and-identity.md): CambiObject and ObjectStore - the native model this synthesis preserves.
- [ADR-005](adr/005-ipc-primitives-control-and-bulk.md): channel substrate Stream rides on as a cap variant.
- [ADR-010](adr/010-persistent-object-store-on-disk-format.md): on-disk format for the CambiObject backend; template for the POSIX-file follow-on.
- [ADR-016](adr/016-win-compat-api-ai-boundary.md): Win32 surface; primary downstream consumer of POSIX storage.
- [ADR-027](adr/027-service-clusters.md): trust-topology unit; clusters can scope POSIX-file namespaces and Stream caps just as they scope CambiObjects.
- [docs/win-compat.md](win-compat.md): virtual filesystem section gets edited (editorial emergence, not divergence) when ADR (1) ratifies.
- [docs/FS-and-ID-design-plan.md](FS-and-ID-design-plan.md): phase intent for identity + storage; predates the synthesis.
