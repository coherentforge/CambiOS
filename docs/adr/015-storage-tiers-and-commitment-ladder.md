# ADR-015: Storage Tiers and the Commitment Ladder

- **Status:** Proposed
- **Date:** 2026-04-16
- **Depends on:** [ADR-003](003-content-addressed-storage-and-identity.md) (Content-Addressed Storage + Identity), [ADR-004](004-cryptographic-integrity.md) (Cryptographic Integrity), [ADR-010](010-persistent-object-store-on-disk-format.md) (Persistent ObjectStore On-Disk Format)
- **Related:** [ADR-000](000-zta-and-cap.md) (Zero-Trust Architecture), [ADR-007](007-capability-revocation-and-telemetry.md) (audit state lives in the private tier established here)
- **Supersedes:** N/A. Extends the storage model around CambiObject; does not retire it.

## Problem

CambiOS's storage primitive — the CambiObject (ADR-003/004/010) — is content-addressed, Blake3-hashed, author-stamped, owner-bound, Ed25519-signed, and immutable. Phase 1C hardened this by removing any unsigned fallback, making signed-storage a load-bearing invariant.

This fits one class of storage cleanly: **published, cross-boundary-shareable, cryptographically-attributable content.** A dweb attestation needs a known author, a verifiable signature, and content-addressability. Those properties are what let any CambiOS node in the ecosystem verify the object without trusting the transport.

But CambiOS storage has more than one class, and the universal-CambiObject model imposes ceremony on classes that don't need it — and blocks them entirely when the signing path is unavailable:

- **Working content** (a text file being edited) may be discarded, edited over days, or never shared. Routing every save through author-signing adds ceremony with no trust-boundary payoff.
- **Device-local state** (recognition records for enrolled identities, audit drain pointers, configuration, session persistence) needs *integrity* against tampering but not *user-attribution*. Nothing outside this device will verify it.
- **Distribution artifacts** (kernel, boot modules) are already handled separately (ARCSIG trailer, build-time signed, runtime verified against a compiled-in distribution key). A class distinction already exists there; this ADR makes that distinction systematic across all storage.

The collapse surfaces the moment real user workflows arrive. *Open an editor, type, save, reopen tomorrow* is not a trust-boundary event; it is a **commitment to keep local content**. The current architecture asks that workflow to either live only in RAM (lost on reboot) or route through a signing path that, in hardware-backed mode, requires a presence channel (USB HID) that does not yet exist. Either way, the user cannot save a text file — not because of a missing feature, but because the architecture classified the operation as something it isn't.

This ADR proposes that storage in CambiOS is **tiered by commitment level**, with a shared object primitive across tiers. Each tier differs in what identity is attached, what trust radius is claimed, and what lifecycle applies. Tier transitions are explicit, driven by user action, and ceremonial where it matters.

## Design Target

### The commitment ladder

```
┌──────────────────────────────────────────────────────────────────┐
│ TEMP — in-memory, owned by the authoring process                 │
│ • Not storage. No object, no hash, no persistence.               │
│ • Bytes live in the process's address space; ownership is the    │
│   Principal bound to that process.                               │
│ • Power loss or process exit = gone.                             │
└──────────────────────────────────────────────────────────────────┘
                 ↓ SAVE — ownership transfer + Creator mint
┌──────────────────────────────────────────────────────────────────┐
│ PRIVATE CAMBIOBJECT — device-scoped, integrity-tagged            │
│ • Content-addressed, Blake3-hashed (same as public).             │
│ • Creator Principal stamped at save time.                        │
│ • Device MAC tag: integrity against in-device tampering.         │
│ • No user-signature; no cross-device verification claim.         │
│ • Immutable record; naming layer (bindings) handles mutation.    │
│ • Encrypted at rest under the device key.                        │
└──────────────────────────────────────────────────────────────────┘
         ↓ SHARE — outbound boundary crossing, automatic promotion
┌──────────────────────────────────────────────────────────────────┐
│ PUBLIC CAMBIOBJECT — ecosystem-scoped, author-signed             │
│ • Same content, same Blake3 hash as the private it was promoted  │
│   from. Promotion is an in-place tier transition, not a copy.    │
│ • Author Principal + Ed25519 signature added at promotion.       │
│ • Provenance: the binding's history records the promotion point. │
│ • Cross-device verifiable; the dweb unit of trust.               │
│ • Still encrypted at rest locally; the signature — not the       │
│   ciphertext — is what makes it ecosystem-verifiable.            │
└──────────────────────────────────────────────────────────────────┘
```

A fourth class — **distribution artifacts** (kernel, boot modules) — sits alongside, not within, this ladder. Already handled by build-time signing + runtime verification against a compiled-in distribution key; not revisited by this ADR beyond confirming it stays distinct.

### Property matrix

| Class | Identity | Integrity | Trust radius | Mutation | Encryption at rest |
|---|---|---|---|---|---|
| **Temp** | (process's bound Principal) | (process memory) | process-local | in place | N/A |
| **Private CambiObject** | Creator Principal | Device MAC | this device | immutable record; binding retargets | yes |
| **Public CambiObject** | Author Principal + signature | Ed25519 signature | cross-device (ecosystem) | immutable, permanent | yes |
| **Distribution artifact** | Distribution Principal + signature | Ed25519 signature | ecosystem read-only | replaced by update | implementation-defined |

### Ownership transfer on save

Temp bytes are owned by the authoring process. The **save** operation is a structured transfer:

1. Kernel reads the buffer from the process (page-walked user memory).
2. Kernel computes the Blake3 hash.
3. Kernel mints a private record: content, hash, tier-tag, Creator Principal, device MAC over (content || header).
4. Kernel encrypts the record under the device key before writing to disk.
5. Returns the hash to the authoring process, which updates its binding (name → hash) through fs-service.

The Creator Principal defaults to the saving process's bound Principal, but an optional **"Creator-as" delegation** is supported for system services acting on behalf of a user (auto-save daemons, sync agents). The delegation is capability-gated — a service cannot claim an arbitrary Principal as Creator; it must hold a delegated-authoring capability granted by the user Principal it is acting for.

### Naming, mutation, and chain of custody

Private and public records are both immutable. What mutates is a separate **binding** maintained by fs-service: a `(name, current_hash, class, history)` structure owned by a Principal.

- Editing a file = reading content via the binding, modifying in temp, saving a new private record, retargeting the binding's `current_hash`.
- The binding's `history` is append-only and **unbounded by default** — every prior save stays in the chain, forming a chain of custody for the file. Pruning is a user/policy concern, not an architectural one; devices under storage pressure can expose pruning operations, but the format does not impose a cap.
- Publishing (see below) is recorded in the history as a promotion marker, not a fork. There is one thread of edits per binding; public records are point-in-time snapshots along that thread.

Bindings themselves are private CambiObjects serialized by fs-service into well-known locations under the owner's namespace. Naming lives inside fs-service; it is not a separate service — the cases where a name→thing mapping happens outside filesystem concerns (DID resolution, capability aliases, IPC endpoint names) are different namespaces with different trust models and live in their own services.

### Share as the promotion trigger (no standalone publish)

Promotion from private to public is **not** a standalone ceremony. It happens automatically at the moment content crosses the device boundary outbound — cross-device IPC, Yggdrasil send, dweb publication, any transport that carries bytes off this device.

Flow, at the boundary:

```
outbound_share(hash, recipient_or_channel) {
    1. Load record by hash. Verify device MAC. Decrypt.
    2. Inspect tier:
         - Public: transmit directly.
         - Private: require presence proof (signing authority
           reachable). If absent → fail fast with
           PresenceRequired; caller prompts user or queues.
    3. Presence-proved path:
         a. User (via key-store or presence-gated service) signs:
              content || blake3_hash || share_timestamp || recipient
         b. Kernel updates the record in-place:
              - tier_tag: PRIVATE → PUBLIC
              - add: author_principal, signature, provenance
         c. fs-service updates the binding's history with a
            promotion marker at the current hash.
    4. Transmit the (now-public) record.
}
```

Key consequences:

- One record per hash, ever. Tier is a mutable field in the record header; promotion flips the tag. No dual entries for the same hash. No ADR-010 keying divergence.
- Audit is natural: every promotion is a share; every share is recorded with provenance. "Here's what you shared, with whom, when" falls out for free.
- "Publish without sharing" is not a primary path. If it becomes useful (offline staging, pre-authored attestations), it is an explicit exception added later.

For attestations created by programs *without* going through a private-save stage (e.g., a service directly mints a signed attestation from computed content), `SYS_OBJ_PUT_SIGNED` remains the direct path. It writes a public record at creation time with an already-computed signature. This is distinct from share-triggered promotion and serves programs that are already operating inside an authorized signing context.

### Encryption at rest

Every record written to the filesystem is encrypted under a per-device symmetric key, regardless of tier:

- **Device key:** generated at first boot from hardware entropy, persisted in a reserved superblock slot, never transmitted off-device. In sovereign-silicon deployments, sealed to the platform.
- **Cipher:** authenticated encryption (AEAD). XChaCha20-Poly1305 and AES-GCM are both candidates; final choice deferred to implementation. AArch64, x86_64, and RISC-V all target platforms with hardware crypto acceleration (ARMv8 crypto extensions, AES-NI, RISC-V scalar-crypto).
- **Framing:** per-record nonce, AEAD tag covers (tier-tag || header || ciphertext).
- **Relationship to identity material:** the device encryption key and the device MAC key are the same key under an AEAD construction (confidentiality and integrity from one key). They are device facts, not identity material — they protect against local tampering but make no identity claim to any outside observer.

**On-disk format reserves the ciphertext framing from day one.** Early-development builds may use a null/pass-through cipher (identity function) while key management is stabilized, but the record format always carries the AEAD fields. This avoids a format retrofit later. ADR-010 receives a minor amendment (header bytes reserved for tier-tag and AEAD nonce); no structural divergence.

Encryption is orthogonal to tier. A public CambiObject is still encrypted at rest on each device holding it — the user-signature is what makes it cross-device verifiable; the per-device encryption is what protects it locally.

## Decision

### Storage tiers: Temp, Private, Public, Distribution

Four classes, three in the commitment ladder (Temp → Private → Public), one sibling (Distribution). Each has its own identity semantics, trust radius, and lifecycle. Tier is encoded in a one-byte tag in every ObjectStore record header.

### Share-triggered promotion, no standalone publish syscall

No `SYS_OBJ_PUBLISH`. Promotion is performed inline by the transport layer at the outbound device boundary, as part of the share operation. The transport invokes kernel-side promotion helpers; the helpers require presence proof before flipping the tier tag and adding signature/provenance.

### One record per hash; tier transitions in-place

When a private record is promoted, its tier tag flips and signature/provenance fields are appended within the existing record slot. No new record is minted. No (hash, tier) dual-keying. ADR-010's mount scan continues to key by hash alone.

### Save = ownership transfer + Creator mint

`SYS_OBJ_SAVE_PRIVATE` (replacing direct use of `SYS_OBJ_PUT_JUNIOR` as named in the draft) transfers temp-owned bytes to a private record, stamps Creator from the saving Principal (or delegated Principal if a `CreatorAs` capability is held), computes the device MAC, and encrypts before writing. Returns the content hash.

`SYS_OBJ_PUT_SIGNED` stays for programs minting public records directly (already-signed attestations, not saved-and-shared content).

### Bindings live in fs-service

Name → hash mapping, history, and per-Principal namespacing are all fs-service responsibilities. Bindings are themselves stored as private CambiObjects in a reserved system namespace. No separate bindings service.

### Unbounded binding history

Binding history is append-only and not automatically pruned. Chain of custody is preserved by default; devices under storage pressure can expose pruning UI but the architecture does not impose a cap.

### Ownership and access control on private records

Private records are owned by their Creator Principal. Access (read, share, delete) by another Principal requires an explicit capability grant from the owner. Ownership is the intrinsic partition; capabilities handle delegated access. The ObjectStore itself remains flat; fs-service enforces ownership-scoped reads and grant-based cross-Principal access.

### New capabilities

- `CapabilityKind::ShareObject` — **session-scoped.** Held by a Principal from the moment presence is re-proved at strong-proof level, for the duration of the presence session. Gates the share-triggered promotion path. Granted at presence re-proof; revoked at presence lapse, explicit lock, or session timeout. Within a session, no per-share re-proof required; shares flow at the pace the user works.
- `CapabilityKind::CreatorAs` — held by system services authorized to stamp Creator as a user Principal (auto-save, sync). Granted by the user Principal being impersonated, time-bounded, explicitly scoped.

### Encryption at rest, mandatory by format

All records encrypted with a device AEAD key. Format reserves framing from day one; early-dev implementations may use a null cipher; v1 release targets real AEAD.

### Device state migrates into the private tier

ADR-007 audit drain pointers, recognition records (enrolled pubkeys from the enrollment ceremony), policy-service configuration, and session-persistence state are all stored as private CambiObjects owned by a reserved system Principal. The "device state has no persistence plan" gap surfaced in the ADR-015 design conversation is retired.

### Rename: arcobj → cambiobj

The shell utility that exposes ObjectStore operations is renamed to `cambiobj` as part of the CambiOS → CambiOS rebrand debt. Tier-aware subcommands added in the same pass: `cambiobj list [--tier=private|public|all]`, `cambiobj history <name>`, `cambiobj share <name> <recipient>` (presence-gated).

## Rationale

### Why one primitive across tiers, not separate systems

A separate storage tier for working files (the pre-draft "Shape B") would mean two on-disk formats, two services, two crash-consistency stories, two mount scans. The content-layer concern ("store bytes, index by hash") is identical for private and public; what differs is identity semantics, not storage mechanics. Sharing the primitive keeps the ObjectStore as one system with a tier field.

### Why private ≠ weakened public

Softening CambiObject's invariant ("every record has an author and a signature") to accommodate drafts — "Shape A" in the design conversation — would make the load-bearing invariant conditional. Every consumer downstream would have to distinguish signed-mode from unsigned-mode on the same type, and failures of the form "I thought this was signed" would become bugs waiting to be written. Giving private its own tier keeps the full CambiObject invariant intact: any operation that expects a public record gets one with all its guarantees.

### Why share triggers promotion, not a standalone publish

Publishing in the abstract ("I decide to commit this publicly") is a contortion; nobody publishes except as part of sharing. Binding promotion to the share event makes the moment of commitment observable (audit records every share), makes it meaningful in the UI (confirm-share dialog IS the publish ceremony), and avoids a category of "ready-to-share but not shared" intermediate state with no natural consumer. Programs that need to mint pre-signed attestations still have `SYS_OBJ_PUT_SIGNED`; that path is distinct and serves a different use case.

### Why one mutable object, no fork

A fork model (keep editing the private after publishing the public) creates a parallel timeline with two hashes, two pointers, and UI questions about "which one is current." The single-mutable-object model — one thread of edits, public records as markers in the binding's history — matches how humans actually think about files. "I shared this at version 4. I've since edited to version 6. Version 4 is still out there; version 6 is what I'm working on now." The chain of custody carries the promotion point as a historical fact without branching the structure.

### Why encryption is mandatory, not optional

CambiOS's posture is "verifiably yours." Plaintext at rest would mean anyone with physical access to the device (or a compromised service with disk-read capabilities) can read every stored byte. Encryption at rest is table stakes for a 2026 security-focused OS; hardware acceleration is universally available on the three target architectures; the cost is roughly 1 cycle per byte. Making it mandatory in the format (with a null-cipher escape hatch for early dev) prevents a retrofit.

### Why bindings are inside fs-service

A separate bindings service was considered and rejected. Cases where a name→thing mapping is useful outside filesystem concerns (DID resolution, capability aliases, IPC endpoint names) are each their own namespace with their own trust model and their own service. There is no general-purpose bindings primitive that buys itself across those cases. Keeping bindings inside fs-service keeps filesystem cohesion.

### Why session-scoped share capability

Four granularities were considered: per-share fresh proof, session-scoped, scope-limited session (N shares or specific recipients), interactive-confirm (session-scoped but each share prompts a UI confirm). Per-share fresh proof is strongest but punishing — sharing 10 files = 10 gestures, and friction that users route around is worse than weaker security honestly implemented. Scope-limited adds UI complexity (pre-declaring what a session covers) before there's evidence that users need it. Interactive-confirm mixes a software gate into a security boundary that is supposed to be hardware-gated, which muddles the model.

Session-scoped is the clean middle: a strong ratchet at session start (presence re-proof) followed by frictionless operation within the session. Compromise windows are bounded by the session timeout, not by individual share friction. Session timeout itself is a policy value (see Open Questions) configurable by the user.

## Open Questions

1. **Presence session timeout.** Session-scoped sharing (Decision) is bounded by how long a presence session lasts. Policy values — idle timeout, hard timeout, event-based invalidation (USB eject, lid close, explicit lock) — are user-configurable; defaults TBD at first share-UI design. Likely layered: short timeout for share-capability specifically, longer timeout for general UI access.

2. **Promotion UX when presence is absent.** When the transport hits a private object and no presence session is active, does the caller block (prompt user, wait for gesture), fail fast (surface PresenceRequired, caller handles), or queue (stash the share intent, fire when presence returns)? Likely all three behaviors should be available; caller picks per-call. TBD at first share-integration phase.

3. **Binding-history pruning UI.** Unbounded history is the architectural default; devices under storage pressure need a user-facing way to prune. Should pruning be policy-driven (oldest-N, older-than-T), file-by-file explicit, or wholesale? Deferred.

4. **Device key rotation.** What triggers rotation? What re-encrypts existing records? Leaning: no rotation in v1; design when the first reason appears (hardware replacement, suspected compromise, policy).

5. **Multi-recipient shares.** A single share to multiple recipients — does each recipient get its own promotion event in the binding history, or one promotion with a multi-recipient record? Leaning: one promotion event per share-target; multi-recipient share = N promotion events recorded atomically. TBD.

6. **Distribution-artifact encryption.** Kernel and boot modules are currently plaintext on the ESP / boot volume. Do they get encryption too, or does "read by firmware before the OS is up" force them to stay plaintext? Probably the latter; worth a Divergence entry or a follow-on ADR if it matters.

7. **Binding serialization format.** Bindings-as-private-records need a concrete serialization. Likely a small CBOR-like table; specific format deferred to implementation.

## Divergence

(None yet — to be appended as implementation reveals what needs correcting.)
