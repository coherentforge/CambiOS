<!--
doc_type: design_plan
owns: identity + storage architecture sequencing
auto_refresh: forbidden
last_synced_to_code: N/A (intent doc, not status)
authoritative_for: phase intent, settled architectural decisions for identity + storage
-->

# CambiOS Identity + Storage Architecture — Design Plan

> **Intent doc.** This file captures *what we are building and why*, in dependency order. It does **not** track current status — that lives in [STATUS.md § Phase markers](../STATUS.md#phase-markers). It does **not** carry implementation details for how each phase looks in code — that lives in the code itself, in the per-subsystem reference docs (e.g. [SECURITY.md](SECURITY.md), [SCHEDULER.md](../src/scheduler/SCHEDULER.md)), and in the relevant ADRs.
>
> If you are looking for "is phase X done?" — read [STATUS.md](../STATUS.md). If you are looking for "what does phase X mean and why are we building it that way?" — you are in the right document.

## Context

CambiOS has a working microkernel (preemptive multitasking, SMP, ring-3 user tasks, IPC + capabilities, zero-trust interceptor, Limine module loading). The decisions on identity and storage are philosophically and practically the most consequential architectural decisions in the project so far. Because it defines what a "file" means, and respects sovereignty at the user and data object level, this decision propagates into every object the system touches.

This plan reflects design decisions made through extended discussion. It is a working document and subject to change. The authoritative design documents are:

- **[identity.md](identity.md)** — what identity *is* in CambiOS (Ed25519 Principals, biometric commitment, recovery model, did:key)
- **[CambiOS.md](CambiOS.md)** — source-of-truth architecture document that constrains every plan including this one

This plan is the implementation sequencing that flows from those two documents.

See something off? Share, please.

## Foundational Principle

**Is it robust and secure? Does it keep the protocol open, or does it tie behavior to a specific implementation?** Every architectural decision should be evaluated against this.

**CambiOS is a protocol as much as an OS.** The CambiOS microkernel enables secure hardware access to a system of open protocols. The identity and storage layers define a protocol specification *as* the implementation. Any system that implements the `ObjectStore` trait (content-addressed signed objects with author/owner), uses Ed25519 Principals for identity, and speaks SSB for inter-instance communication is a compatible peer — regardless of what kernel, language, or hardware it runs on.

The microkernel is the reference implementation: by design the most security-hardened, sovereignty-respecting version of the protocol, but not the only valid one. Forks are extensions of the network, not threats to it. This is a direct consequence of "no attestation, no gatekeeper" ([identity.md](identity.md)): by not requiring instance attestation, CambiOS is defined by its protocol, not its binary.

## Settled Decisions

These are the load-bearing decisions for the identity and storage layers. They constrain everything below them. Changing one of these is an ADR-level event.

**Every file has an owner AND an author** — two distinct roles at the object level. Author is the Ed25519 public key of whoever created the object — immutable, set at creation, never changes. Owner is the Ed25519 public key of whoever currently controls the object — transferable via signed ownership transfer objects. The owner signs the object (tying content to controller). Example: an employee creates a document at work — they are the author, but the employer is the owner. An independent contractor creates a document — they are both author and owner unless a contract transfers ownership. Files are signed artifacts, not bytes at a path.

**Content-addressed object store** — files are CambiObjects identified by Blake3 content hash. Names/paths are a separate layer (a "directory" is itself an CambiObject mapping names to hashes). This is the native storage model.

**ObjectStore trait as the VFS abstraction** — not a traditional block-device VFS. Local storage, sovereign cloud, P2P logs, and RAM are all backing store implementations behind the same trait. The seams are in the right place from day one.

**Ed25519 now, hybrid Ed25519 + ML-DSA (post-quantum) as production target** — ML-DSA signatures are 3309 bytes vs 64. The on-disk format needs variable-length signature fields from day one. See [ADR-004](adr/004-cryptographic-integrity.md) for the cryptographic integrity rationale.

**Bootstrap identity** — minimal, temporary in implementation, permanent in interface. Kernel uses a bootstrap Principal (compiled-in YubiKey-derived public key in current implementation; private key never enters kernel memory). Same `sign()` / `verify()` / `Principal` interface throughout. Per [ADR-003](adr/003-content-addressed-storage-and-identity.md).

**Kernel stamps `sender_principal` on IPC messages** — zero-cost unforgeable identity for local IPC. Signatures only at network boundaries (future). The `sender_principal` field is set by the kernel in the IPC send path; user-space cannot forge it. Per [ADR-003](adr/003-content-addressed-storage-and-identity.md) and [ADR-002](adr/002-three-layer-enforcement-pipeline.md).

**Eventually-consistent revocation** — owner publishes signed revocation to their append-only log. Propagation via SSB-inspired social layer. Not instant, but violations are detectable and consequential. Architecturally supported but not implemented in early phases. The kernel-level capability revocation primitive (a separate concern for in-kernel capability management) is specified in [ADR-007](adr/007-capability-revocation-and-telemetry.md).

**did:key as the DID method** — self-contained, no resolver, no registry, verification is pure cryptography.

**Biometric commitment for key derivation (future)** — context vector (biometric scan + device entropy + social attestation) anchors identity to a physical person. Primary modality: retinal scan (vascular pattern is unique, stable over lifetime, not shared in normal social contexts). Secondary/fallback: facial geometry. ZKP for privacy — prove identity without revealing biometric data. Recovery via biometric proof + social quorum. Interface slot exists from Phase 0 via `IdentityContext`. DNA was considered but rejected due to genetic privacy concerns and the impracticality of casual DNA scanning.

**SSB bridge with tinySSB fallback (future)** — gateway service bridging capability grants and identity attestations across transport boundary. Primary: full SSB — mature protocol, established social replication model, aligns with eventually-consistent revocation via append-only logs. Fallback: tinySSB — for constrained environments (IoT, low-bandwidth P2P links). The bridge service negotiates: SSB when bandwidth allows, tinySSB when it doesn't. Progressive ML-DSA sync over both transports (Ed25519 in-band, ML-DSA when bandwidth allows).

**Signed modules** — every user-space module (ELF binary) must be signed by a trusted Principal before the kernel will execute it. Without this, a malicious actor could craft a module that operates within the architecture's constraints (valid ELF, passes W^X checks, uses correct syscall ABI) but performs harmful actions. The existing `BinaryVerifier` gate in the loader is the enforcement point — it has been extended to require a valid signature over the ELF content. The signing key's Principal must be in a trusted set (initially just the bootstrap Principal; later, a configurable trust anchor list). Per [ADR-004](adr/004-cryptographic-integrity.md).

**Ownership transfer model** — ownership of an `CambiObject` is transferred via a signed `OwnershipTransfer` object: the current owner signs a statement delegating ownership to a new Principal. The transfer object itself is an `CambiObject` (content-addressed, signed, stored in the ObjectStore). This creates an auditable chain of custody. The original author field remains immutable — authorship is historical fact, ownership is current control.

**Connected by consent, no attestation required** — each CambiOS instance generates its own bootstrap keypair independently. No shared root key, no instance attestation, no gatekeeper. The system is not isolated or monopolized — anyone can build a compatible instance that speaks the same protocol (`ObjectStore` trait + SSB bridge + Ed25519 signatures). Connection is bilateral consent: when you consent to connect with another Principal, they can send objects directly to your `ObjectStore` — not via email or intermediary, but Principal-to-Principal transfer over the SSB bridge, landing in sovereign storage you control. Consent has concrete mechanics: their Principal is added to your trust list with specific `ObjectRights` (send, but maybe not delete or modify). The social UI surfaces incoming objects. You choose whether to accept ownership transfer or hold a copy they still own. The virtual world mirrors the real one — there are people you don't want to connect with, and the architecture respects that by making connection opt-in with no default trust.

**Copy resistance** — CambiOS objects are persistent and unique. Because every object is content-addressed and signed by its owner, creating a "copy" means creating a new object with a new owner signature — the copy is a distinct object with its own identity, not a duplicate. This makes unauthorized copying detectable (the original's lineage doesn't include the copy) and the copy cannot claim to be the original.

## Phase Intent (in dependency order)

This section describes *what each phase is for* — the architectural goal, the thing that becomes possible after the phase, and the constraints that justify its scope.

For *current implementation status* of each phase (built / in progress / planned), see [STATUS.md § Phase markers](../STATUS.md#phase-markers).

For *implementation details* of each phase (which structs, which files, which syscalls), the source of truth is the code itself. Each subsystem has its own implementation reference doc that auto-refreshes when the code changes.

### Phase 0 — Identity primitives in the kernel + RAM-backed ObjectStore

**Goal:** Make the storage object model coherent. Every IPC message carries an unforgeable sender identity. Every stored object has an author and an owner. A filesystem service can exist in user-space and enforce ownership without trusting its callers' self-claimed identities.

**Why this is the foundation:** Without `sender_principal` stamping in the kernel, ownership enforcement has to rely on user-space trust — which means it has no foundation at all. Without the `ObjectStore` trait, every storage backend reinvents the same access model. Phase 0 establishes both at minimal scope: identity primitives in the IPC layer, CambiObject as the storage unit, RAM-backed implementation that proves the trait works.

**Scope:** kernel `Principal` type, `sender_principal` on IPC `Message`, `BindPrincipal`/`GetPrincipal` syscalls, `CambiObject` data structure, `ObjectStore` trait, RAM-backed implementation, FS service as user-space ELF on a dedicated IPC endpoint.

**Out of scope:** real cryptography (Phase 0 uses placeholder hashing and unsigned objects), persistent storage (RAM only), key management (private key in a kernel static), signed ELF loading (loader still passes any structurally valid binary).

**Cross-references:** [ADR-003](adr/003-content-addressed-storage-and-identity.md) — Content-Addressed Storage and Cryptographic Identity — is the ADR that captures Phase 0's design rationale.

### Phase 1 — Real cryptography

**Goal:** Replace Phase 0's placeholder hashing and unsigned objects with production-grade cryptography. Once Phase 1 is in, content addresses are collision-resistant, ownership claims are verifiable, and the boot module set is provably authentic.

**Why this comes second:** Phase 0 establishes the data model and the interfaces. Phase 1 makes the security claims real. Doing them in this order means the interfaces don't change between phases — only the implementations of `compute_hash()` and `verify_signature()` change. The migration is non-breaking: Phase 0 tests continue to pass, with crypto added on top.

**Scope:** Blake3 for content hashing (replaces FNV-1a), Ed25519 signature verification on `ObjPut` (ownership becomes provable), signed ELF modules (`BinaryVerifier` extended to require a valid Ed25519 signature; host-side signing tool produces signed binaries at build time), real entropy for the bootstrap keypair (replacing the deterministic Phase 0 seed).

**Out of scope:** key management isolation (private key still in a kernel static; that's Phase 1B/1C), post-quantum signatures (deferred to Phase 4), ownership transfer signatures (deferred to Phase 2).

**Cross-references:** [ADR-004](adr/004-cryptographic-integrity.md) — Cryptographic Integrity (Blake3 + Ed25519) — captures the algorithm choices and migration path.

### Phase 1B — Hardware-backed bootstrap identity

**Goal:** Move the bootstrap private key out of the kernel entirely. Once Phase 1B is in, no part of the bootstrap private key ever enters kernel memory; the public key is compiled in (extracted from the YubiKey at build time), and signing happens on the YubiKey itself via the OpenPGP smart card interface during the host-side signing tool's run.

**Why this matters:** A private key in a kernel static is a kernel compromise away from being exfiltrated. Hardware-backed keys are a structural defense — the secret never lives in software, so software compromise cannot leak it.

**Scope:** YubiKey as the root of trust for boot module signing, `sign-elf` host tool that talks to the YubiKey's OpenPGP applet, `bootstrap_pubkey.bin` as the only key material in kernel memory (a public key, not a secret), `--seed` mode in `sign-elf` for CI/dev workflows that don't have a YubiKey.

**Out of scope:** runtime YubiKey access from the running kernel (requires USB HID, deferred to post-v1), key rotation, multi-key trust anchors.

### Phase 1C — Key-store service in degraded mode + signed ObjectStore puts

**Goal:** Move the key-handling logic out of the kernel entirely, even for the bootstrap identity. Establishes the user-space key-store as the gateway for all signing operations. Phase 1C ships a key-store service that runs in "degraded mode" — it has no access to a private key (the YubiKey lives only on the build host, not at runtime) — but the IPC interface and the FS service's calling convention are real. When runtime YubiKey access is added later, the key-store transitions out of degraded mode without changes to its consumers.

**Why this matters:** It establishes the architectural boundary. The kernel manages identity *binding* (which Principal belongs to which process); user-space manages identity *material* (where the keys live, how signing happens). The boundary is real even when one side is currently a no-op.

**Scope:** `user/key-store-service/` with an IPC endpoint for signing requests, `ObjPutSigned` syscall for storing pre-signed objects in the kernel ObjectStore, fs-service requests signing from the key-store before calling `ObjPut` (and falls back to unsigned puts when the key-store is in degraded mode), `ClaimBootstrapKey` syscall as the one-shot kernel→user transfer of any bootstrap secret material that exists.

**Out of scope:** runtime YubiKey communication (requires USB HID — post-v1), per-process derived keys for delegated signing (requires the biometric/social work in later phases), hardware-backed sealed storage of derived keys (TPM/Secure Enclave integration — long-term).

### Phase 2A — First user-space hardware driver (network)

**Goal:** Prove the user-space driver pattern works on real hardware semantics (PCI discovery, virtqueues, DMA, hostile-device validation). Establishes the template that all subsequent device drivers will follow — disk, USB, GPU, audio, etc.

**Why this comes after identity/storage:** Drivers are downstream consumers of the capability and identity model. Doing identity first means drivers are signed-and-verified from the start; doing the driver pattern first would have meant retrofitting identity into a driver model that didn't expect it.

**Scope:** `user/virtio-net/` as a Rust `no_std` ELF driver, PCI bus scan in the kernel (with results exposed via `DeviceInfo` syscall), `MapMmio` and `AllocDma` syscalls for kernel-mediated device access, hostile-device validation pattern (`DeviceValue<T>` wrapper), TX/RX virtqueue management with DMA bounce buffers in user-space.

**Out of scope:** real bare-metal NIC drivers (Intel I219-LM is the post-Phase-2A target), interrupt-driven RX (currently polled), zero-copy paths (the virtio-net driver still copies data through bounce buffers — the bulk-data optimization comes with channels in Phase 3).

### Phase 2B — First user-space network service (UDP)

**Goal:** Demonstrate that a complete network stack can run in user-space on top of the driver from Phase 2A, with no kernel networking code. Proves the architectural claim that "networking is a user-space service, not a kernel subsystem."

**Why this matters:** Every conventional OS has its network stack in the kernel, and every conventional OS has been bitten by network-stack vulnerabilities that escalated to root. CambiOS puts the entire stack in ring 3 from day one. A bug in UDP parsing crashes a user-space service; it cannot become a kernel exploit.

**Scope:** `user/udp-stack/` as an ARP + IPv4 + UDP service over the virtio-net IPC interface, NTP demo as a working end-to-end vertical slice, hardcoded SLIRP configuration as the initial network state (DHCP comes later, in the v1 roadmap).

**Out of scope:** TCP (Phase 4 / v1 roadmap item 6), DHCP (paused pending Phase 3 architecture), DNS (depends on DHCP), TLS (depends on TCP), full IP stack with options/fragmentation (the current UDP stack is intentionally minimal).

### Phase 3 — Bulk data path, externalized policy, capability revocation, audit telemetry

**Goal:** The architectural substrate for real workloads. Makes it possible to run video, file I/O, AI inference, and any workload where the kernel cannot be on the data path. Externalizes policy decisions so the AI security layer (post-v1) has somewhere to attach. Adds capability revocation as a kernel primitive so detected misbehavior can be intervened in. Adds an audit telemetry channel so the AI watcher has something to observe.

**Why this is a single phase, not four:** The four pieces are co-dependent. Channels need revocation to handle teardown. Revocation is useful only if there's something deciding when to invoke it — that's the policy service. The policy service is useful only if it has something to observe — that's the audit telemetry channel. Telemetry is useful only if it can drive interventions — that's revocation, again. Doing one without the others produces an incomplete architecture; doing all four at once produces a substrate that everything else can sit on.

**Why this is a *separate phase* from the v1 roadmap items that come after:** DHCP, DNS, TCP, virtio-blk, and persistent storage all benefit from channels. They are not functionally blocked by Phase 3 — DHCP can fit in 256-byte messages with care, TCP can copy through control IPC at terrible throughput — but doing them on the old substrate means rebuilding them later when channels exist. Phase 3 first, then the v1 roadmap on top of the new architecture.

**Scope:**
- **Channels** ([ADR-005](adr/005-ipc-primitives-control-and-bulk.md)): shared-memory data path with capability-gated setup, kernel-mediated only at create/attach/close
- **Policy service** ([ADR-006](adr/006-policy-service.md)): user-space externalization of `IpcInterceptor::on_syscall` decisions, per-CPU caching, fail-open on policy service failure
- **Capability revocation** ([ADR-007](adr/007-capability-revocation-and-telemetry.md)): atomic kernel primitive to invalidate a capability across all holders, with TLB shootdown for channel mappings
- **Audit telemetry** ([ADR-007](adr/007-capability-revocation-and-telemetry.md)): kernel-produced event stream over a dedicated channel, consumed by the policy service (and eventually the AI watcher)

**Out of scope:** the AI watcher itself (post-v1; Phase 3 builds the substrate, the AI plugs in later), per-channel doorbell notification (the simple IPC-notification path is sufficient for v1; doorbells are an optimization), MPMC channels (SPSC is sufficient; MPMC is harder and rarely needed), in-kernel policy interpreter (rejected by ADR-006 in favor of the upcall pattern).

**Cross-references:** [ADR-005](adr/005-ipc-primitives-control-and-bulk.md), [ADR-006](adr/006-policy-service.md), [ADR-007](adr/007-capability-revocation-and-telemetry.md). Phase 3 is the design point where these three ADRs land as a coordinated architecture change.

### Phase 4 — Persistent storage

**Goal:** Replace the RAM-backed `ObjectStore` with a disk-backed implementation. Once Phase 4 is in, content-addressed objects survive reboot, and the v1 milestone of "interactive, network-capable, identity-rooted OS running on real hardware with persistent storage" is achievable.

**Scope:** Virtio-blk driver in user-space (same pattern as virtio-net, on Phase 3's channel substrate for bulk data), disk-backed `ObjectStore` implementation behind the same trait Phase 0 defined, CambiObject CLI in the shell that exercises the storage path end-to-end (`arcobj put`, `arcobj get`, `arcobj list`, `arcobj delete`).

**Out of scope:** VFS / mount infrastructure (post-v1; the FS service stays a flat object gateway in Phase 4), filesystem snapshots, garbage collection of unreferenced objects (deferred until objects accumulate enough to make GC matter), encryption at rest (the ObjectStore stores already-signed objects; encryption is a higher-layer concern).

### Phase 5 — Identity-routed networking

**Goal:** Bridge from IP/DNS-based addressing to Principal-based addressing. Once Phase 5 is in, two CambiOS instances can find and authenticate each other without DNS, without IP assignment, and without trusting any infrastructure beyond the cryptographic primitives CambiOS already has.

**Scope:** Yggdrasil-style mesh networking, Ed25519 Principal → IPv6 mapping (Yggdrasil's `200::/7` address space derives directly from a 32-byte public key), X25519 key exchange derived from Ed25519 keys, Noise protocol handshake, spanning-tree routing, peer-to-peer discovery without bootstrap servers (or with minimal user-controlled bootstrap nodes).

**Why this comes after persistent storage:** Identity-routed networking is the interface to the social layer ([identity.md](identity.md) § "Social Attestation"). The social layer wants to write attestations as `CambiObject`s in the local store. Without persistent storage, the social layer is amnesiac across reboots, which defeats the point of an attestation log.

### Phase 6 — Biometric commitment + key recovery

**Goal:** Solve the "lost key" problem without a central authority. A user whose device is destroyed should be able to regenerate their identity from biological context plus social attestation, not from a backup file or a recovery service.

**Why this is post-v1:** It requires substantial new work (biometric capture, ZKP libraries, social attestation protocol), and it depends on the social layer (Phase 5/7). v1 focuses on the OS being usable; biometric identity is the next-generation user experience layer.

**Scope per [identity.md](identity.md):** retinal scan as primary modality, facial geometry as fallback, zero-knowledge proofs for privacy, social quorum recovery, key rotation protocol with rotation records in the user's append-only log.

### Phase 7 — SSB bridge

**Goal:** Cross-instance identity attestation and capability grants over append-only logs. Once Phase 7 is in, CambiOS instances form a federated network where identities and trust relationships propagate through signed log replication, not through any central directory.

**Scope per [identity.md](identity.md):** SSB protocol implementation (or tinySSB for constrained links), bridge service that translates between IPC capabilities and SSB log entries, eventually-consistent revocation via signed revocation objects in social feeds, progressive ML-DSA signature sync (Ed25519 first, ML-DSA when bandwidth allows).

## Verification Posture

Each phase has its own verification gate. The gates are listed in [STATUS.md § Test coverage](../STATUS.md#test-coverage); the gates themselves are what each phase must pass to be considered done:

**Architectural invariants (apply to every phase):**

- `sender_principal` is set by the kernel only, never by sender code
- `BindPrincipal` syscall is restricted to the bootstrap Principal
- All new identity/storage code is arch-portable (no `#[cfg(target_arch)]` in `src/fs/` or identity-related IPC changes)
- `CambiObject.author` is immutable after creation — no API path allows modification
- `CambiObject.owner` defaults to author at creation — creator is controller unless explicitly transferred
- Ownership transfer requires the current owner's signature (enforced at the ObjectStore level once cryptography is in)
- Lock ordering is maintained: `OBJECT_STORE` is at position 8 (highest-numbered system lock), see [ADR-001](adr/001-smp-scheduling-and-lock-hierarchy.md)

These invariants survive across phases. New phases may add new invariants but cannot weaken these.

## Cross-references

- **[CambiOS.md](CambiOS.md)** — source-of-truth architecture document
- **[identity.md](identity.md)** — identity architecture, key lifecycle, biological model
- **[STATUS.md](../STATUS.md)** — current implementation status of every phase and subsystem
- **[ADR-003](adr/003-content-addressed-storage-and-identity.md)** — Phase 0 design rationale
- **[ADR-004](adr/004-cryptographic-integrity.md)** — Phase 1 cryptographic primitives
- **[ADR-005](adr/005-ipc-primitives-control-and-bulk.md)** — Phase 3 channels
- **[ADR-006](adr/006-policy-service.md)** — Phase 3 policy externalization
- **[ADR-007](adr/007-capability-revocation-and-telemetry.md)** — Phase 3 revocation + telemetry
- **[CLAUDE.md](../CLAUDE.md)** — kernel technical reference and required-reading map
- **[SECURITY.md](SECURITY.md)** — current enforcement status, gap analysis
