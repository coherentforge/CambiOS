# ArcOS Identity + Storage Architecture — Implementation Plan

## Context

ArcOS has a working microkernel (preemptive multitasking, SMP, ring-3 user tasks, IPC + capabilities, zero-trust interceptor, Limine module loading). The next critical decisions are on identity and storage — philosophically and practically the most consequential architectural decision in the project so far. Because it defines what a "file" means, and respects sovereignty at the user and data object level, this decision propagates into every object the system touches.

This plan reflects design decisions made through extended discussion but is a working document and subject to change. The authoritative design document is [identity.md]. This plan is the implementation sequencing that flows from it.

See something "off"? Share, please.


---

## Foundational Principle

Is it robust and secure? Does it keep the protocol open, or does it tie behavior to a specific implementation? Every architectural decision should be evaluated against this.

**ArcOS is a protocol as much as an OS.** The ArcOS microkernel enables secure hardware access to a system of open protocols. The identity and storage layers define a protocol specification as the implementation. Any system that implements the ObjectStore trait (content-addressed signed objects with author/owner), uses Ed25519 Principals for identity, and speaks SSB for inter-instance communication is a compatible peer — regardless of what kernel, language, or hardware it runs on. The microkernel is the reference implementation: by design the most security-hardened, sovereignty-respecting version of the protocol, but not the only valid one. Forks are extensions of the network, not threats to it. This is a direct consequence of "no attestation, no gatekeeper" ([identity.md]): by not requiring instance attestation, ArcOS is defined by its protocol, not its binary.

---

## Settled Decisions

**Every file has an owner AND an author** — two distinct roles at the object level. Author is the Ed25519 public key of whoever created the object — immutable, set at creation, never changes. Owner is the Ed25519 public key of whoever currently controls the object — transferable via signed ownership transfer objects. The owner signs the object (tying content to controller). Example: an employee creates a document at work — they are the author, but the employer is the owner. An independent contractor creates a document — they are both author and owner unless a contract transfers ownership. Files are signed artifacts, not bytes at a path.

**Content-addressed object store** — files are ArcObjects identified by Blake3 content hash. Names/paths are a separate layer (a "directory" is itself an ArcObject mapping names to hashes). This is the native storage model.

**ObjectStore trait as the VFS abstraction** — not a traditional block-device VFS. Local storage, sovereign cloud, P2P logs, and RAM are all backing store implementations behind the same trait. The seams are in the right place from day one.

**Ed25519 now, hybrid Ed25519 + ML-DSA (post-quantum) as production target** — ML-DSA signatures are 3309 bytes vs 64. The on-disk format needs variable-length signature fields from day one.

**Bootstrap identity** — minimal, temporary in implementation, permanent in interface. Kernel generates keypair from device entropy. Private key moves to key store service later. Same sign()/verify()/Principal interface throughout.

**Kernel stamps sender_principal on IPC messages** — zero-cost unforgeable identity for local IPC. Signatures only at network boundaries (future).

**Eventually-consistent revocation** — owner publishes signed revocation to their append-only log. Propagation via SSB-inspired social layer. Not instant, but violations are detectable and consequential. Architecturally supported but not implemented in Phase 0.

**did:key as the DID method** — self-contained, no resolver, no registry, verification is pure cryptography.

**Biometric commitment for key derivation (future)** — context vector (biometric scan + device entropy + social attestation) anchors identity to a physical person. Primary modality: retinal scan (vascular pattern is unique, stable over lifetime, not shared in normal social contexts). Secondary/fallback: facial geometry. ZKP for privacy — prove identity without revealing biometric data. Recovery via biometric proof + social quorum. Interface slot exists from Phase 0 via IdentityContext. DNA was considered but rejected due to genetic privacy concerns and the impracticality of casual DNA scanning.

**SSB bridge with tinySSB fallback (future)** — gateway service bridging capability grants and identity attestations across transport boundary. Primary: full SSB — mature protocol, established social replication model, aligns with eventually-consistent revocation via append-only logs. Fallback: tinySSB — for constrained environments (IoT, low-bandwidth P2P links). The bridge service negotiates: SSB when bandwidth allows, tinySSB when it doesn't. Progressive ML-DSA sync over both transports (Ed25519 in-band, ML-DSA when bandwidth allows).

**Signed modules** — every user-space module (ELF binary) must be signed by a trusted Principal before the kernel will execute it. Without this, a malicious actor could craft a module that operates within the architecture's constraints (valid ELF, passes W^X checks, uses correct syscall ABI) but performs harmful actions. The existing BinaryVerifier gate in the loader is the enforcement point — it will be extended to require a valid signature over the ELF content. The signing key's Principal must be in a trusted set (initially just the bootstrap Principal; later, a configurable trust anchor list).

**Ownership transfer model** — ownership of an ArcObject is transferred via a signed OwnershipTransfer object: the current owner signs a statement delegating ownership to a new Principal. The transfer object itself is an ArcObject (content-addressed, signed, stored in the ObjectStore). This creates an auditable chain of custody. The original author field remains immutable — authorship is historical fact, ownership is current control.

**Connected by consent, no attestation required** — each ArcOS instance generates its own bootstrap keypair independently. No shared root key, no instance attestation, no gatekeeper. The system is not isolated or monopolized — anyone can build a compatible instance that speaks the same protocol (ObjectStore trait + SSB bridge + Ed25519 signatures). Connection is bilateral consent: when you consent to connect with another Principal, they can send objects directly to your ObjectStore — not via email or intermediary, but Principal-to-Principal transfer over the SSB bridge, landing in sovereign storage you control. Consent has concrete mechanics: their Principal is added to your trust list with specific ObjectRights (send, but maybe not delete or modify). The social UI surfaces incoming objects. You choose whether to accept ownership transfer or hold a copy they still own. The virtual world mirrors the real one — there are people you don't want to connect with, and the architecture respects that by making connection opt-in with no default trust.

**Copy resistance** — ArcOS objects are persistent and unique. Because every object is content-addressed and signed by its owner, creating a "copy" means creating a new object with a new owner signature — the copy is a distinct object with its own identity, not a duplicate. This makes unauthorized copying detectable (the original's lineage doesn't include the copy) and the copy cannot claim to be the original.

---

## Source of Truth

- [identity.md](identity.md) — identity architecture, key lifecycle, biological model, implementation roadmap
- [CLAUDE.md](CLAUDE.md) — kernel technical reference, lock ordering, build commands, development conventions
- This plan — implementation sequencing only

---

## What Gets Built (Phase 0)

Phase 0 is the minimum needed to make the storage object model coherent. It has two parts: kernel identity primitives (stamps identity onto IPC) and the ObjectStore trait + RAM-backed implementation. Together they let a filesystem service exist in user-space, enforce ownership, and serve objects — all in RAM, no disk, no crypto crate yet.

### Part A: Kernel Identity Primitives

**Goal:** Every IPC message carries an unforgeable sender identity. Processes have a cryptographic Principal bound to them.

**A1. Principal type** (`src/ipc/mod.rs`)

```rust
Principal { public_key: [u8; 32], key_hash: [u8; 16] }
```

- `from_public_key()` constructor computes `key_hash` (FNV-1a, not cryptographic — fast comparison only)
- PartialEq/Eq based on full `public_key` (not hash)
- Debug shows first 8 bytes hex

**A2. sender_principal on Message** (`src/ipc/mod.rs`)

- Add `sender_principal: Option<[u8; 32]>` field to `Message`
- Update `Message::new()` to initialize it as `None`
- Kernel stamps it in `send_message_with_capability()` — looks up sender's Principal from CapabilityManager, copies public_key into the field
- Sender cannot forge it — the kernel sets it, not the sender

**A3. Principal on ProcessCapabilities** (`src/ipc/capability.rs`)

- Add `principal: Option<Principal>` field to `ProcessCapabilities`
- Add `bind_principal()` and `get_principal()` methods on `CapabilityManager`
- `bind_principal()` restricted: only callable for processes that don't already have a Principal bound (rebinding requires explicit unbind first — prevents identity theft)

**A4. New syscalls** (`src/syscalls/mod.rs`, `src/syscalls/dispatcher.rs`)

- `BindPrincipal = 11` — identity service binds a Principal to a ProcessId. Args: process_id (u32), pubkey_ptr (*const u8), pubkey_len (must be 32). Restricted to the identity service process (checked by Principal — only the bootstrap Principal can call this).
- `GetPrincipal = 12` — process reads its own Principal. Args: out_buf (*mut u8), buf_len (must be >= 32). Returns 32 bytes of public key or error if no Principal bound.

**A5. Bootstrap Principal** (`src/microkernel/main.rs`)

- At boot, after heap init, generate a 32-byte "bootstrap public key" from RDRAND (x86_64) or device entropy
- For Phase 0: use a deterministic seed (no real crypto yet — just a fixed 32-byte value that serves as the bootstrap identity)
- Bind this as the Principal for kernel processes and the identity service (when it exists)
- Store the bootstrap Principal in a global static for the BindPrincipal restriction check

**A6. IPC stamping integration**

- `send_message_with_capability()` in `src/ipc/mod.rs`: after capability check passes, look up sender's Principal from cap_mgr, stamp `msg.sender_principal`
- This requires the CapabilityManager reference to be available — it already is (passed as `&capability::CapabilityManager`)

---

### Part B: ObjectStore Trait + ArcObject

**Goal:** Define the native storage abstraction and a RAM-backed implementation. No disk, no crypto verification yet — just the data model and trait.

**B1. ArcObject type** (`src/fs/mod.rs` — new module)

```rust
pub struct ArcObject {
    pub content_hash:  [u8; 32],         // Blake3 hash (the object's address)
    pub author:        [u8; 32],         // Ed25519 public key of creator (IMMUTABLE)
    pub owner:         [u8; 32],         // Ed25519 public key of current controller (transferable)
    pub sig_algo:      SignatureAlgo,    // Ed25519 or ML-DSA (future)
    pub signature:     SignatureBytes,   // Owner's signature over content (variable-length)
    pub capabilities:  ObjectCapSet,    // Access grants
    pub lineage:       Option<[u8; 32]>, // Hash of parent object (provenance chain)
    pub created_at:    u64,              // Monotonic timestamp (ticks)
    pub content:       ObjectContent,    // The actual data
}
```

- `author` is set at creation time and never changes. It records who created the object — historical fact.
- `owner` is the current controller. It starts as the author (creator = controller by default). Ownership can be transferred via a signed OwnershipTransfer object (see settled decisions). The owner signs the object.
- `SignatureAlgo`: `enum { Ed25519 = 0, MlDsa65 = 1 }`
- `SignatureBytes`: holds variable-length sig data. For Phase 0, only Ed25519 (64 bytes). Use `[u8; 64]` initially with `sig_algo` field for future extension.
- `ObjectCapSet`: bounded array of `ObjectCapability { principal: [u8; 32], rights: ObjectRights, expiry: Option<u64> }`
- `ObjectContent`: `alloc::vec::Vec<u8>` (heap-allocated variable-length content)
- `ObjectRights`: `{ read: bool, write: bool, execute: bool }`

**B2. ObjectStore trait** (`src/fs/mod.rs`)

```rust
pub trait ObjectStore {
    fn get(&self, hash: &[u8; 32]) -> Result<&ArcObject, StoreError>;
    fn put(&mut self, object: ArcObject) -> Result<[u8; 32], StoreError>;
    fn delete(&mut self, hash: &[u8; 32]) -> Result<(), StoreError>;
    fn list(&self, namespace: &[u8; 32]) -> Result<&[([u8; 32], ObjectMeta)], StoreError>;
}
```

- `StoreError`: NotFound, CapacityExceeded, InvalidObject, PermissionDenied
- `ObjectMeta`: lightweight metadata (owner, created_at, content_len) for listings without loading full content

**B3. RamObjectStore implementation** (`src/fs/ram.rs`)

- Fixed-capacity: 256 objects max (bounded array, no_std friendly)
- Linear scan for get/delete/list (fine for initial testing)
- `put()` computes content hash (for Phase 0: simple FNV or CRC — real Blake3 in Phase 1)
- Heap-allocated via `new_boxed()` pattern (matches existing conventions)

**B4. Wire into lib.rs**

- Add `pub mod fs;` to `src/lib.rs`
- Add global static: `pub static OBJECT_STORE: Spinlock<Option<Box<RamObjectStore>>> = Spinlock::new(None);`
- Lock ordering position: 8 (after INTERRUPT_ROUTER at 7) — the FS is the highest-level subsystem
- Initialize in `main.rs` after all other subsystems

---

## Files Modified

| File | Change |
|------|--------|
| `src/ipc/mod.rs` | Add Principal type, sender_principal field on Message, stamping in send_message_with_capability() |
| `src/ipc/capability.rs` | Add principal: Option\<Principal\> to ProcessCapabilities, bind_principal()/get_principal() on CapabilityManager |
| `src/syscalls/mod.rs` | Add BindPrincipal = 11, GetPrincipal = 12 |
| `src/syscalls/dispatcher.rs` | Implement handlers for syscalls 11 and 12 |
| `src/lib.rs` | Add pub mod fs;, add OBJECT_STORE global static, update lock ordering comment |
| `src/microkernel/main.rs` | Bootstrap Principal generation, OBJECT_STORE initialization |
| `src/fs/mod.rs` | New — ArcObject, ObjectStore trait, types |
| `src/fs/ram.rs` | New — RamObjectStore implementation |

**Files NOT Modified:** `src/scheduler/`, `src/memory/`, `src/arch/`, `src/loader/`, `src/ipc/interceptor.rs`. No new crate dependencies (no ed25519-compact, no blake3 — Phase 0 uses simple hashing).

---

## What Gets Built Later (Not Phase 0)

These are explicitly deferred. The architecture supports them but no code is written yet.

**Phase 1:** `ed25519-compact` + `blake3` crates. Real signature verification in ObjectStore. Identity service as user-space ELF. Key store service (private key leaves kernel static, enters managed service). Signed module enforcement: extend BinaryVerifier to require a valid Ed25519 signature over ELF content; host-side signing tool to sign ELF binaries before inclusion in boot media.

**Phase 2:** Ownership transfer objects (OwnershipTransfer as ArcObject). ELF note section parser for embedded signatures. Trust anchor management (configurable set of Principals authorized to sign modules).

**Phase 3:** FS service as user-space process (registers endpoint, accepts get/put/list/delete over IPC, enforces sovereignty via sender_principal). Block device driver. On-disk format with variable-length signature fields.

**Phase 4:** ML-DSA hybrid signatures. SSB bridge service (capability grants + identity attestations over append-only logs, tinySSB fallback for constrained links). Eventually-consistent revocation via signed revocation objects in SSB feeds.

**Phase 5:** Biometric commitment (retinal scan primary, facial geometry fallback, ZKP for privacy). Social attestation recovery. Full DID integration. Key rotation protocol. Instance discovery and trust bootstrapping via SSB social graph.

---

## Verification

After Phase 0 implementation:

```bash
# All existing tests still pass (136+)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Clean builds for both targets
cargo build --target x86_64-unknown-none --release
cargo build --target aarch64-unknown-none --release

# QEMU boot (x86_64) — verify IPC messages carry sender_principal
make run
```

**New tests to add:**
- `Principal::from_public_key()` — construction, equality, fast_eq
- Principal binding on CapabilityManager — bind, get, double-bind rejection
- Message with sender_principal — stamping in send_message_with_capability
- ArcObject construction — hash computation, capability set, author != owner scenarios
- ArcObject author immutability — verify author field cannot be changed after creation
- RamObjectStore — put/get/delete/list, capacity exhaustion, not-found
- ObjectStore sovereignty check — get with wrong principal returns PermissionDenied

**Architectural invariants to verify:**
- sender_principal is set by kernel only, never by sender code
- BindPrincipal syscall is restricted to bootstrap Principal
- Message size increase doesn't overflow EndpointQueue fixed buffers (16 messages × ~300 bytes each — check IpcManager heap allocation)
- Lock ordering maintained: OBJECT_STORE(8) is the highest-numbered lock
- All new code is arch-portable (no `#[cfg(target_arch)]` in `src/fs/` or identity-related IPC changes)
- ArcObject.author is immutable after creation — no API path allows modification
- ArcObject.owner defaults to author at creation — creator is controller unless explicitly transferred
- Ownership transfer requires current owner's signature (enforced at ObjectStore level in Phase 1+)
