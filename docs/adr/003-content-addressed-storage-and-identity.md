# ADR-003: Content-Addressed Storage and Cryptographic Identity

- **Status:** Accepted
- **Date:** 2026-04-05
- **Depends on:** ADR-000 (Zero-Trust Architecture and Capability-Based Access Control)
- **Context:** Establishing the native storage and identity model — what a "file" is in CambiOS and how authorship, ownership, and provenance work

## Problem

Traditional filesystems store bytes at paths. A file has no inherent notion of who created it, who controls it, or whether its contents have been tampered with. Metadata like ownership and permissions are bolted on as external attributes — maintained by the OS, not intrinsic to the data. This creates several structural problems:

1. **No provenance.** A file's history (who created it, who modified it, what it was derived from) exists only in external logs that can be lost, falsified, or simply not kept.

2. **Ownership is ambient.** Unix-style ownership is an integer UID assigned by the local system. It has no meaning across machines, can be reassigned by root, and tells you nothing about the actual entity that produced the data.

3. **Integrity is unchecked.** A file can be silently modified — by a compromised process, a bug, or a malicious actor — with no detection mechanism unless the application layer separately implements checksums.

4. **Copying strips identity.** Copying a file to another system, email, or storage medium severs it from its ownership and permission metadata. The copy is indistinguishable from any other sequence of bytes.

CambiOS needs a storage model where every object is self-describing: it carries its own identity, authorship, ownership proof, and integrity guarantee regardless of where it lives.

## Decision

CambiOS adopts a **content-addressed object store** as its native storage model and **cryptographic Principals** (Ed25519 public keys) as its identity primitive. Every stored object (an CambiObject) is identified by the hash of its content, carries immutable authorship and transferable ownership, and is signed by its owner. Identity is established by key generation, not by registration with an authority.

These two decisions — content-addressing and cryptographic identity — are co-dependent. Content-addressing without identity produces anonymous blobs. Identity without content-addressing produces signed bytes that can be silently swapped. Together they produce **signed artifacts with unforgeable provenance**.

## Architecture

### Principal: The Identity Primitive

A Principal is a 32-byte Ed25519 public key. It is the identity of a process, a user, or a service.

```rust
pub struct Principal {
    pub public_key: [u8; 32],
    pub key_hash: [u8; 16],   // FNV-1a — fast comparison only, not cryptographic
}
```

Principals are:
- **Self-issued.** Generating a key pair creates the identity. No enrollment, no authority.
- **Unforgeable.** Only the holder of the corresponding private key can produce valid signatures.
- **Bound to processes.** The kernel binds a Principal to each process via `BindPrincipal` (syscall 11). Only the bootstrap Principal can perform this binding — preventing identity theft.

### IPC Sender Stamping

Every IPC message carries a `sender_principal` field stamped by the kernel in `send_message_with_capability()`. The sender cannot set or forge this field — the kernel reads the sender's bound Principal from the CapabilityManager and writes it into the message.

This provides **zero-cost unforgeable identity for local IPC**. Receiving processes know who sent every message without cryptographic verification overhead. Signatures are reserved for network boundaries (future phases).

### CambiObject: The Storage Unit

Every stored object in CambiOS is an CambiObject:

```rust
pub struct CambiObject {
    pub content_hash:  [u8; 32],         // content address (FNV-1a Phase 0, Blake3 Phase 1)
    pub author:        [u8; 32],         // creator's public key — IMMUTABLE
    pub owner:         [u8; 32],         // current controller's public key — transferable
    pub signature:     [u8; 64],         // owner's signature (Ed25519 Phase 1+)
    pub acl:           [(Principal, ObjectRights); 8],  // access control list
    pub lineage:       Option<[u8; 32]>, // hash of parent object (provenance chain)
    pub content:       Vec<u8>,          // the actual data
}
```

Key properties:

| Property | Meaning |
|----------|---------|
| **Content-addressed** | The object's identity is the hash of its content. Same content = same address. Different content = different object. |
| **Immutable author** | The `author` field is set at creation and never changes. It records who brought the object into existence — historical fact. |
| **Transferable owner** | The `owner` field is the current controller. Starts as the author. Can be transferred via signed OwnershipTransfer objects. |
| **Signed** | The owner signs the object. Stripping or changing the owner field invalidates the signature. |
| **Lineage** | Optional pointer to a parent object hash. Forking a document produces a new object with the original in its lineage — the chain of attribution is permanent. |

### ObjectStore Trait

The storage abstraction is a trait, not a filesystem:

```rust
pub trait ObjectStore {
    fn get(&self, hash: &[u8; 32]) -> Result<&CambiObject, StoreError>;
    fn put(&mut self, object: CambiObject) -> Result<[u8; 32], StoreError>;
    fn delete(&mut self, hash: &[u8; 32]) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<[u8; 32]>, StoreError>;
    fn count(&self) -> usize;
}
```

`RamObjectStore` is the Phase 0 implementation: a fixed-capacity (256 objects) heap-allocated store with linear scan. It validates that content hashes match on put and enforces basic capacity limits. This is deliberately minimal — a block-device-backed implementation will follow the same trait.

### FS Service: User-Space ObjectStore Gateway

The filesystem service (`user/fs-service/`) is the first real user-space service in CambiOS. It runs as a Rust `no_std` ELF, registers IPC endpoint 16, and enters a service loop:

1. `RecvMsg` — receives IPC with `sender_principal` + command payload
2. Parse command (PUT/GET/DELETE/LIST)
3. Verify sender's authorization via `sender_principal`
4. Call ObjPut/ObjGet/ObjDelete/ObjList kernel syscalls
5. `Write` response back to sender

The FS service demonstrates the microkernel pattern: storage policy (who can access what) runs in user-space, while storage mechanism (the ObjectStore) is a kernel-managed resource accessed via syscalls.

### Syscalls

Seven new syscalls support identity and storage:

| Number | Name | Purpose |
|--------|------|---------|
| 11 | BindPrincipal | Bind a 32-byte Principal to a process (restricted to bootstrap Principal) |
| 12 | GetPrincipal | Read the calling process's bound Principal |
| 13 | RecvMsg | Identity-aware receive: returns `[sender_principal:32][from_endpoint:4][payload:N]` |
| 14 | ObjPut | Store an CambiObject, returns 32-byte content hash |
| 15 | ObjGet | Retrieve object content by hash |
| 16 | ObjDelete | Delete object (ownership enforced — only owner can delete) |
| 17 | ObjList | List all object hashes (packed 32-byte hashes) |

### Bootstrap Principal

At boot, the kernel generates a deterministic 32-byte bootstrap Principal (Phase 0 uses a fixed seed; Phase 1 will use real entropy). This Principal is bound to all kernel processes (PIDs 0–2) and boot modules. It serves as the initial trust anchor — the only Principal authorized to call `BindPrincipal` on other processes.

The bootstrap Principal is explicitly temporary in implementation but permanent in interface. The `Principal` type, the `bind_principal()`/`get_principal()` API, and the `sender_principal` stamping mechanism are the production interfaces. The bootstrap seed and FNV-1a hashing are Phase 0 scaffolding.

## Why Content-Addressing

| Alternative | Problem |
|-------------|---------|
| Path-based (Unix/NTFS) | Identity is location. Move or copy = lose provenance. |
| UUID-based | Random identifier with no relation to content. Duplicate detection impossible. |
| Block-addressed | Couples storage to physical layout. Meaningless across devices. |
| Content-addressed | Identity is intrinsic. Same content = same address everywhere. Tamper-evident. Deduplication is free. |

Content-addressing also makes the ObjectStore trait naturally implementable across backing stores: RAM, block device, network peer, or sovereign cloud. The object's address doesn't change when it moves between stores.

## Why Author and Owner Are Separate

A single "owner" field conflates two distinct concepts:

- **Authorship** — who created this object. Historical fact. Immutable.
- **Ownership** — who currently controls this object. Current authority. Transferable.

An employee creates a document at work — they are the author, the employer is the owner. An independent contractor creates a document — they are both author and owner. Separating these fields preserves both provenance and authority through ownership transfers.

## Lock Ordering

`OBJECT_STORE` sits at position 8 in the lock hierarchy — the highest-numbered lock:

```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7) → OBJECT_STORE(8)
```

Position 8 reflects that the ObjectStore is the highest-level kernel subsystem — it depends on everything below it (IPC for message delivery, capabilities for access control, frames for storage) but nothing depends on it. Syscall handlers that touch the ObjectStore acquire its lock last.

`BOOTSTRAP_PRINCIPAL` is outside the hierarchy — written once at boot, read-only thereafter.

## Phase Progression

The interfaces (`Principal`, `CambiObject`, `bind_principal`/`get_principal`, `sender_principal` stamping, `ObjectStore` trait) are stable. The backing implementations evolve through phases:

| Aspect | Initial design (Phase 0) | Production target |
|------------|---------|-------------------|
| Content hashing | Stub | Blake3 (cryptographic) |
| Signatures | Placeholder field | Ed25519 verification |
| Bootstrap identity | Deterministic seed | Hardware-backed YubiKey root of trust |
| Storage backing | RAM-only | Block device + network peers |
| Ownership transfer | Not in scope | Signed OwnershipTransfer objects |

For which phase is currently realized in the code, see [STATUS.md § Phase markers](../../STATUS.md#phase-markers). The interfaces are final. The implementations upgrade in place.

## Verification

Test counts and what each test covers (Principal construction, IPC sender stamping, CambiObject hashing, RamObjectStore put/get/delete/list/capacity, etc.) live in [STATUS.md § Test coverage](../../STATUS.md#test-coverage).

## References

- [ADR-000](000-zta-and-cap.md): Zero-Trust Architecture and Capability-Based Access Control
- [ADR-004](004-cryptographic-integrity.md): Cryptographic integrity (Blake3 + Ed25519)
- [identity.md](../../identity.md): Identity architecture (authoritative design document)
- [FS-and-ID-design-plan.md](../../FS-and-ID-design-plan.md): Phase intent for identity + storage
- `src/fs/mod.rs`, `src/fs/ram.rs`: CambiObject and RamObjectStore
- `src/ipc/mod.rs`: Principal type, sender_principal stamping
- `src/ipc/capability.rs`: Principal binding on ProcessCapabilities
- `user/fs-service/src/main.rs`: User-space FS service
