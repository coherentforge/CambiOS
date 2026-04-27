# ADR-004: Cryptographic Integrity — Blake3 Hashing and Ed25519 Signatures

- **Status:** Accepted
- **Date:** 2026-04-05
- **Depends on:** ADR-003 (Content-Addressed Storage and Cryptographic Identity)
- **Context:** Upgrading Phase 0 placeholder hashing and unsigned objects to production cryptography

> *For implementation status (which phase markers are met, what's hardware-backed, what tests exist) see [STATUS.md](../../STATUS.md). This ADR is the decision; status lives with the code.*

## Problem

ADR-003 established the content-addressed storage model and cryptographic identity system. Phase 0 implements the correct interfaces and data model but uses placeholder cryptography:

1. **FNV-1a for content hashing.** FNV-1a is a non-cryptographic hash — fast but trivially collidable. An attacker can craft two different objects with the same FNV-1a hash, making content-addressing meaningless as an integrity guarantee. The ObjectStore cannot distinguish a legitimate object from a tampered one.

2. **Signatures are not verified.** CambiObject has a `signature` field and `author`/`owner` fields, but nothing verifies that the signature is valid. Any process can claim any Principal as its author or owner. The ownership model is structurally correct but not enforced.

3. **ELF modules are unsigned.** The BinaryVerifier gate checks structural properties (W^X, entry point, overlap) but not provenance. A valid-looking ELF with correct structure but malicious behavior passes all current checks. There is no way to distinguish a legitimate boot module from a crafted one.

These are not Phase 0 bugs — they are explicit scope cuts documented in ADR-003. But they represent the gap between the current implementation and a system where integrity claims are actually backed by cryptography.

## Decision

Integrate `blake3` for content hashing and `ed25519-compact` for digital signatures. Replace FNV-1a in the ObjectStore, add signature verification to object storage and retrieval, and extend the BinaryVerifier to require signed ELF modules.

### Why These Algorithms

**Blake3** for content hashing:

- **256-bit output** — Same size as the existing `content_hash` field. Drop-in replacement.
- **Collision-resistant** — Cryptographic hash function. Finding two inputs with the same hash is computationally infeasible.
- **Fast** — Designed for speed. Outperforms SHA-256 by 5-10x on modern hardware. Critical because content hashing happens on every `ObjPut`.
- **Tree-hashable** — Supports parallel hashing of large objects (future optimization for multi-MB content).
- **`no_std` compatible** — The `blake3` crate supports `no_std` with `default-features = false`.

**Ed25519** (`ed25519-compact`) for signatures:

- **32-byte keys, 64-byte signatures** — Matches the existing field sizes in CambiObject and Principal. No structural changes needed.
- **Fast verification** — ~70µs per verification on modern hardware. Acceptable for per-object verification.
- **Deterministic** — Same key + same message always produces the same signature. Important for reproducible builds and testing.
- **`no_std` compatible** — `ed25519-compact` is pure Rust, `no_std`, no allocator required for core operations.
- **Foundation for `did:key`** — The DID method planned for Phase 4 (identity.md) natively encodes Ed25519 keys.
- **Classical baseline for hybrid mode** — When ML-DSA-65 (post-quantum) is added, Ed25519 remains the classical half of hybrid signatures (identity.md Phase 1.5).

### Why Not Other Options

| Alternative | Reason rejected |
|-------------|----------------|
| SHA-256 | Slower than Blake3. No tree-hashing. Same security level. |
| SHA-3 | Slower still. Designed as SHA-2 backup, not as primary hash for high-throughput use. |
| `ring` (Ed25519) | Wraps C/asm. Difficult cross-compilation for `aarch64-unknown-none`. `ed25519-compact` is pure Rust. |
| `ed25519-dalek` | Heavier dependency tree. `ed25519-compact` is minimal and `no_std`-native. |
| RSA | Large keys (2048+ bits), slow verification, no advantage over Ed25519 for this use case. |

## Architecture

### Content Hash Upgrade

Replace FNV-1a with Blake3 in `RamObjectStore::put()`:

```rust
// Phase 0 (current)
fn compute_hash(content: &[u8]) -> [u8; 32] {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in content { hash = (hash ^ byte as u64).wrapping_mul(FNV_PRIME); }
    // ... pack into [u8; 32]
}

// Phase 1 (this ADR)
fn compute_hash(content: &[u8]) -> [u8; 32] {
    *blake3::hash(content).as_bytes()
}
```

The `content_hash` field type (`[u8; 32]`) does not change. All ObjectStore trait implementations, syscall handlers, and the FS service work unchanged — they operate on opaque 32-byte hashes.

### Signature Verification on ObjectStore Operations

**On `ObjPut`:** After computing the content hash, verify that `object.signature` is a valid Ed25519 signature over `object.content` by `object.owner`. If verification fails, reject with `InvalidObject`.

**On `ObjGet`:** Optionally re-verify signature on retrieval (defense-in-depth against storage corruption). This can be made configurable if verification cost becomes measurable.

**On `ObjDelete`:** Ownership check already enforced (only owner's Principal can delete). No additional signature work needed — the ownership check is via `sender_principal` (kernel-stamped, unforgeable).

### Bootstrap Principal Upgrade

Replace the deterministic seed with real entropy:

- **x86_64:** `RDRAND` instruction (hardware random number generator)
- **AArch64:** Read from Limine's entropy or ARM generic random (`RNDR` if available)

The bootstrap Principal becomes a real Ed25519 keypair. The private key is stored in a kernel static (Phase 0/1) and later moves to the key store service.

### Signed ELF Modules

Extend `BinaryVerifier` with a signature check:

1. **Host-side signing tool:** A build-time utility that signs ELF binaries with a specified Ed25519 private key. The signature is appended as an ELF note section (`.note.cambios.sig`) or stored as a detached signature alongside the binary.

2. **Loader verification:** `BinaryVerifier::verify()` gains an additional check: extract the signature from the ELF, verify it against the ELF content using the signer's public key, and confirm the signer's Principal is in the trusted set.

3. **Trusted set:** Initially just the bootstrap Principal. Later, a configurable list of Principals authorized to sign modules (trust anchor management).

```
ELF loading pipeline (updated):

  Raw ELF bytes
      │
      ▼
  BinaryVerifier::verify()
      ├── Structural checks (existing: W^X, entry, overlap, bounds)
      ├── Signature extraction (new: .note.cambios.sig or detached)
      ├── Ed25519 verification (new: sig over ELF content by signer)
      └── Trust check (new: signer's Principal in trusted set)
      │
      ▼
  Frame allocation + page mapping (only if all checks pass)
```

The existing property holds: a binary that fails verification causes zero side effects.

### Key Store Service (Phase 1C)

The private key for the bootstrap identity moves from a kernel static to a user-space capability-gated service:

- The key store registers an IPC endpoint
- Signing operations are IPC requests: "sign this data with key X"
- The key store returns the signature; the private key never leaves the service
- Only processes with the appropriate capability can request signatures
- Hardware-backed storage (TPM, Secure Enclave) integrated where available

This is a separate service, not part of the ObjectStore or FS service. It follows the microkernel principle: the kernel manages identity binding (Principal → process), while key material management runs in isolated user-space.

## Dependency Integration

### Cargo.toml additions

```toml
[dependencies]
blake3 = { version = "1", default-features = false }
ed25519-compact = { version = "2", default-features = false }
```

Both crates are `no_std` compatible with `default-features = false`. Neither requires an allocator for core operations.

### Stack Usage

Ed25519 signing/verification uses ~2KB of stack. Blake3 hashing uses ~1KB. Both are well within the 256KB boot stack budget. The key store service (user-space) has its own 16KB stack, more than sufficient.

### Build Verification

Both crates must compile for all three targets:
- `x86_64-unknown-none` (kernel)
- `aarch64-unknown-none` (kernel)
- `x86_64-apple-darwin` (host tests)

If `blake3` has platform-specific SIMD optimizations, they must be disabled for bare-metal targets (the `no_std` feature flag handles this).

## Migration Path

The upgrade is designed to be incremental and non-breaking:

1. **Add crate dependencies.** Build passes — no code changes yet.
2. **Replace FNV-1a with Blake3 in `compute_hash()`.** All existing tests pass — the hash function is opaque to callers.
3. **Generate real bootstrap keypair.** Replace deterministic seed with RDRAND/entropy-derived Ed25519 keypair.
4. **Add signature verification to `ObjPut`.** New objects must be properly signed. Existing Phase 0 test objects will need updated test helpers that produce valid signatures.
5. **Build host-side signing tool.** Sign hello.elf and fs-service ELF at build time.
6. **Extend BinaryVerifier.** Require valid signature on ELF load.
7. **Implement key store service.** Move private key out of kernel static.

Steps 1–4 can be done in a single commit. Steps 5–6 are a second commit. Step 7 is a separate phase.

## Security Properties Gained

| Property | Before (Phase 0) | After (Phase 1) |
|----------|-------------------|------------------|
| Content integrity | FNV-1a — trivially collidable | Blake3 — collision-resistant |
| Ownership proof | Claimed but not verified | Ed25519 signature verification |
| Module provenance | Structural checks only | Signed by trusted Principal |
| Identity binding | Deterministic seed | Real entropy, real keypair |
| Key isolation | Private key in kernel static | Key store service (Phase 1C) |

## What This Does Not Cover

- **Post-quantum signatures (ML-DSA-65).** Deferred to Phase 1.5 per identity.md. The `SignatureAlgo` enum and variable-length signature field are already in place.
- **Ownership transfer verification.** OwnershipTransfer objects require signature chains. Deferred to Phase 2.
- **Network-boundary signatures.** IPC uses kernel-stamped `sender_principal` (unforgeable locally). Signatures are only needed when objects cross machine boundaries (SSB bridge, Phase 4).
- **Biometric key derivation.** Phase 2+ per identity.md.

## Verification

After implementation:

```bash
# All tests pass (existing + new crypto tests)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Clean builds for both targets
cargo build --target x86_64-unknown-none --release
cargo build --target aarch64-unknown-none --release

# QEMU: signed modules load, unsigned modules rejected
make run
```

New tests to add:
- Blake3 hash computation matches reference vectors
- Ed25519 sign/verify round-trip
- ObjPut rejects objects with invalid signatures
- ObjPut accepts objects with valid signatures
- BinaryVerifier rejects unsigned ELF
- BinaryVerifier accepts properly signed ELF
- Bootstrap keypair is non-deterministic across boots (RDRAND-based)

## References

- ADR-003: Content-Addressed Storage and Cryptographic Identity
- [identity.md](../identity.md): Identity architecture — Ed25519 as classical foundation, ML-DSA-65 as post-quantum target
- [FS-and-ID-design-plan.md](../FS-and-ID-design-plan.md): Phase 1 specification
- `blake3` crate: https://crates.io/crates/blake3
- `ed25519-compact` crate: https://crates.io/crates/ed25519-compact
- Bernstein et al., "High-speed high-security signatures" (2012) — Ed25519 specification
- O'Connor et al., "BLAKE3: one function, fast everywhere" (2020)
