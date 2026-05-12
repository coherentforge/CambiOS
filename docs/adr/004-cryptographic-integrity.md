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

## Divergence

### 2026-04-06 — Signed-ELF format: `.note.cambios.sig` proposal → ARCSIG binary trailer

- **Implementation:** commit `391aa4e` (`Crypto Phase 1B/1C: Blake3 + Ed25519 signatures, key-store service, signed ELF loading`)
- **Trigger:** Implementation of the §Signed ELF Modules subsection. The ADR offered two options ("appended as an ELF note section (`.note.cambios.sig`) or stored as a detached signature alongside the binary"); a third option — a binary trailer — was chosen because it is parser-free at the loader. No ELF section-header walk, no detached-file lookup, no path resolution before the trust check fires.

#### What changed

Signatures are an 8-byte-header binary trailer appended after the last byte of the ELF, not an ELF note section:

```text
[original ELF bytes][sig: 64 bytes]["ARCSIG"][version: u8 = 1][algo: u8 = 0]
```

Constants and the inspection helper live in [src/loader/mod.rs:287-360](../../src/loader/mod.rs#L287-L360):
- `SIGNATURE_TRAILER_PREFIX = b"ARCSIG"`
- `TRAILER_VERSION_V1 = 1`, `TRAILER_ALGO_ED25519 = 0`
- `SIGNATURE_TRAILER_V1_ED25519_SIZE = 72` (64-byte signature + 8-byte header)
- `inspect_signature_trailer()` is the version/algo dispatch point — adding ML-DSA-65 later is a new `(version, algo)` arm, not a format revision.

The host-side tool that produces the trailer is [tools/sign-elf/](../../tools/sign-elf/); the signed payload is `blake3(elf_bytes)`, not the raw bytes, so verification is constant-cost regardless of binary size.

#### What did *not* change

- **The §Verification property** holds: a binary that fails the trailer check causes zero side effects. The trailer is inspected before any frame allocation or page mapping.
- **The trusted-set model** described in §Signed ELF Modules: trust anchor is still the bootstrap Principal at boot; configurable signer set is still a later step.

#### Why not `.note.cambios.sig`

| Considered | Why rejected |
|---|---|
| ELF note section (`.note.cambios.sig`) | Requires the loader to parse the section header table *before* it has decided to trust the binary. Trailer parsing is a single suffix compare against `"ARCSIG"` — strictly less surface than walking section headers, which is a verifier-friendly cost. |
| Detached `.sig` file alongside the binary | Requires path resolution and a second I/O path. Boot modules arrive as in-memory blobs from Limine; there is no "alongside" at the point the verifier runs. |

### 2026-04-06 — `ObjPut` verification split into `SYS_OBJ_PUT` (unsigned) + `SYS_OBJ_PUT_SIGNED` (verified)

- **Implementation:** commit `391aa4e` (same Phase 1B/1C landing)
- **Trigger:** Implementation surfaced two distinct call patterns that the ADR's unified §Signature Verification on ObjectStore Operations description collapsed into one. The unified path was unworkable: in-process content production (e.g., a service hashing its own working buffer into the store) has no externally producible signature, and forcing it through a signed path would mean either round-tripping every put through the key-store service or stamping a no-op signature.

#### What changed

Two syscalls instead of one:

- **`SYS_OBJ_PUT`** ([dispatcher.rs:1404](../../src/syscalls/dispatcher.rs#L1404)) — unsigned put. The kernel hashes content with Blake3 and stores it. Provenance is carried by `sender_principal` (kernel-stamped, unforgeable on the local node), not by an object signature. This is the right shape for service-local content where the producer's identity is already attested by the IPC frame.
- **`SYS_OBJ_PUT_SIGNED`** ([dispatcher.rs:1666](../../src/syscalls/dispatcher.rs#L1666)) — signed put. The caller supplies an Ed25519 signature over the content; the kernel verifies against the caller's Principal via `crypto::verify` before storing. This is the right shape for content that will outlive the IPC frame (replication, cross-node transfer, audit-log entries).

The two paths share the Blake3 hashing step and the store insert; they differ only on whether `signature` is required and verified.

#### What did *not* change

- **The CambiObject signature field** still exists and is still semantically "Ed25519 signature over content by owner." Unsigned puts carry a zero-filled signature field, which is observably distinct from a verified one — readers can tell the two apart.
- **`ObjGet` defense-in-depth re-verification** as described in the ADR remains an open option, now keyed off "signature is non-zero" rather than "signature always present."

### 2026-05-01 — Bootstrap entropy plan superseded by compile-time CKEY pubkey (Frame-B via ADR-025/026)

- **Implementation:** commit `d41a16e` (`kernel+tool: Principal-as-AID + crypto-agility plumbing (ADR-025)`)
- **Superseded by:** [ADR-025](025-principal-as-aid.md) (Principal as 32-byte AID) and [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (kernel transcribes identity events without interpreting them).
- **Trigger:** ADR-004's §Bootstrap Principal Upgrade proposed runtime entropy (`RDRAND` / `RNDR`) producing a real Ed25519 keypair held in a kernel static, later migrating to the key-store service. The Frame-B identity resolution (kernel is arbiter, not Principal; user holds keys) ratified by ADR-025/026 makes the kernel-owned private key the wrong primitive entirely: there is no role for the kernel to *be* a signing identity. The bootstrap key needs to be a verification anchor the kernel can recognize, not a keypair the kernel can use.

#### What changed

The bootstrap path is no longer "kernel generates a keypair on boot." It is "kernel compiles in a public key file produced offline by the operator's signing tool":

- **`bootstrap_pubkey.bin`** ships in-tree, generated by `sign-elf --export-pubkey bootstrap_pubkey.bin` from either a YubiKey-resident private key (production) or a `--seed <hex>` value (CI/test).
- **CKEY v1 envelope** wraps the 32-byte Ed25519 public key with an 8-byte header (`"CKEY" + version:1 + algo:1 + aid_prefix:2`). Parsed at compile time by `parse_bootstrap_pubkey_v1()` in [src/microkernel/main.rs:1963-2010](../../src/microkernel/main.rs#L1963-L2010) — wrong magic / version / algo is a `const fn` panic at build, not a runtime check.
- **`BOOTSTRAP_PRINCIPAL`** is populated from the parsed pubkey at boot ([main.rs:1929-1943](../../src/microkernel/main.rs#L1929-L1943)). No `RDRAND`, no `RNDR`, no kernel-side key generation, no kernel-resident private key.

#### Vestigial surface

- **`BOOTSTRAP_SECRET_KEY` static** is preserved at the kernel-static site but is unreferenced by any write — `claim()` always returns `None` and any caller of `SYS_CLAIM_BOOTSTRAP_KEY` receives `PermissionDenied`. Kept so the syscall number and the named static survive for Frame-B reuse (e.g., a future signing-attestation flow that the kernel transcribes without performing).
- **`SYS_CLAIM_BOOTSTRAP_KEY`** ([dispatcher.rs:1617-1656](../../src/syscalls/dispatcher.rs#L1617-L1656)) likewise survives as a documented vestige. Removal is not safe — the ABI slot must remain stable until the post-v1 handle-table refactor lands.

#### What this means for the §Key Store Service subsection

The ADR's §Key Store Service describes a forward path where "the private key for the bootstrap identity moves from a kernel static to a user-space capability-gated service." Under Frame-B, the private key was never in the kernel static in production — it has always lived on the YubiKey (or behind `--seed` for CI). The key-store service ([user/key-store-service/](../../user/key-store-service/)) is still real and still the correct primitive, but its job is to mediate *user-owned* signing keys, not to receive a key the kernel was holding.

#### What did *not* change

- **Ed25519 + Blake3 as the chosen primitives** stand. ADR-025 reframes what the 32 bytes *mean* (AID, not necessarily a public key) but keeps the algorithm choices made here.
- **The trust anchor at boot** is still "the bootstrap Principal," just sourced from a compile-time file instead of runtime entropy. The verifier-side properties (collision-resistance, non-forgeability of the signing identity) are unchanged.
- **The `SignatureAlgo` enum + variable-length signature field** anticipated in §What This Does Not Cover for the post-quantum upgrade survives as the right shape under ADR-025's crypto-agility plumbing.
