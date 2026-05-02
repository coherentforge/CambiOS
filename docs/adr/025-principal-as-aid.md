# ADR-025: Principal as 32-byte AID (decoupled from key bytes)

- **Status:** Proposed
- **Date:** 2026-04-30
- **Depends on:** [ADR-003](003-content-addressed-storage-and-identity.md) (the original "Principal IS the Ed25519 pubkey" decision this supersedes the implementation contract for), [ADR-005](005-ipc-primitives-control-and-bulk.md) (the 256-byte IPC envelope this protects)
- **Related:** [identity.md](../identity.md) (algorithm-agnostic design intent, post-quantum roadmap), [ADR-004](004-cryptographic-integrity.md) (signing primitives), [ADR-007](007-capability-revocation-and-telemetry.md) (Principal binding on capabilities)
- **Context:** What the 32 bytes inside a `Principal` *mean* — pubkey bytes vs. opaque identifier — and why that distinction is load-bearing for v1.5+ post-quantum migration

## Problem

Through 2026-04, the kernel's `Principal` type was defined in [src/ipc/mod.rs](../../src/ipc/mod.rs) as:

```rust
pub struct Principal {
    pub public_key: [u8; 32],
}
```

The struct field name is the contract: the 32 bytes are the Ed25519 public key, and five non-test kernel sites read them as such — feeding `principal.public_key` directly into `verify_signature(&[u8; 32], ...)`. [ADR-003](003-content-addressed-storage-and-identity.md) ratifies this explicitly: *"A Principal is a 32-byte Ed25519 public key. It is the identity of a process, a user, or a service."*

[identity.md](../identity.md) ratifies the opposite intent. It declares the identity layer **algorithm-agnostic**, with dynamic-sized public keys (32 bytes for Ed25519, 1952 bytes for ML-DSA-65, 1984 bytes for Hybrid Ed25519+ML-DSA-65) and a Phase 1.5 post-quantum upgrade on the roadmap.

These two designs cannot both be true at v1.5. The collision surfaces in three places:

1. **256-byte IPC envelope.** Every IPC message carries a `sender_principal: Option<Principal>` ([src/ipc/mod.rs:172](../../src/ipc/mod.rs#L172)) stamped by the kernel. If `Principal` grows from 32 bytes to 1952 bytes when ML-DSA-65 lands, the message envelope ([ADR-005](005-ipc-primitives-control-and-bulk.md)) breaks structurally — either `sender_principal` becomes variable-length (defeats the verification-tractability rationale) or it migrates out of the message (defeats unforgeable identity stamping).

2. **Capability table sizing.** [ADR-008](008-boot-time-sized-object-tables.md)'s `[Option<ProcessCapabilities>; num_slots]` allocates fixed memory at boot under the assumption that a Principal is 32 bytes. A 60× growth in Principal size is not a tuning question; it forces the table out of contiguous boot memory.

3. **Verification call sites bake in Ed25519.** Five hot-path sites do `verify_signature(&principal.public_key, ...)`. Migrating to ML-DSA-65 means changing each site to know which algorithm to invoke, what key length to expect, what signature length to receive — a five-site refactor for an algorithm change that should be a one-arm extension.

The root cause is conceptual: **identity stability and key algorithm are conflated.** A Principal that *is* a key cannot survive key rotation or algorithm migration without changing its bytes — and changing its bytes means it is no longer the same identity. Every consumer of `sender_principal` is a consumer of "this process's current pubkey," not "this process's identity."

## Decision

**A `Principal` is a 32-byte Autonomic Identifier (AID), not a public key.** The 32 bytes are an opaque identifier whose interpretation is decoupled from any underlying signing key.

In v1, the AID bytes coincide with an Ed25519 public key — there is no key event log yet, no rotation, no keystore. The bytes a process binds via `BindPrincipal` are still raw Ed25519 pubkey bytes today, and the verifier still reads them as such. **The change is semantic, not behavioral.**

In v1.5+, the AID is `blake3(key_event_log_inception_block)` — the KERI-style identifier of an identity, computed once at inception and stable for the lifetime of the identity regardless of how many key rotations or algorithm migrations occur. The actual signing key is resolved at verify time via the keystore service ([deferred ADR](#deferred), post-v1).

The 32-byte size becomes architectural, not tuning. It is fixed by the AID model — `blake3` produces a 32-byte digest, and the AID's purpose is to be a stable identifier of bounded size. Changing it would require redesigning IPC stamping, capability tables, and audit records simultaneously.

## Architecture

### What the change is, today

The kernel-side `Principal` type acquires accessors that name the two distinct future paths:

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Principal {
    pub(crate) aid: [u8; 32],
}

impl Principal {
    pub const fn from_aid(aid: [u8; 32]) -> Self { Principal { aid } }

    /// The AID — 32-byte identity tag. Used for equality, IPC stamping, lookup.
    pub fn aid(&self) -> &[u8; 32] { &self.aid }

    /// The current signing key bytes for this Principal.
    ///
    /// In v1: returns the AID bytes directly (AID and key coincide).
    /// In v1.5+: this function's body becomes a keystore lookup. All verify
    /// sites already call through here, so the migration is one function-body
    /// change, not a five-site refactor.
    pub fn current_key_bytes(&self) -> &[u8; 32] { &self.aid }
}
```

`aid()` and `current_key_bytes()` look identical today. They diverge structurally at v1.5: `aid()` is always the AID, `current_key_bytes()` becomes a keystore round-trip. The split is the cheap insurance policy that makes the v1.5 migration a single function-body change rather than a five-site refactor.

### What the change is *not*

- **Not a keystore.** No new service, no new IPC, no boot-ordering change. Pre-v1, the AID bytes are the key bytes; resolution is the identity function.
- **Not a hash computation.** `BindPrincipal` still accepts raw 32-byte values from userspace; the kernel does not hash them. The semantic shift is "we now treat these 32 bytes as the AID, and v1 happens to use raw pubkey bytes as a v1-only AID-derivation shortcut."
- **Not a Principal type redesign.** The wire format of `sender_principal` (32 bytes) is unchanged. Memory layout is unchanged. Equality semantics are unchanged.
- **Not a change to ARCSIG signing.** The bootstrap pubkey, signed boot module verification, and ObjectStore puts continue to operate on raw Ed25519 keys. The Principal is the v1 identifier; the keys are still load-bearing signing material.

### Why "AID" and not "fingerprint" or "key hash"

The KERI/AID model commits to a specific property: **the identifier is computed once, from an inception event, and is stable across all subsequent key state**. A "fingerprint" or "key hash" would be `blake3(current_pubkey)` — which changes on every rotation, defeating the point. An AID is `blake3(inception_event_log[0])` — fixed at identity creation, invariant under rotation. The vocabulary matters because the property matters.

For v1, the inception event log is implicit: the AID bytes are the Ed25519 pubkey, and "rotation" is undefined. v1.5 introduces the explicit log.

### Boot trust model (unchanged)

The bootstrap Principal continues to be compile-time embedded via `bootstrap_pubkey.bin` ([src/microkernel/main.rs](../../src/microkernel/main.rs)). The file gets a header in a separate change (Change C of the same plan) so the algorithm is explicit, but the trust model — kernel boot pulls the AID-equals-pubkey directly from the binary — is unchanged. Bootstrap rotation is a system-level event analogous to root CA rotation, per [identity.md § Bootstrap Principal: A Special Case](../identity.md#the-bootstrap-principal-a-special-case).

## Consequences

### Pre-v1 (this change)

- One field rename, ~8 mechanical replacements at non-test sites. No behavioral change. No new dependencies.
- Field becomes `pub(crate)` so the API exposes only `aid()` / `current_key_bytes()`. Any external consumer of `principal.public_key` breaks at compile time — fine pre-v1.
- [ADR-003](003-content-addressed-storage-and-identity.md) gets a `## Divergence` appendix pointing to this ADR; the original "Principal IS the Ed25519 pubkey" text remains as historical record per the prompt-shaping rule on append-only ADRs.
- [identity.md](../identity.md) gets an explicit reconciliation: "A Principal is a 32-byte AID. Underlying keys are algorithm-agnostic and dynamic-sized; the AID is fixed at 32 bytes."

### Post-v1 (deferred)

- A keystore service must exist before any `current_key_bytes()` call site runs — that is, before ELF verification at boot. This is a boot-ordering rework. Scoped to its own ADR when designed.
- The keystore service holds the AID → current key mapping. Key rotation updates the mapping; the AID does not change. The keystore is the only entity that needs to know which algorithm a given AID's key uses.
- ML-DSA-65 / Hybrid signatures land at Phase 1.5 of [identity.md](../identity.md). The verifier dispatch (Change A of this same plan, `crypto::verify(SignatureAlgorithm, ...)`) accommodates the new algorithm; the keystore returns the algorithm tag along with the key bytes.

### What this enables that cannot be done without it

| Capability | Without ADR-025 | With ADR-025 |
|---|---|---|
| Post-quantum migration | Wire-format break; redesign IPC, capability tables, audit records. | One keystore lookup body changes; wire format unchanged. |
| Key rotation | Identity changes when key changes. Every signed artifact's `owner` field must be re-stamped or proof-chained. | AID is stable. Only the keystore mapping changes. Existing artifacts validate without modification. |
| Hybrid Ed25519+ML-DSA | `sender_principal` cannot hold both keys. | `sender_principal` holds the AID; the keystore returns whichever algorithm(s) the AID maps to. |

## Verification

After this change:

- `Principal` has no `pub` data fields. Field access goes through `aid()` or `current_key_bytes()` — verifier sites call only `current_key_bytes()`.
- `cargo grep -F '.public_key' src/` returns no matches outside test code or the bootstrap pubkey loader (which speaks the file format, not the type).
- `make check-all` (x86_64 + aarch64 + riscv64) green per [ADR-013](013-riscv64-architecture-support.md).
- `cargo test --lib` covers `Principal` equality (AID-based), `from_aid` constructor, `is_zero` sentinel, and the conventional Debug/Display fingerprint format.

## Deferred

- **Keystore service ADR.** Where the AID → current-key mapping lives, how rotation events update it, what capability gates protect it, and how the boot path orders keystore-availability against ELF verification. **Revisit when:** Phase 1.5 of [identity.md](../identity.md) is funded, or the first signed boot module needs a non-bootstrap AID.
- **Inception event log format.** The `blake3(inception_event_log[0])` derivation that produces an AID at v1.5+. KERI provides a starting model; a CambiOS-native specification will adapt it for the no-network, content-addressed object store. **Revisit when:** keystore service ADR begins.
- **Bootstrap rotation procedure.** v1 ships with a single compile-time-embedded bootstrap Principal. A signed firmware-update path that rotates the bootstrap AID is a system-level operation. **Revisit when:** the first scheduled bootstrap rotation is operationally required (e.g., backup YubiKey rotation).
