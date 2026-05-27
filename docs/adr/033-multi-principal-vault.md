# ADR-033: Multi-Principal Vault

- **Status:** Proposed
- **Date:** 2026-05-27
- **Depends on:** [ADR-025](025-principal-as-aid.md) (Principal as 32-byte AID — the identity primitive entries in the vault key on), [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (transcribe-not-interpret — the kernel does not reason about plurality, which is what makes a userspace vault structurally possible), [ADR-024](024-syscall-abi-crate.md) (the ABI crate the vault's libsys wrappers extend)
- **Related:** [identity.md](../identity.md) (the design doc this ADR materializes; vault section names the architectural slot this ADR specifies), [ADR-000](000-zta-and-cap.md) (zero-trust + capability foundations the vault operates within), [ADR-007](007-capability-revocation-and-telemetry.md) (capability revocation — the vault's per-Principal key rotation maps onto cap-revocation semantics at the boundary), [ADR-032](032-full-disk-encryption-below-substrate.md) (`PivBackend` consumer; the vault's `decrypt_with` API is what FDE eventually routes through for the user-key-backed unwrap path)
- **Supersedes:** N/A
- **Context:** `identity.md` (rewritten 2026-05-26) ratified the hardware-key model: private keys live in YubiKey-class silicon, never in software; the vault is a *directory* of `AID → hardware-key-slot` bindings, not a key store. The Frame-A vestige cleanup (2026-05-27) removed the kernel-side `BOOTSTRAP_SECRET_KEY` + `SYS_CLAIM_BOOTSTRAP_KEY` path that the legacy `key-store-service` consumed. What's missing is the architectural specification for what the post-Frame-B `key-store-service` actually *is*. This ADR specifies it.

## Problem

Per `identity.md`, plurality is a structural property: a human holds many Principals, one per context, by design. Per ADR-026, the kernel transcribes the bound AID on every IPC and authored object without interpreting which Principal it is or which human it represents. Plurality therefore *cannot* live in the kernel — there is no architectural slot for "this set of AIDs belongs to the same human" inside the kernel ring. It has to live above.

Three concrete questions stay open until they're answered explicitly:

### 1. Where does the human-↔-Principals mapping live?

Userspace, by exclusion. Not in the kernel (transcribe-not-interpret). Not in any cloud service (no central authority). Not on disk in plaintext (privacy). The remaining slot is a userspace service local to the user's device — and `user/key-store-service` at endpoint 17 has held the architectural slot for it since the bootstrap-identity work. The question is what that service *contains* in the hardware-key model.

### 2. How does a spawning process pick which Principal its child runs under?

Per `identity.md`, the unit of identity in CambiOS is the process: one process, one bound Principal for life. The parent process picks the child's Principal at spawn time. *How* the parent picks needs an API — and *which* Principals the parent is allowed to pick from needs an authority model.

### 3. How do other services (FDE unlock, object signing, IPC sender_principal stamping) get signatures and decrypted bytes without ever seeing private keys?

Private keys live in hardware silicon. Operations against them — sign, ECDH-decrypt — require the hardware token to be physically present and (per slot policy) touched. The vault is the *only* userspace process that should mediate token access: services route through the vault's IPC, the vault routes through `user/ccid`'s IPC (per Stream B), the CCID layer drives PIV APDUs over USB to the YubiKey. No service holds a YubiKey-CCID handle directly; the vault owns the policy decision of "which token, which slot, what touch policy" for any given AID.

## Decision

`user/key-store-service` at endpoint 17 *is* the multi-Principal vault. Its post-Frame-B shape is specified by this ADR and consists of (1) a data model, (2) a userspace API surface, (3) a plurality model, (4) a trust boundary specification, and (5) an explicit § Out of Scope list with revisit triggers.

### 1. Data Model

```
Vault {
    principals:    Vec<VaultEntry>,             // many, by design (ADR-025 + identity.md plurality)
    context_map:   HashMap<ContextLabel, AID>,  // local-only "context_label → which AID"
}

VaultEntry {
    aid:                 [u8; 32],              // stable across key rotations (ADR-025)
    key_handle:          KeyHandle,             // points into hardware
    inception_record:    Option<InceptionEvent>, // KERI-style provenance (post-v1)
    rotation_history:    Vec<RotationEvent>,    // append-only chain (post-v1)
}

KeyHandle {
    device_id:           HardwareDeviceId,      // e.g., YubiKey serial 12345678
    sign_slot:           PivSlot,               // PIV slot 9C (Ed25519 sign) for signing AID's artifacts
    decrypt_slot:        Option<PivSlot>,       // PIV slot 9D (X25519 ECDH) for envelope decryption
}
```

The vault knows *which device, which slot* holds the key for *which AID*; it never holds the key bytes themselves. `HardwareDeviceId` is opaque (USB serial number, vendor-defined string, or a logical identifier the vault assigns at provisioning time — the exact encoding lands with implementation; see § Out of Scope). `PivSlot` is the 1-byte PIV slot identifier (`0x9C`, `0x9D`, etc.) per NIST SP 800-73-4.

`InceptionEvent` and `RotationEvent` carry the KERI-style provenance chain that identity.md references; their concrete byte format lands when key rotation lands (the first consumer of either field). v1 entries can leave both `None` — `inception_record = None` means "no provenance yet recorded," `rotation_history = []` means "this is the original key for this AID, no rotations yet."

`context_map` is the userland-only "social_app → Principal_social" lookup table. It carries no cryptographic weight; it is a UX affordance the vault uses to answer `bind_for_spawn(context)`. The mapping is per-vault (per-device); cross-device CRDT replication of the directory carries it forward.

### 2. API Surface

The vault exposes three IPC primitives over endpoint 17. None of them are kernel syscalls — the kernel does not reason about plurality (per ADR-026); the vault is fully userspace.

```
vault.bind_for_spawn(context: &[u8]) -> Result<AID, VaultError>
```

Called by a parent process before invoking the spawn syscall. The vault looks up `context` in `context_map`; if found, returns the corresponding AID. If not found, the vault may (per future policy) prompt the user to select a Principal, mint a new one, or refuse. The caller's identity must be one the vault recognizes as belonging to the same human (see § Trust Boundary below).

```
vault.sign_with(aid: AID, data: &[u8]) -> Result<Signature, VaultError>
```

Sign `data` with the AID's signing key. The vault translates `aid → VaultEntry.key_handle.sign_slot`, then issues `CMD_PIV_SIGN` over IPC to `user/ccid` (endpoint 33), which drives the PIV `GENERAL AUTHENTICATE` APDU on the indicated slot. The hardware token may prompt for touch per slot policy. The signature is returned to the caller; no key material crosses the boundary.

```
vault.decrypt_with(aid: AID, ciphertext: &[u8]) -> Result<Plaintext, VaultError>
```

Same shape, different operation. The vault translates `aid → VaultEntry.key_handle.decrypt_slot`, then issues `CMD_PIV_DECRYPT` over IPC to `user/ccid`, which drives X25519 ECDH on the indicated slot. Returns the decrypted bytes.

Authored content signing (`obj_put_signed`), FDE wrap-key unwrap (per ADR-032), and IPC sender_principal stamping for signed handshakes all route through this trio of APIs.

### 3. Plurality Model (v1)

**One AID per hardware key. Primary + backup as the minimum.**

The simplest concrete instantiation: a user provisions two hardware keys (typically two YubiKeys), each holding the same AID's signing and decryption keys, related by a rotation chain so that loss of the primary triggers a backup-signed rotation proof to the new primary. Both keys produce signatures verifiable against the same public key; both decrypt envelopes wrapped under the same key.

Additional AIDs come from additional hardware keys. A user who wants three distinct identity contexts provisions three keys (or sets of keys). The "many Principals per human" structural claim is preserved; the v1 friction is "physical hardware per identity context" rather than "click a UI button."

**Per-context KDF plurality is named, not built.** A future option: a single hardware key signs a per-context challenge, the vault derives a per-context Principal key from the signature output via KDF. One physical key, many AIDs. The wire format reserves space for this (the `KeyHandle` could carry a per-context derivation tag in the future); the implementation lands when single-key-many-Principals becomes load-bearing UX. **Revisit when:** a real user wants more than primary-and-backup-of-one-identity AND the friction of an additional hardware key per context proves too high.

### 4. Trust Boundary

**Who can call the vault?** Only processes the vault recognizes as belonging to the same human-or-platform context. The vault uses `recv_verified` on its endpoint and inspects the caller's bound AID:

- If the caller's AID is one of the vault's own `VaultEntry.aid` values → recognized; the call proceeds.
- If the caller is the bootstrap Principal (platform identity per identity.md § The Bootstrap Principal) → recognized for platform-scoped operations (signing kernel-spawned services, FDE bootstrap unwrap during fde-mount).
- Otherwise → `VaultError::NotAuthorized`. The vault does not hand AIDs or signatures to processes it cannot identify.

**What does the vault verify before signing/decrypting?** That the requested AID exists in its directory and that the underlying hardware token is present (responds to a CCID `GetSlotStatus` smoke). Failure to find either → `VaultError::AidNotFound` or `VaultError::TokenAbsent`. The vault does not interpret what the data being signed *means* — it signs whatever bytes the caller hands over. Authority to sign is established by "the caller is bound to an AID the vault recognizes, and the request asks for the same AID's key."

**What does the kernel verify?** Per ADR-026, nothing about identity content. The kernel transcribes the bound AID on outgoing IPC and authored objects. The kernel does not gate which AID a parent picks for a child — that gate lives in the vault (via `bind_for_spawn`'s caller-recognition check) and in the future cap layer (a `CreateProcess` capability the vault holds, gating which children-AIDs the vault hands out for which parents). The kernel just sees `spawn(elf, aid)` and binds.

This composition — vault gates AID handout, kernel transcribes the binding — keeps the "kernel doesn't reason about plurality" invariant intact while still preventing arbitrary userspace processes from forging spawn-time AID bindings.

### 5. Cross-Device Sync

The vault's *directory* (AIDs + KeyHandle metadata + context_map + inception/rotation records) replicates across the user's devices via per-AID CRDT replication. Private keys cannot replicate — they live in silicon. A second device joining the user's vault gets the directory replicated; the user must provision a second physical hardware-key pair on the new device, with a rotation chain linking the new pair to the same AIDs (signed by the existing primary key during the enrollment ceremony).

Concrete CRDT choice (RGA, Causal Tree, OR-Set with custom merge, or a project-specific CRDT) lands with implementation; see § Out of Scope below for the revisit trigger. The structural property — per-AID replication, end-to-end encrypted, no server-side knowledge of the human-↔-AIDs mapping — is the load-bearing decision.

## Consequences

### Positive

- **Hardware-key model fully realized at v1+ target.** No software-held private keys, no derived-vault-key entropy, no biometric-as-daily-auth. Touch the key, you're you.
- **Plurality structurally clean.** The kernel stays plurality-ignorant; the human-↔-Principals mapping lives in exactly one userspace process; observers see the Principal in front of them but never the link to the human or to other Principals.
- **Adjacent services simplify.** `user/fs-service`'s eventual signed-write migration routes through `vault.sign_with` rather than through a separate `CMD_SIGN` path. `user/fde-mount` routes through `vault.decrypt_with` for the live (non-dev-piv) FDE unlock path. The vault becomes the *one place* signing and ECDH-decryption happens, which is exactly the property the threat-model wants.
- **Stream B alignment.** `user/ccid` (post-B-vii) is already the correct transport for the vault's CCID APDU dispatch. When B-viii/B-ix land, the vault's `sign_with` and `decrypt_with` plug straight into the existing PIV-over-CCID pipe — no architectural retrofitting needed.

### Negative

- **Provisioning ceremony.** Setting up the vault for the first time requires the user to have hardware keys (typically two: primary + backup). The "buy hardware" step is a real friction increment over password-or-biometric models. Per-context KDF plurality (future) mitigates this for users wanting more than 1-2 AIDs without proportional hardware purchases.
- **Lost-keys-no-backup is severance, not recovery.** If a user loses both primary and backup with no biometric+social recovery infrastructure (Phases 2-3 of identity.md, post-v1), the affected AIDs are functionally dead. The user can mint new AIDs but with no automatic continuity to the lost ones. This is the right default for v1 (no broken-promise of "we can recover anything"), but it's a sharper edge than legacy password-based systems.
- **Vault is now a load-bearing IPC service.** A bug in the vault is a bug in every signed operation. The blast radius is broad. Mitigations: small surface (~three IPC primitives), no dynamic dispatch, future formal-verification target (the vault's authority-check logic is exactly the kind of pure-function predicate Kani/Verus harnesses can prove).

### Operational

- **`user/key-store-service` gets restructured around the vault data model.** Existing CMD_PIV_* paths stay; new `CMD_VAULT_BIND_FOR_SPAWN`, `CMD_VAULT_SIGN_WITH`, `CMD_VAULT_DECRYPT_WITH` commands land alongside. `libsys::keystore` grows three new opcodes and three new wrapper functions; `cambios-abi`'s syscall table is *not* affected (these are IPC commands, not kernel syscalls — per the trust boundary above).
- **Lock hierarchy unchanged.** The vault holds its directory in a single userspace `Spinlock`; no new top-level kernel lock is needed.
- **Boot order unchanged.** key-store-service already loads in the boot manifest before any service that would call it. Vault primitives become callable post-`module_ready`.

## Out of Scope (Deferred with Revisit Triggers)

- **Wire format for `VaultEntry` on disk.** The struct shape is specified above; the byte-level encoding (CBOR? bespoke TLV? Protobuf-like?) is deferred until implementation begins, when the trade-off between Rust ergonomics, cross-language readability, and verification-friendly stability becomes concrete. **Revisit when:** vault implementation starts in earnest.
- **CRDT choice for cross-device directory sync.** Per § Cross-Device Sync above. **Revisit when:** a second device joins a user's vault and the merge-semantics question becomes concrete.
- **Biometric ZKP recovery.** Per identity.md § Recovery, Biology, and Community. Future Phase 2. Vault interface accommodates the recovery slot (`RecoveryContext` field on `VaultEntry`) when it lands.
- **Social attestation quorum.** Per identity.md § Recovery. Future Phase 3.
- **Per-context KDF plurality.** Named in § Plurality Model above. **Revisit when:** real users want more than primary-and-backup-of-one-identity AND additional-hardware friction proves too high.
- **`CreateProcess` capability gating** in spawn syscall (the kernel-side complement to the vault's `bind_for_spawn` authority check). **Revisit when:** a malicious-userspace threat model concretely demonstrates the bypass (process spawns directly with forged AID); for v1 with zero users and a controlled boot manifest, the vault-side gate is sufficient.
- **Vault-coercion duress mode** (a separate hardware-key presentation that signs decoy artifacts and alerts peers). Future research, see identity.md § Open Questions.

## Implementation Status

- **Current (2026-05-27):** `user/key-store-service` serves `CMD_PIV_*` via the PIV backend (SwPivBackend under `--features dev-piv`; InertPivBackend otherwise; CcidPivBackend lands at B-ix). No vault directory exists yet. No `bind_for_spawn`/`sign_with`/`decrypt_with` IPC. Processes spawned during boot are bound to the bootstrap Principal; no multi-AID plurality is exercised at runtime.

- **Phase 1C (per identity.md):** This ADR's architecture lands. `key-store-service` gains the `Vault` data model, the three IPC primitives, `recv_verified` enforcement on endpoint 17, and a path through `user/ccid` for token operations. Userspace clients (`fs-service`, `fde-mount`, new boot modules) migrate to `vault.sign_with` / `vault.decrypt_with` rather than the legacy direct-PIV-call paths.

- **Beyond:** Phases 2 (biometric recovery), 3 (social quorum), and 4 (DID encoding) extend the vault per identity.md's roadmap. The data model above accommodates each addition without structural change.
