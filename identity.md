# ArcOS Identity Architecture

This document captures the design thinking behind ArcOS identity — what identity means in ArcOS, how it relates to files, keys, biology, and social context, and what gets built in what order. It is a living design document, not a specification. When implementation decisions are made, this document gets updated to reflect them.

For the foundational security architecture this plugs into, see [security.md](security.md).
For the filesystem object model that depends on identity, see [filesystem.md](filesystem.md) (forthcoming).

---

## The Core Claim

In ArcOS, everything is an object with an attributable source. Files are signed artifacts with a creator and an owner. Messages are assertions made by an identity. Processes run under an identity with tokenized capabilities. 

Identity is primitive and the system is built on that.

---

## What Identity Is Not

Briefly:

**It is not a username.** A human-readable label assigned by a central authority can be reassigned, revoked, or duplicated across systems. ArcOS has no username system.

**It is not password based.** Passwords are shared secrets too easily stolen, leaked, or forgotten. ArcOS has no password authentication.

**It is not an account.** Accounts exist in someone else's database, are granted by an authority, can be suspended, and cease to exist when the service does. 

**It is not a certificate from a CA.** Certificate authorities can be compromised, coerced, or simply disappear. ArcOS does not delegate trust to any claimed authority.

---

## Authentication vs. Identity

Daily Access vs. Identity Establishment

Daily use should be frictionless. Password or otherwise traditionally secured workstation access will be integral to the UX, another topic outside the scope of this document.

---

## What Identity Is

An ArcOS identity is irrevocable. A **cryptographic key pair** is generated locally, controlled exclusively by its holder, verifiable by anyone, and dependent on no external authority for its existence. The identity layer is **algorithm-agnostic** — all key material, signatures, and verification are mediated through dynamic-sized fields so the system can transition between classical and post-quantum schemes without structural changes.

```
Identity {
    algorithm:    SignatureAlgorithm,   // which scheme produced this key
    public_key:   Vec<u8>,             // dynamic-sized — 32 bytes (Ed25519) to 1312 bytes (ML-DSA-65)
    // private_key never stored in this struct — lives in the key store
}

enum SignatureAlgorithm {
    Ed25519,                  // classical: 32-byte keys, 64-byte signatures
    MlDsa65,                  // post-quantum: FIPS 204 (ML-DSA-65, formerly Dilithium3)
    Hybrid(Box<[SignatureAlgorithm; 2]>),  // dual-mode: both must verify
}
```

The public key is the identity. Anyone who holds your public key can verify that data was signed by you. No one who lacks your private key can produce a valid signature. There is no enrollment, no approval, no account creation. Generating the key pair is the act of creating the identity.

In **dual mode**, a signature is the concatenation of a classical Ed25519 signature and a post-quantum ML-DSA-65 signature. Both must verify independently. This provides security against classical attackers today and quantum attackers in the future — an attacker must break *both* schemes to forge a signature.

### Quantum-Resistant Dual-Mode Design

ArcOS does not bet on a single cryptographic assumption surviving the next several decades. The identity layer operates in three modes, selectable per identity and upgradeable over time:

| Mode | Algorithm | Public Key | Signature | Use Case |
|------|-----------|------------|-----------|----------|
| **Classical** | Ed25519 | 32 bytes | 64 bytes | Bootstrap, lightweight devices, backward compatibility |
| **Post-Quantum** | ML-DSA-65 (FIPS 204) | 1952 bytes | 3293 bytes | Maximum quantum resistance, post-transition |
| **Hybrid** | Ed25519 + ML-DSA-65 | 1984 bytes | 3357 bytes | Transition period — secure against both classical and quantum attack |

Hybrid mode is the **default for new identities**. Classical mode remains available for constrained environments and is the bootstrap default until the post-quantum implementation stabilizes.

### Why These Algorithms

**Ed25519** is the classical foundation:

- **Small keys** — 32 bytes public, 32 bytes private. Efficient to store, transmit, and embed in file metadata.
- **Small signatures** — 64 bytes. Minimal overhead for ownership proof.
- **Fast** — Verification is cheap enough to do on every file access without measurable overhead.
- **Constant-time** — Resistant to timing side-channel attacks.
- **Foundation of `did:key`** — The DID method most aligned with ArcOS's no-central-authority principle encodes Ed25519 keys directly.
- **Mature and audited** — Decades of deployment, well-understood security properties.

**ML-DSA-65** (NIST FIPS 204, formerly Dilithium3) is the post-quantum layer:

- **Lattice-based** — Security reduces to Module Learning With Errors (MLWE), believed hard for both classical and quantum computers.
- **NIST standardized** — FIPS 204 finalized August 2024. Not experimental — production-grade standard.
- **Reasonable sizes** — Among post-quantum signature schemes, ML-DSA has the best balance of key size, signature size, and verification speed. 1952-byte public keys and 3293-byte signatures are large compared to Ed25519 but tractable for an OS that controls its own storage format.
- **Fast verification** — ~0.5ms on modern hardware. Acceptable for file access verification, especially with caching.
- **No trusted setup** — Unlike some ZKP-based approaches, lattice signatures require no ceremony or shared state.

### Dynamic-Sized Field Space

All structures that carry keys or signatures use **length-prefixed dynamic fields** rather than fixed-size arrays. This is a deliberate architectural choice:

```
SignedField {
    algorithm:  SignatureAlgorithm,  // identifies the scheme
    length:     u32,                 // byte length of the data field
    data:       [u8],               // key or signature bytes, algorithm-dependent size
}
```

This means:

- **No recompilation on algorithm change.** Switching from Ed25519 to Hybrid does not change struct layouts, file formats, or IPC message formats.
- **Mixed-algorithm ecosystems work.** A file signed with Ed25519 and a file signed with ML-DSA-65 coexist in the same filesystem. Verifiers dispatch on the algorithm tag.
- **Future algorithms slot in.** If NIST standardizes a superior scheme (e.g., SLH-DSA for hash-based fallback, or a future lattice improvement), it becomes a new variant of `SignatureAlgorithm` with no structural changes.
- **Wire format is self-describing.** A signed object carries enough information to verify itself without external schema knowledge.

---

## Identity and Files

The decision that files have owners is the decision that shapes everything above it.

A file in ArcOS's native format is not bytes with a path. It is:

```
File {
    content:          [u8],
    creator:          SignedField,        // who made this — IMMUTABLE, set at creation
    owner:            SignedField,        // who controls this — transferable
    signature:        SignedField,        // owner's signature (dynamic-sized)
    capabilities:     CapabilitySet,      // who can do what with this file
    lineage:          Option<ObjectHash>, // what was this derived from?
    created_at:       Timestamp,
    content_hash:     Blake3Hash,         // integrity, separate from signature
}
```

**Creator** is the identity that brought the object into existence. It is set at creation and never changes — it is historical fact. **Owner** is the identity that currently controls the object. At creation, the creator is the owner. Ownership can be transferred; creatorship cannot.

An employee creates a document at work — they are the creator, the employer is the owner. An independent contractor creates a document — they are both creator and owner unless a contract transfers ownership. The distinction matters: creatorship is provenance (who made this), ownership is authority (who controls this).

The owner signs the object. The signature ties content to controller cryptographically. Stripping the owner field invalidates the signature. You cannot forge ownership. You can only derive a new file with yourself as owner, and the lineage field traces back to the original.

### Ownership Transfer

Ownership is transferred via a signed `OwnershipTransfer` object — itself an ArcObject stored in the ObjectStore:

```
OwnershipTransfer {
    object_hash:      Blake3Hash,        // the object being transferred
    from_owner:       SignedField,       // current owner (signs this transfer)
    to_owner:         SignedField,       // new owner
    signature:        SignedField,       // current owner's signature over this transfer
    terms:            Option<TransferTerms>,  // negotiated conditions (finex)
    created_at:       Timestamp,
}
```

Every ownership change is a signed, content-addressed object. The auditable chain of custody can be independently verified. Ownership transfer is the primitive that higher-level protocols build on: financial exchange, licensing, delegation. Those are userspace protocols, and do not belong in the identity layer, listed here for context. See finex.md (forthcoming) for the negotiated exchange protocol.

### What This Enables

Provenance is structural. Because the creator field is immutable and ownership verified by signature, attribution cannot be stripped or forged. Forking any document produces a new object with the original hash in lineage - the chain of attribution is permanent and traceable without anyone's cooperation.

Sharing is replication of the same signed artifact, it's not a copy with back-referencing. A file you push to a peer is verifiable as yours regardless of where it lives. A sovereign cloud host stores objects as ciphertext they cannot read, forge, or credibly deny origins of.

The append-only social log is not a separate concept. Each post is an ArcObject. Linking by lineage creates the social log. Commerce is not a separate layer either. The identity primitive provides for the exchange primitive; a userspace finex module builds negotiation, terms, and settlement on top. 

---

## The Biological Identity Model

### The Problem With Keys Alone

A key pair solves the cryptographic problem of identity. It does not solve the human problem of identity: what happens when you lose the key?

In a pure key-pair model, losing the private key means losing the identity. Every file you signed becomes unextendable (you can no longer produce new signatures). Recovery requires either a trusted third party (central authority, violates ArcOS principles) or a pre-established recovery mechanism (another secret to lose).

### Biometrics as Entropy, Not as Key

The biological insight is this: **biometric data is not a private key, but it is a powerful entropy source for key derivation.**

You do not sign with your retina. You derive a key *from* your biometric profile (or a committed representation of it) such that possession of a matching biological sample is required to regenerate the key. The key is not stored anywhere. We derive keys from things inherent to being alive.

The primary biometric modalities, in order of preference:

1. **Retinal scan** 
2. **Facial geometry**
3. **DNA/epigenetic profiling** (future fallback)

```
private_key = KDF(biometric_commitment, device_context, social_attestation)
```

If you lose your device, you regenerate the key from the same inputs. The derived key is the same. Your identity is continuous.

### Uniqueness and Context Vectors

No single biometric is perfectly unique in isolation. Identical twins have nearly indistinguishable facial geometry at birth. Retinal patterns are unique but could theoretically be spoofed with sufficient technology. The resolution is a **context vector**: identity is derived not from a single measurement but from multiple independent signals that converge on a unique individual.

```
IdentityContext {
    biometric_commitment:  Option<BiometricHash>,    // committed biometric profile (ZKP)
                                                     // retinal scan, facial geometry, or DNA (future)
    device_entropy:        [u8; 32],                 // hardware-bound randomness
    social_attestation:    Option<Vec<Attestation>>, // quorum of trusted contacts
    temporal_proof:        Option<Timestamp>,        // continuity across time
}
```

The biometric modalities, in order of current preference:

1. **Retinal scan** — vascular patterns are distinct even between identical twins (shaped by stochastic developmental processes, not genetics alone). Stable over a lifetime.
2. **Facial geometry** — 3D facial structure diverges with age and life experience. Widely accessible via commodity hardware.
3. **DNA/epigenetic profiling** (future) — deferred until social and ethical consensus exists. Slots into the context vector as an additional field when ready.

Combined with device entropy (hardware-bound) and social attestation (community-bound), the context vector produces a unique identity even in adversarial edge cases.

The context vector makes identity a function of who you are biologically *and* what devices you control *and* what your social context attests.

### Privacy: Zero-Knowledge Proofs

Biometric data is inherently sensitive. A retinal scan reveals the unique vascular structure of your eye. Facial geometry is recognizable. DNA reveals disease predisposition, family relationships, and ancestry. None of this can be exposed in a public registry or embedded in a file header.

The zero-knowledge proof approach resolves this:

```
ZKP: "I possess a biometric sample consistent with the committed profile,
     without revealing the profile itself,
     without revealing which modality was used,
     without revealing anything about my biology beyond the proof."
```

The commitment (a hash of the biometric profile) is public and stored with the identity. The raw biometric data never leaves the device. Verification is proof of biological consistency, not disclosure of biological data.

This is an active research area (biometric ZKPs). ArcOS does not implement it now. But the interface is designed to accommodate it when it matures.

### Key Recovery via Biometric Context

Lost key recovery without a central authority:

```
Recovery protocol:
1. Present fresh biometric sample (retinal scan, facial geometry, or future modality)
2. ZKP proves sample matches committed profile
3. Quorum of trusted social graph contacts attest continuity
   ("this biometric matches the entity we have communicated with")
4. New device generates new key pair from same IdentityContext inputs
5. Old key rotated out with a signed rotation proof
6. File lineage chains updated with rotation record
```

The private key is never stored. It is derived. The derivation inputs are things you are (biology) and people who know you (social graph). Losing them all would be tricky at best.

---

## Social Attestation and DAO/NAO Alignment

### The Social Graph as Identity Infrastructure

ArcOS's SSB-inspired social layer is core identity infrastructure. The append-only signed logs of your peers are a verifiable record of their interaction with you over time. A quorum of peers attesting to your identity is more than a social nicety. It is a cryptographic recovery mechanism.

This maps directly onto DAO (Decentralized Autonomous Organization) governance models: quorum decisions, on-log attestation, authority without central control. A recovery quorum functions like a DAO vote — a threshold of known parties must attest before a key rotation is authorized.

The NAO framing — Networked/Natural Autonomous Organization — extends this toward biological and social systems as the model for decentralized governance. An identity system grounded in biological context and social attestation is a NAO-native design: authority derives from nature (biology) and community (social graph), not from institutions.

### Enrollment: The Cold-Start Problem

The hardest question in biological identity is the first enrollment. At some point, a biometric sample must be committed for the first time. If that enrollment is compromised, the identity is compromised from its origin.

The proposed resolution is that enrollment is a **witnessed social act**, not a database transaction:

- Existing identities in your social graph witness and attest the enrollment
- The enrollment record is signed by the witnesses and stored in their append-only logs
- A new identity's provenance is traceable to the community that witnessed its creation

A new identity's trust weight reflects the depth and history of its attestation graph — not a binary trusted/untrusted distinction, but a continuous signal that grows with genuine interaction.

This mirrors how human identity has always worked at its most fundamental level: community recognition, not institutional registration. You exist as an identity because people who know you attest to your existence. ArcOS makes this explicit and cryptographic.

Bootstrapping the system requires real human group interaction. 

---

## Key Lifecycle

### Generation

Key generation is local. No network required. No authority consulted. The key pair is generated from the IdentityContext on first boot or first identity creation.

### Storage

The private key lives in the key store — a capability-gated kernel service. No user-space process holds the raw private key. Signing operations are requests to the key store: "sign this data with my identity key." The key store returns the signature. The private key does not leave the store.

When hardware security modules are available (TPM, Secure Enclave), the private key lives in hardware and the signing operation is performed inside the secure element. The raw key material is never exposed to software under any circumstances.

### Rotation

Key rotation is required when a device is lost or a key is suspected compromised. The rotation protocol:

1. New key pair generated on new device
2. Recovery quorum attests continuity (biometric + social)
3. Old public key signs a rotation record pointing to new public key (if old key is still accessible)
4. If old key is inaccessible: quorum attestation alone authorizes rotation, recorded in witnesses' logs
5. New key issued with a rotation proof that links it to the original identity chain
6. Files signed with old key remain valid — the rotation proof establishes they were made by the same identity

### Delegation to Processes

When a process signs something on your behalf (a file system write, an IPC message), it does not use your identity key directly. It uses a **derived process capability** — a key generated from your identity key and scoped to that process's purpose.

```
process_key = KDF(identity_private_key, process_capability_hash, timestamp)
```

Signatures from processes are verifiable as deriving from your identity without exposing your root private key to the process. A compromised process cannot forge your identity for operations outside its scope.

---

## Implementation Roadmap

### Phase 0: Bootstrap Identity (unblocks FS)

The minimum needed to make the filesystem object model coherent during development. Deliberately minimal. Explicitly temporary in implementation, permanent in interface.

```rust
struct IdentityContext {
    device_entropy:        [u8; 32],          // available now
    biometric_commitment:  Option<Hash>,       // None until Phase 2
    social_attestation:    Option<Vec<Attestation>>, // None until Phase 3
    temporal_proof:        Option<Timestamp>,  // None until Phase 2
}

fn derive_keypair(
    context: &IdentityContext,
    algorithm: SignatureAlgorithm,       // Classical, PostQuantum, or Hybrid
) -> KeyPair;                            // algorithm-tagged, dynamic-sized

fn sign(data: &[u8], keypair: &KeyPair) -> SignedField;   // dynamic-sized output
fn verify(data: &[u8], sig: &SignedField, pubkey: &SignedField) -> bool;
```

A `BootstrapIdentity` is generated at first boot from device entropy using **Ed25519** (classical mode). It is stored (as a key pair, not derived) in a fixed location. It is explicitly not the final identity model — it is a scaffold that makes the FS work while the real identity system is built above it. The bootstrap identity can be upgraded to Hybrid mode in Phase 1.5 via key rotation.

The interface it exposes is the permanent interface — algorithm-agnostic, dynamic-sized. The implementation behind it changes. The interface does not.

### Phase 1: Key Store Service

The key store becomes a proper userspace service, capability-gated. The raw private key leaves the bootstrap static and enters a managed service. Signing is a request to the service, not a direct call.

Hardware-backed key storage (TPM) integrated where available.

### Phase 1.5: Post-Quantum Upgrade

ML-DSA-65 implementation integrated into the key store. New identities default to Hybrid mode (Ed25519 + ML-DSA-65). Existing Ed25519 identities can upgrade via key rotation — the rotation proof is dual-signed (old Ed25519 key signs the new Hybrid key, establishing continuity). File verification dispatches on the `SignatureAlgorithm` tag and validates accordingly.

### Phase 2: Biometric Commitment

ZKP-based biometric commitment. The IdentityContext `biometric_commitment` field becomes populated with retinal scan (primary) or facial geometry (secondary). Key derivation incorporates biological context. Recovery via biometric proof becomes possible.

This requires ZKP infrastructure and biometric scanning integration — future work, but the interface slot exists from Phase 0. DNA/epigenetic profiling may be added as a future modality if social and ethical consensus emerges.

### Phase 3: Social Attestation and Recovery

Social graph quorum recovery. The `social_attestation` field in IdentityContext becomes populated from the SSB-inspired social layer. Key rotation via quorum attestation is implemented. The cold-start enrollment protocol is defined.

### Phase 4: Full DID Integration

`did:key` encoding of identity public keys. Ed25519 keys use the existing `did:key` multicodec. ML-DSA-65 and Hybrid keys use extended multicodec prefixes (pending W3C/IETF standardization of post-quantum DID methods). Identity becomes expressible as a DID, interoperable with the broader decentralized identity ecosystem. Cryptographic capabilities across networked ArcOS nodes become possible.

---

## Architectural Invariants

These must hold after every change to identity-related code:

1. **Private keys never leave the key store.** No user-space process receives a raw private key. Signing is always a request to the key store service.

2. **Every file has a creator and an owner.** The native ArcOS filesystem format has no concept of a creatorless or ownerless file. The creator field is immutable — no API path may modify it after creation. The owner field is transferable only via signed `OwnershipTransfer` objects. Files created by system processes during bootstrap have the bootstrap identity as both creator and owner.

3. **Signatures are verified before trust.** A file's owner field is meaningless without verifying the signature. Code that reads owner without verifying signature is a bug.

4. **Biological data never leaves the device unencrypted.** Biometric commitments are hashes. ZKPs are proofs. Raw biological data is never transmitted, stored remotely, or exposed to any process other than the identity service.

5. **Enrollment is witnessed.** The cold-start enrollment protocol requires social attestation. Unwitnessed enrollment is not supported in production — only in bootstrap/development mode, and explicitly labeled as such.

6. **Key rotation preserves lineage.** A rotated identity is the same identity. Files signed with the old key and files signed with the new key are traceable to the same root through the rotation proof chain.

---

## Open Questions

These are known unknowns.

Phase 1.5 blockers:

- **ML-DSA-65 `no_std` implementation** — Which Rust crate for ML-DSA-65 works in `no_std` bare-metal? `pqcrypto-dilithium` wraps C; `ml-dsa` (RustCrypto) is pure Rust but may need maturity review. Stack usage for lattice operations on a 256KB boot stack needs measurement.
- **Hybrid signature verification cost** — Dual verification (Ed25519 + ML-DSA-65) on every file access approximately doubles CPU cost. Is per-file caching of verification results sufficient, or does hot-path file access need a session-scoped verification bypass?

Further future unresolved:

- **ZKP library selection** — Which ZKP system is appropriate for biometric proofs? Groth16, PLONK, STARKs? The choice affects proof size, verification time, and trusted setup requirements.
- **Retinal scanning hardware** — What consumer-grade retinal scanning APIs exist? Integration with mobile/desktop hardware (e.g., IR camera arrays). Phase 2 may require partnership with hardware vendors or standardization efforts.
- **Facial geometry stability** — How is aging, injury, or surgical change handled? What is the false rejection rate over a 10-year window? Is periodic re-enrollment needed, and if so, how does that interact with the commitment model?
- **Quorum size and threshold** — How many social attestations are required for key recovery? What prevents a social engineering attack on the quorum?
- **DNA as future modality** — Under what conditions (social consensus, privacy infrastructure maturity, regulatory clarity) would DNA/epigenetic profiling be activated? What governance mechanism decides this — per-user opt-in, community vote, or protocol-level upgrade?
- **Process key scoping** — How is the process_capability_hash computed? What prevents a process from claiming a broader scope than it was granted?
- **Rotation during social graph unavailability** — If a key is lost and the social graph is offline (no network), how is recovery handled? Is there a time-limited local recovery path?
- **Post-quantum DID encoding** — `did:key` multicodec for ML-DSA-65 is not yet standardized. ArcOS may need to define a provisional encoding and migrate when the standard lands. What is the compatibility strategy?
- **Portable identity sessions** — If identity is a Principal and not a machine, any ArcOS terminal becomes your terminal when you authenticate. What does a guest session on foreign hardware look like? What capabilities does it get? What happens to locally-cached objects on logout? This is a UX and security design question that sits at the intersection of the key store service and the consent model.
