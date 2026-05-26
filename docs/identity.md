# CambiOS Identity Architecture

This document captures the design thinking behind CambiOS identity — what identity means in CambiOS, how it relates to files, keys, biology, and social context, and what gets built in what order. It is a living design document, not a specification. When implementation decisions are made, this document gets updated to reflect them.

For the foundational security architecture this plugs into, see [security.md](security.md).
For the filesystem object model that depends on identity, see [filesystem.md](filesystem.md) (forthcoming).

---

## The Core Claim

In CambiOS, everything is an object with an attributable source. Files are signed artifacts with a creator and an owner. Messages are assertions made by an identity. Processes run under an identity with tokenized capabilities.

Identity is primitive and the system is built on that.

---

## Identity, Concretely: The Hardware Key

The user-facing identity primitive is a **hardware security key**. Presenting the key — physically inserting it and confirming with a touch or PIN — is the personhood-and-identity proof, both established in a single motion. The signature the key produces *is* the identity assertion; possession-plus-presentation *is* the proof that you are the holder. There is no separate authentication step, no password, no "log in" before "act as."

This collapses two questions that conventional systems answer separately:

- **Are you a person?** (Are you not a script, a stolen credential file, a leaked password?)
- **Which person are you?** (Which Principal is making this assertion?)

The hardware key answers both, simultaneously, every time. A YubiKey-class device cannot sign without a physical touch (or a separate biometric, depending on the model and slot policy). A stolen private key blob doesn't exist to steal — the key never leaves the silicon. Coerced presentation is a separate threat with its own mitigation track (see [Open Questions § Hardware-key presentation under coercion](#open-questions)); this primitive doesn't pretend to solve it.

The system does the rest of the work behind the scenes. The vault maps your key to the right Principal for the current spawn context. The kernel transcribes the Principal onto outgoing IPC and authored objects. The cap layer gates what the Principal can do. None of this is user-visible. You touch the key; you're you.

This is the v1+ target architecture for user identity. The current implementation uses a software bootstrap key for platform signing (see [Implementation Roadmap § Phase 0](#phase-0-bootstrap-identity)); hardware-rooted bootstrap lands when distribution becomes concrete, and is gated on hardware-vendor support for the cryptographic algorithms the rest of the stack uses (see [Open Questions](#open-questions)).

---

## What Identity Is Not

Briefly:

**It is not a username.** A human-readable label assigned by a central authority can be reassigned, revoked, or duplicated across systems. CambiOS has no username system.

**It is not password based.** Passwords are shared secrets too easily stolen, leaked, or forgotten. CambiOS has no password authentication.

**It is not an account.** Accounts exist in someone else's database, are granted by an authority, can be suspended, and cease to exist when the service does.

**It is not a certificate from a CA.** Certificate authorities can be compromised, coerced, or simply disappear. CambiOS does not delegate trust to any claimed authority.

**It is not singular.** A human is not a single Principal. A human holds many Principals — one per context, relationship, or session — held in a local vault. Each Principal is its own atomic origin; the system never sees them as facets of a unified identity. The "many" is structural, not a feature added later. Privacy follows from this: observers see the Principal in front of them, never the human behind it.

---

## Authentication vs. Identity

Daily access vs. identity establishment.

Daily use is hardware-key authentication. The user touches their key; the vault unlocks; the vault selects which Principal each newly-spawned process should act under. There is no separate password step and no biometric step on the daily-use path — the hardware key is the personhood proof, the signature is the identity assertion, and the vault's role is to map "which key, which slot, which context" to "which Principal" (see [The Vault](#the-vault) below).

Identity establishment — generating a new Principal, witnessing an enrollment, recovering a lost vault — is ceremonial and explicit. Biometric proofs and social attestation participate in the recovery and witnessing paths (see [Recovery, Biology, and Community](#recovery-biology-and-community) below), not in daily authentication. The two paths share machinery but are distinct in the user experience.

---

## What Identity Is

A CambiOS identity is an irrevocable cryptographic key pair, generated locally, controlled exclusively by its holder, verifiable by anyone, and dependent on no external authority for its existence. The identity layer is **algorithm-agnostic** — all key material, signatures, and verification are mediated through dynamic-sized fields so the system can transition between classical and post-quantum schemes without structural changes.

The identity primitive itself, however, is a **fixed 32-byte AID (Autonomic Identifier)** — separate from the underlying key bytes. This is the load-bearing decision: the AID is what identifies a Principal, the keys are what authenticate signatures *from* that Principal, and the two are decoupled so keys can rotate or change algorithm without changing the identity. See [ADR-025](adr/025-principal-as-aid.md) for the full ratification.

```
Principal {
    aid:          [u8; 32],            // KERI-style identifier — fixed 32 bytes, stable across rotations
    // The AID is computed once at inception:
    //   v1:    aid = ed25519_public_key_bytes  (no key event log yet)
    //   v1.5+: aid = blake3(key_event_log_inception_block)
}

Identity {  // resolved at verify time via the vault (post-v1)
    algorithm:    SignatureAlgorithm,   // which scheme produced the current key
    public_key:   Vec<u8>,              // dynamic-sized — 32 bytes (Ed25519) to 1952 bytes (ML-DSA-65)
    // private_key never stored in this struct — lives in the vault
}

enum SignatureAlgorithm {
    Ed25519,                  // classical: 32-byte keys, 64-byte signatures
    MlDsa65,                  // post-quantum: FIPS 204 (ML-DSA-65, formerly Dilithium3)
    Hybrid(Box<[SignatureAlgorithm; 2]>),  // dual-mode: both must verify
}
```

The AID is the identity. Anyone who knows your AID can ask for the current verification key and check that data was signed by you. No one who lacks the corresponding private key can produce a valid signature. There is no enrollment, no approval, no account creation. Generating the key pair (and recording the inception event) is the act of creating the identity.

In **v1**, the vault is implicit — the AID bytes coincide with an Ed25519 public key, so resolution is the identity function. In **v1.5+**, key rotation and algorithm migration become first-class: the AID stays fixed; the vault's mapping changes. Existing signed artifacts continue to validate because the AID-to-key-history chain is preserved in the rotation log.

In **dual mode**, a signature is the concatenation of a classical Ed25519 signature and a post-quantum ML-DSA-65 signature. Both must verify independently. This provides security against classical attackers today and quantum attackers in the future — an attacker must break *both* schemes to forge a signature.

### Plurality is the default

A human holds many Principals. Each is its own AID, with its own keys, its own signatures, its own scope of use. The vault — a userspace service, local to the user's device — is the only place where these Principals are grouped under a single human. The kernel never holds this grouping; observers never see it. The link between "this human" and "this set of Principals" exists in exactly one place, by construction.

This is the privacy posture. CambiOS doesn't make users anonymous; it makes them plural. An observer holding a Principal sees a 32-byte AID and the artifacts that AID has authored or signed. They cannot reverse it to a human identity, and they cannot link it to other Principals the same human holds, because the linking information lives only in the user's vault.

### Three layers, separate

Identity in CambiOS lives at three architectural layers, and they should be kept distinct:

| Layer | What it knows | What it does |
|---|---|---|
| **Vault** (userspace, on-device) | Many Principals belong to this human | Selects which Principal a newly-spawned process binds to; holds private keys; gates with biometric/hardware unlock |
| **Per-Principal** (within one identity) | One Principal, with its own keys | Signs, verifies, derives scoped sub-keys for processes via KDF; rotates keys; publishes revocation/rotation proofs |
| **Kernel** (the OS itself) | One process, one bound Principal | Stamps `sender_principal` on IPC; transcribes the Principal onto authored objects; never reasons about plurality |

The boundary between the vault layer and the kernel layer is the **spawn syscall**. The parent process consults the vault (`bind_for_spawn(context)` returns a Principal); the kernel binds the new process to that single Principal; the kernel does not know the vault exists. Plurality lives entirely above the kernel.

### Kernel transcribes; never interprets in the hot path

The kernel's role with identity is **transcription**, not interpretation. It reads the bound Principal from process state, copies it onto outgoing IPC messages, stamps it onto authored objects, and stores it in audit events. It does not branch on Principal values to make policy decisions. Capability checks key on `ProcessId` and a handle table; they do not consult the Principal.

This is the verification posture: any kernel hot-path code that branches on a Principal value violates an invariant. The places where the kernel *does* interpret identity — signature verification at object authorship, bind-stability enforcement, bootstrap-Principal vestiges (being moved to capabilities per [ADR-023](adr/023-audit-consumer-capability.md)) — are at boundary operations (boot, cap promotion, object ingress), where they're already cheap to be expensive.

There is one carve-out: **mechanical set-membership at user-defined ingress boundaries** is permitted. A block list, expressed as a set of denied Principals, checked O(1) on every message receive, is set-membership — not policy adjudication. The kernel decides ∈/∉, not "should this Principal be allowed." That distinction is load-bearing for the [Revocation Model](#revocation-model-boundary-anchored-eventually-consistent) section below.

### Capability shape duality

Identity richness shows up in capabilities through a structural duality. Caps have two forms:

| Internal cap (kernel ring, hot path) | External cap (boundary, cold path) |
|---|---|
| `Capability { endpoint, rights }` — table entry in `ProcessCapabilities` | Sub-Principal + scope + lineage + (future) non-revocation witness |
| Bitfield check, ~ns (linear scan over `[Option<Capability>; 32]`) | Cryptographic check, ~μs |
| Identity is a process-level field, not embedded in the cap | Cap carries its own identity richness |
| Revocation: TTL or atomic table mutation | Revocation: accumulator update / witness staleness |

Internal caps are what processes use during their lifetime — looked up dozens of times per syscall, in the IPC hot path, where every nanosecond compounds. External caps are what travel: stored alongside persistent objects, handed across process or device boundaries, restored after restart. The kernel never holds the rich form. It receives an external cap at promotion (grant, restore, attach) — verifies it once, expensively — and installs the corresponding internal handle. It emits external caps at delegation. Inside the ring, only handles.

This is the same shape as control IPC versus channels ([ADR-005](adr/005-ipc-primitives-control-and-bulk.md)): hot-path messages are kernel-mediated and per-byte-checked; channel data flows through the MMU after a single kernel-mediated setup. The cap layer applies the same posture.

### Quantum-Resistant Dual-Mode Design

CambiOS does not bet on a single cryptographic assumption surviving the next several decades. The identity layer operates in three modes, selectable per identity and upgradeable over time:

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
- **Foundation of `did:key`** — The DID method most aligned with CambiOS's no-central-authority principle encodes Ed25519 keys directly.
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

The 32-byte AID stays fixed across all modes — algorithm-agnosticism applies to keys and signatures, not to the identity tag itself. See [ADR-025 § Architecture](adr/025-principal-as-aid.md) and [ADR-005 § Divergence: 2026-05-01](adr/005-ipc-primitives-control-and-bulk.md) for the load-bearing reasoning.

---

## The Vault

The vault is a userspace service that maps the user's Principals to their hardware key slots. It is the answer to "where do private keys live, and how do they map to running processes?" — and the answer to both halves is *the hardware key holds them; the vault holds the directory.*

In v0–1B, the vault is implicit — a software bootstrap key sits in a kernel static (used for platform signing only), and there is no runtime key management for user Principals. **Phase 1C** (below) is where the vault becomes a real service, extending the existing `key-store-service` slot at endpoint 17.

### What the vault holds

The vault is a **directory of `AID → hardware-key-slot` bindings**, not a key store. Private keys never live in software; they live in the hardware tokens (YubiKey PIV slots) and are exercised in-place via the CCID transport (see [ADR-032](adr/032-full-disk-encryption-below-substrate.md)'s `PivBackend::CcidPiv`). The vault knows *which device, which slot* holds the key for *which Principal*; it never holds the key bytes themselves.

```
Vault {
    principals:    Vec<VaultEntry>,             // many, by design
    context_map:   HashMap<ContextLabel, AID>,  // local-only "social_app → Principal_X"
}

VaultEntry {
    aid:                 [u8; 32],
    key_handle:          KeyHandle,             // (device_id, slot_id) — points into hardware
    inception_record:    Option<...>,           // KERI-style provenance, post-v1
    rotation_history:    Vec<...>,              // append-only, post-v1
}

KeyHandle {
    device_id:           HardwareDeviceId,      // e.g., YubiKey serial 12345678
    sign_slot:           PivSlot,               // PIV slot 9C (Ed25519 sign)
    decrypt_slot:        Option<PivSlot>,       // PIV slot 9D (X25519 ECDH) if needed
}
```

Operations against a Principal — sign data, decrypt envelope — route through the vault, which translates `AID → KeyHandle`, then issues the PIV APDU to the hardware token via `user/ccid`'s IPC. The vault is bookkeeping plus a transport coordinator; the private key bytes never enter its address space (or any userspace process's address space).

Because private keys never exist in software, the vault has **no "vault key" to derive and no "decrypt at session start" step**. Unlocking the vault means proving you hold the corresponding hardware token — typically a touch on the relevant key as the first operation that needs it. There is no biometric-derived KDF for daily use; biometric and social attestation come back in [Recovery, Biology, and Community](#recovery-biology-and-community) below for the cold-path recovery / witnessing roles, not for daily authentication.

### Plurality: primary and backup

v1 plurality is **one Principal per hardware key**, with at minimum a **primary + backup** key pair per user (typical: two YubiKeys, one carried, one in secure offline storage). The primary signs and decrypts during daily use; the backup is the recovery path if the primary is lost, stolen, or destroyed. Both hold the same AID's signing authority via a key-rotation chain — see [Key Lifecycle § Rotation](#rotation) for how the backup signs a rotation proof that replaces the lost primary.

Additional Principals come from additional keys. A user who genuinely needs separate identity contexts (e.g., distinct work-vs-personal identities with non-correlatable artifacts) provisions a separate key, or a separate slot on the same key, for each. The "many Principals per human" structural claim is preserved; the v1 friction is "buy another hardware key" rather than "click a UI button to mint an off-the-cuff Principal."

A future option keeps the door open for per-context KDF plurality: one hardware key signing a per-context challenge produces a deterministic per-context Principal key. This delivers many Principals from a single key without the "buy another device" friction, at the cost of more design surface. The slot is named here so the wire formats accommodate it; the implementation lands when it's load-bearing (a second key proves too friction-heavy for users wanting more than primary-and-backup).

### How processes get a Principal

Spawning is the identity-transition primitive. The parent process consults the vault before invoking spawn:

```
parent → vault.bind_for_spawn(context_label) → Principal P
parent → spawn(elf, principal=P)
kernel → binds new process to P; the rest of its lifetime uses P
```

The kernel learns nothing about the vault. It receives "spawn this child as Principal P" and treats P as opaque 32 bytes to transcribe forward. From the kernel's view, plurality does not exist — every process is bound to one Principal at the moment of creation, and stays bound for life.

Want to act as a different Principal? Spawn a different process. The process is the unit of identity in CambiOS. There is no "switch Principal mid-execution" syscall and there will not be — that would put a policy decision (which identity am I now?) inside the kernel ring, which is the wrong place for it.

### Why this is the privacy story

The human↔Principals mapping exists in exactly one place: the vault, on the user's device, in volatile memory while unlocked, encrypted at rest. It does not exist in the kernel. It does not exist on disk in plaintext. It does not exist in any observer's view.

A cloud service that talks to one of your Principals sees that Principal's AID and that Principal's signed artifacts. A different cloud service talking to a different one of your Principals sees a different AID and a different set of artifacts. The two cloud services cannot link them — the link is held only by you, locally.

This is anonymity-from-plurality, not anonymity-from-absence. You are not anonymous to the system you're using; you're anonymous *across* systems. Multi-Principal-by-default makes correlation attacks fail by construction, not by policy.

### What the vault is *not*

- **Not an aggregating identity.** There is no "vault Principal" that signs on behalf of the others. Each Principal in the vault is its own atomic origin. The vault is bookkeeping.
- **Not a kernel concept.** The kernel never knows the vault exists. The cap that grants access to the vault is held by userspace, like any other userspace capability.
- **Not a singleton.** A user may have multiple vaults (one per device), synchronized via per-Principal CRDT replication. Cross-device sync is local-first and end-to-end encrypted; no server holds vault state.
- **Not the same service as init.** [Init](adr/018-init-process-and-boot-manifest.md) supervises boot-time service lifecycle; the vault is the identity selector. They cooperate (init may consult the vault when spawning manifest entries) but are different services.

---

## Identity and Files

The decision that files have owners is the decision that shapes everything above it.

A file in CambiOS's native format is not bytes with a path. It is:

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

This is the canonical **cold-path identity-rich** artifact. Files travel: across processes, across devices, across humans. They outlive their creating processes. They survive reboots. They cannot rely on anyone's process being alive to vouch for them. So they carry full identity richness intrinsically — author Principal, owner Principal, signature, lineage. The cost (signature verification on each load) is paid at the boundary the file crosses, not in any hot path.

An employee creates a document at work — they are the creator, the employer is the owner. An independent contractor creates a document — they are both creator and owner unless a contract transfers ownership. The distinction matters: creatorship is provenance (who made this), ownership is authority (who controls this).

The owner signs the object. The signature ties content to controller cryptographically. Stripping the owner field invalidates the signature. You cannot forge ownership. You can only derive a new file with yourself as owner, and the lineage field traces back to the original.

### Per-Principal isolation

Files authored by one of your Principals are owned by that Principal. They are not implicitly shared with your other Principals — even though you, the human, are behind both. Sharing across your own Principals (because you, the human, are working in different contexts and want to move content between them) is an **explicit grant**, like sharing with another human.

This sounds severe but it is the right default. The whole point of multi-Principal is that the system never knows which Principals belong to the same human. If `social_Principal` could implicitly access `banking_Principal`'s files, the link would have to live somewhere queryable — defeating the privacy story. Instead, the user explicitly bridges contexts when they want to. The vault makes this easy in the UI; the architecture keeps it explicit.

### Ownership Transfer

Ownership is transferred via a signed `OwnershipTransfer` object — itself a CambiObject stored in the ObjectStore:

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

Provenance is structural. Because the creator field is immutable and ownership verified by signature, attribution cannot be stripped or forged. Forking any document produces a new object with the original hash in lineage — the chain of attribution is permanent and traceable without anyone's cooperation.

Sharing is replication of the same signed artifact, it's not a copy with back-referencing. A file you push to a peer is verifiable as yours regardless of where it lives. A sovereign cloud host stores objects as ciphertext they cannot read, forge, or credibly deny origins of.

The append-only social log is not a separate concept. Each post is a CambiObject. Linking by lineage creates the social log. Commerce is not a separate layer either. The identity primitive provides for the exchange primitive; a userspace finex module builds negotiation, terms, and settlement on top.

---

## Recovery, Biology, and Community

Daily authentication is the hardware key (see [Identity, Concretely](#identity-concretely-the-hardware-key) and [The Vault](#the-vault) above). This section is about what happens at the edges of that model: when keys are lost, when AIDs need to migrate, when a new identity must be witnessed into existence. Biological identity and social attestation participate here, not in daily use.

### When Keys Are Lost

A hardware-key model solves the cryptographic problem of identity and eliminates the "stolen private key file" attack surface. It does not solve the human problem of identity: what happens when you lose the keys themselves — physically misplaced, destroyed in a fire, lost in a flood, stolen, or rendered unusable by hardware failure?

The system answers this in tiers:

1. **Primary key lost; backup still held.** The default v1 model (see [The Vault § Plurality](#plurality-primary-and-backup)). The backup hardware key signs a rotation proof; the AID stays fixed; the old key is marked dead in the rotation log. The user replaces the primary with a new physical key; the new key is added to the vault as the new primary, the backup re-takes its role.

2. **Both primary and backup lost.** The AID has no live private key. Without external help, the AID is functionally dead — its public key still verifies old signatures (so signed artifacts remain valid), but no new signatures can be produced. The user can generate a new AID with new hardware, with no automatic continuity to the old AID.

3. **Both lost AND continuity required.** This is where biology and community step in — the recovery floor below the hardware-key chain. Re-establishing continuity requires *external evidence that you are the same human who controlled the old AID*: biometric proof, plus a quorum of social attesters who can vouch for the link between the lost-AID person and the present-day person standing in front of them. This is post-v1 research; the design slot is named here for future filling.

### Biometric Proof as Recovery Evidence (Future)

Biometric data is not the daily-use identity primitive (the hardware key is). It can, however, serve as evidence in the recovery tier above: "the human re-establishing this AID is the same human whose biometric was committed at the AID's inception."

**Biometric as proof, not as entropy.** Earlier framings of this document modeled biometric data as the entropy source for a derived vault key. In the hardware-key model that role evaporates — the vault has no software-held key to derive. What biometric still does is *attest continuity*: a fresh biometric measurement, proven via ZKP against a commitment made at the AID's inception, lets the recovery quorum verify "yes, this is the human we previously knew."

The proposed primary modalities, in order of preference:

1. **Retinal scan** — vascular patterns are distinct even between identical twins (shaped by stochastic developmental processes, not genetics alone). Stable over a lifetime.
2. **Facial geometry** — 3D facial structure diverges with age and life experience. Widely accessible via commodity hardware.
3. **DNA/epigenetic profiling** — held back until social and ethical consensus exists. **Revisit when:** a published civil-society standard or major identity-protocol acceptance for DNA-as-identity surfaces, or explicit user-base demand makes the question concrete.

No single biometric is perfectly unique in isolation. The resolution is a **context vector**: recovery evidence draws from multiple independent signals — biometric + temporal continuity + device-binding history + social attestation — that converge on a unique individual.

```
RecoveryContext {
    biometric_commitment:  Option<BiometricHash>,    // committed at AID inception (ZKP)
    device_entropy:        Option<[u8; 32]>,         // historic hardware-bound entropy
    social_attestation:    Option<Vec<Attestation>>, // quorum of trusted contacts
    temporal_proof:        Option<Timestamp>,        // continuity across time
}
```

This is post-v1 research. The design slot exists; the implementation lands when biometric ZKP infrastructure and the social-attestation substrate mature. **Revisit when:** a real user loses both hardware keys with continuity required, OR the broader ZKP / biometric tooling ecosystem produces a usable production stack.

### Privacy: Zero-Knowledge Proofs

Biometric data is inherently sensitive. A retinal scan reveals the unique vascular structure of your eye. Facial geometry is recognizable. DNA reveals disease predisposition, family relationships, and ancestry. None of this can be exposed in a public registry or embedded in a file header.

The zero-knowledge proof approach resolves this:

```
ZKP: "I possess a biometric sample consistent with the committed profile,
     without revealing the profile itself,
     without revealing which modality was used,
     without revealing anything about my biology beyond the proof."
```

The commitment (a hash of the biometric profile) is public and stored with the AID's inception record. The raw biometric data never leaves the device. Verification is proof of biological consistency, not disclosure of biological data.

This is an active research area. CambiOS does not implement biometric ZKPs in v1. The interface is designed to accommodate them at the recovery layer when they mature.

### Recovery Protocol (Future)

When v2+ infrastructure exists, the full recovery flow looks like:

```
Recovery protocol (v2+):
1. User has lost all hardware keys for AID_old; wants to establish AID_new
   with continuity attestation to AID_old.
2. User provisions fresh hardware keys (new primary + new backup).
3. User presents fresh biometric sample on a new device.
4. ZKP proves sample matches AID_old's inception biometric commitment.
5. Recovery quorum (peers attest from their SSB feeds): "we previously
    interacted with the human now presenting this biometric; the link to
    AID_old is one we observed over time."
6. Quorum signs a continuity attestation tying AID_old → AID_new, published
    to peer SSB feeds.
7. Verifiers walking the social graph see the continuity attestation
    alongside AID_old's old signatures; new signatures by AID_new inherit
    the historical trust weight at whatever discount the verifier chooses.
```

The recovery anchor is what you are biologically *and* who knows you. Losing both — destroyed biometric (rare) and isolated from your entire social graph (rare) — would be tricky at best, by design.

---

## Social Attestation and DAO/NAO Alignment

### The Social Graph as Identity Infrastructure

CambiOS's SSB-inspired social layer is core identity infrastructure. The append-only signed logs of your peers are a verifiable record of their interaction with you over time. A quorum of peers attesting to your identity is more than a social nicety. It is a cryptographic recovery mechanism.

This maps directly onto DAO (Decentralized Autonomous Organization) governance models: quorum decisions, on-log attestation, authority without central control. A recovery quorum functions like a DAO vote — a threshold of known parties must attest before a vault recovery is authorized.

The NAO framing — Networked/Natural Autonomous Organization — extends this toward biological and social systems as the model for decentralized governance. An identity system grounded in biological context and social attestation is a NAO-native design: authority derives from nature (biology) and community (social graph), not from institutions.

### Enrollment: The Cold-Start Problem

The hardest question in biological identity is the first enrollment. At some point, a biometric sample must be committed for the first time. If that enrollment is compromised, every Principal in the vault that depends on it is compromised from origin.

The proposed resolution is that enrollment is a **witnessed social act**, not a database transaction:

- Existing identities in your social graph witness and attest the enrollment
- The enrollment record is signed by the witnesses and stored in their append-only logs
- A new vault's provenance is traceable to the community that witnessed its creation

A new vault's trust weight reflects the depth and history of its attestation graph — not a binary trusted/untrusted distinction, but a continuous signal that grows with genuine interaction.

This mirrors how human identity has always worked at its most fundamental level: community recognition, not institutional registration. You exist as an identity because people who know you attest to your existence. CambiOS makes this explicit and cryptographic.

Bootstrapping the system requires real human group interaction.

---

## Key Lifecycle

### Generation

Key generation is local. No network required. No authority consulted. Each Principal in the vault is generated independently — generating a new Principal is a vault operation, not a separate ceremony. The `IdentityContext` (biometric + device entropy + social attestation) seeds the vault key, which in turn protects each Principal's private material at rest.

A human typically holds many Principals: one per context, one per relationship, one per service category, possibly ephemeral ones for one-shot interactions. Generating a new Principal is cheap and contextual.

### Storage

Private keys live in the vault. No userspace process other than the vault holds raw private key material. Signing operations are requests to the vault: "sign this data with Principal X." The vault returns the signature; the private key does not leave.

When hardware security modules are available (TPM, Secure Enclave), Principals' private keys live in hardware and signing happens inside the secure element. The vault becomes a thin coordinator between the userspace requester and the hardware. The raw key material is never exposed to software under any circumstances.

### Rotation

Key rotation is per-Principal, not vault-wide. A Principal whose key is compromised rotates; the AID stays fixed; the vault's mapping updates; existing artifacts signed by the old key remain valid through the rotation chain.

The rotation protocol:

1. New key pair generated within the vault, bound to the same AID
2. Recovery quorum attests continuity (biometric + social) for high-value rotations
3. Old public key signs a rotation record pointing to new public key (if old key is still accessible)
4. If old key is inaccessible: quorum attestation alone authorizes rotation, recorded in witnesses' logs
5. New key is the current key for the AID; the rotation proof links the new key to the original identity chain
6. Files signed with old key remain valid — the rotation proof establishes they were made by the same identity

### Delegation to Processes

CambiOS's three-layer identity model maps cleanly onto process delegation:

**Vault layer:** the parent process consults the vault at spawn time. The vault returns a Principal `P` appropriate to the spawn context. Different children of the same parent can be bound to different Principals if the parent (with vault permission) chooses.

**Per-Principal layer:** *within* a Principal `P`, processes can derive scoped sub-keys for fine-grained delegation:

```
process_key = KDF(P_private_key, process_capability_hash, timestamp)
```

A signature from a process's scoped key is verifiable as deriving from `P` without exposing `P`'s root private key to the process. A compromised process under `P` cannot forge `P`'s identity for operations outside its scope. This per-Principal KDF model is the original delegation primitive (preserved from prior versions of this document); it operates *underneath* the vault's multi-Principal selection.

**Kernel layer:** the kernel sees one process, one bound Principal. The bound Principal is the AID stamped onto every IPC message and authored object. The kernel does not see — and does not care — that this Principal is one of many in the user's vault.

---

## Revocation Model: Boundary-Anchored, Locally-Convergent

CambiOS does not have a central authority that can revoke identities. There is no certificate revocation list, no global kill switch, no admin who can delete you. Revocation is **local**, **social**, and structurally tiered to match the cap-shape duality from [What Identity Is](#what-identity-is): hot-path mechanisms for hot-path caps, cold-path mechanisms for cold-path caps.

There are three distinct mechanisms, serving different purposes.

### Local Blocking (Immediate, Kernel-Enforced, Set-Membership)

Every Principal maintains a **block list** — an immutable, append-only set of Principals that are denied IPC access. When a Principal is blocked, the kernel refuses IPC messages from that sender before they reach the recipient.

The block-list check sits at the IPC ingress boundary — every message receive consults a per-Principal hash set or bloom filter, O(1). Importantly, this is **mechanical set-membership, not policy adjudication.** The kernel decides ∈/∉; it does not branch on the Principal's *value* to make a policy decision about *what kind of identity* this is. The user defines the set; the kernel enforces the membership check. This distinction is what keeps the check compatible with the "kernel transcribes, doesn't interpret" invariant.

Block lists are published to the owner's SSB feed so peers can see who you've blocked, but the enforcement is local. You don't need anyone's permission to block, and no one can force you to unblock.

The block list is stored per-process in the capability manager, not in a global table — blocking is a per-Principal decision, not a system-wide one. A user's `social_Principal` may block someone their `banking_Principal` happily transacts with, because they are different identities making different trust decisions, even though they belong to the same human.

### Capability Revocation (Tiered by Cap Shape)

Beyond IPC blocking, the cap-shape duality implies two revocation paradigms:

**Internal caps (kernel table):** synchronous, kernel-led, push-based revocation. The `revoke()` method atomically removes the capability from the holder's table, issues TLB shootdowns for any associated channel mappings, invalidates per-CPU policy caches, and notifies the holder via control IPC. After `revoke()` returns, no thread on any CPU can use the revoked capability. This is the model specified in [ADR-007](adr/007-capability-revocation-and-telemetry.md), and it remains correct for in-kernel caps where the kernel has direct authority over the table.

**External caps (persistent, cross-domain):** asynchronous, holder-led, pull-based via **non-revocation witnesses**. For caps that outlive their issuing process — caps stored alongside CambiObjects, caps handed across device boundaries, caps issued for cross-Principal grants — the kernel cannot reach across boundaries to push a revocation. Instead, the issuer maintains an accumulator (a small constant-size cryptographic structure, published as a CambiObject); cap holders carry witnesses against the accumulator; verification at use checks witness-against-current-accumulator membership. Revocation is an accumulator update — holders converge asynchronously by refreshing their witnesses; revoked holders cannot generate a new witness because their cap was excluded from the new accumulator.

The two paradigms compose. A cap promoted *into* the kernel table from an external presentation is checked once (witness verified, accumulator membership confirmed) and then becomes a fast bearer token until it expires or is explicitly revoked. The cold-path crypto pays for itself at the boundary; the hot-path stays hot. See ADR-007's forthcoming amendment for the full witness-and-accumulator design.

### Revocation Publication (Social, Eventually Consistent)

When a key is compromised or permanently retired, the owner (or their recovery quorum) publishes a signed proof to their append-only SSB feed. There are two types:

**KeyRotationProof** — "My old key is retired; my new key is this one." The old key signs the proof if it's still accessible (see Key Lifecycle > Rotation above). If the old key is lost, the recovery quorum attests the rotation instead. The rotated identity is the *same* identity (same AID) — files signed with the old key remain valid, linked through the rotation chain.

**KeyRevocationProof** — "This key is dead. There is no successor." This is for permanent compromise where the owner cannot or does not wish to rotate. The revocation proof is signed by a quorum of social attestors (since the compromised key itself is untrusted). A revoked key has no continuity — it is a severed identity.

Peers learn about revocations through normal SSB feed replication. When a peer sees a rotation or revocation proof in a feed they follow, they can choose to adopt the block — adding the old key to their own block list. This propagates outward through the social graph: your close contacts learn in seconds, their contacts in minutes, distant nodes over a longer window as replication reaches them.

### The AI Watcher's Role

The AI security service ([ADR-007](adr/007-capability-revocation-and-telemetry.md), [PHILOSOPHY.md](PHILOSOPHY.md)) consumes the audit telemetry stream — IPC patterns, capability denials, channel events, process lifecycle — and detects behavioral anomalies. **The AI does not write policy**, and it does not decide who is allowed to do what. What it does, when it notices an anomaly, is **flag and recommend containment**:

1. AI sees `Principal_X` exhibiting access patterns inconsistent with its history.
2. AI sends a recommendation to the policy service: "Recommend narrowing capability set on `Principal_X`."
3. Policy service evaluates the recommendation against its rules (which may or may not act on AI input — configurable).
4. If the policy service decides to act, it calls `SYS_REVOKE_CAPABILITY`. The kernel performs the mechanical revocation.

The AI never invokes kernel intervention primitives directly. It holds two capabilities — read the audit channel, send recommendations to the policy service — and that is the entirety of its authority. Compromising the AI cannot directly compromise anything; the worst it can do is send bad recommendations, which still have to pass through the policy service.

Critically, **containment is per-Principal**. When the AI flags `social_Principal`, the human's other Principals are untouched. The blast radius of a sandbox event is a context, not a person. This composition with multi-Principal-by-default is what makes "AI watches and contains" usable in practice — narrowing one identity does not disrupt the human's broader work.

### The Bootstrap Principal: Platform Identity, Not Human Identity

The bootstrap Principal is **the platform itself** — kernel, boot modules, signed code that makes up "CambiOS on this disk." It is not a person, does not represent a person, and lives entirely outside the vault model. There is one bootstrap Principal per build, not per human; it cannot be socially revoked because it has no social graph.

The bootstrap Principal's role is narrow: sign the boot modules at build time, verify those signatures at boot time. The kernel's baked-in `bootstrap_pubkey.bin` is the trust anchor for "this code came from the entity that built this CambiOS image."

**Distribution model (target):**

For distributed releases, the bootstrap Principal is the **distributor's identity** — Coherent Forge (or whoever else releases binaries) holds the bootstrap private key on hardware and signs each release. The release ships with `bootstrap_pubkey.bin` matching that hardware. Users running distributed binaries are trusting the distributor to have signed the right things.

For **users who compile from source**, the bootstrap Principal is *theirs*. The existing `make gen-dev-piv-keys` machinery (post-rename: `make gen-bootstrap-key`) writes a fresh keypair to `bootstrap_pubkey.bin`, the kernel rebuilds with that key baked in, the user's `sign-elf` signs the boot modules with the corresponding private key. The structural exit from "trust the distributor" is "compile your own and become the distributor for your own machine."

This is the Linux Secure Boot + MOK shape: factory keys for distributors, user-replaceable trust anchors for self-builders. The crucial property is that the bootstrap is **per-distribution**, not **per-user**. Your daily-use YubiKey-backed Principal lives in the vault and is unrelated to the bootstrap. Two different hardware-key-rooted identities at two different layers — never confused.

**Current implementation status (v1):**

The bootstrap key today is a **software keypair** generated by `gen-dev-piv-keys` from a per-developer seed, baked into the kernel and used by `sign-elf` for boot module signatures. This is sufficient for zero-user development and self-hosted use; the hardware-rooted bootstrap lands when distribution becomes concrete. Two gating factors:

1. **No distribution yet, no user-facing trust-chain question.** Premature to commit hardware to a role that doesn't yet have a real-world claim.
2. **Hardware-vendor algorithm support is still maturing.** The full CambiOS stack is Ed25519 (signing) + X25519 (envelope decrypt); the SwissBit iShield Key 2 Pro's PIV applet currently supports only NIST curves + RSA (see [Open Questions](#open-questions)). YubiKey 5.7+ supports Ed25519/X25519 on PIV; the cleanest hardware bootstrap awaits either SwissBit roadmap progress or a deliberate algorithm-split design choice across the bootstrap and user-identity roles.

When distribution becomes real, the hardware bootstrap question gets a dedicated ADR.

**Bootstrap key revocation** is a **system-level event** rather than a social/quorum one: firmware update, new hardware key provisioning, re-signing of boot modules, release of a new image with the new `bootstrap_pubkey.bin`. Pre-installed users on the old image stay there until they choose to upgrade; no global revocation, no forced upgrade. The social revocation model does not apply at this layer.

### Properties

| Property | Traditional CA | CambiOS Revocation |
|----------|---------------|--------------------|
| **Latency (push)** | Seconds (CRL/OCSP) | Microseconds (kernel revoke for internal caps) |
| **Latency (social)** | N/A | Seconds to minutes (social graph replication) |
| **Latency (witness)** | N/A | Asynchronous (witness staleness window, bounded by refresh policy) |
| **Scope** | Global | Local-first, social, per-Principal |
| **Authority** | Central (CA decides) | Distributed (each peer decides independently) |
| **Censorship resistance** | Low (CA can revoke anyone) | High (revocation is a claim peers evaluate, not a directive) |
| **Scaling cost** | O(n) global list | O(1) per-peer block + O(1) accumulator membership |
| **Offline resilience** | Fails (can't reach OCSP) | Degrades gracefully (local blocks + cached witnesses still work) |

### Why This Is Sufficient

This model trades **instant global revocation** for **layered local revocation with eventual consistency**. The trade is worth it because:

1. **Real-world identity already works this way.** When someone's identity is compromised, you tell the people who matter — your friends, your colleagues, your bank. You don't issue a global broadcast. The people who need to know find out fast; the people who don't need to know find out in due course, or not at all.

2. **The attacker's window is narrow.** An attacker with a stolen key cannot immediately impersonate you to your actual contacts — you notify them through a trusted side channel (in person, phone call, pre-shared signal) and they block instantly. The attacker can only fool strangers who haven't received the revocation yet, and strangers have low trust weight by default.

3. **Central revocation is a central vulnerability.** Any system that can revoke you globally can be coerced, compromised, or corrupted into revoking you unjustly. CambiOS eliminates this attack surface entirely. No single entity — not even the OS itself — can erase your identity from the network.

4. **The three mechanisms are tier-appropriate.** Internal caps need synchronous push (the kernel can do it). Persistent caps need async pull (witnesses against accumulators). Identity-level revocation needs social propagation. Trying to use one mechanism for all three would make some operations too slow and others too brittle. Tiering is honest about the cost structure.

---

## Implementation Roadmap

### Phase 0: Bootstrap Identity

The bootstrap identity is the platform's root of trust — used to sign kernel and boot modules at build time, verified at boot time against a kernel-baked public key. The bootstrap Principal is platform identity, not human identity; see [The Bootstrap Principal](#the-bootstrap-principal-platform-identity-not-human-identity) above for the full discussion.

**Current implementation (v1):** A software keypair generated by `make gen-dev-piv-keys` from a per-developer seed. The public key is baked into the kernel via `include_bytes!`; the private key is held by the developer for `sign-elf` to sign boot modules. Sufficient for zero-user development and self-hosted use.

```rust
// bootstrap_pubkey.bin: 32-byte Ed25519 public key from gen-dev-piv-keys
const BOOTSTRAP_PUBKEY: &[u8; 32] = include_bytes!("bootstrap_pubkey.bin");
```

**Hardware-rooted bootstrap (v1+ target):** The bootstrap keypair lives in a tamper-resistant hardware token (YubiKey PIV slot 9C or equivalent). `sign-elf` communicates with the token; the private key never leaves silicon. This lands when:

1. Distribution becomes real (an organization releases CambiOS binaries to users that aren't the developer), creating a meaningful trust-chain claim worth anchoring.
2. Hardware-vendor algorithm support catches up to the stack's Ed25519/X25519 family. YubiKey 5.7+ supports Ed25519 on PIV; SwissBit's iShield Key 2 Pro PIV applet is currently NIST-curves only (request filed with vendor for Ed25519 support).

The current interface is algorithm-agnostic via dynamic-sized fields; switching from software to hardware bootstrap, or from one algorithm family to another, is a build-time change without structural impact. See [Open Questions § Bootstrap hardware](#open-questions) for the gating decision.

### Phase 1: Cryptographic Hardening

Real entropy for runtime randomness, signed ELF verification with the bootstrap public key, content-addressed object storage with Blake3 hashes, Ed25519 signature verification on `ObjPut`. See [ADR-004](adr/004-cryptographic-integrity.md) and [ADR-003](adr/003-content-addressed-storage-and-identity.md) for the details.

### Phase 1.5: Post-Quantum Upgrade

ML-DSA-65 implementation integrated alongside Ed25519. New Principals default to Hybrid mode (Ed25519 + ML-DSA-65). Existing Ed25519 Principals can upgrade via key rotation — the rotation proof is dual-signed (old Ed25519 key signs the new Hybrid key, establishing continuity). File verification dispatches on the `SignatureAlgorithm` tag and validates accordingly.

### Phase 1C: Vault Service (Hardware-Key Directory)

The `key-store-service` slot at endpoint 17 (currently degraded — endpoint reserved, no real backend) becomes the **multi-Principal vault**. Per the hardware-key model in [The Vault](#the-vault) above, the vault is a directory of `AID → hardware-key-slot` bindings; private keys live in the YubiKey hardware, never in software.

**Scope:**
- Vault holds N entries per human, one per provisioned hardware-key slot. v1 minimum: a primary + backup pair (typical: two YubiKeys with matching slot 9C signing keys).
- Userspace API exposes `bind_for_spawn(context_label) → AID` for parent processes consulting the vault before spawn.
- Userspace API exposes `sign_with(aid, data) → Signature` for authored content and IPC handshakes; the vault routes through `user/ccid`'s IPC to drive the corresponding hardware token (touch required per slot policy).
- No vault key derivation, no biometric KDF — daily-use unlock is hardware-key touch on the first operation that needs a signature.
- Cross-device sync uses per-Principal CRDT replication of the directory (AIDs + hardware-key-handle metadata); private keys cannot sync because they live in silicon. A second device gets a second pair of hardware keys, with a rotation chain linking them to the same AID.
- The `ObjPutSigned` syscall stays the cap-gated "store this pre-signed object" primitive; signing happens in the vault (via the hardware token) before the syscall is invoked.

**Out of scope (this phase):**
- Runtime hardware-key access on bare metal (requires Stream B B-viii/B-ix CCID + PIV applet completion).
- Hardware-backed sealed storage of derived keys (TPM/Secure Enclave integration; long-term).
- Witness-bearing capabilities for cold-path revocation (deferred to ADR-007 amendment).
- Per-context KDF plurality (one hardware key → many context-specific Principals via on-device signing of context labels). Slot reserved; lands when multi-key plurality friction becomes load-bearing.

### Phase 2: Biometric Recovery Infrastructure (Future)

Per [Recovery, Biology, and Community § Biometric Proof as Recovery Evidence](#biometric-proof-as-recovery-evidence-future), biometric ZKP becomes available at the **recovery tier**, not in daily authentication. The `RecoveryContext.biometric_commitment` field gets populated at AID inception; recovery flows can present a fresh biometric sample and prove continuity to the inception commitment via ZKP.

Requires ZKP infrastructure and biometric scanning integration — post-v1 research. The hardware-key daily-use path doesn't depend on this; biometric is purely recovery floor.

### Phase 3: Social Attestation Quorum (Future)

Social graph quorum recovery and witnessed enrollment. The `RecoveryContext.social_attestation` field becomes populated from the SSB-inspired social layer. Lost-key recovery via quorum attestation is implemented. The cold-start enrollment protocol — witnessed AID inception with peer-signed attestations — is defined and tooling lands.

This is the recovery floor that participates with biometric ZKP (Phase 2) to handle "both hardware keys lost AND continuity required" cases.

### Phase 4: Full DID Integration

`did:key` encoding of identity public keys. Ed25519 keys use the existing `did:key` multicodec. ML-DSA-65 and Hybrid keys use extended multicodec prefixes (pending W3C/IETF standardization of post-quantum DID methods). Identities become expressible as DIDs, interoperable with the broader decentralized identity ecosystem. Cryptographic capabilities across networked CambiOS nodes become possible.

---

## Architectural Invariants

These must hold after every change to identity-related code:

1. **Private keys never exist in software.** Per the hardware-key model, private keys live in tamper-resistant silicon (YubiKey PIV slots or equivalent) and are exercised in-place via the CCID transport. The vault holds the AID → hardware-key-slot directory, never the key bytes. No userspace process — including the vault — sees raw private key material at any point. (Pre-hardware-bootstrap-rollout: the software bootstrap key for platform signing is the one exception, explicitly named in [The Bootstrap Principal](#the-bootstrap-principal-platform-identity-not-human-identity); it does not represent a human and is scoped to build-time code signing.)

2. **Every file has a creator and an owner.** The native CambiOS filesystem format has no concept of a creatorless or ownerless file. The creator field is immutable — no API path may modify it after creation. The owner field is transferable only via signed `OwnershipTransfer` objects. Files created by system processes during bootstrap have the bootstrap identity as both creator and owner.

3. **Signatures are verified before trust.** A file's owner field is meaningless without verifying the signature. Code that reads owner without verifying signature is a bug.

4. **Biological data never leaves the device unencrypted.** Biometric commitments are hashes. ZKPs are proofs. Raw biological data is never transmitted, stored remotely, or exposed to any process other than the vault.

5. **Enrollment is witnessed.** The cold-start enrollment protocol requires social attestation. Unwitnessed enrollment is not supported in production — only in bootstrap/development mode, and explicitly labeled as such.

6. **Key rotation preserves lineage.** A rotated identity is the same identity (same AID). Files signed with the old key and files signed with the new key are traceable to the same root through the rotation proof chain.

7. **The kernel transcribes identity in the hot path; it interprets only at boundaries.** Kernel hot-path code (capability checks, IPC stamping, audit emission) must not branch on Principal values to make policy decisions. Mechanical set-membership at user-defined ingress boundaries (block lists) is permitted — set membership is not adjudication. Identity interpretation (signature verification, cap promotion, bootstrap-Principal special cases) happens only at boundary operations where the surrounding context already pays high fixed cost.

8. **A process is bound to exactly one Principal at any moment.** Plurality is a vault property, not a process property. The kernel never holds, receives, or reasons about a "set of Principals" for a single process. To act as a different Principal, spawn a different process.

9. **The human↔Principals mapping never leaves the user's device.** The vault is the only entity that knows which Principals belong to the same human. This link is held in volatile memory while the vault is unlocked, encrypted at rest, and never transmitted in plaintext. Cross-device vault sync is end-to-end encrypted with no server-side knowledge of the mapping.

---

## Open Questions

These are known unknowns.

Bootstrap hardware:

- **Hardware-vendor algorithm support for the bootstrap role.** The stack is Ed25519 (signing) + X25519 (envelope decrypt). YubiKey 5.7+ PIV supports both. SwissBit's iShield Key 2 Pro PIV applet is currently NIST curves + RSA only. Three live design options, none chosen pending distribution + vendor roadmap clarity: (1) algorithm split (P-256 bootstrap + Ed25519 user identity; kernel verifies both schemes), (2) FIDO2-mode `sign-elf` adapter (SwissBit's FIDO2 supports Ed25519; stack stays algorithm-uniform), (3) different bootstrap device (additional YubiKey 5.7+ in the bootstrap role; SwissBit repurposed). **Revisit when:** SwissBit responds re: Ed25519/X25519 PIV roadmap, OR distribution becomes concrete and the decision becomes load-bearing.

Phase 1.5 blockers:

- **ML-DSA-65 `no_std` implementation** — Which Rust crate for ML-DSA-65 works in `no_std` bare-metal? `pqcrypto-dilithium` wraps C; `ml-dsa` (RustCrypto) is pure Rust but may need maturity review. Stack usage for lattice operations on a 256KB boot stack needs measurement.
- **Hybrid signature verification cost** — Dual verification (Ed25519 + ML-DSA-65) on every file access approximately doubles CPU cost. Is per-file caching of verification results sufficient, or does hot-path file access need a session-scoped verification bypass?

Vault design questions:

- **Cross-device vault directory sync.** Per-AID CRDT replication is the natural model (each AID owns its directory entry; the entry replicates across the user's devices). Concrete CRDT choice (RGA, Causal Tree, OR-Set with custom merge) deferred until vault implementation begins. Private keys cannot sync — they live in silicon. A second device gets a second hardware-key pair, with a rotation chain linking it to the same AID. **Revisit when:** Phase 1C lands and a second device joins the user's vault.
- **Witness-bearing cap envelope format.** The external cap form sketched in [Capability shape duality](#capability-shape-duality) — sub-Principal + scope + lineage + non-revocation witness — does not yet have a wire/disk format. Deferred to the ADR-007 amendment that lands non-revocation accumulators. **Revisit when:** the first non-FS persistent cap (e.g., a delegated network grant that survives process exit) needs to be serialized.
- **Hardware-key presentation under coercion.** A physical touch on a hardware key can be compelled — the silicon doesn't distinguish "willing" from "coerced." A duress mode (a separate slot that signs decoy artifacts and alerts peers, or a PIN entry that activates a containment mode) is a real research direction but explicitly deferred. **Revisit when:** a credible threat model surfaces that requires it (e.g., journalist-protection deployment).

Further future unresolved:

- **ZKP library selection** — Which ZKP system is appropriate for biometric proofs? Groth16, PLONK, STARKs? The choice affects proof size, verification time, and trusted setup requirements.
- **Retinal scanning hardware** — What consumer-grade retinal scanning APIs exist? Integration with mobile/desktop hardware (e.g., IR camera arrays). Phase 2 may require partnership with hardware vendors or standardization efforts.
- **Facial geometry stability** — How is aging, injury, or surgical change handled? What is the false rejection rate over a 10-year window? Is periodic re-enrollment needed, and if so, how does that interact with the commitment model?
- **Quorum size and threshold** — How many social attestations are required for vault recovery? What prevents a social engineering attack on the quorum?
- **DNA as future modality** — Under what conditions (social consensus, privacy infrastructure maturity, regulatory clarity) would DNA/epigenetic profiling be activated? What governance mechanism decides this — per-user opt-in, community vote, or protocol-level upgrade?
- **Process key scoping** — How is the `process_capability_hash` computed? What prevents a process from claiming a broader scope than it was granted?
- **Rotation during social graph unavailability** — If a key is lost and the social graph is offline (no network), how is recovery handled? Is there a time-limited local recovery path?
- **Post-quantum DID encoding** — `did:key` multicodec for ML-DSA-65 is not yet standardized. CambiOS may need to define a provisional encoding and migrate when the standard lands. What is the compatibility strategy?
