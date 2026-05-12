# CambiOS Identity Synthesis: Translation, Not Adoption

This document is the design context under which CambiOS participates in decentralized identity ecosystems (the First Person Network, ToIP-stack-compatible verifiable trust networks, KERI-based key event chains) without being defined by any of them. It is not a decision record. It is the framing the follow-on ADRs cite when they pick specific mechanisms.

- **Status:** Design context for follow-on ADRs (AI-as-Principal, Multi-Principal Vault, Translation-Layer Compatibility). Forward-looking. No code lands from this document directly.
- **Date:** 2026-05-07
- **Depends on:** [ADR-025](adr/025-principal-as-aid.md) (Principal as 32-byte AID), [ADR-026](adr/026-identity-transcription-at-the-kernel-ring.md) (kernel transcribes; cap-shape duality)
- **Related:** [identity.md](identity.md) (source-of-truth identity architecture), [ADR-027](adr/027-service-clusters.md) (service clusters as the trust-topology unit), [ADR-007](adr/007-capability-revocation-and-telemetry.md) (audit ring + capability revocation), [ADR-004](adr/004-cryptographic-integrity.md) (ELF / ARCSIG signing)
- **External context:** First Person Project White Paper v1.2 (2026-01-23), OpenVTC reference implementation (Apache-2.0, Rust)

## Synthesis Principle

ADR-026 established that capabilities have two shapes: the kernel's compact `(endpoint, rights)` handle and the rich-form envelope that crosses trust domains. This document generalizes the same duality up one level, to identity itself.

Internal shapes (kernel, vault state, IPC payloads) are CambiOS-native: 32-byte AID Principals, service-cluster manifests, ObjectStore-persisted credentials, sub-Principal-keyed cap inventories. External shapes (network wire, credential exchange, registry lookup) are whatever the counterparty needs: did:webvh, did:scid, did:peer, raw KERI AIDs, W3C VCs, VRC envelopes, PHC presentations. The userspace vault is the translation layer.

The principle, in three words: **mechanical kernel, multilingual vault, topological clusters**. Three layers, clear separation, each verifiable independently, each maps to its own ADR.

## Layer-by-Layer

### Kernel ring

Unchanged from ADR-025 / ADR-026. Principal is a 32-byte AID. Capabilities are `(endpoint, rights)` table entries. The transcription invariant holds: kernel does not interpret identity values, it transcribes them. No DID, VRC, ToIP, or DTG knowledge inside the ring. Verification posture per ADR-000 § Divergence remains intact. Future formal verification of the cap subsystem is unaffected by this synthesis because nothing in this document touches kernel code.

### Multi-Principal vault

A userspace service that owns the FPP-and-friends boundary. It holds keys (BIP-32 derivation, YubiKey-rooted), generates AIDs, manages multi-Persona via P-DIDs derived under each Principal, and speaks external DID methods at the network boundary as the counterparty requires. Internal vault state is CambiOS-native: sub-Principal-keyed, ObjectStore-persisted, IPC-mediated. External presentation is generated on demand from internal state, not stored persistently in external form.

Concretely, the vault speaks at v1:

- did:webvh for FPN counterparties (per the OpenVTC reference implementation)
- did:peer for pairwise relationship DIDs
- raw KERI AIDs for KERI-suite peers
- A CambiOS-native canonical encoding for in-system communication

New methods plug in as adapter modules. If the FPN ecosystem shifts in v1.3, the adapter changes; kernel and core vault state do not.

### Service clusters as trust-topology unit

ADR-027 introduced service clusters as the kernel-mediated boundary for revocation. They generalize naturally to trust-topology context. A user's "social cluster" might be (vault, social-Principal, browser, social-AI). A "banking cluster" might be (vault, banking-Principal, banking-app, banking-AI). Clusters can be CambiOS-only, or they can present as Verifiable Trust Communities at the FPP boundary if the user wants outside recognition. The cluster manifest becomes the natural site for "which external trust ecosystems is this cluster a member of."

### AI agents as Principals

AI services run as ordinary CambiOS processes with their own Principals, ELF-signed binaries (ARCSIG), and policy-service-mediated cap inventories. The seven First Person Certified AI tests from white paper Part 8 (training, data storage, authenticated delegation, recovery, fiduciary duty, auditing, certification) become deliverables the vault, policy-service, and kernel jointly achieve. CambiOS's certification posture is structurally stronger than FPP's paperwork program: the binary is hardware-attested via ARCSIG, the Principal is YubiKey-rooted, the cap inventory is policy-service-bounded. Any verifier with the bootstrap public key can confirm these claims cryptographically.

## The Translation Layer Pattern

The vault's translation layer follows the same architectural shape as fs-service: a userspace mediator that speaks rich external formats at one face and emits compact internal handles at the other.

Inbound (cap promotion):

1. External rich-form credential arrives at a CambiOS endpoint, over IPC if local cluster, over a network-to-IPC bridge if remote.
2. Vault verifies the issuer signature against the published DID document, checks scope and validity window, checks revocation if the credential type carries it.
3. Vault derives an internal cap-handle and hands it to the relying-party process.
4. Relying party uses the handle through normal CambiOS cap mechanics. Kernel sees only `(endpoint, rights)`.

Outbound (cap delegation):

1. CambiOS process requests delegation of an internal cap to a remote counterparty.
2. Vault wraps the internal handle in whatever rich envelope the counterparty needs (VRC for FPP peer, raw KERI for KERI peer, did:cambios for another CambiOS box if we mint our own method, plain W3C VC for a generic verifier).
3. Vault signs with the appropriate Persona key, YubiKey-attested where required.
4. Envelope ships to the network. Kernel never sees the envelope.

Both directions verify cryptographically. Neither bothers the kernel ring. The translation layer's bugs are userspace bugs: isolatable, replaceable, and bounded in blast radius without touching verification-target kernel code.

## FPP-Shape to CambiOS-Shape Mapping

| FPP shape | CambiOS shape | Translation point |
|---|---|---|
| Sovereign wallet / Personal Network Manager (PNM) | Multi-Principal vault (userspace service) | None: the vault *is* the PNM, in CambiOS conventions |
| Autonomic Identifier (AID) | Principal (32-byte, kernel) | None: kernel uses the bytes verbatim |
| `did:webvh` / `did:scid` / `did:peer` | Vault-emitted DID at network boundary | Vault wraps Principal in DID envelope on egress, unwraps on ingress |
| Verifiable Relationship Credential (VRC) | Rich-form cap at boundary; internal `(endpoint, rights)` | Vault translates on grant, restore, attach, delegate |
| Personhood Credential (PHC) | A CambiOS Principal bound to user via YubiKey ceremony, with vault attestation | Vault emits PHC envelope from internal binding when an FPP counterparty asks |
| Verifiable Membership Credential (VMC) | Cluster membership assertion (ADR-027 manifest entry) | Vault generates VMC on outbound presentation |
| Verifiable Persona Credential (VPC) | P-DID document signed by vault | Vault generates on outbound persona-share |
| Verifiable Endorsement Credential (VEC) | Userspace credential, ObjectStore-persisted | Vault translates inbound, generates outbound |
| Trust Spanning Protocol (TSP) | Network transport, terminated in userspace | TSP-over-IPC bridge process; kernel sees only IPC bytes |
| Trust Registry Query Protocol (TRQP) | Userspace trust-registry-query service | None: pure userspace |
| Verifiable Trust Community (VTC) | Service cluster (ADR-027), optionally with FPP-shaped governance manifest | Cluster manifest presents as VTC if user wants outside recognition |
| First Person Certified AI Agent | Principal-bound AI service + ELF-signed binary + policy-service-mediated cap inventory + YubiKey attestation | Vault generates "Certified AI" credential for outbound presentation |
| FedID / DIDComm / ActivityPub | Userspace network protocols | Out of kernel scope entirely |

## Structural Wins

1. **Verification-friendly kernel stays verification-friendly.** ADR-000, 002, 026 do not move. Translation-layer bugs are userspace bugs, contained.
2. **Multi-DID-method support is architecturally free.** Vault picks per context. New methods plug in as adapter modules. If a counterparty network changes its credential format, the adapter changes; kernel does not.
3. **Native first-class FPN participation without being FPP-defined.** Users can hold PHCs, exchange VRCs, join VTCs, all backed by CambiOS Principal infrastructure. No adoption ceremony of FPP-the-organization at the architecture level.
4. **AI agents become a kernel-mediated identity-fabric primitive.** Hardware-anchored certification (ELF-signed + YubiKey-attested + policy-bounded) is structurally stronger than paperwork certification. The seven FPP tests are properties any verifier can check cryptographically.
5. **Architectural sovereignty.** CambiOS is not riding any single ecosystem's roadmap. If the FPN forks or stalls, CambiOS keeps working with whatever its users' counterparties speak.
6. **Three-layer story, each layer separately verifiable.** Kernel (mechanical), vault (cryptographic), service clusters (topological). Each maps to an independent ADR, each to an independent verification effort.

## YubiKey Double Duty

The YubiKey-as-root-of-trust roadmap was conceived in two separate contexts: kernel-side ELF and ARCSIG signing for CambiOS binaries, and userspace identity-vault key derivation for FPP-compatible credentials. Under this synthesis, those two uses share a single hardware secret with two derivation paths:

- `m/0'/...` for ELF / ARCSIG signing keys (kernel boot path)
- `m/1'/...` for Persona DID signing keys (vault, per OpenVTC convention)
- `m/2'/...` for WebVH log-entry update keys (vault DID-management)
- `m/3'/.../...` for Relationship DID keys (vault, per-relationship)

One YubiKey ceremony, two outputs. The user's "this is me" gesture authorizes both "this is my code" and "this is my identity assertion." UX simplification with no security cost: derivation paths are domain-separated, leaks in one branch do not compromise the other.

## ADR Slots This Document Opens

Three follow-on ADRs cite this synthesis as design context. Drafting order, dependency-respecting:

1. **AI Agents as First-Class Principals.** Cites this doc plus white paper Part 8. Specifies how an AI service is bound to a Principal, how its cap inventory is sourced from the user's vault, how `SYS_REVOKE_CAPABILITY` mediates containment, what hardware attestation the binary must carry, and how the seven FPP tests become operational deliverables. Defers vault implementation specifics to ADR (2).

2. **Multi-Principal Vault.** Cites this doc plus ADR-025 plus the AI-as-Principal ADR. Specifies internal vault state, the P-DID / M-DID / R-DID / C-DID taxonomy as CambiOS storage shape, BIP-32 derivation with YubiKey root, key rotation discipline (within-DID rotation vs new-DID-per-context vs persona migration), the translation-layer interface, and the v1 set of external DID methods spoken.

3. **Translation-Layer Compatibility.** Cites this doc plus the vault ADR. Specifies the adapter-module interface for adding new external languages, the trust-task-protocol catalog CambiOS supports at v1, the TSP-over-IPC bridge mechanism, the TRQP userspace service, and the inbound and outbound cap-promotion validation rules.

Each ADR is small, focused, and decideable in isolation. Each one adds a layer the prior ones did not have to commit to.

## Open Questions Carried Forward

These resolve in the follow-on ADRs:

- **AID width.** CambiOS Principal is 32 bytes per ADR-025; FPP examples use 16-byte SCIDs. Vault canonical-encoding decision in ADR (2). Most likely path: vault stores 32 bytes always; narrower-source AIDs are zero-padded or hash-extended on intake; canonical 32-byte form is what the kernel sees.
- **Adopt vs fork vs interop with `openvtc-core`.** Instinct is fork-ish: take BIP-32 derivation, VRC types, Ed25519 signing primitives. Swap storage from OS-keyring to keystore-service, swap transport from DIDComm-mediator to CambiOS IPC for local pairs and DIDComm-over-network for remote. Decision in ADR (2) or ADR (3).
- **Key rotation discipline.** Kernel does not care; vault must spec which of (within-DID rotation / new-DID-per-context / persona migration) it implements at v1, with revisit-when triggers for the others. Anti-profiling lever lives at "new-DID-per-context"; forward-secrecy lever lives at "within-DID rotation"; clean-break lever lives at "persona migration." Decision in ADR (2).
- **Persona-migration trust task.** If CambiOS implements it as a userspace contribution back to the ToIP trust-task-protocol catalog, that is a productive upstream contribution. Decision deferred until a second user-flow demands it.
- **VTA-the-server-side-agent vs CambiOS service patterns.** In CambiOS, "VTA" is just a userspace service; no new architecture needed. Naming convention deferred to ADR (3) so the wire-format spec uses one canonical term throughout.

## Cross-References

- [identity.md](identity.md): source-of-truth identity architecture; this synthesis extends it with the FPP-compatibility framing.
- [ADR-025](adr/025-principal-as-aid.md): Principal as 32-byte AID; the kernel-side identity primitive.
- [ADR-026](adr/026-identity-transcription-at-the-kernel-ring.md): kernel transcribes, does not interpret; cap-shape duality this document generalizes.
- [ADR-027](adr/027-service-clusters.md): service clusters as the trust-topology unit.
- [ADR-007](adr/007-capability-revocation-and-telemetry.md): audit ring and capability revocation; the substrate for AI-agent containment.
- [ADR-004](adr/004-cryptographic-integrity.md): ELF signing (ARCSIG) that the YubiKey attestation builds on.
- First Person Project White Paper v1.2 (external; 2026-01-23): https://firstperson.network/white-paper
- OpenVTC reference implementation (external; Apache-2.0): https://github.com/OpenVTC/openvtc
