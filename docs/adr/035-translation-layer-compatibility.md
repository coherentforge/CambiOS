# ADR-035: Translation-Layer Compatibility — Interop with ToIP / FPP / KERI via the Vault

- **Status:** Proposed
- **Date:** 2026-06-04
- **Depends on:** [ADR-025](025-principal-as-aid.md) (Principal as 32-byte AID — the identifier CambiOS presents at the boundary), [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (transcribe-not-interpret — what keeps the polyglot boundary in userspace, out of the ring), [ADR-033](033-multi-principal-vault.md) (the vault that hosts the translation layer)
- **Related:** [ADR-027](027-service-clusters.md) (service clusters ≈ Verifiable Trust Communities at the FPP boundary), [ADR-007](007-capability-revocation-and-telemetry.md) (audit ring + revocation; non-revocation accumulators back cold-path credential revocation), [ADR-004](004-cryptographic-integrity.md) (ELF/ARCSIG signing the "Certified AI" attestation builds on), [identity-synthesis.md](../identity-synthesis.md) (the design context that opens this ADR slot)
- **Supersedes:** N/A
- **Context:** `identity-synthesis.md` frames CambiOS as participating in decentralized-identity ecosystems — KERI key-event chains, the ToIP trust-spanning stack, the First Person Network — *without being defined by any of them*. It establishes the principle (*mechanical kernel, multilingual vault, topological clusters*) but defers the interface to a follow-on ADR. This is that ADR: it specifies **where external-trust-ecosystem translation lives and what its contract with the kernel ring is.**

## Problem

The decentralized-trust world is three layers from three lineages: **KERI** (identifier / node — self-certifying AIDs with rotation continuity), the **ToIP Trust Spanning Protocol** (spanning / transport — VID-addressed authentic messaging), and the **First Person Project** (credential / graph — personhood credentials, relationship credentials, the emergent trust graph). CambiOS wants to interoperate with all three using **its own identifier**, not by adopting KERI's stack or any single DID method.

This is feasible because TSP is **VID-agnostic by construction**: a VID is "an identifier over which the controller can provide cryptographic proof of control," and DIDs are *a* W3C standard for VIDs — one type, not the only one. A CambiOS-native 32-byte AID that proves key control is an admissible VID. So the interop contract is the **VID boundary**, not adoption.

The open architectural question: a polyglot boundary that speaks did:webvh, did:peer, raw KERI AIDs, W3C VCs, and FPP VRC/PHC envelopes is, by nature, full of external-format knowledge. Where does it live without contaminating the kernel ring, whose verification posture (ADR-000/002/026) depends on the kernel *not* interpreting identity?

## Decision

1. **The vault is the sole translation layer.** All external-format knowledge lives in the userspace multi-Principal vault (ADR-033). The kernel ring stays mechanical: Principals are opaque 32-byte AIDs it transcribes; capabilities are `(endpoint, rights)` handles. ADR-026's transcribe-not-interpret invariant is untouched — no DID/VRC/TSP knowledge enters the ring.

2. **Adapter-module interface.** External "languages" plug in as vault adapter modules behind a common encode/decode/verify interface. The v1 set: did:webvh (FPN counterparties), did:peer (pairwise relationship DIDs), raw KERI AID (KERI-suite peers), W3C VC (generic verifiers), VRC/PHC (FPP). New methods are new adapters; kernel and core vault state do not change.

3. **CambiOS brings its own AID as a VID.** No KERI/DID-method adoption at the identifier layer. The vault *presents* the Principal in whatever VID/DID envelope a counterparty needs on egress and unwraps on ingress. KERI is influence at the AID-design level only (ADR-025: stable identifier decoupled from rotating keys), never a runtime dependency — CESR, ACDC, and the KERI witness network are explicitly not adopted.

4. **TSP-over-IPC bridge.** A userspace bridge process terminates TSP at the network edge and speaks CambiOS IPC inward; the kernel sees only IPC bytes. TSP's authenticity / confidentiality / metadata-privacy guarantees are a userspace concern.

5. **TRQP service.** Trust-registry queries (ToIP TRQP V2.0) are a pure-userspace service; no kernel involvement.

6. **Inbound = cap promotion.** An external rich-form credential arrives; the vault verifies the issuer signature against the published DID document, checks scope + validity window + revocation, then derives an internal `(endpoint, rights)` handle for the relying party. Kernel sees only the handle — the same cap-shape duality as ADR-026 / fs-service.

7. **Outbound = cap delegation.** The vault wraps an internal handle in the counterparty's envelope (VRC for an FPP peer, raw KERI for a KERI peer, plain W3C VC for a generic verifier), signs with the appropriate Persona key (YubiKey-attested where required), and ships it. The kernel never sees the envelope.

8. **Relationship-strength is CambiOS-defined.** FPP's graph is purely topological (count/threshold proofs; it specifies no scoring). The continuous relationship-strength edge weight is computed in userspace from signed interaction history — local, subjective, per-Principal (not a global social-credit score), and never adjudicated by the kernel.

## Consequences

**Positive**
- The verification-friendly kernel stays untouched (ADR-000/002/026 do not move); translation-layer bugs are userspace and bounded.
- Multi-method / multi-ecosystem support is architecturally free via adapter modules; no roadmap lock-in to FPP/ToIP/KERI as organizations. If a counterparty network changes its format, the adapter changes; the kernel does not.
- Native FPN participation (hold PHCs, exchange VRCs, present clusters as VTCs) is backed by CambiOS Principal infrastructure with no organizational adoption ceremony.
- AI-agent identity falls out: a Principal-bound, ELF-signed (ADR-004), policy-bounded, YubiKey-attested agent is a *cryptographically checkable* "First Person Certified AI," structurally stronger than a paperwork certification.

**Costs / risks**
- The vault becomes the polyglot boundary — its complexity grows; mitigated by the adapter-module seam.
- Trust concentrates in the vault (it holds Persona keys and speaks every dialect); mitigated by YubiKey-rooting and userspace isolation.

## Alternatives Rejected

- **Adopt KERI / CESR / ACDC wholesale** — couples CambiOS to one ecosystem's wire format and governance; violates "translation, not adoption."
- **Kernel-level DID / credential handling** — breaks the transcribe-not-interpret invariant and the verification posture.
- **No interop (CambiOS-only identifiers)** — forfeits the network effect of the emerging trust layer.

## Open Questions / Deferrals

Pin concrete bindings against external specs, not the FPP white paper (which is a vision/architecture doc, not a protocol spec):

- **VRC envelope choice** — FPP leaves the format open (not declared W3C VC, not ACDC). Decide CambiObject-native vs W3C-VC wrapper at the boundary. **Revisit when:** the first VRC round-trip with a real FPN counterparty is implemented.
- **PHC uniqueness / nullifier** — FPP specifies none; the per-context-nullifier ZK personhood mechanism is CambiOS's to design, tied to the biometric-vault phase. **Revisit when:** biometric commitment (identity.md Phase 2) begins.
- **TSP wire binding** — not in the FPP paper; pin against the ToIP TSP spec and the OWF Rust implementation. **Revisit when:** the TSP-over-IPC bridge is implemented.
- **Kernel-mediated bridge/registry channels** — the bridge and TRQP services are userspace and add no new kernel lock; ADR-034's deferred-reclamation lock is unrelated. Should a future revision require a kernel-mediated channel for the bridge, it slots into the lock hierarchy as it stands post-ADR-034. **Revisit when:** a bridge channel needs kernel mediation rather than plain IPC.
