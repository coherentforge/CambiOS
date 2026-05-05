# ADR-026: Identity Transcription at the Kernel Ring

- **Status:** Accepted
- **Date:** 2026-05-02
- **Depends on:** [ADR-025](025-principal-as-aid.md) (Principal as 32-byte AID — the identity primitive this builds on), [ADR-000](000-zta-and-cap.md) (ZTA + capability foundations), [ADR-002](002-three-layer-enforcement-pipeline.md) (Three-Layer Enforcement Pipeline — the existing hot-path cap check), [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC Primitives — precedent for the same shape duality at the IPC layer)
- **Related:** [identity.md](../identity.md) (rewritten 2026-05-02 to land the multi-Principal vault and the framing this ADR codifies), [ADR-007](007-capability-revocation-and-telemetry.md) (Capability Revocation — receives an amendment for non-revocation accumulators that this ADR motivates), [ADR-010](010-persistent-object-store-on-disk-format.md) (cold-path cap form, on-disk), [ADR-015](015-storage-tiers-and-commitment-ladder.md) (same duality at the storage layer), [ADR-016](016-win-compat-api-ai-boundary.md) (strongest existing precedent for AI-doesn't-write-policy)
- **Supersedes:** N/A
- **Context:** Codifying the kernel-side architectural posture for identity, caps, and AI containment that has been implicit in the codebase and converging across multiple design conversations

## Problem

Three load-bearing claims have accumulated about how identity, capabilities, and AI integration *should* fit together inside the CambiOS kernel. None of them is contradicted by any existing ADR. None of them is *ratified* by any existing ADR either. They have lived in design conversation, in memory, and in the ongoing rewrite of [identity.md](../identity.md), but not in a citable architectural decision record.

The three claims:

**Claim 1 — The kernel transcribes identity in the hot path; it does not interpret.** Existing kernel code already follows this rule by accident in the load-bearing places (capability checks key on `ProcessId`, not on `sender_principal`; IPC stamping copies bytes; audit emission carries Principal as data). It violates the rule in the vestigial places ([BOOTSTRAP_PRINCIPAL](../../src/lib.rs) equality checks before [ADR-023](023-audit-consumer-capability.md)'s migration). The rule is the verification target the kernel is implicitly being designed for; future contributors need to know it explicitly.

**Claim 2 — Capabilities have two forms.** The kernel's cap is a `(endpoint, rights)` table entry — small, identity-poor, fast. Persistent caps (object permissions on disk per [ADR-010](010-persistent-object-store-on-disk-format.md), boot-manifest grants per [ADR-018](018-init-process-and-boot-manifest.md), future cross-Principal grants) are identity-rich envelopes carrying author, scope, lineage, expiry. The kernel never holds the rich form during ordinary operation; it consumes the rich form once at promotion (grant, restore, attach) and emits the rich form at delegation. Inside the ring, only handles. This duality is in the codebase already — `Capability {endpoint, rights}` in `src/ipc/capability.rs:103` is the internal form; the on-disk `caps[8]` array in [ADR-010](010-persistent-object-store-on-disk-format.md)'s record header is the external form. The duality is real; it is unstated.

**Claim 3 — AI watches, flags, and sandboxes — but does not write policy.** [PHILOSOPHY.md](../PHILOSOPHY.md) says "AI watches, doesn't decide." [ADR-007](007-capability-revocation-and-telemetry.md) makes this concrete (audit channel + recommendation IPC to policy service; only policy service calls `SYS_REVOKE_CAPABILITY`). [ADR-016](016-win-compat-api-ai-boundary.md) cites the verification posture explicitly when removing the AI translation layer. But the more nuanced statement — *AI doesn't write policy, AI does take containment action* — has only lived in design memory. The "purely passive AI" reading drifts toward "AI is observation only, no architectural seat for response," which is not what the architecture wants. The refinement matters because future AI integrations will keep asking the question.

These three claims are co-dependent. Identity transcription is what makes the cap-shape duality work (the kernel can hold opaque AIDs because it never reasons about them; rich forms live where reasoning is permitted). The cap-shape duality is what makes "AI watches and sandboxes" mechanically possible (containment is narrowing the holder's internal cap set; audit consumption is reading the cold-path event ring). The AI containment scope is per-Principal, which is what makes multi-Principal vault work (containment of `social_Principal` doesn't disturb `banking_Principal`).

Stating them together is the ADR's job. Stating them separately would let the dependencies drift.

## The Reframe

> **Identity richness is a boundary phenomenon, not a kernel phenomenon. The kernel's job is mechanical: transcribe values it holds, enforce membership against tables it owns, produce audit events for observers it cannot reach. Identity-rich operations — signature verification, accumulator-membership proof, ZK cap verification, attestation — happen at boundaries the kernel mediates *to*, not inside the kernel ring itself. Cost is concentrated where cost is already paid.**

This reframe doesn't invent new mechanism. It names the line that separates work the kernel does from work it merely facilitates. The line has been implicit across ADRs 000, 002, 005, 007, 010, 015, 016, 023, and 025 — each of those has a piece of it. This ADR makes the line explicit and citable.

## Decision

Three architectural commitments. They are codified together because they are mutually reinforcing; codifying any one alone would let the others drift.

### 1. Identity transcription invariant

The kernel transcribes identity values; it does not interpret them in the hot path.

**What "transcribe" means.** Read a Principal AID from `ProcessCapabilities.principal`, copy it onto an outgoing IPC `sender_principal` field, stamp it onto an authored CambiObject's `creator` / `owner` fields, write it into an audit event. The kernel treats AIDs as opaque 32-byte tags ([ADR-025](025-principal-as-aid.md)). It does not branch on the *value* of an AID to make a policy decision.

**What "interpret" means.** Branch on a Principal value to make a policy decision: "if `caller.principal() == BOOTSTRAP_PRINCIPAL`, allow X." The bootstrap-Principal vestiges in the current codebase are interpretation. [ADR-023](023-audit-consumer-capability.md) is in the process of moving these to capability checks (mechanical) rather than identity equality (interpretation). The migration trend is this ADR's invariant in practice.

**The hot-path rule:** *Any kernel hot-path code that branches on a Principal value violates this invariant and is a bug.*

**The boundary carve-outs:** The kernel *does* interpret Principal values at three classes of operation, and these are explicitly permitted because they are at boundaries where interpretation is structurally appropriate:

- **Cap promotion** (grant, delegate, restore, attach). When an external rich-form cap arrives at the kernel boundary — a manifest entry at boot per [ADR-018](018-init-process-and-boot-manifest.md), an object cap restored from disk per [ADR-010](010-persistent-object-store-on-disk-format.md), a delegation across processes — the kernel verifies the cap's signature against the issuing Principal. This is interpretation; it happens once at the boundary, not on every use.
- **Signature verification** at content-author boundaries. `ObjPutSigned` verifies a caller-supplied signature against the caller's bound Principal. Signed-ELF verification verifies the binary's ARCSIG signature against the bootstrap Principal. Both are at ingress boundaries; both are slow (μs scale) but pay for themselves once, not per-use.
- **Bootstrap-Principal vestiges**, being migrated to capability checks per [ADR-023](023-audit-consumer-capability.md). The migration is the on-going expression of this invariant.

**The set-membership carve-out:** Mechanical set-membership tests at user-defined ingress boundaries are *not* interpretation. A block list, expressed as a per-Principal hash set or bloom filter, checked O(1) on every IPC receive (per [identity.md § Local Blocking](../identity.md#local-blocking-immediate-kernel-enforced-set-membership)), decides ∈/∉ — it does not branch on the Principal's *value* to make a policy decision *about that value*. The user defines the set; the kernel enforces membership. This distinction is load-bearing for the block-list mechanism to remain compatible with the invariant.

### 2. Capability shape duality

Capabilities have two forms in CambiOS, and the boundary between them is architecturally significant.

**Internal cap (kernel ring, hot path):**

```rust
pub struct Capability {
    pub endpoint: EndpointId,
    pub rights: CapabilityRights,
}
```

Stored in `[Option<Capability>; 32]` per process, in `ProcessCapabilities`. Cap checks (`verify_access` at [src/ipc/capability.rs:231](../../src/ipc/capability.rs#L231)) are linear scan + bitfield comparison; nanoseconds. No identity is embedded in the cap; the process's bound Principal is a separate field. The kernel never branches on a Principal value during the cap check.

**External cap (boundary, cold path):**

The wire/disk shape that a cap takes when crossing a trust domain — stored alongside an object on disk, included in a boot manifest, passed across processes via delegation, handed to another device. Carries the rich identity context: sub-Principal of the issuer, scope (what this cap permits), lineage (who derived it from whom, in what chain), and (future) a non-revocation witness against an issuer-maintained accumulator. Verification is cryptographic — signature check, scope check, witness-against-accumulator membership — and runs in the microseconds-to-milliseconds range. Acceptable because it runs at boundary operations only.

**The kernel never holds the rich form during ordinary use.** It receives a rich-form cap once at *promotion* (the boundary operation that installs an internal handle), verifies it expensively, and from that point operates on the internal handle until the cap is revoked or expires. Inversely, when the kernel emits a cap outward (delegation across processes, persistence to disk), it produces a rich-form envelope from the internal handle plus the issuing Principal's signing context.

**Existing precedent for the same shape duality:**

| Layer | Hot-path / internal form | Cold-path / external form |
|---|---|---|
| **IPC** ([ADR-005](005-ipc-primitives-control-and-bulk.md)) | 256-byte control message, kernel-mediated, cap-checked per send | Channel: kernel touches at create/attach/close only; MMU enforces between |
| **Storage** ([ADR-015](015-storage-tiers-and-commitment-ladder.md)) | Temp (in-memory, process-bound) | Private + Public CambiObjects: signed, encrypted, identity-rich |
| **Caps** (this ADR) | `(endpoint, rights)` table entry | Sub-Principal + scope + lineage + (future) witness |
| **Time** ([ADR-022](022-wall-clock-time.md)) | Lock-free atomics, opaque to consumers | `source_tag` reserved field for future signed/peer-attested time |

The pattern is the same across these layers: the hot path operates on collapsed handles for speed; the cold path carries identity richness for verifiability across boundaries. This ADR codifies the cap layer's instance of the pattern.

### 3. AI watches, flags, sandboxes — but does not write policy

The AI security service is an observer with structural authority to *initiate containment*, not to *adjudicate*. The line is between **policy authorship** (which the AI does not perform) and **mechanical containment under uncertainty** (which the AI initiates and the policy service mediates).

**What the AI does NOT do:**
- Decide what is allowed or banned. That is policy, encoded in capability shape and Principal grants.
- Directly invoke kernel intervention primitives (`SYS_REVOKE_CAPABILITY`, etc.). The AI holds no cap that lets it do so.
- Generate code, plans, or interpretations that run on the security path. [ADR-016](016-win-compat-api-ai-boundary.md) explicitly removed AI-generated translation plans from the win-compat layer for this reason — AI-generated semantics on the verification target is not allowed.

**What the AI does:**
- Reads the audit telemetry channel (per [ADR-007](007-capability-revocation-and-telemetry.md)).
- Detects behavioral anomalies against per-Principal baselines.
- Sends recommendations to the policy service: "Recommend narrowing capability set on `Principal_X` because observed pattern Y deviates from baseline Z."
- Produces no other side effects.

**What the policy service does (the gatekeeper):**
- Receives AI recommendations as ordinary IPC messages.
- Evaluates them against its own configurable rules (which may or may not act on AI input).
- If the rules authorize action, calls `SYS_REVOKE_CAPABILITY` or other kernel intervention primitives.

**What the kernel does (mechanical):**
- Performs the revocation atomically per [ADR-007](007-capability-revocation-and-telemetry.md).
- Emits a `CAPABILITY_REVOKED` audit event so observers (including the AI itself) see the action.
- Does not consult the AI; does not consult any LLM; does not branch on any AI-derived signal.

**Containment is per-Principal, not per-human.** The AI flags `Principal_X`; the policy service narrows `Principal_X`'s caps; the human's other Principals (held in their vault per the multi-Principal model in [identity.md § The Vault](../identity.md#the-vault)) are untouched. A compromised `social_Principal` does not take down `banking_Principal`. This composition with multi-Principal-by-default is what makes "AI watches and contains" a usable architecture rather than a brittle one — narrowing one identity does not disrupt the human's broader work.

**Precedent (already shipping):** [ADR-007 § How These Two Primitives Combine](007-capability-revocation-and-telemetry.md#how-these-two-primitives-combine) describes exactly this loop: anomaly → audit event → policy-service evaluation → revocation → confirmation event. The refinement this ADR makes is only at the *interpretation* of "AI watches without controlling" — adding the explicit distinction between policy authorship (forbidden) and containment initiation (permitted, mediated, mechanical).

## Architecture

### What this changes in code

**Nothing immediately.** This ADR codifies posture, not mechanism. Every claim it states is either already true in the codebase (transcription invariant: kernel hot path does not branch on Principal; cap-shape: internal `(endpoint, rights)` already exists) or is the target of separate ongoing work (ADR-023's bootstrap-Principal migration; ADR-007's forthcoming amendment for non-revocation accumulators). What this ADR adds is the load-bearing context that future contributors can cite.

The static-analysis lint that would *enforce* the transcription invariant — flag any kernel hot-path code that compares a `Principal` value — is a future ASSUMPTIONS.md / Convention 9 candidate. Today the discipline is code review. Defer the lint until a violation lands or a near-violation is caught in review.

### Where the transcription invariant currently holds (illustrative, non-exhaustive)

- `CapabilityManager::verify_access` ([src/ipc/capability.rs:231](../../src/ipc/capability.rs#L231)) — keys on `ProcessId`, never reads `Principal`. ✓
- `IpcManager::send_message_with_capability` — stamps `sender_principal` (transcription), then enforces via cap check (no Principal branching). ✓
- `DefaultInterceptor::on_send` ([src/ipc/interceptor.rs](../../src/ipc/interceptor.rs)) — runtime policy on payload + bounds + self-send; does not consult Principal value. ✓
- `audit::emit` — stamps Principal into event records (transcription); does not branch on Principal value. ✓

### Where the transcription invariant is currently *violated*, with active migration

- `BOOTSTRAP_PRINCIPAL` equality checks in syscall handlers (see `handle_bind_principal`, the pre-ADR-023 form of `handle_audit_attach`, etc.). Each such check is interpretation. [ADR-023](023-audit-consumer-capability.md) replaces the audit-attach version with `CapabilityKind::AuditConsumer`. Similar migrations are anticipated for the remaining bootstrap-only checks; each replacement closes a transcription-invariant violation in the same motion.
- `BindPrincipal`'s "no rebind without unbind" enforcement reads the bound Principal to enforce stability. This is interpretation, but it is at the bind-syscall boundary — a one-shot operation per process, not a hot path. Permitted under the carve-out for boundary operations.

### How this composes with existing ADRs

| ADR | What it gives this framing | What this framing gives it |
|---|---|---|
| [ADR-000](000-zta-and-cap.md) | The capability primitive itself; "no ambient authority" | Names which checks are mechanical (capability membership) vs interpretive (signature verification) |
| [ADR-002](002-three-layer-enforcement-pipeline.md) | Three-layer pipeline operates on `ProcessId` keyed caps in the hot path | Confirms the layers are transcription-compatible by design |
| [ADR-005](005-ipc-primitives-control-and-bulk.md) | Control vs bulk — same shape duality at IPC layer | Names the shape duality once, generalized across layers |
| [ADR-007](007-capability-revocation-and-telemetry.md) | Audit + revocation primitives; AI loop already specified | Receives a Divergence amendment for non-revocation accumulators (separate work; this ADR is the framing it cites) |
| [ADR-010](010-persistent-object-store-on-disk-format.md) | On-disk `caps[8]` array — the cold-path cap form | Names that array as the canonical external cap form; future witness reservation is its concern |
| [ADR-015](015-storage-tiers-and-commitment-ladder.md) | Storage tiers Temp/Private/Public — same shape duality at storage layer | Confirms duality is structural, not coincidental |
| [ADR-016](016-win-compat-api-ai-boundary.md) | Removed AI translation; cited verification posture explicitly | Receives the refined "AI watches, flags, sandboxes" formulation as a citable principle |
| [ADR-018](018-init-process-and-boot-manifest.md) | Manifest binds Principal → endpoint reservations + initial caps (external rich form) | Confirms manifest is the canonical boot-time external cap envelope |
| [ADR-023](023-audit-consumer-capability.md) | Migrates one bootstrap-Principal check to capability check | Confirms the migration trend matches the transcription invariant |
| [ADR-025](025-principal-as-aid.md) | AID as 32-byte opaque identifier decoupled from key bytes | Confirms why AID is the right primitive for transcription — it's identity, not key material |

## Threat Model Impact

This ADR codifies posture; it does not introduce new mechanism. Threat-model impact is therefore narrow.

| Threat | Mitigation before this ADR | Mitigation after this ADR |
|---|---|---|
| Future contributor adds a kernel hot-path check that branches on a Principal value | Caught (or missed) by code review | Caught by code review citing the transcription invariant; future static lint is a defined project |
| Future ADR introduces a kernel-side AI inference path | "We don't do that" — implicit | "AI doesn't write policy" — citable principle, with [ADR-016](016-win-compat-api-ai-boundary.md) as the live precedent |
| Future cap design tries to merge internal and external forms | Implicit drift | Cap-shape duality is a stated property; merging is a divergence event |
| Compromised AI service produces malicious recommendations | Same as today: policy service is the gatekeeper | Same. AI's blast radius is bounded by the policy service mediating every recommendation. |

The TCB does not grow. The attack surface does not change. The cost is one ADR's worth of doc-sync; the benefit is that future design conversations have a citable architectural decision to align against.

## Verification Stance

The transcription invariant is a verification-friendly property:

- **Kernel hot-path code never branches on `Principal` value.** Decidable by static analysis: trace every `Principal` field load in kernel code, classify each branch decision, verify the predicate is not "compare to constant or compare to variable Principal." Today done by code review; viable as a Kani harness or a custom Rust lint when the proof infrastructure expands.
- **Cap shape duality** decomposes the cap-machinery proof obligation into two smaller theorems:
  1. *Boundary translation soundness:* an external cap presented at a promotion boundary, with valid signature and scope, produces an internal handle that captures the cap's authority. Conversely, an internal grant emitted as an external cap carries enough information for any verifier in the future to validate the grant.
  2. *Internal cap machinery soundness:* table operations (grant, revoke, verify, delegate-with-no-escalation) preserve the existing capability invariants. [ADR-000 § Divergence (2026-04-21)](000-zta-and-cap.md#divergence) already documents Kani harnesses for the second theorem class. The first is a forward-looking target.
- **AI containment scope.** The "AI does not call kernel intervention primitives directly" property is verifiable by capability inventory: the AI service's `ProcessCapabilities` table at boot contains exactly two entries — read on the audit channel and send on the policy-service endpoint. No `revoke` right, no `delegate` right on any kernel-administrative endpoint. Verifiable from boot manifest inspection; the upcoming [ADR-018](018-init-process-and-boot-manifest.md) manifest is the canonical declaration site.

## Why Not Other Options

### Option A: Don't write this ADR; keep the framing in identity.md only

**Why considered.** identity.md was rewritten 2026-05-02 to land all three claims. A reader who finds identity.md finds the framing. No additional document needed.

**Why rejected.** The framing is broader than identity. Cap-shape duality applies to every cap, not just identity-bearing ones. The transcription invariant applies to every kernel hot path that touches identity, not just identity-architecture work. The AI-doesn't-write-policy refinement applies to every AI integration, not just identity-related ones. Burying these inside an identity-architecture document hides them from future kernel-architecture work. ADRs are the index where architectural decisions live; the framing belongs there.

### Option B: Combine with a multi-Principal vault ADR

**Why considered.** The vault is the userspace half of the same architectural picture. Single ADR covering "kernel transcribes; vault holds plurality; cap shape duality reflects the boundary; AI sandboxes per-Principal" is conceptually unified.

**Why rejected (for now).** The vault is a userspace service spec — APIs, sync substrate, biometric integration, recovery protocol. It deserves its own ADR with its own threat model, its own deferred questions, and its own verification posture. This ADR is the *kernel-architecture statement* that the vault ADR will cite. The multi-Principal vault may land as its own ADR, or as the keystore-service ADR deferred by [ADR-025](025-principal-as-aid.md#deferred). Either way, the kernel-side framing is settled here, separately, first.

### Option C: Per-claim ADRs

**Why considered.** Three claims, three ADRs. Each ADR is small, focused, easy to review.

**Why rejected.** The three claims are co-dependent (see Problem section). Splitting them lets future ADRs cite one in isolation, which would let the dependencies drift. The transcription invariant *justifies* the cap-shape duality; the cap-shape duality *enables* per-Principal AI containment; per-Principal AI containment *requires* the multi-Principal vault to be useful. They are one architectural picture; one ADR.

### Option D: Express as a Divergence on ADR-025

**Why considered.** [ADR-025](025-principal-as-aid.md) is the closest existing ADR to this framing — it makes the AID primitive opaque and decoupled-from-keys, which is what enables transcription.

**Why rejected.** A Divergence appendix preserves the original ADR's decision and adds new reasoning that flows from implementation experience. This ADR is not changing ADR-025's decision; it is *building on it*. The right pattern is a new ADR that depends on ADR-025, not a Divergence that conflates the two.

## Migration Path

This ADR codifies posture, so the migration is documentation and discipline, not code:

1. **Land this ADR.** Update `make check-adrs` regenerated INDEX.md.
2. **CLAUDE.md Required Reading.** Add a row mapping "Kernel-side identity architecture / AI containment scope" → this ADR (the row is doc-only; existing identity-related rows continue pointing at identity.md + ADR-025).
3. **Future bootstrap-Principal migrations.** Each replacement of a `BOOTSTRAP_PRINCIPAL` equality check with a capability check (continuing the [ADR-023](023-audit-consumer-capability.md) pattern) cites this ADR's transcription invariant in its commit body.
4. **Future cap-design ADRs.** When the witness-bearing cap envelope format lands (anticipated in the [ADR-007](007-capability-revocation-and-telemetry.md) amendment for non-revocation accumulators), it cites this ADR's cap-shape duality as the home for the external form.
5. **Future AI integrations.** Any new ADR proposing kernel-AI integration cites this ADR's "AI does not write policy" formulation; the proposal must demonstrate that the AI's capability inventory is read-only on observation channels and send-only on recommendation channels.
6. **Static lint for transcription invariant.** Deferred. **Revisit when:** a kernel-side hot-path Principal-value branch is proposed in a code review and rejected, or a near-violation is shipped and caught later. Either is the trigger to invest in the lint mechanism.

## Cross-References

- **[identity.md](../identity.md)** — Source-of-truth identity architecture document; rewritten 2026-05-02 to land the multi-Principal vault and the framing this ADR codifies. The "Architectural Invariants" section in identity.md (entries 7, 8, 9) is the per-component statement of this ADR's decisions.
- **[ADR-025](025-principal-as-aid.md)** — Principal as 32-byte AID; the identity primitive that makes transcription a coherent operation.
- **[ADR-000](000-zta-and-cap.md)** — Capability foundations; the internal cap form lives here.
- **[ADR-002](002-three-layer-enforcement-pipeline.md)** — Three-layer enforcement pipeline; the hot-path cap check that is transcription-compatible by design.
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** — IPC primitives; precedent for the same shape duality at the IPC layer.
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Capability revocation + audit telemetry; the AI loop is specified here, the non-revocation amendment will live here.
- **[ADR-010](010-persistent-object-store-on-disk-format.md)** — Cold-path cap form on-disk; the external cap envelope's storage layout.
- **[ADR-015](015-storage-tiers-and-commitment-ladder.md)** — Storage tiers; same shape duality at the storage layer.
- **[ADR-016](016-win-compat-api-ai-boundary.md)** — Strongest existing precedent for "AI doesn't write policy"; cites verification posture explicitly when removing AI-generated translation plans.
- **[ADR-018](018-init-process-and-boot-manifest.md)** — Init process and boot manifest; canonical boot-time external cap envelope.
- **[ADR-023](023-audit-consumer-capability.md)** — Audit consumer capability; first migration of a bootstrap-Principal check to a capability check, in the spirit of this ADR's transcription invariant.
- **[PHILOSOPHY.md](../PHILOSOPHY.md)** — "AI watches, doesn't decide" is the unrefined statement this ADR refines.

## See Also in CLAUDE.md

When this ADR lands, the following CLAUDE.md sections should reference it:

- **§ "Required Reading by Subsystem"** — add a new row for "Kernel-side identity architecture / cap-shape duality / AI containment scope" pointing to this ADR. Existing identity row continues pointing at identity.md + ADR-025; this is a separate row for kernel-architecture work.
- **§ "Stop-and-Ask Gate"** — the "Identity-gate bypass" bullet may be extended with a reference to this ADR's transcription invariant when the lint discussion lands.

## Open Questions / Deferred

> **Deferred decision.** Whether to combine the kernel-side framing (this ADR) with a multi-Principal vault ADR. **Revisit when:** the multi-Principal vault implementation begins (Phase 1C), or when [ADR-025](025-principal-as-aid.md)'s deferred keystore-service ADR is being scoped. Either is the trigger to decide whether one combined ADR or two separate ADRs serves the architecture better.

> **Deferred decision.** Static lint for the transcription invariant — a custom Rust lint or Kani harness that flags kernel hot-path code branching on `Principal` values. **Revisit when:** a near-violation is caught in code review, or the formal-verification effort expands to cover the cap subsystem more broadly.

> **Deferred decision.** Witness-bearing cap envelope format. The external cap form sketched here — sub-Principal + scope + lineage + non-revocation witness — does not yet have a concrete wire/disk format. **Revisit when:** the [ADR-007](007-capability-revocation-and-telemetry.md) amendment for non-revocation accumulators is being designed. The format lives there, not here; this ADR only names the slot.
