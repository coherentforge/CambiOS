# ADR-017: User-Directed Cloud Inference

- **Status:** Proposed
- **Date:** 2026-04-21
- **Slot history:** This slot previously held a Phase 1 Win32 catalog companion to [ADR-016](016-win-compat-api-ai-boundary.md). When ADR-016 was rewritten (2026-04-21) to fold the catalog into its own body, the ADR-017 slot was reclaimed rather than left vacant. The prior catalog content is in git history.
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-007](007-capability-revocation-and-telemetry.md) (Audit Telemetry)
- **Related:** [PHILOSOPHY.md](../PHILOSOPHY.md)
- **Supersedes:** N/A

## Context

CambiOS's founding principle is **generative, not extractive**. The system exists to give the user capability, not to extract data, attention, or agency from them. Zero telemetry is a consequence of that principle, not the principle itself.

On-device AI inference was always part of the design: local models assisting with security monitoring, UX, policy authoring, and (in earlier drafts) Windows compat translation. What the design did *not* settle was the status of **cloud-hosted inference** — larger models the user could call when the local tier could not answer.

For a time, the "zero telemetry" framing was doing double duty: it correctly foreclosed on system-initiated data exfiltration, but it also accidentally foreclosed on user-initiated cloud calls — which are not the same thing. A user asking a cloud model a question and receiving an answer is not telemetry; it is a remote compute request the user consciously chose to make. Conflating the two would either (a) cap the AI capabilities of CambiOS at whatever runs locally on a given machine, or (b) force the "zero telemetry" principle to be quietly violated when cloud inference is added later. Both are bad outcomes; both are avoided by distinguishing the two at the principle level now.

This ADR draws the line.

## Decision

**User-directed cloud inference is permitted and is not telemetry. It is governed by the principle that any data leaving the device must be user-initiated, user-visible, and user-revocable — and that the data leaving the device is the content of the user's query, not a side effect of their behavior.**

Three properties define the boundary:

1. **User-initiated.** The data flow originates from an action the user took — a query they typed, a file they asked to process, a task they delegated. The user's agency is the cause; the data flow is the effect. System-initiated data flows (background reports, passive telemetry, automatic feedback loops) remain forbidden by the generative-not-extractive principle.
2. **Data flow is the product.** The data being sent is the content of the user's request. The response is what the user asked for. There is no secondary data flow — no logs, no usage metrics, no "system information" attached to the call — beyond what is strictly required to deliver the response. The shape of the request is `(user_query, response)`, not `(user_query, response, <side channel>)`.
3. **User-visible and user-revocable.** The user can see every cloud call made on their behalf (via audit + a dashboard surface), the user can deny any class of cloud call by policy, and the user can disconnect cloud inference entirely at any time without losing any on-device functionality. The system must degrade gracefully — fewer capabilities, not broken ones — when cloud inference is unavailable.

These three properties together are what distinguish cloud inference from telemetry. Telemetry is system-initiated, opaque, and treats data as a byproduct of behavior. Cloud inference under this ADR is user-initiated, visible, and treats data as the content of a deliberate request.

## Default Behavior

**Local-only by default.** A fresh CambiOS install makes no cloud calls. All AI capabilities available to the user work offline — possibly with reduced quality or capability — before any cloud endpoint is configured.

**Opt-in escalation.** The user (or an administrator in managed-deployment contexts) configures one or more cloud inference endpoints, granting a capability per endpoint to the AI subsystem that will use it. Each cloud endpoint is:

- Named (user-chosen label)
- Bound to a CambiOS capability, granted like any other resource access
- Scoped — the endpoint can be granted for some tasks (e.g., code assistance) and not others (e.g., personal document processing)
- Revocable — revoking the capability immediately stops new calls; in-flight calls complete or time out

The AI subsystem chooses whether to attempt cloud escalation per-request based on the granted capability scope and its own local assessment of whether the local model can handle the request. Escalation is never silent — see [Audit](#audit).

## Automatic Local→Cloud Escalation

A sharper case: when the local model produces a low-confidence result, should the system automatically re-run the query against a granted cloud endpoint, or must each escalation be a distinct user action?

Both models respect the three-property boundary — the user granted the cloud capability, the user's query is the data, the escalation is visible in audit. They differ in how they interpret "user-initiated":

- **Strict interpretation.** Each cloud call requires a distinct user action ("ask the bigger model"). Simple model to reason about; preserves the user's moment-by-moment agency. Imposes friction on every escalation.
- **Delegated interpretation.** Granting the cloud capability is itself the user-initiating action; within the scope of that grant, automatic escalation is permitted. Lower friction; slightly further from the original user action each time.

Neither is obviously wrong. The strict interpretation is closer to the principle's spirit; the delegated interpretation matches how most users think about "I've connected a cloud model" (they don't re-confirm on each use).

**Deferred decision.** The call here depends on observed behavior under Phase 1 usage. The strict model is the safe initial default; if it proves painful in practice, the delegated model is available as an opt-in. Leaving this undecided in the design doc before there is a first target UX would be premature.

**Revisit when:** the first CambiOS build with configured cloud inference ships and the first week of user-reported friction data is available. Specifically: if more than ~20% of the user base turns off strict-mode confirmation within the first week, the delegated model is the right default; if users leave strict mode on, the current default is correct.

## What This Permits

- A user asking an on-device AI agent a question that the agent chooses to route to a configured cloud model, with that routing visible in the audit trail.
- A user explicitly invoking "use the big model for this" from any interface that surfaces AI assistance.
- An administrator in a managed-deployment context (enterprise CambiOS install) configuring cloud endpoints on behalf of users, subject to the users' individual revocation rights.
- Cloud-side computation that *produces* data the user asked for (generated text, translated code, analyzed document) — because the output *is* the user's request.

## What This Still Forbids

- Any system-initiated data transmission not originating from an explicit user action — this is unchanged.
- Any "usage analytics" attached to cloud calls — the payload is the user's query and only the user's query.
- Any "learning loop" where cloud-call contents are retained by CambiOS or its operators to improve the local system — retention is the cloud provider's concern, bound by whatever agreement the user chose to enter when they granted the endpoint.
- Any implicit fallback to cloud inference when no cloud capability has been granted — local-only means local-only.
- Any degradation of local capability that depends on cloud availability — the local tier must be complete unto itself.

## Audit

Every cloud call emits an audit event using [ADR-007](007-capability-revocation-and-telemetry.md)'s infrastructure. The event schema:

```
AuditEventKind::CloudInference {
    endpoint_id:    u32,   // which granted cloud endpoint
    requester:      u32,   // which sandbox / subsystem initiated
    escalation_kind: u8,   // 0=explicit user request, 1=automatic (delegated mode)
    bytes_sent:     u32,   // payload size
    bytes_received: u32,   // response size
    duration_ms:    u16,   // round-trip wall clock
}
```

Fits the 64-byte `RawAuditEvent` format. Unlike most audit events, cloud-inference events are **user-visible by default** — a user-space surface (future work) reads the audit ring and renders a "cloud calls made on my behalf" view. This is the mechanism by which the user-visible property of the boundary is operationalized: if the user cannot see it, it does not meet the standard.

No telemetry from CambiOS about these calls is ever emitted back to any party other than the user's own dashboard surface. The audit ring stays on-device.

## Tier / Hardware Implications

The removal of cloud inference from the "forbidden" column changes the hardware floor for AI-using CambiOS deployments. Under local-only inference, the tier of hardware capable of running CambiOS's AI features was gated by how much model fits on-device. Under user-directed cloud inference, the local tier need only be capable enough to handle what the user chose to run locally; anything beyond can escalate.

This relaxes the hardware requirements for the AI-using deployment tiers (see [ADR-009](009-purpose-tiers-scope.md)) from "can run a 70B-class model on-device" to "can run a small on-device model + has a network stack + user has configured a cloud endpoint." The larger addressable user base is a direct consequence.

The shape of the tier policy for AI features is a TUNING decision to be settled once local-model candidates and cloud-endpoint integrations are concrete. This ADR commits only to the principle; the tier-policy detail lands when it lands.

## Relationship to Other ADRs

- **[ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities).** Cloud endpoints are CambiOS capabilities. The capability model is the mechanism by which cloud access is granted, scoped, and revoked. A cloud endpoint with no capability held is an endpoint that cannot be called — same property as any other privileged resource.
- **[ADR-007](007-capability-revocation-and-telemetry.md) (Audit Telemetry).** The `CloudInference` event kind uses this ADR's infrastructure. The user-visible dashboard is a different consumer of the same audit ring.
- **[ADR-009](009-purpose-tiers-scope.md) (Deployment Tiers).** Hardware floor for AI-using tiers relaxes — see above.
- **[ADR-016](016-win-compat-api-ai-boundary.md) (Windows Compatibility).** Independent. The bounded-static-shim model of ADR-016 does not depend on cloud inference. The two ADRs share a history (both arose from the same conversation that separated "AI in the compat pipeline" from "AI as a user capability"), but they are independent decisions.

## Deferred Decisions

- **Automatic local→cloud escalation default.** See § [Automatic Local→Cloud Escalation](#automatic-local-cloud-escalation). Revisit when: first week of usage data post-ship.
- **Managed-deployment override rights.** In an enterprise context, an administrator may want to pin cloud-endpoint grants (user cannot revoke) or forbid specific endpoints (user cannot add). The principle supports this — the administrator is acting on the user's behalf within a prior agreement — but the exact grant-override mechanism is undesigned.
  **Revisit when:** the first managed-deployment integration is a concrete project.
- **Cloud endpoint signature / provenance.** A user granting a cloud capability is trusting the endpoint's behavior and data handling. Whether CambiOS verifies the endpoint's identity cryptographically (e.g., via the same Principal system used for on-device services) or relies on user judgment is an open question.
  **Revisit when:** the first supported cloud endpoint ships.

## Non-Goals

- **CambiOS-hosted cloud inference.** This ADR permits the user to call cloud models; it does not commit CambiOS itself to hosting one. Any hosted service is a separate project with its own decisions.
- **Anonymizing or proxying cloud calls.** The user chose the endpoint; the endpoint sees who is calling it (by IP, at minimum, and by whatever identity the user configured). CambiOS does not add a privacy layer beyond what the user themselves arranges. Future privacy-preserving transports are not in scope here.

## Cross-References

- [PHILOSOPHY.md](../PHILOSOPHY.md) — The generative-not-extractive principle that this ADR operationalizes.
- [STATUS.md](../../STATUS.md) — AI subsystem status.
- [ADR-016](016-win-compat-api-ai-boundary.md) — The decision that removed AI translation from the compat layer, freeing this ADR to focus on user-facing AI features.
