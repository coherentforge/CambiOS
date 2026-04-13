# ADR-006: Policy Service — Externalized Authorization Decisions

- **Status:** Proposed
- **Date:** 2026-04-10
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-002](002-three-layer-enforcement-pipeline.md) (Three-Layer Enforcement Pipeline)
- **Related:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC Primitives), [ADR-007](007-capability-revocation-and-telemetry.md) (Capability Revocation + Telemetry)
- **Context:** Moving policy decisions out of kernel code so they can evolve, be observed, and (eventually) be AI-informed without ever giving the AI kernel privileges

## Problem

CambiOS already separates **enforcement** from **decision** in spirit, but not yet in implementation. The kernel enforces capability checks on every IPC operation ([ADR-002](002-three-layer-enforcement-pipeline.md)'s three-layer pipeline). The check itself — "does the calling process hold the right capability for this operation?" — is mechanical: a table lookup against the per-process `ProcessCapabilities` struct, with the capability table treated as the single source of truth.

What's missing is the upstream question: **how does a capability get into that table in the first place, and under what conditions can it be added, modified, or revoked?**

Right now the answer is hardcoded in the kernel:
- `SYS_REGISTER_ENDPOINT` grants the calling process full rights on the new endpoint, no questions asked
- Boot module loading grants the bootstrap Principal full rights on the kernel processes, with the trust check baked into `BinaryVerifier`
- Delegation is allowed if the source holds the `delegate` right and is not escalating beyond what they already have
- The `IpcInterceptor::on_syscall` hook exists at [src/syscalls/dispatcher.rs](../../src/syscalls/dispatcher.rs) but its default policy is permissive — it always returns `Allow`. [SECURITY.md](../../SECURITY.md) lists per-process syscall allowlists as "Not implemented" (gap #1, highest priority)

Each of these decisions is *policy*. Each one is currently expressed as Rust code inside the kernel. Each one is therefore impossible to update without recompiling the kernel, impossible to observe without instrumenting the kernel, and impossible to drive from a separate process — including the AI security service that [PHILOSOPHY.md](../../PHILOSOPHY.md) and [CambiOS.md](../../CambiOS.md) both describe as a userspace observer.

The architectural intent is already documented. [CambiOS.md line 88](../../CambiOS.md) lists "Policy" as one of the **Core Services** in the layer diagram, sitting *above* the microkernel. [PHILOSOPHY.md lines 73-99](../../PHILOSOPHY.md) explicitly says the AI security layer "observes without controlling the microkernel" and "enforces through capabilities already present in the system." [SECURITY.md gap #1](../../SECURITY.md#gap-analysis) names per-process syscall allowlists as the highest-impact missing piece, with the explicit note that "the hook exists. Just needs policy tables."

So the gap is not "we need to invent a policy mechanism." The gap is "we need to give the existing policy slot a real implementation, *and* we need to put that implementation outside the kernel so it can evolve independently and be observed by the AI security layer."

This ADR specifies how.

## The Reframe

The principle this ADR formalizes:

> **The kernel makes mechanical checks. The policy service makes decisions.**

Mechanical checks are O(1) lookups against the capability table: "does process P hold a capability with rights R on endpoint E? Y/N." These belong in the kernel because they happen on every IPC and they need to be fast, formally verifiable, and impossible to bypass.

Decisions are the upstream question: "should process P be granted/denied this capability in the first place? Should this delegation chain be allowed? Should this syscall pattern trigger a behavioral alert?" These do not belong in the kernel. They are policy, and policy changes — every system has different policy needs, every workload reveals new edge cases, and every security incident teaches new rules. Kernel code that needs to be recompiled for each policy update is a tax on adaptation.

The reframe matches the existing architecture's spirit. [ADR-002](002-three-layer-enforcement-pipeline.md) made the interceptor a `trait` precisely so policies could be substituted without recompiling the IPC layer. The trait exists; the substitutable implementation does not. This ADR builds it.

## Decision

Extract authorization policy decisions into a **user-space policy service**, accessed by the kernel via an upcall mechanism similar to how Linux's LSM (Linux Security Modules) hooks work — except the policy is in a separate process, not loaded into the kernel as code.

### What runs where

| Component | Location | Responsibility |
|---|---|---|
| **Capability table** | Kernel (`src/ipc/capability.rs`) | Authoritative storage of who-holds-what. Mechanical lookups only. |
| **Capability check** | Kernel (`CapabilityManager::verify_access()`) | Per-message lookup against the table. O(1). Returns `Allowed` or `PermissionDenied`. |
| **`IpcInterceptor` hook** | Kernel (`src/ipc/interceptor.rs`) | Calls the policy service for decisions. Caches results to avoid per-message upcalls in the steady state. |
| **Policy decisions** | User-space `policy-service` | Decides: should this capability be granted? Should this syscall pattern be allowed? Should this channel creation be approved? |
| **Policy logic** | Inside `policy-service`, replaceable | The default implementation is hardcoded "allow if signed by bootstrap key + on the syscall allowlist for this binary's stated profile." Replaceable with rule-based, ML-informed, or human-attended logic without kernel changes. |
| **AI observation** | Separate user-space `ai-watcher` (future) | Subscribes to telemetry from the policy service. Recommends policy changes via IPC. **Never makes decisions directly.** Cannot bypass the policy service. The policy service decides whether to act on AI recommendations. |

This is the layering [CambiOS.md line 88](../../CambiOS.md) already specifies. The kernel does five things ("Scheduling | Memory | IPC | Capabilities | Interrupts"); Policy is one of the Core Services *above* the kernel. The capability manager stays in the kernel because that's where mechanical enforcement happens. The decision-making layer moves up.

### How a policy decision happens

```
Process A makes a syscall (or IPC operation, or capability request)
    │
    ▼
Kernel: SyscallDispatcher / IPC send path
    │
    ▼
Kernel: IpcInterceptor::on_syscall(caller, syscall_number)
    │   │
    │   ├── Check policy decision cache for (process_id, decision_key)
    │   │   ├── Hit (within TTL): use cached Allow/Deny
    │   │   └── Miss: fall through to upcall
    │   │
    │   ▼
    │   Upcall: send policy-query message to policy-service via control IPC
    │       (existing 256-byte path — small structured query)
    │   │
    │   ▼
    │   Block this caller until policy-service responds
    │       (uses the existing scheduler block/wake primitives —
    │        see SCHEDULER.md § Blocking and Wake Primitives)
    │   │
    │   ▼
    │   policy-service: evaluates the query against its rules
    │       - Looks up the calling process's syscall profile
    │       - Looks up the calling process's identity (Principal)
    │       - Consults its rule engine
    │       - May ask the AI watcher for a recommendation (advisory only)
    │       - Returns Allow / Deny / DeferToHuman
    │   │
    │   ▼
    │   Kernel: receives response, caches it, wakes the blocked caller
    │   │
    │   ▼
    │   IpcInterceptor::on_syscall returns the decision
    │
    ▼
Kernel: continues with the syscall (Allow) or returns PermissionDenied (Deny)
```

The cache makes this practical. Most syscalls in any given workload follow a small set of repeated patterns: "fs-service calling SYS_RECV_MSG on endpoint 16," "udp-stack calling SYS_WRITE to endpoint 20," etc. A cache keyed on `(process_id, decision_key)` — where `decision_key` is the syscall number, target endpoint, and any other dimension the policy depends on — turns the steady state into a single hash lookup per syscall. The upcall to the policy service happens once per cache miss, not once per syscall.

Cache invalidation has two triggers:
1. **TTL expiry** — every cached decision has an associated tick count and expires after a configurable window (default: 1 second of ticks)
2. **Explicit invalidation** — when the policy service updates its rules, it sends an `INVALIDATE_CACHE` message to the kernel, which clears the relevant cache entries. The kernel doesn't have to interpret the new rules — it just drops the cache.

### What the policy service decides

The set of policy questions the policy service answers (full list, expandable as new questions are identified):

| Question | When asked | Default policy (v0) |
|---|---|---|
| `should_allow_syscall(process, syscall_number)` | On every syscall via the existing `on_syscall` hook | Allow if `syscall_number` is in the process's profile (initially: a permissive profile derived from the process's stated capabilities at load time) |
| `should_allow_ipc_send(sender, target_endpoint, message_summary)` | On every IPC send | Allow if sender holds send rights (existing capability check is the source of truth — policy adds optional rate limiting, anomaly detection) |
| `should_allow_capability_grant(grantor, grantee, capability)` | On `RegisterEndpoint`, on delegation | Allow if grantor is permitted to grant this capability under current rules |
| `should_allow_capability_revoke(revoker, target, capability)` | On `SYS_REVOKE_CAPABILITY` (see [ADR-007](007-capability-revocation-and-telemetry.md)) | Allow if revoker holds the revoke authority (initially: only the bootstrap Principal) |
| `should_allow_channel_create(creator, peer, size, purpose)` | On `SYS_CHANNEL_CREATE` (see [ADR-005](005-ipc-primitives-control-and-bulk.md)) | Allow if creator + peer have a pre-existing capability relationship |
| `should_allow_channel_attach(attacher, capability_token)` | On `SYS_CHANNEL_ATTACH` | Allow if attacher's Principal matches the named peer in the capability |
| `should_allow_binary_load(verifier, binary_metadata)` | On ELF load (alongside the existing `BinaryVerifier`) | Allow if signed by a trusted Principal (current behavior — wrapped in policy interface so it can be augmented later) |
| `should_handle_anomaly(process, anomaly_kind, severity)` | When the AI watcher reports an anomaly | Initially: log only. Later: revoke specific capabilities, suspend, terminate, escalate to human |

The kernel does not need to know any of these details. It only needs to know: "ask the policy service, get a yes or no, act on it." The policy service is where the *logic* lives.

### The default policy implementation

The first version of the policy service is **deliberately stupid**. It implements exactly what the kernel does today, just relocated:

```rust
// Pseudo-code, will live in user/policy-service/src/main.rs
fn should_allow_syscall(query: SyscallQuery) -> Decision {
    // Look up the process's syscall profile (keyed on Principal)
    let profile = profiles.get(&query.process.principal)
        .unwrap_or(&DEFAULT_PROFILE);
    if profile.allowed_syscalls.contains(&query.syscall_number) {
        Decision::Allow
    } else {
        Decision::Deny
    }
}

fn should_allow_capability_grant(query: GrantQuery) -> Decision {
    // Mechanical: existing kernel logic, just relocated
    if query.grantor.holds(&query.capability)
        && query.grantor.has_delegate_right(&query.capability)
        && !query.escalates_authority()
    {
        Decision::Allow
    } else {
        Decision::Deny
    }
}
```

This is intentional. The point of the v0 policy service is to **establish the architectural slot**, not to introduce new policy. It must produce identical decisions to the kernel today, modulo the per-process syscall allowlist (which is the one place where SECURITY.md gap #1 says we want different behavior than the kernel currently has). The migration is an *architectural* refactor — the *behavior* is unchanged.

The reason this matters: refactoring the call site is risky. Changing the policy at the same time as moving it is reckless. The first version of the policy service ships with the same decisions the kernel makes today, and the test suite verifies that the relocated version produces identical results on every existing IPC test case. Then, *and only then*, do we start adding policy that the kernel never had.

### How the AI fits in (the "old school" stance)

The AI security service is a **user-space watcher**. It does not make decisions. It does not block IPC. It does not call the kernel. It does exactly two things:

1. **Subscribes to telemetry** from the policy service. Every decision the policy service makes, every cache hit and miss, every cache invalidation, every IPC pattern observation flows to the AI watcher via standard IPC. See [ADR-007 § Audit Telemetry](007-capability-revocation-and-telemetry.md#audit-telemetry) for the telemetry format.

2. **Sends recommendations** back to the policy service via the same IPC mechanism. A recommendation is a structured message: "Process P has done X, which deviates from the baseline by N standard deviations. Recommended action: revoke capability C / suspend / log." The policy service receives the recommendation, evaluates it against its own rules, and decides whether to act.

The decision authority is the policy service. The AI is **advisory**. The policy service can ignore AI recommendations entirely, can require multiple AI agreements before acting, can require human confirmation for high-impact actions, can run with no AI watcher at all. The policy service is the sole interface to the kernel for policy mutations.

This means:
- An AI bug cannot directly compromise the kernel. The worst it can do is send bad recommendations to the policy service, which the policy service may or may not act on.
- The AI can be replaced, updated, or removed without touching the kernel or even the policy service.
- A user who doesn't trust the AI can run with `ai-watcher` disabled — the policy service still works, just without anomaly recommendations.
- The user remains in the loop. The default v0 policy service has no AI integration at all. AI integration is opt-in, configurable, and replaceable.

This matches [PHILOSOPHY.md lines 73-99](../../PHILOSOPHY.md):

> "Security LLM watches syscalls, detects anomalies, revokes capabilities when patterns diverge from expected behavior. It *observes* without *controlling* the microkernel. It enforces through capabilities already present in the system."

The "AI watches" stance is not a constraint we're imposing on top of the architecture — it's a constraint the architecture is *designed to express*. The policy service is the load-bearing component that makes "AI observes, AI advises, humans/policy decides" a structural property of the system, not a policy promise.

## Architecture

### Where the policy service runs

`policy-service` is a user-space ELF, like every other Core Service (fs-service, key-store, virtio-net, udp-stack). It runs in ring 3, holds capabilities for an IPC endpoint dedicated to policy queries, and is signed at build time by the bootstrap key. It is loaded as a boot module and started during the kernel's normal user-space service init phase.

The kernel knows the policy service's IPC endpoint via a compile-time constant (or, eventually, via the boot manifest in [ADR-021 Init Process](../../CLAUDE.md#planned-next-steps-roadmap), when that exists). The endpoint is reserved for the policy service — no other process can register it.

### The upcall mechanism

The kernel-to-user upcall reuses the existing IPC primitives. There is no new transport layer. The kernel synthesizes a control IPC message addressed to the policy service's endpoint, blocks the calling task on a `MessageWait` for the response, and resumes the task when the response arrives. The whole interaction is on the existing 256-byte control path (queries are small structured records, well under 256 bytes).

The trick is that the upcall is initiated by the *kernel*, not by a user-space process. This is distinct from the normal IPC flow where user-space sends a message and waits for a reply. The kernel needs to:

1. Build a `PolicyQuery` message in kernel memory (no allocation in the hot path — uses a pre-allocated per-CPU query buffer)
2. Use the existing IPC enqueue path to deliver it to the policy service's endpoint
3. Block the calling task with `BlockReason::PolicyWait(query_id)` (a new variant)
4. When the policy service's response arrives, the IPC layer matches the response to the query_id, wakes the blocked task with the decision, and resumes execution

This is the only architectural change to the IPC layer itself: the new `BlockReason::PolicyWait` and the kernel-initiated send path. Everything else reuses what's already there.

### Caching

The cache lives in the kernel, in the interceptor, indexed by `(process_id, decision_key)`. Decisions have a TTL (default: 100 ticks ≈ 1 second). Cache hits are O(1) hash lookups; cache misses fall through to the upcall.

The cache is **per-CPU** to avoid lock contention. Each CPU has its own cache; cache invalidation messages from the policy service are broadcast to all CPUs via the same IPI mechanism the TLB shootdown uses ([ADR-001](001-smp-scheduling-and-lock-hierarchy.md) § "Wake and block primitives").

Cache size is bounded — say, 256 entries per CPU. When the cache is full, the oldest entry is evicted (LRU or simple round-robin; the choice doesn't matter much because policy decisions are usually long-lived). Eviction is silent — the next access just goes through the upcall path, which adds latency but never causes incorrect behavior.

### Bootstrap problem

The policy service is itself a user-space process, and user-space processes need policy decisions to start. The bootstrap is:

1. **Boot phase 1.** The kernel loads the policy service binary from the boot module set. `BinaryVerifier` checks the signature against the bootstrap Principal — this is the *only* policy decision in the boot path that doesn't go through the policy service, because the policy service doesn't exist yet. The check is hardcoded ("trust the bootstrap key") and is a deliberate exception.

2. **Boot phase 2.** The policy service starts. It binds to its reserved IPC endpoint. It loads its policy rules (initially: from a compile-time table; eventually: from a signed config file in the ObjectStore).

3. **Boot phase 3.** The kernel sets a flag: `POLICY_SERVICE_READY = true`. From this point forward, the `IpcInterceptor` hooks call the policy service for decisions. Before this point, they fall back to the kernel-default permissive policy (the current behavior).

4. **Boot phase 4.** All other user-space services (fs-service, key-store, virtio-net, etc.) start. They go through the policy service for everything.

The window between phases 1 and 3 is the only time the kernel makes its own policy decisions. That window is hundreds of milliseconds, deterministic, and only the bootstrap-trusted code runs in it. This is acceptable — it matches the current behavior of "boot modules are trusted because they're signed."

### Failure modes

What happens if the policy service crashes?

| Failure | Detection | Response |
|---|---|---|
| Policy service crashes (process exit) | Kernel scheduler notices the task is `Terminated` | `POLICY_SERVICE_READY = false`. Subsequent policy queries fall back to the kernel-default permissive policy. The kernel logs the failure to the boot console. The init process (when it exists — see roadmap item 21) restarts the policy service. While the restart is in progress, behavior is identical to a v0 system without the policy service — i.e., the existing scaffolding. |
| Policy service hangs (responsive but slow) | Kernel times out after N ticks waiting for a response | Specific query falls back to permissive default. Cached entries continue to work. Repeated hangs trigger the same restart path as a crash. |
| Policy service returns a malformed response | Kernel drops the response, treats as no-decision | Same as a hang — fall back to permissive default for that query. |
| Policy service is compromised (returns Allow when it should return Deny) | Cannot be detected from kernel side | This is the same threat as any compromised user-space service. Mitigated by the policy service being signed at build time, holding minimal capabilities (only the policy endpoint and the audit channel), and being one of the smallest user-space services. The policy service is itself in the TCB-of-policy, even though it's not in the kernel TCB. |
| Kernel cache poisoning | Cache is per-CPU, written only by `IpcInterceptor`, no IPC path can write directly | Not exploitable from user-space without compromising the kernel itself. |

The fallback to permissive policy is intentional. **The kernel does not become unusable when the policy service is unavailable.** A policy service crash should not crash the kernel, and a policy service compromise should not be worse than a non-existent policy service. The system degrades to the v0 CambiOS posture (capability checks still enforced, syscall allowlists not enforced) rather than refusing to operate.

This is a deliberate tradeoff. The alternative — fail-closed, where every syscall is denied if the policy service is down — would mean the policy service is a single point of failure for the entire OS. Fail-open is the safer choice for a kernel whose other security properties (capabilities, identity stamping, ELF verification) remain in force regardless of policy service state.

### Performance considerations

**Without caching:** an upcall per syscall would be a disaster. Every syscall would block, schedule the policy service, schedule the policy response back, and resume — easily 10 microseconds added per syscall, dominating the scheduler. Untenable.

**With caching:** the steady state is one hash lookup per syscall plus the existing capability check. The upcall happens only on the first instance of each (process, decision) pair, plus cache misses on TTL expiry. Measured against current CambiOS workloads (~24 syscalls, simple control patterns), the steady-state overhead is sub-microsecond. The first call from a new process pays the upcall cost once.

**For high-frequency syscalls** (`SYS_YIELD`, `SYS_GET_PID`), the cache should never miss in the steady state — these are the most-repeated patterns. The TTL of 1 second means the upcall happens at most once per second per (process, syscall) pair, which is negligible.

**Future optimization:** for known-trivial decisions (`SYS_GET_PID` is always allowed for any process), the cache can be pre-populated at process creation. Also out of scope for v0.

## Threat Model Impact

| Threat | Without policy service | With policy service |
|---|---|---|
| Compromised user process tries unauthorized syscall | Blocked by `on_syscall` returning `PermissionDenied` (currently scaffolding-only — the hook exists but the policy is permissive) | Blocked by policy service deny + cached for the next attempt |
| Attacker installs malicious code that requests excessive capabilities | Blocked at boot (signed binary + verifier) | Same — policy service does not change boot-time signing |
| AI security service is compromised | N/A (no AI today) | AI is sandboxed: it can only send recommendations to the policy service. The policy service decides whether to act. Worst case: AI sends bad recommendations, policy service ignores them or applies them, behavior reverts to manual policy update |
| Policy service is compromised | N/A | Subset of "compromised user-space service" — affects policy decisions but not capability storage. Capability table remains kernel-managed and unforgeable |
| Cache poisoning (kernel-side cache) | N/A | Not exploitable: cache is per-CPU, written only by `IpcInterceptor`, no IPC path writes it directly |
| Policy service doesn't respond | Operation blocks | Falls back to permissive default after timeout — operation continues with v0 CambiOS behavior |
| Adversary races policy responses (sends fake response before real one) | N/A | Responses are matched on `query_id` (kernel-generated nonce); the policy service is the only process holding the policy endpoint capability, so no other process can send responses |

The key property: **the kernel TCB does not grow.** The policy service is in the policy-decision TCB but not the kernel TCB. A policy service compromise does not give an attacker kernel privileges — only the ability to influence which capabilities get granted, which is a strictly smaller authority than kernel access.

## Verification Stance

The kernel side of the policy service interaction is small enough to verify:
- The cache lookup is a hash table operation
- The upcall path uses existing IPC primitives (already verified by ADR-002's enforcement pipeline)
- The fallback to permissive default is a single conditional
- The new `BlockReason::PolicyWait` adds one variant to the existing block reason enum

The policy service itself is user-space code and is **not** in the kernel verification target. Its correctness is enforced through:
- Standard testing (unit tests on the policy logic, integration tests on the upcall path)
- Compilation as a signed boot module (build-time integrity)
- Capability isolation (it can only do what its capabilities allow, same as any other user-space service)
- The fallback path in the kernel (a buggy policy service degrades the system, doesn't crash it)

This matches CLAUDE.md's verification posture: kernel code is verification-targeted, user-space code is reviewed and tested but not formally verified.

## Why Not Other Options

### Option A: Leave policy in the kernel, expand the existing interceptor

**Why considered.** The interceptor already exists. Adding more rules to `DefaultInterceptor` is mechanically easy. No new IPC, no new service, no new failure modes.

**Why rejected.** It violates the architectural intent in [CambiOS.md line 88](../../CambiOS.md) ("Policy" as a Core Service above the kernel) and [PHILOSOPHY.md lines 73-99](../../PHILOSOPHY.md) ("AI watches without controlling the kernel"). It also makes AI integration impossible without putting the AI in the kernel, which everyone agrees is a non-starter. The default interceptor is fine as a fallback; it is not where the actual policy logic should live long-term.

### Option B: Load policy as a kernel module (Linux LSM-style)

**Why considered.** Faster than IPC. Used by every major Linux distribution. Industry-standard pattern.

**Why rejected.** Requires loading code into the kernel, which violates the microkernel TCB rule. Updates require kernel restart. AI integration would require AI inference in kernel context (impossible at the latencies real models need). And the verification posture takes a hit — code loaded into the kernel must be re-verified on every load, vs a user-space service that's verified once at build time and isolated by capability + page table.

### Option C: Inline policy interpreter (eBPF-style) in the kernel

**Why considered.** Linux uses this for some BPF-based LSMs. The policy is bytecode, the kernel runs an interpreter, updates require no recompilation.

**Why rejected.** Introduces a JIT compiler or interpreter in the kernel — orders of magnitude more complexity than the entire current CambiOS kernel. The verification story for an in-kernel bytecode interpreter is unsolved (eBPF has had multiple kernel CVEs from verifier bugs). And the latency story isn't actually better than an IPC upcall with caching, because the steady state for both is "no kernel-side work."

### Option D: Run the policy service in user-space, accessed via IPC upcall (chosen)

**Why chosen.** Aligns with the existing layered architecture. Composes with capability isolation. Replaceable without kernel changes. AI-compatible without making AI a kernel component. Verification surface stays small. Failure mode is graceful (fall back to permissive default). Performance is acceptable with caching. Matches the documented intent in CambiOS.md and PHILOSOPHY.md.

The cost is: more user-space code, a new IPC upcall path, a new `BlockReason` variant, and the discipline of keeping the policy service's startup before any other user-space service. All of these are local, contained changes.

## Migration Path

This ADR's implementation can be sequenced incrementally:

1. **Define the `PolicyQuery` and `PolicyDecision` message formats.** No code changes — just documentation of the wire format.

2. **Add `BlockReason::PolicyWait`** to the scheduler. One enum variant. Trivial.

3. **Add the kernel-side upcall path:** `policy_query()` function in the interceptor that builds a query, blocks the caller, waits for response, returns decision. Initially has no callers — just exists.

4. **Add the per-CPU cache.** Hash table keyed on `(process_id, decision_key)`. Initially empty, no callers.

5. **Build the v0 policy service.** A new user-space crate (`user/policy-service/`) with the same shape as fs-service or key-store. Implements `should_allow_syscall`, `should_allow_capability_grant`, etc. — all returning the kernel's current behavior. Sign and load as a boot module.

6. **Wire up the first `on_syscall` upcall.** In `IpcInterceptor::on_syscall`, replace the permissive default with: cache lookup → if miss, `policy_query()` → cache result → return decision. Initially the policy service returns Allow for everything; nothing visible should change.

7. **Test against the existing test suite.** All 218 tests should still pass. Any test that does fail is identifying a behavior change that needs investigation.

8. **Add per-process syscall allowlists** in the policy service (closes [SECURITY.md gap #1](../../SECURITY.md#gap-analysis)). The first real policy that the kernel never had.

9. **Add capability grant/revoke decisions** through the policy service. Closes the kernel→userspace migration of decision logic.

10. **Add the audit telemetry channel** (see [ADR-007](007-capability-revocation-and-telemetry.md)). Policy service starts emitting decisions to a telemetry endpoint.

11. **Build the AI watcher** (much later — post-v1). Subscribes to the telemetry channel, sends recommendations back to the policy service via IPC. The policy service decides what to do with them.

Steps 1–7 establish the architectural slot without changing observable behavior. Step 8 is the first behavior change and the first time the policy service is doing real work. Steps 9–10 complete the policy migration. Step 11 is the AI integration, which is now a userspace concern, completely orthogonal to the kernel.

## Cross-References

- **[ADR-000](000-zta-and-cap.md)** — Capability foundations (capabilities are still enforced by the kernel; policy decides who gets them)
- **[ADR-002](002-three-layer-enforcement-pipeline.md)** — The interceptor pattern this ADR makes real (the `on_syscall` hook is the slot that's getting filled)
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** — Channel creation goes through policy too (`should_allow_channel_create`)
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Revocation primitive used by the policy service; audit telemetry consumed by the AI watcher
- **[CambiOS.md § Architecture](../../CambiOS.md)** — Layer diagram showing "Policy" as a Core Service above the microkernel
- **[PHILOSOPHY.md](../../PHILOSOPHY.md) lines 73-99** — "AI observes without controlling the kernel"
- **[SECURITY.md § Gap Analysis](../../SECURITY.md#gap-analysis)** — Items 1, 5, "Runtime behavioral AI" all addressed by this ADR + ADR-007
- **[SCHEDULER.md § Blocking and Wake Primitives](../../src/scheduler/SCHEDULER.md#blocking-and-wake-primitives)** — `BlockReason::PolicyWait` joins the existing block reasons

## See Also in CLAUDE.md

When implementing the changes specified by this ADR, the following CLAUDE.md sections must be updated to reflect the new architecture:

- **§ "Current state"** paragraph — note that the policy service is a Core Service alongside fs-service, key-store, etc.
- **§ "Lock Ordering"** — the policy cache is per-CPU and lock-free; no new lock added to the hierarchy
- **§ "Syscall Numbers"** — no new syscall numbers (the upcall is implemented internally as a kernel-initiated IPC)
- **§ "Required Reading by Subsystem"** (when added) — under "If you are touching capability/policy code"
- **§ "Post-Change Review Protocol" Step 8** (when added) — adding policy questions requires updating SECURITY.md's enforcement status table
