# ADR-002: Three-Layer Enforcement Pipeline for IPC and Syscalls

- **Status:** Accepted
- **Date:** 2026-04-04
- **Depends on:** ADR-000 (Zero-Trust Architecture and Capability-Based Access Control)
- **Superseded by parts of:** ADR-006 (Policy Service) reframes the Layer 1 hook as a thin client of an externalized policy service rather than as in-kernel policy code. The pipeline shape is unchanged.
- **Context:** Wiring the zero-trust security model into the syscall and IPC hot paths

> *For implementation status of each layer (enforced, scaffolding, designed) see [SECURITY.md § Enforcement Status Summary](../SECURITY.md). This ADR captures the decision; status lives with the code.*

## Problem

ADR-000 establishes that CambiOS uses capability-based access control and zero-trust principles. But a security *model* is not enforcement — it needs to be wired into the code paths where operations actually happen.

The question: where in the syscall and IPC dispatch pipeline do we enforce access control, and how do we structure the checks so that:

1. A single bypass does not grant unrestricted access
2. Enforcement is mandatory (no code path skips it)
3. Different kinds of violations are caught by different layers (defense in depth)
4. The system remains extensible (custom policies, AI integration) without modifying the kernel

## Alternatives Considered

### A. Single capability check

Check capabilities once at IPC send/recv time. Simple. The problem: capabilities verify *authority* (does this process have the right token?) but not *structural correctness* (is this message well-formed? is this endpoint in bounds? is this syscall appropriate for this process?). A single layer conflates two concerns.

**Rejected** because it leaves an entire class of attacks (payload overflow, out-of-bounds endpoints, inappropriate syscalls) unaddressed.

### B. Capability check + inline validation

Check capabilities, then validate the message inline in the IPC manager. Better coverage, but the validation logic is hardcoded in the IPC module. Adding new policies (per-process syscall allowlists, AI behavioral analysis, rate limiting) requires modifying IPC internals.

**Rejected** because it couples policy to mechanism, making the system rigid.

### C. Three independent layers with a trait-based interceptor (chosen)

Separate enforcement into three layers, each with a distinct responsibility. The middle layer (capabilities) is hardcoded. The outer layers (interceptor) are trait-based — the default implementation provides baseline policy, and custom implementations can be substituted without kernel modification.

**Chosen** because it provides defense in depth, clean separation of concerns, and extensibility.

## Decision

Enforce access control through three independent layers in the following order:

```
Layer 1: IpcInterceptor::on_syscall()     → Pre-dispatch policy
Layer 2: CapabilityManager::verify_access() → Authority verification
Layer 3: IpcInterceptor::on_send/recv()    → Structural validation
```

Each layer is independently useful. Each layer returns a pass/fail decision. A failure at any layer halts the operation immediately. The layers do not depend on each other — bypassing Layer 1 does not weaken Layer 2 or 3.

### Layer 1: Interceptor Pre-Dispatch

**What it checks:** Is this process allowed to invoke this syscall at all?

**Why it's first:** Rejecting an unauthorized syscall before any work happens is the cheapest possible enforcement. If a serial driver has no business calling `SYS_ALLOCATE`, we want to catch that before touching the capability manager or IPC state.

**Implementation:** `IpcInterceptor::on_syscall(process_id, syscall_number)` is called at the top of `SyscallDispatcher::dispatch()`, before routing to any handler. The hook itself is in-kernel; the *decision* it forwards is externalized to the policy service ([ADR-006](006-policy-service.md)).

### Layer 2: Capability Verification

**What it checks:** Does this process hold the required capability for this operation?

**Why it's in the middle:** This is the core access control. It runs after the pre-dispatch filter (which catches obviously wrong syscalls) but before the message is processed (so no state is modified for unauthorized operations).

**Implementation:** `CapabilityManager::verify_access(process_id, endpoint, required_rights)` is called inside `send_message_with_capability()` and `recv_message_with_capability()`. Returns `PermissionDenied` if the process lacks the required rights.

### Layer 3: Interceptor Post-Capability

**What it checks:** Is this message structurally valid? Does it violate runtime policy?

**Why it's last:** Capability verification confirms authority. Structural validation confirms sanity. These are orthogonal concerns. A process might legitimately hold send rights on an endpoint but construct a malformed message (oversized payload, out-of-bounds endpoint ID). Layer 3 catches what Layer 2 doesn't look for.

**Implementation:** `IpcInterceptor::on_send(sender, endpoint, message)` and `IpcInterceptor::on_recv(receiver, endpoint)` are called after capability verification, before the IPC operation executes. Default checks: endpoint bounds, payload size (256 bytes — see [ADR-005](005-ipc-primitives-control-and-bulk.md) for why bulk data takes a separate path), no self-send, no self-delegation.

## The Interceptor Trait

```rust
pub trait IpcInterceptor: Send + Sync {
    fn on_send(&self, sender: ProcessId, endpoint: EndpointId, msg: &Message) -> InterceptDecision;
    fn on_recv(&self, receiver: ProcessId, endpoint: EndpointId) -> InterceptDecision;
    fn on_delegate(&self, source: ProcessId, target: ProcessId, endpoint: EndpointId, rights: CapabilityRights) -> InterceptDecision;
    fn on_syscall(&self, caller: ProcessId, syscall: SyscallNumber) -> InterceptDecision;
}
```

The interceptor is a trait object (`Box<dyn IpcInterceptor>`), set once at boot via `IpcManager::set_interceptor()`. This design means:

- **Custom policies don't require kernel recompilation.** A production interceptor can implement syscall allowlists, rate limiting, AI hooks, or audit logging by implementing the trait.
- **The default interceptor provides safe baselines.** Endpoint bounds, payload limits, and self-send prevention are always present unless explicitly overridden.
- **The interceptor cannot be removed at runtime.** Once set, it processes every operation. There is no "disable security" path.

## Delegation Enforcement

Capability delegation has its own three-check flow, analogous to IPC:

```
1. IpcInterceptor::on_delegate()  → Policy check (bounds, self-delegation)
2. ProcessCapabilities::can_delegate() → Source holds delegate right + no escalation
3. CapabilityManager::grant()     → Target receives the capability
```

The non-escalation property is critical: a process with `{send, delegate}` can delegate `{send}` or `{send, delegate}`, but cannot delegate `{send, recv}` because it doesn't hold `recv`. The delegate right lets you share what you have, not fabricate what you don't.

## Mandatory Enforcement

The pipeline is not optional. There is no `send_message_unchecked()` or `bypass_verification()` in the codebase. The enforcement functions are the only IPC code paths:

- `send_message_with_capability()` is the only send path. It calls `verify_access()` and `on_send()`.
- `recv_message_with_capability()` is the only recv path. It calls `verify_access()` and `on_recv()`.
- `SyscallDispatcher::dispatch()` is the only syscall entry. It calls `on_syscall()`.
- `load_elf_process()` is the only binary load path. It calls `BinaryVerifier::verify()`.

Adding a "fast path" that skips enforcement requires deliberate modification to kernel code. This is by design — the enforcement is structural, not configurable.

## ELF Verification (Related)

The ELF verification gate is not part of the IPC pipeline, but it follows the same philosophy: mandatory, pre-allocation, independently useful. See ADR-000 for the verification checks.

The verifier is also trait-based (`BinaryVerifier`), allowing custom verification logic (e.g., AI-powered static analysis) without modifying the loader.

## Performance Considerations

The three-layer pipeline adds overhead to every IPC operation. Measured against the design goals:

- **Layer 1** (`on_syscall`): One virtual method call + one comparison per syscall. Negligible.
- **Layer 2** (`verify_access`): Linear scan of up to 32 capabilities per process. At 32 entries, this is a cache-line-friendly sequential scan. Negligible for the current cap count.
- **Layer 3** (`on_send`/`on_recv`): Two to three integer comparisons. Negligible.

Total overhead per IPC: sub-microsecond. The IPC message copy itself dominates. Security enforcement is not the bottleneck.

If capability tables grow beyond 32 entries in the future, `verify_access` should be replaced with a hash table or bitmap. This is a data structure change inside `ProcessCapabilities`, not an architectural change.

## Verification

Test coverage of each layer (current counts and what they exercise) lives in [STATUS.md § Test coverage](../../STATUS.md#test-coverage). End-to-end verification runs through `SYS_WRITE` and `SYS_READ` syscall paths in QEMU.

## References

- [ADR-000](000-zta-and-cap.md): Zero-Trust Architecture and Capability-Based Access Control
- [ADR-005](005-ipc-primitives-control-and-bulk.md): IPC Primitives — Control Path and Bulk Path
- [ADR-006](006-policy-service.md): Policy Service — Externalized Policy Decisions
- [SECURITY.md](../SECURITY.md): Living enforcement status reference
- `src/ipc/interceptor.rs`: IpcInterceptor trait + DefaultInterceptor
- `src/ipc/capability.rs`: CapabilityManager + ProcessCapabilities
- `src/ipc/mod.rs`: send/recv with capability + interceptor enforcement
- `src/syscalls/dispatcher.rs`: Syscall dispatch with pre-dispatch interceptor
- `src/loader/mod.rs`: BinaryVerifier trait + DefaultVerifier

## Divergence

### 2026-04-17 — dyn dispatch → IpcInterceptorBackend enum

- **Date:** 2026-04-17
- **Implementation:** commit `1f5cb2d` (`ipc/interceptor: dyn dispatch → IpcInterceptorBackend enum`)
- **Trigger:** Formal-verification audit identified `interceptor: Option<Box<dyn IpcInterceptor>>` (on both `IpcManager` and `ShardedIpcManager`) as a `dyn` trait object on a kernel hot path. Every IPC `send` and `recv` invokes the interceptor; `SyscallDispatcher::dispatch` invokes it pre-handler. CLAUDE.md's Formal Verification rule against trait objects in kernel hot paths applies. Same precedent as [ADR-003 § Divergence](003-content-addressed-storage-and-identity.md#divergence) for `OBJECT_STORE`.

#### What changed

Kernel-side interceptor dispatch moves from `Box<dyn IpcInterceptor>` to an enum dispatch shim:

```rust
pub enum IpcInterceptorBackend {
    Default(DefaultInterceptor),
    // future: PolicyService(PolicyServiceInterceptor) — when ADR-006 lands
}

impl IpcInterceptor for IpcInterceptorBackend {
    fn on_send(&self, sender: ProcessId, endpoint: EndpointId, msg: &Message)
        -> InterceptDecision
    {
        match self {
            Self::Default(i) => i.on_send(sender, endpoint, msg),
        }
    }
    // ... on_recv / on_delegate / on_syscall delegated identically
}

// In IpcManager and ShardedIpcManager:
interceptor: Option<IpcInterceptorBackend>,
```

#### Reconciling with the original "custom policies without kernel recompilation" intent

The original ADR-002 text argued that the trait-object design enables custom interceptors without recompiling the kernel. This intent was **superseded by ADR-006** before the interceptor migration even happened. ADR-006 reframes the substitution model: policy decisions move *outside the kernel entirely* into a userspace `policy-service`, which the in-kernel `IpcInterceptor` upcalls into. The kernel-side interceptor becomes a thin client of the external service, not a swappable in-kernel policy module.

In practice, "swap a different in-kernel interceptor without recompiling" was never viable for CambiOS — the kernel is signed, monolithic, and rooted in the bootstrap Principal. Any in-kernel code change requires a kernel rebuild + re-signing. The runtime extensibility ADR-002 sought is achieved by the policy-service IPC boundary, not by `dyn` dispatch in kernel code.

So the in-kernel interceptor impl set is closed-world by construction:
- `DefaultInterceptor` — current; permissive baseline (endpoint bounds, payload size, no self-send, all syscalls allowed).
- `PolicyServiceInterceptor` — future; thin upcall client per ADR-006 (lands when the policy-service IPC path is built).
- Possibly a `LegacyInterceptor` or test-only impl in unit-test scopes (still permitted: tests can use `dyn` per the Formal Verification rule's "non-test kernel code" qualifier).

That's three enumerable variants, not an open extension point. Enum dispatch fits the actual world.

#### What did *not* change

- **The `IpcInterceptor` trait remains the specification** with all four hooks (`on_send`, `on_recv`, `on_delegate`, `on_syscall`), `Send + Sync` bounds, and current decision/deny-reason types. Backends still `impl IpcInterceptor for ...`. *(Superseded by the 2026-05-12 entry below: `on_syscall` was removed from the trait when the Layer 1 bypass was made permanent.)*
- **The three-layer enforcement pipeline** described in this ADR is intact: pre-dispatch hook → capability check → structural validation. Only the in-kernel storage/dispatch of the hook changes. *(See the 2026-05-12 entry for the Layer 1 transport change.)*
- **Test code using `dyn IpcInterceptor`** (e.g., the `DenyAllSends` mock in `interceptor.rs`'s test module) is unchanged — `dyn` is permitted in non-kernel test scopes.

#### Cost

Adding a new in-kernel interceptor (e.g., when `PolicyServiceInterceptor` lands) requires one new enum variant and one new arm per delegated method (4 hooks × 1 arm each = 4 arms). Closed-world, exhaustive match, monomorphized. The compiler enforces every method updates the new variant — exactly the verification-friendly cost.

#### Why not other options

| Considered | Why rejected |
|---|---|
| Keep `dyn`, document the verification debt in `ASSUMPTIONS.md` | Pure deferral. The fix is structurally cheap and the debt is on the hot IPC path. Same logic as ADR-003. |
| Drop the `IpcInterceptor` trait; single concrete struct with internal `Backend` enum | Loses the spec/impl separation. The trait is the layer-1/layer-3 contract that ADR-006's policy-service implementation also satisfies via its in-kernel client. Conflating them erases the audit point. *(The premise — that ADR-006's implementation would route through the trait — was already false by 2026-04-13 and the 2026-05-12 entry below records the correction.)* |
| Static-dispatch generics on `IpcManager<I: IpcInterceptor>` | Doesn't compile for the global `IPC_MANAGER` static — same blocker as `OBJECT_STORE`. |

#### Verification

After this change, every IPC `send`/`recv`, every delegation, and every syscall pre-dispatch dispatches via match-arm calls. The trait remains as the specification. The kernel binary contains no `dyn IpcInterceptor` references. The two `// VERIFICATION DEBT:` markers in `src/ipc/mod.rs` (and the corresponding [STATUS.md § Known issues](../../STATUS.md#known-issues) entry) are removed in the same change.

### 2026-05-12 — Layer 1 hook removed; `policy::policy_check` is the in-kernel Layer 1

- **Date of effective bypass:** 2026-04-13, commit `11340ff` (`Phase 3.4 + services cleanup: policy service, syscall allowlists, Linux-model logging`). This is when `SyscallDispatcher::dispatch` started calling `crate::policy::policy_check(...)` directly, making the `IpcInterceptor::on_syscall` hook unreachable on the kernel hot path.
- **Date of trait-surface removal:** 2026-05-12, commit `34b4342` (`ipc/interceptor: drop dead on_syscall hook (policy_check supersedes)`). This is when the now-dead method was dropped from the trait, the `IpcInterceptorBackend` enum-dispatch shim, `DefaultInterceptor`, and the test code.
- **Trigger:** ADR-002 review against the actual code revealed the 2026-04-13 divergence had never been recorded. The 2026-04-17 entry above (dyn → enum) was written when the on_syscall bypass was already in place but didn't flag it, and projected a future `PolicyServiceInterceptor` variant that the architecture had already foreclosed. Carrying a documented trait method with no kernel caller and no planned caller is the kind of spec/code drift Convention 1 ("invariants encoded in types") and the formal-verification rule both push back against.

#### What changed

The Layer 1 transport changed. The diagram at the top of this ADR shows `Layer 1: IpcInterceptor::on_syscall()` as the pre-dispatch policy hook. The actual transport since 2026-04-13 is:

```rust
// src/syscalls/dispatcher.rs (excerpt)
let decision = crate::policy::policy_check(
    ctx.process_id,
    ctx.task_id,
    ctx.cr3,
    syscall_num as u32,
);
if let InterceptDecision::Deny(_) = decision {
    crate::audit::emit(crate::audit::RawAuditEvent::syscall_denied(
        ctx.process_id, syscall_num, crate::audit::now(), 0,
    ));
    return Err(SyscallError::PermissionDenied);
}
```

`policy_check` is the in-kernel half of ADR-006's externalized policy service. It consults a per-CPU cache, may upcall to the userspace policy service on miss (blocking the calling task on `BlockReason::PolicyWait`), and returns an `InterceptDecision`. The kernel calls it directly: no trait, no enum dispatch, no virtual call. ADR-006's authority over Layer 1 is unchanged. Only the wiring changed.

After 2026-05-12, the trait surface matches: `IpcInterceptor` has three methods (`on_send`, `on_recv`, `on_delegate`). `DenyReason::SyscallNotPermitted` remains because `policy_check` emits it as the deny reason — it is part of the policy decision wire format, not part of the interceptor trait.

#### Reconciling with the three-layer pipeline

The three-layer model is still the right description of the enforcement shape:

1. **Layer 1 — pre-dispatch policy.** Now `policy::policy_check(...)` called directly from `SyscallDispatcher::dispatch`. Previously routed through `IpcInterceptor::on_syscall`. The check, the deny reason, and the audit emission are unchanged from the original ADR; only the call site changed.
2. **Layer 2 — capability verification.** Unchanged. `CapabilityManager::verify_access` at `src/ipc/capability.rs`, called from `send_message_with_capability` and `recv_message_with_capability`.
3. **Layer 3 — structural validation.** Unchanged. `IpcInterceptor::on_send` / `on_recv` / `on_delegate` via the `IpcInterceptorBackend` enum.

The "three independent layers" claim and the "defense in depth" claim survive intact. What changed is that Layer 1 is no longer one of the interceptor's hooks. It is its own module (`src/policy/`) consulting its own state (per-CPU cache + userspace upcall).

#### Reconciling with the original "custom Layer 1 policies without kernel recompilation" intent

The original ADR-002 argued that the trait-object design would let custom Layer 1 policies (syscall allowlists, AI hooks, rate limiting) substitute for `DefaultInterceptor` without kernel recompilation. The 2026-04-17 entry above already noted that this intent was overtaken by ADR-006: substitution happens at the userspace policy-service boundary, not at the in-kernel interceptor seam. What that entry didn't acknowledge — but the code already reflected — is that ADR-006's in-kernel client *also* doesn't use the `IpcInterceptor` trait. The trait was the seam in the original design; the seam moved to `policy::policy_check`'s function signature.

This is not a new ADR-006 divergence so much as making the 04-17 reconciliation honest: there never was a `PolicyServiceInterceptor` enum variant, and there will not be one.

#### What did *not* change

- **The three-layer pipeline shape.** Still pre-dispatch policy → capability → structural validation, in that order.
- **`IpcInterceptor` as the Layer 2/3 specification.** The trait remains the contract for IPC-layer enforcement (send, recv, delegate). What changed is that it never claimed Layer 1 — Layer 1 has its own transport.
- **`DenyReason` enum.** All variants kept, including `SyscallNotPermitted` (used by `policy_check`) and `PolicyViolation`.
- **Layer 1 enforcement strength.** `DefaultInterceptor::on_syscall` was permissive baseline (always `Allow`). `policy_check` falls back to `Allow` when the policy service is unavailable. Same default behavior, same upgrade path (ADR-006).
- **Test surface for the IPC-layer hooks.** `on_send` / `on_recv` / `on_delegate` tests untouched.

#### Cost

The trait now matches the kernel hot path: every method on `IpcInterceptor` has a live kernel caller. The enum dispatch shim has three arms instead of four; one match arm and one delegated method per backend variant fewer.

The conceptual cost is that the "pre-dispatch hook" in the diagram is no longer a method on the interceptor trait. Anyone reading just the diagram and the trait will not see the Layer 1 transport. This ADR's Layer 1 section and ADR-006's "How a policy decision happens" section both need to spell out the actual call site. Documentation drift in that direction is the price of moving the seam.

#### Why not other options

| Considered | Why rejected |
|---|---|
| Keep `on_syscall` on the trait, comment-out the impl, mark as "reserved for future use" | Dead code with worse visibility. A future verifier still has to reason about the trait surface; a future maintainer still wonders why the hook exists. The architecture (ADR-006 + PHILOSOPHY.md's "AI watches, doesn't decide") has actively foreclosed the use cases that would route through it. Git history (this entry plus commit `34b4342`) is the durable record. |
| Re-route `policy::policy_check` through the `IpcInterceptor` trait, restoring the original ADR-002 shape | Adds an indirection over a single concrete client (`PolicyServiceClient`). The closed-world enum from the 2026-04-17 entry would have exactly two variants — `Default` (permissive, used only in tests) and `PolicyService` (used in production) — with no third on the horizon. The verification benefit of going through the trait is the spec/impl separation the trait provides; that separation is already provided by `policy::policy_check`'s typed signature and the `InterceptDecision` return type. The indirection buys nothing the function signature doesn't already buy. |
| Move `policy_check` into the interceptor module without using the trait | Loses the locality benefit of `src/policy/` (per-CPU cache, upcall machinery, wait-state management all colocate there). The interceptor module's job is IPC-layer structural validation; the policy module's job is policy decisions. Keeping them as siblings keeps each module's surface small. |

#### Verification

- `grep -rn "on_syscall" src/ user/` after this commit returns: the trait+impl+enum sites are gone; only historical-context comments remain in `src/policy/mod.rs` ("Replaces the old `IpcInterceptor::on_syscall()` path") and `src/syscalls/dispatcher.rs` ("Replaces the old IPC_MANAGER → interceptor → on_syscall path"). These are factual references to the architecture change, not callers.
- `make check-all`: x86_64 + aarch64 + riscv64 build cleanly with the trait method removed.
- `cargo test --lib`: 638 passed.
- ADR-006's "How a policy decision happens" section and `docs/SECURITY.md`'s enforcement pipeline diagram are updated in the same docs commit to match the actual transport.
