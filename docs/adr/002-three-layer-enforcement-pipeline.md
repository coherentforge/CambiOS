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
