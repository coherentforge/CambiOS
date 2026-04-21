# ADR-019: Process Fault Reaping and Peer-Generation Signaling

- **Status:** Proposed
- **Date:** 2026-04-19
- **Depends on:** [ADR-007](007-capability-revocation-and-telemetry.md) (Revocation + audit telemetry), [ADR-008](008-boot-time-sized-object-tables.md) (Generation counters on ProcessId), [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives — Principal-stamped messages)
- **Related:** [ADR-018](018-init-process-and-boot-manifest.md) (Init process and boot manifest — owns the **supervisor policy** half), [ADR-002](002-three-layer-enforcement-pipeline.md) (policy-as-userspace pattern this follows)
- **Supersedes:** N/A

## Scope Boundary (read this first)

This ADR is **the kernel-side substrate** for dealing with process death that was not the process's own `SYS_EXIT`. It is explicitly *not* a supervisor design. The split:

| Concern | Owner |
|---|---|
| Reaping a faulting process (resource reclamation, parent wake, audit) | **This ADR (kernel)** |
| Distinguishing fault-kill from clean exit in the ABI | **This ADR (kernel)** |
| Capturing fault context (fault kind, faulting address, PC) into the audit trail | **This ADR (kernel)** |
| Signaling peer restart to surviving clients (endpoint generation counter) | **This ADR (kernel)** |
| Deciding *whether*, *when*, and *how often* to restart a dead service | [ADR-018](018-init-process-and-boot-manifest.md) (user-space init) |
| Restart backoff, dependency-graph restart propagation, giveup thresholds | [ADR-018](018-018-init-process-and-boot-manifest.md) (user-space init, manifest) |
| Crash-dump-as-CambiObject for consent-based diagnostics | **Future ADR** (deferred — captured as open question below) |

The rule is the same one ADR-002 and ADR-006 already follow: **kernel makes mechanical checks, user-space makes policy decisions.** Init deciding to restart a service is a policy decision. The kernel delivering a clean, faithful record of what happened is a mechanical concern.

## Context

Today, two user-process death paths exist with asymmetric cleanup:

- `SYS_EXIT` (clean exit, [src/syscalls/dispatcher.rs](../../src/syscalls/dispatcher.rs) `handle_exit`) performs full reclamation: capability table, channel mappings (with TLB shootdown), VMA-tracked frames, page tables, 4 MiB contiguous heap. Wakes the parent task. Emits an `AuditEventKind::ProcessTerminated` event. Yields.
- User fault (GPF / page-fault / UD, [src/interrupts/mod.rs](../../src/interrupts/mod.rs) `exceptions::*`) calls `crate::terminate_current_task()`, which marks `TaskState::Terminated` and returns — and then yields. Nothing else.

The fault path leaks every resource `handle_exit` reclaims. It never wakes the parent, so a hypothetical init watching via `SYS_WAIT_TASK` never learns the service died. It emits no audit event, so a user-space observer subscribing to the audit ring ([ADR-007](007-capability-revocation-and-telemetry.md)) sees no fault.

[ADR-018 § 4 "The init process"](018-init-process-and-boot-manifest.md) and [§ "Restart and backoff"](018-init-process-and-boot-manifest.md) assume `SYS_WAIT_TASK` *does* return on service fault. That assumption is currently false. This ADR makes it true.

Separately, even once fault reap is correct, a surviving client that held a stable reference to a now-restarted peer (for example, a shell holding an fs-service endpoint handle across an fs-service restart) has no primitive to notice the peer is a different incarnation. The ProcessId generation counter ([ADR-008 § Open Problem 9](008-boot-time-sized-object-tables.md)) solves stale ProcessIds at the slot level — it does not solve stale *endpoint* references, because clients address peers by endpoint, not by pid.

## Problem

Four specific mechanical problems, each needed independently but composing into one coherent fix.

**Problem 1 — fault path is not a reap.** `terminate_current_task()` in [src/lib.rs:262](../../src/lib.rs#L262) marks one boolean and returns. Every resource the process held stays held. Frames leak, peers see stale shared-memory mappings, capability slots stay occupied. A malicious or buggy process can exhaust kernel memory by repeatedly faulting via spawned children.

**Problem 2 — no parent notification on fault.** `SYS_WAIT_TASK` only wakes on `SYS_EXIT` (via the parent-wake path in `handle_exit`). A parent — whether init or a user-space spawner — cannot observe a child's fault. Restart policy ([ADR-018](018-init-process-and-boot-manifest.md) § Restart and backoff) requires this observation.

**Problem 3 — fault-kill is indistinguishable from clean exit.** Even if `SYS_WAIT_TASK` fired on fault, today's ABI surfaces only a `u32` exit code. A peer has no way to distinguish "process exited voluntarily with code 1" from "process faulted with a page fault at RIP 0x402300." The restart policy in [ADR-018](018-018-init-process-and-boot-manifest.md) wants to treat these differently: clean exit of a `OneShot` service is success; fault of a `OneShot` service may warrant a giveup. Today they are the same code path at the wire format.

**Problem 4 — no peer-generation signal.** When fs-service restarts, clients holding endpoint-16 handles receive messages from "fs-service" at the same endpoint number with the same bound Principal — the manifest guarantees that (see [ADR-018 § 1](018-init-process-and-boot-manifest.md)). But any *stateful* handle the client held (an open inode, a session cookie, a long-lived channel) is now held against a process that no longer exists. The client has no kernel-observable primitive to detect this. They will see silent failures, stale reads, or worse — a new occupant of the same process slot interpreting the client's stale handle as its own.

**Why these compose.** Fix Problem 1 without Problem 2 and init learns nothing. Fix both without Problem 3 and init cannot distinguish clean exit from fault. Fix all three without Problem 4 and the restart *happens* correctly but clients corrupt state against the new incarnation. The four are one mechanism.

## The Reframe

> **A process that faults should look, from every observer's point of view, exactly like a process that called `SYS_EXIT` — except the exit reason is "kernel killed me for reason X" and every peer learns the specific incarnation that died.**

Concretely, this means:
1. The fault handler delegates to the same reclamation routine `handle_exit` uses. The reap is structurally one function, called from two entry points (voluntary exit and kernel fault).
2. The audit event produced on fault is a distinct kind — `ProcessFaulted` — with fields for the fault class and faulting address. The existing `ProcessTerminated` stays for clean exits.
3. The parent-wake path fires on both voluntary exit and fault. `SYS_WAIT_TASK` returns a struct that distinguishes the two.
4. Each IPC endpoint carries a monotonic generation counter, bumped whenever the current owner exits or is reaped. Messages carry the sender's endpoint-generation; receivers can detect "my peer restarted" by a single equality check on a saved generation.

None of this requires a new kernel subsystem. The mechanisms (audit events, capability revocation, VMA reclaim, generation counters) already exist — they just aren't wired through the fault path, and endpoints don't yet carry generations.

## Decision

### 1. Unify the reap path

Extract the body of `handle_exit` (from the scheduler-state update through `destroy_process`) into a single function:

```rust
// In src/process.rs or a new src/process/reap.rs.
pub fn reap_process(
    process_id: ProcessId,
    task_id: TaskId,
    reason: ExitReason,
);
```

`handle_exit` calls `reap_process(..., ExitReason::Exited(code))`. The fault handlers call `reap_process(..., ExitReason::Faulted(fault_kind, fault_addr, pc))` and then yield, replacing today's `terminate_current_task()` + bare yield loop.

### 2. `ExitReason` enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Process called SYS_EXIT with this code.
    Exited(i32),
    /// Kernel killed the process due to an unrecoverable fault.
    Faulted {
        kind: FaultKind,
        fault_addr: u64,    // CR2 on x86, FAR_EL1 on AArch64, stval on RISC-V
        pc: u64,            // RIP / ELR_EL1 / sepc at fault
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultKind {
    PageFault = 0,
    GeneralProtection = 1,
    InvalidOpcode = 2,
    StackOverflow = 3,      // emitted by a future guard-page handler
    DivideByZero = 4,
    // Reserved range for arch-specific faults not in the common set.
}
```

Exhaustive `match` on `FaultKind` is a verification target — no unknown/default case.

### 3. New audit variant

Add to `AuditEventKind` in [src/audit/mod.rs](../../src/audit/mod.rs):

```rust
/// Kernel reaped the process due to an unrecoverable fault.
ProcessFaulted = 16,
```

Builder signature:

```rust
pub fn process_faulted(
    pid: ProcessId,
    fault_kind: FaultKind,
    fault_addr: u64,
    pc: u64,
    runtime_ticks: u64,
    timestamp: u64,
    sequence: u32,
) -> Self;
```

The existing `ProcessTerminated = 12` keeps its current meaning (clean `SYS_EXIT`). Keeping them distinct means a policy-service or supervisor consuming audit can pattern-match on event kind without inspecting exit-code bits. Kind 15 is already `AuditDropped`; 16 is the next free slot.

### 4. `SYS_WAIT_TASK` ABI shift

Current: `SYS_WAIT_TASK` returns a single `i32` exit code. New: it writes an `ExitInfo` struct (24 bytes) to a caller-provided buffer and returns 0/error.

```rust
#[repr(C)]
pub struct ExitInfo {
    pub reason_tag: u8,       // 0 = Exited, 1 = Faulted
    pub fault_kind: u8,       // valid iff reason_tag == 1
    pub _pad: [u8; 6],
    pub exit_code: i32,       // valid iff reason_tag == 0
    pub fault_addr: u64,      // valid iff reason_tag == 1
    pub pc: u64,              // valid iff reason_tag == 1
}
```

This is a breaking ABI change to one syscall. Every current caller (only shell today, soon init per ADR-018) must update. Worked-example discipline from CLAUDE.md applies — all seven syscall-landing steps get re-run.

Scope note: `ExitInfo` deliberately does **not** carry a register-file snapshot. A full register snapshot belongs in the crash-dump-as-CambiObject design (flagged in Open Problems) where it can be paired with VMA snapshots, an audit slice, and signing — not in every `SYS_WAIT_TASK` return payload. Supervisors that only need to decide "restart or give up" have no use for register state; supervisors that need to diagnose get it from the future dump object, not from this syscall.

### 5. Endpoint generation counter — stable numbers, refreshed identity

Extend the endpoint registry. Each endpoint carries a `u32` generation bumped on every ownership transition:

- Bumped when `SYS_REGISTER_ENDPOINT` claims a previously-owned endpoint (including reclaim after reap).
- Bumped during the reap path for every endpoint the dying process owned.

**Endpoint numbers are stable across restarts; generation counters carry the "new incarnation" signal.** A restarted service (same Principal per the manifest) re-registers the same endpoint number and receives a fresh generation. This matches [ADR-018](018-init-process-and-boot-manifest.md)'s endpoint-reservation model — the manifest pins endpoint 16 to fs-service's Principal, so only that Principal can ever own 16, whether on first boot or after restart N. Fresh endpoint numbers per restart (the alternative) would require a naming-service daemon, break the manifest's reservation model, and introduce race windows while a service is mid-restart.

Receive-side syscalls (`SYS_RECV_MSG`, `SYS_TRY_RECV_MSG`) already return the sender's `from_endpoint`; they also return the sender's current endpoint generation. Clients cache the generation they last observed; a mismatch means "peer restarted, my stateful handles are stale."

This generalizes the ProcessId generation counter pattern ([ADR-008 § Open Problem 9](008-boot-time-sized-object-tables.md)) from slot-reuse to endpoint-reuse. The memory cost is one `u32` per endpoint — at the current `ENDPOINT_COUNT` SCAFFOLDING bound that is a few KB; trivial.

Scope note: endpoint-level generation is deliberately the only generation-counter surface exposed to clients. `ProcessId` already carries its own generation for slot-reuse detection inside the kernel; clients do not address peers by `ProcessId`, so exposing a process-level generation would duplicate the signal without giving clients a new observable. One counter, one level, one client check.

### 6. Fault handler changes (per arch)

Each arch's user-fault handlers ([src/interrupts/mod.rs](../../src/interrupts/mod.rs) x86, the AArch64 EL0 sync handler, the RISC-V trap dispatch) replaces its `terminate_current_task() + yield` sequence with:

```rust
if is_user_mode(&stack_frame) {
    let ctx = capture_syscall_context_from_fault();
    reap_process(
        ctx.process_id,
        ctx.task_id,
        ExitReason::Faulted { kind, fault_addr, pc },
    );
    loop { yield_save_and_switch(); }
}
```

Kernel-mode faults retain today's `halt()` behavior — a kernel fault is unrecoverable regardless, and ADR-019 is not the place to add kernel fault recovery.

## Architecture

### Reap-path lock order

The reap path runs the same locks `handle_exit` runs, in the same order:

```
SCHEDULER(1) → [purge_task] → release
CAPABILITY_MANAGER(4) → [revoke_all_for_process] → release
CHANNEL_MANAGER(5) → [revoke_all_for_process] → release → teardown_channel_mappings
PROCESS_TABLE(6) → FRAME_ALLOCATOR(7) → [destroy_process] → release
AUDIT (lock-free per-CPU staging)
```

No new locks. No reordering. The fault-entry version runs in interrupt context with interrupts disabled on entry; it must not acquire a lock that an interrupt-disabled context cannot take. The existing `handle_exit` is already callable with interrupts enabled (it's a syscall), and switching to disabled-on-entry is strictly safer because no nested interrupt can preempt a partial reap.

### Audit emission in fault context

`emit()` in [src/audit/mod.rs:592](../../src/audit/mod.rs#L592) is already safe to call from any context that has a valid GS base / TPIDR_EL1. Fault handlers run with per-CPU state initialized (we are well past early boot by the time a user process can fault), so emission is straightforward. The event is produced **before** the structural reclamation that destroys the process — otherwise the runtime-ticks field would be indeterminate and the ProcessId might refer to a slot already being marked free. Order inside `reap_process`:

1. Mark task `Terminated`, capture exit metadata, wake parent.
2. Emit audit event (`ProcessTerminated` or `ProcessFaulted`).
3. Reclaim capabilities → channels → VMAs → page tables → heap.
4. Yield.

### Endpoint generation lookup

An additional dense `[u32; ENDPOINT_COUNT]` array in the endpoint registry. Every endpoint-wire protocol path that currently returns a `from_endpoint: u32` is extended to return a `(from_endpoint: u32, from_endpoint_generation: u32)` pair. Every recv-side syscall and every `VerifiedMessage` ([user/libsys/src/lib.rs](../../user/libsys/src/lib.rs)) carries the pair.

Userspace services get a `sys::endpoint_generation(ep)` helper that caches their peers' generations. The helper is not in the kernel TCB — clients who don't check get silent staleness, which is the same failure mode as ignoring a ProcessId generation. The kernel provides the mechanism; correctness is a userspace-protocol concern.

## Threat Model Impact

| Threat | Without this ADR | With this ADR |
|---|---|---|
| Process spins faulting children to exhaust kernel frames | Each fault leaks ~4 MiB. O(n) fault iterations → OOM | Each fault fully reaps. Bounded — process exits its own frame budget |
| Supervisor doesn't see a crashed service | Parent never woken; audit silent | Parent woken via `SYS_WAIT_TASK`; audit event emitted |
| Restart policy can't distinguish crash from clean exit | Both surface as exit code only | `ExitInfo.reason_tag` + `AuditEventKind::ProcessFaulted` distinguish them structurally |
| Client uses a stale handle against a new incarnation of fs-service | Silent, with whatever wire-protocol misinterpretation follows | Kernel-observable `from_endpoint_generation` mismatch; client detects and resets |
| Fault-kill evades the audit trail | No event; external observer sees nothing | `ProcessFaulted` with fault class + faulting address + PC goes into the audit ring |
| Compromised service faults on purpose to clear state | Cleared silently, process table slot reused, peer mappings dangle | Cleared through same reap as a crash, audit event records the fault, peers detect via generation |

The kernel TCB does not grow. `reap_process` is a refactor of `handle_exit` plus the fault-path entry; `ProcessFaulted` is one audit variant; endpoint generation is a dense array plus one equality check. No dynamic dispatch, no new unsafe, no lock hierarchy change.

## Verification Stance

- `ExitReason` and `FaultKind` are `#[repr(u8)]` exhaustive enums. Every consumer `match`es exhaustively; no default arm.
- `reap_process` is a single function with a fixed sequence of bounded-iteration reclamation steps. Each sub-step (`revoke_all_for_process`, `destroy_process`, etc.) is already bounded.
- Endpoint generation: a `u32` counter with wrapping increment. Verification target: "a client observing generation N can never confuse N with a wrap-around collision within the lifetime of a boot." At 1e6 restarts/sec (absurd) a u32 wraps in ~71 minutes; restarts are bounded to far less than that by any reasonable backoff policy. A u64 removes even this theoretical concern at the cost of 4 bytes per endpoint; we pick u32 and document the assumption in `ASSUMPTIONS.md`.
- The fault-to-reap path adds no new `unsafe`. Arch-specific context capture reuses existing `stack_frame` / `ESR_EL1` / `scause` accessors.

## Why Not Other Options

### Option A: Exit code convention (negative = fault)

**Why considered.** Zero-ABI-change. Fault handlers call `handle_exit` with `exit_code = 0x80000000 | fault_kind`; callers inspect the high bit.

**Why not.** Punning on exit codes rules out all 2^31 exit codes as "possible faults" for any careful caller. It conflates two semantically different events at the ABI level. The one new `ExitInfo` struct (Option decision 4) avoids the pun and delivers the extra fields (fault_addr, PC) the supervisor actually needs. ABI-change cost is real but one-time; the pun cost is permanent.

### Option B: Kernel owns the restart policy

**Why considered.** Fewer moving parts. The kernel already knows when a process died; it could just respawn.

**Why not.** This is exactly what [ADR-018](018-init-process-and-boot-manifest.md) rejects and explicitly defers to init. Restart backoff, dependency-graph ordering, manifest-driven giveup thresholds, and observability of "init gave up on service X" are all policy decisions that belong in user space. The kernel would have to grow a manifest parser and a backoff timer — both user-space concerns in every microkernel shipping. Same rejection reason as ADR-006 for the policy service.

### Option C: Let the scheduler GC leaked resources on next schedule

**Why considered.** Current fault path already yields; the next `schedule()` call sees `TaskState::Terminated` and could reap there.

**Why not.** Moves reclamation to an unrelated code path that runs under the scheduler lock — every lock below SCHEDULER(1) in the hierarchy is now forbidden in that path, but reclamation needs CAPABILITY_MANAGER(4), CHANNEL_MANAGER(5), PROCESS_TABLE(6), FRAME_ALLOCATOR(7). Forces lock inversion or deferred-work queues, both of which are new mechanisms for a problem solved by calling the same reap path at fault time. Verification cost is higher than doing the work directly.

### Option D: Per-endpoint session cookies instead of generation counters

**Why considered.** The generation counter is coarse — "peer restarted" tells you to discard all state, but maybe you held 50 handles and only one is actually stale.

**Why not.** For v1, peer-restarted → discard-all-stateful-state is exactly the right model. Finer-grained cookies push complexity into every service that wants to be restart-friendly; the generation counter gets 100% of the "detect restart" problem with one `u32`. Cookies can be layered on top in a specific service's wire protocol (e.g., fs-service hands out inode handles with embedded generation); the kernel doesn't need to know.

## Open Problems (deferred)

### Crash-dump-as-CambiObject

The companion question — consent-based crash diagnosis without telemetry — is the natural follow-on. The fault audit event this ADR produces is the event *someone* needs to hook into to produce a dump, but the dump format, retention, sanitization, and export mechanism are their own design. Flagged for a future ADR rather than scoped here so that 019 can land on its own merits:

> **Deferred decision.** Kernel fault handler could, in addition to emitting `ProcessFaulted`, construct a `CambiObject` containing the fault context, selected VMA snapshots, and a slice of recent audit events — author = faulting process's Principal, owner = operator. User-initiated export is `obj_get` + send; kernel never initiates. **Revisit when:** the first post-restart diagnostic question surfaces that the `ProcessFaulted` audit event alone cannot answer ("I want to know *why* udp-stack crashed, not just that it did"). That is the observable trigger for the follow-on ADR. Fault-addr + PC in the audit event will answer most first-round questions; the dump ADR is needed when it stops being enough.

### Guard-page stack overflow detection

`FaultKind::StackOverflow` is defined but not yet distinguishable from `PageFault`. Requires a guard-page convention on user stacks that the fault handler can recognize. Deferred as a strictly additive refinement — landing `FaultKind::PageFault` is correct; `StackOverflow` is a better diagnostic for a subset of those faults.

### Kernel-mode fault recovery

Kernel-mode faults still `halt()`. Recoverable kernel faults (e.g., a page-walk failure inside a syscall handler because of a malformed user pointer) are a real future ask but a much larger scope — they require a fixup-table or try/catch-style landing-pad mechanism plus a clear separation of recoverable-vs-unrecoverable kernel fault sites. Deliberately out of this ADR: 019 lands clean user-fault reaping without entangling the kernel-fault recovery design. **Revisit when:** a syscall handler path needs to tolerate user-pointer misbehavior without the halt — today the explicit page-walk helpers in the syscall dispatcher avoid the question; the trigger is the first path where that indirection is too expensive.

### Generation counter on channels

Channels ([ADR-005](005-ipc-primitives-control-and-bulk.md)) are already torn down on reap — peers see their mapped region get invalidated. Whether a channel *also* needs a generation counter (for the case where a peer attaches a new channel at the same id before the old peer has noticed) is a separate question. Tentative answer: no, because channel ids are not stable across restart — a restarted service creates a new channel at a new id. Flagging here so the ADR review catches any missed case.

## Migration Path / Phased Plan

A **single commit-boundary landing** is not appropriate — the ABI change to `SYS_WAIT_TASK` requires every caller to update, and the fault-path rework is non-trivial. Phasing:

**Phase 019.A — Reap-path refactor.** Extract `reap_process` from `handle_exit`. `handle_exit` is a thin wrapper that calls `reap_process(ExitReason::Exited(code))`. No behavior change. Green across all three arches (tri-arch gate). Lands a commit.

**Phase 019.B — Fault handlers call `reap_process`.** x86_64 GPF + page-fault + UD, AArch64 EL0 sync, RISC-V U-mode trap dispatch. Today's `terminate_current_task` is removed. Each arch's commit verifies the existing "user fault kills task" integration still works plus new leakless behavior.

**Phase 019.C — `ProcessFaulted` audit variant + fault-context fields.** Additive to AuditEventKind. User-space audit consumers that don't know the new variant see a kind byte = 16 and can ignore. Backward compatible.

**Phase 019.D — `SYS_WAIT_TASK` ABI shift to `ExitInfo`.** Breaking change. Land in the same commit as every caller's update. Today's callers: shell (user-facing `wait` command). Init-the-process doesn't exist yet per [ADR-018](018-init-process-and-boot-manifest.md).

**Phase 019.E — Endpoint generation counter.** Additive field on recv-side syscalls + `VerifiedMessage`. Clients that ignore the new field see no regression; clients that check it gain restart-detection.

Each phase is independently testable, independently revertable, and each one moves the state of the art forward without requiring the next to be ready.

