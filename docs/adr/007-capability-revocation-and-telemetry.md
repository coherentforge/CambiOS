# ADR-007: Capability Revocation and Audit Telemetry

- **Status:** Proposed
- **Date:** 2026-04-10
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-002](002-three-layer-enforcement-pipeline.md) (Three-Layer Enforcement Pipeline)
- **Related:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC Primitives), [ADR-006](006-policy-service.md) (Policy Service)
- **Context:** Two related kernel primitives that together enable real-world security operations: pulling capabilities back when something goes wrong, and giving the AI security layer something to observe

## Problem

CambiOS has working capability *grants*: every IPC endpoint has rights, every process has a capability table, every operation checks its right against the table. What's missing is the ability to **take capabilities back**.

[SECURITY.md gap #5](../../SECURITY.md#gap-analysis) flags this directly: "Required before any real multi-service deployment. A driver update needs to revoke the old driver's capabilities." The use cases are concrete and not hypothetical:

- A user-space service is updated; its replacement holds new capabilities; the old service's capabilities must be revoked atomically before the new service starts handling requests.
- A driver is detected to be misbehaving (sending traffic to unauthorized endpoints, accessing memory it shouldn't, exhibiting anomalous syscall patterns); the policy service decides to revoke its IPC capabilities to contain the damage.
- A process delegates a capability to another process; later, the original holder decides the delegation was a mistake and wants to invalidate it.
- A process is terminated normally; its capabilities should be cleaned up so the kernel doesn't hold stale references in the capability tables.
- A channel ([ADR-005](005-ipc-primitives-control-and-bulk.md)) needs to be force-closed because one of its peers is misbehaving; the kernel must atomically unmap the shared memory from both processes and revoke the underlying capability.

The kernel today cannot do any of this. Capabilities are granted at process creation or via delegation; they live until the process exits. There is no `revoke()` method. There is no way for a third party to invalidate a granted right. There is no kernel primitive that says "this capability is no longer valid, regardless of who holds it."

The second missing piece is the telemetry that makes revocation *useful*. [PHILOSOPHY.md lines 73-99](../../PHILOSOPHY.md) describes the AI security service as a watcher:

> "Security LLM watches syscalls, detects anomalies, revokes capabilities when patterns diverge from expected behavior. It *observes* without *controlling* the microkernel."

For this to be a real architectural commitment instead of an aspiration, the AI needs **something to watch**. Right now there is nothing — the kernel has no observability surface for the AI security service to subscribe to. Capability grants happen, capability checks happen, IPC messages flow, but none of this is exported to a monitoring layer. There's no audit log. There's no event stream. There's no per-process behavioral history.

[ADR-006](006-policy-service.md) introduces the policy service, which is the *decision maker* for capability mutations. But the policy service's decisions are only as good as the information it has. Without telemetry from the kernel, the policy service is making decisions in the dark — it can answer "should this process be allowed to make this syscall?" based on a static profile, but it can't answer "is this process behaving anomalously compared to its own historical pattern?"

These two gaps — revocation and telemetry — are the same architectural problem: **the kernel needs to expose observability and intervention surfaces that the policy service (and the AI watcher behind it) can use without being inside the kernel.** This ADR specifies both, because solving them separately produces an incomplete architecture: revocation without telemetry leaves the AI blind, and telemetry without revocation leaves the AI watching helplessly while violations happen.

## Decision

Add two kernel primitives:

1. **Capability revocation** (`SYS_REVOKE_CAPABILITY` and `CapabilityManager::revoke()`) — atomically invalidate a previously granted capability, notify the holder via control IPC, and force the kernel to drop any cached state related to the capability.

2. **Audit telemetry channel** — a kernel-maintained event stream of capability-relevant operations (grants, denies, revokes, channel creates, anomaly hooks), exposed to user-space subscribers (initially the policy service, eventually the AI watcher) via the bulk-data channel mechanism from [ADR-005](005-ipc-primitives-control-and-bulk.md).

These two primitives are the substrate that makes [ADR-006](006-policy-service.md)'s policy service real. Without them, the policy service can answer "yes or no" to grant decisions but cannot intervene in already-granted authority and cannot learn from history. With them, the policy service can decide to revoke based on observed patterns, the AI watcher can subscribe to the event stream and produce recommendations, and the user retains the ability to inspect or override any of it.

## Capability Revocation

### What revocation means

Revoking a capability is **atomic, immediate, and structural**. After `revoke()` returns:

- The capability is gone from the holder's `ProcessCapabilities` table
- Any in-progress IPC operation that has not yet completed its capability check will fail the check
- Any cached policy decision involving the capability is invalidated across all CPUs
- Any associated kernel resources (channel mappings, IPC subscriptions) are cleaned up
- The holder is notified via a control IPC message so it knows the operation that uses the capability will now fail

The revocation is **structural** in the sense that the holder's continued attempts to use the capability are blocked by the same mechanism that blocks any unauthorized access — the capability table lookup returns "not found." There is no soft-revocation, no warning period, no grace period. After `revoke()`, the capability is invalid the way a capability that was never granted is invalid.

This is intentional. A graceful revocation with a warning period would mean the holder gets to use the capability one last time after being notified that it's being taken away — exactly the moment when a misbehaving holder is most likely to do something destructive. The clean primitive is "the capability is gone, full stop, the holder is notified after the fact."

### Who can revoke

Revocation requires authority. Three parties can call `SYS_REVOKE_CAPABILITY`:

1. **The original grantor.** A process that delegated a capability to another process can revoke its own delegation. This matches the existing delegation model — if you can grant, you can ungrant.

2. **A process with the `revoke` right on the underlying endpoint.** A new capability right is added: `CapabilityRights { send, receive, delegate, revoke }`. The `revoke` right is *not* automatically granted with `delegate` — they are separate. A process that delegates without revoke right cannot un-delegate, which is sometimes the right behavior (e.g., for audit-trail purposes).

3. **The bootstrap Principal** (and, after [ADR-006](006-policy-service.md)'s policy service exists, anyone holding the policy service's revoke endpoint capability). This is the "policy service can intervene" path. The policy service holds a special capability that lets it revoke any other capability in the system, granted at boot time as part of the policy service's bootstrap manifest.

A revocation attempt by a process that is none of the above returns `PermissionDenied`. The check happens in `CapabilityManager::revoke()` before any state is mutated.

### How revocation interacts with channels

Channel revocation is the most complex case because it has to atomically unmap shared memory from two processes. The full sequence:

```
policy-service (or any authorized revoker) calls SYS_REVOKE_CAPABILITY
    │
    ▼
Kernel: CapabilityManager::revoke(capability)
    ├── Look up the capability in the system-wide capability table
    ├── Verify the caller has revoke authority (one of the three checks above)
    ├── Look up the capability holders (peers, in the channel case)
    │
    ▼
For each holder:
    ├── Remove the capability from the holder's ProcessCapabilities table
    ├── If the capability is a channel role:
    │   ├── Look up the channel's page table mappings in that holder
    │   ├── Unmap the pages (existing memory subsystem)
    │   ├── Issue TLB shootdown for the holder's CPUs (existing tlb::shootdown_range)
    │   └── (the holder's next access through stale references faults)
    ├── If the capability is an endpoint right:
    │   ├── If the holder is currently blocked on RecvMsg for this endpoint, wake it with a Revoked status
    │   └── Mark the holder's per-process subscription as invalid
    │
    ▼
Invalidate the policy cache (per-CPU broadcast, see ADR-006)
    │
    ▼
Emit a CAPABILITY_REVOKED event to the audit telemetry channel (see below)
    │
    ▼
Send a control IPC notification to each former holder:
    "Capability X has been revoked. Future operations using it will fail."
    │
    ▼
Free the kernel-side capability record (or mark Revoked)
    │
    ▼
SYS_REVOKE_CAPABILITY returns Success to the caller
```

The key invariant: **after `revoke()` returns, no thread on any CPU can use the revoked capability.** The TLB shootdown for channels and the policy cache invalidation for syscall decisions are both completed before the syscall returns. There is no race window where the capability is "mostly revoked but still accessible."

The TLB shootdown is the most expensive part — it requires sending an IPI to every CPU that has the holder's page tables loaded, waiting for acknowledgment, and only then releasing the lock. The existing `tlb::shootdown_range()` implementation handles this; channel revocation reuses it.

### Failure modes

What happens if revocation is called with bad arguments?

| Failure | Detection | Response |
|---|---|---|
| Capability does not exist | Capability table lookup returns None | Return `Err(NotFound)`. No state changes. |
| Caller has no revoke authority | Check before any mutation | Return `Err(PermissionDenied)`. No state changes. |
| Holder process has been terminated | Holder process_id lookup returns None | Skip that holder; continue with remaining holders if any. (Not an error — terminated processes are equivalent to "already revoked.") |
| TLB shootdown times out | Shootdown wait loop with bounded retries | Log the failure, force the unmap anyway, mark the holder process for termination. A process whose TLB cannot be shot down is unrecoverable — terminate it before continuing. |
| Holder is currently inside a syscall handler that holds the capability | The capability check happens at the start of the operation, not at the end. Re-checks during the handler will fail post-revocation. | Behavior depends on the handler. For IPC send: the message has already been enqueued, the recv side will see it. For IPC recv: the receive returns the existing queued message. In-flight operations complete; new operations after `revoke()` returns fail. |

The "in-flight operations complete" property is important. Revocation is not retroactive. If a message was already enqueued before the capability was revoked, the recipient still gets it. This matches how filesystem permissions work in every Unix-like system: revoking a process's read permission on a file does not unread bytes that have already been read. It is the prevention of *future* operations, not the undoing of past ones.

### Revocation API

```rust
// Kernel side (CapabilityManager)
pub fn revoke(&mut self, capability: CapabilityHandle, revoker: ProcessId)
    -> Result<(), CapabilityError>;

// Syscall (number TBD)
//   Args: arg1 = capability handle (u64)
//   Returns: 0 on success, negative error code
SYS_REVOKE_CAPABILITY
```

The capability handle is a kernel-managed identifier — it does not encode the capability itself, just a reference into the kernel's capability table. The handle is opaque to user-space. A process can hold multiple capability handles; revoking one does not affect the others.

### What this gives us

With revocation, the policy service from [ADR-006](006-policy-service.md) becomes capable of **intervention**, not just decision. Concretely:

- The policy service can revoke a misbehaving process's capabilities without restarting the kernel or the process
- The AI watcher (when it exists) can recommend revocations based on behavioral anomalies; the policy service evaluates the recommendations and acts (or doesn't)
- A driver update can revoke the old driver's capabilities atomically before granting them to the new driver
- A user can manually revoke a capability via a future shell command, with the policy service as the gatekeeper

This closes [SECURITY.md gap #5](../../SECURITY.md#gap-analysis) and provides the substrate for [PHILOSOPHY.md's](../../PHILOSOPHY.md) "AI revokes capabilities when patterns diverge."

## Audit Telemetry

### What gets logged

The kernel emits events to a dedicated **audit telemetry channel** (using the channel mechanism from [ADR-005](005-ipc-primitives-control-and-bulk.md)). The event types are:

| Event | When emitted | Payload |
|---|---|---|
| `CAPABILITY_GRANTED` | After a successful `RegisterEndpoint` or delegation | `{ grantor, grantee, endpoint, rights, timestamp }` |
| `CAPABILITY_REVOKED` | After a successful `revoke()` | `{ revoker, holder, capability, reason, timestamp }` |
| `CAPABILITY_DENIED` | When a capability check returns `PermissionDenied` | `{ caller, attempted_endpoint, attempted_rights, timestamp }` |
| `IPC_SEND` | After successful IPC send (sampled, not every send) | `{ sender, recipient_endpoint, payload_len, timestamp }` |
| `IPC_RECV` | After successful IPC recv (sampled) | `{ receiver, sender_principal, payload_len, timestamp }` |
| `CHANNEL_CREATED` | After `SYS_CHANNEL_CREATE` | `{ creator, peer, size, purpose, channel_id, timestamp }` |
| `CHANNEL_ATTACHED` | After `SYS_CHANNEL_ATTACH` | `{ attacher, channel_id, timestamp }` |
| `CHANNEL_CLOSED` | After channel close (any path) | `{ closer, channel_id, bytes_transferred_estimate, lifetime_ticks, timestamp }` |
| `SYSCALL_DENIED` | When the policy service denies a syscall | `{ caller, syscall_number, reason, timestamp }` |
| `BINARY_LOADED` | After `BinaryVerifier::verify()` succeeds | `{ binary_hash, signer_principal, size, timestamp }` |
| `BINARY_REJECTED` | After `BinaryVerifier::verify()` fails | `{ binary_hash, rejection_reason, timestamp }` |
| `PROCESS_CREATED` | After process creation | `{ process_id, principal, parent, timestamp }` |
| `PROCESS_TERMINATED` | After process exit | `{ process_id, exit_code, runtime_ticks, timestamp }` |
| `POLICY_QUERY` | When the policy service is consulted (high volume — sampled) | `{ caller, query_kind, decision, cached, timestamp }` |
| `ANOMALY_HOOK` | Reserved for future use; emitted when the AI watcher (when it exists) flags a pattern | `{ subject, anomaly_kind, severity, evidence_summary, timestamp }` |

Each event is a small structured record (32-128 bytes). They're emitted to the audit channel as fast as possible, with some events sampled (IPC sends/recvs in the steady state are too high-volume to log every one — 1-in-N sampling is configurable).

### How the channel works

The audit telemetry channel uses [ADR-005](005-ipc-primitives-control-and-bulk.md)'s data channel primitive. Specifically:

- **Producer:** the kernel itself
- **Consumer:** the policy service (initially), and any other subscriber that holds the audit telemetry capability (later: the AI watcher, audit log services, debugging tools)
- **Channel type:** SPSC (single producer = kernel, single consumer = policy service)
- **Size:** 64 KB ring buffer (configurable; small because events are small and the consumer reads continuously)
- **Direction:** kernel → consumer (consumer cannot write)

The channel is created at boot, before any user-space service starts. The kernel allocates the pages, marks them with a special "kernel-producer" flag (since the normal channel create syscall is initiated by user-space, this is a special boot-time variant), and produces events into the ring buffer as they happen. The policy service attaches to the channel as part of its initialization.

The kernel side of the producer is **lockless** — events are written to a per-CPU ring buffer first, then drained to the global audit channel by a background task. This avoids per-event lock contention on the audit channel, which would otherwise dominate the syscall hot path.

### Backpressure

What if the consumer falls behind? The audit channel is a fixed-size ring buffer. If the producer outpaces the consumer:

1. **Soft backpressure (cache layer).** Each per-CPU ring buffer has its own depth. If the per-CPU ring fills up, events on that CPU are dropped silently. The drop count is incremented in a per-CPU `dropped_events` counter, which is itself emitted as an event (with delay) when the ring drains.

2. **Hard backpressure (global channel).** If the global audit channel ring buffer fills up faster than the policy service can drain it, the kernel drops the oldest events first (FIFO drop, not LIFO). The dropped count is preserved in a `total_dropped_events` counter visible via `SYS_AUDIT_INFO`.

3. **No blocking.** The kernel never blocks on the audit channel. Audit logging is best-effort. If logging is failing, the system continues operating; the audit consumer eventually notices the gaps and can decide what to do.

This is a deliberate design choice. The alternative — blocking the producer when the channel is full — would mean a slow consumer can DoS the kernel. Audit telemetry is observability, not enforcement; making it best-effort preserves the system's ability to function under load even when monitoring is degraded.

### What the AI watcher does (eventually)

This ADR does not implement the AI watcher. It defines the *substrate* the AI watcher would attach to. When the AI is built (sometime after v1), it will:

1. Attach to the audit telemetry channel (acquires the audit consumer capability from the policy service)
2. Stream events from the channel into its inference engine
3. Build per-process behavioral baselines: what syscalls each Principal usually makes, what endpoints each process usually talks to, what time-of-day patterns each service follows
4. Detect deviations: a process suddenly making syscalls it has never made before, talking to an endpoint it has never used, transferring data volumes far above its baseline
5. Emit recommendations to the policy service: "Process P is exhibiting anomaly X. Recommended action: revoke capability Y / suspend / log only."

The policy service receives the recommendations as ordinary IPC messages, evaluates them against its own rules (which may or may not act on AI input — this is configurable), and, if it decides to act, calls `SYS_REVOKE_CAPABILITY` or other intervention primitives.

Critically: **the AI is not in the kernel, the AI is not in the policy service, and the AI cannot directly invoke kernel intervention primitives.** It is a third user-space process holding two capabilities — one to read the audit channel, one to send recommendations to the policy service. Compromising the AI service cannot directly compromise anything; the worst it can do is send bad recommendations. Even those bad recommendations have to go through the policy service, which is the gatekeeper.

This matches the "old school" stance from PHILOSOPHY.md: the AI watches and informs; humans (or hardcoded policy) decide; the kernel enforces.

### Telemetry size and performance

Rough sizing:

- Event size: ~64 bytes average
- Event rate at typical workload: ~1000 events/sec (IPC dominant)
- Throughput: ~64 KB/sec
- Channel size: 64 KB → ~1 second of buffering at typical rates

For high-volume workloads (a video server handling many channels), the rate can spike to 100k events/sec (~6 MB/sec). Sampling (1-in-100 IPC events under steady state) keeps the rate manageable. The policy service is responsible for tuning the sampling rate based on what it's observing.

The producer-side cost in the kernel is approximately:
- Per event: write 64 bytes to a per-CPU ring (one cache line, sub-100ns)
- Per drain (every N ticks or when per-CPU ring half-full): copy from per-CPU ring to global ring, advance pointers (microseconds)
- Per syscall in the steady state: zero — events are recorded but not logged

The cost is comfortably below the IPC overhead it observes. Audit telemetry adds **less than 1% overhead** to the syscall hot path, which is the right order of magnitude for security observability.

## How These Two Primitives Combine

Revocation and telemetry are designed to work together:

```
1. Process P does something anomalous: makes a syscall it has never made before
   ──── kernel: AUDIT(SYSCALL_DENIED or POLICY_QUERY) ────►  audit channel

2. policy-service reads the event from the audit channel
   ──── computes: "this is anomalous, deviation = N stddev"

3. policy-service consults its rules (or, eventually, asks the AI watcher)
   ──── decides: "revoke P's capability for that endpoint"

4. policy-service: SYS_REVOKE_CAPABILITY(P's endpoint capability)
   ──── kernel: revoke(); update tables; TLB shootdown; cache invalidate
   ──── kernel: AUDIT(CAPABILITY_REVOKED) ────►  audit channel
   ──── kernel: send notification to P via control IPC

5. P attempts to use the revoked capability again
   ──── kernel: capability check fails; returns PermissionDenied
   ──── kernel: AUDIT(CAPABILITY_DENIED) ────►  audit channel

6. policy-service sees the CAPABILITY_DENIED event
   ──── confirms: "yes, the revocation took effect"

7. (optional) The AI watcher, subscribed to the same channel, sees the
   anomaly → revoke → confirmation pattern and learns it
```

The same telemetry that lets the AI/policy detect the anomaly is the same telemetry that confirms the intervention worked. The same revocation primitive that the policy service uses is the same one a future kernel update tool would use to swap drivers. There's no special path for security operations — the primitives are general-purpose, and security is one consumer.

## Architecture

### Capability table changes

The existing `Capability` struct gains a `revoke` right:

```rust
pub struct CapabilityRights {
    pub send: bool,
    pub receive: bool,
    pub delegate: bool,
    pub revoke: bool,   // NEW
}
```

And the `CapabilityManager` gains a `revoke()` method:

```rust
impl CapabilityManager {
    pub fn revoke(
        &mut self,
        capability: CapabilityHandle,
        revoker: ProcessId,
    ) -> Result<(), CapabilityError>;

    pub fn revoke_all_for_process(
        &mut self,
        process_id: ProcessId,
    ) -> Result<usize, CapabilityError>;
}
```

The second method is for process termination cleanup — when a process exits, all of its held capabilities are revoked. This is internal cleanup, not a user-facing primitive.

### New syscall

| Number | Name | Purpose |
|---|---|---|
| (TBD) | `SYS_REVOKE_CAPABILITY` | Revoke a capability the caller has authority to revoke |
| (TBD) | `SYS_AUDIT_INFO` | Read kernel audit statistics: total events, dropped events, channel state |

`SYS_AUDIT_INFO` exists for observability of the observer — the policy service needs to know if its audit consumer is keeping up.

### Audit channel boot sequence

The audit telemetry channel is special: it's the only channel created by the kernel (rather than by a user-space process via `SYS_CHANNEL_CREATE`). The boot sequence:

1. Kernel allocates the audit channel ring buffer (64 KB) from the frame allocator
2. Kernel initializes the per-CPU staging buffers and the producer-side state
3. Kernel creates a `ChannelRecord` with `creator_principal = bootstrap`, `peer_principal = unset` (filled in when the policy service attaches)
4. Kernel begins emitting events; events accumulate in the per-CPU buffers
5. Kernel loads the policy service binary (part of the boot module set)
6. Policy service starts, requests the audit consumer capability via `SYS_AUDIT_ATTACH` (a special variant of `SYS_CHANNEL_ATTACH` for the kernel-produced audit channel)
7. Kernel verifies the policy service's identity matches the expected one (signed binary check, same as any boot module), maps the audit channel pages into the policy service as RO, returns the consumer handle
8. Policy service begins draining the audit channel
9. Steady-state operation begins

If the policy service is not yet ready when events are produced (between steps 4 and 8), the per-CPU buffers fill up and the global ring drops the oldest events. The kernel logs the drop count to the boot console as a non-fatal warning. Once the policy service attaches, the full event stream resumes.

### Lock ordering

The audit telemetry mechanism does not introduce a new lock to the hierarchy. The per-CPU staging buffers are lock-free (single producer per CPU, no contention). The global drain task acquires the audit channel ring lock briefly during drain, but the ring lock is at the same hierarchy position as the channel manager (TBD during implementation), and it is never held while acquiring scheduler or capability locks.

The revocation primitive does add a new sequencing constraint: `revoke()` must hold `CAPABILITY_MANAGER(4)` and may need to acquire `PROCESS_TABLE(5)` and `FRAME_ALLOCATOR(6)` to clean up associated channel mappings. This matches the existing lock order — revocation always acquires in 4 → 5 → 6 sequence, never the reverse.

## Threat Model Impact

### What revocation gives us

| Threat | Mitigation without revocation | Mitigation with revocation |
|---|---|---|
| Compromised driver continues to misbehave after detection | Restart the driver process (loses state) | Atomically revoke its capabilities; subsequent operations fail; replacement driver starts cleanly |
| Misbehaving channel peer floods consumer | Consumer must close the channel manually | Policy service revokes the channel capability; both sides immediately lose access |
| Mistakenly delegated capability | No way to take it back | Original grantor revokes delegation |
| AI watcher detects anomaly but cannot intervene | N/A (AI didn't exist) | AI recommends; policy service decides; revocation enforces |
| Stale capabilities accumulate after process termination | Never cleaned up; clutter | `revoke_all_for_process()` cleans up automatically on exit |

### What telemetry gives us

| Threat | Without telemetry | With telemetry |
|---|---|---|
| Unknown attacker exploits a known-vulnerable user-space service | Detected only after damage is visible (file corruption, network exfiltration) | Behavioral anomaly visible in audit stream within seconds; policy/AI can recommend intervention |
| Insider misuse: legitimately authorized process abuses its capabilities | Hard to distinguish from normal operation | Per-process baselines flag deviations; the audit log proves what happened |
| Slow-motion attacks (low-and-slow data exfiltration) | Below threshold of any single check | Long-term audit history shows cumulative pattern |
| Confused-deputy attack inside a service | Capability check passes (the deputy holds the capability legitimately) | The pattern of *which* operations the deputy is performing on behalf of the attacker shows up in the audit stream |

### What this does NOT protect against

- **A compromised policy service.** The policy service holds the revoke authority. If it's compromised, it can revoke arbitrary capabilities or fail to revoke ones it should. Mitigated by: (a) the policy service is signed at build time, (b) it runs with minimal capabilities, (c) revocation events are themselves audited so a compromised policy service has to revoke logging capabilities to hide its tracks.
- **Forged audit events.** Only the kernel writes to the audit channel. User-space subscribers can read but not write. The channel is RO from the consumer side. Forgery requires kernel compromise.
- **Kernel-level compromise.** All bets off — the kernel is the root of trust for both revocation and telemetry. This is the existing TCB boundary; this ADR does not change it.

## Verification Stance

Revocation:
- **Atomicity** — `revoke()` is a single critical section under `CAPABILITY_MANAGER`. The capability is removed from all holder tables before the lock is released. Verifiable as a single-locked operation.
- **No partial revocation** — either all holders lose the capability or none do (rollback on failure).
- **No leak after revoke** — TLB shootdown and cache invalidation complete before `revoke()` returns. Verifiable as a sequence of mandatory steps in the implementation.

Telemetry:
- **Lossless or correctly-counted loss** — every event is either delivered or counted in the dropped-events counter. Never silently dropped without accounting.
- **Read-only from consumer** — channel mapping permission enforced by MMU; verifiable from page table state.
- **Event format integrity** — events are fixed-size with a checksum or magic number; consumer can detect ring buffer corruption.

These are smaller verification targets than the kernel hot path. The revocation primitive is one new method on `CapabilityManager` plus the channel/IPC interaction that calls it. The telemetry mechanism is a producer/consumer channel (which inherits its verification story from [ADR-005](005-ipc-primitives-control-and-bulk.md)) plus an event encoder in the kernel.

## Migration Path

1. **Add `revoke` right to `CapabilityRights`.** Existing capabilities default to `revoke = false` (only the original grantor can revoke; no one else has standing). One enum/struct change.

2. **Implement `CapabilityManager::revoke()`** with the full holder-cleanup logic. Initially no callers. Tests verify the table mutation, the holder notification, and the error paths.

3. **Implement `CapabilityManager::revoke_all_for_process()`** — used by process termination. Wire it into the existing `handle_exit` path. Now all process exits result in capability cleanup; this is testable end-to-end.

4. **Add `SYS_REVOKE_CAPABILITY`** as a syscall. The first user-facing way to call revoke from outside the kernel. Initial check: only the bootstrap Principal can call it (matches the existing pattern for `SYS_BIND_PRINCIPAL`).

5. **Implement the kernel side of the audit channel.** Per-CPU staging buffers, drain task, channel record, ring buffer. Initially no consumer — events accumulate and drop on overflow.

6. **Implement `SYS_AUDIT_ATTACH`** — special channel attach variant for the kernel-produced audit channel. Allows the policy service (and only the policy service, by signed-binary check) to attach.

7. **Wire event emission into the existing kernel hot paths.** Capability grant, capability deny, IPC send/recv (sampled), binary load, process create/exit. Each call site gets one line: `audit::emit(Event::Whatever { ... })`. The audit subsystem absorbs the event into the per-CPU buffer.

8. **Update the policy service** ([ADR-006](006-policy-service.md)) to attach to the audit channel and start consuming. Initially the policy service just logs to its own console — no decisions based on audit events yet.

9. **Add intervention logic** to the policy service: rules that watch for specific event patterns (capability denied + repeated within window → flag; binary rejection → log; anomaly hook → revoke) and call `SYS_REVOKE_CAPABILITY` when triggered. This is the first time the audit data drives behavior.

10. **Eventually:** the AI watcher process. Attaches to the audit channel as a second consumer (channels can be SPMC if the policy service grants the AI watcher its own consumer capability). Sends recommendations to the policy service via standard IPC. The policy service decides what to do with them.

Steps 1–4 implement revocation. Steps 5–9 implement telemetry. Step 10 is the eventual AI integration, which happens long after this ADR lands and is its own scope of work.

The order is deliberate: revocation comes first because it has no dependencies on user-space code. Telemetry follows because it depends on [ADR-005](005-ipc-primitives-control-and-bulk.md)'s channel mechanism, which is more invasive. The two together complete the substrate that [ADR-006](006-policy-service.md)'s policy service needs to be useful.

## Cross-References

- **[ADR-000](000-zta-and-cap.md)** — Capability foundations (revocation extends the existing model)
- **[ADR-002](002-three-layer-enforcement-pipeline.md)** — Enforcement pipeline (capability check still happens; revocation makes the check fail post-revoke)
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** — Channels (audit telemetry uses the channel primitive; channel revocation uses the primitive defined here)
- **[ADR-006](006-policy-service.md)** — Policy service (the primary consumer of audit telemetry and the primary caller of `SYS_REVOKE_CAPABILITY`)
- **[CambiOS.md § AI Integration](../../CambiOS.md)** — Three pillars: security, compatibility, operations. The audit telemetry substrate enables Pillar 1 (Security AI)
- **[PHILOSOPHY.md](../../PHILOSOPHY.md) lines 73-99** — "AI watches without controlling" — this ADR provides the *something to watch*
- **[SECURITY.md § Gap Analysis](../../SECURITY.md#gap-analysis)** — Closes gap #5 (capability revocation) and provides the substrate for items "Audit logging" and "Runtime behavioral AI"

## See Also in CLAUDE.md

When implementing the changes specified by this ADR, the following CLAUDE.md sections must be updated to reflect the new architecture:

- **§ "Current state"** paragraph — note revocation primitive and audit channel
- **§ "Lock Ordering"** — no new lock added; revocation uses existing 4 → 5 → 6 sequence
- **§ "Syscall Numbers"** — add `SYS_REVOKE_CAPABILITY` and `SYS_AUDIT_INFO` when assigned
- **§ "Required Reading by Subsystem"** (when added) — under "If you are touching capability/policy code"
- **§ "Post-Change Review Protocol" Step 8** (when added) — adding new audit event types requires updating SECURITY.md and any docs that reference the audit format

## Divergence

Phase 3.3 implementation (2026-04-12) diverges from this ADR in three ways:

1. **Phase renamed from "Telemetry" to "Audit."** The word "telemetry" is culturally loaded (Windows telemetry, etc.) and invites misunderstanding for a project that is explicitly telemetry-free to the outside world. The module is `crate::audit`, events are "audit events", the channel is the "audit ring". The word "telemetry" still appears in this ADR's original text (immutable history) but all new code and docs use "audit".

2. **Global ring is kernel-internal, not a ChannelManager record.** The ADR specifies using "the channel mechanism from ADR-005." Implementation revealed that the kernel has no ProcessId, no Principal, and no VMA tracker — the channel state machine would require extensive special-casing. Instead, the ring is a dedicated `AuditRing` struct backed by contiguous physical pages allocated at boot. When the policy service attaches via `SYS_AUDIT_ATTACH`, those same physical pages are mapped RO into its address space — reusing the same `map_range` logic but bypassing `ChannelManager`. This preserves the ADR's intent (kernel produces, consumer reads RO) without architectural contortion.

3. **Drain via BSP timer ISR piggyback, not a dedicated background task.** The ADR mentions a "background task" for draining per-CPU staging buffers to the global ring. Implementation uses the BSP timer ISR (100 Hz) with `try_lock()` and a bounded batch size (`DRAIN_BATCH_SIZE = 64`). This avoids consuming a scheduler slot for what is essentially "copy 640 bytes every 10ms". If profiling shows the drain is too expensive for ISR context, it can be moved to a dedicated task without changing the `emit()` API or buffer layout.
