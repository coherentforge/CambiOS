# ADR-030: Stream as Cap Variant on Channels

- **Status:** Proposed
- **Date:** 2026-05-12
- **Depends on:** [ADR-028](028-three-storage-models.md) (Three Storage Models - the kernel-API discipline this ADR provides the Stream cap shape for), [ADR-005](005-ipc-primitives-control-and-bulk.md) (channel substrate Stream rides on as a cap variant), [storage-planning.md](../storage-planning.md) (the synthesis that named Stream as the third storage model)
- **Related:** [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (sender_principal stamping carries unchanged into Stream traffic), [ADR-027](027-service-clusters.md) (cluster cap inventories scope Stream caps; cluster revoke composes with Stream's force-close), [ADR-007](007-capability-revocation-and-telemetry.md) (audit ring carries the Stream lifecycle events; tombstone-on-revoke pattern composes with Stream force-close), [ADR-024](024-syscall-abi-crate.md) (`StreamCapShape` lives in `cambios-abi`), [ADR-014](014-compositor-scanout-driver-protocol.md) (rendering pipeline is the v1 Stream consumer; § Divergence 2026-04-20's double-copy pixel path is structurally a Stream)
- **Supersedes:** N/A
- **Context:** [ADR-028](028-three-storage-models.md) committed to three co-equal storage models and three seam syscalls; [ADR-029](029-posix-file-storage-model.md) provided the POSIX backend. This ADR provides the third leg: the Stream model's full kernel mechanics. ADR-028 reserved `SYS_STREAM = 50` and committed to "the Stream cap shape's full structure is deferred to ADR-030" - this ADR fills in `StreamCapShape`'s knobs (`consume`, `rewind_window`, `buffer_max`, `fan_out_count`, `lifetime_bytes`, `lifetime_duration`), specifies how each is checked at the kernel boundary, and ratifies the composition of Stream with [ADR-005](005-ipc-primitives-control-and-bulk.md) channels. The synthesis's Stream model is the architectural primitive behind the rendering pipeline ([ADR-014](014-compositor-scanout-driver-protocol.md) § Divergence 2026-04-20), signed-carrier input flows, NDA-bound document review, and IPC-layer ephemerality for content-protection workloads. This ADR makes that primitive load-bearing rather than implicit.

## Problem

ADR-028 named Stream as one of the three native storage models and stated its structural property ("bytes through this cap do not become addressable through this cap"). It deferred the mechanism. Four gaps motivate this ADR.

### Gap 1 - `StreamCapShape` is named but has no structure

ADR-028 § Decision 5 listed Stream cap knobs in prose - `consume`, `rewind_window`, `buffer_max`, `fan_out_count`, `lifetime_*` - without specifying types, units, validity constraints, or composition rules. `SYS_STREAM` takes a `StreamCapShape` argument that doesn't yet exist. Userspace clients (`libstream` per ADR-028) cannot build against the cap shape until it's specified. The synthesis's IPC-layer-ephemerality property is "cap-shape invariant, not a runtime check" - which requires the cap shape to be a concrete checkable structure.

### Gap 2 - The channel substrate composition is asserted but not detailed

ADR-028 § Architecture says "`StreamEndpoint` state lives in a new `StreamTable` parallel to the `ChannelManager`, with role-typed entries (Producer / Consumer / Bidirectional, matching channel role shape per ADR-005)." But Stream is one-way by ADR-028's § Decision 5 ("Stream is one-way by construction"). The Bidirectional role is structurally absent. The Producer / Consumer role assignment, the attach mechanics, the close mechanics, and the interaction with ADR-005's existing channel lifecycle all need explicit specification.

### Gap 3 - Backpressure semantics are unspecified

When a Stream sender produces bytes faster than receivers consume them, the kernel has to choose: block the sender, drop bytes, or fail the send. ADR-028 says "buffer_max: kernel-enforced ceiling on receiver-side buffering. Unbounded buffer = receiver has effectively captured." But what does "buffer is full" mean operationally? The synthesis's "lossless ephemerality" claim depends on this decision: drop-with-audit makes Stream best-effort, sender-blocks-when-full makes it lossless under the cap shape.

### Gap 4 - Lifetime exhaustion and force-close are undefined

`lifetime_bytes` and `lifetime_duration` are named but their kernel-side enforcement isn't. When the bound is exhausted, what happens? Sender's next write fails? Receivers see end-of-stream? Cluster cap inventories (ADR-027) need to know when a Stream cap is consumed-and-done versus still-active. Audit events fire at force-close - but which events, with what payload?

## The Reframe

> A **Stream cap** is a cap-shape annotation on top of an [ADR-005](005-ipc-primitives-control-and-bulk.md) channel that imposes structural ephemerality bounds: how many receivers may attach, how much they may buffer, whether they may rewind, when the kernel force-closes the flow. The channel substrate does the byte transport (memory-mapped page ring, sender-write + receiver-read, no kernel involvement on the hot path). The Stream cap shape constrains the *capability* the sender holds and the *capability* each receiver attaches with - not the per-byte flow. There is no per-byte kernel check; there is no Stream-specific data path. The ephemerality property falls out of "the kernel never gives the receiver a Capture or Demote handle, the channel pages are unmapped on Stream close, and the cap shape's bounds were enforced at the boundary events (open, attach, close)."

The reframe is the cap-shape duality from [ADR-026](026-identity-transcription-at-the-kernel-ring.md) and the channel-as-substrate posture from [ADR-005](005-ipc-primitives-control-and-bulk.md) composed: a Stream is what the channel is *when its cap shape declares it ephemeral*. There is no separate Stream data path. The kernel mediates the boundary (open, attach, send-permission, close); the channel substrate carries the bytes at memory bandwidth between the boundary events.

## Decision

Five commitments. They are co-dependent: each makes the others coherent.

### 1. `StreamCapShape` - the full cap-shape structure

```rust
// In cambios-abi (per ADR-024):
pub struct StreamCapShape {
    /// Required for any Stream cap. Without this, the cap is not a Stream cap.
    pub consume: bool,

    /// Maximum backward-seek window in bytes from current read position.
    /// 0 = pure forward-only stream; >0 = receiver may re-read up to N bytes back.
    /// The bound is the integrity boundary: rewind_window = MAX_STREAM_RECEIVER_BUFFER
    /// effectively gives the receiver a full buffer of replayable bytes, which the
    /// synthesis calls "captured." Cap creator picks the bound at open time.
    pub rewind_window: u64,

    /// Maximum receiver-side buffering, in bytes. Parameterizes the channel
    /// substrate's flow-control watermark (per ADR-005); the kernel allocates
    /// at least one page (BLOCK_SIZE) regardless, since the channel substrate
    /// is a memory-mapped page ring.
    /// 0 = zero-buffer flow control: sender's next write blocks until the
    /// previous write has been fully drained by the receiver. Used for
    /// tightly-coupled rendering pipelines where frame-N+1 should not begin
    /// until frame-N is consumed. The kernel still allocates one page.
    /// >0 = receiver may hold up to N bytes in flight before sender blocks.
    /// Unbounded is forbidden; the cap shape rejects at open if
    /// buffer_max > MAX_STREAM_RECEIVER_BUFFER SCAFFOLDING bound.
    pub buffer_max: u64,

    /// Maximum simultaneous receivers. Slot is reclaimed when a receiver detaches.
    /// 1 = one-shot stream (single consumer). >1 = fan-out (audio system might want
    /// 1-to-N for multiple output devices; rendering pipeline is 1-to-1). Max bounded
    /// by MAX_STREAM_FAN_OUT SCAFFOLDING.
    pub fan_out_count: u32,

    /// Total bytes the sender may transmit before kernel force-closes the stream.
    /// 0 = unbounded (use lifetime_duration or sender-driven close). >0 = kernel
    /// closes the stream when the cumulative byte count reaches the bound.
    pub lifetime_bytes: u64,

    /// Maximum stream duration in monotonic ticks before kernel force-closes.
    /// 0 = unbounded (use lifetime_bytes or sender-driven close). >0 = kernel
    /// closes the stream when (now - stream_opened_at) >= bound.
    pub lifetime_duration: u64,

    /// Emit AUDIT_STREAM_OPEN / AUDIT_STREAM_CLOSE events. Per-byte audit is
    /// structurally absent (that would defeat ephemerality). Open / attach /
    /// close are auditable; the flow is not.
    pub audit_lifecycle: bool,

    /// If true, the kernel verifies sender_principal == cap creator's Principal
    /// on each SYS_CHANNEL_WRITE. Used for signed-carrier flows where the sender's
    /// identity is load-bearing per byte. Adds a per-send cap check; off by default.
    pub sender_principal_required: bool,
}
```

**Validity constraints** (checked at `SYS_STREAM` open):

- `consume` MUST be true. A `StreamCapShape` with `consume = false` is not a Stream cap and rejected with `EINVAL`.
- When `buffer_max == 0` (zero-buffer flow control), `rewind_window` MUST also be 0. Zero-buffer flow control retains no history because the producer blocks on every write until the previous is fully drained; there is no surviving window of past bytes to rewind into. Rejected with `EINVAL`. Otherwise `rewind_window` and `buffer_max` are independent dimensions: the channel substrate sizes the ring as `buffer_max + rewind_window` (in-flight headroom plus rewindable history) per Decision 2, so a cap shape may declare more rewindable history than in-flight buffer if the workload wants it.
- `rewind_window <= MAX_STREAM_RECEIVER_BUFFER` SCAFFOLDING (rewindable history is bounded by the same per-receiver memory ceiling that bounds the in-flight buffer).
- `buffer_max <= MAX_STREAM_RECEIVER_BUFFER` SCAFFOLDING (set to 16 MiB for v1 - sized to cover 4K @ 60 fps uncompressed pixel flow with 1 frame of buffering; raise when a workload exceeds it).
- `fan_out_count >= 1 && fan_out_count <= MAX_STREAM_FAN_OUT` SCAFFOLDING (set to 16 for v1 - covers audio fan-out to multiple output devices, rendering pipeline broadcast to multiple displays; replace when a workload exceeds it).
- `lifetime_bytes == 0 || lifetime_bytes <= MAX_STREAM_LIFETIME_BYTES` SCAFFOLDING (set to 4 TiB for v1, matching `MAX_CAMBIO_CONTENT_BYTES`; a single Stream cap can move up to a full content-sized payload).
- `lifetime_duration == 0 || lifetime_duration <= MAX_STREAM_LIFETIME_DURATION_TICKS` SCAFFOLDING (set to 100Hz × 86400 = 8_640_000 ticks = 24 hours; long-running streams renegotiate caps daily).
- If both `lifetime_bytes == 0 && lifetime_duration == 0`, the cap is unbounded by lifetime - it lives until sender-driven close or all-receivers-detached. Permitted; the `STREAM_OPENED` audit event's payload includes a `cap_shape_unbounded: bool` discriminant that fires for this case.

The `StreamCapShape` is part of the syscall ABI (`cambios-abi` per [ADR-024](024-syscall-abi-crate.md)) and carries no public-field-access constructors - userspace clients build it through a `StreamCapShapeBuilder` that runs the validity checks before the syscall is issued, so invalid shapes are caught at compile/link time on the client side rather than at syscall entry.

### 2. Knob enforcement at the kernel boundary

Enforcement is concentrated at boundary events (open, attach, send-permission, close), not at the per-byte flow. The channel substrate handles bytes at memory bandwidth between events.

| Event | Knob checks |
|---|---|
| `SYS_STREAM` open | All Decision-1 validity constraints. Plus: sender's cap-set must permit the proposed cap (no escalation - a sender cannot create a Stream with `lifetime_bytes` higher than their own outbound-data budget per cluster policy if cluster policy enforces such a budget). Channel record per [ADR-005](005-ipc-primitives-control-and-bulk.md) is created with the Stream cap shape attached to its kernel-side record. |
| `SYS_CHANNEL_ATTACH` (receiver side) | Receiver's cap-shape must accept the offered bounds (a receiver that expects forward-only cannot attach to a stream with `rewind_window > 0` if their cap-shape declares forward-only; mismatched shapes return `EINVAL`). Active-receiver-count is incremented; if it would exceed `fan_out_count`, the attach is rejected with `EBUSY`. |
| `SYS_CHANNEL_WRITE` (sender) | Kernel checks: (a) `bytes_sent.checked_add(write_size)` against `lifetime_bytes` (if > 0); arithmetic uses checked/saturating ops so adversarial inputs cannot overflow the comparison. If exhausted, the kernel transitions the stream to `Closing` with `CloseReason::LifetimeBytesExhausted` and returns `EPIPE`. (b) duration check: `now - stream_opened_at <= lifetime_duration` (if > 0); else transition to `Closing` with `CloseReason::LifetimeDurationExhausted` and return `EPIPE`. (c) if `sender_principal_required`, kernel-stamped `sender_principal` must equal the cap creator's Principal; else `EACCES`. Note: this is a per-write 32-byte equality check on the data path; workloads that do not need per-byte sender identity should leave the flag off (see Threat Model note). (d) `buffer_max` enforcement: the channel substrate's flow-control mechanism (ADR-005 § Channel flow control) handles this; the cap shape's `buffer_max` parameterizes the channel's flow-control watermark at open time, so per-byte enforcement is the channel substrate's existing path with the right parameter, not new code. |
| `SYS_CHANNEL_READ` (receiver) | If `rewind_window > 0`, receiver may seek backward up to `rewind_window` bytes from current read position; the kernel verifies the seek target is within the bounded window. Seeking beyond the window returns `EINVAL`. Seeks forward beyond what the sender has written return `EAGAIN`. **Wraparound semantics:** the channel substrate retains the last `rewind_window` bytes in addition to the in-flight buffer, so the effective ring size from the producer's perspective is `buffer_max + rewind_window` (rounded up to page granularity). Producer's flow-control watermark is `receiver_current_read_position - rewind_window`; producer blocks when reaching that watermark, ensuring rewind targets are always present in the ring. Backward seek never returns "bytes already overwritten" because the producer cannot overwrite within the rewind region. |
| Stream close (sender-driven, lifetime-exhausted, or all-receivers-detached) | Kernel marks the stream record `Closing` and passively waits up to `STREAM_DRAIN_TIMEOUT_TICKS = 50` SCAFFOLDING for receivers to call `SYS_CHANNEL_READ` on their own and consume remaining in-flight bytes. The kernel does not pump bytes - it just leaves the channel mapped and lets the receiver drain. After the timeout (or when all in-flight bytes are consumed, whichever comes first), the kernel atomically unmaps the channel pages from all receivers per [ADR-005](005-ipc-primitives-control-and-bulk.md)'s channel-revoke + [ADR-007](007-capability-revocation-and-telemetry.md) Divergence 7 tombstone pattern. |

No per-byte kernel check on the data path. The cap shape parameterizes the channel substrate at open time; the substrate carries bytes at memory bandwidth between boundary events.

### 3. Channel substrate composition - Producer-only, one-way, no Bidirectional

Stream is one-way by ADR-028 § Decision 5. The composition with [ADR-005](005-ipc-primitives-control-and-bulk.md)'s channel role model:

- **Sender** holds a Producer-role channel handle. The Stream cap is the Producer's cap. The sender writes bytes via `SYS_CHANNEL_WRITE` per ADR-005's existing path; the cap shape parameterizes the write path's enforcement.
- **Receiver(s)** hold Consumer-role channel handles, up to `fan_out_count` of them. Each Consumer attaches via `SYS_CHANNEL_ATTACH` per ADR-005's existing path; the attach is gated on cap-shape compatibility (Decision 2) and on `active_receiver_count < fan_out_count`.
- **Bidirectional is absent.** A Stream is structurally one-way. The kernel does not create a Stream from a Bidirectional channel; `SYS_STREAM` rejects an attempt to base a Stream on a Bidirectional cap with `EINVAL`.

The channel substrate carries the bytes through the existing memory-mapped page ring; the kernel touches the bytes only at boundary events. ADR-005 § "Channel state" requires no changes; the Stream cap shape is an additional field on the channel record:

```rust
// In src/ipc/channel.rs (existing ChannelRecord, with Stream extension):
pub struct ChannelRecord {
    // ... existing fields per ADR-005
    pub stream_cap_shape: Option<StreamCapShape>,
}
```

`Option<StreamCapShape>` because not every channel is a Stream - control-IPC channels, audio-driver channels with no ephemerality bounds, etc. continue to exist as plain channels per ADR-005. A channel is a Stream iff `stream_cap_shape.is_some()`.

### 4. Lifecycle - session-scoped, no persistence across process restart

Stream lifecycle:

1. **Open.** Sender calls `SYS_STREAM(source, peer_principal, cap_shape)`. Kernel validates cap shape, creates a channel record (per ADR-005) with `stream_cap_shape = Some(cap_shape)`, allocates channel pages, returns `StreamEndpoint` (Producer side) to sender and queues channel ID for receiver attach.
2. **Attach.** Receiver calls `SYS_CHANNEL_ATTACH(channel_id, expected_cap_shape)`. Kernel validates the receiver's expected cap shape matches what the sender offered (Decision 2). Maps channel pages into receiver's address space. Increments `active_receiver_count`.
3. **Stream traffic.** Sender writes via `SYS_CHANNEL_WRITE`; receivers read via `SYS_CHANNEL_READ`. Bytes flow through the memory-mapped ring. Kernel checks lifetime exhaustion at every write per Decision 2.
4. **Detach.** A Consumer calls `SYS_CHANNEL_DETACH`. Decrements `active_receiver_count`. If 0, the stream may force-close (Decision 5 of [ADR-027](027-service-clusters.md)'s revoke pattern applied: the Stream record transitions to `Closing` and unmaps from the sender). Sender can poll for "all receivers detached" via `SYS_CHANNEL_INFO`.
5. **Close.** Three triggers: (a) sender calls `SYS_CHANNEL_CLOSE` explicitly; (b) lifetime bound exhausted (Decision 2); (c) all receivers detached. In all three, the kernel marks the stream `Closing` and passively waits up to `STREAM_DRAIN_TIMEOUT_TICKS` for receivers to drain remaining in-flight bytes via their own `SYS_CHANNEL_READ` calls. The kernel does not pump bytes during drain. After the timeout (or earlier if drain completes), the kernel unmaps channel pages from every endpoint via ADR-005's channel revoke + ADR-007 Divergence 7 tombstone pattern. The `StreamEndpoint` and `Consumer` handles become invalid; subsequent reads/writes return `EPIPE`.

**Session-scoped, not persistent.** A Stream does not survive past the sender process's exit. If the sender dies mid-stream, the kernel detects (per the existing process-fault reaping per [ADR-019](019-process-fault-reaping-and-peer-generation.md)) and triggers the close path. Receivers see `EPIPE`. A future workload that wants cross-restart Stream persistence would require an additional ADR; v1 does not.

**Sender-driven close is the common case.** Lifetime-exhausted is the rare case (cap was over-provisioned and the workload didn't use the full bound). All-receivers-detached is the rendering-pipeline case (consumer process exits cleanly).

### 5. Audit + identity composition

Stream's identity story is inherited unchanged from [ADR-026](026-identity-transcription-at-the-kernel-ring.md):

- `sender_principal` is kernel-stamped on every `SYS_CHANNEL_WRITE` from the sender. Receivers see the kernel-stamped value via the message-receive structure per ADR-005. No new identity machinery.
- If `sender_principal_required` is set in the cap shape, the kernel additionally verifies the stamped value equals the cap creator's Principal on every write. This is for signed-carrier flows where the sender's identity is per-byte load-bearing (a trusted-tier input device's `sender_principal` must match the cap's expected value for every input event the kernel injects into the stream).

Audit events fire at lifecycle boundaries, not per-byte:

| Event | When | Payload |
|---|---|---|
| `STREAM_OPENED` | `SYS_STREAM` succeeds | sender Principal, cap shape (truncated), channel ID, source descriptor, `cap_shape_unbounded: bool` (true when both lifetime bounds are 0 per Decision 1) |
| `STREAM_ATTACHED` | `SYS_CHANNEL_ATTACH` succeeds on a Stream channel | receiver Principal, channel ID, active_receiver_count after attach |
| `STREAM_DETACHED` | `SYS_CHANNEL_DETACH` on a Stream | receiver Principal, channel ID, active_receiver_count after detach |
| `STREAM_CLOSED` | close completes from any trigger (sender, lifetime-exhausted, all-detached, kernel force) | channel ID, `reason: CloseReason`, total bytes_sent, total duration_ticks, drain_completed_or_timed_out |

The `CloseReason` enum on `STREAM_CLOSED` carries the distinction between sender-driven close, lifetime exhaustion (either bound), all-receivers-detached, and kernel-forced close. One event covers all close paths; no separate `STREAM_LIFETIME_EXHAUSTED` or `STREAM_FORCE_CLOSED` events.

Per-byte-flow audit is structurally absent. Auditing every write would defeat the ephemerality property by making the audit ring a parallel record of the stream's contents. The cap shape's `audit_lifecycle` field is the on/off switch for the events above; if false, only `STREAM_OPENED` is forced (an open event is always auditable for compliance) and the rest are suppressed.

**Cluster cap inventories** ([ADR-027](027-service-clusters.md)): a Stream cap held by a cluster member is part of the member's cap inventory. Cluster revoke ([ADR-027](027-service-clusters.md) § Decision 3) walks the cluster's member list and revokes their caps, which for Stream caps means the stream is force-closed (the channel revoke runs the unmap, audit event fires, sender and receivers see `EPIPE`). The cluster-revoke and Stream-close mechanisms share the same kernel paths; no new code beyond Stream's cap-table integration.

## Architecture

### Kernel state (incremental on top of ADR-005)

```rust
// In src/ipc/channel.rs (ChannelRecord, extended):
pub struct ChannelRecord {
    // ... existing fields per ADR-005 (channel_id, role, peer_principal,
    //     producer_pid, consumer_pids, frame_buffer_lba, etc.)
    pub stream_cap_shape: Option<StreamCapShape>,
    pub stream_state: Option<StreamState>,
}

pub struct StreamState {
    pub opened_at_tick: u64,
    pub bytes_sent: u64,
    pub active_receiver_count: u32,
    pub state: StreamLifecycleState,
}

pub enum StreamLifecycleState {
    Active,
    Closing { reason: CloseReason, drain_deadline_tick: u64 },
    Closed,
}

pub enum CloseReason {
    SenderClosed,
    LifetimeBytesExhausted,
    LifetimeDurationExhausted,
    AllReceiversDetached,
    KernelForce { audit_ref: AuditEventId },
}
```

No new top-level lock. `stream_cap_shape` and `stream_state` are fields on the existing `ChannelRecord`; modifications go through `CHANNEL_MANAGER(6)` per the existing channel lock placement. No `STREAM_TABLE` separate from the channel table - Streams ARE channels with the cap shape attached.

### Bounded iteration claims (for verification)

- **`fan_out_count` bound** is checked at `SYS_CHANNEL_ATTACH`; the attach increments `active_receiver_count` and rejects if it would exceed `fan_out_count`. Constant-time check; no iteration.
- **Lifetime bound checks** at `SYS_CHANNEL_WRITE` are constant-time additions and comparisons; no iteration.
- **`STREAM_DRAIN_TIMEOUT_TICKS = 50`** (SCAFFOLDING) bounds the close path's drain wait: kernel waits up to 50 ticks (500ms at 100Hz) for receivers to drain in-flight bytes before unmapping. The wait is a bounded sleep, not an iteration.
- **All `MAX_STREAM_*` SCAFFOLDING bounds** carry the Convention 8 doc comment and land in [ASSUMPTIONS.md](../ASSUMPTIONS.md) when the implementation lands.

### CAMBIO interaction (not applicable)

Stream does not interact with CAMBIO. Stream sources are CambiObjects or POSIX files (per ADR-028's `StreamSource` enum), but the source's storage backend is read-only from the Stream's perspective - Stream reads bytes from the source, streams them through the channel, and never modifies the source. The CAMBIO interaction model from ADR-029 applies to the source side if the sender wants to seal the streamed content; the seal happens through `SYS_CAMBIO` independently of the Stream.

### Capability checks

| Stream operation | Cap chain |
|---|---|
| `SYS_STREAM` (open) | `Read(source)` (CambiObject or FileDescriptor); `ChannelCreate` (per ADR-005); cap-shape validity (Decision 1). If the sender belongs to a cluster whose policy declares an outbound-data budget per ADR-027, the kernel checks `lifetime_bytes` against that budget; otherwise no general cap-set-vs-cap-shape check applies. |
| `SYS_CHANNEL_ATTACH` (receiver) | Receiver's cap-shape matches sender's offered shape; `active_receiver_count < fan_out_count` |
| `SYS_CHANNEL_WRITE` | Lifetime bound not exhausted; if `sender_principal_required`, sender's stamped Principal matches cap creator |
| `SYS_CHANNEL_READ` | If seeking backward, target within `rewind_window` of current position |
| `SYS_CHANNEL_DETACH` | None beyond ADR-005's existing checks |
| `SYS_CHANNEL_CLOSE` | Caller is sender, or holds cluster-revoke cap for a cluster the stream belongs to (per ADR-027) |

No new `CapabilityKind`. The composition is the discipline - Stream's `consume` flag plus the cap-shape parameters drive the kernel-side enforcement of existing channel mechanics.

## Threat Model

### What this ADR protects against

| Threat | Mitigation |
|---|---|
| Receiver buffers unbounded bytes to evade the ephemerality property | `buffer_max` cap-shape bound; channel substrate's flow control parameterized at open time; receiver cannot exceed the cap. Unbounded `buffer_max` is rejected at open per Decision 1. |
| Receiver rewinds past the bounded window to re-read consumed bytes | `rewind_window` cap-shape bound; kernel verifies seek target on every `SYS_CHANNEL_READ` backward seek. |
| Sender extends a Stream beyond its declared lifetime | `lifetime_bytes` + `lifetime_duration` checked at every write; kernel force-closes when exceeded, emits audit event. |
| Receiver count exceeds the cap-declared bound | `fan_out_count` checked at every attach; rejected when full. |
| Sender impersonates a different Principal mid-stream | `sender_principal_required` flag verifies kernel-stamped `sender_principal` per write when the workload requires per-byte sender identity (signed-carrier flows). |
| Per-byte traffic leaks via the audit ring | Audit fires only at lifecycle events; per-byte audit is structurally absent. The cap shape's `audit_lifecycle` flag controls everything except `STREAM_OPENED` (which is always audited for compliance). |
| Bidirectional Stream re-introduces capture via the reverse direction | `SYS_STREAM` rejects Bidirectional channels with `EINVAL`. A Stream is structurally one-way; the reverse direction does not exist as a kernel surface. |
| Process-fault leaves a Stream half-open | The existing process-fault reaping per ADR-019 detects sender or receiver exit; the close path runs automatically; pages unmap; audit fires. |

### What this ADR does NOT protect against

| Risk | Mitigation |
|---|---|
| Receiver with independent write caps copies the consumed bytes to a separate POSIX file | Out of scope for the Stream cap itself per ADR-028 § Decision 5. Full "bytes never persist anywhere" containment composes Stream cap with deployment-level sandboxing (receiver's cap inventory excludes write caps anywhere) via ADR-027 cluster scoping or win-compat sandboxed Principals. |
| Sender colludes with receiver to leak Stream content via a side channel (out-of-band IPC, shared memory granted independently of the Stream) | Out of scope. The Stream cap constrains the Stream's substrate; it does not constrain whatever other caps sender and receiver independently hold. If two cooperating processes have other channels between them, what they exchange is between them. Same posture as ADR-005's "what channels do not protect against." |
| Receiver attaches but never reads, holding a `fan_out_count` slot indefinitely | Out of scope for v1. A malicious receiver attached to a `fan_out_count = 1` Stream can DoS the sender by never consuming. v1 does not include an idle-timeout mechanism. The intended deployment posture (cluster-scoped receivers, sandboxed Principals) typically guarantees consuming behavior at the deployment layer. See Open Questions / Deferred for the `idle_timeout_ticks` cap-shape knob proposal. |
| Receiver records the rendered output (camera at the screen, microphone at the speakers) | Out of scope - the analog-hole bypass that ADR-028 acknowledges as the only remaining capture vector under Stream + sandboxed receiver. CambiOS does not address external physical capture. |
| Stream lifetime bound is set too high by a careless sender | Cap-shape validation rejects bounds exceeding `MAX_STREAM_LIFETIME_*` SCAFFOLDING, but within those bounds the sender's choice is honored. Userspace policy (cluster manifests, posix-fs-service shim) may impose tighter limits than the kernel enforces. |

### Impact on existing threats

- [ADR-005](005-ipc-primitives-control-and-bulk.md)'s channel threat model continues to apply unchanged for Stream's substrate. Stream is a cap-shape annotation; it does not weaken any channel guarantee.
- [ADR-007](007-capability-revocation-and-telemetry.md)'s revocation pattern: Stream force-close runs the existing channel revoke path. The Divergence 7 tombstone pattern composes - on Stream close, peer mappings are tombstoned, receivers reap on next `SYS_CHANNEL_INFO` poll.
- [ADR-026](026-identity-transcription-at-the-kernel-ring.md)'s transcription invariant: `sender_principal` stamping is unchanged. Stream's `sender_principal_required` is a per-write equality check, not interpretation; the kernel verifies the stamped value against the expected value and accepts or rejects, but does not interpret the Principal's semantics.
- [ADR-027](027-service-clusters.md)'s cluster-scoped cap inventories: a Stream cap held by a cluster member participates in cluster revoke. The revoke path force-closes the Stream as part of the cluster's atomic teardown.

## Verification Stance

The kernel surface is the verification target. Five distinct claims:

- **Cap-shape validity.** Every `SYS_STREAM` call's `StreamCapShape` argument either passes Decision 1's validity constraints (closed enum of checks) or returns `EINVAL`. Kani target: "no `SYS_STREAM` returns success for a `StreamCapShape` violating any Decision-1 constraint."
- **Fan-out boundedness.** `active_receiver_count <= fan_out_count` is an invariant maintained across all attach/detach paths. Kani target: "for every channel record where `stream_cap_shape.is_some()`, `stream_state.active_receiver_count <= stream_cap_shape.fan_out_count` at every reachable state."
- **Lifetime enforcement.** Every `SYS_CHANNEL_WRITE` to a Stream channel either passes both bound checks - `lifetime_bytes == 0 || bytes_sent.checked_add(write_size).map_or(false, |t| t <= lifetime_bytes)` and `lifetime_duration == 0 || now - opened_at <= lifetime_duration` - or the kernel transitions the stream to `Closing` and returns `EPIPE`. Kani target: "no write to a Stream channel succeeds after a lifetime bound is exhausted; the transition to `Closing` is total and irreversible; the bytes-sent comparison uses checked arithmetic so adversarial `write_size` inputs cannot overflow into a false-positive pass."
- **Rewind bound.** Every backward `SYS_CHANNEL_READ` seek has target within `rewind_window` of current read position, else `EINVAL`. Kani target: a closed-world check on the seek-target arithmetic.
- **Bidirectional absent.** `SYS_STREAM` rejects Bidirectional channels at open. Kani target: "for every channel record where `stream_cap_shape.is_some()`, `role != ChannelRole::Bidirectional`."

The verification surface delta vs. existing kernel: small. Stream is a cap-shape annotation on the existing channel substrate; no new lock, no new state machine beyond the three-state `StreamLifecycleState` enum (Active / Closing / Closed). The per-byte data path is the existing ADR-005 channel path with parameterized flow-control watermarks. The boundary-event enforcement is a handful of cap-shape constraint checks.

## Why Not Other Options

### Option A: Stream as a separate kernel substrate (not a channel cap variant)

Build a parallel data path for Stream traffic that doesn't share channel mechanics.

**Why considered.** Stream's ephemerality property could be enforced more aggressively at the kernel level if Stream owned its own substrate (per-byte audit at kernel discretion, mandatory zeroing on close, etc.).

**Why rejected.** The channel substrate per ADR-005 already provides the byte-transport mechanism at memory bandwidth between boundary events. A parallel substrate is redundant code, redundant verification surface, and forces the kernel onto the per-byte path - which is the very thing ADR-005 spent design effort getting off. Stream's structural property is in the cap shape, not in the data path; building a separate data path conflates them.

### Option B: Make Stream cap shape mutable post-open (renegotiable)

Allow the sender to widen or narrow the cap-shape bounds after the Stream is open. A workload that needs more lifetime can ask for more; a workload that wants to reduce buffering can tighten.

**Why considered.** Sender-driven adaptive caps could simplify userspace - the cap creator does not have to predict the exact bounds at open time.

**Why rejected.** Mutable cap shapes break the synthesis's "cap-shape invariant" property. If the sender can widen `lifetime_bytes` arbitrarily, the receiver's structural-ephemerality guarantee depends on the sender's restraint, not on the cap shape. The fix - "the receiver must reject widening" - moves the enforcement to the receiver, which defeats the kernel-side guarantee. Stream caps are immutable post-open; if the workload outgrows them, the sender closes and reopens with a wider cap.

### Option C: Defer the cap shape's full structure; ship `consume`-only in v1

A minimal `StreamCapShape { consume: bool }` would deliver the synthesis's "this is a Stream cap, not a regular channel" property without the bound knobs. Add `rewind_window`, `buffer_max`, etc. when workloads demand them.

**Why considered.** Smaller initial surface. Faster path to landing some form of Stream cap. The bound knobs are speculative until a workload measures need.

**Why rejected.** Without `buffer_max`, the receiver-buffering attack (Decision 1, Threat Model row 1) is trivial - receiver buffers unboundedly and the ephemerality property is gone. The bound knobs are not optional; they are what make the cap-shape invariant hold. `consume`-only is the same shape as a regular ADR-005 channel with a "this is a Stream" annotation that does nothing - which is precisely what the synthesis excluded as "userspace convention, not kernel guarantee."

### Option D: Make per-byte audit configurable rather than structurally absent

Allow workloads to opt into per-byte audit if the privacy concern is outweighed by the audit-trail requirement (forensics, legal holds, etc.).

**Why considered.** Some compliance regimes might genuinely want a full audit log of every byte streamed.

**Why rejected.** Per-byte audit defeats the ephemerality property by making the audit ring a parallel record of the stream contents. The synthesis is emphatic that Stream is for workloads where the bytes should not be addressable post-flow; an audit log that records the bytes is addressable storage of the bytes. Workloads that want full audit should not use Stream - they should use CAMBIO + ObjectStore, where every audit-eligible record is addressable by hash. The mismatch between "audit every byte" and "no byte persists" is structural, not configurable.

### Option E: Defer this ADR until a v1 workload demonstrates need

ADR-014's rendering pipeline is the canonical v1 Stream consumer; the audio-driver case is downstream; signed-carrier input is signed-carrier-hardware-dependent. Ship v1 with the rendering pipeline using ADR-005 channels directly and add the Stream cap shape when the second consumer arrives.

**Why considered.** YAGNI. The kernel surface stays smaller; verification budget stays smaller.

**Why rejected.** ADR-028 already named `SYS_STREAM = 50` and committed to the cap-shape concept. Shipping without ADR-030 leaves `SYS_STREAM` partially specified - a `StreamCapShape` argument with no structure, no validity rules, no enforcement semantics. The kernel cannot accept the syscall in a meaningful way. Either ADR-028's `SYS_STREAM` commitment is walked back (the ADR is amended to drop the cap shape concept), or ADR-030 lands to give the cap shape a structure. ADR-028 already shipped; ADR-030 lands.

## Migration Path

Documentation + reservation first, implementation depends on the channel substrate already being mature.

1. **Land this ADR as `Proposed`.** No code touched. `StreamCapShape` structure, knob enforcement, channel composition, lifecycle, and audit semantics are now citeable.
2. **`cambios-abi` extension.** Add `StreamCapShape`, `StreamLifecycleState`, `CloseReason` to `cambios-abi` per ADR-024. Opaque builder API for userspace clients with compile-time validity checks. No kernel handlers yet.
3. **`ChannelRecord` extension.** Add `stream_cap_shape: Option<StreamCapShape>` and `stream_state: Option<StreamState>` to `src/ipc/channel.rs`. Default `None` for existing channels. No behavior change - existing channel paths (control-IPC, audio driver, etc.) ignore `stream_cap_shape = None` and execute their existing logic; only paths that explicitly check `stream_cap_shape.is_some()` adopt Stream-aware behavior.
4. **`SYS_STREAM` handler.** Implements Decision 1 validity checks + channel record creation + cap-shape attach. Returns `StreamEndpoint`.
5. **`SYS_CHANNEL_ATTACH` extension.** Stream-aware attach: cap-shape match check, fan-out count increment + bound check.
6. **`SYS_CHANNEL_WRITE` extension.** Stream-aware write: lifetime bound check, sender-principal-required check, flow-control parameterized by `buffer_max`.
7. **`SYS_CHANNEL_READ` extension.** Stream-aware read: rewind-window seek validation.
8. **Stream close path.** Sender-close, lifetime-exhausted, all-receivers-detached triggers; drain timeout; tombstone unmap per ADR-007 Divergence 7.
9. **Audit integration.** `STREAM_OPENED`, `STREAM_ATTACHED`, `STREAM_DETACHED`, `STREAM_CLOSED { reason: CloseReason, ... }` events per Decision 5's consolidated table.
10. **ADR-014 § Divergence 2026-04-20 alignment.** The rendering pipeline's existing double-copy pixel path becomes a `StreamCapShape { consume: true, rewind_window: 0, buffer_max: 1_FRAME_BYTES, fan_out_count: NUM_DISPLAYS, lifetime_bytes: 0, lifetime_duration: 0, audit_lifecycle: false, sender_principal_required: false }` at the compositor → scanout-driver boundary. The pixel path's existing audit footprint stays unchanged (no per-frame audit was happening anyway). Compositor → scanout streams are intentionally `cap_shape_unbounded` per Decision 1; the cluster lifecycle (rendering limb per ADR-027) bounds them externally — when the cluster is revoked, the stream is force-closed as part of the atomic teardown.
11. **`libstream` userspace library.** Wraps `SYS_STREAM` + `SYS_CHANNEL_ATTACH` + cap-shape builder for ergonomic consumer use. Per ADR-028's Userspace module structure.

Each step independently bisectable. Steps 1-3 are pre-implementation; steps 4-11 chain through actual code.

## Cross-References

- **[ADR-028](028-three-storage-models.md)** - The kernel-API discipline this ADR provides the Stream cap shape for; `SYS_STREAM = 50` reservation lives there.
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** - Channel substrate Stream rides on; ADR-030 extends `ChannelRecord` with `stream_cap_shape`.
- **[storage-planning.md](../storage-planning.md)** - The synthesis the Stream model comes from; ADR-030 fills in the cap-shape structure the synthesis sketched.
- **[ADR-024](024-syscall-abi-crate.md)** - `cambios-abi` is where `StreamCapShape` and related types live.
- **[ADR-026](026-identity-transcription-at-the-kernel-ring.md)** - `sender_principal` stamping carries unchanged; Stream's `sender_principal_required` is per-write equality, not interpretation.
- **[ADR-027](027-service-clusters.md)** - Cluster cap inventories scope Stream caps; cluster revoke composes with Stream force-close.
- **[ADR-007](007-capability-revocation-and-telemetry.md)** - Audit ring carries Stream lifecycle events; Divergence 7 tombstone pattern composes with Stream's close path.
- **[ADR-014](014-compositor-scanout-driver-protocol.md)** - Rendering pipeline is the v1 Stream consumer per § Divergence 2026-04-20; the compositor → scanout-driver pixel flow becomes a Stream at step 10.
- **[ADR-019](019-process-fault-reaping-and-peer-generation.md)** - Process-fault reaping triggers Stream close when sender or receiver exits.
- **[ADR-029](029-posix-file-storage-model.md)** - Stream sources from POSIX files use the FileDescriptor `backing` tag; the read path is the same as any POSIX read.

## See Also in CLAUDE.md

When this ADR's implementation lands, the following CLAUDE.md sections must be updated:

- **§ "Required Reading by Subsystem"** - add a row for "Stream cap shape / ephemerality / cap-bounded byte flow" pointing at this ADR, storage-planning.md, ADR-028.
- **§ "Syscall Numbers"** - `SYS_STREAM` (50) already reserved per ADR-028; gains its handler when this ADR's migration step 4 lands.
- **§ "Lock Ordering"** - no changes (Stream lives under `CHANNEL_MANAGER(6)` per ADR-005's existing placement).
- **§ "Design Documents"** - already updated when ADR-028 landed; no additional entries needed.

## Open Questions / Deferred

> **Deferred decision.** Whether Stream caps survive process restart for trusted long-running flows (a sensor stream that must persist across the sensor driver's quarantine and respawn). v1 is strictly session-scoped per Decision 4; restart-survival would require the cap shape to declare durability and the kernel to persist the stream record + replay the channel pages, which is a substantial expansion. **Revisit when:** a v1 workload (signed-carrier sensor flow, long-running audio session) demonstrates the need; the post-v1 reframe is "Stream durability" as an additional cap-shape knob.

> **Deferred decision.** Whether `fan_out_count` slot reclamation on detach is monotonic (slot-once-used-stays-burned) or reclaimable (detach frees the slot). v1 leans reclaimable to support the rendering-pipeline reconnect-after-crash case (the renderer dies, respawns, re-attaches without needing a new cap), but the alternative (monotonic) has a cleaner verification claim because `active_receiver_count` only grows. **Revisit when:** a workload's behavior depends on the choice; if monotonic is cleaner under Kani, the v1 stance flips.

> **Deferred decision.** Whether the cap-shape builder validation runs at compile time (via const fn or const generics) or at runtime in the userspace library. Compile-time validation gives stronger guarantees but constrains the ergonomic API; runtime validation is more flexible. Lean compile-time for the simple constraints (`consume == true`, `fan_out_count >= 1`, single-field SCAFFOLDING upper bounds), runtime for the conditional `buffer_max == 0 ⇒ rewind_window == 0` rule (which requires reading two fields together). **Revisit when:** the `libstream` library is implemented and the constraint set is final.

> **Deferred decision.** Whether per-receiver cap shapes are independent (each receiver attaches with its own shape, kernel honors the most restrictive bound) or unified (the sender's shape applies to all receivers). v1 is unified - the sender declares the shape at open, every receiver attaches with the same shape. The per-receiver variant would support "Stream is open with rewind_window=1024 globally, but this particular receiver has rewind_window=0 because their cap policy is tighter," which is a real win-compat use case. **Revisit when:** a workload needs per-receiver tighter bounds without the kernel needing to track multiple shapes per channel.

> **Deferred decision.** Whether Stream's `audit_lifecycle` flag interacts with cluster-scoped audit policy (ADR-027 might want to enforce audit on all member streams regardless of cap-shape preference). v1 honors the cap-shape flag; cluster overrides are a future ADR-027 Divergence appendix concern. **Revisit when:** a v1 cluster (rendering limb, future audio limb) demonstrates a need to override member-cap audit settings.

> **Deferred decision.** Whether `STREAM_DRAIN_TIMEOUT_TICKS` should become a per-cap-shape field (`drain_timeout_ticks: u64`) rather than a single SCAFFOLDING constant. A 4 TiB `lifetime_bytes` stream with a slow receiver wants a longer drain timeout than a 60 fps rendering pipeline that wants tight teardown. The single constant is reasonable for v1 (50 ticks = 500ms covers both cases adequately at coarse grain) but a workload-tuned per-cap value is the natural endgame. **Revisit when:** a workload demonstrates the single-constant choice produces either teardown stalls or premature unmaps.

> **Deferred decision.** Whether a receiver that attaches but never reads (holding a `fan_out_count` slot indefinitely) should be auto-detached after `STREAM_IDLE_TIMEOUT_TICKS` of no `SYS_CHANNEL_READ` activity. v1 ships without idle-timeout enforcement (the threat model "does NOT protect" against this case explicitly). Adding the knob is a cap-shape extension (`idle_timeout_ticks: u64`). **Revisit when:** a workload demonstrates idle-slot DoS in production deployment, or a `fan_out_count = 1` Stream is a critical path with untrusted-receiver exposure.
