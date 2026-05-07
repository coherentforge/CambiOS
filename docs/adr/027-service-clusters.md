# ADR-027: Service Clusters — Identity-Bound Channel Meshes

- **Status:** Proposed
- **Date:** 2026-05-03
- **Depends on:** [ADR-005](005-ipc-primitives-control-and-bulk.md) (channels — the substrate clusters compose), [ADR-007](007-capability-revocation-and-telemetry.md) (capability revocation — clusters extend with cluster-shaped revoke), [ADR-002](002-three-layer-enforcement-pipeline.md) (the cap check the cluster cap promotion runs through)
- **Related:** [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (cluster cap is the canonical example of the cap-shape duality at the boundary), [ADR-011](011-graphics-architecture-and-scaling.md) (rendering limb is the first cluster), [ADR-012](012-input-architecture-and-device-classes.md) (input member of the rendering limb), [ADR-018](018-init-process-and-boot-manifest.md) (boot manifest is where cluster definitions live), [identity.md](../identity.md) (per-Principal containment composes with cluster-shaped revoke)
- **Supersedes:** N/A
- **Context:** Today the rendering limb (compositor + scanout-driver + input + libgui clients) bootstraps via N pairwise control-IPC handshakes (`RegisterCompositor` / `WelcomeCompositor` / `DisplayConnected` / `channel_attach`); each new member adds another pair. Channel teardown is per-channel and per-process (`revoke_all_for_process` on exit), which produced the open compositor #PF on clean client exit (HN-blocker, 2026-04-25). There is no first-class concept of "these services share a fate" — the kernel sees a flat set of channels with no shared lifetime, no shared trust, no shared revoke.

## Problem

Three structural gaps motivate the cluster abstraction. They are interrelated; addressing them piecemeal produces partial fixes — and the project's "no partial-state limping" stance rules out partial fixes as the long-run answer.

### Gap 1 — N pairwise handshakes for what is conceptually one mesh

The rendering limb consists of four roles today:

- **scanout-driver** (ep27, virtio-gpu / Limine FB) — owns the scanout buffer; producer-side of one channel per display.
- **compositor** (ep28) — peer of every scanout channel (writes pixels), and peer of every per-window surface channel (reads from clients), and target of every input event (writes audit on focus change).
- **virtio-input** (ep30) — producer-side of one channel into the compositor for input events; eventually multiple input devices.
- **libgui clients** (variable) — each spawns and creates one or more surface channels with the compositor as peer.

Today every pair uses control-IPC handshakes (`RegisterX` / `WelcomeY` / `DisplayConnected` / capability tokens passed via 256-byte messages) before any of them can call `channel_attach`. The kernel mediates every one of those handshake messages: capability check at send, interceptor at send, queue enqueue, capability check at recv, interceptor at recv, queue dequeue. The compositor's [`handshake_with_scanout_driver`](../../user/compositor/src/main.rs#L565) alone is six syscalls before the first pixel can flow. Add input, add a window, add a second display — the count grows multiplicatively.

This per-pair handshake is *coordination*, and per [ADR-026](026-identity-transcription-at-the-kernel-ring.md)'s reframe ("identity richness is a boundary phenomenon, not a kernel phenomenon"), the kernel should be on the path for the boundary events (cluster construction, member identity verification, cluster revoke), not for every coordination message between members of an established mesh.

### Gap 2 — No shared lifetime or shared fate

The compositor #PF on clean client exit is the load-bearing example. When a graphical client exits cleanly, the kernel calls `ChannelManager::revoke_all_for_process(client_pid)`, which returns a list of revoked channel records; the syscall handler then unmaps the channel pages from each peer's address space. Compositor task 8 was mid-read of `client_surface_vaddr` when its mapping vanished; #PF, kernel kills compositor, screen freezes.

The fundamental cause is **per-channel teardown without coordination at the trust-domain level**. The compositor and the client are *each other's* peer on a surface channel; closing the channel atomically severs both sides' mappings, but neither side gets a synchronous opportunity to quiesce. Today the only synchronization signal is the asynchronous audit `ChannelClosed` event, which arrives after the unmap.

The fix has two pieces, separable in scope but unified in design:

1. **Per-channel quiesce protocol** — needed independently for client surface channels, where the client (a libgui app) is short-lived and not a cluster member. Closes the immediate compositor #PF. Pre-HN candidate.
2. **Cluster-shaped atomic revoke** — for channels between cluster members (compositor↔scanout, compositor↔input). Gives the kernel a structural object so all cluster channels tear down in one locked transition, with no window during which some are gone and others aren't.

Both pieces share the same quiesce protocol mechanism. The cluster abstraction makes the protocol natural to express ("revoke the cluster" → kernel walks the manifest, runs quiesce per channel, then atomic unmap) rather than an ad-hoc loop in a userspace coordinator. The "no partial-state limping" criterion is what disqualifies the pure-userspace alternative: a coordinator that loops through `SYS_CHANNEL_REVOKE` calls *necessarily* leaves windows where some cluster channels are alive and others are gone, and that is exactly the partial-state limping the project rejects.

### Gap 3 — No identity binding for member-to-member coordination

A surface-channel client trusts that the compositor is the peer it negotiated with. A scanout-driver trusts that the compositor it sent `WelcomeCompositor` to is the same one it'll send `FrameDisplayed` acks to. Today this trust is mediated indirectly via the kernel-stamped `sender_principal` field on every IPC message ([ADR-026](026-identity-transcription-at-the-kernel-ring.md) § Identity transcription invariant). It works, but every member must check `sender_principal` against the expected peer Principal on every message it cares about.

A cluster lets the kernel say *once*, at construction time, "these N Principals are the cluster members" and bind that fact into a kernel-signed cluster record — the same posture channel records take today (per [ADR-005 §"Channel record"](005-ipc-primitives-control-and-bulk.md#channel-record-kernel-state)). Members can then trust the cluster handle as a proof-of-membership without re-checking on every message. This is the **identity-rich envelope side** of the cap-shape duality from [ADR-026](026-identity-transcription-at-the-kernel-ring.md): the cluster is the cold-path / boundary form; per-message routing within the cluster stays on the hot-path / internal form (still capability-checked per send/recv, identical to today).

## The Reframe

> **A *service cluster* is a kernel-arbitrated, identity-bound mesh of channels with a shared lifetime, a manifest of expected members, and a single atomic revoke. The kernel touches a cluster exactly four times: at create (manifest registered, members named), at member-join (member's Principal verified, cap promoted into internal handles), at member-leave (cluster integrity policy applied), and at cluster-revoke (every channel atomically torn down with the quiesce protocol). Between those four touches, the channels operate exactly as ADR-005 defines — bytes flow through the MMU at full memory bandwidth, control IPC carries small messages, the kernel sees no payload data.**

The reframe deliberately mirrors [ADR-005](005-ipc-primitives-control-and-bulk.md)'s framing of channels: the kernel mediates *boundary events*, not *steady-state coordination*. The cluster is the boundary at which mutual trust is established; once established, members coordinate among themselves on existing channel + control-IPC primitives. This is the cap-shape duality from [ADR-026](026-identity-transcription-at-the-kernel-ring.md) applied to a *set* of caps: the rich form (the cluster envelope) lives at the boundary; the collapsed form (the per-channel handles, the per-cap `(endpoint, rights)` table entries) lives in the hot path.

## Decision

Three commitments. They are co-dependent: each makes the others coherent.

### 1. Cluster as a thin kernel object — bookkeeping over channels, not a new IPC primitive

A cluster is a named record in a new `ClusterManager` table, holding:

- A unique `ClusterId` (with generation counter, matching `ChannelId` / `ProcessId` shape — see [src/ipc/channel.rs:88](../../src/ipc/channel.rs#L88)).
- A manifest: list of expected member Principals + their roles within the cluster (e.g. `RenderingLimb { compositor, scanout, input }`).
- A list of channel IDs that compose the cluster (populated as members join).
- A kernel-signed record (signed at create with the bootstrap key per the same posture as channel records — [ADR-005 §"Channel record"](005-ipc-primitives-control-and-bulk.md#channel-record-kernel-state) line 159).
- A lifecycle state: `Forming → Active → Revoking → Revoked`.

The cluster is **not a new IPC primitive**. It does not carry data. It does not buffer messages. It does not have endpoints in the IPC sense. It is a manifest + a state machine + a set of cap-promotion + revoke handlers. The data flow within a cluster goes through the existing channels ([ADR-005](005-ipc-primitives-control-and-bulk.md)) and existing control IPC (the 256-byte path); the cluster only changes how that channel + IPC mesh is *set up* and *torn down*.

This keeps the cluster abstraction at the same layer as `ChannelManager`: pure bookkeeping. The actual frame allocation, page mapping, TLB shootdown happen in the existing channel syscall handlers. The cluster manager calls into them at construction and revocation; in between, channels are operated on directly (channel_attach, channel_close — unchanged).

### 2. Mutual cap-grant at construction with fixed per-role policies

When a cluster is created, the manifest names the expected members. Each Principal in the manifest gets, at member-join time, a pre-computed set of caps:

- Channel-create rights for each channel role the member owns within the cluster (e.g. compositor gets create-rights for the per-window surface channels; scanout-driver gets create-rights for the scanout channel).
- Channel-attach pre-authorization for each channel role the member is the peer of.
- Endpoint send/recv rights for the in-cluster control-IPC traffic (e.g. compositor↔scanout `WelcomeCompositor`, compositor↔input `InputEvent`).
- Optionally: a `ClusterRevoke` cap (held by a designated coordinator member, typically the role most likely to detect cluster-breaking conditions — for the rendering limb, the compositor).

The cap promotion happens once per member at join time. After promotion, the member sees only internal caps (`Capability { endpoint, rights }` per [src/ipc/capability.rs:103](../../src/ipc/capability.rs#L103)). This is exactly [ADR-026](026-identity-transcription-at-the-kernel-ring.md)'s cap-shape duality: rich form at the boundary, collapsed form inside.

The motivation for *mutual* (rather than per-pair) cap-grant is to eliminate the pairwise handshake. With mutual grant, when the compositor calls `channel_attach(scanout_channel_id)`, the cap is already in the compositor's table — no need for the scanout-driver to first send a capability token via control IPC. The boot-time `RegisterCompositor` / `WelcomeCompositor` exchange becomes optional metadata (e.g. negotiating display geometry) rather than a load-bearing capability handshake.

**Cap origin in v1: fixed per-role policies.** Each `(ClusterPolicy, ClusterRole)` pair maps to a fixed cap set, hardcoded in a kernel cluster-policy module (e.g. `RenderingLimb::Compositor` → known set of attach + create rights). This trades flexibility for verifiability: cap promotion is a closed-world pattern-match rather than open-world data interpretation. The general-purpose form (caps listed explicitly in the manifest at create time) is deferred until a second cluster type forces the question.

### 3. Cluster-shaped revoke synchronized via the quiesce protocol

A `SYS_CLUSTER_REVOKE` syscall, callable by:

- The original cluster creator (typically `init` per [ADR-018](018-init-process-and-boot-manifest.md))
- Any member holding the `ClusterRevoke` cap (typically the coordinator, e.g. compositor)
- The bootstrap-Principal-equivalent path (until [ADR-007](007-capability-revocation-and-telemetry.md) Phase 3.4 lands the policy service)

When invoked, the kernel:

1. Marks the cluster `Revoking` in the bookkeeping. New channel-attach calls referencing the cluster fail.
2. **Quiesce phase**: kernel sends a `ClusterRevoking` control-IPC message to every active member, then waits up to a bounded timeout (~10 timer ticks = 100ms) for each member to either (a) explicitly ack via `SYS_CLUSTER_QUIESCE_ACK`, or (b) get scheduled out of any in-flight channel reads (kernel marks each member's task `Blocked(ClusterQuiesceWait)` when it next yields). Members that have exited or are unresponsive past timeout are recorded; the kernel kills the unresponsive task before unmap (it was non-cooperative; the cluster is being torn down anyway).
3. **Atomic revoke phase**: kernel walks the cluster's channel list, calls `ChannelManager::revoke` on each, then for each revoked record performs the existing unmap + TLB shootdown sequence per [ADR-007 §"How revocation interacts with channels"](007-capability-revocation-and-telemetry.md#how-revocation-interacts-with-channels). All members lose all cluster channels in a single locked transition. *No window during which some channels are alive and others are gone.*
4. **Cap revoke phase**: kernel walks each member's `ProcessCapabilities` and removes the caps the cluster granted at join. Other caps (held independently of the cluster) are untouched.
5. **Audit emission**: `CLUSTER_REVOKED` event with member list + revoke reason — uses the existing [ADR-007](007-capability-revocation-and-telemetry.md) audit ring.

The same quiesce protocol mechanism is used for per-channel revoke (`SYS_CHANNEL_REVOKE` and `revoke_all_for_process`), uniformly. This means client surface channels (where the client is not a cluster member) also get quiesce-before-unmap, which is what closes the compositor #PF on clean client exit. The mechanism is unified: revoke is revoke; cluster revoke is N atomic revokes wrapped in a manifest-aware transaction.

## Architecture

### Kernel state

```rust
pub struct ClusterManager {
    /// Cluster table. None = free slot.
    clusters: [Option<ClusterRecord>; MAX_CLUSTERS],
    /// Per-slot generation counter for stale-handle rejection.
    generations: [u32; MAX_CLUSTERS],
    /// Number of slots currently Forming, Active, or Revoking.
    count: usize,
}

pub struct ClusterRecord {
    pub id: ClusterId,
    pub state: ClusterState, // Forming → Active → Revoking → Revoked
    pub policy: ClusterPolicy, // RenderingLimb { ... } | StorageLimb { ... } | ...
    pub creator_pid: ProcessId,
    pub members: [Option<ClusterMember>; MAX_CLUSTER_MEMBERS],
    pub channels: [Option<ChannelId>; MAX_CLUSTER_CHANNELS],
    pub created_at_tick: u64,
    pub kernel_signature: [u8; 64], // bootstrap-key signed at create
}

pub struct ClusterMember {
    pub principal: Principal,
    pub role: ClusterRole, // role-within-policy enum
    pub joined_pid: Option<ProcessId>, // None until join
    pub state: MemberState, // Expected → Joined → Departed
}

pub enum ClusterPolicy {
    RenderingLimb {
        // Fixed manifest for v1.
    },
    // StorageLimb { ... } reserved
    // AudioLimb { ... } reserved
}
```

`MAX_CLUSTERS` and `MAX_CLUSTER_MEMBERS` / `MAX_CLUSTER_CHANNELS` are SCAFFOLDING bounds per [Convention 8](../../CLAUDE.md#development-conventions). Endgame estimate: 4–8 simultaneous clusters at HN-era v1 (rendering limb, storage limb, audio limb when it lands, a coordinator cluster for `init` itself), 4–8 members per cluster, 4–8 channels per cluster. 4× headroom puts the bounds at 32 / 32 / 32. Memory cost is well under 64 KiB. Each bound carries the doc comment + replacement criterion required by Convention 8 and gets a row in [ASSUMPTIONS.md](../ASSUMPTIONS.md) when the implementation lands.

### Lock ordering

`CLUSTER_MANAGER` enters the canonical hierarchy at position 4.5 — between `CAPABILITY_MANAGER(4)` and `CHANNEL_MANAGER(5)`. The cluster manager is fundamentally a coordinator over caps and channels; the semantic ordering matches its acquisition pattern.

When the implementation lands, the [CLAUDE.md § Lock Ordering](../../CLAUDE.md#lock-ordering) hierarchy renumbers:

```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
CLUSTER_MANAGER(5) → CHANNEL_MANAGER(6) → PROCESS_TABLE(7) →
FRAME_ALLOCATOR(8) → INTERRUPT_ROUTER(9) → OBJECT_STORE(10)
```

Cluster operations acquire `CLUSTER_MANAGER` → (`CAPABILITY_MANAGER` for cap promotion / revoke) → `CHANNEL_MANAGER` (for channel revoke) → `PROCESS_TABLE` (for member-PID lookup) → `FRAME_ALLOCATOR` (for unmap-driven frame frees). Strictly downward — no inversion.

### Syscalls

Reserve 5 syscall numbers (per [ADR-022](022-wall-clock-time.md) slot-reservation discipline; current reservations end at 40 with new syscalls starting at 41 per the wallclock-impl handoff):

| Number | Name | Purpose | Identity-required |
|---|---|---|---|
| 41 | `SYS_CLUSTER_CREATE` | Create a `Forming` cluster from a `ClusterPolicy` manifest. Caller becomes creator. Returns `ClusterId`. | yes |
| 42 | `SYS_CLUSTER_JOIN` | Join a cluster as a named member. Kernel verifies caller's Principal matches the manifest's expected Principal for the named role. Promotes the role's caps into the caller's `ProcessCapabilities`. | yes |
| 43 | `SYS_CLUSTER_QUIESCE_ACK` | Member ack of the `ClusterRevoking` notification. Kernel transitions the member to "ready for unmap." Also used by per-channel revoke quiesce. | yes |
| 44 | `SYS_CLUSTER_REVOKE` | Initiate cluster revoke. Caller must be creator or hold `ClusterRevoke` cap. | yes |
| 45 | `SYS_CLUSTER_INFO` | Read cluster metadata (state, members, channel IDs). Read-only. | yes |

ABI lives in `cambios-abi` per [ADR-024](024-syscall-abi-crate.md); kernel re-exports as today.

### Capability-kind extension

Two new variants in `CapabilityKind` ([src/ipc/capability.rs:26](../../src/ipc/capability.rs#L26)):

```rust
pub enum CapabilityKind {
    // ... existing variants
    /// Right to create a new service cluster.
    /// Granted to `init` at boot; rarely held by anything else.
    CreateCluster,
    /// Right to call SYS_CLUSTER_REVOKE on a cluster the holder is a
    /// member of. Granted at join time per the cluster's policy
    /// (typically only the coordinator role holds this).
    ClusterRevoke,
}
```

### Worked example: rendering limb bootstrap

Compare today vs cluster-shaped:

**Today** (control-IPC handshake count):

```
init → spawn(scanout-driver)
init → spawn(compositor)
compositor → SYS_WRITE(SCANOUT_DRIVER_ENDPOINT, "RegisterCompositor")
scanout-driver → SYS_RECV; sends "WelcomeCompositor"
compositor → SYS_RECV
scanout-driver → SYS_CHANNEL_CREATE(scanout_buf, peer=compositor_principal, role=Consumer)
scanout-driver → SYS_WRITE(COMPOSITOR_ENDPOINT, "DisplayConnected{channel_id}")
compositor → SYS_RECV
compositor → SYS_CHANNEL_ATTACH(channel_id)
init → spawn(virtio-input)
virtio-input → SYS_CHANNEL_CREATE(input_evq, peer=compositor_principal, role=Producer)
virtio-input → SYS_WRITE(COMPOSITOR_ENDPOINT, "InputDeviceConnected{channel_id}")
compositor → SYS_RECV
compositor → SYS_CHANNEL_ATTACH(channel_id)
... per-window-client: another channel_create / send-token / channel_attach pair
```

**Cluster-shaped:**

```
init → SYS_CLUSTER_CREATE(RenderingLimb { compositor, scanout, input })
init → spawn(scanout-driver)        → scanout-driver SYS_CLUSTER_JOIN(RenderingLimb, role=Scanout)
init → spawn(compositor)            → compositor    SYS_CLUSTER_JOIN(RenderingLimb, role=Compositor)
init → spawn(virtio-input)          → virtio-input  SYS_CLUSTER_JOIN(RenderingLimb, role=Input)
scanout-driver → SYS_CHANNEL_CREATE(scanout_buf, peer=compositor_principal, role=Consumer)
                 // compositor's attach-cap was pre-granted at JOIN
compositor → SYS_CHANNEL_ATTACH(channel_id)  // succeeds without prior token-passing IPC
virtio-input → SYS_CHANNEL_CREATE(input_evq, peer=compositor_principal, role=Producer)
compositor → SYS_CHANNEL_ATTACH(channel_id)
```

The geometry-and-format negotiation (`DisplayConnected` payload) can still travel via control IPC after attach — but it carries display metadata, not capability tokens. The cap is structural.

Net change: ~4 control-IPC sends + ~4 receives eliminated per cluster bring-up. More importantly: the control-IPC sequencing is no longer load-bearing for *correctness*, only for *coordination*. A buggy or absent `WelcomeCompositor` no longer breaks the trust relationship — that lives in the cluster manifest, signed by the kernel.

### Compositor #PF on client exit — what the unified quiesce protocol gives us

A libgui client is not a member of `RenderingLimb` (clients are short-lived; the limb is long-lived). Each client's surface channel sits *outside* the cluster. So cluster-shaped revoke doesn't directly apply to the bug.

However, Decision 5 commits to the *same quiesce protocol* applying uniformly to per-channel revoke (`SYS_CHANNEL_REVOKE` and `revoke_all_for_process`). The compositor receives `ChannelRevoking` *before* its surface channel is unmapped; it stops reading from the channel; it acks; the kernel proceeds. If the compositor is buggy and doesn't ack, the timeout fires, the kernel kills the compositor's task — but only as a last resort, after giving the cooperative path 100ms to complete.

The protocol is a per-channel revoke fix; the cluster makes it natural to express across N channels at once. Either piece can land first:

- **Per-channel quiesce as standalone work** (pre-HN candidate): adds `BlockReason::ChannelQuiesceWait`, `SYS_CHANNEL_QUIESCE_ACK` (or fold into `SYS_CHANNEL_QUIESCE_ACK = 43` reserved here), the `Revoking` channel state, and the timeout machinery. Closes the HN-blocker. ~1 week of focused work.
- **Cluster manager + handlers** (post-HN): builds on the quiesce primitive. Adds the manifest, the cap-promotion logic, and the cluster-revoke transaction wrapper.

## Threat Model

### What clusters protect against

| Threat | Mitigation |
|---|---|
| Member impersonation: a non-cluster process tries to `SYS_CLUSTER_JOIN` as the compositor | Kernel verifies caller's bound Principal matches the manifest's expected Principal at join time. Mismatch returns `PermissionDenied`. |
| Privilege accumulation: a member gains caps beyond what the cluster role permits | Cap promotion at join uses fixed `RenderingLimb { ... }` policy. Member can't request additional caps from the cluster. Members can still grant caps independently per existing delegation rules. |
| Forged cluster handle: caller passes a `ClusterId` it never joined | The cluster record is kernel-signed at create; lookups verify the handle's generation against the slot. Forgery requires kernel compromise. |
| Replay of cluster construction: malicious init replays a `ClusterPolicy` with an attacker-controlled member | Cluster creation requires `CapabilityKind::CreateCluster`, granted only to `init` at boot. Compromising `init` is already game-over for boot integrity (it's the parent of every service). |
| Compositor #PF on member exit | Quiesce protocol gives the surviving peer a synchronous opportunity to stop reading before the kernel unmaps. Members that fail to ack within 100ms are killed before the unmap. |
| Partial-state cluster teardown: some channels gone, others still alive | Not possible. Cluster revoke is a single locked transition in step 3 ("Atomic revoke phase"). All cluster channels lose mapping in the same critical section. |

### What clusters do NOT protect against

| Risk | Mitigation |
|---|---|
| Two cooperating malicious cluster members coordinate via shared channel the kernel can't see | Same as [ADR-005 §"What channels do NOT protect against"](005-ipc-primitives-control-and-bulk.md#what-channels-do-not-protect-against-and-what-mitigates-each) — the kernel never reads channel payloads. If two members have legitimate caps to a shared channel, what they say is between them. |
| Member fabricates fake cluster traffic on a non-cluster endpoint | Endpoints are still capability-gated per [ADR-002](002-three-layer-enforcement-pipeline.md). The cluster manifest doesn't change endpoint cap semantics. A member's caps are limited to what the cluster role grants + whatever it held independently. |
| Coordinator (compositor) abuses its `ClusterRevoke` cap to DoS the cluster | This is by design: the coordinator's role *is* to detect cluster-breaking conditions and tear down. If we don't trust the compositor with `ClusterRevoke`, we don't trust it with the rendering limb at all. The cap can be migrated to a separate watchdog process if needed. |
| Bootstrap-Principal compromise | All bets off, same as today. Cluster creation goes through `CapabilityKind::CreateCluster`; if the cap holder is compromised, attacker can name arbitrary clusters. The TCB boundary is unchanged. |

### Impact on existing threats

- [ADR-005](005-ipc-primitives-control-and-bulk.md)'s per-channel threat model continues to apply. Cluster revoke is a structural-revoke (MMU enforces) on every channel in the cluster simultaneously.
- [ADR-007](007-capability-revocation-and-telemetry.md)'s revocation atomicity continues to apply per channel; the cluster wraps N channels with a shared lifecycle but doesn't weaken any one channel's atomicity.
- [ADR-026](026-identity-transcription-at-the-kernel-ring.md)'s transcription invariant: cluster operations branch on Principal *values* at member-join time (verifying caller matches expected member). This is interpretation, but it's a **boundary operation** — at the cap promotion boundary explicitly carved out in [ADR-026 §"Boundary carve-outs"](026-identity-transcription-at-the-kernel-ring.md#1-identity-transcription-invariant). Not a hot path.

## Verification Stance

The cluster state machine is small enough for static analysis:

- **Cluster lifecycle:** `Forming → Active → Revoking → Revoked`. No backward transitions. No transitions on stale handles (generation counter rejects). Verifiable as a finite state machine; Kani harness target alongside the existing channel-manager proofs.
- **Member lifecycle:** `Expected → Joined → Departed`. Forward only.
- **Cap promotion soundness:** the caps a member receives at join match the cluster policy's declared role caps for that role. With Decision 2's fixed policies, this is a structural pattern-match check — every `(ClusterPolicy, ClusterRole)` pair has a fixed cap set, exhaustively matched.
- **Atomicity of cluster revoke:** the entire revoke (mark-revoking → quiesce → atomic-channel-revoke → cap-revoke → audit) runs under `CLUSTER_MANAGER` lock with the appropriate sub-locks. Verifiable as a single critical section, or — if we want to release `CLUSTER_MANAGER` during the quiesce wait — as a two-phase commit with a pinned cluster state.
- **Cluster-shaped quiesce protocol bounded latency:** quiesce wait ≤ 10 ticks (100ms). Bounded iteration per [Formal Verification](../../CLAUDE.md#formal-verification-non-negotiable-constraint).

The cluster's *internal* operation (member-to-member channel + IPC traffic) inherits [ADR-005](005-ipc-primitives-control-and-bulk.md)'s verification story unchanged — clusters are setup/teardown sugar, not new data path.

The verification surface delta vs. the existing kernel: roughly 30–50% on top of the channel subsystem's existing target. State machines are simpler than `CapabilityManager` (already proven via Kani per [ADR-000 § Divergence (2026-04-21)](000-zta-and-cap.md)). The fixed-policy choice in Decision 2 is doing the heavy lifting here — it makes cap promotion a closed-world enum match rather than open-world data interpretation, which is the cheap-to-verify shape.

## Why Not Other Options

### Option A: Pure userspace coordinator service (no kernel ABI growth)

A userspace `cluster-coordinator` service holds manifests; brokers `channel_create` calls between members at boot; broadcasts cluster-shutdown messages on member exit detected via existing audit telemetry; never touches the kernel beyond standard syscalls.

**Why considered.** The cycles-outside-the-ring heuristic: default toward the option that keeps the ring narrower. Kernel adds zero new syscalls, zero new state machine, zero new lock entries. Coordinator is a normal service in the boot manifest. [ADR-018](018-init-process-and-boot-manifest.md)'s manifest-driven boot is a natural shape for cluster definitions to live in.

**Why rejected.** Three properties the userspace coordinator cannot provide, all of which are load-bearing for the rendering limb in v1:

1. **Atomic revoke.** A coordinator that decides "tear down the rendering limb" cannot atomically revoke all channels — there is necessarily a window between the decision and the last `SYS_CHANNEL_REVOKE` it issues. During that window, surviving channels still carry data. The "no partial-state limping" criterion is what disqualifies this — partial-state teardown is exactly the limping the project rejects, and only a kernel-side single-locked-transition can avoid it.
2. **Boot-gate sequencing.** Today `ModuleReady` ([ADR-018](018-init-process-and-boot-manifest.md)) gates module-spawn ordering at the kernel level. A cluster-aware boot would say "don't release any of {compositor, scanout, input} until all three have called `SYS_CLUSTER_JOIN`" — a kernel-level guarantee. A userspace coordinator can approximate this but cannot enforce it; a buggy member that skips coordination still gets to run.
3. **Identity binding without re-checks on every message.** A userspace coordinator can broker cap distribution but cannot signed-attest "these N Principals are the cluster" the way the kernel can sign a cluster record (same posture as channel records). Members would still have to verify peer Principals on every message they care about.

The compositor #PF reframing is important here: per-channel quiesce is needed regardless of the cluster decision, because the bug is on a client surface channel where the client is not a cluster member. Per-channel quiesce is sunk cost. Option A would *also* implement per-channel quiesce; the question between Option A and clusters is therefore *only* about what the cluster shape adds **on top of** per-channel quiesce. The three properties above are that addition.

### Option B: Extend ADR-005 channels with "channel groups" instead of new abstraction

Add a `group_id` field to `ChannelRecord`; `SYS_CHANNEL_CREATE_IN_GROUP` and `SYS_GROUP_REVOKE`. No new manager, just channel-table extension.

**Why considered.** Smaller surface area. No new lock. No new manifest concept.

**Why rejected.** The cluster's distinguishing properties — *named manifest of expected members, identity-bound mesh, coordinator role, cluster-aware boot ordering* — don't fit naturally into "channels with a group tag." The manifest is fundamentally a separate concept (which Principals are expected, in which roles, with what cap shapes). Forcing it into ChannelManager bookkeeping bloats the channel record and conflates two abstractions. The cap-promotion logic doesn't belong in a channel record at all. Channel groups would solve atomic revoke alone but lose the manifest, identity, and boot-gate properties.

### Option C: Embed cluster semantics in the boot manifest only (no runtime API)

Boot manifest [ADR-018](018-init-process-and-boot-manifest.md) declares clusters; `init` consumes the manifest and orchestrates everything via existing syscalls; no `SYS_CLUSTER_*` API at runtime.

**Why considered.** Even thinner than Option A. The cluster *concept* exists (in the manifest), but nothing in the kernel knows about it.

**Why rejected.** Same atomic-revoke and boot-gate gaps as Option A. Plus: clusters formed dynamically (e.g. a new monitor hot-plugs and joins the rendering limb) aren't expressible. Static-only clusters work for the rendering limb today but bake in a limitation that's painful to relax later.

### Option D: Defer entirely; revisit post-HN

Don't write the ADR. Land the per-channel quiesce as a standalone fix. Revisit clusters when a second consumer (storage limb? audio limb?) shows up.

**Why considered.** Pre-HN time is precious. Adding kernel ABI right before launch is risky.

**Why rejected.** Writing the ADR is cheap (this document); landing the implementation is the costly part, and the implementation can wait. The ADR is the architectural decision and the audit trail. Per Decision 7 below, this ADR lands as `Proposed` pre-HN; the implementation lands post-HN. Deferring even the ADR risks the rendering limb solidifying further with ad-hoc per-channel patterns that have to be retrofitted later.

## Migration Path

Documentation + discipline first, code last:

1. **Land this ADR as `Proposed`.** No code touched. Cluster concept is now citeable for any compositor / virtio-gpu / virtio-input work that wants to "leave room" for cluster migration.
2. **Per-channel quiesce protocol** (independent work, optional cluster dependency). Adds the synchronous quiesce-or-timeout to `SYS_CHANNEL_REVOKE` and `revoke_all_for_process`. Closes the compositor #PF. Pre-HN candidate if scoped tight.
3. **`cambios-abi` syscall reservations.** Reserve numbers 41–45 per the Syscalls table above. Do not implement handlers; reservation only — same posture as [ADR-022](022-wall-clock-time.md)'s wallclock reservation. Pre-HN-safe.
4. **`ClusterManager` skeleton.** Pure-bookkeeping module under `src/ipc/cluster.rs` (mirrors `src/ipc/channel.rs` shape — see [src/ipc/channel.rs](../../src/ipc/channel.rs) for the template). Tests for the state machine + cap-promotion-soundness. No syscall handlers yet. Post-HN.
5. **Syscall handlers.** Wire the 5 syscalls into `src/syscalls/dispatcher.rs`. Cluster-create + cluster-join enable the rendering limb migration. Cluster-revoke wires to `ChannelManager::revoke` per the protocol in §"Decision 3."
6. **Rendering limb migration.** Update [user/compositor/src/main.rs](../../user/compositor/src/main.rs), the scanout drivers ([user/scanout-virtio-gpu/](../../user/scanout-virtio-gpu/) and [user/scanout-limine/](../../user/scanout-limine/)), and [user/virtio-input/](../../user/virtio-input/) to call `SYS_CLUSTER_JOIN` at startup. The pairwise-handshake control-IPC messages stay in place initially as metadata exchange (geometry, device-class) — they no longer carry capability tokens.
7. **Cluster-shaped revoke wiring.** Compositor (or a watchdog) holds `ClusterRevoke` cap; on cluster-fatal condition (display vanished, scanout-driver crashed), call `SYS_CLUSTER_REVOKE`. `init` re-spawns the limb if the policy says so.
8. **Storage limb.** Same shape, after rendering limb is proven.
9. **Audio limb.** When audio lands.

Each step independently bisectable. Steps 1–3 are cheap and pre-HN-safe. Steps 4–7 are post-HN.

## Cross-References

- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** — Channel substrate; clusters are bookkeeping over channel records.
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Revocation primitive that cluster revoke composes; audit ring carries `CLUSTER_REVOKED` events.
- **[ADR-002](002-three-layer-enforcement-pipeline.md)** — Cap check pipeline; cluster operations route through the existing layer-2 capability check.
- **[ADR-026](026-identity-transcription-at-the-kernel-ring.md)** — Cap-shape duality; clusters are the canonical example of the rich/external form (manifest-bound, kernel-signed) collapsing into the internal/hot-path form (per-channel handles, per-process cap entries).
- **[ADR-011](011-graphics-architecture-and-scaling.md)** — Rendering limb is the first cluster.
- **[ADR-012](012-input-architecture-and-device-classes.md)** — Input is a member of the rendering limb.
- **[ADR-018](018-init-process-and-boot-manifest.md)** — Boot manifest is where v1 cluster definitions live.
- **[ADR-024](024-syscall-abi-crate.md)** — `cambios-abi` is where `SyscallNumber::Cluster*` lives.
- **[CLAUDE.md § Lock Ordering](../../CLAUDE.md#lock-ordering)** — `CLUSTER_MANAGER` insertion at position 5 (post-implementation renumber).
- **[identity.md § The Vault](../identity.md)** — Multi-Principal vault composes with cluster-shaped revoke (containment of one Principal's caps doesn't disturb other Principals' clusters).

## See Also in CLAUDE.md

When this ADR's implementation lands, the following CLAUDE.md sections must be updated:

- **§ "Lock Ordering"** — insert `CLUSTER_MANAGER(5)`; renumber `CHANNEL_MANAGER` → 6, `PROCESS_TABLE` → 7, etc. Update the `IrqSpinlock` annotations and the comment in `src/lib.rs`.
- **§ "Required Reading by Subsystem"** — added at ADR-landing time, points at this ADR + [ADR-005](005-ipc-primitives-control-and-bulk.md) + [ADR-018](018-init-process-and-boot-manifest.md). The row sits alongside the existing IPC bulk path row.
- **§ "Syscall Numbers"** — add SYS_CLUSTER_* (41–45) when implementation lands.

## Open Questions / Deferred

> **Deferred decision.** Whether `CapabilityKind::ClusterRevoke` should be granted automatically at join time (per-role policy) or require an explicit grant from the creator. **Revisit when:** the rendering limb's coordinator role is being implemented and we see whether automatic grant produces the right authority shape.

> **Deferred decision.** Dynamic cluster membership (a member joins or leaves an active cluster). **Revisit when:** the first runtime hot-plug scenario lands — multi-monitor display reconnect, or audio device hot-plug. The skeleton in this ADR assumes static membership at construction time; relaxation is additive.

> **Deferred decision.** Cross-cluster member overlap (one process is a member of multiple clusters). **Revisit when:** a service appears that legitimately participates in two limbs (e.g. a media player that's both a rendering-limb client and an audio-limb client). Cap-promotion semantics in the overlap aren't worked out here.

> **Deferred decision.** General-purpose clusters (caps listed explicitly in the manifest at create time) vs. the v1 fixed-policy form. **Revisit when:** the second cluster type is being designed (storage limb), and the temptation to share the cluster substrate becomes concrete. The v1 fixed-policy form is the verification-friendly shape; relaxing it is a verification-cost decision.

## Divergence

The cluster-implementation chain (skeleton at [src/ipc/cluster.rs](../../src/ipc/cluster.rs) landed 2026-05-06 at `c9e31fe`; ABI reservation landed 2026-05-07 at `779e47b`) diverges from this ADR in two ways. The original Decisions stay as immutable history; entries below name what changed and why.

1. **Cluster syscall slots renumbered from 41–45 to 44–47 (cooperative ack stays at 43).** The original § Syscalls table reserves 41–45 for `SYS_CLUSTER_CREATE` / `_JOIN` / `_QUIESCE_ACK` / `_REVOKE` / `_INFO`. Slots 41/42/43 shipped before this ADR ratified — `AuditEmitInputFocus = 41` (input-focus audit emit), `GetProcessPrincipal = 42` ([ADR-023](023-audit-consumer-capability.md) audit consumer principal lookup), and `ChannelQuiesceAck = 43` (per-channel quiesce ack at `58175eb`; this ADR's § Decision 5 already folded cluster cooperative ack into the same slot, and the implementation honors that unification). The remaining cluster handles therefore reserve at the next free slots: `ClusterCreate = 44`, `ClusterJoin = 45`, `ClusterRevoke = 46`, `ClusterInfo = 47`. The § See Also in CLAUDE.md note that says "add SYS_CLUSTER_\* (41–45) when implementation lands" inherits this renumber.

   No decision content changes. Every cluster syscall stays identity-required, the cap-gating posture stays the same, and the responsibilities of each handle stay as the original § Syscalls table specifies. Only the numbers move.

2. **v1 picks path A — advisory quiesce — leaning on tombstone-on-revoke from ADR-007 Divergence 7.** The original § Decision 3 step 2 specifies a synchronous quiesce phase: kernel sends `ClusterRevoking` to every active member, waits up to ~10 ticks (100ms) for each to ack via the cooperative-ack slot or get scheduled out, then atomically revokes all cluster channels. The [ADR-007 Divergence entries 7–9](007-capability-revocation-and-telemetry.md#divergence) (2026-05-05) introduced the tombstone-on-revoke pattern for RO peer mappings: instead of unmapping the peer's PTE on channel revoke, the kernel swaps the PTE to a kernel-owned shared RO zero page, and the peer's userspace half (`SYS_CHANNEL_INFO` check + reap on `Revoked` state, landed in `70bd6a5`/`a2ce7db`/`b79ed85`) drops the dead reference within one frame.

   That refinement reduces the cluster-revoke quiesce step from load-bearing to advisory under v1's mapping cases:

   - **RO peer mappings under tombstone:** the PTE swap + TLB shootdown is safe regardless of peer-task state (parked, running, mid-blit). No quiesce needed before the swap.
   - **RW peer mappings under unmap:** the peer faults on subsequent writes. ADR-007 Divergence 8 names this as v1-acceptable kill-via-fault behavior for the catastrophic-state cases (writer surviving the consumer's death is not a v1 workload).

   v1 cluster revoke therefore wraps N atomic per-channel revokes (each running tombstone-or-unmap per ADR-007 Divergence 7) inside a single locked cluster-state transition (`Active → Revoking → Revoked`). The quiesce machinery from § Decision 3 step 2 is **not removed**: `Scheduler::arm_quiesce`, `BlockReason::ChannelQuiesceWait`, `SYS_CHANNEL_QUIESCE_ACK = 43`, and the cluster bookkeeping's `RevokingClusterSnapshot` (which exposes joined member pids + channels for fan-out) all remain. Cluster revoke just does not *invoke* quiesce for v1's RO-mapping cases.

   **When path B becomes load-bearing again.** Under SMP RW peer mappings — a Producer-role channel writer running concurrently on another CPU during unmap, or a future Bidirectional channel teardown — the unmap-then-fault path is racy without quiesce: the peer can be mid-write at the moment of TLB shootdown, the write succeeds against the soon-to-be-invalidated TLB entry, and the data is lost or partially observable. v1's stance holds because no v1 workload puts an RW writer in a hot path on a separate CPU from its consumer; SMP-tier-1 services explicitly serialize.

   Cluster revoke can flip to path B (run quiesce per RW channel during the cluster's per-channel walk) by adding a single `arm_quiesce_for_process` + `complete_teardown` call inside the handler — the bookkeeping skeleton at [src/ipc/cluster.rs](../../src/ipc/cluster.rs) is already shaped for it (the `RevokingClusterSnapshot` carries everything the per-channel walk needs).

   **Replace when:** an SMP-tier service legitimately runs an RW channel writer + consumer on different CPUs and survives the consumer's death. Concrete triggers: GPU compute pipeline where a writer service feeds a consumer that may be revoked under live workload; persistent-storage write-back path where a writer is mid-flush when the storage limb's consumer is revoked. Until either lands, path A is the v1 stance.
