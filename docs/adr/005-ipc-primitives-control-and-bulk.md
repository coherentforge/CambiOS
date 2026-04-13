# ADR-005: IPC Primitives — Control Path and Bulk Data Path

- **Status:** Proposed
- **Date:** 2026-04-10
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-002](002-three-layer-enforcement-pipeline.md) (Three-Layer Enforcement Pipeline)
- **Supersedes:** N/A
- **Context:** Defining the IPC architecture as CambiOS moves from proof-of-concept workloads to real applications (networking, video, file I/O, future AI inference)

## Problem

CambiOS today has one IPC primitive: a kernel-mediated, fixed-size, 256-byte message-passing path. Every byte that travels between two processes is copied through the kernel, capability-checked, interceptor-checked, and identity-stamped. The hot path has been good enough for the workloads it has carried so far — control RPCs between user-space services, syscall return values, signed-binary verification messages, key-store signing requests.

It is not good enough for the workloads CambiOS exists to support.

A 60 fps display server moving 8 MB frames at 1080p needs ~500 MB/s of guest-to-guest bandwidth. An LLM inference service producing tokens needs multi-GB/s for KV cache and embedding traffic. A virtio-blk driver moving disk blocks at NVMe rates needs sustained hundreds of MB/s. A video decoder writing to a framebuffer needs to do it without copying through ring 0 on every macroblock. None of these can be implemented on a 256-byte-at-a-time path with kernel-mediated copies.

The naive fix is "make the IPC payload bigger." That fix is wrong, for reasons that took us a while to articulate clearly. Bumping the limit from 256 to 1024 doesn't unblock video. Bumping it to 4096 doesn't unblock LLM inference. Bumping it to a megabyte breaks the verification posture the kernel was built for and still doesn't get us the throughput we need. The fundamental problem is not the *size* of the message — it is the *path*. Per-byte kernel mediation cannot scale to data-plane workloads, regardless of how generously we size the message buffer.

A second problem hides under the first: the existing 256-byte limit was never written down as a *decision*. It was a number chosen during the early days of the project, justified implicitly by the verification stance ("fixed-size messages are easier to reason about"), and then carried forward without anyone explaining the reasoning. SECURITY.md mentions it. The IPC source code uses it. No ADR explains it. This is exactly the kind of implicit decision that future contributors silently break — by raising the limit "for performance," by adding a `send_unchecked()` fast path, by rationalizing a special case for one workload that becomes the precedent for all others.

This ADR fixes both problems at once. It writes down the reasoning behind the existing 256-byte path as a deliberate decision, and it introduces a separate primitive for bulk data that doesn't compromise that reasoning.

## The Reframe

The framing that resolves this is taken directly from [CambiOS.md](../../CambiOS.md) and [PHILOSOPHY.md](../../PHILOSOPHY.md), which both already authorize what we're about to do. The relevant principle is:

> **The kernel mediates *policy*, not *bytes*.**

The kernel's job is not to read every byte that flows between two processes. Its job is to decide who is allowed to talk to whom, about what, with what constraints, and then to enforce those constraints structurally — through page tables, capabilities, and the hardware MMU — rather than dynamically by inspecting traffic.

A capability check at IPC send time is *policy*: "is process A allowed to send a message to endpoint E?" That check belongs in the kernel. It happens once per message, and it's cheap.

A 4 MB framebuffer copy is *not policy*. It's *bytes*. The decision about whether the display server is allowed to share memory with its client is the same kind of decision as the IPC capability check — made once, structurally enforced, requires no per-byte mediation. Once the decision is made, the bytes flow through the page tables (which the MMU enforces on every access, in hardware, at full memory bandwidth) without any additional kernel involvement.

This reframe does not weaken security. It moves enforcement from a per-byte check (which is theatre, because by the time bytes are flowing the security decision has already been made) to a per-channel check at setup time (which is the actual moment authority is granted). [CambiOS.md line 134](../../CambiOS.md) already encodes this: "There is no shared memory between services unless explicitly granted through a capability."

## Decision

CambiOS has **two distinct IPC primitives**, with non-overlapping responsibilities:

### 1. Control IPC — small, fixed-size, kernel-mediated, verification-friendly

The existing IPC layer. Messages are fixed-size (256 bytes payload + 24 bytes metadata = 280 bytes per slot), pre-allocated in fixed-depth queues (16 messages × 32 endpoints = 512 slots), copied through kernel memory on every send. The control path enforces capability checks on every send and recv (via [ADR-002](002-three-layer-enforcement-pipeline.md)'s three-layer pipeline), stamps the sender's `Principal` on every message ([ADR-003](003-content-addressed-storage-and-identity.md)), and runs through the zero-trust interceptor.

This path is for **control plane** traffic: RPC calls, status updates, capability negotiation, syscall return values, error reporting, channel handshakes (see below), notification of bulk-path readiness, identity attestations, command/response patterns like the existing fs-service / key-store / virtio-net interfaces. Anywhere small structured messages with policy enforcement on every byte make sense.

The 256-byte limit is intentional and is now part of the documented architecture. It exists because:

1. **Bounded total memory.** 32 endpoints × 16 messages × 280 bytes = 140 KB. Pre-allocated at boot. No dynamic allocation in the IPC hot path. No fragmentation. No OOM under load — `QueueFull` is a normal error returned to a sender, not a kernel crisis.

2. **Verification tractability.** Fixed-size structures with bounded depth are the easiest case for formal verification. No reasoning about variable-length buffers, no reasoning about allocator state, no reasoning about realloc. The IPC layer's invariants — payload bounds, queue bounds, no use-after-free, no double-send — are provable from type invariants alone. This matches CLAUDE.md's "Formal Verification (Non-Negotiable Constraint)" stance: "pure logic separated from effects," "bounded iteration," "invariants encoded in types."

3. **Predictable hot-path latency.** A fixed copy size means a predictable copy cost. No path-dependent performance — every IPC send is the same cost, every recv is the same cost. This is what makes the three-layer enforcement pipeline negligible: the security checks are sub-microsecond because everything around them is also sub-microsecond.

4. **Defense in depth on every message.** Because every byte goes through the kernel, every byte gets checked. Capability verification, interceptor policy, sender stamping, payload bounds, endpoint bounds — all of [ADR-002](002-three-layer-enforcement-pipeline.md)'s pipeline runs on every send. This is the right tradeoff for control messages, where security matters more than throughput.

The 256-byte limit was right for its purpose. It is not "small because we never bothered to make it bigger." It is small because **making it bigger would cost the verification posture without solving the data-plane problem**. The right answer is a different primitive for the data plane, leaving the control path unchanged.

### 2. Data Channels — variable-size, capability-gated shared memory, kernel-mediated only at setup and teardown

A new primitive for **bulk data** traffic. A channel is a region of physical memory that the kernel maps into two processes' address spaces, with a capability that records the relationship: which two principals are connected, in which directions, with what size, with what stated purpose, signed by the kernel's bootstrap key.

A channel is **not** a stream of bytes through the kernel. It is shared memory, established by a kernel handshake, then operated on directly by user-space processes through their own page table mappings.

The kernel touches a channel exactly four times in its lifetime:

1. **Create.** Process A calls `SYS_CHANNEL_CREATE(size, peer_principal, direction, purpose)`. The kernel allocates physically contiguous DMA-aligned pages, maps them into A's address space (RW for the producer side), creates a capability record naming A as the creator and the peer as the intended recipient, signs the record with the bootstrap key, and returns a `ChannelHandle` and an opaque capability token to A.

2. **Attach.** Process A passes the capability token to the peer (B) via the existing 256-byte control IPC. B calls `SYS_CHANNEL_ATTACH(capability)`. The kernel verifies the capability is valid, verifies B's `Principal` matches the named peer, maps the same physical pages into B's address space (RO or RW depending on direction), and returns B's own `ChannelHandle`.

3. **Close.** Either side calls `SYS_CHANNEL_CLOSE(handle)`. The kernel unmaps the pages from both processes, frees the physical memory, and revokes the capability. Both `ChannelHandle`s become invalid.

4. **Revoke (force-close).** The policy service (see [ADR-006](006-policy-service.md)) or the kernel itself (during process teardown) calls `SYS_CHANNEL_REVOKE(capability)`. The kernel unmaps from both processes, frees the memory, marks the capability revoked. Distinct from `CLOSE` because it can be initiated by a third party with the appropriate authority, not just by one of the channel's endpoints.

Between those four kernel touches, the bytes flow directly through the shared mapping. Producer writes; consumer reads. The MMU enforces the access mode (RO vs RW) on every load/store, in hardware, at full memory bandwidth. **The kernel does not see, copy, inspect, or mediate the data.** It sees the capability that authorized the connection, and it sees the topology of who-is-talking-to-whom, but it does not touch payload bytes after `ATTACH` returns.

### How they work together

A typical bulk-data session:

```
Process A (producer) wants to stream video frames to Process B (consumer).

1. A: SYS_CHANNEL_CREATE(size = 4 MB, peer = B's principal,
                         direction = AtoB, purpose = "video.framebuffer")
   → Kernel allocates 4 MB, maps into A as RW, creates capability,
     returns (handle_A, capability_token).

2. A: SYS_WRITE(B's control endpoint, control_message {
        "I want to stream you video frames",
        capability_token
    })
   → 256-byte control IPC, three-layer enforcement, sender_principal stamped.

3. B: SYS_RECV_MSG(B's endpoint)
   → Receives the control message with kernel-stamped sender = A's Principal.
   → Inspects the offered capability: "Is this a channel I want to accept?"

4. B: SYS_CHANNEL_ATTACH(capability_token)
   → Kernel verifies B is the named peer, maps the 4 MB region into B as RO,
     returns handle_B.

5. A and B both now hold mappings of the same 4 MB. A writes frames into a
   ring buffer within the region. B reads them. Producer/consumer
   coordination is via standard SPSC ring buffer semantics (head/tail
   indices, atomic acquire/release fences) — entirely user-space.

6. A: SYS_WRITE(B's control endpoint, "frame N ready")
   → 1-byte notification through control IPC. Cheap. Per batch, not per byte.

7. B: SYS_RECV_MSG(...) → wakes, reads the new frames from shared memory.

   (In tighter loops, B can poll the ring head directly without the
   notification — the channel exists as soon as ATTACH succeeds.)

8. Eventually: A: SYS_CHANNEL_CLOSE(handle_A)
   → Kernel unmaps from both A and B, frees physical pages, revokes
     capability. Subsequent access from either side faults.
```

The control IPC carries small structured messages: the channel offer, the "data ready" pings, status, errors. The channel carries the bulk data. Each primitive does what it's good at; neither is asked to do what it isn't designed for.

## Architecture

### Channel capability

A new variant in the existing capability table:

```rust
pub enum CapabilityKind {
    Endpoint { endpoint: EndpointId, rights: CapabilityRights }, // existing
    Channel  { channel_id: ChannelId, role: ChannelRole, peer: Principal },
}

pub enum ChannelRole {
    Producer,        // RW mapping
    Consumer,        // RO mapping
    Bidirectional,   // RW on both sides (rare; explicit opt-in)
}
```

The capability is held in the same `ProcessCapabilities` table the existing endpoint capabilities live in, so the kernel's revocation, delegation, and policy checks all extend naturally — see [ADR-007](007-capability-revocation-and-telemetry.md) for revocation specifics.

### Channel record (kernel state)

```rust
pub struct ChannelRecord {
    pub id: ChannelId,
    pub creator_principal: Principal,    // Who called CREATE
    pub peer_principal: Principal,        // The named recipient
    pub size_bytes: u64,                  // Total channel size
    pub physical_base: u64,               // Physical address of page-aligned region
    pub creator_handle: Option<ChannelHandle>,
    pub peer_handle: Option<ChannelHandle>,  // None until ATTACH
    pub created_at_tick: u64,
    pub purpose: PurposeTag,             // Small enum or hash of a purpose string
    pub bytes_written_estimate: AtomicU64, // For telemetry — see ADR-007
    pub state: ChannelState,             // Active | Revoked | Closed
    pub kernel_signature: [u8; 64],      // Bootstrap key signs the record on creation
}

pub enum ChannelState {
    AwaitingAttach,
    Active,
    Revoked,
    Closed,
}
```

The kernel signature on the record is what makes channel telemetry trustworthy after the fact. The policy service (and the AI security service that may eventually replace it) can read the record and know that the metadata wasn't forged — the bootstrap key signed it at creation time. See [ADR-007](007-capability-revocation-and-telemetry.md) for the telemetry consumer side.

### New syscalls

| Number | Name | Purpose |
|---|---|---|
| (TBD) | `SYS_CHANNEL_CREATE` | Allocate a new channel; map RW into caller; return handle + capability token |
| (TBD) | `SYS_CHANNEL_ATTACH` | Verify capability token, map RO/RW into caller; return handle |
| (TBD) | `SYS_CHANNEL_CLOSE` | Unmap from both peers, free pages, revoke capability |
| (TBD) | `SYS_CHANNEL_REVOKE` | Force-close from a third party with revoke authority |
| (TBD) | `SYS_CHANNEL_INFO` | Read channel metadata (size, peers, purpose, byte counts) |

Numbers will be assigned when implementation lands. They are deliberately not specified here because the syscall numbering for CambiOS is contiguous and assigning them now would create gaps if implementation order shifts.

### Notification

The primary notification mechanism is **control IPC**: when a producer has written a batch of data into a channel ring buffer, it sends a small message through its existing 256-byte path saying "X bytes available." The consumer wakes (via the existing IPC blocking primitives — see [SCHEDULER.md § Blocking and Wake Primitives](../../src/scheduler/SCHEDULER.md#blocking-and-wake-primitives)), reads from the shared memory, and processes.

This means **no new notification primitive** in the kernel. The existing IPC layer carries the wake-up. The channel just carries the data the wake-up refers to.

For latency-critical workloads (audio, real-time inference) that can't tolerate the per-batch IPC notification, a future enhancement is per-channel doorbells with a dedicated `SYS_WAIT_CHANNEL` blocking primitive. This is explicitly out of scope for the initial implementation — we add it when measurement says we need it. The "send a small IPC after each batch" pattern is sufficient for everything currently on the v1 roadmap.

### Memory management and page tables

Channel memory comes from the existing physical frame allocator. The kernel allocates a contiguous (or chunked, for very large channels) range, marks it as "channel-pinned" in the frame allocator's bookkeeping (it cannot be swapped, paged out, or relocated while the channel exists), and maps it into the relevant processes' page tables via the existing per-process page table machinery (`OffsetPageTable` on x86_64, the L0–L3 walker on AArch64).

On `CLOSE` or `REVOKE`, the kernel must:

1. Unmap from process A (using the existing `unmap` path)
2. Issue a TLB shootdown for A's CPUs (existing `tlb::shootdown_range()` infrastructure)
3. Unmap from process B
4. Issue a TLB shootdown for B's CPUs
5. Free the physical pages back to the frame allocator
6. Mark the channel record as `Closed` or `Revoked`

The TLB shootdown uses the existing IPI machinery on x86_64 ([ADR-001 § Lock Ordering](001-smp-scheduling-and-lock-hierarchy.md#lock-ordering)) and the TLBI broadcast on AArch64.

### Capability revocation interaction

Channel close and channel revoke both interact with the capability manager (which sits at lock position 4 in the hierarchy). The full revocation primitive — including how a third party initiates it and how the kernel atomically tears down the mapping — is specified in [ADR-007](007-capability-revocation-and-telemetry.md).

The key invariant: **a revoked channel cannot leak data after revocation.** Once `SYS_CHANNEL_REVOKE` returns, both processes' page table mappings are gone and their TLBs are flushed. Any subsequent access from either side faults. This is structural enforcement — the MMU does the work, the kernel doesn't have to remember to check anything.

## Threat Model

### What channels protect against

| Threat | Mitigation |
|---|---|
| Process C reads a channel between A and B | Page table mappings exist only in A's and B's address spaces. C has no mapping. |
| Process A writes garbage into a channel after revocation | Revocation unmaps and TLB-shootdowns before returning. Subsequent writes fault. |
| Producer A overflows the channel | Channel size is fixed at create time. Ring buffer capacity is enforced by user-space code (which is the producer's own code — there is no incentive to overflow your own buffer). MMU enforces no access past the end of the mapping. |
| Consumer B writes to a producer-controlled region | B's mapping is RO. Writes fault. |
| Process A creates a channel, hands the capability to a process A is *not* authorized to talk to | The capability is bound to a specific peer Principal at create time. ATTACH verifies the calling process's Principal matches. Wrong Principal → attach fails. |
| Process A delegates a channel capability to escalate beyond its own authority | Same as endpoint capabilities — delegation requires explicit `delegate` rights and cannot escalate beyond what the holder already has. The capability manager's existing checks apply. |
| Forged channel capability | The capability includes a kernel signature over the record. ATTACH verifies the signature. Forgery requires the bootstrap key, which lives only on the YubiKey. |
| Process killed while holding a channel mapping | Process teardown calls `SYS_CHANNEL_REVOKE` for every channel the process is party to. Mappings are removed from the surviving peer atomically. The peer's next access through stale references faults; the peer learns of the close via control IPC. |

### What channels do NOT protect against (and what mitigates each)

| Risk | Mitigation |
|---|---|
| A malicious producer floods the consumer with garbage data | The consumer chose to attach. If A is sending garbage, B can `CLOSE` the channel and stop receiving. The capability is opt-in — the consumer is never forced to accept a channel from a process they don't trust. |
| Two cooperating malicious processes coordinate via shared memory the kernel can't see | This is true and intentional. The kernel never reads payload bytes. If process A and B both have legitimate capabilities to a shared channel, what they say to each other through that channel is between them. The kernel guarantees only what it always guaranteed: A and B were authorized to communicate, B's identity is what A thinks it is, the topology of communication is auditable. |
| The producer keeps writing data the consumer never reads, and the channel fills up | Producer-side problem. The ring buffer is producer-managed; the producer is responsible for backpressure. If the producer doesn't implement backpressure, that's a producer bug, not a kernel bug. |
| Side-channel timing attacks via shared memory access patterns | Same as any shared-memory system. CambiOS does not currently mitigate Spectre/Meltdown-class side channels and channels do not change this story. |
| The AI security service wants to inspect channel contents in real time | The AI doesn't get per-byte inspection by default. It gets per-channel telemetry (creation, capability holders, byte counts, lifecycle events) via the policy service, which is sufficient for behavioral anomaly detection. If a specific channel needs payload inspection, the policy service can request a snapshot — see [ADR-007 § Audit Telemetry](007-capability-revocation-and-telemetry.md#audit-telemetry). Inline payload inspection for every byte is *out of scope* — it's the wrong layer for AI. |

### Impact on the threat model from ADR-000

[ADR-000 § Threat Model](000-zta-and-cap.md#threat-model) lists threats and their mitigations. Channels do not weaken any of those. They add a new primitive to which the same enforcement principles apply:

- Channels are accessible only through capabilities (matches ADR-000's "no ambient authority")
- Channels have unforgeable creator/peer identity (matches ADR-003's identity model)
- Channels can be revoked (matches the gap analysis in [SECURITY.md § Gap Analysis](../../SECURITY.md#gap-analysis))
- Channels are auditable: every channel has a kernel-signed record naming who created it, who attached, when, and for what purpose

The TCB does not grow. The channel manager is a few hundred lines added to the kernel; it operates on the same primitives (page tables, frame allocator, capability manager, IPI for TLB shootdown) that the kernel already has.

## Verification Stance

The 256-byte fixed-size control IPC's verification properties are unchanged. ADR-002's three-layer enforcement still runs on every control message. The interceptor still inspects every send. The capability check still happens on every send. The verification target is the same.

Channels add a new verification target with a *simpler* property to prove: **the kernel correctly maps and unmaps the channel pages, and the capability check at ATTACH time matches the named peer.** Once those two facts are verified, the data flow is outside the kernel's responsibility and outside its verification surface.

This is structurally easier than verifying a stream. The kernel doesn't have to prove anything about the bytes; it has to prove that the *plumbing* (page table entries, TLB shootdowns, capability records) is correct. Page table reasoning is well-understood, and the relevant invariants are local: "after `ATTACH` returns, B has a mapping of the channel pages with the requested access mode and no other process does."

The trade is: we get a primitive that scales to any bandwidth, in exchange for verifying a different set of invariants than the control IPC verifies. The total verification surface increases, but each subsystem's invariants stay individually tractable. This is consistent with [CLAUDE.md § Formal Verification](../../CLAUDE.md#formal-verification-non-negotiable-constraint): "pure logic separated from effects" — the channel manager's logic (allocate, map, sign, record) is pure with respect to the data flow, and the data flow is the MMU's job.

## Why Not Just Make the Control IPC Bigger?

Several alternatives were considered before settling on two distinct primitives. Each is rejected for specific reasons.

### Option A: Bump the IPC payload from 256 to 1024 (or 2048, or 4096) bytes

**Why considered.** It's a five-line change. Memory cost is bounded (1024 bytes × 16 messages × 32 endpoints = 512 KB). Most current workloads would fit.

**Why rejected.** The 256-byte limit was the *symptom*; the architecture is the *cause*. A bigger fixed-size message gets us 4× headroom and then we hit the same wall when video, audio, file I/O, and inference workloads land. The verification surface gets bigger (4× more bytes per slot to reason about), the memory cost gets bigger, and the underlying problem ("kernel mediates every byte") is unchanged. We'd have spent the architectural complexity budget without buying the architectural property we actually need.

### Option B: Variable-size messages with a kernel slab allocator

**Why considered.** Pay only for what you use. Supports arbitrary sizes. Clean evolution from the existing API.

**Why rejected.** Three reasons. First, the verification posture takes a serious hit — variable-length buffers, allocator state, fragmentation, and OOM in the IPC hot path are all things the current design avoids by construction. Second, the throughput bound is still "kernel copies every byte" — even with a 64 KB message, a 500 MB/s video stream means ~8000 syscalls per second on the data path. Third, an in-kernel allocator on the IPC hot path is exactly the kind of complexity that bites later — lock contention, allocation failures under load, the need for OOM handling in the IPC layer itself.

### Option C: Two-tier IPC — small fast path + large slow path, both kernel-mediated

**Why considered.** Some microkernels (early seL4, MINIX 3) do this. Small messages take a register-based fast path; large messages take a copy-based slow path. Both go through the kernel.

**Why rejected.** The slow path still copies through the kernel, so it doesn't solve the throughput problem. It only solves the *latency* problem for large *control* messages (which we don't have — our control messages are already small). The fast path is something we could add as a future optimization to the existing 256-byte IPC if profiling shows it matters, but it's orthogonal to the data-plane question.

### Option D: External shared memory primitive (the chosen option, written here for completeness)

**Why chosen.** Solves the throughput problem structurally — the kernel is not on the data path, so its throughput limit does not apply. Composes with the existing capability and identity systems. Authorized by [CambiOS.md line 134](../../CambiOS.md). Verifiable as a separate, simpler invariant set than the control IPC. Enables real workloads (video, file I/O, LLM inference, audio) without compromising the control path's security properties.

The tradeoff: more kernel code (channel manager), more user-space discipline (ring buffer protocols), and a different threat model conversation (the channel data is between the two peers, not inspectable by the kernel — but the *topology* is). All three of these are acceptable in exchange for an architecture that scales to general-purpose workloads.

## Migration Path

This ADR is a *design*. Implementation lands in stages:

1. **ADR drafted, reviewed, accepted.** This document. Plus ADR-006 and ADR-007, which depend on it.
2. **Capability revocation primitive.** Independent of channels but required for the channel close path. See ADR-007.
3. **Channel manager + syscalls.** Kernel-side: `ChannelManager`, `ChannelRecord`, four new syscalls, page table integration, TLB shootdown integration.
4. **`libchannel` user-space crate.** Ring buffer library, channel handle wrappers, attach/close helpers, the standard SPSC pattern.
5. **First migration: virtio-net ↔ udp-stack.** The cleanest existing data path. Currently uses 256-byte IPC for raw Ethernet frames, which is barely large enough for one packet header. Migrating it proves the channel mechanism end-to-end and gives us a real performance baseline.
6. **Subsequent migrations.** Driven by the v1 roadmap — TCP stack, virtio-blk, persistent ObjectStore, etc. Each new data-plane consumer uses channels from the start; existing 256-byte consumers can migrate when convenient.
7. **Performance validation.** Measure end-to-end throughput on the virtio-net ↔ udp-stack path before and after migration. Use the result to size future channel allocations and tune the ring buffer protocol.

The control IPC layer is unchanged throughout this process. Existing services (fs-service, key-store, hello, shell) continue to work as-is. The architectural change is *additive* — nothing existing has to be rewritten, removed, or broken.

## Implementation Notes (for the eventual coder)

These are out of scope for the ADR but worth recording so they're not rediscovered later:

- **Channel size minimum.** One page (4 KB). Channels smaller than a page don't make sense — they would defeat the point of avoiding the kernel copy path, since 4 KB is already smaller than the kernel's per-message overhead amortized over a batch.
- **Channel size maximum.** Soft cap at 16 MB initially, configurable. Hard cap is bounded by available physical memory and by the per-process VMA tracker's capacity. Larger channels (100 MB+ for full video buffers) are possible but should require explicit policy approval — the policy service can decide.
- **Alignment.** Channels are page-aligned and the size is rounded up to a page. The producer's ring buffer head/tail metadata lives in the first page; payload starts on the second page. This is a `libchannel` convention, not a kernel-enforced layout.
- **AArch64 cache coherency.** ARM weakly-ordered memory means producer writes need release semantics and consumer reads need acquire semantics for the head/tail pointers. The ring buffer library handles this; the kernel doesn't need to.
- **NUMA.** Out of scope for v1. When NUMA awareness lands, channel allocation should prefer the producer's local node — this matches how Linux DPDK and similar high-throughput frameworks work.
- **Multi-producer / multi-consumer.** The default channel is SPSC (single producer, single consumer). MPMC is possible but should be a different capability variant — the lock-free ring buffer for MPMC is materially harder than SPSC, and most workloads don't need it.

## Cross-References

- **[ADR-000](000-zta-and-cap.md)** — Capability foundations (channels are capabilities)
- **[ADR-002](002-three-layer-enforcement-pipeline.md)** — Three-layer enforcement (still applies to control IPC; channels add their own setup-time check)
- **[ADR-003](003-content-addressed-storage-and-identity.md)** — Identity primitives (channels carry creator + peer Principals)
- **[ADR-006](006-policy-service.md)** — Policy externalization (channel creation may be policy-gated)
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Revocation mechanics + telemetry consumers (channel close paths and AI observability)
- **[CambiOS.md § The Microkernel](../../CambiOS.md)** — Source-of-truth: "no shared memory between services unless explicitly granted through a capability"
- **[CLAUDE.md § Lock Ordering](../../CLAUDE.md#lock-ordering)** — Channel manager will sit at a new position in the hierarchy (TBD during implementation)
- **[SECURITY.md § Gap Analysis](../../SECURITY.md#gap-analysis)** — Capability revocation gap (closes via ADR-007 + channels)
- **[SCHEDULER.md § Blocking and Wake Primitives](../../src/scheduler/SCHEDULER.md#blocking-and-wake-primitives)** — Notification path (channels reuse existing IPC wake)

## See Also in CLAUDE.md

When implementing the changes specified by this ADR, the following CLAUDE.md sections must be updated to reflect the new architecture:

- **§ "Current state"** paragraph — note channel support
- **§ "Lock Ordering"** — add the channel manager's position
- **§ "Syscall Numbers"** — add the four new channel syscalls when assigned
- **§ "Required Reading by Subsystem"** (when added) — under "If you are touching IPC" and "If you are adding a new user-space service"
- **§ "Post-Change Review Protocol" Step 8** (when added) — channels touch page tables, so the change set affects the memory subsystem reference docs as well
