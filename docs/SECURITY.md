# CambiOS Security Architecture

This document maps the zero-trust enforcement points in the CambiOS microkernel — *what* is enforced, *where* in the code, and *why*. It is the security-specific reference; project-wide implementation status (what's built vs. designed vs. planned, test counts, phase markers) lives in **[STATUS.md](../STATUS.md)**.

**Required reading by topic:**
- Foundational security *decision* (why capabilities, why zero-trust): [ADR-000](adr/000-zta-and-cap.md)
- Enforcement *pipeline* decision (why three layers, why this ordering): [ADR-002](adr/002-three-layer-enforcement-pipeline.md)
- Content-addressed storage and identity: [ADR-003](adr/003-content-addressed-storage-and-identity.md)
- Cryptographic integrity (signed binaries, signed objects): [ADR-004](adr/004-cryptographic-integrity.md)
- IPC primitives — control path and bulk-data channels: [ADR-005](adr/005-ipc-primitives-control-and-bulk.md)
- Policy service — externalized `on_syscall` decisions: [ADR-006](adr/006-policy-service.md)
- Capability revocation and audit telemetry: [ADR-007](adr/007-capability-revocation-and-telemetry.md)

---

## Enforcement Status Summary

This table maps every enforcement point to its code location and *what* it does. For the project-wide "is X built yet" view, see [STATUS.md § Subsystem status](../STATUS.md#subsystem-status).

| Enforcement Point | Status | Blocks on Failure | Where |
|---|---|---|---|
| ELF entry point validation | **Enforced** | Binary not loaded | `loader/mod.rs` |
| ELF kernel space rejection | **Enforced** | Binary not loaded | `loader/mod.rs` |
| ELF W^X enforcement | **Enforced** | Binary not loaded | `loader/mod.rs` |
| ELF segment overlap detection | **Enforced** | Binary not loaded | `loader/mod.rs` |
| ELF memory limit | **Enforced** | Binary not loaded | `loader/mod.rs` |
| ELF Ed25519 signature verification | **Enforced** | Binary not loaded | `loader/mod.rs` (`SignedBinaryVerifier`) |
| Capability check (IPC send) | **Enforced** | `PermissionDenied` | `ipc/mod.rs` |
| Capability check (IPC recv) | **Enforced** | `PermissionDenied` | `ipc/mod.rs` |
| Capability delegation validation | **Enforced** | `AccessDenied` | `ipc/capability.rs` |
| Interceptor: syscall pre-dispatch | **Scaffolding** (designed in [ADR-006](adr/006-policy-service.md)) | Always allows; policy externalization pending | `syscalls/dispatcher.rs` |
| Interceptor: IPC send policy | **Enforced** | `PermissionDenied` | `ipc/mod.rs`, `ipc/interceptor.rs` |
| Interceptor: IPC recv policy | **Enforced** | `PermissionDenied` | `ipc/mod.rs`, `ipc/interceptor.rs` |
| Interceptor: delegation policy | **Enforced** | `AccessDenied` | `ipc/capability.rs` |
| IPC sender_principal stamping | **Enforced** | N/A (kernel stamps unconditionally) | `ipc/mod.rs` |
| BindPrincipal restricted to bootstrap | **Enforced** | `PermissionDenied` | `syscalls/dispatcher.rs` |
| ObjPut Ed25519 signature verification | **Enforced** | `PermissionDenied` | `syscalls/dispatcher.rs` (`ObjPutSigned`) |
| ObjDelete ownership enforcement | **Enforced** | `PermissionDenied` | `syscalls/dispatcher.rs` |
| FS service principal-based access | **Enforced** | Error response to caller | `user/fs-service/src/main.rs` |
| Bulk-data channel capability checks | **Enforced** (creator + peer-Principal match at attach) | `ChannelError::*` | `ipc/channel.rs` |
| Capability revocation (`SYS_REVOKE_CAPABILITY`) | **Enforced** (bootstrap-only authority for now per ADR-007 Phase 3.1) | `PermissionDenied` | `syscalls/dispatcher.rs`, `ipc/capability.rs::revoke` |
| Audit telemetry channel | **Enforced** (per-CPU SPSC buffers → BSP drain → `AUDIT_RING`; consumer reads via `SYS_AUDIT_ATTACH`/`SYS_AUDIT_INFO`) | N/A (best-effort, drops counted) | `audit/{mod,buffer,drain}.rs`, `syscalls/dispatcher.rs` |
| Audit on input focus transition (T-7 Phase A) | **Enforced** (compositor emits `InputFocusChange` via `SYS_AUDIT_EMIT_INPUT_FOCUS`; capability narrowed to compositor only) | `PermissionDenied` if non-compositor | `syscalls/dispatcher.rs::handle_audit_emit_input_focus`, `microkernel/main.rs::register_process_capabilities` |
| Audit drain-skip counter (T-8) | **Enforced** (lock-free `AUDIT_DRAIN_SKIPS` atomic; surfaced through `SYS_AUDIT_INFO` offset 44..48) | N/A (visibility primitive) | `audit/drain.rs`, `syscalls/dispatcher.rs::handle_audit_info` |
| Externalized policy service | **Scaffolding** (boot-module identified at `POLICY_SERVICE_PID`; `on_syscall` hook still permissive — see [ADR-006](adr/006-policy-service.md)) | Always allows | `microkernel/main.rs`, `ipc/interceptor.rs` |
| Per-process syscall allowlists | **Designed in [ADR-006](adr/006-policy-service.md)**, not implemented | — | — |
| Runtime behavioral AI (advisory only) | **Designed in [ADR-007](adr/007-capability-revocation-and-telemetry.md)**, not implemented | — | — |
| Cryptographic capabilities (cross-node) | Planned (post-v1) | — | — |

**Enforced** = real check that returns an error and blocks the operation on failure. **Scaffolding** = hook is wired into the call path but the default policy is permissive (real policy lives in the linked ADR). **Designed** = ADR drafted, code not yet written.

Code line numbers were intentionally removed from this table — they drift on every change. Use grep or your editor's symbol search to find the specific call site within the listed file.

---

## The Three-Layer Enforcement Pipeline

Every IPC operation passes through three independent enforcement layers. Bypassing one does not bypass the others.

```
Process makes SYS_WRITE or SYS_READ syscall
    |
    v
+-----------------------------------------------+
|  Layer 1: Interceptor pre-dispatch             |
|  IpcInterceptor::on_syscall()                  |
|  - Per-process syscall allowlist               |
|  - Status: SCAFFOLDING (always allows)         |
|  - File: syscalls/dispatcher.rs:182            |
+-----------------------------------------------+
    |
    v
+-----------------------------------------------+
|  Layer 2: Capability verification              |
|  CapabilityManager::verify_access()            |
|  - Process must hold correct rights for        |
|    the target endpoint (SEND or RECV)          |
|  - Status: ENFORCED                            |
|  - File: ipc/capability.rs:114-128             |
+-----------------------------------------------+
    |
    v
+-----------------------------------------------+
|  Layer 3: Interceptor post-capability          |
|  IpcInterceptor::on_send() / on_recv()         |
|  - Endpoint bounds check                       |
|  - Payload size limit (256 bytes)              |
|  - No self-send                                |
|  - Status: ENFORCED                            |
|  - File: ipc/interceptor.rs:145-212            |
+-----------------------------------------------+
    |
    v
  IPC operation proceeds
```

### Why Three Layers Instead of One

A single capability check would be sufficient if capabilities were the only thing that could go wrong. They aren't:

- **Layer 1** catches a compromised process that tries to invoke syscalls outside its profile. A serial driver that only needs `Write` and `WaitIrq` should never call `Allocate`. Even if it holds capabilities, it shouldn't be making that syscall at all.

- **Layer 2** is the core access control. Capabilities are unforgeable kernel-managed tokens. If you don't hold the right token, the operation fails. This is the load-bearing wall.

- **Layer 3** catches structural violations that capabilities don't address: oversized payloads (buffer overflow prevention), out-of-bounds endpoints (kernel memory safety), self-send (deadlock prevention). These are invariants about the *message*, not the *authority*.

Each layer is independently useful. Together, they make exploitation require three independent bypasses.

---

## ELF Verification Gate

The verifier runs before the loader allocates any resources. A binary that fails verification causes zero side effects — no frames allocated, no pages mapped, no process created.

```
Raw ELF binary bytes
    |
    v
Parse ELF header + collect LOAD segments
    |
    v
+-----------------------------------------------+
|  BinaryVerifier::verify()                      |
|  1. Entry point falls within a LOAD segment    |
|  2. All segments in user space (< canonical)   |
|  3. No segment is both writable AND executable  |
|  4. No overlapping segment virtual addresses    |
|  5. Total memory footprint <= 256 MB            |
+-----------------------------------------------+
    |                          |
    | Allow                    | Deny(reason)
    v                          v
  Allocate frames,           Return error immediately.
  create page table,         No resources consumed.
  map segments,
  create process.
```

### What the Verifier Prevents

| Attack | Check | Result |
|---|---|---|
| Jump to kernel code | Entry point must be in a LOAD segment | `EntryPointOutOfRange` |
| Map pages into kernel space | All segments < 0x0000_8000_0000_0000 | `SegmentInKernelSpace` |
| Self-modifying shellcode | No page is W+X simultaneously | `WritableAndExecutable` |
| Aliased memory confused deputy | Segments must not overlap | `OverlappingSegments` |
| OOM denial of service | Total memory <= 256 MB | `ExcessiveMemory` |

### Can a Binary Bypass the Verifier?

No. `load_elf_process()` takes `verifier: &dyn BinaryVerifier` as a required parameter. The verify call is unconditional — there is no code path that skips it. The only way to load a binary without verification is to write a new loader that doesn't call the verifier, which requires modifying kernel code.

---

## Capability System

### What a Capability Is

A capability is a kernel-managed `(endpoint, rights)` pair. User-space cannot see, touch, or fabricate capabilities. They exist only inside the kernel's `CapabilityManager`.

```
Capability {
    endpoint: EndpointId,     // Which IPC endpoint
    rights: CapabilityRights, // What operations are allowed
}

CapabilityRights {
    send: bool,      // Can send messages to this endpoint
    receive: bool,   // Can receive messages from this endpoint
    delegate: bool,  // Can grant this capability to another process
}
```

### How Capabilities Are Created

There are exactly two paths:

1. **SYS_REGISTER_ENDPOINT** — A process registers a new IPC endpoint. The kernel grants the registering process full rights (send + recv + delegate) on that endpoint. This is the only way to create a new capability from nothing.

2. **Delegation** — A process that holds a capability with `delegate = true` can grant a subset of its rights to another process. You cannot delegate more rights than you hold. You cannot delegate without the delegate right.

### What Prevents Forgery

- `ProcessCapabilities` is a struct in `capability.rs` with all internal fields private. No public constructor — only `CapabilityManager` methods can create or mutate instances.
- Capabilities are stored in a kernel-managed table indexed by process ID. User-space has no pointer to this table.
- The only mutations are through `CapabilityManager` methods, which enforce all invariants.
- There is no syscall that says "give me a capability for endpoint X." The only paths are register (you create the endpoint) or delegate (someone who has it gives it to you).

### Delegation Flow

```
Process A holds: Capability { endpoint: 5, rights: send + delegate }
Process A delegates to Process B: rights = send (no delegate)

Checks:
  1. Interceptor: on_delegate(A, B, endpoint=5, rights=send) → Allow?
  2. A has delegate right on endpoint 5? → Yes
  3. A holds at least the rights being delegated (send)? → Yes
  4. Grant to B: Capability { endpoint: 5, rights: send }

Result: B can send to endpoint 5. B cannot delegate further.
```

### What Delegation Cannot Do

- **Escalate rights.** A process with send-only cannot delegate recv. A process without delegate cannot delegate at all.
- **Self-delegate.** The interceptor rejects source == target.
- **Exceed 32 capabilities per process.** The per-process table has a hard limit.

---

## Identity Enforcement (Phase 0)

Cryptographic identity is woven into the kernel's IPC and storage layers. There are no passwords. Every process either has a bound Principal (an Ed25519 public key) or has no identity at all.

### Principal Binding

A `Principal` is a 32-byte Ed25519 public key bound to a process by the kernel. Binding is restricted:

- Only a process whose own Principal matches the **bootstrap Principal** can call `SYS_BIND_PRINCIPAL` (syscall 11). All other callers get `PermissionDenied`.
- A process can be bound at most once. Double-bind attempts are rejected.
- Kernel processes 0–2 are bound to the bootstrap Principal at boot.

The bootstrap Principal's public key is compiled into the kernel from `bootstrap_pubkey.bin`, extracted from the signing YubiKey. The private key lives exclusively on the hardware YubiKey — it never enters kernel memory. Boot modules are signed at build time by the YubiKey via the `sign-elf` tool's OpenPGP smart card interface.

### IPC Sender Identity (Unforgeable)

Every IPC message carries a `sender_principal` field. This field is **set by the kernel** in `send_message_with_capability()` at [ipc/mod.rs:586](../src/ipc/mod.rs#L586), not by user code. User-space cannot write to this field — any value it sets is overwritten before the message is enqueued.

```
Process A calls SYS_WRITE → kernel IPC path:
  1. Capability check (does A have SEND on this endpoint?)
  2. Kernel reads A's bound Principal from CapabilityManager
  3. Kernel stamps msg.sender_principal = A's Principal (or None if unbound)
  4. Interceptor check
  5. Message enqueued with unforgeable identity
```

The receiving process (via `SYS_RECV_MSG`, syscall 13) gets the 32-byte `sender_principal` prepended to the payload. It can verify who sent the message without trusting the sender's self-identification.

### What Identity Prevents

| Attack | Enforcement | Result |
|---|---|---|
| Process claims to be another identity | Kernel stamps real Principal | Forgery impossible |
| Unauthorized process binds identities | Only bootstrap Principal can call BindPrincipal | `PermissionDenied` |
| Process reads another's identity | GetPrincipal returns caller's own | No cross-process read |

---

## ObjectStore Enforcement (Phase 0)

CambiOS storage is content-addressed signed objects, not files-at-paths. The `ObjectStore` is the kernel's storage primitive; the FS service is a user-space gateway to it.

### Ownership Model

Every `CambiObject` has an immutable **author** (who created it) and a transferable **owner** (who controls it). The kernel enforces ownership on destructive operations:

- **ObjPut** (syscall 14): The caller's Principal becomes the author and owner. Content is hashed (Blake3) and stored. Returns the 32-byte content hash.
- **ObjGet** (syscall 15): Any process can read by hash. No ownership check on read (content-addressed data is inherently shareable).
- **ObjDelete** (syscall 16): The kernel verifies the caller's Principal matches the object's owner at [dispatcher.rs:939](../src/syscalls/dispatcher.rs#L939). Non-owners get `PermissionDenied`.
- **ObjList** (syscall 17): Lists all hashes. No access restriction (hashes are not secrets — the content they reference may be).

### FS Service (User-Space Enforcement Layer)

The FS service (`user/fs-service/`) runs as a user-space process on IPC endpoint 16. It adds an additional enforcement layer on top of the kernel's ObjectStore syscalls:

- Receives messages via `SYS_RECV_MSG`, which includes the kernel-stamped `sender_principal`
- DELETE commands check that `sender_principal` is non-zero (anonymous callers rejected) at [fs-service/src/main.rs:218](user/fs-service/src/main.rs#L218)
- Delegates to kernel ObjDelete, which does the real ownership check

This is defense-in-depth: the FS service rejects obviously unauthorized requests before they reach the kernel, and the kernel enforces the authoritative ownership check.

---

## Interceptor Details

The `IpcInterceptor` trait defines four hooks. The `DefaultInterceptor` provides baseline policy. Custom interceptors can be substituted for stricter enforcement.

### Hook: on_syscall (Layer 1)

**Current status: Scaffolding.** Always returns `Allow`.

This hook fires before the syscall dispatcher routes to a handler. It receives the caller's process ID and the syscall number. The intended use is per-process syscall allowlists:

```
Serial driver profile: [Write, WaitIrq, Yield, GetPid]
Filesystem driver profile: [Read, Write, Allocate, Free, RegisterEndpoint, Yield]
```

A process that attempts a syscall outside its profile gets `PermissionDenied` before any work happens. The hook is wired at `dispatcher.rs:182` — only the policy logic is missing.

### Hook: on_send (Layer 3)

**Current status: Enforced.** Three checks:

1. Endpoint ID < MAX_ENDPOINTS (32) — prevents out-of-bounds access
2. Payload length <= 256 bytes — prevents buffer overflow
3. Sender process ID != endpoint ID — prevents self-send deadlock

### Hook: on_recv (Layer 3)

**Current status: Enforced.** One check:

1. Endpoint ID < MAX_ENDPOINTS (32) — prevents out-of-bounds access

### Hook: on_delegate (Layer 3)

**Current status: Enforced.** Two checks:

1. Endpoint ID < MAX_ENDPOINTS (32) — prevents out-of-bounds access
2. Source process ID != target process ID — prevents self-delegation

### Substituting a Custom Interceptor

The interceptor is held as `IpcInterceptorBackend` — an enum-dispatch shim ([ADR-002 § Divergence](adr/002-three-layer-enforcement-pipeline.md#divergence)) chosen over `Box<dyn IpcInterceptor>` so dispatch monomorphizes (no dynamic dispatch in the kernel hot path; same precedent as ADR-003 for `OBJECT_STORE`). At boot, `main.rs` installs the `DefaultInterceptor` variant. Adding a new interceptor implementation today means adding a variant to the enum and an arm to the impl; the swap site is still a single line: `ipc.set_interceptor(IpcInterceptorBackend::MyInterceptor(MyInterceptor::new()))`.

A production deployment's interceptor could:

- Read per-process syscall profiles from a policy table
- Log all capability exercises to an audit buffer
- Connect to the AI security engine for behavioral analysis
- Enforce rate limits on IPC send frequency

---

## Bulk-Data Channels (Phase 3 — Designed)

The 256-byte fixed control IPC is *not* the data plane. Bulk data (video frames, file blocks, LLM token streams) needs a separate primitive: shared-memory **channels**, designed in [ADR-005](adr/005-ipc-primitives-control-and-bulk.md). Channels are a security-relevant addition because they introduce the first IPC path the kernel does *not* read byte-for-byte. The security model must hold without that read.

How the model still holds:

- **Channel creation is a control-IPC operation.** `SYS_CHANNEL_CREATE` is mediated by the kernel and gated by capabilities. A process cannot conjure a channel into existence — it must hold the right to ask the kernel to create one between two consenting endpoints.
- **Capabilities, not pointers.** A `ChannelCapability` is a kernel-managed token. The mapped pages are only accessible to processes that hold a capability for that channel. There is no "anyone with the address can read it" semantic.
- **Notification still goes through control IPC.** The producer writes data into the shared ring, then sends a small "data ready" message through the existing 256-byte IPC path. The kernel still sees the notification, still stamps `sender_principal` on it, still runs the interceptor. The bulk data is the payload of the *transaction*, but the *transaction itself* is still kernel-mediated.
- **Channels are revocable.** `SYS_CHANNEL_REVOKE` (paired with the capability revocation primitive in [ADR-007](adr/007-capability-revocation-and-telemetry.md)) tears down the shared mapping and any in-flight references. A compromised process loses its data plane the same way it loses its control plane.
- **The kernel can still observe.** Audit telemetry ([ADR-007](adr/007-capability-revocation-and-telemetry.md)) records channel create/attach/close/revoke events. The AI never sees the bytes flowing through a channel; it sees that two services have a channel, how often it's used, and whether the topology is anomalous. *The AI watches; it does not decide.*

What channels do *not* change: the verification stance for control-path messages (256 bytes, fixed, kernel reads every byte), the capability model, the three-layer enforcement pipeline, or `sender_principal` stamping. Channels are an *additional* primitive, not a replacement.

---

## Externalized Policy and Audit Telemetry (Phase 3)

Three architectural moves shift how security policy is decided and observed without changing what the kernel enforces. Two have shipped; one remains in design:

**Capability revocation ([ADR-007](adr/007-capability-revocation-and-telemetry.md)) — shipped.** `SYS_REVOKE_CAPABILITY` lives in `syscalls/dispatcher.rs`, backed by `CapabilityManager::revoke` with audit emission. Authority is bootstrap-only in Phase 3.1; the broader authority surface called for in ADR-007 (original grantor, holders of the new `revoke` right, the policy service) is queued for Phase 3.4. Atomic teardown of in-flight references is in place via the existing channel close path + capability table mutation. This was the prerequisite for everything else in Phase 3 — without revocation, the AI's recommendations would have no teeth and the policy service could only deny *new* operations, never undo prior grants.

**Audit telemetry ([ADR-007](adr/007-capability-revocation-and-telemetry.md)) — shipped.** Capability grant / revocation / denial, IPC send/recv (sampled), channel create/attach/close, syscall denial, binary load/reject, process create/exit, and (T-7 Phase A, 2026-04-25) input focus transitions all produce audit events. Events flow through per-CPU lock-free SPSC staging buffers → BSP-driven `drain_tick` → a global `AUDIT_RING`. User-space consumers attach via `SYS_AUDIT_ATTACH` (bootstrap-only) and read offsets via `SYS_AUDIT_INFO`. Best-effort delivery: dropped events are counted both per-buffer (`AuditDropped` synthetic event) and at drain time (T-8 `AUDIT_DRAIN_SKIPS` lock-free counter, `SYS_AUDIT_INFO` offset 44..48). The audit channel is the *only* way the AI security service learns what's happening on the system — there is no kernel hook the AI can call directly, no capability the AI holds to suspend a process, no out-of-band introspection. The AI is a user-space process that reads an event stream and emits recommendations into the policy service's input queue.

**Policy externalization ([ADR-006](adr/006-policy-service.md)) — still scaffolding.** The `IpcInterceptor::on_syscall` hook is wired into the kernel and the policy service boot module is identified at `POLICY_SERVICE_PID`, but the decision path is still permissive (`POLICY_SERVICE_READY` enables enforcement only after the service registers; the default decision today is `Allow`). The plan is to move the *decision* into the user-space `policy-service` while keeping the *enforcement* in the kernel. The kernel asks "is process P allowed to call syscall N with these args?" via a fast per-CPU cache; the policy service answers and the kernel acts. Cache invalidation, fail-open semantics on policy-service crash, and the bootstrap order that allows the policy service to load *before* it gates other services are all spelled out in the ADR. Critically: the AI is never the policy service. The policy service is deterministic Rust code; the AI is an *advisor* that can recommend changes to policy-service rules through its own audit channel. The AI watches, the policy service decides, the kernel enforces.

---

## Gap Analysis

The gaps below are organized by whether they have a design (ADR drafted) or are still open questions. Implementation status of each item lives in [STATUS.md](../STATUS.md).

### Designed, Implementation Pending (Phase 3)

| Gap | Impact | Where It's Designed |
|---|---|---|
| **Per-process syscall allowlists** | A compromised process can invoke any syscall it has arguments for | [ADR-006](adr/006-policy-service.md) — `on_syscall` hook routed through policy service |
| **Externalized policy decisions** | All policy lives inside the kernel; cannot be updated without a kernel rebuild | [ADR-006](adr/006-policy-service.md) |
| **Capability revocation — broader authority** | Today only the bootstrap Principal can call `SYS_REVOKE_CAPABILITY`. ADR-007 calls for the original grantor, any process holding the new `revoke` right, and the policy service to also be able to revoke; that authority surface is queued for Phase 3.4. | [ADR-007](adr/007-capability-revocation-and-telemetry.md) |
| **Runtime behavioral AI (advisory)** | No detection of anomalous capability usage patterns | [ADR-007](adr/007-capability-revocation-and-telemetry.md) — AI consumes the audit channel, recommends to policy service, never decides directly |
| **Privileged audit consumer** | The audit ring + drain-skip counter ship today, but no kernel-side actor polls them and escalates on rising skip counts. T-7 / T-8 in [threat-model.md](threat-model.md) document the gap. | TBD — likely a small `audit-health` boot module or a policy-service responsibility |

### Open / Not Yet Designed

| Gap | Impact | Notes |
|---|---|---|
| **ObjGet access control** | Any process can read any object by hash | Hashes are not secrets, so this is not strictly a defect — but per-object ACLs may be wanted for sensitive content. ObjectStore already has the `ObjectCapSet` field; needs an enforcement story. |
| **Capability expiry / TTL** | Granted capabilities last forever unless revoked | Add TTL field to `Capability`, check in `verify_access()`. Useful for short-lived delegations (e.g., "let this one binary read this one file"). |
| **IPC rate limiting** | No defense against IPC flooding DoS | `on_send` hook — track send count per process per interval. Becomes more important once channels exist (ADR-005), since channels open a path the kernel *doesn't* per-byte inspect. |
| **Cryptographic capabilities** | Capabilities don't work across networked CambiOS nodes | Replace kernel tables with signed tokens. Only matters once Yggdrasil mesh networking lands; not a v1 concern. |

### Done (Historical)

- ~~**Bootstrap Principal hardening**~~ — Hardware-backed YubiKey root of trust. Secret key never enters kernel memory. Boot modules signed at build time, verified at load time.
- ~~**ELF signature verification**~~ — `SignedBinaryVerifier` enforces Ed25519 signatures (ARCSIG trailer) on all boot modules.
- ~~**IPC sender_principal stamping**~~ — Kernel stamps unforgeable identity on every control-IPC message.
- ~~**Capability revocation primitive**~~ — `SYS_REVOKE_CAPABILITY` lives at `syscalls/dispatcher.rs`; backed by `CapabilityManager::revoke` with audit emission. Authority is bootstrap-only for Phase 3.1 (broader authority queued — see Gap Analysis above).
- ~~**Audit telemetry channel**~~ — Per-CPU lock-free SPSC staging buffers + BSP-driven `drain_tick` → `AUDIT_RING` consumer. 17 event kinds wired (see [threat-model.md T-7 / T-8](threat-model.md#t-7--virtio-input-focus-hijack)). Best-effort delivery: drops are counted (per-buffer staging-drop counter + `AUDIT_DRAIN_SKIPS` lock-free leading-indicator counter, surfaced through `SYS_AUDIT_INFO`).
- ~~**Bulk-data shared-memory channels (control-path)**~~ — `SYS_CHANNEL_CREATE` / `SYS_CHANNEL_ATTACH` / `SYS_CHANNEL_REVOKE` ship per [ADR-005](adr/005-ipc-primitives-control-and-bulk.md). Kernel-mediated creation, capability-gated allocation, peer-Principal match at attach. The pages flow user-to-user; the create/attach/close events flow through the audit ring.
- ~~**ELF page-permission conflict rejection (T-5)**~~ — `DefaultVerifier` rejects any pair of `PT_LOAD` segments whose page-aligned ranges overlap with conflicting permissions (`DenyReason::PagePermConflict`). Closes the build-time hygiene gap that signed binaries could otherwise sneak through.

### Priority Order for Phase 3

Items 1–3 below have shipped (see "Done (Historical)"); items 4–6 are what's left, in dependency order. Tracked alongside the project-wide phase markers in [STATUS.md § Phase markers](../STATUS.md#phase-markers).

1. ~~**Capability revocation** — every other Phase 3 item depended on this.~~ Shipped (bootstrap-only authority in Phase 3.1; broader authority surface tracked under Gap Analysis).
2. ~~**Audit telemetry channel**~~ — shipped (per-CPU buffers + drain + ring + `SYS_AUDIT_*` consumer surface).
3. ~~**Channels** — bulk-data path.~~ Shipped (control-path: create/attach/close/revoke through capabilities; bulk pages flow user-to-user).
4. **Policy service** — boot-module shipped and identified at `POLICY_SERVICE_PID`; the `on_syscall` decision path is still permissive scaffolding. Externalizing the actual decisions is what's left.
5. **Privileged audit consumer** — the audit ring + drain-skip counter are observable but nothing kernel-side polls them and escalates. Required for T-7 / T-8 to graduate from "visibility" to "structural defense."
6. **Behavioral AI** — sits on top of policy + audit consumer. Watches the audit channel, emits recommendations into the policy service's input.

For test coverage of the currently-enforced security points, see [STATUS.md § Test coverage](../STATUS.md#test-coverage).

---

## Architectural Invariants

These properties must hold after every change to security-related code:

1. **No binary runs without verification.** Every path from raw bytes to executing code passes through `BinaryVerifier::verify()`.

2. **No IPC without capability.** Every `send_message` and `recv_message` passes through `verify_access()`. There is no "internal" send that skips the check.

3. **No delegation without authorization.** `can_delegate()` enforces that the source holds the delegate right and is not escalating beyond its own rights.

4. **Interceptor is not optional.** The interceptor is set at boot and cannot be removed at runtime. Every IPC operation passes through it. The interceptor and capability check are independent — bypassing one does not bypass the other.

5. **Verification before allocation.** The ELF verifier runs before any frame allocation, page mapping, or process creation. A denied binary consumes zero resources.

6. **Deny by default.** A new process holds zero capabilities. It cannot do anything until explicitly granted access.

7. **Sender identity is unforgeable.** The kernel stamps `msg.sender_principal` in the IPC send path. User-space values are overwritten. A receiving process can trust `sender_principal` as kernel-attested.

8. **Only bootstrap can bind identity.** `SYS_BIND_PRINCIPAL` checks the caller's Principal against `BOOTSTRAP_PRINCIPAL`. No other process can assign identities, even if it holds all IPC capabilities.

9. **Only owners can delete objects.** `SYS_OBJ_DELETE` verifies the caller's Principal matches the object's `owner` field. This is enforced in the kernel, not just in user-space services.
