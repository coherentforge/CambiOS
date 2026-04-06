# ArcOS Security Architecture

This document maps the zero-trust enforcement points in the ArcOS microkernel — what's enforced, where, and how. It is a living reference. When an enforcement point moves from scaffolding to real, or a new layer is added, this document gets updated.

For the foundational security *decision* (why capabilities, why zero-trust), see [ADR-000](docs/adr/000-zta-and-cap.md).
For the enforcement *pipeline* decision (why three layers, why this ordering), see [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md).

---

## Enforcement Status Summary

| Enforcement Point | Status | Blocks on Failure | Location |
|---|---|---|---|
| ELF entry point validation | **Enforced** | Binary not loaded | `loader/mod.rs:154` |
| ELF kernel space rejection | **Enforced** | Binary not loaded | `loader/mod.rs:165` |
| ELF W^X enforcement | **Enforced** | Binary not loaded | `loader/mod.rs:172` |
| ELF segment overlap detection | **Enforced** | Binary not loaded | `loader/mod.rs:180` |
| ELF memory limit | **Enforced** | Binary not loaded | `loader/mod.rs:193` |
| Capability check (IPC send) | **Enforced** | `PermissionDenied` | `ipc/mod.rs:582` |
| Capability check (IPC recv) | **Enforced** | `PermissionDenied` | `ipc/mod.rs:612` |
| Capability delegation validation | **Enforced** | `AccessDenied` | `capability.rs:425` |
| Interceptor: syscall pre-dispatch | **Scaffolding** | Always allows (hook wired, policy permissive) | `dispatcher.rs:182` |
| Interceptor: IPC send policy | **Enforced** | `PermissionDenied` | `ipc/mod.rs:591` |
| Interceptor: IPC recv policy | **Enforced** | `PermissionDenied` | `ipc/mod.rs:618` |
| Interceptor: delegation policy | **Enforced** | `AccessDenied` | `capability.rs:425` |
| IPC sender_principal stamping | **Enforced** | N/A (kernel stamps unconditionally) | `ipc/mod.rs:586` |
| BindPrincipal restricted to bootstrap | **Enforced** | `PermissionDenied` | `dispatcher.rs:671` |
| ObjDelete ownership enforcement | **Enforced** | `PermissionDenied` | `dispatcher.rs:939` |
| FS service principal-based access | **Enforced** | Error response to caller | `user/fs-service/src/main.rs:218` |
| Per-process syscall allowlists | **Not implemented** | — | — |
| Runtime behavioral monitoring (AI) | **Not implemented** | — | — |
| Capability revocation | **Not implemented** | — | — |
| Capability audit logging | **Not implemented** | — | — |
| Cryptographic capabilities | **Not implemented** | — | — |

**Enforced** = real check that returns an error and blocks the operation on failure.
**Scaffolding** = hook is wired into the call path but the default policy is permissive.
**Not implemented** = no code exists yet.

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

Every IPC message carries a `sender_principal` field. This field is **set by the kernel** in `send_message_with_capability()` at [ipc/mod.rs:586](src/ipc/mod.rs#L586), not by user code. User-space cannot write to this field — any value it sets is overwritten before the message is enqueued.

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

ArcOS storage is content-addressed signed objects, not files-at-paths. The `ObjectStore` is the kernel's storage primitive; the FS service is a user-space gateway to it.

### Ownership Model

Every `ArcObject` has an immutable **author** (who created it) and a transferable **owner** (who controls it). The kernel enforces ownership on destructive operations:

- **ObjPut** (syscall 14): The caller's Principal becomes the author and owner. Content is hashed (Blake3) and stored. Returns the 32-byte content hash.
- **ObjGet** (syscall 15): Any process can read by hash. No ownership check on read (content-addressed data is inherently shareable).
- **ObjDelete** (syscall 16): The kernel verifies the caller's Principal matches the object's owner at [dispatcher.rs:939](src/syscalls/dispatcher.rs#L939). Non-owners get `PermissionDenied`.
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

The interceptor is a trait object (`Box<dyn IpcInterceptor>`). At boot, `main.rs` installs the `DefaultInterceptor`. A production deployment could install a stricter interceptor that:

- Reads per-process syscall profiles from a policy table
- Logs all capability exercises to an audit buffer
- Connects to the AI security engine for behavioral analysis
- Enforces rate limits on IPC send frequency

The swap is a single line: `ipc.set_interceptor(Box::new(MyInterceptor::new()))`.

---

## Gap Analysis

### What's Needed for Full Zero-Trust

| Gap | Impact | Difficulty | Where It Plugs In |
|---|---|---|---|
| **Per-process syscall allowlists** | A compromised process can invoke any syscall it has arguments for | Medium | `on_syscall` hook — policy logic, not plumbing |
| **ELF signature verification** | Any structurally valid binary can load — no code authenticity check | Medium | `BinaryVerifier` + Ed25519 signature check before loading |
| **Capability revocation** | A capability granted in error cannot be taken back | Medium | `CapabilityManager` needs `revoke()` method + API to trigger it |
| **Audit logging** | No forensic trail of capability exercises or identity operations | Low | Interceptor hooks already see every operation; need a log sink |
| **ObjGet access control** | Any process can read any object by hash | Low | ObjectStore or FS service can add per-object ACL checks |
| **Runtime behavioral AI** | No detection of anomalous capability usage patterns | High | Interceptor hooks are the integration points; needs AI inference engine |
| **Cryptographic capabilities** | Capabilities don't work across networked ArcOS nodes | High | Replace kernel tables with signed tokens (HMAC or Ed25519) |
| **Capability expiry** | Granted capabilities last forever | Low | Add TTL field to `Capability`, check in `verify_access()` |
| **IPC rate limiting** | No defense against IPC flooding DoS | Medium | `on_send` hook — track send count per process per interval |
| ~~**Bootstrap Principal hardening**~~ | ~~Phase 0 uses deterministic seed~~ | ~~Medium~~ | **DONE**: Hardware-backed YubiKey root of trust, compiled-in public key |

### Priority Order

1. **Per-process syscall allowlists** — Highest impact for lowest effort. The hook exists. Just needs policy tables.
2. **ELF signature verification** — Currently any valid-structure ELF can load. Ed25519 signatures tie binaries to trusted builders.
3. **Audit logging** — Every security incident investigation starts with "what happened?" Need the log before it matters.
4. ~~**Bootstrap Principal hardening**~~ — **DONE.** YubiKey hardware-backed root of trust. Secret key never enters kernel memory.
5. **Capability revocation** — Required before any real multi-service deployment. A driver update needs to revoke the old driver's capabilities.
6. **IPC rate limiting** — Defense against the most obvious DoS vector.
7. **Runtime behavioral AI** — The big win, but requires the AI inference engine to exist first.
8. **Capability expiry** — Nice-to-have; most useful for temporary delegations.
9. **Cryptographic capabilities** — Only matters when ArcOS nodes communicate. Network stack comes first.

---

## Test Coverage

| Component | Tests | What They Cover |
|---|---|---|
| Capability manager | 11 | Grant, verify, delegation, escalation prevention, capacity limits, Principal bind/get |
| IPC interceptor | 13 | Payload validation, bounds checks, self-send, delegation policy, syscall filtering, custom interceptors |
| ELF verifier | 14 | W^X, kernel space rejection, overlapping segments, memory limits, entry point boundary cases, segment collection, custom verifiers |
| IPC sender_principal | 4 | Default None, kernel stamping on capability send, no-principal path, direct send bypass |
| ObjectStore (types + crypto) | 21 | Principal equality, content hashing (Blake3), Ed25519 sign/verify, ArcObject creation/author immutability/owner model/lineage, ObjectCapSet |
| RamObjectStore | 12 | Put/get, idempotency, invalid hash rejection, delete, list, capacity exhaustion, slot reuse, author/owner preservation |
| IPC + capability integration | via QEMU | SYS_WRITE and SYS_READ exercise the full three-layer pipeline end-to-end |

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
