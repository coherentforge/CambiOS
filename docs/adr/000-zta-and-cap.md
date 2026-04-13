# ADR-000: Zero-Trust Architecture and Capability-Based Access Control

- **Status:** Accepted
- **Date:** 2026-04-03
- **Context:** Foundational security architecture — every other ADR is downstream of this one

## Problem

Traditional operating systems use a perimeter security model: authenticate at the boundary (login, privilege check), then grant broad access to the interior. A process running as a user inherits all of that user's permissions — filesystem access, network sockets, IPC endpoints — regardless of whether the process needs them. A single exploited vulnerability escalates to the full authority of the compromised identity.

Access control lists (ACLs) mitigate this by attaching permission lists to resources, but ACLs are:

1. **Checked at the gate, not enforced continuously.** A process that bypasses or escalates past the initial check inherits whatever the policy file says.
2. **Ambient.** Authority comes from identity (who you are), not possession (what you hold). A compromised PDF reader can read SSH keys because it runs as you and you can read SSH keys.
3. **Unverifiable at scale.** Policy is distributed across files, tables, and configuration. Auditing who can do what requires reconstructing the full authority graph — an NP-hard problem in practice.

CambiOS needs a security model where compromising any single component — a driver, a service, even a kernel subsystem — gains the attacker exactly nothing beyond the explicitly granted rights of that component.

## Decision

CambiOS adopts two complementary security principles as its foundational architecture:

1. **Zero-Trust Architecture (ZTA):** No process, driver, or kernel component is trusted by default, regardless of whether it is already running inside the system. Every operation is verified at the time of use.

2. **Capability-Based Access Control (CAP):** Authority is represented by unforgeable tokens (capabilities) that grant specific rights to specific resources. A process can only perform an operation if it physically possesses the capability to do so. There is no ambient authority.

These are not features bolted onto a conventional kernel. They are the security model. Any change that weakens or bypasses them must justify itself against this document.

## The Distinction That Matters

The traditional mental model is **authentication** — proving who you are. Capabilities are about **authorization** — what you can do, enforced structurally rather than by policy lookup.

The security property is not "we checked and you're allowed." It is "you physically cannot do what you weren't given a token for."

This is the analogy: traditional OS security is a building where you badge in at the front door and then roam freely. Capabilities are a building where every door has its own lock and your keycard only opens the specific doors you were explicitly granted. Getting past the front door gets you nothing you weren't already given.

## Architecture

### Trust boundaries

CambiOS has three trust levels, each with a strict enforcement boundary:

| Level | Runs in | Trust | Enforcement |
|---|---|---|---|
| **Microkernel** | Ring 0 | Trusted (minimal TCB) | Hardware protection, formal verification target |
| **System services** | Ring 3 | Untrusted | Capability check on every IPC, interceptor policy |
| **User applications** | Ring 3 | Untrusted | Capability check on every IPC, interceptor policy, ELF verification |

Drivers, filesystems, and networking run as Ring 3 services — not in the kernel. The microkernel's trusted computing base is the scheduler, IPC dispatcher, and capability manager. Everything else is outside the trust boundary.

### Capability model

A capability in CambiOS is a kernel-managed `(endpoint, rights)` pair:

```rust
pub struct Capability {
    pub endpoint: EndpointId,
    pub rights: CapabilityRights,
}

pub struct CapabilityRights {
    pub send: bool,      // Can send messages to this endpoint
    pub receive: bool,   // Can receive messages from this endpoint
    pub delegate: bool,  // Can pass this capability to another process
}
```

Capabilities are:

- **Unforgeable.** Only the kernel can create or modify them. User processes cannot fabricate a capability — there is no syscall to "grant yourself access."
- **Per-process.** Each process holds up to 32 capabilities in a kernel-managed table (`ProcessCapabilities`). The table is not accessible from userspace.
- **Checked on every operation.** Every IPC send checks `SEND` rights. Every IPC recv checks `RECV` rights. Every delegation checks `DELEGATE` rights and that the delegator holds at least the rights being delegated (no escalation).
- **Revocable.** The kernel can revoke a capability at any time, immediately cutting off a compromised process's access.

### Enforcement points

Access control is enforced at three layers (defense-in-depth):

```
Syscall entry
    │
    ▼
┌──────────────────────────────┐
│  1. IpcInterceptor::on_syscall()  │  Pre-dispatch: syscall allowlist
└──────────────────────────────┘
    │
    ▼
┌──────────────────────────────┐
│  2. CapabilityManager::verify_access()  │  Capability check: unforgeable token
└──────────────────────────────┘
    │
    ▼
┌──────────────────────────────┐
│  3. IpcInterceptor::on_send/recv()  │  Runtime policy: payload, bounds, self-send
└──────────────────────────────┘
    │
    ▼
  IPC operation proceeds
```

1. **Pre-dispatch interceptor** (`on_syscall`): Per-process syscall allowlists. A driver that only needs `Write` and `WaitIrq` cannot invoke `Allocate` or `RegisterEndpoint`.

2. **Capability check** (`verify_access`): The process must hold a capability with the required rights for the target endpoint. No capability → `AccessDenied`. No exceptions.

3. **Post-capability interceptor** (`on_send`, `on_recv`, `on_delegate`): Runtime policy enforcement even after capability verification. Guards against payload overflow, endpoint-out-of-bounds, self-send, delegation escalation, and custom policy violations.

A compromised process must bypass all three layers to perform an unauthorized operation. Each layer is independent.

### ELF verification gate

Zero trust extends to code loading. Every ELF binary passes through a `BinaryVerifier` before any memory allocation or page table mapping occurs:

| Check | Purpose |
|---|---|
| Entry point in LOAD segment | Prevent jumping into unmapped memory |
| All segments in user space | Prevent mapping into kernel address space |
| W^X enforcement | No page is both writable and executable |
| No overlapping segments | Prevent confused-deputy via aliased memory |
| Memory limit | Prevent OOM-based denial of service |

The verifier runs before the loader allocates frames or maps pages. A binary that fails verification causes zero side effects — no resources to clean up, no partial state.

## Threat Model

### What CambiOS protects against

| Threat | Mitigation |
|---|---|
| Compromised user process | Capabilities limit blast radius to explicitly granted endpoints |
| Compromised driver | Runs in Ring 3 with per-device capabilities only |
| Privilege escalation | No ambient authority; capabilities are unforgeable and non-inheritable |
| Confused deputy | Capabilities travel with the operation, not the identity |
| Malicious binary | ELF verifier rejects before any execution or allocation |
| IPC-based attack | Interceptor validates payload, bounds, and policy on every message |
| Capability leakage | Delegation requires explicit `delegate` right; no escalation allowed |

### What the microkernel trusts

The TCB (trusted computing base) is intentionally minimal:

- **Scheduler** — task state transitions, context switch
- **IPC dispatcher** — message routing between endpoints
- **Capability manager** — capability creation, verification, revocation
- **Page table management** — Ring 0 mapping operations

Everything not in this list — drivers, networking, filesystem, application logic — runs outside the trust boundary under capability enforcement.

## Why Not ACLs

| Property | ACLs | Capabilities |
|---|---|---|
| Authority source | Identity (who you are) | Possession (what you hold) |
| Enforcement | At the gate (check once) | On every operation |
| Escalation risk | Bug → inherit ambient authority | Bug → limited to held capabilities |
| Confused deputy | Possible (authority is ambient) | Prevented (authority travels with token) |
| Auditability | Reconstruct from scattered policy | Read the capability tables |
| Revocation | Update policy files | Drop the capability |

The fundamental difference: ACLs answer "is this identity allowed?" Capabilities answer "does this process hold the right token?" The second question cannot be fooled by escalation because there is nothing to escalate to — you either have the token or you don't.

## Where This Lives in the Codebase

The components this ADR describes:

| Component | File | Role |
|---|---|---|
| `CapabilityManager` | `src/ipc/capability.rs` | System-wide capability tables, grant/revoke/verify |
| `ProcessCapabilities` | `src/ipc/capability.rs` | Per-process capability table |
| `IpcInterceptor` trait | `src/ipc/interceptor.rs` | Zero-trust policy enforcement hooks |
| `DefaultInterceptor` | `src/ipc/interceptor.rs` | Baseline policies (payload, bounds, self-send, escalation) |
| `BinaryVerifier` trait | `src/loader/mod.rs` | Pre-execution ELF verification gate |
| `IpcManager` | `src/ipc/mod.rs` | Message passing with capability + interceptor checks |
| `SyscallDispatcher` | `src/syscalls/dispatcher.rs` | Syscall entry with interceptor pre-dispatch |

For the current implementation status of each item (enforced vs. scaffolding vs. designed), see [SECURITY.md § Enforcement Status Summary](../../SECURITY.md). For test counts, see [STATUS.md](../../STATUS.md).

### Lock ordering (security-critical globals)

```
SCHEDULER(1) → TIMER(2) → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7)
```

`CAPABILITY_MANAGER` at position 4 means capabilities are verified after IPC state is consistent but before process metadata or memory operations. This ordering ensures that a capability revocation cannot race with an in-flight IPC that already passed its check.

## Design Principles

1. **Deny by default.** A newly created process holds zero capabilities. It cannot communicate, allocate, or access any resource until explicitly granted.

2. **No ambient authority.** There is no concept of "root," "admin," or "kernel mode process" that bypasses capability checks. The kernel itself is not a process and does not hold capabilities.

3. **Least privilege.** A process is granted only the capabilities it needs. A serial driver gets `send`/`recv` on the serial IPC endpoint and `WaitIrq` for the serial IRQ. Nothing else.

4. **Structural enforcement.** Security is enforced by the architecture, not by policy configuration. There is no security policy file to misconfigure. The code either checks the capability or it doesn't compile.

5. **Defense in depth.** Three independent enforcement layers (interceptor pre-dispatch → capability check → interceptor post-check). Bypassing one layer does not bypass the others.

6. **Verify before execute.** No binary runs without passing the verification gate. No memory is allocated for unverified binaries.

7. **No telemetry.** CambiOS does not phone home, report analytics, or exfiltrate any data. Security monitoring is local and under the operator's control.

## Future Work

The architectural extensions to the capability model have been moved into their own ADRs so that each can be debated, accepted, and implemented independently:

- **Per-process syscall allowlists, externalized policy decisions** — see [ADR-006: Policy Service](006-policy-service.md).
- **Capability revocation, audit logging, AI-assisted anomaly detection (advisory only)** — see [ADR-007: Capability Revocation and Audit Telemetry](007-capability-revocation-and-telemetry.md).
- **Bulk-data IPC path that does not weaken the capability model** — see [ADR-005: IPC Primitives — Control Path and Bulk Path](005-ipc-primitives-control-and-bulk.md).

The remaining open item not yet captured in its own ADR:

**Cryptographic capabilities.** Replace kernel-managed capability tables with cryptographically signed tokens (HMAC or Ed25519). Enables distributed capability verification across networked CambiOS nodes without a central authority. Only relevant once mesh networking lands.

## Divergence

**Identity gate (2026-04-13).** The original ADR described capabilities as the enforcement mechanism but did not mandate that a process *have an identity* before participating in the capability system. Implementation adds a stronger requirement: the syscall dispatcher now gates all capability-bearing, IPC, memory, and device syscalls behind a non-zero Principal check. Unidentified processes can only Exit, Yield, GetPid, GetTime, Print, and GetPrincipal. This ensures that identity is load-bearing — a kernel fork that strips Principal stamping renders every userspace service inert (via `recv_verified` in libsys), not merely "less secure." The design motivation is licensing protection: the security model must be structural, not a peelable layer.

**Unsigned object storage removed (2026-04-13).** fs-service no longer falls back to unsigned `ObjPut` when the key-store is unavailable. All object storage now requires a valid Ed25519 signature via `ObjPutSigned`. If the key-store is degraded, storage operations are denied rather than permitted without cryptographic integrity.

## References

- Dennis, J.B. & Van Horn, E.C. "Programming Semantics for Multiprogrammed Computations" (1966) — origin of capability-based security
- Levy, H.M. "Capability-Based Computer Systems" (1984) — comprehensive survey
- NIST SP 800-207 "Zero Trust Architecture" (2020) — ZTA principles
- seL4 capability model — closest contemporary implementation in a verified microkernel
