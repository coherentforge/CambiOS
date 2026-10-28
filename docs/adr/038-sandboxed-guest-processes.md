# ADR-038: Sandboxed Guest Processes - Unsigned Code Under a Derived Principal

- **Status:** Proposed
- **Date:** 2026-10-27
- **Depends on:** [ADR-000](000-zta-and-cap.md) (zero trust + capabilities: a guest holds exactly what its host handed down), [ADR-004](004-cryptographic-integrity.md) (the signed-ELF gate this ADR carves one audited, capability-gated exception into), [ADR-018](018-init-process-and-boot-manifest.md) (manifest-only spawn; every guest host is a manifest row), [ADR-025](025-principal-as-aid.md) (Principal as 32-byte AID; guest AIDs are derived AIDs), [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (transcribe-not-interpret; the derivation is mechanical), [ADR-019](019-process-fault-reaping-and-peer-generation.md) + [ADR-034](034-deferred-task-resource-reclamation.md) (the exit, fault and reap substrate guests die through), [ADR-020](020-typed-user-buffer-slices-at-syscall-boundary.md) (the descriptor and image are user buffers), [ADR-006](006-policy-service.md) (the policy service decides under the ceiling this ADR adds), [ADR-007](007-capability-revocation-and-telemetry.md) (audit)
- **Related:** [ADR-016](016-win-compat-api-ai-boundary.md) + [win-compat.md](../win-compat.md) (the first consumer design, written before this primitive existed; its `SandboxedPrincipal` is realised here as a derived AID), [ADR-033](033-multi-principal-vault.md) (guests are never vault entries, which is what keeps them from signing as the user), [ADR-035](035-translation-layer-compatibility.md) (a Principal-bound, policy-bounded agent as a checkable identity), [ADR-029](029-posix-file-storage-model.md) + [ADR-030](030-stream-cap-variant.md) (the fd table and streams a POSIX guest's I/O rides on), [ADR-037](037-native-app-framework.md) (the host is an ordinary `service_main!` service), [SECURITY.md](../SECURITY.md), [threat-model.md](../threat-model.md)
- **Supersedes:** N/A

## Scope Boundary (read this first)

This ADR defines the **kernel primitive** for running code the operator did not sign: how a guest process is created, what identity it carries, what authority it can hold, how its syscall and memory envelopes are bounded, and how its host ends it. It is not a POSIX layer, not a Win32 layer, not a browser process model and not an agent runtime. Those are hosts: userspace services that consume this primitive.

| Concern | Owner |
|---|---|
| Creating a guest from an unsigned ELF image, under a derived AID, with delegated authority | **This ADR (kernel)** |
| Syscall ceiling and memory ceiling per guest, enforced mechanically | **This ADR (kernel)** |
| Host-initiated termination of a guest | **This ADR (kernel)** |
| Initial-stack layout a C runtime expects (`argc` / `argv` / `envp` / `auxv`) | **This ADR (kernel loader)** |
| What a guest's syscalls *mean* (libc semantics, Win32 semantics, Linux ABI) | Hosts and the libc port; [ADR-016](016-win-compat-api-ai-boundary.md) for Win32 |
| Dynamic (post-spawn) allow/deny decisions under the ceiling | [ADR-006](006-policy-service.md) policy service |
| Which files a guest sees, what its stdio is wired to, whether it has network | Host, via the caps it delegates and the services it brokers |
| Pre-execution analysis of guest code (the AI watcher's static pass) | Host, before it calls the spawn; the kernel supplies the content hash and the audit record |
| Which user Persona a guest acts for | [ADR-033](033-multi-principal-vault.md) vault, via the host as broker. Deferred here; see Open Questions |

The rule is the one every ADR since [ADR-002](002-three-layer-enforcement-pipeline.md) follows: the kernel makes mechanical checks, userspace makes decisions. The kernel checks that a guest's authority is a subset of its host's. The host decides what that subset is.

## Context

Since [ADR-018](018-init-process-and-boot-manifest.md) step 9, `SYS_SPAWN` is manifest-only: the name must be a transcribed row, the row's `SpawnAuthority` decides who may spawn it, the ELF is a boot module verified against the bootstrap key, and the kernel binds the row's derived AID and installs exactly the row's grants. There is no other way to create a process. This is correct for the operating system's own services and apps: every byte that runs was signed by the operator at build time.

It also means CambiOS cannot run anything else. Three consumers now need exactly that:

1. **The headless agent sandbox.** An LLM agent's tool calls (`python3 script.py`, `git clone`, a compiler) are arbitrary programs the operator never saw. The product is running them with least privilege and a faithful audit record.
2. **Windows compatibility** ([win-compat.md](../win-compat.md)). A PE binary cannot carry an ARCSIG trailer. The design already calls for a sandboxed Principal per application instance, a private endpoint per sandbox, and a declarative `SandboxPolicy`; it assumed a primitive that did not exist.
3. **A browser.** Per-site processes running untrusted JavaScript and Wasm are the same shape again: unsigned code, isolated address space, authority handed down by a host.

All three want the same five things from the kernel: run unsigned code in its own address space; give it an identity that is attributable to its host but cannot impersonate anything; let it hold only a strict subset of its host's authority; bound its syscalls and memory structurally; and let the host end it. The three consumers satisfy the second-consumer rule for a shared primitive several times over.

What exists today and is reused unchanged: per-process page tables and heaps, the capability table and its monotone delegation check ([ADR-000](000-zta-and-cap.md) Verified Properties), the structural ELF checks in `DefaultVerifier`, the identity gate, `SYS_WAIT_TASK` with generation-carrying handles and `ExitInfo` ([ADR-019](019-process-fault-reaping-and-peer-generation.md)), the reap substrate ([ADR-034](034-deferred-task-resource-reclamation.md)), the per-process fd table ([ADR-029](029-posix-file-storage-model.md)), the manifest's 128-bit syscall set and the policy service that interprets it ([ADR-006](006-policy-service.md), manifest wire v2), and the audit taxonomy in `cambios-abi`.

What does not exist: a spawn path that takes an image from memory instead of the boot module registry; a verifier that accepts an unsigned image; an identity for a process the manifest does not name; a kernel-enforced syscall or memory ceiling; a way to kill a child; and an initial user stack carrying arguments. Today the loader sets `rsp` to the stack top and nothing else, which no C runtime survives.

## Problem

**Problem 1 - admission.** The only loader entry verifies an ARCSIG trailer against the bootstrap key. Admitting unsigned code by weakening that check for everyone would destroy the property [ADR-004](004-cryptographic-integrity.md) exists to give. Admitting it through a separate, capability-gated path that keeps every structural check and records what was admitted does not.

**Problem 2 - identity.** Every process must have a bound Principal before it can do anything ([ADR-000](000-zta-and-cap.md) Divergence, identity gate). Manifest rows get build-time derived AIDs. A guest has no row. If the host could supply any AID, it could supply fs-service's and squat its reserved endpoints; if the kernel bound no AID, the guest could not even write to its own stdout. The guest needs an AID that is unforgeable, attributable to its host, structurally disjoint from every manifest and key-backed AID, and useless for signing.

**Problem 3 - authority.** `install_manifest_row` installs grants the operator signed. A guest's grants come from an untrusted host at runtime. The kernel must refuse any grant the host does not itself hold, with the same no-escalation rule `delegate_capability` already proves.

**Problem 4 - envelope.** The policy service can deny syscalls dynamically, but it is an IPC round trip to a userspace service, it falls back to Allow before that service exists, and a decision is not a bound. A guest running agent-generated code needs a ceiling the kernel enforces with a bit test before any decision is consulted, plus a memory ceiling so one runaway `SYS_ALLOCATE` loop cannot take the machine with it.

**Problem 5 - termination.** There is no kill primitive. A host whose guest loops forever can only wait. A sandbox the host cannot stop is not a sandbox.

**Problem 6 - the first instruction.** A musl or relibc `_start` reads `argc`, `argv`, `envp` and the auxiliary vector from the initial stack. Without that layout no POSIX program starts, and the libc port ([ADR-038 § Cross-References](#cross-references) names where that lands) has nothing to stand on.

**Why these are one mechanism.** Admission without identity cannot pass the identity gate. Identity without the subset rule is impersonation with a different name. A subset of capabilities without a syscall ceiling still allows `SYS_SPAWN`-shaped mischief under whatever the host forgot to withhold. All of it without a kill is a denial of service the host cannot end. The first instruction is what makes any of it useful for the consumers that motivated it.

## The Reframe

> **A guest is an ordinary process whose identity and authority are both derived from its host's, and whose envelope is a strict subset of its host's. The sandbox is not a mode the kernel enters. It is the absence of any authority the host did not hand down.**

Once created, a guest is scheduled, audited, reaped and waited on exactly like every other process. Nothing downstream of creation knows it is a guest. The only places that know are the spawn path (derivation and subset checks), the dispatcher's first check (the ceiling bit test), `SYS_ALLOCATE` (the memory ceiling), and the kill path.

## Decision

### 1. A new system capability: `CreateGuest`

`CapabilityKind::CreateGuest` (manifest `system_caps::CREATE_GUEST = 11`) gates `SYS_SPAWN_GUEST`. It is granted by the manifest to hosts: the agent sandbox host, `win-compat`, a browser's process broker. `CreateProcess` does not imply it; a shell that may launch manifest apps may not run unsigned code.

A guest may hold `CreateGuest` only if its host delegated it under the subset rule (§ 4). This is what makes nested guests possible (a shell guest spawning `python3` spawning a compiler) without any special case: every level is a guest of the level above. Nesting depth is bounded:

```rust
/// SCAFFOLDING: maximum guest nesting depth (a manifest process is depth 0).
/// Why: bounds the ancestor walk in kill and in budget subdivision; keeps
///      ceilings composable without recursion. v1-endgame estimate: shell →
///      interpreter → subprocess → build tool ≈ 4; 16 = ≤25% utilization.
///      Memory cost: one u8 per process descriptor.
/// Replace when: a real workload nests past 16 (a build system inside an
///      agent inside an agent would be the shape). See docs/ASSUMPTIONS.md.
pub const MAX_GUEST_DEPTH: u8 = 16;
```

### 2. `SYS_SPAWN_GUEST`: image from memory, descriptor by value

```text
SpawnGuest = 76    arg1 = descriptor_ptr (user), arg2 = descriptor_len (must equal size_of::<GuestSpawnDescriptor>())
                   returns the child's generation-carrying TaskId (as SYS_SPAWN does), or a typed error
```

The descriptor is a fixed-layout `#[repr(C)]` struct defined in `cambios-abi` ([ADR-024](024-syscall-abi-crate.md)), read through `UserReadSlice` ([ADR-020](020-typed-user-buffer-slices-at-syscall-boundary.md)):

```rust
#[repr(C)]
pub struct GuestSpawnDescriptor {
    /// ELF image in the host's address space. The only loadable container.
    /// A host that loads another format (PE) builds an ELF-shaped image in
    /// memory: sections become LOAD segments with their permissions, the
    /// entry is the host's thunk. Bounded by the loader's MAX_PROCESS_MEMORY.
    pub image_ptr: u64,
    pub image_len: u64,
    /// Host-chosen label, mixed into the guest AID (§ 3). The host decides
    /// whether a label is stable ("python3") or per-instance (label || nonce).
    pub label: [u8; 32],
    /// Authority to hand down. Each entry must be ≤ what the host holds (§ 4).
    /// No wildcard form: a guest is told exactly which endpoints it may reach.
    pub grants: [GuestGrant; GUEST_GRANTS_MAX],
    pub grant_count: u32,
    /// Syscall ceiling, same representation as the manifest's per-entry set
    /// (`SYSCALL_MASK_WORDS` words, bit N = syscall N). Must be ⊆ the host's
    /// effective ceiling (§ 5).
    pub syscall_mask: [u64; SYSCALL_MASK_WORDS],
    /// Cumulative SYS_ALLOCATE ceiling in pages, image and stack included.
    /// Must be ≤ the host's remaining budget when the host is itself a guest.
    pub mem_limit_pages: u32,
    /// Nesting depth is kernel-computed (host depth + 1); this field is
    /// reserved and must be 0.
    pub reserved: u32,
    /// NUL-separated argv strings, then an empty string, then NUL-separated
    /// envp strings, laid onto the guest's initial stack per § 6.
    pub args_ptr: u64,
    pub args_len: u64,
    /// Must be 0. Reserved for the Linux-ABI trap-redirect flag a binary-
    /// compatibility host will need (see Open Questions).
    pub flags: u64,
}

#[repr(C)]
pub struct GuestGrant {
    /// 0 = Endpoint { endpoint, rights }, 1 = System { kind }
    pub tag: u32,
    pub endpoint: u32,
    pub rights: u32,
    pub kind: u32,
}
```

```rust
/// ARCHITECTURAL: a guest can be handed at most as many endpoint capabilities
/// as a process can hold. Lockstep with the per-process capability table size
/// (32, ADR-000). Changing one changes the other.
pub const GUEST_GRANTS_MAX: usize = 32;

/// SCAFFOLDING: argv + envp blob ceiling.
/// Why: Linux's ARG_MAX is 128 KiB; agent tool calls and build commands run to
///      a few KiB. 64 KiB sits well under 25% of what musl-built tools ask for
///      in practice while bounding the stack copy. Memory cost: none resident;
///      it is a per-call copy bound.
/// Replace when: a real guest's argv + envp exceeds 64 KiB (a generated
///      compiler command line is the likely shape). See docs/ASSUMPTIONS.md.
pub const GUEST_ARGS_MAX: usize = 64 * 1024;
```

The handler follows `handle_spawn`'s sequence exactly: `CreateGuest` check under `CAPABILITY_MANAGER(4)` alone; descriptor and image read via typed slices; subset checks (§ 4, § 5) under `CAPABILITY_MANAGER(4)` alone; then `SCHEDULER(1)` of the home CPU → `PROCESS_TABLE(7)` → `FRAME_ALLOCATOR(8)` for the load; drop all three; then `CAPABILITY_MANAGER(4)` again to install grants and bind the AID. No new lock. No lock held across the subset checks and the load at once, so a host that drops a capability between check and install only ever under-grants its guest, never over-grants it: the install re-validates each grant against the host's table at install time and skips (and audits) any that no longer hold.

The image is read from the host's address space through `UserReadSlice` in page-sized steps straight into the guest's freshly allocated segment frames, never into a kernel buffer: an image can be tens of megabytes and the kernel heap is 4 MiB.

### 3. Identity: a derived AID the kernel computes

```text
guest_aid = blake3( GUEST_AID_DOMAIN_TAG || host_aid || label )
GUEST_AID_DOMAIN_TAG = "cambios:v1:guest-aid:"
```

The tag joins `SERVICE_AID_DOMAIN_TAG` and `INIT_AID_DOMAIN_TAG` in `cambios-manifest`. Properties, each load-bearing:

- **Structurally disjoint from every manifest AID.** Different domain tag, so no guest AID equals a service or init AID; endpoint reservations key on manifest AIDs, so a guest can never register a reserved endpoint whatever label its host picks.
- **Disjoint from key-backed AIDs** with overwhelming probability, and in v1.5+ structurally (key-backed AIDs are `blake3(inception_block)` under their own derivation).
- **Attributable.** The host's AID is an input; the audit record (§ 8) carries host pid and guest pid; fs-service and the vault can treat "derived from host X" as a fact, because the derivation is public and recomputable.
- **Not a signing key, not a vault entry.** The vault's trust boundary ([ADR-033](033-multi-principal-vault.md) § 4) recognises only its own entries and the bootstrap Principal. A guest asking `sign_with` gets `NotAuthorized` with no new code. A guest that needs something signed asks its host; the host decides and brokers. This is the "cycles outside the ring" shape and it is also the security property: unsigned code cannot produce the user's signature.
- **Deterministic by construction, ephemeral by convention.** The kernel adds no nonce. A host that wants per-instance identity mixes one into the label; a host that wants a stable identity for ACL grants ("this sandbox may read `/work`") reuses the label. The kernel does not decide which is right.

On [ADR-026](026-identity-transcription-at-the-kernel-ring.md): the kernel hashing a host identity and a label into a child identity interprets nothing about what either identity means, who the human is, or what the label denotes. It is the same class of operation as stamping `sender_principal`: mechanical transcription of a fact the kernel already holds. `blake3` is already in the kernel (object hashing, manifest verification). The alternative, a host-supplied AID, is rejected for v1 and recorded under Why Not (Option E).

### 4. Authority: the subset rule, re-validated at install

Every `GuestGrant` is checked against the host's own capability table:

- `Endpoint { endpoint, rights }`: the host must hold a capability on `endpoint` whose rights are a superset of `rights` **and** carry `delegate`. This is `delegate_capability`'s monotone rule ([ADR-000](000-zta-and-cap.md) Verified Properties: Monotone delegation), applied to a not-yet-existing grantee.
- `System { kind }`: the host must hold `kind`. `CreateGuest` is delegable like any other; so is `CreateProcess` (a guest may then spawn manifest apps, which is a host decision).
- Nothing else is installed. No `AllEndpoints` form, no implicit reply-send grant: a guest that must reply to a client is handed that client's endpoint explicitly or talks only to its host.

Any grant that fails the check fails the whole spawn with `PermissionDenied` before any resource is allocated, and emits `CapabilityDenied` with the host as subject. The spawn is all-or-nothing on the pre-check so a host cannot probe its own table by partial success. At install time (after the load, under a second `CAPABILITY_MANAGER` acquisition) each grant is checked again against the host's table; a grant that no longer holds is skipped and audited, never installed. Under-granting is fail-safe; over-granting is the bug the two checks exclude.

### 5. Syscall ceiling: a bit test before any decision

`ProcessDescriptor` gains `syscall_ceiling: [u64; SYSCALL_MASK_WORDS]`. For manifest-spawned processes it is all-ones (the manifest's per-entry set is the policy service's to enforce, unchanged). For a guest it is the descriptor's `syscall_mask`, which must satisfy `mask ⊆ host.syscall_ceiling` or the spawn fails with `InvalidArg`.

The dispatcher tests the ceiling bit immediately after the identity gate and before `policy_check`: clear bit → `PermissionDenied`, `SyscallDenied` audit event with `arg0 = syscall_number`. Two syscalls are unmaskable: `Exit` and `Yield`. A guest must always be able to die and to give up the CPU; every other syscall, `Print` included, is the host's to allow.

This is layered under [ADR-006](006-policy-service.md), not instead of it. The ceiling is a structural bound set once at creation (the host's statement of what the guest can ever do); the policy service is the dynamic decision under that bound (what the guest may do now). The ceiling never consults anything, never blocks, never falls back to Allow, and costs one `AND` per syscall. It also closes, for guests, [SECURITY.md](../SECURITY.md) gap #1's "allows by default before the policy service registers" window: a guest's ceiling is in force from its first instruction.

### 6. Memory ceiling and the initial stack

`ProcessDescriptor` gains `alloc_budget_pages: u32` and `alloc_used_pages: u32`. For manifest processes the budget is unbounded (today's behaviour). For a guest it is `mem_limit_pages`, charged at creation for image segments and stack, and charged in `handle_allocate` / credited in `handle_free`. A guest host's remaining budget bounds its guests' budgets (`child.limit ≤ host.limit - host.used` at spawn), so budgets subdivide rather than multiply down a nesting chain. Exceeding the budget is `OutOfMemory`, the error `SYS_ALLOCATE` already returns.

CPU-time quotas are not in this ADR. The agent sandbox's first deployment is one sandbox per microVM, so the VM is the CPU boundary. **Revisit when:** a host wants more than one mutually-untrusted guest tree per machine (multi-tenant in one VM).

**Initial stack.** The loader lays out the guest's user stack in the System V ELF ABI shape every libc `_start` expects, from `args_ptr`:

```text
higher addresses
    envp strings, argv strings (copied)
    16 bytes of AT_RANDOM material
    auxv: AT_PHDR, AT_PHENT, AT_PHNUM, AT_PAGESZ, AT_ENTRY, AT_RANDOM, AT_NULL
    NULL
    envp[0..m]
    NULL
    argv[0..n]
    argc
rsp →
```

16-byte aligned at `argc`. Manifest-spawned processes keep today's bare stack (`argc = 0` is not written; nothing reads it) so no existing service changes. `AT_RANDOM` is filled from the kernel's timer-derived seed today, which is weak; musl uses it for the stack-protector canary and `AT_RANDOM`'s quality bounds that defence. **Revisit when:** a kernel entropy source lands (`SYS_GET_RANDOM` or a hardware RNG driver), at which point this field is the first consumer.

### 7. Termination: `SYS_KILL_TASK`

```text
KillTask = 77    arg1 = child TaskId (generation-carrying, as returned by SpawnGuest / Spawn)
                 returns 0, or NotFound (stale generation), PermissionDenied (not a child), InvalidArg
```

Only the parent may kill, in v1 (ancestor kill is a host-side loop over its own children's children; **Revisit when:** a host needs to kill a subtree whose intermediate guest is unresponsive, which argues for kernel-side subtree kill). The caller's `parent_task` relationship is checked under the target's `SCHEDULER` lock, resolved through `TASK_CPU_MAP` exactly as `wake_task_on_cpu` does.

Mechanism: the target is marked `KillPending` (a new `TaskState` variant, so the state machine stays explicit) and woken if blocked. At its next kernel entry on its own CPU (syscall return, timer tick, or the wake itself) it runs the [ADR-019](019-process-fault-reaping-and-peer-generation.md) reap in its own context with `ExitReason::Killed { by: ProcessId }`, which is what the ADR-034 self-referential capture requires. If it is currently running on another CPU, that CPU is kicked (`kick_cpu`) so the next timer entry is immediate. No cross-CPU reap, no new lock, no reap from the killer's context.

This amends ADR-019's `ExitReason` with a `Killed` variant and `ExitInfo`'s wire tag accordingly. The amendment is shown as a diff before it lands, per the ADR-edit rule; this ADR records the intent.

### 8. Audit

Two taxonomy rows in `cambios-abi` (next free kinds at drafting time):

```text
GuestSpawned = 23 => "proc.guest_spawned", Security,
    "subject=guest_pid object=host_pid arg0=depth arg1..arg3=image_hash[0..24]";
ProcessKilled = 24 => "proc.killed", Lifecycle,
    "subject=pid arg0=killer_pid arg1=runtime_ticks";
```

`GuestSpawned` is the admission record the signed-ELF path does not need: what ran, who ran it, how deep. Together with `BinaryLoaded`'s existing hash prefix convention it lets an operator or an AI watcher answer "which unsigned images ran today, under whom". Existing kinds carry the rest unchanged: `ProcessCreated`, `ProcessTerminated`, `ProcessFaulted`, `CapabilityDenied` (subset-rule failures), `SyscallDenied` (ceiling denials).

The content hash is computed once at admission (`blake3(image)`), emitted here, and otherwise discarded: the kernel keeps no image hash table. A host that wants allow-lists keeps its own.

### 9. Admission: structural checks without the signature

A `GuestVerifier` implements `BinaryVerifier` with every `DefaultVerifier` check (entry in a LOAD segment, user-space only, W^X, no overlapping segments, no page-permission conflict, memory limit) and no signature check. An ARCSIG trailer, if present, is stripped and ignored: a host-signed guest would attest nothing (the host would sign anything) and would blur what a signature means in this system. The verifier is selected by the `SpawnGuest` path only; `SYS_SPAWN` and boot-module load keep `SignedBinaryVerifier`.

W^X holds for guests. JIT engines need writable-then-executable pages; V8's `--jitless` and SpiderMonkey's interpreter modes run without them. **Revisit when:** the first JIT guest (a browser engine or Node without `--jitless`) is a consumer; the primitive then is a `SYS_MPROTECT` that permits W→X transitions under a `JitPages` system capability a host must explicitly delegate, never an RWX mapping.

## Architecture

### Host anatomy (userspace, for orientation)

A host is an ordinary manifest service ([ADR-037](037-native-app-framework.md) `service_main!`) whose row grants it `CreateGuest`, `CreateProcess` if it should also launch apps, and the endpoint caps it intends to hand down. For the agent sandbox:

```text
sandbox-host (manifest row, depth 0)
  ├─ reads a tool call from the control channel (virtio-vsock service)
  ├─ runs any pre-execution analysis it likes on the image bytes
  ├─ SpawnGuest { image: busybox/python3/git (musl static), label, grants: [stdio endpoints, fs endpoint], mask: POSIX-tier-1 set, mem_limit }
  ├─ brokers stdio: guest writes to a host endpoint; host forwards to the control channel
  ├─ WaitTask with a deadline; KillTask on timeout
  └─ relays ExitInfo (Exited / Faulted / Killed) and the audit slice
```

`win-compat` is the same skeleton with a PE-to-ELF image builder and its shim endpoint in the grants. A browser's process broker is the same skeleton with one guest per site.

### What a guest sees

An address space with its image, a stack carrying `argv` / `envp` / `auxv`, a 4 MiB heap region like every process, a bound Principal that passes the identity gate, exactly the capabilities in its descriptor, a syscall set no wider than its host's, and a page budget. It can register endpoints from the unreserved range ([ADR-018](018-init-process-and-boot-manifest.md) § 3), open files its ACLs permit ([ADR-029](029-posix-file-storage-model.md)), and die by `Exit`, fault, or kill. It cannot tell it is a guest except by reading its own AID and noticing nobody will sign for it.

### Lock ordering

No new lock enters the hierarchy. `SpawnGuest` replicates `handle_spawn`'s acquisition sequence. `KillTask` takes exactly one `SCHEDULER` lock (the target's home CPU, via `TASK_CPU_MAP`), holds no other lock, and kicks the CPU after release. The ceiling bit test and budget accounting read fields of the current process's descriptor under locks the dispatcher already takes for those paths (`PROCESS_TABLE(7)` in `handle_allocate`; the ceiling is copied into the per-task fast-path state at creation so the dispatcher's bit test takes no lock at all).

## Threat Model Impact

| Threat | Before this ADR | With this ADR |
|---|---|---|
| Unsigned code runs on CambiOS | Impossible, and so is every consumer in Context | Possible only through `SpawnGuest`, only for `CreateGuest` holders, only with every structural ELF check, only with an admission audit record carrying the content hash |
| Guest impersonates a service (squats endpoint 16) | n/a | Guest AID is domain-tagged; reservations key on manifest AIDs; structurally impossible regardless of label |
| Guest signs as the user | n/a | Guest AID is not a vault entry; `sign_with` → `NotAuthorized` ([ADR-033](033-multi-principal-vault.md) § 4) with no new code |
| Host escalates its guest beyond itself | n/a | Subset rule, pre-checked and re-validated at install; the monotone-delegation property already proved for `delegate_capability` |
| Host forgets to withhold a dangerous syscall | n/a | Ceiling is a bit test before policy; policy service still decides underneath; `Exit`/`Yield` only unmaskable |
| Guest exhausts memory | Any process can today, bounded only by the frame allocator | Page budget per guest, subdivided down nesting chains |
| Runaway guest cannot be stopped | No kill primitive | `KillTask` by the parent; reap in the target's own context through ADR-019/034 |
| Compromised host | Same as any compromised manifest service | Blast radius is the host's own capability set; its guests hold subsets of it; nothing a guest does widens the host |
| Guest faults | ADR-019 reaps and reports `Faulted` | Unchanged; the host receives `ExitInfo` and decides |
| Image bytes change between host analysis and spawn (TOCTOU in the host's own memory) | n/a | The kernel hashes what it loads and records that hash; a host that analysed different bytes can detect the mismatch in the audit record. Host-internal; not a kernel invariant |

Key property: **the kernel's signed-only admission is unchanged for everything the manifest describes.** The exception is a separate path, gated by a capability the manifest must grant, that keeps every structural check and adds an admission record. [ADR-004](004-cryptographic-integrity.md)'s claim becomes "every byte the operator's image runs was signed; every byte that was not signed is attributed to the manifest service that admitted it".

## Verification Stance

The additions are pure functions over bounded inputs, the shape the verification posture wants:

- **Descriptor parse:** fixed layout, bounded arrays, total validator; host-testable, Kani target ("accepted descriptor ⇒ every grant has a valid tag and every count is within bound").
- **Subset rule:** `grant ⊆ host_caps` over a 32-slot table and a 128-bit mask; the monotone-delegation proof in `verification/capability-proofs/` extends to "a guest's installed set is a subset of its host's set at install time".
- **AID derivation:** a hash over fixed-size inputs; the property to pin is domain separation ("no guest AID equals any AID derivable under the service or init tags for any inputs"), which follows from the tag prefix and is stated as an invariant test rather than proved.
- **Ceiling test:** one `AND`; the property is "a clear bit is never dispatched", a dispatcher-level harness.
- **Budget:** a counter with a bound; the property is "used ≤ limit after any sequence of allocate/free", the capacity-invariant shape already proved for the capability table.
- **Kill:** the new `KillPending` state is one arm in an exhaustive `match`; the reap runs through the already-specified ADR-019/034 path. The property to add there is "a `KillPending` task reaches `Terminated` through `reap_process` exactly once".

Nothing here is a trait object, an unbounded loop, or a new lock. Hosts are userspace and are not verification targets.

## Why Not Other Options

### Option A: Policy service mediates guest admission via upcall
Route `SpawnGuest` through the ADR-006 upcall so the policy service approves each image. **Rejected.** Admission of untrusted code should not depend on an IPC round trip to a userspace service that falls back to Allow before it exists; a ceiling must be a bound, not a decision. The policy service keeps the dynamic layer under the ceiling, which is its role.

### Option B: Host loads the guest into its own address space (the Wine shape)
No new primitive; the host maps and jumps. **Rejected.** No isolation between guest and shim, W^X becomes the host's problem, a guest fault kills the host, and the capability model has nothing to attach to. win-compat.md already chose separate processes for these reasons.

### Option C: Guests are manifest entries
Describe every runnable program in the signed manifest. **Rejected.** The manifest is signed at build time; the whole point is code the operator never saw. On-demand apps stay manifest rows; guests are a different thing.

### Option D: Host signs the guest with a host key and the normal loader accepts it
**Rejected.** The signature would attest only that the host chose to run it, which the `CreateGuest` capability and the admission audit already say more honestly. It would also make "signed" mean two different things in one system.

### Option E: Host supplies the guest AID (vault `bind_for_spawn` → `spawn(elf, aid)`)
[ADR-033](033-multi-principal-vault.md) sketched this shape. **Deferred, not rejected.** Any AID-accepting syscall needs an anti-impersonation rule (not a reserved AID, not a manifest AID, not bootstrap, not init), which is a blacklist where derivation gives a structural guarantee. The derived AID also leaves the vault boundary untouched. **Revisit when:** a guest must act *as* a user Persona rather than *for* one through its host (signed commits from inside an agent sandbox is the likely first case); the descriptor's `flags` reserves the bit.

### Option F: Reuse `SYS_SPAWN` with a flag
**Rejected.** `SYS_SPAWN` takes a name; this takes an image, a label, grants, a mask, a budget and arguments. Overloading it would make the identity-gate and capability tests in `cambios-abi` lie about what the number does. Two syscalls, two meanings.

## Migration Path

Dependency-ordered; each step builds and passes the tri-arch gate on its own.

1. **ABI.** `SyscallNumber::{SpawnGuest = 76, KillTask = 77}`, both `requires_identity`; `GuestSpawnDescriptor`, `GuestGrant`, `GUEST_GRANTS_MAX`, `GUEST_ARGS_MAX` in `cambios-abi`; `GUEST_AID_DOMAIN_TAG` and `system_caps::CREATE_GUEST = 11` in `cambios-manifest`; the two taxonomy rows; identity-gate tests updated. `CapabilityKind::CreateGuest` and its manifest mapping in `src/manifest.rs`.
2. **Loader.** `GuestVerifier`; `load_elf_process` gains an image source that reads through a `UserReadSlice` page by page; the initial-stack builder (§ 6) behind an `Option<&ArgsBlob>` so existing callers pass `None`.
3. **Spawn.** `handle_spawn_guest`: descriptor read, `CreateGuest` check, subset pre-check, mask-subset check, budget check, AID derivation, load, install with re-validation, `GuestSpawned` audit. `ProcessDescriptor` gains `syscall_ceiling`, `alloc_budget_pages`, `alloc_used_pages`, `guest_depth`.
4. **Envelope.** Ceiling bit test in the dispatcher after the identity gate; budget accounting in `handle_allocate` / `handle_free`.
5. **Kill.** `TaskState::KillPending`, `handle_kill_task`, `ExitReason::Killed`, `ExitInfo` wire tag, `ProcessKilled` audit. ADR-019 body amended with the shown diff.
6. **First host.** `libsys` wrappers `spawn_guest` / `kill_task`; a `sandbox-host` manifest row that spawns one fixed unsigned guest (a musl-static `hello` that prints its `argv`) and relays its exit. This is the first visible demo and the test fixture for every step above.
7. **Docs sync.** SECURITY.md enforcement rows (guest admission, ceiling, budget, kill); ASSUMPTIONS.md rows for `MAX_GUEST_DEPTH`, `GUEST_GRANTS_MAX`, `GUEST_ARGS_MAX`; win-compat.md alignment note (`SandboxedPrincipal` → derived AID; `SandboxPolicy` → descriptor fields); CLAUDE.md Required Reading row "Guest processes / sandbox hosts / unsigned code"; STATUS.md.

The libc port and the agent sandbox host proper are consumers that start at step 6 and are tracked outside this ADR.

## Open Questions / Deferrals

- **Linux-ABI binary compatibility (guest syscalls trapped to a personality server).** The descriptor's `flags` reserves the redirect bit. **Revisit when:** a specific Linux binary that cannot be recompiled against the libc port is the blocker (Node without a musl build is the likely first).
- **JIT pages.** § 9. **Revisit when:** the first JIT guest is a consumer.
- **Entropy for `AT_RANDOM`.** § 6. **Revisit when:** a kernel entropy source lands.
- **CPU-time quotas.** § 6. **Revisit when:** multi-tenant guests in one VM.
- **Subtree kill.** § 7. **Revisit when:** an unresponsive intermediate guest blocks a host's teardown.
- **Guest acting as a Persona.** Option E. **Revisit when:** signed artefacts from inside a guest are required.
- **Guest file ownership.** win-compat.md's "author = sandbox, owner = parent user" is an fs-service policy over the guest AID's derivation; this ADR gives fs-service the fact (host AID is an input to the derivation) but does not specify the policy. **Revisit when:** the first host writes files on a guest's behalf through fs-service.

## Cross-References

- [SECURITY.md](../SECURITY.md): enforcement table gains four rows at step 7.
- [threat-model.md](../threat-model.md): a `T-9 - Unsigned guest admission` entry lands with step 3, cross-referencing the table above.
- [win-compat.md](../win-compat.md) and [ADR-016](016-win-compat-api-ai-boundary.md): first consumer; alignment note at step 7. ADR-016's body is untouched by this ADR.
- [ADR-019](019-process-fault-reaping-and-peer-generation.md): `ExitReason::Killed` amendment at step 5, diff shown first.
- [ADR-033](033-multi-principal-vault.md): § 4 trust boundary is what makes guest AIDs unable to sign; no change needed there.
- [STATUS.md](../../STATUS.md): the headless agent sandbox track lists this ADR as its first kernel step.
- Stage note (working doc, not checked in): `notes/stage-f-cross-platform-hardware.md` § 11 and § 13 record the decision chain that led here.
