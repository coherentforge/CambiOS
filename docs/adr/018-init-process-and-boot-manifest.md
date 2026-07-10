# ADR-018: Init Process and Boot Manifest

- **Status:** Accepted
- **Date:** 2026-04-19
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-003](003-content-addressed-storage-and-identity.md) (Identity/Principal model), [ADR-004](004-cryptographic-integrity.md) (Signed boot modules — ARCSIG trailer), [ADR-008](008-boot-time-sized-object-tables.md) (Boot-time-sized object tables), [ADR-025](025-principal-as-aid.md) (Principal as 32-byte AID), [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (transcribe-don't-interpret — the kernel-side manifest handling follows this pattern)
- **Related:** [ADR-006](006-policy-service.md) (Policy service — explicitly defers init/manifest design to this ADR), [ADR-002](002-three-layer-enforcement-pipeline.md), [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives), [ADR-007](007-capability-revocation-and-telemetry.md) (Revocation + telemetry), [ADR-012](012-input-architecture-and-device-classes.md), [ADR-014](014-compositor-scanout-driver-protocol.md), [ADR-019](019-process-fault-reaping-and-peer-generation.md) (kernel substrate for restart observation — prerequisite for migration step 10), [ADR-024](024-syscall-abi-crate.md) (shared-crate consumption pattern `cambios-manifest` follows), [ADR-034](034-deferred-task-resource-reclamation.md) (generation-carrying task handles init's supervision keys on), [ADR-037](037-native-app-framework.md) (service runtime that emits the readiness ping; its Phase-2 endpoint registry is `build-manifest`'s input)
- **Supersedes:** N/A (introduces the init/manifest slot that ADR-006 and ADR-008 both explicitly deferred)

> Body revised at acceptance (2026-07-06) against the tree as of ADR-037's
> landing: kernel-side transcription replaces the install syscall, Principals
> are AIDs per ADR-025, grants gained the narrow-receive/wildcard-send
> default, and the migration path was resequenced. The drafting-time text it
> replaces is in git history (this ADR was never previously Accepted, so no
> Divergence appendix applies).

## Context

CambiOS today boots by reading a hand-rolled comment in `limine.conf`, loading each listed ELF as a boot module, and releasing them in file-declaration order via a linear chain built out of `BOOT_MODULE_ORDER`, `BlockReason::BootGate`, and the `SYS_MODULE_READY` syscall. The kernel does the sequencing. Endpoint numbers for core services (policy endpoint, fs-service endpoint 16, key-store endpoint 17, virtio-blk endpoint 24/26, and so on) are compile-time `const`s sprinkled across the kernel and every user-space crate. When a service crashes post-boot, nothing restarts it.

This works for bring-up. It is not what a general-purpose OS does in production, and two already-accepted ADRs have explicitly deferred work to a "future init-process ADR":

- **[ADR-006](006-policy-service.md) § Architecture** — "The kernel knows the policy service's IPC endpoint via a compile-time constant (or, eventually, via the boot manifest declared by the future init-process ADR, when that lands — the init-process design is deferred until a second boot module needs user-declared endpoints, at which point a hand-rolled compile-time table stops scaling)."
- **[ADR-006](006-policy-service.md) § Failure Modes** — "The init process (when it exists — see roadmap item 21) restarts the policy service."
- **[ADR-008](008-boot-time-sized-object-tables.md) § Decision (point 7)** — "When CambiOS grows a boot-manifest mechanism (anticipated post-v1, alongside the init process and service configuration work), the table sizing policy moves from compile-time configuration to the manifest."

The "second boot module needs user-declared endpoints" threshold ADR-006 named has been crossed many times over: the endpoint census at acceptance time spans 16 through 33 plus app slots, across the kernel, `user/libsys`, `user/libfs-proto`, `user/libgui-proto`, `user/libscanout`, and every service crate. Every new core service today requires editing at least three crates to teach them each other's endpoint numbers.

This ADR designs the slot the two reference ADRs are waiting for.

## Problem

Four problems have accumulated that the compile-time / kernel-sequenced approach cannot cleanly address.

**Problem 1 — endpoint numbers are ambient.** Core service endpoints are `const u32` values scattered across the kernel (`src/ipc/`, `src/syscalls/dispatcher.rs`) and every user crate (`user/libsys/`, `user/fs-service/`, etc.). Nothing structural prevents a different process from calling `SYS_REGISTER_ENDPOINT(16)` and squatting on the fs-service slot — `handle_register_endpoint` performs no ownership check at all. The restriction "only fs-service gets endpoint 16" is enforced by convention — by the fact that fs-service is the only thing coded to register 16 — not by structure. This conflicts with [ADR-000](000-zta-and-cap.md)'s zero-trust stance: authority for a stable identity-bearing endpoint should be a capability check, not a convention.

**Problem 2 — the kernel owns the service lifecycle.** `BOOT_MODULE_ORDER`, `BlockReason::BootGate`, and `SYS_MODULE_READY` exist to sequence boot module startup. This is scaffolding. It does not compose with post-boot lifecycle needs (crash restart, dependency reordering after a service upgrade, shutdown sequencing) because the kernel isn't the right component to own any of those. Every production OS (systemd, launchd, sysvinit, runit, s6) has a user-space supervisor for exactly this reason. Keeping the logic in the kernel means either growing the kernel into a supervisor — violating the microkernel principle and the verification-first commitment — or rewriting it later.

**Problem 3 — service set is not declarative.** Adding or removing a boot-time service today requires editing `limine.conf`, coordinating endpoint constants across multiple crates, and hoping the implicit dependency comments stay accurate. There is no single file that answers the question "what boot-time services does this deployment run, and what is each allowed to do?" The manifest ADR-006 and ADR-008 anticipate is precisely this file.

**Problem 4 — no crash recovery for core services.** When the policy service, fs-service, or virtio-blk driver crashes, nothing brings it back. [ADR-006 § Failure Modes](006-policy-service.md#failure-modes) describes graceful degradation on policy-service crash (fall back to permissive default), but the "restart" half of the recovery is explicitly delegated to the future init process. That future is now.

**A fifth problem surfaced at acceptance review — identity is ambient too.** Every boot module and every spawned process today binds the *bootstrap* Principal (`register_process_capabilities`, `handle_spawn`). An endpoint reservation keyed on Principal is vacuous while everything shares one Principal: `Reserved(bootstrap)` blocks nobody. Per-service identity is load-bearing for Problem 1's fix, so this ADR must also assign each core service its own Principal.

**Why these problems must be solved together.** Each piece in isolation produces a half-measure: a manifest without init is just a config file nobody reads; init without a manifest is a hard-coded service list; endpoint reservations without per-service identity are vacuous; crash recovery without init is kernel-resident supervision. The pieces compose into one mechanism — a signed manifest describing the core service set, a kernel that transcribes the manifest's security claims into enforcement tables, and an init process that owns the lifecycle the manifest describes.

## The Reframe

The architectural insight:

> **The kernel spawns init and hands init the manifest. Init runs the rest of the system. The kernel transcribes the manifest's security sections — endpoint ownership, per-service identity, initial capabilities — into write-once enforcement tables at boot, but never interprets its policy: ordering, dependencies, and lifecycle are init's alone.**

This is [ADR-026](026-identity-transcription-at-the-kernel-ring.md)'s transcribe-don't-interpret pattern applied to boot configuration, and it matches the split already established for policy ([ADR-006](006-policy-service.md)): the kernel makes mechanical checks ("does this Principal own this endpoint?"), and a user-space service makes decisions ("should this service be restarted?"). Init is the decision-maker for service lifecycle, the way the policy service is the decision-maker for authorization.

The reframe does not invent new kernel primitives — `SYS_SPAWN`, the capability system, and the signed-ELF loader are all in place, and no new syscall is added. What this ADR adds is:

1. A signed manifest blob, loaded as a boot module: transcribed by the kernel (security sections), interpreted by init (policy sections).
2. Kernel enforcement tables — an endpoint-reservation table and a per-module spawn-grant table — populated once at boot from the verified blob, before any user instruction runs, immutable for the life of the boot.
3. An init process (PID 1) that parses the manifest's policy fields and drives `SYS_SPAWN` in dependency order, then owns restart policy.
4. The removal of `BOOT_MODULE_ORDER`, `BlockReason::BootGate`, and `SYS_MODULE_READY` — the scaffolding init replaces.

The kernel's boot surface shrinks (the sequencing machinery is deleted; a bounded pure parse is added). The user-space supervision surface grows in a place where it belongs.

## Decision

CambiOS adopts a **user-space init process (PID 1) driven by a signed boot manifest** as the mechanism for core-service lifecycle, endpoint reservation, per-service identity, and capability assignment.

### 1. The manifest is a signed boot-loaded blob, transcribed by the kernel

The manifest is a fixed-layout binary blob plus an `ARCSIG` trailer (the existing signing mechanism from [ADR-004](004-cryptographic-integrity.md) § Divergence 1 — the trailer signs `blake3(blob)`, so it is content-agnostic and the loader's existing `inspect_signature_trailer` path is reused unchanged). It is loaded as a Limine boot module alongside init and the services it describes.

During boot-module load — before any user task exists — the kernel:

1. verifies the blob's ARCSIG trailer against the bootstrap Principal (exactly as for signed ELFs);
2. **transcribes** the blob's security sections into two write-once kernel tables: the endpoint-reservation table (endpoint → owning AID) and the spawn-grant table (module name → AID + capability grants);
3. maps the blob read-only into init's address space at a fixed address for init's policy-side parse.

The tables follow the `BOOTSTRAP_PRINCIPAL` lifecycle pattern: written once at boot while single-threaded, read-only thereafter, **not** part of the lock hierarchy. There is nothing to race and no runtime mutation path — per-boot immutability is a security property, not a limitation.

The blob is **not** an ELF. It is a flat record structure. Rationale:

- Fixed-layout parsing has a bounded-loop, no-allocation shape that is cheap to verify — the parser is a pure function over a byte slice, host-testable and a Kani target (the BuddyAllocator template applied to parsing).
- No general-purpose deserialization library in either TCB.
- The blob is authored by the bootstrap holder at build time; self-describing wire formats (CBOR, JSON) add no value when there is one producer and two same-repo consumers.

The parser is written once, in a shared crate (`cambios-manifest`, root-level, `no_std`, zero-dep, MPL-2.0 — the [ADR-024](024-syscall-abi-crate.md) consumption pattern), and consumed by the kernel (security sections), init (policy sections), and `tools/build-manifest` (serializer + validation).

### 2. Per-entry shape

Each manifest entry describes one boot-time service:

```rust
pub struct ManifestEntry {
    /// The 32-byte AID (ADR-025) this service runs as. The kernel binds
    /// it at spawn time from the transcribed table; the manifest's
    /// bootstrap signature IS the authorization for the name → AID
    /// binding. v1 derivation: build-manifest generates a domain-tagged
    /// Blake3 hash of the module name — deterministic, distinct per
    /// service, and deliberately not a valid signing key (services that
    /// sign use the key-store, ADR-033). Module *authenticity* is
    /// unchanged: the ELF's own ARCSIG trailer is still verified against
    /// the bootstrap key at load/spawn.
    pub principal: [u8; 32],

    /// Name of the boot module to load, matches strip_module_name()
    /// output (e.g. "policy-service", "fs-service").
    pub module_name: BoundedStr<MODULE_NAME_MAX>,

    /// Endpoints this AID owns exclusively for the lifetime of the
    /// boot. RegisterEndpoint(N) from any other Principal is rejected
    /// with PermissionDenied. The entry may reserve zero endpoints
    /// (services that only talk to others).
    pub reserved_endpoints: BoundedVec<u32, RESERVED_ENDPOINTS_MAX>,

    /// Capabilities the kernel installs on this process at spawn,
    /// before any user instruction runs. Replaces both the blanket
    /// "grant everything to trusted boot modules" path and the
    /// name-based narrow grants in load_boot_modules.
    pub granted_capabilities: BoundedVec<CapabilityGrant, GRANTS_MAX>,

    /// Lifecycle policy — init-interpreted; the kernel ignores it.
    pub lifetime: ServiceLifetime,

    /// Names of services that must reach steady state before this one
    /// is spawned — init-interpreted; the kernel ignores it. Init
    /// resolves this into a startup DAG and spawns in topological
    /// order. Cycles are a manifest-validation error (caught at build
    /// time by build-manifest and again by init).
    pub depends_on: BoundedVec<BoundedStr<MODULE_NAME_MAX>, DEPS_MAX>,
}

pub enum ServiceLifetime {
    OneShot,
    Persistent {
        /// Exponential backoff: first restart after `initial_delay_ms`,
        /// doubling to a cap of `max_delay_ms`. After `max_restarts`
        /// consecutive failures within `failure_window_ms`, init gives
        /// up on the service and emits a ServiceDead audit event.
        initial_delay_ms: u32,
        max_delay_ms: u32,
        max_restarts: u16,
        failure_window_ms: u32,
    },
}

pub enum CapabilityGrant {
    /// Rights on one named endpoint.
    Endpoint { endpoint: u32, rights: CapabilityRights },
    /// Rights on every endpoint. v1 services carry
    /// `AllEndpoints { send }` because replies target clients'
    /// self-chosen reply endpoints, which cannot be pre-declared.
    AllEndpoints { rights: CapabilityRights },
    /// A system capability (CreateProcess, CreateChannel,
    /// MapFramebuffer, AuditConsumer, SetWallclock, ...).
    System { kind: CapabilityKind },
}
```

**Default grant posture (v1): narrow receive, wildcard send.** Each service's default grants are `Endpoint { receive }` on exactly its reserved endpoints plus `AllEndpoints { send }` — a service can never drain another service's queue, even if a reservation check were buggy, while replies to dynamic client endpoints keep working. Narrowing *send* is deferred — **Revisit when:** a reply-capability mechanism (seL4-style reply caps, or ADR-030 stream caps) is in scope. What v1 *does* narrow: the name-based grants in `load_boot_modules` (MapFramebuffer, AuditConsumer, SetWallclock) become per-entry manifest data, and CreateProcess/CreateChannel/CreateCluster stop being universal — each service declares what it holds.

All bounds (`MODULE_NAME_MAX`, `RESERVED_ENDPOINTS_MAX`, `GRANTS_MAX`, `DEPS_MAX`, `MAX_MANIFEST_ENTRIES`) are SCAFFOLDING bounds per Development Convention 8 and get rows in [ASSUMPTIONS.md](../ASSUMPTIONS.md) when implementation lands. `MAX_MANIFEST_ENTRIES` moves in lockstep with `MAX_BOOT_MODULES` (sized together for the v1-endgame service count at ≤25% utilization). The reservation table itself is sized by `MAX_ENDPOINTS` — ARCHITECTURAL lockstep, not a separate bound.

### 3. What the manifest does **not** declare

Explicitly out of scope, to avoid the "describe the whole process tree" trap:

- **Unreserved endpoints** — processes spawned post-boot (shells, apps, PE-compat sandboxes, transient workers) register self-chosen endpoint numbers from the unreserved range via `SYS_REGISTER_ENDPOINT`, exactly as today (first-come). There is no dynamic endpoint allocator yet; when one is needed it allocates from the unreserved range and the reservation table needs no change.
- **User-spawned processes** — the shell spawning a game, a build system spawning `cargo`, an app spawning a worker. These are not init's concern; the spawner is the parent and owns lifecycle. They take the legacy spawn path (today's blanket-grant posture, bootstrap-bound) until a policy-mediated grant flow narrows it — that is [ADR-006](006-policy-service.md)'s territory, not this ADR's.
- **Policy** — who can call which syscall, who can create channels, who can delegate capabilities. That's the policy service's job ([ADR-006](006-policy-service.md)). The manifest declares *initial* capabilities at spawn; policy decides *subsequent* grants and revocations.
- **Table sizing until post-v1** — ADR-008 § 7 commits that `TableSizingPolicy` moves into the manifest eventually. This ADR defines the manifest shape that migration targets, but does not land the migration itself. See the Migration Path section.

### 4. The init process

Init is a user-space ELF (`user/init/`), signed by the bootstrap key, loaded as a boot module. It is the first and only process the kernel creates directly. It is bound at creation to **its own AID**, carried in the manifest header — audit shows init's actions as init, not as the operator. Its responsibilities:

1. **Parse the manifest's policy fields.** The same blob the kernel verified and transcribed, via the same `cambios-manifest` parser. Reject on any structural error (unknown version, oversize bounds, cyclic `depends_on`, missing module). Init's parse cannot affect security state — grants, reservations, and identity were transcribed by the kernel before init's first instruction. A buggy init parse can mis-order or refuse to spawn; it cannot mis-grant.
2. **Spawn services in DAG order.** For each service in topological order of `depends_on`: call `SYS_SPAWN(module_name)` — the existing syscall, unchanged ABI. The kernel recognizes manifest-listed names when the caller is init and atomically binds the entry's AID + installs exactly the entry's grants (see § 5). Block on the service's readiness signal — a minimal "I'm up" IPC to init's endpoint (endpoint 1, reserved to init's AID), emitted by the service runtime entry macro ([ADR-037](037-native-app-framework.md) `service_main!`) where `SYS_MODULE_READY` is emitted today — before spawning dependents.
3. **Own post-boot service lifecycle.** When a Persistent service exits, apply the service's restart policy. OneShot services are logged and not restarted. Prerequisite: [ADR-019](019-process-fault-reaping-and-peer-generation.md) phases A/B make faults reap and wake the parent at all (today they do neither), and phase D distinguishes fault from clean exit.
   > **Deferred decision.** Init's steady-state wake model — it must observe N children's exits *and* readiness pings on its endpoint with one blocking primitive. Candidates: a kernel-authored exit-notification message to init's endpoint (single RecvMsg loop; precedent: the kernel already writes IPC on the virtio-blk kernel-cmd path), or a wait-any variant of `SYS_WAIT_TASK`. **Revisit when:** migration step 10 starts.
4. **Audit.** Spawns and exits are already kernel-audited (`ProcessCreated`, `ProcessTerminated`; ADR-019 adds `ProcessFaulted`). The genuinely new event is init's *decision* audit — restart-gave-up (`ServiceDead`) — which lands with migration step 10 through the `cambios-abi` audit taxonomy; the emission mechanism (narrow emit syscall vs kernel-emitted on wait outcome) is decided there.

Init holds exactly **one** privileged capability at boot: `CreateProcess`. It holds no grant authority at all — grants flow from the kernel's transcribed table at spawn time, so init cannot widen, forge, or reassign them. Init is a mechanism for executing the manifest's policy, not an authority beyond it.

### 5. The kernel's boot surface: what is removed, what is added

The kernel removes:

- `BOOT_MODULE_ORDER` in [src/lib.rs](../../src/lib.rs) and `BootModuleOrder` in [src/boot_modules.rs](../../src/boot_modules.rs)
- `BlockReason::BootGate` in [src/scheduler/task.rs](../../src/scheduler/task.rs)
- `SyscallNumber::ModuleReady` (= 36) and `handle_module_ready` — the slot is retired permanently, never reused (same discipline as slot 18)
- `SPAWN_ONLY_MODULES` in `load_boot_modules` — under init, "loaded but not spawned" is simply "not in the manifest"
- The blanket-grant path for boot modules (`register_process_capabilities`: send/receive on all endpoints + CreateProcess + CreateChannel + CreateCluster to everyone) and the name-based narrow grants (MapFramebuffer, AuditConsumer, SetWallclock) — all subsumed by manifest `granted_capabilities`. (The `POLICY_SERVICE_PID` name-hook at spawn stays — it is kernel-internal interceptor plumbing, not a capability.)

The kernel adds:

- The **endpoint-reservation table**: dense `[EndpointReservation; MAX_ENDPOINTS]`, each slot `Unreserved` (first-come, as today) or `Reserved(aid)`. Checked inside `SYS_REGISTER_ENDPOINT` before the existing self-grant logic. Write-once at boot.
- The **spawn-grant table**: module name → (AID, grants). Write-once at boot.
- The **manifest transcription path** in boot-module load: identify the manifest module by name, verify ARCSIG, parse via `cambios-manifest`, populate both tables. Invalid manifest → typed boot error ([ADR-021](021-typed-boot-error-propagation.md); `make check-boot-panics` applies). Absent manifest → empty tables, behavior identical to today.
- A **manifest branch in `handle_spawn`**: if the requested name is in the spawn-grant table *and* the caller is init (PID 1 — structural, kernel-created), bind the table's AID and install exactly the table's grants instead of the legacy blanket. All other callers take today's path unchanged.

No new syscall. `SYS_SPAWN`'s ABI is untouched; the libsys wrapper is untouched.

Net: the kernel's boot path loads init + manifest + signed service modules, verifies all signatures, transcribes the manifest, spawns init, and goes to the idle loop. The boot sequencing logic that exists today is deleted, not refactored.

### 6. Bootstrap chicken-and-egg

Init needs a manifest to know what to spawn. The manifest needs to be signed. Signing needs the bootstrap key. The bootstrap key is held by the operator (the YubiKey root of trust) and used at build time to sign the manifest blob as part of the image (`tools/build-manifest`, with the same YubiKey / `--seed` / dev-piv paths as `tools/sign-elf`). At runtime:

1. Limine loads the kernel, init, the manifest blob, and every service ELF referenced by the manifest as boot modules.
2. The kernel, during early boot, verifies each signed ELF and the manifest blob against the bootstrap public key (compile-time embedded per [ADR-004](004-cryptographic-integrity.md) § Divergence 3).
3. The kernel transcribes the manifest into the reservation + spawn-grant tables.
4. The kernel creates init as PID 1, binds init's manifest-declared AID, maps the manifest blob read-only into init's address space at a fixed address, and installs `CreateProcess`.
5. Init runs.

Fs-service, key-store, and the ObjectStore do not exist yet at step 4. The manifest cannot live in the ObjectStore at v1 for exactly this reason — the ObjectStore depends on fs-service, which depends on the manifest to be loaded. This is why v1 pins the manifest to a boot module. Post-v1, when a second-stage loader can materialize the manifest from the persistent ObjectStore, the same parser handles both sources.

## Architecture

### Manifest wire format

```
┌────────────────────────────────────────────────────────────┐
│ magic: "CBOSMANI" (8 bytes)                                │
│ version: u32 (= 1)                                         │
│ entry_count: u32                                           │
│ entries_offset: u32   (offset from start of blob)          │
│ strings_offset: u32   (interned module names + dep names)  │
│ strings_len: u32                                           │
│ init_aid: [u8; 32]    (AID the kernel binds to PID 1)      │
│ init_endpoint: u32    (readiness-ping endpoint; v1 = 1)    │
├────────────────────────────────────────────────────────────┤
│ Entry 0: fixed-size ManifestEntryRaw                       │
│   principal: [u8; 32]                                      │
│   module_name_ref: StringRef (offset + len into strings)   │
│   reserved_endpoints: [u32; RESERVED_ENDPOINTS_MAX]        │
│   reserved_endpoints_len: u8                               │
│   granted_capabilities: [CapabilityGrantRaw; GRANTS_MAX]   │
│   granted_capabilities_len: u8                             │
│   lifetime: ServiceLifetimeRaw (tag + fields)              │
│   depends_on: [StringRef; DEPS_MAX]                        │
│   depends_on_len: u8                                       │
│   reserved: [u8; 16]                                       │
├────────────────────────────────────────────────────────────┤
│ Entry 1 … Entry N-1                                        │
├────────────────────────────────────────────────────────────┤
│ String table (UTF-8, no NUL terminators; length-prefixed   │
│ by StringRef; validated to be inside strings_len)          │
├────────────────────────────────────────────────────────────┤
│ ARCSIG trailer (existing Ed25519 signing format, over      │
│ blake3 of everything above)                                │
└────────────────────────────────────────────────────────────┘
```

Every `[u32; N]` / `[T; N]` array is a fixed-size inline field with a separate length byte. No variable-length inline fields, no pointers, no dynamic dispatch. Parsing is a bounded loop over `entry_count` records with range-checks on every offset before access. The parser lives in the shared `cambios-manifest` crate; its bounds-check logic is small enough to be an explicit verification target. Reservation rows may exist without a matching spawn entry (init's own endpoint; virtio-blk's kernel-reply endpoint 25).

### Startup sequence (post-kernel-init)

```
Kernel init (frame alloc, heap, object tables per ADR-008)
    │
    ▼
Kernel verifies signatures on all boot modules + manifest blob
    │
    ▼
Kernel transcribes manifest security sections into write-once tables:
endpoint reservations + per-module (AID, grants) spawn table
    │
    ▼
Kernel creates PID 1 (init), binds init's manifest-declared AID,
maps manifest read-only into init's AS, installs CreateProcess
    │
    ▼
Init parses manifest policy fields, validates DAG, no cycles
    │
    ▼
Init spawns services in topological order:
    for svc in topo_order(manifest):
        block until all svc.depends_on are ready
        SYS_SPAWN(svc.module_name)        ← kernel applies AID + grants
        block on svc's readiness ping to init's endpoint
    │
    ▼
Steady state: init supervises exits, dispatches restarts per policy
(wake model decided at step 10; requires ADR-019)
```

### Endpoint reservation check

`SYS_REGISTER_ENDPOINT(n)` gains one check before its current self-grant logic:

```rust
match endpoint_reservation_table[n] {
    Unreserved => { /* proceed as today */ }
    Reserved(aid) if caller.principal().aid() == &aid => { /* proceed */ }
    Reserved(_) => return Err(SyscallError::PermissionDenied),
}
```

The table is a flat `[EndpointReservation; MAX_ENDPOINTS]` — ARCHITECTURAL lockstep with `MAX_ENDPOINTS` (an endpoint that exists is reservable; at 64 endpoints the table is ~2 KB). Endpoints the manifest does not list stay `Unreserved` and behave exactly as today. Endpoint 0 is structurally unreservable (it is the `REPLY_ENDPOINT` "unset" sentinel); endpoint 1 is init's.

Restarts need no table change by design: reservations are keyed by AID, not by process, so a restarted service binds the same manifest AID and legitimately re-registers the same endpoint. [ADR-019](019-process-fault-reaping-and-peer-generation.md)'s endpoint *generation* counter — not this table — is what signals "new incarnation" to clients.

### Restart and backoff

Init tracks per-service restart state:

```rust
struct ServiceRuntime {
    entry: &'static ManifestEntry,
    task_id: TaskId,               // generation-carrying (ADR-034)
    last_restart_at_ticks: u64,
    consecutive_failures_in_window: u16,
    next_delay_ms: u32,
}
```

On observing a Persistent service's exit, init:

1. If `consecutive_failures_in_window >= max_restarts` within `failure_window_ms` of the first failure in the window: emit `ServiceDead`, stop restarting.
2. Else sleep for `next_delay_ms`, then re-spawn via the same DAG path.
3. Double `next_delay_ms` up to `max_delay_ms`. Reset to `initial_delay_ms` after a healthy window elapses without another failure.

The backoff is deliberately simple. More sophisticated supervision strategies (watchdog pings, health-check endpoints, jittered restart) are explicit non-goals for v1; they can be added without changing the kernel surface.

**Prerequisite:** this section is inert until [ADR-019](019-process-fault-reaping-and-peer-generation.md) lands its phases A/B (fault path reaps and wakes the parent — today a faulting service leaks and no one is notified) and D (`ExitInfo` distinguishes fault from clean exit). ADR-019 is reviewed for acceptance as its own gate before migration step 10.

### Interaction with ADR-008 table sizing

The `TableSizingPolicy` defined in ADR-008 § 2 stays compile-time for the initial init/manifest landing. The migration to manifest-driven sizing is a follow-up commit that adds a top-level `TableSizingPolicy` field to the manifest header and moves ADR-008's compile-time const into a fallback default. The Migration Path section below sequences this.

## Threat Model Impact

| Threat | Without init/manifest | With init/manifest |
|---|---|---|
| Rogue process squats core service endpoint | Succeeds if timing works — `SYS_REGISTER_ENDPOINT(16)` is unconditional | Kernel rejects: reservation table enforces per-endpoint AID ownership, and per-service AIDs make the check discriminating (bootstrap-bound user spawns cannot claim fs-service's slot) |
| Attacker replaces a service ELF at build time | Caught by existing signed-ELF verification | Same — manifest entries reference module names; the ELF's ARCSIG check still applies independently |
| Attacker replaces the manifest blob itself | N/A (no manifest today) | Blob is ARCSIG-signed by the bootstrap key; kernel rejects unsigned/wrong-key blob before transcription |
| Attacker adds an entry to the manifest | N/A | Blob is signed as one unit; any edit invalidates the signature |
| Compromised init grants itself or a service extra capabilities | N/A | Structurally impossible: grants flow only from the kernel's boot-transcribed table. Init passes no grant data at spawn and has no install authority — there is nothing to forge |
| Compromised init lies about manifest content | N/A | Impossible for security sections: the kernel transcribed them itself from the verified blob before init's first instruction. Init's parse affects only ordering and lifecycle |
| Compromised init refuses to start / mis-orders services | N/A | Same threat as any compromised user-space supervisor — a service doesn't run. Detected by absent readiness pings; does not affect other services' identity, reservations, or grants. Not a kernel-TCB compromise |
| Crashed policy service never restarts | Matches ADR-006 § Failure Modes: permissive fallback, no recovery | Init restarts per manifest policy; permissive window is bounded by restart delay |

Key property: **the kernel gains no runtime-attacker-reachable surface.** The one kernel-side addition that touches manifest bytes — the transcription parse — runs once at boot, single-threaded, on input that is operator-signed *before* parsing begins; it is a bounded pure function and a verification target, not an attack surface. Init is in the boot-lifecycle TCB but not the kernel TCB: its worst failure mode is refusing to supervise, never widening authority.

## Verification Stance

Kernel-side additions are small and fit the verification posture:

- The endpoint-reservation and spawn-grant tables are dense arrays with O(1) indexed / name-keyed lookup, written once at boot (the `BOOTSTRAP_PRINCIPAL` lifecycle — outside the lock hierarchy entirely).
- The transcription parse is a bounded loop over `entry_count` fixed-size records — a pure function over a byte slice, shared with userspace via `cambios-manifest`, host-tested against every structural error case, and a natural Kani target ("parsed tables ≡ well-formed blob content").
- `handle_spawn`'s manifest branch is a name-keyed table lookup plus a bounded grant-application loop.
- Deleting `BootGate`, `BOOT_MODULE_ORDER`, and `SYS_MODULE_READY` removes more verification surface than the additions introduce.

Init itself is user-space and is **not** in the kernel verification target. Its correctness is enforced through:

- Signed ELF + build-time testing of the manifest parser on malformed inputs (the same parser crate the kernel uses — written and tested once).
- Structural containment: init's parse cannot affect grants, reservations, or identity (kernel-transcribed before init runs); its failure domain is ordering and lifecycle only.
- The audit trail ([ADR-007](007-capability-revocation-and-telemetry.md)) records every spawn and exit; step 10 adds init's give-up decisions.

This matches CLAUDE.md's verification posture: kernel code is verification-targeted, user-space code is reviewed and tested but not formally verified.

## Why Not Other Options

### Option A: Keep sequencing in the kernel, just replace the comment with a struct

**Why considered.** Smallest delta. The existing `BOOT_MODULE_ORDER` machinery already works.

**Why rejected.** Entrenches supervision in the kernel. Does nothing for post-boot crash recovery, endpoint reservation enforcement, or declarative service sets. Pushes every future evolution (backoff, DAG ordering, audit) into the kernel TCB. Explicitly violates the [ADR-006](006-policy-service.md) / [CambiOS.md](../CambiOS.md) layering commitment.

### Option B: CBOR or similar self-describing wire format for the manifest

**Why considered.** Standard, tool-friendly, flexible. Easy to extend.

**Why rejected.** Adds a `no_std` CBOR parser to two TCBs — now including the kernel's, since the kernel transcribes. The manifest has one producer (build time) and two same-repo consumers — self-description buys nothing. A fixed-layout binary with a version field can evolve with explicit version bumps, which is what we want anyway.

### Option C: Kernel parses the manifest — *adopted in part at acceptance review (2026-07-06)*

**Why considered.** The kernel has the blob and has already verified its signature; it can populate the enforcement tables itself, and no install syscall is needed.

**What the original rejection got right, and kept.** The drafting-time rejection ("every parser bug becomes a kernel CVE; init is the right architectural place") conflated two concerns. The one it was right about stays rejected: the kernel must not *interpret* the manifest — sequencing, dependency resolution, restart policy, lifecycle are user-space decisions, exactly as ADR-006 splits policy from mechanism.

**What changed.** The acceptance review re-derived the parsing question and reversed it. The drafted alternative — init parses, then hands the kernel the derived tables via a one-shot `SYS_INSTALL_ENDPOINT_RESERVATIONS` syscall — turned out to be strictly worse: it added a syscall, a capability kind, a one-shot protocol, and a hash-check handshake, and its enforcement tables were only as faithful as *unverified-at-runtime userspace parsing*, all to buy a "smaller kernel TCB" argument that does not survive scrutiny. The transcription parse is ~150 lines of bounded, allocation-free offset-walking over input that is **operator-signed before parsing begins**, run once at boot, single-threaded, pre-userspace — smaller and purer than the ELF header walk the loader already performs, and a better verification target than a trust link. Kernel-side transcription strengthens the end-to-end property to "enforcement tables ≡ signed blob content" with no userspace in the chain, and deletes an entire syscall from the design. Transcribe, don't interpret ([ADR-026](026-identity-transcription-at-the-kernel-ring.md)) is the governing pattern.

### Option D: Multiple init processes (launchd-style agents)

**Why considered.** Matches modern macOS and systemd-user patterns. Per-user supervisors.

**Why rejected.** Out of scope for v1. CambiOS is a single-operator system today; multi-user / per-user supervision is a post-v1 concern and this ADR does not preclude adding user-level supervisors later as children of the system init.

### Option E: Embed the manifest in init's ELF as a `.rodata` section

**Why considered.** One fewer boot module. Manifest signature is part of init's signature — one fewer verify call.

**Why rejected.** Conflates init with its configuration, and (post-review) would force the kernel to parse init's ELF sections to reach the security data it must transcribe. An operator who wants to adjust the manifest (change reservations, add a service) would have to rebuild init. Separating the manifest keeps init minimal and keeps the manifest the only thing the operator touches for fleet configuration.

### Option F (chosen): Separate signed manifest blob, kernel transcription, user-space init

**Why chosen.** Aligns with the layering [ADR-006](006-policy-service.md) established for policy and the transcription stance [ADR-026](026-identity-transcription-at-the-kernel-ring.md) established for identity. Shrinks the kernel's boot machinery while adding only a bounded pure parse. Composes with the existing signing infrastructure. Makes the core service set declarative and per-service identity real. Gives ADR-006's and ADR-008's explicit "future init" references a concrete home. Does not close off the post-v1 migration to ObjectStore-hosted manifests.

## Migration Path

Sequenced to be landable in bounded commits with no regressions between them. The tri-arch regression gate applies at every step. The manifest is per-build data: each step ships a manifest matching that step's reality (tables are per-*boot* immutable, not per-project).

1. **`cambios-manifest` crate** — wire format, parser, validation, grant/AID types. Root-level, `no_std`, zero-dep, MPL-2.0, workspace-excluded (the `cambios-abi` pattern). Host tests for every structural error case. No kernel change.
2. **`tools/build-manifest`** — consumes the endpoint-registry source artifact ([ADR-037](037-native-app-framework.md) Phase 2 — the registry TOML and the manifest source are one artifact, build-manifest is its single consumer), derives v1 service AIDs, validates endpoint uniqueness + DAG acyclicity + bounds, emits the signed blob (same YubiKey / `--seed` / dev-piv signing paths as `tools/sign-elf`). `make manifest` target.
3. **Endpoint-reservation table** in the kernel (`src/ipc/endpoint_reservation.rs`), checked in `SYS_REGISTER_ENDPOINT`. Write-once lifecycle documented at the static. Empty table ⇒ behavior unchanged.
4. **Kernel manifest transcription** — identify the manifest module by name during boot-module load, verify ARCSIG, parse via `cambios-manifest`, populate reservation + spawn-grant tables. Invalid ⇒ typed boot error (ADR-021). Absent ⇒ empty tables, behavior unchanged.
5. **`handle_spawn` manifest branch** (init-only, name-keyed). Dormant — no manifest module is loaded yet, so the table is empty.
6. **`user/init/`** — policy-field parse, DAG resolver, spawn + readiness loop. Host tests for parser and DAG logic. No allocator.
7. **Boot integration, coexistence.** `limine.conf` gains `init.elf` and `manifest.bin`. The kernel transcribes (step 4 goes live), maps the blob into init, spawns init as PID 1 with its manifest AID + `CreateProcess`. **The step-7 manifest reserves only endpoint 1 (init's)** — old-chain services are still bootstrap-bound, so reserving their endpoints to per-service AIDs would make their own registrations fail. Init parses, validates, and idles; the `BOOT_MODULE_ORDER` chain still starts every service. Zero behavior change, full machinery exercised.
8. **Cutover.** Manifest-listed services leave the boot chain (the kernel loads them registry-only); init spawns them in DAG order; the full reservation set and per-service AIDs ship in this step's manifest; `service_main!`'s `module_ready()` becomes the readiness ping to endpoint 1 (one macro edit + the explicit call in no-endpoint-form services). **Required sweep:** per-service AIDs change `sender_principal` values peers observe — audit every bootstrap-equality assumption (channel `peer_principal` flows, any service checking sender == bootstrap). Cutover lands as one step with heavy boot proof (`make run-quiet` + interactive), with dependency-closed waves as the fallback plan if it fights back.
9. **Delete the scaffolding.** Remove `BOOT_MODULE_ORDER`, `BootModuleOrder`, `BlockReason::BootGate`, `SyscallNumber::ModuleReady` (slot 36 retired with a tombstone comment, never reused — the slot-18 discipline), `handle_module_ready`, the libsys wrapper, `SPAWN_ONLY_MODULES`, and the blanket boot-grant path. Update CLAUDE.md, STATUS.md, the ABI tests (36 is in the identity-exempt set today), and dependent tests. This is the irreversible commit.
10. **Wire restart policy.** Backoff loop in init, the wake-model decision (see § 4 deferred decision), `ServiceDead` audit via the `cambios-abi` taxonomy, integration test that kills a boot service and asserts init restarts it. **Prerequisite:** ADR-019 acceptance + phases A/B/D — reviewed as its own gate before this step starts.
11. **Move `TableSizingPolicy` into the manifest.** Add a top-level manifest field, have the kernel pass it to ADR-008's sizing path, and demote the compile-time const to a fallback default. Fulfills ADR-008 § 7.
12. **Post-v1: migrate the manifest source.** When the persistent ObjectStore ([ADR-010](010-persistent-object-store-on-disk-format.md)) is the trusted source for system configuration, the manifest moves there. The parser stays. The loader path (boot module → ObjectStore lookup) is the only change.

Steps 1–7 establish the slot without behavior change. Step 8 is the first behavior change. Step 9 is the irreversible architectural shift. Steps 10–12 add functionality on top.

## Cross-References

- **[ADR-000](000-zta-and-cap.md)** — Capabilities; the endpoint reservation check is a new capability-style structural authority check
- **[ADR-004](004-cryptographic-integrity.md)** — ARCSIG signing format; the manifest blob reuses the trailer + `blake3(payload)` scheme unchanged
- **[ADR-006](006-policy-service.md)** — Policy service; explicitly defers endpoint-registry and restart-authority to this ADR (its § Architecture deferral triggers at steps 7-8); init holds restart authority, policy mediates subsequent grant decisions
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Audit channel; spawns/exits kernel-audited today, init's `ServiceDead` lands at step 10
- **[ADR-008](008-boot-time-sized-object-tables.md)** — `TableSizingPolicy`; this ADR's manifest is the vehicle for ADR-008 § 7's promised migration (step 11)
- **[ADR-019](019-process-fault-reaping-and-peer-generation.md)** — kernel substrate for restart observation (fault reap, parent wake, `ExitInfo`, endpoint generations); prerequisite for step 10; its endpoint-generation counter is the "new incarnation" signal that composes with stable reservations
- **[ADR-024](024-syscall-abi-crate.md)** — the shared-contract-crate pattern `cambios-manifest` follows (workspace-excluded, `no_std`, MPL-2.0, consumed by kernel + userspace + tools)
- **[ADR-025](025-principal-as-aid.md)** — Principal as opaque 32-byte AID; manifest `principal` fields are AIDs, and v1's derived service AIDs are deliberately not signing keys
- **[ADR-026](026-identity-transcription-at-the-kernel-ring.md)** — transcribe-don't-interpret; the kernel-side manifest handling is this pattern applied to boot configuration
- **[ADR-033](033-multi-principal-vault.md)** — services that need real signing keys use the key-store; manifest AIDs carry identity, not key material
- **[ADR-034](034-deferred-task-resource-reclamation.md)** — generation-carrying task handles; init's supervision keys restarts on them
- **[ADR-037](037-native-app-framework.md)** — `service_main!` is where the readiness ping is emitted (one macro site + explicit no-endpoint services); its Phase-2 endpoint registry is `build-manifest`'s input artifact
- **[ADR-002](002-three-layer-enforcement-pipeline.md)** — Enforcement pipeline; `SYS_REGISTER_ENDPOINT` gains one check, same pattern as other kernel-side mechanical checks
- **[ADR-012](012-input-architecture-and-device-classes.md)** / **[ADR-014](014-compositor-scanout-driver-protocol.md)** — Input-hub and compositor/scanout-driver both need reserved endpoints; this ADR is the mechanism they plug into

## See Also in CLAUDE.md

Updates required as the implementation lands:

- **§ "Quick Reference"** — add `make manifest` / `tools/build-manifest` build command (step 2)
- **§ "Syscall Numbers"** — note `ModuleReady` (36) retirement at step 9; no syscall additions
- **§ "Lock Ordering" (additional lock domains)** — add the reservation + spawn-grant tables to the `BOOTSTRAP_PRINCIPAL`-pattern list (written once at boot, read-only thereafter, not in the hierarchy) at step 3-4
- **§ "Required Reading by Subsystem"** — add a row for "init / service lifecycle / manifest" (steps 6-7)
- **§ "Platform Gotchas"** — note that the manifest blob is a required boot module post-cutover; missing manifest ⇒ kernel refuses to spawn init (step 8)
- **§ "Deep Reference" / directory layout** — add `cambios-manifest/`, `user/init/`, `tools/build-manifest/`
- **Worked example "Adding a new syscall"** — unaffected (this ADR adds none); the boot-module walkthroughs that mention `module_ready` update at step 9
