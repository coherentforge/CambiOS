# ADR-018: Init Process and Boot Manifest

- **Status:** Proposed
- **Date:** 2026-04-19
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-003](003-content-addressed-storage-and-identity.md) (Identity/Principal model), [ADR-004](004-cryptographic-integrity.md) (Signed boot modules), [ADR-008](008-boot-time-sized-object-tables.md) (Boot-time-sized object tables)
- **Related:** [ADR-006](006-policy-service.md) (Policy service — explicitly defers init/manifest design to this ADR), [ADR-002](002-three-layer-enforcement-pipeline.md), [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives), [ADR-007](007-capability-revocation-and-telemetry.md) (Revocation + telemetry), [ADR-012](012-input-architecture-and-device-classes.md), [ADR-014](014-compositor-scanout-driver-protocol.md)
- **Supersedes:** N/A (introduces the init/manifest slot that ADR-006 and ADR-008 both explicitly deferred)

## Context

CambiOS today boots by reading a hand-rolled comment in `limine.conf`, loading each listed ELF as a boot module, and releasing them in file-declaration order via a linear chain built out of `BOOT_MODULE_ORDER`, `BlockReason::BootGate`, and the `SYS_MODULE_READY` syscall. The kernel does the sequencing. Endpoint numbers for core services (policy endpoint, fs-service endpoint 16, key-store endpoint 17, virtio-blk endpoint 24/26, and so on) are compile-time `const`s sprinkled across the kernel and every user-space crate. When a service crashes post-boot, nothing restarts it.

This works for bring-up. It is not what a general-purpose OS does in production, and two already-accepted ADRs have explicitly deferred work to a "future init-process ADR":

- **[ADR-006](006-policy-service.md) § Architecture** — "The kernel knows the policy service's IPC endpoint via a compile-time constant (or, eventually, via the boot manifest declared by the future init-process ADR, when that lands — the init-process design is deferred until a second boot module needs user-declared endpoints, at which point a hand-rolled compile-time table stops scaling)."
- **[ADR-006](006-policy-service.md) § Failure Modes** — "The init process (when it exists — see roadmap item 21) restarts the policy service."
- **[ADR-008](008-boot-time-sized-object-tables.md) § Decision (point 7)** — "When CambiOS grows a boot-manifest mechanism (anticipated post-v1, alongside the init process and service configuration work), the table sizing policy moves from compile-time configuration to the manifest."

The "second boot module needs user-declared endpoints" threshold ADR-006 named has been crossed: policy-service, key-store, fs-service, virtio-blk, compositor, and shell all have hard-coded endpoint numbers spread across the kernel and user crates, and the input-hub ([ADR-012](012-input-architecture-and-device-classes.md)) and scanout-driver ([ADR-014](014-compositor-scanout-driver-protocol.md)) add two more on the near horizon. Every new core service today requires editing at least three crates to teach them each other's endpoint numbers.

This ADR designs the slot the two reference ADRs are waiting for.

## Problem

Four problems have accumulated that the compile-time / kernel-sequenced approach cannot cleanly address.

**Problem 1 — endpoint numbers are ambient.** Core service endpoints are `const u32` values scattered across the kernel (`src/ipc/`, `src/syscalls/dispatcher.rs`) and every user crate (`user/libsys/`, `user/fs-service/`, etc.). Nothing structural prevents a different process from calling `SYS_REGISTER_ENDPOINT(16)` and squatting on the fs-service slot. The restriction "only fs-service gets endpoint 16" is enforced by convention — by the fact that fs-service is the only thing coded to register 16 — not by structure. This conflicts with [ADR-000](000-zta-and-cap.md)'s zero-trust stance: authority for a stable identity-bearing endpoint should be a capability check, not a convention.

**Problem 2 — the kernel owns the service lifecycle.** `BOOT_MODULE_ORDER`, `BlockReason::BootGate`, and `SYS_MODULE_READY` exist to sequence boot module startup. This is scaffolding. It does not compose with post-boot lifecycle needs (crash restart, dependency reordering after a service upgrade, shutdown sequencing) because the kernel isn't the right component to own any of those. Every production OS (systemd, launchd, sysvinit, runit, s6) has a user-space supervisor for exactly this reason. Keeping the logic in the kernel means either growing the kernel into a supervisor — violating the microkernel principle and the verification-first commitment — or rewriting it later.

**Problem 3 — service set is not declarative.** Adding or removing a boot-time service today requires editing `limine.conf`, coordinating endpoint constants across multiple crates, and hoping the implicit dependency comments stay accurate. There is no single file that answers the question "what boot-time services does this deployment run, and what is each allowed to do?" The manifest ADR-006 and ADR-008 anticipate is precisely this file.

**Problem 4 — no crash recovery for core services.** When the policy service, fs-service, or virtio-blk driver crashes, nothing brings it back. [ADR-006 § Failure Modes](006-policy-service.md#failure-modes) describes graceful degradation on policy-service crash (fall back to permissive default), but the "restart" half of the recovery is explicitly delegated to the future init process. That future is now.

**Why these problems must be solved together.** Each piece in isolation produces a half-measure: a manifest without init is just a config file nobody reads; init without a manifest is a hard-coded service list; endpoint reservations without a manifest is a new capability with no declarative source of authority; crash recovery without init is kernel-resident supervision. The four pieces compose into one mechanism — a signed manifest describing the core service set, an init process that reads it and owns the lifecycle, and a kernel that enforces the reservations but does not interpret the manifest.

## The Reframe

The architectural insight:

> **The kernel spawns init and hands init the manifest. Init runs the rest of the system. The kernel enforces manifest-derived invariants (endpoint ownership, initial capabilities) but never parses the manifest itself.**

This matches the pattern already established for policy ([ADR-006](006-policy-service.md)): the kernel makes mechanical checks ("does this Principal own this endpoint?"), and a user-space service makes decisions ("should this service be spawned, restarted, granted X?"). Init is the decision-maker for service lifecycle, the way the policy service is the decision-maker for authorization.

The reframe does not invent new kernel primitives. `SYS_SPAWN`, the capability system, the signed-ELF loader, and the Principal binding (`SYS_BIND_PRINCIPAL`) are all already in place. What this ADR adds is:

1. A signed manifest blob, loaded as a boot module, consumed by init.
2. An init process that parses the manifest and drives `SYS_SPAWN` + capability installation in dependency order.
3. A kernel endpoint-reservation table, populated at init start, that rejects `SYS_REGISTER_ENDPOINT(N)` from any Principal other than the one the manifest assigned to `N`.
4. The removal of `BOOT_MODULE_ORDER`, `BlockReason::BootGate`, and `SYS_MODULE_READY` — the scaffolding init replaces.

The kernel's boot surface shrinks. The user-space supervision surface grows in a place where it belongs.

## Decision

CambiOS adopts a **user-space init process (PID 1) driven by a signed boot manifest** as the mechanism for core-service lifecycle, endpoint reservation, and capability assignment.

### 1. The manifest is a signed boot-loaded blob

The manifest is a fixed-layout binary blob plus an `ARCSIG` trailer (the existing signing mechanism from [ADR-004](004-cryptographic-integrity.md), reused rather than reinvented). It is loaded as a Limine boot module alongside init and the services it describes. The kernel verifies the signature against the bootstrap Principal before handing init a mapped read-only pointer to the blob.

The blob is **not** an ELF. It is a flat record structure parsed by init. Rationale:

- Fixed-layout parsing has a bounded-loop, no-allocation shape that is cheap to verify.
- No dependency on a general-purpose deserialization library in the init process's TCB.
- The blob is authored by the bootstrap holder at build time; self-describing wire formats (CBOR, JSON) add no value when there is one producer and one consumer.

The wire format is specified in the Architecture section below.

### 2. Per-entry shape

Each manifest entry describes one boot-time service:

```rust
pub struct ManifestEntry {
    /// 32-byte Ed25519 public key — the Principal this service claims at
    /// SYS_BIND_PRINCIPAL. The kernel checks that the signed ELF's
    /// embedded public key matches this value before allowing the bind.
    pub principal: [u8; 32],

    /// Name of the boot module to load, matches strip_module_name()
    /// output (e.g. "policy-service", "fs-service").
    pub module_name: BoundedStr<MODULE_NAME_MAX>,

    /// Endpoints this Principal owns exclusively for the lifetime of
    /// the boot. RegisterEndpoint(N) from any other Principal is
    /// rejected with PermissionDenied. The entry may reserve zero
    /// endpoints (services that only talk to others).
    pub reserved_endpoints: BoundedVec<u32, RESERVED_ENDPOINTS_MAX>,

    /// Capabilities the kernel installs on this process at spawn,
    /// before any user instruction runs. Replaces the ad-hoc "bootstrap
    /// Principal grants full rights at boot" convention.
    pub granted_capabilities: BoundedVec<CapabilityGrant, GRANTS_MAX>,

    /// Lifecycle policy. OneShot services exit and are not restarted
    /// (e.g. a future identity-bootstrap tool). Persistent services
    /// are restarted by init on exit according to the restart policy.
    pub lifetime: ServiceLifetime,

    /// Names of services that must reach steady state before this one
    /// is spawned. Init resolves this into a startup DAG and spawns in
    /// topological order. Cycles are a manifest-validation error.
    pub depends_on: BoundedVec<BoundedStr<MODULE_NAME_MAX>, DEPS_MAX>,
}

pub enum ServiceLifetime {
    OneShot,
    Persistent {
        /// Exponential backoff: first restart after `initial_delay_ms`,
        /// doubling to a cap of `max_delay_ms`. After `max_restarts`
        /// consecutive failures within `failure_window_ms`, init gives
        /// up on the service and emits an AuditEventKind::ServiceDead.
        initial_delay_ms: u32,
        max_delay_ms: u32,
        max_restarts: u16,
        failure_window_ms: u32,
    },
}

pub struct CapabilityGrant {
    pub kind: CapabilityKind,
    pub target: CapabilityTarget,  // endpoint id, channel id, etc.
    pub rights: CapabilityRights,
}
```

All bounds (`MODULE_NAME_MAX`, `RESERVED_ENDPOINTS_MAX`, `GRANTS_MAX`, `DEPS_MAX`, `MAX_MANIFEST_ENTRIES`) are SCAFFOLDING bounds per Development Convention 8 and get rows in [ASSUMPTIONS.md](../ASSUMPTIONS.md) when implementation lands.

### 3. What the manifest does **not** declare

Explicitly out of scope, to avoid the "describe the whole process tree" trap:

- **Dynamic endpoints** — processes spawned post-boot (shells, apps, PE-compat sandboxes, transient workers) register endpoints via `SYS_REGISTER_ENDPOINT` and receive dynamic numbers, exactly as today. No manifest entry.
- **User-spawned processes** — the shell spawning `hello.elf`, a build system spawning `cargo`, an app spawning a worker. These are not init's concern; the spawner is the parent and owns lifecycle.
- **Policy** — who can call which syscall, who can create channels, who can delegate capabilities. That's the policy service's job ([ADR-006](006-policy-service.md)). The manifest declares *initial* capabilities at spawn; policy decides *subsequent* grants and revocations.
- **Table sizing until post-v1** — ADR-008 § 7 commits that `TableSizingPolicy` moves into the manifest eventually. This ADR defines the manifest shape that migration targets, but does not land the migration itself. See the Migration Path section.

### 4. The init process

Init is a user-space ELF (`user/init/`), signed by the bootstrap key, loaded as a boot module. It is the first and only process the kernel creates directly. Its responsibilities:

1. **Read and validate the manifest.** Parse the blob the kernel mapped into its address space. Reject on any structural error (unknown version, oversize bounds, cyclic `depends_on`, missing module, duplicate endpoint reservation).
2. **Install the endpoint reservation table.** One kernel call (`SYS_INSTALL_ENDPOINT_RESERVATIONS`, new) passes the (Principal, endpoint) pairs derived from the manifest. The kernel atomically populates its reservation table. This call is one-shot: the kernel rejects subsequent calls, period. There is no "re-read manifest at runtime" path in v1.
3. **Spawn services in DAG order.** For each service in topological order of `depends_on`: call `SYS_SPAWN(module_name, initial_capabilities)` — a spawn variant that atomically creates the process and installs the grants. Block on the service's readiness signal (a minimal "I'm up" IPC to a well-known init endpoint) before spawning dependents.
4. **Own post-boot service lifecycle.** When `SYS_WAIT_TASK` returns for a Persistent service, apply the service's restart policy. OneShot services are logged and not restarted.
5. **Emit audit events.** Every spawn, restart, and give-up emits an `AuditEventKind::ServiceLifecycle` event through the existing audit infrastructure ([ADR-007](007-capability-revocation-and-telemetry.md)).

Init holds exactly two privileged capabilities at boot: `CreateProcess` (to call `SYS_SPAWN`) and `InstallEndpointReservations` (a new kind, one-shot, consumed by the single install call). It does **not** hold `GrantCapability` as a general authority — the capability-install-list passed to `SYS_SPAWN` is bounded by what the signed manifest says, and the kernel validates the install against the manifest hash init presented when registering. Init is a mechanism for executing the manifest, not an authority beyond it.

### 5. The kernel's shrunken boot surface

The kernel removes:

- `BOOT_MODULE_ORDER` in [src/lib.rs](../../src/lib.rs)
- `BootModuleOrder` in [src/boot_modules.rs](../../src/boot_modules.rs)
- `BlockReason::BootGate` in [src/scheduler/task.rs](../../src/scheduler/task.rs)
- `SyscallNumber::ModuleReady` and `handle_module_ready` in the syscall layer
- The per-module "register endpoint on behalf of bootstrap Principal at load" ad-hoc grants in `load_boot_modules`

The kernel adds:

- The endpoint reservation table: an array keyed by endpoint id, each slot either `Unreserved` (any Principal may `RegisterEndpoint` it) or `Reserved(Principal)` (only that Principal may register it). Checked inside `SYS_REGISTER_ENDPOINT`.
- `SyscallNumber::InstallEndpointReservations` (one-shot, init-only).
- `SYS_SPAWN` extended to accept a capability-install-list validated against the manifest.
- A `ServiceDead` audit event variant consumed by the eventual AI watcher.

Net: the kernel's boot path loads init + manifest + signed service modules, verifies all signatures, spawns init, hands it the manifest pointer, and goes to the idle loop. The boot sequencing logic that exists today is deleted, not refactored.

### 6. Bootstrap chicken-and-egg

Init needs a manifest to know what to spawn. The manifest needs to be signed. Signing needs the bootstrap key. The bootstrap key is held by the operator (the YubiKey root of trust per `project_yubikey_root_of_trust`) and used at build time to sign the manifest blob as part of the image. At runtime:

1. Limine loads the kernel, init, the manifest blob, and every service ELF referenced by the manifest as boot modules.
2. The kernel, during early boot, enumerates the boot modules and verifies each signed ELF + the manifest blob against the bootstrap public key (already embedded in the kernel per [ADR-004](004-cryptographic-integrity.md)).
3. The kernel creates init as PID 1, maps the manifest blob read-only into init's address space at a known address, and installs `CreateProcess` + `InstallEndpointReservations` capabilities on init.
4. Init runs.

Fs-service, key-store, and the ObjectStore do not exist yet at step 3. The manifest cannot live in the ObjectStore at v1 for exactly this reason — the ObjectStore depends on fs-service, which depends on the manifest to be loaded. This is why v1 pins the manifest to a boot module. Post-v1, when a second-stage loader can materialize the manifest from the persistent ObjectStore, the same parser handles both sources.

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
│ reserved: [u8; 36]    (zeroed in v1)                       │
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
│ ARCSIG trailer (existing Ed25519 signing format)           │
└────────────────────────────────────────────────────────────┘
```

Every `[u32; N]` / `[T; N]` array is a fixed-size inline field with a separate length byte. No variable-length inline fields, no pointers, no dynamic dispatch. Parsing is a bounded loop over `entry_count` records, each a `core::mem::transmute` into the raw struct after range-checks on the two offsets. A reference parser lands in `user/init/src/manifest.rs`; the bounds-check logic is small enough to be an explicit verification target.

### Startup sequence (post-kernel-init)

```
Kernel init (frame alloc, heap, object tables per ADR-008)
    │
    ▼
Kernel verifies signatures on all boot modules + manifest blob
    │
    ▼
Kernel creates PID 1 (init), maps manifest read-only into init's AS,
installs CreateProcess + InstallEndpointReservations caps, starts init
    │
    ▼
Init parses manifest, validates DAG, no cycles
    │
    ▼
Init calls SYS_INSTALL_ENDPOINT_RESERVATIONS(manifest_hash, reservations[])
    │
    ▼
Kernel validates manifest hash matches the blob it loaded, populates
the reservation table, marks the install one-shot-consumed
    │
    ▼
Init spawns services in topological order:
    for svc in topo_order(manifest):
        block on all svc.depends_on to be ready
        SYS_SPAWN(svc.module_name, svc.granted_capabilities, manifest_hash)
        block on svc's readiness ping to init's endpoint
    │
    ▼
Steady state: init blocks in SYS_WAIT_TASK, dispatches restarts per
policy when services exit
```

### Endpoint reservation check

`SYS_REGISTER_ENDPOINT(n)` gains one check before its current capability-install logic:

```rust
match endpoint_reservation_table[n] {
    Unreserved => { /* proceed as today */ }
    Reserved(principal) if caller.principal() == principal => { /* proceed */ }
    Reserved(_) => return Err(SyscallError::PermissionDenied),
}
```

The table is a flat `[EndpointReservation; ENDPOINT_RESERVATION_TABLE_SIZE]` where `ENDPOINT_RESERVATION_TABLE_SIZE` is a SCAFFOLDING bound sized for v1 core-service count × 4 headroom (per Development Convention 8's "≤25% utilization" rule). Endpoints beyond the reservation table size cannot be reserved and are always `Unreserved` — dynamic endpoints live in that upper range.

### Restart and backoff

Init tracks per-service restart state:

```rust
struct ServiceRuntime {
    entry: &'static ManifestEntry,
    task_id: TaskId,
    last_restart_at_ticks: u64,
    consecutive_failures_in_window: u16,
    next_delay_ms: u32,
}
```

On `SYS_WAIT_TASK` return for a Persistent service, init:

1. If `consecutive_failures_in_window >= max_restarts` within `failure_window_ms` of the first failure in the window: emit `ServiceDead`, stop restarting.
2. Else sleep for `next_delay_ms`, then re-spawn via the same DAG path.
3. Double `next_delay_ms` up to `max_delay_ms`. Reset to `initial_delay_ms` after a healthy window elapses without another failure.

The backoff is deliberately simple. More sophisticated supervision strategies (watchdog pings, health-check endpoints, jittered restart) are explicit non-goals for v1; they can be added without changing the kernel surface.

### Interaction with ADR-008 table sizing

The `TableSizingPolicy` defined in ADR-008 § 2 stays compile-time for the initial init/manifest landing. The migration to manifest-driven sizing is a follow-up commit that adds a top-level `TableSizingPolicy` field to the manifest header and moves ADR-008's compile-time const into a fallback default. The Migration Path section below sequences this.

## Threat Model Impact

| Threat | Without init/manifest | With init/manifest |
|---|---|---|
| Rogue process squats core service endpoint | Succeeds if timing works — `SYS_REGISTER_ENDPOINT(16)` is unconditional | Kernel rejects: reservation table enforces per-endpoint Principal ownership |
| Attacker replaces a service ELF at build time | Caught by existing signed-ELF verification | Same — manifest entries reference module names, signature check still applies |
| Attacker replaces the manifest blob itself | N/A (no manifest today) | Blob is ARCSIG-signed by bootstrap key; kernel rejects unsigned/wrong-key blob before init runs |
| Attacker adds an entry to the manifest | N/A | Blob is signed as one unit; any edit invalidates the signature |
| Compromised init grants itself extra capabilities | N/A | Init's `SYS_SPAWN` install-list is validated against the manifest hash init registered; kernel rejects grants not in the manifest. Init cannot grant authority it cannot prove the bootstrap signer authorized. |
| Compromised init refuses to start a service | N/A | Same threat as any compromised user-space supervisor — service does not run. Detected by absence of readiness ping; does not affect other services. Not a kernel-TCB compromise. |
| Crashed policy service never restarts | Matches ADR-006 § Failure Modes: permissive fallback, no recovery | Init restarts per manifest policy; permissive window is bounded by restart delay |
| Manifest hash substitution at install time | N/A | `SYS_INSTALL_ENDPOINT_RESERVATIONS` validates the hash against the blob the kernel loaded, not a hash init claims — init cannot present a forged hash |

Key property: **the kernel TCB does not grow.** Init is in the boot-lifecycle TCB but not the kernel TCB. A compromised init cannot escalate into kernel privileges; its authority is bounded by what the signed manifest authorizes and by the two capabilities (`CreateProcess`, `InstallEndpointReservations`) the kernel granted it.

## Verification Stance

Kernel-side additions are small and fit the verification posture:

- The endpoint reservation table is a dense array with an O(1) indexed lookup. Reservation install is one-shot and idempotent-after-success.
- The `SYS_INSTALL_ENDPOINT_RESERVATIONS` path is a single bounded loop over the reservation list with a hash-equality check.
- `SYS_SPAWN`'s install-list validation is a bounded iteration over the requested grants cross-checked against the manifest-derived allowed set.
- Deleting `BootGate`, `BOOT_MODULE_ORDER`, and `SYS_MODULE_READY` removes more verification surface than the additions introduce.

Init itself is user-space and is **not** in the kernel verification target. Its correctness is enforced through:

- Signed ELF + build-time testing of the manifest parser on malformed inputs.
- Capability isolation: init only holds what the kernel granted it; its worst failure mode is refusing to supervise, not bypassing authorization.
- The ObjectStore audit trail (via ADR-007) records every spawn and restart decision.

This matches CLAUDE.md's verification posture: kernel code is verification-targeted, user-space code is reviewed and tested but not formally verified.

## Why Not Other Options

### Option A: Keep sequencing in the kernel, just replace the comment with a struct

**Why considered.** Smallest delta. The existing `BOOT_MODULE_ORDER` machinery already works.

**Why rejected.** Entrenches supervision in the kernel. Does nothing for post-boot crash recovery, endpoint reservation enforcement, or declarative service sets. Pushes every future evolution (backoff, DAG ordering, audit) into the kernel TCB. Explicitly violates the [ADR-006](006-policy-service.md) / [CambiOS.md](../CambiOS.md) layering commitment.

### Option B: CBOR or similar self-describing wire format for the manifest

**Why considered.** Standard, tool-friendly, flexible. Easy to extend.

**Why rejected.** Adds a no_std CBOR parser to the init TCB — extra dependency, extra verification surface, extra attack surface. The manifest has one producer (build time) and one consumer (init) — self-description buys nothing. A fixed-layout binary with a version field can evolve with explicit version bumps, which is what we want anyway.

### Option C: Kernel parses the manifest

**Why considered.** Removes the init "install reservations" syscall. Kernel has the blob already; could populate reservation table itself.

**Why rejected.** Puts parser logic in the kernel TCB. Every parser bug becomes a kernel CVE. The init process already exists as the right architectural place for this — putting the parser there costs one syscall and keeps the kernel's responsibility to "verify the signature, enforce the result of the parse."

### Option D: Multiple init processes (launchd-style agents)

**Why considered.** Matches modern macOS and systemd-user patterns. Per-user supervisors.

**Why rejected.** Out of scope for v1. CambiOS is a single-operator system today; multi-user / per-user supervision is a post-v1 concern and this ADR does not preclude adding user-level supervisors later as children of the system init.

### Option E: Embed the manifest in init's ELF as a `.rodata` section (chosen: no)

**Why considered.** One fewer boot module. Manifest signature is part of init's signature — one fewer verify call.

**Why rejected.** Conflates init with its configuration. An operator who wants to adjust the manifest (change reservations, add a service) would have to rebuild init. Separating the manifest keeps init minimal and keeps the manifest the only thing the operator touches for fleet configuration.

### Option F (chosen): Separate signed manifest blob, user-space init, shrunken kernel

**Why chosen.** Aligns with the layering [ADR-006](006-policy-service.md) established for policy. Shrinks the kernel. Composes with the existing signing infrastructure. Makes the core service set declarative. Gives ADR-006's and ADR-008's explicit "future init" references a concrete home. Does not close off the post-v1 migration to ObjectStore-hosted manifests.

## Migration Path

Sequenced to be landable in bounded commits with no regressions between them. The tri-arch regression gate applies at every step.

1. **Define the manifest wire format** as a Rust module (`arcos_core::manifest`) shared between kernel, init, and the build tooling. Pure data structures + parsing logic, no side effects. Unit tests on host for every structural error case.
2. **Add the bootstrap-side build tool** (`tools/build-manifest/`) that takes a TOML or Rust-defined source and emits a signed manifest blob. Sign with the same YubiKey path as `tools/sign-elf/`.
3. **Add the endpoint reservation table** to the kernel (`src/ipc/endpoint_reservation.rs`). Initially empty, initially no caller — just the data structure and its check in `SYS_REGISTER_ENDPOINT`. Behavior is unchanged (empty table ⇒ all endpoints unreserved).
4. **Add `SyscallNumber::InstallEndpointReservations`** (new variant, new handler). Gated by a new `InstallEndpointReservations` capability kind, no one holds it yet. No caller.
5. **Extend `SYS_SPAWN`** to accept a capability-install-list and a manifest-hash argument. Backward-compatible: current callers pass an empty list + the sentinel hash `[0; 32]`, which the kernel treats as "legacy spawn, no manifest cross-check." Behavior unchanged for existing code paths.
6. **Write the init process** (`user/init/`). Parser, DAG resolver, restart loop, audit emission. Standalone tests on host for the parser and DAG logic. Hard-coded manifest in this step for bring-up.
7. **Land the init-as-first-module change.** `limine.conf` gains `init.elf` and `manifest.bin`. Kernel verifies both, spawns init with the manifest pointer, grants init its two capabilities. Other boot modules still load through the existing path. Init starts, parses, but does nothing yet — coexistence with the old `BOOT_MODULE_ORDER` chain.
8. **Cut over service startup to init.** Remove service entries from the old boot chain. Init spawns them via `SYS_SPAWN`. Verify all existing integration tests pass. At this step, `BOOT_MODULE_ORDER` / `BootGate` / `SYS_MODULE_READY` are unused for new services but the machinery is still compiled in.
9. **Delete the scaffolding.** Remove `BOOT_MODULE_ORDER`, `BootModuleOrder`, `BlockReason::BootGate`, `SyscallNumber::ModuleReady`, `handle_module_ready`. Update CLAUDE.md, STATUS.md, and dependent tests. This is the irreversible commit.
10. **Wire restart policy.** Implement `ServiceLifetime::Persistent` backoff in init. Add integration test that kills a boot service and asserts init restarts it.
11. **Move `TableSizingPolicy` into the manifest.** Add a top-level manifest field, have the kernel pass it to ADR-008's sizing path, and demote the compile-time const to a fallback default. Fulfills ADR-008 § 7.
12. **Post-v1: migrate the manifest source.** When the persistent ObjectStore ([ADR-010](010-persistent-object-store-on-disk-format.md)) is the trusted source for system configuration, the manifest moves there. The parser stays. The loader path (boot module → ObjectStore lookup) is the only change.

Steps 1–7 establish the slot without behavior change. Step 8 is the first behavior change. Step 9 is the irreversible architectural shift. Steps 10–12 add functionality on top.

## Cross-References

- **[ADR-000](000-zta-and-cap.md)** — Capabilities; the endpoint reservation check is a new capability-style structural authority check
- **[ADR-003](003-content-addressed-storage-and-identity.md)** — Principals; manifest entries bind module → Principal identity
- **[ADR-004](004-cryptographic-integrity.md)** — ARCSIG signing format; manifest reuses it
- **[ADR-006](006-policy-service.md)** — Policy service; explicitly defers endpoint-registry and restart-authority to this ADR; init holds the bootstrap restart authority until policy-service is up, thereafter cooperates with policy for grant decisions
- **[ADR-008](008-boot-time-sized-object-tables.md)** — `TableSizingPolicy`; this ADR's manifest is the vehicle for ADR-008 § 7's promised migration
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Audit channel; init emits `ServiceLifecycle` and `ServiceDead` events
- **[ADR-002](002-three-layer-enforcement-pipeline.md)** — Enforcement pipeline; `SYS_REGISTER_ENDPOINT` gains one check, same pattern as other kernel-side mechanical checks
- **[ADR-012](012-input-architecture-and-device-classes.md)** / **[ADR-014](014-compositor-scanout-driver-protocol.md)** — Input-hub and compositor/scanout-driver both need reserved endpoints; this ADR is the mechanism they plug into

## See Also in CLAUDE.md

Updates required when the implementation lands:

- **§ "Quick Reference"** — add `make manifest` / `tools/build-manifest` build command
- **§ "Syscall Numbers"** — note `InstallEndpointReservations` addition and `ModuleReady` removal
- **§ "Required Reading by Subsystem"** — add a row for "init / service lifecycle / manifest"
- **§ "Platform Gotchas"** — note that the manifest blob is a required boot module; missing manifest = kernel refuses to spawn init
- **§ "Deep Reference" / directory layout** — add `user/init/` and `tools/build-manifest/`
