# ADR-008: Boot-Time-Sized Kernel Object Tables

- **Status:** Proposed
- **Date:** 2026-04-11
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-009](009-purpose-tiers-scope.md) (Purpose, Deployment Tiers, and Scope Boundaries)
- **Related:** [ADR-001](001-smp-scheduling-and-lock-hierarchy.md) (Lock hierarchy), [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives — channels are downstream consumers of this decision), [ADR-007](007-capability-revocation-and-telemetry.md) (revocation primitive wired in Wave 1)
- **Supersedes:** N/A

## Context

ArcOS's kernel today stores per-process state — the process descriptor table and the capability table — in fixed-size dense arrays sized by a compile-time constant. The constant was `MAX_PROCESSES = 32` until Wave 1 of Phase 3 (capability revocation) landed, at which point the conversation about raising it surfaced that "pick a bigger constant" does not address the real problem. The real problem is that *any* compile-time constant has structural failure modes at the two ends of the project's target hardware range (embedded at one end, future high-memory workstations at the other) and in the sawtooth between phases. This ADR documents the allocation model ArcOS adopts to resolve that.

This ADR is written after [ADR-009](009-purpose-tiers-scope.md), which commits the project to three deployment tiers and a broad but bounded hardware range. ADR-009 establishes the hardware precondition; this ADR designs the mechanism that serves it.

## Problem

ArcOS's kernel currently stores per-process state in fixed-size dense arrays sized by the compile-time constant `MAX_PROCESSES = 32`. This includes the process descriptor table in [src/process.rs](../../src/process.rs) and the capability table in [src/ipc/capability.rs](../../src/ipc/capability.rs). Every slot is preallocated at boot, regardless of whether it is used. Lookups are O(1) array indexing. Verification invariants reason about the array as a statically-bounded structure.

This was the right design when the kernel ran three processes in total. It is the wrong design for a general-purpose operating system that targets modern hardware and expects to run user workloads beyond a handful of core services. Four problems have accumulated, and together they motivate this ADR.

**Problem 1 — the bound is too small for general-purpose workloads.**

The value of 32 is a scaffolding artifact from the kernel's earliest days. Today the project runs 7 boot modules plus idle, and the v1 roadmap adds at least another dozen core-service processes (policy service, audit watcher, init, DHCP client, DNS resolver, TCP stack, virtio-blk driver, persistent ObjectStore, ArcObject CLI, Yggdrasil peer service, and the tier-dependent AI services described in [ADR-009](009-purpose-tiers-scope.md)). Beyond core services, general-purpose use involves spawned user programs — shells, editors, build systems, browser helper processes, PE-compatibility sandboxes. Any realistic Tier 3 session hits 32 before the user has opened their second application.

[ADR-009](009-purpose-tiers-scope.md) commits the project to being a first-class general-purpose operating system across three deployment tiers. A cap of 32 is incompatible with that commitment at every tier.

**Problem 2 — sawtoothing across phases.**

Even if the value were larger, the compile-time-constant design creates a predictable failure mode: the bound gets chosen to cover "today's workload plus a buffer," then gets blown through at the next phase boundary, triggering disruptive refactors exactly when the project is busiest with other work. This pattern has a name: the sawtooth. Each phase spawns a new subsystem, the new subsystem brings new processes, the bound gets crossed, and the fix becomes emergency work.

We have already seen this pattern start. Wave 1 (capability revocation) raised the question of whether `MAX_PROCESSES = 32` was still adequate — it was not, and the conversation that followed surfaced that "pick the next bigger number" would just defer the same conversation to Wave 3 or 4. The project needs an allocation model that does not require hand-picking bounds at each phase boundary.

**Problem 3 — ambient authority in process creation.**

The current kernel allows any kernel code path that reaches the process table to create a new process. The restriction to "bootstrap Principal + boot modules" is enforced by convention — by the fact that only the boot path currently calls `create_process` — not by structure. Adding a new caller would be straightforward. A bug that caused an unexpected caller to invoke `create_process` would succeed.

This conflicts with the zero-trust stance documented in [ADR-000](000-zta-and-cap.md), which requires "no ambient authority" — authority should be structural, held as explicit capabilities, not derived from reachability. The capability table system is the mechanism for structural authority throughout the rest of the kernel; process creation is an exception that has drifted into an ambient-authority design.

A fix for this problem does not strictly require changing the allocation model — capability-gated process creation is independent of whether processes come from a dense array, a heap, or an object pool. But it is a natural companion to any allocation model change, because the right place to check "does the caller hold the `create_process` capability" is at the same site where the allocation happens. Bundling the fix with the allocation change costs almost nothing and closes a zero-trust gap that otherwise would need its own commit later.

**Problem 4 — compile-time sizing does not survive a wide hardware range.**

[ADR-009](009-purpose-tiers-scope.md) commits ArcOS to three deployment tiers spanning approximately three orders of magnitude of hardware: from a 256 MB embedded board at the Tier 1 minimum through 8 GB desktops and laptops at the Tier 3 floor to future workstations with hundreds of gigabytes or terabytes of RAM. A single compile-time `MAX_PROCESSES` constant cannot serve this range. A number that is comfortable on a 16 GB desktop is absurdly small on a future 1 TB workstation. A number sized for the future is catastrophic on a 512 MB embedded board.

[ADR-009](009-purpose-tiers-scope.md) also commits the project to "Platform Is an Implementation Detail" and to a single kernel binary running across each tier's hardware range. A compile-time constant breaks that commitment as soon as the hardware range is wide. The project can either accept multiple kernel builds for different hardware classes (rejected by the single-binary principle), pick a single number and accept that it is wrong for both extremes (rejected by the general-purpose commitment), or find an allocation model that adapts to hardware at boot time.

**Why these problems must be solved together.**

Any one of the four could be addressed in isolation. Problem 1 could be fixed by picking a bigger constant. Problem 2 could be fixed by writing an escape-hatch ADR describing future evolution. Problem 3 could be fixed by adding capability-gated creation in a focused commit. Problem 4 could be fixed by a boot-time-sized table.

Addressing them separately would result in four commits, each introducing churn in the same subsystems (process table, capability table, boot sequence, verification target), each requiring its own test and review pass, and each deferring the inevitable conversation about what the allocation model should actually be. This ADR proposes that they are cheaper to solve together because the solutions reinforce each other: boot-time sizing solves Problems 1 and 4, capability-gated creation solves Problem 3, and the combination renders the sawtooth of Problem 2 largely moot — the bound is adaptive to hardware, so phase boundaries do not cross it unless the hardware itself is insufficient, and if the hardware is insufficient the fix is "the deployment is below the tier floor," not "refactor the kernel."

The scope of the change is small enough to fit in a bounded set of commits and large enough that a design document is warranted.

## The Reframe

The architectural insight that resolves the four problems is:

> **Kernel object capacity should be a function of available memory, not a compile-time decision.**

A compile-time constant forces the kernel to decide, before it knows what hardware it will run on, how much state it can ever manage. That decision is structurally wrong: the kernel does know how much hardware it has — it learns it at boot, from the bootloader's memory map — and the right time to size the tables is then.

The reframe does not change what the tables *are*. They remain dense arrays. They remain preallocated. Lookups remain O(1). The verification invariants remain invariants over a fixed-size structure. The only thing that changes is *when* the size is fixed: at boot, once, from a policy declared at the tier boundary, rather than at kernel compile time.

This is a smaller change than it sounds like. A runtime constant that is set once during init and never modified thereafter is, for every practical purpose that matters to the kernel and to a verifier, the same as a compile-time constant. Loops over the table still have a static bound within any given boot of the kernel. The dense-array verification story is preserved. What is gained is adaptivity: the same kernel binary produces a small table on a small machine and a large table on a large machine, with no code paths that differ between them.

Paired with structural capability-gated process creation — where creating a process requires holding a `create_process` capability, not just being code that can reach the process table — the reframe also closes the ambient-authority gap. The two changes are natural companions and land together.

## Decision

ArcOS adopts a **boot-time-sized dense array** allocation model for per-process kernel object tables, paired with **structural capability-gated process creation**. Specifically:

**1. The kernel takes its table sizing policy as an explicit input, not as a hidden formula.** A `TableSizingPolicy` struct declares the sizing decision in configuration that can be read, verified, and adjusted independently of kernel source. The kernel's role is to *apply* the policy to the actual hardware at boot; it does not decide the policy.

**2. The policy has three fields:**

```rust
pub struct TableSizingPolicy {
    /// Minimum number of slots, regardless of available memory.
    /// Enforced floor for the smallest supported hardware.
    pub min_slots: u32,

    /// Maximum number of slots, regardless of available memory.
    /// Enforced ceiling so the table cannot grow beyond what the
    /// tier is willing to preallocate.
    pub max_slots: u32,

    /// The scaling parameter: one slot is allocated for every
    /// `ram_per_slot` bytes of available RAM, subject to the
    /// min/max clamps above. A larger value gives fewer slots
    /// per gigabyte (conservative); a smaller value gives more
    /// slots per gigabyte (generous).
    pub ram_per_slot: u64,
}
```

**3. The computation applied at boot is:**

```rust
let scaled = (available_memory_bytes / policy.ram_per_slot) as u32;
let num_slots = scaled.clamp(policy.min_slots, policy.max_slots);
```

This is the entire sizing logic. There is no magic constant, no hidden derivation. The three policy fields are the only tuning knobs; the computation is a single clamp operation that a verifier can treat as a simple arithmetic transformation of policy inputs.

**4. The policy is declared at the tier boundary, not in the kernel's core logic.** Per [ADR-009](009-purpose-tiers-scope.md), the tier is an install-time choice — it determines which build of ArcOS is shipped and which user-space services are loaded. The tier also carries the table sizing policy as part of its build-time configuration. Each tier ships with a default policy that reflects the expected workload density for that tier:

- **Tier 1 — ArcOS-Embedded.** Conservative policy. Example: `{ min_slots: 32, max_slots: 256, ram_per_slot: 4 MiB }`. On a 256 MB embedded board this produces 64 slots; on a 1 GB system it produces 256 slots (capped by max).
- **Tier 2 — ArcOS-Standard (no AI).** Moderate policy. Example: `{ min_slots: 128, max_slots: 4096, ram_per_slot: 2 MiB }`. On a 2 GB system this produces 1024 slots; on a 16 GB system it produces 4096 slots (capped by max).
- **Tier 3 — ArcOS-Full.** Generous policy. Example: `{ min_slots: 256, max_slots: 65536, ram_per_slot: 1 MiB }`. On an 8 GB system this produces 8192 slots; on a 32 GB system it produces 32768 slots; on a 128 GB workstation it produces 65536 slots (capped by max).

These values are starting points, not final commitments. They are documented in [ASSUMPTIONS.md](../../ASSUMPTIONS.md) and can be tuned when real workload data exists. The kernel binary is identical across tiers per ADR-009's "same kernel binary across tiers" commitment. What differs between tiers is the `TableSizingPolicy` value the kernel's init path reads from the tier's build-time configuration.

**5. The policy is visible and adjustable at build time today, with a documented migration to boot-time configuration when a manifest mechanism exists.** Because the policy is three explicit numbers rather than a hidden formula, an operator deploying ArcOS to unusual hardware can adjust the policy at build time without touching kernel source beyond the tier configuration file. The policy for each tier lives in a dedicated kernel configuration module (`src/config/tier.rs` in Wave 2a's implementation). Three Cargo features — `tier1`, `tier2`, `tier3` — select which tier's policy is compiled in; exactly one is set per kernel build. An operator who wants a custom policy adds a `tier_custom` feature with their own policy values and rebuilds.

Build-time configuration is the right mechanism for Wave 2 because ArcOS does not yet have a boot-manifest infrastructure — the kernel does not read any runtime-loaded configuration today. Introducing boot-manifest support just for table sizing would be a larger scope change than this ADR needs. The long-term direction, however, is clear: **when ArcOS grows a boot-manifest mechanism (anticipated post-v1, alongside the init process and service configuration work), the table sizing policy moves from compile-time configuration to the manifest.** The compile-time const becomes a fallback default for the case where no manifest is present, and an operator who wants a different policy adjusts the manifest rather than rebuilding the kernel. This ADR does not design the manifest itself, but it commits that the table sizing policy will be among the first things to move into it, because the policy is already structured to make that migration clean: the struct, the fields, and the clamp computation are the same on either side of the move — only the *source* of the policy values changes.

**6. At the kernel level, the policy is an axiom.** The kernel does not decide the policy; it receives the policy from the tier configuration and applies it. From the verifier's perspective, `num_slots` is an input parameter constrained by the policy's min and max fields, not a value derived from a formula with magic constants. This is a stronger verification target than a hidden formula: the verifier proves properties of the table given `num_slots`, and the policy's constraints on `num_slots` (`min_slots ≤ num_slots ≤ max_slots`) are checked at init time and then treated as invariants.

**7. Process creation requires a `create_process` capability.** A new capability kind is introduced that grants the holder the right to invoke the kernel's process-creation path. The bootstrap Principal holds this capability implicitly at boot (see the Migration Path section). As the policy service ([ADR-006](006-policy-service.md)) comes online, policy decides who else holds it. Without this capability, a caller cannot create a process — the check is structural, at the allocation site, and cannot be bypassed by code that happens to reach the process table.

The combination is intentionally minimal. The kernel's allocation machinery, verification posture, and IPC primitives are untouched. Only the sizing mechanism changes, and the sizing policy is expressed as explicit configuration rather than hidden in kernel source.

## Architecture

### Boot-time sizing, in detail

The sizing computation runs during kernel initialization, after the frame allocator has been set up (so that `available_memory_bytes` is known) and before any user-space process is created (so that the tables exist when they are first used). The sequence:

1. Frame allocator initialized, `available_memory_bytes` is the sum of usable regions from the bootloader memory map.
2. The tier's `TableSizingPolicy` is read from the compile-time configuration (`src/config/tier.rs`).
3. `num_slots = clamp(available_memory_bytes / policy.ram_per_slot, policy.min_slots, policy.max_slots)`.
4. Process table allocated: `Vec<Option<ProcessDescriptor>>` with capacity `num_slots`, initialized to `None` for every slot.
5. Capability table allocated: `Vec<Option<ProcessCapabilities>>` with capacity `num_slots`, initialized to `None` for every slot.
6. `num_slots` stored in a kernel-global read-only location (set once, read many).
7. Init continues, process 0 (idle) is created, boot modules are loaded as processes, etc.

After step 6, `num_slots` is effectively a compile-time constant from the perspective of every code path that reads it. The kernel does not check whether `num_slots` has changed because it cannot change.

### Lookup, iteration, and bounds

All process lookups and iterations reference `num_slots` as the upper bound instead of the previous compile-time `MAX_PROCESSES`. The translation is mechanical:

```rust
// Before
for i in 0..MAX_PROCESSES {
    if let Some(proc) = &process_table[i] { /* ... */ }
}

// After
for i in 0..num_slots() {
    if let Some(proc) = &process_table[i] { /* ... */ }
}
```

The function `num_slots()` is a simple accessor reading the kernel-global value. It is inlined by the compiler in practice, and the loop bound is a loop-invariant value that the compiler can hoist and reason about for optimization. For the purposes of iteration-cost reasoning, this is equivalent to the current compile-time bound.

The `ProcessId` type remains `u32`, as it is today. The `num_slots` value acts as a runtime bound on the valid range of `ProcessId` values; creating a process with `ProcessId >= num_slots` is a bounds violation caught at the creation site.

### Capability-gated process creation

A new capability kind is added to the capability type enum:

```rust
pub enum CapabilityKind {
    Endpoint { endpoint: EndpointId, rights: CapabilityRights }, // existing
    CreateProcess, // NEW — authority to create new processes
    // (future) Channel, etc.
}
```

A process holding `CapabilityKind::CreateProcess` may invoke the process-creation syscall (or the kernel-internal creation path). A process not holding it receives `CapabilityError::AccessDenied` at the authority check.

The check happens in the process-creation primitive itself — not at the syscall boundary, and not scattered across call sites. Every path that creates a process, including the boot path, the shell-spawned program path, and any future spawn-from-service path, passes through a single `ProcessTable::create_process(creator_principal, ...)` function that performs the capability check before allocating a slot. Call sites that cannot present a valid creator principal cannot create processes.

At boot, the kernel itself creates process 0 (idle) and the initial boot module processes *before* any capability tables exist in a usable state. This is a bootstrapping exception — the kernel holds implicit authority during boot because there is no other authority source yet. The exception is narrow: it applies only to the boot sequence, ends when the bootstrap Principal is bound and the `create_process` capability is granted to it, and is documented in the boot sequence.

After boot, the bootstrap Principal holds `CapabilityKind::CreateProcess`. It delegates to the init process when init exists. Init (per [ADR-009](009-purpose-tiers-scope.md)'s tier-dependent boot manifest) decides which subsequent services receive the capability and at what scope. The policy service ([ADR-006](006-policy-service.md)) eventually mediates delegations and revocations of `create_process` as a first-class policy question.

### Interaction with the capability table

The capability table is sized to the same `num_slots` as the process table, and is indexed the same way. A `ProcessCapabilities` slot exists for every process slot. This is intentional — keeping the two tables co-indexed means a `ProcessId` is a valid index into both, and the existing verification invariants about per-process capability state remain invariants after this change.

Wave 1's `revoke_all_for_process` (from [ADR-007](007-capability-revocation-and-telemetry.md)) already handles tearing down the capability table entries on process exit. This ADR does not change that path. The capability table rows are cleared when the process exits; the row itself remains allocated in memory because the underlying `Vec<Option<ProcessCapabilities>>` is sized for the kernel's lifetime.

### Slots per tier on representative hardware

Before reading the table below, note the layering: the tier is an install-time choice — the user installs Tier 1, Tier 2, or Tier 3 by choosing which build image to deploy — and the tier's build-time configuration sets the `TableSizingPolicy` in the resulting kernel image. The user never sees the policy; the tier choice is what they see. Every boot of a given tier's kernel applies that tier's compiled-in policy to whatever hardware is actually present. The table below shows what each tier's default policy produces on representative hardware configurations. The numbers are derived from the example policies in the Decision section.

| Tier | Hardware | Policy inputs | `num_slots` |
|------|----------|---------------|-------------|
| Tier 1 | 256 MB (minimum) | `ram_per_slot=4 MiB, min=32, max=256` | 64 |
| Tier 1 | 512 MB | `ram_per_slot=4 MiB, min=32, max=256` | 128 |
| Tier 1 | 1 GB (typical ceiling) | `ram_per_slot=4 MiB, min=32, max=256` | 256 (max) |
| Tier 2 | 1 GB (minimum) | `ram_per_slot=2 MiB, min=128, max=4096` | 512 |
| Tier 2 | 4 GB | `ram_per_slot=2 MiB, min=128, max=4096` | 2048 |
| Tier 2 | 16 GB (typical ceiling) | `ram_per_slot=2 MiB, min=128, max=4096` | 4096 (max) |
| Tier 3 | 8 GB (minimum) | `ram_per_slot=1 MiB, min=256, max=65536` | 8192 |
| Tier 3 | 32 GB | `ram_per_slot=1 MiB, min=256, max=65536` | 32768 |
| Tier 3 | 128 GB | `ram_per_slot=1 MiB, min=256, max=65536` | 65536 (max) |
| Tier 3 | 1 TB (future) | `ram_per_slot=1 MiB, min=256, max=65536` | 65536 (max) |

At every tier, the number of slots comfortably exceeds realistic workload needs. The Tier 3 cap of 65536 is reached at 128 GB and stays there on larger hardware — this is a deliberate upper bound, not a failure mode, and an operator running a workload that needs more than 65536 processes can raise `max_slots` in the tier configuration and rebuild. The same kernel binary handles every row in the table without a code path distinction. The memory cost of the preallocated tables scales with `num_slots × bytes_per_slot`, where `bytes_per_slot` is determined by the current kernel's per-process footprint; on current kernel state this is in the low tens of KB, giving table footprints from under 1 MB at the Tier 1 minimum to ~1 GB at the Tier 3 max — always a modest fraction of available RAM.

### Lock ordering

The boot-time sizing changes happen during kernel initialization, before the lock hierarchy is in force. No new locks are introduced by this ADR. The existing `CAPABILITY_MANAGER(4)` and `PROCESS_TABLE(5)` locks protect the same data structures, just at a potentially larger size. The `create_process` authority check happens under `CAPABILITY_MANAGER(4)`, which is already acquired during existing capability checks. No lock-ordering implications.

## General-Purpose Viability

This section addresses the question that shaped the choice between the options considered in the Why Not Other Options section: *does this approach survive general-purpose workloads across the full tier range, or does it have hidden failure modes?*

The short answer is yes, because the chosen approach is structurally conservative. It does not introduce any mechanism that is new to operating systems at scale (dense arrays with runtime-sized capacity are standard), does not depend on solving any open research problems (defragmentation, Retype budget management), and does not require hardware support beyond what ArcOS already assumes.

### Scaling properties

- **Upper bound.** The upper bound on `num_slots` is `policy.max_slots`. Under the default Tier 3 policy, this is 65536 slots — comfortably more than any realistic general-purpose workload. Under custom policies, the operator chooses. The ceiling is visible in the tier configuration, not hidden in a formula, which makes it easy to reason about and easy to raise when a workload demands it.
- **Lower bound.** `policy.min_slots` guarantees the approach is usable even at the hardware floor of each tier. Under the default policies, Tier 1 guarantees at least 32 slots, Tier 2 at least 128, Tier 3 at least 256. These values accommodate the minimal core service set of each tier plus meaningful workload headroom.
- **Middle.** At every point between these extremes, `num_slots` scales linearly with available memory via `ram_per_slot`. Memory cost grows proportionally with `num_slots` and remains a modest fraction of RAM across the full range.

### Workload stress cases

Three workload patterns matter for general-purpose viability. Each is handled cleanly by the chosen approach:

**A desktop session with many running programs.** A user running ArcOS as their daily driver might have shell, editor, browser, messaging client, file manager, and several helper processes — perhaps 30-50 processes total. On Tier 3 at 8 GB, `num_slots` is 8192. The session consumes well under 1% of the slots. Comfortable.

**A build system spawning many short-lived processes.** A compilation invoking a build tool that spawns parallel worker processes (compiler, linker, assembler, etc) might have 200-500 concurrent processes at peak. On Tier 3 at 8 GB, this consumes 2-6% of the slots. Well within capacity. On Tier 3 at 32 GB, it's under 2%.

**A long-running server with accumulating zombies.** Without aggressive reaping, terminated processes hold slots until they are reused. A long-running system could, over time, fill the slot space with zombies. This is the scenario most likely to stress the approach, and it is addressed in the Open Problems section below — zombie reaping is a separate concern that this ADR does not solve but also does not make worse.

### Graceful degradation across tiers

Per [ADR-009](009-purpose-tiers-scope.md)'s "Graceful degradation across tiers" principle, the chosen approach degrades cleanly from Tier 3 to Tier 1:

- On Tier 3, the policy is generous, the table is large, and every feature has room.
- On Tier 2, the policy is moderate, the table is smaller, and fewer services run (because no AI tier components), so the ratio of used slots to available slots is similar to Tier 3.
- On Tier 1, the policy is conservative, the table is small, but only minimal services run, and the ratio is still reasonable.

The same formula produces appropriate sizing at each tier because each tier declares its own policy. A single kernel binary works across the hardware range because the sizing adapts to the hardware, and each tier carries a policy tuned to its expected workload density.

### What is not solved

The chosen approach does not solve the "what if a workload wants more than the current policy's max_slots" question. If a user tries to run a build system that needs 10,000 concurrent processes on a Tier 3 kernel whose `max_slots` is 65536, it works fine — but if they somehow need 100,000 concurrent processes, they either raise `max_slots` in a custom tier configuration and rebuild, or they accept that the operation fails at 65536. This is not a new failure mode — every operating system has a process count ceiling. The chosen approach makes the ceiling explicit (it is in the tier configuration, not hidden) and adjustable (changing it is a one-line edit plus a rebuild).

## Verification Stance

ArcOS's verification posture, documented in [CLAUDE.md](../../CLAUDE.md) under "Formal Verification (Non-Negotiable Constraint)," has several requirements that any kernel change must respect:

- Bounded iteration (no unbounded loops in kernel paths)
- Invariants encoded in types where possible
- State machines over exhaustive enums
- Pure logic separated from effects
- Minimal `unsafe`

The boot-time-sized dense array preserves all of these:

**Bounded iteration is preserved.** Loops over the process table iterate `0..num_slots()`, where `num_slots` is a runtime constant set once at init. From the perspective of any loop that runs after init (which is all of them), the bound is fixed. A verifier that can reason about "this value is set once during init and never changes" — which is essentially every verifier — treats `num_slots` the same as a compile-time constant for the purposes of loop-bound reasoning. The claim "no unbounded loops" remains literally true: every loop has a static bound, the bound is just read from a global rather than inlined from a constant.

**Invariants encoded in types remain encoded.** The process table is still `Vec<Option<ProcessDescriptor>>`. The `ProcessId` newtype remains distinct from `u32`. The `ProcessCapabilities` slot structure is unchanged. The capability kind enum gains a new variant (`CreateProcess`), which is a trivially-verified extension of the existing exhaustive match.

**State machines are preserved.** The `TaskState` enum, the `CapabilityKind` enum, and every other state enum in the kernel are unchanged except for the addition of `CapabilityKind::CreateProcess`.

**Pure logic separated from effects.** The boot-time sizing computation is pure — a `clamp` over an arithmetic expression — testable in isolation, and has no hardware dependencies once `available_memory_bytes` is known. The allocation effect (calling `Vec::with_capacity`) happens once, at init, and is isolated from the computation.

**Minimal unsafe.** The chosen approach adds no new unsafe blocks. It uses Rust's `Vec` with a capacity hint, which is safe by construction. Every existing unsafe block in the kernel remains unchanged.

**The verification target that actually changes** is the one invariant that used to read "the process table has exactly `MAX_PROCESSES` slots" and now reads "the process table has exactly `num_slots` slots, where `num_slots` is constrained by the `TableSizingPolicy` applied at init to satisfy `policy.min_slots ≤ num_slots ≤ policy.max_slots` and has not changed since." This is *more specific* than a compile-time constant, not less. A verifier reasoning about post-init kernel state treats the `TableSizingPolicy` fields as axioms (inputs to the kernel from the tier configuration), treats the clamp computation as a simple arithmetic fact, and proves properties of the table parameterized by `num_slots`. This is a simpler proof target than reasoning about a hidden formula, because there is no formula to reason about — there is a struct and a clamp.

**What about adversarial `num_slots`?** A natural question is whether an attacker could influence `num_slots` by manipulating the bootloader memory map. The answer: the bootloader memory map is trusted input (at ArcOS's trust boundary for the hardware), and if it is compromised, every other kernel invariant that depends on it is also compromised. This is not a new attack surface introduced by this ADR — the frame allocator already trusts the memory map, and the scheduler's per-CPU state already trusts the CPU count derived from ACPI. The `num_slots` computation is one more place that trusts the memory map, using the same trust model the rest of the boot sequence already uses. Additionally, the `max_slots` clamp provides a hard upper bound that does not depend on memory map input at all — an attacker who reported absurdly large memory would still see `num_slots` capped at `policy.max_slots`.

## Threat Model Impact

The chosen approach has two effects on the threat model: it closes the ambient-authority gap in process creation, and it does not open any new attack surfaces.

### Ambient authority closed

The current kernel's process creation is gated by convention — only the boot path calls it, and the project trusts itself not to add other callers without thought. This is a fragile guarantee. A code refactor, a forgotten security review, or a well-intentioned feature could add a new call site, and the check "is this caller authorized to create processes" would simply not happen because it is not represented anywhere.

The chosen approach makes the check structural. Every process-creation path passes through `ProcessTable::create_process(creator_principal, ...)`, which verifies the `CreateProcess` capability before allocating a slot. A caller without the capability cannot create a process, period. The check is at the allocation site, not at call sites, so new call sites inherit the check automatically without having to remember to add it.

This closes a gap in the zero-trust story from [ADR-000](000-zta-and-cap.md). Before this change, "no ambient authority" was true for every kernel operation *except* process creation. After this change, it is true for process creation as well.

### No new attack surfaces

The boot-time sizing itself is not an attack surface. `num_slots` is computed from the bootloader memory map and the tier policy, both of which are already trusted inputs to the kernel's boot sequence (see Verification Stance). An attacker with the ability to manipulate the memory map can already affect many parts of the kernel; `num_slots` is not a new capability for such an attacker, and the `max_slots` clamp prevents even a memory-map-compromising attacker from forcing an unbounded allocation.

The capability-gated `create_process` adds an authority check at a point that previously had none. This is a strict improvement in the threat model — the surface is smaller, not larger.

The capability table still serves the same role it did before, with one additional capability kind. Existing capability checks continue to work without modification. Existing capability-related threats (forgery, delegation abuse, grant escalation) are unchanged.

### What this does not protect against

- **Compromise of the bootstrap Principal.** If an attacker holds the bootstrap Principal's key, they can grant themselves `CreateProcess` and any other capability. This is the same trust assumption the rest of the kernel makes about the bootstrap Principal; this ADR does not change it.
- **Memory exhaustion attacks.** A caller holding `CreateProcess` can create processes until `num_slots` is exhausted. This is a resource exhaustion attack, not an authority bypass. The mitigation is in policy — the policy service ([ADR-006](006-policy-service.md)) can revoke `CreateProcess` from misbehaving callers — and in graceful failure — once the table is full, new creations return a well-defined error rather than crashing. The kernel is protected; the workload may not be.
- **Kernel compromise.** If the kernel is compromised, every invariant this ADR depends on is compromised, including `num_slots`. This is the same trust boundary the rest of the kernel has; this ADR does not change it.

## Migration Path

The migration from the current dense-array-with-`MAX_PROCESSES` design to the boot-time-sized approach lands as a set of contained changes during Wave 2 of Phase 3. The order is chosen so that each step is individually landable and individually testable.

**Wave 2a.0 — Prep commit (methodology and documentation).** Ready to commit alongside this ADR. Contains:
- The Post-Change Review Protocol amendment for flagging pre-existing warnings.
- The Development Convention 8 refinement for bounds sizing with end-in-mind.
- New rows in [ASSUMPTIONS.md](../../ASSUMPTIONS.md) for the tier policies and `TableSizingPolicy` fields, each pointing at this ADR for rationale.
- CLAUDE.md updates: documentation cross-references to this ADR and [ADR-009](009-purpose-tiers-scope.md).

**Wave 2a — `MAX_PROCESSES` becomes runtime; table allocation moves to boot init.** Changes:
- `MAX_PROCESSES` removed as a compile-time constant.
- `TableSizingPolicy` struct added to a new `src/config/tier.rs` module.
- `tier1`, `tier2`, `tier3` Cargo features added; exactly one must be set per build.
- `num_slots` added as a runtime constant, computed during kernel init from the compiled-in policy and available memory.
- `ProcessTable` and `ProcessCapabilities` storage converted from fixed-size arrays to `Vec<Option<...>>` with `num_slots` capacity at init.
- Every `for i in 0..MAX_PROCESSES` loop updated to `for i in 0..num_slots()`.
- Every bounds check of `ProcessId` updated to use `num_slots()`.
- Tests for sizing computation on synthetic memory sizes (256 MB, 8 GB, 1 TB) with each tier policy.
- QEMU smoke test on both architectures confirms the kernel boots at the same RAM configurations as before.
- Runtime check: kernel logs the chosen `num_slots` at boot so it is visible in dmesg-equivalent output during development.

**Wave 2b — `CreateProcess` capability introduced; authority check added at creation site.** Changes:
- `CapabilityKind::CreateProcess` added to the capability kind enum.
- `ProcessTable::create_process` gains a `creator_principal` parameter and performs the authority check.
- Boot sequence grants `CreateProcess` to the bootstrap Principal after Principal binding is complete.
- All existing call sites updated to pass the creator Principal.
- Unit tests for authority check (authorized creator, unauthorized creator, bootstrap exception during boot).
- Integration test: attempt to create a process without holding `CreateProcess` and verify `AccessDenied` is returned.

**Wave 2c — Wave 1's `CapabilityHandle` refactor.** The Wave 1 TODO noted that Wave 2 would refactor `SYS_REVOKE_CAPABILITY` from `(target_pid, endpoint_id)` arguments to a single `CapabilityHandle`. That refactor happens here because the capability table is now sized differently and the refactor is cheapest when it lands alongside the table changes. This is mechanical — the `CapabilityHandle` is already a u64, the refactor is at the syscall boundary and in the revoke logic, and tests from Wave 1 are updated accordingly.

**Wave 2d — Channel manager lands on the new foundation.** Channels (per [ADR-005](005-ipc-primitives-control-and-bulk.md)) can now be built assuming the boot-time-sized process/capability tables. The channel manager inherits the same allocation pattern: `num_channel_slots` computed at boot using its own `TableSizingPolicy` instance, channels are dense-array allocated, and the channel manager reserves its own lock position in the hierarchy. Channels are not directly affected by this ADR except that they are built on top of it — so migration of the IPC bulk path happens here as a consumer of the new table sizing.

The order is **2a.0 → 2a → 2b → 2c → 2d**. Each step is a separate commit with its own tests and verification. Steps 2a and 2b are the load-bearing parts of this ADR's implementation; 2c and 2d are follow-on work enabled by them.

A rollback plan exists for each step: each commit can be reverted without affecting the others, because each is a contained change with its own test coverage. If, during 2a implementation, the runtime-sized table reveals a verification-tool problem that blocks progress (see Open Problem 3), we can revert 2a and reconsider. If, during 2b, the authority check introduces a boot-sequence circular dependency that is hard to resolve, we can revert 2b and reconsider. The chosen approach is deliberately minimal so that rollback is cheap.

## Why Not Other Options

Several alternatives were considered before settling on the chosen approach. Each is named here with the specific reasons it was not chosen, so future contributors do not re-litigate decisions without new information.

**Alternative 1: Keep the current small dense array (MAX_PROCESSES = 32).**

*Why considered.* Zero code change. Already verified. Well-understood.

*Why rejected.* Cannot support general-purpose workloads, which is a first-class project goal per [ADR-009](009-purpose-tiers-scope.md). Cannot survive the v1 process count (core services plus shell plus a few spawned children). Sawtooths at phase boundaries. The value of 32 is a scaffolding artifact from the kernel's earliest days, not a deliberate design point.

**Alternative 2: Expanded dense array with compile-time MAX_PROCESSES (e.g., 4096 or 8192).**

*Why considered.* Simple, low-risk, preserves current verification properties.

*Why rejected.* Does not scale across hardware. A compile-time constant has to pick one number for every target machine. 4096 is too few for a datacenter node, too many for a 512 MB embedded board. This forces either multiple kernel builds (violating the single-binary goal in [ADR-009](009-purpose-tiers-scope.md)) or an unsatisfying compromise on one hardware class. The boot-time sizing in the chosen approach preserves everything this option gives us while scaling naturally.

**Alternative 3: Very large compile-time dense array sized to future hardware (MAX_PROCESSES = 65536+).**

*Why considered.* "Effectively unbounded" for any realistic current workload.

*Why rejected.* Preallocated memory cost is significant on small hardware — 30-80 MB permanently consumed from the kernel heap at the larger values. On embedded ARM boards with 512 MB RAM, that is 6-15% of RAM before the OS does anything. Violates platform-agnostic aspirations. The chosen approach reaches the same ceiling on hardware that can afford it without penalizing hardware that cannot.

**Alternative 4: Tiered allocation — fixed system table plus growable user region.**

*Why considered.* Strong verification for system services combined with scalable user-process capacity.

*Why deferred, not rejected.* This remains a viable candidate for a future architectural evolution if the chosen approach's ceiling ever becomes a pain point. It is deferred from the current decision because (a) it introduces complexity in process lookup and lifecycle that we do not yet need, (b) it requires designing and verifying the user region's allocation strategy, which is a project in itself, and (c) the chosen approach's boot-time sizing removes most of the pressure that would motivate this option. A future ADR could supersede this one if tiered allocation becomes attractive.

**Alternative 5: Full seL4-style object memory with Retype from untyped pool.**

*Why considered.* Strongly aligned with verification-first goals. Eliminates ambient authority structurally via capability-gated Retype. Counting-invariant verification target. Proven in embedded systems.

*Why rejected.* Fragmentation under long-running general-purpose workloads is an unsolved problem with no satisfying solution in existing systems. Memory defragmentation in a live kernel is either latency-spiking stop-the-world compaction or permanent background-worker overhead — neither acceptable for a general-purpose OS. seL4 avoids the problem by targeting workloads (embedded, aerospace, automotive) that reboot frequently and have predictable object counts; ArcOS's general-purpose aspirations per [ADR-009](009-purpose-tiers-scope.md) do not get that dodge. Additionally: not proven as a general-purpose OS substrate in any public deployment. The chosen approach preserves most of object memory's benefits (bounded memory, verification-friendly, capability-gated creation) without introducing the fragmentation risk. This option remains a candidate for a superseding ADR if future work reveals a satisfying fragmentation solution, but it is not required and not chosen for v1.

**Alternative 6: Capability-gated process creation (structural), independent of allocation mechanism.**

*Why considered.* Fixes ambient authority without touching allocation.

*Why adopted as part of the chosen solution.* This is the zero-trust improvement we need regardless of how memory is allocated. The chosen approach includes it: a process cannot be created without the caller holding a `create_process` capability. This is granted to the bootstrap Principal, to init, and to the policy service (when it lands in Wave 4), and delegated as the policy service sees fit. It costs almost nothing in code and is load-bearing for the zero-trust story.

**Alternative 7: Redox-style heap-allocated process tree.**

*Why considered.* Scales to general-purpose workloads without a fixed cap.

*Why rejected.* The kernel heap allocator is itself in the verification target. Variable-length heap-allocated collections are harder to verify than fixed arrays. ArcOS's verification-first posture makes this an unacceptable trade. Redox accepts it; ArcOS does not.

**Alternative 8: Linux-style PID bitmap plus slab allocator.**

*Why considered.* Industry-proven, scales to millions of processes, mature tooling.

*Why rejected.* Same verification objection as Redox-style, plus additional complexity (bitmap, slab, reference counting, PID recycling). Linux's scale is a distraction — ArcOS's v1 targets do not need tens of thousands of processes per CPU. The chosen approach meets the real requirement without importing Linux's allocation stack.

**Alternative 9: Fuchsia-style handle table with slab-allocated kernel objects.**

*Why considered.* Fuchsia is the closest prior art — a microkernel OS with a handle-to-object model and general-purpose ambitions.

*Why rejected.* Fuchsia's verification story is not as strong as ArcOS aims to be (Fuchsia relies on testing and review, not formal methods). Its handle table design is capability-ish but not as structurally enforced as ArcOS's capability system intends to be. Adopting Fuchsia's model would compromise ArcOS's verification posture without a clear gain over the chosen approach.

**Alternative 10: Hidden formula with a single kernel-internal fraction.**

*Why considered.* An earlier draft of this ADR proposed `num_slots = (available_memory × 0.5%) / bytes_per_slot` as a kernel-internal computation. It would have scaled with hardware and achieved most of the chosen approach's benefits.

*Why rejected.* A hidden formula conflates mechanism and policy: the kernel both *decides* the sizing and *applies* it, with the decision expressed as magic constants in kernel source. This is harder to verify (the verifier has to reason about the formula), harder to adjust (every tuning change touches kernel source), and does not match ArcOS's pattern of "kernel provides mechanism, configuration above it provides policy." The chosen approach — explicit `TableSizingPolicy` declared at the tier boundary — keeps the kernel as a pure applier of policy inputs, which is cleaner on all three axes. This is a refinement of the chosen approach, not a fundamentally different one; it is listed separately because an earlier version of this ADR did choose it before it was replaced.

## Open Problems

The chosen approach resolves the four problems in this ADR's Problem section. It does not resolve every problem ArcOS will face at scale. This section enumerates the known-unsolved parts so future contributors do not have to discover them under pressure.

**Problem 1: Default tier policies are initial values, not final.**

The `TableSizingPolicy` values shown in the Decision section for each tier are starting points chosen from estimated workload density. Whether Tier 1's `{ min: 32, max: 256, ram_per_slot: 4 MiB }` is right depends on what Tier 1 deployments actually run, and similarly for Tiers 2 and 3. The values are one-line edits in the tier configuration and can be adjusted when real workload data exists. The chosen approach does not commit to specific numbers for each tier — it commits to "tier-declared policy applied at boot."

**Problem 2: Per-process state growth may require policy tuning.**

As the kernel evolves and per-process state grows (new capability kinds, channel tables, audit subscriptions, policy cache entries), the per-slot memory footprint grows. The `TableSizingPolicy` does not automatically account for this — the policy's `ram_per_slot` is a decision about workload density, not a measurement of per-slot size. A future kernel with larger per-process state may need a larger `ram_per_slot` value (fewer slots per gigabyte) to prevent over-commit of kernel memory. This is tracked as a future tuning concern, not a structural problem.

**Problem 3: Verification tooling confirmation.**

The claim that "boot-time constant is as verification-friendly as a compile-time constant" is plausible but unconfirmed. Most formal verification tools handle "runtime value set once at init, never changed" cleanly — it is treated as a symbolic constant for reasoning purposes. The chosen approach's axiom-style policy (three fields, a clamp, no formula to reason about) is additionally simpler to prove than a formula-based approach. However, ArcOS has not yet committed to a specific verifier (Isabelle, Coq, Kani, Verus, etc), and different tools have different support for this pattern.

Before committing this approach to code, a proof sketch should confirm that the chosen verifier treats boot-time axioms cleanly. If it does not, we re-evaluate — either switch to a compile-time constant (reintroducing the hardware-range problem) or pick a different verification tool.

The risk is low but real. The claim is plausible enough to proceed on, with the commitment to revisit if it turns out to be wrong.

**Problem 4: Policy of who holds the process-creation capability.**

The chosen approach makes the mechanism clean: a capability is required, the check is structural. The *policy* of which processes hold the capability, how delegation works, whether children inherit creation authority, and under what circumstances the policy service can revoke it — these are policy questions, not mechanism questions. They are properly the domain of [ADR-006](006-policy-service.md) (policy service) and will be answered in Wave 4.

Until the policy service exists, the interim behavior is: the bootstrap Principal holds `CreateProcess`. Init holds it when init exists. Boot modules loaded at boot have it implicitly via the bootstrap Principal's delegation. No other processes have it. This matches the current de-facto behavior and does not introduce new policy.

**Problem 5: Debug story for large process counts.**

At the upper end of the chosen approach's scaling (tens of thousands of slots on future datacenter hardware), full kernel state dumps are impractical. Shell commands like `ps` or `cap list` need pagination. This is a tooling problem, not a kernel problem, but it is a cost of the expanded sizing and is named here so future tooling work accounts for it. Not a blocker for v1.

**Problem 6: Zombie accumulation.**

Dense arrays are stable in layout over time, but zombie processes (terminated but not yet fully reaped) still hold slots until cleanup runs. Without aggressive reaping — which the current kernel does partially, per [STATUS.md](../../STATUS.md)'s "Process lifecycle cleanup is partial" known issue — a long-running system could accumulate zombies. The chosen approach does not make this worse, but it does make the problem *less visible* (you hit it later on larger machines), which is a subtle risk. Fixing zombie reaping is tracked separately and is prerequisite for long-running general-purpose operation.

**Problem 7: Per-process capability cap revisit.**

The current per-process capability cap of 32 is a scaffolding artifact from the earliest days of the kernel. Under the chosen approach, the overall capability table scales with memory, but each individual process's cap stays at 32. Wave 2d (channels), Wave 3 (audit subscription), and Wave 4 (policy service) will all add to the per-process capability count — channels as first-class capabilities, audit subscriptions as a new capability kind, and policy-service-granted authorities as additions to the existing set. 32 will get tight quickly. This ADR does not fix it, but it names the issue as something Wave 2 should revisit in a companion commit.

**Problem 8: Interaction with channels (Wave 2d).**

Channels are kernel objects. Under the chosen approach, channel allocation should use the same `TableSizingPolicy` pattern — a separate policy instance for channels, declared in the tier configuration alongside the process-table policy, with its own `min_slots`, `max_slots`, and `ram_per_slot` values. [ADR-005](005-ipc-primitives-control-and-bulk.md) currently describes channels as if they have their own allocation story; under this ADR, they inherit the table-sizing-policy pattern. ADR-005 should be updated when channels are implemented to align with this decision. This is a Wave 2d task, not a prerequisite of this ADR.

## Cross-References

- **[ADR-000](000-zta-and-cap.md)** — Capability foundations. This ADR extends the capability system with a new kind (`CreateProcess`) and uses the existing capability check machinery for structural authority enforcement.
- **[ADR-001](001-smp-scheduling-and-lock-hierarchy.md)** — Lock hierarchy. This ADR does not add new locks; the existing `CAPABILITY_MANAGER(4)` and `PROCESS_TABLE(5)` positions are unchanged.
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** — IPC primitives (channels). Channels are downstream consumers of this ADR's allocation pattern; ADR-005 will be updated when Wave 2d implements channels on top of the new table sizing.
- **[ADR-006](006-policy-service.md)** — Policy service. The policy of who holds `CreateProcess` is mediated by the policy service when it lands in Wave 4. This ADR provides the mechanism; ADR-006 decides the policy.
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Capability revocation. Wave 1 landed the revocation primitive used here for process-exit cleanup. This ADR does not change revocation mechanics.
- **[ADR-009](009-purpose-tiers-scope.md)** — Purpose, deployment tiers, and scope boundaries. This ADR depends on ADR-009 for the hardware floors (Tier 1 minimum 256 MB, Tier 2 minimum 1 GB, Tier 3 minimum 8 GB) that establish the hardware range this ADR's allocation model serves. This ADR also inherits ADR-009's "single kernel binary across tiers" commitment, with the tier-specific part expressed as a `TableSizingPolicy` value in the tier's build configuration.
- **[CLAUDE.md § Lock Ordering](../../CLAUDE.md#lock-ordering)** — Lock hierarchy reference. Unchanged by this ADR.
- **[CLAUDE.md § Formal Verification](../../CLAUDE.md#formal-verification-non-negotiable-constraint)** — Verification posture. This ADR's Verification Stance section defends the claim that boot-time-sized tables preserve the verification properties the posture requires.
- **[STATUS.md](../../STATUS.md)** — Implementation status. This ADR's Wave 2 sub-waves will update STATUS.md as they land.
- **[ASSUMPTIONS.md](../../ASSUMPTIONS.md)** — Numeric bounds catalog. This ADR adds rows for the tier policies (`TIER1_POLICY`, `TIER2_POLICY`, `TIER3_POLICY`) as TUNING entries. The existing `MAX_PROCESSES` row is removed as the constant itself is removed.

## See Also in CLAUDE.md

When this ADR is implemented, the following CLAUDE.md sections should be updated:

- **"Current state"** paragraph — note that the process table and capability table are boot-time-sized from a tier-declared policy, and cite this ADR for the rationale.
- **"Memory Layout"** section — update the per-process memory layout description to reflect that `num_slots` is computed at boot from the tier policy rather than fixed at compile time.
- **"Syscall Numbers"** — no new syscall numbers; the `create_process` authority check is internal to the existing process creation path.
- **"Required Reading by Subsystem"** — add a new row for "Process or capability allocation / table sizing" pointing to this ADR.
- **"Post-Change Review Protocol"** — Step 8 should note that changes to per-process state (new fields in `ProcessDescriptor`, `ProcessCapabilities`, etc) may require revisiting the default tier policies because the per-slot memory footprint has changed.
