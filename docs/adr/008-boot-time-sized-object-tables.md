# ADR-008: Boot-Time-Sized Kernel Object Tables

- **Status:** Proposed
- **Date:** 2026-04-11
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-009](009-purpose-tiers-scope.md) (Purpose, Deployment Tiers, and Scope Boundaries)
- **Related:** [ADR-001](001-smp-scheduling-and-lock-hierarchy.md) (Lock hierarchy), [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives — channels are downstream consumers of this decision), [ADR-007](007-capability-revocation-and-telemetry.md) (revocation primitive wired in Wave 1)
- **Supersedes:** N/A

## Context

CambiOS's kernel today stores per-process state — the process descriptor table and the capability table — in fixed-size dense arrays sized by a compile-time constant. The constant was `MAX_PROCESSES = 32` until Wave 1 of Phase 3 (capability revocation) landed, at which point the conversation about raising it surfaced that "pick a bigger constant" does not address the real problem. The real problem is that *any* compile-time constant has structural failure modes at the two ends of the project's target hardware range (embedded at one end, future high-memory workstations at the other) and in the sawtooth between phases. This ADR documents the allocation model CambiOS adopts to resolve that.

This ADR is written after [ADR-009](009-purpose-tiers-scope.md), which commits the project to three deployment tiers and a broad but bounded hardware range. ADR-009 establishes the hardware precondition; this ADR designs the mechanism that serves it.

## Problem

CambiOS's kernel currently stores per-process state in fixed-size dense arrays sized by the compile-time constant `MAX_PROCESSES = 32`. This includes the process descriptor table in [src/process.rs](../../src/process.rs) and the capability table in [src/ipc/capability.rs](../../src/ipc/capability.rs). Every slot is preallocated at boot, regardless of whether it is used. Lookups are O(1) array indexing. Verification invariants reason about the array as a statically-bounded structure.

This was the right design when the kernel ran three processes in total. It is the wrong design for a general-purpose operating system that targets modern hardware and expects to run user workloads beyond a handful of core services. Four problems have accumulated, and together they motivate this ADR.

**Problem 1 — the bound is too small for general-purpose workloads.**

The value of 32 is a scaffolding artifact from the kernel's earliest days. Today the project runs 7 boot modules plus idle, and the v1 roadmap adds at least another dozen core-service processes (policy service, audit watcher, init, DHCP client, DNS resolver, TCP stack, virtio-blk driver, persistent ObjectStore, CambiObject CLI, Yggdrasil peer service, and the tier-dependent AI services described in [ADR-009](009-purpose-tiers-scope.md)). Beyond core services, general-purpose use involves spawned user programs — shells, editors, build systems, browser helper processes, PE-compatibility sandboxes. Any realistic Tier 3 session hits 32 before the user has opened their second application.

[ADR-009](009-purpose-tiers-scope.md) commits the project to being a first-class general-purpose operating system across three deployment tiers. A cap of 32 is incompatible with that commitment at every tier.

**Problem 2 — sawtoothing across phases.**

Even if the value were larger, the compile-time-constant design creates a predictable failure mode: the bound gets chosen to cover "today's workload plus a buffer," then gets blown through at the next phase boundary, triggering disruptive refactors exactly when the project is busiest with other work. This pattern has a name: the sawtooth. Each phase spawns a new subsystem, the new subsystem brings new processes, the bound gets crossed, and the fix becomes emergency work.

We have already seen this pattern start. Wave 1 (capability revocation) raised the question of whether `MAX_PROCESSES = 32` was still adequate — it was not, and the conversation that followed surfaced that "pick the next bigger number" would just defer the same conversation to Wave 3 or 4. The project needs an allocation model that does not require hand-picking bounds at each phase boundary.

**Problem 3 — ambient authority in process creation.**

The current kernel allows any kernel code path that reaches the process table to create a new process. The restriction to "bootstrap Principal + boot modules" is enforced by convention — by the fact that only the boot path currently calls `create_process` — not by structure. Adding a new caller would be straightforward. A bug that caused an unexpected caller to invoke `create_process` would succeed.

This conflicts with the zero-trust stance documented in [ADR-000](000-zta-and-cap.md), which requires "no ambient authority" — authority should be structural, held as explicit capabilities, not derived from reachability. The capability table system is the mechanism for structural authority throughout the rest of the kernel; process creation is an exception that has drifted into an ambient-authority design.

A fix for this problem does not strictly require changing the allocation model — capability-gated process creation is independent of whether processes come from a dense array, a heap, or an object pool. But it is a natural companion to any allocation model change, because the right place to check "does the caller hold the `create_process` capability" is at the same site where the allocation happens. Bundling the fix with the allocation change costs almost nothing and closes a zero-trust gap that otherwise would need its own commit later.

**Problem 4 — compile-time sizing does not survive a wide hardware range.**

[ADR-009](009-purpose-tiers-scope.md) commits CambiOS to three deployment tiers spanning approximately three orders of magnitude of hardware: from a 256 MB embedded board at the Tier 1 minimum through 8 GB desktops and laptops at the Tier 3 floor to future workstations with hundreds of gigabytes or terabytes of RAM. A single compile-time `MAX_PROCESSES` constant cannot serve this range. A number that is comfortable on a 16 GB desktop is absurdly small on a future 1 TB workstation. A number sized for the future is catastrophic on a 512 MB embedded board.

[ADR-009](009-purpose-tiers-scope.md) also commits the project to "Platform Is an Implementation Detail" and to a single kernel binary running across each tier's hardware range. A compile-time constant breaks that commitment as soon as the hardware range is wide. The project can either accept multiple kernel builds for different hardware classes (rejected by the single-binary principle), pick a single number and accept that it is wrong for both extremes (rejected by the general-purpose commitment), or find an allocation model that adapts to hardware at boot time.

**Why these problems must be solved together.**

Any one of the four could be addressed in isolation. Problem 1 could be fixed by picking a bigger constant. Problem 2 could be fixed by writing an escape-hatch ADR describing future evolution. Problem 3 could be fixed by adding capability-gated creation in a focused commit. Problem 4 could be fixed by a boot-time-sized table.

Addressing them separately would result in four commits, each introducing churn in the same subsystems (process table, capability table, boot sequence, verification target), each requiring its own test and review pass, and each deferring the inevitable conversation about what the allocation model should actually be. This ADR proposes that they are cheaper to solve together because the solutions reinforce each other: boot-time sizing solves Problems 1 and 4, capability-gated creation solves Problem 3, and the combination renders the sawtooth of Problem 2 largely moot — the bound is adaptive to hardware, so phase boundaries do not cross it unless the hardware itself is insufficient, and if the hardware is insufficient the fix is "the deployment is below the tier floor," not "refactor the kernel."

The scope of the change is small enough to fit in a bounded set of commits and large enough that a design document is warranted.

## The Reframe

The architectural insight that resolves the four problems is:

> **Kernel object capacity should be a function of available memory, expressed as an explicit memory budget, not a compile-time decision.**

A compile-time constant forces the kernel to decide, before it knows what hardware it will run on, how much state it can ever manage. That decision is structurally wrong: the kernel does know how much hardware it has — it learns it at boot, from the bootloader's memory map — and the right time to size the tables is then.

The key refinement: the sizing decision is expressed as *how much memory the kernel is allowed to reserve for these tables*, not as *how many slots to allocate*. Memory is the unit both the operator and the verifier can reason about from first principles — the operator knows exactly what they are committing, and the verifier reasons about a known byte budget divided by a compile-time per-slot size. Slot count is a derived value, not a primary input. This avoids the trap where an operator declares a slot count without being able to see what memory that will actually consume as per-slot size evolves.

The reframe does not change what the tables *are*. They remain dense arrays. They remain preallocated. Lookups remain O(1). The verification invariants remain invariants over a fixed-size structure. The only things that change are *when* the size is fixed (at boot, once, from a policy declared at the tier boundary, rather than at kernel compile time) and *where* the tables live (in a dedicated region allocated directly from the frame allocator, separate from the kernel heap).

Paired with structural capability-gated process creation — where creating a process requires holding a `create_process` capability, not just being code that can reach the process table — the reframe also closes the ambient-authority gap. The three changes (budget-denominated sizing, dedicated region, capability-gated creation) are natural companions and land together.

## Decision

CambiOS adopts a **boot-time-sized dense array** allocation model for per-process kernel object tables, paired with **structural capability-gated process creation**. The tables live in a dedicated memory region carved from the frame allocator at boot init, separate from the kernel heap. The sizing policy is expressed as a RAM budget rather than a slot count. Specifically:

**1. The kernel takes its table sizing policy as an explicit input, not as a hidden formula.** A `TableSizingPolicy` struct declares the sizing decision in configuration that can be read, verified, and adjusted independently of kernel source. The kernel's role is to *apply* the policy to the actual hardware at boot; it does not decide the policy.

**2. The policy has five fields, expressing operator intent in memory terms:**

```rust
pub struct TableSizingPolicy {
    /// Minimum slot count, always guaranteed regardless of budget.
    /// If the budget alone would produce fewer slots, this value wins
    /// and the budget is effectively exceeded for this floor.
    pub min_slots: u32,

    /// Maximum slot count, never exceeded regardless of budget.
    /// Caps the budget calculation: if (budget / slot_overhead) would
    /// exceed max_slots, the extra budget is unused and the table is
    /// sized to max_slots.
    pub max_slots: u32,

    /// Fractional budget as parts-per-million of available RAM.
    /// Example: 30_000 = 3% of RAM. Kernel computes
    /// (available_memory * ppm / 1_000_000) as the target budget,
    /// then clamps to the absolute floor and ceiling below.
    pub ram_budget_ppm: u32,

    /// Absolute floor on the RAM budget (bytes).
    /// If the fractional calculation produces less than this, this
    /// value is used. Ensures small-RAM systems have a workable budget
    /// even when the fractional slice is tiny.
    pub ram_budget_floor: u64,

    /// Absolute ceiling on the RAM budget (bytes).
    /// If the fractional calculation produces more than this, this
    /// value is used. Prevents huge-RAM systems from reserving absurdly
    /// large object tables when the workload does not justify it.
    pub ram_budget_ceiling: u64,
}
```

The policy reads as operator intent in two sentences: "Commit this fraction of RAM to the tables, clamped between this floor and this ceiling. Allocate as many slots as that budget affords, clamped between this minimum and this maximum."

**3. The computation applied at boot is a fractional budget with two clamps and a derivation:**

```rust
const SLOT_OVERHEAD: usize =
    core::mem::size_of::<Option<ProcessDescriptor>>()
    + core::mem::size_of::<Option<ProcessCapabilities>>();

// Fractional budget, u128 intermediate to prevent overflow on huge RAM.
let fractional = (available_memory_bytes as u128)
    .saturating_mul(policy.ram_budget_ppm as u128)
    / 1_000_000;
let fractional = fractional.min(u64::MAX as u128) as u64;

// Clamp to absolute floor and ceiling.
let budget = fractional.clamp(policy.ram_budget_floor, policy.ram_budget_ceiling);

// Derive slot count from budget and compile-time slot overhead.
let slots_from_budget = (budget / SLOT_OVERHEAD as u64) as u32;

// Clamp slot count to operator-declared min/max.
let num_slots = slots_from_budget.clamp(policy.min_slots, policy.max_slots);
```

Five fields, two clamps, one arithmetic derivation using a compile-time constant for slot overhead. The verifier treats the five policy fields as axioms from the tier configuration, treats `SLOT_OVERHEAD` as a compile-time constant, and reasons about each clamp as a simple inequality. The `u128` intermediate prevents overflow on unusual memory sizes; on realistic hardware the optimizer lowers it to ordinary integer operations.

**4. The policy is declared at the tier boundary, not in the kernel's core logic.** Per [ADR-009](009-purpose-tiers-scope.md), the tier is an install-time choice — it determines which build of CambiOS is shipped and which user-space services are loaded. The tier also carries the table sizing policy as part of its build-time configuration. Each tier ships with a default policy:

- **Tier 1 — CambiOS-Embedded.** `{ min_slots: 32, max_slots: 256, ram_budget_ppm: 15_000, ram_budget_floor: 2 MiB, ram_budget_ceiling: 8 MiB }`. Reads as: "1.5% of RAM, clamped 2 MiB to 8 MiB, for between 32 and 256 slots." Embedded deployments typically run small, stable sets of fixed-function processes; the 256-slot ceiling reflects that a deployment needing more is probably the wrong fit for Tier 1.
- **Tier 2 — CambiOS-Standard (no AI).** `{ min_slots: 128, max_slots: 4096, ram_budget_ppm: 20_000, ram_budget_floor: 16 MiB, ram_budget_ceiling: 64 MiB }`. Reads as: "2% of RAM, clamped 16 MiB to 64 MiB, for between 128 and 4096 slots." Sized for a typical single-user desktop or workstation; operators on shared multi-user machines or heavy build farms can raise the ceiling in a custom tier configuration.
- **Tier 3 — CambiOS-Full.** `{ min_slots: 256, max_slots: 65536, ram_budget_ppm: 30_000, ram_budget_floor: 64 MiB, ram_budget_ceiling: 512 MiB }`. Reads as: "3% of RAM, clamped 64 MiB to 512 MiB, for between 256 and 65536 slots." Sized to accommodate heavy general-purpose workloads (large builds, many user applications, AI services with per-request workers). Operators with workloads exceeding 65536 processes can raise the ceiling in a custom tier configuration — the cap is a default, not a physical limit.

These values are starting points, not final commitments. They are documented in [ASSUMPTIONS.md](../../ASSUMPTIONS.md) and can be tuned when real workload data exists. The kernel binary is identical across tiers per ADR-009's "same kernel binary across tiers" commitment; what differs is the `TableSizingPolicy` value compiled in from the tier's configuration.

**5. Two clamps, two failure modes, both preventable.** The interface has two clamps because the two bounds prevent two different kinds of failure:

- **`ram_budget_ceiling`** prevents runaway *memory* consumption: if per-slot overhead grows in a future kernel (more per-process state added), the ceiling prevents the tables from consuming an unreasonable fraction of RAM even if `max_slots` is high. The binding constraint shifts from slot count to memory budget when per-slot growth crosses the threshold.
- **`max_slots`** prevents runaway *slot* counts: even on enormous hardware, the table does not scale without bound. This is where an operator declares "I do not want more than N processes on this deployment regardless of how much RAM is available." The ceiling is visible, adjustable, and part of the tier configuration.

On current kernel state, `max_slots` is typically the binding constraint at the ram_budget_ceiling (budget affords many more slots than `max_slots` permits). If future per-process state growth makes the budget the tighter constraint, the interface shifts gracefully without any policy changes — the kernel starts producing fewer slots at the same budget, and the operator sees the shift in the boot-time log.

**6. The tables live in a dedicated "kernel object table region," not in the kernel heap.** The process and capability tables are allocated as a single contiguous region directly from the frame allocator during boot init, mapped into the kernel's address space via the HHDM, and never freed for the lifetime of the kernel. This is a deliberate architectural commitment that this ADR makes, rather than leaving to implementation time. The rationale and mechanism are detailed in the Architecture section below. The kernel heap remains at its current size for Wave 2a; growing the heap to absorb other Phase 3 subsystem pressure (audit ring buffers, channel bookkeeping, policy cache) is a separate decision from this ADR.

**7. The policy is visible and adjustable at build time today, with a documented migration to boot-time configuration when a manifest mechanism exists.** Because the policy is five explicit numbers rather than a hidden formula, an operator deploying CambiOS to unusual hardware can adjust the policy at build time without touching kernel source beyond the tier configuration file. The policy for each tier lives in a dedicated kernel configuration module (`src/config/tier.rs` in Wave 2a's implementation). Three Cargo features — `tier1`, `tier2`, `tier3` — select which tier's policy is compiled in; exactly one is set per kernel build. A build-script check rejects a configuration with zero or multiple tier features set. An operator who wants a custom policy adds a `tier_custom` feature with their own policy values and rebuilds.

Build-time configuration is the right mechanism for Wave 2 because CambiOS does not yet have a boot-manifest infrastructure — the kernel does not read any runtime-loaded configuration today. Introducing boot-manifest support just for table sizing would be a larger scope change than this ADR needs. The long-term direction, however, is clear: **when CambiOS grows a boot-manifest mechanism (anticipated post-v1, alongside the init process and service configuration work), the table sizing policy moves from compile-time configuration to the manifest.** The compile-time const becomes a fallback default for the case where no manifest is present, and an operator who wants a different policy adjusts the manifest rather than rebuilding the kernel. This ADR does not design the manifest itself, but it commits that the table sizing policy will be among the first things to move into it, because the policy is already structured to make that migration clean: the struct, the fields, and the computation are the same on either side of the move — only the *source* of the policy values changes.

**8. At the kernel level, the policy is an axiom.** The kernel does not decide the policy; it receives the policy from the tier configuration and applies it. From the verifier's perspective, `num_slots` is an input parameter constrained by the policy fields and the compile-time `SLOT_OVERHEAD`, not a value derived from a formula with magic constants. This is a stronger verification target than a hidden formula: the verifier proves properties of the table given `num_slots`, and the policy's constraints on `num_slots` (derived from the two clamps) are checked at init time and then treated as invariants.

**9. Process creation requires a `create_process` capability.** A new capability kind is introduced that grants the holder the right to invoke the kernel's process-creation path. The bootstrap Principal holds this capability implicitly at boot (see the Migration Path section). As the policy service ([ADR-006](006-policy-service.md)) comes online, policy decides who else holds it. Without this capability, a caller cannot create a process — the check is structural, at the allocation site, and cannot be bypassed by code that happens to reach the process table.

The combination is intentionally minimal. The kernel's allocation machinery (with the exception of the new kernel object table region described below), verification posture, and IPC primitives are untouched. Only the sizing mechanism, the object storage path, and the process-creation authority check change.

## Architecture

### Boot-time sizing, in detail

The sizing computation runs during kernel initialization, after the frame allocator has been set up (so that `available_memory_bytes` is known) and before any user-space process is created (so that the tables exist when they are first used). The sequence:

1. Frame allocator initialized; `available_memory_bytes` is the sum of usable regions from the bootloader memory map.
2. The tier's `TableSizingPolicy` is read from the compile-time configuration (`src/config/tier.rs`).
3. Fractional budget computed: `available × ppm / 1_000_000`, u128 intermediate, saturating multiplication.
4. Budget clamped to `[ram_budget_floor, ram_budget_ceiling]`.
5. `slots_from_budget` derived: `budget / SLOT_OVERHEAD` (compile-time constant).
6. `num_slots` clamped to `[min_slots, max_slots]`.
7. Kernel object table region allocated: a single contiguous physical frame allocation sized to hold both tables (see the Kernel Object Table Region subsection below).
8. Region mapped into the kernel's address space via the HHDM.
9. Process table initialized as a slice into the region, `num_slots` entries of `Option<ProcessDescriptor>`, all `None`.
10. Capability table initialized as a slice into the region after the process table (starting on the next page boundary), `num_slots` entries of `Option<ProcessCapabilities>`, all `None`.
11. `num_slots`, the region base address, and the two table pointers stored in kernel-global read-only locations (set once, read many).
12. Kernel logs the chosen `num_slots`, the region size, and the binding constraint (which of the five policy fields was active) so the operator has visibility at boot.
13. Init continues; process 0 (idle) is created; boot modules are loaded as processes; etc.

After step 11, `num_slots` is effectively a compile-time constant from the perspective of every code path that reads it. The kernel does not check whether `num_slots` has changed because it cannot change.

### What the RAM budget means for a running program

A running program on CambiOS sees "available memory" = physical RAM minus kernel commitments. The kernel object table region is one of those commitments: memory the kernel reserves at boot, never frees, and never makes visible to user space.

On 8 GB Tier 3 with the default policy, the region reserves roughly 200 MiB (the `ram_budget_ceiling` at 3% of 8 GB is 246 MiB, clamped down to 512 MiB ceiling — the ceiling is not the binding constraint at this RAM size, but `max_slots × SLOT_OVERHEAD` typically is). Combined with other kernel commitments (heap, frame bitmap, per-CPU state, kernel code and page tables), total kernel memory footprint at boot is a few hundred MiB. User programs on an 8 GB machine see approximately 7.5 GB available — about 95% of physical memory.

For comparison on the same hardware:
- Windows 11: kernel + services + background tasks typically commit 4-8 GB at boot. Users see 8-12 GB.
- Linux (full desktop distro): ~1-2 GB committed at boot. Users see 14-15 GB.
- CambiOS Tier 3: ~200-400 MiB committed at boot. Users see ~7.5 GB.

The kernel object table region is the largest single commitment this ADR introduces, and it is still a small fraction of what commercial OSes reserve. The commitment is pre-allocated at boot and stays committed regardless of workload — a lightly-loaded Tier 3 machine has the same table footprint as a heavily-loaded one. This is the "set once, never changes" property that makes the allocation verification-clean. The tradeoff is that memory capacity reserved for slots that may go unused cannot be reclaimed by user programs. For CambiOS's goals (verification, predictability, no allocation failures in the hot path), this tradeoff is deliberate, and the memory cost remains modest — a few percent of RAM at every tier.

### Kernel Object Table Region

The process and capability tables are allocated from a dedicated physical memory region, separate from the kernel heap. This is a deliberate architectural choice, not a convenience.

**Rationale:**

1. **Size.** At Tier 3 the tables can need hundreds of megabytes of contiguous allocation. This is substantially larger than the current 4 MiB kernel heap. Putting allocations of this size into the heap would require growing the heap by orders of magnitude, which wastes memory on smaller tiers and conflates two architecturally different kinds of storage.

2. **Lifetime.** The tables are allocated once at boot and never freed. They do not need the heap's free-and-reallocate machinery. Putting long-lived, large allocations on the heap wastes the heap's capacity on things that could be allocated more efficiently with a one-shot region allocator.

3. **Verification.** A dedicated region has a single, declared memory range that is easier to reason about than a heap allocation of similar size. Verification properties of the tables (bounded iteration, valid index range, disjoint-from-other-allocations) are parameterized by `num_slots` and the region base address, neither of which interacts with the heap allocator's state.

4. **Separation of concerns.** "Kernel object storage" and "kernel working memory" are architecturally different things. Linux's slab allocator, seL4's untyped memory, and other production kernels all distinguish between them. CambiOS's current conflation into a single heap is a scaffolding choice from the early kernel days; this ADR introduces the separation for the specific objects it covers.

5. **Reusable pattern for future kernel objects.** When Wave 2d implements channels, they use the same pattern: a dedicated region for the channel table, sized by a channel-specific `TableSizingPolicy` declared in the tier configuration alongside the process-table policy. The architectural template this ADR establishes is reusable for every future kernel-object allocation that needs the same properties (long-lived, large, dense-array, known-at-boot). Future regions for additional kernel object kinds (capability registry entries, audit records, policy cache rows) can use the same allocation path.

**Mechanism:**

At boot, after computing `num_slots`, the kernel computes the total region size:

```rust
let region_bytes = (num_slots as usize * SLOT_OVERHEAD).next_multiple_of(PAGE_SIZE);
let num_pages = region_bytes / PAGE_SIZE;
```

The kernel allocates `num_pages` contiguous physical frames from the frame allocator as a single large allocation. This is within the frame allocator's existing contiguous-allocation capability — the same machinery the kernel uses for early-boot bootstrap frames and for DMA allocations. The region is mapped into the kernel's virtual address space via the HHDM on both architectures (x86_64: `0xFFFF800000000000` offset; AArch64: `0xFFFF000000000000` offset), using the existing mapping paths.

The two tables are laid out within the region:

- Process table: starts at region base, spans `num_slots × size_of::<Option<ProcessDescriptor>>()` bytes.
- Capability table: starts at the next page-aligned offset after the process table, spans `num_slots × size_of::<Option<ProcessCapabilities>>()` bytes.

The page-aligned boundary between the two tables prevents cache-line-level false sharing and simplifies verification reasoning about their disjointness.

**Kernel heap stays at its current size for Wave 2a.** The kernel heap is currently 4 MiB. Phase 3 subsystems other than the object tables (audit ring buffers per [ADR-007](007-capability-revocation-and-telemetry.md), channel bookkeeping metadata per [ADR-005](005-ipc-primitives-control-and-bulk.md), per-CPU policy caches per [ADR-006](006-policy-service.md)) may still pressure the heap and may warrant growing it in a future commit, but that growth is decoupled from the table sizing question this ADR resolves. A future ADR or implementation commit can address the kernel heap independently once the shape of the pressure is known.

**Frame allocator interaction.** The kernel object table region is a large one-shot allocation that the frame allocator sees as a single call at init time. The frame allocator's bitmap-based design already handles contiguous multi-frame allocations; no new allocator mechanism is required. The region is allocated before any user-space process exists, so there is no contention with user-space allocations. The frame allocator's bitmap is sized to cover the machine's physical memory range (see the `MAX_FRAMES` entry in [ASSUMPTIONS.md](../../ASSUMPTIONS.md)); on hardware with large physical memory ranges, the bitmap grows accordingly, which is already tracked as a scaffolding concern for the bare-metal bring-up.

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

Wave 1's `revoke_all_for_process` (from [ADR-007](007-capability-revocation-and-telemetry.md)) already handles tearing down the capability table entries on process exit. This ADR does not change that path. The capability table rows are cleared when the process exits; the row itself remains allocated in the kernel object table region because the region is sized for the kernel's lifetime.

### Lock ordering

The boot-time sizing and region allocation changes happen during kernel initialization, before the lock hierarchy is in force. No new locks are introduced by this ADR. The existing `CAPABILITY_MANAGER(4)` and `PROCESS_TABLE(5)` locks protect the same data structures, just at a potentially larger size and stored in the kernel object table region instead of the heap. The `create_process` authority check happens under `CAPABILITY_MANAGER(4)`, which is already acquired during existing capability checks. No lock-ordering implications.

## General-Purpose Viability

This section addresses the question that shaped the choice between the options considered in the Why Not Other Options section: *does this approach survive general-purpose workloads across the full tier range, or does it have hidden failure modes?*

The short answer is yes, because the chosen approach is structurally conservative. It does not introduce any mechanism that is new to operating systems at scale (dense arrays with runtime-sized capacity are standard; dedicated regions for long-lived kernel objects are standard), does not depend on solving any open research problems (defragmentation, Retype budget management), and does not require hardware support beyond what CambiOS already assumes.

### Scaling properties

- **Upper bound.** Two upper bounds exist: `max_slots` and `ram_budget_ceiling`. The binding one depends on per-slot overhead. At current per-slot sizes, `max_slots` is the typical binding constraint on Tier 3. If per-slot overhead grows, the budget ceiling begins to bind first. Both bounds are visible in the tier configuration and adjustable.
- **Lower bound.** Two lower bounds exist: `min_slots` and `ram_budget_floor`. The binding one is whichever produces more slots. The `min_slots` floor guarantees the approach is usable even at the hardware floor of each tier regardless of budget math.
- **Middle.** At every point between these extremes, the budget scales linearly with available memory via `ram_budget_ppm`, and the slot count scales linearly with the budget. Memory cost and slot count both grow smoothly across the hardware range.

### Workload stress cases

Three workload patterns matter for general-purpose viability. Each is handled cleanly by the chosen approach:

**A desktop session with many running programs.** A user running CambiOS as their daily driver might have shell, editor, browser, messaging client, file manager, and several helper processes — perhaps 30-50 processes total. On Tier 3 at 8 GB, `num_slots` is in the tens of thousands. The session consumes well under 1% of the slots. Comfortable.

**A build system spawning many short-lived processes.** A compilation invoking a build tool that spawns parallel worker processes might have 200-500 concurrent processes at peak. On Tier 3 at 8 GB this is a small fraction of the slots. Well within capacity.

**A long-running server with accumulating zombies.** Without aggressive reaping, terminated processes hold slots until they are reused. A long-running system could, over time, fill the slot space with zombies. This is the scenario most likely to stress the approach. **The general-purpose viability claims this section makes implicitly depend on zombie reaping being implemented before any Tier 3 deployment runs for meaningful length of time.** Zombie reaping is tracked in [STATUS.md](../../STATUS.md)'s process lifecycle cleanup known issue as a prerequisite for declaring Tier 3 ready for long-running production use; it is not a blocker for Wave 2 shipping, but it is a blocker for declaring the "general-purpose viable" claim complete.

### Graceful degradation across tiers

Per [ADR-009](009-purpose-tiers-scope.md)'s "Graceful degradation across tiers" principle, the chosen approach degrades cleanly from Tier 3 to Tier 1:

- On Tier 3, the policy is generous, the region is large, and every feature has room.
- On Tier 2, the policy is moderate, the region is smaller, and fewer services run (because no AI tier components), so the ratio of used slots to available slots is similar to Tier 3.
- On Tier 1, the policy is conservative, the region is small, but only minimal services run, and the ratio is still reasonable.

The same formula produces appropriate sizing at each tier because each tier declares its own policy. A single kernel binary works across the hardware range because the sizing adapts to the hardware, and each tier carries a policy tuned to its expected workload density.

### Tuning from real-world data

The chosen approach is designed to be measured and tuned, not decided once and forgotten. Once the code lands, four measurements matter:

1. `num_slots` vs. peak concurrent process count — does the slot capacity match workload demand?
2. Region memory commitment vs. actual slot utilization — is the budget sized right?
3. Process creation latency — is the allocation path healthy?
4. Kernel heap pressure at peak — are the Wave 3 subsystems pushing the heap toward its limit?

All four are visible through the kernel's boot-time log output (for the static values) and through Wave 3's audit telemetry (for the runtime values). Tuning responses to the data:

- If peak concurrent processes brushes `max_slots`, raise the ceiling.
- If the region is mostly empty at peak load, lower `ram_budget_ceiling` or `ram_budget_ppm`.
- If the region is tight and the workload runs out of slots before exhausting other resources, raise the budget.
- If per-slot overhead grows (new per-process state added in a later wave), the budget may need to grow too — but the signal is "region fills up sooner than expected."

Each adjustment is a few fields in `src/config/tier.rs` followed by a rebuild. No ADR rewrite, no kernel surgery. The architecture is designed to be tunable precisely because the numbers cannot be finalized without workload data.

### What is not solved

The chosen approach does not solve the "what if a workload wants more than the current policy's clamps allow" question. If a user tries to run a workload that exceeds `max_slots` or `ram_budget_ceiling`, they either raise the bound in a custom tier configuration and rebuild, or they accept that the operation fails at the limit. This is not a new failure mode — every operating system has a process count ceiling. The chosen approach makes the ceiling explicit and adjustable.

## Verification Stance

CambiOS's verification posture, documented in [CLAUDE.md](../../CLAUDE.md) under "Formal Verification (Non-Negotiable Constraint)," has several requirements that any kernel change must respect:

- Bounded iteration (no unbounded loops in kernel paths)
- Invariants encoded in types where possible
- State machines over exhaustive enums
- Pure logic separated from effects
- Minimal `unsafe`

The boot-time-sized dense array with dedicated region preserves all of these:

**Bounded iteration is preserved.** Loops over the process table iterate `0..num_slots()`, where `num_slots` is a runtime constant set once at init. From the perspective of any loop that runs after init (which is all of them), the bound is fixed. A verifier that can reason about "this value is set once during init and never changes" — which is essentially every verifier — treats `num_slots` the same as a compile-time constant for the purposes of loop-bound reasoning.

**Invariants encoded in types remain encoded.** The process table is still `&mut [Option<ProcessDescriptor>]`, now backed by the kernel object table region instead of a `Vec`. The `ProcessId` newtype remains distinct from `u32`. The `ProcessCapabilities` slot structure is unchanged. The capability kind enum gains a new variant (`CreateProcess`), which is a trivially-verified extension of the existing exhaustive match.

**State machines are preserved.** The `TaskState` enum, the `CapabilityKind` enum, and every other state enum in the kernel are unchanged except for the addition of `CapabilityKind::CreateProcess`.

**Pure logic separated from effects.** The boot-time sizing computation is pure — a u128-intermediate multiply, a clamp, a divide, another clamp, all over values that are either axioms (policy fields) or compile-time constants (`SLOT_OVERHEAD`). It is testable in isolation and has no hardware dependencies once `available_memory_bytes` is known. The region-allocation effect happens once, at init, and is isolated from the computation.

**Minimal unsafe.** The chosen approach adds one new unsafe boundary: the transmutation between "a range of physical frames" and "a slice of `Option<ProcessDescriptor>`." This is a single, well-localized unsafe block with clear preconditions (the region was allocated at sufficient size, was mapped into the kernel's address space, is aligned, and is not aliased). It is audited and documented with a `// SAFETY:` comment per the project convention. The rest of the kernel accesses the tables through the safe slice interface.

**The verification target that actually changes** is the one invariant that used to read "the process table has exactly `MAX_PROCESSES` slots" and now reads "the process table has exactly `num_slots` slots, where `num_slots` is derived from a `TableSizingPolicy` and `SLOT_OVERHEAD` via a deterministic clamp computation at init, and has not changed since, and where the table occupies a known range of physical memory that does not overlap any other kernel allocation." This is *more specific* than a compile-time constant, not less. A verifier reasoning about post-init kernel state treats the five `TableSizingPolicy` fields as axioms (inputs to the kernel from the tier configuration), treats `SLOT_OVERHEAD` as a compile-time constant, treats the clamp computation as a simple arithmetic fact, and proves properties of the table parameterized by `num_slots` and its base address. This is a well-understood verification pattern.

**What about adversarial inputs?** A natural question is whether an attacker could influence `num_slots` by manipulating the bootloader memory map. The answer: the bootloader memory map is trusted input (at CambiOS's trust boundary for the hardware), and if it is compromised, every other kernel invariant that depends on it is also compromised. This is not a new attack surface introduced by this ADR — the frame allocator already trusts the memory map, and the scheduler's per-CPU state already trusts the CPU count derived from ACPI. The `num_slots` computation is one more place that trusts the memory map, using the same trust model the rest of the boot sequence already uses. Additionally, the `ram_budget_ceiling` and `max_slots` clamps provide hard upper bounds that do not depend on memory map input at all — an attacker who reported absurdly large memory would still see `num_slots` capped at the policy bounds.

## Threat Model Impact

The chosen approach has two effects on the threat model: it closes the ambient-authority gap in process creation, and it does not open any new attack surfaces.

### Ambient authority closed

The current kernel's process creation is gated by convention — only the boot path calls it, and the project trusts itself not to add other callers without thought. This is a fragile guarantee. A code refactor, a forgotten security review, or a well-intentioned feature could add a new call site, and the check "is this caller authorized to create processes" would simply not happen because it is not represented anywhere.

The chosen approach makes the check structural. Every process-creation path passes through `ProcessTable::create_process(creator_principal, ...)`, which verifies the `CreateProcess` capability before allocating a slot. A caller without the capability cannot create a process, period. The check is at the allocation site, not at call sites, so new call sites inherit the check automatically without having to remember to add it.

This closes a gap in the zero-trust story from [ADR-000](000-zta-and-cap.md). Before this change, "no ambient authority" was true for every kernel operation *except* process creation. After this change, it is true for process creation as well.

### No new attack surfaces

The boot-time sizing itself is not an attack surface. `num_slots` is computed from the bootloader memory map, the tier policy, and `SLOT_OVERHEAD`, all of which are already trusted inputs to the kernel's boot sequence. An attacker with the ability to manipulate the memory map can already affect many parts of the kernel; `num_slots` is not a new capability for such an attacker, and the policy clamps prevent even a memory-map-compromising attacker from forcing an unbounded allocation.

The dedicated kernel object table region is similarly not a new attack surface. It is a one-shot physical allocation made at init time, before any user-space process exists, and is not accessible from user space (it is mapped only in the kernel's half of the address space via the HHDM). User-space code has no way to interact with the region directly.

The capability-gated `create_process` adds an authority check at a point that previously had none. This is a strict improvement in the threat model — the surface is smaller, not larger.

The capability table still serves the same role it did before, with one additional capability kind. Existing capability checks continue to work without modification. Existing capability-related threats (forgery, delegation abuse, grant escalation) are unchanged.

### What this does not protect against

- **Compromise of the bootstrap Principal.** If an attacker holds the bootstrap Principal's key, they can grant themselves `CreateProcess` and any other capability. This is the same trust assumption the rest of the kernel makes about the bootstrap Principal; this ADR does not change it.
- **Memory exhaustion attacks.** A caller holding `CreateProcess` can create processes until the slot limit is reached. This is a resource exhaustion attack, not an authority bypass. The mitigation is in policy — the policy service ([ADR-006](006-policy-service.md)) can revoke `CreateProcess` from misbehaving callers — and in graceful failure — once the table is full, new creations return a well-defined error rather than crashing. The kernel is protected; the workload may not be.
- **Kernel compromise.** If the kernel is compromised, every invariant this ADR depends on is compromised, including `num_slots` and the integrity of the object table region. This is the same trust boundary the rest of the kernel has; this ADR does not change it.

## Migration Path

The migration from the current dense-array-with-`MAX_PROCESSES` design to the boot-time-sized approach lands as a set of contained changes during Wave 2 of Phase 3. The order is chosen so that each step is individually landable and individually testable.

**Wave 2a.0 — Prep commit (methodology and documentation).** Ready to commit alongside this ADR. Contains:
- The Post-Change Review Protocol amendment for flagging pre-existing warnings.
- The Development Convention 8 refinement for bounds sizing with end-in-mind.
- New rows in [ASSUMPTIONS.md](../../ASSUMPTIONS.md) for the tier policies and `TableSizingPolicy` fields, each pointing at this ADR for rationale.
- CLAUDE.md updates: documentation cross-references to this ADR and [ADR-009](009-purpose-tiers-scope.md).

**Wave 2a — `MAX_PROCESSES` becomes runtime; tables move to a dedicated region.** Changes:
- `MAX_PROCESSES` removed as a compile-time constant.
- `TableSizingPolicy` struct added to a new `src/config/tier.rs` module, with `min_slots`, `max_slots`, `ram_budget_ppm`, `ram_budget_floor`, and `ram_budget_ceiling` fields.
- `tier1`, `tier2`, `tier3` Cargo features added; exactly one must be set per build. A build-script check rejects a configuration with zero or multiple tier features set.
- `num_slots` added as a runtime constant, computed during kernel init from the compiled-in policy, available memory, and `SLOT_OVERHEAD`.
- New "kernel object table region" allocation path: direct contiguous physical frame allocation from the frame allocator at init, HHDM-mapped, lifetime is kernel-lifetime. Documented in CLAUDE.md's Memory Layout section.
- `ProcessTable` and `ProcessCapabilities` storage converted from fixed-size arrays to slices backed by the dedicated region.
- Every `for i in 0..MAX_PROCESSES` loop updated to `for i in 0..num_slots()`.
- Every bounds check of `ProcessId` updated to use `num_slots()`.
- Tests for sizing computation on synthetic memory sizes (256 MB, 4 GB, 8 GB, 32 GB, 1 TB) with each tier policy.
- Tests for the region allocator (correct frame count, correct mapping, correct table layout, disjoint-region invariant).
- QEMU smoke test on both architectures confirms the kernel boots with the new allocation path and reports the chosen `num_slots`, the region size, and the binding constraint at boot.

**Wave 2b — `CreateProcess` capability introduced; authority check added at creation site.** Changes:
- `CapabilityKind::CreateProcess` added to the capability kind enum.
- `ProcessTable::create_process` gains a `creator_principal` parameter and performs the authority check.
- Boot sequence grants `CreateProcess` to the bootstrap Principal after Principal binding is complete.
- All existing call sites updated to pass the creator Principal.
- Unit tests for authority check (authorized creator, unauthorized creator, bootstrap exception during boot).
- Integration test: attempt to create a process without holding `CreateProcess` and verify `AccessDenied` is returned.

**Phase 3.2c — ProcessId generation counter.** This sub-phase introduces the generation counter described in Open Problem 9: `ProcessId` becomes a `(slot_index, generation)` pair, and stale-reference lookups fail the generation check and return `ProcessNotFound` instead of targeting the wrong process. `ProcessTable` allocates slots internally via linear scan and stamps the current generation. `CapabilityManager` validates generation on every lookup. Tests cover stale-reference rejection across all lookup paths and ProcessId encoding round-trips. The `CapabilityHandle` refactor originally planned for this sub-phase is deferred — see the Divergence section at the end of this ADR for rationale.

**Wave 2d — Channel manager lands on the new foundation.** Channels (per [ADR-005](005-ipc-primitives-control-and-bulk.md)) can now be built assuming the boot-time-sized process/capability tables and the dedicated region pattern. The channel manager inherits the same allocation pattern: a channel-specific `TableSizingPolicy` declared in the tier configuration alongside the process-table policy, channels stored in a dedicated channel object table region, and the channel manager reserves its own lock position in the hierarchy. Channels are not directly affected by this ADR except that they are built on top of it — so migration of the IPC bulk path happens here as a consumer of the new table sizing and region pattern.

The order is **2a.0 → 2a → 2b → 2c → 2d**. Each step is a separate commit with its own tests and verification. Steps 2a and 2b are the load-bearing parts of this ADR's implementation; 2c and 2d are follow-on work enabled by them.

A rollback plan exists for each step: each commit can be reverted without affecting the others, because each is a contained change with its own test coverage. If, during 2a implementation, the runtime-sized table or the dedicated region reveals a verification-tool problem that blocks progress (see Open Problem 3), we can revert 2a and reconsider. If, during 2b, the authority check introduces a boot-sequence circular dependency that is hard to resolve, we can revert 2b and reconsider. The chosen approach is deliberately minimal so that rollback is cheap.

## Why Not Other Options

Several alternatives were considered before settling on the chosen approach. Each is named here with the specific reasons it was not chosen, so future contributors do not re-litigate decisions without new information.

**Alternative 1: Keep the current small dense array (MAX_PROCESSES = 32).**

*Why considered.* Zero code change. Already verified. Well-understood.

*Why rejected.* Cannot support general-purpose workloads, which is a first-class project goal per [ADR-009](009-purpose-tiers-scope.md). Cannot survive the v1 process count. Sawtooths at phase boundaries. The value of 32 is a scaffolding artifact from the kernel's earliest days, not a deliberate design point.

**Alternative 2: Expanded dense array with compile-time MAX_PROCESSES (e.g., 4096 or 8192).**

*Why considered.* Simple, low-risk, preserves current verification properties.

*Why rejected.* Does not scale across hardware. A compile-time constant has to pick one number for every target machine. 4096 is too few for a datacenter node, too many for a 512 MB embedded board. This forces either multiple kernel builds (violating the single-binary goal in [ADR-009](009-purpose-tiers-scope.md)) or an unsatisfying compromise on one hardware class.

**Alternative 3: Very large compile-time dense array sized to future hardware (MAX_PROCESSES = 65536+).**

*Why considered.* "Effectively unbounded" for any realistic current workload.

*Why rejected.* Preallocated memory cost is significant on small hardware. Violates platform-agnostic aspirations. The chosen approach reaches the same ceiling on hardware that can afford it without penalizing hardware that cannot.

**Alternative 4: Tiered allocation — fixed system table plus growable user region.**

*Why considered.* Strong verification for system services combined with scalable user-process capacity.

*Why deferred, not rejected.* This remains a viable candidate for a future architectural evolution if the chosen approach's ceiling ever becomes a pain point. It is deferred from the current decision because (a) it introduces complexity in process lookup and lifecycle that we do not yet need, (b) it requires designing and verifying the user region's allocation strategy, which is a project in itself, and (c) the chosen approach's boot-time sizing removes most of the pressure that would motivate this option.

**Alternative 5: Full seL4-style object memory with Retype from untyped pool.**

*Why considered.* Strongly aligned with verification-first goals. Eliminates ambient authority structurally via capability-gated Retype. Counting-invariant verification target. Proven in embedded systems.

*Why rejected.* Fragmentation under long-running general-purpose workloads is an unsolved problem with no satisfying solution in existing systems. Memory defragmentation in a live kernel is either latency-spiking stop-the-world compaction or permanent background-worker overhead — neither acceptable for a general-purpose OS. seL4 avoids the problem by targeting workloads that reboot frequently and have predictable object counts; CambiOS's general-purpose aspirations per [ADR-009](009-purpose-tiers-scope.md) do not get that dodge. Not proven as a general-purpose OS substrate in any public deployment. The chosen approach preserves most of object memory's benefits (bounded memory, verification-friendly, capability-gated creation, dedicated region for kernel objects) without introducing the fragmentation risk. Remains a candidate for a superseding ADR if future work reveals a satisfying fragmentation solution.

**Alternative 6: Capability-gated process creation (structural), independent of allocation mechanism.**

*Why considered.* Fixes ambient authority without touching allocation.

*Why adopted as part of the chosen solution.* This is the zero-trust improvement we need regardless of how memory is allocated. The chosen approach includes it: a process cannot be created without the caller holding a `create_process` capability.

**Alternative 7: Redox-style heap-allocated process tree.**

*Why considered.* Scales to general-purpose workloads without a fixed cap.

*Why rejected.* The kernel heap allocator is itself in the verification target. Variable-length heap-allocated collections are harder to verify than fixed arrays. CambiOS's verification-first posture makes this an unacceptable trade.

**Alternative 8: Linux-style PID bitmap plus slab allocator.**

*Why considered.* Industry-proven, scales to millions of processes, mature tooling.

*Why rejected.* Same verification objection as Redox-style, plus additional complexity. Linux's scale is a distraction — CambiOS's v1 targets do not need tens of thousands of processes per CPU.

**Alternative 9: Fuchsia-style handle table with slab-allocated kernel objects.**

*Why considered.* Fuchsia is the closest prior art — a microkernel OS with a handle-to-object model and general-purpose ambitions.

*Why rejected.* Fuchsia's verification story is not as strong as CambiOS aims to be. Its handle table design is capability-ish but not as structurally enforced as CambiOS's capability system intends to be.

**Alternative 10: Hidden formula with a single kernel-internal fraction.**

*Why considered.* An earlier draft of this ADR proposed `num_slots = (available_memory × 0.5%) / bytes_per_slot` as a kernel-internal computation.

*Why rejected.* A hidden formula conflates mechanism and policy. This is harder to verify, harder to adjust, and does not match CambiOS's pattern of "kernel provides mechanism, configuration above it provides policy." Subsequent drafts introduced explicit policy fields, eventually arriving at the memory-budget formulation in the chosen approach.

**Alternative 11: Tables allocated from the kernel heap.**

*Why considered.* Simplest possible allocation path — use the existing heap allocator, grow the heap if needed.

*Why rejected.* The kernel heap is sized for small, transient allocations. The process and capability tables are large, long-lived, and would dominate the heap's capacity. Growing the heap to absorb them conflates "kernel object storage" with "kernel working memory" — two architecturally different things that production kernels distinguish. The chosen approach separates them by introducing the kernel object table region as a dedicated allocation path, keeping the heap small and focused on its actual purpose.

**Alternative 12: Slot-count-denominated policy (`reference_memory` + `reference_slots`).**

*Why considered.* An earlier draft of this ADR expressed the policy in slot-count terms: "at N bytes of memory, allocate M slots." This read cleanly as operator intent about process capacity.

*Why rejected.* The operator declares a slot count without knowing how much memory those slots will consume, because per-slot overhead is kernel-internal. An upgrade that increases per-slot size silently grows memory consumption while the slot count stays the same. Expressing the policy in memory-budget terms (the chosen approach) makes the memory cost visible and the slot count a derived value — both the operator and the verifier can reason from first principles about what will actually be committed.

## Open Problems

The chosen approach resolves the four problems in this ADR's Problem section. It does not resolve every problem CambiOS will face at scale. This section enumerates the known-unsolved parts so future contributors do not have to discover them under pressure.

**Problem 1: Default tier policies are initial values, not final.**

The `TableSizingPolicy` values shown in the Decision section for each tier are starting points chosen from estimated workload density. Whether the defaults are right depends on what each tier's deployments actually run. The values are one-line edits in the tier configuration and can be adjusted when real workload data exists. The chosen approach does not commit to specific numbers for each tier — it commits to "tier-declared memory-budget policy applied at boot."

**Problem 2: Per-process state growth shifts the binding constraint.**

As the kernel evolves and per-process state grows, `SLOT_OVERHEAD` grows, and the number of slots that fit in a given budget shrinks. The chosen approach handles this *automatically* — the budget stays the same, the slot count falls — which is the right behavior because memory consumption stays bounded. However, if per-slot overhead grows substantially, the binding constraint shifts from `max_slots` to `ram_budget_ceiling`, and operators may need to raise the ceiling to maintain the same effective slot capacity. This is tracked as a future tuning concern, not a structural problem. The kernel logs the binding constraint at boot, so the shift is visible.

**Problem 3: Verification tooling confirmation.**

The claim that "boot-time constant is as verification-friendly as a compile-time constant" is plausible but unconfirmed. Most formal verification tools handle "runtime value set once at init, never changed" cleanly. The chosen approach's axiom-style policy (five fields, two clamps, arithmetic over policy axioms and a compile-time constant) is additionally simpler to prove than a formula-based approach. However, CambiOS has not yet committed to a specific verifier, and different tools have different support for this pattern.

Before committing this approach to code, a proof sketch should confirm that the chosen verifier treats boot-time axioms cleanly and can reason about a slice-backed table whose base address is determined at init. If it cannot, we re-evaluate — either switch to a compile-time constant (reintroducing the hardware-range problem) or pick a different verification tool.

**Problem 4: Policy of who holds the process-creation capability.**

The chosen approach makes the mechanism clean: a capability is required, the check is structural. The *policy* of which processes hold the capability, how delegation works, whether children inherit creation authority, and under what circumstances the policy service can revoke it — these are policy questions, not mechanism questions. They are properly the domain of [ADR-006](006-policy-service.md) (policy service) and will be answered in Wave 4.

Until the policy service exists, the interim behavior is: the bootstrap Principal holds `CreateProcess`. Init holds it when init exists. Boot modules loaded at boot have it implicitly via the bootstrap Principal's delegation. No other processes have it. This matches the current de-facto behavior and does not introduce new policy.

**Problem 5: Debug story for large process counts.**

At the upper end of the chosen approach's scaling (tens of thousands of slots), full kernel state dumps are impractical. Shell commands like `ps` or `cap list` need pagination. This is a tooling problem, not a kernel problem, but it is a cost of the expanded sizing. Not a blocker for v1.

**Problem 6: Zombie accumulation.**

Dense arrays are stable in layout over time, but zombie processes (terminated but not yet fully reaped) still hold slots until cleanup runs. Without aggressive reaping — which the current kernel does partially, per [STATUS.md](../../STATUS.md)'s "Process lifecycle cleanup is partial" known issue — a long-running system could accumulate zombies. The chosen approach does not make this worse, but it does make the problem *less visible* (you hit it later on larger machines), which is a subtle risk. Fixing zombie reaping is tracked separately and is prerequisite for long-running general-purpose operation.

**Problem 7: Per-process capability cap revisit.**

The current per-process capability cap of 32 is a scaffolding artifact from the earliest days of the kernel. Wave 2d (channels), Wave 3 (audit subscription), and Wave 4 (policy service) will all add to the per-process capability count. 32 will get tight quickly. This ADR does not fix it, but it names the issue as something Wave 2 should revisit in a companion commit.

**Problem 8: Interaction with channels (Wave 2d).**

Channels are kernel objects. Under the chosen approach, channel allocation should use the same `TableSizingPolicy` pattern and its own dedicated region — a separate policy instance for channels, declared in the tier configuration alongside the process-table policy, with its own `min_slots`, `max_slots`, `ram_budget_ppm`, `ram_budget_floor`, and `ram_budget_ceiling` values, and its own region allocated from the frame allocator at init. [ADR-005](005-ipc-primitives-control-and-bulk.md) currently describes channels as if they have their own allocation story; under this ADR, they inherit the table-sizing-policy + dedicated-region pattern. ADR-005 should be updated when channels are implemented to align with this decision. This is a Wave 2d task, not a prerequisite of this ADR.

**Problem 9: ProcessId stability under slot reuse.**

A `ProcessId` in CambiOS is currently the slot index of a process in the process table. When a process exits and its slot becomes free, a future process allocated to the same slot reuses the same `ProcessId`. This has a subtle failure mode: stale references to the old `ProcessId` — stored in parent/child relationships, capability grants, audit log entries, debug dumps — now point at the new process, and operations that follow them silently target the wrong target. At the current kernel's low process counts and slow churn the risk is small; as `num_slots` scales up under this ADR and process churn increases (build systems, PE-compat sandboxes, helper processes), the risk grows.

The standard fix is to separate slot index from stable process identity by adding a generation counter to each slot, incremented on reuse. `ProcessId` becomes a `(slot_index, generation)` pair; every dereference compares both fields; a stale reference whose generation no longer matches the current slot occupant fails the lookup and returns an error rather than targeting the wrong process.

This ADR commits to introducing the generation counter as part of Wave 2c, alongside the `CapabilityHandle` refactor. Wave 2a lands the boot-time-sized tables; Wave 2b lands the authority check; Wave 2c lands the generation counter and the handle refactor together on a stable allocator foundation. Adding the generation counter earlier would expand Wave 2a's scope; adding it later risks it being forgotten or arriving after workloads that generate meaningful slot churn.

## Cross-References

- **[ADR-000](000-zta-and-cap.md)** — Capability foundations. This ADR extends the capability system with a new kind (`CreateProcess`) and uses the existing capability check machinery for structural authority enforcement.
- **[ADR-001](001-smp-scheduling-and-lock-hierarchy.md)** — Lock hierarchy. This ADR does not add new locks; the existing `CAPABILITY_MANAGER(4)` and `PROCESS_TABLE(5)` positions are unchanged.
- **[ADR-005](005-ipc-primitives-control-and-bulk.md)** — IPC primitives (channels). Channels are downstream consumers of this ADR's allocation pattern and its dedicated-region architecture; ADR-005 will be updated when Wave 2d implements channels.
- **[ADR-006](006-policy-service.md)** — Policy service. The policy of who holds `CreateProcess` is mediated by the policy service when it lands in Wave 4. This ADR provides the mechanism; ADR-006 decides the policy.
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Capability revocation. Wave 1 landed the revocation primitive used here for process-exit cleanup. This ADR does not change revocation mechanics.
- **[ADR-009](009-purpose-tiers-scope.md)** — Purpose, deployment tiers, and scope boundaries. This ADR depends on ADR-009 for the hardware floors that establish the hardware range this ADR's allocation model serves. This ADR also inherits ADR-009's "single kernel binary across tiers" commitment.
- **[CLAUDE.md § Lock Ordering](../../CLAUDE.md#lock-ordering)** — Lock hierarchy reference. Unchanged by this ADR.
- **[CLAUDE.md § Memory Layout](../../CLAUDE.md#memory-layout)** — Memory layout reference. This ADR adds the kernel object table region as a new entry in the memory layout, distinct from the kernel heap.
- **[CLAUDE.md § Formal Verification](../../CLAUDE.md#formal-verification-non-negotiable-constraint)** — Verification posture. This ADR's Verification Stance section defends the claim that boot-time-sized tables with dedicated-region storage preserve the verification properties the posture requires.
- **[STATUS.md](../../STATUS.md)** — Implementation status. This ADR's Wave 2 sub-waves will update STATUS.md as they land.
- **[ASSUMPTIONS.md](../../ASSUMPTIONS.md)** — Numeric bounds catalog. This ADR adds rows for the tier policies (`TIER1_POLICY`, `TIER2_POLICY`, `TIER3_POLICY`) as TUNING entries. The existing `MAX_PROCESSES` row is removed as the constant itself is removed.

## See Also in CLAUDE.md

When this ADR is implemented, the following CLAUDE.md sections should be updated:

- **"Current state"** paragraph — note that the process table and capability table are boot-time-sized from a tier-declared memory-budget policy and stored in a dedicated kernel object table region, and cite this ADR for the rationale.
- **"Memory Layout"** section — add the kernel object table region as a new entry with its allocation mechanism (frame allocator), its mapping (HHDM), and its lifetime (kernel-lifetime). Update the per-process memory layout description to reflect that `num_slots` is computed at boot from the tier policy rather than fixed at compile time.
- **"Syscall Numbers"** — no new syscall numbers; the `create_process` authority check is internal to the existing process creation path.
- **"Required Reading by Subsystem"** — add a new row for "Process or capability allocation / table sizing" pointing to this ADR.
- **"Post-Change Review Protocol"** — Step 8 should note that changes to per-process state (new fields in `ProcessDescriptor`, `ProcessCapabilities`, etc) may require revisiting the default tier policies because `SLOT_OVERHEAD` has changed, which shifts how many slots fit in a given budget.

## Divergence

Implementation divergences from the original plan, documented here so the ADR doesn't silently become fiction.

**Phase 3.2b — authority check at call site, not inside `create_process` (2026-04-12).**
The ADR planned for `ProcessTable::create_process` to gain a `creator_principal` parameter and perform the authority check internally. Implementation placed the check at the syscall boundary (`handle_spawn`) instead, keeping ProcessTable focused on allocation. Cleaner separation of concerns — the check lives where both the capability manager and process table locks are available, avoiding a circular dependency.

**Phase 3.2c — `CapabilityHandle` refactor deferred (2026-04-12).**
The ADR planned for Phase 3.2c to refactor `SYS_REVOKE_CAPABILITY` from two args `(target_pid, endpoint_id)` to a single `CapabilityHandle`. During implementation, analysis showed that packing a `CapabilityHandle` into u64 requires truncating the 32-bit generation counter (from the new u64 `ProcessId`) to 16 bits, creating a theoretical false-match gap that formal verification cannot dismiss. The generation counter in `ProcessId` already provides full stale-reference protection for the two-arg interface — the handle packaging was cosmetic, not a safety improvement. Implementing a truncated handle now would create rework when the proper solution (kernel-side handle table with no truncation) lands in Phase 3.4 alongside the policy service. The `CapabilityHandle` refactor is deferred to Phase 3.4, where the policy service provides a real consumer and the handle table can be designed once, correctly.

**Phase 3.2c — `ProcessId` widened to u64 (2026-04-12).**
The ADR's Open Problem 9 described `ProcessId` becoming a `(slot_index, generation)` pair but did not specify the width. The original plan considered u32 encoding `(u16 slot, u16 generation)`, but this creates a hard ceiling at 65536 for both slot index and generation — Tier 3's `max_slots` is exactly 65536, leaving zero headroom. `ProcessId` was implemented as u64 with `(u32 slot, u32 generation)`, giving ~4 billion of each. Syscall args are already u64, so no ABI change. Cost: 4 extra bytes per ProcessId storage, negligible.
