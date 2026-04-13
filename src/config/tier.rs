// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Deployment tier configuration and boot-time table sizing policy.
//!
//! Per [ADR-008], the kernel computes the number of process/capability
//! table slots at boot from three inputs:
//!
//! 1. The **tier policy** (a [`TableSizingPolicy`]), selected at build
//!    time by the `CAMBIOS_TIER` environment variable (see `build.rs`).
//! 2. The **available RAM** at boot, measured from the Limine memory
//!    map and passed into [`init_num_slots`].
//! 3. The compile-time constant [`SLOT_OVERHEAD`], computed from
//!    `size_of::<ProcessDescriptor>() + size_of::<ProcessCapabilities>()`.
//!
//! The computation is a pure function: [`num_slots_from`]. It is a
//! `const fn` so the verifier can reason about it symbolically — the
//! five policy fields are axioms, `SLOT_OVERHEAD` is a compile-time
//! constant, and the two clamps are simple inequalities.
//!
//! The result is stored in a single `static AtomicUsize`
//! ([`NUM_SLOTS`]) at boot init and read by everything downstream via
//! [`num_slots`]. Before [`init_num_slots`] has been called, `num_slots`
//! returns 0 — callers that read it before boot init is complete are
//! bugs.
//!
//! [ADR-008]: ../../docs/adr/008-boot-time-sized-object-tables.md

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::ipc::capability::ProcessCapabilities;
use crate::process::ProcessDescriptor;

// ============================================================================
// Build-time tier selection — exclusivity check
// ============================================================================
//
// `build.rs` emits exactly one of `--cfg tier1`, `--cfg tier2`, or
// `--cfg tier3`, defaulting to `tier3` when `CAMBIOS_TIER` is unset. The
// checks below catch the impossible cases: zero tiers or multiple
// tiers. If either fires at compile time, `build.rs` is broken.

#[cfg(not(any(tier1, tier2, tier3)))]
compile_error!(
    "no tier selected — build.rs should default to tier3 when CAMBIOS_TIER is unset. \
     Check that build.rs is being picked up and that cargo is re-running it."
);

#[cfg(any(all(tier1, tier2), all(tier1, tier3), all(tier2, tier3)))]
compile_error!(
    "exactly one tier must be selected — build.rs should emit at most one --cfg flag."
);

// ============================================================================
// TableSizingPolicy
// ============================================================================

/// A deployment tier's boot-time table sizing policy.
///
/// The policy declares how to compute `num_slots` from the available
/// RAM at boot. See [ADR-008] § Decision for the mathematics and
/// [`num_slots_from`] for the computation.
///
/// The five fields are treated as *axioms* by the verifier: they come
/// from the tier configuration, not from runtime state, and the
/// verifier reasons about them symbolically via the two clamps.
///
/// [ADR-008]: ../../docs/adr/008-boot-time-sized-object-tables.md
#[derive(Debug, Clone, Copy)]
pub struct TableSizingPolicy {
    /// Minimum number of slots — floor regardless of RAM budget.
    /// Guarantees the kernel is usable even on the hardware floor of
    /// the tier.
    pub min_slots: u32,

    /// Maximum number of slots — ceiling regardless of RAM budget.
    /// Prevents unbounded slot count on enormous hardware. The operator
    /// can raise this in a custom tier configuration if the default is
    /// too restrictive for their workload.
    pub max_slots: u32,

    /// Fraction of RAM to budget for the object tables, in parts per
    /// million. For example `15_000` = 1.5%. Converted to a byte count
    /// via `available_memory_bytes * ram_budget_ppm / 1_000_000`.
    pub ram_budget_ppm: u32,

    /// Minimum byte budget — floor regardless of available RAM.
    /// Guarantees the tables have enough room on small deployments.
    pub ram_budget_floor: u64,

    /// Maximum byte budget — ceiling regardless of available RAM.
    /// Prevents the tables from consuming an unreasonable fraction of
    /// RAM on large deployments, and forms the backstop against
    /// per-slot-overhead growth shifting the binding constraint.
    pub ram_budget_ceiling: u64,
}

// ============================================================================
// SLOT_OVERHEAD — compile-time per-slot byte count
// ============================================================================

/// HARDWARE-ish: per-slot overhead computed from the in-kernel process
/// and capability structures. Not "hardware" in the ABI sense, but also
/// not a tuning knob — this is whatever the compiler says today based
/// on `ProcessDescriptor` and `ProcessCapabilities` layout, plus some
/// padding for future per-process state.
///
/// When a new field lands in either struct, `SLOT_OVERHEAD` changes
/// automatically, which shifts how many slots fit in a given budget.
/// ADR-008 § Post-Change Review notes this explicitly: changes to
/// per-process state may require revisiting the tier defaults.
///
/// The extra `+ 256` is a conscious padding: it gives tier policies ~4×
/// headroom against per-field growth so the first few Phase 3 additions
/// (audit subscription, channel handles, policy-service capability) do
/// not immediately force a policy retune.
pub const SLOT_OVERHEAD: usize = core::mem::size_of::<ProcessDescriptor>()
    + core::mem::size_of::<ProcessCapabilities>()
    + 256;

// ============================================================================
// Per-tier policies
// ============================================================================
//
// Defaults from ADR-008 § Decision. Documented in ASSUMPTIONS.md § Tier
// policies with replacement criteria.

/// TUNING: Tier 1 (CambiOS-Embedded) default policy.
/// 1.5% of RAM, clamped 2–8 MiB, for 32–256 slots.
pub const TIER1_POLICY: TableSizingPolicy = TableSizingPolicy {
    min_slots: 32,
    max_slots: 256,
    ram_budget_ppm: 15_000,
    ram_budget_floor: 2 * 1024 * 1024,
    ram_budget_ceiling: 8 * 1024 * 1024,
};

/// TUNING: Tier 2 (CambiOS-Standard, no AI) default policy.
/// 2% of RAM, clamped 16–64 MiB, for 128–4096 slots.
pub const TIER2_POLICY: TableSizingPolicy = TableSizingPolicy {
    min_slots: 128,
    max_slots: 4096,
    ram_budget_ppm: 20_000,
    ram_budget_floor: 16 * 1024 * 1024,
    ram_budget_ceiling: 64 * 1024 * 1024,
};

/// TUNING: Tier 3 (CambiOS-Full) default policy.
/// 3% of RAM, clamped 64–512 MiB, for 256–65536 slots.
pub const TIER3_POLICY: TableSizingPolicy = TableSizingPolicy {
    min_slots: 256,
    max_slots: 65536,
    ram_budget_ppm: 30_000,
    ram_budget_floor: 64 * 1024 * 1024,
    ram_budget_ceiling: 512 * 1024 * 1024,
};

// ============================================================================
// ACTIVE_POLICY — the compile-time selected tier
// ============================================================================

/// The `TableSizingPolicy` the kernel was compiled for. Exactly one of
/// the three tier cfgs is set per build; this constant binds to that
/// tier's policy.
#[cfg(tier1)]
pub const ACTIVE_POLICY: TableSizingPolicy = TIER1_POLICY;
#[cfg(tier2)]
pub const ACTIVE_POLICY: TableSizingPolicy = TIER2_POLICY;
#[cfg(tier3)]
pub const ACTIVE_POLICY: TableSizingPolicy = TIER3_POLICY;

/// The name of the compiled-in tier, for boot logs and diagnostics.
#[cfg(tier1)]
pub const ACTIVE_TIER_NAME: &str = "tier1";
#[cfg(tier2)]
pub const ACTIVE_TIER_NAME: &str = "tier2";
#[cfg(tier3)]
pub const ACTIVE_TIER_NAME: &str = "tier3";

// ============================================================================
// Pure sizing computation
// ============================================================================

/// Why this constant is here: `u64::clamp` is not a `const fn` on
/// stable Rust, so the pure `num_slots_from` function can't call it.
#[inline]
const fn clamp_u64(value: u64, lo: u64, hi: u64) -> u64 {
    if value < lo {
        lo
    } else if value > hi {
        hi
    } else {
        value
    }
}

#[inline]
const fn clamp_u32(value: u32, lo: u32, hi: u32) -> u32 {
    if value < lo {
        lo
    } else if value > hi {
        hi
    } else {
        value
    }
}

/// Compute `num_slots` from a policy and an available-memory figure.
///
/// This is the pure function at the heart of ADR-008's sizing model.
/// It is a `const fn` so it can be tested in isolation, reasoned about
/// by a verifier without any hardware state, and optimized into a
/// handful of integer operations at each call site.
///
/// Algorithm:
///
/// 1. `fractional = available_memory_bytes * ram_budget_ppm / 1_000_000`
///    (the notional budget as a fraction of available RAM, using u128
///    intermediate to avoid overflow on unusual inputs).
/// 2. Clamp to `[ram_budget_floor, ram_budget_ceiling]` to get `budget`.
/// 3. `slots_from_budget = budget / SLOT_OVERHEAD`.
/// 4. Clamp to `[min_slots, max_slots]` to get `num_slots`.
///
/// The two clamps map to ADR-008's two failure-mode bounds: the budget
/// clamp prevents runaway memory consumption, the slot clamp prevents
/// runaway slot count.
pub const fn num_slots_from(policy: &TableSizingPolicy, available_memory_bytes: u64) -> u32 {
    // Step 1: compute the raw fractional budget via u128 to avoid overflow.
    let fractional: u128 = (available_memory_bytes as u128)
        .saturating_mul(policy.ram_budget_ppm as u128)
        / 1_000_000;
    // Cap at u64::MAX before downcasting — on pathological inputs
    // the u128 result might exceed u64 range; the clamp would handle
    // that anyway but we also want the intermediate to be representable.
    let budget_raw: u64 = if fractional > u64::MAX as u128 {
        u64::MAX
    } else {
        fractional as u64
    };

    // Step 2: clamp the budget to [floor, ceiling].
    let budget = clamp_u64(budget_raw, policy.ram_budget_floor, policy.ram_budget_ceiling);

    // Step 3: budget -> slot count via SLOT_OVERHEAD.
    // SLOT_OVERHEAD is a compile-time constant; division by it is
    // well-defined and > 0 by construction (every slot has real state).
    let slots_from_budget_u64 = budget / (SLOT_OVERHEAD as u64);

    // Downcast to u32 for the final clamp. On realistic hardware this
    // never saturates (max_slots is a u32 ceiling), but we clamp
    // explicitly for verifier clarity.
    let slots_from_budget: u32 = if slots_from_budget_u64 > u32::MAX as u64 {
        u32::MAX
    } else {
        slots_from_budget_u64 as u32
    };

    // Step 4: clamp to [min_slots, max_slots].
    clamp_u32(slots_from_budget, policy.min_slots, policy.max_slots)
}

// ============================================================================
// Binding constraint diagnostics
// ============================================================================

/// Which clamp fired in the `num_slots_from` computation, if any.
///
/// Emitted in the kernel boot log so operators can see at a glance
/// whether they've hit a policy ceiling and whether the binding is
/// slot-count or RAM-budget. Per ADR-008, this is useful because the
/// binding shifts as `SLOT_OVERHEAD` grows — knowing which clamp is
/// active tells you whether the next per-process-state addition will
/// push the system off a cliff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingConstraint {
    /// Neither clamp fired: the raw fractional budget produced a slot
    /// count within `[min_slots, max_slots]` and the budget itself was
    /// within `[ram_budget_floor, ram_budget_ceiling]`. The policy has
    /// headroom in every direction.
    Unconstrained,
    /// The RAM budget was clamped **up** to `ram_budget_floor`.
    /// Available memory is below the tier's minimum budget.
    BudgetFloor,
    /// The RAM budget was clamped **down** to `ram_budget_ceiling`.
    /// Available memory is above the tier's maximum budget, and the
    /// operator-visible signal is "budget ceiling is the bottleneck".
    BudgetCeiling,
    /// The slot count was clamped **up** to `min_slots`. The RAM
    /// budget was enough to buy some slots but not enough to reach
    /// the tier's floor.
    MinSlots,
    /// The slot count was clamped **down** to `max_slots`. The RAM
    /// budget affords more slots than the tier permits — the slot
    /// ceiling is the bottleneck.
    MaxSlots,
}

impl BindingConstraint {
    /// Human-readable name for the boot log.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unconstrained => "unconstrained",
            Self::BudgetFloor => "budget_floor",
            Self::BudgetCeiling => "budget_ceiling",
            Self::MinSlots => "min_slots",
            Self::MaxSlots => "max_slots",
        }
    }
}

/// Determine which clamp (if any) bound the `num_slots_from` result.
///
/// Runs the same arithmetic as `num_slots_from` but reports whether
/// each clamp fired. The slot clamp takes precedence in the reported
/// result: if both a budget clamp and a slot clamp fired, the slot
/// clamp is reported (because it's the user-facing "you hit the cap"
/// signal), with the budget clamp implicit.
pub const fn binding_constraint_for(
    policy: &TableSizingPolicy,
    available_memory_bytes: u64,
) -> BindingConstraint {
    // Step 1: raw fractional budget.
    let fractional: u128 = (available_memory_bytes as u128)
        .saturating_mul(policy.ram_budget_ppm as u128)
        / 1_000_000;
    let budget_raw: u64 = if fractional > u64::MAX as u128 {
        u64::MAX
    } else {
        fractional as u64
    };

    // Step 2: which budget clamp (if any) fired?
    let budget_clamp = if budget_raw < policy.ram_budget_floor {
        Some(BindingConstraint::BudgetFloor)
    } else if budget_raw > policy.ram_budget_ceiling {
        Some(BindingConstraint::BudgetCeiling)
    } else {
        None
    };

    let budget = clamp_u64(budget_raw, policy.ram_budget_floor, policy.ram_budget_ceiling);

    // Step 3: raw slot count.
    let slots_from_budget_u64 = budget / (SLOT_OVERHEAD as u64);
    let slots_from_budget: u32 = if slots_from_budget_u64 > u32::MAX as u64 {
        u32::MAX
    } else {
        slots_from_budget_u64 as u32
    };

    // Step 4: which slot clamp (if any) fired? Slot clamp takes
    // precedence over budget clamp in the reported result.
    if slots_from_budget < policy.min_slots {
        return BindingConstraint::MinSlots;
    }
    if slots_from_budget > policy.max_slots {
        return BindingConstraint::MaxSlots;
    }

    match budget_clamp {
        Some(c) => c,
        None => BindingConstraint::Unconstrained,
    }
}

// ============================================================================
// Runtime num_slots — set once at boot, read lock-free thereafter
// ============================================================================

/// The runtime-computed slot count for the process and capability
/// tables. Written once in [`init_num_slots`] during kernel boot, read
/// lock-free everywhere else via [`num_slots`].
///
/// Before `init_num_slots` is called, this reads as 0. Any caller that
/// reads it before boot init is complete has a bug — the kernel object
/// table region has not been allocated yet, so there is no valid table
/// storage at that point.
static NUM_SLOTS: AtomicUsize = AtomicUsize::new(0);

/// Initialize the runtime slot count from the active tier policy and
/// the available-memory figure (usually the sum of USABLE regions from
/// the Limine memory map).
///
/// Must be called exactly once, during kernel boot, before the kernel
/// object table region is allocated and before anything reads
/// `num_slots()`. Returns the computed slot count for the caller's
/// convenience.
pub fn init_num_slots(available_memory_bytes: u64) -> usize {
    let n = num_slots_from(&ACTIVE_POLICY, available_memory_bytes) as usize;
    NUM_SLOTS.store(n, Ordering::Release);
    n
}

/// Override the runtime slot count after a post-computation cap has
/// been applied (e.g. the contiguous-run-fitting heuristic in
/// `init_kernel_object_tables`). Must be called after `init_num_slots`
/// and before anything reads `num_slots()`.
pub fn init_num_slots_override(n: usize) {
    NUM_SLOTS.store(n, Ordering::Release);
}

/// Read the runtime slot count. Returns 0 before `init_num_slots` has
/// been called (bug indicator: callers should never read this before
/// kernel boot is complete).
#[inline]
pub fn num_slots() -> usize {
    NUM_SLOTS.load(Ordering::Acquire)
}

// ============================================================================
// Tests (host)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: SLOT_OVERHEAD should be > 0 and should include the sum
    /// of the two main per-slot structs plus our padding.
    #[test]
    fn slot_overhead_is_nonzero_and_includes_components() {
        let sum = core::mem::size_of::<ProcessDescriptor>()
            + core::mem::size_of::<ProcessCapabilities>();
        assert!(SLOT_OVERHEAD > 0);
        assert!(SLOT_OVERHEAD >= sum);
        assert_eq!(SLOT_OVERHEAD, sum + 256);
    }

    /// Tier 1 policy sanity: bounds are ordered and non-empty.
    #[test]
    fn tier1_policy_bounds_are_sensible() {
        assert!(TIER1_POLICY.min_slots <= TIER1_POLICY.max_slots);
        assert!(TIER1_POLICY.ram_budget_floor <= TIER1_POLICY.ram_budget_ceiling);
        assert!(TIER1_POLICY.ram_budget_ppm > 0);
    }

    #[test]
    fn tier2_policy_bounds_are_sensible() {
        assert!(TIER2_POLICY.min_slots <= TIER2_POLICY.max_slots);
        assert!(TIER2_POLICY.ram_budget_floor <= TIER2_POLICY.ram_budget_ceiling);
        assert!(TIER2_POLICY.ram_budget_ppm > 0);
    }

    #[test]
    fn tier3_policy_bounds_are_sensible() {
        assert!(TIER3_POLICY.min_slots <= TIER3_POLICY.max_slots);
        assert!(TIER3_POLICY.ram_budget_floor <= TIER3_POLICY.ram_budget_ceiling);
        assert!(TIER3_POLICY.ram_budget_ppm > 0);
    }

    /// Tiers are progressively larger: tier1 ⊆ tier2 ⊆ tier3 on the
    /// slot ceiling and budget ceiling axes.
    #[test]
    fn tiers_are_progressively_larger() {
        assert!(TIER1_POLICY.max_slots <= TIER2_POLICY.max_slots);
        assert!(TIER2_POLICY.max_slots <= TIER3_POLICY.max_slots);
        assert!(TIER1_POLICY.ram_budget_ceiling <= TIER2_POLICY.ram_budget_ceiling);
        assert!(TIER2_POLICY.ram_budget_ceiling <= TIER3_POLICY.ram_budget_ceiling);
    }

    // ----- num_slots_from: clamp behavior -----

    #[test]
    fn num_slots_floor_clamps_tiny_memory_to_min_slots() {
        // 1 MiB of RAM is below every tier's ram_budget_floor; the
        // budget clamps up to the floor, and then the slot count is
        // whatever the floor buys (which exceeds max_slots in some
        // cases). Either way, the result is within [min_slots, max_slots].
        let n = num_slots_from(&TIER1_POLICY, 1 * 1024 * 1024);
        assert!(n >= TIER1_POLICY.min_slots);
        assert!(n <= TIER1_POLICY.max_slots);
    }

    #[test]
    fn num_slots_ceiling_clamps_huge_memory() {
        // 1 TiB of RAM against tier1's 8 MiB budget ceiling: budget is
        // clamped down to 8 MiB, slots are capped at tier1.max_slots.
        let n = num_slots_from(&TIER1_POLICY, 1024 * 1024 * 1024 * 1024);
        assert_eq!(n, TIER1_POLICY.max_slots);
    }

    #[test]
    fn num_slots_zero_memory_stays_at_min_slots() {
        // Zero available RAM: budget starts at 0, clamps up to
        // ram_budget_floor, and then the slot count is clamped up to
        // at least min_slots.
        assert_eq!(
            num_slots_from(&TIER3_POLICY, 0),
            clamp_u32(
                (TIER3_POLICY.ram_budget_floor / SLOT_OVERHEAD as u64) as u32,
                TIER3_POLICY.min_slots,
                TIER3_POLICY.max_slots,
            )
        );
    }

    // ----- num_slots_from: realistic memory sizes per ADR-008 -----

    /// 256 MB — typical Tier 1 lower-end embedded target.
    #[test]
    fn tier1_at_256_mb() {
        let n = num_slots_from(&TIER1_POLICY, 256 * 1024 * 1024);
        assert!(n >= TIER1_POLICY.min_slots);
        assert!(n <= TIER1_POLICY.max_slots);
    }

    /// 4 GB — typical low-end Tier 2 workstation.
    #[test]
    fn tier2_at_4_gb() {
        let n = num_slots_from(&TIER2_POLICY, 4 * 1024 * 1024 * 1024);
        assert!(n >= TIER2_POLICY.min_slots);
        assert!(n <= TIER2_POLICY.max_slots);
    }

    /// 8 GB — common Tier 2/3 developer machine.
    #[test]
    fn tier2_at_8_gb() {
        let n = num_slots_from(&TIER2_POLICY, 8 * 1024 * 1024 * 1024);
        assert!(n >= TIER2_POLICY.min_slots);
        assert!(n <= TIER2_POLICY.max_slots);
    }

    /// 32 GB — high-end Tier 3 workstation (e.g. Dell 3630 target at
    /// 16 GB gets scaled up for headroom testing).
    #[test]
    fn tier3_at_32_gb() {
        let n = num_slots_from(&TIER3_POLICY, 32u64 * 1024 * 1024 * 1024);
        assert!(n >= TIER3_POLICY.min_slots);
        assert!(n <= TIER3_POLICY.max_slots);
    }

    /// 1 TB — sanity test that pathological RAM doesn't break the math.
    ///
    /// After Phase 3.2a Item 1 (BuddyAllocator moved to per-heap storage),
    /// `SLOT_OVERHEAD` shrunk from ~22 KB to ~2 KB. Tier3's 512 MiB
    /// budget ceiling now buys far more slots than `max_slots = 65536`,
    /// so tier3 at large RAM is **slot-bound** (max_slots is the binding
    /// constraint). This is the binding flip the ADR-008 Post-Change
    /// Review note predicted.
    #[test]
    fn tier3_at_1_tb_is_slot_bound() {
        let n = num_slots_from(&TIER3_POLICY, 1024u64 * 1024 * 1024 * 1024);
        assert_eq!(
            n, TIER3_POLICY.max_slots,
            "tier3 at 1 TiB should hit the max_slots ceiling ({}), got {}",
            TIER3_POLICY.max_slots, n
        );
    }

    #[test]
    fn num_slots_is_monotonic_in_memory() {
        // More memory never produces fewer slots. (The clamps can
        // saturate, but never reverse direction.)
        let a = num_slots_from(&TIER3_POLICY, 1 * 1024 * 1024 * 1024);
        let b = num_slots_from(&TIER3_POLICY, 4 * 1024 * 1024 * 1024);
        let c = num_slots_from(&TIER3_POLICY, 16u64 * 1024 * 1024 * 1024);
        assert!(a <= b);
        assert!(b <= c);
    }

    // ----- num_slots() runtime accessor -----

    #[test]
    fn num_slots_reads_zero_before_init() {
        // This test runs in the shared static env with other tests, so
        // we can't guarantee init hasn't been called already. We only
        // check that it returns something >= 0 (trivially true) and
        // that init_num_slots sets a sensible value.
        let _ = num_slots(); // just verify it doesn't panic
    }

    #[test]
    fn init_num_slots_sets_runtime_value() {
        let computed = init_num_slots(4 * 1024 * 1024 * 1024);
        assert_eq!(num_slots(), computed);
        assert!(computed >= ACTIVE_POLICY.min_slots as usize);
        assert!(computed <= ACTIVE_POLICY.max_slots as usize);
    }

    // ----- binding_constraint_for -----

    #[test]
    fn binding_zero_memory_hits_budget_floor() {
        // Zero RAM → fractional=0 → clamped up to ram_budget_floor.
        let b = binding_constraint_for(&TIER3_POLICY, 0);
        // Floor may drive to BudgetFloor or MinSlots depending on
        // whether the floored budget buys enough slots to clear
        // min_slots. For TIER3_POLICY today it clears min_slots so
        // the binding is BudgetFloor.
        assert!(matches!(
            b,
            BindingConstraint::BudgetFloor | BindingConstraint::MinSlots
        ));
    }

    #[test]
    fn binding_huge_memory_hits_slot_ceiling_at_tier3() {
        // 1 TiB on tier3: fractional budget is 30 GiB, clamped down
        // to 512 MiB ceiling. After Item 1 (SLOT_OVERHEAD shrink), the
        // 512 MiB budget buys ~262K slots, well above max_slots (65536).
        // The slot clamp fires: binding is MaxSlots.
        let b = binding_constraint_for(&TIER3_POLICY, 1024u64 * 1024 * 1024 * 1024);
        assert_eq!(b, BindingConstraint::MaxSlots);
    }

    #[test]
    fn binding_huge_memory_hits_slot_ceiling_at_tier1() {
        // Tier1 budget ceiling (8 MiB) divided by SLOT_OVERHEAD
        // (~22.5 KB) is ~364 slots, which exceeds tier1.max_slots (256).
        // So tier1 at large RAM is slot-bound, not budget-bound.
        let b = binding_constraint_for(&TIER1_POLICY, 1024u64 * 1024 * 1024 * 1024);
        assert_eq!(b, BindingConstraint::MaxSlots);
    }

    #[test]
    fn binding_slot_ceiling_shadows_budget_ceiling() {
        // A policy constructed to trigger BOTH clamps: budget ceiling
        // fires AND the resulting slot count exceeds max_slots. The
        // reported binding should be MaxSlots (slot clamp takes
        // precedence in the reported result).
        let policy = TableSizingPolicy {
            min_slots: 1,
            max_slots: 4, // very small cap
            ram_budget_ppm: 1_000_000, // 100% of RAM
            ram_budget_floor: 0,
            ram_budget_ceiling: SLOT_OVERHEAD as u64 * 1_000, // room for 1000 slots
        };
        // 10 TiB of RAM → 10 TiB budget → clamped down to 1000 slots' worth.
        // Budget clamp would fire (BudgetCeiling). Slot count = 1000,
        // which > max_slots (4), so slot clamp also fires. MaxSlots wins.
        let b = binding_constraint_for(&policy, 10u64 * 1024 * 1024 * 1024 * 1024);
        assert_eq!(b, BindingConstraint::MaxSlots);
    }
}
