// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Kernel configuration — build-time policy selection.
//!
//! This module holds configuration that is chosen at build time rather
//! than at runtime. Today the only such configuration is the deployment
//! tier (see [`tier`]), which drives boot-time sizing of the kernel
//! object tables.
//!
//! See [ADR-008] (boot-time-sized object tables) and [ADR-009] (tiers
//! and scope) for the architectural rationale.
//!
//! [ADR-008]: ../../docs/adr/008-boot-time-sized-object-tables.md
//! [ADR-009]: ../../docs/adr/009-purpose-tiers-scope.md

pub mod tier;

pub use tier::{
    binding_constraint_for, init_num_slots, num_slots, num_slots_from, BindingConstraint,
    TableSizingPolicy, ACTIVE_POLICY, ACTIVE_TIER_NAME, SLOT_OVERHEAD, TIER1_POLICY,
    TIER2_POLICY, TIER3_POLICY,
};
