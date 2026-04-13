// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Build-time tier selection for CambiOS.
//!
//! CambiOS ships as a single kernel binary that is tuned for one of three
//! deployment tiers at build time (see [ADR-009] and [ADR-008]):
//!
//! - `tier1` — CambiOS-Embedded (small, fixed-function deployments)
//! - `tier2` — CambiOS-Standard (typical single-user desktop / workstation)
//! - `tier3` — CambiOS-Full (heavy general-purpose, bare metal, AI workloads)
//!
//! The choice is made via the `CAMBIOS_TIER` environment variable. When
//! unset, the build defaults to `tier3` — every build is a Tier 3 build
//! unless the developer is specifically working on Tier 1 or Tier 2.
//!
//! This script diverges slightly from ADR-008's literal wording ("add
//! Cargo features") in favor of an env-var-driven `--cfg` emit. The
//! intent is preserved: exactly one tier is compiled in per build, the
//! policy is selected at compile time, and a garbage value is a build
//! error. The mechanism is simpler — no Cargo features to forget,
//! automatic default, single place makes the choice.
//!
//! [ADR-008]: docs/adr/008-boot-time-sized-object-tables.md
//! [ADR-009]: docs/adr/009-purpose-tiers-scope.md

fn main() {
    // Register the cfg names so the compiler doesn't warn about unknown
    // `--cfg tierN` flags. Rust 1.80+ requires `rustc-check-cfg` for
    // user-defined cfg identifiers.
    println!("cargo:rustc-check-cfg=cfg(tier1)");
    println!("cargo:rustc-check-cfg=cfg(tier2)");
    println!("cargo:rustc-check-cfg=cfg(tier3)");
    // cargo-fuzz passes --cfg fuzzing via RUSTFLAGS; register it so the
    // compiler doesn't warn about an unknown cfg on nightly.
    println!("cargo:rustc-check-cfg=cfg(fuzzing)");

    // Re-run if the user changes the tier selection.
    println!("cargo:rerun-if-env-changed=CAMBIOS_TIER");

    let tier = std::env::var("CAMBIOS_TIER").unwrap_or_else(|_| "tier3".to_string());

    match tier.as_str() {
        "tier1" | "tier2" | "tier3" => {
            println!("cargo:rustc-cfg={}", tier);
            // The selected tier is reported at kernel boot in the
            // "kernel object table: N slots, ..." log line, so there
            // is no need to print from the build script.
        }
        other => {
            panic!(
                "CAMBIOS_TIER must be one of: tier1, tier2, tier3 (got: {:?}). \
                 Leave unset to default to tier3.",
                other
            );
        }
    }
}
