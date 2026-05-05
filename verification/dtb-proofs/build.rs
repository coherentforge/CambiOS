// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

// Set `--cfg fuzzing` so the `populate()` entry point and its
// `super::{BootInfo, MemoryRegion, MemoryRegionKind}` import in
// src/boot/riscv.rs (`#[cfg(not(any(test, fuzzing)))]`) are compiled
// out. The kernel's BootInfo machinery would otherwise pull
// `crate::boot::install` and friends into the proof crate, requiring
// the full kernel dependency graph.

fn main() {
    println!("cargo:rustc-cfg=fuzzing");
    println!("cargo:rerun-if-changed=build.rs");
}
