// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

// Set `--cfg fuzzing` so the audit emit at src/ipc/capability.rs:696
// (`#[cfg(not(any(test, fuzzing)))]`) is compiled out. The audit path
// would otherwise pull crate::audit and crate::scheduler into the
// proof crate, requiring the full kernel dependency graph.

fn main() {
    println!("cargo:rustc-cfg=fuzzing");
    println!("cargo:rerun-if-changed=build.rs");
}
