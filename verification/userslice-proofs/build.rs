// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

// Mirror the capability-proofs convention: set `--cfg fuzzing` so any
// future `cfg(not(any(test, fuzzing)))`-gated audit / scheduler call
// inside `src/syscalls/user_slice.rs` is compiled out without dragging
// the kernel's full graph into this proof crate. user_slice.rs has no
// such gates today; the flag is inert until it does.

fn main() {
    println!("cargo:rustc-cfg=fuzzing");
    println!("cargo:rerun-if-changed=build.rs");
}
