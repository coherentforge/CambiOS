// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kani proof harnesses for the kernel's `BuddyAllocator`.
//!
//! These proofs reuse `src/memory/buddy_allocator.rs` via `#[path]`
//! inclusion, so the proven code is exactly what the kernel compiles.
//!
//! Run with `cargo kani` from this directory. Kani uses its own bundled
//! nightly toolchain (independent of the kernel's `rust-toolchain.toml`)
//! and a CBMC-based bounded model checker under the hood.

#[path = "../../../src/memory/buddy_allocator.rs"]
pub mod buddy_allocator;

#[cfg(kani)]
mod proofs {
    use super::buddy_allocator::*;

    /// Property: `free()` must reject any offset inside the reserved prefix.
    ///
    /// Generalizes `test_free_rejects_offset_in_reserved_prefix` from three
    /// hand-picked offsets (0, 16, 1008) to **all** offsets in the reserved
    /// range, for **all** prefix sizes in [16, 256] bytes. Bounded small for
    /// the first proof so the loop unrolling in `mark_range` (up to 16
    /// iterations at this bound) terminates fast.
    #[kani::proof]
    #[kani::unwind(17)]
    fn proof_free_rejects_reserved_prefix() {
        let reserved_bytes: usize = kani::any();
        kani::assume(reserved_bytes >= 16 && reserved_bytes <= 256);

        let mut allocator = BuddyAllocator::new_with_reserved_prefix(reserved_bytes);

        let offset: usize = kani::any();
        kani::assume(offset < reserved_bytes);

        assert!(
            !allocator.free(offset),
            "free must reject any offset inside the reserved prefix"
        );
    }
}
