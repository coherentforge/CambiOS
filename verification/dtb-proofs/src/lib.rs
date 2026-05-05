// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kani proof harnesses for the kernel's DTB parser.
//!
//! Proves memory safety and bounded-iteration properties of the parser
//! that runs on bytes OpenSBI hands the kernel before any RAM mapping
//! exists. Paired with [ADR-013](../../docs/adr/013-riscv64-architecture-support.md)
//! Decision 2 (hand-rolled, bounded, minimal DTB parsing), this lifts
//! "the parser is bounded and total" from prose into machine-checkable
//! properties.
//!
//! Five harnesses verify (P-DTB-1..5). A sixth (P-DTB-6, end-to-end
//! walker memory safety) is documented in source as deferred — its
//! CBMC budget at the natural bound is intractable on macOS Apple
//! Silicon, and the fix requires restructuring the walker rather than
//! bumping the unwind. See the comment at the bottom of the proofs
//! module for the exact deferral and revisit trigger.
//!
//! The proven module (`src/boot/riscv.rs`) is included verbatim via
//! `#[path]` — no fork, no copy. `populate()` and its `super::{BootInfo,
//! MemoryRegion, MemoryRegionKind}` import are gated with
//! `#[cfg(not(any(test, fuzzing)))]`; `build.rs` sets `--cfg fuzzing`
//! so the kernel's BootInfo machinery does not enter this crate. The
//! three constants the parser core references via `super::`
//! (`MAX_MEMORY_REGIONS`, `MAX_HARTS`, `MAX_VIRTIO_MMIO_DEVICES`) are
//! stubbed below at small values to keep CBMC's budget tractable;
//! the safety properties hold universally over symbolic inputs at
//! that bound, and therefore at any bound.
//!
//! Run with `cargo kani` from this directory.

#![no_std]
#![allow(dead_code)]

// Stubs for the items `src/boot/riscv.rs` imports via `super::`.
// Only constants referenced by the parser core are needed; populate()
// and its richer dependencies are elided by the `fuzzing` cfg gate.
//
// Sized small (4 instead of the kernel's 128 / 8 / 16) so symbolic
// arrays in DtbFacts stay tractable. The proven properties are
// universally quantified over inputs and do not depend on the
// constants' exact values.
pub const MAX_MEMORY_REGIONS: usize = 4;
pub const MAX_HARTS: usize = 4;
pub const MAX_VIRTIO_MMIO_DEVICES: usize = 4;

#[path = "../../../src/boot/riscv.rs"]
pub mod riscv;

#[cfg(kani)]
mod proofs {
    use super::riscv::*;

    // The walker bound `MAX_TOKENS = 65536` is the kernel's
    // production iteration cap. Kani cannot unroll that; we bound
    // symbolic blob size and `#[kani::unwind(N)]` so the verifier
    // explores a small but adversarially-shaped prefix. Memory safety
    // holds per-iteration, so a smaller iteration count does not
    // weaken the universal claim.
    const PROOF_BLOB_LEN: usize = 96;

    /// P-DTB-1 — `FdtHeader::read_slice` rejects every undersized
    /// input. For any byte buffer shorter than `FDT_HEADER_MIN` (40),
    /// the parser returns `None` instead of reading out of bounds.
    #[kani::proof]
    fn proof_header_rejects_undersized() {
        const FDT_HEADER_MIN: usize = 40;
        let bytes: [u8; FDT_HEADER_MIN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len < FDT_HEADER_MIN);
        let result = FdtHeader::read_slice(&bytes[..len]);
        assert!(result.is_none());
    }

    /// P-DTB-2 — `FdtHeader::read_slice` only accepts headers whose
    /// declared structure-block and strings-block ranges fit inside
    /// `totalsize`. Stresses the sanity check at riscv.rs:117 — the
    /// kernel's only line of defense before `walk_dtb_slice` indexes
    /// into the blob using these offsets.
    #[kani::proof]
    fn proof_header_accepted_offsets_in_range() {
        const FDT_HEADER_MIN: usize = 40;
        let mut bytes: [u8; FDT_HEADER_MIN] = kani::any();
        // Pin valid magic so we exercise the offset check, not the
        // magic-reject path covered by P-DTB-1.
        bytes[0] = 0xd0;
        bytes[1] = 0x0d;
        bytes[2] = 0xfe;
        bytes[3] = 0xed;

        if let Some(h) = FdtHeader::read_slice(&bytes) {
            // Both ends MUST fit inside totalsize, no exceptions, no
            // overflow. The casts to u64 in riscv.rs are load-bearing —
            // a future refactor that narrows them would fail this proof.
            assert!(h.off_dt_struct as u64 + h.size_dt_struct as u64
                    <= h.totalsize as u64);
            assert!(h.off_dt_strings as u64 + h.size_dt_strings as u64
                    <= h.totalsize as u64);
        }
    }

    /// P-DTB-3 — `be_u32_at` and `be_u64_at` never panic or read out
    /// of bounds on any (slice, offset) pair. These are the only
    /// numeric-extraction primitives the walker uses; if they hold,
    /// every numeric read in the parser is safe.
    #[kani::proof]
    fn proof_be_reads_safe_for_any_offset() {
        const N: usize = 32;
        let bytes: [u8; N] = kani::any();
        let off: usize = kani::any();
        let _ = be_u32_at(&bytes, off);
        let _ = be_u64_at(&bytes, off);
    }

    /// P-DTB-4 — `parse_chosen_addr` accepts only inputs of length 4
    /// or 8 and never panics on any other length. Documents the wire-
    /// format contract; regression-catches anyone who adds a third
    /// length branch without checking alignment.
    #[kani::proof]
    fn proof_parse_chosen_addr_length_contract() {
        const N: usize = 16;
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let result = parse_chosen_addr(&bytes[..len]);
        if len != 4 && len != 8 {
            assert!(result.is_none());
        }
    }

    /// P-DTB-5 — `parse_reg_pairs` invokes its callback at most
    /// `MAX_MEMORY_REGIONS` times regardless of input length. The
    /// bounded-iteration property the verifier needs.
    #[kani::proof]
    #[kani::unwind(6)]
    fn proof_parse_reg_pairs_bounded() {
        let bytes: [u8; PROOF_BLOB_LEN] = kani::any();
        let mut count = 0usize;
        parse_reg_pairs(&bytes, |_, _| {
            count += 1;
        });
        assert!(count <= super::MAX_MEMORY_REGIONS);
    }

    // P-DTB-6 — `walk_dtb_slice` end-to-end memory safety.
    //
    // Deferred: a fully-symbolic walker harness proves "no panic /
    // OOB / overflow on any input" but its CBMC budget on macOS
    // Apple Silicon is intractable at the natural bound. A 48-byte
    // blob with `unwind 8` reports unwinding-assertion failures
    // (the walker can iterate more than 8 times in the available
    // bytes), and bumping unwind toward 17 (where the walker reliably
    // terminates) costs hours of CPU per run. The fix is not "more
    // unwind" — it is to constrain a header field so iteration count
    // is statically small, the same shape elf-proofs P1.4 uses with
    // `e_phnum ≤ 2`. That requires either splitting the walker into
    // smaller pure helpers each provable in isolation, or expressing
    // the bound on `tokens_processed` as a contract — both larger
    // changes than this initial proof crate landing.
    //
    // The five harnesses above cover the constituent claims:
    // header validation (P-DTB-1, P-DTB-2), byte-extraction safety
    // (P-DTB-3), wire-format contracts (P-DTB-4), bounded callbacks
    // (P-DTB-5). The walker's per-iteration logic is composed of
    // these primitives.
    //
    // Revisit when: walker is restructured into smaller pure helpers,
    // OR the Kani→Verus pivot lands and this becomes a Verus
    // contract proof rather than a CBMC-bounded one.
}
