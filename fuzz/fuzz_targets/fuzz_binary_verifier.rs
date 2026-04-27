// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Fuzz target: binary verifier (DefaultVerifier)
//!
//! Exercises the verify-before-execute security gate with synthetic segments.
//! This tests the verifier logic *independently* of the ELF parser, covering
//! cases that valid ELF parsing would never produce (the adversarial model).
//!
//! Properties that must hold:
//! - W^X: no segment both writable and executable → Allow
//! - No segment in kernel space (>= 0x0000_8000_0000_0000) → Allow
//! - No overlapping segments → Allow
//! - Total memory <= 256 MiB → Allow
//! - Entry point within a segment → Allow

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use cambios_core::loader::elf::{ElfBinary, SegmentLoad};
use cambios_core::loader::{BinaryVerifier, DefaultVerifier, VerifyResult};

/// Fuzzer-generated segment with constrained ranges to increase
/// coverage of the verifier's logic branches.
#[derive(Arbitrary, Debug)]
struct FuzzSegment {
    vaddr: u64,
    memsz: u64,
    filesz: u64,
    writable: bool,
    executable: bool,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    entry_point: u64,
    segments: Vec<FuzzSegment>,
}

fuzz_target!(|input: FuzzInput| {
    // Cap segment count to match kernel limit
    let seg_count = input.segments.len().min(16);
    if seg_count == 0 {
        return;
    }

    let segments: Vec<SegmentLoad> = input.segments[..seg_count]
        .iter()
        .map(|s| SegmentLoad {
            vaddr: s.vaddr,
            memsz: s.memsz,
            filesz: s.filesz,
            file_offset: 0,
            writable: s.writable,
            executable: s.executable,
        })
        .collect();

    // Compute load_base and load_size from segments (mirrors analyze_binary)
    let load_base = segments.iter().map(|s| s.vaddr).min().unwrap_or(0);
    let load_end = segments
        .iter()
        .map(|s| s.vaddr.saturating_add(s.memsz))
        .max()
        .unwrap_or(0);

    let metadata = ElfBinary {
        entry_point: input.entry_point,
        load_base,
        load_size: load_end.saturating_sub(load_base),
        num_segments: seg_count as u16,
    };

    let verifier = DefaultVerifier::new();
    let result = verifier.verify(&[], &metadata, &segments);

    // Post-condition checks: if the verifier said Allow, the invariants
    // must actually hold. A failure here is a verifier bypass bug.
    if let VerifyResult::Allow = result {
        // Entry point must be within some segment
        let entry_ok = segments
            .iter()
            .any(|s| input.entry_point >= s.vaddr && input.entry_point < s.vaddr + s.memsz);
        assert!(entry_ok, "Verifier allowed entry point outside all segments");

        for seg in &segments {
            // No W^X violation
            assert!(
                !(seg.writable && seg.executable),
                "Verifier allowed W+X segment"
            );

            // No kernel-space segment
            let seg_end = seg.vaddr.saturating_add(seg.memsz);
            assert!(
                seg.vaddr < 0x0000_8000_0000_0000 && seg_end <= 0x0000_8000_0000_0000,
                "Verifier allowed kernel-space segment"
            );
        }

        // No overlapping segments
        for i in 0..segments.len() {
            for j in (i + 1)..segments.len() {
                let a_end = segments[i].vaddr + segments[i].memsz;
                let b_end = segments[j].vaddr + segments[j].memsz;
                assert!(
                    !(segments[i].vaddr < b_end && segments[j].vaddr < a_end),
                    "Verifier allowed overlapping segments"
                );
            }
        }

        // Total memory within limit
        let total: u64 = segments.iter().map(|s| s.memsz).sum();
        assert!(
            total <= 256 * 1024 * 1024,
            "Verifier allowed excessive memory"
        );
    }
});
