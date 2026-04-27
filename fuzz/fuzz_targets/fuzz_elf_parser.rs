// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Fuzz target: ELF parser
//!
//! Feeds random bytes through the full ELF parsing pipeline:
//! parse_header → analyze_binary → collect_load_segments.
//! Any panic or UB here means an attacker-crafted ELF can crash the kernel.

#![no_main]

use libfuzzer_sys::fuzz_target;

use cambios_core::loader::elf;

fuzz_target!(|data: &[u8]| {
    // Phase 1: header parsing — must not panic on any input
    let header = match elf::parse_header(data) {
        Ok(h) => h,
        Err(_) => return,
    };

    // Phase 2: program header iteration — crafted offsets/counts must not OOB
    for i in 0..header.e_phnum as usize {
        let _ = elf::get_program_header(data, &header, i);
    }

    // Phase 3: full analysis — integer overflow on vaddr + memsz, etc.
    let _ = elf::analyze_binary(data);

    // Phase 4: segment collection — the path that feeds the verifier
    let _ = elf::collect_load_segments(data);
});
