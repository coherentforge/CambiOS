// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS initrd archive format — a minimal TLV used by the RISC-V
//! boot path to surface signed boot modules to the kernel.
//!
//! # Why a custom format
//!
//! Limine hands x86_64/aarch64 a pre-parsed list of modules directly.
//! RISC-V boots via OpenSBI which only has a single `-initrd` entry
//! point, so we need *some* multi-module container at that entry. cpio
//! would work but its parser (newc magic, null-terminated variable-
//! width fields, 4-byte padding with trailer sentinel) is more surface
//! area than this project needs — and verification transparency (ADR-
//! 013 / CLAUDE.md verification preface) favours a format the kernel
//! can parse in ~40 lines.
//!
//! # Layout (little-endian, 8-byte aligned)
//!
//! ```text
//! +---------------------------------------------------------------+
//! | Archive header (16 bytes)                                     |
//! |  0..8   magic = "CAMBINIT"                                    |
//! |  8..12  version = 1 (u32)                                     |
//! |  12..16 count (u32)                                           |
//! +---------------------------------------------------------------+
//! | Entry 0 header (72 bytes)                                     |
//! |  0..4   data_size (u32)                                       |
//! |  4..8   name_len  (u32, ≤ MAX_MODULE_NAME_LEN = 64)           |
//! |  8..72  name bytes, zero-padded                               |
//! | Entry 0 data (data_size bytes, padded up to 8-byte alignment) |
//! | Entry 1 header (72 bytes)                                     |
//! | Entry 1 data ...                                              |
//! | ...                                                           |
//! +---------------------------------------------------------------+
//! ```
//!
//! Every payload starts at an 8-byte-aligned offset (relative to the
//! archive base), so if the archive itself sits at a page-aligned
//! physical address, each module's `phys_addr` is at least 8-byte
//! aligned — enough for the ELF header reads the loader performs.
//!
//! # Host tool
//!
//! `tools/mkinitrd` writes this exact format. Both ends must move
//! together if the format evolves; the version field is the hook for
//! that.

use super::{MAX_MODULE_NAME_LEN, ModuleInfo};

/// Magic value at archive start: ASCII "CAMBINIT".
pub const ARCHIVE_MAGIC: [u8; 8] = *b"CAMBINIT";

/// Archive format version; bumped on any incompatible layout change.
pub const ARCHIVE_VERSION: u32 = 1;

/// Size of the archive header (magic + version + count).
pub const ARCHIVE_HEADER_SIZE: usize = 16;

/// Size of each entry header (data_size + name_len + fixed name slot).
pub const ENTRY_HEADER_SIZE: usize = 8 + MAX_MODULE_NAME_LEN;

/// Align `n` up to the next multiple of 8.
#[inline]
const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Parse an initrd archive whose bytes are live at `archive_bytes` and
/// whose physical base is `archive_phys`. For each valid entry, call
/// `on_module` with a populated `ModuleInfo`.
///
/// `archive_phys` is added to the byte offset of the entry's data to
/// produce the phys_addr exposed through [`ModuleInfo`] — matching the
/// Limine adapter's phys_addr semantics so the boot_modules registry
/// and the loader treat both archs identically.
///
/// Returns the number of entries successfully parsed. On a format
/// error (bad magic, unsupported version, count exceeds remaining
/// bytes) returns 0 after walking as far as possible — partial
/// archives are rejected whole rather than half-loaded.
///
/// # Bounded iteration
/// The loop terminates after at most `max_entries` iterations and
/// after at most `archive_bytes.len()` bytes consumed, so this
/// function is safe to call even on a malicious archive.
pub fn parse(
    archive_bytes: &[u8],
    archive_phys: u64,
    max_entries: usize,
    mut on_module: impl FnMut(ModuleInfo),
) -> usize {
    if archive_bytes.len() < ARCHIVE_HEADER_SIZE {
        return 0;
    }
    if archive_bytes[0..8] != ARCHIVE_MAGIC {
        return 0;
    }
    let version = u32::from_le_bytes([
        archive_bytes[8],
        archive_bytes[9],
        archive_bytes[10],
        archive_bytes[11],
    ]);
    if version != ARCHIVE_VERSION {
        return 0;
    }
    let count = u32::from_le_bytes([
        archive_bytes[12],
        archive_bytes[13],
        archive_bytes[14],
        archive_bytes[15],
    ]) as usize;

    let bounded_count = count.min(max_entries);
    let mut cursor = ARCHIVE_HEADER_SIZE;
    let mut parsed = 0usize;

    for _ in 0..bounded_count {
        if cursor + ENTRY_HEADER_SIZE > archive_bytes.len() {
            return parsed;
        }
        let data_size = u32::from_le_bytes([
            archive_bytes[cursor],
            archive_bytes[cursor + 1],
            archive_bytes[cursor + 2],
            archive_bytes[cursor + 3],
        ]) as usize;
        let name_len = u32::from_le_bytes([
            archive_bytes[cursor + 4],
            archive_bytes[cursor + 5],
            archive_bytes[cursor + 6],
            archive_bytes[cursor + 7],
        ]) as usize;
        if name_len > MAX_MODULE_NAME_LEN {
            return parsed;
        }

        let name_start = cursor + 8;
        let data_start = cursor + ENTRY_HEADER_SIZE;
        if data_start + data_size > archive_bytes.len() {
            return parsed;
        }

        let mut name_buf = [0u8; MAX_MODULE_NAME_LEN];
        name_buf[..name_len]
            .copy_from_slice(&archive_bytes[name_start..name_start + name_len]);

        on_module(ModuleInfo {
            phys_addr: archive_phys + data_start as u64,
            size: data_size as u64,
            name: name_buf,
            name_len: name_len as u8,
        });
        parsed += 1;

        // Advance past header + data, aligning the next header to 8
        // bytes (the host tool pads explicitly — the kernel mirrors
        // the alignment to stay bug-for-bug compatible).
        cursor = align8(data_start + data_size);
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn build_archive(modules: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&ARCHIVE_MAGIC);
        buf.extend_from_slice(&ARCHIVE_VERSION.to_le_bytes());
        buf.extend_from_slice(&(modules.len() as u32).to_le_bytes());

        for (name, data) in modules {
            let data_size = data.len() as u32;
            let name_len = name.len() as u32;
            buf.extend_from_slice(&data_size.to_le_bytes());
            buf.extend_from_slice(&name_len.to_le_bytes());
            let mut name_field = [0u8; MAX_MODULE_NAME_LEN];
            name_field[..name.len()].copy_from_slice(name.as_bytes());
            buf.extend_from_slice(&name_field);
            buf.extend_from_slice(data);
            while buf.len() % 8 != 0 {
                buf.push(0);
            }
        }
        buf
    }

    #[test]
    fn parse_empty_archive() {
        let archive = build_archive(&[]);
        let mut count = 0;
        let parsed = parse(&archive, 0, 16, |_| count += 1);
        assert_eq!(parsed, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn parse_two_modules() {
        let archive = build_archive(&[
            ("policy", b"policy-elf-bytes"),
            ("shell", b"shell-elf-bytes-longer"),
        ]);
        let mut mods: Vec<ModuleInfo> = Vec::new();
        let parsed = parse(&archive, 0x8f00_0000, 16, |m| mods.push(m));
        assert_eq!(parsed, 2);
        assert_eq!(mods.len(), 2);

        assert_eq!(mods[0].name_bytes(), b"policy");
        assert_eq!(mods[0].size, b"policy-elf-bytes".len() as u64);
        assert_eq!(
            mods[0].phys_addr,
            0x8f00_0000 + (ARCHIVE_HEADER_SIZE + ENTRY_HEADER_SIZE) as u64
        );

        assert_eq!(mods[1].name_bytes(), b"shell");
        assert_eq!(mods[1].size, b"shell-elf-bytes-longer".len() as u64);
        // Module 1's data follows module 0's data + 8-byte align padding.
        let m0_end = mods[0].phys_addr + mods[0].size;
        let expected_m1_start =
            ((m0_end + 7) & !7u64) + ENTRY_HEADER_SIZE as u64;
        assert_eq!(mods[1].phys_addr, expected_m1_start);
    }

    #[test]
    fn reject_bad_magic() {
        let mut archive = build_archive(&[("x", b"data")]);
        archive[0] = 0x00;
        let mut count = 0;
        let parsed = parse(&archive, 0, 16, |_| count += 1);
        assert_eq!(parsed, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn reject_unknown_version() {
        let mut archive = build_archive(&[("x", b"data")]);
        archive[8] = 99; // bump version to unknown value
        let mut count = 0;
        let parsed = parse(&archive, 0, 16, |_| count += 1);
        assert_eq!(parsed, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn truncated_entry_stops_cleanly() {
        let archive = build_archive(&[
            ("one", b"first"),
            ("two", b"second"),
        ]);
        // Chop off the second entry entirely.
        let cutoff = ARCHIVE_HEADER_SIZE
            + ENTRY_HEADER_SIZE
            + b"first".len()
            + 3; // mid-padding
        let truncated = &archive[..cutoff];
        let mut mods: Vec<ModuleInfo> = Vec::new();
        let parsed = parse(truncated, 0, 16, |m| mods.push(m));
        assert_eq!(parsed, 1);
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name_bytes(), b"one");
    }

    #[test]
    fn max_entries_cap_respected() {
        let archive = build_archive(&[
            ("a", b"aa"),
            ("b", b"bb"),
            ("c", b"cc"),
        ]);
        let mut mods: Vec<ModuleInfo> = Vec::new();
        let parsed = parse(&archive, 0, 2, |m| mods.push(m));
        assert_eq!(parsed, 2);
        assert_eq!(mods.len(), 2);
    }
}
