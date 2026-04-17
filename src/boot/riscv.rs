// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Boot adapter for RISC-V (OpenSBI + DTB).
//!
//! Counterpart to [`super::limine`] for the RISC-V boot path. OpenSBI
//! (M-mode firmware, ships with QEMU as `-bios default`) hands the
//! kernel a physical pointer to a Flattened Device Tree (DTB) in
//! register `a1`. This module's job is to walk the DTB, populate a
//! [`super::BootInfo`], and call [`super::install`].
//!
//! Per [ADR-013](../../docs/adr/013-riscv64-architecture-support.md)
//! § Decision 2 the parser is hand-rolled, bounded, and minimal —
//! only reads the nodes the kernel actually needs.
//!
//! ## Phase R-2.b
//!
//! - Walks the structure block with bounded iteration
//! - Finds `/memory@*` nodes and extracts `reg` base/size pairs as
//!   `MemoryRegionKind::Usable`
//! - Adds reservations for OpenSBI, the DTB itself, and the kernel
//!   image so the frame allocator doesn't hand those back out
//!
//! Deferred: reading `#address-cells` / `#size-cells` from each
//! node's parent (we assume the QEMU-virt-standard `<2>`/`<2>` at
//! root scope). `/reserved-memory` walking (we hard-code the two
//! reservations we know about). Boot modules via `/chosen/initrd-*`
//! — Phase R-6.

use super::{BootInfo, MemoryRegion, MemoryRegionKind};

// ============================================================================
// FDT header + tokens
// ============================================================================

/// FDT header magic bytes in big-endian. Every valid DTB starts with this.
const FDT_MAGIC: u32 = 0xd00dfeed;

/// FDT structure block tokens (big-endian u32s).
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

/// SCAFFOLDING: DTB structure-block walk bound — max tokens processed.
/// Why: verification requires bounded iteration; a malicious/corrupt
///      DTB must not loop forever. 64 K tokens is far more than any
///      realistic platform (QEMU virt is a few hundred; real SoCs a
///      few thousand). Memory cost: none (just an iteration limit).
/// Replace when: a real platform's DTB exceeds this. Unlikely; would
///      indicate pathological fragmentation worth investigating.
const MAX_TOKENS: usize = 65536;

/// SCAFFOLDING: node-path nesting depth bound.
/// Why: bounded recursion protection. DTBs in practice have depth ~4
///      ( /cpus/cpu@0/interrupt-controller ). Memory cost: one
///      small integer.
const MAX_DEPTH: usize = 32;

/// Minimum DTB header size (version-17 layout = 40 bytes).
const FDT_HEADER_MIN: usize = 40;

/// FDT header fields we care about. Raw u32s are big-endian on disk;
/// fields here are already converted to native endianness.
#[derive(Clone, Copy, Debug)]
struct FdtHeader {
    totalsize: u32,
    off_dt_struct: u32,
    #[allow(dead_code)]
    off_dt_strings: u32,
    size_dt_struct: u32,
    #[allow(dead_code)]
    size_dt_strings: u32,
}

impl FdtHeader {
    /// Read the FDT header from a physical address. `ptr` must point
    /// at least `FDT_HEADER_MIN` bytes of memory containing a valid
    /// header. Returns `None` on bad magic or if fields are
    /// structurally incoherent.
    ///
    /// # Safety
    /// - `ptr` must be a valid readable address for at least 40 bytes.
    unsafe fn read(ptr: *const u8) -> Option<Self> {
        // All fields are big-endian u32 at fixed offsets.
        // SAFETY: Caller promises ptr + 40 bytes is readable.
        let read_u32 = |offset: usize| -> u32 {
            // SAFETY: offset < FDT_HEADER_MIN; caller promises readability.
            let bytes = unsafe {
                core::slice::from_raw_parts(ptr.add(offset), 4)
            };
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        };

        let magic = read_u32(0);
        if magic != FDT_MAGIC {
            return None;
        }
        // Per Devicetree Spec v0.4 §5.2:
        //   offset 32 = size_dt_strings
        //   offset 36 = size_dt_struct
        // (Easy to swap accidentally — earlier revisions listed them
        // in the other order. Always check the current spec.)
        let header = FdtHeader {
            totalsize: read_u32(4),
            off_dt_struct: read_u32(8),
            off_dt_strings: read_u32(12),
            size_dt_strings: read_u32(32),
            size_dt_struct: read_u32(36),
        };

        // Sanity: totalsize must cover the structure and strings
        // blocks with their offsets inside the blob.
        let struct_end = header.off_dt_struct as u64 + header.size_dt_struct as u64;
        let strings_end = header.off_dt_strings as u64 + header.size_dt_strings as u64;
        if struct_end > header.totalsize as u64
            || strings_end > header.totalsize as u64
        {
            return None;
        }

        Some(header)
    }
}

// ============================================================================
// DTB walker
// ============================================================================

/// Read a big-endian u32 from a byte slice offset. Returns 0 if the
/// read would overrun (caller should treat that as a termination).
fn be_u32_at(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read a big-endian u64 from a byte slice offset.
fn be_u64_at(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Find the end of a null-terminated name starting at `offset`.
/// Returns (name_bytes, next_aligned_offset).
fn read_name<'a>(data: &'a [u8], offset: usize) -> (&'a [u8], usize) {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    let name = &data[offset..end];
    // Skip the null + round up to 4-byte alignment.
    let after_null = end + 1;
    let aligned = (after_null + 3) & !3;
    (name, aligned)
}

/// Match a node name against `/memory` or `/memory@<addr>`. The DTB
/// encodes `memory@80000000` for a memory node at physical 0x80000000.
fn is_memory_node(name: &[u8]) -> bool {
    if !name.starts_with(b"memory") {
        return false;
    }
    let rest = &name[b"memory".len()..];
    rest.is_empty() || rest.starts_with(b"@")
}

/// Match a node name against `/cpus` (always un-addressed; no `@`).
fn is_cpus_node(name: &[u8]) -> bool {
    name == b"cpus"
}

/// Parse `reg` property values as (address, size) pairs. Assumes
/// `#address-cells = 2` and `#size-cells = 2` at the root (standard
/// for QEMU virt and most RISC-V platforms). Reads pairs of u64s
/// in big-endian.
///
/// Returns up to [`super::MAX_MEMORY_REGIONS`] pairs; excess is
/// silently dropped (bounded iteration).
fn parse_reg_pairs(prop_value: &[u8], mut callback: impl FnMut(u64, u64)) {
    let entry_size = 16; // 2 × u64 = 16 bytes
    let count = prop_value.len() / entry_size;
    let bounded_count = count.min(super::MAX_MEMORY_REGIONS);

    for i in 0..bounded_count {
        let off = i * entry_size;
        let addr = be_u64_at(prop_value, off);
        let size = be_u64_at(prop_value, off + 8);
        callback(addr, size);
    }
}

/// Walk the DTB, calling `on_memory(base, size)` for each
/// `/memory@*` node's `reg` property and `on_cpu_timebase(hz)` for
/// the `/cpus` node's `timebase-frequency` property (once per DTB).
///
/// # Safety
/// `dtb_phys` must point at a valid FDT blob.
unsafe fn walk_dtb(
    dtb_phys: u64,
    mut on_memory: impl FnMut(u64, u64),
    mut on_cpu_timebase: impl FnMut(u32),
) -> Option<u32> {
    let ptr = dtb_phys as *const u8;

    // SAFETY: caller guarantees a valid FDT at this address.
    let header = unsafe { FdtHeader::read(ptr) }?;

    let totalsize = header.totalsize as usize;
    // SAFETY: same — we now have the totalsize from the validated header.
    let full_blob = unsafe { core::slice::from_raw_parts(ptr, totalsize) };

    // Structure block — the token stream we walk.
    let struct_start = header.off_dt_struct as usize;
    let struct_end = struct_start + header.size_dt_struct as usize;
    if struct_end > full_blob.len() {
        return None;
    }
    let struct_block = &full_blob[struct_start..struct_end];

    // Strings block — prop name lookups.
    // We match prop names via `nameoff` into the strings block.

    // State machine: walk tokens. Track depth + per-depth flags for
    // which interesting-ancestor context the current node inherits
    // from. Only direct children of the root matter for our match set
    // (/memory@* and /cpus), but the stack-based approach generalizes
    // if a future addition needs deeper tracking.
    let mut depth: usize = 0;
    let mut pos: usize = 0;
    let mut in_memory_node = false;
    let mut in_cpus_node = false;
    let mut tokens_processed = 0;

    // Parallel stacks: at each ancestor depth, is this ancestor the
    // /memory or /cpus node? Flags rebuild on END_NODE by re-OR'ing
    // the still-active depths.
    let mut in_memory_stack = [false; MAX_DEPTH];
    let mut in_cpus_stack = [false; MAX_DEPTH];

    while pos + 4 <= struct_block.len() && tokens_processed < MAX_TOKENS {
        tokens_processed += 1;
        let token = be_u32_at(struct_block, pos);
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                // Name follows, null-terminated, padded to 4 bytes.
                let (name, next_pos) = read_name(struct_block, pos);
                pos = next_pos;

                let is_mem = depth == 1 && is_memory_node(name);
                let is_cpus = depth == 1 && is_cpus_node(name);
                if depth < MAX_DEPTH {
                    in_memory_stack[depth] = is_mem;
                    in_cpus_stack[depth] = is_cpus;
                }
                if is_mem {
                    in_memory_node = true;
                }
                if is_cpus {
                    in_cpus_node = true;
                }
                depth += 1;
            }
            FDT_END_NODE => {
                if depth == 0 {
                    break; // Malformed — END without matching BEGIN
                }
                depth -= 1;
                // Rebuild "in interesting ancestor" flags after leaving
                // one level. In practice only the direct ancestor at
                // depth 1 ever matches; the stack scan is defensive.
                if depth > 0 {
                    in_memory_node = in_memory_stack[..depth].iter().any(|&f| f);
                    in_cpus_node = in_cpus_stack[..depth].iter().any(|&f| f);
                } else {
                    in_memory_node = false;
                    in_cpus_node = false;
                }
            }
            FDT_PROP => {
                // PROP header: u32 len, u32 nameoff
                if pos + 8 > struct_block.len() {
                    break;
                }
                let len = be_u32_at(struct_block, pos) as usize;
                let nameoff = be_u32_at(struct_block, pos + 4) as usize;
                pos += 8;

                // Bounds-check the value.
                if pos + len > struct_block.len() {
                    break;
                }
                let value = &struct_block[pos..pos + len];
                pos = (pos + len + 3) & !3; // align to 4

                if !in_memory_node && !in_cpus_node {
                    continue;
                }

                // Resolve the property name from the strings block.
                let strings_start = header.off_dt_strings as usize;
                let strings_end = strings_start + header.size_dt_strings as usize;
                if nameoff >= header.size_dt_strings as usize
                    || strings_end > full_blob.len()
                {
                    continue;
                }
                let strings = &full_blob[strings_start..strings_end];
                let prop_name_end = strings[nameoff..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| nameoff + i)
                    .unwrap_or(strings.len());
                let prop_name = &strings[nameoff..prop_name_end];

                if in_memory_node && prop_name == b"reg" {
                    parse_reg_pairs(value, |base, size| {
                        on_memory(base, size);
                    });
                } else if in_cpus_node && prop_name == b"timebase-frequency" {
                    // timebase-frequency is usually a u32 at `/cpus`.
                    // On some DTBs it is per-cpu, but QEMU virt and
                    // every standards-compliant RISC-V platform we
                    // care about emit it at the parent.
                    if value.len() >= 4 {
                        on_cpu_timebase(be_u32_at(value, 0));
                    }
                }
            }
            FDT_NOP => {
                // Skip.
            }
            FDT_END => {
                break;
            }
            _ => {
                // Unknown token — malformed DTB, stop.
                break;
            }
        }
    }

    Some(header.totalsize)
}

// ============================================================================
// Public API
// ============================================================================

/// Populate `BootInfo` from the DTB OpenSBI handed us.
///
/// # Safety
/// - `dtb_phys` must point at a valid FDT blob (present in `a1` on
///   S-mode entry per the RISC-V SBI spec).
/// - Must be called exactly once, before [`super::info`] is read.
pub unsafe fn populate(dtb_phys: u64) {
    let mut info = BootInfo::empty();

    // HHDM offset was set by `kmain_riscv64` before this call (it
    // matches the value in src/arch/riscv64/entry.rs). Record it so
    // downstream consumers — which go through boot::info() — see it.
    info.hhdm_offset = crate::hhdm_offset();

    // Walk the DTB for /memory@* nodes and /cpus/timebase-frequency.
    let mut timer_hz: Option<u32> = None;
    // SAFETY: caller promises a valid FDT at dtb_phys.
    let dtb_totalsize = unsafe {
        walk_dtb(
            dtb_phys,
            |base, size| {
                let _ = info.push_memory_region(MemoryRegion {
                    base,
                    length: size,
                    kind: MemoryRegionKind::Usable,
                });
            },
            |hz| {
                timer_hz = Some(hz);
            },
        )
    };
    info.timer_base_frequency_hz = timer_hz;

    // Reserve OpenSBI's range on QEMU virt (0x80000000..0x80200000).
    // Real platforms: OpenSBI's extent comes from `/reserved-memory`
    // nodes; walking those is a Phase R-2.b follow-up. For QEMU virt
    // the layout is stable and documented.
    //
    // SCAFFOLDING: hardcoded QEMU-virt OpenSBI extent. Real /reserved-
    // memory parsing lands with the broader DTB walker in R-6.
    let _ = info.push_memory_region(MemoryRegion {
        base: 0x8000_0000,
        length: 0x20_0000, // 2 MiB
        kind: MemoryRegionKind::BootloaderReclaimable,
    });

    // Reserve the DTB blob itself (from dtb_phys for totalsize bytes).
    if let Some(size) = dtb_totalsize {
        let _ = info.push_memory_region(MemoryRegion {
            base: dtb_phys,
            length: size as u64,
            kind: MemoryRegionKind::Reserved,
        });
    }

    // Reserve the kernel image extent (0x80200000 .. _kernel_end phys).
    // We take the address of the VMA symbol `_kernel_end` (higher-half)
    // and subtract 0xffffffff00000000 to get the physical end. We
    // *cannot* export `_kernel_end_phys` as an absolute symbol from the
    // linker — it would be a low (~0x80XXXXXX) value that PC-relative
    // Rust code can't address from the higher-half kernel (32-bit
    // displacement range doesn't span that gap — see linker-riscv64.ld).
    extern "C" {
        static _kernel_end: u8;
    }
    // SAFETY: linker symbol — we only take its address, never dereference.
    let kernel_end_vma = (&raw const _kernel_end) as u64;
    // Same offset used in the linker script's AT() expressions.
    const VMA_TO_PMA_OFFSET: u64 = 0xffffffff_00000000;
    let kernel_end_phys = kernel_end_vma - VMA_TO_PMA_OFFSET;
    let kernel_start: u64 = 0x8020_0000;
    if kernel_end_phys > kernel_start {
        let _ = info.push_memory_region(MemoryRegion {
            base: kernel_start,
            length: kernel_end_phys - kernel_start,
            kind: MemoryRegionKind::ExecutableAndModules,
        });
    }

    super::install(info);
}
