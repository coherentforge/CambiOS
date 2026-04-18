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

/// Interesting-ancestor kind tracked per depth in the DTB walker.
///
/// Replaces earlier parallel boolean stacks (`in_memory_stack`,
/// `in_cpus_stack`) with one enum per depth — same information density,
/// easier to extend, and the property-dispatch match reads as a single
/// switch on `device_stack[depth-1]` instead of a cascade of `if`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    /// Not a node we care about.
    None,
    /// `/memory@*` — `reg` property gives usable RAM ranges.
    Memory,
    /// `/cpus` — parent of per-hart nodes; owns the platform
    /// `timebase-frequency` property.
    Cpus,
    /// `/soc` — the bus-like parent that holds PLIC, serial, virtio,
    /// etc. We never read props directly from `/soc` but descend into
    /// its children.
    Soc,
    /// `/soc/plic@*` — `reg` → MMIO base + size of the PLIC.
    Plic,
    /// `/soc/serial@*` — `interrupts` → PLIC source ID of the console
    /// UART.
    Serial,
}

/// Classify a node name into a [`DeviceKind`] given its depth and the
/// parent node's kind. Called from the walker on every `BEGIN_NODE`.
///
/// The walker treats nodes at depth 1 as root-level (parent = the
/// unnamed root), and depth 2 as `/soc/*` children when `parent ==
/// DeviceKind::Soc`. Deeper nesting is `None` — we do not care about
/// anything below `/soc/plic@*/interrupts-extended`'s referenced
/// interrupt-controller subnodes.
fn classify_node(depth: usize, parent: DeviceKind, name: &[u8]) -> DeviceKind {
    match depth {
        1 => {
            if name.starts_with(b"memory") {
                let rest = &name[b"memory".len()..];
                if rest.is_empty() || rest.starts_with(b"@") {
                    return DeviceKind::Memory;
                }
            }
            if name == b"cpus" {
                return DeviceKind::Cpus;
            }
            if name == b"soc" {
                return DeviceKind::Soc;
            }
            DeviceKind::None
        }
        2 if parent == DeviceKind::Soc => {
            if name.starts_with(b"plic") {
                // Matches both `plic` and `plic@0c000000` forms.
                let rest = &name[b"plic".len()..];
                if rest.is_empty() || rest.starts_with(b"@") {
                    return DeviceKind::Plic;
                }
            }
            if name.starts_with(b"serial") {
                let rest = &name[b"serial".len()..];
                if rest.is_empty() || rest.starts_with(b"@") {
                    return DeviceKind::Serial;
                }
            }
            DeviceKind::None
        }
        _ => DeviceKind::None,
    }
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

/// Collected facts the kernel needs from the DTB. Populated by a
/// single pass of [`walk_dtb`]; consumed by [`populate`] to build the
/// public `BootInfo`.
///
/// Everything here is plain data — no kernel types leak in. The walker
/// is deliberately the only place that touches big-endian FDT byte
/// layout.
struct DtbFacts {
    memory: [(u64, u64); super::MAX_MEMORY_REGIONS],
    memory_count: usize,
    timer_base_hz: Option<u32>,
    plic_mmio: Option<(u64, u64)>,
    console_irq: Option<u32>,
    totalsize: u32,
}

impl DtbFacts {
    const fn new() -> Self {
        Self {
            // Manual init — `Default` on arrays > 32 requires const
            // generics + manual impl we don't need here.
            memory: [(0u64, 0u64); super::MAX_MEMORY_REGIONS],
            memory_count: 0,
            timer_base_hz: None,
            plic_mmio: None,
            console_irq: None,
            totalsize: 0,
        }
    }

    fn push_memory(&mut self, base: u64, size: u64) {
        if self.memory_count < self.memory.len() {
            self.memory[self.memory_count] = (base, size);
            self.memory_count += 1;
        }
    }
}

/// Walk the DTB and collect the facts the kernel needs in one pass.
/// Returns `None` on invalid/truncated FDT.
///
/// Matches:
/// - `/memory@*` → `reg` → memory regions (usable RAM).
/// - `/cpus` → `timebase-frequency` → platform timer tick rate.
/// - `/soc/plic@*` → `reg` → PLIC MMIO base + size.
/// - `/soc/serial@*` → `interrupts` → console IRQ source ID.
///
/// # Safety
/// `dtb_phys` must point at a valid FDT blob.
unsafe fn walk_dtb(dtb_phys: u64) -> Option<DtbFacts> {
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
    let strings_start = header.off_dt_strings as usize;
    let strings_end = strings_start + header.size_dt_strings as usize;
    if strings_end > full_blob.len() {
        return None;
    }
    let strings = &full_blob[strings_start..strings_end];

    let mut facts = DtbFacts::new();
    facts.totalsize = header.totalsize;

    // Walk state.
    let mut depth: usize = 0;
    let mut pos: usize = 0;
    let mut tokens_processed = 0;

    // Stack of DeviceKind per ancestor depth. `device_stack[d]` is the
    // kind of the node opened at depth d. `current_kind()` below looks
    // up the innermost depth's kind to dispatch property parsing.
    let mut device_stack = [DeviceKind::None; MAX_DEPTH];

    while pos + 4 <= struct_block.len() && tokens_processed < MAX_TOKENS {
        tokens_processed += 1;
        let token = be_u32_at(struct_block, pos);
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                // Name follows, null-terminated, padded to 4 bytes.
                let (name, next_pos) = read_name(struct_block, pos);
                pos = next_pos;

                let parent = if depth == 0 {
                    DeviceKind::None
                } else if depth - 1 < MAX_DEPTH {
                    device_stack[depth - 1]
                } else {
                    DeviceKind::None
                };
                let kind = classify_node(depth, parent, name);
                if depth < MAX_DEPTH {
                    device_stack[depth] = kind;
                }
                depth += 1;
            }
            FDT_END_NODE => {
                if depth == 0 {
                    break; // Malformed — END without matching BEGIN
                }
                depth -= 1;
                if depth < MAX_DEPTH {
                    device_stack[depth] = DeviceKind::None;
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

                if pos + len > struct_block.len() {
                    break;
                }
                let value = &struct_block[pos..pos + len];
                pos = (pos + len + 3) & !3; // align to 4

                // Which interesting node are we inside? `depth - 1`
                // because the prop belongs to the most recently opened
                // node, and we incremented depth on BEGIN_NODE.
                if depth == 0 {
                    continue;
                }
                let kind = if depth - 1 < MAX_DEPTH {
                    device_stack[depth - 1]
                } else {
                    DeviceKind::None
                };
                if kind == DeviceKind::None {
                    continue;
                }

                // Resolve the property name from the strings block.
                if nameoff >= header.size_dt_strings as usize {
                    continue;
                }
                let prop_name_end = strings[nameoff..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| nameoff + i)
                    .unwrap_or(strings.len());
                let prop_name = &strings[nameoff..prop_name_end];

                match (kind, prop_name) {
                    (DeviceKind::Memory, b"reg") => {
                        parse_reg_pairs(value, |base, size| {
                            facts.push_memory(base, size);
                        });
                    }
                    (DeviceKind::Cpus, b"timebase-frequency") => {
                        // u32 at /cpus on QEMU virt and every
                        // standards-compliant RISC-V platform we care
                        // about.
                        if facts.timer_base_hz.is_none() && value.len() >= 4 {
                            facts.timer_base_hz = Some(be_u32_at(value, 0));
                        }
                    }
                    (DeviceKind::Plic, b"reg") => {
                        // Under /soc `#address-cells = #size-cells =
                        // 2`. One pair = 16 bytes.
                        if facts.plic_mmio.is_none() && value.len() >= 16 {
                            let base = be_u64_at(value, 0);
                            let size = be_u64_at(value, 8);
                            facts.plic_mmio = Some((base, size));
                        }
                    }
                    (DeviceKind::Serial, b"interrupts") => {
                        // QEMU virt encodes the console IRQ as a
                        // single u32 (PLIC source ID). Multi-cell
                        // interrupt-parents are a future concern.
                        if facts.console_irq.is_none() && value.len() >= 4 {
                            facts.console_irq = Some(be_u32_at(value, 0));
                        }
                    }
                    _ => {}
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => break, // Unknown token — malformed, stop.
        }
    }

    Some(facts)
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

    // Walk the DTB once; collect memory + /cpus/timebase-frequency +
    // /soc/plic reg + /soc/serial interrupts.
    //
    // SAFETY: caller promises a valid FDT at dtb_phys.
    let facts = unsafe { walk_dtb(dtb_phys) };
    let dtb_totalsize = facts.as_ref().map(|f| f.totalsize);

    if let Some(facts) = &facts {
        for i in 0..facts.memory_count {
            let (base, size) = facts.memory[i];
            let _ = info.push_memory_region(MemoryRegion {
                base,
                length: size,
                kind: MemoryRegionKind::Usable,
            });
        }
        info.timer_base_frequency_hz = facts.timer_base_hz;
        info.plic_mmio = facts.plic_mmio;
        info.console_irq = facts.console_irq;
    }

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
