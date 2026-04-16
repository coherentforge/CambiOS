// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! AArch64 page-table bit encoding and MMIO bring-up.
//!
//! The shared 4-level / 4 KiB / 48-bit paging module in
//! [`crate::memory::paging`](../../memory/index.html) delegates all
//! arch-specific concerns to this file:
//!
//! - PTE/descriptor bit constants (`DESC_*`, `ADDR_MASK`)
//! - Table vs. leaf distinction (on AArch64 bit[1] distinguishes them
//!   at L0/L1/L2; at L3 bit[1]=1 means "page")
//! - Leaf and table descriptor constructors (`make_leaf_pte`,
//!   `make_table_pte`)
//! - Barrier sequence after installing a mapping (`barrier_map`)
//! - Kernel page-table root read (`kernel_root_phys` — TTBR1_EL1)
//! - Active user page-table root read (`active_root` — TTBR0_EL1)
//! - Early MMIO mapping into TTBR1 before the heap exists
//!   (`early_map_mmio`)
//! - The `flags` submodule — `PageFlags`, the user/kernel constructors,
//!   and the internal `DEVICE_MEMORY_FLAG` sentinel used by
//!   `make_leaf_pte` to pick AttrIndx
//!
//! Refactored out of `src/memory/mod.rs` in Phase R-3.a (see
//! [ADR-013](../../../docs/adr/013-riscv64-architecture-support.md)
//! Divergence) so the RISC-V port can plug a Sv48 sibling into the same
//! shared module without duplicating the walk logic.

// ============================================================================
// Descriptor bit layout (AArch64, 4 KiB granule, 48-bit VA)
// ============================================================================
//
// [0]     Valid
// [1]     Table (L0-L2) or Page (L3) — must be 1 for valid entries
// [4:2]   AttrIndx (MAIR index: 0=Device, 1=Normal)
// [5]     NS (non-secure)
// [7:6]   AP — access permissions:
//           00: EL1 RW, EL0 no access
//           01: EL1 RW, EL0 RW
//           10: EL1 RO, EL0 no access
//           11: EL1 RO, EL0 RO
// [9:8]   SH — shareability: 11=Inner Shareable
// [10]    AF — Access Flag (must be 1 to avoid access fault)
// [47:12] Output address (physical page frame)
// [53]    PXN — Privileged eXecute Never
// [54]    UXN/XN — User eXecute Never

/// Valid bit — entry is active.
pub const DESC_VALID: u64 = 1 << 0;
/// Table descriptor (L0-L2) or Page descriptor (L3).
pub const DESC_TABLE: u64 = 1 << 1;
/// Access Flag — must be set to avoid access faults.
const DESC_AF: u64 = 1 << 10;
/// Inner Shareable (for SMP coherency).
const DESC_ISH: u64 = 0b11 << 8;
/// AP[1]: EL0 accessible.
const DESC_AP_EL0: u64 = 1 << 6;
/// AP[2]: Read-only.
const DESC_AP_RO: u64 = 1 << 7;
/// AttrIndx=1 (Normal memory in MAIR — see boot config).
const DESC_ATTR_NORMAL: u64 = 1 << 2;
/// AttrIndx=0 (Device-nGnRnE in MAIR).
const DESC_ATTR_DEVICE: u64 = 0 << 2;
/// PXN: Privileged eXecute Never.
const DESC_PXN: u64 = 1 << 53;
/// UXN: User eXecute Never.
const DESC_UXN: u64 = 1 << 54;
/// Mask for output address bits [47:12].
pub const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// ============================================================================
// PTE predicates and accessors (called from shared paging module)
// ============================================================================

/// True if the entry is valid (bit[0] set).
#[inline]
pub fn pte_is_valid(pte: u64) -> bool {
    pte & DESC_VALID != 0
}

/// True if a valid entry points to a next-level page table.
///
/// At L0/L1/L2 the distinction is: bit[1]=1 → table descriptor,
/// bit[1]=0 → block descriptor. At L3 bit[1]=1 means "page" (leaf), so
/// this predicate is only meaningful at L0-L2 — the shared walk code
/// only calls it while descending.
#[inline]
pub fn pte_is_table(pte: u64) -> bool {
    pte & DESC_VALID != 0 && pte & DESC_TABLE != 0
}

/// Extract the output physical address from a PTE.
#[inline]
pub fn pte_addr(pte: u64) -> u64 {
    pte & ADDR_MASK
}

/// Build a table descriptor pointing at `child_phys` (an L1/L2/L3 table
/// frame). Valid + Table; attributes come from the deeper levels.
#[inline]
pub fn make_table_pte(child_phys: u64) -> u64 {
    child_phys | DESC_VALID | DESC_TABLE
}

/// Build an L3 leaf (page) descriptor.
///
/// Inspects `flags.internal_bits()` for the device-memory sentinel
/// (`DEVICE_MEMORY_FLAG`) and translates it into AttrIndx=0 (Device) vs.
/// AttrIndx=1 (Normal). All other bits in `flags` are AP/UXN/PXN, which
/// OR directly into the descriptor.
#[inline]
pub fn make_leaf_pte(phys: u64, flags: flags::PageFlags) -> u64 {
    let raw = flags.raw();
    let is_device = raw & flags::DEVICE_MEMORY_FLAG != 0;
    let attr = if is_device { DESC_ATTR_DEVICE } else { DESC_ATTR_NORMAL };
    // Strip the internal sentinel before OR'ing into hardware bits.
    let hw_flags = raw & !flags::DEVICE_MEMORY_FLAG;
    phys | DESC_VALID | DESC_TABLE | DESC_AF | DESC_ISH | attr | hw_flags
}

/// Barrier sequence after installing a new leaf mapping.
///
/// `dsb ishst` waits for store completion so the MMU table walker
/// observes the new PTE; `isb` flushes the pipeline so subsequent
/// instructions see the mapping. TLB invalidation for an *existing*
/// mapping is done separately via `arch::tlb::shootdown_page`.
///
/// # Safety
/// Must be called from EL1. No memory side effects.
#[inline]
pub unsafe fn barrier_map() {
    // SAFETY: dsb/isb have no side effects beyond the pipeline flush
    // and table-walker synchronization they are documented to perform.
    unsafe {
        core::arch::asm!("dsb ishst", "isb", options(nostack));
    }
}

// ============================================================================
// Root-read helpers
// ============================================================================

/// Read the active user page-table root from TTBR0_EL1.
///
/// # Safety
/// HHDM offset must already be set and TTBR0_EL1 must hold a valid L0.
#[inline]
pub unsafe fn active_root() -> u64 {
    let ttbr0: u64;
    // SAFETY: Reading TTBR0_EL1 from EL1 is always legal.
    unsafe {
        core::arch::asm!(
            "mrs {0}, ttbr0_el1",
            out(reg) ttbr0,
            options(nostack, nomem, preserves_flags),
        );
    }
    ttbr0 & ADDR_MASK
}

/// Read the kernel page-table root from TTBR1_EL1.
///
/// On AArch64 the kernel lives in a separate translation regime from
/// user space — `early_map_mmio` installs device mappings here so they
/// are visible to the kernel regardless of which process's TTBR0 is
/// loaded.
///
/// # Safety
/// Must be called from EL1.
#[inline]
pub unsafe fn kernel_root_phys() -> u64 {
    let ttbr1: u64;
    // SAFETY: Reading TTBR1_EL1 from EL1 is always legal.
    unsafe {
        core::arch::asm!(
            "mrs {0}, ttbr1_el1",
            out(reg) ttbr1,
            options(nostack, nomem, preserves_flags),
        );
    }
    ttbr1 & ADDR_MASK
}

// ============================================================================
// Early-boot MMIO mapping (no allocator required)
// ============================================================================

/// Map a single 4 KiB MMIO page into the kernel page table (TTBR1_EL1).
///
/// Runs before the heap and frame allocator are online. Uses the shared
/// bootstrap frame pool in `crate::memory::paging` for missing
/// intermediate L1/L2/L3 tables.
///
/// Writes Device-nGnRnE (AttrIndx=0), kernel RW, non-executable,
/// inner-shareable.
///
/// # Safety
/// - HHDM offset must already be set.
/// - `phys_addr` must be a valid MMIO physical address.
/// - Single-core boot only.
pub unsafe fn early_map_mmio(phys_addr: u64) -> Result<(), &'static str> {
    // Delegate to the shared early-mmio driver with arch-specific pieces
    // injected. The driver handles walk + bootstrap alloc + leaf write;
    // we supply the root, the leaf descriptor, and the VA-targeted TLB
    // invalidation.
    let pa = phys_addr & !0xFFF;
    // SAFETY: Caller guarantees HHDM is set and phys_addr is valid MMIO.
    // The shared helper reads/writes HHDM-mapped page tables under
    // single-core boot.
    unsafe {
        crate::memory::paging::early_map_mmio_arch(
            pa,
            kernel_root_phys(),
            |pa_frame| {
                // Kernel RW + Device-nGnRnE + UXN + PXN + AF + ISH + valid + "page"
                pa_frame
                    | DESC_VALID
                    | DESC_TABLE
                    | DESC_AF
                    | DESC_ISH
                    | DESC_ATTR_DEVICE
                    | DESC_PXN
                    | DESC_UXN
            },
            |va| {
                // Per-VA TLB invalidate + barrier pair.
                // SAFETY: vale1is is broadcast-capable and safe from
                // EL1; the VA argument is shifted to the VPN form TLBI
                // expects. Closure body inherits the enclosing
                // `unsafe` in `early_map_mmio` — single-core boot, EL1.
                core::arch::asm!(
                    "dsb ishst",
                    "tlbi vale1is, {va}",
                    "dsb ish",
                    "isb",
                    va = in(reg) va >> 12,
                    options(nostack),
                );
            },
        )
    }
}

// ============================================================================
// flags — descriptor permission bits, arch-opaque to callers
// ============================================================================

/// Page permission flags for AArch64 descriptors.
///
/// `PageFlags` is a thin newtype wrapping the subset of L3 descriptor
/// bits that vary per mapping (AP[2:1], UXN, PXN, and the internal
/// `DEVICE_MEMORY_FLAG` sentinel). `make_leaf_pte` OR's these into the
/// final descriptor after translating `DEVICE_MEMORY_FLAG` into the
/// AttrIndx bits.
pub mod flags {
    use super::*;

    /// Wrapper for AArch64 L3 descriptor permission bits.
    #[derive(Debug, Clone, Copy)]
    pub struct PageFlags(u64);

    impl PageFlags {
        /// Escape hatch for `make_leaf_pte`. Not a public contract.
        #[inline]
        pub(super) fn raw(self) -> u64 {
            self.0
        }
    }

    /// Bit 62 is unused in AArch64 descriptors — we repurpose it as an
    /// internal flag to signal device memory (AttrIndx=0 instead of 1).
    /// Stripped by `make_leaf_pte` before OR'ing into hardware bits.
    pub(super) const DEVICE_MEMORY_FLAG: u64 = 1 << 62;

    /// Kernel read-only: EL1 RO, no EL0 access, UXN + PXN.
    pub const KERNEL_RO: PageFlags = PageFlags(DESC_AP_RO | DESC_UXN | DESC_PXN);

    /// Kernel read-write: EL1 RW, no EL0 access, UXN + PXN (no execute).
    pub fn kernel_rw() -> PageFlags {
        PageFlags(DESC_UXN | DESC_PXN)
    }

    /// User read-only, executable from EL0.
    /// PXN set: kernel can't execute user pages.
    pub fn user_ro() -> PageFlags {
        PageFlags(DESC_AP_EL0 | DESC_AP_RO | DESC_PXN)
    }

    /// User read-write, no execute (W^X) + PXN (no kernel execute of
    /// user pages).
    pub fn user_rw() -> PageFlags {
        PageFlags(DESC_AP_EL0 | DESC_UXN | DESC_PXN)
    }

    /// User MMIO: EL0 RW, device memory (uncacheable), no execute.
    /// Used for mapping device MMIO regions into user-space drivers.
    pub fn user_mmio() -> PageFlags {
        PageFlags(DESC_AP_EL0 | DESC_UXN | DESC_PXN | DEVICE_MEMORY_FLAG)
    }
}
