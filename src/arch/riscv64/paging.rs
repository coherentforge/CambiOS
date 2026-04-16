// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! RISC-V Sv48 page-table bit encoding and MMIO bring-up.
//!
//! Sibling of [`crate::arch::aarch64::paging`]. The shared 4-level /
//! 4 KiB / 48-bit paging module in [`crate::memory::paging`] calls into
//! this file whenever it needs to inspect or construct a PTE. See
//! [ADR-013](../../../docs/adr/013-riscv64-architecture-support.md) for
//! the decisions this module encodes, and the plan-file note at
//! `/Users/jasonricca/.claude/plans/melodic-tumbling-muffin.md` for the
//! R-3.a ordering rationale (split the shared cfg before the first
//! consumer — PLIC in R-3.d — lands).
//!
//! ## Sv48 PTE layout
//!
//! ```text
//! 63    62..61   60..54    53..10        9..8   7   6   5   4   3   2   1   0
//! N     PBMT     Reserved  PPN[3:0]      RSW    D   A   G   U   X   W   R   V
//! ```
//!
//! - `V` valid; `R` read; `W` write; `X` execute; `U` user-accessible;
//!   `G` global (not ASID-tagged); `A` accessed; `D` dirty.
//! - Bits `53:10` carry the 44-bit PPN. Physical address of the target
//!   page is `(pte >> 10) << 12` or equivalently `(pte & ADDR_MASK) << 2`.
//! - Bits `60:54` are reserved; **setting them faults on a hart without
//!   the relevant extension**. CambiOS leaves them zero.
//! - Bits `62:61` are Svpbmt (Supervisor-mode Physical Memory Base mask
//!   Type). We intentionally leave them zero — see `early_map_mmio`.
//!
//! A PTE is a **pointer to the next-level table** when valid *and*
//! `R|W|X = 0`. A PTE is a **leaf** when valid *and* at least one of
//! `R|W|X` is set. We use this distinction in `pte_is_table`.

// ============================================================================
// Sv48 PTE bit constants
// ============================================================================

/// Valid.
pub const PTE_V: u64 = 1 << 0;
/// Read.
const PTE_R: u64 = 1 << 1;
/// Write.
const PTE_W: u64 = 1 << 2;
/// Execute.
const PTE_X: u64 = 1 << 3;
/// User-accessible (U-mode can access).
const PTE_U: u64 = 1 << 4;
/// Global — not tagged by ASID; survives ASID switches.
const PTE_G: u64 = 1 << 5;
/// Accessed — MMU sets on access unless software manages it.
const PTE_A: u64 = 1 << 6;
/// Dirty — MMU sets on write unless software manages it.
const PTE_D: u64 = 1 << 7;

/// Mask for the PPN field (44 bits at positions 53:10).
///
/// `(pte & ADDR_MASK) << 2` yields the physical address of the target
/// page or next-level table.
pub const ADDR_MASK: u64 = ((1u64 << 44) - 1) << 10;

/// Mask for the 44-bit satp PPN field (positions 43:0).
const SATP_PPN_MASK: u64 = (1u64 << 44) - 1;

// ============================================================================
// PTE predicates and accessors
// ============================================================================

/// True if the entry is valid (bit[0] set).
#[inline]
pub fn pte_is_valid(pte: u64) -> bool {
    pte & PTE_V != 0
}

/// True if a valid entry is a pointer to a next-level page table.
///
/// Sv48 encodes this implicitly: a valid entry with no R/W/X bits is a
/// table descriptor; any of R/W/X makes it a leaf.
#[inline]
pub fn pte_is_table(pte: u64) -> bool {
    pte & PTE_V != 0 && pte & (PTE_R | PTE_W | PTE_X) == 0
}

/// Extract the target physical address from a PTE.
#[inline]
pub fn pte_addr(pte: u64) -> u64 {
    (pte & ADDR_MASK) << 2
}

/// Build a table descriptor pointing at `child_phys` (an L1/L2/L3 table
/// frame). Valid only; no R/W/X, so the walker descends.
#[inline]
pub fn make_table_pte(child_phys: u64) -> u64 {
    ((child_phys >> 12) << 10) | PTE_V
}

/// Build a leaf PTE for a 4 KiB page.
///
/// Always sets `A` (Accessed) and `D` (Dirty) so the MMU does not fault
/// the first access/write — CambiOS does not use software-managed A/D.
/// All remaining permission bits come from `flags`.
#[inline]
pub fn make_leaf_pte(phys: u64, flags: flags::PageFlags) -> u64 {
    ((phys >> 12) << 10) | PTE_V | PTE_A | PTE_D | flags.raw()
}

/// Barrier sequence after installing a new leaf mapping.
///
/// `sfence.vma zero, zero` flushes all TLB entries for all ASIDs on the
/// current hart — broad, but correct, and the shared paging module
/// installs one mapping at a time so the cost is a wash. Remote-hart
/// invalidation lands in Phase R-5 via SBI IPI.
///
/// # Safety
/// Must be called from S-mode.
#[inline]
pub unsafe fn barrier_map() {
    // SAFETY: sfence.vma is always legal in S-mode; no memory effects
    // beyond TLB invalidation.
    unsafe {
        core::arch::asm!("sfence.vma zero, zero", options(nostack));
    }
}

// ============================================================================
// Root-read helpers
// ============================================================================

/// Read the active page-table root from `satp` and convert the 44-bit
/// PPN field into a byte address.
///
/// Unlike AArch64 (TTBR0/TTBR1 split), RISC-V has a single `satp` per
/// hart; both user and kernel mappings live in the same table. The
/// "kernel half" versus "user half" is a VA convention, not a hardware
/// split.
///
/// # Safety
/// HHDM offset must be set; `satp` must point to a valid L3 (Sv48 root)
/// or be zero (paging off — in which case the shared walk code is not
/// called).
#[inline]
pub unsafe fn active_root() -> u64 {
    let satp: u64;
    // SAFETY: csrr is a pure read of satp; nomem + preserves_flags hold.
    unsafe {
        core::arch::asm!(
            "csrr {0}, satp",
            out(reg) satp,
            options(nostack, nomem, preserves_flags),
        );
    }
    (satp & SATP_PPN_MASK) << 12
}

/// Read the kernel page-table root.
///
/// On RISC-V there is no TTBR split — the kernel and the current user
/// process share a single `satp`, with kernel VAs living in the top
/// half (bit[47] sign-extended). `early_map_mmio` therefore operates on
/// the same root `active_root` returns.
///
/// # Safety
/// Same as `active_root`.
#[inline]
pub unsafe fn kernel_root_phys() -> u64 {
    // SAFETY: delegated read.
    unsafe { active_root() }
}

// ============================================================================
// Early-boot MMIO mapping (no allocator required)
// ============================================================================

/// Map a single 4 KiB MMIO page into the current page table.
///
/// Runs before the heap and frame allocator are online. Uses the shared
/// bootstrap frame pool in [`crate::memory::paging`] for missing
/// intermediate L1/L2/L3 tables.
///
/// ## Device memory attribution on RISC-V
///
/// This function leaves the Svpbmt field (bits 62:61) zero. That means
/// the PTE itself does not declare the page as device memory — the
/// hart's Physical Memory Attribute (PMA) table is trusted to mark the
/// MMIO region strongly-ordered / non-cacheable. On QEMU virt this is
/// the case by construction; on CambiOS-designed RISC-V hardware the
/// PMA configuration is a hardware-design concern (ADR-013 § Strategic
/// Posture — generic-first). If we eventually target a platform with a
/// permissive default PMA, this is where Svpbmt `PBMT=IO` gets added.
///
/// # Safety
/// - HHDM offset must already be set.
/// - `phys_addr` must be a valid MMIO physical address.
/// - Single-core boot only.
pub unsafe fn early_map_mmio(phys_addr: u64) -> Result<(), &'static str> {
    let pa = phys_addr & !0xFFF;
    // SAFETY: caller guarantees HHDM set + phys_addr is valid MMIO.
    // The shared helper walks HHDM-mapped tables during single-core boot.
    unsafe {
        crate::memory::paging::early_map_mmio_arch(
            pa,
            kernel_root_phys(),
            |pa_frame| {
                // Kernel RW MMIO leaf: V+R+W+A+D+G. No U (kernel-only),
                // no X (never execute MMIO), no Svpbmt (trust PMA).
                ((pa_frame >> 12) << 10)
                    | PTE_V
                    | PTE_R
                    | PTE_W
                    | PTE_A
                    | PTE_D
                    | PTE_G
            },
            |va| {
                // sfence.vma for a single VA. Target VA encoded in rs1;
                // asid = x0 means "all ASIDs".
                //
                // SAFETY: sfence.vma is legal from S-mode and only
                // affects this hart's TLB. Closure body inherits the
                // enclosing `unsafe` in `early_map_mmio` — single-core
                // boot, S-mode.
                core::arch::asm!(
                    "sfence.vma {va}, zero",
                    va = in(reg) va,
                    options(nostack),
                );
            },
        )
    }
}

// ============================================================================
// flags — descriptor permission bits, arch-opaque to callers
// ============================================================================

/// Page permission flags for RISC-V Sv48 PTEs.
///
/// Mirrors the AArch64 `flags` surface so the shared paging module and
/// the kernel at large can speak in one vocabulary (`kernel_rw()`,
/// `user_rw()`, etc.). `make_leaf_pte` OR's `flags.raw()` into the PTE
/// unchanged — no RISC-V analog to AArch64's `DEVICE_MEMORY_FLAG`
/// sentinel is needed because PMA carries the device attribute on this
/// arch (see `early_map_mmio` notes).
pub mod flags {
    use super::*;

    /// Wrapper for RISC-V Sv48 PTE permission bits.
    #[derive(Debug, Clone, Copy)]
    pub struct PageFlags(u64);

    impl PageFlags {
        /// Escape hatch for `make_leaf_pte`. Not a public contract.
        #[inline]
        pub(super) fn raw(self) -> u64 {
            self.0
        }
    }

    /// Kernel read-only: R, G, not U, not X.
    pub const KERNEL_RO: PageFlags = PageFlags(PTE_R | PTE_G);

    /// Kernel read-write: R + W, G, not U, not X.
    pub fn kernel_rw() -> PageFlags {
        PageFlags(PTE_R | PTE_W | PTE_G)
    }

    /// User read-only, executable from U-mode: R + X + U.
    pub fn user_ro() -> PageFlags {
        PageFlags(PTE_R | PTE_X | PTE_U)
    }

    /// User read-write, no execute (W^X): R + W + U.
    pub fn user_rw() -> PageFlags {
        PageFlags(PTE_R | PTE_W | PTE_U)
    }

    /// User MMIO: R + W + U. Device memory attribution is delegated to
    /// the hart's PMA — we do not set Svpbmt PBMT bits. See
    /// `early_map_mmio` for the rationale.
    pub fn user_mmio() -> PageFlags {
        PageFlags(PTE_R | PTE_W | PTE_U)
    }
}
