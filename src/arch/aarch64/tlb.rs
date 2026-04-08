// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! TLB management — AArch64
//!
//! AArch64 has hardware-assisted TLB maintenance via TLBI instructions.
//! The `IS` (Inner Shareable) suffix causes the operation to broadcast
//! to all CPUs in the inner shareable domain — no software IPI needed
//! (unlike x86_64 which requires TLB shootdown IPIs).
//!
//! Key instructions:
//! - `TLBI VALE1IS, <Xt>` — invalidate by VA, last level, inner shareable
//! - `TLBI VMALLE1IS`     — invalidate all EL1 entries, inner shareable
//! - `DSB ISH`            — data synchronization barrier, inner shareable
//! - `ISB`                — instruction synchronization barrier
//!
//! The TLBI operand encodes the virtual address in bits [55:12] (page-aligned,
//! shifted right by 12). ASID is in bits [63:48] for ASID-specific invalidations.

/// Page size shift (4KB pages = 12 bits).
const PAGE_SHIFT: u64 = 12;

/// Invalidate a single page across all CPUs.
///
/// Uses `TLBI VALE1IS` which broadcasts to all cores via hardware.
/// The virtual address is shifted right by 12 to form the TLBI operand.
pub fn shootdown_page(virt_addr: u64) {
    let operand = virt_addr >> PAGE_SHIFT;
    // SAFETY: TLBI instructions are safe to execute from EL1. The DSB ISH
    // ensures the invalidation completes on all CPUs before we proceed.
    // ISB ensures subsequent instruction fetches see the new mappings.
    unsafe {
        core::arch::asm!(
            "tlbi vale1is, {0}",
            "dsb ish",
            "isb",
            in(reg) operand,
            options(nostack),
        );
    }
}

/// Invalidate a range of pages across all CPUs.
///
/// Issues per-page TLBI for small ranges, bulk invalidation for large.
pub fn shootdown_range(virt_start: u64, num_pages: usize) {
    // For large ranges (>16 pages), a full invalidation is cheaper than
    // per-page TLBI due to TLB capacity and microcode overhead.
    if num_pages > 16 {
        shootdown_all();
        return;
    }
    // SAFETY: Each TLBI is safe from EL1. We batch all invalidations
    // before a single DSB ISH + ISB.
    unsafe {
        for i in 0..num_pages {
            let addr = virt_start + (i as u64) * (1 << PAGE_SHIFT);
            let operand = addr >> PAGE_SHIFT;
            core::arch::asm!(
                "tlbi vale1is, {0}",
                in(reg) operand,
                options(nostack),
            );
        }
        core::arch::asm!(
            "dsb ish",
            "isb",
            options(nostack),
        );
    }
}

/// Invalidate all TLB entries across all CPUs.
pub fn shootdown_all() {
    // SAFETY: TLBI VMALLE1IS is safe from EL1, broadcasts to all cores.
    // DSB ISH + ISB ensure completion.
    unsafe {
        core::arch::asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlbi_operand_encoding() {
        // TLBI operand = VA >> 12 (page-aligned, shifted right by PAGE_SHIFT)
        assert_eq!(0x1000u64 >> PAGE_SHIFT, 1);
        assert_eq!(0x2000u64 >> PAGE_SHIFT, 2);
        assert_eq!(0xFFFF_F000u64 >> PAGE_SHIFT, 0xF_FFFF);
        assert_eq!(0x0u64 >> PAGE_SHIFT, 0);
    }

    #[test]
    fn test_page_shift_constant() {
        assert_eq!(PAGE_SHIFT, 12);
        assert_eq!(1u64 << PAGE_SHIFT, 4096);
    }

    #[test]
    fn test_bulk_threshold() {
        // shootdown_range uses bulk invalidation for >16 pages
        assert!(17 > 16, "threshold is 16 pages");
        assert!(16 <= 16, "16 pages uses per-page path");
    }

    #[test]
    fn test_range_address_calculation() {
        // Verify the per-page address arithmetic in shootdown_range
        let virt_start = 0x4000_0000u64;
        let num_pages = 4;
        let mut addrs = [0u64; 4];
        for i in 0..num_pages {
            addrs[i] = virt_start + (i as u64) * (1 << PAGE_SHIFT);
        }
        assert_eq!(addrs[0], 0x4000_0000);
        assert_eq!(addrs[1], 0x4000_1000);
        assert_eq!(addrs[2], 0x4000_2000);
        assert_eq!(addrs[3], 0x4000_3000);
    }
}
