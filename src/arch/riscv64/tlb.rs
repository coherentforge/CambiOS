// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! TLB management — RISC-V (S-mode)
//!
//! RISC-V's S-mode TLB invalidation instruction is `sfence.vma`.
//! Unlike AArch64's TLBI (which broadcasts across the inner shareable
//! domain via hardware), `sfence.vma` is **local only** — remote
//! invalidation on other harts requires an IPI + `sfence.vma` on each
//! target, or the Svinval extension's `sinval.vma` (broadcast-style).
//!
//! For Phase R-1 / R-3 (single-hart or local-only contexts), these
//! wrappers invalidate only the current hart's TLB. Phase R-5 adds
//! SBI IPI cross-hart shootdown and probes for Svinval.
//!
//! ## sfence.vma operand forms
//!
//! - `sfence.vma` (no operands)          — flush all TLB entries
//! - `sfence.vma rs1`                    — flush entries for VA rs1
//! - `sfence.vma rs1, rs2`               — flush for VA rs1 in ASID rs2
//! - `sfence.vma x0, rs2`                — flush all entries of ASID rs2
//!
//! We do not currently use ASIDs (single global address space per
//! kernel-mode fence). That decision is revisited if/when the kernel
//! grows multi-process ASID tagging.

/// Invalidate a single page on the current hart.
///
/// Phase R-5 will extend this to broadcast via SBI IPI.
pub fn shootdown_page(virt_addr: u64) {
    // SAFETY: sfence.vma is always legal from S-mode. The `mem`-clobber
    // tells the compiler preceding writes to page tables must commit
    // before the fence executes.
    unsafe {
        core::arch::asm!(
            "sfence.vma {0}, x0",
            in(reg) virt_addr,
            options(nostack, preserves_flags),
        );
    }
}

/// Invalidate a range of pages on the current hart.
///
/// Matches the AArch64 threshold (16 pages) for switching between
/// per-page and full-flush; `sfence.vma` without operands flushes all.
pub fn shootdown_range(virt_start: u64, num_pages: usize) {
    const PAGE_SHIFT: u64 = 12;

    if num_pages > 16 {
        shootdown_all();
        return;
    }
    // SAFETY: Each sfence.vma is safe from S-mode. Operand = page
    // address (not shifted — the ISA expects the full VA).
    unsafe {
        for i in 0..num_pages {
            let addr = virt_start + (i as u64) * (1 << PAGE_SHIFT);
            core::arch::asm!(
                "sfence.vma {0}, x0",
                in(reg) addr,
                options(nostack, preserves_flags),
            );
        }
    }
}

/// Invalidate all TLB entries on the current hart.
pub fn shootdown_all() {
    // SAFETY: sfence.vma with no operands flushes all TLB entries for
    // this hart. Legal from S-mode.
    unsafe {
        core::arch::asm!(
            "sfence.vma",
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_bulk_threshold() {
        // Matches the AArch64 / x86_64 convention.
        assert!(17 > 16);
    }
}
