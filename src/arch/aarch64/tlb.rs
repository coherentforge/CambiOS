//! TLB management — AArch64 scaffold
//!
//! AArch64 has hardware-assisted TLB maintenance via TLBI instructions.
//! On ARMv8.4+, TLBI broadcasts are handled by hardware (no IPI needed).
//! On earlier cores, software IPIs (SGI) can coordinate invalidation.
//!
//! Key instructions:
//! - `TLBI VALE1IS, <Xt>` — invalidate by VA, last level, inner shareable
//! - `TLBI VMALLE1IS`     — invalidate all EL1 entries, inner shareable
//! - `DSB ISH`            — data synchronization barrier, inner shareable
//! - `ISB`                — instruction synchronization barrier

/// Invalidate a single page across all CPUs.
///
/// On ARMv8.4+, uses `TLBI VALE1IS` (broadcast by hardware).
pub fn shootdown_page(_virt_addr: u64) {
    todo!("AArch64: TLBI VALE1IS + DSB ISH + ISB")
}

/// Invalidate a range of pages across all CPUs.
pub fn shootdown_range(_virt_start: u64, _num_pages: usize) {
    todo!("AArch64: TLBI range or per-page loop")
}

/// Invalidate all TLB entries across all CPUs.
pub fn shootdown_all() {
    todo!("AArch64: TLBI VMALLE1IS + DSB ISH + ISB")
}
