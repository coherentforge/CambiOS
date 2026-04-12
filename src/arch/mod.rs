// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Architecture abstraction layer
//!
//! Re-exports the active architecture's primitives. Portable modules (spinlock)
//! live directly under `arch/`. Architecture-specific modules live under
//! `arch/<target>/` and are selected at compile time via `#[cfg(target_arch)]`.
//!
//! ## Adding a new architecture
//!
//! 1. Create `arch/<target>/mod.rs` with the same public API as `x86_64/mod.rs`
//! 2. Add a `#[cfg(target_arch = "<target>")]` block below
//! 3. Implement: SavedContext, context_save/restore/switch, timer_isr_stub,
//!    GDT/privilege setup, syscall entry

// Portable modules (no architecture-specific code)
pub mod mmio;
pub mod spinlock;

// Architecture-specific modules
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

// ============================================================================
// Portable TLB shootdown wrapper (Phase 3.2d.iii)
// ============================================================================

/// Invalidate a range of pages across all CPUs.
///
/// Portable wrapper over the arch-specific TLB shootdown. Called by
/// channel close/revoke and process exit to ensure no CPU caches
/// stale mappings after unmap.
///
/// # Safety
///
/// The page table modifications (unmaps) must already be visible in
/// memory before calling this. Must be called at ring 0 / EL1.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn tlb_shootdown_range(virt_addr: u64, page_count: u32) {
    // SAFETY: caller guarantees page table mods are committed.
    unsafe { x86_64::tlb::shootdown_range(virt_addr, page_count) }
}

/// AArch64 variant: TLBI broadcast instructions (hardware-mediated, no IPI).
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn tlb_shootdown_range(virt_addr: u64, page_count: u32) {
    // AArch64 shootdown_range is inherently safe (TLBI + DSB + ISB),
    // but we wrap it as unsafe to match the portable API contract.
    aarch64::tlb::shootdown_range(virt_addr, page_count as usize);
}
