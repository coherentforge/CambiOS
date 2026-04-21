// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Safe MMIO register access abstraction
//!
//! Wraps volatile reads/writes to memory-mapped I/O regions. All MMIO access
//! in the kernel should go through this module rather than calling
//! `core::ptr::read_volatile`/`write_volatile` directly.
//!
//! # Safety model
//! The unsafe boundary is at construction time: the caller of `new()` must
//! guarantee that `base` points to a valid, mapped MMIO region of sufficient
//! size. Once constructed, all register reads and writes are safe — the type
//! encapsulates the pointer validity invariant.

/// A memory-mapped I/O region with typed 32-bit register access.
///
/// Constructed from a validated base address (e.g., from HHDM mapping or
/// `early_map_mmio`). All subsequent reads/writes are safe because the base
/// address validity is guaranteed at construction time.
#[derive(Clone, Copy)]
pub struct MmioRegion {
    base: usize,
}

impl MmioRegion {
    /// Create a new MMIO region handle.
    ///
    /// # Safety
    /// `base` must be a valid virtual address pointing to a mapped MMIO region.
    /// The region must remain mapped for the lifetime of this handle.
    /// The mapping must use appropriate caching attributes (e.g., uncacheable
    /// for device MMIO).
    #[inline]
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Read a 32-bit register at the given byte offset from the base.
    #[inline]
    pub fn read32(&self, offset: usize) -> u32 {
        // SAFETY: base was validated at construction time. The caller is
        // responsible for providing a valid offset within the MMIO region.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    /// Write a 32-bit value to a register at the given byte offset from the base.
    #[inline]
    pub fn write32(&self, offset: usize, value: u32) {
        // SAFETY: base was validated at construction time. The caller is
        // responsible for providing a valid offset within the MMIO region.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Read a 64-bit register at the given byte offset from the base.
    #[inline]
    pub fn read64(&self, offset: usize) -> u64 {
        // SAFETY: Same as read32.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u64) }
    }

    /// Write a 64-bit value to a register at the given byte offset from the base.
    #[inline]
    pub fn write64(&self, offset: usize, value: u64) {
        // SAFETY: Same as write32.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u64, value) }
    }

    /// Return the base address of this MMIO region.
    #[inline]
    pub const fn base(&self) -> usize {
        self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmio_region_construction() {
        // Verify construction preserves the base address.
        // SAFETY: Test only — we never dereference the pointer.
        let region = unsafe { MmioRegion::new(0xDEAD_0000) };
        assert_eq!(region.base(), 0xDEAD_0000);
    }
}
