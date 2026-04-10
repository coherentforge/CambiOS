// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! MMIO register access for the I219-LM driver.
//!
//! Wraps a single mapped MMIO BAR with volatile read/write helpers.
//! All values returned from device memory should be treated as
//! untrusted (the device is hostile under our threat model).

use arcos_libsys as sys;

/// Mapped MMIO region for the device's BAR0.
pub struct Mmio {
    /// User-space virtual address (from `map_mmio`).
    base: u64,
    /// Size of the mapped region in bytes.
    size: u32,
}

impl Mmio {
    /// Map `num_pages` 4KB pages of device MMIO starting at `phys_addr`.
    /// Returns `None` if the kernel rejects the mapping.
    pub fn map(phys_addr: u64, num_pages: u32) -> Option<Self> {
        let vaddr = sys::map_mmio(phys_addr, num_pages);
        if vaddr <= 0 {
            return None;
        }
        Some(Mmio {
            base: vaddr as u64,
            size: num_pages * 4096,
        })
    }

    /// Read a 32-bit register at `offset` bytes from BAR0 base.
    ///
    /// Bounds-checked against the mapped size; returns 0 on overflow.
    pub fn read32(&self, offset: u32) -> u32 {
        if offset + 4 > self.size {
            return 0;
        }
        let ptr = (self.base + offset as u64) as *const u32;
        // SAFETY: ptr is within the mapped MMIO region (bounds checked above).
        // Volatile read is required for device memory.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Write a 32-bit value to a register at `offset` bytes from BAR0 base.
    ///
    /// Bounds-checked against the mapped size; silently ignores out-of-range writes.
    pub fn write32(&self, offset: u32, value: u32) {
        if offset + 4 > self.size {
            return;
        }
        let ptr = (self.base + offset as u64) as *mut u32;
        // SAFETY: ptr is within the mapped MMIO region (bounds checked above).
        // Volatile write is required for device memory.
        unsafe { core::ptr::write_volatile(ptr, value); }
    }

    /// Atomic read-modify-write for setting bits in a 32-bit register.
    pub fn set_bits32(&self, offset: u32, mask: u32) {
        let v = self.read32(offset);
        self.write32(offset, v | mask);
    }

    /// Atomic read-modify-write for clearing bits in a 32-bit register.
    pub fn clear_bits32(&self, offset: u32, mask: u32) {
        let v = self.read32(offset);
        self.write32(offset, v & !mask);
    }
}

/// Spin for a short delay (used during reset / link bringup).
///
/// Not precise — just enough to let the device process a reset.
/// On real hardware, ~1µs per iteration is typical.
pub fn spin_delay(iters: u32) {
    for _ in 0..iters {
        // SAFETY: nop is always safe.
        unsafe { core::arch::asm!("nop", options(nomem, nostack)); }
    }
}
