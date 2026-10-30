// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! DMA pages from `SYS_ALLOC_DMA` and volatile MMIO access. The whole
//! `unsafe` surface of the driver lives here: a page the kernel handed us
//! (both addresses known, 4 KiB, ours for the process lifetime) and
//! register accesses inside a BAR the kernel mapped.

use cambios_libsys as sys;

/// One 4 KiB DMA page: kernel-mapped virtual address + physical address
/// for the controller.
#[derive(Clone, Copy)]
pub struct DmaPage {
    pub vaddr: u64,
    pub paddr: u64,
}

impl DmaPage {
    pub const SIZE: usize = 4096;

    /// Allocate and zero one page. Queues rely on zeroed memory for the
    /// phase-bit protocol; data pages simply start clean.
    pub fn new() -> Option<Self> {
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut paddr);
        if ret < 0 {
            return None;
        }
        let page = DmaPage { vaddr: ret as u64, paddr };
        page.zero();
        Some(page)
    }

    pub fn zero(&self) {
        // SAFETY: `vaddr` is the start of a 4 KiB DMA page the kernel
        // mapped for this process; the write covers exactly that page.
        unsafe { core::ptr::write_bytes(self.vaddr as *mut u8, 0, Self::SIZE) };
    }

    /// Copy from the page at `offset` into `dst` (clamped to the page).
    pub fn read(&self, offset: usize, dst: &mut [u8]) -> usize {
        if offset >= Self::SIZE {
            return 0;
        }
        let len = core::cmp::min(dst.len(), Self::SIZE - offset);
        // SAFETY: src..src+len lies inside this page (clamped above);
        // `dst` is a live mutable slice of `len` bytes; regions distinct.
        unsafe { core::ptr::copy_nonoverlapping((self.vaddr + offset as u64) as *const u8, dst.as_mut_ptr(), len) };
        len
    }

    /// Volatile 32-bit read at `offset` (for completion-queue polling —
    /// the controller writes these behind the compiler's back).
    pub fn read_u32(&self, offset: usize) -> u32 {
        debug_assert!(offset + 4 <= Self::SIZE && offset % 4 == 0);
        // SAFETY: offset is 4-byte aligned and inside the page; the page
        // is DMA memory the controller may write concurrently, hence volatile.
        unsafe { core::ptr::read_volatile((self.vaddr + offset as u64) as *const u32) }
    }

    /// Volatile 32-bit write at `offset` (submission-queue entries).
    pub fn write_u32(&self, offset: usize, value: u32) {
        debug_assert!(offset + 4 <= Self::SIZE && offset % 4 == 0);
        // SAFETY: as `read_u32`; the controller reads these after the
        // doorbell write, so the store must not be elided or reordered.
        unsafe { core::ptr::write_volatile((self.vaddr + offset as u64) as *mut u32, value) }
    }

}

/// The controller's register BAR, mapped by `SYS_MAP_MMIO`.
#[derive(Clone, Copy)]
pub struct Mmio {
    base: u64,
    size: u64,
}

impl Mmio {
    /// Map `size` bytes at `phys`; `None` if the kernel refuses.
    pub fn map(phys: u64, size: u32) -> Option<Self> {
        let pages = ((size as u64 + 0xFFF) / 0x1000).max(1) as u32;
        let mapped = sys::map_mmio(phys, pages);
        if mapped < 0 {
            return None;
        }
        Some(Mmio { base: mapped as u64, size: pages as u64 * 4096 })
    }

    fn check(&self, offset: u64, width: u64) -> bool {
        offset % width == 0 && offset + width <= self.size
    }

    pub fn read32(&self, offset: u64) -> u32 {
        if !self.check(offset, 4) {
            return 0xFFFF_FFFF;
        }
        // SAFETY: offset is aligned and inside the mapped BAR (checked);
        // device registers are volatile by nature.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    pub fn write32(&self, offset: u64, value: u32) {
        if !self.check(offset, 4) {
            return;
        }
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    pub fn read64(&self, offset: u64) -> u64 {
        if !self.check(offset, 8) {
            return u64::MAX;
        }
        // SAFETY: as `read32`; CAP/ASQ/ACQ are 8-byte registers and the
        // NVMe spec permits 32-bit or 64-bit accesses to them.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u64) }
    }

    pub fn write64(&self, offset: u64, value: u64) {
        if !self.check(offset, 8) {
            return;
        }
        // SAFETY: as `read64`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u64, value) }
    }
}
