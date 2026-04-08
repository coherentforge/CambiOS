// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Page table management
//!
//! Provides kernel page table operations on top of the Limine-provided identity
//! + HHDM mapping. Uses the x86_64 crate's `OffsetPageTable` for safe
//! traversal via the HHDM offset.
//!
//! ## Memory layout (set up by Limine, extended here)
//!
//! | Virtual range                      | Maps to            | Purpose            |
//! |------------------------------------|---------------------|--------------------|
//! | 0x0000_0000_0000 .. kernel_end     | Identity (phys=virt)| Limine default     |
//! | 0xFFFF_8000_0000_0000 + phys       | Physical memory     | HHDM               |
//! | Per-process user-space ranges       | Per-process frames  | Future user tasks  |

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    OffsetPageTable, PageTable, PageTableFlags, Mapper, Page, Size4KiB,
    FrameAllocator as X86FrameAllocator, PhysFrame as X86PhysFrame,
};
use x86_64::{PhysAddr, VirtAddr};
use super::frame_allocator::{FrameAllocator, PhysFrame, PAGE_SIZE};
use core::fmt;

/// Errors from page table operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingError {
    /// Frame allocator out of memory
    FrameAllocationFailed,
    /// Attempted to map an already-mapped page
    AlreadyMapped,
    /// Page is not mapped (for unmap/query)
    NotMapped,
    /// Invalid virtual address (not canonical, etc.)
    InvalidAddress,
}

impl fmt::Display for PagingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PagingError::FrameAllocationFailed => write!(f, "frame allocation failed"),
            PagingError::AlreadyMapped => write!(f, "page already mapped"),
            PagingError::NotMapped => write!(f, "page not mapped"),
            PagingError::InvalidAddress => write!(f, "invalid virtual address"),
        }
    }
}

/// Adapter: wraps our FrameAllocator to implement the x86_64 crate trait.
///
/// The x86_64 crate's `OffsetPageTable::map_to()` needs a `FrameAllocator`
/// to allocate intermediate page table frames (PDP, PD, PT levels).
pub struct FrameAllocatorAdapter<'a> {
    inner: &'a mut FrameAllocator,
}

impl<'a> FrameAllocatorAdapter<'a> {
    pub fn new(allocator: &'a mut FrameAllocator) -> Self {
        Self { inner: allocator }
    }
}

// SAFETY: allocate_frame returns a correctly aligned 4 KiB physical frame
// obtained from our bitmap-based FrameAllocator, which guarantees each frame
// is allocated at most once. The frame's physical address is valid memory
// reported by Limine.
unsafe impl<'a> X86FrameAllocator<Size4KiB> for FrameAllocatorAdapter<'a> {
    fn allocate_frame(&mut self) -> Option<X86PhysFrame<Size4KiB>> {
        self.inner
            .allocate()
            .ok()
            .map(|f| X86PhysFrame::containing_address(PhysAddr::new(f.addr)))
    }
}

/// Get the active PML4 page table via HHDM.
///
/// # Safety
/// The HHDM offset must have been set (`crate::set_hhdm_offset`).
/// CR3 must point to a valid PML4. Only one mutable reference may
/// exist at a time.
pub unsafe fn active_page_table() -> OffsetPageTable<'static> {
    let (pml4_frame, _) = Cr3::read();
    let phys = pml4_frame.start_address().as_u64();
    let hhdm = crate::hhdm_offset();
    let virt = (phys + hhdm) as *mut PageTable;

    // SAFETY: CR3 points to a valid PML4 frame. HHDM offset (set by Limine) maps
    // all physical memory to the higher half, so (phys + hhdm) is a valid virtual
    // address for this frame. Caller ensures only one mutable reference exists.
    unsafe { OffsetPageTable::new(&mut *virt, VirtAddr::new(hhdm)) }
}

/// Get an OffsetPageTable for a specific PML4 physical address via HHDM.
///
/// # Safety
/// `pml4_phys` must point to a valid PML4 page table frame.
/// Only one mutable reference may exist at a time.
pub unsafe fn page_table_from_cr3(pml4_phys: u64) -> OffsetPageTable<'static> {
    let hhdm = crate::hhdm_offset();
    let virt = (pml4_phys + hhdm) as *mut PageTable;
    // SAFETY: pml4_phys was obtained from create_process_page_table() or Cr3::read();
    // both produce valid PML4 physical addresses. HHDM maps it to a valid VA.
    // Caller ensures only one mutable reference exists.
    unsafe { OffsetPageTable::new(&mut *virt, VirtAddr::new(hhdm)) }
}

/// Map a single 4 KiB virtual page to a physical frame.
///
/// Allocates intermediate page table levels (PDP, PD, PT) as needed
/// from the frame allocator.
pub fn map_page(
    page_table: &mut OffsetPageTable,
    virt_addr: u64,
    phys_addr: u64,
    flags: PageTableFlags,
    frame_alloc: &mut FrameAllocator,
) -> Result<(), PagingError> {
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt_addr));
    let frame = X86PhysFrame::containing_address(PhysAddr::new(phys_addr));

    let mut adapter = FrameAllocatorAdapter::new(frame_alloc);

    // SAFETY: page and frame are derived from validated addresses. The adapter
    // provides valid physical frames for intermediate page table levels. map_to
    // writes entries into the page table hierarchy rooted at page_table.
    unsafe {
        page_table
            .map_to(page, frame, flags, &mut adapter)
            .map_err(|_| PagingError::AlreadyMapped)?
            .flush();
    }

    Ok(())
}

/// Unmap a single 4 KiB virtual page.
///
/// Returns the physical frame that was mapped (caller can free it).
///
/// ## SMP note
/// This performs a **local** TLB flush only. If the mapping is in a page table
/// active on multiple CPUs (e.g., the kernel page table), the caller must also
/// call `arch::x86_64::tlb::shootdown_page(virt_addr)` to invalidate remote
/// TLB entries. Per-process page tables that are only active on one CPU at a
/// time do not need a shootdown.
pub fn unmap_page(
    page_table: &mut OffsetPageTable,
    virt_addr: u64,
) -> Result<PhysFrame, PagingError> {
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt_addr));

    let (frame, flush) = page_table
        .unmap(page)
        .map_err(|_| PagingError::NotMapped)?;

    flush.flush();

    Ok(PhysFrame {
        addr: frame.start_address().as_u64(),
    })
}

/// Map a contiguous range of virtual pages to contiguous physical frames.
///
/// Maps `count` 4 KiB pages starting at `virt_base` → `phys_base`.
pub fn map_range(
    page_table: &mut OffsetPageTable,
    virt_base: u64,
    phys_base: u64,
    count: usize,
    flags: PageTableFlags,
    frame_alloc: &mut FrameAllocator,
) -> Result<(), PagingError> {
    for i in 0..count {
        let offset = i as u64 * PAGE_SIZE;
        map_page(
            page_table,
            virt_base + offset,
            phys_base + offset,
            flags,
            frame_alloc,
        )?;
    }
    Ok(())
}

/// Query the physical address mapped by a virtual address.
///
/// Returns `None` if the page is not mapped.
pub fn translate(page_table: &OffsetPageTable, virt_addr: u64) -> Option<u64> {
    use x86_64::structures::paging::mapper::Translate;
    let virt = VirtAddr::new(virt_addr);
    page_table.translate_addr(virt).map(|pa| pa.as_u64())
}

/// Create a new PML4 for a user process.
///
/// Allocates a fresh 4 KiB frame, zeros it, then copies the kernel-half entries
/// (indices 256..512) from the current active PML4 so the kernel is mapped in
/// every address space. Returns the physical address of the new PML4 (suitable
/// for loading into CR3).
///
/// # Safety
/// Must be called with a valid HHDM offset already set.
pub fn create_process_page_table(
    frame_alloc: &mut FrameAllocator,
) -> Result<u64, PagingError> {
    // Allocate a frame for the new PML4
    let pml4_frame = frame_alloc
        .allocate()
        .map_err(|_| PagingError::FrameAllocationFailed)?;
    let pml4_phys = pml4_frame.addr;

    let hhdm = crate::hhdm_offset();

    // Zero the entire new PML4
    let new_pml4 = (pml4_phys + hhdm) as *mut PageTable;
    // SAFETY: pml4_phys is a freshly allocated frame. HHDM maps it to a valid VA.
    // We zero 4096 bytes (one page), which is exactly the frame size.
    unsafe {
        core::ptr::write_bytes(new_pml4 as *mut u8, 0, PAGE_SIZE as usize);
    }

    // Copy kernel-half entries (256..512) from the current PML4
    let (current_pml4_frame, _) = Cr3::read();
    let current_pml4_phys = current_pml4_frame.start_address().as_u64();
    let current_pml4 = (current_pml4_phys + hhdm) as *const PageTable;

    // SAFETY: Both current_pml4 and new_pml4 are valid HHDM-mapped page tables.
    // We copy entries 256..512 (the kernel half): 256 × 8 = 2048 bytes.
    // Source and destination don't overlap (different physical frames).
    unsafe {
        let src = (current_pml4 as *const u8).add(256 * 8);
        let dst = (new_pml4 as *mut u8).add(256 * 8);
        core::ptr::copy_nonoverlapping(src, dst, 256 * 8);
    }

    Ok(pml4_phys)
}

/// Free a process page table PML4 frame.
///
/// Only frees the PML4 frame itself. Intermediate page table frames
/// (PDP/PD/PT) allocated for user-space mappings are NOT freed — the caller
/// must unmap user pages first. Kernel-half entries (256..512) are shared
/// pointers and must NOT be freed.
pub fn free_process_page_table(
    frame_alloc: &mut FrameAllocator,
    pml4_phys: u64,
) {
    let _ = frame_alloc.free(PhysFrame { addr: pml4_phys });
}

/// Standard flag combinations for common page types.
pub mod flags {
    use x86_64::structures::paging::PageTableFlags;

    /// Kernel code: present, readable (no writable, no user)
    pub const KERNEL_RO: PageTableFlags = PageTableFlags::PRESENT;

    /// Kernel data: present, writable
    pub fn kernel_rw() -> PageTableFlags {
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE
    }

    /// User code: present, user-accessible
    pub fn user_ro() -> PageTableFlags {
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
    }

    /// User data: present, writable, user-accessible
    pub fn user_rw() -> PageTableFlags {
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
    }

    /// User MMIO: present, writable, user-accessible, uncacheable (NO_CACHE).
    /// For mapping device MMIO regions into user-space processes.
    pub fn user_mmio() -> PageTableFlags {
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_CACHE
    }
}
