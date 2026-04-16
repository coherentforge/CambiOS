// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Memory management subsystem
//!
//! Handles memory initialization, paging, and allocation strategies.
//! Designed with verification in mind: clear interfaces and explicit assumptions.

#[cfg(target_arch = "x86_64")]
use x86_64::registers::control::Cr3;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::paging::PageTable;
use core::sync::atomic::{AtomicU8, Ordering};

pub mod buddy_allocator;
pub mod frame_allocator;
pub mod heap;
pub mod object_table;

#[cfg(target_arch = "x86_64")]
pub mod paging;

/// AArch64 page table implementation.
///
/// Implements a 4-level page table walk for 4KB granule, 48-bit virtual
/// address space (levels L0-L3). Each level has 512 entries × 8 bytes = 4KB.
///
/// ## Address translation (4KB granule, 48-bit VA)
/// ```text
/// VA[47:39] → L0 index (9 bits, 512 entries)
/// VA[38:30] → L1 index (9 bits, 512 entries)
/// VA[29:21] → L2 index (9 bits, 512 entries)
/// VA[20:12] → L3 index (9 bits, 512 entries)
/// VA[11:0]  → page offset (12 bits, 4KB)
/// ```
///
/// ## Descriptor format (4KB granule)
/// ```text
/// [0]     = Valid
/// [1]     = Table (L0-L2) or Page (L3) — must be 1 for valid entries
/// [4:2]   = AttrIndx (MAIR index: 0=Device, 1=Normal)
/// [5]     = NS (non-secure)
/// [7:6]   = AP — access permissions:
///           00: EL1 RW, EL0 no access
///           01: EL1 RW, EL0 RW
///           10: EL1 RO, EL0 no access
///           11: EL1 RO, EL0 RO
/// [9:8]   = SH — shareability: 11=Inner Shareable
/// [10]    = AF — Access Flag (must be 1 to avoid access fault)
/// [47:12] = Output address (physical page frame)
/// [53]    = PXN — Privileged eXecute Never
/// [54]    = UXN/XN — User eXecute Never
/// ```
///
/// ## TTBR split
/// - TTBR0_EL1: user mapping (VA bit[55]=0, lower half)
/// - TTBR1_EL1: kernel mapping (VA bit[55]=1, upper half, 0xFFFF...)
///
/// We use TTBR0_EL1 for process page tables (switched on context switch)
/// and TTBR1_EL1 for the kernel page table (shared across all processes).
#[cfg(not(target_arch = "x86_64"))]
pub mod paging {
    use super::frame_allocator::{FrameAllocator, PhysFrame, PAGE_SIZE};
    use core::fmt;

    // ========================================================================
    // Error type (matches x86_64 version)
    // ========================================================================

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PagingError {
        FrameAllocationFailed,
        AlreadyMapped,
        NotMapped,
        InvalidAddress,
    }

    impl fmt::Display for PagingError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    // ========================================================================
    // AArch64 descriptor bit definitions
    // ========================================================================

    /// Valid bit — entry is active
    const DESC_VALID: u64 = 1 << 0;
    /// Table descriptor (L0-L2) or Page descriptor (L3)
    const DESC_TABLE: u64 = 1 << 1;
    /// Access Flag — must be set to avoid access faults
    const DESC_AF: u64 = 1 << 10;
    /// Inner Shareable (for SMP coherency)
    const DESC_ISH: u64 = 0b11 << 8;
    /// AP[1]: EL0 accessible
    const DESC_AP_EL0: u64 = 1 << 6;
    /// AP[2]: Read-only
    const DESC_AP_RO: u64 = 1 << 7;
    /// AttrIndx=1 (Normal memory in MAIR — see boot config)
    const DESC_ATTR_NORMAL: u64 = 1 << 2;
    /// AttrIndx=0 (Device-nGnRnE in MAIR)
    #[allow(dead_code)]
    const DESC_ATTR_DEVICE: u64 = 0 << 2;
    /// PXN: Privileged eXecute Never
    const DESC_PXN: u64 = 1 << 53;
    /// UXN: User eXecute Never
    const DESC_UXN: u64 = 1 << 54;
    /// Mask for output address bits [47:12]
    const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    /// Number of entries per page table level
    const ENTRIES_PER_TABLE: usize = 512;

    // ========================================================================
    // Page table handle
    // ========================================================================

    /// Handle to a root page table (L0).
    ///
    /// Wraps the physical address of the L0 table (the value that goes into
    /// TTBR0_EL1 or was read from it).
    pub struct PageTableRef {
        /// Physical address of the L0 page table (TTBR0_EL1 value)
        root_phys: u64,
    }

    /// Extract the HHDM offset for physical-to-virtual translation.
    #[inline]
    fn hhdm() -> u64 {
        crate::hhdm_offset()
    }

    /// Convert a physical address to a virtual address via HHDM.
    #[inline]
    fn phys_to_virt(phys: u64) -> *mut u64 {
        (phys + hhdm()) as *mut u64
    }

    /// Extract the L0 index from a 48-bit VA.
    #[inline]
    const fn l0_index(va: u64) -> usize {
        ((va >> 39) & 0x1FF) as usize
    }
    /// Extract the L1 index from a 48-bit VA.
    #[inline]
    const fn l1_index(va: u64) -> usize {
        ((va >> 30) & 0x1FF) as usize
    }
    /// Extract the L2 index from a 48-bit VA.
    #[inline]
    const fn l2_index(va: u64) -> usize {
        ((va >> 21) & 0x1FF) as usize
    }
    /// Extract the L3 index from a 48-bit VA.
    #[inline]
    const fn l3_index(va: u64) -> usize {
        ((va >> 12) & 0x1FF) as usize
    }

    /// Read a page table entry at a given level and index.
    ///
    /// # Safety
    /// `table_phys` must be the physical address of a valid page table frame.
    #[inline]
    unsafe fn read_entry(table_phys: u64, index: usize) -> u64 {
        debug_assert!(index < ENTRIES_PER_TABLE);
        let ptr = phys_to_virt(table_phys);
        // SAFETY: table_phys is a valid page table frame, index is in bounds.
        // HHDM maps the frame to a valid VA. Volatile read for hardware coherency.
        unsafe { core::ptr::read_volatile(ptr.add(index)) }
    }

    /// Write a page table entry at a given level and index.
    ///
    /// # Safety
    /// `table_phys` must be the physical address of a valid page table frame.
    #[inline]
    unsafe fn write_entry(table_phys: u64, index: usize, value: u64) {
        debug_assert!(index < ENTRIES_PER_TABLE);
        let ptr = phys_to_virt(table_phys);
        // SAFETY: Same as read_entry. Volatile write ensures hardware sees update.
        unsafe { core::ptr::write_volatile(ptr.add(index), value) };
    }

    /// Walk levels L0→L1→L2, allocating intermediate tables as needed.
    /// Returns the physical address of the L3 table.
    ///
    /// At each level, if the entry is not valid, allocate a new frame,
    /// zero it, and install a table descriptor pointing to it.
    unsafe fn walk_to_l3(
        root_phys: u64,
        va: u64,
        frame_alloc: &mut FrameAllocator,
    ) -> Result<u64, PagingError> {
        let indices = [l0_index(va), l1_index(va), l2_index(va)];
        let mut table_phys = root_phys;

        // SAFETY: Caller guarantees root_phys is a valid page table. Each
        // iteration either descends into an existing valid table or allocates
        // a fresh zeroed frame and installs a table descriptor.
        unsafe {
            for &idx in &indices {
                let entry = read_entry(table_phys, idx);
                if entry & DESC_VALID != 0 {
                    // Entry exists — descend
                    table_phys = entry & ADDR_MASK;
                } else {
                    // Allocate a new table frame
                    let frame = frame_alloc
                        .allocate()
                        .map_err(|_| PagingError::FrameAllocationFailed)?;
                    // Zero the new table
                    // SAFETY: frame.addr is a freshly allocated frame, HHDM maps it.
                    core::ptr::write_bytes(
                        phys_to_virt(frame.addr) as *mut u8,
                        0,
                        PAGE_SIZE as usize,
                    );
                    // Install table descriptor: Valid + Table + ISH + AF + Normal
                    let desc = frame.addr | DESC_VALID | DESC_TABLE;
                    write_entry(table_phys, idx, desc);
                    table_phys = frame.addr;
                }
            }
        }

        Ok(table_phys)
    }

    /// Walk levels L0→L1→L2 (read-only, no allocation).
    /// Returns the physical address of the L3 table, or None if any level is unmapped.
    unsafe fn walk_to_l3_readonly(root_phys: u64, va: u64) -> Option<u64> {
        let indices = [l0_index(va), l1_index(va), l2_index(va)];
        let mut table_phys = root_phys;

        // SAFETY: Caller guarantees root_phys is a valid page table.
        // Each level descends through valid table descriptors.
        unsafe {
            for &idx in &indices {
                let entry = read_entry(table_phys, idx);
                if entry & DESC_VALID == 0 {
                    return None;
                }
                table_phys = entry & ADDR_MASK;
            }
        }

        Some(table_phys)
    }

    // ========================================================================
    // Public API (matches x86_64 paging module)
    // ========================================================================

    /// Get a handle to the active user page table (TTBR0_EL1).
    ///
    /// # Safety
    /// HHDM offset must be set. TTBR0_EL1 must point to a valid L0 table.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn active_page_table() -> PageTableRef {
        let ttbr0: u64;
        // SAFETY: Reading TTBR0_EL1 from EL1 is always safe.
        unsafe {
            core::arch::asm!(
                "mrs {0}, ttbr0_el1",
                out(reg) ttbr0,
                options(nostack, nomem, preserves_flags),
            );
        }
        PageTableRef {
            root_phys: ttbr0 & ADDR_MASK,
        }
    }

    /// Fallback for non-aarch64, non-x86_64 targets (test host).
    #[cfg(not(target_arch = "aarch64"))]
    pub unsafe fn active_page_table() -> PageTableRef {
        PageTableRef { root_phys: 0 }
    }

    /// Get a page table handle from a physical address (TTBR0 value).
    ///
    /// Named `page_table_from_cr3` for API compatibility with x86_64 code.
    ///
    /// # Safety
    /// `cr3` must be the physical address of a valid L0 page table.
    pub unsafe fn page_table_from_cr3(cr3: u64) -> PageTableRef {
        PageTableRef {
            root_phys: cr3 & ADDR_MASK,
        }
    }

    /// Map a single 4KB virtual page to a physical frame.
    ///
    /// Allocates intermediate page table levels (L1, L2, L3) as needed.
    pub fn map_page(
        pt: &mut PageTableRef,
        virt_addr: u64,
        phys_addr: u64,
        page_flags: flags::PageFlags,
        frame_alloc: &mut FrameAllocator,
    ) -> Result<(), PagingError> {
        // Masking below is tolerant in release builds (preserves existing
        // behavior) but hides callsite bugs where a byte-offset was mistaken
        // for a frame-aligned address. Assert the contract at the boundary.
        debug_assert_eq!(virt_addr & 0xFFF, 0, "map_page virt_addr not page-aligned");
        debug_assert_eq!(phys_addr & 0xFFF, 0, "map_page phys_addr not page-aligned");
        let va = virt_addr & !0xFFF; // Page-align
        let pa = phys_addr & !0xFFF;

        // SAFETY: pt.root_phys is valid. frame_alloc may allocate.
        let l3_phys = unsafe { walk_to_l3(pt.root_phys, va, frame_alloc)? };

        let idx = l3_index(va);
        // SAFETY: l3_phys is valid.
        let existing = unsafe { read_entry(l3_phys, idx) };
        if existing & DESC_VALID != 0 {
            return Err(PagingError::AlreadyMapped);
        }

        // Build L3 page descriptor:
        // Valid + Page(1) + AF + ISH + memory type + user flags
        let is_device = page_flags.0 & flags::DEVICE_MEMORY_FLAG != 0;
        let attr = if is_device { DESC_ATTR_DEVICE } else { DESC_ATTR_NORMAL };
        // Strip the internal DEVICE_MEMORY_FLAG before writing to hardware
        let hw_flags = page_flags.0 & !flags::DEVICE_MEMORY_FLAG;
        let desc = pa
            | DESC_VALID
            | DESC_TABLE  // At L3, bit[1]=1 means "page" descriptor
            | DESC_AF
            | DESC_ISH
            | attr
            | hw_flags;

        // SAFETY: l3_phys and idx are valid.
        unsafe { write_entry(l3_phys, idx, desc) };

        // Ensure the new mapping is visible
        // SAFETY: DSB+ISB barrier sequence is valid at EL1 and has no
        // side effects beyond flushing the pipeline and TLB.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("dsb ishst", "isb", options(nostack));
        }

        Ok(())
    }

    /// Unmap a single 4KB page and return the physical frame.
    pub fn unmap_page(
        pt: &mut PageTableRef,
        virt_addr: u64,
    ) -> Result<PhysFrame, PagingError> {
        let va = virt_addr & !0xFFF;

        // SAFETY: pt.root_phys is valid.
        let l3_phys = unsafe {
            walk_to_l3_readonly(pt.root_phys, va)
                .ok_or(PagingError::NotMapped)?
        };

        let idx = l3_index(va);
        // SAFETY: l3_phys is valid.
        let entry = unsafe { read_entry(l3_phys, idx) };
        if entry & DESC_VALID == 0 {
            return Err(PagingError::NotMapped);
        }

        let frame_phys = entry & ADDR_MASK;

        // Clear the entry
        // SAFETY: l3_phys and idx are valid.
        unsafe { write_entry(l3_phys, idx, 0) };

        // Invalidate TLB for this page
        #[cfg(target_arch = "aarch64")]
        {
            crate::arch::tlb::shootdown_page(va);
        }

        Ok(PhysFrame { addr: frame_phys })
    }

    /// Map a contiguous range of virtual pages to contiguous physical frames.
    pub fn map_range(
        pt: &mut PageTableRef,
        virt_base: u64,
        phys_base: u64,
        count: usize,
        page_flags: flags::PageFlags,
        frame_alloc: &mut FrameAllocator,
    ) -> Result<(), PagingError> {
        for i in 0..count {
            let offset = i as u64 * PAGE_SIZE;
            map_page(
                pt,
                virt_base + offset,
                phys_base + offset,
                page_flags,
                frame_alloc,
            )?;
        }
        Ok(())
    }

    /// Query the physical address mapped by a virtual address.
    ///
    /// Returns `None` if the page is not mapped.
    pub fn translate(pt: &PageTableRef, virt_addr: u64) -> Option<u64> {
        let va = virt_addr & !0xFFF;
        let page_offset = virt_addr & 0xFFF;

        // SAFETY: pt.root_phys is valid.
        let l3_phys = unsafe { walk_to_l3_readonly(pt.root_phys, va)? };

        let idx = l3_index(va);
        // SAFETY: l3_phys is valid.
        let entry = unsafe { read_entry(l3_phys, idx) };
        if entry & DESC_VALID == 0 {
            return None;
        }

        Some((entry & ADDR_MASK) + page_offset)
    }

    /// Create a new L0 page table for a user process.
    ///
    /// Allocates a fresh 4KB frame, zeros it, then copies the kernel-half
    /// entries (L0 indices 256..512) from TTBR1_EL1 so kernel space is
    /// mapped in every address space. Returns the physical address of the
    /// new L0 table (suitable for loading into TTBR0_EL1).
    ///
    /// ## AArch64 vs x86_64
    /// On x86_64, kernel entries live in the upper half of the PML4
    /// (indices 256..512). On AArch64 with split TTBR0/TTBR1, the kernel
    /// uses TTBR1_EL1 (addresses ≥ 0xFFFF_0000_0000_0000) and user uses
    /// TTBR0_EL1 (addresses < 0x0001_0000_0000_0000). Since the kernel
    /// lives in TTBR1 space, we do NOT need to copy kernel entries into
    /// user page tables — they're entirely separate tables.
    pub fn create_process_page_table(
        frame_alloc: &mut FrameAllocator,
    ) -> Result<u64, PagingError> {
        let frame = frame_alloc
            .allocate()
            .map_err(|_| PagingError::FrameAllocationFailed)?;

        // Zero the entire L0 table
        // SAFETY: frame.addr is a freshly allocated frame, HHDM maps it.
        unsafe {
            core::ptr::write_bytes(
                phys_to_virt(frame.addr) as *mut u8,
                0,
                PAGE_SIZE as usize,
            );
        }

        // On AArch64 with TTBR0/TTBR1 split, user L0 tables are clean
        // (no kernel entries to copy — kernel lives in TTBR1 space).
        // If Limine uses a unified TTBR0 with kernel mapped in upper
        // half, we'd need to copy entries here. For now, keep it clean.

        Ok(frame.addr)
    }

    /// Free a process page table L0 frame.
    ///
    /// Only frees the L0 frame itself. Intermediate frames (L1/L2/L3)
    /// must be freed by unmapping all user pages first.
    pub fn free_process_page_table(
        frame_alloc: &mut FrameAllocator,
        phys: u64,
    ) {
        let _ = frame_alloc.free(PhysFrame { addr: phys });
    }

    /// Walk an AArch64 TTBR0 L0 table and free all intermediate page
    /// table frames (L1, L2, L3 levels), then free the L0 frame itself.
    ///
    /// **Precondition:** All user-space *leaf* pages must already be
    /// unmapped by `ProcessDescriptor::reclaim_user_vmas()`. This
    /// function frees the intermediate page table structures only.
    ///
    /// On AArch64 with TTBR0/TTBR1 split, the entire L0 table is
    /// user-only (kernel lives in TTBR1), so all 512 L0 entries can
    /// be walked safely.
    ///
    /// Phase 3.2d.ii (Roadmap item 17): closes the page-table-frame
    /// leak on AArch64.
    ///
    /// Returns the total number of frames freed (including the L0).
    pub fn reclaim_process_page_tables(
        l0_phys: u64,
        frame_alloc: &mut FrameAllocator,
    ) -> usize {
        if l0_phys == 0 {
            return 0;
        }

        let mut freed = 0usize;

        // SAFETY: l0_phys is a valid L0 page table address from
        // create_process_page_table. phys_to_virt maps it via HHDM.
        // The process is terminated so no CPU has this table in TTBR0.
        let l0_virt = phys_to_virt(l0_phys) as *const u64;

        for l0_idx in 0..512usize {
            // SAFETY: l0_virt points to a 4 KiB page table with 512
            // 8-byte entries. l0_idx < 512.
            let l0_entry = unsafe { core::ptr::read(l0_virt.add(l0_idx)) };
            if l0_entry & DESC_VALID == 0 {
                continue;
            }
            // Must be a table descriptor (not a block) at L0.
            if l0_entry & DESC_TABLE == 0 {
                continue;
            }
            let l1_phys = l0_entry & ADDR_MASK;
            let l1_virt = phys_to_virt(l1_phys) as *const u64;

            for l1_idx in 0..512usize {
                // SAFETY: same reasoning.
                let l1_entry = unsafe { core::ptr::read(l1_virt.add(l1_idx)) };
                if l1_entry & DESC_VALID == 0 {
                    continue;
                }
                // Skip 1 GiB block descriptors (we don't use them for
                // user space, but guard against future use).
                if l1_entry & DESC_TABLE == 0 {
                    continue;
                }
                let l2_phys = l1_entry & ADDR_MASK;
                let l2_virt = phys_to_virt(l2_phys) as *const u64;

                for l2_idx in 0..512usize {
                    // SAFETY: same reasoning.
                    let l2_entry = unsafe { core::ptr::read(l2_virt.add(l2_idx)) };
                    if l2_entry & DESC_VALID == 0 {
                        continue;
                    }
                    // Skip 2 MiB block descriptors.
                    if l2_entry & DESC_TABLE == 0 {
                        continue;
                    }
                    let l3_phys = l2_entry & ADDR_MASK;
                    // Free the L3 frame.
                    let _ = frame_alloc.free(PhysFrame { addr: l3_phys });
                    freed += 1;
                }

                // Free the L2 frame.
                let _ = frame_alloc.free(PhysFrame { addr: l2_phys });
                freed += 1;
            }

            // Free the L1 frame.
            let _ = frame_alloc.free(PhysFrame { addr: l1_phys });
            freed += 1;
        }

        // Free the L0 frame itself.
        let _ = frame_alloc.free(PhysFrame { addr: l0_phys });
        freed += 1;

        freed
    }

    // ========================================================================
    // Early boot MMIO mapping (no allocator needed)
    // ========================================================================

    /// Small pool of page-aligned 4KB frames for early boot page table
    /// allocation, before the frame allocator is initialized.
    ///
    /// Limine's HHDM on AArch64 maps RAM but NOT device MMIO regions.
    /// We need to map PL011 (0x0900_0000) and GIC (0x0800_0000) into
    /// the kernel page table (TTBR1) before serial output works.
    ///
    /// 3 frames is enough for worst case: one each for L1, L2, L3 tables.
    /// (L0 always exists — it's the root from TTBR1.)
    #[repr(C, align(4096))]
    struct BootstrapFrame([u8; 4096]);
    static mut BOOTSTRAP_FRAMES: [BootstrapFrame; 3] = [
        BootstrapFrame([0; 4096]),
        BootstrapFrame([0; 4096]),
        BootstrapFrame([0; 4096]),
    ];
    static BOOTSTRAP_NEXT: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);

    /// Translate a kernel virtual address to physical by walking TTBR1.
    ///
    /// Kernel statics live at 0xFFFFFFFF80000000+ which is NOT the HHDM —
    /// it's Limine's kernel mapping. We must walk TTBR1's page tables to
    /// find the physical address.
    #[cfg(target_arch = "aarch64")]
    unsafe fn kernel_virt_to_phys(ttbr1_root: u64, va: u64) -> Option<u64> {
        // SAFETY: Caller guarantees ttbr1_root is the TTBR1 root page table.
        // walk_to_l3_readonly and read_entry access valid HHDM-mapped tables.
        unsafe {
            let l3_phys = walk_to_l3_readonly(ttbr1_root, va)?;
            let idx = l3_index(va);
            let entry = read_entry(l3_phys, idx);
            if entry & DESC_VALID == 0 {
                return None;
            }
            Some((entry & ADDR_MASK) + (va & 0xFFF))
        }
    }

    /// Allocate one bootstrap frame (physical address).
    /// Returns None if all 3 frames are exhausted.
    ///
    /// Uses TTBR1 page table walk to find the physical address of the
    /// kernel static, since kernel statics are NOT in the HHDM.
    #[cfg(target_arch = "aarch64")]
    unsafe fn bootstrap_alloc(ttbr1_root: u64) -> Option<u64> {
        let idx = BOOTSTRAP_NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if idx >= 3 {
            return None;
        }
        // SAFETY: idx is bounds-checked above (< 3). BOOTSTRAP_FRAMES is a static
        // array — accessing it during single-core boot is safe (no aliasing).
        // kernel_virt_to_phys walks valid TTBR1 page tables.
        unsafe {
            let virt = &BOOTSTRAP_FRAMES[idx] as *const _ as u64;
            kernel_virt_to_phys(ttbr1_root, virt)
        }
    }

    /// Map a single 4KB MMIO page into the kernel page table (TTBR1_EL1).
    ///
    /// This function works before the heap and frame allocator are initialized.
    /// It uses a small static pool of bootstrap frames for any missing
    /// intermediate page table levels.
    ///
    /// The page is mapped as device memory (AttrIndx=0), kernel RW,
    /// non-executable, inner-shareable.
    ///
    /// # Safety
    /// - HHDM offset must already be set (via `set_hhdm_offset`).
    /// - `phys_addr` must be a valid MMIO physical address (page-aligned).
    /// - Must only be called during single-core boot.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn early_map_mmio(phys_addr: u64) -> Result<(), &'static str> {
        let pa = phys_addr & !0xFFF;
        let hhdm_off = hhdm();
        let va = pa + hhdm_off; // HHDM virtual address for this MMIO page

        // SAFETY: All operations below access HHDM-mapped page tables and
        // bootstrap frames during single-core boot. Inline asm reads/writes
        // system registers from EL1. Caller guarantees HHDM offset is set
        // and phys_addr is a valid MMIO address.
        unsafe {
            // Read TTBR1_EL1 (kernel page table root)
            let ttbr1: u64;
            // SAFETY: Reading TTBR1_EL1 from EL1 is always safe.
            core::arch::asm!(
                "mrs {0}, ttbr1_el1",
                out(reg) ttbr1,
                options(nostack, nomem, preserves_flags),
            );
            let root_phys = ttbr1 & ADDR_MASK;

            // Walk L0 → L1 → L2, allocating missing levels from bootstrap pool
            let indices = [l0_index(va), l1_index(va), l2_index(va)];
            let mut table_phys = root_phys;

            for &idx in &indices {
                let entry = read_entry(table_phys, idx);
                if entry & DESC_VALID != 0 {
                    // Entry exists — descend
                    table_phys = entry & ADDR_MASK;
                } else {
                    // Allocate from bootstrap pool
                    let frame_phys = bootstrap_alloc(root_phys)
                        .ok_or("early_map_mmio: bootstrap frames exhausted")?;
                    // Zero the new table via HHDM
                    core::ptr::write_bytes(
                        phys_to_virt(frame_phys) as *mut u8,
                        0,
                        PAGE_SIZE as usize,
                    );
                    // Install table descriptor
                    let desc = frame_phys | DESC_VALID | DESC_TABLE;
                    write_entry(table_phys, idx, desc);
                    table_phys = frame_phys;
                }
            }

            // Now table_phys is the L3 table. Write the page entry.
            let idx = l3_index(va);
            let existing = read_entry(table_phys, idx);
            if existing & DESC_VALID != 0 {
                // Already mapped — that's fine for MMIO
                return Ok(());
            }

            // Device memory descriptor: Valid + Page + AF + ISH + AttrIndx=0 (Device)
            // + PXN + UXN (never execute MMIO)
            let desc = pa
                | DESC_VALID
                | DESC_TABLE  // At L3, bit[1]=1 means "page"
                | DESC_AF
                | DESC_ISH
                | DESC_ATTR_DEVICE
                | DESC_PXN
                | DESC_UXN;

            write_entry(table_phys, idx, desc);

            // Ensure mapping is visible
            core::arch::asm!(
                "dsb ishst",
                "tlbi vale1is, {va}",
                "dsb ish",
                "isb",
                va = in(reg) va >> 12,
                options(nostack),
            );
        }

        Ok(())
    }

    /// Page permission flags for AArch64 descriptors.
    ///
    /// These encode the AP[2:1], UXN, and PXN bits that get OR'd into
    /// L3 page descriptors.
    pub mod flags {
        use super::*;

        /// Wrapper for AArch64 L3 descriptor permission bits.
        #[derive(Debug, Clone, Copy)]
        pub struct PageFlags(pub(super) u64);

        /// Kernel read-only: EL1 RO, no EL0 access, UXN + PXN
        pub const KERNEL_RO: PageFlags = PageFlags(DESC_AP_RO | DESC_UXN | DESC_PXN);

        /// Kernel read-write: EL1 RW, no EL0 access, UXN + PXN (no execute)
        pub fn kernel_rw() -> PageFlags {
            PageFlags(DESC_UXN | DESC_PXN)
        }

        /// User read-only: EL0 readable, not writable, executable from EL0
        /// (PXN set = kernel can't execute user pages)
        pub fn user_ro() -> PageFlags {
            PageFlags(DESC_AP_EL0 | DESC_AP_RO | DESC_PXN)
        }

        /// User read-write: EL0 RW, UXN (no execute by default — W^X),
        /// PXN (kernel can't execute user pages)
        pub fn user_rw() -> PageFlags {
            PageFlags(DESC_AP_EL0 | DESC_UXN | DESC_PXN)
        }

        /// Bit 62 is unused in AArch64 descriptors — we repurpose it as an
        /// internal flag to signal device memory (AttrIndx=0 instead of 1).
        pub(super) const DEVICE_MEMORY_FLAG: u64 = 1 << 62;

        /// User MMIO: EL0 RW, device memory (uncacheable), no execute.
        /// For mapping device MMIO regions into user-space processes.
        pub fn user_mmio() -> PageFlags {
            PageFlags(DESC_AP_EL0 | DESC_UXN | DESC_PXN | DEVICE_MEMORY_FLAG)
        }
    }
}

/// Memory configuration constants
pub mod config {
    /// Bootloader entry point in physical memory (real mode)
    pub const BOOTLOADER_BASE: u64 = 0x7c00;
    
    /// Kernel load address in physical memory
    pub const KERNEL_LOAD_ADDR: u64 = 0x100000;
    
    /// Extended memory base address
    pub const EXTENDED_MEMORY_BASE: u64 = 0x100000;
}

/// Memory initialization state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryInitState {
    Uninitialized = 0,
    Configured = 1,
    Ready = 2,
}

static MEMORY_STATE: AtomicU8 = AtomicU8::new(MemoryInitState::Uninitialized as u8);

/// Initialize memory management
///
/// # Safety
/// Must be called once during boot. Currently a placeholder.
pub unsafe fn init() {
    // SAFETY: configure_memory only writes an atomic; no actual unsafe memory ops yet.
    unsafe { configure_memory() };
    MEMORY_STATE.store(MemoryInitState::Ready as u8, Ordering::Release);
}

/// Configure memory structures and enable protections
unsafe fn configure_memory() {
    // Placeholder for memory configuration
    // In a full implementation, this would:
    // - Set up page tables
    // - Enable paging
    // - Configure memory protection units
    MEMORY_STATE.store(MemoryInitState::Configured as u8, Ordering::Release);
}

/// Get current memory initialization state
pub fn state() -> MemoryInitState {
    match MEMORY_STATE.load(Ordering::Acquire) {
        1 => MemoryInitState::Configured,
        2 => MemoryInitState::Ready,
        _ => MemoryInitState::Uninitialized,
    }
}

/// Interface for memory allocation verification
pub trait MemoryAllocator {
    fn allocate(&mut self, size: usize) -> Option<*mut u8>;
    fn deallocate(&mut self, ptr: *mut u8, size: usize);
    fn is_aligned(&self, ptr: *const u8, alignment: usize) -> bool;
}

/// Get current page table root via HHDM mapping.
///
/// CR3 holds a physical address — we add the HHDM offset to get a
/// kernel-accessible virtual pointer.
///
/// # Safety
///
/// Caller must ensure no other mutable reference to the active PML4
/// exists. The returned reference aliases the live page table that the
/// CPU is walking — modifications must be carefully sequenced.
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_page_table() -> Option<&'static mut PageTable> {
    let (level_4_table_frame, _) = Cr3::read();
    let phys_addr = level_4_table_frame.start_address().as_u64();
    let virt_addr = (phys_addr + crate::hhdm_offset()) as *mut PageTable;
    // SAFETY: CR3 points to a valid PML4 frame set up by Limine or create_process_page_table.
    // Adding the HHDM offset gives a kernel-accessible virtual address. The borrow is
    // 'static because the page table lives as long as the kernel does.
    Some(unsafe { &mut *virt_addr })
}
