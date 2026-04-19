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

/// Shared 4-level / 4 KiB / 48-bit paging for AArch64 + RISC-V (Sv48).
///
/// The walk logic, bootstrap frame pool, map/unmap/translate/reclaim
/// operations, and `PageTableRef` are identical across both arches —
/// they only differ in how a PTE is interpreted and constructed. Those
/// arch-specific pieces live in [`crate::arch::paging`] (one per arch,
/// resolved at cfg time), and this module calls into them:
///
/// - `pte_is_valid`, `pte_is_table`, `pte_addr` — predicates/accessors
/// - `make_table_pte`, `make_leaf_pte` — PTE constructors
/// - `barrier_map` — post-mapping barrier sequence
/// - `active_root` — read the current per-hart page-table root
/// - `flags` submodule — permission constructors re-exported here
/// - `early_map_mmio` — per-arch MMIO bring-up entry point, which calls
///   back into this module's `early_map_mmio_arch` driver
///
/// R-3.a split this module from the original "AArch64-implementation
/// gated with `#[cfg(not(target_arch = "x86_64"))]`" shape so RISC-V
/// Sv48 can plug in without duplicating the walk logic. See ADR-013's
/// Divergence section.
#[cfg(not(target_arch = "x86_64"))]
pub mod paging {
    use super::frame_allocator::{FrameAllocator, PhysFrame, PAGE_SIZE};
    use crate::arch::paging as ap;
    use core::fmt;

    /// Re-export the active arch's flag vocabulary so the rest of the
    /// kernel writes `paging::flags::kernel_rw()` and gets the right
    /// bits per arch.
    pub use ap::flags;

    /// Re-export the active arch's early-boot MMIO entry point. Calls
    /// back into `early_map_mmio_arch` below with arch-specific closures.
    pub use ap::early_map_mmio;

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

    /// Number of entries per page table level (4 KiB × 512 × 8 B).
    const ENTRIES_PER_TABLE: usize = 512;

    // ========================================================================
    // Page table handle
    // ========================================================================

    /// Handle to a root page table (L0).
    ///
    /// Wraps the physical address of the L0 table (the value that goes
    /// into TTBR0_EL1 on AArch64 or satp PPN × 4 KiB on RISC-V).
    pub struct PageTableRef {
        root_phys: u64,
    }

    #[inline]
    fn hhdm() -> u64 {
        crate::hhdm_offset()
    }

    #[inline]
    fn phys_to_virt(phys: u64) -> *mut u64 {
        (phys + hhdm()) as *mut u64
    }

    // Index extractors — shared across AArch64 + RISC-V Sv48 (identical
    // 9/9/9/9/12 split).

    #[inline]
    const fn l0_index(va: u64) -> usize {
        ((va >> 39) & 0x1FF) as usize
    }
    #[inline]
    const fn l1_index(va: u64) -> usize {
        ((va >> 30) & 0x1FF) as usize
    }
    #[inline]
    const fn l2_index(va: u64) -> usize {
        ((va >> 21) & 0x1FF) as usize
    }
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

    /// Walk L0→L1→L2, allocating intermediate tables from `frame_alloc`
    /// as needed. Returns the physical address of the L3 table.
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
                if ap::pte_is_valid(entry) {
                    table_phys = ap::pte_addr(entry);
                } else {
                    let frame = frame_alloc
                        .allocate()
                        .map_err(|_| PagingError::FrameAllocationFailed)?;
                    // SAFETY: frame.addr is a freshly allocated frame, HHDM maps it.
                    core::ptr::write_bytes(
                        phys_to_virt(frame.addr) as *mut u8,
                        0,
                        PAGE_SIZE as usize,
                    );
                    write_entry(table_phys, idx, ap::make_table_pte(frame.addr));
                    table_phys = frame.addr;
                }
            }
        }

        Ok(table_phys)
    }

    /// Walk L0→L1→L2 read-only. Returns None if any level is unmapped.
    unsafe fn walk_to_l3_readonly(root_phys: u64, va: u64) -> Option<u64> {
        let indices = [l0_index(va), l1_index(va), l2_index(va)];
        let mut table_phys = root_phys;

        // SAFETY: Caller guarantees root_phys is a valid page table.
        // Each level descends through valid table descriptors.
        unsafe {
            for &idx in &indices {
                let entry = read_entry(table_phys, idx);
                if !ap::pte_is_valid(entry) {
                    return None;
                }
                table_phys = ap::pte_addr(entry);
            }
        }

        Some(table_phys)
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Get a handle to the active page table on this CPU.
    ///
    /// On AArch64 this reads TTBR0_EL1 (user page-table). On RISC-V it
    /// reads satp's PPN field. Both land here via `ap::active_root()`.
    ///
    /// # Safety
    /// HHDM offset must be set. The active root must point to a valid
    /// L0 table (i.e. paging must be enabled and configured).
    #[cfg(target_os = "none")]
    pub unsafe fn active_page_table() -> PageTableRef {
        // SAFETY: delegated to arch; valid in bare-metal.
        PageTableRef {
            root_phys: unsafe { ap::active_root() },
        }
    }

    /// Host-test stub (macOS unit tests don't exercise kernel paging).
    #[cfg(not(target_os = "none"))]
    pub unsafe fn active_page_table() -> PageTableRef {
        PageTableRef { root_phys: 0 }
    }

    /// Build a handle from a raw root phys address (e.g. from a
    /// `ProcessDescriptor::cr3` field).
    ///
    /// Named `page_table_from_cr3` for API compatibility with code that
    /// predates the multi-arch port — the field name on
    /// `ProcessDescriptor` kept its x86 origin.
    ///
    /// # Safety
    /// `cr3` must be the physical address of a valid L0 page table.
    pub unsafe fn page_table_from_cr3(cr3: u64) -> PageTableRef {
        PageTableRef {
            root_phys: cr3 & !0xFFF,
        }
    }

    /// Map a single 4 KiB virtual page to a physical frame.
    pub fn map_page(
        pt: &mut PageTableRef,
        virt_addr: u64,
        phys_addr: u64,
        page_flags: flags::PageFlags,
        frame_alloc: &mut FrameAllocator,
    ) -> Result<(), PagingError> {
        debug_assert_eq!(virt_addr & 0xFFF, 0, "map_page virt_addr not page-aligned");
        debug_assert_eq!(phys_addr & 0xFFF, 0, "map_page phys_addr not page-aligned");
        let va = virt_addr & !0xFFF;
        let pa = phys_addr & !0xFFF;

        // SAFETY: pt.root_phys is valid. frame_alloc may allocate.
        let l3_phys = unsafe { walk_to_l3(pt.root_phys, va, frame_alloc)? };
        let idx = l3_index(va);
        // SAFETY: l3_phys is valid.
        let existing = unsafe { read_entry(l3_phys, idx) };
        if ap::pte_is_valid(existing) {
            return Err(PagingError::AlreadyMapped);
        }

        let desc = ap::make_leaf_pte(pa, page_flags);
        // SAFETY: l3_phys and idx are valid.
        unsafe { write_entry(l3_phys, idx, desc) };
        // SAFETY: barrier_map has no side effects beyond the documented
        // pipeline/TLB-walker sync per arch.
        unsafe { ap::barrier_map() };

        Ok(())
    }

    /// Unmap a single 4 KiB page and return the physical frame.
    pub fn unmap_page(
        pt: &mut PageTableRef,
        virt_addr: u64,
    ) -> Result<PhysFrame, PagingError> {
        let va = virt_addr & !0xFFF;

        // SAFETY: pt.root_phys is valid.
        let l3_phys = unsafe {
            walk_to_l3_readonly(pt.root_phys, va).ok_or(PagingError::NotMapped)?
        };
        let idx = l3_index(va);
        // SAFETY: l3_phys is valid.
        let entry = unsafe { read_entry(l3_phys, idx) };
        if !ap::pte_is_valid(entry) {
            return Err(PagingError::NotMapped);
        }
        let frame_phys = ap::pte_addr(entry);

        // Clear the entry first so subsequent walks miss.
        // SAFETY: l3_phys and idx are valid.
        unsafe { write_entry(l3_phys, idx, 0) };

        // Invalidate TLB. On AArch64 this is a broadcast TLBI; on
        // RISC-V it is a local sfence.vma today (SBI-IPI-broadcast lands
        // in Phase R-5 per ADR-013 Decision 5).
        #[cfg(target_os = "none")]
        crate::arch::tlb::shootdown_page(va);

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
    /// Returns `None` if the page is not mapped.
    pub fn translate(pt: &PageTableRef, virt_addr: u64) -> Option<u64> {
        let va = virt_addr & !0xFFF;
        let page_offset = virt_addr & 0xFFF;

        // SAFETY: pt.root_phys is valid.
        let l3_phys = unsafe { walk_to_l3_readonly(pt.root_phys, va)? };
        let idx = l3_index(va);
        // SAFETY: l3_phys is valid.
        let entry = unsafe { read_entry(l3_phys, idx) };
        if !ap::pte_is_valid(entry) {
            return None;
        }
        Some(ap::pte_addr(entry) + page_offset)
    }

    /// Create a new L0 page table for a user process.
    ///
    /// Returns the physical address of a freshly zeroed L0 table.
    ///
    /// On AArch64 the L0 is fine with zero kernel-half entries because
    /// the kernel lives in TTBR1 (separate translation regime from the
    /// user's TTBR0). On RISC-V there is no TTBR split — kernel and
    /// user share a single `satp` — so the new L0's upper half
    /// (indices 256..512, covering VA `0xffff_8000_0000_0000` and up)
    /// must carry the same entries as the currently-loaded root, or
    /// the first kernel-side trap taken while this satp is loaded
    /// would fault fetching its own instructions (kernel text
    /// unmapped).
    pub fn create_process_page_table(
        frame_alloc: &mut FrameAllocator,
    ) -> Result<u64, PagingError> {
        let frame = frame_alloc
            .allocate()
            .map_err(|_| PagingError::FrameAllocationFailed)?;

        // SAFETY: frame.addr is a freshly allocated frame, HHDM maps it.
        unsafe {
            core::ptr::write_bytes(
                phys_to_virt(frame.addr) as *mut u8,
                0,
                PAGE_SIZE as usize,
            );
        }

        // RISC-V: copy kernel-half L0 entries (indices 256..512) from
        // the currently-active satp root so the kernel is still mapped
        // after `csrw satp, new_root` swaps address spaces. Otherwise
        // the next trap faults on instruction-fetch.
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: csrr satp is always legal from S-mode; walker
            // reads use HHDM-mapped tables; single-writer-at-boot.
            unsafe {
                let satp: u64;
                core::arch::asm!(
                    "csrr {0}, satp",
                    out(reg) satp,
                    options(nostack, nomem, preserves_flags),
                );
                let current_root_phys = (satp & ((1u64 << 44) - 1)) << 12;
                let src = phys_to_virt(current_root_phys) as *const u64;
                let dst = phys_to_virt(frame.addr);
                for i in 256..512 {
                    let entry = core::ptr::read(src.add(i));
                    core::ptr::write(dst.add(i), entry);
                }
            }
        }

        Ok(frame.addr)
    }

    /// Free a process page table L0 frame.
    ///
    /// Only frees the L0 frame itself. Intermediate frames (L1/L2/L3)
    /// must be freed by unmapping all user pages first (or by calling
    /// [`reclaim_process_page_tables`]).
    pub fn free_process_page_table(frame_alloc: &mut FrameAllocator, phys: u64) {
        let _ = frame_alloc.free(PhysFrame { addr: phys });
    }

    /// Walk a process L0 table and free all intermediate page-table
    /// frames (L1, L2, L3), then free the L0 frame itself.
    ///
    /// **Precondition:** All leaf user pages must already be unmapped
    /// by `ProcessDescriptor::reclaim_user_vmas()`. This function frees
    /// only the intermediate page-table structures.
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

        // SAFETY: l0_phys is a valid L0 page table from
        // create_process_page_table. HHDM maps it. Process is
        // terminated so no CPU has this table loaded.
        let l0_virt = phys_to_virt(l0_phys) as *const u64;

        for l0_idx in 0..512usize {
            // SAFETY: l0_virt points to a 4 KiB page table with 512
            // 8-byte entries. l0_idx < 512.
            let l0_entry = unsafe { core::ptr::read(l0_virt.add(l0_idx)) };
            if !ap::pte_is_valid(l0_entry) || !ap::pte_is_table(l0_entry) {
                // Either unused or a block/leaf descriptor (AArch64 1 GiB
                // block or RISC-V gigapage) — we don't create those for
                // user page tables, but skip them defensively.
                continue;
            }
            let l1_phys = ap::pte_addr(l0_entry);
            let l1_virt = phys_to_virt(l1_phys) as *const u64;

            for l1_idx in 0..512usize {
                // SAFETY: same reasoning.
                let l1_entry = unsafe { core::ptr::read(l1_virt.add(l1_idx)) };
                if !ap::pte_is_valid(l1_entry) || !ap::pte_is_table(l1_entry) {
                    continue;
                }
                let l2_phys = ap::pte_addr(l1_entry);
                let l2_virt = phys_to_virt(l2_phys) as *const u64;

                for l2_idx in 0..512usize {
                    // SAFETY: same reasoning.
                    let l2_entry = unsafe { core::ptr::read(l2_virt.add(l2_idx)) };
                    if !ap::pte_is_valid(l2_entry) || !ap::pte_is_table(l2_entry) {
                        continue;
                    }
                    let l3_phys = ap::pte_addr(l2_entry);
                    let _ = frame_alloc.free(PhysFrame { addr: l3_phys });
                    freed += 1;
                }

                let _ = frame_alloc.free(PhysFrame { addr: l2_phys });
                freed += 1;
            }

            let _ = frame_alloc.free(PhysFrame { addr: l1_phys });
            freed += 1;
        }

        let _ = frame_alloc.free(PhysFrame { addr: l0_phys });
        freed += 1;

        freed
    }

    // ========================================================================
    // Early-boot MMIO mapping — arch closures inject the leaf + flush
    // ========================================================================

    /// Pool of 3 × 4 KiB page-aligned static frames for early-boot
    /// page-table allocation, before the frame allocator is online.
    ///
    /// On AArch64, Limine's HHDM does not cover device MMIO, so PL011
    /// and the GIC must be mapped into TTBR1 before serial output works.
    /// On RISC-V, PLIC MMIO similarly must be mapped (R-3.d).
    ///
    /// 3 frames is the worst case for one new MMIO page: one each for
    /// a missing L1, L2, and L3 table. (The L0 is always present — it
    /// is the root.)
    #[repr(C, align(4096))]
    struct BootstrapFrame([u8; 4096]);
    static mut BOOTSTRAP_FRAMES: [BootstrapFrame; 3] = [
        BootstrapFrame([0; 4096]),
        BootstrapFrame([0; 4096]),
        BootstrapFrame([0; 4096]),
    ];
    static BOOTSTRAP_NEXT: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);

    /// Translate a kernel virtual address to physical by walking the
    /// kernel page-table root.
    ///
    /// Kernel statics (`BOOTSTRAP_FRAMES`) live at kernel VAs that are
    /// *not* in the HHDM — they are part of the kernel's own mapping
    /// (TTBR1 on AArch64, upper half of `satp` on RISC-V). We have to
    /// walk the root to find their physical address.
    unsafe fn kernel_virt_to_phys(root_phys: u64, va: u64) -> Option<u64> {
        // SAFETY: Caller guarantees root_phys is the kernel page-table
        // root. walk_to_l3_readonly and read_entry access valid
        // HHDM-mapped tables.
        unsafe {
            let l3_phys = walk_to_l3_readonly(root_phys, va)?;
            let idx = l3_index(va);
            let entry = read_entry(l3_phys, idx);
            if !ap::pte_is_valid(entry) {
                return None;
            }
            Some(ap::pte_addr(entry) + (va & 0xFFF))
        }
    }

    /// Allocate one bootstrap frame (physical address). Returns None if
    /// all 3 frames are exhausted.
    ///
    /// Uses kernel page-table walk to resolve the phys of the static
    /// frame, because the HHDM does not cover kernel static addresses.
    unsafe fn bootstrap_alloc(root_phys: u64) -> Option<u64> {
        let idx = BOOTSTRAP_NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if idx >= 3 {
            return None;
        }
        // SAFETY: idx < 3 by the bounds check above. BOOTSTRAP_FRAMES is
        // a static array; single-core boot guarantees no aliasing.
        // kernel_virt_to_phys walks valid kernel page tables.
        unsafe {
            let virt = &BOOTSTRAP_FRAMES[idx] as *const _ as u64;
            kernel_virt_to_phys(root_phys, virt)
        }
    }

    /// Shared driver for early MMIO bring-up. Each arch's
    /// `early_map_mmio(pa)` calls here with its kernel root, a leaf-PTE
    /// constructor closure (so the arch owns the exact descriptor/PTE
    /// bits for Device memory), and a VA-targeted TLB flush closure (so
    /// the arch owns its barrier + invalidation sequence).
    ///
    /// # Safety
    /// - HHDM offset must already be set.
    /// - `pa` must be page-aligned and a valid MMIO physical address.
    /// - `root_phys` must be the kernel page-table root on this CPU.
    /// - Must only be called during single-core boot.
    pub(crate) unsafe fn early_map_mmio_arch(
        pa: u64,
        root_phys: u64,
        make_leaf: impl Fn(u64) -> u64,
        flush: impl Fn(u64),
    ) -> Result<(), &'static str> {
        let hhdm_off = hhdm();
        let va = pa + hhdm_off;

        // SAFETY: Caller preconditions satisfied. All accesses go
        // through HHDM-mapped tables during single-core boot.
        unsafe {
            let indices = [l0_index(va), l1_index(va), l2_index(va)];
            let mut table_phys = root_phys;

            for &idx in &indices {
                let entry = read_entry(table_phys, idx);
                if ap::pte_is_valid(entry) && ap::pte_is_table(entry) {
                    table_phys = ap::pte_addr(entry);
                } else {
                    let frame_phys = bootstrap_alloc(root_phys)
                        .ok_or("early_map_mmio: bootstrap frames exhausted")?;
                    core::ptr::write_bytes(
                        phys_to_virt(frame_phys) as *mut u8,
                        0,
                        PAGE_SIZE as usize,
                    );
                    write_entry(table_phys, idx, ap::make_table_pte(frame_phys));
                    table_phys = frame_phys;
                }
            }

            let idx = l3_index(va);
            let existing = read_entry(table_phys, idx);
            if ap::pte_is_valid(existing) {
                // Already mapped — tolerate (idempotent MMIO bring-up).
                return Ok(());
            }

            write_entry(table_phys, idx, make_leaf(pa));
            flush(va);
        }

        Ok(())
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
