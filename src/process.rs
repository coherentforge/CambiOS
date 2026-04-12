// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

/// Process management, heap allocation, and virtual memory area tracking
///
/// Manages per-process state including memory allocators and VMA tracking.
/// Each process gets a BuddyAllocator (pure bookkeeping) plus a VmaTracker
/// that records user-space virtual memory allocations for proper free/unmap.

use crate::memory::buddy_allocator::BuddyAllocator;
use crate::memory::frame_allocator::{FrameAllocator, FrameAllocError, PAGE_SIZE};
use crate::memory::paging;
use crate::ipc::ProcessId;
extern crate alloc;
use alloc::boxed::Box;

// ============================================================================
// Virtual Memory Area (VMA) tracking
// ============================================================================

/// SCAFFOLDING: maximum number of tracked memory regions per process.
/// Why: bounded slot table for the bump-allocated VMA tracker, sized for current
///      services which use only a handful of regions.
/// Replace when: channels (ADR-005) attach shared-memory mappings as VMAs — the
///      first service that holds 5+ channels is on the edge. Also pressure from
///      any future mmap-style API. See ASSUMPTIONS.md.
const MAX_VMAS: usize = 64;

/// Base virtual address for dynamic user-space allocations.
/// Placed above code (0x400000) and stack (0x800000) regions.
pub const VMA_ALLOC_BASE: u64 = 0x1000_0000;

/// A tracked virtual memory region in a process's address space.
#[derive(Clone, Copy)]
pub struct VmaEntry {
    /// User-space virtual address (page-aligned)
    pub base_vaddr: u64,
    /// Number of 4 KB pages in this region
    pub num_pages: u32,
}

/// Per-process virtual memory area tracker.
///
/// Pure bookkeeping — does not touch page tables or physical memory.
/// Records which virtual address ranges have been allocated so they
/// can be looked up and freed properly.
///
/// Uses a simple bump allocator for virtual addresses. Freed address
/// ranges are not reused (the 47-bit user address space is large enough
/// that exhaustion is not a practical concern for a microkernel).
///
/// # Invariants (for formal verification)
///
/// - `count <= MAX_VMAS` (64).
/// - `next_vaddr >= VMA_ALLOC_BASE` and is always page-aligned.
/// - `next_vaddr < USER_SPACE_END` (0x0000_8000_0000_0000).
/// - All `Some` entries have `base_vaddr` page-aligned and within user space.
/// - No two `Some` entries overlap in their virtual address ranges.
/// - `count` equals the number of `Some` entries in `entries`.
pub struct VmaTracker {
    entries: [Option<VmaEntry>; MAX_VMAS],
    count: usize,
    /// Next virtual address to allocate from (bump, page-aligned)
    next_vaddr: u64,
}

impl VmaTracker {
    /// Create a new empty VMA tracker.
    pub const fn new() -> Self {
        VmaTracker {
            entries: [None; MAX_VMAS],
            count: 0,
            next_vaddr: VMA_ALLOC_BASE,
        }
    }

    /// Allocate a virtual address region of `num_pages` pages.
    ///
    /// Returns the base virtual address, or `None` if no slots remain.
    /// Does NOT map pages — the caller must do frame alloc + map_page.
    pub fn allocate_region(&mut self, num_pages: u32) -> Option<u64> {
        if num_pages == 0 {
            return None;
        }

        // Find a free slot
        let slot = self.entries.iter().position(|e| e.is_none())?;

        let vaddr = self.next_vaddr;
        let size = num_pages as u64 * 4096;

        // Overflow check (stay in lower-half user space)
        if vaddr.checked_add(size)? >= 0x0000_8000_0000_0000 {
            return None;
        }

        self.entries[slot] = Some(VmaEntry {
            base_vaddr: vaddr,
            num_pages,
        });
        self.count += 1;
        self.next_vaddr = vaddr + size;

        Some(vaddr)
    }

    /// Look up a VMA by its base virtual address.
    pub fn find(&self, vaddr: u64) -> Option<&VmaEntry> {
        self.entries.iter().filter_map(|e| e.as_ref()).find(|e| e.base_vaddr == vaddr)
    }

    /// Remove a VMA by its base virtual address.
    ///
    /// Returns the entry so the caller can unmap pages and free frames.
    pub fn free_region(&mut self, vaddr: u64) -> Option<VmaEntry> {
        for slot in self.entries.iter_mut() {
            if let Some(entry) = slot {
                if entry.base_vaddr == vaddr {
                    let removed = *entry;
                    *slot = None;
                    self.count -= 1;
                    return Some(removed);
                }
            }
        }
        None
    }

    /// Number of active allocations.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ============================================================================
// Wave 2a: MAX_PROCESSES is no longer a compile-time constant.
//
// The number of process slots is now computed at boot from the active
// tier policy and the available-memory figure — see
// `crate::config::num_slots()`. Use that function (or `ProcessTable::
// capacity()`) instead of any old reference to `MAX_PROCESSES`.
//
// Per ADR-008, the tables that MAX_PROCESSES used to size now live in
// the kernel object table region, allocated once at boot in
// `crate::memory::object_table::init()`.
// ============================================================================

/// SCAFFOLDING: per-process heap size (1 MiB).
/// Why: default budget per process. Today every process gets a
///      contiguous physical heap of this size, allocated from the
///      frame allocator in `ProcessDescriptor::new` and freed in
///      `handle_exit` via `FrameAllocator::free_contiguous`. No
///      longer tied to a pre-reserved slab.
/// Replace when: udp-stack is already feeling this. Future: per-service
///      heap sizing, lazy heap mapping, or growable heap via extra
///      allocations. See ASSUMPTIONS.md.
pub const HEAP_SIZE: u64 = 0x100000;

/// Number of 4 KiB frames in a process heap (1 MiB / 4 KiB = 256).
pub const HEAP_PAGES: usize = (HEAP_SIZE / PAGE_SIZE) as usize;

/// Errors from `ProcessDescriptor::new` — today, only heap allocation
/// can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessCreateError {
    /// The frame allocator could not provide a contiguous heap region.
    /// Wraps the underlying frame allocator error for diagnostics.
    HeapAllocFailure(FrameAllocError),
}

/// Process descriptor with VMA tracking. The per-process buddy
/// allocator no longer lives inline — it's constructed in place at
/// the start of each process's heap by [`ProcessDescriptor::new`] and
/// accessed via [`ProcessDescriptor::allocator_mut`]. See the module
/// doc and ADR-008 Wave 2a follow-up for the rationale.
///
/// # Invariants (for formal verification)
///
/// - `cr3 == 0` means the process uses the kernel page table (kernel tasks).
/// - `cr3 != 0` is a valid physical address of a PML4/L0 page table with
///   kernel-half entries (256..511 on x86_64) cloned from the kernel PML4.
/// - `phys_base` is page-aligned and within the physical address range
///   covered by the frame allocator.
/// - `virt_base == phys_base + hhdm_offset` (HHDM mapping for kernel access).
/// - `heap_size == HEAP_PAGES * PAGE_SIZE` for every currently-live descriptor.
/// - The physical range `[phys_base, phys_base + heap_size)` was allocated
///   via `FrameAllocator::allocate_contiguous(HEAP_PAGES)` and must be freed
///   via `FrameAllocator::free_contiguous(phys_base, HEAP_PAGES)` exactly
///   once when the process exits.
/// - **The first `size_of::<BuddyAllocator>()` bytes of the managed heap
///   contain a valid `BuddyAllocator` struct**, constructed in place by
///   `ProcessDescriptor::new` via `core::ptr::write` and initialized with
///   `new_with_reserved_prefix` so user allocations never overlap.
/// - All VMA entries in `vma` reference user-space addresses in the lower
///   canonical half (< `USER_SPACE_END`).
/// - BuddyAllocator offsets are relative to `virt_base`, not absolute.
pub struct ProcessDescriptor {
    /// Physical base address of this process's heap (for page tables).
    /// The first `size_of::<BuddyAllocator>()` bytes at this address hold
    /// the process's buddy allocator state (Wave 2a follow-up).
    pub phys_base: u64,
    /// HHDM-mapped virtual base (for kernel-side access).
    /// `virt_base as *mut BuddyAllocator` is a valid, initialized pointer
    /// for the lifetime of the descriptor.
    pub virt_base: u64,
    /// Heap size in bytes
    pub heap_size: u64,
    /// Physical address of PML4 page table (CR3 value). 0 = uses kernel page table.
    pub cr3: u64,
    /// Tracks user-space virtual memory allocations (for SYS_ALLOCATE / SYS_FREE)
    pub vma: VmaTracker,
}

impl ProcessDescriptor {
    /// Create a new process descriptor, dynamically allocating its
    /// heap region from the frame allocator and placing a fresh
    /// `BuddyAllocator` in the first few KB of that heap.
    ///
    /// Wave 2a: heap is no longer at a deterministic PID-derived
    /// physical address. Each process gets a fresh contiguous region
    /// from the frame allocator, which means process exit MUST free
    /// it via [`ProcessDescriptor::reclaim_heap`] to avoid a leak.
    ///
    /// Wave 2a follow-up (Item 1): the per-process `BuddyAllocator`
    /// lives in the heap itself at `virt_base..virt_base + size_of::<BuddyAllocator>()`,
    /// constructed via `core::ptr::write` with
    /// `new_with_reserved_prefix` so user allocations skip the
    /// allocator's own state. This shrinks `SLOT_OVERHEAD` (the per-
    /// process object-table cost) from ~22 KB to ~a few hundred bytes
    /// — see ADR-008 § "Current binding observation" for the effect
    /// on tier policies.
    ///
    /// `hhdm_offset`: the higher-half direct map offset from Limine,
    /// so the kernel can access process heap memory via
    /// `virt_base = phys_base + hhdm_offset`.
    ///
    /// Returns `Err(ProcessCreateError::HeapAllocFailure(_))` if the
    /// frame allocator cannot provide `HEAP_PAGES` contiguous frames.
    /// The caller's responsibility is to propagate the error to its
    /// own caller (usually `ProcessTable::create_process`).
    pub fn new(
        _process_id: ProcessId,
        hhdm_offset: u64,
        frame_alloc: &mut FrameAllocator,
    ) -> Result<Self, ProcessCreateError> {
        let frame = frame_alloc
            .allocate_contiguous(HEAP_PAGES)
            .map_err(ProcessCreateError::HeapAllocFailure)?;
        let phys_base = frame.addr;
        let virt_base = phys_base + hhdm_offset;

        // Placement-new the buddy allocator at the start of the heap.
        // The reserved prefix equals the allocator's own struct size
        // so the allocator can never hand out a range that overlaps
        // its own bitmap storage.
        //
        // SAFETY:
        // - `virt_base` points at freshly-allocated HHDM-mapped frames
        //   (just returned from `allocate_contiguous`). We are the
        //   exclusive owner of these frames — nothing else holds a
        //   reference.
        // - The frames form a single contiguous region of
        //   `HEAP_SIZE = 1 MiB`, which is much larger than
        //   `size_of::<BuddyAllocator>()` (~20 KB). No risk of writing
        //   past the end.
        // - `virt_base` is page-aligned (frame allocator returns
        //   page-aligned bases) which satisfies any alignment
        //   requirement `BuddyAllocator` has (its max alignment is
        //   that of `u64`, which is 8 bytes, well below 4096).
        // - `BuddyAllocator` is `#[repr(C)]` with only plain-array
        //   fields, so the layout is deterministic and safe to
        //   construct via `core::ptr::write`.
        unsafe {
            core::ptr::write(
                virt_base as *mut BuddyAllocator,
                BuddyAllocator::new_with_reserved_prefix(
                    core::mem::size_of::<BuddyAllocator>(),
                ),
            );
        }

        Ok(ProcessDescriptor {
            phys_base,
            virt_base,
            heap_size: HEAP_SIZE,
            cr3: 0, // 0 = uses kernel page table (no per-process table yet)
            vma: VmaTracker::new(),
        })
    }

    /// Return a mutable reference to the in-place `BuddyAllocator` at
    /// the start of this process's heap.
    ///
    /// # Safety / invariant
    ///
    /// This helper only produces a valid reference as long as
    /// `ProcessDescriptor::new` successfully constructed the
    /// descriptor — that's where the allocator is placement-new'd.
    /// All constructors go through `new`, so the invariant holds
    /// for every live descriptor. The returned reference is tied to
    /// `self`'s borrow, so the borrow checker enforces unique access
    /// despite the raw pointer cast inside.
    #[inline]
    fn allocator_mut(&mut self) -> &mut BuddyAllocator {
        // SAFETY: `self.virt_base` holds a valid, initialized
        // `BuddyAllocator` by the struct invariant documented above.
        // The `&mut self` borrow guarantees no aliased access. The
        // lifetime of the returned reference is tied to `self`.
        unsafe { &mut *(self.virt_base as *mut BuddyAllocator) }
    }

    /// Return the heap region back to the frame allocator.
    ///
    /// Called by `handle_exit` / `ProcessTable::destroy_process` as
    /// part of process lifecycle cleanup (Roadmap item 17). After
    /// this call, the descriptor's `phys_base` and `virt_base` point
    /// at frames that no longer belong to this process — the caller
    /// must drop the descriptor immediately and never touch it again.
    ///
    /// The in-place `BuddyAllocator` is NOT explicitly dropped: it's
    /// a plain-array struct with no `Drop` impl, so releasing the
    /// frames is the complete cleanup. The bits of storage that used
    /// to hold its bitmap are simply returned to the pool.
    ///
    /// Returns the frame allocator error on failure, but in normal
    /// operation this should never fail: we allocated `HEAP_PAGES`
    /// contiguous frames in `new`, and the bitmap invariant
    /// guarantees `free_contiguous` succeeds on any base we allocated.
    pub fn reclaim_heap(
        &self,
        frame_alloc: &mut FrameAllocator,
    ) -> Result<(), FrameAllocError> {
        frame_alloc.free_contiguous(self.phys_base, HEAP_PAGES)
    }

    /// Allocate memory, returning the kernel-accessible virtual address.
    /// Returns 0 on failure.
    pub fn allocate(&mut self, size: usize) -> usize {
        let virt_base = self.virt_base as usize;
        match self.allocator_mut().allocate(size) {
            Some(alloc) => virt_base + alloc.offset,
            None => 0,
        }
    }

    /// Free memory by its kernel-accessible virtual address.
    pub fn free(&mut self, virt_addr: usize) -> bool {
        let virt_base = self.virt_base as usize;
        if virt_addr < virt_base {
            return false;
        }
        let offset = virt_addr - virt_base;
        self.allocator_mut().free(offset)
    }
}

/// Process table — slice-backed storage from the kernel object table
/// region.
///
/// Wave 2a: storage is a `&'static mut [Option<ProcessDescriptor>]`
/// slice handed in from `memory::object_table::init()`. The slice
/// length equals `config::num_slots()`, computed at boot from the
/// active tier policy and available RAM. See ADR-008.
pub struct ProcessTable {
    processes: &'static mut [Option<ProcessDescriptor>],
    /// Cached HHDM offset for creating new processes
    hhdm_offset: u64,
}

impl ProcessTable {
    /// Construct a process table backed by an already-initialized
    /// slice from the kernel object table region.
    ///
    /// The slice must have every slot pre-initialized to `None`
    /// (which `object_table::init` guarantees). The returned
    /// `Box<Self>` lives on the kernel heap; only its small header
    /// (slice pointer, length, hhdm_offset) lands there — the actual
    /// slot storage lives in the object table region.
    pub fn from_object_slice(
        processes: &'static mut [Option<ProcessDescriptor>],
        hhdm_offset: u64,
    ) -> Option<Box<Self>> {
        // Small header — trivial allocation, no manual slot init needed.
        let table = ProcessTable {
            processes,
            hhdm_offset,
        };
        Some(Box::new(table))
    }

    /// Number of slots in the table (equal to `config::num_slots()`).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.processes.len()
    }

    /// Create a new process and allocate its heap region.
    ///
    /// Wave 2a: always requires a frame allocator now, because
    /// `ProcessDescriptor::new` itself allocates the per-process heap
    /// via `FrameAllocator::allocate_contiguous(HEAP_PAGES)`. The
    /// previous `frame_alloc: Option<...>` parameter went away — if
    /// you don't want a per-process page table, pass
    /// `create_page_table = false`.
    ///
    /// Failure modes:
    /// - `"Process ID out of range"` — `process_id.0 >= capacity()`
    /// - `"Process already exists"` — slot already `Some`
    /// - `"Failed to allocate process heap"` — frame allocator
    ///   exhausted (after Wave 2a, heaps are allocated on demand)
    /// - `"Failed to allocate page table"` — per-process PML4
    ///   allocation failed
    pub fn create_process(
        &mut self,
        process_id: ProcessId,
        frame_alloc: &mut FrameAllocator,
        create_page_table: bool,
    ) -> Result<(), &'static str> {
        let idx = process_id.0 as usize;
        if idx >= self.processes.len() {
            return Err("Process ID out of range");
        }

        if self.processes[idx].is_some() {
            return Err("Process already exists");
        }

        let mut desc = match ProcessDescriptor::new(process_id, self.hhdm_offset, frame_alloc) {
            Ok(d) => d,
            Err(ProcessCreateError::HeapAllocFailure(_)) => {
                return Err("Failed to allocate process heap");
            }
        };

        // Optionally create a per-process page table
        if create_page_table {
            match paging::create_process_page_table(frame_alloc) {
                Ok(cr3) => {
                    desc.cr3 = cr3;
                    // Kernel access to the process heap is already available
                    // via the cloned HHDM mappings in the kernel half (entries 256..512).
                    // User-space mappings at low addresses are set up separately.
                }
                Err(_) => {
                    // Unwind the heap allocation so we don't leak frames.
                    // If free_contiguous itself fails we still bubble up the
                    // original error to the caller — at that point the frame
                    // allocator is inconsistent regardless.
                    let _ = desc.reclaim_heap(frame_alloc);
                    return Err("Failed to allocate page table");
                }
            }
        }

        self.processes[idx] = Some(desc);
        Ok(())
    }

    /// Allocate memory for a process, returning kernel-accessible virtual address.
    /// Returns 0 on failure.
    pub fn allocate_for(&mut self, process_id: ProcessId, size: usize) -> usize {
        let idx = process_id.0 as usize;
        if idx >= self.processes.len() {
            return 0;
        }
        match self.processes[idx].as_mut() {
            Some(desc) => desc.allocate(size),
            None => 0,
        }
    }

    /// Free memory for a process by kernel-accessible virtual address.
    pub fn free_for(&mut self, process_id: ProcessId, virt_addr: usize) -> bool {
        let idx = process_id.0 as usize;
        if idx >= self.processes.len() {
            return false;
        }
        match self.processes[idx].as_mut() {
            Some(desc) => desc.free(virt_addr),
            None => false,
        }
    }

    /// Get process physical heap base address from the stored descriptor.
    ///
    /// Wave 2a: heaps are no longer at a deterministic
    /// `PROCESS_HEAP_BASE + pid * HEAP_SIZE` address — the base is
    /// whatever the frame allocator handed us at creation time. This
    /// getter reads the stored `phys_base` field.
    pub fn get_heap_base(&self, process_id: ProcessId) -> u64 {
        let idx = process_id.0 as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_ref().map(|p| p.phys_base).unwrap_or(0)
        } else {
            0
        }
    }

    /// Get process heap size
    pub fn get_heap_size(&self, process_id: ProcessId) -> u64 {
        let idx = process_id.0 as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_ref().map(|p| p.heap_size).unwrap_or(0)
        } else {
            0
        }
    }

    /// Destroy a process and reclaim its heap back to the frame allocator.
    ///
    /// Wave 2a / Roadmap item 17 (partial): the per-process heap
    /// region is freed via `FrameAllocator::free_contiguous` so
    /// subsequent process creations can reuse those frames. Page
    /// tables, VMA regions, and endpoint subscriptions are still
    /// leaked — those are tracked separately under item 17.
    pub fn destroy_process(
        &mut self,
        process_id: ProcessId,
        frame_alloc: &mut FrameAllocator,
    ) {
        let idx = process_id.0 as usize;
        if idx >= self.processes.len() {
            return;
        }
        if let Some(desc) = self.processes[idx].take() {
            // Best effort: reclaim the heap. If free_contiguous fails
            // (frame allocator corruption, which shouldn't happen),
            // we've already removed the descriptor from the table —
            // the frames are lost but the slot is free.
            let _ = desc.reclaim_heap(frame_alloc);
        }
    }

    /// Get a process's CR3 (PML4 physical address). Returns 0 if no per-process page table.
    pub fn get_cr3(&self, process_id: ProcessId) -> u64 {
        let idx = process_id.0 as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_ref().map(|p| p.cr3).unwrap_or(0)
        } else {
            0
        }
    }

    /// Check whether a process slot is occupied.
    pub fn slot_occupied(&self, process_id: ProcessId) -> bool {
        let idx = process_id.0 as usize;
        idx < self.processes.len() && self.processes[idx].is_some()
    }

    /// Get mutable access to a process's VMA tracker.
    pub fn vma_mut(&mut self, process_id: ProcessId) -> Option<&mut VmaTracker> {
        let idx = process_id.0 as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_mut().map(|p| &mut p.vma)
        } else {
            None
        }
    }

    /// Get read-only access to a process's VMA tracker.
    pub fn vma(&self, process_id: ProcessId) -> Option<&VmaTracker> {
        let idx = process_id.0 as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_ref().map(|p| &p.vma)
        } else {
            None
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vma_allocate_basic() {
        let mut vma = VmaTracker::new();
        let addr = vma.allocate_region(1).unwrap();
        assert_eq!(addr, VMA_ALLOC_BASE);
        assert_eq!(vma.count(), 1);
    }

    #[test]
    fn test_vma_allocate_sequential() {
        let mut vma = VmaTracker::new();
        let a1 = vma.allocate_region(1).unwrap(); // 1 page
        let a2 = vma.allocate_region(4).unwrap(); // 4 pages
        assert_eq!(a1, VMA_ALLOC_BASE);
        assert_eq!(a2, VMA_ALLOC_BASE + 4096);
        assert_eq!(vma.count(), 2);
    }

    #[test]
    fn test_vma_allocate_zero_pages() {
        let mut vma = VmaTracker::new();
        assert!(vma.allocate_region(0).is_none());
        assert_eq!(vma.count(), 0);
    }

    #[test]
    fn test_vma_find() {
        let mut vma = VmaTracker::new();
        let addr = vma.allocate_region(3).unwrap();
        let entry = vma.find(addr).unwrap();
        assert_eq!(entry.base_vaddr, addr);
        assert_eq!(entry.num_pages, 3);
    }

    #[test]
    fn test_vma_find_nonexistent() {
        let vma = VmaTracker::new();
        assert!(vma.find(0x42000).is_none());
    }

    #[test]
    fn test_vma_free_region() {
        let mut vma = VmaTracker::new();
        let addr = vma.allocate_region(2).unwrap();
        assert_eq!(vma.count(), 1);

        let removed = vma.free_region(addr).unwrap();
        assert_eq!(removed.base_vaddr, addr);
        assert_eq!(removed.num_pages, 2);
        assert_eq!(vma.count(), 0);
        assert!(vma.find(addr).is_none());
    }

    #[test]
    fn test_vma_free_nonexistent() {
        let mut vma = VmaTracker::new();
        assert!(vma.free_region(0xDEAD_0000).is_none());
    }

    #[test]
    fn test_vma_free_then_allocate_reuses_slot() {
        let mut vma = VmaTracker::new();
        let a1 = vma.allocate_region(1).unwrap();
        vma.free_region(a1);

        // New allocation gets the next bump address, not the freed one
        let a2 = vma.allocate_region(1).unwrap();
        assert_eq!(a2, VMA_ALLOC_BASE + 4096);
        // But the freed slot was reused in the array
        assert_eq!(vma.count(), 1);
    }

    #[test]
    fn test_vma_capacity_exhaustion() {
        let mut vma = VmaTracker::new();
        for _ in 0..MAX_VMAS {
            assert!(vma.allocate_region(1).is_some());
        }
        // 65th allocation fails — no free slots
        assert!(vma.allocate_region(1).is_none());
        assert_eq!(vma.count(), MAX_VMAS);
    }
}
