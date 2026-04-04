/// Process management, heap allocation, and virtual memory area tracking
///
/// Manages per-process state including memory allocators and VMA tracking.
/// Each process gets a BuddyAllocator (pure bookkeeping) plus a VmaTracker
/// that records user-space virtual memory allocations for proper free/unmap.

use crate::memory::buddy_allocator::BuddyAllocator;
use crate::memory::frame_allocator::FrameAllocator;
use crate::memory::paging;
use crate::ipc::ProcessId;
extern crate alloc;
use alloc::boxed::Box;

// ============================================================================
// Virtual Memory Area (VMA) tracking
// ============================================================================

/// Maximum number of tracked allocations per process
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

/// Maximum number of concurrent processes
/// Note: Each ProcessDescriptor contains a ~20KB allocator (bitmap + order map).
/// Kept small (32) to limit total footprint.
pub const MAX_PROCESSES: usize = 32;

/// Base physical address for process heaps.
/// Each process gets its own heap at: PROCESS_HEAP_BASE + (pid * HEAP_SIZE).
///
/// Starts at 8MB to avoid conflicts with the kernel heap (4MB at 0x200000).
pub const PROCESS_HEAP_BASE: u64 = 0x800000;
pub const HEAP_SIZE: u64 = 0x100000; // 1MB per process

/// Process descriptor with heap allocator and VMA tracking
pub struct ProcessDescriptor {
    /// Pure bookkeeping allocator (returns offsets, no memory I/O)
    pub allocator: BuddyAllocator,
    /// Physical base address of this process's heap (for page tables)
    pub phys_base: u64,
    /// HHDM-mapped virtual base (for kernel-side access)
    pub virt_base: u64,
    /// Heap size in bytes
    pub heap_size: u64,
    /// Physical address of PML4 page table (CR3 value). 0 = uses kernel page table.
    pub cr3: u64,
    /// Tracks user-space virtual memory allocations (for SYS_ALLOCATE / SYS_FREE)
    pub vma: VmaTracker,
}

impl ProcessDescriptor {
    /// Create a new process descriptor
    ///
    /// `hhdm_offset`: the higher-half direct map offset from Limine,
    /// so the kernel can access process heap memory.
    pub fn new(process_id: ProcessId, hhdm_offset: u64) -> Self {
        let phys_base = PROCESS_HEAP_BASE + (process_id.0 as u64 * HEAP_SIZE);
        ProcessDescriptor {
            allocator: BuddyAllocator::new(),
            phys_base,
            virt_base: phys_base + hhdm_offset,
            heap_size: HEAP_SIZE,
            cr3: 0, // 0 = uses kernel page table (no per-process table yet)
            vma: VmaTracker::new(),
        }
    }

    /// Allocate memory, returning the kernel-accessible virtual address.
    /// Returns 0 on failure.
    pub fn allocate(&mut self, size: usize) -> usize {
        match self.allocator.allocate(size) {
            Some(alloc) => self.virt_base as usize + alloc.offset,
            None => 0,
        }
    }

    /// Free memory by its kernel-accessible virtual address.
    pub fn free(&mut self, virt_addr: usize) -> bool {
        if virt_addr < self.virt_base as usize {
            return false;
        }
        let offset = virt_addr - self.virt_base as usize;
        self.allocator.free(offset)
    }
}

/// Process table
pub struct ProcessTable {
    processes: [Option<ProcessDescriptor>; MAX_PROCESSES],
    /// Cached HHDM offset for creating new processes
    hhdm_offset: u64,
}

impl ProcessTable {
    /// Create an empty process table
    pub fn new(hhdm_offset: u64) -> Self {
        ProcessTable {
            processes: [const { None }; MAX_PROCESSES],
            hhdm_offset,
        }
    }

    /// Create an empty process table directly on the heap.
    ///
    /// Allocates raw memory (MAX_PROCESSES × size_of::<ProcessDescriptor>() bytes)
    /// and initializes each slot explicitly to `None`.
    /// We cannot rely on zeroed memory == `None` because the compiler may
    /// assign discriminant 0 to `Some` for `Option<ProcessDescriptor>` on
    /// bare-metal targets (observed on `x86_64-unknown-none` release builds).
    pub fn new_boxed(hhdm_offset: u64) -> Box<Self> {
        use alloc::alloc::{alloc, Layout};
        let layout = Layout::new::<Self>();
        // SAFETY: layout is non-zero-sized (ProcessTable contains arrays).
        let ptr = unsafe { alloc(layout) as *mut Self };
        if ptr.is_null() {
            panic!("Failed to allocate ProcessTable");
        }
        // SAFETY: ptr is valid, properly aligned, and large enough for ProcessTable.
        // We initialize every field before constructing the Box.
        unsafe {
            for i in 0..MAX_PROCESSES {
                core::ptr::addr_of_mut!((*ptr).processes[i]).write(None);
            }
            core::ptr::addr_of_mut!((*ptr).hhdm_offset).write(hhdm_offset);
            Box::from_raw(ptr)
        }
    }

    /// Create a new process with its own page table.
    ///
    /// Allocates a fresh PML4 with kernel mappings cloned, then maps the
    /// process heap region as user-accessible. Pass `None` for frame_alloc
    /// to skip page table creation (process uses kernel page table).
    pub fn create_process(
        &mut self,
        process_id: ProcessId,
        frame_alloc: Option<&mut FrameAllocator>,
    ) -> Result<(), &'static str> {
        let idx = process_id.0 as usize;
        if idx >= MAX_PROCESSES {
            return Err("Process ID out of range");
        }

        if self.processes[idx].is_some() {
            return Err("Process already exists");
        }

        let mut desc = ProcessDescriptor::new(process_id, self.hhdm_offset);

        // Optionally create a per-process page table
        if let Some(fa) = frame_alloc {
            match paging::create_process_page_table(fa) {
                Ok(cr3) => {
                    desc.cr3 = cr3;
                    // Kernel access to the process heap is already available
                    // via the cloned HHDM mappings in the kernel half (entries 256..512).
                    // User-space mappings at low addresses are set up separately.
                }
                Err(_) => return Err("Failed to allocate page table"),
            }
        }

        self.processes[idx] = Some(desc);
        Ok(())
    }

    /// Allocate memory for a process, returning kernel-accessible virtual address.
    /// Returns 0 on failure.
    pub fn allocate_for(&mut self, process_id: ProcessId, size: usize) -> usize {
        let idx = process_id.0 as usize;
        if idx >= MAX_PROCESSES {
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
        if idx >= MAX_PROCESSES {
            return false;
        }
        match self.processes[idx].as_mut() {
            Some(desc) => desc.free(virt_addr),
            None => false,
        }
    }

    /// Get process physical heap base address
    pub fn get_heap_base(&self, process_id: ProcessId) -> u64 {
        PROCESS_HEAP_BASE + (process_id.0 as u64 * HEAP_SIZE)
    }

    /// Get process heap size
    pub fn get_heap_size(&self, process_id: ProcessId) -> u64 {
        let idx = process_id.0 as usize;
        if idx < MAX_PROCESSES {
            self.processes[idx].as_ref().map(|p| p.heap_size).unwrap_or(0)
        } else {
            0
        }
    }

    /// Destroy a process
    pub fn destroy_process(&mut self, process_id: ProcessId) {
        let idx = process_id.0 as usize;
        if idx < MAX_PROCESSES {
            self.processes[idx] = None;
        }
    }

    /// Get a process's CR3 (PML4 physical address). Returns 0 if no per-process page table.
    pub fn get_cr3(&self, process_id: ProcessId) -> u64 {
        let idx = process_id.0 as usize;
        if idx < MAX_PROCESSES {
            self.processes[idx].as_ref().map(|p| p.cr3).unwrap_or(0)
        } else {
            0
        }
    }

    /// Check whether a process slot is occupied.
    pub fn slot_occupied(&self, process_id: ProcessId) -> bool {
        let idx = process_id.0 as usize;
        idx < MAX_PROCESSES && self.processes[idx].is_some()
    }

    /// Get mutable access to a process's VMA tracker.
    pub fn vma_mut(&mut self, process_id: ProcessId) -> Option<&mut VmaTracker> {
        let idx = process_id.0 as usize;
        if idx < MAX_PROCESSES {
            self.processes[idx].as_mut().map(|p| &mut p.vma)
        } else {
            None
        }
    }

    /// Get read-only access to a process's VMA tracker.
    pub fn vma(&self, process_id: ProcessId) -> Option<&VmaTracker> {
        let idx = process_id.0 as usize;
        if idx < MAX_PROCESSES {
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
