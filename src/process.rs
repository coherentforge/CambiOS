/// Process management and heap allocation
///
/// Manages per-process state including memory allocators.
/// Each process gets a BuddyAllocator (pure bookkeeping) plus physical and
/// virtual base addresses. The allocator returns offsets; this module
/// translates them to the caller's address space.

use crate::memory::buddy_allocator::BuddyAllocator;
use crate::ipc::ProcessId;
extern crate alloc;
use alloc::boxed::Box;

/// Maximum number of concurrent processes
/// Note: Each ProcessDescriptor contains a ~20KB allocator (bitmap + order map).
/// Kept small (32) to limit total footprint.
pub const MAX_PROCESSES: usize = 32;

/// Base physical address for process heaps
/// Each process gets its own heap at: PROCESS_HEAP_BASE + (pid * HEAP_SIZE)
pub const PROCESS_HEAP_BASE: u64 = 0x200000;
pub const HEAP_SIZE: u64 = 0x100000; // 1MB per process

/// Process descriptor with heap allocator
pub struct ProcessDescriptor {
    /// Pure bookkeeping allocator (returns offsets, no memory I/O)
    pub allocator: BuddyAllocator,
    /// Physical base address of this process's heap (for page tables)
    pub phys_base: u64,
    /// HHDM-mapped virtual base (for kernel-side access)
    pub virt_base: u64,
    /// Heap size in bytes
    pub heap_size: u64,
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
    pub fn new_boxed(hhdm_offset: u64) -> Box<Self> {
        use alloc::alloc::{alloc_zeroed, Layout};
        let layout = Layout::new::<Self>();
        let ptr = unsafe { alloc_zeroed(layout) as *mut Self };
        if ptr.is_null() {
            panic!("Failed to allocate ProcessTable");
        }
        // Write the hhdm_offset field (rest is valid as zeroed: Option = None)
        unsafe {
            core::ptr::addr_of_mut!((*ptr).hhdm_offset).write(hhdm_offset);
            Box::from_raw(ptr)
        }
    }

    /// Create a new process
    pub fn create_process(&mut self, process_id: ProcessId) -> Result<(), &'static str> {
        let idx = process_id.0 as usize;
        if idx >= MAX_PROCESSES {
            return Err("Process ID out of range");
        }

        if self.processes[idx].is_some() {
            return Err("Process already exists");
        }

        self.processes[idx] = Some(ProcessDescriptor::new(process_id, self.hhdm_offset));
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
}
