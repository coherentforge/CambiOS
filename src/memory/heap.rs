// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kernel heap allocator
//!
//! A simple linked-list free-list allocator that implements `GlobalAlloc`.
//! Initialized from a USABLE region in the Limine physical memory map,
//! accessed via the Higher-Half Direct Map (HHDM).
//!
//! This gives kernel code access to `alloc::boxed::Box`, `alloc::vec::Vec`, etc.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

/// Minimum block size — must fit a FreeBlock header (2 × usize = 16 bytes on x86-64)
const MIN_BLOCK_SIZE: usize = 16;

/// Alignment for all allocations (16 bytes — x86-64 ABI requirement)
const HEAP_ALIGN: usize = 16;

/// Free block header stored in-place in unallocated memory
#[repr(C)]
struct FreeBlock {
    size: usize,
    next: *mut FreeBlock,
}

/// Kernel heap allocator state.
///
/// Uses a sorted free-list with first-fit allocation and block coalescing on free.
/// Protected by a simple spinlock for multicore safety.
///
/// # Invariants (for formal verification)
///
/// - The free list is sorted by ascending address. For any node `n`,
///   `n.next` is either null or points to a higher address.
/// - Adjacent free blocks are coalesced: no two consecutive free blocks
///   exist where `node_addr + node_size == next_node_addr`.
/// - Every free block has `size >= MIN_BLOCK_SIZE` (16 bytes).
/// - All free block pointers fall within `[heap_base, heap_base + heap_size)`.
/// - The sum of all free block sizes plus all allocated block sizes equals
///   `heap_size` (no memory is leaked or double-counted).
/// - After `initialized == true`, `heap_base` and `heap_size` are immutable.
/// - The allocator header `[block_base, block_total_size]` at `(user_ptr - 16)`
///   is only valid for pointers returned by `alloc()`.
pub struct KernelHeapAllocator {
    /// Head of the free block list (sorted by address for coalescing)
    free_list: *mut FreeBlock,
    /// Whether the allocator has been initialized
    initialized: bool,
    /// Total heap size in bytes
    heap_size: usize,
    /// Heap base virtual address
    heap_base: usize,
}

/// Global allocator wrapper with spinlock
pub struct LockedHeapAllocator {
    lock: AtomicBool,
    inner: core::cell::UnsafeCell<KernelHeapAllocator>,
}

// SAFETY: All access to the inner KernelHeapAllocator is gated by the atomic
// spinlock (acquire/release). No caller can obtain a reference without holding
// the lock, so there are no data races.

/// SAFETY: Locked access via atomic spinlock prevents concurrent mutation.
unsafe impl Send for LockedHeapAllocator {}
/// SAFETY: Locked access via atomic spinlock prevents concurrent mutation.
unsafe impl Sync for LockedHeapAllocator {}

impl Default for LockedHeapAllocator {
    fn default() -> Self { Self::new() }
}

impl LockedHeapAllocator {
    /// Create an uninitialized allocator (call `init` before use)
    pub const fn new() -> Self {
        LockedHeapAllocator {
            lock: AtomicBool::new(false),
            inner: core::cell::UnsafeCell::new(KernelHeapAllocator {
                free_list: ptr::null_mut(),
                initialized: false,
                heap_size: 0,
                heap_base: 0,
            }),
        }
    }

    fn acquire(&self) {
        while self.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
    }

    fn release(&self) {
        self.lock.store(false, Ordering::Release);
    }

    /// Initialize the heap allocator with a memory region.
    ///
    /// # Safety
    /// `heap_start` must point to a valid, writable region of at least `heap_size` bytes
    /// that is not used by anything else. Must be called exactly once.
    pub unsafe fn init(&self, heap_start: usize, heap_size: usize) {
        self.acquire();
        // SAFETY: We hold the spinlock; inner.get() gives exclusive access.
        let inner = unsafe { &mut *self.inner.get() };

        assert!(!inner.initialized, "Kernel heap already initialized");
        assert!(heap_size >= MIN_BLOCK_SIZE, "Heap too small");
        assert!(heap_start.is_multiple_of(HEAP_ALIGN), "Heap base not aligned");

        let block = heap_start as *mut FreeBlock;
        // SAFETY: heap_start is a valid, writable, heap_size-byte region per caller contract.
        // heap_size >= MIN_BLOCK_SIZE ensures the region can hold at least one FreeBlock.
        unsafe { (*block).size = heap_size };
        // SAFETY: Same region — writing the next pointer of the initial free block.
        unsafe { (*block).next = ptr::null_mut() };

        inner.free_list = block;
        inner.heap_base = heap_start;
        inner.heap_size = heap_size;
        inner.initialized = true;

        self.release();
    }

    /// Returns true if the allocator has been initialized
    pub fn is_initialized(&self) -> bool {
        self.acquire();
        // SAFETY: Lock is held; inner.get() gives shared access for a Copy field read.
        let val = unsafe { (*self.inner.get()).initialized };
        self.release();
        val
    }

    /// Returns (used, free) byte counts for diagnostics
    pub fn stats(&self) -> (usize, usize) {
        self.acquire();
        // SAFETY: Lock is held; inner.get() gives shared access.
        let inner = unsafe { &*self.inner.get() };
        let mut free = 0usize;
        let mut current = inner.free_list;
        while !current.is_null() {
            // SAFETY: Each node in the free list was written by init() or dealloc().
            // The list is sorted by address and nodes don't overlap, so each
            // FreeBlock pointer is valid while we hold the lock.
            // SAFETY: current is a valid FreeBlock pointer within the heap region;
            // we hold the spinlock so no concurrent mutation.
            free += unsafe { (*current).size };
            // SAFETY: Same invariant as above — current is valid, lock is held.
            current = unsafe { (*current).next };
        }
        self.release();
        (inner.heap_size - free, free)
    }
}

/// SAFETY: The atomic spinlock serializes all alloc/dealloc calls.
/// The free-list is maintained such that all FreeBlock pointers remain
/// valid while the lock is held, and allocated regions are never
/// returned to the list until dealloc is called with the matching pointer.
unsafe impl GlobalAlloc for LockedHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(MIN_BLOCK_SIZE);
        let align = layout.align().max(HEAP_ALIGN);
        // We store [block_base, block_total_size] in 16 bytes before the user pointer.
        // This means the user pointer is always at least 16 bytes into the block.
        let header_size: usize = 16; // 2 × usize

        self.acquire();
        // SAFETY: Lock is held; inner.get() gives exclusive access.
        let inner = unsafe { &mut *self.inner.get() };

        // Pre-init allocation is a callsite bug: something ran before
        // memory::init() and tried to allocate on the kernel heap. The
        // silent null-return below is the correct release-build fallback
        // but hides the callsite; this assert names it directly in debug
        // builds so the failure lands at the bad call, not downstream.
        debug_assert!(
            inner.initialized,
            "kernel heap alloc before memory::init()",
        );

        if !inner.initialized {
            self.release();
            return ptr::null_mut();
        }

        // First-fit search through sorted free list.
        // All pointer dereferences below access FreeBlock nodes in the free list.
        // Each node was written by init() or dealloc() and is valid while we hold the lock.
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = inner.free_list;

        while !current.is_null() {
            let block_addr = current as usize;
            // SAFETY: current is a valid FreeBlock pointer; lock is held.
            let block_size = unsafe { (*current).size };

            // User data starts after 16-byte header, aligned
            let data_start = block_addr + header_size;
            let aligned_start = align_up(data_start, align);
            let total_needed = (aligned_start - block_addr) + size;

            if block_size >= total_needed {
                let remainder = block_size - total_needed;

                // Remove or split the block from the free list FIRST
                // (before we overwrite the FreeBlock header with our alloc header)
                // SAFETY: current is valid; reading next pointer.
                let next_block = unsafe { (*current).next };

                if remainder >= MIN_BLOCK_SIZE + header_size {
                    // Split: create a new free block after this allocation
                    let new_block = (block_addr + total_needed) as *mut FreeBlock;
                    // SAFETY: new_block is within the heap region (block_addr + total_needed < block_end).
                    unsafe { (*new_block).size = remainder };
                    // SAFETY: Same pointer — writing the next field.
                    unsafe { (*new_block).next = next_block };

                    if prev.is_null() {
                        inner.free_list = new_block;
                    } else {
                        // SAFETY: prev is a valid FreeBlock pointer in the free list.
                        unsafe { (*prev).next = new_block };
                    }
                } else {
                    // Use the whole block
                    if prev.is_null() {
                        inner.free_list = next_block;
                    } else {
                        // SAFETY: prev is a valid FreeBlock pointer.
                        unsafe { (*prev).next = next_block };
                    }
                }

                // Write 2-word header: [block_base, total_block_size]
                let hdr = (aligned_start - header_size) as *mut [usize; 2];
                // SAFETY: hdr points to the 16-byte header region within the allocated block.
                unsafe { (*hdr)[0] = block_addr };
                // SAFETY: Same header region — writing block size.
                unsafe { (*hdr)[1] = if remainder >= MIN_BLOCK_SIZE + header_size { total_needed } else { block_size } };

                self.release();
                return aligned_start as *mut u8;
            }

            prev = current;
            // SAFETY: current is valid; reading next pointer.
            current = unsafe { (*current).next };
        }

        self.release();
        ptr::null_mut() // Out of memory
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }

        let header_size: usize = 16;
        let hdr = (ptr as usize - header_size) as *mut [usize; 2];
        // SAFETY: ptr was returned by our alloc(), which writes a [block_base, block_size]
        // header at (aligned_start - 16). Reading it back here recovers the original
        // allocation metadata. If ptr was NOT returned by this allocator, this is UB.
        let block_addr = unsafe { (*hdr)[0] };
        // SAFETY: Same header — reading the block size field.
        let block_size = unsafe { (*hdr)[1] };

        self.acquire();
        // SAFETY: Lock is held; inner.get() gives exclusive access.
        let inner = unsafe { &mut *self.inner.get() };

        // Insert freed block into sorted free list and coalesce.
        // All pointer dereferences below access FreeBlock nodes in the free list
        // or the newly freed block, sorted by address, non-overlapping.
        let freed = block_addr as *mut FreeBlock;
        // SAFETY: freed points to the start of the block being returned.
        unsafe { (*freed).size = block_size };

        // Find insertion point (list is sorted by address)
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = inner.free_list;

        while !current.is_null() && (current as usize) < block_addr {
            prev = current;
            // SAFETY: current is a valid FreeBlock in the free list; lock is held.
            current = unsafe { (*current).next };
        }

        // Insert into list
        // SAFETY: freed is valid — writing next pointer.
        unsafe { (*freed).next = current };
        if prev.is_null() {
            inner.free_list = freed;
        } else {
            // SAFETY: prev is a valid FreeBlock pointer.
            unsafe { (*prev).next = freed };
        }

        // Coalesce with next block if adjacent
        if !current.is_null() {
            // SAFETY: freed is valid — reading size.
            let freed_end = block_addr + unsafe { (*freed).size };
            if freed_end == current as usize {
                // SAFETY: current is valid — reading size for coalesce.
                let current_size = unsafe { (*current).size };
                // SAFETY: freed is valid — adding coalesced size.
                unsafe { (*freed).size += current_size };
                // SAFETY: current is valid — reading next pointer for splice.
                let current_next = unsafe { (*current).next };
                // SAFETY: freed is valid — updating next pointer.
                unsafe { (*freed).next = current_next };
            }
        }

        // Coalesce with previous block if adjacent
        if !prev.is_null() {
            // SAFETY: prev is valid — reading size.
            let prev_end = prev as usize + unsafe { (*prev).size };
            if prev_end == freed as usize {
                // SAFETY: freed is valid — reading size for coalesce.
                let freed_size = unsafe { (*freed).size };
                // SAFETY: prev is valid — adding coalesced size.
                unsafe { (*prev).size += freed_size };
                // SAFETY: freed is valid — reading next pointer.
                let freed_next = unsafe { (*freed).next };
                // SAFETY: prev is valid — updating next pointer.
                unsafe { (*prev).next = freed_next };
            }
        }

        self.release();
    }
}

/// Align `addr` upward to `align` (must be a power of 2)
#[inline]
const fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::alloc::Layout;

    /// Helper: create a heap in a Vec-backed buffer
    fn make_test_heap(size: usize) -> (LockedHeapAllocator, Vec<u8>) {
        let alloc = LockedHeapAllocator::new();
        let mut buf = vec![0u8; size + 16]; // extra for alignment
        let base = align_up(buf.as_mut_ptr() as usize, 16);
        unsafe { alloc.init(base, size) };
        (alloc, buf)
    }

    #[test]
    fn test_basic_alloc_dealloc() {
        let (alloc, _buf) = make_test_heap(4096);
        let layout = Layout::from_size_align(64, 16).unwrap();

        let ptr = unsafe { alloc.alloc(layout) };
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % 16, 0);

        unsafe { alloc.dealloc(ptr, layout) };

        // Should be able to allocate again after free
        let ptr2 = unsafe { alloc.alloc(layout) };
        assert!(!ptr2.is_null());
        unsafe { alloc.dealloc(ptr2, layout) };
    }

    #[test]
    fn test_multiple_allocs() {
        let (alloc, _buf) = make_test_heap(4096);
        let layout = Layout::from_size_align(64, 16).unwrap();

        let mut ptrs = Vec::new();
        for _ in 0..10 {
            let ptr = unsafe { alloc.alloc(layout) };
            assert!(!ptr.is_null(), "allocation failed");
            ptrs.push(ptr);
        }

        // All pointers should be different and aligned
        for i in 0..ptrs.len() {
            assert_eq!(ptrs[i] as usize % 16, 0);
            for j in (i + 1)..ptrs.len() {
                assert_ne!(ptrs[i], ptrs[j]);
            }
        }

        // Free all
        for ptr in ptrs {
            unsafe { alloc.dealloc(ptr, layout) };
        }
    }

    #[test]
    fn test_oom_returns_null() {
        let (alloc, _buf) = make_test_heap(256);
        let big_layout = Layout::from_size_align(512, 16).unwrap();
        let ptr = unsafe { alloc.alloc(big_layout) };
        assert!(ptr.is_null());
    }

    #[test]
    fn test_coalescing() {
        let (alloc, _buf) = make_test_heap(4096);
        let layout = Layout::from_size_align(128, 16).unwrap();

        // Allocate 3 blocks
        let p1 = unsafe { alloc.alloc(layout) };
        let p2 = unsafe { alloc.alloc(layout) };
        let p3 = unsafe { alloc.alloc(layout) };
        assert!(!p1.is_null() && !p2.is_null() && !p3.is_null());

        // Free all three (should coalesce back into one big block)
        unsafe {
            alloc.dealloc(p1, layout);
            alloc.dealloc(p2, layout);
            alloc.dealloc(p3, layout);
        }

        // Should now be able to allocate a larger block from coalesced space
        let big_layout = Layout::from_size_align(384, 16).unwrap();
        let big = unsafe { alloc.alloc(big_layout) };
        assert!(!big.is_null());
        unsafe { alloc.dealloc(big, big_layout) };
    }

    #[test]
    fn test_stats() {
        let (alloc, _buf) = make_test_heap(4096);
        let (used, free) = alloc.stats();
        assert_eq!(used, 0);
        assert_eq!(free, 4096);

        let layout = Layout::from_size_align(64, 16).unwrap();
        let ptr = unsafe { alloc.alloc(layout) };
        assert!(!ptr.is_null());

        let (used, free) = alloc.stats();
        assert!(used > 0);
        assert!(free < 4096);
        assert_eq!(used + free, 4096);

        unsafe { alloc.dealloc(ptr, layout) };
    }
}
