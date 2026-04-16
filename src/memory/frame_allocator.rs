// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Physical frame allocator
//!
//! Bitmap-based allocator for 4 KiB physical pages. Initialized from the
//! Limine memory map: only USABLE regions become available frames.
//!
//! Design:
//! - Bitmap tracks allocation state (1 bit per 4 KiB frame)
//! - Supports up to 16 GiB physical memory (4194304 frames × 4 KiB)
//! - Thread-safe: intended to be wrapped in a Spinlock at the call site
//! - Excludes reserved regions, kernel heap, and kernel image automatically

use core::fmt;

/// Page / frame size: 4 KiB
pub const PAGE_SIZE: u64 = 4096;

/// SCAFFOLDING: physical frame allocator covers the first 16 GiB.
/// (4194304 frames × 4 KiB = 16 GiB; bitmap is 512 KiB in `.bss`.)
///
/// Fits both QEMU targets and the Dell 3630 bare-metal target:
/// - x86_64 QEMU: RAM at 0x0, typically ≤ 512 MiB
/// - AArch64 QEMU virt: RAM at 0x40000000 (1 GiB), needs frames up to ~1.25 GiB
/// - Dell 3630 bare metal: 16 GiB RAM — this is why the ceiling was raised
///
/// Why: bitmap-based allocator with .bss-sized bitmap is the simplest correct
///      implementation. The old 2 GiB ceiling was a documented bare-metal
///      blocker (Dell 3630 has 16 GiB); bumping to 16 GiB resolves that and
///      gives headroom for the v1 endgame graphics workload (ADR-011) which
///      can hold multi-GiB GPU textures, backing stores, and framebuffers.
///      Bitmap grows from 64 KiB to 512 KiB in .bss — a 448 KiB increase
///      in the kernel's runtime memory footprint, no impact on binary size.
/// Replace when: bare-metal targets with > 16 GiB of RAM need the full
///      physical range tracked. At that point, consider a tiered structure
///      (multi-level bitmap or sparse tree) rather than growing the flat
///      bitmap further — at 32 GiB the bitmap would be 1 MiB, at 64 GiB it
///      would be 2 MiB, and the linear-scan allocator becomes prohibitively
///      slow for allocate_contiguous of large regions. See docs/ASSUMPTIONS.md.
const MAX_FRAMES: usize = 4194304;

/// Bitmap words needed: 4194304 / 64 = 65536
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// Physical frame allocator using a bitmap.
///
/// Each bit represents a 4 KiB frame:
/// - 0 = free
/// - 1 = allocated or reserved
///
/// # Invariants (for formal verification)
///
/// - `total_frames <= MAX_FRAMES` (4194304, covering 0–16 GiB physical).
/// - `free_frames <= total_frames` always.
/// - `free_frames` equals the number of 0-bits in `bitmap[0..total_frames]`.
/// - `search_hint < BITMAP_WORDS` (wraps around on overflow).
/// - A frame is allocated iff its bit is set: `bitmap[idx/64] & (1 << (idx%64)) != 0`.
/// - Frames outside `0..total_frames` have their bits permanently set to 1.
/// - Once `initialized == true`, the bitmap is consistent and ready for use.
/// - Thread safety: caller must hold the FRAME_ALLOCATOR spinlock (lock order 6).
pub struct FrameAllocator {
    /// Allocation bitmap (1 = used, 0 = free)
    bitmap: [u64; BITMAP_WORDS],
    /// Total number of frames tracked (up to MAX_FRAMES)
    total_frames: usize,
    /// Number of currently free frames
    free_frames: usize,
    /// Hint: start searching from this word index (wraps around)
    search_hint: usize,
    /// Whether the allocator has been initialized
    initialized: bool,
}

/// Result of a frame allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysFrame {
    /// Physical address of the frame (4 KiB aligned)
    pub addr: u64,
}

impl PhysFrame {
    /// Create a PhysFrame from an address (must be page-aligned)
    pub fn containing_address(addr: u64) -> Self {
        PhysFrame {
            addr: addr & !(PAGE_SIZE - 1),
        }
    }

    /// Frame index in the bitmap
    fn index(self) -> usize {
        (self.addr / PAGE_SIZE) as usize
    }
}

impl fmt::Display for PhysFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PhysFrame({:#x})", self.addr)
    }
}

/// Errors from the frame allocator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAllocError {
    OutOfMemory,
    NotInitialized,
    InvalidFrame,
    DoubleFree,
}

impl FrameAllocator {
    /// Create an uninitialized frame allocator.
    ///
    /// All frames start as "used" (bitmap = all 1s). `init_region()` marks
    /// USABLE regions as free.
    pub const fn new() -> Self {
        FrameAllocator {
            bitmap: [u64::MAX; BITMAP_WORDS], // All frames marked used
            total_frames: 0,
            free_frames: 0,
            search_hint: 0,
            initialized: false,
        }
    }
}

impl Default for FrameAllocator {
    fn default() -> Self { Self::new() }
}

impl FrameAllocator {
    /// Mark a physical region as available (free) for allocation.
    ///
    /// Called once per USABLE entry in the Limine memory map.
    /// `base` and `length` are physical addresses/sizes.
    pub fn add_region(&mut self, base: u64, length: u64) {
        let start_frame = base.div_ceil(PAGE_SIZE); // Round up
        let end_frame = (base + length) / PAGE_SIZE; // Round down

        for frame_idx in start_frame..end_frame {
            let idx = frame_idx as usize;
            if idx >= MAX_FRAMES {
                break;
            }
            self.clear_bit(idx);
            self.free_frames += 1;
            if idx >= self.total_frames {
                self.total_frames = idx + 1;
            }
        }
    }

    /// Mark a physical region as reserved (prevents allocation).
    ///
    /// Use this to exclude the kernel image, kernel heap, page tables, etc.
    pub fn reserve_region(&mut self, base: u64, length: u64) {
        let start_frame = base / PAGE_SIZE; // Round down (conservative)
        let end_frame = (base + length).div_ceil(PAGE_SIZE); // Round up

        for frame_idx in start_frame..end_frame {
            let idx = frame_idx as usize;
            if idx >= MAX_FRAMES {
                break;
            }
            if !self.is_set(idx) {
                // Was free, now reserved
                self.set_bit(idx);
                self.free_frames = self.free_frames.saturating_sub(1);
            }
        }
    }

    /// Finalize initialization after all regions have been added/reserved.
    pub fn finalize(&mut self) {
        self.initialized = true;
    }

    /// Allocate a single 4 KiB physical frame.
    ///
    /// Returns the physical address of the allocated frame, or an error.
    pub fn allocate(&mut self) -> Result<PhysFrame, FrameAllocError> {
        if !self.initialized {
            return Err(FrameAllocError::NotInitialized);
        }

        let words = self.total_frames.div_ceil(64);

        // Search from hint, wrapping around
        for offset in 0..words {
            let word_idx = (self.search_hint + offset) % words;
            let word = self.bitmap[word_idx];

            if word == u64::MAX {
                continue; // All bits set — no free frames in this word
            }

            // Find first zero bit
            let bit = (!word).trailing_zeros() as usize;
            let frame_idx = word_idx * 64 + bit;

            if frame_idx >= self.total_frames {
                continue;
            }

            self.set_bit(frame_idx);
            self.free_frames -= 1;
            self.search_hint = word_idx; // Start next search here

            return Ok(PhysFrame {
                addr: frame_idx as u64 * PAGE_SIZE,
            });
        }

        Err(FrameAllocError::OutOfMemory)
    }

    /// Allocate `count` physically contiguous 4 KiB frames.
    ///
    /// Scans the bitmap for a run of `count` consecutive free bits.
    /// Returns the physical address of the first frame, or an error.
    /// All frames in the run are marked as allocated.
    ///
    /// Two use cases today:
    /// - DMA buffers (virtio-net, etc.) where the device needs a physically
    ///   contiguous buffer. Per-call cap is now 32768 frames (128 MiB) —
    ///   raised for the v1 endgame graphics workload (ADR-011) which needs
    ///   GPU command buffers and GPU-visible memory regions well above the
    ///   virtio-net envelope.
    /// - Per-process heaps (Phase 3.2a) where each process needs a
    ///   `HEAP_SIZE / PAGE_SIZE` contiguous physical run (1024 frames /
    ///   4 MiB by default). The bitmap scan is `O(total_frames)`
    ///   regardless of `count`, so there's no per-call runtime concern for
    ///   reasonably-sized requests.
    pub fn allocate_contiguous(&mut self, count: usize) -> Result<PhysFrame, FrameAllocError> {
        if !self.initialized {
            return Err(FrameAllocError::NotInitialized);
        }

        if count == 0 {
            return Err(FrameAllocError::OutOfMemory);
        }

        if count > self.free_frames {
            return Err(FrameAllocError::OutOfMemory);
        }

        // Scan for a run of `count` consecutive free frames
        let mut run_start: usize = 0;
        let mut run_len: usize = 0;

        for idx in 0..self.total_frames {
            if self.is_set(idx) {
                // Allocated — reset the run
                run_len = 0;
            } else {
                // Free frame
                if run_len == 0 {
                    run_start = idx;
                }
                run_len += 1;

                if run_len == count {
                    // Found a sufficient run — mark all frames as allocated
                    for i in run_start..run_start + count {
                        self.set_bit(i);
                    }
                    self.free_frames -= count;

                    return Ok(PhysFrame {
                        addr: run_start as u64 * PAGE_SIZE,
                    });
                }
            }
        }

        Err(FrameAllocError::OutOfMemory)
    }

    /// Free `count` physically contiguous 4 KiB frames starting at `base`.
    ///
    /// Inverse of `allocate_contiguous`. Used by the process heap reclaim
    /// path in `handle_exit` (Phase 3.2a).
    ///
    /// All `count` frames must currently be allocated; partially-freed
    /// regions return `DoubleFree` and leave the bitmap unchanged (the
    /// check is performed as a pre-pass so partial success is impossible).
    pub fn free_contiguous(
        &mut self,
        base: u64,
        count: usize,
    ) -> Result<(), FrameAllocError> {
        if !self.initialized {
            return Err(FrameAllocError::NotInitialized);
        }

        if count == 0 {
            return Ok(());
        }

        if !base.is_multiple_of(PAGE_SIZE) {
            return Err(FrameAllocError::InvalidFrame);
        }

        let start_idx = (base / PAGE_SIZE) as usize;
        let end_idx = start_idx.saturating_add(count);

        if end_idx > self.total_frames {
            return Err(FrameAllocError::InvalidFrame);
        }

        // Pre-pass: every frame in [start_idx, end_idx) must be allocated,
        // otherwise fail without touching the bitmap.
        for idx in start_idx..end_idx {
            if !self.is_set(idx) {
                return Err(FrameAllocError::DoubleFree);
            }
        }

        // Clear all bits and update the free-frame counter.
        for idx in start_idx..end_idx {
            self.clear_bit(idx);
        }
        self.free_frames += count;

        // Move hint back so future allocations can re-use this range.
        let word_idx = start_idx / 64;
        if word_idx < self.search_hint {
            self.search_hint = word_idx;
        }

        Ok(())
    }

    /// Free a previously allocated frame.
    pub fn free(&mut self, frame: PhysFrame) -> Result<(), FrameAllocError> {
        if !self.initialized {
            return Err(FrameAllocError::NotInitialized);
        }

        let idx = frame.index();
        if idx >= self.total_frames {
            return Err(FrameAllocError::InvalidFrame);
        }

        if !self.is_set(idx) {
            return Err(FrameAllocError::DoubleFree);
        }

        self.clear_bit(idx);
        self.free_frames += 1;

        // Move hint back if this frees an earlier word
        let word_idx = idx / 64;
        if word_idx < self.search_hint {
            self.search_hint = word_idx;
        }

        Ok(())
    }

    /// Number of free 4 KiB frames
    pub fn free_count(&self) -> usize {
        self.free_frames
    }

    /// Total tracked frames
    pub fn total_count(&self) -> usize {
        self.total_frames
    }

    /// Whether the allocator has been initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // --- Bitmap helpers ---

    fn set_bit(&mut self, idx: usize) {
        self.bitmap[idx / 64] |= 1u64 << (idx % 64);
    }

    fn clear_bit(&mut self, idx: usize) {
        self.bitmap[idx / 64] &= !(1u64 << (idx % 64));
    }

    fn is_set(&self, idx: usize) -> bool {
        (self.bitmap[idx / 64] >> (idx % 64)) & 1 == 1
    }
}

impl fmt::Debug for FrameAllocator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FrameAllocator")
            .field("total_frames", &self.total_frames)
            .field("free_frames", &self.free_frames)
            .field("initialized", &self.initialized)
            .finish()
    }
}

// ============================================================================
// Per-CPU frame cache — reduces global FRAME_ALLOCATOR lock contention
// ============================================================================

/// TUNING: per-CPU frame cache capacity (32 frames = 128 KiB). Trades global
/// allocator lock contention against per-CPU memory parked unused. Sized to
/// cover typical single-syscall allocations without touching the global lock.
/// Needs benchmarks, not opinion, to change.
const CACHE_CAPACITY: usize = 32;

/// TUNING: refill batch size — balances refill frequency vs. lock hold time.
const REFILL_COUNT: usize = 16;

/// TUNING: drain batch size — returns memory to the global pool for other CPUs
/// when the cache is full. Same trade-off as REFILL_COUNT.
const DRAIN_COUNT: usize = 16;

/// Per-CPU frame cache — LIFO stack of pre-allocated physical frames.
///
/// Reduces global `FRAME_ALLOCATOR` lock contention by serving most
/// allocations and frees from a CPU-local pool. The global allocator
/// is only touched on refill (cache empty) and drain (cache full).
///
/// Thread safety: wrapped in a per-CPU Spinlock in `lib.rs`. Only the
/// owning CPU accesses its cache, so contention is effectively zero.
pub struct FrameCache {
    /// Physical addresses of cached free frames (LIFO stack).
    stack: [u64; CACHE_CAPACITY],
    /// Number of valid frames in the cache (top-of-stack index).
    count: usize,
}

impl Default for FrameCache {
    fn default() -> Self { Self::new() }
}

impl FrameCache {
    /// Create an empty frame cache.
    pub const fn new() -> Self {
        FrameCache {
            stack: [0; CACHE_CAPACITY],
            count: 0,
        }
    }

    /// Pop a frame from the local cache. Returns `None` if empty.
    pub fn pop(&mut self) -> Option<PhysFrame> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(PhysFrame { addr: self.stack[self.count] })
    }

    /// Push a frame to the local cache.
    ///
    /// Returns `Some(frame)` if the cache is full (caller must return it
    /// to the global allocator). Returns `None` on success.
    pub fn push(&mut self, frame: PhysFrame) -> Option<PhysFrame> {
        if self.count >= CACHE_CAPACITY {
            return Some(frame);
        }
        self.stack[self.count] = frame.addr;
        self.count += 1;
        None
    }

    /// Refill the cache from the global allocator.
    ///
    /// Allocates up to `REFILL_COUNT` frames and pushes them onto the stack.
    /// Returns the number of frames obtained.
    pub fn refill(&mut self, global: &mut FrameAllocator) -> usize {
        let want = REFILL_COUNT.min(CACHE_CAPACITY - self.count);
        let mut got = 0;
        for _ in 0..want {
            match global.allocate() {
                Ok(frame) => {
                    self.stack[self.count] = frame.addr;
                    self.count += 1;
                    got += 1;
                }
                Err(_) => break,
            }
        }
        got
    }

    /// Drain frames from the cache back to the global allocator.
    ///
    /// Pops up to `DRAIN_COUNT` frames and frees them globally,
    /// making room for new local frees.
    pub fn drain(&mut self, global: &mut FrameAllocator) -> usize {
        let n = DRAIN_COUNT.min(self.count);
        for _ in 0..n {
            self.count -= 1;
            let _ = global.free(PhysFrame { addr: self.stack[self.count] });
        }
        n
    }

    /// Number of cached frames.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_allocator() {
        let alloc = FrameAllocator::new();
        assert!(!alloc.is_initialized());
        assert_eq!(alloc.free_count(), 0);
    }

    #[test]
    fn test_add_region_and_allocate() {
        let mut alloc = FrameAllocator::new();
        // Add 1 MB region starting at 1 MB
        alloc.add_region(0x100000, 0x100000);
        alloc.finalize();

        assert!(alloc.is_initialized());
        assert_eq!(alloc.free_count(), 256); // 1 MB / 4 KB = 256 frames

        let frame = alloc.allocate().unwrap();
        assert_eq!(frame.addr, 0x100000);
        assert_eq!(alloc.free_count(), 255);
    }

    #[test]
    fn test_free_frame() {
        let mut alloc = FrameAllocator::new();
        alloc.add_region(0x100000, 0x100000);
        alloc.finalize();

        let frame = alloc.allocate().unwrap();
        assert_eq!(alloc.free_count(), 255);

        alloc.free(frame).unwrap();
        assert_eq!(alloc.free_count(), 256);
    }

    #[test]
    fn test_double_free() {
        let mut alloc = FrameAllocator::new();
        alloc.add_region(0x100000, 0x100000);
        alloc.finalize();

        let frame = alloc.allocate().unwrap();
        alloc.free(frame).unwrap();
        assert_eq!(alloc.free(frame), Err(FrameAllocError::DoubleFree));
    }

    #[test]
    fn test_reserve_region() {
        let mut alloc = FrameAllocator::new();
        alloc.add_region(0x100000, 0x100000); // 256 frames
        alloc.reserve_region(0x100000, 0x10000); // Reserve first 64 KB = 16 frames
        alloc.finalize();

        assert_eq!(alloc.free_count(), 240);

        // First allocation should skip reserved frames
        let frame = alloc.allocate().unwrap();
        assert_eq!(frame.addr, 0x110000); // Starts after reserved region
    }

    #[test]
    fn test_exhaustion() {
        let mut alloc = FrameAllocator::new();
        alloc.add_region(0x100000, 0x4000); // 4 frames
        alloc.finalize();

        for _ in 0..4 {
            assert!(alloc.allocate().is_ok());
        }
        assert_eq!(alloc.allocate(), Err(FrameAllocError::OutOfMemory));
    }

    #[test]
    fn test_not_initialized() {
        let mut alloc = FrameAllocator::new();
        alloc.add_region(0x100000, 0x100000);
        // Forgot to call finalize()
        assert_eq!(alloc.allocate(), Err(FrameAllocError::NotInitialized));
    }

    #[test]
    fn test_unaligned_region() {
        let mut alloc = FrameAllocator::new();
        // Region that doesn't start on page boundary
        alloc.add_region(0x100100, 0x2000); // Starts 256 bytes into a page
        alloc.finalize();

        // Should round up start, round down end
        // Start: ceil(0x100100 / 4096) = frame 257 (addr 0x101000)
        // End: floor((0x100100 + 0x2000) / 4096) = frame 258 (addr 0x102000)
        // So only 1 frame available
        assert_eq!(alloc.free_count(), 1);
        let frame = alloc.allocate().unwrap();
        assert_eq!(frame.addr, 0x101000);
    }

    // ================================================================
    // FrameCache tests
    // ================================================================

    #[test]
    fn test_cache_push_pop() {
        let mut cache = FrameCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        // Push a frame
        let frame = PhysFrame { addr: 0x1000 };
        assert!(cache.push(frame).is_none());
        assert_eq!(cache.len(), 1);

        // Pop it back
        let popped = cache.pop().unwrap();
        assert_eq!(popped.addr, 0x1000);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_lifo_order() {
        let mut cache = FrameCache::new();
        cache.push(PhysFrame { addr: 0x1000 });
        cache.push(PhysFrame { addr: 0x2000 });
        cache.push(PhysFrame { addr: 0x3000 });

        assert_eq!(cache.pop().unwrap().addr, 0x3000); // LIFO
        assert_eq!(cache.pop().unwrap().addr, 0x2000);
        assert_eq!(cache.pop().unwrap().addr, 0x1000);
    }

    #[test]
    fn test_cache_full_returns_overflow() {
        let mut cache = FrameCache::new();
        for i in 0..CACHE_CAPACITY {
            assert!(cache.push(PhysFrame { addr: (i as u64) * 0x1000 }).is_none());
        }
        assert_eq!(cache.len(), CACHE_CAPACITY);

        // Next push should return the overflow frame
        let overflow = cache.push(PhysFrame { addr: 0xFF000 });
        assert!(overflow.is_some());
        assert_eq!(overflow.unwrap().addr, 0xFF000);
        assert_eq!(cache.len(), CACHE_CAPACITY); // Unchanged
    }

    #[test]
    fn test_cache_pop_empty() {
        let mut cache = FrameCache::new();
        assert!(cache.pop().is_none());
    }

    #[test]
    fn test_cache_refill() {
        let mut alloc = FrameAllocator::new();
        alloc.add_region(0x100000, 0x100000); // 256 frames
        alloc.finalize();

        let mut cache = FrameCache::new();
        let got = cache.refill(&mut alloc);
        assert_eq!(got, REFILL_COUNT);
        assert_eq!(cache.len(), REFILL_COUNT);
        assert_eq!(alloc.free_count(), 256 - REFILL_COUNT);
    }

    #[test]
    fn test_cache_drain() {
        let mut alloc = FrameAllocator::new();
        alloc.add_region(0x100000, 0x100000); // 256 frames
        alloc.finalize();

        let mut cache = FrameCache::new();
        cache.refill(&mut alloc);
        assert_eq!(cache.len(), REFILL_COUNT);

        let drained = cache.drain(&mut alloc);
        assert_eq!(drained, DRAIN_COUNT.min(REFILL_COUNT));
        assert_eq!(alloc.free_count(), 256); // All returned
    }

    #[test]
    fn test_cache_refill_exhaustion() {
        let mut alloc = FrameAllocator::new();
        alloc.add_region(0x100000, 0x4000); // Only 4 frames
        alloc.finalize();

        let mut cache = FrameCache::new();
        let got = cache.refill(&mut alloc);
        assert_eq!(got, 4); // Got all available, less than REFILL_COUNT
        assert_eq!(cache.len(), 4);
    }

    // ================================================================
    // Contiguous allocation tests
    // ================================================================

    #[test]
    fn test_allocate_contiguous_basic() {
        let mut fa = FrameAllocator::new();
        // Add a region of 100 frames starting at physical address 0x100000
        fa.add_region(0x100000, 100 * 4096);
        fa.finalize();

        // Allocate 4 contiguous frames
        let base = fa.allocate_contiguous(4).unwrap();
        assert_eq!(base.addr % 4096, 0); // Page-aligned

        // Allocate another contiguous run — should succeed and be different
        let base2 = fa.allocate_contiguous(4).unwrap();
        assert_ne!(base.addr, base2.addr);
    }

    #[test]
    fn test_allocate_contiguous_too_large() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 10 * 4096); // Only 10 frames
        fa.finalize();

        // Request 20 contiguous frames — should fail
        assert_eq!(fa.allocate_contiguous(20), Err(FrameAllocError::OutOfMemory));
    }

    #[test]
    fn test_allocate_contiguous_exact_fit() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 8 * 4096); // Exactly 8 frames
        fa.finalize();

        // Allocate all 8 as contiguous
        let base = fa.allocate_contiguous(8).unwrap();
        assert_eq!(base.addr, 0x100000);
        assert_eq!(fa.free_count(), 0);

        // No more room
        assert_eq!(fa.allocate_contiguous(1), Err(FrameAllocError::OutOfMemory));
    }

    #[test]
    fn test_allocate_contiguous_fragmented() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 10 * 4096); // 10 frames
        fa.finalize();

        // Allocate every other frame to fragment the bitmap
        // Frames at indices 256..266 (0x100000 = frame 256)
        let f0 = fa.allocate().unwrap(); // frame 256
        let _f1 = fa.allocate().unwrap(); // frame 257
        let f2 = fa.allocate().unwrap(); // frame 258
        let _f3 = fa.allocate().unwrap(); // frame 259
        let f4 = fa.allocate().unwrap(); // frame 260

        // Free alternating frames to create gaps
        fa.free(f0).unwrap(); // free 256
        fa.free(f2).unwrap(); // free 258
        fa.free(f4).unwrap(); // free 260

        // Now free: 256, 258, 260, 261, 262, 263, 264, 265 (8 free total)
        // But 256 and 258 are isolated (257, 259 are allocated)
        // Longest contiguous run: 261-265 = 5 frames

        // Request 4 contiguous — should succeed from the tail run
        let base = fa.allocate_contiguous(4).unwrap();
        assert!(base.addr >= 0x100000);

        // Request 5 contiguous — should fail now (only scattered frames left)
        assert_eq!(fa.allocate_contiguous(5), Err(FrameAllocError::OutOfMemory));
    }

    #[test]
    fn test_allocate_contiguous_zero_count() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 10 * 4096);
        fa.finalize();

        assert_eq!(fa.allocate_contiguous(0), Err(FrameAllocError::OutOfMemory));
    }

    #[test]
    fn test_allocate_contiguous_large_run() {
        // Phase 3.2a: the 64-frame cap on allocate_contiguous was lifted so
        // process heaps (now 1024 frames / 4 MiB by default) can be
        // allocated through this API. Verify that a 256-frame run works
        // end-to-end (a still-reasonable stand-in for heap allocation).
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 300 * 4096); // 300 frames
        fa.finalize();

        let base = fa.allocate_contiguous(256).unwrap();
        assert_eq!(base.addr, 0x100000);
        assert_eq!(fa.free_count(), 44);

        // Request a second 256-frame run — fails, only 44 frames left.
        assert_eq!(
            fa.allocate_contiguous(256),
            Err(FrameAllocError::OutOfMemory)
        );
    }

    /// Exercises allocate_contiguous at the new process-heap size
    /// (HEAP_PAGES = 1024, HEAP_SIZE = 4 MiB) after the v1-endgame bump
    /// (ADR-011). If this ever regresses, process spawn will fail with
    /// OOM even though there's enough total RAM — catch it here, not in
    /// QEMU boot logs.
    #[test]
    fn test_allocate_contiguous_heap_sized_run() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 1100 * 4096); // 1100 frames (> HEAP_PAGES=1024)
        fa.finalize();

        let base = fa.allocate_contiguous(1024).unwrap();
        assert_eq!(base.addr, 0x100000);
        assert_eq!(fa.free_count(), 76);
    }

    #[test]
    fn test_allocate_contiguous_larger_than_region() {
        // Requesting more frames than exist should fail with OutOfMemory,
        // not succeed by accident. (Replaces the old 64-frame cap test.)
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 100 * 4096); // 100 frames
        fa.finalize();

        assert_eq!(
            fa.allocate_contiguous(101),
            Err(FrameAllocError::OutOfMemory)
        );
    }

    #[test]
    fn test_allocate_contiguous_not_initialized() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 10 * 4096);
        // No finalize()
        assert_eq!(fa.allocate_contiguous(4), Err(FrameAllocError::NotInitialized));
    }

    #[test]
    fn test_allocate_contiguous_free_count_correct() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 50 * 4096); // 50 frames
        fa.finalize();
        assert_eq!(fa.free_count(), 50);

        fa.allocate_contiguous(16).unwrap();
        assert_eq!(fa.free_count(), 34);

        fa.allocate_contiguous(16).unwrap();
        assert_eq!(fa.free_count(), 18);
    }

    #[test]
    fn test_free_contiguous_round_trip() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 300 * 4096); // 300 frames
        fa.finalize();
        assert_eq!(fa.free_count(), 300);

        // Allocate a 256-frame heap-sized run and free it.
        let base = fa.allocate_contiguous(256).unwrap();
        assert_eq!(fa.free_count(), 44);

        fa.free_contiguous(base.addr, 256).unwrap();
        assert_eq!(fa.free_count(), 300);

        // The freed range should be allocatable again at the same base
        // (search hint was rolled back).
        let base2 = fa.allocate_contiguous(256).unwrap();
        assert_eq!(base2.addr, base.addr);
    }

    #[test]
    fn test_free_contiguous_double_free_atomic() {
        // Partially-overlapping free should fail without touching the bitmap.
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 20 * 4096);
        fa.finalize();

        let base = fa.allocate_contiguous(8).unwrap();
        fa.free_contiguous(base.addr, 4).unwrap(); // Free first 4
        assert_eq!(fa.free_count(), 16);

        // Try to free the whole 8-frame range — frames 4..8 are still
        // allocated, but frames 0..4 are already free. The pre-pass
        // detects this and returns DoubleFree before touching the bitmap.
        assert_eq!(
            fa.free_contiguous(base.addr, 8),
            Err(FrameAllocError::DoubleFree)
        );

        // Bitmap was not mutated — the remaining 4 allocated frames are
        // still accounted for.
        assert_eq!(fa.free_count(), 16);

        // We can still free the trailing 4 correctly.
        fa.free_contiguous(base.addr + 4 * PAGE_SIZE, 4).unwrap();
        assert_eq!(fa.free_count(), 20);
    }

    #[test]
    fn test_free_contiguous_unaligned_base() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 10 * 4096);
        fa.finalize();

        let base = fa.allocate_contiguous(4).unwrap();

        // Unaligned base rejected.
        assert_eq!(
            fa.free_contiguous(base.addr + 1, 4),
            Err(FrameAllocError::InvalidFrame)
        );
    }

    #[test]
    fn test_free_contiguous_out_of_range() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 10 * 4096);
        fa.finalize();

        // start_idx + count > total_frames -> InvalidFrame.
        // 0x100000 = frame 256, + 8 = frame 264, but we only have frames
        // 256..266 (10 frames). Requesting 20 from 256 -> frame 276 > 266.
        assert_eq!(
            fa.free_contiguous(0x100000, 20),
            Err(FrameAllocError::InvalidFrame)
        );
    }

    #[test]
    fn test_free_contiguous_zero_count_is_noop() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 10 * 4096);
        fa.finalize();

        let free_before = fa.free_count();
        assert!(fa.free_contiguous(0x100000, 0).is_ok());
        assert_eq!(fa.free_count(), free_before);
    }
}
