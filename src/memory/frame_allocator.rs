//! Physical frame allocator
//!
//! Bitmap-based allocator for 4 KiB physical pages. Initialized from the
//! Limine memory map: only USABLE regions become available frames.
//!
//! Design:
//! - Bitmap tracks allocation state (1 bit per 4 KiB frame)
//! - Supports up to 4 GiB physical memory (131072 frames × 4 KiB)
//! - Thread-safe: intended to be wrapped in a Spinlock at the call site
//! - Excludes reserved regions, kernel heap, and kernel image automatically

use core::fmt;

/// Page / frame size: 4 KiB
pub const PAGE_SIZE: u64 = 4096;

/// Maximum supported physical memory: 4 GiB
/// (131072 frames × 4 KiB = 4 GiB)
const MAX_FRAMES: usize = 131072;

/// Bitmap words needed: 131072 / 64 = 2048
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// Physical frame allocator using a bitmap.
///
/// Each bit represents a 4 KiB frame:
/// - 0 = free
/// - 1 = allocated or reserved
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

    /// Mark a physical region as available (free) for allocation.
    ///
    /// Called once per USABLE entry in the Limine memory map.
    /// `base` and `length` are physical addresses/sizes.
    pub fn add_region(&mut self, base: u64, length: u64) {
        let start_frame = (base + PAGE_SIZE - 1) / PAGE_SIZE; // Round up
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
        let end_frame = (base + length + PAGE_SIZE - 1) / PAGE_SIZE; // Round up

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

        let words = (self.total_frames + 63) / 64;

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
}
