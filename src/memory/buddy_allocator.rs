// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Buddy Allocator for Process Heaps
//!
//! Pure bookkeeping allocator: tracks slot allocation via bitmaps without
//! touching the managed memory. Returns offsets from base, not addresses.
//! The caller (ProcessDescriptor) is responsible for translating offsets
//! to the correct address space (physical for page tables, HHDM-virtual
//! for kernel access).
//!
//! This design:
//! - Eliminates BlockHeader overhead (no 8-byte header per allocation)
//! - Never performs unsafe memory I/O — fully testable without real memory
//! - Is address-space agnostic — works with physical, virtual, or test addresses

use core::fmt;

/// Minimum block size: 16 bytes
pub const MIN_ORDER: usize = 4; // 2^4 = 16 bytes
pub const MIN_SIZE: usize = 1 << MIN_ORDER;

/// Maximum order: 2^19 = 512KB per process heap
pub const MAX_ORDER: usize = 19;
pub const MAX_SIZE: usize = 1 << MAX_ORDER;

/// Number of free lists (one per order)
pub const NUM_ORDERS: usize = MAX_ORDER - MIN_ORDER + 1;

/// Result of a successful allocation: offset from heap base and the order used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    /// Byte offset from heap base where the usable block starts
    pub offset: usize,
    /// Order (log2 of block size) — needed for free
    pub order: usize,
}

/// Buddy allocator state for a single process heap
///
/// Tracks allocation state purely via bitmaps. Each bit represents a
/// minimum-sized (16-byte) slot. For larger orders, multiple consecutive
/// bits are set. The allocator stores the order for each allocation in a
/// separate parallel bitmap so that `free()` only needs the offset.
///
/// ## In-place construction (Phase 3.2a follow-up)
///
/// As of the Phase 3.2a follow-up, the allocator is constructed in place at
/// the start of each process heap (not as a field of `ProcessDescriptor`
/// anymore). The first `reserved_slots * MIN_SIZE` bytes of the heap hold
/// the allocator's own state and are reserved so user allocations never
/// overlap. Use [`BuddyAllocator::new_with_reserved_prefix`] to construct
/// an allocator with a pre-reserved prefix; [`BuddyAllocator::new`] is
/// still valid for standalone use (unit tests, future allocator contexts).
///
/// `#[repr(C)]` fixes the field layout so placement-new via raw pointer
/// is layout-stable across compiler versions. The struct has no lifetimes,
/// no references, and no interior unsafety — just plain array storage.
#[repr(C)]
pub struct BuddyAllocator {
    /// Allocation status: bit set = slot occupied
    /// 512 × 64 = 32768 slots × 16 bytes = 512KB addressable (= MAX_SIZE)
    allocations: [u64; 512],

    /// Order stored per allocation start slot (4 bits per slot, packed)
    /// 32768 slots / 2 per byte = 16384 bytes = 16KB
    /// Only the first slot of each allocation has a meaningful order value.
    orders: [u8; 16384],

    /// Number of slots reserved at offset 0 (for in-place construction).
    /// When non-zero, `find_free_slots` starts its search at `reserved_slots`
    /// and `free` rejects offsets below `reserved_slots * MIN_SIZE`. Always
    /// zero for `new()`; set by `new_with_reserved_prefix`.
    reserved_slots: u32,
}

impl BuddyAllocator {
    /// Create a new buddy allocator for a process heap with no reserved prefix.
    ///
    /// Suitable for unit tests and standalone contexts where the allocator
    /// does not share memory with the heap it manages. For the in-place
    /// case (where the allocator lives at the start of the heap), use
    /// [`BuddyAllocator::new_with_reserved_prefix`] instead.
    pub fn new() -> Self {
        BuddyAllocator {
            allocations: [0; 512],
            orders: [0; 16384],
            reserved_slots: 0,
        }
    }
}

impl Default for BuddyAllocator {
    fn default() -> Self { Self::new() }
}

impl BuddyAllocator {
    /// Create a new buddy allocator with the first `reserved_bytes` of the
    /// managed heap marked as allocated and protected from `free()`.
    ///
    /// Used for in-place construction at the start of a process heap: the
    /// allocator's own state (this struct) lives at offset 0..`reserved_bytes`,
    /// and user allocations must never overlap that region. This constructor:
    ///
    /// 1. Initializes a fresh allocator with all slots free and `reserved_slots == 0`.
    /// 2. Computes `slots = ceil(reserved_bytes / MIN_SIZE)` — the number of
    ///    `MIN_SIZE`-aligned slots that cover the reserved prefix.
    /// 3. Marks those slots as allocated in the `allocations` bitmap so
    ///    `find_free_slots` skips them.
    /// 4. Records `reserved_slots = slots` so `free()` rejects any offset
    ///    below the prefix — without this field, a stray `free(0)` call
    ///    would read the (zero-initialized) orders bitmap, decode
    ///    `MIN_ORDER = 4`, mark the first 16 bytes as free, and leave the
    ///    rest of the reserved prefix in an inconsistent "used but
    ///    unreachable from the free list" state. The explicit field
    ///    closes that footgun.
    ///
    /// The order bitmap is left untouched for reserved slots — nothing
    /// reads it, because the `reserved_slots` check in `free` bails out
    /// before the order lookup.
    pub fn new_with_reserved_prefix(reserved_bytes: usize) -> Self {
        let mut allocator = Self::new();
        if reserved_bytes == 0 {
            return allocator;
        }
        let slots = reserved_bytes.div_ceil(MIN_SIZE);
        let total_slots = MAX_SIZE / MIN_SIZE;
        // Cap at total_slots so we never mark bits outside the bitmap.
        // Caller-side invariant: reserved_bytes should be << MAX_SIZE, but
        // defensive clamp costs nothing and prevents a silent wrap.
        let slots = slots.min(total_slots);
        allocator.mark_range(0, slots, true);
        allocator.reserved_slots = slots as u32;
        allocator
    }

    /// Allocate a block of the requested size
    ///
    /// Returns `Some(Allocation)` with the byte offset and order, or `None`
    /// if the heap is exhausted. The caller translates the offset to the
    /// appropriate address space.
    pub fn allocate(&mut self, size: usize) -> Option<Allocation> {
        if size == 0 || size > MAX_SIZE {
            return None;
        }

        let order = self.order_for_size(size);
        let block_size = 1usize << order;
        let slots_needed = block_size / MIN_SIZE;

        if let Some(start_slot) = self.find_free_slots(slots_needed) {
            self.mark_range(start_slot, slots_needed, true);
            self.set_order(start_slot, order);

            Some(Allocation {
                offset: start_slot * MIN_SIZE,
                order,
            })
        } else {
            None
        }
    }

    /// Free a previously allocated block by its byte offset from heap base.
    ///
    /// The order is recovered from the internal order map — callers don't
    /// need to remember it.
    ///
    /// Returns `false` (without mutating state) if:
    /// - the offset is not `MIN_SIZE`-aligned,
    /// - the offset is beyond the managed region,
    /// - the offset falls inside the reserved prefix (if any),
    /// - the slot is not currently allocated (double-free),
    /// - the decoded order is out of range.
    pub fn free(&mut self, offset: usize) -> bool {
        if !offset.is_multiple_of(MIN_SIZE) {
            return false;
        }

        let start_slot = offset / MIN_SIZE;
        let total_slots = MAX_SIZE / MIN_SIZE;
        if start_slot >= total_slots {
            return false;
        }

        // Reject any free that targets the reserved prefix (in-place
        // allocator state). Without this check, a stray `free(0)` would
        // read the zero-initialized orders bitmap, decode `MIN_ORDER`,
        // and partially unmark the reserved range — leaving the
        // allocator in an inconsistent state.
        if start_slot < self.reserved_slots as usize {
            return false;
        }

        // Verify slot is actually allocated
        if !self.is_allocated(start_slot) {
            return false;
        }

        let order = self.get_order(start_slot);
        if !(MIN_ORDER..=MAX_ORDER).contains(&order) {
            return false;
        }

        let block_size = 1usize << order;
        let slots_needed = block_size / MIN_SIZE;

        self.mark_range(start_slot, slots_needed, false);
        true
    }

    /// Calculate the smallest order that fits the size
    fn order_for_size(&self, size: usize) -> usize {
        let mut order = MIN_ORDER;
        while order < MAX_ORDER && (1 << order) < size {
            order += 1;
        }
        order
    }

    /// Find a contiguous run of `count` free slots, skipping the
    /// reserved prefix (if any).
    ///
    /// Starting the scan at `reserved_slots` instead of 0 skips the
    /// in-place-allocator-state bits that are already marked
    /// allocated. Without this, every `allocate` call would waste
    /// `reserved_slots` iterations resetting the run on every marked
    /// bit before reaching free territory — with a 20 KB allocator
    /// prefix that's 1280 wasted iterations per allocate.
    fn find_free_slots(&self, count: usize) -> Option<usize> {
        let total_slots = MAX_SIZE / MIN_SIZE;
        let start = self.reserved_slots as usize;
        let mut run_start = start;
        let mut run_len = 0;

        for slot in start..total_slots {
            if self.is_allocated(slot) {
                run_start = slot + 1;
                run_len = 0;
            } else {
                run_len += 1;
                if run_len >= count {
                    return Some(run_start);
                }
            }
        }
        None
    }

    /// Check if a single slot is allocated
    fn is_allocated(&self, slot: usize) -> bool {
        let word = slot / 64;
        let bit = slot % 64;
        word < self.allocations.len() && (self.allocations[word] & (1 << bit)) != 0
    }

    /// Mark a range of slots as allocated or free
    fn mark_range(&mut self, start: usize, count: usize, allocated: bool) {
        for slot in start..start + count {
            let word = slot / 64;
            let bit = slot % 64;
            if word < self.allocations.len() {
                if allocated {
                    self.allocations[word] |= 1 << bit;
                } else {
                    self.allocations[word] &= !(1 << bit);
                }
            }
        }
    }

    /// Store the order for an allocation's start slot.
    /// Stored as (order - MIN_ORDER) in 4 bits, so orders 4-19 map to nibbles 0-15.
    fn set_order(&mut self, slot: usize, order: usize) {
        let byte_idx = slot / 2;
        if byte_idx < self.orders.len() {
            let shift = (slot % 2) * 4;
            let encoded = ((order - MIN_ORDER) as u8) & 0xF;
            self.orders[byte_idx] &= !(0xF << shift);
            self.orders[byte_idx] |= encoded << shift;
        }
    }

    /// Retrieve the stored order for a slot
    fn get_order(&self, slot: usize) -> usize {
        let byte_idx = slot / 2;
        if byte_idx < self.orders.len() {
            let shift = (slot % 2) * 4;
            let encoded = ((self.orders[byte_idx] >> shift) & 0xF) as usize;
            encoded + MIN_ORDER
        } else {
            0
        }
    }
}

impl fmt::Debug for BuddyAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuddyAllocator")
            .field("max_size", &MAX_SIZE)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocator_creation() {
        let allocator = BuddyAllocator::new();
        // Should start with all slots free
        assert!(allocator.allocations.iter().all(|&w| w == 0));
    }

    #[test]
    fn test_order_calculation() {
        let allocator = BuddyAllocator::new();

        // 16 bytes should fit in order 4 (MIN_ORDER)
        let order_16 = allocator.order_for_size(16);
        assert!(order_16 >= MIN_ORDER);

        // Larger sizes should need higher orders
        let order_256 = allocator.order_for_size(256);
        assert!(order_256 > order_16);
    }

    #[test]
    fn test_allocate_deallocate() {
        let mut allocator = BuddyAllocator::new();

        // Allocate 64 bytes
        let alloc = allocator.allocate(64).expect("allocation should succeed");
        assert_eq!(alloc.offset, 0); // First allocation starts at offset 0

        // Free should succeed
        assert!(allocator.free(alloc.offset));

        // Double-free should fail
        assert!(!allocator.free(alloc.offset));
    }

    #[test]
    fn test_multiple_allocations() {
        let mut allocator = BuddyAllocator::new();

        let a1 = allocator.allocate(16).unwrap();
        let a2 = allocator.allocate(16).unwrap();

        // Second allocation should be at a different offset
        assert_ne!(a1.offset, a2.offset);

        // Free both
        assert!(allocator.free(a1.offset));
        assert!(allocator.free(a2.offset));
    }

    #[test]
    fn test_order_recovery() {
        let mut allocator = BuddyAllocator::new();

        // Allocate various sizes and verify order is tracked
        let small = allocator.allocate(16).unwrap();
        assert_eq!(small.order, MIN_ORDER);

        let medium = allocator.allocate(1024).unwrap();
        assert!(medium.order >= 10); // 2^10 = 1024

        // Free both using only the offset (order recovered internally)
        assert!(allocator.free(small.offset));
        assert!(allocator.free(medium.offset));
    }

    #[test]
    fn test_exhaustion() {
        let mut allocator = BuddyAllocator::new();

        // Allocate the entire heap
        let big = allocator.allocate(MAX_SIZE);
        assert!(big.is_some());

        // Next allocation should fail
        assert!(allocator.allocate(16).is_none());

        // Free and reallocate
        assert!(allocator.free(big.unwrap().offset));
        assert!(allocator.allocate(16).is_some());
    }

    // ========================================================================
    // Reserved-prefix construction (Phase 3.2a Item 1: in-place allocator state)
    // ========================================================================

    #[test]
    fn test_new_with_reserved_prefix_zero_is_same_as_new() {
        let mut a = BuddyAllocator::new_with_reserved_prefix(0);
        let b = a.allocate(16).unwrap();
        assert_eq!(b.offset, 0, "zero reservation should behave like new()");
    }

    #[test]
    fn test_new_with_reserved_prefix_first_alloc_skips_prefix() {
        // Reserve 1024 bytes (64 slots).
        let mut allocator = BuddyAllocator::new_with_reserved_prefix(1024);

        // First allocation must land past the reserved prefix.
        let alloc = allocator.allocate(16).unwrap();
        assert!(
            alloc.offset >= 1024,
            "first allocation at offset {} overlaps the 1024-byte reserved prefix",
            alloc.offset
        );
    }

    #[test]
    fn test_new_with_reserved_prefix_rounds_up_to_min_size() {
        // 17 bytes rounds up to 32 bytes (2 slots × 16).
        let mut allocator = BuddyAllocator::new_with_reserved_prefix(17);

        let alloc = allocator.allocate(16).unwrap();
        // The reserved prefix is 2 slots (32 bytes), so the first
        // free alloc lands at offset 32.
        assert_eq!(alloc.offset, 32);
    }

    #[test]
    fn test_free_rejects_offset_in_reserved_prefix() {
        let mut allocator = BuddyAllocator::new_with_reserved_prefix(1024);

        // Attempting to free any offset inside the reserved prefix
        // must return false without mutating state.
        assert!(!allocator.free(0));
        assert!(!allocator.free(16));
        assert!(!allocator.free(1008)); // last slot in the prefix

        // The prefix is still "allocated" and the next allocate still
        // lands past it, confirming no partial-unmark happened.
        let alloc = allocator.allocate(16).unwrap();
        assert!(alloc.offset >= 1024);
    }

    #[test]
    fn test_new_with_reserved_prefix_allocator_state_size() {
        // The practical Phase 3.2a use case: reserve enough space for the
        // allocator's own state. size_of::<BuddyAllocator>() is the
        // actual reservation size in ProcessDescriptor::new.
        let state_size = core::mem::size_of::<BuddyAllocator>();
        let mut allocator = BuddyAllocator::new_with_reserved_prefix(state_size);

        let alloc = allocator.allocate(16).unwrap();
        assert!(
            alloc.offset >= state_size,
            "allocation at offset {} overlaps allocator state of size {}",
            alloc.offset,
            state_size
        );
    }

    #[test]
    fn test_new_with_reserved_prefix_allocate_free_cycle_works() {
        // User allocations past the reserved prefix must still round-trip
        // through allocate/free correctly.
        let mut allocator =
            BuddyAllocator::new_with_reserved_prefix(core::mem::size_of::<BuddyAllocator>());

        let a1 = allocator.allocate(64).unwrap();
        let a2 = allocator.allocate(128).unwrap();
        assert_ne!(a1.offset, a2.offset);

        assert!(allocator.free(a1.offset));
        assert!(allocator.free(a2.offset));

        // After freeing, we can re-allocate and get valid offsets.
        let a3 = allocator.allocate(64).unwrap();
        assert!(a3.offset >= core::mem::size_of::<BuddyAllocator>());
    }

    #[test]
    fn test_new_with_reserved_prefix_oversized_clamps() {
        // Pathological: reserve more than the entire managed region.
        // Should not panic or wrap; the allocator ends up with every
        // slot marked allocated, and allocate() returns None.
        let mut allocator = BuddyAllocator::new_with_reserved_prefix(MAX_SIZE * 2);
        assert!(allocator.allocate(16).is_none());
    }
}
