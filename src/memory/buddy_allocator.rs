/// Buddy Allocator for Process Heaps
///
/// Pure bookkeeping allocator: tracks slot allocation via bitmaps without
/// touching the managed memory. Returns offsets from base, not addresses.
/// The caller (ProcessDescriptor) is responsible for translating offsets
/// to the correct address space (physical for page tables, HHDM-virtual
/// for kernel access).
///
/// This design:
/// - Eliminates BlockHeader overhead (no 8-byte header per allocation)
/// - Never performs unsafe memory I/O — fully testable without real memory
/// - Is address-space agnostic — works with physical, virtual, or test addresses

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
pub struct BuddyAllocator {
    /// Allocation status: bit set = slot occupied
    /// 512 × 64 = 32768 slots × 16 bytes = 512KB addressable (= MAX_SIZE)
    allocations: [u64; 512],

    /// Order stored per allocation start slot (4 bits per slot, packed)
    /// 32768 slots / 2 per byte = 16384 bytes = 16KB
    /// Only the first slot of each allocation has a meaningful order value.
    orders: [u8; 16384],
}

impl BuddyAllocator {
    /// Create a new buddy allocator for a process heap
    pub fn new() -> Self {
        BuddyAllocator {
            allocations: [0; 512],
            orders: [0; 16384],
        }
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
    pub fn free(&mut self, offset: usize) -> bool {
        if offset % MIN_SIZE != 0 {
            return false;
        }

        let start_slot = offset / MIN_SIZE;
        let total_slots = MAX_SIZE / MIN_SIZE;
        if start_slot >= total_slots {
            return false;
        }

        // Verify slot is actually allocated
        if !self.is_allocated(start_slot) {
            return false;
        }

        let order = self.get_order(start_slot);
        if order < MIN_ORDER || order > MAX_ORDER {
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

    /// Find a contiguous run of `count` free slots
    fn find_free_slots(&self, count: usize) -> Option<usize> {
        let total_slots = MAX_SIZE / MIN_SIZE;
        let mut run_start = 0;
        let mut run_len = 0;

        for slot in 0..total_slots {
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

    /// Store the order for an allocation's start slot (4 bits, packed 2 per byte)
    fn set_order(&mut self, slot: usize, order: usize) {
        let byte_idx = slot / 2;
        if byte_idx < self.orders.len() {
            let shift = (slot % 2) * 4;
            // Clear the nibble, then set it
            self.orders[byte_idx] &= !(0xF << shift);
            self.orders[byte_idx] |= ((order as u8) & 0xF) << shift;
        }
    }

    /// Retrieve the stored order for a slot
    fn get_order(&self, slot: usize) -> usize {
        let byte_idx = slot / 2;
        if byte_idx < self.orders.len() {
            let shift = (slot % 2) * 4;
            ((self.orders[byte_idx] >> shift) & 0xF) as usize
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
}
