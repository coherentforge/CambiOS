// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Fuzz target: BuddyAllocator
//!
//! Replays random sequences of allocate/free operations against the buddy
//! allocator. Catches panics, internal inconsistencies, double-free acceptance,
//! and state corruption from adversarial operation sequences.
//!
//! Properties that must hold:
//! - No panic on any operation sequence
//! - allocate never returns overlapping regions
//! - free of an unallocated offset returns false (no silent corruption)
//! - free of offset 0..reserved_slots returns false (reserved prefix)

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use arcos_core::memory::buddy_allocator::{BuddyAllocator, MIN_SIZE};

/// Operations the fuzzer can invoke.
#[derive(Arbitrary, Debug)]
enum Op {
    /// Allocate a block of the given size.
    Alloc { size: u16 },
    /// Free the Nth outstanding allocation (index into our tracking vec).
    Free { index: u8 },
    /// Free a raw offset (adversarial — may not be a valid allocation).
    FreeRaw { offset: u32 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Whether to use a reserved prefix (in-place construction mode).
    use_reserved: bool,
    /// Reserved bytes when use_reserved is true.
    reserved_bytes: u16,
    /// Sequence of operations to replay.
    ops: Vec<Op>,
}

fuzz_target!(|input: FuzzInput| {
    let mut allocator = if input.use_reserved {
        BuddyAllocator::new_with_reserved_prefix(input.reserved_bytes as usize)
    } else {
        BuddyAllocator::new()
    };

    // Track outstanding allocations: (offset, order)
    let mut live: Vec<(usize, usize)> = Vec::new();

    for op in &input.ops {
        match op {
            Op::Alloc { size } => {
                let size = *size as usize;
                if let Some(alloc) = allocator.allocate(size) {
                    // Verify no overlap with existing live allocations
                    let new_start = alloc.offset;
                    let new_end = new_start + (1usize << alloc.order);
                    for &(existing_offset, existing_order) in &live {
                        let ex_start = existing_offset;
                        let ex_end = ex_start + (1usize << existing_order);
                        assert!(
                            new_end <= ex_start || new_start >= ex_end,
                            "Overlapping allocations: [{:#x}..{:#x}) and [{:#x}..{:#x})",
                            new_start, new_end, ex_start, ex_end
                        );
                    }
                    // Verify the allocation respects the reserved prefix
                    if input.use_reserved {
                        let reserved_slots = (input.reserved_bytes as usize + MIN_SIZE - 1) / MIN_SIZE;
                        let reserved_end = reserved_slots * MIN_SIZE;
                        assert!(
                            alloc.offset >= reserved_end,
                            "Allocation at {:#x} overlaps reserved prefix ending at {:#x}",
                            alloc.offset, reserved_end
                        );
                    }
                    live.push((alloc.offset, alloc.order));
                }
            }
            Op::Free { index } => {
                let idx = *index as usize;
                if idx < live.len() {
                    let (offset, _order) = live.remove(idx);
                    let freed = allocator.free(offset);
                    assert!(freed, "Free of valid allocation at {:#x} returned false", offset);
                }
            }
            Op::FreeRaw { offset } => {
                let offset = *offset as usize;
                // Raw free — may or may not be valid. Must not panic.
                // If offset is in our live set, remove it.
                if let Some(pos) = live.iter().position(|&(o, _)| o == offset) {
                    let freed = allocator.free(offset);
                    if freed {
                        live.remove(pos);
                    }
                } else {
                    // Not a live allocation — free should return false
                    let freed = allocator.free(offset);
                    assert!(
                        !freed,
                        "Free of non-live offset {:#x} returned true (double-free or phantom)",
                        offset
                    );
                }
            }
        }
    }
});
