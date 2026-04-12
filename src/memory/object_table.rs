// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Kernel object table region — Phase 3.2a of [ADR-008].
//!
//! The "kernel object table region" is a single contiguous physical
//! allocation that backs two disjoint, page-aligned slices:
//!
//! - **Process slots:** `[Option<ProcessDescriptor>; num_slots]`
//! - **Capability slots:** `[Option<ProcessCapabilities>; num_slots]`
//!
//! Both are sized at boot from `config::num_slots()`, which is itself
//! derived from the active [`TableSizingPolicy`] and the bootloader's
//! memory map. The region is allocated directly from the
//! [`FrameAllocator`] at init time, HHDM-mapped (using Limine's linear
//! `phys + hhdm_offset` map), and held for the lifetime of the kernel —
//! there is no "free the object table" path.
//!
//! ## Why a dedicated region, not the kernel heap?
//!
//! Per ADR-008 § Decision, kernel object storage and kernel working
//! memory are architecturally distinct. The object table holds state
//! whose lifetime equals the kernel's; the kernel heap serves `Box`
//! and `Vec` allocations with much shorter lifetimes. Conflating them
//! means a kernel heap OOM can consume slots, and a slot leak can
//! consume kernel heap. Splitting them gives each its own budget and
//! each its own verification-friendly invariants.
//!
//! ## Safety model
//!
//! `init()` produces two `&'static mut` slices from raw pointers. The
//! safety of this rests on three invariants:
//!
//! 1. `init()` is called **exactly once** per kernel lifetime.
//! 2. The underlying physical region is allocated exclusively by the
//!    frame allocator, is never returned, and does not overlap with
//!    any other kernel data structure.
//! 3. The region is fully initialized (every slot explicitly written
//!    to `None`) before the slices are handed out.
//!
//! All three are enforced in `init()`: the frame allocator gives back
//! a disjoint region, every slot is explicitly written via
//! `core::ptr::write(None)` (we cannot rely on zeroed memory being
//! `None` for `Option<T>` with niche-optimized contents — see
//! `ProcessTable::new_boxed` for the same gotcha), and the caller
//! (kernel boot path) is responsible for the "exactly once" part.
//!
//! [ADR-008]: ../../../docs/adr/008-boot-time-sized-object-tables.md

extern crate alloc;

use crate::config::BindingConstraint;
use crate::ipc::capability::ProcessCapabilities;
use crate::memory::frame_allocator::{FrameAllocError, FrameAllocator, PAGE_SIZE};
use crate::process::ProcessDescriptor;

/// Errors returned by `init()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectTableError {
    /// The frame allocator failed to produce a contiguous region of
    /// the requested size. Wraps the underlying frame allocator error.
    FrameAllocFailure(FrameAllocError),
    /// `num_slots` was zero. Precondition violation — the caller must
    /// call `config::init_num_slots()` before this function.
    NoSlots,
}

/// The initialized kernel object table region.
///
/// Holds the two page-aligned slices backed by a single contiguous
/// physical allocation, plus diagnostic fields for boot logging and
/// for handing off to `ProcessTable` / `CapabilityManager`.
///
/// The slice references have `'static` lifetime. Once this struct has
/// been constructed, the slices must be moved into their consumers
/// (`ProcessTable::from_object_table`, `CapabilityManager::from_object_table`)
/// rather than borrowed — there can only be one live `&'static mut`
/// per slice.
pub struct ObjectTable {
    /// Slice of process slots, length == `num_slots`. Every element
    /// starts as `None`.
    pub process_slots: &'static mut [Option<ProcessDescriptor>],

    /// Slice of capability slots, length == `num_slots`. Every element
    /// starts as `None`.
    pub capability_slots: &'static mut [Option<ProcessCapabilities>],

    /// Number of slots in each table (both slices have this length).
    pub num_slots: usize,

    /// Physical base address of the contiguous region.
    pub region_base_phys: u64,

    /// Total size of the region in bytes (page-aligned).
    pub region_bytes: u64,

    /// Which constraint bound the slot count computation. Reported
    /// verbatim in the boot log.
    pub binding: BindingConstraint,
}

/// Compute the total number of bytes the object table region needs
/// for `num_slots` process slots and `num_slots` capability slots,
/// with the inter-subregion boundary aligned to a page.
///
/// Exposed for tests and for the boot log to print the region size
/// without calling `init()`.
pub const fn region_bytes_for(num_slots: usize) -> u64 {
    let process_bytes = num_slots * core::mem::size_of::<Option<ProcessDescriptor>>();
    let capability_bytes = num_slots * core::mem::size_of::<Option<ProcessCapabilities>>();

    let process_aligned = align_up_const(process_bytes, PAGE_SIZE as usize);
    let capability_aligned = align_up_const(capability_bytes, PAGE_SIZE as usize);

    (process_aligned + capability_aligned) as u64
}

/// `const fn` page-up alignment. `align` must be a power of two.
#[inline]
const fn align_up_const(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Initialize the kernel object table region.
///
/// Allocates a contiguous physical region from `frame_alloc`, carves
/// it into two page-aligned subregions, initializes every slot in
/// both subregions to `None`, and returns the populated `ObjectTable`.
///
/// Must be called exactly once per kernel lifetime.
///
/// # Arguments
///
/// - `frame_alloc` — mutable reference to the global frame allocator
///   (caller must hold the `FRAME_ALLOCATOR` lock).
/// - `num_slots` — number of slots to allocate in each subregion.
///   Usually `config::num_slots()` after `config::init_num_slots()`
///   has run.
/// - `hhdm_offset` — the Limine HHDM offset, used to translate the
///   allocated physical base into a kernel-accessible virtual address.
/// - `binding` — the `BindingConstraint` that drove `num_slots`,
///   stored verbatim for diagnostics.
pub fn init(
    frame_alloc: &mut FrameAllocator,
    num_slots: usize,
    hhdm_offset: u64,
    binding: BindingConstraint,
) -> Result<ObjectTable, ObjectTableError> {
    if num_slots == 0 {
        return Err(ObjectTableError::NoSlots);
    }

    // Compute the two page-aligned subregion sizes and the total
    // allocation size (in pages, for the frame allocator).
    let process_bytes = num_slots * core::mem::size_of::<Option<ProcessDescriptor>>();
    let capability_bytes = num_slots * core::mem::size_of::<Option<ProcessCapabilities>>();

    let process_bytes_aligned = align_up_const(process_bytes, PAGE_SIZE as usize);
    let capability_bytes_aligned = align_up_const(capability_bytes, PAGE_SIZE as usize);

    let total_bytes = process_bytes_aligned + capability_bytes_aligned;
    let total_pages = total_bytes / PAGE_SIZE as usize;

    // Allocate the contiguous physical region.
    let frame = frame_alloc
        .allocate_contiguous(total_pages)
        .map_err(ObjectTableError::FrameAllocFailure)?;

    let region_base_phys = frame.addr;
    let region_base_virt = region_base_phys + hhdm_offset;

    // The two subregion pointers. Process subregion starts at the
    // region base (page-aligned by frame allocation); capability
    // subregion starts after the page-aligned process subregion.
    let process_ptr = region_base_virt as *mut Option<ProcessDescriptor>;
    let capability_ptr =
        (region_base_virt + process_bytes_aligned as u64) as *mut Option<ProcessCapabilities>;

    // Initialize every slot to `None` via explicit writes. We cannot
    // rely on zeroed memory being `None` because niche optimization
    // may place the discriminant in a way that makes all-zeros a
    // `Some(...)` variant — see `ProcessTable::new_boxed` for the
    // same gotcha audited earlier.
    //
    // SAFETY: process_ptr and capability_ptr are page-aligned (frame
    // allocator returned a page-aligned base, subregion boundary is
    // page-aligned), the region has `num_slots` slots of each type of
    // storage (we allocated enough bytes, rounded up), we own the
    // region exclusively (just allocated from the frame allocator,
    // no aliases exist), and boot is single-threaded at this point.
    unsafe {
        for i in 0..num_slots {
            process_ptr.add(i).write(None);
        }
        for i in 0..num_slots {
            capability_ptr.add(i).write(None);
        }
    }

    // SAFETY: All slots initialized above; pointers are valid and
    // SAFETY: process_ptr is non-null, page-aligned, initialized to None via
    // write_bytes(0) + ptr::write(None), and owned exclusively by this call.
    // Lifetime is 'static because the region is never freed.
    let process_slots: &'static mut [Option<ProcessDescriptor>] =
        unsafe { core::slice::from_raw_parts_mut(process_ptr, num_slots) };
    // SAFETY: Same as above — capability_ptr is the next page-aligned sub-region,
    // properly initialized and exclusively owned.
    let capability_slots: &'static mut [Option<ProcessCapabilities>] =
        unsafe { core::slice::from_raw_parts_mut(capability_ptr, num_slots) };

    Ok(ObjectTable {
        process_slots,
        capability_slots,
        num_slots,
        region_base_phys,
        region_bytes: total_bytes as u64,
        binding,
    })
}

// ============================================================================
// Tests (host)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `region_bytes_for` must produce a page-aligned total.
    #[test]
    fn region_bytes_are_page_aligned() {
        for &n in &[1usize, 32, 256, 1024, 4096, 65536] {
            let bytes = region_bytes_for(n);
            assert_eq!(
                bytes % PAGE_SIZE,
                0,
                "region_bytes_for({}) = {} is not page-aligned",
                n,
                bytes
            );
        }
    }

    /// `region_bytes_for` must be monotonic in `num_slots` and must
    /// accommodate at least the required storage for both subregions.
    #[test]
    fn region_bytes_monotonic_and_sufficient() {
        let prev = region_bytes_for(1);
        let next = region_bytes_for(2);
        assert!(next >= prev);

        // For large num_slots, the total must be at least the sum of
        // the unpadded subregion sizes.
        let n = 1024usize;
        let min_required = n * core::mem::size_of::<Option<ProcessDescriptor>>()
            + n * core::mem::size_of::<Option<ProcessCapabilities>>();
        assert!(region_bytes_for(n) >= min_required as u64);
    }

    /// `init` with a host-test frame allocator produces disjoint,
    /// correctly-sized, fully-initialized slices.
    ///
    /// Host testing trick: the frame allocator returns a fake
    /// "physical" base that isn't real host memory (writing to
    /// 0x100000 SIGSEGVs). We allocate a real host-side backing
    /// buffer and compute `hhdm_offset` so that `phys + hhdm_offset`
    /// lands on the buffer. In the real kernel, HHDM serves the same
    /// purpose: a linear map from physical to virtual where the
    /// virtual range is real writable memory.
    #[test]
    fn init_produces_valid_slices() {
        let num_slots = 32usize;
        let needed_bytes = region_bytes_for(num_slots) as usize;

        // Build a FrameAllocator with a generous free region so the
        // contiguous allocation succeeds at the base of the region.
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 4 * 1024 * 1024);
        fa.finalize();
        let before_free = fa.free_count();

        // Allocate a real, page-aligned host-side buffer of the same
        // size we're about to pretend to allocate physically.
        // Over-allocate by one page so we can snap the base up to a
        // page boundary.
        let page = PAGE_SIZE as usize;
        let buf_capacity = needed_bytes + page;
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(buf_capacity);
        // SAFETY: we only write through the init() path, which
        // initializes every slot to None. The buffer has enough
        // capacity; we treat it as `needed_bytes` of writable memory
        // at a page-aligned address.
        unsafe { buf.set_len(buf_capacity); }
        let raw_ptr = buf.as_mut_ptr() as usize;
        let aligned_virt = (raw_ptr + page - 1) & !(page - 1);

        // The FrameAllocator's first `allocate_contiguous` will
        // return `0x100000` (the start of our fake region). We want
        // `virt = phys + hhdm_offset` to land on `aligned_virt`, so
        // `hhdm_offset = aligned_virt - 0x100000`.
        let fake_phys_base = 0x100000u64;
        let hhdm_offset = aligned_virt as u64 - fake_phys_base;

        let table = init(
            &mut fa,
            num_slots,
            hhdm_offset,
            BindingConstraint::Unconstrained,
        )
        .expect("object_table::init failed");

        assert_eq!(table.num_slots, num_slots);
        assert_eq!(table.region_bytes, needed_bytes as u64);
        assert_eq!(table.process_slots.len(), num_slots);
        assert_eq!(table.capability_slots.len(), num_slots);
        assert_eq!(table.region_base_phys, fake_phys_base);

        // Every slot must be None after init (explicit write in init).
        for slot in table.process_slots.iter() {
            assert!(slot.is_none());
        }
        for slot in table.capability_slots.iter() {
            assert!(slot.is_none());
        }

        // Frame allocator should have handed out exactly the page
        // count we computed.
        let expected_pages = needed_bytes / page;
        assert_eq!(fa.free_count(), before_free - expected_pages);

        // Process and capability subregions must not overlap.
        let process_start = table.process_slots.as_ptr() as usize;
        let capability_start = table.capability_slots.as_ptr() as usize;
        let process_end =
            process_start + num_slots * core::mem::size_of::<Option<ProcessDescriptor>>();
        assert!(
            capability_start >= process_end,
            "capability subregion ({:#x}) must start at or after process \
             subregion end ({:#x})",
            capability_start,
            process_end
        );

        // Capability subregion's start must be page-aligned (ADR-008
        // § Architecture: the two subregions are separated by a page
        // boundary for false-sharing and verification reasons).
        assert_eq!(
            capability_start % page,
            0,
            "capability subregion base {:#x} is not page-aligned",
            capability_start
        );

        // Binding is preserved.
        assert_eq!(table.binding, BindingConstraint::Unconstrained);

        // The 'static slice references above are only valid as long
        // as `buf` is alive, but since this is a host-side test and
        // we don't use the slices after `buf` drops, the aliasing is
        // contained to the test scope. Explicitly drop `buf` here so
        // the order is clear in the test reader's mind.
        drop(table);
        drop(buf);
    }

    /// `init` rejects `num_slots == 0`.
    #[test]
    fn init_rejects_zero_slots() {
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 4 * 1024 * 1024);
        fa.finalize();

        let result = init(&mut fa, 0, 0, BindingConstraint::Unconstrained);
        assert!(matches!(result, Err(ObjectTableError::NoSlots)));
    }

    /// `init` propagates frame allocator failure when the region is
    /// larger than the pool.
    #[test]
    fn init_propagates_frame_alloc_failure() {
        // Tiny frame allocator: 4 frames = 16 KiB. Even with the
        // smaller ProcessDescriptor (BuddyAllocator moved to per-heap
        // storage), a 32-slot object table needs ~12 pages, so this
        // must fail with OutOfMemory.
        let mut fa = FrameAllocator::new();
        fa.add_region(0x100000, 4 * 4096);
        fa.finalize();

        let result = init(&mut fa, 32, 0, BindingConstraint::Unconstrained);
        assert!(matches!(result, Err(ObjectTableError::FrameAllocFailure(_))));
    }
}
