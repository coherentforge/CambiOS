// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Process management, heap allocation, and virtual memory area tracking
//!
//! Manages per-process state including memory allocators and VMA tracking.
//! Each process gets a BuddyAllocator (pure bookkeeping) plus a VmaTracker
//! that records user-space virtual memory allocations for proper free/unmap.

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
/// Why: bounded slot table for the bump-allocated VMA tracker, sized for the
///      v1 endgame target of a multi-monitor graphics compositor (ADR-011).
///      That process is estimated to hold ~50 VMA entries: 3 framebuffer
///      mappings + ~6 scanout channel mappings + ~30 window surface channels
///      + GPU MMIO mappings + GPU command/memory channels + heap + stack.
///      256 slots gives 4× headroom over that estimate per CLAUDE.md
///      Convention 8.
///      Memory cost: VmaTracker grows from 64 × ~24 B ≈ 1.5 KiB to 256 × ~24 B
///      ≈ 6 KiB per process. Trivial across boot modules.
/// Replace when: channels (ADR-005) attach shared-memory mappings as VMAs —
///      the first service that holds 50+ channels is on the edge. Or any
///      future mmap-style API. See docs/ASSUMPTIONS.md.
const MAX_VMAS: usize = 256;

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
/// - `count <= MAX_VMAS` (256).
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

impl Default for VmaTracker {
    fn default() -> Self { Self::new() }
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

    /// Register a pre-determined virtual address region in the tracker.
    ///
    /// Unlike [`allocate_region`] (which bumps `next_vaddr`), this
    /// accepts a caller-chosen `base_vaddr` — used by the ELF loader
    /// to record user segments (mapped at the ELF's `p_vaddr`) and
    /// the user stack (mapped at `DEFAULT_STACK_TOP - stack_size`).
    /// Without this, loader-created mappings bypass the tracker, and
    /// `reclaim_user_vmas` on process exit never sees them — the
    /// leaf user frames leak and (on RISC-V) the organic TLB-
    /// shootdown path never fires.
    ///
    /// Returns `true` if the entry was recorded, `false` if the
    /// tracker is full (MAX_VMAS exceeded) or inputs are invalid.
    /// Does NOT map pages — the caller must do frame alloc + map_page.
    pub fn register_region(&mut self, base_vaddr: u64, num_pages: u32) -> bool {
        if num_pages == 0 {
            return false;
        }
        if base_vaddr & 0xFFF != 0 {
            return false; // must be page-aligned
        }
        let Some(size) = (num_pages as u64).checked_mul(4096) else {
            return false;
        };
        let Some(end) = base_vaddr.checked_add(size) else {
            return false;
        };
        if end > 0x0000_8000_0000_0000 {
            return false; // stays in lower-half user space
        }

        let Some(slot) = self.entries.iter().position(|e| e.is_none()) else {
            return false;
        };
        self.entries[slot] = Some(VmaEntry {
            base_vaddr,
            num_pages,
        });
        self.count += 1;
        true
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
// Phase 3.2a: MAX_PROCESSES is no longer a compile-time constant.
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

/// SCAFFOLDING: per-process heap size (4 MiB).
/// Why: default budget per process. Today every process gets a
///      contiguous physical heap of this size, allocated from the
///      frame allocator in `ProcessDescriptor::new` and freed in
///      `handle_exit` via `FrameAllocator::free_contiguous`. Bumped
///      from 1 MiB to 4 MiB because udp-stack was already documented
///      as feeling the 1 MiB ceiling, and the v1 endgame graphics
///      workload (ADR-011) will push harder: GUI clients need space
///      for widget trees, font atlases, and software-rendered
///      backing stores. 4 MiB is the modest bump that buys today's
///      services breathing room without overcommitting per-process
///      memory across all boot modules (7 × 4 MiB = 28 MiB baseline,
///      comfortable on 128 MiB+ QEMU targets).
/// Replace when: a process needs more than 4 MiB of heap — the right
///      fix at that point is per-process heap sizing (spawn
///      argument), not bumping the global constant again. See
///      docs/ASSUMPTIONS.md.
pub const HEAP_SIZE: u64 = 0x400000;

/// Number of 4 KiB frames in a process heap (4 MiB / 4 KiB = 1024).
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
/// doc and ADR-008 Phase 3.2a follow-up for the rationale.
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
    /// the process's buddy allocator state (Phase 3.2a follow-up).
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
    /// Phase 3.2a: heap is no longer at a deterministic PID-derived
    /// physical address. Each process gets a fresh contiguous region
    /// from the frame allocator, which means process exit MUST free
    /// it via [`ProcessDescriptor::reclaim_heap`] to avoid a leak.
    ///
    /// Phase 3.2a follow-up (Item 1): the per-process `BuddyAllocator`
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
        //   `HEAP_SIZE = 4 MiB`, which is much larger than
        //   `size_of::<BuddyAllocator>()` (~20 KB). No risk of writing
        //   past the end.
        // - `virt_base` is page-aligned (frame allocator returns
        //   page-aligned bases) which satisfies any alignment
        //   requirement `BuddyAllocator` has (its max alignment is
        //   that of `u64`, which is 8 bytes, well below 4096).
        // - `BuddyAllocator` is `#[repr(C)]` with only plain-array
        //   fields, so the layout is deterministic and safe to
        //   construct via `core::ptr::write`.
        // In-place init avoids materializing a ~20 KB BuddyAllocator
        // temporary on the kernel stack. ptr::write with a by-value
        // argument would force the compiler to stage the struct on our
        // 32 KB kstack before the memcpy; in practice that dips RSP
        // into the adjacent task's kstack and silently zeros saved
        // SavedContext frames there. See BuddyAllocator::init_at.
        // SAFETY: virt_base is a freshly allocated, page-aligned,
        // HHDM-mapped region of HEAP_SIZE bytes (>> size_of::<BuddyAllocator>()).
        // We are the exclusive owner of those frames.
        unsafe {
            BuddyAllocator::init_at(
                virt_base as *mut BuddyAllocator,
                core::mem::size_of::<BuddyAllocator>(),
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

    /// Reclaim all user-space VMA-tracked regions.
    ///
    /// Walks the VMA tracker, unmaps each region's pages from the
    /// process page table, and frees the underlying physical frames
    /// back to the frame allocator.
    ///
    /// Must be called **before** `reclaim_page_tables()` because
    /// unmapping requires a valid page table.
    ///
    /// Returns the number of VMA regions reclaimed (for diagnostics).
    ///
    /// Phase 3.2d.ii (Roadmap item 17): closes the VMA region leak
    /// that previously occurred on process exit.
    #[cfg(not(test))]
    pub fn reclaim_user_vmas(
        &mut self,
        frame_alloc: &mut FrameAllocator,
    ) -> usize {
        if self.cr3 == 0 {
            // Kernel tasks have no per-process page table or user VMAs.
            return 0;
        }

        let mut reclaimed = 0usize;

        // Drain all VMA entries. We collect bases first to avoid
        // borrowing conflicts with the VMA tracker.
        let mut bases = [0u64; MAX_VMAS];
        let mut base_count = 0usize;
        for entry in self.vma.entries.iter().flatten() {
            if base_count < MAX_VMAS {
                bases[base_count] = entry.base_vaddr;
                base_count += 1;
            }
        }

        for &base in &bases[..base_count] {
            if let Some(entry) = self.vma.free_region(base) {
                // Unmap each page and free its physical frame.
                // SAFETY: self.cr3 is a valid PML4 physical address
                // (set by create_process_page_table in ProcessTable::
                // create_process). We hold exclusive access to the
                // ProcessDescriptor (via &mut self), and the process
                // is terminated so its page table is not loaded in
                // any CPU's CR3.
                let mut pt = unsafe {
                    paging::page_table_from_cr3(self.cr3)
                };
                for page_idx in 0..entry.num_pages as usize {
                    let vaddr = entry.base_vaddr + (page_idx as u64) * PAGE_SIZE;
                    if let Ok(phys_frame) = paging::unmap_page(&mut pt, vaddr) {
                        let _ = frame_alloc.free(phys_frame);
                    }
                    // Ignore NotMapped — the page may have been
                    // allocated in the VMA tracker but never actually
                    // mapped (e.g., a failed allocation that reserved
                    // virtual space but couldn't get a frame).
                }
                reclaimed += 1;
            }
        }

        reclaimed
    }

    /// Test-only stub: drains the VMA tracker without touching page
    /// tables (which don't exist in host tests). Returns the number of
    /// VMA entries that were drained. Mirrors the kernel behavior of
    /// returning 0 for kernel tasks (cr3 == 0).
    #[cfg(test)]
    pub fn reclaim_user_vmas(
        &mut self,
        _frame_alloc: &mut FrameAllocator,
    ) -> usize {
        if self.cr3 == 0 {
            return 0;
        }
        let mut reclaimed = 0usize;
        let mut bases = [0u64; MAX_VMAS];
        let mut base_count = 0usize;
        for entry in self.vma.entries.iter().flatten() {
            if base_count < MAX_VMAS {
                bases[base_count] = entry.base_vaddr;
                base_count += 1;
            }
        }
        for i in 0..base_count {
            if self.vma.free_region(bases[i]).is_some() {
                reclaimed += 1;
            }
        }
        reclaimed
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
/// Phase 3.2a: storage is a `&'static mut [Option<ProcessDescriptor>]`
/// slice handed in from `memory::object_table::init()`. The slice
/// length equals `config::num_slots()`, computed at boot from the
/// SCAFFOLDING: number of recent process exits to remember for
/// principal-after-exit lookup.
/// Why: an audit consumer reading buffered events may encounter a
/// `subject_pid` whose process has already exited and whose slot may
/// have been reused. Without a recent-exits ring, the consumer cannot
/// resolve the original Principal — a non-issue for short-lived
/// consumers but a correctness gap for batch readers and the
/// kernelvisor. At ~10 process exits/min in steady state and audit
/// consumers reading at ≥1/sec, 64 entries covers ~6 minutes of exit
/// history. 25%-utilization rule: typical workload uses ~16 entries.
/// Replace when: kernelvisor stress test shows >64 distinct exits
/// within any 10-second consumer-lag window, or a per-Principal
/// resolution table replaces the ring entirely.
pub const RECENT_EXITS_RING_SIZE: usize = 64;

/// One recorded exit: maps a (slot, generation) pair to the Principal
/// that was bound at exit time.
#[derive(Clone, Copy)]
struct RecentExit {
    slot: u32,
    generation: u32,
    principal: crate::ipc::Principal,
}

/// Bounded circular buffer of recently-exited processes.
///
/// Used by `SYS_GET_PROCESS_PRINCIPAL` to resolve a `subject_pid` whose
/// process slot has already been reused. The ring is FIFO-overwriting:
/// when full, the oldest entry is silently displaced. A consumer that
/// hasn't read in long enough to span the ring's span will see `Enoent`
/// for old `subject_pid`s — that's the cost of a fixed-size ring, and
/// the bound exists to be verifiable per CLAUDE.md's "bounded iteration"
/// rule.
pub struct RecentExitsRing {
    entries: [Option<RecentExit>; RECENT_EXITS_RING_SIZE],
    write_idx: usize,
}

impl RecentExitsRing {
    pub const fn new() -> Self {
        Self {
            entries: [None; RECENT_EXITS_RING_SIZE],
            write_idx: 0,
        }
    }

    /// Record an exit. Overwrites the oldest entry on wraparound.
    pub fn push(&mut self, slot: u32, generation: u32, principal: crate::ipc::Principal) {
        self.entries[self.write_idx] = Some(RecentExit { slot, generation, principal });
        self.write_idx = (self.write_idx + 1) % RECENT_EXITS_RING_SIZE;
    }

    /// Look up an exit by (slot, generation). Returns the Principal that
    /// was bound at exit time, or `None` if the (slot, generation) pair
    /// is not in the ring (either never recorded or already overwritten).
    pub fn lookup(&self, slot: u32, generation: u32) -> Option<crate::ipc::Principal> {
        for entry in self.entries.iter() {
            if let Some(rx) = entry {
                if rx.slot == slot && rx.generation == generation {
                    return Some(rx.principal);
                }
            }
        }
        None
    }
}

/// active tier policy and available RAM. See ADR-008.
///
/// Phase 3.2c: per-slot generation counters prevent stale `ProcessId`
/// references from targeting a reused slot. The generation for a slot
/// is incremented in `destroy_process` and stamped into the
/// `ProcessId` returned by `create_process`. Lookups compare the
/// caller's `ProcessId.generation()` against the stored generation.
pub struct ProcessTable {
    processes: &'static mut [Option<ProcessDescriptor>],
    /// Cached HHDM offset for creating new processes
    hhdm_offset: u64,
    /// Per-slot generation counter (Phase 3.2c, ADR-008 § Open Problem 9).
    /// Heap-allocated at construction, one `u32` per slot. Incremented
    /// in `destroy_process` when a slot becomes free. The current
    /// generation is stamped into the `ProcessId` returned by
    /// `create_process`, so stale references (whose generation no
    /// longer matches) are rejected by every lookup.
    generations: Box<[u32]>,
    /// Recent-exits ring for `SYS_GET_PROCESS_PRINCIPAL` lookups when
    /// the target process has already exited. Populated by callers via
    /// `record_exit` before `destroy_process` increments the generation.
    recent_exits: RecentExitsRing,
}

impl ProcessTable {
    /// Construct a process table backed by an already-initialized
    /// slice from the kernel object table region.
    ///
    /// The slice must have every slot pre-initialized to `None`
    /// (which `object_table::init` guarantees). The returned
    /// `Box<Self>` lives on the kernel heap; only its small header
    /// (slice pointer, length, hhdm_offset, generations) lands there —
    /// the actual slot storage lives in the object table region.
    ///
    /// Phase 3.2c: also allocates a heap-backed generation counter array,
    /// one `u32` per slot, all starting at 0.
    pub fn from_object_slice(
        processes: &'static mut [Option<ProcessDescriptor>],
        hhdm_offset: u64,
    ) -> Option<Box<Self>> {
        let num_slots = processes.len();
        let generations = alloc::vec![0u32; num_slots].into_boxed_slice();
        let table = ProcessTable {
            processes,
            hhdm_offset,
            generations,
            recent_exits: RecentExitsRing::new(),
        };
        Some(Box::new(table))
    }

    /// Record an exit in the recent-exits ring before the slot is reused.
    /// Caller (`handle_exit`) reads the principal from the capability
    /// manager and passes it in here, then calls `destroy_process`.
    pub fn record_exit(&mut self, process_id: ProcessId, principal: crate::ipc::Principal) {
        self.recent_exits.push(process_id.slot(), process_id.generation(), principal);
    }

    /// Look up the principal that was bound to a process at exit time.
    /// Returns `None` if the (slot, generation) pair is not in the ring.
    pub fn lookup_recent_exit(&self, process_id: ProcessId) -> Option<crate::ipc::Principal> {
        self.recent_exits.lookup(process_id.slot(), process_id.generation())
    }

    /// Find a free slot by linear scan. Returns the slot index, or
    /// `None` if all slots are occupied.
    ///
    /// Phase 3.2c: replaces the external `NEXT_PROCESS_ID` atomic.
    /// Linear scan is O(n) in `num_slots` but bounded and
    /// verification-friendly (no free-list state to reason about).
    fn find_free_slot(&self) -> Option<usize> {
        self.processes.iter().position(|slot| slot.is_none())
    }

    /// Number of slots in the table (equal to `config::num_slots()`).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.processes.len()
    }

    /// Create a new process and allocate its heap region.
    ///
    /// Phase 3.2c: the process table allocates the slot internally via
    /// linear scan and stamps the current generation counter into the
    /// returned `ProcessId`. The caller no longer passes a ProcessId
    /// — it receives one. This closes the ambient-authority gap where
    /// any caller could pick an arbitrary slot index.
    ///
    /// Failure modes:
    /// - `"No free process slots"` — all slots occupied
    /// - `"Failed to allocate process heap"` — frame allocator
    ///   exhausted (after Phase 3.2a, heaps are allocated on demand)
    /// - `"Failed to allocate page table"` — per-process PML4
    ///   allocation failed
    pub fn create_process(
        &mut self,
        frame_alloc: &mut FrameAllocator,
        create_page_table: bool,
    ) -> Result<ProcessId, &'static str> {
        let idx = self.find_free_slot().ok_or("No free process slots")?;
        let generation = self.generations[idx];
        let process_id = ProcessId::new(idx as u32, generation);

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
        Ok(process_id)
    }

    /// Allocate memory for a process, returning kernel-accessible virtual address.
    /// Returns 0 on failure.
    pub fn allocate_for(&mut self, process_id: ProcessId, size: usize) -> usize {
        let idx = process_id.slot() as usize;
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
        let idx = process_id.slot() as usize;
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
    /// Phase 3.2a: heaps are no longer at a deterministic
    /// `PROCESS_HEAP_BASE + pid * HEAP_SIZE` address — the base is
    /// whatever the frame allocator handed us at creation time. This
    /// getter reads the stored `phys_base` field.
    pub fn get_heap_base(&self, process_id: ProcessId) -> u64 {
        let idx = process_id.slot() as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_ref().map(|p| p.phys_base).unwrap_or(0)
        } else {
            0
        }
    }

    /// Get process heap size
    pub fn get_heap_size(&self, process_id: ProcessId) -> u64 {
        let idx = process_id.slot() as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_ref().map(|p| p.heap_size).unwrap_or(0)
        } else {
            0
        }
    }

    /// Destroy a process and reclaim all its kernel-managed resources.
    ///
    /// Phase 3.2d.ii (Roadmap item 17): full lifecycle cleanup. The
    /// reclamation order is important:
    ///
    /// 1. **VMA regions** — unmap every VMA-tracked user page and free
    ///    its physical frame. Must come first because unmapping
    ///    requires a valid page table.
    /// 2. **Page table frames** — walk the user-half of the PML4 and
    ///    free all intermediate page table structures (PDP/PD/PT).
    ///    Must come after VMA reclaim (leaf pages are gone).
    /// 3. **Heap** — free the contiguous heap region (existing path).
    /// 4. **Generation increment** — prevent stale ProcessId from
    ///    targeting the reused slot (Phase 3.2c).
    ///
    /// Kernel stack deallocation is deferred to a separate cleanup
    /// pass (bounded leak, requires scheduler-level deferred-free
    /// mechanism). See STATUS.md.
    pub fn destroy_process(
        &mut self,
        process_id: ProcessId,
        frame_alloc: &mut FrameAllocator,
    ) {
        let idx = process_id.slot() as usize;
        if idx >= self.processes.len() {
            return;
        }
        if let Some(mut desc) = self.processes[idx].take() {
            // Step 1: Reclaim VMA-tracked user-space regions.
            // Unmaps pages from the process page table and frees
            // physical frames. Must precede page table reclaim.
            let _vma_count = desc.reclaim_user_vmas(frame_alloc);

            // Step 2: Reclaim page table frames (PML4 + intermediates).
            // Only for processes with a per-process page table (cr3 != 0).
            #[cfg(not(test))]
            if desc.cr3 != 0 {
                paging::reclaim_process_page_tables(desc.cr3, frame_alloc);
            }

            // Step 3: Reclaim the heap region.
            let _ = desc.reclaim_heap(frame_alloc);

            // Step 4: Increment generation so the next occupant of this
            // slot gets a distinct ProcessId. Wrapping is intentional —
            // u32 gives ~4 billion reuses per slot before wrap.
            self.generations[idx] = self.generations[idx].wrapping_add(1);
        }
    }

    /// Get a process's CR3 (PML4 physical address). Returns 0 if no per-process page table.
    pub fn get_cr3(&self, process_id: ProcessId) -> u64 {
        let idx = process_id.slot() as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_ref().map(|p| p.cr3).unwrap_or(0)
        } else {
            0
        }
    }

    /// Check whether a process slot is occupied.
    pub fn slot_occupied(&self, process_id: ProcessId) -> bool {
        let idx = process_id.slot() as usize;
        idx < self.processes.len() && self.processes[idx].is_some()
    }

    /// Get mutable access to a process's VMA tracker.
    pub fn vma_mut(&mut self, process_id: ProcessId) -> Option<&mut VmaTracker> {
        let idx = process_id.slot() as usize;
        if idx < self.processes.len() {
            self.processes[idx].as_mut().map(|p| &mut p.vma)
        } else {
            None
        }
    }

    /// Get read-only access to a process's VMA tracker.
    pub fn vma(&self, process_id: ProcessId) -> Option<&VmaTracker> {
        let idx = process_id.slot() as usize;
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
    fn test_vma_register_region_basic() {
        let mut vma = VmaTracker::new();
        assert!(vma.register_region(0x400000, 2));
        assert_eq!(vma.count(), 1);
        let entry = vma.find(0x400000).unwrap();
        assert_eq!(entry.base_vaddr, 0x400000);
        assert_eq!(entry.num_pages, 2);
    }

    #[test]
    fn test_vma_register_region_rejects_unaligned() {
        let mut vma = VmaTracker::new();
        assert!(!vma.register_region(0x400100, 1));
        assert_eq!(vma.count(), 0);
    }

    #[test]
    fn test_vma_register_region_rejects_zero_pages() {
        let mut vma = VmaTracker::new();
        assert!(!vma.register_region(0x400000, 0));
        assert_eq!(vma.count(), 0);
    }

    #[test]
    fn test_vma_register_region_rejects_kernel_space() {
        let mut vma = VmaTracker::new();
        // One page starting just past the canonical user-space end.
        assert!(!vma.register_region(0x0000_8000_0000_0000, 1));
        assert_eq!(vma.count(), 0);
    }

    #[test]
    fn test_vma_register_region_coexists_with_allocate() {
        // The loader uses register_region for fixed VAs; syscall Allocate
        // uses allocate_region (bump). Both must populate the same tracker.
        let mut vma = VmaTracker::new();
        assert!(vma.register_region(0x400000, 1)); // ELF segment
        let bump_addr = vma.allocate_region(2).unwrap(); // syscall Allocate
        assert_eq!(bump_addr, VMA_ALLOC_BASE);
        assert_eq!(vma.count(), 2);
        assert!(vma.find(0x400000).is_some());
        assert!(vma.find(bump_addr).is_some());
    }

    #[test]
    fn test_vma_register_region_fills_all_slots() {
        let mut vma = VmaTracker::new();
        for i in 0..MAX_VMAS {
            let base = 0x400000 + (i as u64) * 0x1000;
            assert!(vma.register_region(base, 1));
        }
        // Next register must fail with no slots.
        assert!(!vma.register_region(0x800000, 1));
        assert_eq!(vma.count(), MAX_VMAS);
    }

    #[test]
    fn test_vma_capacity_exhaustion() {
        let mut vma = VmaTracker::new();
        for _ in 0..MAX_VMAS {
            assert!(vma.allocate_region(1).is_some());
        }
        // Next allocation after MAX_VMAS fills the tracker → no free slots
        assert!(vma.allocate_region(1).is_none());
        assert_eq!(vma.count(), MAX_VMAS);
    }

    // ========================================================================
    // Phase 3.2d.ii: reclaim_user_vmas tests
    //
    // These use the #[cfg(test)] stub which drains the VMA tracker
    // without touching real page tables.
    // ========================================================================

    /// Helper: construct a ProcessDescriptor with a dummy heap
    /// (no real frame allocation in test mode).
    fn test_descriptor() -> ProcessDescriptor {
        ProcessDescriptor {
            phys_base: 0x1000_0000,
            virt_base: 0xFFFF_8001_0000_0000,
            heap_size: HEAP_SIZE,
            cr3: 0x2000_0000, // non-zero → has per-process PT
            vma: VmaTracker::new(),
        }
    }

    #[test]
    fn test_reclaim_user_vmas_empty() {
        let mut desc = test_descriptor();
        let mut fa = FrameAllocator::new();
        assert_eq!(desc.reclaim_user_vmas(&mut fa), 0);
        assert_eq!(desc.vma.count(), 0);
    }

    #[test]
    fn test_reclaim_user_vmas_drains_tracker() {
        let mut desc = test_descriptor();
        let mut fa = FrameAllocator::new();

        // Allocate 3 VMA regions.
        desc.vma.allocate_region(1).unwrap();
        desc.vma.allocate_region(4).unwrap();
        desc.vma.allocate_region(2).unwrap();
        assert_eq!(desc.vma.count(), 3);

        let reclaimed = desc.reclaim_user_vmas(&mut fa);
        assert_eq!(reclaimed, 3);
        assert_eq!(desc.vma.count(), 0);
    }

    #[test]
    fn test_reclaim_user_vmas_kernel_task_is_noop() {
        let mut desc = test_descriptor();
        desc.cr3 = 0; // kernel task — no per-process page table
        let mut fa = FrameAllocator::new();

        // Even with VMA entries, a kernel task's reclaim is a no-op
        // (in the real kernel; in test mode the stub always drains).
        // The test verifies the function returns without error.
        assert_eq!(desc.reclaim_user_vmas(&mut fa), 0);
    }

    // ========================================================================
    // RecentExitsRing tests — bounded-buffer principal lookup for exited
    // processes. Used by SYS_GET_PROCESS_PRINCIPAL.
    // ========================================================================

    #[test]
    fn recent_exits_ring_empty_lookup_returns_none() {
        let ring = RecentExitsRing::new();
        assert!(ring.lookup(0, 0).is_none());
        assert!(ring.lookup(5, 3).is_none());
    }

    #[test]
    fn recent_exits_ring_round_trips_one_entry() {
        let mut ring = RecentExitsRing::new();
        let p = crate::ipc::Principal::from_public_key([0xAA; 32]);
        ring.push(7, 2, p);
        assert_eq!(ring.lookup(7, 2), Some(p));
        // Wrong slot or wrong generation → None.
        assert!(ring.lookup(7, 3).is_none());
        assert!(ring.lookup(8, 2).is_none());
    }

    #[test]
    fn recent_exits_ring_keeps_distinct_entries() {
        let mut ring = RecentExitsRing::new();
        let p1 = crate::ipc::Principal::from_public_key([0x11; 32]);
        let p2 = crate::ipc::Principal::from_public_key([0x22; 32]);
        ring.push(1, 0, p1);
        ring.push(2, 0, p2);
        assert_eq!(ring.lookup(1, 0), Some(p1));
        assert_eq!(ring.lookup(2, 0), Some(p2));
    }

    #[test]
    fn recent_exits_ring_overwrites_oldest_on_wrap() {
        let mut ring = RecentExitsRing::new();
        // Fill the ring to capacity + 1 so the first entry is evicted.
        let first = crate::ipc::Principal::from_public_key([0x01; 32]);
        ring.push(0, 0, first);
        for i in 1..=RECENT_EXITS_RING_SIZE as u32 {
            ring.push(i, 0, crate::ipc::Principal::from_public_key([(i & 0xFF) as u8; 32]));
        }
        // First entry was at index 0; one extra push wrapped and overwrote it.
        assert!(ring.lookup(0, 0).is_none(), "first entry should have been evicted");
        // Last-pushed entries are still present.
        assert!(ring.lookup(RECENT_EXITS_RING_SIZE as u32, 0).is_some());
    }

    #[test]
    fn recent_exits_ring_distinguishes_generations_at_same_slot() {
        let mut ring = RecentExitsRing::new();
        let p_gen0 = crate::ipc::Principal::from_public_key([0xA0; 32]);
        let p_gen1 = crate::ipc::Principal::from_public_key([0xA1; 32]);
        ring.push(3, 0, p_gen0);
        ring.push(3, 1, p_gen1);
        assert_eq!(ring.lookup(3, 0), Some(p_gen0));
        assert_eq!(ring.lookup(3, 1), Some(p_gen1));
    }
}
