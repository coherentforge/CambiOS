// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Deferred reclamation of a terminating task's self-referential resources.
//!
//! A task dies in its own running context (a `SYS_EXIT` syscall, or a fault
//! taken while it is current), so its page-table root is still loaded in
//! CR3/satp/TTBR0 and its kernel stack is still in use. Those two resources —
//! plus the task slot, deferred to a later phase — cannot be freed inline
//! without the CPU pulling the floor out from under itself (the confirmed
//! triple-fault: freeing the active PML4 unmaps the address space, and the
//! next TLB miss faults on an unmapped fault handler). Everything else a dying
//! task owns (capabilities, channels, clusters, VMA frames, the heap) is still
//! reclaimed inline in the death path — only the irreducibly self-referential
//! set is deferred here.
//!
//! See [ADR-034](../docs/adr/034-deferred-task-resource-reclamation.md).
//!
//! ## Mechanism (Phase A)
//!
//! The death path captures `{ page-table root, kernel-stack top }` by value,
//! marks the task `Terminated`, and pushes the pair onto
//! [`crate::PER_CPU_RECLAIM_QUEUE`] for its own CPU — under the queue lock
//! alone, with no hierarchy lock held (ADR-034 §3 lock discipline). It then
//! yields. Because `purge_task` has already cleared `current_task`, the timer
//! ISR takes its no-switch path (`time_slice_expired()` is `false` with no
//! current task), so the dying task is never involuntarily switched away
//! between the enqueue and its terminal yield — the queued item is durable
//! before any context switch, and any switch (the terminal yield) moves the
//! CPU off the dead root and stack *as part of the switch* (CR3/satp reload +
//! stack swap) before the reaper can run.
//!
//! [`drain_local`] runs later, from this CPU's idle loop, in normal context
//! (interrupts enabled, `SCHEDULER` not held). It frees the page-table root +
//! intermediates and the kernel stack — by then no CPU is on either.

extern crate alloc;

// Only `free_kernel_stack` (kernel-only, `cfg(not(test))`) uses Layout.
#[cfg(not(test))]
use core::alloc::Layout;

/// One deferred-reclamation work item: the self-referential resources of a
/// single terminated task that could not be freed from its own context.
///
/// `Copy` so the bounded queue can be a plain array initialized in a `const fn`
/// and `pop()` can return by value.
#[derive(Clone, Copy)]
pub struct ReclaimItem {
    /// Physical address of the task's page-table root (PML4 / satp L0 /
    /// TTBR0 L0). `0` means the task had no per-process table (a kernel
    /// task) and there is nothing to free.
    pub root_phys: u64,
    /// Top (highest address) of the task's heap-allocated kernel stack, as
    /// stored in `Task::kernel_stack_top`. `0` means the task ran on the boot
    /// stack (the idle task) and there is nothing to free.
    pub kstack_top: u64,
    /// The terminated task whose scheduler slot is to be reclaimed (ADR-034
    /// Phase B). Carries the full `(slot, generation)` so the reaper frees the
    /// slot only if it still holds that exact dead task, then bumps the slot's
    /// generation so the next occupant gets a distinct `TaskId`.
    pub task_id: crate::scheduler::TaskId,
}

/// SCAFFOLDING: depth of each per-CPU deferred-reclaim queue. Tracks
/// `crate::MAX_TASKS` — not an independent guess.
/// Why: a CPU can hold at most `MAX_TASKS` Terminated-but-unreaped tasks
///      (a slot cannot be reused until reaped), so a queue this deep makes
///      overflow structurally impossible (ADR-034 §5). Cost: `MAX_TASKS` ×
///      16 B = 4 KiB/CPU, × `MAX_CPUS` = 1 MiB zero-init `.bss` fleet-wide.
/// Replace when: `MAX_TASKS` changes (keep equal), or a design ever lets a
///      CPU hold more than `MAX_TASKS` pending reclaims. See ASSUMPTIONS.md.
pub const RECLAIM_QUEUE_CAPACITY: usize = crate::MAX_TASKS;

/// Bounded per-CPU queue of pending [`ReclaimItem`]s.
///
/// LIFO is fine — reclamation order does not matter, every queued item is
/// freed. A fixed array + length avoids any heap allocation in the death path
/// (which must not allocate) and makes the structure `const`-constructible for
/// the per-CPU static array.
pub struct ReclaimQueue {
    items: [ReclaimItem; RECLAIM_QUEUE_CAPACITY],
    len: usize,
}

impl ReclaimQueue {
    /// Empty queue. `const` so [`crate::PER_CPU_RECLAIM_QUEUE`] can be a
    /// `static` initialized with `[const { IrqSpinlock::new(...) }; MAX_CPUS]`.
    pub const fn new() -> Self {
        Self {
            items: [ReclaimItem {
                root_phys: 0,
                kstack_top: 0,
                task_id: crate::scheduler::TaskId::IDLE,
            }; RECLAIM_QUEUE_CAPACITY],
            len: 0,
        }
    }

    /// Push an item. Returns `Err(item)` (never panics, never blocks) if the
    /// queue is full — structurally impossible when sized to `MAX_TASKS`, but
    /// the death path must have a non-panicking fallback (it degrades to a
    /// bounded leak, not a crash).
    pub fn push(&mut self, item: ReclaimItem) -> Result<(), ReclaimItem> {
        if self.len >= RECLAIM_QUEUE_CAPACITY {
            return Err(item);
        }
        self.items[self.len] = item;
        self.len += 1;
        Ok(())
    }

    /// Pop the most-recently-pushed item, or `None` when empty.
    pub fn pop(&mut self) -> Option<ReclaimItem> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(self.items[self.len])
    }

    /// Number of items currently queued (for the high-watermark trigger in
    /// ADR-034's Open Problems).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for ReclaimQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Drain this CPU's reclaim queue, freeing each item's page-table root +
/// intermediates and kernel stack. Called from the per-CPU idle loop
/// (`microkernel_loop` and the AP idle loops) in normal context — interrupts
/// enabled, no hierarchy lock held.
///
/// Lock discipline (ADR-034 §3): pop under the queue lock **alone**, release
/// it, then take `FRAME_ALLOCATOR(8)` for the frame frees — never nested. The
/// kernel-stack free goes through the global allocator (a distinct lock),
/// taken only after `FRAME_ALLOCATOR` is released. The slot free takes the
/// local `SCHEDULER(1)` last, also un-nested with the others.
///
/// The slot lives in *this* CPU's scheduler: the dying task enqueued to its
/// own CPU's queue, and a Terminated+purged task cannot migrate, so the slot
/// is local to the reaper. No foreign-`SCHEDULER` acquisition (ADR-034 §3).
///
/// Bounded: the loop runs at most `RECLAIM_QUEUE_CAPACITY` times per call
/// (the queue cannot grow while we drain it on this CPU — the only pusher is a
/// dying task running on this same CPU, which cannot run concurrently with the
/// idle loop).
#[cfg(not(test))]
pub fn drain_local() {
    loop {
        // Pop under the queue lock alone; the guard is dropped at the end of
        // this block, before FRAME_ALLOCATOR is acquired below.
        let item = {
            let mut queue = crate::local_reclaim_queue().lock();
            match queue.pop() {
                Some(item) => item,
                None => break,
            }
        };

        // Free the page-table root + intermediate frames. The owning task has
        // yielded off this root (it is no CPU's active CR3/satp/TTBR0), so the
        // active-root guard inside `reclaim_process_page_tables` is pure
        // defense-in-depth here.
        if item.root_phys != 0 {
            let mut frame_alloc = crate::FRAME_ALLOCATOR.lock();
            crate::memory::paging::reclaim_process_page_tables(item.root_phys, &mut frame_alloc);
        }

        // Free the kernel stack the task stood on (FRAME_ALLOCATOR released).
        if item.kstack_top != 0 {
            free_kernel_stack(item.kstack_top);
        }

        // Reclaim the scheduler slot (ADR-034 Phase B) and bump the slot's
        // generation so the next occupant gets a distinct TaskId. Both happen
        // under the local SCHEDULER lock so no create on this CPU can grab the
        // freed slot with the stale generation in between. `reap_slot`
        // validates the slot still holds that exact Terminated task, so a
        // double-drain or a racing reuse is a no-op rather than a corruption.
        if !item.task_id.is_idle() {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_mut() {
                if sched.reap_slot(item.task_id) {
                    crate::bump_task_generation(item.task_id.slot());
                }
            }
        }
    }
}

/// Free a heap-allocated kernel stack given its top address.
///
/// The stack was allocated in `loader::load_elf_process` via the global
/// allocator with `Layout::from_size_align(KERNEL_STACK_SIZE, 16)`, and
/// `kernel_stack_top == base + KERNEL_STACK_SIZE`, so the base pointer handed
/// back to `dealloc` is exactly `kstack_top - KERNEL_STACK_SIZE`.
#[cfg(not(test))]
fn free_kernel_stack(kstack_top: u64) {
    let base = (kstack_top - crate::loader::KERNEL_STACK_SIZE as u64) as *mut u8;
    // `KERNEL_STACK_SIZE` is non-zero and `16` is a power of two, so this
    // never errors; match rather than `unwrap()` (banned in kernel code) and
    // skip the free on the impossible error (a bounded leak, not a panic).
    if let Ok(layout) = Layout::from_size_align(crate::loader::KERNEL_STACK_SIZE, 16) {
        // SAFETY: `base` is the exact pointer `alloc(layout)` returned in
        // `load_elf_process` (kstack_top = base + KERNEL_STACK_SIZE, same
        // layout). The owning task is `Terminated` and has executed its
        // terminal `yield_save_and_switch`, so no CPU's RSP/SP is within this
        // region and the task is never rescheduled — no live reference
        // remains. Freed exactly once: the item is enqueued only by the winner
        // of the `Running -> Terminated` transition (ADR-034 §3 enqueue-once).
        unsafe { alloc::alloc::dealloc(base, layout) };
    }
}
