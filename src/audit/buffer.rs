// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Lock-free single-producer single-consumer (SPSC) staging buffer for audit events.
//!
//! This module contains the per-CPU staging ring buffer used by `audit::emit()`.
//! It is a pure data structure with no hardware dependencies, designed for
//! formal verification following the BuddyAllocator pattern.
//!
//! # Concurrency model
//!
//! Each `StagingBuffer` has exactly one producer (the local CPU) and one consumer
//! (the BSP drain task). The producer calls `push()` from syscall handlers and ISR
//! context. The consumer calls `drain_to()` from the timer ISR on the BSP.
//!
//! The SPSC protocol uses `Acquire`/`Release` atomic ordering on `head` and `tail`
//! indices — no locks, no CAS, no spin loops.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::audit::RawAuditEvent;

/// SCAFFOLDING: maximum entries in each per-CPU staging buffer.
///
/// Why: at ~64 bytes/event, this is 8 KiB per CPU. At 1000 events/sec spread
///      across 4 CPUs, each CPU sees ~250 events/sec. With drain running at
///      100 Hz (every timer tick), that is ~2.5 events per drain cycle under
///      typical load. 128 entries gives 50× headroom. At v1 (16 services ×
///      N channels), spikes to ~1000 events/CPU/sec would fill ~10 entries per
///      drain cycle. 128 entries handles a 10× burst without drops.
///      Memory: 256 CPUs × 8 KiB = 2 MiB worst case (all online); ~16 KiB typical (2 CPUs).
///
/// Replace when: observed drop rates exceed 0.1% under sustained load.
pub const STAGING_BUFFER_CAPACITY: usize = 128;

/// Lock-free SPSC ring buffer for audit events.
///
/// The producer (local CPU) writes via `push()`. The consumer (drain task)
/// reads via `drain_to()`. Both are wait-free on the fast path.
///
/// # Layout
///
/// `head` is the next write index (owned by producer, read by consumer).
/// `tail` is the next read index (owned by consumer, read by producer).
/// The buffer is empty when `head == tail`, full when `(head + 1) % cap == tail`.
/// One slot is always unused to distinguish full from empty.
///
/// # Safety
///
/// This type is `Sync` because the SPSC protocol ensures no concurrent
/// writes to the same index. The `UnsafeCell` wrapping the entry array
/// is accessed only through the atomic-guarded push/drain protocol.
pub struct StagingBuffer {
    /// Next write position. Written by producer, read by consumer.
    head: AtomicU32,
    /// Next read position. Written by consumer, read by producer.
    tail: AtomicU32,
    /// Events dropped because the buffer was full.
    dropped: AtomicU64,
    /// Fixed-size ring of events.
    entries: UnsafeCell<[MaybeUninit<RawAuditEvent>; STAGING_BUFFER_CAPACITY]>,
}

// SAFETY: StagingBuffer is designed for single-producer single-consumer access.
// The SPSC protocol (atomic head/tail with Acquire/Release ordering) ensures that
// the producer and consumer never access the same entry concurrently. The
// `UnsafeCell` is only accessed through the guarded push/drain_to methods.
unsafe impl Sync for StagingBuffer {}

// SAFETY: StagingBuffer contains only atomics, UnsafeCell of Copy types, and
// MaybeUninit of a Copy type. All are Send-safe.
unsafe impl Send for StagingBuffer {}

impl Default for StagingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl StagingBuffer {
    /// Create a new empty staging buffer.
    ///
    /// This is `const fn` so it can be used in static initializers.
    pub const fn new() -> Self {
        Self {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            dropped: AtomicU64::new(0),
            entries: UnsafeCell::new([const { MaybeUninit::uninit() }; STAGING_BUFFER_CAPACITY]),
        }
    }

    /// Push an event into the buffer.
    ///
    /// Returns `true` if the event was stored, `false` if the buffer was full
    /// (in which case the `dropped` counter is incremented).
    ///
    /// # Producer-side only
    ///
    /// Must be called only by the owning CPU. This is guaranteed by the
    /// per-CPU buffer design — each CPU indexes `PER_CPU_AUDIT_BUFFER[cpu_id]`.
    #[inline(always)]
    pub fn push(&self, event: RawAuditEvent) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let next_head = (head + 1) % STAGING_BUFFER_CAPACITY as u32;

        // Check if full: next write position would collide with tail.
        let tail = self.tail.load(Ordering::Acquire);
        if next_head == tail {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Write the event into the slot.
        // SAFETY: `head` is only advanced by this CPU (single producer), so no
        // other writer touches entries[head]. The consumer only reads up to the
        // old head (before our Release store below), so no concurrent read.
        unsafe {
            let entries = &mut *self.entries.get();
            entries[head as usize] = MaybeUninit::new(event);
        }

        // Publish the new head. The Release pairs with the consumer's Acquire
        // load of head, ensuring the event data is visible before head advances.
        self.head.store(next_head, Ordering::Release);
        true
    }

    /// Drain events from the buffer into an output slice.
    ///
    /// Copies up to `out.len()` events from the buffer into `out`, advancing
    /// the tail. Returns the number of events actually drained.
    ///
    /// # Consumer-side only
    ///
    /// Must be called only by the drain task (BSP timer ISR). Only one
    /// consumer exists per buffer.
    pub fn drain_to(&self, out: &mut [RawAuditEvent]) -> usize {
        if out.is_empty() {
            return 0;
        }

        let tail = self.tail.load(Ordering::Relaxed);
        // Acquire-load head to see all events the producer has published.
        let head = self.head.load(Ordering::Acquire);

        if head == tail {
            return 0; // Empty
        }

        // Calculate available count (handles wrap-around).
        let available = if head >= tail {
            (head - tail) as usize
        } else {
            (STAGING_BUFFER_CAPACITY as u32 - tail + head) as usize
        };

        let count = available.min(out.len());

        // Copy events from the ring into the output slice.
        // SAFETY: self.entries.get() returns a valid pointer to the entry
        // array. Only this consumer reads these slots; the producer only
        // writes at head (beyond our read range).
        let entries = unsafe { &*self.entries.get() };
        for (i, slot) in out[..count].iter_mut().enumerate() {
            let idx = ((tail as usize) + i) % STAGING_BUFFER_CAPACITY;
            // SAFETY: This slot was written by the producer (idx is between
            // tail and head), so the MaybeUninit is initialized.
            *slot = unsafe { entries[idx].assume_init() };
        }

        // Advance tail. The Release pairs with the producer's Acquire load
        // of tail, ensuring the producer sees the freed slots.
        let new_tail = ((tail as usize + count) % STAGING_BUFFER_CAPACITY) as u32;
        self.tail.store(new_tail, Ordering::Release);

        count
    }

    /// Number of events currently in the buffer.
    ///
    /// This is a snapshot — the actual count may change immediately after
    /// this returns. Useful for diagnostics and testing.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head >= tail {
            (head - tail) as usize
        } else {
            (STAGING_BUFFER_CAPACITY as u32 - tail + head) as usize
        }
    }

    /// Whether the buffer is currently empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total number of events dropped due to buffer-full overflow.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Reset the dropped counter to zero, returning the previous value.
    ///
    /// Called by the drain task after emitting a synthetic `AuditDropped` event.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }

    /// The usable capacity of the buffer (one slot reserved for full/empty disambiguation).
    pub const fn usable_capacity() -> usize {
        STAGING_BUFFER_CAPACITY - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::RawAuditEvent;

    fn make_event(kind: u8) -> RawAuditEvent {
        let mut data = [0u8; 64];
        data[0] = kind;
        RawAuditEvent { data }
    }

    #[test]
    fn new_buffer_is_empty() {
        let buf = StagingBuffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.dropped(), 0);
    }

    #[test]
    fn push_single_event() {
        let buf = StagingBuffer::new();
        assert!(buf.push(make_event(1)));
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
    }

    #[test]
    fn push_and_drain_single() {
        let buf = StagingBuffer::new();
        buf.push(make_event(42));

        let mut out = [RawAuditEvent::ZERO; 4];
        let n = buf.drain_to(&mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].data[0], 42);
        assert!(buf.is_empty());
    }

    #[test]
    fn push_to_capacity() {
        let buf = StagingBuffer::new();
        let cap = StagingBuffer::usable_capacity();

        for i in 0..cap {
            assert!(buf.push(make_event(i as u8)), "push {i} should succeed");
        }
        assert_eq!(buf.len(), cap);

        // Next push should fail — buffer full
        assert!(!buf.push(make_event(0xFF)));
        assert_eq!(buf.dropped(), 1);
    }

    #[test]
    fn push_when_full_increments_dropped() {
        let buf = StagingBuffer::new();
        let cap = StagingBuffer::usable_capacity();

        // Fill the buffer
        for i in 0..cap {
            buf.push(make_event(i as u8));
        }

        // Drop 5 more
        for _ in 0..5 {
            assert!(!buf.push(make_event(0)));
        }
        assert_eq!(buf.dropped(), 5);
    }

    #[test]
    fn drain_returns_correct_events_in_order() {
        let buf = StagingBuffer::new();
        for i in 0..10u8 {
            buf.push(make_event(i));
        }

        let mut out = [RawAuditEvent::ZERO; 16];
        let n = buf.drain_to(&mut out);
        assert_eq!(n, 10);
        for i in 0..10u8 {
            assert_eq!(out[i as usize].data[0], i);
        }
    }

    #[test]
    fn drain_partial() {
        let buf = StagingBuffer::new();
        for i in 0..10u8 {
            buf.push(make_event(i));
        }

        // Drain only 4
        let mut out = [RawAuditEvent::ZERO; 4];
        let n = buf.drain_to(&mut out);
        assert_eq!(n, 4);
        assert_eq!(buf.len(), 6);

        // Drain remaining
        let mut out2 = [RawAuditEvent::ZERO; 16];
        let n2 = buf.drain_to(&mut out2);
        assert_eq!(n2, 6);
        assert!(buf.is_empty());
    }

    #[test]
    fn drain_empty_is_noop() {
        let buf = StagingBuffer::new();
        let mut out = [RawAuditEvent::ZERO; 4];
        assert_eq!(buf.drain_to(&mut out), 0);
    }

    #[test]
    fn drain_with_zero_len_output() {
        let buf = StagingBuffer::new();
        buf.push(make_event(1));
        let mut out = [];
        assert_eq!(buf.drain_to(&mut out), 0);
        assert_eq!(buf.len(), 1); // unchanged
    }

    #[test]
    fn wrap_around_push_and_drain() {
        let buf = StagingBuffer::new();
        let cap = StagingBuffer::usable_capacity();

        // Fill entirely
        for i in 0..cap {
            buf.push(make_event(i as u8));
        }

        // Drain all
        let mut out = [RawAuditEvent::ZERO; STAGING_BUFFER_CAPACITY];
        let n = buf.drain_to(&mut out);
        assert_eq!(n, cap);
        assert!(buf.is_empty());

        // Fill again — this exercises the wrap-around path
        for i in 0..cap {
            assert!(buf.push(make_event((i + 100) as u8)), "second fill push {i}");
        }
        assert_eq!(buf.len(), cap);

        // Drain and verify data integrity after wrap
        let mut out2 = [RawAuditEvent::ZERO; STAGING_BUFFER_CAPACITY];
        let n2 = buf.drain_to(&mut out2);
        assert_eq!(n2, cap);
        for i in 0..cap {
            assert_eq!(out2[i].data[0], ((i + 100) % 256) as u8);
        }
    }

    #[test]
    fn interleaved_push_drain() {
        let buf = StagingBuffer::new();

        // Simulate alternating producer/consumer pattern
        for round in 0..10u8 {
            // Push a batch
            for j in 0..5u8 {
                buf.push(make_event(round * 10 + j));
            }
            // Drain a batch
            let mut out = [RawAuditEvent::ZERO; 3];
            let n = buf.drain_to(&mut out);
            assert_eq!(n, 3);
        }

        // 10 rounds × 5 pushes = 50, 10 rounds × 3 drains = 30, so 20 remain
        assert_eq!(buf.len(), 20);
    }

    #[test]
    fn take_dropped_resets_counter() {
        let buf = StagingBuffer::new();
        let cap = StagingBuffer::usable_capacity();

        for i in 0..cap {
            buf.push(make_event(i as u8));
        }
        buf.push(make_event(0)); // dropped
        buf.push(make_event(0)); // dropped
        assert_eq!(buf.dropped(), 2);

        let prev = buf.take_dropped();
        assert_eq!(prev, 2);
        assert_eq!(buf.dropped(), 0);
    }

    #[test]
    fn usable_capacity_is_one_less_than_array() {
        assert_eq!(
            StagingBuffer::usable_capacity(),
            STAGING_BUFFER_CAPACITY - 1
        );
    }

    #[test]
    fn multiple_full_cycles() {
        let buf = StagingBuffer::new();
        let cap = StagingBuffer::usable_capacity();

        // Run 5 full fill-drain cycles to stress wrap-around
        for cycle in 0..5u32 {
            for i in 0..cap {
                let val = ((cycle * 100 + i as u32) % 256) as u8;
                assert!(buf.push(make_event(val)), "cycle {cycle} push {i}");
            }
            assert_eq!(buf.len(), cap);

            let mut out = [RawAuditEvent::ZERO; STAGING_BUFFER_CAPACITY];
            let n = buf.drain_to(&mut out);
            assert_eq!(n, cap);
            assert!(buf.is_empty());

            // Verify data
            for i in 0..cap {
                let expected = ((cycle * 100 + i as u32) % 256) as u8;
                assert_eq!(out[i].data[0], expected, "cycle {cycle} entry {i}");
            }
        }

        assert_eq!(buf.dropped(), 0);
    }

    #[test]
    fn len_at_various_fill_levels() {
        let buf = StagingBuffer::new();

        assert_eq!(buf.len(), 0);
        buf.push(make_event(0));
        assert_eq!(buf.len(), 1);

        for _ in 1..50 {
            buf.push(make_event(0));
        }
        assert_eq!(buf.len(), 50);

        let mut out = [RawAuditEvent::ZERO; 25];
        buf.drain_to(&mut out);
        assert_eq!(buf.len(), 25);
    }
}
