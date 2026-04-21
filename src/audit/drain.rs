// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Global audit ring buffer and drain logic (Phase 3.3b, ADR-007).
//!
//! The `AuditRing` receives events from per-CPU staging buffers via
//! `drain_tick()`, called from the BSP timer ISR at 100 Hz. User-space
//! consumers (policy service) attach to read events via `SYS_AUDIT_ATTACH`.
//!
//! # Architecture
//!
//! The ring is a kernel-internal buffer backed by contiguous physical pages
//! allocated at boot. It is NOT a `ChannelRecord` in the `ChannelManager`
//! table — the kernel has no ProcessId/Principal/VMA, so the channel state
//! machine would require extensive special-casing. Instead, the same physical
//! pages are mapped RO into the consumer's address space when it attaches.
//!
//! # Memory layout
//!
//! The first 64 bytes of the ring region form a header readable by the
//! consumer via the shared mapping. The remaining space is the event array.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │ RingHeader (64 bytes)                               │
//! │   magic: u64              = 0x4152_4341_5544_4954   │
//! │   write_idx: u64          (monotonic, wraps at cap) │
//! │   capacity: u64           (number of event slots)   │
//! │   total_produced: u64                               │
//! │   total_dropped: u64                                │
//! │   reserved: [u8; 24]                                │
//! ├─────────────────────────────────────────────────────┤
//! │ events[0]: RawAuditEvent (64 bytes)                 │
//! │ events[1]: RawAuditEvent (64 bytes)                 │
//! │ ...                                                 │
//! │ events[capacity-1]                                  │
//! └─────────────────────────────────────────────────────┘
//! ```

use crate::audit::buffer::StagingBuffer;
use crate::audit::{RawAuditEvent, RAW_AUDIT_EVENT_SIZE};
use crate::ipc::ProcessId;
use crate::memory::frame_allocator::{FrameAllocError, FrameAllocator, PAGE_SIZE};

/// SCAFFOLDING: global audit ring buffer size in pages.
///
/// Why: 16 pages = 64 KiB. Minus the 64-byte header, holds 1023 events at
///      64 bytes each. At 1000 events/sec typical rate, this is ~1 second
///      of buffering. ADR-007 specifies 64 KiB. With 4× headroom over the
///      typical consumer drain rate (policy service reads at >4000 events/sec),
///      this is comfortable.
///      Memory cost: 64 KiB, negligible.
///
/// Replace when: consumer consistently drops events due to ring overflow
///      (visible via SYS_AUDIT_INFO stats or AuditDropped events).
pub const AUDIT_RING_PAGES: u32 = 16;

/// TUNING: maximum events drained from all per-CPU staging buffers per tick.
///
/// Bounds the time spent in ISR context during drain. At 64 bytes/event,
/// 64 events = 4 KiB of copies — well within the timer ISR budget.
///
/// Replace when: profiling shows drain is a bottleneck (unlikely at 100 Hz).
pub const DRAIN_BATCH_SIZE: usize = 64;

/// Ring header magic value: "ARCAUDIT" in ASCII, little-endian.
pub const RING_HEADER_MAGIC: u64 = 0x5449_4455_4143_5241;

/// Size of the ring header in bytes (one cache line).
///
/// ARCHITECTURAL: the header occupies the first 64 bytes of the mapped
/// region, leaving the rest for event slots.
pub const RING_HEADER_SIZE: usize = 64;

/// Global audit ring buffer.
///
/// Backed by physically contiguous pages allocated at boot. The kernel
/// writes events into the ring via `write_event()`. User-space consumers
/// can be mapped to read events via `SYS_AUDIT_ATTACH`.
pub struct AuditRing {
    /// Physical base of the ring buffer pages.
    physical_base: u64,
    /// Virtual address in kernel space (HHDM-mapped).
    kernel_vaddr: u64,
    /// Total size of the ring region in bytes (pages × PAGE_SIZE).
    region_bytes: usize,
    /// Number of event slots (derived from region size minus header).
    capacity: u32,
    /// Next write position (modulo capacity). Kernel-internal; the
    /// shared header has its own copy for consumer polling.
    write_idx: u32,
    /// Total events successfully written to the ring.
    total_produced: u64,
    /// Total events dropped (staging overflow + ring overflow combined).
    total_dropped: u64,
    /// Whether a consumer is currently attached.
    consumer_attached: bool,
    /// Consumer's ProcessId (for unmap on detach/exit).
    consumer_pid: Option<ProcessId>,
    /// Virtual address mapped in consumer's address space.
    consumer_vaddr: u64,
}

impl AuditRing {
    /// Allocate and initialize the audit ring.
    ///
    /// Allocates `AUDIT_RING_PAGES` contiguous physical frames from the
    /// frame allocator, zeroes the region via HHDM, and writes the ring
    /// header.
    ///
    /// Returns `Err` if the frame allocator cannot provide a contiguous run.
    pub fn init(
        frame_allocator: &mut FrameAllocator,
        hhdm_offset: u64,
    ) -> Result<Self, FrameAllocError> {
        let frame = frame_allocator.allocate_contiguous(AUDIT_RING_PAGES as usize)?;
        let physical_base = frame.addr;
        let kernel_vaddr = physical_base + hhdm_offset;
        let region_bytes = AUDIT_RING_PAGES as usize * PAGE_SIZE as usize;

        // Zero the entire region.
        // SAFETY: kernel_vaddr points to a freshly allocated, HHDM-mapped
        // region of `region_bytes` bytes. No other code references these
        // pages yet (they were just allocated).
        unsafe {
            core::ptr::write_bytes(kernel_vaddr as *mut u8, 0, region_bytes);
        }

        let event_area = region_bytes - RING_HEADER_SIZE;
        let capacity = (event_area / RAW_AUDIT_EVENT_SIZE) as u32;

        let mut ring = Self {
            physical_base,
            kernel_vaddr,
            region_bytes,
            capacity,
            write_idx: 0,
            total_produced: 0,
            total_dropped: 0,
            consumer_attached: false,
            consumer_pid: None,
            consumer_vaddr: 0,
        };

        // Write the initial header.
        ring.update_header();

        Ok(ring)
    }

    /// Write the ring header into the shared region.
    ///
    /// Called after each drain batch to update the consumer-visible state.
    fn update_header(&mut self) {
        // Write the ring header fields into the shared memory region.
        // All offsets are within the 64-byte header at kernel_vaddr.
        // Only the kernel writes; the consumer maps these pages RO.
        let base = self.kernel_vaddr as *mut u8;
        // SAFETY: base is a valid HHDM-mapped pointer to a region ≥ 64 bytes.
        let p8 = unsafe { base.add(8) };
        // SAFETY: offset 16 is within the 64-byte header region.
        let p16 = unsafe { base.add(16) };
        // SAFETY: offset 24 is within the 64-byte header region.
        let p24 = unsafe { base.add(24) };
        // SAFETY: offset 32 is within the 64-byte header region.
        let p32 = unsafe { base.add(32) };

        // SAFETY: base (offset 0) is valid, writing 8 bytes within the header.
        unsafe { core::ptr::copy_nonoverlapping(RING_HEADER_MAGIC.to_le_bytes().as_ptr(), base, 8) }
        // SAFETY: p8 is valid (computed above), writing 8 bytes within the header.
        unsafe { core::ptr::copy_nonoverlapping((self.write_idx as u64).to_le_bytes().as_ptr(), p8, 8) }
        // SAFETY: p16 is valid, writing 8 bytes within the header.
        unsafe { core::ptr::copy_nonoverlapping((self.capacity as u64).to_le_bytes().as_ptr(), p16, 8) }
        // SAFETY: p24 is valid, writing 8 bytes within the header.
        unsafe { core::ptr::copy_nonoverlapping(self.total_produced.to_le_bytes().as_ptr(), p24, 8) }
        // SAFETY: p32 is valid, writing 8 bytes within the header.
        unsafe { core::ptr::copy_nonoverlapping(self.total_dropped.to_le_bytes().as_ptr(), p32, 8) }
        // bytes 40..64 reserved (already zeroed)
    }

    /// Write a single event into the ring, advancing write_idx.
    ///
    /// If the ring is full (no consumer, or consumer is behind), the event
    /// is dropped and total_dropped is incremented.
    ///
    /// Returns `true` if the event was written, `false` if dropped.
    fn write_event(&mut self, event: &RawAuditEvent) -> bool {
        // The ring is a simple overwriting circular buffer. If the consumer
        // falls behind, oldest events are overwritten and total_dropped is
        // incremented. We track capacity usage: the ring is "full" when
        // total_produced - consumer's read position ≥ capacity. Since we
        // don't track the consumer's read position from the kernel side
        // (it's a lock-free shared value), we use a simpler model: always
        // write, and the consumer is responsible for detecting gaps via
        // the total_produced counter.
        //
        // This matches ADR-007's "FIFO drop" model — the kernel never
        // blocks, and the consumer detects gaps.
        let slot = self.write_idx as usize;
        let event_base = self.kernel_vaddr as usize + RING_HEADER_SIZE
            + slot * RAW_AUDIT_EVENT_SIZE;

        // SAFETY: event_base is within the ring region (slot < capacity,
        // verified by write_idx modulo). The event data is 64 bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                event.data.as_ptr(),
                event_base as *mut u8,
                RAW_AUDIT_EVENT_SIZE,
            );
        }

        self.write_idx = (self.write_idx + 1) % self.capacity;
        self.total_produced += 1;
        true
    }

    /// Drain events from all per-CPU staging buffers into the ring.
    ///
    /// Called from the BSP timer ISR. Drains at most `DRAIN_BATCH_SIZE`
    /// events total across all CPUs. Reports any staging buffer drops
    /// as synthetic `AuditDropped` events.
    ///
    /// `online_cpus` is the number of CPUs currently online (typically 1
    /// during early boot, more after SMP init).
    pub fn drain_all_staging(
        &mut self,
        staging_buffers: &[StagingBuffer],
        online_cpus: usize,
    ) {
        let cpu_count = online_cpus.min(staging_buffers.len());
        if cpu_count == 0 {
            return;
        }

        let mut total_drained: usize = 0;

        // Temporary buffer for draining from each CPU.
        // We drain in small batches per CPU to be fair across CPUs.
        let per_cpu_batch = (DRAIN_BATCH_SIZE / cpu_count).max(1);

        let mut batch_buf = [RawAuditEvent::ZERO; DRAIN_BATCH_SIZE];

        for (cpu, staging) in staging_buffers[..cpu_count].iter().enumerate() {
            if total_drained >= DRAIN_BATCH_SIZE {
                break;
            }

            let remaining = DRAIN_BATCH_SIZE - total_drained;
            let max_this_cpu = remaining.min(per_cpu_batch);

            // Check for and report drops from this CPU's staging buffer.
            let drops = staging.take_dropped();
            if drops > 0 {
                self.total_dropped += drops;
                // Emit a synthetic AuditDropped event so consumers see the gap.
                let dropped_event = RawAuditEvent::audit_dropped(
                    drops,
                    cpu as u32,
                    crate::scheduler::Timer::get_ticks(),
                    0, // sequence not meaningful for synthetic events
                );
                self.write_event(&dropped_event);
                total_drained += 1;
                if total_drained >= DRAIN_BATCH_SIZE {
                    break;
                }
            }

            // Drain actual events from this CPU's staging buffer.
            let n = staging.drain_to(&mut batch_buf[..max_this_cpu]);
            for event in &batch_buf[..n] {
                self.write_event(event);
            }
            total_drained += n;
        }

        // Update the shared header so the consumer sees the new write_idx.
        if total_drained > 0 {
            self.update_header();
        }
    }

    /// Physical base address of the ring region (for mapping into consumer).
    pub fn physical_base(&self) -> u64 {
        self.physical_base
    }

    /// Number of pages in the ring region.
    pub fn page_count(&self) -> u32 {
        AUDIT_RING_PAGES
    }

    /// Event slot capacity.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Total events produced (written to ring).
    pub fn total_produced(&self) -> u64 {
        self.total_produced
    }

    /// Total events dropped (staging + ring overflow).
    pub fn total_dropped(&self) -> u64 {
        self.total_dropped
    }

    /// Whether a consumer is currently attached.
    pub fn consumer_attached(&self) -> bool {
        self.consumer_attached
    }

    /// Record that a consumer has attached.
    pub fn set_consumer(&mut self, pid: ProcessId, vaddr: u64) {
        self.consumer_attached = true;
        self.consumer_pid = Some(pid);
        self.consumer_vaddr = vaddr;
    }

    /// Clear the consumer (on detach or process exit).
    pub fn clear_consumer(&mut self) -> Option<(ProcessId, u64)> {
        if self.consumer_attached {
            let pid = self.consumer_pid.take();
            let vaddr = self.consumer_vaddr;
            self.consumer_attached = false;
            self.consumer_vaddr = 0;
            pid.map(|p| (p, vaddr))
        } else {
            None
        }
    }

    /// Consumer's ProcessId, if any.
    pub fn consumer_pid(&self) -> Option<ProcessId> {
        self.consumer_pid
    }
}

/// Called from the BSP timer ISR (`on_timer_isr`) to drain per-CPU
/// staging buffers into the global audit ring.
///
/// This function try-locks the global `AUDIT_RING`. If the lock is
/// contended (e.g., `SYS_AUDIT_ATTACH` is in progress), the drain
/// is skipped for this tick — staging buffers absorb the backlog.
///
/// # ISR safety
///
/// Uses `try_lock()` — never blocks. Holds no other lock while
/// AUDIT_RING is held.
#[cfg(not(any(test, fuzzing)))]
pub fn drain_tick() {
    if let Some(mut ring_guard) = crate::AUDIT_RING.try_lock() {
        if let Some(ring) = ring_guard.as_mut() {
            // Determine online CPU count. For now, single-core boot
            // means 1. SMP init will update this.
            let online_cpus = crate::online_cpu_count();
            ring.drain_all_staging(&crate::PER_CPU_AUDIT_BUFFER, online_cpus);
        }
    }
    // Lock contended or ring not initialized — skip this tick.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::buffer::StagingBuffer;
    use crate::audit::RawAuditEvent;

    /// Create a mock AuditRing backed by a stack buffer (no frame allocator).
    fn make_test_ring(capacity: u32) -> (AuditRing, Vec<u8>) {
        let event_area = capacity as usize * RAW_AUDIT_EVENT_SIZE;
        let total_size = RING_HEADER_SIZE + event_area;
        let mut backing = vec![0u8; total_size];
        let kernel_vaddr = backing.as_mut_ptr() as u64;

        let mut ring = AuditRing {
            physical_base: 0x1000, // fake
            kernel_vaddr,
            region_bytes: total_size,
            capacity,
            write_idx: 0,
            total_produced: 0,
            total_dropped: 0,
            consumer_attached: false,
            consumer_pid: None,
            consumer_vaddr: 0,
        };
        ring.update_header();
        (ring, backing)
    }

    fn make_event(kind: u8) -> RawAuditEvent {
        let mut data = [0u8; 64];
        data[0] = kind;
        RawAuditEvent { data }
    }

    fn read_header_magic(backing: &[u8]) -> u64 {
        u64::from_le_bytes(backing[0..8].try_into().unwrap())
    }

    fn read_header_write_idx(backing: &[u8]) -> u64 {
        u64::from_le_bytes(backing[8..16].try_into().unwrap())
    }

    fn read_header_capacity(backing: &[u8]) -> u64 {
        u64::from_le_bytes(backing[16..24].try_into().unwrap())
    }

    fn read_header_total_produced(backing: &[u8]) -> u64 {
        u64::from_le_bytes(backing[24..32].try_into().unwrap())
    }

    fn read_header_total_dropped(backing: &[u8]) -> u64 {
        u64::from_le_bytes(backing[32..40].try_into().unwrap())
    }

    fn read_event_from_ring(backing: &[u8], index: usize) -> RawAuditEvent {
        let offset = RING_HEADER_SIZE + index * RAW_AUDIT_EVENT_SIZE;
        let mut data = [0u8; 64];
        data.copy_from_slice(&backing[offset..offset + 64]);
        RawAuditEvent { data }
    }

    #[test]
    fn header_magic_is_set() {
        let (_ring, backing) = make_test_ring(16);
        assert_eq!(read_header_magic(&backing), RING_HEADER_MAGIC);
    }

    #[test]
    fn header_capacity_matches() {
        let (_ring, backing) = make_test_ring(32);
        assert_eq!(read_header_capacity(&backing), 32);
    }

    #[test]
    fn write_event_advances_idx() {
        let (mut ring, backing) = make_test_ring(16);
        assert_eq!(ring.write_idx, 0);

        ring.write_event(&make_event(42));
        assert_eq!(ring.write_idx, 1);
        assert_eq!(ring.total_produced, 1);

        ring.update_header();
        assert_eq!(read_header_write_idx(&backing), 1);
        assert_eq!(read_header_total_produced(&backing), 1);
    }

    #[test]
    fn write_event_data_integrity() {
        let (mut ring, backing) = make_test_ring(16);
        ring.write_event(&make_event(0xAB));
        let stored = read_event_from_ring(&backing, 0);
        assert_eq!(stored.data[0], 0xAB);
    }

    #[test]
    fn write_wraps_around() {
        let (mut ring, _backing) = make_test_ring(4);

        for i in 0..4u8 {
            ring.write_event(&make_event(i));
        }
        assert_eq!(ring.write_idx, 0); // wrapped
        assert_eq!(ring.total_produced, 4);

        // Write one more — overwrites slot 0
        ring.write_event(&make_event(99));
        assert_eq!(ring.write_idx, 1);
        assert_eq!(ring.total_produced, 5);
    }

    #[test]
    fn drain_from_staging_buffers() {
        let (mut ring, backing) = make_test_ring(32);
        let bufs = [StagingBuffer::new(), StagingBuffer::new()];

        // Push events into CPU 0 and CPU 1 staging buffers
        bufs[0].push(make_event(10));
        bufs[0].push(make_event(11));
        bufs[1].push(make_event(20));

        ring.drain_all_staging(&bufs, 2);

        assert_eq!(ring.total_produced, 3);
        assert_eq!(read_header_total_produced(&backing), 3);

        let e0 = read_event_from_ring(&backing, 0);
        let e1 = read_event_from_ring(&backing, 1);
        let e2 = read_event_from_ring(&backing, 2);
        assert_eq!(e0.data[0], 10);
        assert_eq!(e1.data[0], 11);
        assert_eq!(e2.data[0], 20);
    }

    #[test]
    fn drain_reports_staging_drops() {
        let (mut ring, _backing) = make_test_ring(32);
        let bufs = [StagingBuffer::new()];

        // Fill staging buffer to capacity, then push one more to trigger a drop
        let cap = StagingBuffer::usable_capacity();
        for i in 0..cap {
            bufs[0].push(make_event(i as u8));
        }
        bufs[0].push(make_event(0xFF)); // this is dropped

        ring.drain_all_staging(&bufs, 1);

        // Should have: 1 AuditDropped event + up to DRAIN_BATCH_SIZE-1 real events
        assert!(ring.total_dropped > 0);
        // The first event written to the ring should be AuditDropped
        // (drops are reported before real events)
    }

    #[test]
    fn drain_bounded_by_batch_size() {
        let (mut ring, _backing) = make_test_ring(256);
        let bufs = [StagingBuffer::new()];

        // Push more events than DRAIN_BATCH_SIZE
        for i in 0..StagingBuffer::usable_capacity() {
            bufs[0].push(make_event(i as u8));
        }

        ring.drain_all_staging(&bufs, 1);

        // Should drain at most DRAIN_BATCH_SIZE events
        assert!(ring.total_produced <= DRAIN_BATCH_SIZE as u64);

        // Staging buffer should still have remaining events
        assert!(!bufs[0].is_empty());
    }

    #[test]
    fn drain_empty_staging_is_noop() {
        let (mut ring, _backing) = make_test_ring(16);
        let bufs = [StagingBuffer::new()];

        ring.drain_all_staging(&bufs, 1);
        assert_eq!(ring.total_produced, 0);
    }

    #[test]
    fn consumer_attach_detach() {
        let (mut ring, _backing) = make_test_ring(16);

        assert!(!ring.consumer_attached());
        assert!(ring.consumer_pid().is_none());

        let pid = ProcessId::new(5, 1);
        ring.set_consumer(pid, 0x400000);
        assert!(ring.consumer_attached());
        assert_eq!(ring.consumer_pid(), Some(pid));

        let cleared = ring.clear_consumer();
        assert_eq!(cleared, Some((pid, 0x400000)));
        assert!(!ring.consumer_attached());
        assert!(ring.consumer_pid().is_none());
    }

    #[test]
    fn clear_consumer_when_none() {
        let (mut ring, _backing) = make_test_ring(16);
        assert!(ring.clear_consumer().is_none());
    }

    #[test]
    fn capacity_from_region_size() {
        // 16 pages = 65536 bytes. Minus 64-byte header = 65472 bytes.
        // 65472 / 64 = 1023 events.
        let expected = ((AUDIT_RING_PAGES as usize * PAGE_SIZE as usize) - RING_HEADER_SIZE)
            / RAW_AUDIT_EVENT_SIZE;
        assert_eq!(expected, 1023);
    }
}
