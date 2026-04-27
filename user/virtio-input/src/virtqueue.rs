// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Device-writable event ring for virtio-input.
//!
//! virtio-input's `eventq` (queue 0) is filled with device-writable
//! descriptors. The device writes incoming events into the buffers
//! those descriptors point at; the driver polls the used ring for
//! completions, processes each 8-byte event, then returns the
//! descriptor (re-adds it to the avail ring) so the device can reuse
//! the slot.
//!
//! This is a different shape from the scanout-virtio-gpu transport's
//! two-descriptor command+response chain, so the queue is specialised
//! here rather than sharing a virtqueue module. Each descriptor is a
//! single 8-byte writable buffer (`virtio_input_event` per spec §5.8).

use cambios_libsys as sys;

use crate::transport::ModernTransport;

/// SCAFFOLDING: queue depth in descriptors. Sized for bursty typing
/// and high-rate mouse motion: at 1000 Hz pointer events (typical
/// gaming mouse) with a 100 Hz driver poll tick, the device can
/// queue up to 10 events per tick, comfortably within 64. Power of
/// two per virtio spec. Replace when: a driver poll cycle routinely
/// observes queue saturation (all 64 slots in the used ring before
/// we drain), at which point IRQ-driven wake is the better fix
/// (smaller ring, tighter latency) not a bigger ring.
pub const EVENTQ_SIZE: u16 = 64;

/// ARCHITECTURAL: size of one virtio_input_event (spec §5.8,
/// identical to Linux evdev `struct input_event` in its 8-byte
/// packed form).
pub const EVENT_BYTES: u16 = 8;

/// DMA-page layout. One 4 KiB page covers all four regions with room
/// to spare. Offsets chosen so each region starts at a
/// power-of-two-aligned boundary; padding space is never touched by
/// either side.
const DESC_OFFSET: usize = 0;      // 64 × 16 B = 1024 B → [0..1024)
const AVAIL_OFFSET: usize = 1024;  // 4 + 64 × 2 = 132 B → [1024..1280)
const USED_OFFSET: usize = 1280;   // 4 + 64 × 8 = 516 B → [1280..1808)
const EVENTS_OFFSET: usize = 2048; // 64 × 8 = 512 B → [2048..2560)

pub const VIRTQ_DESC_F_WRITE: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

/// One decoded evdev event from the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvdevEvent {
    pub etype: u16,
    pub code: u16,
    pub value: u32,
}

/// Descriptor-ring pool with per-slot pre-allocated 8-byte buffers.
/// Bootstraps by publishing all `EVENTQ_SIZE` descriptors; each
/// completed event is returned to the device via [`EventRing::refill`].
pub struct EventRing {
    base_vaddr: u64,
    base_paddr: u64,
    avail_idx: u16,
    last_used_idx: u16,
}

impl EventRing {
    /// Allocate the ring + event buffers, publish all descriptors, and
    /// register the addresses with the selected virtqueue. Returns the
    /// queue notify offset so the caller can reach `transport.notify()`.
    pub fn new(transport: &ModernTransport, queue_index: u16) -> Option<(Self, u16)> {
        let mut base_paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut base_paddr);
        if ret < 0 {
            return None;
        }
        let base_vaddr = ret as u64;
        // SAFETY: alloc_dma returned a page-sized region at base_vaddr.
        unsafe {
            core::ptr::write_bytes(base_vaddr as *mut u8, 0, 4096);
        }

        let mut ring = Self {
            base_vaddr,
            base_paddr,
            avail_idx: 0,
            last_used_idx: 0,
        };

        // Publish descriptors: each points at its per-slot 8-byte buffer.
        for i in 0..EVENTQ_SIZE {
            // SAFETY: i < EVENTQ_SIZE so offsets stay inside the desc
            // table (1024 B) and events region (512 B at +2048).
            unsafe {
                let desc = ring.desc_ptr().add(i as usize);
                let buf_paddr = base_paddr + EVENTS_OFFSET as u64
                    + (i as u64) * (EVENT_BYTES as u64);
                core::ptr::write_volatile(
                    desc,
                    VirtqDesc {
                        addr: buf_paddr,
                        len: EVENT_BYTES as u32,
                        flags: VIRTQ_DESC_F_WRITE,
                        next: 0,
                    },
                );
                // avail.ring[i] = i (descriptor index matches slot index
                // for v0 — simplest mapping).
                core::ptr::write_volatile(ring.avail_ring_ptr().add(i as usize), i);
            }
        }
        // Publish avail.idx after all ring writes.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        ring.avail_idx = EVENTQ_SIZE;
        // SAFETY: avail_idx_ptr points at the avail ring's `idx` field,
        // well within the allocated page.
        unsafe {
            core::ptr::write_volatile(ring.avail_idx_ptr(), ring.avail_idx);
        }

        // Register the queue with the device.
        transport.select_queue(queue_index);
        let device_qsize = transport.queue_size();
        if device_qsize == 0 {
            return None;
        }
        transport.set_queue_size(EVENTQ_SIZE);

        let (desc, driver, device) = ring.ring_addrs();
        transport.set_queue_addrs(desc, driver, device);
        let notify_off = transport.queue_notify_off();
        transport.enable_queue();

        Some((ring, notify_off))
    }

    fn ring_addrs(&self) -> (u64, u64, u64) {
        (
            self.base_paddr + DESC_OFFSET as u64,
            self.base_paddr + AVAIL_OFFSET as u64,
            self.base_paddr + USED_OFFSET as u64,
        )
    }

    fn desc_ptr(&self) -> *mut VirtqDesc {
        (self.base_vaddr + DESC_OFFSET as u64) as *mut VirtqDesc
    }

    fn avail_idx_ptr(&self) -> *mut u16 {
        (self.base_vaddr + AVAIL_OFFSET as u64 + 2) as *mut u16
    }

    fn avail_ring_ptr(&self) -> *mut u16 {
        (self.base_vaddr + AVAIL_OFFSET as u64 + 4) as *mut u16
    }

    fn used_idx_ptr(&self) -> *const u16 {
        (self.base_vaddr + USED_OFFSET as u64 + 2) as *const u16
    }

    fn used_ring_ptr(&self) -> *const VirtqUsedElem {
        (self.base_vaddr + USED_OFFSET as u64 + 4) as *const VirtqUsedElem
    }

    fn event_slot_ptr(&self, slot: u16) -> *const u8 {
        (self.base_vaddr + EVENTS_OFFSET as u64 + (slot as u64) * (EVENT_BYTES as u64))
            as *const u8
    }

    /// Poll the used ring for the next completed event. Returns the
    /// decoded 8-byte event plus the descriptor index that must be
    /// passed to [`refill`] once the caller has consumed the event.
    pub fn poll_used(&mut self) -> Option<(EvdevEvent, u16)> {
        // SAFETY: used.idx is a u16 at USED_OFFSET+2.
        let device_idx = unsafe { core::ptr::read_volatile(self.used_idx_ptr()) };
        if device_idx == self.last_used_idx {
            return None;
        }
        let slot = (self.last_used_idx % EVENTQ_SIZE) as usize;
        // SAFETY: slot < EVENTQ_SIZE keeps us inside the used ring
        // (516 B allocated).
        let elem = unsafe { core::ptr::read_volatile(self.used_ring_ptr().add(slot)) };
        let desc_id = elem.id as u16;
        if desc_id >= EVENTQ_SIZE {
            // Malformed used entry. Still advance our index so we
            // don't spin; skip the event.
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            return None;
        }
        // SAFETY: desc_id < EVENTQ_SIZE indexes into the 64-slot event
        // buffer region at EVENTS_OFFSET (512 B allocated).
        let event = unsafe {
            let p = self.event_slot_ptr(desc_id);
            EvdevEvent {
                etype: core::ptr::read_volatile(p as *const u16),
                code: core::ptr::read_volatile(p.add(2) as *const u16),
                value: core::ptr::read_volatile(p.add(4) as *const u32),
            }
        };
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((event, desc_id))
    }

    /// Return a descriptor to the device so its buffer can be reused
    /// for a future event. Must be called exactly once per
    /// [`poll_used`] that returned `Some`.
    pub fn refill(&mut self, transport: &ModernTransport, notify_off: u16, desc_id: u16) {
        let slot = self.avail_idx % EVENTQ_SIZE;
        // SAFETY: slot < EVENTQ_SIZE keeps us inside the avail ring.
        unsafe {
            core::ptr::write_volatile(self.avail_ring_ptr().add(slot as usize), desc_id);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // SAFETY: avail_idx_ptr is 2 bytes at AVAIL_OFFSET+2.
        unsafe {
            core::ptr::write_volatile(self.avail_idx_ptr(), self.avail_idx);
        }
        // Notify — virtio allows the device to skip re-reading avail
        // if it's still chewing through prior descriptors, but there's
        // no harm in notifying every refill at our low rates.
        transport.notify(0, notify_off);
    }
}
