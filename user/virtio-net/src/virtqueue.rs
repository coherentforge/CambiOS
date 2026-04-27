// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Virtqueue implementation — the core virtio transport mechanism.
//!
//! This module contains the ONLY unsafe code in the virtio-net driver.
//! All raw pointer operations are for DMA ring buffer manipulation and
//! volatile accesses to shared device memory.
//!
//! ## Legacy virtio queue memory layout
//!
//! The legacy transport requires a single contiguous DMA allocation with:
//!   - Descriptor table at offset 0: queue_size × 16 bytes
//!   - Available ring immediately after: 6 + queue_size × 2 bytes
//!   - Used ring at the next page boundary: 6 + queue_size × 8 bytes
//!
//! The device is told the PFN (phys_addr / 4096) of this allocation.
//!
//! ## Hostile device model
//!
//! Every value read from the used ring is treated as attacker-controlled:
//! - Used ring indices are bounds-checked before use
//! - Returned descriptor indices are validated against queue size
//! - Returned lengths are clamped to the buffer size we originally posted
//!
//! Any violation triggers a device shutdown — no recovery attempted.

use crate::device::DeviceValue;
use cambios_libsys as sys;

/// Virtqueue descriptor (16 bytes, virtio spec §2.7.5).
#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Descriptor flag: buffer is device-writable (RX).
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Used ring element (8 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

/// Tracks a buffer we posted to the device.
#[derive(Clone, Copy)]
pub struct PendingBuffer {
    pub paddr: u64,
    pub vaddr: u64,
    pub len: u32,
    pub device_writable: bool,
}

/// Compute total pages needed for a legacy virtqueue.
fn legacy_queue_pages(queue_size: u16) -> usize {
    let qs = queue_size as usize;
    // desc + avail area: desc_bytes + avail_bytes, rounded up to page
    let desc_avail_bytes = qs * 16 + 6 + qs * 2;
    let desc_avail_pages = (desc_avail_bytes + 4095) / 4096;
    // used area: used_bytes, rounded up to page
    let used_bytes = 6 + qs * 8;
    let used_pages = (used_bytes + 4095) / 4096;
    desc_avail_pages + used_pages
}

/// Compute the byte offset of the used ring within the allocation.
fn used_ring_offset(queue_size: u16) -> usize {
    let qs = queue_size as usize;
    let desc_avail_bytes = qs * 16 + 6 + qs * 2;
    // Used ring starts at the next page boundary
    (desc_avail_bytes + 4095) & !4095
}

/// Maximum queue size we support. Kept small (32) to fit pending buffer
/// tracking on the user stack without a heap allocator. Two VirtQueues
/// with 32-entry pending arrays = 2 × 32 × 32 bytes = 2 KB.
pub const MAX_QUEUE_SIZE: u16 = 32;

/// A single virtqueue with hostile-device validation.
pub struct VirtQueue {
    /// Base virtual address of the contiguous allocation.
    base_vaddr: u64,
    /// Base physical address (told to the device as PFN).
    base_paddr: u64,

    /// Byte offsets from base for each ring component.
    avail_offset: usize,
    used_offset: usize,

    queue_size: u16,
    next_free_desc: u16,
    free_count: u16,
    last_used_idx: u16,
    avail_idx: u16,

    /// Tracking for posted buffers — validates device-returned indices.
    pending: [Option<PendingBuffer>; MAX_QUEUE_SIZE as usize],

    /// Device has been killed due to a validation failure.
    dead: bool,
}

impl VirtQueue {
    /// Allocate and initialize a legacy virtqueue.
    ///
    /// Allocates a single contiguous DMA region sized for the legacy layout.
    /// Returns `None` if allocation fails or queue_size exceeds MAX_QUEUE_SIZE.
    pub fn new(queue_size: u16) -> Option<Self> {
        if queue_size == 0 || queue_size > MAX_QUEUE_SIZE {
            return None;
        }

        let total_pages = legacy_queue_pages(queue_size);
        let mut base_paddr: u64 = 0;
        let ret = sys::alloc_dma(total_pages as u32, &mut base_paddr);
        if ret < 0 {
            return None;
        }
        let base_vaddr = ret as u64;

        let qs = queue_size as usize;
        let avail_offset = qs * 16; // avail ring starts right after descriptors
        let used_offset = used_ring_offset(queue_size);

        // Initialize free descriptor chain
        let desc_ptr = base_vaddr as *mut VirtqDesc;
        for i in 0..queue_size {
            let d = unsafe { &mut *desc_ptr.add(i as usize) };
            d.addr = 0;
            d.len = 0;
            d.flags = 0;
            d.next = if i + 1 < queue_size { i + 1 } else { 0xFFFF };
        }

        // Zero available ring header (flags=0, idx=0)
        let avail_base = base_vaddr + avail_offset as u64;
        unsafe {
            core::ptr::write_volatile(avail_base as *mut u16, 0); // flags
            core::ptr::write_volatile((avail_base + 2) as *mut u16, 0); // idx
        }

        // Zero used ring header (flags=0, idx=0)
        let used_base = base_vaddr + used_offset as u64;
        unsafe {
            core::ptr::write_volatile(used_base as *mut u16, 0); // flags
            core::ptr::write_volatile((used_base + 2) as *mut u16, 0); // idx
        }

        Some(VirtQueue {
            base_vaddr,
            base_paddr,
            avail_offset,
            used_offset,
            queue_size,
            next_free_desc: 0,
            free_count: queue_size,
            last_used_idx: 0,
            avail_idx: 0,
            pending: [None; MAX_QUEUE_SIZE as usize],
            dead: false,
        })
    }

    /// Physical page frame number (for legacy transport REG_QUEUE_PFN).
    pub fn pfn(&self) -> u32 {
        (self.base_paddr / 4096) as u32
    }

    /// Physical addresses of the three ring sub-regions within the
    /// contiguous allocation. Modern virtio transports report these as
    /// three independent 64-bit addresses via `set_queue_addrs`, unlike
    /// legacy's single-PFN register.
    ///
    /// Returns `(desc_phys, avail_phys, used_phys)`.
    pub fn ring_addrs(&self) -> (u64, u64, u64) {
        let qs = self.queue_size as u64;
        (
            self.base_paddr,
            self.base_paddr + qs * 16,
            self.base_paddr + self.used_offset as u64,
        )
    }

    /// Whether the device has been killed due to a protocol violation.
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// Post a single buffer to the device.
    ///
    /// Returns the descriptor index used, or `None` if the queue is full or dead.
    pub fn push_buffer(
        &mut self,
        paddr: u64,
        vaddr: u64,
        len: u32,
        device_writable: bool,
    ) -> Option<u16> {
        if self.dead || self.free_count == 0 {
            return None;
        }

        let desc_idx = self.next_free_desc;
        if desc_idx >= self.queue_size {
            return None; // Corrupt free list
        }

        let desc_ptr = self.base_vaddr as *mut VirtqDesc;
        let desc = unsafe { &mut *desc_ptr.add(desc_idx as usize) };

        self.next_free_desc = desc.next;
        self.free_count -= 1;

        desc.addr = paddr;
        desc.len = len;
        desc.flags = if device_writable { VIRTQ_DESC_F_WRITE } else { 0 };
        desc.next = 0;

        self.pending[desc_idx as usize] = Some(PendingBuffer {
            paddr,
            vaddr,
            len,
            device_writable,
        });

        // Write to available ring: ring entries start at offset 4 (after flags + idx)
        let avail_base = self.base_vaddr + self.avail_offset as u64;
        let ring_slot = self.avail_idx % self.queue_size;
        unsafe {
            let ring_ptr = (avail_base + 4) as *mut u16;
            core::ptr::write_volatile(ring_ptr.add(ring_slot as usize), desc_idx);
        }
        self.avail_idx = self.avail_idx.wrapping_add(1);

        // Update available ring index (device reads this)
        unsafe {
            core::ptr::write_volatile((avail_base + 2) as *mut u16, self.avail_idx);
        }

        Some(desc_idx)
    }

    /// Poll the used ring for completed buffers.
    ///
    /// Returns `Some((PendingBuffer, validated_len))` for each completed buffer,
    /// or `None` when there are no more. Kills the device on protocol violation.
    pub fn pop_used(&mut self) -> Option<(PendingBuffer, u32)> {
        if self.dead {
            return None;
        }

        let used_base = self.base_vaddr + self.used_offset as u64;

        // Read device's used ring index
        let device_idx = DeviceValue::new(unsafe {
            core::ptr::read_volatile((used_base + 2) as *const u16)
        });

        if self.last_used_idx == device_idx.raw() {
            return None; // No new entries
        }

        // Read the used element
        let ring_idx = self.last_used_idx % self.queue_size;
        let elem_ptr = (used_base + 4) as *const VirtqUsedElem;
        let elem = unsafe { core::ptr::read_volatile(elem_ptr.add(ring_idx as usize)) };

        // VALIDATE: descriptor index within queue bounds
        let validated_idx = match DeviceValue::new(elem.id as u16).validate_index(self.queue_size) {
            Some(idx) => idx,
            None => {
                self.dead = true;
                sys::print(b"[NET] DEVICE KILLED: used ring index out of bounds\n");
                return None;
            }
        };

        // VALIDATE: we actually posted this descriptor
        let pending = match self.pending[validated_idx as usize].take() {
            Some(p) => p,
            None => {
                self.dead = true;
                sys::print(b"[NET] DEVICE KILLED: descriptor not pending\n");
                return None;
            }
        };

        // VALIDATE: clamp returned length
        let validated_len = DeviceValue::new(elem.len).clamp_length(pending.len);

        // Return descriptor to free list
        let desc_ptr = self.base_vaddr as *mut VirtqDesc;
        let desc = unsafe { &mut *desc_ptr.add(validated_idx as usize) };
        desc.next = self.next_free_desc;
        self.next_free_desc = validated_idx;
        self.free_count += 1;

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        Some((pending, validated_len))
    }

    /// Number of free descriptors.
    pub fn free_descriptors(&self) -> u16 {
        self.free_count
    }
}

/// A pre-allocated bounce buffer for DMA.
pub struct BounceBuffer {
    pub vaddr: u64,
    pub paddr: u64,
    pub size: u32,
}

impl BounceBuffer {
    /// Allocate a single-page (4096 byte) bounce buffer via DMA.
    pub fn new() -> Option<Self> {
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut paddr);
        if ret < 0 {
            return None;
        }
        Some(BounceBuffer {
            vaddr: ret as u64,
            paddr,
            size: 4096,
        })
    }

    /// Write data into the bounce buffer. Returns bytes written (clamped to size).
    pub fn write(&self, data: &[u8]) -> usize {
        let len = core::cmp::min(data.len(), self.size as usize);
        let dst = self.vaddr as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, len);
        }
        len
    }

    /// Read data from the bounce buffer into `dst`. Returns bytes read (clamped).
    pub fn read(&self, dst: &mut [u8], len: usize) -> usize {
        let actual = core::cmp::min(core::cmp::min(len, dst.len()), self.size as usize);
        let src = self.vaddr as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), actual);
        }
        actual
    }

    /// Zero the buffer.
    pub fn zero(&self) {
        unsafe {
            core::ptr::write_bytes(self.vaddr as *mut u8, 0, self.size as usize);
        }
    }
}
