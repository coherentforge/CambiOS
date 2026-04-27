// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Virtio-blk virtqueue with descriptor-chain support.
//!
//! Virtio-blk differs from virtio-net in one important way: every request is a
//! *chain* of three descriptors, not a single buffer —
//!
//!   head → request header (read-only, 16 B)
//!        → data buffer    (read-only for writes, write-only for reads)
//!        → status byte    (write-only, 1 B)
//!
//! The driver posts only the head descriptor index to the available ring;
//! the device walks the chain via each descriptor's `next` field.
//!
//! This module contains the ONLY unsafe code in the virtio-blk driver. All
//! raw pointer operations are for DMA ring manipulation and volatile accesses
//! to shared device memory.
//!
//! ## Hostile device model
//!
//! Same posture as virtio-net: every device-returned value (used-ring
//! indices, descriptor lengths) passes through `DeviceValue<T>` before use.
//! Protocol violations kill the device — no recovery attempted.

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

/// Descriptor flags.
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Used ring element (8 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

/// One segment of a descriptor chain.
#[derive(Clone, Copy)]
pub struct ChainSegment {
    pub paddr: u64,
    pub len: u32,
    /// `true` = device writes this segment (read data, status byte).
    /// `false` = device reads this segment (request header, write data).
    pub device_writable: bool,
}

/// Tracks a chain we posted to the device, keyed by head descriptor index.
#[derive(Clone, Copy)]
struct ChainPending {
    /// Number of descriptors linked from the head (including the head).
    length: u8,
    /// Sum of per-segment `len` values — used to clamp the device-returned
    /// `used_len` before we hand it back to the caller.
    total_len: u32,
}

/// Max descriptors per chain. Virtio-blk needs exactly 3 (header + data +
/// status); leaving room for 4 is cheap headroom in case a future feature
/// requires another segment.
pub const MAX_CHAIN_LEN: usize = 4;

/// Compute total pages needed for a legacy virtqueue with the given size.
fn legacy_queue_pages(queue_size: u16) -> usize {
    let qs = queue_size as usize;
    let desc_avail_bytes = qs * 16 + 6 + qs * 2;
    let desc_avail_pages = desc_avail_bytes.div_ceil(4096);
    let used_bytes = 6 + qs * 8;
    let used_pages = used_bytes.div_ceil(4096);
    desc_avail_pages + used_pages
}

fn used_ring_offset(queue_size: u16) -> usize {
    let qs = queue_size as usize;
    let desc_avail_bytes = qs * 16 + 6 + qs * 2;
    (desc_avail_bytes + 4095) & !4095
}

/// Maximum queue size we support.
///
/// The virtio 0.9.x/1.0 LEGACY transport's Queue Size register at offset 0x0C
/// is **read-only** — it reports the device's chosen queue size, and the
/// driver has no mechanism to shrink it. Every avail-ring and used-ring
/// offset on both sides of the interface is computed from this single size.
/// If the driver uses a smaller local queue than the device expects, the
/// device writes the used ring at a larger offset than where the driver
/// reads it — completions appear to "never happen."
///
/// QEMU's virtio-blk-pci advertises a queue size of 128; virtio-net-pci
/// tends to advertise 256. Sized to the larger one so neither driver
/// clamps. Memory cost: one `[Option<ChainPending>; 256]` (~4 KiB) per
/// virtqueue instance.
pub const MAX_QUEUE_SIZE: u16 = 256;

/// A virtqueue that supports descriptor chains (for virtio-blk).
pub struct VirtQueue {
    base_vaddr: u64,
    base_paddr: u64,

    avail_offset: usize,
    used_offset: usize,

    queue_size: u16,
    next_free_desc: u16,
    free_count: u16,
    last_used_idx: u16,
    avail_idx: u16,

    /// Tracking for posted chains, indexed by head descriptor index.
    pending: [Option<ChainPending>; MAX_QUEUE_SIZE as usize],

    /// Device has been killed due to a validation failure.
    dead: bool,
}

impl VirtQueue {
    /// Allocate and initialize a legacy virtqueue. Returns `None` on DMA
    /// failure or unsupported queue size.
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
        let avail_offset = qs * 16;
        let used_offset = used_ring_offset(queue_size);

        // Initialize the free-descriptor chain.
        let desc_ptr = base_vaddr as *mut VirtqDesc;
        for i in 0..queue_size {
            // SAFETY: desc_ptr points at a DMA-allocated region of at least
            // queue_size * 16 bytes; i < queue_size.
            let d = unsafe { &mut *desc_ptr.add(i as usize) };
            d.addr = 0;
            d.len = 0;
            d.flags = 0;
            d.next = if i + 1 < queue_size { i + 1 } else { 0xFFFF };
        }

        let avail_base = base_vaddr + avail_offset as u64;
        // SAFETY: avail_base falls within the DMA region allocated above;
        // the first 4 bytes are flags (u16) + idx (u16). Volatile writes
        // required so the device sees the initialization.
        unsafe {
            core::ptr::write_volatile(avail_base as *mut u16, 0);
            core::ptr::write_volatile((avail_base + 2) as *mut u16, 0);
        }

        let used_base = base_vaddr + used_offset as u64;
        // SAFETY: used_base falls within the DMA region (after avail ring).
        unsafe {
            core::ptr::write_volatile(used_base as *mut u16, 0);
            core::ptr::write_volatile((used_base + 2) as *mut u16, 0);
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

    /// Physical page frame number (for legacy transport `REG_QUEUE_PFN`).
    pub fn pfn(&self) -> u32 {
        (self.base_paddr / 4096) as u32
    }

    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// Post a chain of descriptors as a single request.
    ///
    /// Returns the head descriptor index on success. The caller uses that
    /// index to match against `pop_used` results when multiple requests are
    /// outstanding.
    pub fn push_chain(&mut self, segments: &[ChainSegment]) -> Option<u16> {
        if self.dead {
            return None;
        }
        if segments.is_empty() || segments.len() > MAX_CHAIN_LEN {
            return None;
        }
        let segs_u16 = segments.len() as u16;
        if self.free_count < segs_u16 {
            return None;
        }

        // Reserve the chain's descriptors up front so we can compute `next`
        // indices for each link.
        let mut desc_indices = [0u16; MAX_CHAIN_LEN];
        for (i, slot) in desc_indices.iter_mut().enumerate().take(segments.len()) {
            let idx = self.next_free_desc;
            if idx >= self.queue_size {
                return None; // Corrupt free list.
            }
            *slot = idx;
            let desc_ptr = self.base_vaddr as *mut VirtqDesc;
            // SAFETY: idx < queue_size (checked above); desc_ptr is our
            // DMA-allocated descriptor table.
            let desc = unsafe { &*desc_ptr.add(idx as usize) };
            self.next_free_desc = desc.next;
            let _ = i;
        }
        self.free_count -= segs_u16;

        let head_idx = desc_indices[0];
        let mut total_len: u32 = 0;

        // Write each descriptor in the chain, linking to the next.
        let desc_ptr = self.base_vaddr as *mut VirtqDesc;
        for (i, seg) in segments.iter().enumerate() {
            let is_last = i + 1 == segments.len();
            let mut flags: u16 = 0;
            if !is_last {
                flags |= VIRTQ_DESC_F_NEXT;
            }
            if seg.device_writable {
                flags |= VIRTQ_DESC_F_WRITE;
            }
            let next = if is_last { 0 } else { desc_indices[i + 1] };

            // SAFETY: desc_indices[i] < queue_size (checked at reservation);
            // desc_ptr is our DMA-allocated descriptor table.
            let desc = unsafe { &mut *desc_ptr.add(desc_indices[i] as usize) };
            desc.addr = seg.paddr;
            desc.len = seg.len;
            desc.flags = flags;
            desc.next = next;

            total_len = total_len.saturating_add(seg.len);
        }

        self.pending[head_idx as usize] = Some(ChainPending {
            length: segments.len() as u8,
            total_len,
        });

        // Post the head to the available ring.
        let avail_base = self.base_vaddr + self.avail_offset as u64;
        let ring_slot = self.avail_idx % self.queue_size;
        // SAFETY: avail_base + 4 is the first ring entry; ring_slot <
        // queue_size keeps the write inside the avail region.
        unsafe {
            let ring_ptr = (avail_base + 4) as *mut u16;
            core::ptr::write_volatile(ring_ptr.add(ring_slot as usize), head_idx);
        }
        self.avail_idx = self.avail_idx.wrapping_add(1);

        // Publish the updated avail_idx so the device sees our entry.
        // SAFETY: avail_base + 2 is the u16 idx field in the avail ring header.
        unsafe {
            core::ptr::write_volatile((avail_base + 2) as *mut u16, self.avail_idx);
        }

        Some(head_idx)
    }

    /// Poll the used ring for a completed chain.
    ///
    /// Returns `Some((head_desc_idx, used_len))` for the next completed chain,
    /// or `None` if nothing is available. The returned `used_len` is clamped
    /// to the chain's total posted length. Frees every descriptor in the
    /// chain back to the free list.
    ///
    /// Kills the device on any protocol violation.
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        if self.dead {
            return None;
        }

        let used_base = self.base_vaddr + self.used_offset as u64;
        // SAFETY: used_base + 2 is the u16 idx field in the used ring header;
        // volatile read so we see the device's latest value.
        let device_idx = DeviceValue::new(unsafe {
            core::ptr::read_volatile((used_base + 2) as *const u16)
        });

        if self.last_used_idx == device_idx.raw() {
            return None;
        }

        let ring_idx = self.last_used_idx % self.queue_size;
        let elem_ptr = (used_base + 4) as *const VirtqUsedElem;
        // SAFETY: the used ring starts at used_base + 4 and has queue_size
        // VirtqUsedElem entries; ring_idx < queue_size.
        let elem = unsafe { core::ptr::read_volatile(elem_ptr.add(ring_idx as usize)) };

        // VALIDATE: head descriptor index within queue bounds.
        let head_idx = match DeviceValue::new(elem.id as u16)
            .validate_index(self.queue_size)
        {
            Some(idx) => idx,
            None => {
                self.dead = true;
                sys::print(b"[BLK] DEVICE KILLED: used ring head index out of bounds\n");
                return None;
            }
        };

        // VALIDATE: we actually posted this chain.
        let pending = match self.pending[head_idx as usize].take() {
            Some(p) => p,
            None => {
                self.dead = true;
                sys::print(b"[BLK] DEVICE KILLED: chain head not pending\n");
                return None;
            }
        };

        // VALIDATE: clamp returned length.
        let used_len = DeviceValue::new(elem.len).clamp_length(pending.total_len);

        // Walk the chain, returning each descriptor to the free list.
        let desc_ptr = self.base_vaddr as *mut VirtqDesc;
        let mut cur = head_idx;
        for step in 0..pending.length {
            // SAFETY: cur < queue_size at every step — either the head (just
            // validated) or a `next` field of a previous descriptor that we
            // set in push_chain. validate on each step defensively.
            if cur >= self.queue_size {
                self.dead = true;
                sys::print(b"[BLK] DEVICE KILLED: chain walk out of bounds\n");
                return None;
            }
            let desc = unsafe { &mut *desc_ptr.add(cur as usize) };
            let next_in_chain = desc.next;
            let has_next = (desc.flags & VIRTQ_DESC_F_NEXT) != 0;

            // Free this descriptor.
            desc.next = self.next_free_desc;
            self.next_free_desc = cur;
            self.free_count += 1;

            if !has_next {
                // End of chain. Sanity-check length.
                if step + 1 != pending.length {
                    self.dead = true;
                    sys::print(b"[BLK] DEVICE KILLED: chain length mismatch\n");
                    return None;
                }
                break;
            }
            cur = next_in_chain;
        }

        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((head_idx, used_len))
    }

}

/// A pre-allocated DMA region used as a bounce buffer. One page = 4 KiB —
/// matches both `BLOCK_SIZE` and the x86_64 page granularity.
pub struct BounceBuffer {
    pub vaddr: u64,
    pub paddr: u64,
    pub size: u32,
}

impl BounceBuffer {
    /// Allocate a single-page (4096 B) DMA buffer.
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

    pub fn write(&self, offset: usize, data: &[u8]) -> usize {
        if offset >= self.size as usize {
            return 0;
        }
        let max = self.size as usize - offset;
        let len = core::cmp::min(data.len(), max);
        let dst = (self.vaddr + offset as u64) as *mut u8;
        // SAFETY: dst + len falls within the DMA allocation (checked via max).
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, len);
        }
        len
    }

    pub fn read(&self, offset: usize, dst: &mut [u8]) -> usize {
        if offset >= self.size as usize {
            return 0;
        }
        let max = self.size as usize - offset;
        let len = core::cmp::min(dst.len(), max);
        let src = (self.vaddr + offset as u64) as *const u8;
        // SAFETY: src + len falls within the DMA allocation (checked via max).
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), len);
        }
        len
    }

    pub fn read_u8(&self, offset: usize) -> Option<u8> {
        if offset >= self.size as usize {
            return None;
        }
        let p = (self.vaddr + offset as u64) as *const u8;
        // SAFETY: p is in-range (checked above); volatile so we see the
        // device's write even if the compiler thinks nothing touched this
        // address.
        Some(unsafe { core::ptr::read_volatile(p) })
    }

    pub fn write_u8(&self, offset: usize, val: u8) {
        if offset >= self.size as usize {
            return;
        }
        let p = (self.vaddr + offset as u64) as *mut u8;
        // SAFETY: p is in-range (checked above).
        unsafe {
            core::ptr::write_volatile(p, val);
        }
    }

    pub fn zero(&self) {
        // SAFETY: vaddr points at `size` bytes of driver-owned memory.
        unsafe {
            core::ptr::write_bytes(self.vaddr as *mut u8, 0, self.size as usize);
        }
    }
}
