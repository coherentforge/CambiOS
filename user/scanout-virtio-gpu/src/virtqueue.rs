// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Modern split virtqueue (virtio spec §2.7).
//!
//! Three independent rings — descriptor table, driver ring (avail), and
//! device ring (used) — allocated in one contiguous DMA region and
//! carved into properly-aligned sub-regions. One page (4 KiB) holds a
//! 16-entry queue with generous padding, which is all Scanout-4.a
//! needs: single-command submit / single-response wait.
//!
//! This is **not** a general-purpose modern virtqueue — deliberately
//! scoped to the two-descriptor chain virtio-gpu uses for its simplest
//! commands (command buffer + response buffer). Scanout-4.b / 4.c may
//! either extend this module (multi-segment chains, async completions)
//! or replace it with a shared library if a third modern virtio driver
//! materializes.

use arcos_libsys as sys;

/// SCAFFOLDING: hard-coded queue size for 4.a. 16 descriptors is enough
/// for GET_DISPLAY_INFO (one command buffer + one response buffer =
/// one 2-descriptor chain at a time). Why this size: power of two as
/// the spec requires, large enough that early virtio-gpu command
/// pipelines (4.b RESOURCE_CREATE / ATTACH_BACKING / SET_SCANOUT /
/// TRANSFER / FLUSH) chained together still fit without churn, small
/// enough that all three rings pack comfortably into a single 4 KiB
/// page. Replace when: a backend needs more than ~8 in-flight requests
/// per frame, at which point reassess against QEMU's advertised size
/// (usually 256).
pub const QUEUE_SIZE: u16 = 16;

/// Region layout inside the single DMA page:
/// `[desc: 256 B][avail: 256 B][used: 512 B][pad ...]`. Chosen so each
/// ring starts at a fresh power-of-two offset — makes the alignment
/// constraints trivial to satisfy and leaves 3 KiB of unused slack
/// for any future 4.b growth (larger queue, event-suppression fields).
const DESC_OFFSET: usize = 0;
const AVAIL_OFFSET: usize = 256;
const USED_OFFSET: usize = 512;

/// Descriptor flags (virtio §2.7.5).
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Split-ring descriptor (virtio spec §2.7.5, 16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Used-ring element (8 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

/// One segment of a two-descriptor chain.
#[derive(Clone, Copy)]
pub struct Segment {
    pub paddr: u64,
    pub len: u32,
    /// `true` = device writes (response buffer). `false` = device reads
    /// (command buffer).
    pub device_writable: bool,
}

pub struct ModernVirtQueue {
    base_vaddr: u64,
    base_paddr: u64,
    /// Monotonically incremented on each chain submission.
    avail_idx: u16,
    /// Last `used.idx` the driver has observed.
    last_used_idx: u16,
}

impl ModernVirtQueue {
    /// Allocate and zero the ring region. Returns `None` on DMA failure.
    pub fn new() -> Option<Self> {
        let mut base_paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut base_paddr);
        if ret < 0 {
            return None;
        }
        let base_vaddr = ret as u64;

        // SAFETY: alloc_dma returned a valid page-sized region.
        unsafe {
            core::ptr::write_bytes(base_vaddr as *mut u8, 0, 4096);
        }
        Some(Self {
            base_vaddr,
            base_paddr,
            avail_idx: 0,
            last_used_idx: 0,
        })
    }

    /// Physical addresses of the three ring sub-regions. Values passed
    /// to `ModernTransport::set_queue_addrs` during device queue setup.
    pub fn ring_addrs(&self) -> (u64, u64, u64) {
        (
            self.base_paddr + DESC_OFFSET as u64,
            self.base_paddr + AVAIL_OFFSET as u64,
            self.base_paddr + USED_OFFSET as u64,
        )
    }

    fn desc_ptr(&self) -> *mut VirtqDesc {
        (self.base_vaddr + DESC_OFFSET as u64) as *mut VirtqDesc
    }

    fn avail_flags_ptr(&self) -> *mut u16 {
        (self.base_vaddr + AVAIL_OFFSET as u64) as *mut u16
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

    /// Submit a two-segment chain (command + response). Each chain
    /// consumes two descriptors, so the effective queue depth is
    /// `QUEUE_SIZE / 2` chains in flight. The avail ring still has
    /// QUEUE_SIZE slots, indexed by `avail_idx % QUEUE_SIZE` per spec.
    /// Returns the head descriptor index.
    pub fn submit_two(&mut self, req: Segment, rsp: Segment) -> u16 {
        // Pick a pair of free descriptor slots. Synchronous use: the
        // pair at offset `(avail_idx % (QUEUE_SIZE / 2)) * 2` in the
        // 16-entry descriptor table never overlaps itself within
        // QUEUE_SIZE/2 consecutive submissions.
        let effective_depth = QUEUE_SIZE / 2;
        let head = (self.avail_idx % effective_depth) * 2;
        let second = head + 1;

        // SAFETY: head < QUEUE_SIZE and second = head + 1 ≤ QUEUE_SIZE - 1;
        // both fall within the 16-entry descriptor table at DESC_OFFSET
        // (16 × 16 B = 256 B).
        unsafe {
            let req_desc = self.desc_ptr().add(head as usize);
            core::ptr::write_volatile(
                req_desc,
                VirtqDesc {
                    addr: req.paddr,
                    len: req.len,
                    flags: if req.device_writable {
                        VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
                    } else {
                        VIRTQ_DESC_F_NEXT
                    },
                    next: second,
                },
            );
            let rsp_desc = self.desc_ptr().add(second as usize);
            core::ptr::write_volatile(
                rsp_desc,
                VirtqDesc {
                    addr: rsp.paddr,
                    len: rsp.len,
                    flags: if rsp.device_writable { VIRTQ_DESC_F_WRITE } else { 0 },
                    next: 0,
                },
            );

            // Avail ring: write head index at avail_idx's slot, then bump avail.idx.
            let slot = self.avail_idx % QUEUE_SIZE;
            core::ptr::write_volatile(self.avail_ring_ptr().add(slot as usize), head);
            // Memory-order barrier: make sure descriptor + ring writes land
            // before the device reads avail.idx.
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            self.avail_idx = self.avail_idx.wrapping_add(1);
            core::ptr::write_volatile(self.avail_idx_ptr(), self.avail_idx);
            // Silence unused-field warning on the flags pointer in case
            // a future change elides its initialization path.
            let _ = self.avail_flags_ptr();
        }

        head
    }

    /// Poll the used ring for a completion. Returns `Some(used_len)`
    /// when a new entry appears, `None` otherwise.
    pub fn poll_used(&mut self) -> Option<u32> {
        // SAFETY: used_idx is the 2-byte field at USED_OFFSET + 2.
        let device_idx = unsafe { core::ptr::read_volatile(self.used_idx_ptr()) };
        if device_idx == self.last_used_idx {
            return None;
        }
        let slot = (self.last_used_idx % QUEUE_SIZE) as usize;
        // SAFETY: used_ring starts at USED_OFFSET + 4; slot < QUEUE_SIZE
        // keeps the read inside the allocated 512-byte used region.
        let elem = unsafe { core::ptr::read_volatile(self.used_ring_ptr().add(slot)) };
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some(elem.len)
    }
}

/// A pre-allocated DMA page used as a command or response buffer.
pub struct DmaBuffer {
    pub vaddr: u64,
    pub paddr: u64,
    pub size: u32,
}

impl DmaBuffer {
    pub fn new(pages: u32) -> Option<Self> {
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(pages, &mut paddr);
        if ret < 0 {
            return None;
        }
        let vaddr = ret as u64;
        // SAFETY: alloc_dma returned a mapped DMA region of at least
        // pages * 4096 bytes.
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, (pages * 4096) as usize);
        }
        Some(Self {
            vaddr,
            paddr,
            size: pages * 4096,
        })
    }

    /// Write `data` at offset 0 in the buffer.
    pub fn write(&self, data: &[u8]) {
        let len = core::cmp::min(data.len(), self.size as usize);
        // SAFETY: len ≤ self.size so the write stays inside the DMA region.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.vaddr as *mut u8, len);
        }
    }

    /// Read `len` bytes from offset 0 into `dst`. `dst.len()` must be ≥ `len`.
    pub fn read(&self, dst: &mut [u8], len: usize) {
        let n = core::cmp::min(core::cmp::min(dst.len(), len), self.size as usize);
        // SAFETY: n ≤ self.size so the read stays inside the DMA region.
        unsafe {
            core::ptr::copy_nonoverlapping(self.vaddr as *const u8, dst.as_mut_ptr(), n);
        }
    }
}
