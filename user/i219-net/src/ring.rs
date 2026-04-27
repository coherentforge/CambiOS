// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! TX and RX descriptor ring management for the I219-LM driver.
//!
//! Each ring is a contiguous array of legacy 16-byte descriptors backed
//! by DMA memory. Each descriptor points to a per-descriptor bounce
//! buffer (also DMA memory). The driver writes the tail pointer (TDT/RDT)
//! and the device writes the head (TDH/RDH) plus the descriptor's status.
//!
//! ## Hostile-device assumptions
//!
//! Values written by the device into descriptors (length, status,
//! errors) are validated before use. The driver never trusts a length
//! larger than the bounce buffer size.

use cambios_libsys as sys;

use crate::regs::{RxDesc, TxDesc};

/// Number of descriptors in each ring. Must be a multiple of 8 per the
/// Intel manual; 16 keeps memory usage modest while allowing some
/// in-flight RX buffers.
pub const RING_SIZE: usize = 16;

/// Per-buffer DMA size (one 4KB page). Holds a 1500-byte Ethernet frame
/// with room to spare.
pub const BUF_SIZE: u32 = 4096;

/// A DMA-allocated bounce buffer for a single packet.
#[derive(Clone, Copy)]
pub struct DmaBuf {
    pub vaddr: u64,
    pub paddr: u64,
}

impl DmaBuf {
    pub fn alloc() -> Option<Self> {
        let mut paddr: u64 = 0;
        let ret = sys::alloc_dma(1, &mut paddr);
        if ret <= 0 {
            return None;
        }
        Some(DmaBuf {
            vaddr: ret as u64,
            paddr,
        })
    }

    /// Copy data into the buffer (clamped to BUF_SIZE).
    /// Returns bytes written.
    pub fn write(&self, data: &[u8]) -> usize {
        let len = core::cmp::min(data.len(), BUF_SIZE as usize);
        let dst = self.vaddr as *mut u8;
        // SAFETY: vaddr is from alloc_dma, valid for BUF_SIZE bytes.
        // dst doesn't overlap with data (data is in driver memory,
        // dst is in DMA memory).
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, len); }
        len
    }

    /// Copy data from the buffer into `dst` (clamped).
    /// Returns bytes read.
    pub fn read(&self, dst: &mut [u8], len: usize) -> usize {
        let n = core::cmp::min(core::cmp::min(len, dst.len()), BUF_SIZE as usize);
        let src = self.vaddr as *const u8;
        // SAFETY: vaddr is from alloc_dma, valid for BUF_SIZE bytes.
        unsafe { core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n); }
        n
    }

    /// Zero the buffer.
    pub fn zero(&self) {
        // SAFETY: vaddr is from alloc_dma, valid for BUF_SIZE bytes.
        unsafe { core::ptr::write_bytes(self.vaddr as *mut u8, 0, BUF_SIZE as usize); }
    }
}

/// A descriptor ring (TX or RX) with its bounce buffers.
///
/// The descriptor array itself lives in DMA memory so the device can
/// read it. Each descriptor's `addr` field points to a per-descriptor
/// `DmaBuf`.
pub struct Ring {
    /// Physical address of the descriptor array (programmed into TDBA/RDBA).
    pub desc_paddr: u64,
    /// Virtual address of the descriptor array (for software access).
    desc_vaddr: u64,
    /// Per-descriptor bounce buffers (one per slot).
    bufs: [Option<DmaBuf>; RING_SIZE],
    /// Software's index into the ring (next slot to use).
    ///
    /// For TX: the next descriptor to fill. Equals TDT until written.
    /// For RX: the next descriptor expected to be completed by hardware.
    pub next: u16,
}

impl Ring {
    /// Allocate a new ring.
    ///
    /// Allocates one DMA page for the descriptor array (16 × 16 = 256
    /// bytes used, rest is wasted padding) plus 16 DMA pages for bounce
    /// buffers (one per descriptor).
    pub fn alloc() -> Option<Self> {
        // Allocate the descriptor array (one page is plenty).
        let mut desc_paddr: u64 = 0;
        let desc_vaddr = sys::alloc_dma(1, &mut desc_paddr);
        if desc_vaddr <= 0 {
            return None;
        }
        let desc_vaddr = desc_vaddr as u64;

        // Zero the descriptor array.
        // SAFETY: desc_vaddr is from alloc_dma, valid for 4096 bytes.
        unsafe { core::ptr::write_bytes(desc_vaddr as *mut u8, 0, 4096); }

        // Allocate per-descriptor bounce buffers.
        let mut bufs: [Option<DmaBuf>; RING_SIZE] = [None; RING_SIZE];
        for slot in 0..RING_SIZE {
            bufs[slot] = Some(DmaBuf::alloc()?);
        }

        Some(Ring {
            desc_paddr,
            desc_vaddr,
            bufs,
            next: 0,
        })
    }

    /// Total ring size in bytes (passed to RDLEN/TDLEN).
    pub fn byte_size(&self) -> u32 {
        (RING_SIZE * core::mem::size_of::<TxDesc>()) as u32
    }

    /// Read a TX descriptor by index.
    pub fn tx_desc(&self, idx: usize) -> TxDesc {
        let ptr = (self.desc_vaddr + (idx * core::mem::size_of::<TxDesc>()) as u64) as *const TxDesc;
        // SAFETY: idx < RING_SIZE, descriptors are 16 bytes, total fits in one page.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Write a TX descriptor by index.
    pub fn write_tx_desc(&self, idx: usize, desc: TxDesc) {
        let ptr = (self.desc_vaddr + (idx * core::mem::size_of::<TxDesc>()) as u64) as *mut TxDesc;
        // SAFETY: idx < RING_SIZE.
        unsafe { core::ptr::write_volatile(ptr, desc); }
    }

    /// Read an RX descriptor by index.
    pub fn rx_desc(&self, idx: usize) -> RxDesc {
        let ptr = (self.desc_vaddr + (idx * core::mem::size_of::<RxDesc>()) as u64) as *const RxDesc;
        // SAFETY: idx < RING_SIZE.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Write an RX descriptor by index.
    pub fn write_rx_desc(&self, idx: usize, desc: RxDesc) {
        let ptr = (self.desc_vaddr + (idx * core::mem::size_of::<RxDesc>()) as u64) as *mut RxDesc;
        // SAFETY: idx < RING_SIZE.
        unsafe { core::ptr::write_volatile(ptr, desc); }
    }

    /// Get the bounce buffer for a slot.
    pub fn buf(&self, idx: usize) -> Option<&DmaBuf> {
        self.bufs.get(idx).and_then(|b| b.as_ref())
    }
}
