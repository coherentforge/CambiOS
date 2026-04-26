// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Block device abstraction — a fixed-size-sector storage interface
//!
//! The `BlockDevice` trait is the bridge between `DiskObjectStore` and a
//! physical storage backend. The trait itself contains no hardware access —
//! it's a pure bookkeeping contract that can be backed by:
//!
//! - `MemBlockDevice` — in-kernel RAM buffer, for testing and for bring-up
//!   before a real driver exists.
//! - `VirtioBlkDevice` (Phase 4a.iii) — IPC client to the user-space
//!   virtio-blk driver.
//!
//! Separating the trait from the backend keeps the `DiskObjectStore` logic
//! (on-disk format, index reconstruction, crash consistency) independent of
//! the transport. It also makes the format testable on the host with no
//! hardware dependency.
//!
//! ## Lock-ordering constraint
//!
//! `BlockDevice` implementations may acquire locks that sit *lower* than
//! `OBJECT_STORE` in the kernel lock hierarchy (the virtio-blk adapter
//! acquires `IPC_MANAGER` at position 3). Callers MUST NOT hold the
//! `OBJECT_STORE` spinlock across a `BlockDevice` call once a non-memory
//! backend is wired. `MemBlockDevice` acquires no locks and is safe to call
//! under `OBJECT_STORE`; the restructure to release-and-reacquire lands in
//! Phase 4a.iii when the IPC-capable backend arrives.

extern crate alloc;
// `Vec` and `vec!` are only used by the test-gated `MemBlockDevice`
// below; gate the imports to match so release builds don't carry
// unused-import warnings.
#[cfg(test)]
use alloc::vec;
#[cfg(test)]
use alloc::vec::Vec;

/// HARDWARE: on-disk sector size for the persistent ObjectStore.
/// Why: matches x86_64 page size (4096 B) and is a multiple of every
///      common sector size (512, 4096) exposed by real block devices.
///      Using one constant sector size keeps the format agnostic to
///      whether the underlying hardware reports 512-byte or 4K-native
///      sectors — we issue I/O at 4 KiB regardless.
pub const BLOCK_SIZE: usize = 4096;

/// A single block's worth of data. Fixed-size array so stack-allocated
/// buffers are straightforward and DMA bounce buffers (Phase 4a.iii) can
/// copy into a `Block` without allocation.
pub type Block = [u8; BLOCK_SIZE];

/// Errors from block-device operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// Requested LBA is past the device capacity.
    OutOfBounds,
    /// Backend reported a device-level failure (I/O error, device not ready,
    /// virtqueue status byte non-zero).
    DeviceError,
    /// Backend is not yet ready to service requests (driver still
    /// initializing, IPC endpoint not registered yet).
    NotReady,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::OutOfBounds => write!(f, "LBA out of bounds"),
            Self::DeviceError => write!(f, "block device error"),
            Self::NotReady => write!(f, "block device not ready"),
        }
    }
}

/// A fixed-sector-size storage backend.
///
/// `&mut self` on every operation is intentional: real backends mutate
/// internal queue state (virtio descriptor rings, bounce buffer bookkeeping)
/// even on reads, so a `&self` API would be a lie. Callers serialize access
/// through the `OBJECT_STORE` spinlock.
///
/// `Send` supertrait is required because `DiskObjectStore` owns a
/// `B: BlockDevice` and is wrapped (boxed) inside the `LazyDisk` variant
/// of `ObjectStoreBackend`, which sits behind the `OBJECT_STORE` spinlock
/// and may be accessed from any CPU.
pub trait BlockDevice: Send {
    /// Total number of blocks the backend exposes.
    fn capacity_blocks(&self) -> u64;

    /// Read the block at `lba` into `buf`.
    fn read_block(&mut self, lba: u64, buf: &mut Block) -> Result<(), BlockError>;

    /// Write `buf` to the block at `lba`. Write-through semantics — the data
    /// is not guaranteed durable until `flush` returns.
    fn write_block(&mut self, lba: u64, buf: &Block) -> Result<(), BlockError>;

    /// Barrier: all writes issued before this call are durable (or have
    /// failed) once `flush` returns. A no-op for `MemBlockDevice` (RAM has
    /// no durability story); a virtio-blk `VIRTIO_BLK_T_FLUSH` for the real
    /// backend.
    fn flush(&mut self) -> Result<(), BlockError>;
}

// ============================================================================
// MemBlockDevice — in-RAM backend for unit tests and bring-up
// ============================================================================

/// In-memory `BlockDevice`. Stores the entire disk image in a single `Vec<u8>`
/// of size `capacity_blocks * BLOCK_SIZE`. Contents are zero-initialized.
///
/// This is the backend used by the persistent-store unit tests — the same
/// `DiskObjectStore` code path that will eventually talk to virtio-blk runs
/// against a `MemBlockDevice` in `cargo test`, so the on-disk format is
/// exercised on every test run with zero hardware dependency.
///
/// Test-only: gated under `#[cfg(test)]` so the `expect()` in `new()`
/// stays inside test code per CLAUDE.md's "no panics in non-test
/// kernel code" rule. The struct + impls are never linked into a
/// release kernel build.
#[cfg(test)]
pub struct MemBlockDevice {
    data: Vec<u8>,
    capacity_blocks: u64,
}

#[cfg(test)]
impl MemBlockDevice {
    /// Create a zero-initialized in-memory device with the given capacity in
    /// blocks. Total backing memory = `capacity_blocks * BLOCK_SIZE` bytes.
    pub fn new(capacity_blocks: u64) -> Self {
        let total_bytes = (capacity_blocks as usize)
            .checked_mul(BLOCK_SIZE)
            .expect("MemBlockDevice size overflows usize");
        Self {
            data: vec![0u8; total_bytes],
            capacity_blocks,
        }
    }

    fn byte_range(&self, lba: u64) -> Option<core::ops::Range<usize>> {
        if lba >= self.capacity_blocks {
            return None;
        }
        let start = (lba as usize).checked_mul(BLOCK_SIZE)?;
        let end = start.checked_add(BLOCK_SIZE)?;
        if end > self.data.len() {
            return None;
        }
        Some(start..end)
    }
}

#[cfg(test)]
impl BlockDevice for MemBlockDevice {
    fn capacity_blocks(&self) -> u64 {
        self.capacity_blocks
    }

    fn read_block(&mut self, lba: u64, buf: &mut Block) -> Result<(), BlockError> {
        let range = self.byte_range(lba).ok_or(BlockError::OutOfBounds)?;
        buf.copy_from_slice(&self.data[range]);
        Ok(())
    }

    fn write_block(&mut self, lba: u64, buf: &Block) -> Result<(), BlockError> {
        let range = self.byte_range(lba).ok_or(BlockError::OutOfBounds)?;
        self.data[range].copy_from_slice(buf);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_size_is_page_size() {
        assert_eq!(BLOCK_SIZE, 4096);
    }

    #[test]
    fn mem_device_reports_capacity() {
        let dev = MemBlockDevice::new(32);
        assert_eq!(dev.capacity_blocks(), 32);
    }

    #[test]
    fn mem_device_zero_initialized() {
        let mut dev = MemBlockDevice::new(4);
        let mut buf = [0xFFu8; BLOCK_SIZE];
        dev.read_block(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
        let mut buf2 = [0xFFu8; BLOCK_SIZE];
        dev.read_block(3, &mut buf2).unwrap();
        assert!(buf2.iter().all(|&b| b == 0));
    }

    #[test]
    fn mem_device_write_read_roundtrip() {
        let mut dev = MemBlockDevice::new(8);
        let mut pattern = [0u8; BLOCK_SIZE];
        for (i, b) in pattern.iter_mut().enumerate() {
            *b = (i % 251) as u8; // non-trivial pattern, prime modulus
        }
        dev.write_block(5, &pattern).unwrap();
        let mut read_back = [0u8; BLOCK_SIZE];
        dev.read_block(5, &mut read_back).unwrap();
        assert_eq!(read_back, pattern);
    }

    #[test]
    fn mem_device_blocks_isolated() {
        let mut dev = MemBlockDevice::new(4);
        let a = [0xAAu8; BLOCK_SIZE];
        let b = [0xBBu8; BLOCK_SIZE];
        dev.write_block(1, &a).unwrap();
        dev.write_block(2, &b).unwrap();

        let mut read = [0u8; BLOCK_SIZE];
        dev.read_block(1, &mut read).unwrap();
        assert_eq!(read, a);
        dev.read_block(2, &mut read).unwrap();
        assert_eq!(read, b);
        dev.read_block(0, &mut read).unwrap();
        assert!(read.iter().all(|&x| x == 0));
        dev.read_block(3, &mut read).unwrap();
        assert!(read.iter().all(|&x| x == 0));
    }

    #[test]
    fn mem_device_out_of_bounds_read() {
        let mut dev = MemBlockDevice::new(4);
        let mut buf = [0u8; BLOCK_SIZE];
        assert_eq!(dev.read_block(4, &mut buf), Err(BlockError::OutOfBounds));
        assert_eq!(dev.read_block(u64::MAX, &mut buf), Err(BlockError::OutOfBounds));
    }

    #[test]
    fn mem_device_out_of_bounds_write() {
        let mut dev = MemBlockDevice::new(4);
        let buf = [0u8; BLOCK_SIZE];
        assert_eq!(dev.write_block(4, &buf), Err(BlockError::OutOfBounds));
        assert_eq!(dev.write_block(u64::MAX, &buf), Err(BlockError::OutOfBounds));
    }

    #[test]
    fn mem_device_flush_is_noop() {
        let mut dev = MemBlockDevice::new(1);
        assert_eq!(dev.flush(), Ok(()));
        let buf = [0xFFu8; BLOCK_SIZE];
        dev.write_block(0, &buf).unwrap();
        assert_eq!(dev.flush(), Ok(()));
    }

    #[test]
    fn mem_device_zero_capacity_ok() {
        let mut dev = MemBlockDevice::new(0);
        assert_eq!(dev.capacity_blocks(), 0);
        let mut buf = [0u8; BLOCK_SIZE];
        assert_eq!(dev.read_block(0, &mut buf), Err(BlockError::OutOfBounds));
    }

    #[test]
    fn mem_device_survives_full_pattern_sweep() {
        // Write a distinct byte pattern to every block, then read them all
        // back. Catches any off-by-one in byte_range().
        let cap = 16u64;
        let mut dev = MemBlockDevice::new(cap);
        for lba in 0..cap {
            let buf = [(lba as u8).wrapping_add(1); BLOCK_SIZE];
            dev.write_block(lba, &buf).unwrap();
        }
        for lba in 0..cap {
            let mut buf = [0u8; BLOCK_SIZE];
            dev.read_block(lba, &mut buf).unwrap();
            let expected = (lba as u8).wrapping_add(1);
            assert!(
                buf.iter().all(|&b| b == expected),
                "block {} should be all {:#x}",
                lba,
                expected
            );
        }
    }

    #[test]
    fn block_error_display() {
        use alloc::format;
        assert_eq!(format!("{}", BlockError::OutOfBounds), "LBA out of bounds");
        assert_eq!(format!("{}", BlockError::DeviceError), "block device error");
        assert_eq!(format!("{}", BlockError::NotReady), "block device not ready");
    }
}
