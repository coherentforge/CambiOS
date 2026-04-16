// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Virtio legacy (transitional) PCI transport layer for virtio-blk.
//!
//! Implements the virtio 0.9.x / 1.0 legacy register interface over PCI I/O
//! port BARs. Same underlying protocol as virtio-net's legacy transport; the
//! only difference is the device-specific config region (starts at offset
//! 0x14, holds `capacity` in 512-byte sectors at its head).
//!
//! ## Register layout (BAR 0, I/O port space)
//!
//! | Offset | Size | Name                        |
//! |--------|------|-----------------------------|
//! | 0x00   | 4    | Device Features             |
//! | 0x04   | 4    | Guest Features              |
//! | 0x08   | 4    | Queue Address (PFN)         |
//! | 0x0C   | 2    | Queue Size                  |
//! | 0x0E   | 2    | Queue Select                |
//! | 0x10   | 2    | Queue Notify                |
//! | 0x12   | 1    | Device Status               |
//! | 0x13   | 1    | ISR Status                  |
//! | 0x14   | 8    | `capacity` (512-B sectors)  |
//! | 0x1C   | 4    | `size_max`                  |
//! | 0x20   | 4    | `seg_max`                   |

use arcos_libsys as sys;

/// Legacy virtio register offsets (I/O port BAR).
const REG_DEVICE_FEATURES: u16 = 0x00;
const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_PFN: u16 = 0x08;
const REG_QUEUE_SIZE: u16 = 0x0C;
const REG_QUEUE_SELECT: u16 = 0x0E;
const REG_QUEUE_NOTIFY: u16 = 0x10;
const REG_DEVICE_STATUS: u16 = 0x12;

/// Device-specific config region (virtio-blk).
const REG_BLK_CAPACITY: u16 = 0x14;

/// Device status bits (virtio spec §3.1.1).
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

/// Virtio-blk feature bits (virtio spec §5.2.3). Only `FLUSH` is negotiated
/// by the Phase 4a.ii driver; the others are retained as protocol
/// documentation for future use (e.g. RO enforcement in a read-only tier).
#[allow(dead_code)]
pub const VIRTIO_BLK_F_SIZE_MAX: u32 = 1 << 1;
#[allow(dead_code)]
pub const VIRTIO_BLK_F_SEG_MAX: u32 = 1 << 2;
#[allow(dead_code)]
pub const VIRTIO_BLK_F_RO: u32 = 1 << 5;
#[allow(dead_code)]
pub const VIRTIO_BLK_F_BLK_SIZE: u32 = 1 << 6;
pub const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;

/// Legacy PCI transport for a virtio-blk device.
pub struct LegacyTransport {
    /// Base I/O port (from PCI BAR 0).
    io_base: u16,
}

impl LegacyTransport {
    /// Create a transport handle for the given I/O port base.
    pub fn new(io_base: u16) -> Self {
        Self { io_base }
    }

    // -- Register access (all go through the kernel PortIo syscall) ----------

    fn read8(&self, offset: u16) -> u8 {
        match sys::port_read8(self.io_base + offset) {
            Ok(v) => v,
            Err(_) => { sys::print(b"[BLK] port_read8 ERR\n"); 0xFF }
        }
    }

    fn write8(&self, offset: u16, val: u8) {
        if sys::port_write8(self.io_base + offset, val).is_err() {
            sys::print(b"[BLK] port_write8 ERR\n");
        }
    }

    fn read16(&self, offset: u16) -> u16 {
        match sys::port_read16(self.io_base + offset) {
            Ok(v) => v,
            Err(_) => { sys::print(b"[BLK] port_read16 ERR\n"); 0xFFFF }
        }
    }

    fn write16(&self, offset: u16, val: u16) {
        if sys::port_write16(self.io_base + offset, val).is_err() {
            sys::print(b"[BLK] port_write16 ERR\n");
        }
    }

    fn read32(&self, offset: u16) -> u32 {
        match sys::port_read32(self.io_base + offset) {
            Ok(v) => v,
            Err(_) => { sys::print(b"[BLK] port_read32 ERR\n"); 0xFFFFFFFF }
        }
    }

    fn write32(&self, offset: u16, val: u32) {
        if sys::port_write32(self.io_base + offset, val).is_err() {
            sys::print(b"[BLK] port_write32 ERR\n");
        }
    }

    // -- Device lifecycle ----------------------------------------------------

    pub fn reset(&self) {
        self.write8(REG_DEVICE_STATUS, 0);
    }

    pub fn status(&self) -> u8 {
        self.read8(REG_DEVICE_STATUS)
    }

    pub fn set_status(&self, bits: u8) {
        let current = self.status();
        self.write8(REG_DEVICE_STATUS, current | bits);
    }

    pub fn device_features(&self) -> u32 {
        self.read32(REG_DEVICE_FEATURES)
    }

    pub fn set_guest_features(&self, features: u32) {
        self.write32(REG_GUEST_FEATURES, features);
    }

    // -- Queue configuration -------------------------------------------------

    pub fn select_queue(&self, queue_idx: u16) {
        self.write16(REG_QUEUE_SELECT, queue_idx);
    }

    pub fn queue_size(&self) -> u16 {
        self.read16(REG_QUEUE_SIZE)
    }

    pub fn set_queue_pfn(&self, pfn: u32) {
        self.write32(REG_QUEUE_PFN, pfn);
    }

    pub fn get_queue_pfn(&self) -> u32 {
        self.read32(REG_QUEUE_PFN)
    }

    pub fn notify_queue(&self, queue_idx: u16) -> bool {
        sys::port_write16(self.io_base + REG_QUEUE_NOTIFY, queue_idx).is_ok()
    }

    // -- Virtio-blk-specific registers ---------------------------------------

    /// Read `capacity` from the device-specific config region. Value is the
    /// number of 512-byte sectors — the driver converts to its own block size.
    pub fn read_capacity_sectors(&self) -> u64 {
        // capacity is 8 bytes at REG_BLK_CAPACITY. Read as two u32s to avoid
        // needing a 64-bit port read.
        let lo = self.read32(REG_BLK_CAPACITY) as u64;
        let hi = self.read32(REG_BLK_CAPACITY + 4) as u64;
        (hi << 32) | lo
    }
}
