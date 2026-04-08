// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Virtio legacy (transitional) PCI transport layer.
//!
//! Implements the virtio 0.9.x / 1.0 legacy register interface over PCI I/O
//! port BARs. This is the transport QEMU exposes for `-device virtio-net-pci`.
//!
//! ## Register layout (BAR 0, I/O port space)
//!
//! | Offset | Size | Name                    |
//! |--------|------|-------------------------|
//! | 0x00   | 4    | Device Features         |
//! | 0x04   | 4    | Guest Features          |
//! | 0x08   | 4    | Queue Address (PFN)     |
//! | 0x0C   | 2    | Queue Size              |
//! | 0x0E   | 2    | Queue Select            |
//! | 0x10   | 2    | Queue Notify            |
//! | 0x12   | 1    | Device Status           |
//! | 0x13   | 1    | ISR Status              |
//! | 0x14   | 6    | MAC address (net only)  |

use arcos_libsys as sys;

/// Legacy virtio register offsets (I/O port BAR).
const REG_DEVICE_FEATURES: u16 = 0x00;
const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_PFN: u16 = 0x08;
const REG_QUEUE_SIZE: u16 = 0x0C;
const REG_QUEUE_SELECT: u16 = 0x0E;
const REG_QUEUE_NOTIFY: u16 = 0x10;
const REG_DEVICE_STATUS: u16 = 0x12;
const REG_ISR_STATUS: u16 = 0x13;
const REG_MAC_ADDR: u16 = 0x14;

/// Device status bits.
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

/// Virtio-net feature bits.
pub const VIRTIO_NET_F_MAC: u32 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u32 = 1 << 16;

/// Legacy PCI transport for a virtio device.
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
        sys::port_read8(self.io_base + offset).unwrap_or(0xFF)
    }

    fn write8(&self, offset: u16, val: u8) {
        let _ = sys::port_write8(self.io_base + offset, val);
    }

    fn read16(&self, offset: u16) -> u16 {
        sys::port_read16(self.io_base + offset).unwrap_or(0xFFFF)
    }

    fn write16(&self, offset: u16, val: u16) {
        let _ = sys::port_write16(self.io_base + offset, val);
    }

    fn read32(&self, offset: u16) -> u32 {
        sys::port_read32(self.io_base + offset).unwrap_or(0xFFFFFFFF)
    }

    fn write32(&self, offset: u16, val: u32) {
        let _ = sys::port_write32(self.io_base + offset, val);
    }

    // -- Device lifecycle ----------------------------------------------------

    /// Reset the device (write 0 to status).
    pub fn reset(&self) {
        self.write8(REG_DEVICE_STATUS, 0);
    }

    /// Read device status register.
    pub fn status(&self) -> u8 {
        self.read8(REG_DEVICE_STATUS)
    }

    /// Set device status bits (OR'd with current status).
    pub fn set_status(&self, bits: u8) {
        let current = self.status();
        self.write8(REG_DEVICE_STATUS, current | bits);
    }

    /// Read device-offered features.
    pub fn device_features(&self) -> u32 {
        self.read32(REG_DEVICE_FEATURES)
    }

    /// Write driver-accepted features.
    pub fn set_guest_features(&self, features: u32) {
        self.write32(REG_GUEST_FEATURES, features);
    }

    // -- Queue configuration -------------------------------------------------

    /// Select a virtqueue by index for subsequent queue operations.
    pub fn select_queue(&self, queue_idx: u16) {
        self.write16(REG_QUEUE_SELECT, queue_idx);
    }

    /// Read the maximum queue size for the currently selected queue.
    pub fn queue_size(&self) -> u16 {
        self.read16(REG_QUEUE_SIZE)
    }

    /// Set the queue address (page frame number of the descriptor area).
    /// Legacy virtio uses a single PFN for the combined desc+avail+used area.
    /// For split queues, this is `phys_addr / 4096`.
    pub fn set_queue_pfn(&self, pfn: u32) {
        self.write32(REG_QUEUE_PFN, pfn);
    }

    /// Notify the device that the given queue has new available buffers.
    pub fn notify_queue(&self, queue_idx: u16) {
        self.write16(REG_QUEUE_NOTIFY, queue_idx);
    }

    /// Read and acknowledge the ISR status (clears the interrupt).
    pub fn isr_status(&self) -> u8 {
        self.read8(REG_ISR_STATUS)
    }

    // -- Network-specific registers ------------------------------------------

    /// Read the device MAC address (6 bytes at offset 0x14-0x19).
    pub fn read_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = self.read8(REG_MAC_ADDR + i as u16);
        }
        mac
    }
}
