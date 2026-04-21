// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Virtio legacy transport layer for virtio-blk.
//!
//! Two carrier variants share a single public API via [`Transport`]:
//!
//! - [`LegacyPciTransport`] — virtio 0.9.x / 1.0 legacy registers over PCI I/O
//!   port space (x86_64, aarch64).
//! - [`LegacyMmioTransport`] — virtio-mmio v1 legacy (riscv64 QEMU virt).
//!
//! The wire protocol is identical — same feature bits, same queue structure,
//! same status handshake. Only the register map and access mechanism differ.
//! Both implement the same set of methods so the driver is oblivious to the
//! discovery path.

use arcos_libsys as sys;

// ============================================================================
// Shared constants (wire-protocol, not register-layout)
// ============================================================================

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

// ============================================================================
// LegacyPciTransport — port I/O over kernel-validated PortIo syscall
// ============================================================================

/// Legacy virtio-pci register offsets (I/O port BAR 0).
const PCI_REG_DEVICE_FEATURES: u16 = 0x00;
const PCI_REG_GUEST_FEATURES: u16 = 0x04;
const PCI_REG_QUEUE_PFN: u16 = 0x08;
const PCI_REG_QUEUE_SIZE: u16 = 0x0C;
const PCI_REG_QUEUE_SELECT: u16 = 0x0E;
const PCI_REG_QUEUE_NOTIFY: u16 = 0x10;
const PCI_REG_DEVICE_STATUS: u16 = 0x12;

/// Device-specific config region (virtio-blk, PCI legacy).
const PCI_REG_BLK_CAPACITY: u16 = 0x14;

/// Legacy PCI transport for a virtio-blk device.
pub struct LegacyPciTransport {
    io_base: u16,
}

impl LegacyPciTransport {
    pub fn new(io_base: u16) -> Self {
        Self { io_base }
    }

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

    fn reset(&self) { self.write8(PCI_REG_DEVICE_STATUS, 0); }
    fn status(&self) -> u8 { self.read8(PCI_REG_DEVICE_STATUS) }
    fn set_status(&self, bits: u8) {
        let current = self.status();
        self.write8(PCI_REG_DEVICE_STATUS, current | bits);
    }
    fn device_features(&self) -> u32 { self.read32(PCI_REG_DEVICE_FEATURES) }
    fn set_guest_features(&self, f: u32) { self.write32(PCI_REG_GUEST_FEATURES, f); }
    fn select_queue(&self, q: u16) { self.write16(PCI_REG_QUEUE_SELECT, q); }
    fn queue_size(&self) -> u16 { self.read16(PCI_REG_QUEUE_SIZE) }
    fn set_queue_pfn(&self, pfn: u32) { self.write32(PCI_REG_QUEUE_PFN, pfn); }
    fn get_queue_pfn(&self) -> u32 { self.read32(PCI_REG_QUEUE_PFN) }
    fn notify_queue(&self, q: u16) -> bool {
        sys::port_write16(self.io_base + PCI_REG_QUEUE_NOTIFY, q).is_ok()
    }
    fn read_capacity_sectors(&self) -> u64 {
        let lo = self.read32(PCI_REG_BLK_CAPACITY) as u64;
        let hi = self.read32(PCI_REG_BLK_CAPACITY + 4) as u64;
        (hi << 32) | lo
    }
}

// ============================================================================
// LegacyMmioTransport — volatile MMIO over sys::map_mmio region
// ============================================================================

/// Virtio-mmio v1 legacy register offsets (virtio spec §4.2.2, legacy).
const MMIO_REG_MAGIC_VALUE: usize = 0x000;
const MMIO_REG_VERSION: usize = 0x004;
const MMIO_REG_DEVICE_ID: usize = 0x008;
#[allow(dead_code)]
const MMIO_REG_VENDOR_ID: usize = 0x00c;
const MMIO_REG_HOST_FEATURES: usize = 0x010;
const MMIO_REG_HOST_FEATURES_SEL: usize = 0x014;
const MMIO_REG_GUEST_FEATURES: usize = 0x020;
const MMIO_REG_GUEST_FEATURES_SEL: usize = 0x024;
const MMIO_REG_GUEST_PAGE_SIZE: usize = 0x028;
const MMIO_REG_QUEUE_SEL: usize = 0x030;
const MMIO_REG_QUEUE_NUM_MAX: usize = 0x034;
const MMIO_REG_QUEUE_NUM: usize = 0x038;
const MMIO_REG_QUEUE_ALIGN: usize = 0x03c;
const MMIO_REG_QUEUE_PFN: usize = 0x040;
const MMIO_REG_QUEUE_NOTIFY: usize = 0x050;
#[allow(dead_code)]
const MMIO_REG_INTERRUPT_STATUS: usize = 0x060;
#[allow(dead_code)]
const MMIO_REG_INTERRUPT_ACK: usize = 0x064;
const MMIO_REG_STATUS: usize = 0x070;

/// Device-specific config region starts at 0x100. For virtio-blk the first
/// 8 bytes are `capacity` (u64, in 512-B sectors).
const MMIO_REG_CONFIG_BASE: usize = 0x100;
const MMIO_REG_BLK_CAPACITY_LO: usize = MMIO_REG_CONFIG_BASE + 0x00;
const MMIO_REG_BLK_CAPACITY_HI: usize = MMIO_REG_CONFIG_BASE + 0x04;

/// "virt" magic value written in the MagicValue register.
const MMIO_MAGIC: u32 = 0x74726976;
/// Legacy (v1) virtio-mmio version.
const MMIO_VERSION_LEGACY: u32 = 1;
/// Virtio-blk subsystem device ID.
const MMIO_DEVICE_ID_BLK: u32 = 2;
/// Host page size handed to the device at init (matches frame allocator).
const MMIO_GUEST_PAGE_SIZE: u32 = 4096;

pub struct LegacyMmioTransport {
    base: *mut u32,
}

// SAFETY: LegacyMmioTransport only calls volatile reads/writes through the
// pointer; there is no shared mutable state that crosses threads within the
// driver (services are single-threaded today).
unsafe impl Send for LegacyMmioTransport {}
unsafe impl Sync for LegacyMmioTransport {}

impl LegacyMmioTransport {
    /// Create a transport handle for a virtio-mmio region already mapped into
    /// the caller's address space via `sys::map_mmio`. Verifies MagicValue,
    /// Version, and DeviceID so a wrong mapping fails at init instead of
    /// limping to a queue-setup hang.
    pub fn new(mmio_base_vaddr: u64) -> Option<Self> {
        let base = mmio_base_vaddr as *mut u32;
        let t = Self { base };
        if t.read_raw(MMIO_REG_MAGIC_VALUE) != MMIO_MAGIC {
            sys::print(b"[BLK] mmio: bad MagicValue\n");
            return None;
        }
        if t.read_raw(MMIO_REG_VERSION) != MMIO_VERSION_LEGACY {
            sys::print(b"[BLK] mmio: not v1 legacy\n");
            return None;
        }
        if t.read_raw(MMIO_REG_DEVICE_ID) != MMIO_DEVICE_ID_BLK {
            sys::print(b"[BLK] mmio: not a virtio-blk device\n");
            return None;
        }
        // Guest-page-size is a one-shot write at init — the device needs it
        // to interpret QueuePFN correctly on legacy MMIO.
        t.write_raw(MMIO_REG_GUEST_PAGE_SIZE, MMIO_GUEST_PAGE_SIZE);
        Some(t)
    }

    fn read_raw(&self, offset: usize) -> u32 {
        // SAFETY: base is a kernel-mapped MMIO region of at least 0x200 bytes
        // (one page); all offsets used here are within that range, aligned
        // to 4 bytes.
        unsafe { core::ptr::read_volatile(self.base.byte_add(offset)) }
    }

    fn write_raw(&self, offset: usize, val: u32) {
        // SAFETY: same as read_raw.
        unsafe { core::ptr::write_volatile(self.base.byte_add(offset), val) }
    }

    fn reset(&self) { self.write_raw(MMIO_REG_STATUS, 0); }
    fn status(&self) -> u8 { self.read_raw(MMIO_REG_STATUS) as u8 }
    fn set_status(&self, bits: u8) {
        let current = self.read_raw(MMIO_REG_STATUS);
        self.write_raw(MMIO_REG_STATUS, current | bits as u32);
    }
    fn device_features(&self) -> u32 {
        self.write_raw(MMIO_REG_HOST_FEATURES_SEL, 0);
        self.read_raw(MMIO_REG_HOST_FEATURES)
    }
    fn set_guest_features(&self, f: u32) {
        self.write_raw(MMIO_REG_GUEST_FEATURES_SEL, 0);
        self.write_raw(MMIO_REG_GUEST_FEATURES, f);
    }
    fn select_queue(&self, q: u16) { self.write_raw(MMIO_REG_QUEUE_SEL, q as u32); }
    fn queue_size(&self) -> u16 { self.read_raw(MMIO_REG_QUEUE_NUM_MAX) as u16 }
    fn set_queue_num(&self, n: u16) { self.write_raw(MMIO_REG_QUEUE_NUM, n as u32); }
    fn set_queue_align(&self, align: u32) { self.write_raw(MMIO_REG_QUEUE_ALIGN, align); }
    fn set_queue_pfn(&self, pfn: u32) { self.write_raw(MMIO_REG_QUEUE_PFN, pfn); }
    fn get_queue_pfn(&self) -> u32 { self.read_raw(MMIO_REG_QUEUE_PFN) }
    fn notify_queue(&self, q: u16) -> bool {
        self.write_raw(MMIO_REG_QUEUE_NOTIFY, q as u32);
        true
    }
    fn read_capacity_sectors(&self) -> u64 {
        let lo = self.read_raw(MMIO_REG_BLK_CAPACITY_LO) as u64;
        let hi = self.read_raw(MMIO_REG_BLK_CAPACITY_HI) as u64;
        (hi << 32) | lo
    }
}

// ============================================================================
// Transport — dispatch enum
// ============================================================================

/// Carrier-agnostic virtio transport. The driver holds one of these regardless
/// of whether the device was discovered as virtio-pci (I/O BAR) or virtio-mmio
/// (DTB-derived MMIO region).
pub enum Transport {
    LegacyPci(LegacyPciTransport),
    LegacyMmio(LegacyMmioTransport),
}

impl Transport {
    pub fn reset(&self) {
        match self { Self::LegacyPci(t) => t.reset(), Self::LegacyMmio(t) => t.reset() }
    }
    pub fn status(&self) -> u8 {
        match self { Self::LegacyPci(t) => t.status(), Self::LegacyMmio(t) => t.status() }
    }
    pub fn set_status(&self, bits: u8) {
        match self { Self::LegacyPci(t) => t.set_status(bits), Self::LegacyMmio(t) => t.set_status(bits) }
    }
    pub fn device_features(&self) -> u32 {
        match self { Self::LegacyPci(t) => t.device_features(), Self::LegacyMmio(t) => t.device_features() }
    }
    pub fn set_guest_features(&self, f: u32) {
        match self { Self::LegacyPci(t) => t.set_guest_features(f), Self::LegacyMmio(t) => t.set_guest_features(f) }
    }
    pub fn select_queue(&self, q: u16) {
        match self { Self::LegacyPci(t) => t.select_queue(q), Self::LegacyMmio(t) => t.select_queue(q) }
    }
    pub fn queue_size(&self) -> u16 {
        match self { Self::LegacyPci(t) => t.queue_size(), Self::LegacyMmio(t) => t.queue_size() }
    }
    /// PCI legacy: no-op (queue_size register is RO, device picks size).
    /// MMIO legacy: writes QueueNum — required before set_queue_pfn.
    pub fn set_queue_num(&self, n: u16) {
        match self {
            Self::LegacyPci(_) => {}
            Self::LegacyMmio(t) => t.set_queue_num(n),
        }
    }
    /// PCI legacy: no-op. MMIO legacy: writes QueueAlign (4096).
    pub fn set_queue_align(&self, align: u32) {
        match self {
            Self::LegacyPci(_) => {}
            Self::LegacyMmio(t) => t.set_queue_align(align),
        }
    }
    pub fn set_queue_pfn(&self, pfn: u32) {
        match self { Self::LegacyPci(t) => t.set_queue_pfn(pfn), Self::LegacyMmio(t) => t.set_queue_pfn(pfn) }
    }
    pub fn get_queue_pfn(&self) -> u32 {
        match self { Self::LegacyPci(t) => t.get_queue_pfn(), Self::LegacyMmio(t) => t.get_queue_pfn() }
    }
    pub fn notify_queue(&self, q: u16) -> bool {
        match self { Self::LegacyPci(t) => t.notify_queue(q), Self::LegacyMmio(t) => t.notify_queue(q) }
    }
    pub fn read_capacity_sectors(&self) -> u64 {
        match self { Self::LegacyPci(t) => t.read_capacity_sectors(), Self::LegacyMmio(t) => t.read_capacity_sectors() }
    }
}
