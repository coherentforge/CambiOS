// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Virtio transport layer for virtio-net.
//!
//! Two carrier variants share a single public API via [`Transport`]:
//!
//! - [`ModernPciTransport`] — modern virtio-pci (virtio spec §4.1) over MMIO
//!   BAR capabilities. Used on x86_64 where QEMU's `-device virtio-net-pci`
//!   exposes both legacy I/O ports and modern capabilities; we speak modern
//!   because legacy PCI's `QueueSize` is read-only and QEMU reports 256, which
//!   the driver cannot safely match on its fixed-size pending buffers.
//! - [`LegacyMmioTransport`] — virtio-mmio v1 legacy (aarch64 + riscv64 QEMU
//!   virt). MMIO's `QueueNum` register is writable so the guest can clamp to
//!   [`crate::virtqueue::MAX_QUEUE_SIZE`] and the device honors it.
//!
//! Both transports expose the same methods so the driver is oblivious to the
//! discovery path.

use cambios_libsys as sys;
use cambios_libsys::VirtioModernCaps;

// ============================================================================
// Shared wire-protocol constants
// ============================================================================

/// Device status bits (virtio spec §2.1).
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

/// Virtio-net feature bits.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
/// Modern virtio requires bit 32 in the driver's accepted feature set.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// ============================================================================
// ModernPciTransport — virtio 1.0 over modern virtio-pci (capabilities + MMIO)
// ============================================================================

/// Common-configuration register offsets within `common_cfg` (virtio §4.1.4.3).
const CC_DEVICE_FEATURE_SELECT: usize = 0x00;
const CC_DEVICE_FEATURE: usize = 0x04;
const CC_DRIVER_FEATURE_SELECT: usize = 0x08;
const CC_DRIVER_FEATURE: usize = 0x0C;
const CC_NUM_QUEUES: usize = 0x12;
const CC_DEVICE_STATUS: usize = 0x14;
const CC_QUEUE_SELECT: usize = 0x16;
const CC_QUEUE_SIZE: usize = 0x18;
const CC_QUEUE_ENABLE: usize = 0x1C;
const CC_QUEUE_NOTIFY_OFF: usize = 0x1E;
const CC_QUEUE_DESC: usize = 0x20;
const CC_QUEUE_DRIVER: usize = 0x28;
const CC_QUEUE_DEVICE: usize = 0x30;

/// All four cap structures are expected to live in the same BAR for QEMU's
/// virtio-net-pci. If any differ, [`ModernPciTransport::new`] fails with
/// [`InitError::CapsSpanMultipleBars`].
pub struct ModernPciTransport {
    bar_vaddr: u64,
    common_cfg_off: u32,
    notify_off: u32,
    notify_off_multiplier: u32,
    device_cfg_off: u32,
}

// SAFETY: volatile MMIO only; no shared mutable state across threads.
unsafe impl Send for ModernPciTransport {}
unsafe impl Sync for ModernPciTransport {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    NotModernDevice,
    MissingCap,
    CapsSpanMultipleBars,
    MapMmioFailed,
}

impl ModernPciTransport {
    pub fn new(caps: &VirtioModernCaps, bar_phys: u64, bar_size: u64) -> Result<Self, InitError> {
        if caps.present == 0 {
            return Err(InitError::NotModernDevice);
        }
        if caps.common_cfg.length == 0
            || caps.notify_cfg.length == 0
            || caps.isr_cfg.length == 0
            || caps.device_cfg.length == 0
        {
            return Err(InitError::MissingCap);
        }
        let bar = caps.common_cfg.bar;
        if caps.notify_cfg.bar != bar
            || caps.isr_cfg.bar != bar
            || caps.device_cfg.bar != bar
        {
            return Err(InitError::CapsSpanMultipleBars);
        }

        let pages = bar_size.div_ceil(4096) as u32;
        let mapped = sys::map_mmio(bar_phys, pages);
        if mapped < 0 {
            return Err(InitError::MapMmioFailed);
        }

        Ok(Self {
            bar_vaddr: mapped as u64,
            common_cfg_off: caps.common_cfg.offset,
            notify_off: caps.notify_cfg.offset,
            notify_off_multiplier: caps.notify_off_multiplier,
            device_cfg_off: caps.device_cfg.offset,
        })
    }

    fn cc_ptr(&self, off: usize) -> *mut u8 {
        (self.bar_vaddr as *mut u8)
            .wrapping_add(self.common_cfg_off as usize)
            .wrapping_add(off)
    }

    fn read8(&self, off: usize) -> u8 {
        // SAFETY: bar_vaddr + common_cfg_off + off lies inside the mapped BAR.
        unsafe { core::ptr::read_volatile(self.cc_ptr(off)) }
    }
    fn write8(&self, off: usize, v: u8) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off), v) }
    }
    fn read16(&self, off: usize) -> u16 {
        // SAFETY: same as read8; 2-byte alignment on known offsets.
        unsafe { core::ptr::read_volatile(self.cc_ptr(off) as *const u16) }
    }
    fn write16(&self, off: usize, v: u16) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off) as *mut u16, v) }
    }
    fn read32(&self, off: usize) -> u32 {
        // SAFETY: same as read8; 4-byte alignment on known offsets.
        unsafe { core::ptr::read_volatile(self.cc_ptr(off) as *const u32) }
    }
    fn write32(&self, off: usize, v: u32) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off) as *mut u32, v) }
    }
    fn write64_split(&self, off: usize, v: u64) {
        self.write32(off, v as u32);
        self.write32(off + 4, (v >> 32) as u32);
    }

    pub fn reset(&self) { self.write8(CC_DEVICE_STATUS, 0); }
    pub fn status(&self) -> u8 { self.read8(CC_DEVICE_STATUS) }
    pub fn set_status_bit(&self, bit: u8) {
        let cur = self.status();
        self.write8(CC_DEVICE_STATUS, cur | bit);
    }

    pub fn device_features(&self) -> u64 {
        self.write32(CC_DEVICE_FEATURE_SELECT, 0);
        let lo = self.read32(CC_DEVICE_FEATURE) as u64;
        self.write32(CC_DEVICE_FEATURE_SELECT, 1);
        let hi = self.read32(CC_DEVICE_FEATURE) as u64;
        lo | (hi << 32)
    }

    pub fn set_driver_features(&self, f: u64) {
        self.write32(CC_DRIVER_FEATURE_SELECT, 0);
        self.write32(CC_DRIVER_FEATURE, f as u32);
        self.write32(CC_DRIVER_FEATURE_SELECT, 1);
        self.write32(CC_DRIVER_FEATURE, (f >> 32) as u32);
    }

    #[allow(dead_code)]
    pub fn num_queues(&self) -> u16 { self.read16(CC_NUM_QUEUES) }
    pub fn select_queue(&self, q: u16) { self.write16(CC_QUEUE_SELECT, q); }
    pub fn queue_size(&self) -> u16 { self.read16(CC_QUEUE_SIZE) }
    pub fn set_queue_size(&self, size: u16) { self.write16(CC_QUEUE_SIZE, size); }
    pub fn set_queue_addrs(&self, desc: u64, driver: u64, device: u64) {
        self.write64_split(CC_QUEUE_DESC, desc);
        self.write64_split(CC_QUEUE_DRIVER, driver);
        self.write64_split(CC_QUEUE_DEVICE, device);
    }
    pub fn enable_queue(&self) { self.write16(CC_QUEUE_ENABLE, 1); }
    pub fn queue_notify_off(&self) -> u16 { self.read16(CC_QUEUE_NOTIFY_OFF) }

    pub fn notify(&self, queue_index: u16, queue_notify_off: u16) {
        let addr = self.bar_vaddr as *mut u8;
        let off = self.notify_off as usize
            + (queue_notify_off as usize) * (self.notify_off_multiplier as usize);
        // SAFETY: notify_off + queue_notify_off * multiplier falls inside the
        // mapped BAR (cap length was validated at scan time). 2-byte writes
        // match the spec's requirement for notify registers.
        unsafe {
            core::ptr::write_volatile(addr.wrapping_add(off) as *mut u16, queue_index);
        }
    }

    pub fn read_mac(&self) -> [u8; 6] {
        let base = (self.bar_vaddr + self.device_cfg_off as u64) as *const u8;
        let mut mac = [0u8; 6];
        // SAFETY: device_cfg region is at least 8 bytes for virtio-net (mac[6]
        // + status[2]); we stay inside the region length already validated at
        // `new()` time.
        unsafe {
            for i in 0..6 {
                mac[i] = core::ptr::read_volatile(base.add(i));
            }
        }
        mac
    }
}

// ============================================================================
// LegacyMmioTransport — virtio-mmio v1 legacy (aarch64 + riscv64)
// ============================================================================

/// Virtio-mmio v1 legacy register offsets (virtio spec §4.2.2).
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

const MMIO_REG_CONFIG_BASE: usize = 0x100;
const MMIO_REG_MAC_ADDR: usize = MMIO_REG_CONFIG_BASE + 0x00;

const MMIO_MAGIC: u32 = 0x74726976;
const MMIO_VERSION_LEGACY: u32 = 1;
const MMIO_DEVICE_ID_NET: u32 = 1;
const MMIO_GUEST_PAGE_SIZE: u32 = 4096;

pub struct LegacyMmioTransport {
    base: *mut u32,
}

// SAFETY: volatile MMIO only; no shared mutable state across threads.
unsafe impl Send for LegacyMmioTransport {}
unsafe impl Sync for LegacyMmioTransport {}

impl LegacyMmioTransport {
    pub fn new(mmio_base_vaddr: u64) -> Option<Self> {
        let base = mmio_base_vaddr as *mut u32;
        let t = Self { base };
        if t.read_raw(MMIO_REG_MAGIC_VALUE) != MMIO_MAGIC {
            sys::print(b"[NET] mmio: bad MagicValue\n");
            return None;
        }
        if t.read_raw(MMIO_REG_VERSION) != MMIO_VERSION_LEGACY {
            sys::print(b"[NET] mmio: not v1 legacy\n");
            return None;
        }
        if t.read_raw(MMIO_REG_DEVICE_ID) != MMIO_DEVICE_ID_NET {
            sys::print(b"[NET] mmio: not a virtio-net device\n");
            return None;
        }
        t.write_raw(MMIO_REG_GUEST_PAGE_SIZE, MMIO_GUEST_PAGE_SIZE);
        Some(t)
    }

    fn read_raw(&self, offset: usize) -> u32 {
        // SAFETY: base points at a kernel-mapped MMIO region; offsets used
        // here are within its first 0x200 bytes, aligned to 4.
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
    fn device_features(&self) -> u64 {
        // Legacy MMIO exposes only the low 32 bits of the feature vector.
        self.write_raw(MMIO_REG_HOST_FEATURES_SEL, 0);
        self.read_raw(MMIO_REG_HOST_FEATURES) as u64
    }
    fn set_driver_features(&self, f: u64) {
        self.write_raw(MMIO_REG_GUEST_FEATURES_SEL, 0);
        self.write_raw(MMIO_REG_GUEST_FEATURES, f as u32);
    }
    fn select_queue(&self, q: u16) { self.write_raw(MMIO_REG_QUEUE_SEL, q as u32); }
    fn queue_size(&self) -> u16 { self.read_raw(MMIO_REG_QUEUE_NUM_MAX) as u16 }
    fn set_queue_num(&self, n: u16) { self.write_raw(MMIO_REG_QUEUE_NUM, n as u32); }
    fn set_queue_align(&self, align: u32) { self.write_raw(MMIO_REG_QUEUE_ALIGN, align); }
    fn set_queue_pfn(&self, pfn: u32) { self.write_raw(MMIO_REG_QUEUE_PFN, pfn); }
    fn notify_queue(&self, q: u16) {
        self.write_raw(MMIO_REG_QUEUE_NOTIFY, q as u32);
    }
    fn read_mac(&self) -> [u8; 6] {
        let lo = self.read_raw(MMIO_REG_MAC_ADDR);
        let hi = self.read_raw(MMIO_REG_MAC_ADDR + 4);
        [
            (lo & 0xFF) as u8,
            ((lo >> 8) & 0xFF) as u8,
            ((lo >> 16) & 0xFF) as u8,
            ((lo >> 24) & 0xFF) as u8,
            (hi & 0xFF) as u8,
            ((hi >> 8) & 0xFF) as u8,
        ]
    }
}

// ============================================================================
// Transport — dispatch enum
// ============================================================================

pub enum Transport {
    ModernPci(ModernPciTransport),
    LegacyMmio(LegacyMmioTransport),
}

/// Per-queue notify token returned by [`Transport::setup_queue`]. Modern-pci
/// reads `queue_notify_off` during setup and caches it here; legacy-mmio
/// ignores the field and notifies by writing the queue index alone.
#[derive(Clone, Copy)]
pub struct NotifyToken(pub u16);

impl Transport {
    pub fn reset(&self) {
        match self {
            Self::ModernPci(t) => t.reset(),
            Self::LegacyMmio(t) => t.reset(),
        }
    }
    pub fn status(&self) -> u8 {
        match self {
            Self::ModernPci(t) => t.status(),
            Self::LegacyMmio(t) => t.status(),
        }
    }
    pub fn set_status(&self, bits: u8) {
        match self {
            Self::ModernPci(t) => t.set_status_bit(bits),
            Self::LegacyMmio(t) => t.set_status(bits),
        }
    }
    pub fn device_features(&self) -> u64 {
        match self {
            Self::ModernPci(t) => t.device_features(),
            Self::LegacyMmio(t) => t.device_features(),
        }
    }
    pub fn set_driver_features(&self, f: u64) {
        match self {
            Self::ModernPci(t) => t.set_driver_features(f),
            Self::LegacyMmio(t) => t.set_driver_features(f),
        }
    }
    pub fn select_queue(&self, q: u16) {
        match self {
            Self::ModernPci(t) => t.select_queue(q),
            Self::LegacyMmio(t) => t.select_queue(q),
        }
    }
    pub fn queue_size(&self) -> u16 {
        match self {
            Self::ModernPci(t) => t.queue_size(),
            Self::LegacyMmio(t) => t.queue_size(),
        }
    }

    /// Unified queue-setup path. Selects the queue, reports addresses to the
    /// device, and (modern-pci only) caches the per-queue notify offset.
    ///
    /// Caller must have allocated the virtqueue's ring region and pass its
    /// `(desc, avail, used)` physical addresses alongside the negotiated size.
    pub fn setup_queue(
        &self,
        queue_index: u16,
        negotiated_size: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> NotifyToken {
        match self {
            Self::ModernPci(t) => {
                t.select_queue(queue_index);
                t.set_queue_size(negotiated_size);
                t.set_queue_addrs(desc_phys, avail_phys, used_phys);
                let off = t.queue_notify_off();
                t.enable_queue();
                NotifyToken(off)
            }
            Self::LegacyMmio(t) => {
                t.select_queue(queue_index);
                t.set_queue_num(negotiated_size);
                t.set_queue_align(4096);
                // Legacy MMIO takes a single PFN at the base of the ring.
                let pfn = (desc_phys / 4096) as u32;
                t.set_queue_pfn(pfn);
                // avail_phys / used_phys are implied by the contiguous layout
                // the driver allocated; the device recomputes them from PFN.
                let _ = avail_phys;
                let _ = used_phys;
                NotifyToken(0)
            }
        }
    }

    pub fn notify(&self, queue_index: u16, token: NotifyToken) {
        match self {
            Self::ModernPci(t) => t.notify(queue_index, token.0),
            Self::LegacyMmio(t) => t.notify_queue(queue_index),
        }
    }

    pub fn read_mac(&self) -> [u8; 6] {
        match self {
            Self::ModernPci(t) => t.read_mac(),
            Self::LegacyMmio(t) => t.read_mac(),
        }
    }
}
