// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Modern virtio-pci transport (virtio 1.0+, spec §4.1).
//!
//! Mechanical copy of `user/scanout-virtio-gpu/src/transport.rs`.
//! Kept per-driver for now (rather than factored into a shared
//! `user/libvirtio/` crate) because this is only the second modern
//! virtio driver in-tree; extracting a library at N=2 risks
//! under-designed seams. The third modern virtio driver (e.g.
//! virtio-net-modern, when it lands) is the observable trigger to
//! factor a shared crate.
//!
//! Revisit when: a third modern-virtio consumer appears, OR a
//! real-hardware port trips `InitError::CapsSpanMultipleBars`
//! (which forces per-cap MMIO maps anyway and makes a shared
//! library worth the effort).

use cambios_libsys as sys;
use cambios_libsys::VirtioModernCaps;

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

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

pub struct ModernTransport {
    bar_vaddr: u64,
    common_cfg_off: u32,
    notify_off: u32,
    notify_off_multiplier: u32,
    device_cfg_off: u32,
}

// SAFETY: This struct only performs volatile MMIO reads/writes through
// raw pointers derived from `bar_vaddr`. No shared mutable state crosses
// threads (this driver is single-threaded).
unsafe impl Send for ModernTransport {}
unsafe impl Sync for ModernTransport {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    NotModernDevice,
    MissingCap,
    CapsSpanMultipleBars,
    MapMmioFailed,
}

impl ModernTransport {
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

    /// Virtual address of the device-specific config region. virtio-input
    /// uses this as the `virtio_input_config` struct (spec §5.8).
    pub fn device_cfg_vaddr(&self) -> u64 {
        self.bar_vaddr + self.device_cfg_off as u64
    }

    fn cc_ptr(&self, off: usize) -> *mut u8 {
        (self.bar_vaddr as *mut u8)
            .wrapping_add(self.common_cfg_off as usize)
            .wrapping_add(off)
    }

    fn read8(&self, off: usize) -> u8 {
        // SAFETY: bar_vaddr + common_cfg_off + off lies in the mapped
        // MMIO region (cap length was non-zero at init).
        unsafe { core::ptr::read_volatile(self.cc_ptr(off)) }
    }
    fn write8(&self, off: usize, val: u8) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off), val) }
    }
    fn read16(&self, off: usize) -> u16 {
        // SAFETY: same as read8; 2-byte aligned offsets.
        unsafe { core::ptr::read_volatile(self.cc_ptr(off) as *const u16) }
    }
    fn write16(&self, off: usize, val: u16) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off) as *mut u16, val) }
    }
    fn read32(&self, off: usize) -> u32 {
        // SAFETY: same as read8; 4-byte aligned offsets.
        unsafe { core::ptr::read_volatile(self.cc_ptr(off) as *const u32) }
    }
    fn write32(&self, off: usize, val: u32) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off) as *mut u32, val) }
    }
    fn write64(&self, off: usize, val: u64) {
        self.write32(off, val as u32);
        self.write32(off + 4, (val >> 32) as u32);
    }

    pub fn reset(&self) {
        self.write8(CC_DEVICE_STATUS, 0);
    }
    pub fn status(&self) -> u8 {
        self.read8(CC_DEVICE_STATUS)
    }
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

    pub fn set_driver_features(&self, features: u64) {
        self.write32(CC_DRIVER_FEATURE_SELECT, 0);
        self.write32(CC_DRIVER_FEATURE, features as u32);
        self.write32(CC_DRIVER_FEATURE_SELECT, 1);
        self.write32(CC_DRIVER_FEATURE, (features >> 32) as u32);
    }

    pub fn num_queues(&self) -> u16 {
        self.read16(CC_NUM_QUEUES)
    }
    pub fn select_queue(&self, q: u16) {
        self.write16(CC_QUEUE_SELECT, q);
    }
    pub fn queue_size(&self) -> u16 {
        self.read16(CC_QUEUE_SIZE)
    }
    pub fn set_queue_size(&self, size: u16) {
        self.write16(CC_QUEUE_SIZE, size);
    }
    pub fn set_queue_addrs(&self, desc_phys: u64, driver_phys: u64, device_phys: u64) {
        self.write64(CC_QUEUE_DESC, desc_phys);
        self.write64(CC_QUEUE_DRIVER, driver_phys);
        self.write64(CC_QUEUE_DEVICE, device_phys);
    }
    pub fn enable_queue(&self) {
        self.write16(CC_QUEUE_ENABLE, 1);
    }
    pub fn queue_notify_off(&self) -> u16 {
        self.read16(CC_QUEUE_NOTIFY_OFF)
    }
    pub fn notify(&self, queue_index: u16, queue_notify_off: u16) {
        let addr = self.bar_vaddr as *mut u8;
        let off = self.notify_off as usize
            + (queue_notify_off as usize) * (self.notify_off_multiplier as usize);
        // SAFETY: offset is within the mapped BAR; 2-byte writes match
        // the notify register width.
        unsafe {
            core::ptr::write_volatile(addr.wrapping_add(off) as *mut u16, queue_index);
        }
    }
}
