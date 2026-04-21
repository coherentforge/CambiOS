// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Modern virtio-pci transport (virtio 1.0+, spec §4.1).
//!
//! Unlike the legacy virtio-pci transport used by `user/virtio-blk` (I/O
//! port BAR, fixed register map), modern virtio uses **vendor-specific
//! PCI capabilities** that point into an MMIO BAR at driver-discovered
//! offsets. The kernel's `SYS_VIRTIO_MODERN_CAPS` syscall returns those
//! offsets pre-parsed; this module consumes them.
//!
//! Four register structures matter for 4.a:
//!
//! - **Common configuration** (`cfg_type = 1`): device status, feature
//!   negotiation, per-queue setup registers.
//! - **Notify** (`cfg_type = 2`): doorbell MMIO; per-queue notify address
//!   is `notify_cfg.offset + queue_notify_off * notify_off_multiplier`.
//! - **ISR** (`cfg_type = 3`): interrupt status (unused in 4.a; poll-only).
//! - **Device-specific** (`cfg_type = 4`): virtio-gpu specific registers.
//!
//! **Simplifying assumption for 4.a:** all four cap structures share the
//! same BAR. On QEMU's virtio-gpu-pci this is always BAR 4. If a future
//! device splits them across BARs we'll need to map multiple regions;
//! for now we refuse to init rather than silently map the wrong memory.
//!
//! Revisit when: `InitError::CapsSpanMultipleBars` fires on real
//! hardware — the surviving driver path is `sys::map_mmio` once per
//! distinct BAR, which is a straightforward extension but not worth
//! writing until a real device demands it.

use arcos_libsys as sys;
use arcos_libsys::VirtioModernCaps;

/// Device status bits (virtio spec §2.1).
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

/// Modern virtio requires `VIRTIO_F_VERSION_1` (bit 32) — the driver
/// declares "I speak the modern spec." Without it the device may
/// operate in legacy compatibility mode or refuse init.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Common configuration register offsets within `common_cfg`
/// (virtio spec §4.1.4.3).
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

/// All four cap structures are expected to live in the same BAR for
/// QEMU's virtio-gpu-pci. If any differ, `ModernTransport::new` fails.
pub struct ModernTransport {
    /// Virtual address of the mapped BAR (from `sys::map_mmio`).
    bar_vaddr: u64,
    /// Offset within BAR of the common_cfg structure.
    common_cfg_off: u32,
    /// Offset within BAR of the notify structure.
    notify_off: u32,
    /// Notify-off multiplier (spec §4.1.4.4).
    notify_off_multiplier: u32,
    /// Offset within BAR of the device-specific config structure.
    device_cfg_off: u32,
}

// SAFETY: This struct only performs volatile MMIO reads/writes through
// raw pointers derived from `bar_vaddr`. No shared mutable state crosses
// threads (this driver is single-threaded).
unsafe impl Send for ModernTransport {}
unsafe impl Sync for ModernTransport {}

/// Errors from `ModernTransport::new`. Expressed as enum variants so
/// `_start` can log specific classes rather than a generic "init failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// `caps.present == 0` — the PCI device is not a virtio-modern device.
    NotModernDevice,
    /// One of the four required cap types was absent
    /// (common/notify/isr/device). The cap walk found some but not all.
    MissingCap,
    /// At least two required caps point at different BARs. Supporting this
    /// needs per-cap MMIO maps; deferred until a real device exhibits it.
    ///
    /// Revisit when: this variant is actually returned by `ModernTransport::new`
    /// against real hardware (not QEMU's virtio-gpu-pci, which always
    /// groups all four caps on BAR 4). The fix is per-cap MMIO maps.
    CapsSpanMultipleBars,
    /// `sys::map_mmio` returned an error mapping the BAR.
    MapMmioFailed,
}

impl ModernTransport {
    /// Build a transport handle from kernel-parsed caps + the PCI BAR
    /// physical address and size. Maps the BAR into this process's
    /// address space and records the per-structure offsets.
    ///
    /// The caller is responsible for having confirmed the device is a
    /// virtio-modern device via `caps.present`; the `NotModernDevice`
    /// return value double-checks.
    pub fn new(caps: &VirtioModernCaps, bar_phys: u64, bar_size: u64) -> Result<Self, InitError> {
        if caps.present == 0 {
            return Err(InitError::NotModernDevice);
        }

        // All four caps must be populated — `length == 0` means the
        // kernel's walker didn't find this cap type.
        if caps.common_cfg.length == 0
            || caps.notify_cfg.length == 0
            || caps.isr_cfg.length == 0
            || caps.device_cfg.length == 0
        {
            return Err(InitError::MissingCap);
        }

        // Enforce single-BAR simplifying assumption.
        let bar = caps.common_cfg.bar;
        if caps.notify_cfg.bar != bar
            || caps.isr_cfg.bar != bar
            || caps.device_cfg.bar != bar
        {
            return Err(InitError::CapsSpanMultipleBars);
        }

        // Map the BAR. Round size up to pages and ask the kernel.
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

    /// Virtual address of the device-specific config structure.
    /// virtio-gpu's config region lives here (virtio spec §5.7.4).
    pub fn device_cfg_vaddr(&self) -> u64 {
        self.bar_vaddr + self.device_cfg_off as u64
    }

    // ── Volatile raw accessors over common_cfg ──

    fn cc_ptr(&self, off: usize) -> *mut u8 {
        (self.bar_vaddr as *mut u8)
            .wrapping_add(self.common_cfg_off as usize)
            .wrapping_add(off)
    }

    fn read8(&self, off: usize) -> u8 {
        // SAFETY: bar_vaddr + common_cfg_off + off lives inside the
        // kernel-mapped MMIO region (common_cfg length was non-zero).
        unsafe { core::ptr::read_volatile(self.cc_ptr(off)) }
    }

    fn write8(&self, off: usize, val: u8) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off), val) }
    }

    fn read16(&self, off: usize) -> u16 {
        // SAFETY: same as read8; 2-byte aligned offsets used.
        unsafe { core::ptr::read_volatile(self.cc_ptr(off) as *const u16) }
    }

    fn write16(&self, off: usize, val: u16) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off) as *mut u16, val) }
    }

    fn read32(&self, off: usize) -> u32 {
        // SAFETY: same as read8; 4-byte aligned offsets used.
        unsafe { core::ptr::read_volatile(self.cc_ptr(off) as *const u32) }
    }

    fn write32(&self, off: usize, val: u32) {
        // SAFETY: same as read8.
        unsafe { core::ptr::write_volatile(self.cc_ptr(off) as *mut u32, val) }
    }

    fn write64(&self, off: usize, val: u64) {
        // Spec allows the driver to write as two 32-bit halves (low then
        // high) to devices that expect 32-bit access only — safer default.
        self.write32(off, val as u32);
        self.write32(off + 4, (val >> 32) as u32);
    }

    // ── Device status (virtio §3.1) ──

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

    // ── Feature negotiation (virtio §3.1) ──

    /// Read the 64-bit device_feature vector by driving feature_select
    /// 0 and 1 (low and high halves).
    pub fn device_features(&self) -> u64 {
        self.write32(CC_DEVICE_FEATURE_SELECT, 0);
        let lo = self.read32(CC_DEVICE_FEATURE) as u64;
        self.write32(CC_DEVICE_FEATURE_SELECT, 1);
        let hi = self.read32(CC_DEVICE_FEATURE) as u64;
        lo | (hi << 32)
    }

    /// Acknowledge accepted features (64 bits, driven via select 0/1).
    pub fn set_driver_features(&self, features: u64) {
        self.write32(CC_DRIVER_FEATURE_SELECT, 0);
        self.write32(CC_DRIVER_FEATURE, features as u32);
        self.write32(CC_DRIVER_FEATURE_SELECT, 1);
        self.write32(CC_DRIVER_FEATURE, (features >> 32) as u32);
    }

    // ── Queue setup ──

    /// Total number of supported virtqueues.
    pub fn num_queues(&self) -> u16 {
        self.read16(CC_NUM_QUEUES)
    }

    pub fn select_queue(&self, q: u16) {
        self.write16(CC_QUEUE_SELECT, q);
    }

    /// Device-reported maximum queue size for the selected queue.
    /// Returns 0 if the queue is not implemented.
    pub fn queue_size(&self) -> u16 {
        self.read16(CC_QUEUE_SIZE)
    }

    /// Clamp the selected queue's size down to a driver-chosen value
    /// (must be a power of two ≤ device's reported max).
    pub fn set_queue_size(&self, size: u16) {
        self.write16(CC_QUEUE_SIZE, size);
    }

    /// Physical addresses of the three virtqueue regions.
    pub fn set_queue_addrs(&self, desc_phys: u64, driver_phys: u64, device_phys: u64) {
        self.write64(CC_QUEUE_DESC, desc_phys);
        self.write64(CC_QUEUE_DRIVER, driver_phys);
        self.write64(CC_QUEUE_DEVICE, device_phys);
    }

    pub fn enable_queue(&self) {
        self.write16(CC_QUEUE_ENABLE, 1);
    }

    /// Per-queue notify offset — multiplied by `notify_off_multiplier`
    /// and added to `notify_off` to reach the queue's doorbell.
    pub fn queue_notify_off(&self) -> u16 {
        self.read16(CC_QUEUE_NOTIFY_OFF)
    }

    /// Ring the doorbell for a queue by writing its index to the
    /// queue-specific notify register inside the notify MMIO region.
    pub fn notify(&self, queue_index: u16, queue_notify_off: u16) {
        let addr = self.bar_vaddr as *mut u8;
        let off = self.notify_off as usize
            + (queue_notify_off as usize) * (self.notify_off_multiplier as usize);
        // SAFETY: notify_off + queue_notify_off * multiplier lies inside
        // the BAR region we mapped (the kernel validated the cap-reported
        // length at scan time). 2-byte writes match the spec's
        // requirement for notify registers.
        unsafe {
            core::ptr::write_volatile(addr.wrapping_add(off) as *mut u16, queue_index);
        }
    }
}
