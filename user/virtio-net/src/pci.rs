// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! PCI device discovery helpers for virtio-net.

use arcos_libsys as sys;

/// Virtio vendor ID.
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// Virtio-net legacy device ID (transitional).
pub const VIRTIO_NET_DEVICE_ID_LEGACY: u16 = 0x1000;

/// Virtio-net modern device ID.
pub const VIRTIO_NET_DEVICE_ID_MODERN: u16 = 0x1041;

/// Parsed PCI device info from the DeviceInfo syscall.
pub struct PciDeviceInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub bars: [BarInfo; 6],
    /// Index used in `sys::device_info(index, ...)` — needed to look up the
    /// modern-pci capability layout via `sys::virtio_modern_caps(index)`.
    pub index: u32,
}

/// A single BAR entry.
#[derive(Clone, Copy, Default)]
pub struct BarInfo {
    pub addr: u64,
    pub size: u32,
    pub is_io: bool,
}

impl PciDeviceInfo {
    /// Query device info from the kernel by index.
    pub fn from_index(index: u32) -> Option<Self> {
        let mut buf = [0u8; 108];
        let ret = sys::device_info(index, &mut buf);
        if ret < 0 {
            return None;
        }

        let vendor_id = u16::from_le_bytes([buf[0], buf[1]]);
        let device_id = u16::from_le_bytes([buf[2], buf[3]]);

        let mut bars = [BarInfo::default(); 6];
        for i in 0..6 {
            let o = 12 + i * 16;
            bars[i] = BarInfo {
                addr: u64::from_le_bytes([
                    buf[o], buf[o+1], buf[o+2], buf[o+3],
                    buf[o+4], buf[o+5], buf[o+6], buf[o+7],
                ]),
                size: u32::from_le_bytes([
                    buf[o+8], buf[o+9], buf[o+10], buf[o+11],
                ]),
                is_io: buf[o + 12] != 0,
            };
        }

        Some(PciDeviceInfo {
            vendor_id,
            device_id,
            class: buf[4],
            subclass: buf[5],
            bus: buf[6],
            device: buf[7],
            function: buf[8],
            bars,
            index,
        })
    }

    /// Find the virtio-net device by scanning all PCI devices.
    pub fn find_virtio_net() -> Option<Self> {
        for i in 0..32 {
            if let Some(dev) = Self::from_index(i) {
                if dev.vendor_id == VIRTIO_VENDOR_ID
                    && (dev.device_id == VIRTIO_NET_DEVICE_ID_LEGACY
                        || dev.device_id == VIRTIO_NET_DEVICE_ID_MODERN)
                {
                    return Some(dev);
                }
            } else {
                break; // No more devices
            }
        }
        None
    }
}
