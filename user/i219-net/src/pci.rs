// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! PCI device discovery for the Intel I219-LM Ethernet controller.
//!
//! The I219-LM is the integrated MAC on Intel 100/200/300/400-series PCH
//! chipsets paired with the Lewisville PHY. Several stepping IDs exist;
//! we probe a table of known IDs and accept any match.

use arcos_libsys as sys;

/// Intel PCI vendor ID.
pub const INTEL_VENDOR_ID: u16 = 0x8086;

/// Known I219-LM device IDs.
///
/// The 300-series PCH (Cannon Point, used by the Dell Precision 3630)
/// most likely uses 0x15BB (I219-LM v10) or 0x15BE (I219-LM v11), but
/// Dell ships minor stepping variants across SKUs. We probe the broader
/// I219-LM family — register layout is essentially identical across
/// v8-v13, only PHY firmware quirks differ.
///
/// To find the exact ID on your machine, boot a Linux live USB and run:
///   `lspci -nn | grep Ethernet`
pub const I219_DEVICE_IDS: &[u16] = &[
    // Cannon Point (300-series, Dell 3630 candidates)
    0x15BB, // I219-LM v10
    0x15BC, // I219-V v10
    0x15BD, // I219-V v11
    0x15BE, // I219-LM v11
    // Sunrise Point (100/200-series)
    0x15B7, // I219-LM v8
    0x15B8, // I219-V v8
    0x15B9, // I219-LM3 (Lewisburg)
    // Comet Lake / late 300-series
    0x15E3, // I219-LM v12
];

/// PCI class code for Ethernet controllers (class=0x02, subclass=0x00).
pub const PCI_CLASS_ETHERNET: u8 = 0x02;
pub const PCI_SUBCLASS_ETHERNET: u8 = 0x00;

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
        })
    }

    /// Find an Intel I219-LM device by scanning all PCI devices.
    /// Returns the first match against [`I219_DEVICE_IDS`].
    pub fn find_i219() -> Option<Self> {
        for i in 0..32 {
            if let Some(dev) = Self::from_index(i) {
                if dev.vendor_id == INTEL_VENDOR_ID
                    && dev.class == PCI_CLASS_ETHERNET
                    && dev.subclass == PCI_SUBCLASS_ETHERNET
                    && I219_DEVICE_IDS.contains(&dev.device_id)
                {
                    return Some(dev);
                }
            } else {
                break; // No more devices
            }
        }
        None
    }

    /// Returns the first MMIO BAR (non-I/O), or None.
    pub fn first_mmio_bar(&self) -> Option<&BarInfo> {
        self.bars.iter().find(|b| !b.is_io && b.addr != 0)
    }
}
