// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! PCI device discovery helpers for usb-host.
//!
//! Parses the 108-byte descriptor returned by `SYS_DEVICE_INFO` (kernel
//! handler: `src/syscalls/dispatcher.rs::handle_device_info`) and filters
//! the device list down to the xHCI controller.

use cambios_libsys as sys;

/// PCI base class for Serial Bus Controllers (PCI spec § 1.2 / appendix D).
pub const PCI_CLASS_SERIAL_BUS: u8 = 0x0C;
/// PCI subclass for USB controllers within the Serial Bus class.
pub const PCI_SUBCLASS_USB: u8 = 0x03;
/// PCI programming interface code for xHCI (USB 3.x extensible host).
/// Distinguishes xHCI from EHCI (0x20), OHCI (0x10), UHCI (0x00).
pub const PCI_PROG_IF_XHCI: u8 = 0x30;

/// Parsed PCI device info from the `SYS_DEVICE_INFO` syscall. Mirrors the
/// layout used by virtio-blk / virtio-input; descriptor format documented
/// in `src/syscalls/dispatcher.rs::handle_device_info`.
#[allow(dead_code)]
pub struct PciDeviceInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub bars: [BarInfo; 6],
}

/// A single BAR entry. Fields retained for future-use diagnostics
/// (MMIO sizing, BAR classification).
#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
pub struct BarInfo {
    pub addr: u64,
    pub size: u32,
    pub is_io: bool,
}

impl PciDeviceInfo {
    /// Query device info from the kernel by index. Returns `None` when the
    /// kernel reports no device at that slot (end-of-list).
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
            prog_if: buf[9],
            bus: buf[6],
            device: buf[7],
            function: buf[8],
            bars,
        })
    }

    /// Find the xHCI controller by scanning all PCI devices. Filters on
    /// class+subclass+prog_if so coexisting EHCI / OHCI / UHCI controllers
    /// on the same machine are skipped — important for bare-metal where
    /// modern Intel chipsets expose multiple USB controller classes.
    pub fn find_xhci() -> Option<Self> {
        for i in 0..32 {
            match Self::from_index(i) {
                Some(dev) => {
                    if dev.class == PCI_CLASS_SERIAL_BUS
                        && dev.subclass == PCI_SUBCLASS_USB
                        && dev.prog_if == PCI_PROG_IF_XHCI
                    {
                        return Some(dev);
                    }
                }
                None => return None, // end of device list
            }
        }
        None
    }
}
