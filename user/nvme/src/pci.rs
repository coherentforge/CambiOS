// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Finding the NVMe controller through the kernel's `DeviceInfo` table.

use cambios_libsys as sys;

/// HARDWARE: PCI class 01h (mass storage), subclass 08h (NVM), prog-if 02h
/// (NVMe I/O command set). Any prog-if under 01:08 is accepted — 01h is
/// NVMHCI (pre-1.0), 02h NVMe; the controller registers decide.
pub const CLASS_MASS_STORAGE: u8 = 0x01;
pub const SUBCLASS_NVM: u8 = 0x08;

/// SCAFFOLDING: upper bound on `DeviceInfo` indices probed. Matches the
/// kernel's `MAX_PCI_DEVICES` (128); the loop stops at the first index
/// the kernel rejects anyway, so this only bounds a pathological table.
/// Replace when: the kernel exports its device count through a syscall.
const MAX_DEVICE_INDEX: u32 = 128;

#[derive(Clone, Copy, Default)]
pub struct BarInfo {
    pub addr: u64,
    pub size: u32,
    pub is_io: bool,
}

/// The `DeviceInfo` descriptor (108 bytes) decoded.
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

impl PciDeviceInfo {
    pub fn from_index(index: u32) -> Option<Self> {
        let mut buf = [0u8; 108];
        if sys::device_info(index, &mut buf) < 0 {
            return None;
        }
        let mut bars = [BarInfo::default(); 6];
        for (i, bar) in bars.iter_mut().enumerate() {
            let o = 12 + i * 16;
            *bar = BarInfo {
                addr: u64::from_le_bytes([
                    buf[o], buf[o + 1], buf[o + 2], buf[o + 3],
                    buf[o + 4], buf[o + 5], buf[o + 6], buf[o + 7],
                ]),
                size: u32::from_le_bytes([buf[o + 8], buf[o + 9], buf[o + 10], buf[o + 11]]),
                is_io: buf[o + 12] != 0,
            };
        }
        Some(PciDeviceInfo {
            vendor_id: u16::from_le_bytes([buf[0], buf[1]]),
            device_id: u16::from_le_bytes([buf[2], buf[3]]),
            class: buf[4],
            subclass: buf[5],
            bus: buf[6],
            device: buf[7],
            function: buf[8],
            prog_if: buf[9],
            bars,
        })
    }

    /// The first NVMe controller the kernel enumerated, on any bus.
    pub fn find_nvme() -> Option<Self> {
        for i in 0..MAX_DEVICE_INDEX {
            match Self::from_index(i) {
                Some(dev) if dev.class == CLASS_MASS_STORAGE && dev.subclass == SUBCLASS_NVM => {
                    return Some(dev)
                }
                Some(_) => continue,
                None => break,
            }
        }
        None
    }
}
