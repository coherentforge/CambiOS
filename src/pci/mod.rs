// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! PCI bus enumeration via x86 Configuration Space mechanism 1
//!
//! Performs a brute-force scan of bus 0 at boot, discovering devices and
//! reading their BARs. Results are stored in a static table that is written
//! once during `scan()` and read-only thereafter.
//!
//! # Port I/O
//!
//! PCI configuration space access uses 32-bit port I/O at:
//! - `0x0CF8` — CONFIG_ADDRESS (write bus/device/function/offset)
//! - `0x0CFC` — CONFIG_DATA (read/write the selected dword)
//!
//! # Safety
//!
//! `scan()` is unsafe because it performs raw port I/O and writes to PCI
//! config space (BAR size detection). It must be called exactly once,
//! during BSP boot, before any driver tries to claim a device.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Maximum number of PCI devices we can track.
pub const MAX_PCI_DEVICES: usize = 32;

/// CONFIG_ADDRESS port (0x0CF8).
const CONFIG_ADDRESS: u16 = 0x0CF8;

/// CONFIG_DATA port (0x0CFC).
const CONFIG_DATA: u16 = 0x0CFC;

// ---------------------------------------------------------------------------
// PCI device descriptor
// ---------------------------------------------------------------------------

/// A discovered PCI device.
#[derive(Clone, Copy)]
pub struct PciDevice {
    /// PCI bus number (always 0 in this implementation).
    pub bus: u8,
    /// Device number (0-31).
    pub device: u8,
    /// Function number (0-7).
    pub function: u8,
    /// Vendor ID (0xFFFF = invalid / no device).
    pub vendor_id: u16,
    /// Device ID.
    pub device_id: u16,
    /// Class code (offset 0x0B).
    pub class: u8,
    /// Subclass code (offset 0x0A).
    pub subclass: u8,
    /// Base Address Registers — decoded addresses (0 = unused).
    /// For MMIO BARs: physical address. For I/O BARs: port number.
    pub bars: [u64; 6],
    /// BAR sizes in bytes (0 = unused / unimplemented).
    pub bar_sizes: [u32; 6],
    /// BAR type: true = I/O port, false = MMIO.
    pub bar_is_io: [bool; 6],
}

impl PciDevice {
    const EMPTY: Self = Self {
        bus: 0,
        device: 0,
        function: 0,
        vendor_id: 0xFFFF,
        device_id: 0,
        class: 0,
        subclass: 0,
        bars: [0; 6],
        bar_sizes: [0; 6],
        bar_is_io: [false; 6],
    };
}

// ---------------------------------------------------------------------------
// Static device table (written once at boot, read-only after)
// ---------------------------------------------------------------------------

/// Device table. Written only by `scan()`, read-only afterwards.
static mut DEVICES: [PciDevice; MAX_PCI_DEVICES] = [PciDevice::EMPTY; MAX_PCI_DEVICES];

/// Number of devices discovered so far.
static DEVICE_COUNT: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// 32-bit port I/O helpers
// ---------------------------------------------------------------------------

/// Write a 32-bit value to an x86 I/O port.
///
/// # Safety
/// The caller must ensure `port` is a valid I/O port and that the write is
/// appropriate in the current hardware state.
#[inline]
unsafe fn outl(port: u16, value: u32) {
    // SAFETY: Caller guarantees port validity. 32-bit OUT instruction.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read a 32-bit value from an x86 I/O port.
///
/// # Safety
/// The caller must ensure `port` is a valid I/O port and that the read is
/// appropriate in the current hardware state.
#[inline]
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: Caller guarantees port validity. 32-bit IN instruction.
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            in("dx") port,
            out("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

// ---------------------------------------------------------------------------
// PCI configuration space access
// ---------------------------------------------------------------------------

/// Build a CONFIG_ADDRESS value for the given BDF + register offset.
///
/// Layout of CONFIG_ADDRESS (bit 31 = enable):
/// ```text
/// 31      24 23    16 15   11 10    8 7       2 1 0
/// | Enable | Reserved|  Bus  | Device| Function| Offset | 00 |
/// ```
#[inline]
const fn config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    // Bit 31: enable configuration space mapping
    0x8000_0000
        | ((bus as u32) << 16)
        | ((device as u32 & 0x1F) << 11)
        | ((function as u32 & 0x07) << 8)
        | ((offset as u32) & 0xFC) // bits 1:0 must be zero (dword-aligned)
}

/// Read a 32-bit dword from PCI configuration space.
///
/// # Safety
/// Must be called with interrupts in a safe state (boot or IRQs disabled).
/// `offset` must be dword-aligned (bits 1:0 = 0).
unsafe fn pci_config_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let addr = config_address(bus, device, function, offset);
    // SAFETY: CONFIG_ADDRESS and CONFIG_DATA are standard PCI ports.
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        inl(CONFIG_DATA)
    }
}

/// Write a 32-bit dword to PCI configuration space.
///
/// # Safety
/// Must be called with interrupts in a safe state. Writing to PCI config
/// space can have side effects (e.g., BAR reprogramming). The caller must
/// know what they are doing.
unsafe fn pci_config_write32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let addr = config_address(bus, device, function, offset);
    // SAFETY: CONFIG_ADDRESS and CONFIG_DATA are standard PCI ports.
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        outl(CONFIG_DATA, value);
    }
}

// ---------------------------------------------------------------------------
// BAR decoding
// ---------------------------------------------------------------------------

/// BAR register offsets in PCI config space (0x10 .. 0x24, six BARs).
const BAR_OFFSETS: [u8; 6] = [0x10, 0x14, 0x18, 0x1C, 0x20, 0x24];

/// Decode BARs for a device, including BAR size detection.
///
/// # Safety
/// Temporarily writes 0xFFFF_FFFF to each BAR (standard size-detection
/// protocol) and restores the original value. Must not be called while
/// any driver is actively using the device.
unsafe fn decode_bars(
    bus: u8,
    device: u8,
    function: u8,
    bars: &mut [u64; 6],
    bar_sizes: &mut [u32; 6],
    bar_is_io: &mut [bool; 6],
) {
    let mut i = 0usize;
    while i < 6 {
        let offset = BAR_OFFSETS[i];

        // SAFETY: Standard PCI config read — device was already validated.
        let raw = unsafe { pci_config_read32(bus, device, function, offset) };

        if raw == 0 {
            // BAR not implemented
            i += 1;
            continue;
        }

        let is_io = (raw & 0x1) != 0;

        if is_io {
            // I/O BAR — mask bit 0 (I/O indicator) and bit 1 (reserved)
            let addr = (raw & 0xFFFF_FFFC) as u64;
            bars[i] = addr;
            bar_is_io[i] = true;

            // Size detection
            // SAFETY: Standard BAR sizing protocol — save, write all-ones,
            // read back, restore.
            unsafe {
                pci_config_write32(bus, device, function, offset, 0xFFFF_FFFF);
                let size_raw = pci_config_read32(bus, device, function, offset);
                pci_config_write32(bus, device, function, offset, raw);
                let size_mask = size_raw & 0xFFFF_FFFC;
                if size_mask != 0 {
                    bar_sizes[i] = (!size_mask).wrapping_add(1);
                }
            }

            i += 1;
        } else {
            // Memory BAR
            let bar_type = (raw >> 1) & 0x3; // bits 2:1

            if bar_type == 0b10 && i < 5 {
                // 64-bit BAR — spans this register and the next
                // SAFETY: Reading the next BAR register for the high 32 bits.
                let raw_hi = unsafe {
                    pci_config_read32(bus, device, function, BAR_OFFSETS[i + 1])
                };
                let addr_lo = (raw & 0xFFFF_FFF0) as u64;
                let addr_hi = raw_hi as u64;
                bars[i] = addr_lo | (addr_hi << 32);

                // Size detection for 64-bit BAR: write all-ones to both
                // halves, read back, restore both.
                // SAFETY: Standard BAR sizing — temporarily overwrites both
                // BAR registers and restores them.
                unsafe {
                    pci_config_write32(bus, device, function, offset, 0xFFFF_FFFF);
                    pci_config_write32(
                        bus, device, function, BAR_OFFSETS[i + 1], 0xFFFF_FFFF,
                    );
                    let size_lo =
                        pci_config_read32(bus, device, function, offset);
                    let _size_hi = pci_config_read32(
                        bus, device, function, BAR_OFFSETS[i + 1],
                    );
                    pci_config_write32(bus, device, function, offset, raw);
                    pci_config_write32(
                        bus, device, function, BAR_OFFSETS[i + 1], raw_hi,
                    );

                    // For size, we only store the low 32-bit portion (sizes
                    // > 4 GiB are uncommon and don't fit in bar_sizes[u32]).
                    let size_mask = size_lo & 0xFFFF_FFF0;
                    if size_mask != 0 {
                        bar_sizes[i] = (!size_mask).wrapping_add(1);
                    }
                }

                // Next BAR is the high half — mark it consumed
                bars[i + 1] = 0;
                bar_sizes[i + 1] = 0;
                i += 2;
            } else {
                // 32-bit MMIO BAR
                bars[i] = (raw & 0xFFFF_FFF0) as u64;

                // Size detection
                // SAFETY: Standard BAR sizing protocol.
                unsafe {
                    pci_config_write32(bus, device, function, offset, 0xFFFF_FFFF);
                    let size_raw =
                        pci_config_read32(bus, device, function, offset);
                    pci_config_write32(bus, device, function, offset, raw);
                    let size_mask = size_raw & 0xFFFF_FFF0;
                    if size_mask != 0 {
                        bar_sizes[i] = (!size_mask).wrapping_add(1);
                    }
                }

                i += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan PCI bus 0, devices 0-31, functions 0-7.
///
/// Discovered devices are stored in the global `DEVICES` table. This must be
/// called exactly once during BSP boot, before any PCI driver initialization.
///
/// # Safety
///
/// - Must be called at boot before drivers access PCI devices.
/// - Performs port I/O and temporarily writes to PCI BARs for size detection.
/// - Not reentrant and not thread-safe (single-writer at boot).
pub unsafe fn scan() {
    let mut count = 0usize;

    for dev in 0u8..32 {
        for func in 0u8..8 {
            // SAFETY: Standard PCI config read to probe vendor ID.
            let id_reg = unsafe { pci_config_read32(0, dev, func, 0x00) };
            let vendor_id = (id_reg & 0xFFFF) as u16;

            if vendor_id == 0xFFFF {
                // No device present on this function
                continue;
            }

            if count >= MAX_PCI_DEVICES {
                // Table full — stop scanning
                DEVICE_COUNT.store(count, Ordering::Release);
                return;
            }

            let device_id = ((id_reg >> 16) & 0xFFFF) as u16;

            // Class / subclass at offset 0x08 (bits 31:16 = class:subclass)
            // SAFETY: Device confirmed present by vendor ID check.
            let class_reg = unsafe { pci_config_read32(0, dev, func, 0x08) };
            let class = ((class_reg >> 24) & 0xFF) as u8;
            let subclass = ((class_reg >> 16) & 0xFF) as u8;

            let mut bars = [0u64; 6];
            let mut bar_sizes = [0u32; 6];
            let mut bar_is_io = [false; 6];
            // SAFETY: Device confirmed present; BAR sizing protocol is safe
            // at boot before drivers claim devices.
            unsafe {
                decode_bars(0, dev, func, &mut bars, &mut bar_sizes, &mut bar_is_io);
            }

            // SAFETY: `count < MAX_PCI_DEVICES` guaranteed by the check above.
            // This is the only writer (called once at boot).
            unsafe {
                DEVICES[count] = PciDevice {
                    bus: 0,
                    device: dev,
                    function: func,
                    vendor_id,
                    device_id,
                    class,
                    subclass,
                    bars,
                    bar_sizes,
                    bar_is_io,
                };
            }
            count += 1;
        }
    }

    DEVICE_COUNT.store(count, Ordering::Release);
}

/// Number of PCI devices discovered during `scan()`.
pub fn device_count() -> usize {
    DEVICE_COUNT.load(Ordering::Acquire)
}

/// Get a reference to the Nth discovered device (0-indexed).
///
/// Returns `None` if `index >= device_count()`.
pub fn get_device(index: usize) -> Option<&'static PciDevice> {
    if index >= device_count() {
        return None;
    }
    // SAFETY: `index < device_count()` and the table was fully written by
    // `scan()` (which completed before any reader — guaranteed by
    // Acquire/Release on DEVICE_COUNT). The data is immutable after scan.
    Some(unsafe { &DEVICES[index] })
}

/// Check whether an I/O port falls within any PCI device's I/O BAR range.
///
/// Returns `true` if the port is within a known PCI I/O BAR, `false` otherwise.
/// Used by the kernel to validate port I/O syscalls from user-space.
pub fn is_port_in_pci_bar(port: u16) -> bool {
    let count = device_count();
    let port_u64 = port as u64;
    for i in 0..count {
        // SAFETY: i < count, same reasoning as get_device.
        let dev = unsafe { &DEVICES[i] };
        for bar_idx in 0..6 {
            if dev.bar_is_io[bar_idx] && dev.bars[bar_idx] != 0 && dev.bar_sizes[bar_idx] != 0 {
                let base = dev.bars[bar_idx];
                let end = base + dev.bar_sizes[bar_idx] as u64;
                if port_u64 >= base && port_u64 < end {
                    return true;
                }
            }
        }
    }
    false
}

/// Find a device by vendor and device ID.
///
/// Returns the first match, or `None` if no matching device was found.
pub fn find_by_vendor_device(vendor: u16, device: u16) -> Option<&'static PciDevice> {
    let count = device_count();
    for i in 0..count {
        // SAFETY: i < count, same reasoning as get_device.
        let dev = unsafe { &DEVICES[i] };
        if dev.vendor_id == vendor && dev.device_id == device {
            return Some(dev);
        }
    }
    None
}
