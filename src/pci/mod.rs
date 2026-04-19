// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! PCI (and PCI-shaped) device table
//!
//! Holds a kernel-global table of devices surfaced through the
//! `SYS_DEVICE_INFO` syscall. On x86_64 the table is populated by the
//! Configuration Space mechanism 1 scan ([`scan`]). On riscv64 it is
//! populated from DTB-discovered virtio-mmio regions via
//! [`register_virtio_mmio`] — the syscall shape is the same either way,
//! so user-space drivers use unchanged discovery code.
//!
//! # Port I/O (x86_64 only)
//!
//! PCI configuration space access uses 32-bit port I/O at:
//! - `0x0CF8` — CONFIG_ADDRESS (write bus/device/function/offset)
//! - `0x0CFC` — CONFIG_DATA (read/write the selected dword)
//!
//! # Safety
//!
//! `scan()` (x86_64) is unsafe because it performs raw port I/O and
//! writes to PCI config space (BAR size detection). It must be called
//! exactly once, during BSP boot, before any driver tries to claim a
//! device. `register_virtio_mmio` (riscv64) has an analogous
//! single-writer-at-boot invariant.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Maximum number of PCI devices we can track.
pub const MAX_PCI_DEVICES: usize = 32;

/// CONFIG_ADDRESS port (0x0CF8).
#[cfg(target_arch = "x86_64")]
const CONFIG_ADDRESS: u16 = 0x0CF8;

/// CONFIG_DATA port (0x0CFC).
#[cfg(target_arch = "x86_64")]
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
// 32-bit port I/O helpers (x86_64 only)
// ---------------------------------------------------------------------------

/// Write a 32-bit value to an x86 I/O port.
///
/// # Safety
/// The caller must ensure `port` is a valid I/O port and that the write is
/// appropriate in the current hardware state.
#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
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
// PCI configuration space access (x86_64 only)
// ---------------------------------------------------------------------------

/// Build a CONFIG_ADDRESS value for the given BDF + register offset.
///
/// Layout of CONFIG_ADDRESS (bit 31 = enable):
/// ```text
/// 31      24 23    16 15   11 10    8 7       2 1 0
/// | Enable | Reserved|  Bus  | Device| Function| Offset | 00 |
/// ```
#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
unsafe fn pci_config_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let addr = config_address(bus, device, function, offset);
    // SAFETY: CONFIG_ADDRESS (0xCF8) is a standard PCI port. Selecting the config register.
    unsafe { outl(CONFIG_ADDRESS, addr) };
    // SAFETY: CONFIG_DATA (0xCFC) is a standard PCI port. Reading the selected register.
    unsafe { inl(CONFIG_DATA) }
}

/// Write a 32-bit dword to PCI configuration space.
///
/// # Safety
/// Must be called with interrupts in a safe state. Writing to PCI config
/// space can have side effects (e.g., BAR reprogramming). The caller must
/// know what they are doing.
#[cfg(target_arch = "x86_64")]
unsafe fn pci_config_write32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let addr = config_address(bus, device, function, offset);
    // SAFETY: CONFIG_ADDRESS (0xCF8) is a standard PCI port. Selecting the config register.
    unsafe { outl(CONFIG_ADDRESS, addr) };
    // SAFETY: CONFIG_DATA (0xCFC) is a standard PCI port. Writing the selected register.
    unsafe { outl(CONFIG_DATA, value) };
}

// ---------------------------------------------------------------------------
// BAR decoding (x86_64 only)
// ---------------------------------------------------------------------------

/// BAR register offsets in PCI config space (0x10 .. 0x24, six BARs).
#[cfg(target_arch = "x86_64")]
const BAR_OFFSETS: [u8; 6] = [0x10, 0x14, 0x18, 0x1C, 0x20, 0x24];

/// Decode BARs for a device, including BAR size detection.
///
/// # Safety
/// Temporarily writes 0xFFFF_FFFF to each BAR (standard size-detection
/// protocol) and restores the original value. Must not be called while
/// any driver is actively using the device.
#[cfg(target_arch = "x86_64")]
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

            // Size detection: standard BAR sizing protocol — save, write
            // all-ones, read back, restore.
            // SAFETY: Standard PCI BAR sizing — writes all-ones to the BAR.
            unsafe { pci_config_write32(bus, device, function, offset, 0xFFFF_FFFF) };
            // SAFETY: Read back the size mask.
            let size_raw = unsafe { pci_config_read32(bus, device, function, offset) };
            // SAFETY: Restore the original BAR value.
            unsafe { pci_config_write32(bus, device, function, offset, raw) };
            let size_mask = size_raw & 0xFFFF_FFFC;
            if size_mask != 0 {
                bar_sizes[i] = (!size_mask).wrapping_add(1);
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
                // SAFETY: Standard BAR sizing — write all-ones to low BAR.
                unsafe { pci_config_write32(bus, device, function, offset, 0xFFFF_FFFF) };
                // SAFETY: Write all-ones to high BAR.
                unsafe {
                    pci_config_write32(
                        bus, device, function, BAR_OFFSETS[i + 1], 0xFFFF_FFFF,
                    )
                };
                // SAFETY: Read back low size mask.
                let size_lo =
                    unsafe { pci_config_read32(bus, device, function, offset) };
                // SAFETY: Read back high size mask.
                let _size_hi = unsafe {
                    pci_config_read32(
                        bus, device, function, BAR_OFFSETS[i + 1],
                    )
                };
                // SAFETY: Restore original low BAR value.
                unsafe { pci_config_write32(bus, device, function, offset, raw) };
                // SAFETY: Restore original high BAR value.
                unsafe {
                    pci_config_write32(
                        bus, device, function, BAR_OFFSETS[i + 1], raw_hi,
                    )
                };

                // For size, we only store the low 32-bit portion (sizes
                // > 4 GiB are uncommon and don't fit in bar_sizes[u32]).
                let size_mask = size_lo & 0xFFFF_FFF0;
                if size_mask != 0 {
                    bar_sizes[i] = (!size_mask).wrapping_add(1);
                }

                // Next BAR is the high half — mark it consumed
                bars[i + 1] = 0;
                bar_sizes[i + 1] = 0;
                i += 2;
            } else {
                // 32-bit MMIO BAR
                bars[i] = (raw & 0xFFFF_FFF0) as u64;

                // Size detection: standard BAR sizing protocol.
                // SAFETY: Write all-ones to the BAR.
                unsafe { pci_config_write32(bus, device, function, offset, 0xFFFF_FFFF) };
                // SAFETY: Read back the size mask.
                let size_raw =
                    unsafe { pci_config_read32(bus, device, function, offset) };
                // SAFETY: Restore the original BAR value.
                unsafe { pci_config_write32(bus, device, function, offset, raw) };
                let size_mask = size_raw & 0xFFFF_FFF0;
                if size_mask != 0 {
                    bar_sizes[i] = (!size_mask).wrapping_add(1);
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
#[cfg(target_arch = "x86_64")]
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
/// x86_64 only — aarch64/riscv64 do not expose a port-I/O syscall.
#[cfg(target_arch = "x86_64")]
pub fn is_port_in_pci_bar(port: u16) -> bool {
    let count = device_count();
    let port_u64 = port as u64;
    // SAFETY: count <= MAX_PCI_DEVICES, elements 0..count are initialized
    // by scan_bus. Shared reference only — no mutation.
    let devices = unsafe { &DEVICES[..count] };
    for dev in devices {
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
    // SAFETY: count <= MAX_PCI_DEVICES, elements 0..count are initialized
    // by scan_bus. Shared reference only.
    let devices = unsafe { &DEVICES[..count] };
    devices.iter().find(|dev| dev.vendor_id == vendor && dev.device_id == device)
}

// ---------------------------------------------------------------------------
// Synthetic device registration (non-PCI carriers surfaced through the
// same syscall shape — currently riscv64 virtio-mmio, see ADR-013 / R-6)
// ---------------------------------------------------------------------------

/// Virtio vendor ID used for synthetic virtio-mmio entries, matching the
/// OASIS virtio-over-PCI convention so user-space service discovery code
/// (e.g. `find_virtio_blk()`) recognizes the synthetic entries without
/// special-casing the carrier.
const SYNTHETIC_VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// Offset of the `DeviceID` register inside a virtio-mmio v1 register
/// file (virtio spec §4.2.2).
const VIRTIO_MMIO_DEVICE_ID_OFFSET: usize = 0x008;

/// Register a virtio-mmio device discovered via the DTB.
///
/// Reads the virtio `DeviceID` from the MMIO region (via HHDM — the
/// region must be covered by the boot-time HHDM gigapage mapping, which
/// on QEMU virt is true for all standard virtio-mmio slots), then pushes
/// a synthesized [`PciDevice`] into the global table. The synthesized
/// entry uses the virtio-over-PCI vendor/device ID convention
/// (vendor = 0x1AF4, device = 0x1000 + virtio_id - 1), which is what
/// existing user-space drivers already look up via
/// [`find_by_vendor_device`] / the `SYS_DEVICE_INFO` syscall.
///
/// BAR 0 is populated with the MMIO region as a memory-mapped BAR so
/// the driver's `sys::map_mmio` + transport-selection path fires the
/// `LegacyMmioTransport` branch.
///
/// Returns `false` if the MMIO region reports an invalid MagicValue,
/// a non-legacy version, a zero DeviceID (QEMU exposes empty slots),
/// or the global table is full. In all failure cases the table is
/// left unchanged.
///
/// # Safety
/// - Must be called at boot before any reader of the device table.
/// - Must not race with [`scan`] or another `register_virtio_mmio`.
/// - `hhdm_offset` must already be published via [`crate::hhdm_offset`].
/// - `phys_base` must point at real virtio-mmio hardware whose MMIO
///   region is kernel-readable at `hhdm_offset + phys_base`.
#[cfg(target_arch = "riscv64")]
pub unsafe fn register_virtio_mmio(phys_base: u64, size: u64) -> bool {
    // Virtio-mmio v1 layout — mirrors the user-space transport in
    // user/virtio-blk/src/transport.rs and user/virtio-net/src/transport.rs.
    const MAGIC_OFFSET: usize = 0x000;
    const VERSION_OFFSET: usize = 0x004;
    const EXPECTED_MAGIC: u32 = 0x74726976; // "virt"
    const EXPECTED_VERSION_LEGACY: u32 = 1;

    let vbase = (phys_base + crate::hhdm_offset()) as *const u32;

    // SAFETY: caller guarantees this region is HHDM-mapped and maps to
    // real virtio-mmio hardware. Volatile 32-bit reads are the
    // spec-defined access width.
    let magic = unsafe { core::ptr::read_volatile(vbase.byte_add(MAGIC_OFFSET)) };
    if magic != EXPECTED_MAGIC {
        return false;
    }
    // SAFETY: same as above.
    let version = unsafe { core::ptr::read_volatile(vbase.byte_add(VERSION_OFFSET)) };
    if version != EXPECTED_VERSION_LEGACY {
        return false;
    }
    // SAFETY: same as above.
    let virtio_id =
        unsafe { core::ptr::read_volatile(vbase.byte_add(VIRTIO_MMIO_DEVICE_ID_OFFSET)) };
    if virtio_id == 0 {
        // QEMU advertises 8 virtio-mmio slots at fixed addresses and
        // reports `DeviceID == 0` for unpopulated ones. That is not an
        // error — the slot is just empty.
        return false;
    }

    let current = DEVICE_COUNT.load(Ordering::Acquire);
    if current >= MAX_PCI_DEVICES {
        return false;
    }

    // OASIS virtio-over-PCI transitional mapping:
    //   virtio_id 1 (net)   → device 0x1000
    //   virtio_id 2 (blk)   → device 0x1001
    //   virtio_id 3 (cons)  → device 0x1002
    //   ...
    let synthetic_device_id = 0x1000u16.wrapping_add((virtio_id as u16).wrapping_sub(1));

    // Size caps at u32 — virtio-mmio regions are small (≤ 4 KiB in
    // practice) so truncation of an unexpectedly large value just
    // reports 0 and any user-space driver that notices will fail the
    // subsequent `map_mmio` rather than reading past the region.
    let bar_size: u32 = u32::try_from(size).unwrap_or(0);

    let mut bars = [0u64; 6];
    let mut bar_sizes = [0u32; 6];
    let mut bar_is_io = [false; 6];
    bars[0] = phys_base;
    bar_sizes[0] = bar_size;
    bar_is_io[0] = false; // MMIO, not I/O port

    // SAFETY: index checked above; we are the sole writer during boot.
    unsafe {
        DEVICES[current] = PciDevice {
            bus: 0,
            device: 0,
            function: 0,
            vendor_id: SYNTHETIC_VIRTIO_VENDOR_ID,
            device_id: synthetic_device_id,
            class: 0,
            subclass: 0,
            bars,
            bar_sizes,
            bar_is_io,
        };
    }
    DEVICE_COUNT.store(current + 1, Ordering::Release);
    true
}
