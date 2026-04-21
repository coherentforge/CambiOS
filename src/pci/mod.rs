// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

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
// Virtio-modern PCI capability descriptors (virtio spec §4.1.4)
// ---------------------------------------------------------------------------
//
// Modern virtio-pci devices (device IDs 0x1040..=0x107F, spec revision 1.0+)
// advertise their register structures through vendor-specific PCI capabilities
// with `cap_vndr == 0x09`. Each capability names a BAR index and an offset
// within that BAR where one of the four required register structures lives:
// common config, notify config, ISR status, and device-specific config. A
// fifth structure (PCI-config-access) is optional and not parsed here.
//
// Virtio-gpu and every future modern virtio-pci driver needs these offsets
// to map the device. Parsing at boot (single-writer) and surfacing them via
// the same `PciDevice` table means userspace drivers don't need to touch
// PCI config space themselves — a primitive the current syscall surface
// does not (and should not) expose.

/// One parsed virtio-pci capability entry (virtio spec §4.1.4.1).
///
/// `bar` is the BAR index (0..=5) the structure lives in; `offset` and
/// `length` locate the structure within that BAR. All three are zero when
/// the cap type was not present on the device.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioPciCapEntry {
    pub bar: u8,
    pub _pad: [u8; 3],
    pub offset: u32,
    pub length: u32,
}

/// Parsed virtio-modern capability set for a PCI device.
///
/// `present == 0` means "this device is not a virtio-modern device, or its
/// capability list did not contain any virtio caps." Drivers MUST check
/// `present` before reading any of the cap fields.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioModernCaps {
    /// `cfg_type = 1` — common configuration structure.
    pub common_cfg: VirtioPciCapEntry,
    /// `cfg_type = 2` — notification structure.
    pub notify_cfg: VirtioPciCapEntry,
    /// From the notify cap's trailing u32 (virtio spec §4.1.4.4).
    /// Multiplier applied to queue-specific notify_off to reach the
    /// actual notify register within `notify_cfg`.
    pub notify_off_multiplier: u32,
    pub _pad: u32,
    /// `cfg_type = 3` — ISR status structure.
    pub isr_cfg: VirtioPciCapEntry,
    /// `cfg_type = 4` — device-specific configuration structure.
    pub device_cfg: VirtioPciCapEntry,
    /// 1 iff at least one virtio cap was found on this device.
    pub present: u8,
    pub _pad2: [u8; 7],
}

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
    /// Virtio-modern capability set, parsed once at scan() time.
    /// `virtio_modern.present == 0` for non-virtio-modern devices.
    pub virtio_modern: VirtioModernCaps,
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
        virtio_modern: VirtioModernCaps {
            common_cfg: VirtioPciCapEntry {
                bar: 0,
                _pad: [0; 3],
                offset: 0,
                length: 0,
            },
            notify_cfg: VirtioPciCapEntry {
                bar: 0,
                _pad: [0; 3],
                offset: 0,
                length: 0,
            },
            notify_off_multiplier: 0,
            _pad: 0,
            isr_cfg: VirtioPciCapEntry {
                bar: 0,
                _pad: [0; 3],
                offset: 0,
                length: 0,
            },
            device_cfg: VirtioPciCapEntry {
                bar: 0,
                _pad: [0; 3],
                offset: 0,
                length: 0,
            },
            present: 0,
            _pad2: [0; 7],
        },
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
// Virtio-modern capability list walk (x86_64 only)
// ---------------------------------------------------------------------------

/// HARDWARE: PCI Local Bus Spec 3.0 §6.2.3 — Status register bit 4,
/// "Capabilities List," set when a header-type-0 device advertises a
/// linked list of extended capabilities starting at byte 0x34.
pub(crate) const STATUS_CAP_LIST: u16 = 0x0010;

/// HARDWARE: PCI Local Bus Spec 3.0 §6.1 — config-space offset of the
/// 16-bit Status register (upper half of dword at 0x04).
pub(crate) const STATUS_OFFSET: usize = 0x06;

/// HARDWARE: PCI Local Bus Spec 3.0 §6.2.10 — config-space offset of the
/// Capabilities Pointer (header type 0; points at the first cap entry).
pub(crate) const CAPABILITIES_PTR_OFFSET: usize = 0x34;

/// HARDWARE: PCI Local Bus Spec 3.0 — vendor-specific capability ID.
/// Virtio-modern uses this ID with its own layout (virtio spec §4.1.4).
pub(crate) const CAP_VENDOR_SPECIFIC: u8 = 0x09;

/// SCAFFOLDING: hard bound on capability-list walk iterations.
/// Standard 256-byte PCI config space can hold at most 64 caps of the
/// minimum 4-byte size; virtio modern caps are 16–20 bytes each so the
/// realistic count is much lower. The bound guarantees termination on a
/// malformed or malicious cap list (circular `next` pointer).
/// Why: a verifier cannot reason about an unbounded walk driven by device
/// memory. Replace when: PCIe extended config space (4 KiB) handling
/// lands and we need to accommodate longer cap chains.
pub(crate) const MAX_CAP_WALK_ITERATIONS: usize = 64;

/// HARDWARE: virtio spec §4.1.4 `cfg_type` values identifying which of
/// the four virtio-modern capability structures a given PCI cap entry
/// describes (common cfg, notify cfg, ISR cfg, device-specific cfg).
pub(crate) const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// HARDWARE: virtio spec §4.1.4.4 — notify (doorbell) capability type.
pub(crate) const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// HARDWARE: virtio spec §4.1.4.5 — ISR status capability type.
pub(crate) const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// HARDWARE: virtio spec §4.1.4.6 — device-specific configuration type.
pub(crate) const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// HARDWARE: PCI Local Bus Spec 3.0 §6.1 — standard (non-PCIe-extended)
/// configuration space is 256 bytes. PCIe extended config (4 KiB) is
/// accessed via ECAM and is out of scope until a device needs it.
pub(crate) const PCI_CONFIG_SPACE_SIZE: usize = 256;

/// Read a byte from a config-space snapshot at `offset`, returning 0 on
/// out-of-range offsets. Used by the pure cap-list parser on a buffer.
#[inline]
fn read_u8(cfg: &[u8], offset: usize) -> u8 {
    cfg.get(offset).copied().unwrap_or(0)
}

/// Read a little-endian u16 from a config-space snapshot at `offset`,
/// returning 0 on out-of-range offsets.
#[inline]
fn read_u16_le(cfg: &[u8], offset: usize) -> u16 {
    if offset + 2 > cfg.len() {
        return 0;
    }
    u16::from_le_bytes([cfg[offset], cfg[offset + 1]])
}

/// Read a little-endian u32 from a config-space snapshot at `offset`,
/// returning 0 on out-of-range offsets.
#[inline]
fn read_u32_le(cfg: &[u8], offset: usize) -> u32 {
    if offset + 4 > cfg.len() {
        return 0;
    }
    u32::from_le_bytes([cfg[offset], cfg[offset + 1], cfg[offset + 2], cfg[offset + 3]])
}

/// Parse virtio-modern vendor capabilities from a 256-byte PCI config
/// space snapshot (virtio spec §4.1.4). Pure function with no I/O —
/// callable from tests with a synthetic `cfg` buffer.
///
/// Returns `VirtioModernCaps { present: 0, .. }` on devices without a
/// capabilities list, devices whose cap list contains no recognized
/// virtio entries, or malformed / truncated cap chains.
///
/// Termination is bounded by [`MAX_CAP_WALK_ITERATIONS`] so a circular
/// `next`-pointer chain cannot hang the parser.
pub fn parse_virtio_modern_caps(cfg: &[u8]) -> VirtioModernCaps {
    let mut caps = VirtioModernCaps::default();

    // Capabilities List bit in Status register.
    let status = read_u16_le(cfg, STATUS_OFFSET);
    if status & STATUS_CAP_LIST == 0 {
        return caps;
    }

    // Low 2 bits reserved per spec.
    let mut cap_ptr = read_u8(cfg, CAPABILITIES_PTR_OFFSET) & 0xFC;
    let mut any_virtio_cap = false;
    let mut steps = 0usize;

    while cap_ptr != 0 && steps < MAX_CAP_WALK_ITERATIONS {
        steps += 1;

        // Standard config space is 256 bytes; reject pointers into the
        // device-header region (<0x40) or past the end.
        let p = cap_ptr as usize;
        if p < 0x40 || p >= PCI_CONFIG_SPACE_SIZE {
            break;
        }

        let vndr = read_u8(cfg, p);
        let next = read_u8(cfg, p + 1);

        if vndr == CAP_VENDOR_SPECIFIC {
            // virtio_pci_cap: {vndr:1, next:1, len:1, cfg_type:1, bar:1,
            // pad:3, offset:4, length:4} = 16 bytes. notify cap adds a
            // trailing notify_off_multiplier:4 = 20 bytes total. Require
            // the full 16-byte base fits before reading any of it.
            if p + 16 > PCI_CONFIG_SPACE_SIZE {
                cap_ptr = next & 0xFC;
                continue;
            }

            let cfg_type = read_u8(cfg, p + 3);
            let bar = read_u8(cfg, p + 4);
            let cap_offset = read_u32_le(cfg, p + 8);
            let cap_length = read_u32_le(cfg, p + 12);

            let entry = VirtioPciCapEntry {
                bar,
                _pad: [0; 3],
                offset: cap_offset,
                length: cap_length,
            };

            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => {
                    caps.common_cfg = entry;
                    any_virtio_cap = true;
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    caps.notify_cfg = entry;
                    // notify_off_multiplier at +16; only valid when the
                    // 4 trailing bytes fit in standard config space.
                    if p + 20 <= PCI_CONFIG_SPACE_SIZE {
                        caps.notify_off_multiplier = read_u32_le(cfg, p + 16);
                    }
                    any_virtio_cap = true;
                }
                VIRTIO_PCI_CAP_ISR_CFG => {
                    caps.isr_cfg = entry;
                    any_virtio_cap = true;
                }
                VIRTIO_PCI_CAP_DEVICE_CFG => {
                    caps.device_cfg = entry;
                    any_virtio_cap = true;
                }
                _ => {
                    // Unknown cfg_type (e.g. 5 = VIRTIO_PCI_CAP_PCI_CFG).
                    // Ignore — not needed by any CambiOS driver today.
                }
            }
        }

        cap_ptr = next & 0xFC;
    }

    if any_virtio_cap {
        caps.present = 1;
    }
    caps
}

/// Snapshot 256 bytes of PCI configuration space for `(bus, device, function)`
/// into a stack-local buffer, then parse virtio-modern capabilities. The
/// two-pass shape (snapshot → parse) keeps the parse logic pure and
/// testable without port-I/O access.
///
/// # Safety
/// - Must be called at boot with exclusive access to PCI config space
///   (no other CPU is using 0xCF8/0xCFC).
/// - The `(bus, device, function)` triple must name a device that was
///   confirmed present (vendor ID != 0xFFFF) by the caller.
#[cfg(target_arch = "x86_64")]
unsafe fn walk_virtio_modern_caps(bus: u8, device: u8, function: u8) -> VirtioModernCaps {
    let mut cfg = [0u8; PCI_CONFIG_SPACE_SIZE];
    // Walk standard config space dword-by-dword (64 reads).
    let mut off = 0usize;
    while off < PCI_CONFIG_SPACE_SIZE {
        // SAFETY: caller confirmed device presence; port I/O is safe at
        // boot (single-writer at this phase).
        let dword = unsafe { pci_config_read32(bus, device, function, off as u8) };
        cfg[off..off + 4].copy_from_slice(&dword.to_le_bytes());
        off += 4;
    }
    parse_virtio_modern_caps(&cfg)
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

            // Parse virtio-modern capability structures, if any. Returns
            // a `present: 0` result for non-virtio devices.
            // SAFETY: Device confirmed present; cap walk is side-effect-free.
            let virtio_modern = unsafe { walk_virtio_modern_caps(0, dev, func) };

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
                    virtio_modern,
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

/// HARDWARE: OASIS virtio-over-PCI convention — the vendor ID every
/// virtio device carries. Used here for synthetic virtio-mmio entries
/// so user-space discovery code (e.g. `find_virtio_blk()`) recognizes
/// them without special-casing the MMIO carrier.
const SYNTHETIC_VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// HARDWARE: virtio spec §4.2.2 — offset of the `DeviceID` register
/// inside a virtio-mmio v1 register file.
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
    /// HARDWARE: virtio spec §4.2.2 — `MagicValue` register offset.
    const MAGIC_OFFSET: usize = 0x000;
    /// HARDWARE: virtio spec §4.2.2 — `Version` register offset.
    const VERSION_OFFSET: usize = 0x004;
    /// HARDWARE: virtio spec §4.2.2 — `MagicValue` register reads as
    /// the ASCII string "virt" (little-endian u32) on a live device.
    const EXPECTED_MAGIC: u32 = 0x74726976; // "virt"
    /// HARDWARE: virtio spec §4.2.2 — legacy (v1) device version.
    /// Modern (v2) virtio-mmio devices report 2; we reject them here
    /// because this discovery path only wires legacy MMIO carriers.
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
            // virtio-mmio transport does not expose PCI capabilities;
            // synthetic entries always have `virtio_modern.present == 0`.
            // Driver code must route by BAR 0 classification
            // (is_io == false, MMIO region) rather than by this field.
            virtio_modern: VirtioModernCaps {
                common_cfg: VirtioPciCapEntry {
                    bar: 0,
                    _pad: [0; 3],
                    offset: 0,
                    length: 0,
                },
                notify_cfg: VirtioPciCapEntry {
                    bar: 0,
                    _pad: [0; 3],
                    offset: 0,
                    length: 0,
                },
                notify_off_multiplier: 0,
                _pad: 0,
                isr_cfg: VirtioPciCapEntry {
                    bar: 0,
                    _pad: [0; 3],
                    offset: 0,
                    length: 0,
                },
                device_cfg: VirtioPciCapEntry {
                    bar: 0,
                    _pad: [0; 3],
                    offset: 0,
                    length: 0,
                },
                present: 0,
                _pad2: [0; 7],
            },
        };
    }
    DEVICE_COUNT.store(current + 1, Ordering::Release);
    true
}

// ---------------------------------------------------------------------------
// Tests — virtio-modern capability parser
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 256-byte PCI config-space snapshot with the capabilities
    /// bit set in the Status register and a caller-supplied first-cap
    /// pointer. Everything else is zero. Tests fill in cap bytes by
    /// direct indexing.
    fn blank_cfg_with_cap_ptr(first_cap: u8) -> [u8; PCI_CONFIG_SPACE_SIZE] {
        let mut cfg = [0u8; PCI_CONFIG_SPACE_SIZE];
        // Status register: bit 4 = Capabilities List. Status is the upper
        // 16 bits of the dword at 0x04; little-endian so Status[7:0] lives
        // at byte 0x06.
        cfg[STATUS_OFFSET] = (STATUS_CAP_LIST & 0xFF) as u8;
        cfg[STATUS_OFFSET + 1] = ((STATUS_CAP_LIST >> 8) & 0xFF) as u8;
        cfg[CAPABILITIES_PTR_OFFSET] = first_cap;
        cfg
    }

    /// Write one virtio_pci_cap struct at `p` in `cfg`. Returns the total
    /// bytes written (16 for non-notify caps, 20 for notify caps).
    fn write_virtio_cap(
        cfg: &mut [u8],
        p: usize,
        next: u8,
        cfg_type: u8,
        bar: u8,
        offset: u32,
        length: u32,
        notify_off_multiplier: Option<u32>,
    ) -> usize {
        let cap_len = if notify_off_multiplier.is_some() { 20u8 } else { 16u8 };
        cfg[p] = CAP_VENDOR_SPECIFIC;
        cfg[p + 1] = next;
        cfg[p + 2] = cap_len;
        cfg[p + 3] = cfg_type;
        cfg[p + 4] = bar;
        // pad[5..8] = 0 by construction
        cfg[p + 8..p + 12].copy_from_slice(&offset.to_le_bytes());
        cfg[p + 12..p + 16].copy_from_slice(&length.to_le_bytes());
        if let Some(mul) = notify_off_multiplier {
            cfg[p + 16..p + 20].copy_from_slice(&mul.to_le_bytes());
        }
        cap_len as usize
    }

    #[test]
    fn no_cap_list_bit_returns_not_present() {
        let cfg = [0u8; PCI_CONFIG_SPACE_SIZE];
        // Status register bit 4 not set.
        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 0);
        assert_eq!(caps, VirtioModernCaps::default());
    }

    #[test]
    fn cap_list_bit_with_null_pointer_returns_not_present() {
        let cfg = blank_cfg_with_cap_ptr(0);
        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 0);
    }

    #[test]
    fn single_common_cfg_cap() {
        let mut cfg = blank_cfg_with_cap_ptr(0x40);
        write_virtio_cap(&mut cfg, 0x40, 0, VIRTIO_PCI_CAP_COMMON_CFG,
            /*bar*/ 4, /*offset*/ 0x0000, /*length*/ 0x38, None);
        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 1);
        assert_eq!(caps.common_cfg.bar, 4);
        assert_eq!(caps.common_cfg.offset, 0x0000);
        assert_eq!(caps.common_cfg.length, 0x38);
        // Others unset.
        assert_eq!(caps.notify_cfg, VirtioPciCapEntry::default());
        assert_eq!(caps.isr_cfg, VirtioPciCapEntry::default());
        assert_eq!(caps.device_cfg, VirtioPciCapEntry::default());
        assert_eq!(caps.notify_off_multiplier, 0);
    }

    #[test]
    fn full_virtio_cap_chain_populates_all_fields() {
        // Four caps chained: common (0x40) → notify (0x50) → isr (0x70) →
        // device (0x80) → end. Each cap's `next` points at the next.
        let mut cfg = blank_cfg_with_cap_ptr(0x40);
        write_virtio_cap(&mut cfg, 0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG,
            4, 0x0000, 0x38, None);
        write_virtio_cap(&mut cfg, 0x50, 0x70, VIRTIO_PCI_CAP_NOTIFY_CFG,
            4, 0x3000, 0x1000, Some(4));
        write_virtio_cap(&mut cfg, 0x70, 0x80, VIRTIO_PCI_CAP_ISR_CFG,
            4, 0x1000, 0x4, None);
        write_virtio_cap(&mut cfg, 0x80, 0, VIRTIO_PCI_CAP_DEVICE_CFG,
            4, 0x2000, 0x400, None);

        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 1);
        assert_eq!(caps.common_cfg.bar, 4);
        assert_eq!(caps.common_cfg.offset, 0x0000);
        assert_eq!(caps.common_cfg.length, 0x38);
        assert_eq!(caps.notify_cfg.bar, 4);
        assert_eq!(caps.notify_cfg.offset, 0x3000);
        assert_eq!(caps.notify_cfg.length, 0x1000);
        assert_eq!(caps.notify_off_multiplier, 4);
        assert_eq!(caps.isr_cfg.bar, 4);
        assert_eq!(caps.isr_cfg.offset, 0x1000);
        assert_eq!(caps.isr_cfg.length, 0x4);
        assert_eq!(caps.device_cfg.bar, 4);
        assert_eq!(caps.device_cfg.offset, 0x2000);
        assert_eq!(caps.device_cfg.length, 0x400);
    }

    #[test]
    fn non_virtio_cap_is_ignored() {
        // Put an MSI-X cap (vndr = 0x11) first, virtio common-cfg next.
        let mut cfg = blank_cfg_with_cap_ptr(0x40);
        // MSI-X cap: vndr=0x11, next=0x50, two dummy bytes.
        cfg[0x40] = 0x11;
        cfg[0x41] = 0x50;
        cfg[0x42] = 0x00;
        cfg[0x43] = 0x00;
        // Virtio common cfg at 0x50.
        write_virtio_cap(&mut cfg, 0x50, 0, VIRTIO_PCI_CAP_COMMON_CFG,
            2, 0x100, 0x20, None);

        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 1);
        assert_eq!(caps.common_cfg.bar, 2);
        assert_eq!(caps.common_cfg.offset, 0x100);
    }

    #[test]
    fn unknown_cfg_type_is_ignored_walk_continues() {
        // Unknown cfg_type = 5 (VIRTIO_PCI_CAP_PCI_CFG, not parsed), then
        // a common-cfg at 0x60.
        let mut cfg = blank_cfg_with_cap_ptr(0x40);
        write_virtio_cap(&mut cfg, 0x40, 0x60, /*cfg_type*/ 5,
            0, 0, 0, None);
        write_virtio_cap(&mut cfg, 0x60, 0, VIRTIO_PCI_CAP_COMMON_CFG,
            1, 0x10, 0x38, None);

        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 1);
        assert_eq!(caps.common_cfg.bar, 1);
    }

    #[test]
    fn cap_pointer_below_standard_header_terminates() {
        // cap_ptr points at 0x20 (inside the standard header) — reject.
        let cfg = blank_cfg_with_cap_ptr(0x20);
        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 0);
    }

    #[test]
    fn cap_pointer_straddling_end_of_config_space_skipped() {
        // First cap at 0xF8 — only 8 bytes available, not enough for a
        // 16-byte virtio cap. Parser skips via the next pointer.
        let mut cfg = blank_cfg_with_cap_ptr(0xF8);
        cfg[0xF8] = CAP_VENDOR_SPECIFIC;
        cfg[0xF9] = 0; // next = terminate
        // Bytes beyond cfg_type etc. would run off end.
        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 0);
    }

    #[test]
    fn circular_cap_chain_terminates_at_iteration_bound() {
        // Two caps pointing at each other — infinite loop guard must fire.
        let mut cfg = blank_cfg_with_cap_ptr(0x40);
        write_virtio_cap(&mut cfg, 0x40, 0x60, VIRTIO_PCI_CAP_COMMON_CFG,
            4, 0x0, 0x38, None);
        write_virtio_cap(&mut cfg, 0x60, 0x40, VIRTIO_PCI_CAP_ISR_CFG,
            4, 0x1000, 0x4, None);

        // Should not hang; parser returns with whatever it scanned.
        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 1);
        // Both caps in the cycle got parsed at least once.
        assert_ne!(caps.common_cfg, VirtioPciCapEntry::default());
        assert_ne!(caps.isr_cfg, VirtioPciCapEntry::default());
    }

    #[test]
    fn notify_cap_at_end_of_config_reads_multiplier_only_if_fits() {
        // Notify cap at 0xE8: cap_len = 20 runs to 0xFC (inclusive of last
        // multiplier byte). This should fit — multiplier at [0xF8..0xFC].
        let mut cfg = blank_cfg_with_cap_ptr(0xE8);
        write_virtio_cap(&mut cfg, 0xE8, 0, VIRTIO_PCI_CAP_NOTIFY_CFG,
            4, 0x3000, 0x1000, Some(0xABCD));
        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 1);
        assert_eq!(caps.notify_off_multiplier, 0xABCD);
    }

    #[test]
    fn low_two_bits_of_cap_pointers_masked_off() {
        // Spec: low 2 bits of cap pointers are reserved. Parser must mask.
        let mut cfg = blank_cfg_with_cap_ptr(0x43);  // actual ptr = 0x40
        write_virtio_cap(&mut cfg, 0x40, 0x53, VIRTIO_PCI_CAP_COMMON_CFG,
            3, 0x1000, 0x38, None);
        // Second cap's actual address 0x50; next-pointer in first is 0x53.
        write_virtio_cap(&mut cfg, 0x50, 0, VIRTIO_PCI_CAP_ISR_CFG,
            3, 0x2000, 0x4, None);
        let caps = parse_virtio_modern_caps(&cfg);
        assert_eq!(caps.present, 1);
        assert_eq!(caps.common_cfg.bar, 3);
        assert_eq!(caps.isr_cfg.bar, 3);
    }
}
