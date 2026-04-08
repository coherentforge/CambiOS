// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Minimal ACPI table parser for I/O APIC discovery
//!
//! Parses just enough of the ACPI tables to extract:
//! - I/O APIC base addresses and IDs (MADT type 1)
//! - Interrupt Source Overrides mapping ISA IRQs to GSIs (MADT type 2)
//!
//! ## Discovery path
//! Limine RSDP request → RSDP → XSDT (or RSDT) → MADT → entries
//!
//! ## Portability
//! ACPI tables are architecture-independent. This module contains no
//! arch-specific code — it only interprets byte buffers.

// ============================================================================
// RSDP — Root System Description Pointer
// ============================================================================

/// ACPI RSDP (Root System Description Pointer) version 2.0+
///
/// Located by the bootloader (Limine RSDP request). Contains the physical
/// address of the XSDT (64-bit) or RSDT (32-bit) root table.
#[repr(C, packed)]
struct Rsdp {
    /// "RSD PTR " (8 bytes, not null-terminated)
    signature: [u8; 8],
    /// Checksum (sum of first 20 bytes must be 0)
    checksum: u8,
    /// OEM identifier
    oem_id: [u8; 6],
    /// ACPI revision (0 = v1.0, 2 = v2.0+)
    revision: u8,
    /// Physical address of the RSDT (32-bit)
    rsdt_address: u32,
    // --- ACPI 2.0+ fields below ---
    /// Length of the full RSDP structure
    length: u32,
    /// Physical address of the XSDT (64-bit)
    xsdt_address: u64,
    /// Extended checksum (sum of full structure must be 0)
    extended_checksum: u8,
    _reserved: [u8; 3],
}

/// Validate an RSDP at the given virtual address.
///
/// Returns (xsdt_phys, rsdt_phys, revision). Prefers XSDT if revision >= 2.
///
/// # Safety
/// `vaddr` must point to a valid, mapped RSDP structure.
unsafe fn validate_rsdp(vaddr: usize) -> Result<(u64, u32, u8), &'static str> {
    // SAFETY: Caller guarantees vaddr points to a valid, mapped RSDP structure.
    // All pointer dereferences below are within that structure.
    unsafe {
        let rsdp = &*(vaddr as *const Rsdp);

        // Verify signature
        if &rsdp.signature != b"RSD PTR " {
            return Err("RSDP: bad signature");
        }

        // Verify v1 checksum (first 20 bytes)
        let bytes = core::slice::from_raw_parts(vaddr as *const u8, 20);
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if sum != 0 {
            return Err("RSDP: bad checksum");
        }

        Ok((rsdp.xsdt_address, rsdp.rsdt_address, rsdp.revision))
    }
}

// ============================================================================
// SDT Header — common to all ACPI tables
// ============================================================================

/// Standard ACPI System Description Table header (36 bytes).
///
/// Every ACPI table (RSDT, XSDT, MADT, FADT, etc.) starts with this header.
#[repr(C, packed)]
struct SdtHeader {
    /// 4-byte ASCII signature (e.g., "APIC" for MADT)
    signature: [u8; 4],
    /// Total table length including header
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

const SDT_HEADER_SIZE: usize = core::mem::size_of::<SdtHeader>();

/// Validate an SDT header checksum.
///
/// # Safety
/// `vaddr` must point to a valid, mapped SDT with at least `header.length` bytes.
unsafe fn validate_sdt(vaddr: usize) -> Result<&'static SdtHeader, &'static str> {
    // SAFETY: Caller guarantees vaddr points to a valid, mapped SDT with at
    // least header.length bytes accessible.
    unsafe {
        let header = &*(vaddr as *const SdtHeader);
        let length = header.length as usize;

        if length < SDT_HEADER_SIZE {
            return Err("SDT: length too small");
        }

        let bytes = core::slice::from_raw_parts(vaddr as *const u8, length);
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if sum != 0 {
            return Err("SDT: bad checksum");
        }

        Ok(header)
    }
}

// ============================================================================
// MADT — Multiple APIC Description Table
// ============================================================================

/// MADT header (follows the standard SDT header).
#[repr(C, packed)]
struct MadtHeader {
    sdt: SdtHeader,
    /// Physical address of the Local APIC (usually 0xFEE00000)
    local_apic_address: u32,
    /// Flags (bit 0 = dual 8259 installed)
    flags: u32,
}

/// MADT entry header (type + length, followed by type-specific data).
#[repr(C, packed)]
struct MadtEntryHeader {
    entry_type: u8,
    length: u8,
}

// MADT entry type constants
const MADT_TYPE_LOCAL_APIC: u8 = 0;
const MADT_TYPE_IO_APIC: u8 = 1;
const MADT_TYPE_INTERRUPT_SOURCE_OVERRIDE: u8 = 2;

/// MADT entry type 1: I/O APIC
#[repr(C, packed)]
struct MadtIoApic {
    header: MadtEntryHeader,
    /// I/O APIC ID
    id: u8,
    _reserved: u8,
    /// Physical base address of this I/O APIC's registers
    address: u32,
    /// Global System Interrupt base for this I/O APIC
    gsi_base: u32,
}

/// MADT entry type 2: Interrupt Source Override
///
/// Maps a legacy ISA interrupt to a different GSI. For example,
/// ISA IRQ 0 (PIT timer) is commonly remapped to GSI 2.
#[repr(C, packed)]
struct MadtInterruptSourceOverride {
    header: MadtEntryHeader,
    /// Bus (always 0 = ISA)
    bus: u8,
    /// Original ISA IRQ number
    source: u8,
    /// Global System Interrupt number it maps to
    gsi: u32,
    /// Flags: bits 1:0 = polarity, bits 3:2 = trigger mode
    flags: u16,
}

// ============================================================================
// Parsed ACPI data structures (returned to caller)
// ============================================================================

/// Maximum I/O APICs we support (most systems have 1)
pub const MAX_IO_APICS: usize = 4;

/// Maximum interrupt source overrides
pub const MAX_OVERRIDES: usize = 16;

/// Parsed I/O APIC information from MADT
#[derive(Clone, Copy, Debug)]
pub struct IoApicInfo {
    /// I/O APIC ID (used in destination field of redirection entries)
    pub id: u8,
    /// Physical base address of MMIO registers
    pub address: u64,
    /// First GSI handled by this I/O APIC
    pub gsi_base: u32,
}

/// Polarity for an interrupt source override
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Polarity {
    /// Conforms to bus specification (active-high for ISA)
    BusDefault,
    /// Active high
    ActiveHigh,
    /// Active low
    ActiveLow,
}

/// Trigger mode for an interrupt source override
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TriggerMode {
    /// Conforms to bus specification (edge-triggered for ISA)
    BusDefault,
    /// Edge-triggered
    Edge,
    /// Level-triggered
    Level,
}

/// Parsed interrupt source override from MADT
#[derive(Clone, Copy, Debug)]
pub struct InterruptOverride {
    /// Original ISA IRQ number
    pub source_irq: u8,
    /// Remapped Global System Interrupt
    pub gsi: u32,
    /// Signal polarity
    pub polarity: Polarity,
    /// Trigger mode
    pub trigger: TriggerMode,
}

/// Complete ACPI interrupt topology parsed from MADT
pub struct AcpiInterruptInfo {
    /// I/O APICs found
    pub io_apics: [Option<IoApicInfo>; MAX_IO_APICS],
    /// Number of I/O APICs
    pub io_apic_count: usize,
    /// Interrupt source overrides (ISA → GSI remaps)
    pub overrides: [Option<InterruptOverride>; MAX_OVERRIDES],
    /// Number of overrides
    pub override_count: usize,
    /// Local APIC physical address (from MADT header)
    pub local_apic_address: u32,
}

impl AcpiInterruptInfo {
    const fn new() -> Self {
        AcpiInterruptInfo {
            io_apics: [None; MAX_IO_APICS],
            io_apic_count: 0,
            overrides: [None; MAX_OVERRIDES],
            override_count: 0,
            local_apic_address: 0,
        }
    }

    /// Look up an interrupt source override for a given ISA IRQ.
    ///
    /// Returns the override entry if the IRQ is remapped, or `None` if
    /// the IRQ maps directly to its identity GSI.
    pub fn find_override(&self, isa_irq: u8) -> Option<&InterruptOverride> {
        self.overrides.iter()
            .filter_map(|o| o.as_ref())
            .find(|o| o.source_irq == isa_irq)
    }

    /// Resolve an ISA IRQ to its actual GSI, accounting for overrides.
    pub fn isa_to_gsi(&self, isa_irq: u8) -> u32 {
        match self.find_override(isa_irq) {
            Some(ov) => ov.gsi,
            None => isa_irq as u32, // Identity mapping
        }
    }

    /// Find the I/O APIC responsible for a given GSI.
    pub fn io_apic_for_gsi(&self, gsi: u32) -> Option<&IoApicInfo> {
        // Each I/O APIC handles a range starting at gsi_base.
        // For most systems there's only one I/O APIC covering GSIs 0-23.
        self.io_apics.iter()
            .filter_map(|a| a.as_ref())
            .find(|a| gsi >= a.gsi_base)
    }
}

// ============================================================================
// Main parsing entry point
// ============================================================================

/// Parse ACPI tables starting from the RSDP address provided by Limine.
///
/// Returns structured interrupt topology information needed for I/O APIC setup.
///
/// # Safety
/// `rsdp_phys` must be the physical address of a valid RSDP.
/// The HHDM offset must be set (`crate::hhdm_offset()` returns non-zero).
/// All ACPI tables must be mapped via HHDM.
pub unsafe fn parse_acpi(rsdp_phys: u64) -> Result<AcpiInterruptInfo, &'static str> {
    let hhdm = crate::hhdm_offset();
    let rsdp_virt = rsdp_phys + hhdm;

    // SAFETY: Caller guarantees rsdp_phys is valid and HHDM-mapped.
    // All sub-calls operate on HHDM-mapped ACPI tables.
    unsafe {
        let (xsdt_phys, rsdt_phys, revision) = validate_rsdp(rsdp_virt as usize)?;

        // Find the MADT by walking XSDT (preferred) or RSDT
        let madt_virt = if revision >= 2 && xsdt_phys != 0 {
            find_table_xsdt(xsdt_phys + hhdm, b"APIC", hhdm)?
        } else if rsdt_phys != 0 {
            find_table_rsdt(rsdt_phys as u64 + hhdm, b"APIC", hhdm)?
        } else {
            return Err("ACPI: no XSDT or RSDT");
        };

        parse_madt(madt_virt)
    }
}

/// Walk the XSDT (64-bit pointers) to find a table by signature.
///
/// # Safety
/// `xsdt_virt` must point to a valid, mapped XSDT.
unsafe fn find_table_xsdt(
    xsdt_virt: u64,
    signature: &[u8; 4],
    hhdm: u64,
) -> Result<usize, &'static str> {
    // SAFETY: Caller guarantees xsdt_virt points to a valid, mapped XSDT.
    // All pointer operations below access HHDM-mapped ACPI table memory.
    unsafe {
        let header = validate_sdt(xsdt_virt as usize)?;
        let total_len = header.length as usize;
        let entries_offset = SDT_HEADER_SIZE;
        let entries_len = total_len - entries_offset;
        let entry_count = entries_len / 8; // 64-bit pointers

        let entries_base = xsdt_virt as usize + entries_offset;

        for i in 0..entry_count {
            let phys = core::ptr::read_unaligned((entries_base + i * 8) as *const u64);
            let virt = (phys + hhdm) as usize;
            let entry_header = &*(virt as *const SdtHeader);
            if &entry_header.signature == signature {
                // Validate the found table
                let _ = validate_sdt(virt)?;
                return Ok(virt);
            }
        }

        Err("ACPI: table not found in XSDT")
    }
}

/// Walk the RSDT (32-bit pointers) to find a table by signature.
///
/// # Safety
/// `rsdt_virt` must point to a valid, mapped RSDT.
unsafe fn find_table_rsdt(
    rsdt_virt: u64,
    signature: &[u8; 4],
    hhdm: u64,
) -> Result<usize, &'static str> {
    // SAFETY: Caller guarantees rsdt_virt points to a valid, mapped RSDT.
    // All pointer operations below access HHDM-mapped ACPI table memory.
    unsafe {
        let header = validate_sdt(rsdt_virt as usize)?;
        let total_len = header.length as usize;
        let entries_offset = SDT_HEADER_SIZE;
        let entries_len = total_len - entries_offset;
        let entry_count = entries_len / 4; // 32-bit pointers

        let entries_base = rsdt_virt as usize + entries_offset;

        for i in 0..entry_count {
            let phys = core::ptr::read_unaligned((entries_base + i * 4) as *const u32) as u64;
            let virt = (phys + hhdm) as usize;
            let entry_header = &*(virt as *const SdtHeader);
            if &entry_header.signature == signature {
                let _ = validate_sdt(virt)?;
                return Ok(virt);
            }
        }

        Err("ACPI: table not found in RSDT")
    }
}

/// Parse the MADT and extract I/O APIC and override entries.
///
/// # Safety
/// `madt_virt` must point to a valid, checksum-verified MADT.
unsafe fn parse_madt(madt_virt: usize) -> Result<AcpiInterruptInfo, &'static str> {
    // SAFETY: Caller guarantees madt_virt points to a valid, checksum-verified MADT.
    // All pointer dereferences below access HHDM-mapped ACPI table memory within
    // the bounds established by the MADT's length field.
    unsafe {
        let madt = &*(madt_virt as *const MadtHeader);
        let total_len = madt.sdt.length as usize;

        let mut info = AcpiInterruptInfo::new();
        info.local_apic_address = madt.local_apic_address;

        // Entries start after the MADT header (44 bytes = 36 SDT + 4 LAPIC addr + 4 flags)
        let entries_start = madt_virt + core::mem::size_of::<MadtHeader>();
        let entries_end = madt_virt + total_len;
        let mut offset = entries_start;

        while offset + 2 <= entries_end {
            let entry = &*(offset as *const MadtEntryHeader);
            let entry_len = entry.length as usize;

            if entry_len < 2 || offset + entry_len > entries_end {
                break; // Malformed entry
            }

            match entry.entry_type {
                MADT_TYPE_IO_APIC => {
                    if entry_len >= core::mem::size_of::<MadtIoApic>()
                        && info.io_apic_count < MAX_IO_APICS
                    {
                        let io_apic = &*(offset as *const MadtIoApic);
                        info.io_apics[info.io_apic_count] = Some(IoApicInfo {
                            id: io_apic.id,
                            address: io_apic.address as u64,
                            gsi_base: io_apic.gsi_base,
                        });
                        info.io_apic_count += 1;
                    }
                }
                MADT_TYPE_INTERRUPT_SOURCE_OVERRIDE => {
                    if entry_len >= core::mem::size_of::<MadtInterruptSourceOverride>()
                        && info.override_count < MAX_OVERRIDES
                    {
                        let iso = &*(offset as *const MadtInterruptSourceOverride);
                        let flags = iso.flags;
                        let polarity = match flags & 0x03 {
                            0 => Polarity::BusDefault,
                            1 => Polarity::ActiveHigh,
                            3 => Polarity::ActiveLow,
                            _ => Polarity::BusDefault,
                        };
                        let trigger = match (flags >> 2) & 0x03 {
                            0 => TriggerMode::BusDefault,
                            1 => TriggerMode::Edge,
                            3 => TriggerMode::Level,
                            _ => TriggerMode::BusDefault,
                        };

                        info.overrides[info.override_count] = Some(InterruptOverride {
                            source_irq: iso.source,
                            gsi: iso.gsi,
                            polarity,
                            trigger,
                        });
                        info.override_count += 1;
                    }
                }
                _ => {} // Skip other entry types (Local APIC NMI, etc.)
            }

            offset += entry_len;
        }

        if info.io_apic_count == 0 {
            return Err("MADT: no I/O APIC found");
        }

        Ok(info)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acpi_interrupt_info_new() {
        let info = AcpiInterruptInfo::new();
        assert_eq!(info.io_apic_count, 0);
        assert_eq!(info.override_count, 0);
        assert_eq!(info.local_apic_address, 0);
    }

    #[test]
    fn test_isa_to_gsi_identity() {
        let info = AcpiInterruptInfo::new();
        // No overrides → identity mapping
        assert_eq!(info.isa_to_gsi(1), 1);
        assert_eq!(info.isa_to_gsi(4), 4);
        assert_eq!(info.isa_to_gsi(14), 14);
    }

    #[test]
    fn test_isa_to_gsi_with_override() {
        let mut info = AcpiInterruptInfo::new();
        // ISA IRQ 0 remapped to GSI 2 (common on ACPI systems)
        info.overrides[0] = Some(InterruptOverride {
            source_irq: 0,
            gsi: 2,
            polarity: Polarity::ActiveLow,
            trigger: TriggerMode::Level,
        });
        info.override_count = 1;

        assert_eq!(info.isa_to_gsi(0), 2); // Overridden
        assert_eq!(info.isa_to_gsi(1), 1); // Not overridden
    }

    #[test]
    fn test_find_override() {
        let mut info = AcpiInterruptInfo::new();
        info.overrides[0] = Some(InterruptOverride {
            source_irq: 9,
            gsi: 9,
            polarity: Polarity::ActiveLow,
            trigger: TriggerMode::Level,
        });
        info.override_count = 1;

        assert!(info.find_override(9).is_some());
        assert!(info.find_override(10).is_none());
    }

    #[test]
    fn test_io_apic_for_gsi() {
        let mut info = AcpiInterruptInfo::new();
        info.io_apics[0] = Some(IoApicInfo {
            id: 0,
            address: 0xFEC0_0000,
            gsi_base: 0,
        });
        info.io_apic_count = 1;

        assert!(info.io_apic_for_gsi(0).is_some());
        assert!(info.io_apic_for_gsi(23).is_some());
        assert_eq!(info.io_apic_for_gsi(0).unwrap().address, 0xFEC0_0000);
    }

    #[test]
    fn test_polarity_values() {
        assert_ne!(Polarity::ActiveHigh, Polarity::ActiveLow);
        assert_ne!(Polarity::BusDefault, Polarity::ActiveHigh);
    }

    #[test]
    fn test_trigger_mode_values() {
        assert_ne!(TriggerMode::Edge, TriggerMode::Level);
        assert_ne!(TriggerMode::BusDefault, TriggerMode::Edge);
    }

    #[test]
    fn test_rsdp_struct_size() {
        // RSDP v2 is 36 bytes
        assert_eq!(core::mem::size_of::<Rsdp>(), 36);
    }

    #[test]
    fn test_sdt_header_size() {
        assert_eq!(core::mem::size_of::<SdtHeader>(), 36);
        assert_eq!(SDT_HEADER_SIZE, 36);
    }

    #[test]
    fn test_madt_header_size() {
        // MADT header = SDT (36) + LAPIC addr (4) + flags (4) = 44
        assert_eq!(core::mem::size_of::<MadtHeader>(), 44);
    }
}
