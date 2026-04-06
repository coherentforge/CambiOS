//! I/O APIC driver for routing external device interrupts
//!
//! The I/O APIC (typically at 0xFEC00000) replaces the legacy 8259 PIC for
//! routing external hardware interrupts (keyboard, serial, disk, network)
//! to Local APICs on specific CPUs.
//!
//! ## Register access
//! Uses an indirect register model: write the register index to IOREGSEL
//! (offset 0x00), then read/write data through IOWIN (offset 0x10).
//!
//! ## Redirection table
//! Each I/O APIC input pin has a 64-bit redirection entry that controls:
//! - Destination CPU (APIC ID)
//! - Delivery mode (fixed, lowest-priority, etc.)
//! - Interrupt vector (IDT index)
//! - Polarity and trigger mode
//! - Mask bit (1 = disabled)
//!
//! ## Vector assignment
//! Device vectors start at 33 (DEVICE_VECTOR_BASE), one above the APIC timer
//! vector (32). GSI N maps to vector DEVICE_VECTOR_BASE + N.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::acpi::{AcpiInterruptInfo, Polarity, TriggerMode};

// ============================================================================
// Constants
// ============================================================================

/// MMIO register offsets from I/O APIC base
const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;

/// I/O APIC register indices (written to IOREGSEL)
const IOAPICID: u32 = 0x00;
const IOAPICVER: u32 = 0x01;

/// Redirection table entry low DWORD register index for pin N
const fn redir_low(pin: u32) -> u32 {
    0x10 + pin * 2
}

/// Redirection table entry high DWORD register index for pin N
const fn redir_high(pin: u32) -> u32 {
    0x10 + pin * 2 + 1
}

/// First vector used for device interrupts (timer = 32, devices start at 33)
pub const DEVICE_VECTOR_BASE: u8 = 33;

/// Maximum GSI pins we support routing for
pub const MAX_GSI_PINS: usize = 24;

// Redirection entry bit fields (low DWORD)
const REDIR_MASK: u32 = 1 << 16;       // Interrupt masked
const REDIR_LEVEL: u32 = 1 << 15;      // Level-triggered (vs edge)
const REDIR_ACTIVE_LOW: u32 = 1 << 13; // Active-low polarity (vs high)
// Delivery mode: bits 10:8 (0 = Fixed)
// Destination mode: bit 11 (0 = Physical APIC ID)

// ============================================================================
// Global state
// ============================================================================

/// Virtual address of the primary I/O APIC MMIO registers.
/// Set during init, read by all register access functions.
static IO_APIC_BASE_VIRT: AtomicU64 = AtomicU64::new(0);

/// Maximum redirection entries (read from IOAPICVER during init)
static MAX_REDIR_ENTRIES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

// ============================================================================
// Register access
// ============================================================================

/// Read an I/O APIC register via the indirect access mechanism.
///
/// # Safety
/// I/O APIC must be initialized (IO_APIC_BASE_VIRT set).
#[inline]
unsafe fn ioapic_read(reg: u32) -> u32 {
    let base = IO_APIC_BASE_VIRT.load(Ordering::Relaxed);
    // SAFETY: base is a valid MMIO address mapped with NO_CACHE.
    // Write register index to IOREGSEL, then read data from IOWIN.
    core::ptr::write_volatile((base + IOREGSEL) as *mut u32, reg);
    core::ptr::read_volatile((base + IOWIN) as *const u32)
}

/// Write an I/O APIC register via the indirect access mechanism.
///
/// # Safety
/// I/O APIC must be initialized.
#[inline]
unsafe fn ioapic_write(reg: u32, value: u32) {
    let base = IO_APIC_BASE_VIRT.load(Ordering::Relaxed);
    // SAFETY: Same as ioapic_read — MMIO, NO_CACHE mapped.
    core::ptr::write_volatile((base + IOREGSEL) as *mut u32, reg);
    core::ptr::write_volatile((base + IOWIN) as *mut u32, value);
}

// ============================================================================
// Redirection table entry helpers
// ============================================================================

/// Read a full 64-bit redirection table entry for the given pin.
///
/// # Safety
/// I/O APIC must be initialized. Pin must be in range.
unsafe fn read_redir_entry(pin: u32) -> u64 {
    let low = ioapic_read(redir_low(pin)) as u64;
    let high = ioapic_read(redir_high(pin)) as u64;
    (high << 32) | low
}

/// Write a full 64-bit redirection table entry for the given pin.
///
/// # Safety
/// I/O APIC must be initialized. Pin must be in range.
/// The entry must be correctly formed.
unsafe fn write_redir_entry(pin: u32, entry: u64) {
    // Write high DWORD first (with mask bit set in low to avoid spurious delivery),
    // then low DWORD with the actual configuration.
    ioapic_write(redir_high(pin), (entry >> 32) as u32);
    ioapic_write(redir_low(pin), entry as u32);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the I/O APIC from parsed ACPI information.
///
/// Maps the I/O APIC MMIO registers, reads the version register to
/// determine the number of pins, and masks all entries.
///
/// # Safety
/// - ACPI info must contain at least one valid I/O APIC entry
/// - HHDM offset must be set
/// - Frame allocator must be initialized (for page table mapping)
/// - Must be called with interrupts disabled
pub unsafe fn init(acpi_info: &AcpiInterruptInfo) -> Result<(), &'static str> {
    let io_apic = acpi_info.io_apics[0]
        .as_ref()
        .ok_or("No I/O APIC in ACPI info")?;

    let phys_base = io_apic.address;
    let hhdm = crate::hhdm_offset();
    let virt_base = phys_base + hhdm;

    // Map the I/O APIC MMIO page into the kernel page table
    {
        use x86_64::structures::paging::PageTableFlags;
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH;

        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
        let mut pt = crate::memory::paging::active_page_table();
        // SAFETY: phys_base is the I/O APIC address from ACPI MADT.
        // We map it uncached for MMIO access. AlreadyMapped is OK.
        let _ = crate::memory::paging::map_page(
            &mut pt, virt_base, phys_base, flags, &mut fa_guard,
        );
    }

    IO_APIC_BASE_VIRT.store(virt_base, Ordering::Release);

    // Read version register to get max redirection entries
    let ver = ioapic_read(IOAPICVER);
    let max_entries = ((ver >> 16) & 0xFF) + 1; // Bits 23:16 = max redir entry index
    MAX_REDIR_ENTRIES.store(max_entries, Ordering::Release);

    let id = ioapic_read(IOAPICID) >> 24;
    crate::println!(
        "  I/O APIC: id={} phys={:#x} virt={:#x} pins={}",
        id, phys_base, virt_base, max_entries
    );

    // Mask all entries initially (set mask bit, vector 0)
    for pin in 0..max_entries {
        write_redir_entry(pin, REDIR_MASK as u64);
    }

    Ok(())
}

/// Route a Global System Interrupt to a specific vector and destination CPU.
///
/// Programs the I/O APIC redirection table entry for the given GSI.
/// The pin is unmasked (enabled) after programming.
///
/// # Arguments
/// - `gsi`: Global System Interrupt number (I/O APIC pin index, relative to gsi_base)
/// - `vector`: IDT vector number to deliver
/// - `dest_apic_id`: Local APIC ID of the target CPU
/// - `polarity`: Signal polarity (from MADT override or bus default)
/// - `trigger`: Trigger mode (from MADT override or bus default)
///
/// # Safety
/// I/O APIC must be initialized. Vector must be registered in the IDT.
pub unsafe fn route_irq(
    gsi: u32,
    vector: u8,
    dest_apic_id: u8,
    polarity: Polarity,
    trigger: TriggerMode,
) {
    let max = MAX_REDIR_ENTRIES.load(Ordering::Acquire);
    if gsi >= max {
        crate::println!("WARNING: GSI {} exceeds I/O APIC max entries ({})", gsi, max);
        return;
    }

    // Build low DWORD: vector + delivery mode + polarity + trigger + unmask
    let mut low: u32 = vector as u32; // Bits 7:0 = vector
    // Delivery mode = 0 (Fixed), destination mode = 0 (Physical)

    // Apply polarity (ISA default = active-high)
    match polarity {
        Polarity::ActiveLow => low |= REDIR_ACTIVE_LOW,
        Polarity::ActiveHigh | Polarity::BusDefault => {} // Active-high (ISA default)
    }

    // Apply trigger mode (ISA default = edge-triggered)
    match trigger {
        TriggerMode::Level => low |= REDIR_LEVEL,
        TriggerMode::Edge | TriggerMode::BusDefault => {} // Edge (ISA default)
    }

    // High DWORD: bits 31:24 = destination APIC ID (physical mode)
    let high: u32 = (dest_apic_id as u32) << 24;

    let entry = ((high as u64) << 32) | (low as u64);
    write_redir_entry(gsi, entry);
}

/// Mask (disable) a specific I/O APIC pin.
///
/// # Safety
/// I/O APIC must be initialized.
pub unsafe fn mask_irq(gsi: u32) {
    let max = MAX_REDIR_ENTRIES.load(Ordering::Acquire);
    if gsi >= max {
        return;
    }
    let entry = read_redir_entry(gsi);
    write_redir_entry(gsi, entry | REDIR_MASK as u64);
}

/// Unmask (enable) a specific I/O APIC pin.
///
/// # Safety
/// I/O APIC must be initialized. The pin must already be configured.
pub unsafe fn unmask_irq(gsi: u32) {
    let max = MAX_REDIR_ENTRIES.load(Ordering::Acquire);
    if gsi >= max {
        return;
    }
    let entry = read_redir_entry(gsi);
    write_redir_entry(gsi, entry & !(REDIR_MASK as u64));
}

/// Re-route an existing I/O APIC pin to a different CPU.
///
/// Reads the current redirection entry (preserving vector, polarity, trigger)
/// and updates only the destination APIC ID field. Used by SYS_WAIT_IRQ to
/// implement IRQ affinity — routing a device IRQ to the CPU running the
/// driver task.
///
/// # Safety
/// I/O APIC must be initialized. The pin must already be configured.
pub unsafe fn set_irq_destination(gsi: u32, dest_apic_id: u8) {
    let max = MAX_REDIR_ENTRIES.load(Ordering::Acquire);
    if gsi >= max {
        return;
    }
    let entry = read_redir_entry(gsi);
    // Clear destination field (bits 63:56 of the 64-bit entry = high DWORD bits 31:24)
    // and set the new destination APIC ID.
    let cleared = entry & !((0xFF_u64) << 56);
    let new_entry = cleared | ((dest_apic_id as u64) << 56);
    write_redir_entry(gsi, new_entry);
}

/// Get the maximum number of redirection entries (I/O APIC pins).
pub fn max_entries() -> u32 {
    MAX_REDIR_ENTRIES.load(Ordering::Acquire)
}

/// Configure standard device IRQs from ACPI interrupt topology.
///
/// Routes common ISA IRQs (keyboard, serial, etc.) through the I/O APIC
/// to the BSP, applying any MADT interrupt source overrides.
///
/// # Safety
/// I/O APIC must be initialized. IDT device handlers must be registered.
pub unsafe fn configure_device_irqs(
    acpi_info: &AcpiInterruptInfo,
    bsp_apic_id: u8,
) {
    /// ISA IRQs to route (IRQ number, description)
    const DEVICE_IRQS: &[(u8, &str)] = &[
        (1, "keyboard"),
        (3, "COM2"),
        (4, "COM1/serial"),
        (12, "PS/2 mouse"),
        (14, "primary IDE"),
        (15, "secondary IDE"),
    ];

    for &(isa_irq, name) in DEVICE_IRQS {
        let gsi = acpi_info.isa_to_gsi(isa_irq);
        let vector = DEVICE_VECTOR_BASE + gsi as u8;

        // Get polarity/trigger from MADT override (or defaults for ISA)
        let (polarity, trigger) = match acpi_info.find_override(isa_irq) {
            Some(ov) => (ov.polarity, ov.trigger),
            None => (Polarity::BusDefault, TriggerMode::BusDefault),
        };

        route_irq(gsi, vector, bsp_apic_id, polarity, trigger);
        crate::println!(
            "  IRQ {}: {} → GSI {} → vector {} (dest=CPU {})",
            isa_irq, name, gsi, vector, bsp_apic_id
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redir_register_indices() {
        // Pin 0: low = 0x10, high = 0x11
        assert_eq!(redir_low(0), 0x10);
        assert_eq!(redir_high(0), 0x11);
        // Pin 1: low = 0x12, high = 0x13
        assert_eq!(redir_low(1), 0x12);
        assert_eq!(redir_high(1), 0x13);
        // Pin 23: low = 0x3E, high = 0x3F
        assert_eq!(redir_low(23), 0x3E);
        assert_eq!(redir_high(23), 0x3F);
    }

    #[test]
    fn test_device_vector_base() {
        // Device vectors start right after timer vector (32)
        assert_eq!(DEVICE_VECTOR_BASE, 33);
        // Keyboard (GSI 1) → vector 34
        assert_eq!(DEVICE_VECTOR_BASE + 1, 34);
        // Serial (GSI 4) → vector 37
        assert_eq!(DEVICE_VECTOR_BASE + 4, 37);
    }

    #[test]
    fn test_redir_entry_bit_fields() {
        assert_eq!(REDIR_MASK, 1 << 16);
        assert_eq!(REDIR_LEVEL, 1 << 15);
        assert_eq!(REDIR_ACTIVE_LOW, 1 << 13);
    }

    #[test]
    fn test_max_gsi_pins() {
        // Standard I/O APIC has 24 pins
        assert_eq!(MAX_GSI_PINS, 24);
    }
}
