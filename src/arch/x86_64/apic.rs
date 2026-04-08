// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Local APIC driver for x86-64
//!
//! Replaces the 8259 PIC + 8254 PIT with the Local APIC timer for the BSP.
//! The APIC timer is calibrated against the PIT before the PIT is disabled.
//!
//! ## Boot sequence
//! 1. `disable_pic()` — remap PIC to 0xF0-0xFF and mask all lines
//! 2. `detect_and_init()` — enable Local APIC via IA32_APIC_BASE MSR + SIVR
//! 3. `configure_timer(hz)` — calibrate against PIT, then start periodic mode
//!
//! ## Register access
//! APIC registers are memory-mapped at the physical address from IA32_APIC_BASE.
//! We access them via HHDM (phys + hhdm_offset = kernel-accessible virtual address).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================================
// MSR constants
// ============================================================================

const IA32_APIC_BASE_MSR: u32 = 0x1B;

/// APIC global enable bit in IA32_APIC_BASE
const APIC_BASE_ENABLE: u64 = 1 << 11;

// ============================================================================
// APIC register offsets (from APIC base address)
// ============================================================================

/// Local APIC ID register
const APIC_ID: u32 = 0x020;
/// Spurious Interrupt Vector Register
const APIC_SIVR: u32 = 0x0F0;
/// End-of-Interrupt register
const APIC_EOI: u32 = 0x0B0;
/// LVT Timer register
const APIC_LVT_TIMER: u32 = 0x320;
/// Timer Initial Count register
const APIC_TIMER_ICR: u32 = 0x380;
/// Timer Current Count register
const APIC_TIMER_CCR: u32 = 0x390;
/// Timer Divide Configuration register
const APIC_TIMER_DCR: u32 = 0x3E0;

/// LVT Timer: periodic mode bit
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// LVT Timer: masked bit (suppress delivery)
const LVT_TIMER_MASKED: u32 = 1 << 16;

/// SIVR: APIC Software Enable bit
const SIVR_APIC_ENABLE: u32 = 1 << 8;

/// Spurious interrupt vector (must be in range 0x10..=0xFF)
const SPURIOUS_VECTOR: u8 = 0xFF;

/// Timer interrupt vector (same as the PIT used — vector 32)
pub const TIMER_VECTOR: u8 = 32;

// ============================================================================
// PIC constants (for disabling)
// ============================================================================

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ============================================================================
// PIT constants (for calibration)
// ============================================================================

const PIT_CHANNEL0_DATA: u16 = 0x40;
const PIT_CMD: u16 = 0x43;
/// PIT oscillator frequency (Hz)
const PIT_FREQUENCY: u32 = 1_193_182;
/// Calibration window: ~10ms (divisor for Channel 0 one-shot)
const PIT_CALIBRATION_DIVISOR: u16 = 11932;

// ============================================================================
// State
// ============================================================================

/// APIC base virtual address (HHDM-mapped). Set once during init.
static APIC_BASE_VIRT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Stored BSP calibration (for AP timer configuration)
// ============================================================================

/// APIC timer initial count (set during BSP calibration, used by APs).
static TIMER_INITIAL_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// APIC register access
// ============================================================================

#[inline]
unsafe fn apic_read(offset: u32) -> u32 {
    let base = APIC_BASE_VIRT.load(Ordering::Relaxed);
    // SAFETY: APIC_BASE_VIRT was set to a valid HHDM-mapped address during init.
    // APIC registers are 32-bit aligned at 16-byte boundaries.
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
}

#[inline]
unsafe fn apic_write(offset: u32, value: u32) {
    let base = APIC_BASE_VIRT.load(Ordering::Relaxed);
    // SAFETY: Same as apic_read. APIC registers accept 32-bit aligned writes.
    unsafe { core::ptr::write_volatile((base + offset as u64) as *mut u32, value) };
}

// ============================================================================
// PIC disable
// ============================================================================

/// Disable the 8259 PIC by remapping to vectors 0xF0-0xFF and masking all lines.
///
/// Must be called BEFORE enabling the APIC to prevent spurious PIC interrupts
/// from landing on valid IDT vectors.
///
/// # Safety
/// Must be called during single-threaded boot with interrupts disabled.
pub unsafe fn disable_pic() {
    // SAFETY: All port handles target the 8259 PIC command/data ports during
    // single-threaded boot with interrupts disabled. Ports are valid x86 I/O
    // addresses and we are at ring 0.
    let pic1_cmd = unsafe { super::portio::Port8::new(PIC1_CMD) };
    let pic1_data = unsafe { super::portio::Port8::new(PIC1_DATA) };
    let pic2_cmd = unsafe { super::portio::Port8::new(PIC2_CMD) };
    let pic2_data = unsafe { super::portio::Port8::new(PIC2_DATA) };

    // ICW1: begin initialization, expect ICW4
    pic1_cmd.write(0x11);
    super::portio::io_wait();
    pic2_cmd.write(0x11);
    super::portio::io_wait();

    // ICW2: remap to 0xF0 / 0xF8 (out of the way)
    pic1_data.write(0xF0);
    super::portio::io_wait();
    pic2_data.write(0xF8);
    super::portio::io_wait();

    // ICW3: cascade (master has slave on IRQ2, slave identity 2)
    pic1_data.write(4);
    super::portio::io_wait();
    pic2_data.write(2);
    super::portio::io_wait();

    // ICW4: 8086 mode
    pic1_data.write(0x01);
    super::portio::io_wait();
    pic2_data.write(0x01);
    super::portio::io_wait();

    // Mask all IRQs on both PICs
    pic1_data.write(0xFF);
    pic2_data.write(0xFF);
}

// ============================================================================
// APIC initialization
// ============================================================================

/// Detect and enable the Local APIC.
///
/// Reads IA32_APIC_BASE MSR to find the APIC physical address, maps it
/// via HHDM, and enables the APIC through the Spurious Interrupt Vector Register.
///
/// # Safety
/// Must be called during single-threaded boot with interrupts disabled,
/// after HHDM offset is set.
pub unsafe fn detect_and_init() -> Result<(), &'static str> {
    // Detect APIC via CPUID leaf 1
    let cpuid = core::arch::x86_64::__cpuid(1);
    if cpuid.edx & (1 << 9) == 0 {
        return Err("APIC not available (CPUID)");
    }

    // Read APIC base MSR
    // SAFETY: IA32_APIC_BASE is a valid MSR on all x86_64 with APIC (checked above).
    let mut apic_base = unsafe { super::msr::read(IA32_APIC_BASE_MSR) };

    // Ensure global enable bit is set
    if apic_base & APIC_BASE_ENABLE == 0 {
        apic_base |= APIC_BASE_ENABLE;
        // SAFETY: Writing the enable bit to IA32_APIC_BASE is valid at ring 0.
        unsafe { super::msr::write(IA32_APIC_BASE_MSR, apic_base) };
    }

    // Extract physical base (bits 12..51, page-aligned)
    let phys_base = apic_base & 0x000F_FFFF_FFFF_F000;

    // Map APIC MMIO page into the kernel page table.
    // Limine's HHDM only covers RAM from the memory map; device MMIO regions
    // like the APIC (typically at 0xFEE00000) are not mapped. We must create
    // the mapping explicitly with uncacheable flags.
    let hhdm = crate::hhdm_offset();
    let virt_base = phys_base + hhdm;
    {
        use x86_64::structures::paging::PageTableFlags;
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH;

        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
        // SAFETY: Active page table is the kernel PML4 (single-threaded boot).
        // phys_base is the APIC MMIO address from the MSR. virt_base is the
        // HHDM-mapped address. The page may already be mapped (some firmware
        // configurations), so we ignore AlreadyMapped errors.
        let mut pt = unsafe { crate::memory::paging::active_page_table() };
        let _ = crate::memory::paging::map_page(&mut pt, virt_base, phys_base, flags, &mut fa_guard);
    }

    APIC_BASE_VIRT.store(virt_base, Ordering::Release);

    // SAFETY: APIC MMIO is now mapped and APIC_BASE_VIRT is set. All APIC
    // register accesses below target valid offsets in the APIC register space.
    unsafe {
        // Enable APIC via Spurious Interrupt Vector Register:
        // Set vector to SPURIOUS_VECTOR (0xFF) and set APIC Software Enable bit
        let sivr = apic_read(APIC_SIVR);
        apic_write(APIC_SIVR, sivr | SIVR_APIC_ENABLE as u32 | SPURIOUS_VECTOR as u32);

        let apic_id = apic_read(APIC_ID) >> 24;
        crate::println!(
            "  APIC enabled: phys={:#x} virt={:#x} id={}",
            phys_base, virt_base, apic_id
        );
    }

    Ok(())
}

// ============================================================================
// APIC ID
// ============================================================================

/// Read the Local APIC ID for the current CPU.
///
/// Returns the 8-bit APIC ID (bits 31:24 of the APIC ID register).
///
/// # Safety
/// APIC must be initialized (detect_and_init completed).
pub unsafe fn read_apic_id() -> u32 {
    // SAFETY: APIC is initialized, APIC_BASE_VIRT is valid, APIC_ID is a valid register offset.
    unsafe { apic_read(APIC_ID) >> 24 }
}

// ============================================================================
// APIC EOI
// ============================================================================

/// Send End-of-Interrupt to the Local APIC.
///
/// Must be called from every APIC-delivered interrupt handler before returning.
/// Writing any value to the EOI register signals completion.
///
/// # Safety
/// Must be called from interrupt context after APIC is initialized.
#[inline]
pub unsafe fn write_eoi() {
    // SAFETY: APIC is initialized and we are in interrupt context. Writing 0 to
    // the EOI register signals end-of-interrupt.
    unsafe { apic_write(APIC_EOI, 0) };
}

// ============================================================================
// APIC timer calibration and configuration
// ============================================================================

/// Calibrate the APIC timer against the PIT and configure periodic mode.
///
/// Uses PIT Channel 0 in one-shot mode for a ~10ms calibration window.
/// After calibration, programs the APIC timer to fire at the requested
/// frequency on `TIMER_VECTOR`.
///
/// Returns the calibrated bus frequency (ticks per second).
///
/// # Safety
/// Must be called during single-threaded boot with interrupts disabled.
/// PIC must be disabled first (PIT Channel 0 won't generate an IRQ).
pub unsafe fn configure_timer(frequency_hz: u32) -> u32 {
    // SAFETY: Called during single-threaded boot with interrupts disabled.
    // PIT calibration and all APIC register accesses are valid at this point.
    unsafe {
        let bus_freq = calibrate_against_pit();

        if bus_freq == 0 {
            panic!("APIC timer calibration failed: bus frequency is 0");
        }

        // Configure timer divide: divide by 16 (DCR value 0x03)
        apic_write(APIC_TIMER_DCR, 0x03);

        // Compute initial count for the desired frequency
        let initial_count = bus_freq / frequency_hz;

        // Store for AP reuse (APs skip PIT calibration)
        TIMER_INITIAL_COUNT.store(initial_count, Ordering::Release);

        // LVT Timer: periodic mode, vector TIMER_VECTOR, not masked
        apic_write(APIC_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);

        // Set initial count — this starts the timer
        apic_write(APIC_TIMER_ICR, initial_count);

        crate::println!(
            "  APIC timer: {}Hz (bus={}MHz, count={}, div=16)",
            frequency_hz, bus_freq / 1_000_000, initial_count
        );

        bus_freq
    }
}

/// Calibrate the APIC timer by measuring ticks during a PIT-timed window.
///
/// Programs PIT Channel 0 as a one-shot countdown for ~10ms, runs the APIC
/// timer at max count with divide-by-16, then measures how many APIC ticks
/// elapsed.
///
/// Returns the APIC bus frequency in ticks/second (after divide-by-16).
unsafe fn calibrate_against_pit() -> u32 {
    // SAFETY: Called during single-threaded boot with interrupts disabled.
    // All APIC MMIO and PIT port I/O accesses target valid hardware registers
    // at ring 0. APIC is initialized, PIT ports are standard x86 I/O addresses.
    let pit_cmd = unsafe { super::portio::Port8::new(PIT_CMD) };
    let pit_ch0 = unsafe { super::portio::Port8::new(PIT_CHANNEL0_DATA) };

    unsafe {
        // Step 1: Set APIC timer divide to 16
        apic_write(APIC_TIMER_DCR, 0x03);

        // Step 2: Mask the APIC timer LVT (prevent interrupts during calibration)
        apic_write(APIC_LVT_TIMER, LVT_TIMER_MASKED);

        // Step 3: Set APIC timer initial count to max
        apic_write(APIC_TIMER_ICR, 0xFFFF_FFFF);

        // Step 4: Program PIT Channel 0 for one-shot mode (mode 0)
        // Command: channel 0, access lo/hi, mode 0 (interrupt on terminal count)
        pit_cmd.write(0x30);
        // Write calibration divisor (lo then hi)
        pit_ch0.write((PIT_CALIBRATION_DIVISOR & 0xFF) as u8);
        super::portio::io_wait();
        pit_ch0.write((PIT_CALIBRATION_DIVISOR >> 8) as u8);

        // Step 5: Busy-wait until PIT Channel 0 counts down to 0.
        // Read-back: latch channel 0 count, read lo/hi.
        loop {
            // Latch Channel 0 counter
            pit_cmd.write(0x00); // Latch command for channel 0
            let lo = pit_ch0.read() as u16;
            let hi = pit_ch0.read() as u16;
            let count = (hi << 8) | lo;

            // PIT mode 0: counter decrements to 0 then output goes high.
            // When count wraps very low (or we read 0), calibration window is done.
            // In practice the counter may not hit exact 0 on every read, so we
            // check if the reload bit is set or if count is small.
            if count <= 1 {
                break;
            }
        }

        // Step 6: Read how many APIC ticks elapsed
        let apic_current = apic_read(APIC_TIMER_CCR);
        let elapsed = 0xFFFF_FFFFu32.wrapping_sub(apic_current);

        // Step 7: Stop APIC timer
        apic_write(APIC_TIMER_ICR, 0);

        // Step 8: Convert to bus frequency.
        // PIT calibration window duration: PIT_CALIBRATION_DIVISOR / PIT_FREQUENCY seconds.
        // elapsed APIC ticks occurred in that window.
        // bus_freq = elapsed / (divisor / PIT_FREQUENCY) = elapsed * PIT_FREQUENCY / divisor
        // This is the rate AFTER the divide-by-16 divisor.
        let bus_freq = (elapsed as u64 * PIT_FREQUENCY as u64) / PIT_CALIBRATION_DIVISOR as u64;

        bus_freq as u32
    }
}

// ============================================================================
// AP (Application Processor) APIC initialization
// ============================================================================

/// Enable the Local APIC on an Application Processor.
///
/// Lighter-weight than `detect_and_init()` — skips CPUID check and MMIO mapping
/// (the BSP already mapped the APIC MMIO page, and the page tables are shared).
/// Each AP just needs to enable its own APIC via the MSR and SIVR.
///
/// # Safety
/// Must be called on the AP itself, with interrupts disabled.
/// BSP must have already called `detect_and_init()`.
pub unsafe fn init_ap() {
    // SAFETY: Called on the AP with interrupts disabled. BSP has already
    // initialized APIC_BASE_VIRT. MSR and APIC MMIO accesses are valid at ring 0.
    unsafe {
        // Ensure the APIC global enable bit is set in this AP's MSR
        let mut apic_base = super::msr::read(IA32_APIC_BASE_MSR);
        if apic_base & APIC_BASE_ENABLE == 0 {
            apic_base |= APIC_BASE_ENABLE;
            super::msr::write(IA32_APIC_BASE_MSR, apic_base);
        }

        // Enable APIC via Spurious Interrupt Vector Register
        // (BSP already set the virtual base, which is the same for all CPUs)
        let sivr = apic_read(APIC_SIVR);
        apic_write(APIC_SIVR, sivr | SIVR_APIC_ENABLE as u32 | SPURIOUS_VECTOR as u32);
    }
}

/// Configure the APIC timer on an AP using the BSP's calibration values.
///
/// Skips PIT calibration (PIT is a global resource, not safe to use from APs).
/// Uses the same timer parameters (divide ratio, initial count, vector) that
/// the BSP computed during `configure_timer()`.
///
/// # Safety
/// Must be called on the AP after `init_ap()`. BSP must have completed
/// `configure_timer()` (so TIMER_INITIAL_COUNT is set).
pub unsafe fn configure_timer_ap() {
    let initial_count = TIMER_INITIAL_COUNT.load(Ordering::Acquire);
    if initial_count == 0 {
        // BSP hasn't calibrated yet — this shouldn't happen if boot order is correct
        return;
    }

    // SAFETY: APIC is initialized on this AP (init_ap completed). APIC MMIO
    // is mapped and valid. Timer register offsets are correct.
    unsafe {
        // Same timer configuration as BSP: divide by 16, periodic mode, TIMER_VECTOR
        apic_write(APIC_TIMER_DCR, 0x03);
        apic_write(APIC_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
        apic_write(APIC_TIMER_ICR, initial_count);
    }
}

// ============================================================================
// Inter-Processor Interrupt (IPI) primitives
// ============================================================================
//
// The ICR (Interrupt Command Register) is used to send IPIs to other CPUs.
// In xAPIC mode it is a 64-bit register split across two 32-bit MMIO offsets:
//   - ICR High (0x310): bits 31:24 = destination APIC ID
//   - ICR Low  (0x300): vector, delivery mode, dest shorthand, etc.
// Writing ICR Low *triggers* the IPI, so ICR High must be written first.

/// ICR Low DWORD register offset
const APIC_ICR_LOW: u32 = 0x300;
/// ICR High DWORD register offset
const APIC_ICR_HIGH: u32 = 0x310;

/// ICR delivery status bit (bit 12). 1 = send pending.
const ICR_DELIVERY_STATUS: u32 = 1 << 12;
/// ICR level assert (bit 14). Required for INIT/SIPI, set for Fixed too.
const ICR_LEVEL_ASSERT: u32 = 1 << 14;

/// ICR destination shorthand: no shorthand (use destination field)
const ICR_DEST_NO_SHORTHAND: u32 = 0b00 << 18;
/// ICR destination shorthand: self
const ICR_DEST_SELF: u32 = 0b01 << 18;
/// ICR destination shorthand: all including self
const ICR_DEST_ALL_INCLUDING_SELF: u32 = 0b10 << 18;
/// ICR destination shorthand: all excluding self
const ICR_DEST_ALL_EXCLUDING_SELF: u32 = 0b11 << 18;

/// ICR delivery mode: Fixed (0b000 << 8)
const ICR_DELIVERY_FIXED: u32 = 0b000 << 8;

/// Wait for the previous IPI to be accepted by the target.
///
/// Spins on the ICR delivery status bit until it clears.
/// In practice this completes almost immediately.
///
/// # Safety
/// APIC must be initialized.
#[inline]
unsafe fn wait_for_ipi_delivery() {
    // Intel SDM: "The delivery status bit is cleared after the IPI message
    // has been accepted by the target processor(s) or the APIC bus."
    // SAFETY: APIC is initialized, ICR_LOW is a valid APIC register offset.
    while unsafe { apic_read(APIC_ICR_LOW) } & ICR_DELIVERY_STATUS != 0 {
        core::hint::spin_loop();
    }
}

/// Send a fixed IPI with the given vector to a specific CPU (by APIC ID).
///
/// # Safety
/// APIC must be initialized. Vector must be registered in the target's IDT.
/// Must be called with interrupts disabled (or from interrupt context) to
/// prevent reentrant ICR access.
pub unsafe fn send_ipi(dest_apic_id: u8, vector: u8) {
    // SAFETY: APIC is initialized, interrupts are disabled (or we are in
    // interrupt context), and the vector is registered in the target's IDT.
    // ICR High/Low are valid APIC register offsets.
    unsafe {
        wait_for_ipi_delivery();

        // Write destination APIC ID (bits 31:24 of ICR High)
        apic_write(APIC_ICR_HIGH, (dest_apic_id as u32) << 24);

        // Write ICR Low: vector + Fixed delivery + level assert + no shorthand
        // This triggers the IPI.
        apic_write(
            APIC_ICR_LOW,
            vector as u32 | ICR_DELIVERY_FIXED | ICR_LEVEL_ASSERT | ICR_DEST_NO_SHORTHAND,
        );
    }
}

/// Send a fixed IPI with the given vector to ALL other CPUs (excluding self).
///
/// Uses the "all excluding self" destination shorthand — no need to specify
/// a destination APIC ID.
///
/// # Safety
/// APIC must be initialized. Vector must be registered in every CPU's IDT.
pub unsafe fn send_ipi_all_excluding_self(vector: u8) {
    // SAFETY: APIC is initialized and the vector is registered in every CPU's IDT.
    // ICR High/Low are valid APIC register offsets.
    unsafe {
        wait_for_ipi_delivery();

        // Shorthand mode ignores the destination field, but we clear it for hygiene
        apic_write(APIC_ICR_HIGH, 0);

        // Write ICR Low: vector + Fixed + level assert + all-excluding-self shorthand
        apic_write(
            APIC_ICR_LOW,
            vector as u32 | ICR_DELIVERY_FIXED | ICR_LEVEL_ASSERT | ICR_DEST_ALL_EXCLUDING_SELF,
        );
    }
}

/// Send a fixed IPI to self.
///
/// # Safety
/// APIC must be initialized. Vector must be registered in this CPU's IDT.
pub unsafe fn send_ipi_self(vector: u8) {
    // SAFETY: APIC is initialized and the vector is registered in this CPU's IDT.
    // ICR High/Low are valid APIC register offsets.
    unsafe {
        wait_for_ipi_delivery();

        apic_write(APIC_ICR_HIGH, 0);
        apic_write(
            APIC_ICR_LOW,
            vector as u32 | ICR_DELIVERY_FIXED | ICR_LEVEL_ASSERT | ICR_DEST_SELF,
        );
    }
}
