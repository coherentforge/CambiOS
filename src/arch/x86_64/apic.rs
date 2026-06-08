// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

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

use crate::arch::mmio::{ReadOnly, ReadWrite, WriteOnly};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================================
// MSR constants
// ============================================================================

const IA32_APIC_BASE_MSR: u32 = 0x1B;

/// APIC global enable bit in IA32_APIC_BASE
const APIC_BASE_ENABLE: u64 = 1 << 11;

// ============================================================================
// APIC register values
//
// The register OFFSETS are encoded as field positions in the `LocalApicRegs`
// block below (ADR-036), pinned by `offset_of!` asserts; only the register
// values / flag bits live here as named consts.
// ============================================================================

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
// Local APIC register block (ADR-036)
// ============================================================================
//
// xAPIC mode: the Local APIC registers are 32-bit, memory-mapped at 16-byte
// (0x10) strides from the per-CPU APIC base (Intel SDM Vol 3 § 10.4.1, Table
// 10-1). The field offsets below ARE those SDM offsets, pinned by `offset_of!`
// asserts. (x2APIC mode accesses the same registers via MSRs instead - that
// path is not MMIO and is out of ADR-036 scope, like the IA32_APIC_BASE MSR
// access in `detect_and_init`.) Reserved-padding fields are layout-only.

/// Access classes follow the Intel SDM Vol 3 Table 10-1 register access column,
/// not this code's usage: EOI is the only write-only register, Timer Current
/// Count the only read-only one; every other register (incl. ICR high, Timer
/// Initial Count, Timer Divide Config - which this code only ever writes) is
/// Read/Write, so it stays `ReadWrite` rather than being narrowed to
/// `WriteOnly`. The lone deliberate exception is the APIC ID: the SDM lists it
/// R/W in xAPIC, but it is read-only in x2APIC and the kernel only reads its ID
/// field, so it is typed `ReadOnly` to make an accidental ID write a type error.
#[repr(C)]
#[allow(dead_code)] // reserved-padding fields are layout-only, never read
struct LocalApicRegs {
    _reserved_000_020: [u8; 0x020],
    /// 0x020 - Local APIC ID (ID in bits 31:24).
    id: ReadOnly<u32>,
    _reserved_024_0b0: [u8; 0x0B0 - 0x024],
    /// 0x0B0 - End-of-Interrupt (write-only; any value signals EOI).
    eoi: WriteOnly<u32>,
    _reserved_0b4_0f0: [u8; 0x0F0 - 0x0B4],
    /// 0x0F0 - Spurious Interrupt Vector (software-enable bit 8 + vector 7:0).
    sivr: ReadWrite<u32>,
    _reserved_0f4_300: [u8; 0x300 - 0x0F4],
    /// 0x300 - Interrupt Command Register, low dword (write triggers the IPI).
    icr_low: ReadWrite<u32>,
    _reserved_304_310: [u8; 0x310 - 0x304],
    /// 0x310 - Interrupt Command Register, high dword (dest APIC ID in 31:24).
    icr_high: ReadWrite<u32>,
    _reserved_314_320: [u8; 0x320 - 0x314],
    /// 0x320 - LVT Timer (vector 7:0 + mask bit 16 + periodic bit 17).
    lvt_timer: ReadWrite<u32>,
    _reserved_324_380: [u8; 0x380 - 0x324],
    /// 0x380 - Timer Initial Count (write starts the countdown).
    timer_icr: ReadWrite<u32>,
    _reserved_384_390: [u8; 0x390 - 0x384],
    /// 0x390 - Timer Current Count (read-only; hardware-decremented).
    timer_ccr: ReadOnly<u32>,
    _reserved_394_3e0: [u8; 0x3E0 - 0x394],
    /// 0x3E0 - Timer Divide Configuration.
    timer_dcr: ReadWrite<u32>,
}

const _: () = assert!(core::mem::offset_of!(LocalApicRegs, id) == 0x020);
const _: () = assert!(core::mem::offset_of!(LocalApicRegs, eoi) == 0x0B0);
const _: () = assert!(core::mem::offset_of!(LocalApicRegs, sivr) == 0x0F0);
const _: () = assert!(core::mem::offset_of!(LocalApicRegs, icr_low) == 0x300);
const _: () = assert!(core::mem::offset_of!(LocalApicRegs, icr_high) == 0x310);
const _: () = assert!(core::mem::offset_of!(LocalApicRegs, lvt_timer) == 0x320);
const _: () = assert!(core::mem::offset_of!(LocalApicRegs, timer_icr) == 0x380);
const _: () = assert!(core::mem::offset_of!(LocalApicRegs, timer_ccr) == 0x390);
const _: () = assert!(core::mem::offset_of!(LocalApicRegs, timer_dcr) == 0x3E0);
const _: () = assert!(core::mem::size_of::<LocalApicRegs>() == 0x3E4);

/// Construct the Local APIC register block from the stored HHDM-mapped base.
///
/// # Safety
/// `APIC_BASE_VIRT` must have been initialized (in `detect_and_init`) to a
/// valid, mapped APIC MMIO region of at least `size_of::<LocalApicRegs>()` with
/// uncacheable device attributes. The base is per-CPU but identical across CPUs
/// (the architectural xAPIC base), so every CPU's accesses target its own APIC.
#[inline]
unsafe fn lapic() -> &'static LocalApicRegs {
    let base = APIC_BASE_VIRT.load(Ordering::Relaxed) as usize;
    // SAFETY: `base` is the mapped xAPIC MMIO region (ADR-036 § 3); the caller -
    // every `pub unsafe fn` here - upholds that the APIC was detected and mapped
    // before any register access.
    unsafe { &*(base as *const LocalApicRegs) }
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
    // SAFETY: PIC1_CMD (0x20) is a valid x86 I/O port for the 8259 PIC.
    let pic1_cmd = unsafe { super::portio::Port8::new(PIC1_CMD) };
    // SAFETY: PIC1_DATA (0x21) is a valid x86 I/O port for the 8259 PIC.
    let pic1_data = unsafe { super::portio::Port8::new(PIC1_DATA) };
    // SAFETY: PIC2_CMD (0xA0) is a valid x86 I/O port for the 8259 PIC.
    let pic2_cmd = unsafe { super::portio::Port8::new(PIC2_CMD) };
    // SAFETY: PIC2_DATA (0xA1) is a valid x86 I/O port for the 8259 PIC.
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

    // SAFETY: APIC MMIO is now mapped and APIC_BASE_VIRT is set (ADR-036 § 3).
    // One construction; field accesses below are safe.
    let regs = unsafe { lapic() };

    // Software-enable the APIC and set the spurious vector.
    let sivr = regs.sivr.read();
    regs.sivr.write(sivr | SIVR_APIC_ENABLE | SPURIOUS_VECTOR as u32);

    let apic_id = regs.id.read() >> 24;
    crate::println!(
        "  APIC enabled: phys={:#x} virt={:#x} id={}",
        phys_base, virt_base, apic_id
    );

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
    // SAFETY: the APIC was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { lapic() };
    regs.id.read() >> 24
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
    // SAFETY: the APIC was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { lapic() };
    // Writing any value to the write-only EOI register signals end-of-interrupt.
    regs.eoi.write(0);
}

// ============================================================================
// APIC timer calibration and configuration
// ============================================================================

/// PIT calibration reported a zero bus frequency, so the APIC timer reload
/// count cannot be derived. A typed error (not `()`), per the kernel's
/// every-failure-is-a-typed-error convention; the boot path maps it to
/// [`crate::boot::BootError::ApicCalibrationFailed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApicCalibrationFailed;

/// Calibrate the APIC timer against the PIT and configure periodic mode.
///
/// Uses PIT Channel 0 in one-shot mode for a ~10ms calibration window.
/// After calibration, programs the APIC timer to fire at the requested
/// frequency on `TIMER_VECTOR`.
///
/// Returns [`ApicCalibrationFailed`] if PIT calibration reports a bus
/// frequency of zero — the caller maps that to
/// [`crate::boot::BootError::ApicCalibrationFailed`].
///
/// # Safety
/// Must be called during single-threaded boot with interrupts disabled.
/// PIC must be disabled first (PIT Channel 0 won't generate an IRQ).
pub unsafe fn configure_timer(frequency_hz: u32) -> Result<(), ApicCalibrationFailed> {
    // SAFETY: Called during single-threaded boot with interrupts disabled.
    // PIT calibration is valid at this point.
    let bus_freq = unsafe { calibrate_against_pit() };

    if bus_freq == 0 {
        return Err(ApicCalibrationFailed);
    }

    // SAFETY: the APIC was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { lapic() };
    regs.timer_dcr.write(0x03);

    // Compute initial count for the desired frequency
    let initial_count = bus_freq / frequency_hz;

    // Store for AP reuse (APs skip PIT calibration)
    TIMER_INITIAL_COUNT.store(initial_count, Ordering::Release);

    regs.lvt_timer.write(LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);

    // Writing the initial count starts the timer.
    regs.timer_icr.write(initial_count);

    crate::println!(
        "  APIC timer: {}Hz (bus={}MHz, count={}, div=16)",
        frequency_hz, bus_freq / 1_000_000, initial_count
    );

    Ok(())
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
    // SAFETY: PIT_CMD (0x43) is a valid x86 I/O port for the 8254 PIT.
    let pit_cmd = unsafe { super::portio::Port8::new(PIT_CMD) };
    // SAFETY: PIT_CHANNEL0_DATA (0x40) is a valid x86 I/O port for the 8254 PIT.
    let pit_ch0 = unsafe { super::portio::Port8::new(PIT_CHANNEL0_DATA) };

    // SAFETY: the APIC was initialized (ADR-036 § 3). One construction; used by
    // steps 1-3 and 6-7 below.
    let regs = unsafe { lapic() };

    // Step 1: Set APIC timer divide to 16
    regs.timer_dcr.write(0x03);

    // Step 2: Mask the APIC timer LVT (prevent interrupts during calibration)
    regs.lvt_timer.write(LVT_TIMER_MASKED);

    // Step 3: Set APIC timer initial count to max
    regs.timer_icr.write(0xFFFF_FFFF);

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
        pit_cmd.write(0x00);
        let lo = pit_ch0.read() as u16;
        let hi = pit_ch0.read() as u16;
        let count = (hi << 8) | lo;

        // PIT mode 0: counter decrements to 0 then output goes high.
        // When count wraps very low (or we read 0), calibration window is done.
        if count <= 1 {
            break;
        }
    }

    // Step 6: Read how many APIC ticks elapsed
    let apic_current = regs.timer_ccr.read();
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(apic_current);

    // Step 7: Stop APIC timer
    regs.timer_icr.write(0);

    // Step 8: Convert to bus frequency.
    // PIT calibration window duration: PIT_CALIBRATION_DIVISOR / PIT_FREQUENCY seconds.
    // elapsed APIC ticks occurred in that window.
    // bus_freq = elapsed / (divisor / PIT_FREQUENCY) = elapsed * PIT_FREQUENCY / divisor
    // This is the rate AFTER the divide-by-16 divisor.
    let bus_freq = (elapsed as u64 * PIT_FREQUENCY as u64) / PIT_CALIBRATION_DIVISOR as u64;

    bus_freq as u32
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
    // Ensure the APIC global enable bit is set in this AP's MSR
    // SAFETY: IA32_APIC_BASE is a valid MSR, called on AP with interrupts disabled.
    let mut apic_base = unsafe { super::msr::read(IA32_APIC_BASE_MSR) };
    if apic_base & APIC_BASE_ENABLE == 0 {
        apic_base |= APIC_BASE_ENABLE;
        // SAFETY: Writing the enable bit to IA32_APIC_BASE is valid at ring 0.
        unsafe { super::msr::write(IA32_APIC_BASE_MSR, apic_base) };
    }

    // Enable APIC via Spurious Interrupt Vector Register
    // (BSP already set the virtual base, which is the same for all CPUs)
    // SAFETY: the BSP initialized APIC_BASE_VIRT (ADR-036 § 3). One construction.
    let regs = unsafe { lapic() };
    let sivr = regs.sivr.read();
    regs.sivr.write(sivr | SIVR_APIC_ENABLE | SPURIOUS_VECTOR as u32);
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

    // Same timer configuration as BSP: divide by 16, periodic mode, TIMER_VECTOR
    // SAFETY: the APIC was initialized on this AP (init_ap completed; ADR-036 § 3).
    // One construction.
    let regs = unsafe { lapic() };
    regs.timer_dcr.write(0x03);
    regs.lvt_timer.write(LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
    // Writing the initial count starts the timer.
    regs.timer_icr.write(initial_count);
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

// ICR Low (0x300) / ICR High (0x310) MMIO offsets are encoded as the
// `icr_low` / `icr_high` fields of `LocalApicRegs` (ADR-036), offset-asserted.

/// HARDWARE: Intel SDM Vol 3 §10.6.1 — ICR bit 12, delivery status.
/// 1 = send pending.
const ICR_DELIVERY_STATUS: u32 = 1 << 12;
/// HARDWARE: Intel SDM Vol 3 §10.6.1 — ICR bit 14, level assert.
/// Required for INIT/SIPI; set for Fixed too.
const ICR_LEVEL_ASSERT: u32 = 1 << 14;

/// HARDWARE: Intel SDM Vol 3 §10.6.1 — ICR destination shorthand
/// encoding 0b00, "no shorthand" (use destination field).
const ICR_DEST_NO_SHORTHAND: u32 = 0b00 << 18;
/// HARDWARE: Intel SDM Vol 3 §10.6.1 — ICR shorthand 0b01, self.
const ICR_DEST_SELF: u32 = 0b01 << 18;
/// HARDWARE: Intel SDM Vol 3 §10.6.1 — ICR shorthand 0b10,
/// all processors including self.
const ICR_DEST_ALL_INCLUDING_SELF: u32 = 0b10 << 18;
/// HARDWARE: Intel SDM Vol 3 §10.6.1 — ICR shorthand 0b11,
/// all processors excluding self.
const ICR_DEST_ALL_EXCLUDING_SELF: u32 = 0b11 << 18;

/// HARDWARE: Intel SDM Vol 3 §10.6.1 — ICR delivery-mode bits 10:8,
/// Fixed (0b000).
const ICR_DELIVERY_FIXED: u32 = 0b000 << 8;

/// Wait for the previous IPI to be accepted by the target.
///
/// Spins on the ICR delivery status bit until it clears.
/// In practice this completes almost immediately.
#[inline]
fn wait_for_ipi_delivery(regs: &LocalApicRegs) {
    // Intel SDM: "The delivery status bit is cleared after the IPI message
    // has been accepted by the target processor(s) or the APIC bus."
    while regs.icr_low.read() & ICR_DELIVERY_STATUS != 0 {
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
    // SAFETY: the APIC was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { lapic() };
    wait_for_ipi_delivery(regs);

    // Write destination APIC ID (bits 31:24 of ICR High).
    regs.icr_high.write((dest_apic_id as u32) << 24);

    // Write ICR Low: vector + Fixed delivery + level assert + no shorthand.
    // This write triggers the IPI, so ICR High must already be set.
    regs.icr_low
        .write(vector as u32 | ICR_DELIVERY_FIXED | ICR_LEVEL_ASSERT | ICR_DEST_NO_SHORTHAND);
}

/// Send a fixed IPI with the given vector to ALL other CPUs (excluding self).
///
/// Uses the "all excluding self" destination shorthand — no need to specify
/// a destination APIC ID.
///
/// # Safety
/// APIC must be initialized. Vector must be registered in every CPU's IDT.
pub unsafe fn send_ipi_all_excluding_self(vector: u8) {
    // SAFETY: the APIC was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { lapic() };
    wait_for_ipi_delivery(regs);

    // Shorthand mode ignores the destination field, but we clear it for hygiene.
    regs.icr_high.write(0);

    // Write ICR Low: vector + Fixed + level assert + all-excluding-self shorthand.
    regs.icr_low
        .write(vector as u32 | ICR_DELIVERY_FIXED | ICR_LEVEL_ASSERT | ICR_DEST_ALL_EXCLUDING_SELF);
}

/// Send a fixed IPI to self.
///
/// # Safety
/// APIC must be initialized. Vector must be registered in this CPU's IDT.
pub unsafe fn send_ipi_self(vector: u8) {
    // SAFETY: the APIC was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { lapic() };
    wait_for_ipi_delivery(regs);

    regs.icr_high.write(0);

    regs.icr_low
        .write(vector as u32 | ICR_DELIVERY_FIXED | ICR_LEVEL_ASSERT | ICR_DEST_SELF);
}
