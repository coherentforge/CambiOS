// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! GIC (Generic Interrupt Controller) driver — AArch64
//!
//! Replaces x86_64's Local APIC + I/O APIC. AArch64 uses GICv3:
//! - Distributor: shared MMIO, routes SPIs (Shared Peripheral Interrupts)
//! - Redistributor: per-CPU MMIO, manages PPIs and SGIs
//! - CPU interface: system register access (ICC_* registers)
//!
//! ## Interrupt types
//! | Type | Range    | Description                        |
//! |------|----------|------------------------------------|
//! | SGI  | 0-15     | Software Generated (IPI equivalent) |
//! | PPI  | 16-31    | Private Per-Processor              |
//! | SPI  | 32-1019  | Shared Peripheral                  |
//!
//! ## GICv3 system registers
//! | Register        | Function                         |
//! |-----------------|----------------------------------|
//! | ICC_IAR1_EL1    | Acknowledge interrupt (read)     |
//! | ICC_EOIR1_EL1   | End of interrupt (write)         |
//! | ICC_PMR_EL1     | Priority mask (write)            |
//! | ICC_SRE_EL1     | System register enable           |
//! | ICC_IGRPEN1_EL1 | Group 1 interrupt enable         |
//! | ICC_SGI1R_EL1   | Software Generated Interrupt     |

use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum CPUs supported (matches percpu::MAX_CPUS).
const MAX_CPUS: usize = 256;

/// Per-CPU last acknowledged INTID, saved by `acknowledge_irq()` for `write_eoi()`.
/// Indexed by logical CPU index. 1023 = spurious / no pending acknowledge.
static LAST_IAR: [AtomicU32; MAX_CPUS] = {
    // const-init: array of AtomicU32(1023)
    const INIT: AtomicU32 = AtomicU32::new(1023);
    [INIT; MAX_CPUS]
};

/// Get the current CPU's logical index (for LAST_IAR indexing).
///
/// Reads TPIDR_EL1 → PerCpu → cpu_id. Falls back to 0 if percpu not yet initialized.
#[inline]
fn current_cpu_index() -> usize {
    let tpidr: u64;
    // SAFETY: Reading TPIDR_EL1 is always safe at EL1.
    unsafe {
        core::arch::asm!(
            "mrs {0}, tpidr_el1",
            out(reg) tpidr,
            options(nostack, nomem, preserves_flags),
        );
    }
    if tpidr == 0 {
        return 0; // Percpu not initialized yet — assume BSP
    }
    // SAFETY: tpidr points to a valid PerCpu struct. cpu_id is at offset 8.
    let cpu_id = unsafe { core::ptr::read_volatile((tpidr as usize + 8) as *const u32) };
    cpu_id as usize
}

/// Acknowledge the highest-priority pending interrupt.
///
/// Returns the INTID (0-1019 for valid interrupts, 1023 = spurious).
/// Saves the INTID per-CPU for the subsequent `write_eoi()` call.
///
/// # Safety
/// Must be called from an interrupt handler context at EL1.
pub unsafe fn acknowledge_irq() -> u32 {
    let intid: u64;
    // SAFETY: Reading ICC_IAR1_EL1 from EL1 in an IRQ handler is the
    // standard GICv3 acknowledge sequence.
    unsafe {
        core::arch::asm!(
            "mrs {0}, S3_0_C12_C12_0",  // ICC_IAR1_EL1
            out(reg) intid,
            options(nostack, nomem),
        );
    }
    let id = intid as u32;
    let cpu = current_cpu_index();
    LAST_IAR[cpu].store(id, Ordering::Relaxed);
    id
}

/// Send End-of-Interrupt for the current interrupt.
///
/// On GICv3, writes to ICC_EOIR1_EL1 system register.
/// Uses the INTID from the last `acknowledge_irq()` call on this CPU.
///
/// # Safety
/// Must be called from an interrupt handler context after `acknowledge_irq()`.
pub unsafe fn write_eoi() {
    let cpu = current_cpu_index();
    let intid = LAST_IAR[cpu].load(Ordering::Relaxed) as u64;
    // SAFETY: Writing ICC_EOIR1_EL1 from EL1 is the standard GICv3 EOI
    // sequence. intid is the value returned by ICC_IAR1_EL1.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C12_C12_1, {0}",  // ICC_EOIR1_EL1
            in(reg) intid,
            options(nostack, nomem),
        );
    }
}

/// Read the current CPU's ID from MPIDR_EL1.
///
/// Returns the Aff0 field (lowest 8 bits of affinity), which is the
/// per-cluster CPU number on most platforms.
pub fn read_cpu_id() -> u32 {
    let mpidr: u64;
    // SAFETY: Reading MPIDR_EL1 is always safe at EL1.
    unsafe {
        core::arch::asm!(
            "mrs {0}, mpidr_el1",
            out(reg) mpidr,
            options(nostack, nomem, preserves_flags),
        );
    }
    (mpidr & 0xFF) as u32  // Aff0
}

/// Initialize the GICv3 CPU interface via system registers.
///
/// Enables Group 1 interrupts, sets priority mask to accept all,
/// and ensures system register access is enabled.
///
/// Distributor and Redistributor MMIO initialization is deferred until
/// the device tree / ACPI provides their base addresses.
///
/// # Safety
/// Must be called once per CPU during boot with interrupts masked.
pub unsafe fn init() {
    // SAFETY: All system register accesses below are from EL1 during boot with
    // interrupts masked. This is the standard GICv3 CPU interface init sequence.
    unsafe {
        // Enable system register access (ICC_SRE_EL1.SRE = 1)
        core::arch::asm!(
            "mrs {tmp}, S3_0_C12_C12_5",  // ICC_SRE_EL1
            "orr {tmp}, {tmp}, #1",        // Set SRE bit
            "msr S3_0_C12_C12_5, {tmp}",  // ICC_SRE_EL1
            "isb",
            tmp = out(reg) _,
        );

        // Set priority mask to lowest priority (accept all interrupts)
        // ICC_PMR_EL1 = 0xFF
        core::arch::asm!(
            "mov {tmp}, #0xFF",
            "msr S3_0_C4_C6_0, {tmp}",    // ICC_PMR_EL1
            tmp = out(reg) _,
            options(nostack, nomem),
        );

        // Enable Group 1 interrupts (ICC_IGRPEN1_EL1 = 1)
        core::arch::asm!(
            "mov {tmp}, #1",
            "msr S3_0_C12_C12_7, {tmp}",  // ICC_IGRPEN1_EL1
            "isb",
            tmp = out(reg) _,
        );
    }
}

/// Send an SGI (Software Generated Interrupt) to another CPU.
///
/// On GICv3, writes ICC_SGI1R_EL1 with the target affinity and INTID.
///
/// # Safety
/// Must be called from EL1. `intid` must be in range 0..16.
pub unsafe fn send_sgi(target_aff: u64, intid: u8) {
    debug_assert!(intid < 16, "SGI INTID must be 0-15");
    // ICC_SGI1R_EL1 format:
    // [55:48] = Aff3, [39:32] = Aff2, [23:16] = Aff1
    // [15:0]  = TargetList (bitmask of Aff0 targets)
    // [27:24] = INTID
    // For simplicity: target a single CPU by Aff0 value
    let aff0 = target_aff & 0xFF;
    let target_list = 1u64 << aff0;
    let val = ((intid as u64) << 24) | target_list;
    // SAFETY: Writing ICC_SGI1R_EL1 from EL1 sends an SGI to the target CPU.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C12_C11_5, {0}",  // ICC_SGI1R_EL1
            in(reg) val,
            options(nostack, nomem),
        );
    }
}

/// Base vector for device interrupts (SPI range starts at INTID 32).
pub const DEVICE_VECTOR_BASE: u8 = 32;

// ============================================================================
// GIC Distributor (GICD) — shared across all CPUs
// ============================================================================
//
// QEMU `virt` machine GICv3 MMIO addresses:
//   GICD: 0x0800_0000 (64 KB)
//   GICR: 0x080A_0000 + 0x20000 * cpu_id (per-CPU, two frames per CPU)
//
// These addresses come from the device tree; for QEMU `virt` they are fixed.

use core::sync::atomic::AtomicU64;

/// GICD base address (set during init_distributor).
static GICD_BASE: AtomicU64 = AtomicU64::new(0);

/// GICR base address of CPU 0 (set during init_redistributor).
static GICR_BASE: AtomicU64 = AtomicU64::new(0);

// GICD register offsets
const GICD_CTLR: usize = 0x0000;        // Distributor Control
const GICD_TYPER: usize = 0x0004;       // Interrupt Controller Type
const GICD_ISENABLER: usize = 0x0100;   // Interrupt Set-Enable
const GICD_ICENABLER: usize = 0x0180;   // Interrupt Clear-Enable
const GICD_IPRIORITYR: usize = 0x0400;  // Interrupt Priority (byte per IRQ)
const GICD_ICFGR: usize = 0x0C00;       // Interrupt Configuration (2 bits per IRQ)

// GICR register offsets (per-CPU redistributor)
const GICR_WAKER: usize = 0x0014;       // Redistributor Waker
// SGI/PPI frame is GICR base + 0x10000
const GICR_SGI_BASE: usize = 0x10000;
const GICR_ISENABLER0: usize = GICR_SGI_BASE + 0x0100;  // SGI/PPI set-enable
const GICR_IPRIORITYR: usize = GICR_SGI_BASE + 0x0400;  // SGI/PPI priority

/// GICD MMIO read (32-bit).
///
/// # Safety
/// GICD_BASE must be initialized and the register offset must be valid.
#[inline]
unsafe fn gicd_read(offset: usize) -> u32 {
    let base = GICD_BASE.load(Ordering::Relaxed);
    // SAFETY: base is the GICD MMIO address, offset is a valid register.
    unsafe { core::ptr::read_volatile((base as usize + offset) as *const u32) }
}

/// GICD MMIO write (32-bit).
///
/// # Safety
/// GICD_BASE must be initialized and the register offset must be valid.
#[inline]
unsafe fn gicd_write(offset: usize, value: u32) {
    let base = GICD_BASE.load(Ordering::Relaxed);
    // SAFETY: base is the GICD MMIO address, offset is a valid register.
    unsafe { core::ptr::write_volatile((base as usize + offset) as *mut u32, value); }
}

/// GICR MMIO read for a specific CPU (32-bit).
///
/// # Safety
/// GICR_BASE must be initialized. `cpu_id` must be a valid CPU index.
#[inline]
unsafe fn gicr_read(cpu_id: u32, offset: usize) -> u32 {
    let base = GICR_BASE.load(Ordering::Relaxed);
    let cpu_base = base as usize + (cpu_id as usize) * 0x20000;
    // SAFETY: base + cpu_id offset is the per-CPU GICR frame.
    unsafe { core::ptr::read_volatile((cpu_base + offset) as *const u32) }
}

/// GICR MMIO write for a specific CPU (32-bit).
///
/// # Safety
/// GICR_BASE must be initialized. `cpu_id` must be a valid CPU index.
#[inline]
unsafe fn gicr_write(cpu_id: u32, offset: usize, value: u32) {
    let base = GICR_BASE.load(Ordering::Relaxed);
    let cpu_base = base as usize + (cpu_id as usize) * 0x20000;
    // SAFETY: base + cpu_id offset is the per-CPU GICR frame.
    unsafe { core::ptr::write_volatile((cpu_base + offset) as *mut u32, value); }
}

/// Initialize the GIC Distributor (global, called once on BSP).
///
/// Enables the distributor for Group 1 (NS) interrupts and sets
/// all SPI priorities to the default (0xA0).
///
/// # Safety
/// Must be called once during single-threaded boot with the GICD
/// MMIO region already mapped (via HHDM or explicit mapping).
pub unsafe fn init_distributor(gicd_base: u64) {
    GICD_BASE.store(gicd_base, Ordering::Release);

    // SAFETY: GICD MMIO is mapped and valid. All gicd_read/gicd_write and
    // write_volatile calls below access valid GICD registers. Called once
    // during single-threaded boot.
    unsafe {
        // Disable distributor while configuring
        gicd_write(GICD_CTLR, 0);

        // Read number of supported IRQ lines
        let typer = gicd_read(GICD_TYPER);
        let num_irqs = ((typer & 0x1F) + 1) * 32;
        crate::println!("  GIC Distributor: {} IRQ lines", num_irqs);

        // Set all SPI priorities to 0xA0 (default, lower than SGI/PPI)
        // SPIs start at INTID 32, priorities are byte-addressable
        let mut i = 32u32;
        while i < num_irqs {
            let offset = GICD_IPRIORITYR + (i as usize);
            core::ptr::write_volatile(
                (gicd_base as usize + offset) as *mut u8,
                0xA0,
            );
            i += 1;
        }

        // Disable all SPIs initially
        i = 1; // Register 0 is SGI/PPI (handled by GICR)
        while i < num_irqs / 32 {
            gicd_write(GICD_ICENABLER + (i as usize) * 4, 0xFFFF_FFFF);
            i += 1;
        }

        // Enable distributor: ARE (bit 4) + EnableGrp1NS (bit 1)
        gicd_write(GICD_CTLR, (1 << 4) | (1 << 1));
    }
}

/// Initialize the GIC Redistributor for a specific CPU.
///
/// Wakes the redistributor and enables PPI 30 (ARM Generic Timer).
///
/// # Safety
/// Must be called once per CPU during boot. GICR MMIO must be mapped.
pub unsafe fn init_redistributor(gicr_base: u64, cpu_id: u32) {
    if cpu_id == 0 {
        GICR_BASE.store(gicr_base, Ordering::Release);
    }

    // SAFETY: GICR MMIO is mapped and valid. All gicr_read/gicr_write and
    // write_volatile calls below access valid per-CPU GICR registers.
    // Called once per CPU during boot.
    unsafe {
        // Wake the redistributor (clear ProcessorSleep bit[1])
        let waker = gicr_read(cpu_id, GICR_WAKER);
        gicr_write(cpu_id, GICR_WAKER, waker & !(1 << 1));

        // Wait for ChildrenAsleep (bit[2]) to clear
        while gicr_read(cpu_id, GICR_WAKER) & (1 << 2) != 0 {
            core::hint::spin_loop();
        }

        // Set PPI 30 (timer) priority to 0x80 (higher than SPIs)
        let timer_prio_offset = GICR_IPRIORITYR + 30;
        let cpu_base = gicr_base as usize + (cpu_id as usize) * 0x20000;
        core::ptr::write_volatile(
            (cpu_base + timer_prio_offset) as *mut u8,
            0x80,
        );

        // Enable PPI 30 (ARM Generic Timer) in the redistributor
        // GICR_ISENABLER0 covers INTIDs 0-31 (SGIs and PPIs)
        let enable = gicr_read(cpu_id, GICR_ISENABLER0);
        gicr_write(cpu_id, GICR_ISENABLER0, enable | (1 << 30));
    }

    crate::println!("  GIC Redistributor: CPU {} woken, PPI 30 enabled", cpu_id);
}

/// Enable a Shared Peripheral Interrupt (SPI) in the distributor.
///
/// # Safety
/// GICD must be initialized. `intid` must be in range 32..1020.
pub unsafe fn enable_spi(intid: u32) {
    debug_assert!(intid >= 32 && intid < 1020);
    let reg_idx = (intid / 32) as usize;
    let bit = 1u32 << (intid % 32);
    // SAFETY: GICD is initialized and intid is a valid SPI range.
    unsafe { gicd_write(GICD_ISENABLER + reg_idx * 4, bit); }
}

/// Disable a Shared Peripheral Interrupt (SPI) in the distributor.
///
/// # Safety
/// GICD must be initialized. `intid` must be in range 32..1020.
pub unsafe fn disable_spi(intid: u32) {
    debug_assert!(intid >= 32 && intid < 1020);
    let reg_idx = (intid / 32) as usize;
    let bit = 1u32 << (intid % 32);
    // SAFETY: GICD is initialized and intid is a valid SPI range.
    unsafe { gicd_write(GICD_ICENABLER + reg_idx * 4, bit); }
}

/// Set the trigger mode for an SPI (level or edge).
///
/// # Safety
/// GICD must be initialized. `intid` must be in range 32..1020.
pub unsafe fn set_spi_trigger(intid: u32, edge: bool) {
    debug_assert!(intid >= 32 && intid < 1020);
    let reg_idx = (intid / 16) as usize;
    let bit_offset = ((intid % 16) * 2 + 1) as u32;
    // SAFETY: GICD is initialized and intid is a valid SPI range.
    unsafe {
        let mut val = gicd_read(GICD_ICFGR + reg_idx * 4);
        if edge {
            val |= 1 << bit_offset;
        } else {
            val &= !(1 << bit_offset);
        }
        gicd_write(GICD_ICFGR + reg_idx * 4, val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_last_iar_initial_value() {
        // All CPUs should start with 1023 (spurious)
        for i in 0..8 {
            assert_eq!(LAST_IAR[i].load(Ordering::Relaxed), 1023);
        }
    }

    #[test]
    fn test_device_vector_base() {
        assert_eq!(DEVICE_VECTOR_BASE, 32, "SPIs start at INTID 32");
    }

    #[test]
    fn test_gicd_register_offsets() {
        assert_eq!(GICD_CTLR, 0x0000);
        assert_eq!(GICD_TYPER, 0x0004);
        assert_eq!(GICD_ISENABLER, 0x0100);
        assert_eq!(GICD_ICENABLER, 0x0180);
        assert_eq!(GICD_IPRIORITYR, 0x0400);
        assert_eq!(GICD_ICFGR, 0x0C00);
    }

    #[test]
    fn test_gicr_register_offsets() {
        assert_eq!(GICR_WAKER, 0x0014);
        assert_eq!(GICR_SGI_BASE, 0x10000);
        assert_eq!(GICR_ISENABLER0, 0x10100);
        assert_eq!(GICR_IPRIORITYR, 0x10400);
    }

    #[test]
    fn test_spi_enable_register_math() {
        // SPI 32: register index 1 (32/32), bit 0 (32%32)
        let intid = 32u32;
        let reg_idx = (intid / 32) as usize;
        let bit = 1u32 << (intid % 32);
        assert_eq!(reg_idx, 1);
        assert_eq!(bit, 1);

        // SPI 63: register index 1, bit 31
        let intid = 63u32;
        let reg_idx = (intid / 32) as usize;
        let bit = 1u32 << (intid % 32);
        assert_eq!(reg_idx, 1);
        assert_eq!(bit, 1 << 31);

        // SPI 64: register index 2, bit 0
        let intid = 64u32;
        let reg_idx = (intid / 32) as usize;
        let bit = 1u32 << (intid % 32);
        assert_eq!(reg_idx, 2);
        assert_eq!(bit, 1);
    }

    #[test]
    fn test_spi_trigger_register_math() {
        // SPI 32: ICFGR register 2 (32/16), bit offset 1 ((32%16)*2+1)
        let intid = 32u32;
        let reg_idx = (intid / 16) as usize;
        let bit_offset = ((intid % 16) * 2 + 1) as u32;
        assert_eq!(reg_idx, 2);
        assert_eq!(bit_offset, 1);

        // SPI 47: ICFGR register 2, bit offset 31
        let intid = 47u32;
        let reg_idx = (intid / 16) as usize;
        let bit_offset = ((intid % 16) * 2 + 1) as u32;
        assert_eq!(reg_idx, 2);
        assert_eq!(bit_offset, 31);
    }

    #[test]
    fn test_gicr_cpu_stride() {
        // Each CPU's GICR frame is 0x20000 (128KB stride)
        let base = 0x080A_0000u64;
        let cpu0_base = base + 0 * 0x20000;
        let cpu1_base = base + 1 * 0x20000;
        let cpu3_base = base + 3 * 0x20000;
        assert_eq!(cpu0_base, 0x080A_0000);
        assert_eq!(cpu1_base, 0x080C_0000);
        assert_eq!(cpu3_base, 0x0810_0000);
    }

    #[test]
    fn test_max_cpus_matches() {
        assert_eq!(MAX_CPUS, 256);
    }
}
