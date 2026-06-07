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

use crate::arch::mmio::{ReadOnly, ReadWrite, RegVal};
use bitflags::bitflags;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Maximum CPUs supported (matches percpu::MAX_CPUS).
const MAX_CPUS: usize = 256;

/// Per-CPU last acknowledged INTID, saved by `acknowledge_irq()` for `write_eoi()`.
/// Indexed by logical CPU index. 1023 = spurious / no pending acknowledge.
// Inline-const array init (the kernel's idiom for atomic arrays, e.g.
// TASK_GENERATION in lib.rs) — avoids a named interior-mutable `const`.
static LAST_IAR: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(1023) }; MAX_CPUS];

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
    // Standard GICv3 CPU interface init sequence; from EL1 during boot with
    // interrupts masked.

    // Enable system register access (ICC_SRE_EL1.SRE = 1).
    // SAFETY: ICC_SRE_EL1 access is safe from EL1.
    unsafe {
        core::arch::asm!(
            "mrs {tmp}, S3_0_C12_C12_5",  // ICC_SRE_EL1
            "orr {tmp}, {tmp}, #1",        // Set SRE bit
            "msr S3_0_C12_C12_5, {tmp}",  // ICC_SRE_EL1
            "isb",
            tmp = out(reg) _,
        );
    }

    // Set priority mask to lowest priority (accept all interrupts).
    // ICC_PMR_EL1 = 0xFF.
    // SAFETY: ICC_PMR_EL1 write is safe from EL1.
    unsafe {
        core::arch::asm!(
            "mov {tmp}, #0xFF",
            "msr S3_0_C4_C6_0, {tmp}",    // ICC_PMR_EL1
            tmp = out(reg) _,
            options(nostack, nomem),
        );
    }

    // Enable Group 1 interrupts (ICC_IGRPEN1_EL1 = 1).
    // SAFETY: ICC_IGRPEN1_EL1 write is safe from EL1.
    unsafe {
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
// GIC Distributor (GICD) + Redistributor (GICR) - typed register blocks (ADR-036)
// ============================================================================
//
// QEMU `virt` machine GICv3 MMIO addresses:
//   GICD: 0x0800_0000 (64 KiB) - shared across all CPUs
//   GICR: 0x080A_0000 + 0x20000 * cpu_id - per-CPU, two 64 KiB frames each
//         (RD_base frame at +0x00000, SGI_base frame at +0x10000)
//
// These addresses come from the device tree; for QEMU `virt` they are fixed.
//
// Per ADR-036 the register maps are `#[repr(C)]` blocks whose field offsets ARE
// the GICv3 spec offsets, pinned by `offset_of!` asserts. Construction from a
// mapped base is the single `unsafe` boundary; every field access is safe,
// access-class-checked, and (for control registers) value-typed via `bitflags`.

/// GICD base address (set during `init_distributor`).
static GICD_BASE: AtomicU64 = AtomicU64::new(0);

/// GICR base address of CPU 0 (set during `init_redistributor`).
static GICR_BASE: AtomicU64 = AtomicU64::new(0);

bitflags! {
    /// GICD_CTLR control bits (GICv3, Affinity Routing enabled, Non-Secure view).
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct GicdCtlr: u32 {
        /// Enable Group 1 Non-Secure interrupt forwarding.
        const ENABLE_GRP1NS = 1 << 1;
        /// Affinity Routing Enable (Non-Secure).
        const ARE = 1 << 4;
    }
}

impl RegVal<u32> for GicdCtlr {
    #[inline(always)]
    fn into_raw(self) -> u32 {
        self.bits()
    }
    #[inline(always)]
    fn from_raw(raw: u32) -> Self {
        // Preserve reserved/unknown bits so a read-modify-write never clears them.
        Self::from_bits_retain(raw)
    }
}

bitflags! {
    /// GICR_WAKER bits (redistributor wake handshake).
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct GicrWaker: u32 {
        /// Processor is asleep; cleared to wake the redistributor.
        const PROCESSOR_SLEEP = 1 << 1;
        /// Redistributor children still asleep; polled until clear.
        const CHILDREN_ASLEEP = 1 << 2;
    }
}

impl RegVal<u32> for GicrWaker {
    #[inline(always)]
    fn into_raw(self) -> u32 {
        self.bits()
    }
    #[inline(always)]
    fn from_raw(raw: u32) -> Self {
        // Preserve reserved/unknown bits so clearing PROCESSOR_SLEEP leaves the
        // rest of the register intact.
        Self::from_bits_retain(raw)
    }
}

/// GIC Distributor register block (GICv3). The reserved-padding fields exist
/// only to place the named registers at their GICv3 byte offsets, asserted
/// below; they are never read. Array lengths are HARDWARE facts: 32 enable
/// words cover 1024 INTIDs (1 bit each), 1024 priority bytes cover 1024 INTIDs
/// (1 byte each), 64 config words cover 1024 INTIDs (2 bits each).
#[repr(C)]
#[allow(dead_code)] // reserved-padding fields are layout-only, never read
struct GicdRegs {
    /// 0x0000 - Distributor Control.
    ctlr: ReadWrite<u32, GicdCtlr>,
    /// 0x0004 - Interrupt Controller Type (RO; bits[4:0] = (lines/32) - 1).
    typer: ReadOnly<u32>,
    _reserved_008_100: [u8; 0x0100 - 0x0008],
    /// 0x0100 - Interrupt Set-Enable, one bit per INTID (32 words).
    isenabler: [ReadWrite<u32>; 32],
    /// 0x0180 - Interrupt Clear-Enable, one bit per INTID (32 words).
    icenabler: [ReadWrite<u32>; 32],
    _reserved_200_400: [u8; 0x0400 - 0x0200],
    /// 0x0400 - Interrupt Priority, one byte per INTID.
    ipriorityr: [ReadWrite<u8>; 1024],
    _reserved_800_c00: [u8; 0x0C00 - 0x0800],
    /// 0x0C00 - Interrupt Configuration, 2 bits per INTID (64 words).
    icfgr: [ReadWrite<u32>; 64],
}

const _: () = assert!(core::mem::offset_of!(GicdRegs, ctlr) == 0x0000);
const _: () = assert!(core::mem::offset_of!(GicdRegs, typer) == 0x0004);
const _: () = assert!(core::mem::offset_of!(GicdRegs, isenabler) == 0x0100);
const _: () = assert!(core::mem::offset_of!(GicdRegs, icenabler) == 0x0180);
const _: () = assert!(core::mem::offset_of!(GicdRegs, ipriorityr) == 0x0400);
const _: () = assert!(core::mem::offset_of!(GicdRegs, icfgr) == 0x0C00);
const _: () = assert!(core::mem::size_of::<GicdRegs>() == 0x0D00);

/// GICR RD_base frame (offset 0 within a per-CPU redistributor region). Only
/// WAKER is modeled; everything else is reserved padding to the 64 KiB frame
/// boundary.
#[repr(C)]
#[allow(dead_code)] // reserved-padding fields are layout-only, never read
struct GicrRdFrame {
    _reserved_000_014: [u8; 0x0014],
    /// 0x0014 - Redistributor Waker (wake handshake).
    waker: ReadWrite<u32, GicrWaker>,
    _reserved_018_end: [u8; 0x10000 - 0x0018],
}

const _: () = assert!(core::mem::offset_of!(GicrRdFrame, waker) == 0x0014);
const _: () = assert!(core::mem::size_of::<GicrRdFrame>() == 0x10000);

/// GICR SGI_base frame (offset 0x10000 within a per-CPU redistributor region).
/// Registers here address SGIs (INTID 0..15) and PPIs (INTID 16..31).
#[repr(C)]
#[allow(dead_code)] // reserved-padding fields are layout-only, never read
struct GicrSgiFrame {
    _reserved_000_080: [u8; 0x0080],
    /// 0x0080 - SGI/PPI Interrupt Group (one bit per INTID 0..31).
    igroupr0: ReadWrite<u32>,
    _reserved_084_100: [u8; 0x0100 - 0x0084],
    /// 0x0100 - SGI/PPI Interrupt Set-Enable (one bit per INTID 0..31).
    isenabler0: ReadWrite<u32>,
    _reserved_104_400: [u8; 0x0400 - 0x0104],
    /// 0x0400 - SGI/PPI Interrupt Priority (one byte per INTID 0..31).
    ipriorityr: [ReadWrite<u8>; 32],
    _reserved_420_d00: [u8; 0x0D00 - 0x0420],
    /// 0x0D00 - SGI/PPI Interrupt Group Modifier (one bit per INTID 0..31).
    igrpmodr0: ReadWrite<u32>,
    _reserved_d04_end: [u8; 0x10000 - 0x0D04],
}

const _: () = assert!(core::mem::offset_of!(GicrSgiFrame, igroupr0) == 0x0080);
const _: () = assert!(core::mem::offset_of!(GicrSgiFrame, isenabler0) == 0x0100);
const _: () = assert!(core::mem::offset_of!(GicrSgiFrame, ipriorityr) == 0x0400);
const _: () = assert!(core::mem::offset_of!(GicrSgiFrame, igrpmodr0) == 0x0D00);
const _: () = assert!(core::mem::size_of::<GicrSgiFrame>() == 0x10000);

/// A complete per-CPU redistributor region: RD_base frame followed by SGI_base
/// frame. The per-CPU stride is `size_of::<GicrFrame>()` == 0x20000 (asserted).
#[repr(C)]
struct GicrFrame {
    rd: GicrRdFrame,
    sgi: GicrSgiFrame,
}

const _: () = assert!(core::mem::offset_of!(GicrFrame, rd) == 0x00000);
const _: () = assert!(core::mem::offset_of!(GicrFrame, sgi) == 0x10000);
const _: () = assert!(core::mem::size_of::<GicrFrame>() == 0x20000);
// Nested-field asserts cross-check each SGI/RD register's ABSOLUTE position
// within the per-CPU frame against the GICv3 RD_base / SGI_base spec offsets.
const _: () = assert!(core::mem::offset_of!(GicrFrame, rd.waker) == 0x00014);
const _: () = assert!(core::mem::offset_of!(GicrFrame, sgi.igroupr0) == 0x10080);
const _: () = assert!(core::mem::offset_of!(GicrFrame, sgi.isenabler0) == 0x10100);
const _: () = assert!(core::mem::offset_of!(GicrFrame, sgi.ipriorityr) == 0x10400);
const _: () = assert!(core::mem::offset_of!(GicrFrame, sgi.igrpmodr0) == 0x10D00);

/// Construct the GICD register block from the stored base.
///
/// # Safety
/// `GICD_BASE` must have been initialized (in `init_distributor`) to a valid,
/// mapped GICD MMIO region of at least `size_of::<GicdRegs>()` with device
/// memory attributes.
#[inline]
unsafe fn gicd() -> &'static GicdRegs {
    let base = GICD_BASE.load(Ordering::Relaxed) as usize;
    // SAFETY: `base` is the mapped GICD MMIO region (ADR-036 § 3); the caller -
    // every `pub unsafe fn` here - upholds that the GICD was discovered and
    // mapped before any register access.
    unsafe { &*(base as *const GicdRegs) }
}

/// Construct CPU `cpu_id`'s GICR per-CPU frame from the stored base.
///
/// # Safety
/// `GICR_BASE` must have been initialized (in `init_redistributor` for CPU 0)
/// to a valid, mapped GICR region covering CPUs 0..=`cpu_id`, each a per-CPU
/// frame of `size_of::<GicrFrame>()` (0x20000) with device memory attributes.
#[inline]
unsafe fn gicr(cpu_id: u32) -> &'static GicrFrame {
    let base = GICR_BASE.load(Ordering::Relaxed) as usize;
    let cpu_base = base + (cpu_id as usize) * core::mem::size_of::<GicrFrame>();
    // SAFETY: `cpu_base` is CPU `cpu_id`'s mapped GICR frame; the per-CPU stride
    // is `size_of::<GicrFrame>()` == 0x20000 (asserted), matching the GICv3
    // redistributor layout (ADR-036 § 3, § 5).
    unsafe { &*(cpu_base as *const GicrFrame) }
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
    // SAFETY: `gicd_base` was just stored; the caller mapped the GICD region
    // (ADR-036 § 3). One construction; all field accesses below are safe.
    let regs = unsafe { gicd() };

    // Disable the distributor while configuring it.
    regs.ctlr.write(GicdCtlr::empty());

    // Read number of supported IRQ lines.
    let typer = regs.typer.read();
    let num_irqs = ((typer & 0x1F) + 1) * 32;
    crate::println!("  GIC Distributor: {} IRQ lines", num_irqs);

    // Set all SPI priorities to 0xA0 (default, lower than SGI/PPI). SPIs start
    // at INTID 32; IPRIORITYR is byte-addressable per INTID. num_irqs <= 1024,
    // so the index stays within ipriorityr's bounds.
    let mut i = 32usize;
    while i < num_irqs as usize {
        regs.ipriorityr[i].write(0xA0);
        i += 1;
    }

    // Disable all SPIs initially. Register 0 is SGI/PPI (owned by the GICR), so
    // start at word 1; num_irqs / 32 <= 32 keeps the index within icenabler.
    let mut word = 1usize;
    while word < (num_irqs / 32) as usize {
        regs.icenabler[word].write(0xFFFF_FFFF);
        word += 1;
    }

    // Enable ARE (Affinity Routing) + Group 1 NS interrupt forwarding.
    regs.ctlr.write(GicdCtlr::ARE | GicdCtlr::ENABLE_GRP1NS);
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
    // SAFETY: `GICR_BASE` was set on CPU 0 before any AP runs (ADR-036 § 3);
    // the caller mapped this CPU's redistributor frame. One construction; all
    // field accesses below are safe.
    let frame = unsafe { gicr(cpu_id) };

    // Wake the redistributor: clear ProcessorSleep, then wait for ChildrenAsleep.
    let mut waker = frame.rd.waker.read();
    waker.remove(GicrWaker::PROCESSOR_SLEEP);
    frame.rd.waker.write(waker);
    while frame.rd.waker.read().contains(GicrWaker::CHILDREN_ASLEEP) {
        core::hint::spin_loop();
    }

    // Put all SGIs/PPIs into Group 1 Non-Secure. IGROUPR0 is RES0 on secure-only
    // systems, but on QEMU virt (two-security-state GICv3) bit N == 0 routes
    // INTID N through Group 0 (secure FIQ), which never reaches ICC_IAR1_EL1 at
    // EL1-NS. The BSP tends to come up with bits already set by firmware; APs on
    // QEMU virt do NOT. Explicit assignment makes the AP timer PPI (30)
    // deliverable on every CPU.
    frame.sgi.igroupr0.write(0xFFFF_FFFF);
    // IGRPMODR0 = 0 keeps the assignment Group 1 NS (not Secure). 0 is the reset
    // value, written explicitly for determinism since the IGROUPR0/IGRPMODR0
    // pair jointly encodes the final group.
    frame.sgi.igrpmodr0.write(0);

    // Set PPI 30 (timer) priority to 0x80 (higher than SPIs).
    frame.sgi.ipriorityr[30].write(0x80);

    // Enable PPI 30 (ARM Generic Timer). ISENABLER0 is write-1-to-set - writing
    // a single bit avoids re-enabling stale PPIs a prior boot stage may have left
    // set (the previous read-modify-write was harmless but imprecise).
    frame.sgi.isenabler0.write(1 << 30);

    crate::println!("  GIC Redistributor: CPU {} woken, PPI 30 enabled", cpu_id);
}

/// Enable a Shared Peripheral Interrupt (SPI) in the distributor.
///
/// # Safety
/// GICD must be initialized. `intid` must be in range 32..1020.
pub unsafe fn enable_spi(intid: u32) {
    debug_assert!((32..1020).contains(&intid));
    let reg_idx = (intid / 32) as usize; // <= 31 for intid < 1020
    let bit = 1u32 << (intid % 32);
    // SAFETY: the GICD was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { gicd() };
    regs.isenabler[reg_idx].write(bit);
}

/// Disable a Shared Peripheral Interrupt (SPI) in the distributor.
///
/// # Safety
/// GICD must be initialized. `intid` must be in range 32..1020.
pub unsafe fn disable_spi(intid: u32) {
    debug_assert!((32..1020).contains(&intid));
    let reg_idx = (intid / 32) as usize; // <= 31 for intid < 1020
    let bit = 1u32 << (intid % 32);
    // SAFETY: the GICD was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { gicd() };
    regs.icenabler[reg_idx].write(bit);
}

/// Set the trigger mode for an SPI (level or edge).
///
/// # Safety
/// GICD must be initialized. `intid` must be in range 32..1020.
pub unsafe fn set_spi_trigger(intid: u32, edge: bool) {
    debug_assert!((32..1020).contains(&intid));
    let reg_idx = (intid / 16) as usize; // <= 63 for intid < 1020
    let bit_offset = (intid % 16) * 2 + 1;
    // SAFETY: the GICD was initialized (ADR-036 § 3). One construction.
    let regs = unsafe { gicd() };
    let mut val = regs.icfgr[reg_idx].read();
    if edge {
        val |= 1 << bit_offset;
    } else {
        val &= !(1 << bit_offset);
    }
    regs.icfgr[reg_idx].write(val);
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

    // The GICD/GICR register offsets are now enforced at compile time by the
    // `offset_of!` asserts on GicdRegs / GicrRdFrame / GicrSgiFrame / GicrFrame
    // (a wrong field offset fails to compile), which strictly subsumes the
    // former runtime offset-equality tests.

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
        // Each CPU's GICR frame is 0x20000 (two 64 KiB frames). The typed
        // GicrFrame block's size IS that stride, used directly in `gicr()`.
        assert_eq!(core::mem::size_of::<GicrFrame>(), 0x20000);
        let base = 0x080A_0000u64;
        let stride = core::mem::size_of::<GicrFrame>() as u64;
        assert_eq!(base + 0 * stride, 0x080A_0000);
        assert_eq!(base + 1 * stride, 0x080C_0000);
        assert_eq!(base + 3 * stride, 0x0810_0000);
    }

    #[test]
    fn test_max_cpus_matches() {
        assert_eq!(MAX_CPUS, 256);
    }
}
