//! GIC (Generic Interrupt Controller) driver — AArch64 scaffold
//!
//! Replaces x86_64's Local APIC + I/O APIC. AArch64 uses GICv3:
//! - Distributor: shared, routes SPIs (Shared Peripheral Interrupts)
//! - Redistributor: per-CPU, manages PPIs and SGIs
//! - CPU interface: system register access (ICC_* registers)
//!
//! ## Interrupt types
//! | Type | Range    | Description                        |
//! |------|----------|------------------------------------|
//! | SGI  | 0-15     | Software Generated (IPI equivalent) |
//! | PPI  | 16-31    | Private Per-Processor              |
//! | SPI  | 32-1019  | Shared Peripheral                  |

/// Send End-of-Interrupt for the current interrupt.
///
/// On GICv3, writes to ICC_EOIR1_EL1 system register.
///
/// # Safety
/// Must be called from an interrupt handler context.
pub unsafe fn write_eoi() {
    todo!("AArch64: write ICC_EOIR1_EL1")
}

/// Read the current CPU's ID (MPIDR_EL1 affinity).
pub fn read_cpu_id() -> u32 {
    todo!("AArch64: read MPIDR_EL1")
}

/// Initialize the GIC distributor and CPU interface.
///
/// # Safety
/// Must be called once during boot with interrupts masked.
pub unsafe fn init() {
    todo!("AArch64: GICv3 distributor + redistributor + CPU interface init")
}

/// Base vector for device interrupts (SPI range starts at INTID 32).
pub const DEVICE_VECTOR_BASE: u8 = 32;
