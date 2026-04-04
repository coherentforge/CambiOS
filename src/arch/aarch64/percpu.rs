//! Per-CPU data — AArch64 scaffold
//!
//! AArch64 uses TPIDR_EL1 (Thread ID Register, EL1) as the per-CPU data
//! pointer, equivalent to x86_64's GS base MSR.

/// Per-CPU data structure.
pub struct PerCpu {
    cpu_id: u32,
    apic_id: u32,  // Named for compat; maps to MPIDR affinity on ARM
}

impl PerCpu {
    /// Get this CPU's logical ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

/// Get the current CPU's PerCpu data.
///
/// # Safety
/// TPIDR_EL1 must have been initialized (during BSP/AP init).
pub unsafe fn current_percpu() -> &'static PerCpu {
    todo!("AArch64: read TPIDR_EL1, cast to &PerCpu")
}

/// Initialize BSP per-CPU data.
///
/// # Safety
/// Must be called once on the BSP during boot.
pub unsafe fn init_bsp(_cpu_id: u32) {
    todo!("AArch64: allocate PerCpu, write TPIDR_EL1")
}

/// Initialize AP per-CPU data.
///
/// # Safety
/// Must be called once on each AP during startup.
pub unsafe fn init_ap(_logical_id: u32, _mpidr: u32) {
    todo!("AArch64: allocate PerCpu for AP, write TPIDR_EL1")
}

/// Get count of online CPUs.
pub fn cpu_count() -> u32 {
    1 // stub: BSP only
}
