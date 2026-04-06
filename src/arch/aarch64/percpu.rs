//! Per-CPU data — AArch64 implementation
//!
//! AArch64 uses TPIDR_EL1 (Thread ID Register, EL1) as the per-CPU data
//! pointer, equivalent to x86_64's GS base MSR. TPIDR_EL1 is only
//! accessible from EL1+ and is preserved across exceptions.
//!
//! ## Usage
//! - BSP calls `init_bsp()` during boot
//! - APs call `init_ap()` during their startup sequence
//! - Any code can call `current_percpu()` to read the current CPU's data
//!
//! ## TPIDR_EL1 vs x86_64 GS base
//! - TPIDR_EL1 is a 64-bit register holding an arbitrary value (no segment
//!   descriptor indirection like x86 GS base)
//! - No `swapgs` equivalent needed — EL1 and EL0 have separate registers
//!   (TPIDR_EL1 for kernel, TPIDR_EL0 for user)

/// Maximum number of CPUs supported.
///
/// Matches x86_64 MAX_CPUS (256) for consistency.
pub const MAX_CPUS: usize = 256;

// ============================================================================
// PerCpu struct
// ============================================================================

/// Per-CPU data structure.
///
/// Each CPU core has its own instance, accessed via TPIDR_EL1.
/// `#[repr(C)]` guarantees field order matches declaration.
///
/// ## Layout (offsets)
/// | Offset | Field            | Size |
/// |--------|------------------|------|
/// |   0    | self_ptr         |  8   |
/// |   8    | cpu_id           |  4   |
/// |  12    | (pad)            |  4   |
/// |  16    | mpidr_aff        |  8   |
/// |  24    | current_task_id  |  4   |
/// |  28    | interrupt_depth  |  4   |
#[repr(C)]
pub struct PerCpu {
    /// Pointer to self — enables `mrs x0, tpidr_el1` + load to get the struct.
    self_ptr: *const PerCpu,
    /// Logical CPU index (0 = BSP, 1+ = APs)
    cpu_id: u32,
    /// MPIDR affinity value (hardware CPU identity, used for SGIs)
    mpidr_aff: u64,
    /// Task ID currently running on this CPU (0 = idle/none)
    current_task_id: u32,
    /// Interrupt nesting depth (0 = thread context, >0 = ISR context)
    interrupt_depth: u32,
}

// SAFETY: PerCpu is only accessed by its owning CPU (via TPIDR_EL1), so there
// is no cross-thread sharing of a single instance. The static array requires
// Sync for compilation, but each element is only mutated by its owning CPU
// during single-threaded init (init_bsp/init_ap).
unsafe impl Send for PerCpu {}
unsafe impl Sync for PerCpu {}

impl PerCpu {
    /// Create a zeroed PerCpu (all fields null/zero).
    const fn new() -> Self {
        PerCpu {
            self_ptr: core::ptr::null(),
            cpu_id: 0,
            mpidr_aff: 0,
            current_task_id: 0,
            interrupt_depth: 0,
        }
    }

    /// Logical CPU index (0 = BSP).
    #[inline]
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Hardware MPIDR affinity (equivalent to APIC ID on x86_64).
    #[inline]
    pub fn apic_id(&self) -> u32 {
        self.mpidr_aff as u32
    }

    /// Task ID currently running on this CPU.
    #[inline]
    pub fn current_task_id(&self) -> u32 {
        self.current_task_id
    }

    /// Set the current task ID for this CPU.
    #[inline]
    pub fn set_current_task_id(&mut self, task_id: u32) {
        self.current_task_id = task_id;
    }

    /// Current interrupt nesting depth.
    #[inline]
    pub fn interrupt_depth(&self) -> u32 {
        self.interrupt_depth
    }

    /// Increment interrupt depth (call on ISR entry).
    #[inline]
    pub fn enter_interrupt(&mut self) {
        self.interrupt_depth += 1;
    }

    /// Decrement interrupt depth (call on ISR exit).
    #[inline]
    pub fn exit_interrupt(&mut self) {
        debug_assert!(self.interrupt_depth > 0, "interrupt depth underflow");
        self.interrupt_depth -= 1;
    }

    /// Returns true if currently executing in interrupt context.
    #[inline]
    pub fn in_interrupt(&self) -> bool {
        self.interrupt_depth > 0
    }
}

// ============================================================================
// Static per-CPU data array
// ============================================================================

/// Per-CPU data for all possible CPUs.
/// BSP uses index 0, APs use indices 1..MAX_CPUS.
static mut PER_CPU_DATA: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];

/// Number of initialized CPUs (BSP = 1, incremented as APs come online).
static CPU_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Get the number of online CPUs.
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize per-CPU data for the BSP (CPU 0).
///
/// Sets up the PerCpu struct and writes its address to TPIDR_EL1 so
/// that `current_percpu()` works from this point forward.
///
/// # Safety
/// Must be called once during single-threaded boot on the BSP.
pub unsafe fn init_bsp(mpidr_aff: u64) {
    // SAFETY: Single-threaded boot, no concurrent access to PER_CPU_DATA[0].
    let percpu = &raw mut PER_CPU_DATA[0];
    (*percpu).self_ptr = percpu as *const PerCpu;
    (*percpu).cpu_id = 0;
    (*percpu).mpidr_aff = mpidr_aff;
    (*percpu).current_task_id = 0;
    (*percpu).interrupt_depth = 0;

    // SAFETY: Writing TPIDR_EL1 from EL1 is always safe. percpu has 'static lifetime.
    core::arch::asm!(
        "msr tpidr_el1, {0}",
        in(reg) percpu as u64,
        options(nostack, nomem),
    );

    CPU_COUNT.store(1, core::sync::atomic::Ordering::Release);
}

/// Initialize per-CPU data for an Application Processor.
///
/// # Safety
/// Must be called exactly once per AP, on the AP itself, during its
/// startup sequence. `cpu_index` must be unique and in 1..MAX_CPUS.
pub unsafe fn init_ap(cpu_index: usize, mpidr_aff: u64) {
    assert!(cpu_index > 0 && cpu_index < MAX_CPUS, "AP cpu_index out of range");

    // SAFETY: Each AP initializes only its own PER_CPU_DATA slot.
    let percpu = &raw mut PER_CPU_DATA[cpu_index];
    (*percpu).self_ptr = percpu as *const PerCpu;
    (*percpu).cpu_id = cpu_index as u32;
    (*percpu).mpidr_aff = mpidr_aff;
    (*percpu).current_task_id = 0;
    (*percpu).interrupt_depth = 0;

    // SAFETY: Writing TPIDR_EL1 from EL1 on this AP is safe.
    core::arch::asm!(
        "msr tpidr_el1, {0}",
        in(reg) percpu as u64,
        options(nostack, nomem),
    );

    CPU_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
}

// ============================================================================
// Accessors
// ============================================================================

/// Get the current CPU's PerCpu data (read-only).
///
/// # Safety
/// TPIDR_EL1 must have been initialized via `init_bsp()` or `init_ap()`.
#[inline(always)]
pub unsafe fn current_percpu() -> &'static PerCpu {
    let ptr: u64;
    // SAFETY: TPIDR_EL1 was set to a valid PerCpu pointer during init.
    // The pointed-to data has 'static lifetime (lives in PER_CPU_DATA array).
    core::arch::asm!(
        "mrs {0}, tpidr_el1",
        out(reg) ptr,
        options(nostack, readonly, preserves_flags),
    );
    &*(ptr as *const PerCpu)
}

/// Get the current CPU's PerCpu data (mutable).
///
/// # Safety
/// TPIDR_EL1 must have been initialized. Caller must ensure no concurrent
/// mutable access to this CPU's PerCpu (typically guaranteed by being in
/// a non-preemptible context — ISR or interrupts masked).
#[inline(always)]
pub unsafe fn current_percpu_mut() -> &'static mut PerCpu {
    let ptr: u64;
    // SAFETY: Same as current_percpu; additionally, caller guarantees
    // exclusive access (e.g., interrupts masked or in ISR context).
    core::arch::asm!(
        "mrs {0}, tpidr_el1",
        out(reg) ptr,
        options(nostack, readonly, preserves_flags),
    );
    &mut *(ptr as *mut PerCpu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_percpu_struct_layout() {
        // Verify offsets match the documented layout (used in assembly)
        assert_eq!(mem::offset_of!(PerCpu, self_ptr), 0);
        assert_eq!(mem::offset_of!(PerCpu, cpu_id), 8);
        assert_eq!(mem::offset_of!(PerCpu, mpidr_aff), 16);
        assert_eq!(mem::offset_of!(PerCpu, current_task_id), 24);
        assert_eq!(mem::offset_of!(PerCpu, interrupt_depth), 28);
    }

    #[test]
    fn test_percpu_const_new() {
        let pc = PerCpu::new();
        assert!(pc.self_ptr.is_null());
        assert_eq!(pc.cpu_id(), 0);
        assert_eq!(pc.apic_id(), 0);
        assert_eq!(pc.current_task_id(), 0);
        assert_eq!(pc.interrupt_depth(), 0);
        assert!(!pc.in_interrupt());
    }

    #[test]
    fn test_percpu_interrupt_depth() {
        let mut pc = PerCpu::new();
        assert!(!pc.in_interrupt());

        pc.enter_interrupt();
        assert!(pc.in_interrupt());
        assert_eq!(pc.interrupt_depth(), 1);

        pc.enter_interrupt();
        assert_eq!(pc.interrupt_depth(), 2);

        pc.exit_interrupt();
        assert_eq!(pc.interrupt_depth(), 1);
        assert!(pc.in_interrupt());

        pc.exit_interrupt();
        assert_eq!(pc.interrupt_depth(), 0);
        assert!(!pc.in_interrupt());
    }

    #[test]
    fn test_percpu_task_id() {
        let mut pc = PerCpu::new();
        assert_eq!(pc.current_task_id(), 0);
        pc.set_current_task_id(42);
        assert_eq!(pc.current_task_id(), 42);
    }

    #[test]
    fn test_max_cpus() {
        assert_eq!(MAX_CPUS, 256);
    }

    #[test]
    fn test_cpu_count_initial() {
        // cpu_count should start at 0 or be set during previous test runs
        // (global state), so just verify it's accessible and returns a u32
        let _ = cpu_count();
    }

    #[test]
    fn test_percpu_array_size() {
        // The static array should have MAX_CPUS entries
        // SAFETY: Read-only access to check array length at compile time
        assert_eq!(unsafe { PER_CPU_DATA.len() }, MAX_CPUS);
    }
}
