// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Per-CPU data for SMP support
//!
//! Each CPU core has its own `PerCpu` instance, accessed via the GS segment
//! base register (IA32_GS_BASE MSR). The `self_ptr` field at offset 0 enables
//! efficient `gs:[0]` reads in assembly to retrieve the struct pointer.
//!
//! ## Usage
//! - BSP calls `init_bsp()` during boot after APIC initialization
//! - APs call `init_ap()` during their startup sequence
//! - Any code can call `current_percpu()` to get the current CPU's data
//!
//! ## GS base and swapgs
//! Currently the kernel owns GS base at all times. When user-mode GS base
//! support is added, `swapgs` must be inserted at syscall/interrupt entry
//! and exit points to swap between kernel and user GS base.

/// Maximum number of CPUs supported.
///
/// 256 matches the xAPIC APIC ID space (8-bit). Memory cost is ~50 KB
/// across all per-CPU arrays (GDT, TSS, PerCpu, scheduler) — trivial.
pub const MAX_CPUS: usize = 256;

/// IA32_GS_BASE MSR — holds the base address for GS segment reads
const IA32_GS_BASE: u32 = 0xC000_0101;

// Assembly-visible field offsets (must match #[repr(C)] layout above).
// Used by `syscall_entry` to access kernel_rsp0 and user_rsp_scratch via GS.
/// GS-relative offset of `PerCpu.kernel_rsp0`
pub const PERCPU_KERNEL_RSP0: usize = 24;
/// GS-relative offset of `PerCpu.user_rsp_scratch`
pub const PERCPU_USER_RSP_SCRATCH: usize = 32;

// ============================================================================
// PerCpu struct
// ============================================================================

/// Per-CPU data structure.
///
/// Each CPU core has its own instance, accessed via the GS base MSR.
/// `#[repr(C)]` guarantees field order matches declaration so assembly
/// can use fixed offsets.
///
/// ## Layout (offsets)
/// | Offset | Field            | Size |
/// |--------|------------------|------|
/// |   0    | self_ptr         |  8   |
/// |   8    | cpu_id           |  4   |
/// |  12    | apic_id          |  4   |
/// |  16    | current_task_id  |  4   |
/// |  20    | interrupt_depth  |  4   |
/// |  24    | kernel_rsp0      |  8   |
/// |  32    | user_rsp_scratch |  8   |
#[repr(C)]
pub struct PerCpu {
    /// Pointer to self — enables `mov rax, gs:[0]` to get the PerCpu pointer.
    /// Set once during init and never changed.
    self_ptr: *const PerCpu,
    /// Logical CPU index (0 = BSP, 1+ = APs)
    cpu_id: u32,
    /// Local APIC ID (hardware-assigned, used for IPIs)
    apic_id: u32,
    /// Task ID currently running on this CPU (0 = idle/none)
    current_task_id: u32,
    /// Interrupt nesting depth (0 = thread context, >0 = ISR context)
    interrupt_depth: u32,
    /// Kernel stack pointer for the current task. Read by `syscall_entry` to
    /// switch RSP from user to kernel stack on SYSCALL. Updated by
    /// `set_kernel_stack()` on every context switch.
    kernel_rsp0: u64,
    /// Scratch space for saving user RSP during SYSCALL entry. The stub writes
    /// `mov gs:[PERCPU_USER_RSP_SCRATCH], rsp` before switching to the kernel
    /// stack, then pushes the saved value onto the kernel stack.
    user_rsp_scratch: u64,
}

// SAFETY: PerCpu is only accessed by its owning CPU (via GS base), so there
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
            apic_id: 0,
            current_task_id: 0,
            interrupt_depth: 0,
            kernel_rsp0: 0,
            user_rsp_scratch: 0,
        }
    }

    /// Logical CPU index (0 = BSP).
    #[inline]
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Hardware APIC ID.
    #[inline]
    pub fn apic_id(&self) -> u32 {
        self.apic_id
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

    /// Set the kernel stack pointer for SYSCALL entry.
    ///
    /// Called by `set_kernel_stack()` on every context switch so that
    /// `syscall_entry` can read `gs:[PERCPU_KERNEL_RSP0]` to switch RSP.
    #[inline]
    pub fn set_kernel_rsp0(&mut self, rsp0: u64) {
        self.kernel_rsp0 = rsp0;
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
/// Sets up the PerCpu struct and writes its address to IA32_GS_BASE so
/// that `current_percpu()` works from this point forward.
///
/// # Safety
/// Must be called once during single-threaded boot on the BSP, after
/// APIC initialization (so the APIC ID is available).
pub unsafe fn init_bsp(apic_id: u32) {
    // SAFETY: Single-threaded boot. PER_CPU_DATA is a mutable static but
    // only the BSP accesses index 0 during init with interrupts disabled.
    // IA32_GS_BASE is a valid MSR; percpu has 'static lifetime.
    unsafe {
        let percpu = &raw mut PER_CPU_DATA[0];
        (*percpu).self_ptr = percpu as *const PerCpu;
        (*percpu).cpu_id = 0;
        (*percpu).apic_id = apic_id;
        (*percpu).current_task_id = 0;
        (*percpu).interrupt_depth = 0;

        super::msr::write(IA32_GS_BASE, percpu as u64);
    }

    CPU_COUNT.store(1, core::sync::atomic::Ordering::Release);
}

/// Initialize per-CPU data for an Application Processor.
///
/// # Safety
/// Must be called exactly once per AP, on the AP itself, during its
/// startup sequence. `cpu_index` must be unique and in 1..MAX_CPUS.
pub unsafe fn init_ap(cpu_index: usize, apic_id: u32) {
    assert!(cpu_index > 0 && cpu_index < MAX_CPUS, "AP cpu_index out of range");

    // SAFETY: Each AP calls this exactly once with a unique cpu_index during
    // its startup sequence. PER_CPU_DATA[cpu_index] is only accessed by this AP.
    // IA32_GS_BASE is a valid MSR; percpu has 'static lifetime.
    unsafe {
        let percpu = &raw mut PER_CPU_DATA[cpu_index];
        (*percpu).self_ptr = percpu as *const PerCpu;
        (*percpu).cpu_id = cpu_index as u32;
        (*percpu).apic_id = apic_id;
        (*percpu).current_task_id = 0;
        (*percpu).interrupt_depth = 0;

        super::msr::write(IA32_GS_BASE, percpu as u64);
    }

    CPU_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
}

// ============================================================================
// Accessors
// ============================================================================

/// Get the current CPU's PerCpu data (read-only).
///
/// # Safety
/// GS base must have been initialized via `init_bsp()` or `init_ap()`.
#[inline(always)]
pub unsafe fn current_percpu() -> &'static PerCpu {
    let ptr: *const PerCpu;
    // SAFETY: GS base points to a valid PerCpu struct (initialized by
    // init_bsp/init_ap). Reading gs:[0] yields self_ptr, which is the
    // PerCpu address. The pointed-to data has 'static lifetime.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) ptr,
            options(nostack, readonly, preserves_flags),
        );
        &*ptr
    }
}

/// Get the current CPU's PerCpu data (mutable).
///
/// # Safety
/// GS base must have been initialized. Caller must ensure no concurrent
/// mutable access to this CPU's PerCpu (typically guaranteed by being in
/// a single execution context — thread or ISR — on this CPU).
#[inline(always)]
pub unsafe fn current_percpu_mut() -> &'static mut PerCpu {
    let ptr: *mut PerCpu;
    // SAFETY: Same as current_percpu, but returns &mut. Safe because PerCpu
    // is only accessed by its owning CPU, and the caller guarantees no
    // concurrent mutable access.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) ptr,
            options(nostack, readonly, preserves_flags),
        );
        &mut *ptr
    }
}

/// Convenience: get the current CPU's logical ID.
///
/// # Safety
/// GS base must be initialized.
#[inline(always)]
pub unsafe fn current_cpu_id() -> u32 {
    // SAFETY: Caller guarantees GS base is initialized.
    unsafe { current_percpu() }.cpu_id
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_percpu_size_and_alignment() {
        // PerCpu must be repr(C) with known layout
        assert_eq!(mem::size_of::<PerCpu>(), 40); // 8 + 4 + 4 + 4 + 4 + 8 + 8
        assert!(mem::align_of::<PerCpu>() >= 8); // pointer alignment
    }

    #[test]
    fn test_percpu_field_offsets() {
        // Verify offsets match the documented layout table and assembly constants
        let p = PerCpu::new();
        let base = &p as *const _ as usize;
        assert_eq!(&p.self_ptr as *const _ as usize - base, 0);
        assert_eq!(&p.cpu_id as *const _ as usize - base, 8);
        assert_eq!(&p.apic_id as *const _ as usize - base, 12);
        assert_eq!(&p.current_task_id as *const _ as usize - base, 16);
        assert_eq!(&p.interrupt_depth as *const _ as usize - base, 20);
        assert_eq!(&p.kernel_rsp0 as *const _ as usize - base, PERCPU_KERNEL_RSP0);
        assert_eq!(&p.user_rsp_scratch as *const _ as usize - base, PERCPU_USER_RSP_SCRATCH);
    }

    #[test]
    fn test_percpu_new_is_zeroed() {
        let p = PerCpu::new();
        assert!(p.self_ptr.is_null());
        assert_eq!(p.cpu_id, 0);
        assert_eq!(p.apic_id, 0);
        assert_eq!(p.current_task_id, 0);
        assert_eq!(p.interrupt_depth, 0);
        assert_eq!(p.kernel_rsp0, 0);
        assert_eq!(p.user_rsp_scratch, 0);
    }

    #[test]
    fn test_percpu_task_id() {
        let mut p = PerCpu::new();
        assert_eq!(p.current_task_id(), 0);
        p.set_current_task_id(42);
        assert_eq!(p.current_task_id(), 42);
    }

    #[test]
    fn test_percpu_interrupt_depth() {
        let mut p = PerCpu::new();
        assert!(!p.in_interrupt());
        assert_eq!(p.interrupt_depth(), 0);

        p.enter_interrupt();
        assert!(p.in_interrupt());
        assert_eq!(p.interrupt_depth(), 1);

        p.enter_interrupt(); // nested
        assert_eq!(p.interrupt_depth(), 2);

        p.exit_interrupt();
        assert_eq!(p.interrupt_depth(), 1);
        assert!(p.in_interrupt());

        p.exit_interrupt();
        assert_eq!(p.interrupt_depth(), 0);
        assert!(!p.in_interrupt());
    }

    #[test]
    fn test_percpu_kernel_rsp0() {
        let mut p = PerCpu::new();
        assert_eq!(p.kernel_rsp0, 0);
        p.set_kernel_rsp0(0xFFFF_8000_0010_0000);
        assert_eq!(p.kernel_rsp0, 0xFFFF_8000_0010_0000);
    }

    #[test]
    fn test_max_cpus_reasonable() {
        // Ensure MAX_CPUS doesn't cause unreasonable memory usage
        // 256 CPUs * 40 bytes = 10240 bytes — well within BSS budget
        assert!(MAX_CPUS * mem::size_of::<PerCpu>() < 65536);
    }

    #[test]
    fn test_cpu_count_initial() {
        // Before init, cpu_count should be 0
        // (Note: this test reads a global, so it must not race with other tests
        //  that call init_bsp. Since we don't call init_bsp in tests, this is safe.)
        // We just verify the function doesn't panic.
        let _ = cpu_count();
    }
}
