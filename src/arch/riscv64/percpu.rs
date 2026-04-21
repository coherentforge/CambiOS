// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Per-CPU data — RISC-V (S-mode) implementation
//!
//! RISC-V uses the `tp` register (thread pointer, x4) as the per-CPU
//! data pointer in S-mode. The RISC-V ABI reserves `tp` for thread-
//! local storage and the compiler will not clobber it. This is the
//! analogue of x86_64's GS base and AArch64's TPIDR_EL1.
//!
//! ## `tp` + `sscratch` swap (trap entry)
//!
//! U-mode code owns its own `tp`; when trapping into S-mode we need
//! the kernel's PerCpu pointer. The standard RISC-V pattern is:
//!
//! ```text
//! trap_entry:
//!     csrrw tp, sscratch, tp     # atomic swap: tp = sscratch, sscratch = tp
//!     ...                         # tp now holds kernel PerCpu*
//!     csrrw tp, sscratch, tp     # swap back before sret
//! ```
//!
//! This is RISC-V's equivalent of x86_64's `swapgs`. AArch64 does not
//! need a swap because TPIDR_EL1 is not user-readable from EL0; on
//! RISC-V the `tp` register is fully user-accessible, so we must save
//! the user's value and restore it on exit.
//!
//! `sscratch` holds the kernel PerCpu* when running in U-mode, and zero
//! when running in S-mode (zero signals "trap came from S-mode" so the
//! trap handler knows not to swap — Phase R-3 wires this).

/// Maximum number of harts supported. Matches x86_64 / AArch64 for
/// consistency across architectures.
pub const MAX_CPUS: usize = 256;

// ============================================================================
// PerCpu struct — SAME LAYOUT AS AArch64
// ============================================================================

/// Per-CPU data structure. Layout matches AArch64 for cross-arch parity.
///
/// ## Layout (offsets used by trap handler assembly)
/// | Offset | Field             | Size |
/// |--------|-------------------|------|
/// |   0    | self_ptr          |  8   |
/// |   8    | cpu_id            |  4   |
/// |  12    | (pad)             |  4   |
/// |  16    | hart_id           |  8   |
/// |  24    | kernel_stack_top  |  8   |
/// |  32    | current_task_id   |  4   |
/// |  36    | interrupt_depth   |  4   |
/// |  40    | user_sp_scratch   |  8   |
#[repr(C)]
pub struct PerCpu {
    /// Pointer to self — allows `ld x0, 0(tp)` to fetch the struct.
    self_ptr: *const PerCpu,
    /// Logical CPU index (0 = BSP, 1+ = APs).
    cpu_id: u32,
    /// Hardware hart ID (from OpenSBI / DTB). RISC-V term for what
    /// x86 calls APIC ID or ARM calls MPIDR affinity.
    hart_id: u64,
    /// Kernel stack top for the current task. Updated by
    /// [`super::gdt::set_kernel_stack`] on every context switch.
    /// Read by the trap handler on U→S entry.
    kernel_stack_top: u64,
    /// Task ID currently running on this hart (0 = idle/none).
    current_task_id: u32,
    /// Interrupt nesting depth (0 = thread context, >0 = trap context).
    interrupt_depth: u32,
    /// Phase R-4 trap-entry scratch: on U→S entry the vector stashes
    /// the user's `sp` here (via `sd sp, 40(tp)`) before loading the
    /// kernel stack from `kernel_stack_top`, then immediately copies
    /// it back into the SavedContext's gpr[2] slot once the trap
    /// frame is allocated. Never accessed outside the trap vector.
    user_sp_scratch: u64,
}

// SAFETY: Each PerCpu is only touched by its owning hart (`tp` is set
// once per hart and not shared). Cross-hart reads of `cpu_id` /
// `hart_id` are read-only and benign. The array below requires Sync
// for compilation, but single-writer-per-slot is upheld at init.
unsafe impl Send for PerCpu {}
unsafe impl Sync for PerCpu {}

impl PerCpu {
    /// Create a zeroed PerCpu (all fields null/zero).
    const fn new() -> Self {
        PerCpu {
            self_ptr: core::ptr::null(),
            cpu_id: 0,
            hart_id: 0,
            kernel_stack_top: 0,
            current_task_id: 0,
            interrupt_depth: 0,
            user_sp_scratch: 0,
        }
    }

    /// Logical CPU index (0 = BSP).
    #[inline]
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Hardware hart ID. Named `apic_id` for API symmetry with the
    /// x86_64 and AArch64 backends; the field holds a RISC-V hart id.
    #[inline]
    pub fn apic_id(&self) -> u32 {
        self.hart_id as u32
    }

    /// Task ID currently running on this hart.
    #[inline]
    pub fn current_task_id(&self) -> u32 {
        self.current_task_id
    }

    /// Set the current task ID for this hart.
    #[inline]
    pub fn set_current_task_id(&mut self, task_id: u32) {
        self.current_task_id = task_id;
    }

    /// Current interrupt nesting depth.
    #[inline]
    pub fn interrupt_depth(&self) -> u32 {
        self.interrupt_depth
    }

    /// Increment interrupt depth (call on trap entry).
    #[inline]
    pub fn enter_interrupt(&mut self) {
        self.interrupt_depth += 1;
    }

    /// Decrement interrupt depth (call on trap exit).
    #[inline]
    pub fn exit_interrupt(&mut self) {
        debug_assert!(self.interrupt_depth > 0, "interrupt depth underflow");
        self.interrupt_depth -= 1;
    }

    /// Returns true if currently executing in trap/interrupt context.
    #[inline]
    pub fn in_interrupt(&self) -> bool {
        self.interrupt_depth > 0
    }
}

// ============================================================================
// Static per-CPU data array
// ============================================================================

static mut PER_CPU_DATA: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];

static CPU_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Number of online harts.
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize per-hart data for the BSP (CPU 0) and set `tp`.
///
/// # Safety
/// Must be called once during single-threaded boot on the BSP, after
/// paging is active (because we write a pointer into `tp` that the
/// trap handler will dereference via `sd`/`ld` on any future trap).
pub unsafe fn init_bsp(hart_id: u64) {
    // SAFETY: Single-threaded boot; no concurrent access. percpu has
    // 'static lifetime (lives in PER_CPU_DATA).
    unsafe {
        let percpu = &raw mut PER_CPU_DATA[0];
        (*percpu).self_ptr = percpu as *const PerCpu;
        (*percpu).cpu_id = 0;
        (*percpu).hart_id = hart_id;
        (*percpu).current_task_id = 0;
        (*percpu).interrupt_depth = 0;
        (*percpu).user_sp_scratch = 0;

        // Set tp = kernel PerCpu pointer; clear sscratch = 0. The
        // trap vector's entry `csrrw tp, sscratch, tp` expects this
        // invariant during kernel execution: sscratch == 0 (sentinel
        // for "trap came from kernel"). Before entering U-mode for
        // the first time, the sret-return path sets sscratch =
        // kernel_tp so the next U→S trap picks up the swap.
        core::arch::asm!(
            "mv tp, {ptr}",
            "csrw sscratch, zero",
            ptr = in(reg) percpu as u64,
            options(nostack, nomem, preserves_flags),
        );
    }

    CPU_COUNT.store(1, core::sync::atomic::Ordering::Release);
}

/// Initialize per-hart data for an Application Processor and set `tp`.
///
/// # Safety
/// Must be called exactly once per AP, on the AP itself. `cpu_index`
/// must be unique and in `1..MAX_CPUS`.
pub unsafe fn init_ap(cpu_index: usize, hart_id: u64) {
    assert!(
        cpu_index > 0 && cpu_index < MAX_CPUS,
        "AP cpu_index out of range"
    );

    // SAFETY: Each AP initializes only its own slot. Writing `tp`
    // from S-mode on this hart is safe.
    unsafe {
        let percpu = &raw mut PER_CPU_DATA[cpu_index];
        (*percpu).self_ptr = percpu as *const PerCpu;
        (*percpu).cpu_id = cpu_index as u32;
        (*percpu).hart_id = hart_id;
        (*percpu).current_task_id = 0;
        (*percpu).interrupt_depth = 0;

        core::arch::asm!(
            "mv tp, {0}",
            in(reg) percpu as u64,
            options(nostack, nomem, preserves_flags),
        );
    }

    CPU_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
}

// ============================================================================
// Accessors
// ============================================================================

/// Get the current hart's PerCpu data (read-only).
///
/// # Safety
/// `tp` must have been initialized via [`init_bsp`] / [`init_ap`].
#[inline(always)]
pub unsafe fn current_percpu() -> &'static PerCpu {
    let ptr: u64;
    // SAFETY: `tp` holds a valid *const PerCpu after init. The pointed
    // memory has 'static lifetime (PER_CPU_DATA).
    unsafe {
        core::arch::asm!(
            "mv {0}, tp",
            out(reg) ptr,
            options(nostack, readonly, preserves_flags),
        );
        &*(ptr as *const PerCpu)
    }
}

/// Get the current hart's PerCpu data (mutable).
///
/// # Safety
/// `tp` must be initialized. Caller must ensure no concurrent mutable
/// access to this hart's PerCpu (typically guaranteed by being in a
/// non-preemptible context — trap handler or interrupts masked).
#[inline(always)]
pub unsafe fn current_percpu_mut() -> &'static mut PerCpu {
    let ptr: u64;
    // SAFETY: Same as current_percpu; caller guarantees exclusive access.
    unsafe {
        core::arch::asm!(
            "mv {0}, tp",
            out(reg) ptr,
            options(nostack, readonly, preserves_flags),
        );
        &mut *(ptr as *mut PerCpu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_percpu_struct_layout() {
        // Offsets must match the AArch64 PerCpu layout so that
        // cross-arch portable code that reads percpu fields by offset
        // (via gdt::set_kernel_stack, trap handlers) works uniformly.
        assert_eq!(mem::offset_of!(PerCpu, self_ptr), 0);
        assert_eq!(mem::offset_of!(PerCpu, cpu_id), 8);
        // pad at 12
        assert_eq!(mem::offset_of!(PerCpu, hart_id), 16);
        assert_eq!(mem::offset_of!(PerCpu, kernel_stack_top), 24);
        assert_eq!(mem::offset_of!(PerCpu, current_task_id), 32);
        assert_eq!(mem::offset_of!(PerCpu, interrupt_depth), 36);
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
    fn test_max_cpus() {
        assert_eq!(MAX_CPUS, 256);
    }
}
