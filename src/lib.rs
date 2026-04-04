#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(dead_code)]
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]
//! ArcOS Microkernel - Verification-Ready Core
//!
//! A minimal microkernel for x86-64 supporting:
//! - Process/task management
//! - Message-passing IPC
//! - Capability-based security
//! - Userspace drivers and services

extern crate alloc;

#[cfg(target_arch = "x86_64")]
use x86_64::instructions::hlt;
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicU16, Ordering};

pub mod io;
pub mod memory;
pub mod interrupts;
pub mod platform;
pub mod ipc;
pub mod scheduler;
pub mod arch;
pub mod loader;
pub mod syscalls;
pub mod process;
pub mod acpi;

// Kernel heap allocator — initialized from Limine memory map in kmain
#[cfg(not(test))]
#[global_allocator]
pub static KERNEL_HEAP: memory::heap::LockedHeapAllocator = memory::heap::LockedHeapAllocator::new();

// Re-export power management from platform
pub use platform::{PowerManager, PowerState, PerformanceState};
pub use arch::spinlock::{Spinlock, IrqSpinlock};

use alloc::boxed::Box;

use scheduler::{Scheduler, Timer};
use ipc::IpcManager;
use ipc::capability::CapabilityManager;
use interrupts::InterruptRoutingTable;
use process::ProcessTable;

use memory::frame_allocator::FrameAllocator;

/// Global state protected by spinlocks (multicore-safe)
///
/// CRITICAL: Global lock ordering to prevent deadlocks
/// ====================================================
/// Acquire locks in this order ONLY. Never acquire in reverse or nested order:
/// 1. PER_CPU_SCHEDULER[*] (highest priority - preemption, task state)
/// 2. PER_CPU_TIMER[*] (tick counting)
/// 3. IPC_MANAGER (message queues)
/// 4. CAPABILITY_MANAGER (access control)
/// 5. PROCESS_TABLE (process metadata)
/// 6. FRAME_ALLOCATOR (physical page allocation)
/// 7. INTERRUPT_ROUTER (lowest priority - interrupt routing)
///
/// Per-CPU lock rule: NEVER hold two different CPUs' scheduler (or timer) locks
/// simultaneously. If cross-CPU access is required (e.g., task migration), acquire
/// in ascending CPU index order to prevent A-B / B-A deadlocks.
///
/// Large structs (IpcManager ~1.3MB, CapabilityManager ~100KB, ProcessTable ~132KB)
/// are heap-allocated via Box after the kernel heap is initialized from the Limine
/// memory map. Small structs remain stack-moved or BSS-initialized.

/// Maximum number of CPUs supported (matches xAPIC 8-bit APIC ID space).
/// Re-exported from `arch::x86_64::percpu` for use in global arrays.
pub const MAX_CPUS: usize = 256;

/// Per-CPU scheduler instances. Each CPU owns PER_CPU_SCHEDULER[cpu_id].
/// Indexed by logical CPU ID (0 = BSP, 1+ = APs).
pub static PER_CPU_SCHEDULER: [IrqSpinlock<Option<Box<Scheduler>>>; MAX_CPUS] =
    [const { IrqSpinlock::new(None) }; MAX_CPUS];

/// Per-CPU timer instances. Each CPU owns PER_CPU_TIMER[cpu_id].
pub static PER_CPU_TIMER: [IrqSpinlock<Option<Timer>>; MAX_CPUS] =
    [const { IrqSpinlock::new(None) }; MAX_CPUS];

/// Get the current CPU's scheduler lock.
///
/// Used by ISR and syscall hot paths. Returns the IrqSpinlock for the
/// calling CPU's scheduler instance.
///
/// # Safety
/// GS base must have been initialized via `init_bsp()` or `init_ap()`.
/// This is always true after the boot sequence completes.
#[cfg(target_arch = "x86_64")]
pub fn local_scheduler() -> &'static IrqSpinlock<Option<Box<Scheduler>>> {
    // SAFETY: GS base is set during init_bsp (BSP) or init_ap (APs).
    // After boot, all code paths have a valid GS base.
    let cpu_id = unsafe { arch::x86_64::percpu::current_percpu().cpu_id() } as usize;
    &PER_CPU_SCHEDULER[cpu_id]
}

/// Get the current CPU's timer lock.
///
/// # Safety
/// Same GS base requirement as `local_scheduler()`.
#[cfg(target_arch = "x86_64")]
pub fn local_timer() -> &'static IrqSpinlock<Option<Timer>> {
    // SAFETY: GS base is set during init_bsp (BSP) or init_ap (APs).
    let cpu_id = unsafe { arch::x86_64::percpu::current_percpu().cpu_id() } as usize;
    &PER_CPU_TIMER[cpu_id]
}

// ============================================================================
// Global task → CPU mapping (lock-free via atomics)
// ============================================================================

/// Maximum task slots (must match scheduler::MAX_TASKS).
pub const MAX_TASKS: usize = 32;

/// Sentinel value meaning "task unassigned / no CPU".
pub const TASK_CPU_NONE: u16 = u16::MAX;

/// Global map: TASK_CPU_MAP[task_id] = logical CPU that owns the task.
/// Updated during task creation, migration, and removal.
/// Lock-free reads enable fast cross-CPU wake without scanning all schedulers.
pub static TASK_CPU_MAP: [AtomicU16; MAX_TASKS] =
    [const { AtomicU16::new(TASK_CPU_NONE) }; MAX_TASKS];

/// Record that a task is owned by a specific CPU.
pub fn set_task_cpu(task_id: u32, cpu: u16) {
    if (task_id as usize) < MAX_TASKS {
        TASK_CPU_MAP[task_id as usize].store(cpu, Ordering::Release);
    }
}

/// Look up which CPU owns a task. Returns `None` if unassigned.
pub fn get_task_cpu(task_id: u32) -> Option<u16> {
    if (task_id as usize) < MAX_TASKS {
        let val = TASK_CPU_MAP[task_id as usize].load(Ordering::Acquire);
        if val == TASK_CPU_NONE { None } else { Some(val) }
    } else {
        None
    }
}

/// Wake a task by ID, looking up its owning CPU automatically.
///
/// This is the correct cross-CPU wake primitive. It reads TASK_CPU_MAP
/// to find the right per-CPU scheduler and wakes the task there.
///
/// Returns `true` if the task was successfully woken.
#[cfg(not(test))]
pub fn wake_task_on_cpu(task_id: scheduler::TaskId) -> bool {
    let cpu = match get_task_cpu(task_id.0) {
        Some(c) => c as usize,
        None => return false,
    };
    let mut guard = PER_CPU_SCHEDULER[cpu].lock();
    if let Some(sched) = guard.as_mut() {
        sched.wake_task(task_id).is_ok()
    } else {
        false
    }
}

/// Block a task on the current CPU's scheduler.
///
/// The task must be running on the current CPU (which is always true for
/// the calling task in a syscall or IPC helper).
#[cfg(not(test))]
pub fn block_local_task(
    task_id: scheduler::TaskId,
    reason: scheduler::BlockReason,
) -> bool {
    let mut guard = local_scheduler().lock();
    if let Some(sched) = guard.as_mut() {
        sched.block_task(task_id, reason).is_ok()
    } else {
        false
    }
}

pub static IPC_MANAGER: Spinlock<Option<Box<IpcManager>>> = Spinlock::new(None);
pub static CAPABILITY_MANAGER: Spinlock<Option<Box<CapabilityManager>>> = Spinlock::new(None);
pub static PROCESS_TABLE: Spinlock<Option<Box<ProcessTable>>> = Spinlock::new(None);
pub static FRAME_ALLOCATOR: Spinlock<FrameAllocator> = Spinlock::new(FrameAllocator::new());
pub static INTERRUPT_ROUTER: Spinlock<InterruptRoutingTable> = Spinlock::new(InterruptRoutingTable::new());

/// Higher-half direct map offset from Limine (set once during boot).
/// Physical address + HHDM_OFFSET = kernel-accessible virtual address.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Kernel PML4 physical address (set once during boot, before any user processes).
/// Used to restore CR3 when switching back to kernel tasks.
static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

/// Store the HHDM offset (called once from kmain after Limine response)
pub fn set_hhdm_offset(offset: u64) {
    HHDM_OFFSET.store(offset, Ordering::Release);
}

/// Get the HHDM offset for physical-to-virtual address translation
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Acquire)
}

/// Store the kernel CR3 (called once during boot)
pub fn set_kernel_cr3(cr3: u64) {
    KERNEL_CR3.store(cr3, Ordering::Release);
}

/// Get the kernel CR3 for restoring kernel address space
pub fn kernel_cr3() -> u64 {
    KERNEL_CR3.load(Ordering::Acquire)
}

/// Core subsystem initialization
///
/// # Safety
/// Must be called exactly once, early in boot, on the BSP core.
/// Caller must ensure hardware is in a known-good state (serial port at 0x3F8,
/// no prior IDT loaded, interrupts disabled).
pub unsafe fn init() {
    // SAFETY: Called once during boot; serial port 0x3F8 is the standard COM1 address.
    io::init();
    memory::init();
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Called once during boot with interrupts disabled; IDT not yet loaded.
    interrupts::init();
}

/// Halt the system
pub fn halt() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        hlt();
        #[cfg(not(target_arch = "x86_64"))]
        core::hint::spin_loop();
    }
}

/// Microkernel system state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelState {
    Booting = 0,
    Running = 1,
    Pausing = 2,
    Paused = 3,
    Halted = 4,
}

impl KernelState {
    /// Convert to u8 for atomic storage
    fn as_u8(self) -> u8 {
        self as u8
    }
    
    /// Convert from u8 (atomic storage)
    fn from_u8(val: u8) -> Self {
        match val {
            0 => KernelState::Booting,
            1 => KernelState::Running,
            2 => KernelState::Pausing,
            3 => KernelState::Paused,
            4 => KernelState::Halted,
            _ => KernelState::Halted, // Default fallback
        }
    }
}

/// Atomic kernel state - safe for multicore access
/// 
/// Uses AtomicU8 for lock-free, multicore-safe state management.
/// State transitions are atomic so all cores see consistent state.
static KERNEL_STATE: AtomicU8 = AtomicU8::new(KernelState::Booting as u8);

/// Get current microkernel state (multicore-safe, atomic read)
pub fn state() -> KernelState {
    let val = KERNEL_STATE.load(Ordering::Acquire);
    KernelState::from_u8(val)
}

/// Set microkernel state (multicore-safe, atomic write)
/// 
/// Uses Release ordering to ensure all state changes are visible to other cores.
pub(crate) fn set_state(new_state: KernelState) {
    KERNEL_STATE.store(new_state.as_u8(), Ordering::Release);
}
