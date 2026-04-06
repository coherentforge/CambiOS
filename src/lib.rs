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
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};

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
pub mod fs;

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
/// 7. INTERRUPT_ROUTER (interrupt routing)
/// 8. OBJECT_STORE (filesystem — highest-level subsystem, lowest priority)
///
/// Per-CPU lock rule: NEVER hold two different CPUs' scheduler (or timer) locks
/// simultaneously. If cross-CPU access is required (e.g., task migration), acquire
/// in ascending CPU index order to prevent A-B / B-A deadlocks.
///
/// Additional lock domains (independent of hierarchy above):
/// - PER_CPU_FRAME_CACHE[cpu] — per-CPU, never held with FRAME_ALLOCATOR
/// - SHARDED_IPC.shards[endpoint] — per-endpoint, never held cross-endpoint
/// - BOOTSTRAP_PRINCIPAL — written once at boot, read-only thereafter
///
/// Large structs (IpcManager ~1.3MB, CapabilityManager ~100KB, ProcessTable ~132KB,
/// RamObjectStore ~TBD) are heap-allocated via Box after the kernel heap is
/// initialized from the Limine memory map.

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

/// Get the current CPU's scheduler lock (AArch64).
///
/// # Safety
/// TPIDR_EL1 must have been initialized via `init_bsp()` or `init_ap()`.
#[cfg(target_arch = "aarch64")]
pub fn local_scheduler() -> &'static IrqSpinlock<Option<Box<Scheduler>>> {
    let cpu_id = unsafe { arch::aarch64::percpu::current_percpu().cpu_id() } as usize;
    &PER_CPU_SCHEDULER[cpu_id]
}

/// Get the current CPU's timer lock (AArch64).
#[cfg(target_arch = "aarch64")]
pub fn local_timer() -> &'static IrqSpinlock<Option<Timer>> {
    let cpu_id = unsafe { arch::aarch64::percpu::current_percpu().cpu_id() } as usize;
    &PER_CPU_TIMER[cpu_id]
}

// ============================================================================
// Global task → CPU mapping (lock-free via atomics)
// ============================================================================

/// Maximum task slots (must match scheduler::MAX_TASKS).
pub const MAX_TASKS: usize = 256;

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

/// Terminate the current task on this CPU.
///
/// Called from exception handlers (page fault, data abort) when the faulting
/// task cannot be recovered. Marks the task as Terminated so the scheduler
/// skips it on the next tick. The next timer interrupt will context-switch
/// to a Ready task.
///
/// Returns the TaskId of the terminated task, or None if no current task.
#[cfg(not(test))]
pub fn terminate_current_task() -> Option<scheduler::TaskId> {
    let mut guard = local_scheduler().lock();
    if let Some(sched) = guard.as_mut() {
        if let Some(task_id) = sched.current_task() {
            if let Some(task) = sched.get_task_mut_pub(task_id) {
                task.state = scheduler::TaskState::Terminated;
                return Some(task_id);
            }
        }
    }
    None
}

/// Test stub — exception handlers compile on macOS x86_64 test target
/// but per-CPU scheduler infrastructure is not available.
#[cfg(test)]
pub fn terminate_current_task() -> Option<scheduler::TaskId> {
    None
}

// ============================================================================
// Load balancing
// ============================================================================

/// Number of online CPUs (BSP = 1, incremented by each AP that completes init).
pub static ONLINE_CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// Minimum tick interval between balance attempts (1 second at 100Hz).
const BALANCE_INTERVAL_TICKS: u64 = 100;

/// Tick count at which the last balance attempt ran.
static LAST_BALANCE_TICK: AtomicU64 = AtomicU64::new(0);

/// Attempt to rebalance tasks across CPUs.
///
/// Called from the BSP idle loop. Samples each CPU's runnable task count
/// using `try_lock()` (non-blocking), then migrates one task from the most
/// loaded to the least loaded CPU if the imbalance is >= 2.
///
/// Throttled to run at most once per `BALANCE_INTERVAL_TICKS`.
#[cfg(not(test))]
pub fn try_load_balance() {
    // Throttle: only run every BALANCE_INTERVAL_TICKS
    let current_tick = scheduler::Timer::get_ticks();
    let last = LAST_BALANCE_TICK.load(Ordering::Relaxed);
    if current_tick < last + BALANCE_INTERVAL_TICKS {
        return;
    }
    LAST_BALANCE_TICK.store(current_tick, Ordering::Relaxed);

    let cpu_count = ONLINE_CPU_COUNT.load(Ordering::Acquire) as usize;
    if cpu_count < 2 {
        return;
    }

    // Sample load per CPU using try_lock (non-blocking — safe in idle context)
    // Load = active runnable tasks (Ready + Running, excluding idle task).
    let mut loads: [u16; 256] = [0; 256];
    let mut sampled: [bool; 256] = [false; 256];
    let mut sampled_count: usize = 0;

    for cpu in 0..cpu_count {
        if let Some(guard) = PER_CPU_SCHEDULER[cpu].try_lock() {
            if let Some(sched) = guard.as_ref() {
                loads[cpu] = sched.active_runnable_count() as u16;
                sampled[cpu] = true;
                sampled_count += 1;
            }
        }
    }

    if sampled_count < 2 {
        return;
    }

    // Find most-loaded and least-loaded among sampled CPUs
    let mut max_cpu: usize = 0;
    let mut min_cpu: usize = 0;
    let mut found_first = false;

    for cpu in 0..cpu_count {
        if !sampled[cpu] {
            continue;
        }
        if !found_first {
            max_cpu = cpu;
            min_cpu = cpu;
            found_first = true;
            continue;
        }
        if loads[cpu] > loads[max_cpu] {
            max_cpu = cpu;
        }
        if loads[cpu] < loads[min_cpu] {
            min_cpu = cpu;
        }
    }

    // Only migrate if imbalance >= 2 (avoids pointless 1-task thrashing)
    if max_cpu == min_cpu || loads[max_cpu] < loads[min_cpu] + 2 {
        return;
    }

    // Pick a migratable Ready task from the overloaded CPU
    let task_to_migrate = {
        if let Some(guard) = PER_CPU_SCHEDULER[max_cpu].try_lock() {
            if let Some(sched) = guard.as_ref() {
                sched.pick_migratable_task()
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some(tid) = task_to_migrate {
        // migrate_task handles its own locking with ascending CPU-index order
        let _ = scheduler::migrate_task(tid, max_cpu, min_cpu);
    }
}

/// Bootstrap Principal — the first identity in the system.
///
/// Generated at boot from a deterministic seed (Phase 0 — no real crypto).
/// Used to restrict BindPrincipal syscall: only the bootstrap Principal can
/// bind identities to processes. Written once during boot, read-only after.
pub static BOOTSTRAP_PRINCIPAL: BootstrapPrincipal = BootstrapPrincipal::new();

/// Atomic-like wrapper for the bootstrap Principal.
///
/// Written once at boot via `store()`, read via `load()`. Uses a Spinlock
/// internally because Principal is 32 bytes (too large for hardware atomics).
pub struct BootstrapPrincipal {
    inner: Spinlock<ipc::Principal>,
}

impl BootstrapPrincipal {
    pub const fn new() -> Self {
        BootstrapPrincipal {
            inner: Spinlock::new(ipc::Principal::ZERO),
        }
    }

    /// Set the bootstrap Principal (called once during boot).
    pub fn store(&self, p: ipc::Principal) {
        *self.inner.lock() = p;
    }

    /// Read the bootstrap Principal.
    pub fn load(&self) -> ipc::Principal {
        *self.inner.lock()
    }
}

pub static IPC_MANAGER: Spinlock<Option<Box<IpcManager>>> = Spinlock::new(None);

/// Sharded IPC manager — per-endpoint locking for scalability.
///
/// New code should prefer `SHARDED_IPC` over `IPC_MANAGER` for send/recv
/// operations. Each endpoint has its own lock, so CPUs communicating on
/// different endpoints never contend.
///
/// The old `IPC_MANAGER` is retained for backward compatibility with
/// capability-enforced IPC paths and interceptor setup.
pub static SHARDED_IPC: ipc::ShardedIpcManager = ipc::ShardedIpcManager::new();
pub static CAPABILITY_MANAGER: Spinlock<Option<Box<CapabilityManager>>> = Spinlock::new(None);
pub static PROCESS_TABLE: Spinlock<Option<Box<ProcessTable>>> = Spinlock::new(None);
pub static FRAME_ALLOCATOR: Spinlock<FrameAllocator> = Spinlock::new(FrameAllocator::new());
pub static INTERRUPT_ROUTER: Spinlock<InterruptRoutingTable> = Spinlock::new(InterruptRoutingTable::new());

/// Object store — content-addressed signed object storage (lock position 8).
///
/// Initialized at boot after all other subsystems. Phase 0 uses RamObjectStore
/// (fixed-capacity, RAM-backed). Phase 1+ adds disk-backed implementations.
pub static OBJECT_STORE: Spinlock<Option<Box<fs::ram::RamObjectStore>>> = Spinlock::new(None);

// ============================================================================
// Per-CPU frame cache — reduces global FRAME_ALLOCATOR lock contention
// ============================================================================

use memory::frame_allocator::{FrameCache, PhysFrame, FrameAllocError};

/// Per-CPU frame caches. Each CPU owns `PER_CPU_FRAME_CACHE[cpu_id]`.
/// Contention is effectively zero since only the local CPU accesses its cache.
pub static PER_CPU_FRAME_CACHE: [Spinlock<FrameCache>; MAX_CPUS] =
    [const { Spinlock::new(FrameCache::new()) }; MAX_CPUS];

/// Get the current CPU's frame cache lock.
#[cfg(target_arch = "x86_64")]
pub fn local_frame_cache() -> &'static Spinlock<FrameCache> {
    let cpu_id = unsafe { arch::x86_64::percpu::current_percpu().cpu_id() } as usize;
    &PER_CPU_FRAME_CACHE[cpu_id]
}

/// Get the current CPU's frame cache lock (AArch64).
#[cfg(target_arch = "aarch64")]
pub fn local_frame_cache() -> &'static Spinlock<FrameCache> {
    let cpu_id = unsafe { arch::aarch64::percpu::current_percpu().cpu_id() } as usize;
    &PER_CPU_FRAME_CACHE[cpu_id]
}

/// Allocate a physical frame, preferring the local CPU's cache.
///
/// Fast path (no global lock): pop from per-CPU cache.
/// Slow path (on empty): acquire FRAME_ALLOCATOR, refill cache batch, pop.
///
/// Lock ordering: per-CPU cache acquired and released independently of
/// FRAME_ALLOCATOR. No nested locks — cache is released before global.
#[cfg(not(test))]
pub fn cached_allocate_frame() -> Result<PhysFrame, FrameAllocError> {
    // Fast path: local cache has frames
    {
        let mut cache = local_frame_cache().lock();
        if let Some(frame) = cache.pop() {
            return Ok(frame);
        }
    } // cache lock released

    // Slow path: refill from global allocator
    {
        let mut cache = local_frame_cache().lock();
        let mut global = FRAME_ALLOCATOR.lock();
        let got = cache.refill(&mut global);
        drop(global);

        if got > 0 {
            Ok(cache.pop().unwrap())
        } else {
            Err(FrameAllocError::OutOfMemory)
        }
    }
}

/// Free a physical frame, preferring the local CPU's cache.
///
/// Fast path (no global lock): push to per-CPU cache.
/// Slow path (on full): drain half the cache to global, then push.
#[cfg(not(test))]
pub fn cached_free_frame(frame: PhysFrame) -> Result<(), FrameAllocError> {
    // Fast path: cache has room
    {
        let mut cache = local_frame_cache().lock();
        if cache.push(frame).is_none() {
            return Ok(());
        }
    } // cache lock released — cache is full

    // Slow path: drain half the cache to make room
    {
        let mut cache = local_frame_cache().lock();
        let mut global = FRAME_ALLOCATOR.lock();
        cache.drain(&mut global);
        drop(global);

        // Now there's room — push the frame
        let overflow = cache.push(frame);
        debug_assert!(overflow.is_none(), "cache push failed after drain");
        Ok(())
    }
}

/// Test-mode fallback: allocate directly from global allocator (no per-CPU cache).
#[cfg(test)]
pub fn cached_allocate_frame() -> Result<PhysFrame, FrameAllocError> {
    FRAME_ALLOCATOR.lock().allocate()
}

/// Test-mode fallback: free directly to global allocator (no per-CPU cache).
#[cfg(test)]
pub fn cached_free_frame(frame: PhysFrame) -> Result<(), FrameAllocError> {
    FRAME_ALLOCATOR.lock().free(frame)
}

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
        #[cfg(target_arch = "aarch64")]
        // SAFETY: WFI is always safe at EL1 — it halts the core until the next
        // interrupt (or event from SEV).
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        core::hint::spin_loop();
    }
}

/// Wait for interrupt (AArch64 equivalent of x86_64 `hlt`).
///
/// Halts the CPU until the next interrupt, reducing power consumption.
/// Used in the idle loop and event loop.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn wfi() {
    // SAFETY: WFI is always safe at EL1.
    unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
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

// ============================================================================
// AArch64 logic tests — portable (run on macOS host)
// ============================================================================
//
// These test the pure-logic portions of the AArch64 subsystems: register
// calculations, MMIO offset math, struct layout invariants, timer formulas.
// They don't import from arch::aarch64 (which is cfg-gated) — instead they
// inline the relevant constants and formulas.

#[cfg(test)]
mod aarch64_logic_tests {
    // GIC register math (mirrors gic.rs constants)
    const GICD_ISENABLER: usize = 0x0100;
    const GICD_ICENABLER: usize = 0x0180;
    const GICD_ICFGR: usize = 0x0C00;
    const GICR_SGI_BASE: usize = 0x10000;
    const GICR_STRIDE: usize = 0x20000;

    #[test]
    fn test_gic_spi_enable_register_index() {
        // SPI 32: register 1 (32/32), bit 0
        assert_eq!(32u32 / 32, 1);
        assert_eq!(1u32 << (32u32 % 32), 1);
        // SPI 63: register 1, bit 31
        assert_eq!(63u32 / 32, 1);
        assert_eq!(1u32 << (63u32 % 32), 1 << 31);
        // SPI 64: register 2, bit 0
        assert_eq!(64u32 / 32, 2);
        assert_eq!(1u32 << (64u32 % 32), 1);
    }

    #[test]
    fn test_gic_spi_trigger_config_register() {
        // ICFGR has 2 bits per IRQ, 16 IRQs per 32-bit register
        // SPI 32: register 2 (32/16), bit offset = (32%16)*2+1 = 1
        assert_eq!(32u32 / 16, 2);
        assert_eq!((32u32 % 16) * 2 + 1, 1);
        // SPI 47: register 2, bit offset = (47%16)*2+1 = 31
        assert_eq!(47u32 / 16, 2);
        assert_eq!((47u32 % 16) * 2 + 1, 31);
        // SPI 48: register 3, bit offset = 1
        assert_eq!(48u32 / 16, 3);
        assert_eq!((48u32 % 16) * 2 + 1, 1);
    }

    #[test]
    fn test_gicr_cpu_stride() {
        let base = 0x080A_0000u64;
        assert_eq!(base + 0 * GICR_STRIDE as u64, 0x080A_0000);
        assert_eq!(base + 1 * GICR_STRIDE as u64, 0x080C_0000);
        assert_eq!(base + 3 * GICR_STRIDE as u64, 0x0810_0000);
    }

    #[test]
    fn test_gicr_sgi_frame_offset() {
        // SGI/PPI registers are at GICR base + 0x10000
        assert_eq!(GICR_SGI_BASE, 0x10000);
        assert_eq!(GICR_SGI_BASE + 0x0100, 0x10100); // ISENABLER0
        assert_eq!(GICR_SGI_BASE + 0x0400, 0x10400); // IPRIORITYR
    }

    // Timer calculations (mirrors timer.rs)
    #[test]
    fn test_timer_reload_qemu() {
        // QEMU virt: 62.5 MHz, 100 Hz tick → 625,000 ticks
        let freq = 62_500_000u32;
        assert_eq!(freq / 100, 625_000);
    }

    #[test]
    fn test_timer_reload_real_hw() {
        // Common real hardware: 24 MHz
        assert_eq!(24_000_000u32 / 100, 240_000);
        // Another common: 400 MHz
        assert_eq!(400_000_000u32 / 100, 4_000_000);
    }

    #[test]
    fn test_timer_elapsed_ms() {
        let freq: u64 = 62_500_000;
        let boot: u64 = 1000;
        let now: u64 = 63_501_000;
        let elapsed = ((now - boot) * 1000) / freq;
        assert_eq!(elapsed, 1016);
    }

    #[test]
    fn test_timer_ppi_intid() {
        // ARM timer PPI is INTID 30 (physical non-secure EL1)
        assert_eq!(30u32, 30);
    }

    // TLB operand encoding (mirrors tlb.rs)
    const PAGE_SHIFT: u64 = 12;

    #[test]
    fn test_tlbi_operand_encoding() {
        assert_eq!(0x1000u64 >> PAGE_SHIFT, 1);
        assert_eq!(0x2000u64 >> PAGE_SHIFT, 2);
        assert_eq!(0x4000_0000u64 >> PAGE_SHIFT, 0x40000);
    }

    #[test]
    fn test_tlbi_range_addresses() {
        let start = 0x4000_0000u64;
        let page_size = 1u64 << PAGE_SHIFT;
        assert_eq!(start + 0 * page_size, 0x4000_0000);
        assert_eq!(start + 1 * page_size, 0x4000_1000);
        assert_eq!(start + 15 * page_size, 0x4000_F000);
    }

    #[test]
    fn test_tlbi_bulk_threshold() {
        // >16 pages triggers full invalidation instead of per-page
        let per_page_limit = 16;
        assert!(17 > per_page_limit);
        assert!(16 <= per_page_limit);
    }

    // PerCpu struct layout validation (mirrors percpu.rs layout table)
    #[test]
    fn test_percpu_documented_offsets() {
        // The documented layout in percpu.rs:
        // offset 0: self_ptr (8 bytes, *const PerCpu)
        // offset 8: cpu_id (4 bytes, u32)
        // offset 12: padding (4 bytes)
        // offset 16: mpidr_aff (8 bytes, u64)
        // offset 24: current_task_id (4 bytes, u32)
        // offset 28: interrupt_depth (4 bytes, u32)
        // total: 32 bytes
        //
        // Verify that the layout assumptions match u64 alignment rules.
        assert_eq!(core::mem::size_of::<u64>(), 8);
        assert_eq!(core::mem::size_of::<u32>(), 4);
        assert_eq!(core::mem::size_of::<*const u8>(), 8); // 64-bit pointer
        // Total with alignment padding: 8 + 4 + (4 pad) + 8 + 4 + 4 = 32
        assert_eq!(8 + 4 + 4 + 8 + 4 + 4, 32);
    }
}
