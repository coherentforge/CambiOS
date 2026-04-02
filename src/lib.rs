#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(dead_code)]
#![feature(abi_x86_interrupt)]
//! ArcOS Microkernel - Verification-Ready Core
//!
//! A minimal microkernel for x86-64 supporting:
//! - Process/task management
//! - Message-passing IPC
//! - Capability-based security
//! - Userspace drivers and services

extern crate alloc;

use x86_64::instructions::hlt;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

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

// Kernel heap allocator — initialized from Limine memory map in kmain
#[cfg(not(test))]
#[global_allocator]
pub static KERNEL_HEAP: memory::heap::LockedHeapAllocator = memory::heap::LockedHeapAllocator::new();

// Re-export power management from platform
pub use platform::{PowerManager, PowerState, PerformanceState};
pub use arch::spinlock::Spinlock;

use alloc::boxed::Box;

use scheduler::{Scheduler, Timer};
use ipc::IpcManager;
use ipc::capability::CapabilityManager;
use interrupts::InterruptRoutingTable;
use process::ProcessTable;

/// Global state protected by spinlocks (multicore-safe)
///
/// CRITICAL: Global lock ordering to prevent deadlocks
/// ====================================================
/// Acquire locks in this order ONLY. Never acquire in reverse or nested order:
/// 1. SCHEDULER (highest priority - preemption, task state)
/// 2. TIMER (tick counting)
/// 3. IPC_MANAGER (message queues)
/// 4. CAPABILITY_MANAGER (access control)
/// 5. PROCESS_TABLE (process metadata)
/// 6. INTERRUPT_ROUTER (lowest priority - interrupt routing)
///
/// Large structs (IpcManager ~1.3MB, CapabilityManager ~100KB, ProcessTable ~132KB)
/// are heap-allocated via Box after the kernel heap is initialized from the Limine
/// memory map. Small structs remain stack-moved or BSS-initialized.
pub static SCHEDULER: Spinlock<Option<Box<Scheduler>>> = Spinlock::new(None);
pub static TIMER: Spinlock<Option<Timer>> = Spinlock::new(None);
pub static IPC_MANAGER: Spinlock<Option<Box<IpcManager>>> = Spinlock::new(None);
pub static CAPABILITY_MANAGER: Spinlock<Option<Box<CapabilityManager>>> = Spinlock::new(None);
pub static PROCESS_TABLE: Spinlock<Option<Box<ProcessTable>>> = Spinlock::new(None);
pub static INTERRUPT_ROUTER: Spinlock<InterruptRoutingTable> = Spinlock::new(InterruptRoutingTable::new());

/// Higher-half direct map offset from Limine (set once during boot).
/// Physical address + HHDM_OFFSET = kernel-accessible virtual address.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Store the HHDM offset (called once from kmain after Limine response)
pub fn set_hhdm_offset(offset: u64) {
    HHDM_OFFSET.store(offset, Ordering::Release);
}

/// Get the HHDM offset for physical-to-virtual address translation
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Acquire)
}

/// Core subsystem initialization
pub unsafe fn init() {
    io::init();
    memory::init();
    interrupts::init();
}

/// Halt the system
pub fn halt() -> ! {
    loop {
        hlt();
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
