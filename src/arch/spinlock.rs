// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Spinlock implementations for synchronizing kernel state
//!
//! Two variants:
//! - `Spinlock<T>`: basic spinlock, suitable for locks never acquired from ISR context
//! - `IrqSpinlock<T>`: saves/disables interrupts before acquiring, prevents same-CPU
//!   deadlock when a timer ISR fires while the lock is held
//!
//! On SMP, `IrqSpinlock` is required for any lock that might be contended from
//! both thread context and ISR context (e.g., SCHEDULER, TIMER).

use core::sync::atomic::{AtomicBool, Ordering};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

/// A simple spinlock for mutual exclusion
pub struct Spinlock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

impl<T> Spinlock<T> {
    /// Create a new spinlock protecting the given data
    pub const fn new(data: T) -> Self {
        Spinlock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }
    
    /// Acquire the lock (spins until available)
    pub fn lock(&self) -> SpinlockGuard<'_, T> {
        // Spin until we can acquire the lock
        loop {
            match self.locked.compare_exchange(
                false,
                true,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return SpinlockGuard { lock: self },
                Err(_) => {
                    // Lock is held, spin
                    core::hint::spin_loop();
                }
            }
        }
    }
    
    /// Try to acquire the lock without spinning
    pub fn try_lock(&self) -> Option<SpinlockGuard<'_, T>> {
        match self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => Some(SpinlockGuard { lock: self }),
            Err(_) => None,
        }
    }
}

// SAFETY: Spinlock<T> can be sent between threads if T: Send, because
// the spinlock ensures only one thread accesses the inner T at a time.
unsafe impl<T: Send> Send for Spinlock<T> {}
// SAFETY: Spinlock<T> can be shared between threads (&Spinlock<T> is Send)
// because all access goes through lock() which enforces mutual exclusion
// via an atomic compare-exchange.
unsafe impl<T: Send> Sync for Spinlock<T> {}

/// RAII guard for a spinlock
pub struct SpinlockGuard<'a, T> {
    lock: &'a Spinlock<T>,
}

impl<'a, T> Deref for SpinlockGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        // SAFETY: The SpinlockGuard exists only while the lock is held (Acquire
        // ordering), so we have exclusive access to the UnsafeCell contents.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinlockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The SpinlockGuard exists only while the lock is held (Acquire
        // ordering) and &mut self guarantees we are the sole accessor.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinlockGuard<'a, T> {
    fn drop(&mut self) {
        // Release the lock
        self.lock.locked.store(false, Ordering::Release);
    }
}

// ============================================================================
// Interrupt-save/restore helpers (arch-specific)
// ============================================================================

/// Save current interrupt state and disable interrupts.
/// Returns an opaque token to restore the previous state.
#[inline(always)]
fn save_and_disable_interrupts() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let rflags: u64;
        // SAFETY: Reading RFLAGS and disabling interrupts is safe at ring 0.
        // pushfq/popfq is balanced (net stack effect zero). cli prevents
        // interrupts until sti or popfq restores IF.
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {}",
                "cli",
                out(reg) rflags,
                options(nomem, preserves_flags),
            );
        }
        rflags as usize
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // Test/non-x86 target: no-op (no cli/sti in userspace)
        0
    }
}

/// Restore interrupt state from a previously saved token.
#[inline(always)]
fn restore_interrupts(saved: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        // Only re-enable interrupts if they were enabled before (IF bit = bit 9)
        if saved & (1 << 9) != 0 {
            // SAFETY: Re-enabling interrupts is safe. We only do this if IF was
            // set before save_and_disable_interrupts() was called.
            unsafe {
                core::arch::asm!("sti", options(nomem, nostack));
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = saved;
    }
}

// ============================================================================
// IrqSpinlock — interrupt-disabling spinlock
// ============================================================================

/// A spinlock that disables interrupts while held.
///
/// Prevents same-CPU deadlock: if a timer ISR fires while this lock is held,
/// the ISR cannot attempt to acquire the same lock because interrupts are
/// disabled. On drop, the guard restores the previous interrupt state.
///
/// Use this for locks accessed from both thread context and ISR context
/// (SCHEDULER, TIMER). Use plain `Spinlock` for locks that are never
/// acquired from ISR context (IPC_MANAGER, CAPABILITY_MANAGER, etc.).
pub struct IrqSpinlock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

impl<T> IrqSpinlock<T> {
    /// Create a new interrupt-disabling spinlock.
    pub const fn new(data: T) -> Self {
        IrqSpinlock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock: save and disable interrupts, then spin until available.
    pub fn lock(&self) -> IrqSpinlockGuard<'_, T> {
        let saved = save_and_disable_interrupts();
        loop {
            match self.locked.compare_exchange(
                false,
                true,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return IrqSpinlockGuard { lock: self, saved_irq_state: saved },
                Err(_) => core::hint::spin_loop(),
            }
        }
    }

    /// Try to acquire without spinning. Disables interrupts only on success.
    pub fn try_lock(&self) -> Option<IrqSpinlockGuard<'_, T>> {
        let saved = save_and_disable_interrupts();
        match self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => Some(IrqSpinlockGuard { lock: self, saved_irq_state: saved }),
            Err(_) => {
                // Failed — restore interrupts before returning
                restore_interrupts(saved);
                None
            }
        }
    }
}

/// SAFETY: Mutual exclusion via atomic CAS with interrupt disable.
/// IrqSpinlock additionally saves/restores interrupt state, preventing
/// same-CPU deadlock when a timer ISR fires while the lock is held.
unsafe impl<T: Send> Send for IrqSpinlock<T> {}
/// SAFETY: Same as Send — atomic CAS + interrupt disable guarantees exclusive access.
unsafe impl<T: Send> Sync for IrqSpinlock<T> {}

/// RAII guard for IrqSpinlock. Restores interrupt state on drop.
pub struct IrqSpinlockGuard<'a, T> {
    lock: &'a IrqSpinlock<T>,
    saved_irq_state: usize,
}

impl<'a, T> Deref for IrqSpinlockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Lock is held (Acquire ordering), exclusive access guaranteed.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for IrqSpinlockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: Lock is held, &mut self guarantees sole accessor.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for IrqSpinlockGuard<'a, T> {
    fn drop(&mut self) {
        // Release lock, then restore interrupts
        self.lock.locked.store(false, Ordering::Release);
        restore_interrupts(self.saved_irq_state);
    }
}
