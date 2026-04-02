/// Simple spinlock implementation for synchronizing kernel state
/// 
/// Used to protect critical sections and ensure exclusive access to shared mutable state.
/// Suitable for single-core and multicore contexts (no fairness guarantees on multicore).

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

// Safe because Spinlock enforces exclusive access
unsafe impl<T: Send> Send for Spinlock<T> {}
unsafe impl<T: Send> Sync for Spinlock<T> {}

/// RAII guard for a spinlock
pub struct SpinlockGuard<'a, T> {
    lock: &'a Spinlock<T>,
}

impl<'a, T> Deref for SpinlockGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinlockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinlockGuard<'a, T> {
    fn drop(&mut self) {
        // Release the lock
        self.lock.locked.store(false, Ordering::Release);
    }
}
