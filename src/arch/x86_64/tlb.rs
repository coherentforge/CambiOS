// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! TLB shootdown via Inter-Processor Interrupts
//!
//! When one CPU modifies shared page tables (unmap, permission change), other
//! CPUs may hold stale TLB entries. The TLB shootdown protocol ensures
//! coherence:
//!
//! 1. Initiating CPU fills the global `SHOOTDOWN` request with the address
//!    range to invalidate, sets `pending` to the number of remote CPUs.
//! 2. Initiating CPU sends a broadcast IPI (vector 0xFE) to all other CPUs.
//! 3. Each target CPU's ISR reads the request, executes `invlpg` for each
//!    page (or reloads CR3 for large ranges), decrements `pending`, sends EOI.
//! 4. Initiating CPU spins until `pending` reaches 0.
//!
//! A spinlock serializes concurrent shootdown requests (only one CPU can
//! initiate at a time). The ISR never acquires the lock — it only reads
//! the request state and decrements the atomic counter.
//!
//! ## Vector assignment
//! - 0xFE: TLB shootdown IPI (just below spurious at 0xFF)

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

/// IPI vector for TLB shootdown requests
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xFE;

/// If more pages than this need invalidation, do a full CR3 reload instead
/// of individual `invlpg` calls. `invlpg` is cheaper per-page, but a full
/// flush is cheaper when the count is large.
const MAX_INDIVIDUAL_PAGES: u32 = 32;

// ============================================================================
// Shootdown request state
// ============================================================================

/// Global TLB shootdown request.
///
/// Only the initiating CPU writes these fields (while holding `LOCK`).
/// The ISR on target CPUs only reads `start_addr` and `page_count`,
/// and atomically decrements `pending`.
struct ShootdownRequest {
    /// Virtual address of the first page to invalidate (page-aligned).
    /// 0 with page_count=0 means "full flush" (reload CR3).
    start_addr: AtomicU64,
    /// Number of 4 KiB pages to invalidate. 0 = full flush.
    page_count: AtomicU32,
    /// Number of CPUs that have not yet processed this request.
    /// Initiating CPU spins until this reaches 0.
    pending: AtomicU32,
}

static SHOOTDOWN: ShootdownRequest = ShootdownRequest {
    start_addr: AtomicU64::new(0),
    page_count: AtomicU32::new(0),
    pending: AtomicU32::new(0),
};

/// Serializes shootdown initiation. Only one CPU can run a shootdown at a time.
/// The ISR never touches this — it only reads request fields and decrements pending.
static LOCK: AtomicBool = AtomicBool::new(false);

/// Acquire the shootdown lock (spin until we get it).
#[inline]
fn lock_acquire() {
    while LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        // Spin with hint while contended
        while LOCK.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
    }
}

/// Release the shootdown lock.
#[inline]
fn lock_release() {
    LOCK.store(false, Ordering::Release);
}

// ============================================================================
// Local TLB flush primitives
// ============================================================================

/// Invalidate a single TLB entry for the given virtual address on this CPU.
///
/// # Safety
/// Must be called at ring 0.
#[inline]
pub unsafe fn invlpg(virt_addr: u64) {
    // SAFETY: `invlpg` invalidates the TLB entry for the page containing
    // the given virtual address. Ring 0 only.
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virt_addr,
            options(nostack, preserves_flags),
        );
    }
}

/// Flush the entire TLB by reloading CR3.
///
/// # Safety
/// Must be called at ring 0.
#[inline]
pub unsafe fn flush_all_local() {
    let cr3: u64;
    // SAFETY: Reading CR3 is safe at ring 0.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem));
    }
    // SAFETY: Writing the same CR3 value back flushes all non-global TLB entries.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

// ============================================================================
// ISR handler (called on target CPUs)
// ============================================================================

/// TLB shootdown ISR — called on each target CPU when the initiating CPU
/// sends the broadcast IPI.
///
/// Reads the global shootdown request, invalidates the requested pages
/// (or flushes all), decrements the pending counter, and sends EOI.
///
/// This is registered in the IDT at vector TLB_SHOOTDOWN_VECTOR (0xFE).
pub extern "x86-interrupt" fn tlb_shootdown_isr(
    _stack_frame: x86_64::structures::idt::InterruptStackFrame,
) {
    let page_count = SHOOTDOWN.page_count.load(Ordering::Acquire);

    if page_count == 0 {
        // Full flush requested
        // SAFETY: Ring 0 ISR context.
        unsafe { flush_all_local() };
    } else if page_count <= MAX_INDIVIDUAL_PAGES {
        // Invalidate individual pages
        let start = SHOOTDOWN.start_addr.load(Ordering::Acquire);
        for i in 0..page_count as u64 {
            // SAFETY: Ring 0 ISR context.
            unsafe { invlpg(start + i * 4096) };
        }
    } else {
        // Too many pages — full flush is cheaper
        // SAFETY: Ring 0 ISR context.
        unsafe { flush_all_local() };
    }

    // Signal completion
    SHOOTDOWN.pending.fetch_sub(1, Ordering::AcqRel);

    // SAFETY: We are in an APIC-delivered interrupt handler.
    unsafe { super::apic::write_eoi() };
}

// ============================================================================
// Shootdown API (called by initiating CPU)
// ============================================================================

/// Invalidate a single page across all CPUs.
///
/// Flushes the local TLB entry, then sends an IPI to all other CPUs and
/// waits for them to flush. On a single-CPU system this is just a local
/// `invlpg`.
///
/// # Safety
/// Must be called at ring 0. The page table modification that necessitated
/// this shootdown must already be visible (written to memory) before calling.
pub unsafe fn shootdown_page(virt_addr: u64) {
    // SAFETY: Caller ensures ring 0 and page table changes are visible.
    unsafe { shootdown_range(virt_addr, 1) };
}

/// Invalidate a range of pages across all CPUs.
///
/// # Arguments
/// - `virt_addr`: Virtual address of the first page (page-aligned)
/// - `page_count`: Number of 4 KiB pages to invalidate
///
/// # Safety
/// Must be called at ring 0. Page table changes must be visible in memory.
pub unsafe fn shootdown_range(virt_addr: u64, page_count: u32) {
    // Always flush locally first
    if page_count <= MAX_INDIVIDUAL_PAGES {
        for i in 0..page_count as u64 {
            // SAFETY: Caller ensures ring 0.
            unsafe { invlpg(virt_addr + i * 4096) };
        }
    } else {
        // SAFETY: Caller ensures ring 0.
        unsafe { flush_all_local() };
    }

    // If only one CPU is online, we're done
    let online = super::percpu::cpu_count();
    if online <= 1 {
        return;
    }

    // Serialize shootdown requests
    lock_acquire();

    // Fill the request
    SHOOTDOWN.start_addr.store(virt_addr, Ordering::Release);
    SHOOTDOWN.page_count.store(page_count, Ordering::Release);
    // pending = number of *other* CPUs (all online minus self)
    let remote_cpus = online - 1;
    SHOOTDOWN.pending.store(remote_cpus, Ordering::Release);

    // Send IPI to all other CPUs
    // SAFETY: APIC is initialized and TLB_SHOOTDOWN_VECTOR is registered in all IDTs.
    unsafe { super::apic::send_ipi_all_excluding_self(TLB_SHOOTDOWN_VECTOR) };

    // Spin until all remote CPUs have processed the request
    while SHOOTDOWN.pending.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }

    lock_release();
}

/// Flush the entire TLB on all CPUs.
///
/// # Safety
/// Must be called at ring 0.
pub unsafe fn shootdown_all() {
    // SAFETY: Caller ensures ring 0.
    unsafe { flush_all_local() };

    let online = super::percpu::cpu_count();
    if online <= 1 {
        return;
    }

    lock_acquire();

    // page_count = 0 signals "full flush" to the ISR
    SHOOTDOWN.start_addr.store(0, Ordering::Release);
    SHOOTDOWN.page_count.store(0, Ordering::Release);
    let remote_cpus = online - 1;
    SHOOTDOWN.pending.store(remote_cpus, Ordering::Release);

    // SAFETY: APIC is initialized and TLB_SHOOTDOWN_VECTOR is registered in all IDTs.
    unsafe { super::apic::send_ipi_all_excluding_self(TLB_SHOOTDOWN_VECTOR) };

    while SHOOTDOWN.pending.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }

    lock_release();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shootdown_vector() {
        // TLB shootdown vector is just below spurious (0xFF)
        assert_eq!(TLB_SHOOTDOWN_VECTOR, 0xFE);
    }

    #[test]
    fn test_max_individual_pages() {
        // Threshold for switching from invlpg to full CR3 reload
        assert!(MAX_INDIVIDUAL_PAGES > 0);
        assert!(MAX_INDIVIDUAL_PAGES <= 64); // sanity: not unreasonably large
    }

    #[test]
    fn test_shootdown_request_initial_state() {
        // Verify initial state is zeroed (no pending request)
        assert_eq!(SHOOTDOWN.start_addr.load(Ordering::Relaxed), 0);
        assert_eq!(SHOOTDOWN.page_count.load(Ordering::Relaxed), 0);
        assert_eq!(SHOOTDOWN.pending.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_lock_acquire_release() {
        // Verify lock can be acquired and released (also covers initial state:
        // lock_acquire spins until LOCK is false, so it implicitly asserts
        // the lock is available before acquiring).
        lock_acquire();
        assert!(LOCK.load(Ordering::Relaxed));
        lock_release();
        assert!(!LOCK.load(Ordering::Relaxed));
    }
}
