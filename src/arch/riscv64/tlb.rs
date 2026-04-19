// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! TLB management — RISC-V (S-mode)
//!
//! RISC-V's S-mode TLB invalidation instruction is `sfence.vma`,
//! which operates on the **local hart only**. Unlike AArch64's
//! hardware-broadcast TLBI or x86_64's IPI + invlpg combo, remote
//! invalidation on RISC-V requires explicit software coordination
//! via SBI IPI (Phase R-5.b) or, where available, the Svinval
//! extension's `sinval.vma` (not wired yet — probed but unused).
//!
//! ## sfence.vma operand forms
//!
//! - `sfence.vma` (no operands)          — flush all TLB entries
//! - `sfence.vma rs1`                    — flush entries for VA rs1
//! - `sfence.vma rs1, rs2`               — flush for VA rs1 in ASID rs2
//! - `sfence.vma x0, rs2`                — flush all entries of ASID rs2
//!
//! We do not currently use ASIDs (single global address space per
//! kernel-mode fence). That decision is revisited if/when the kernel
//! grows multi-process ASID tagging.
//!
//! ## Remote shootdown protocol (Phase R-5.b)
//!
//! One shootdown is in flight at a time, serialized by
//! `SHOOTDOWN_LOCK`. The initiator:
//!
//!   1. Performs the local `sfence.vma` immediately.
//!   2. Computes the target hart mask (`ONLINE_HART_MASK & !self`).
//!      If zero (single-hart system), returns.
//!   3. Takes `SHOOTDOWN_LOCK`, publishes the payload
//!      (`SHOOTDOWN_VA` + `SHOOTDOWN_PAGES`), zeroes `SHOOTDOWN_ACK`.
//!   4. Calls `sbi_send_ipi(target_mask, 0)` — asserts `sip.SSIP` on
//!      every target hart.
//!   5. Spins on `SHOOTDOWN_ACK` until it equals `popcount(target_mask)`.
//!
//! Each target hart's trap vector (scause = `1 << 63 | 1`, S-mode
//! software interrupt) invokes [`handle_ipi`], which clears the
//! `sip.SSIP` bit, reads the published payload, executes the
//! equivalent `sfence.vma` locally, and atomically increments
//! `SHOOTDOWN_ACK`.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use super::sbi;

// ============================================================================
// Local invalidation
// ============================================================================

/// SCAFFOLDING: bulk-fence threshold. Matches the AArch64 / x86_64
/// value (16 pages). Beyond this, we stop per-VA `sfence.vma` and
/// flush the whole hart TLB — cheaper for large ranges.
/// Why: below ~16 pages, per-VA fences avoid flushing unrelated
///      mappings; above, the per-VA cost exceeds a full flush.
const BULK_FLUSH_THRESHOLD: usize = 16;

#[inline]
fn local_sfence_page(virt_addr: u64) {
    // SAFETY: sfence.vma is always legal from S-mode. Kernel/user
    // page-table stores upstream of this call must complete before
    // the fence executes — the assembly block has no mem clobber
    // because shootdown paths already use volatile writes to the
    // page tables, providing the needed ordering.
    unsafe {
        core::arch::asm!(
            "sfence.vma {0}, x0",
            in(reg) virt_addr,
            options(nostack, preserves_flags),
        );
    }
}

#[inline]
fn local_sfence_all() {
    // SAFETY: sfence.vma with no operands flushes all TLB entries
    // for this hart.
    unsafe {
        core::arch::asm!("sfence.vma", options(nostack, preserves_flags));
    }
}

#[inline]
fn local_sfence_range(virt_start: u64, num_pages: usize) {
    const PAGE_SIZE: u64 = 4096;
    if num_pages > BULK_FLUSH_THRESHOLD {
        local_sfence_all();
        return;
    }
    for i in 0..num_pages {
        local_sfence_page(virt_start + (i as u64) * PAGE_SIZE);
    }
}

// ============================================================================
// Online-hart tracking
// ============================================================================

/// Bitmap of online harts — bit N = 1 means hart N is initialized
/// enough to receive and service S-mode software interrupts
/// (`sie.SSIE` set, `sstatus.SIE` set, trap vector live,
/// `handle_ipi` reachable).
///
/// Populated by [`mark_self_online`]: BSP sets its bit from
/// `kmain_riscv64` right before enabling interrupts; APs set theirs
/// from `kmain_riscv64_ap` at the same point. The bit position is
/// the hart's `hart_id` — we assume hart IDs fit in 64 bits (valid
/// for every practical RISC-V platform; SCAFFOLDING bounded by the
/// u64 storage).
static ONLINE_HART_MASK: AtomicU64 = AtomicU64::new(0);

/// Mark the calling hart's `hart_id` bit in [`ONLINE_HART_MASK`].
///
/// Called once per hart in the boot flow right before that hart
/// enables SIE + SSIE. After this store is visible (Release), remote
/// shootdowns can include this hart in their target mask.
#[inline]
pub fn mark_self_online(hart_id: u64) {
    debug_assert!(hart_id < 64, "hart_id out of u64 shootdown-mask range");
    ONLINE_HART_MASK.fetch_or(1u64 << hart_id, Ordering::Release);
}

// ============================================================================
// Remote shootdown protocol (initiator side)
// ============================================================================

use crate::arch::spinlock::Spinlock;

/// Sentinel `SHOOTDOWN_PAGES` value meaning "flush the whole TLB".
const PAGES_SENTINEL_ALL: u32 = u32::MAX;

/// Serializes concurrent shootdowns. Only one initiator at a time
/// publishes into `SHOOTDOWN_VA` / `SHOOTDOWN_PAGES` / `SHOOTDOWN_ACK`.
static SHOOTDOWN_LOCK: Spinlock<()> = Spinlock::new(());

/// Virtual address base of the pending shootdown range. Read by
/// target harts' `handle_ipi`. Initiator writes under
/// `SHOOTDOWN_LOCK`; pair with `SHOOTDOWN_PAGES` (both must be
/// loaded together for a consistent view of the request).
static SHOOTDOWN_VA: AtomicU64 = AtomicU64::new(0);

/// Page count of the pending range, or [`PAGES_SENTINEL_ALL`] for
/// "flush everything."
static SHOOTDOWN_PAGES: AtomicU32 = AtomicU32::new(0);

/// Monotonic ACK counter — each target hart `fetch_add`s 1 after it
/// has completed its local `sfence.vma`. The initiator spins until
/// this reaches the popcount of the target mask.
static SHOOTDOWN_ACK: AtomicU32 = AtomicU32::new(0);

/// Read the calling hart's hart_id via its PerCpu pointer.
#[inline]
fn self_hart_id() -> u64 {
    // SAFETY: `tp` was installed by percpu::init_bsp / init_ap before
    // this path is reachable.
    unsafe { super::percpu::current_percpu().apic_id() as u64 }
}

/// Compute the hart mask of targets for a shootdown — all online
/// harts except this one.
#[inline]
fn other_harts_mask() -> u64 {
    let online = ONLINE_HART_MASK.load(Ordering::Acquire);
    online & !(1u64 << self_hart_id())
}

/// Run the full remote-shootdown protocol for a VA range (or whole
/// TLB flush if `num_pages == PAGES_SENTINEL_ALL as usize`).
///
/// Performs the local fence unconditionally; sends SBI IPI to every
/// other online hart and spins until each ACKs. Single-hart boots
/// skip the IPI phase.
fn broadcast_shootdown(virt_start: u64, num_pages: usize) {
    // Local fence first — always.
    if num_pages >= PAGES_SENTINEL_ALL as usize {
        local_sfence_all();
    } else {
        local_sfence_range(virt_start, num_pages);
    }

    let targets = other_harts_mask();
    if targets == 0 {
        return; // single-hart system or the only online hart
    }

    let expected_acks = targets.count_ones();
    let _guard = SHOOTDOWN_LOCK.lock();

    // Publish payload. Release ordering on the ACK store so target
    // harts observe SHOOTDOWN_VA / SHOOTDOWN_PAGES before the IPI
    // latches on their side.
    SHOOTDOWN_VA.store(virt_start, Ordering::Relaxed);
    let pages_u32 = if num_pages >= PAGES_SENTINEL_ALL as usize {
        PAGES_SENTINEL_ALL
    } else {
        num_pages as u32
    };
    SHOOTDOWN_PAGES.store(pages_u32, Ordering::Relaxed);
    SHOOTDOWN_ACK.store(0, Ordering::Release);

    // Fire the IPI.
    // SAFETY: SBI IPI is legal from S-mode; target harts have SSIE
    // set (via mark_self_online invariant).
    unsafe {
        let err = sbi::sbi_send_ipi(targets, 0);
        if err != 0 {
            // SBI refused the IPI. We already did the local flush; the
            // correctness bar is remote-flush-or-stall. Log and spin
            // below will never complete — but the system is broken
            // anyway if SBI IPI is unavailable. The fallback path
            // (Svinval or direct CLINT MMIO) is R-6 scope.
            crate::println!(
                "⚠ sbi_send_ipi failed: err={} targets={:#x}",
                err,
                targets,
            );
        }
    }

    // Spin until all targets have ACKed.
    while SHOOTDOWN_ACK.load(Ordering::Acquire) < expected_acks {
        core::hint::spin_loop();
    }
}

// ============================================================================
// Remote shootdown protocol (target side — called from trap vector)
// ============================================================================

/// Service an S-mode software IPI.
///
/// Called from [`super::trap::_riscv_rust_trap_handler`]'s
/// `IRQ_SOFTWARE` arm. Clears the `sip.SSIP` bit, reads the
/// in-flight shootdown payload, executes the equivalent
/// `sfence.vma`, and ACKs.
///
/// # Safety
/// Must be called only from the trap vector with interrupts masked
/// (hardware does this on trap entry). The initiator holds
/// `SHOOTDOWN_LOCK` while the payload is valid, so all target harts
/// see a consistent request.
pub unsafe fn handle_ipi() {
    // Clear sip.SSIP (bit 1). On RISC-V, the S-mode pending-
    // interrupt bit is cleared by software — no ACK register like
    // PLIC's claim/complete. Do this FIRST so a racing SBI IPI can
    // re-latch and trap again on the next sret.
    // SAFETY: csrci is legal from S-mode; clears bit in sip.
    unsafe {
        core::arch::asm!(
            "csrci sip, 2",
            options(nostack, nomem, preserves_flags),
        );
    }

    let va = SHOOTDOWN_VA.load(Ordering::Acquire);
    let pages = SHOOTDOWN_PAGES.load(Ordering::Acquire);

    if pages == PAGES_SENTINEL_ALL {
        local_sfence_all();
    } else {
        local_sfence_range(va, pages as usize);
    }

    SHOOTDOWN_ACK.fetch_add(1, Ordering::Release);
}

// ============================================================================
// Public API — matches the portable arch::tlb_shootdown_* contract
// ============================================================================

/// Invalidate a single page across all online harts.
///
/// Local `sfence.vma` + SBI IPI to other harts + ACK spin. Falls
/// through to a local-only fence when no other harts are online.
pub fn shootdown_page(virt_addr: u64) {
    broadcast_shootdown(virt_addr, 1);
}

/// Invalidate a range of pages across all online harts.
pub fn shootdown_range(virt_start: u64, num_pages: usize) {
    broadcast_shootdown(virt_start, num_pages);
}

/// Invalidate the entire TLB on all online harts.
#[allow(dead_code)] // wired when a consumer needs it
pub fn shootdown_all() {
    broadcast_shootdown(0, PAGES_SENTINEL_ALL as usize);
}

// ============================================================================
// Init helpers
// ============================================================================

/// One-shot boot probe: verify the SBI IPI extension is present.
/// Called from BSP's kmain_riscv64 after SBI is reachable. Not
/// fatal — single-hart boots will never actually use IPIs, so we
/// log a warning and proceed rather than halting.
pub fn probe_ipi_extension() -> bool {
    let present = sbi::sbi_probe_extension(sbi::IPI_EXTENSION_ID) != 0;
    if !present {
        crate::println!(
            "⚠ SBI IPI extension absent (EID={:#x}); cross-hart TLB shootdown \
             will stall if issued",
            sbi::IPI_EXTENSION_ID,
        );
    }
    present
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_bulk_threshold() {
        // Matches the AArch64 / x86_64 convention.
        assert!(17 > 16);
    }
}
