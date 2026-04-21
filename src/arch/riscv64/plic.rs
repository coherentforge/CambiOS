// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! PLIC — Platform-Level Interrupt Controller (RISC-V S-mode driver)
//!
//! Per [ADR-013](../../../docs/adr/013-riscv64-architecture-support.md)
//! Decision 5, the PLIC is the sole platform-wide router for *device*
//! interrupts on RISC-V. Timers ride CLINT-via-SBI (ADR-013 Decision
//! 4); IPIs will ride SBI too (R-5). The PLIC lives entirely in MMIO
//! and is discovered at boot from the DTB's `/soc/plic@*` node.
//!
//! ## Register layout (standard SiFive-derived PLIC)
//!
//! All offsets are from the MMIO base that the DTB reports:
//!
//! ```text
//!   base + 0x000000..0x001000   priority[source_id]   u32 each, source 0 = unused
//!   base + 0x001000..0x001080   pending bitmap        u32 per 32 sources
//!   base + 0x002000..0x200000   enable bitmap per context (stride 0x80)
//!   base + 0x200000..           per-context control (stride 0x1000):
//!       +0x00  threshold
//!       +0x04  claim/complete
//! ```
//!
//! ## Context mapping on QEMU virt (and the SiFive ecosystem)
//!
//! A "context" is `(hart, privilege_level)`. On QEMU virt the layout
//! is `hart N M-mode = context 2N`, `hart N S-mode = context 2N + 1`.
//! For single-hart boot on hart 0, S-mode context = 1. Phase R-5 will
//! generalize to all harts and revisit context mapping for platforms
//! that skip M-mode contexts (some embedded cores).
//!
//! ## Phase R-3.d scope
//!
//! This module owns:
//! - [`init`] — map the MMIO, clear all priorities, threshold = 0,
//!   set `sie.SEIE`.
//! - [`enable_irq`] / [`disable_irq`] — toggle a source on this hart's
//!   S-mode context, set priority = 1 (enabled).
//! - [`claim`] / [`complete`] — the hardware handshake.
//! - [`dispatch_pending`] — one-shot entry point from the trap vector:
//!   claim → `crate::INTERRUPT_ROUTER` lookup (`try_lock` — lock
//!   position 8) → inline UART-RX fallback for R-3.d → complete.
//!
//! The [`INTERRUPT_ROUTER`] integration is forward-compatible: once a
//! user-space driver registers a TaskId for an IRQ (R-3.f / R-4+),
//! the dispatch path sends it the [`InterruptContext`] via the
//! existing IPC machinery, matching x86_64/AArch64. Until then the
//! inline UART path provides the R-3.d milestone signal.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Register offsets
// ============================================================================

/// Priority register stride (per source).
const REG_PRIORITY_STRIDE: u64 = 4;

/// Enable-bitmap base (per-context enables).
const REG_ENABLE_BASE: u64 = 0x2000;
/// Per-context enable-bitmap stride.
const REG_ENABLE_STRIDE: u64 = 0x80;

/// Per-context control base (threshold + claim/complete).
const REG_CONTEXT_BASE: u64 = 0x20_0000;
/// Per-context control stride.
const REG_CONTEXT_STRIDE: u64 = 0x1000;
/// Context control: threshold offset.
const REG_CONTEXT_THRESHOLD: u64 = 0x00;
/// Context control: claim/complete offset (one register, read = claim,
/// write = complete).
const REG_CONTEXT_CLAIM: u64 = 0x04;

/// SCAFFOLDING: max PLIC source ID we set priority / clear enables for
/// during init. Real hardware can have up to 1023 sources but QEMU
/// virt uses ~16, and the `interrupts` extension registry bounds what
/// the interrupt-routing table can track at `u8` (224) anyway.
/// Why: bounded iteration at init; 128 covers QEMU virt, every
///   realistic SiFive-ecosystem board, and the router's `u8` IrqNumber
///   with headroom. Memory cost: none (iteration count only).
/// Replace when: a real platform uses source IDs > 128.
/// See docs/ASSUMPTIONS.md.
const MAX_SOURCES: u32 = 128;

/// SCAFFOLDING: hart 0 S-mode context on QEMU virt (and standard
/// SiFive PLIC context ordering: context 2N = hart N M-mode, 2N+1 =
/// hart N S-mode). R-5 generalizes once we bring up APs.
/// Why: single-hart boot targets hart 0; S-mode = context 1.
/// Replace when: R-5 wakes APs — context must be computed per hart
///   or read from the DTB `interrupts-extended` property on the PLIC
///   node (which lists `<phandle> <irq>` pairs per context).
const HART0_S_CONTEXT: u32 = 1;

// ============================================================================
// Module state (published once by `init`)
// ============================================================================

/// PLIC MMIO base as a kernel virtual address (after `early_map_mmio`
/// walks the region into the HHDM). Zero until [`init`] publishes.
static PLIC_MMIO_VBASE: AtomicU64 = AtomicU64::new(0);

/// PLIC MMIO size in bytes (as reported by the DTB `reg` property).
/// Zero until [`init`] publishes.
static PLIC_MMIO_SIZE: AtomicU64 = AtomicU64::new(0);

/// Hart S-mode context used by this kernel. Zero if PLIC is not live.
/// R-5 revisits when multiple harts start taking IRQs.
static S_CONTEXT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// MMIO helpers — 32-bit word-aligned accesses
// ============================================================================

#[inline]
fn base() -> u64 {
    PLIC_MMIO_VBASE.load(Ordering::Acquire)
}

/// Read a 32-bit register at `base + offset`.
///
/// # Safety
/// `offset` must be within the mapped MMIO range published by `init`.
#[inline]
unsafe fn read32(offset: u64) -> u32 {
    let ptr = (base() + offset) as *const u32;
    // SAFETY: caller asserts offset is in range; PLIC MMIO is 4-byte
    // aligned and word-accessible.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Write a 32-bit register at `base + offset`.
///
/// # Safety
/// `offset` must be within the mapped MMIO range published by `init`.
#[inline]
unsafe fn write32(offset: u64, value: u32) {
    let ptr = (base() + offset) as *mut u32;
    // SAFETY: same as read32.
    unsafe { core::ptr::write_volatile(ptr, value) };
}

#[inline]
fn priority_offset(source_id: u32) -> u64 {
    (source_id as u64) * REG_PRIORITY_STRIDE
}

#[inline]
fn enable_offset(context: u32, source_id: u32) -> u64 {
    REG_ENABLE_BASE + (context as u64) * REG_ENABLE_STRIDE + ((source_id as u64) / 32) * 4
}

#[inline]
fn enable_bit(source_id: u32) -> u32 {
    1u32 << (source_id % 32)
}

#[inline]
fn threshold_offset(context: u32) -> u64 {
    REG_CONTEXT_BASE + (context as u64) * REG_CONTEXT_STRIDE + REG_CONTEXT_THRESHOLD
}

#[inline]
fn claim_offset(context: u32) -> u64 {
    REG_CONTEXT_BASE + (context as u64) * REG_CONTEXT_STRIDE + REG_CONTEXT_CLAIM
}

// ============================================================================
// Initialization
// ============================================================================

/// Map the PLIC MMIO region into kernel space (via R-3.a's
/// `early_map_mmio`), reset all per-source priorities, clear the
/// S-mode context's enable bitmap, set threshold = 0 (accept any
/// priority ≥ 1), and enable `sie.SEIE` so S-mode takes external
/// interrupts.
///
/// Individual sources are enabled per-driver via [`enable_irq`]. No
/// IRQ fires from the PLIC until at least one source has priority ≥ 1
/// *and* a set enable bit for the target context.
///
/// # Safety
/// - HHDM offset must be set; `early_map_mmio` may run.
/// - Must be called once during single-hart boot, after the trap
///   vector is installed and the kernel heap is up.
/// - `phys_base` / `size_bytes` must match a real PLIC MMIO region
///   (from the DTB).
pub unsafe fn init(phys_base: u64, size_bytes: u64) -> Result<(), &'static str> {
    // Bound-check the size so an obviously bad DTB value does not
    // trigger a huge mapping loop. A real PLIC on QEMU virt is about
    // 6 MiB; cap at 16 MiB here.
    if size_bytes == 0 || size_bytes > 16 * 1024 * 1024 {
        return Err("plic::init: implausible PLIC MMIO size");
    }

    // Map the entire region into the HHDM. `early_map_mmio` walks one
    // page at a time; the bootstrap frame pool tops up L1/L2/L3
    // intermediates on the first page and is reused for every
    // subsequent page (the region fits within one L2 slot on QEMU
    // virt — 0x0C00_0000..0x0C60_0000 is ~6 MiB, still well below
    // the 1 GiB L1-block boundary and within 3 adjacent L2 2-MiB
    // slots so at most one fresh L3 table per 2-MiB chunk).
    //
    // SAFETY: caller guarantees `phys_base`/`size_bytes` describe a
    // real MMIO region and HHDM is live.
    let pages = size_bytes.div_ceil(4096);
    for page in 0..pages {
        unsafe {
            crate::memory::paging::early_map_mmio(phys_base + page * 4096)?;
        }
    }

    // Publish the kernel-VA base now that every page is mapped.
    let vbase = phys_base + crate::hhdm_offset();
    PLIC_MMIO_VBASE.store(vbase, Ordering::Release);
    PLIC_MMIO_SIZE.store(size_bytes, Ordering::Release);
    S_CONTEXT.store(HART0_S_CONTEXT, Ordering::Release);

    // Zero every source priority so no IRQ will fire from a
    // stale-register start. Source 0 is reserved (priority always 0).
    //
    // SAFETY: MMIO is just mapped; offsets are bounded by MAX_SOURCES.
    unsafe {
        for src in 1..MAX_SOURCES {
            write32(priority_offset(src), 0);
        }

        // Clear every enable bit in this hart's S-mode context —
        // MAX_SOURCES / 32 u32 words at the context's enable base.
        for word in 0..(MAX_SOURCES / 32) {
            let off = REG_ENABLE_BASE
                + (HART0_S_CONTEXT as u64) * REG_ENABLE_STRIDE
                + (word as u64) * 4;
            write32(off, 0);
        }

        // Threshold = 0: accept any IRQ with priority ≥ 1.
        write32(threshold_offset(HART0_S_CONTEXT), 0);
    }

    // Enable supervisor external interrupts (sie.SEIE, bit 9). Now
    // the hart will trap on PLIC-asserted IRQs once any source is
    // armed via `enable_irq`.
    //
    // SAFETY: csrs is legal from S-mode.
    unsafe {
        core::arch::asm!(
            "csrs sie, {0}",
            in(reg) 1u64 << 9,
            options(nostack, nomem, preserves_flags),
        );
    }

    Ok(())
}

/// Arm a source: priority = 1 and enable bit set for this hart's
/// S-mode context. Idempotent.
///
/// # Safety
/// [`init`] must have run. `source_id` must be in 1..MAX_SOURCES.
pub unsafe fn enable_irq(source_id: u32) {
    debug_assert!(
        source_id >= 1 && source_id < MAX_SOURCES,
        "plic::enable_irq: source_id out of range",
    );
    if base() == 0 {
        return;
    }
    let ctx = S_CONTEXT.load(Ordering::Acquire);
    // SAFETY: caller promises init has run; offsets are bounded.
    unsafe {
        // Priority = 1 = enabled.
        write32(priority_offset(source_id), 1);
        // Enable bit.
        let eoff = enable_offset(ctx, source_id);
        let current = read32(eoff);
        write32(eoff, current | enable_bit(source_id));
    }
}

/// Disarm a source. Priority = 0 and enable bit cleared. Idempotent.
///
/// # Safety
/// Same as [`enable_irq`].
#[allow(dead_code)] // wired when the first driver registers a revocation flow
pub unsafe fn disable_irq(source_id: u32) {
    debug_assert!(
        source_id >= 1 && source_id < MAX_SOURCES,
        "plic::disable_irq: source_id out of range",
    );
    if base() == 0 {
        return;
    }
    let ctx = S_CONTEXT.load(Ordering::Acquire);
    // SAFETY: same.
    unsafe {
        write32(priority_offset(source_id), 0);
        let eoff = enable_offset(ctx, source_id);
        let current = read32(eoff);
        write32(eoff, current & !enable_bit(source_id));
    }
}

/// Claim the highest-priority pending IRQ on this hart's S-mode
/// context. Returns the source ID, or 0 if nothing is pending
/// (spurious external-IRQ trap).
///
/// Reading the claim register atomically marks the source in-service
/// so the PLIC stops asserting the S-mode external line until
/// [`complete`] writes the same source back.
pub fn claim() -> u32 {
    if base() == 0 {
        return 0;
    }
    let ctx = S_CONTEXT.load(Ordering::Acquire);
    // SAFETY: init has run; offset is bounded; claim is a
    // side-effect-carrying read but it's the documented PLIC protocol.
    unsafe { read32(claim_offset(ctx)) }
}

/// Signal to the PLIC that the driver has finished handling
/// `source_id`. Re-opens the source for the next assertion.
pub fn complete(source_id: u32) {
    if base() == 0 || source_id == 0 {
        return;
    }
    let ctx = S_CONTEXT.load(Ordering::Acquire);
    // SAFETY: init has run; offset is bounded.
    unsafe { write32(claim_offset(ctx), source_id) };
}

// ============================================================================
// Trap-vector entry point
// ============================================================================

/// Console IRQ — the source ID the kernel treats as "read a byte from
/// the primary UART inline." Set by kmain after reading
/// `BootInfo::console_irq` from the DTB; zero means "no inline
/// handling." Phase R-3.d diagnostic — once a real console driver
/// registers in [`INTERRUPT_ROUTER`], we delete the inline path.
static CONSOLE_IRQ: AtomicU32 = AtomicU32::new(0);

/// Record the console IRQ for inline R-3.d handling. Called once
/// during kmain wiring.
pub fn set_console_irq(irq: u32) {
    CONSOLE_IRQ.store(irq, Ordering::Release);
}

/// Handle every pending external IRQ on this hart. Called from the
/// S-mode trap handler when `scause` is the external-interrupt cause.
///
/// Loops until [`claim`] returns 0 so a single trap can drain
/// coincident IRQs — PLIC asserts one level to the hart regardless of
/// how many sources are pending, and we must complete each source
/// individually before SEIE re-latches.
///
/// # Safety
/// Must be called from S-mode ISR context (interrupts masked, trap
/// frame on the kernel stack). [`init`] must have run.
pub unsafe fn dispatch_pending() {
    loop {
        let source_id = claim();
        if source_id == 0 {
            return;
        }

        // Try to route through the portable router — `try_lock`
        // because the router's lock (position 8) sits above anything
        // we hold on the interrupt path. If contended, we skip the
        // lookup and fall through to inline handling; the router
        // state is observational for R-3.d (no driver is registered
        // yet so `lookup` would return `None` anyway).
        let routed = crate::INTERRUPT_ROUTER
            .try_lock()
            .and_then(|t| {
                t.lookup(crate::interrupts::routing::IrqNumber(source_id as u8))
            })
            .is_some();

        if routed {
            // R-4+: a registered driver task — hand off via IPC. The
            // IPC wake path is wired alongside the first real RISC-V
            // device driver, not here. Until then, just note it.
            crate::println!(
                "[R-3 IRQ {}] router has route (task dispatch pending R-4)",
                source_id,
            );
        } else if source_id == CONSOLE_IRQ.load(Ordering::Acquire) && source_id != 0 {
            // R-3.d diagnostic: read the waiting byte and log it.
            // Single-key echo, no line editing — this is proof the
            // PLIC path works end-to-end, not a console driver.
            if let Some(byte) = crate::io::read_byte() {
                crate::println!("[R-3 RX] {:#04x} ({:?})", byte, byte as char);
            } else {
                // LSR.DR was clear by the time we read — spurious or
                // a different source sharing the IRQ line.
                crate::println!("[R-3 RX] IRQ {} but no byte ready", source_id);
            }
        } else {
            crate::println!(
                "[R-3 IRQ {}] no handler (router empty, not console)",
                source_id,
            );
        }

        complete(source_id);
    }
}
