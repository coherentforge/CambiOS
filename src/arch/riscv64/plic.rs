// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! PLIC — Platform-Level Interrupt Controller (RISC-V S-mode driver)
//!
//! Per [ADR-013](../../../docs/adr/013-riscv64-architecture-support.md)
//! Decision 5, the PLIC is the sole platform-wide router for *device*
//! interrupts on RISC-V. Timers ride CLINT-via-SBI (ADR-013 Decision
//! 4); IPIs ride SBI too. The PLIC lives entirely in MMIO
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
//! For single-hart boot on hart 0, S-mode context = 1. Multi-hart
//! support generalizes to all harts and revisits context mapping for
//! platforms that skip M-mode contexts (some embedded cores).
//!
//! ## Module scope
//!
//! This module owns:
//! - [`init`] — map the MMIO, clear all priorities, threshold = 0,
//!   set `sie.SEIE`.
//! - [`enable_irq`] / [`disable_irq`] — toggle a source on this hart's
//!   S-mode context, set priority = 1 (enabled).
//! - [`claim`] / [`complete`] — the hardware handshake.
//! - [`dispatch_pending`] — one-shot entry point from the trap vector:
//!   claim → `crate::INTERRUPT_ROUTER` lookup (`try_lock` — lock
//!   position 8) → inline UART-RX fallback → complete.
//!
//! The [`INTERRUPT_ROUTER`] integration is forward-compatible: once a
//! user-space driver registers a TaskId for an IRQ, the dispatch path
//! sends it the [`InterruptContext`] via the existing IPC machinery,
//! matching x86_64/AArch64. Until then the inline UART path provides
//! a working signal.

use crate::arch::mmio::ReadWrite;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Region base offsets
//
// The within-region layout (per-source priority stride, threshold/claim
// offsets) is now encoded as field positions in the typed blocks below, pinned
// by offset_of!/size_of asserts. Only the three region base offsets and the
// two per-context strides remain as consts - they drive the accessor address
// math (the PLIC's per-context regions can't be one flat block; see below).
// ============================================================================

/// Enable-bitmap region base (per-context enables start here).
const REG_ENABLE_BASE: u64 = 0x2000;
/// Per-context enable-bitmap stride (== size_of::<PlicEnableCtx>()).
const REG_ENABLE_STRIDE: u64 = 0x80;

/// Per-context control region base (threshold + claim/complete start here).
const REG_CONTEXT_BASE: u64 = 0x20_0000;
/// Per-context control stride.
const REG_CONTEXT_STRIDE: u64 = 0x1000;

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
/// hart N S-mode).
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
static S_CONTEXT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Typed register blocks (ADR-036)
//
// The PLIC's full spec register file spans ~64 MiB, but only the DTB-reported
// region (~6 MiB on QEMU virt) is mapped - so a single flat `#[repr(C)]` block
// covering the whole spec would over-claim the mapping at construction. Instead
// each of the three regions is a small typed block reached by an asserted-
// stride accessor (the GIC `gicr(cpu_id)` pattern), claiming only its sub-block
// of the mapped region. Within-region offsets are pinned by offset_of!/size_of.
// ============================================================================

#[inline]
fn base() -> u64 {
    PLIC_MMIO_VBASE.load(Ordering::Acquire)
}

/// Per-source priority registers (PLIC base + 0x0). Source 0 is reserved
/// (priority always 0). 1024 = the PLIC spec's maximum source count.
#[repr(C)]
struct PlicPriorities {
    prio: [ReadWrite<u32>; 1024],
}
const _: () = assert!(core::mem::size_of::<PlicPriorities>() == 0x1000);

/// One context's interrupt-enable bitmap: 1 bit per source, 32 words cover all
/// 1024 sources. At PLIC base + REG_ENABLE_BASE + context * REG_ENABLE_STRIDE.
#[repr(C)]
struct PlicEnableCtx {
    words: [ReadWrite<u32>; 32],
}
const _: () = assert!(core::mem::size_of::<PlicEnableCtx>() as u64 == REG_ENABLE_STRIDE);

/// One context's control block. At PLIC base + REG_CONTEXT_BASE +
/// context * REG_CONTEXT_STRIDE.
#[repr(C)]
struct PlicContext {
    /// +0x00 priority threshold: the context masks any source whose priority
    /// is <= this value.
    threshold: ReadWrite<u32>,
    /// +0x04 claim/complete: reading claims the highest-priority pending
    /// source (and marks it in-service); writing the same id completes it.
    claim: ReadWrite<u32>,
}
const _: () = assert!(core::mem::offset_of!(PlicContext, threshold) == 0x00);
const _: () = assert!(core::mem::offset_of!(PlicContext, claim) == 0x04);

/// Construct the priority-register block (PLIC base + 0x0).
///
/// # Safety
/// `init` must have published a valid, mapped PLIC base.
#[inline]
unsafe fn plic_priorities() -> &'static PlicPriorities {
    // SAFETY: the priority region is at the PLIC base, inside the mapped MMIO
    // (ADR-036 § 3); `init` published the base.
    unsafe { &*(base() as *const PlicPriorities) }
}

/// Construct `context`'s enable-bitmap block.
///
/// # Safety
/// `init` must have run and `context` must be a PLIC context whose enable
/// bitmap lies within the mapped region.
#[inline]
unsafe fn plic_enable(context: u32) -> &'static PlicEnableCtx {
    let addr = base() + REG_ENABLE_BASE + (context as u64) * REG_ENABLE_STRIDE;
    // SAFETY: `addr` is this context's enable bitmap within mapped PLIC MMIO;
    // the stride is REG_ENABLE_STRIDE == size_of::<PlicEnableCtx>() (asserted).
    unsafe { &*(addr as *const PlicEnableCtx) }
}

/// Construct `context`'s control block (threshold + claim/complete).
///
/// # Safety
/// `init` must have run and `context` must be a PLIC context whose control
/// block lies within the mapped region.
#[inline]
unsafe fn plic_context(context: u32) -> &'static PlicContext {
    let addr = base() + REG_CONTEXT_BASE + (context as u64) * REG_CONTEXT_STRIDE;
    // SAFETY: `addr` is this context's control block within mapped PLIC MMIO.
    unsafe { &*(addr as *const PlicContext) }
}

#[inline]
fn enable_bit(source_id: u32) -> u32 {
    1u32 << (source_id % 32)
}

// ============================================================================
// Initialization
// ============================================================================

/// Map the PLIC MMIO region into kernel space (via
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
        // SAFETY: per-page invocation of the same precondition asserted
        // for the loop above; `phys_base + page * 4096` stays inside
        // the MMIO region the caller described.
        unsafe {
            crate::memory::paging::early_map_mmio(phys_base + page * 4096)?;
        }
    }

    // Publish the kernel-VA base now that every page is mapped.
    let vbase = phys_base + crate::hhdm_offset();
    PLIC_MMIO_VBASE.store(vbase, Ordering::Release);
    PLIC_MMIO_SIZE.store(size_bytes, Ordering::Release);
    S_CONTEXT.store(HART0_S_CONTEXT, Ordering::Release);

    // Zero every source priority so no IRQ fires from a stale-register start.
    // Source 0 is reserved (priority always 0). The loop bound is a compile-time
    // constant < the array length, so every index is provably in range.
    // SAFETY: the base was just published; the PLIC region is mapped (ADR-036 § 3).
    let prios = unsafe { plic_priorities() };
    for src in 1..MAX_SOURCES {
        prios.prio[src as usize].write(0);
    }

    // Clear every enable bit in this hart's S-mode context (MAX_SOURCES / 32
    // u32 words).
    // SAFETY: as above; HART0_S_CONTEXT's enable bitmap is within the mapping.
    let en = unsafe { plic_enable(HART0_S_CONTEXT) };
    for word in 0..(MAX_SOURCES / 32) {
        en.words[word as usize].write(0);
    }

    // Threshold = 0: accept any IRQ with priority >= 1.
    // SAFETY: as above; HART0_S_CONTEXT's control block is within the mapping.
    let ctx = unsafe { plic_context(HART0_S_CONTEXT) };
    ctx.threshold.write(0);

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
        (1..MAX_SOURCES).contains(&source_id),
        "plic::enable_irq: source_id out of range",
    );
    if base() == 0 {
        return;
    }
    let ctx_id = S_CONTEXT.load(Ordering::Acquire);
    // Priority = 1 = enabled. source_id < MAX_SOURCES (debug_assert) keeps the
    // array index in range - same bounded-index pattern as the GIC enable_spi.
    // SAFETY: base != 0 means init published a mapped base (ADR-036 § 3).
    let prios = unsafe { plic_priorities() };
    prios.prio[source_id as usize].write(1);

    // Set this source's enable bit (read-modify-write the context's word).
    // SAFETY: as above; ctx_id is this kernel's S-mode context.
    let en = unsafe { plic_enable(ctx_id) };
    let word = (source_id / 32) as usize;
    let current = en.words[word].read();
    en.words[word].write(current | enable_bit(source_id));
}

/// Disarm a source. Priority = 0 and enable bit cleared. Idempotent.
///
/// # Safety
/// Same as [`enable_irq`].
#[allow(dead_code)] // wired when the first driver registers a revocation flow
pub unsafe fn disable_irq(source_id: u32) {
    debug_assert!(
        (1..MAX_SOURCES).contains(&source_id),
        "plic::disable_irq: source_id out of range",
    );
    if base() == 0 {
        return;
    }
    let ctx_id = S_CONTEXT.load(Ordering::Acquire);
    // SAFETY: base != 0 means init published a mapped base (ADR-036 § 3).
    let prios = unsafe { plic_priorities() };
    prios.prio[source_id as usize].write(0);
    // SAFETY: as above; ctx_id is this kernel's S-mode context.
    let en = unsafe { plic_enable(ctx_id) };
    let word = (source_id / 32) as usize;
    let current = en.words[word].read();
    en.words[word].write(current & !enable_bit(source_id));
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
    let ctx_id = S_CONTEXT.load(Ordering::Acquire);
    // SAFETY: base != 0 means init published a mapped base (ADR-036 § 3).
    let ctx = unsafe { plic_context(ctx_id) };
    // Reading the claim register is a side-effecting read (it marks the source
    // in-service) - the documented PLIC claim protocol.
    ctx.claim.read()
}

/// Signal to the PLIC that the driver has finished handling
/// `source_id`. Re-opens the source for the next assertion.
pub fn complete(source_id: u32) {
    if base() == 0 || source_id == 0 {
        return;
    }
    let ctx_id = S_CONTEXT.load(Ordering::Acquire);
    // SAFETY: base != 0 means init published a mapped base (ADR-036 § 3).
    let ctx = unsafe { plic_context(ctx_id) };
    // Writing the source id back to the claim register completes it.
    ctx.claim.write(source_id);
}

// ============================================================================
// Trap-vector entry point
// ============================================================================

/// Console IRQ — the source ID the kernel treats as "read a byte from
/// the primary UART inline." Set by kmain after reading
/// `BootInfo::console_irq` from the DTB; zero means "no inline
/// handling." Diagnostic path — once a real console driver
/// registers in [`INTERRUPT_ROUTER`], we delete the inline path.
static CONSOLE_IRQ: AtomicU32 = AtomicU32::new(0);

/// Record the console IRQ for inline diagnostic handling. Called once
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
        // state is observational (no driver is registered
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
            // Diagnostic: read the waiting byte and log it.
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
