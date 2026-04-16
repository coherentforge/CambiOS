// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Architecture-specific code (riscv64gc)
//!
//! Third architecture backend, targeting RISC-V S-mode with OpenSBI in
//! M-mode. See [ADR-013](../../docs/adr/013-riscv64-architecture-support.md)
//! for the load-bearing decisions (bootloader, DTB parsing, Sv48 paging,
//! SBI timer, PLIC, `tp`/`sscratch` per-CPU).
//!
//! ## x86_64 / AArch64 / RISC-V mapping
//!
//! | x86_64             | AArch64            | RISC-V (S-mode)              |
//! |--------------------|--------------------|------------------------------|
//! | GDT + TSS          | EL1/EL0 (no segs)  | S/U (no segs, SPP in sstatus) |
//! | IDT                | VBAR_EL1           | stvec (single vector)         |
//! | SYSCALL/SYSRET     | SVC / ERET         | ecall / sret                  |
//! | Local APIC timer   | Generic Timer      | SBI `sbi_set_timer`           |
//! | I/O APIC           | GIC Distributor    | PLIC                          |
//! | CR3 (PML4)         | TTBR0_EL1          | satp (Sv48)                   |
//! | IRETQ              | ERET               | SRET                          |
//! | HLT                | WFI                | WFI                           |
//! | GS base (per-CPU)  | TPIDR_EL1          | `tp` register + `sscratch`    |
//! | TLB shootdown IPI  | TLBI broadcast     | SBI IPI + local sfence.vma    |
//!
//! ## Phase status
//!
//! Phase R-1 lands the skeleton: SavedContext layout, stub context
//! primitives (panic until Phase R-3), percpu via `tp` register, trap
//! vector install stub, minimal PLIC/TLB wrappers. Context switching
//! proper, timer ticks, and U-mode entry come in Phase R-3 / R-4. See
//! the plan file at `/Users/jasonricca/.claude/plans/
//! melodic-tumbling-muffin.md`.

pub mod entry;
pub mod paging;
pub mod percpu;
pub mod plic;
pub mod syscall;
pub mod timer;
pub mod tlb;

/// Read the current hart's S-mode interrupt-enable state.
///
/// Returns `true` if S-mode interrupts are enabled (SSTATUS.SIE set).
/// Used by portable `debug_assert!` at call sites that require interrupts
/// masked — see CLAUDE.md § Timer / Preemptive Scheduling.
#[cfg(target_os = "none")]
#[inline]
pub fn interrupts_enabled() -> bool {
    let sstatus: u64;
    // SAFETY: csrr is a pure read of sstatus; nomem + preserves_flags hold.
    unsafe {
        core::arch::asm!(
            "csrr {0}, sstatus",
            out(reg) sstatus,
            options(nomem, preserves_flags),
        );
    }
    (sstatus & (1 << 1)) != 0 // SSTATUS.SIE
}

/// Host-test stub (same rationale as the x86_64 version).
#[cfg(not(target_os = "none"))]
#[inline]
pub fn interrupts_enabled() -> bool {
    false
}

/// GDT compatibility shim.
///
/// RISC-V has no segment selectors — privilege is managed via modes
/// (U/S/M). These constants exist so that `loader/mod.rs` can construct
/// a `SavedContext` without per-field cfg-gating. Mirrors the AArch64
/// shim at `src/arch/aarch64/mod.rs::gdt`.
pub mod gdt {
    /// User code "selector" — placeholder (U-mode has no segment)
    pub const USER_CS: u16 = 0;
    /// User stack "selector" — placeholder
    pub const USER_SS: u16 = 0;
    /// Kernel code "selector" — placeholder (S-mode has no segment)
    pub const KERNEL_CS: u16 = 0;
    /// Kernel stack "selector" — placeholder
    pub const KERNEL_SS: u16 = 0;

    /// Initialize S-mode configuration.
    ///
    /// On RISC-V there are no segment descriptors; privilege is a CSR
    /// bit. This is a no-op — OpenSBI hands us a S-mode context and the
    /// boot stub sets up paging (`satp`) plus the trap vector (`stvec`)
    /// before `kmain`.
    ///
    /// # Safety
    /// Must be called during early boot with interrupts masked.
    pub unsafe fn init() {
        // No-op on RISC-V.
    }

    /// Per-CPU init. No segment state per hart on RISC-V.
    ///
    /// # Safety
    /// Must be called once per AP during early init.
    pub unsafe fn init_for_cpu(_cpu_index: usize) {
        // No-op on RISC-V.
    }

    /// Store the kernel stack top in the current hart's PerCpu entry.
    ///
    /// The trap handler reads this field on U→S entry to switch off the
    /// user stack. The access is `tp`-relative (PerCpu lives in the
    /// struct pointed to by `tp`), matching how AArch64 does this
    /// TPIDR_EL1-relatively.
    ///
    /// # Safety
    /// - `tp` must already hold a valid `*mut PerCpu` (set via
    ///   [`percpu::init_bsp`] / [`percpu::init_ap`]).
    /// - Called from S-mode with interrupts masked.
    pub unsafe fn set_kernel_stack(stack_top: u64) {
        // PerCpu.kernel_stack_top is at offset 24 (same shape as
        // AArch64's PerCpu). On RISC-V we reach it through `tp`, not
        // TPIDR_EL1.
        //
        // SAFETY: `tp` was initialized by percpu::init_bsp. The pointed
        // memory is a valid `PerCpu` and this CPU has exclusive access
        // during context switch (interrupts masked).
        unsafe {
            core::arch::asm!(
                "sd {val}, 24(tp)",
                val = in(reg) stack_top,
                options(nostack, preserves_flags),
            );
        }
    }
}

use crate::scheduler::CpuContext;

// ============================================================================
// SavedContext — trap frame built on S-mode trap entry
// ============================================================================

/// Full register snapshot captured on trap entry.
///
/// The RISC-V trap handler (in Phase R-3) saves all 32 GPRs plus
/// `sepc` and `sstatus` into this struct on the kernel stack, then
/// passes its SP to the portable scheduler. On trap exit the same
/// struct is restored and `sret` returns to user or kernel mode.
///
/// Layout (byte offsets used by assembly in Phase R-3):
/// ```text
///   0..256  gpr[0..32]   (x0..x31 — x0 hardwired zero, slot unused)
/// 256..264  sepc
/// 264..272  sstatus
/// ```
/// Total size: 272 bytes (happens to match AArch64's SavedContext
/// exactly — the two architectures both save 32 GPRs plus two CSRs).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SavedContext {
    /// x0..x31. x0 is hardwired zero; its slot is kept only to make
    /// indexing uniform with register numbers. The trap handler never
    /// writes or reads gpr[0].
    pub gpr: [u64; 32],
    /// Saved PC (sepc CSR value at trap entry).
    pub sepc: u64,
    /// Saved status (sstatus CSR value at trap entry — encodes previous
    /// privilege via SPP and previous interrupt enable via SPIE).
    pub sstatus: u64,
}

/// Size in bytes of the trap frame pushed on the kernel stack.
///
/// Used by `loader/mod.rs` to compute `kstack_top - ISR_FRAME_SIZE`
/// for the initial trap frame of a newly loaded process. Matches the
/// AArch64 value (288 bytes — 272 rounded up to 16-byte alignment).
pub const ISR_FRAME_SIZE: u64 = 288;

// ============================================================================
// Explicit context switch primitives (stubs — Phase R-3 fills them in)
// ============================================================================
//
// RISC-V AAPCS calling convention:
//   a0..a7 = args, a0..a1 = return values, ra = return address (x1),
//   sp = stack pointer (x2), callee-saved: s0..s11 (x8..x9, x18..x27)
//
// Phase R-3 will implement these in `global_asm!` following the AArch64
// pattern (stp/ldp → sd/ld, `ret` → `ret`).
//
// Until then, calling any of these means the scheduler is live on
// RISC-V — which shouldn't happen in Phase R-1 (serial banner + halt).
// If they are called, we panic loudly rather than silently corrupting.

/// Stub: save callee-saved regs to `ctx`. Phase R-3.
///
/// # Safety
/// `ctx` must be a valid `*mut CpuContext`.
#[no_mangle]
pub unsafe extern "C" fn context_save(_ctx: *mut CpuContext) {
    panic!("riscv64 context_save: not implemented until Phase R-3");
}

/// Stub: restore regs from `ctx` and jump to saved PC. Phase R-3.
///
/// # Safety
/// `ctx` must be a valid `*const CpuContext` holding a coherent snapshot.
#[no_mangle]
pub unsafe extern "C" fn context_restore(_ctx: *const CpuContext) -> ! {
    panic!("riscv64 context_restore: not implemented until Phase R-3");
}

/// Stub: save current, restore next, jump. Phase R-3.
///
/// # Safety
/// Both pointers must be valid. `current_ctx` is written, `next_ctx` is read.
#[no_mangle]
pub unsafe extern "C" fn context_switch(
    _current_ctx: *mut CpuContext,
    _next_ctx: *const CpuContext,
) -> ! {
    panic!("riscv64 context_switch: not implemented until Phase R-3");
}

/// Stub: voluntary yield via synthetic trap frame. Phase R-3.
///
/// When called, the caller is voluntarily giving up the CPU. In Phase
/// R-3 this builds a SavedContext on the kernel stack (identical shape
/// to what the trap vector would push), calls `yield_inner`, and
/// restores from the possibly-different context via `sret`.
///
/// # Safety
/// Must be called from S-mode with the scheduler initialized.
#[no_mangle]
pub unsafe extern "C" fn yield_save_and_switch() {
    panic!("riscv64 yield_save_and_switch: not implemented until Phase R-3");
}

/// Park the current hart until the next interrupt.
///
/// Masks S-mode interrupts, sets SP to the per-CPU kernel stack, then
/// loops on `wfi`. The interrupt handler will resume scheduling when
/// the next timer tick fires (Phase R-3 onward).
///
/// For Phase R-1 this is simply `wfi` in a loop — no scheduling yet.
///
/// # Safety
/// `kernel_stack_top` must point to the top of a valid kernel stack for
/// this hart, or zero if no stack switch is desired.
pub fn halt_until_preempted(_kernel_stack_top: u64) -> ! {
    loop {
        // SAFETY: wfi is always legal from S-mode. It blocks until a
        // pending interrupt is observed; if interrupts are masked we
        // still wake on pending bits but the trap does not fire.
        unsafe {
            core::arch::asm!("wfi", options(nostack, nomem, preserves_flags));
        }
    }
}

// ============================================================================
// Switch-context coordination (used by loader/scheduler)
// ============================================================================

/// Stashed pointer to an on-stack SavedContext, set by the yield path
/// when it needs the scheduler to inspect the current trap frame.
/// Mirrors the AArch64 SWITCH_CONTEXT_PTR pattern. Phase R-3 wires it
/// through the trap handler.
static SWITCH_CONTEXT_PTR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn set_switch_context(ctx: *const SavedContext) {
    SWITCH_CONTEXT_PTR.store(ctx as u64, core::sync::atomic::Ordering::Release);
}

pub fn clear_switch_context() {
    SWITCH_CONTEXT_PTR.store(0, core::sync::atomic::Ordering::Release);
}

pub fn get_switch_context() -> u64 {
    SWITCH_CONTEXT_PTR.load(core::sync::atomic::Ordering::Acquire)
}

/// Copy register state from a SavedContext (trap frame) into the
/// scheduler's CpuContext (callee-saved view). Phase R-3.
pub fn saved_to_cpu_context(_saved: &SavedContext, _cpu: &mut CpuContext) {
    // Phase R-3 — no-op placeholder so the symbol exists for any
    // portable code that references it.
}

/// Copy register state from the scheduler's CpuContext into a
/// SavedContext (trap frame). Phase R-3.
pub fn cpu_to_saved_context(_cpu: &CpuContext, _saved: &mut SavedContext) {
    // Phase R-3 — no-op placeholder.
}
