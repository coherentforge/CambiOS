// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! RISC-V boot entry — `_start` + Sv48 boot trampoline
//!
//! OpenSBI hands control here in S-mode with paging disabled
//! (`satp = 0`). Register state on entry (per RISC-V SBI spec):
//!
//!   a0 = hart id (the booting hart's id, may be non-zero on QEMU)
//!   a1 = physical address of the Flattened Device Tree (DTB)
//!
//! Phase R-2 responsibilities of `_start`:
//!   1. Park secondary harts on `wfi` (SMP wake is Phase R-5).
//!   2. Set up a small boot stack in .bss (`BOOT_STACK`).
//!   3. Call Rust [`riscv64_fill_boot_page_tables`] to populate the
//!      Sv48 boot page tables (identity map + HHDM + higher-half
//!      kernel map) and return the `satp` value.
//!   4. Write `satp`, `sfence.vma`, and absolute-jump to the
//!      higher-half virtual address of [`kmain_riscv64`].
//!
//! ## Sv48 boot map (documented in linker-riscv64.ld too)
//!
//!   L3[0]   -> L2_IDENTITY (identity 0..512 GiB via gigapage leaves)
//!   L3[256] -> L2_IDENTITY (HHDM at 0xffff_8000_0000_0000, same table)
//!   L3[511] -> L2_KERNEL   (L2_KERNEL[510] gigapage to physical
//!                           0x8000_0000 — kernel at 0xffffffff80000000)
//!
//! The L2_IDENTITY table is shared between L3[0] and L3[256] — both
//! map the same physical range, so one L2 table with 512 gigapages
//! suffices. The kernel map uses a separate L2 table because it sits
//! at a different L3 index and only one gigapage is populated.
//!
//! Total static page-table memory: 3 × 4 KiB = 12 KiB in `.bss`.
//!
//! ## The long jump
//!
//! After `satp` is written, PC is still at a low physical address
//! (0x802XXXXX) — execution continues correctly because L3[0] identity-
//! maps that range. But all of the kernel's *static* symbols are
//! linked at their higher-half VMA. To reach them via sensible
//! relative addressing, we must jump once to a higher-half PC.
//!
//! PC-relative `la` cannot reach 0xffffffff80200000 from physical
//! 0x80200000 (the 32-bit signed displacement doesn't span that
//! gap), so we load the target virtual address from a `.quad` in
//! `.rodata`. The linker writes the absolute virtual address into
//! the quad at build time, and the `ld` instruction reads 8 bytes
//! from that location (reached via PC-relative `la`, which gives
//! the *physical* address of the quad — same data regardless of
//! paging state). The loaded value is the *virtual* address of
//! `kmain_riscv64`, which becomes valid as soon as paging is on.
//!
//! Per [ADR-013](../../docs/adr/013-riscv64-architecture-support.md)
//! § Decision 3 this is the "Sv48 with Sv39 fallback" path — we
//! picked Sv48 up front since QEMU virt supports it and the 4-level
//! shape matches the existing shared paging module.

use core::sync::atomic::{AtomicBool, Ordering};

/// Boot stack size for the BSP. 16 KiB suffices for early init
/// (panic frames + DTB walk) before per-task kernel stacks exist.
///
/// SCAFFOLDING: small fixed boot stack used only by the early entry
/// path on the BSP.
/// Why: 16 KiB matches the AArch64 boot stack convention; Phase R-3
///      scheduler creates per-task stacks.
/// Replace when: per-CPU / per-task kernel stacks land.
pub const BOOT_STACK_SIZE: usize = 16 * 1024;

#[unsafe(link_section = ".bss.boot_stack")]
static mut BOOT_STACK: [u8; BOOT_STACK_SIZE] = [0; BOOT_STACK_SIZE];

// ============================================================================
// Sv48 boot page tables (static, page-aligned, in .bss)
// ============================================================================

/// Sv48 page table — 512 u64 entries, 4 KiB aligned.
#[repr(C, align(4096))]
struct PageTable([u64; 512]);

impl PageTable {
    const fn zero() -> Self {
        PageTable([0; 512])
    }
}

/// Sv48 root (L3) — 1 entry per 512 GiB of VA.
static mut BOOT_L3: PageTable = PageTable::zero();

/// L2 shared by identity map (L3[0]) and HHDM (L3[256]). Each of its
/// 512 entries is a gigapage leaf covering 1 GiB of physical memory.
static mut BOOT_L2_IDENTITY: PageTable = PageTable::zero();

/// L2 for the higher-half kernel map (L3[511]). Only entry [510] is a
/// gigapage pointing at physical 0x8000_0000 (kernel VMA base).
static mut BOOT_L2_KERNEL: PageTable = PageTable::zero();

// ============================================================================
// Sv48 PTE bits
// ============================================================================

/// PTE bits. See the RISC-V privileged spec, "Sv48 PTE Format."
#[allow(dead_code)]
mod pte {
    pub const V: u64 = 1 << 0; // Valid
    pub const R: u64 = 1 << 1; // Readable
    pub const W: u64 = 1 << 2; // Writable
    pub const X: u64 = 1 << 3; // Executable
    pub const U: u64 = 1 << 4; // User-accessible
    pub const G: u64 = 1 << 5; // Global (all address spaces)
    pub const A: u64 = 1 << 6; // Accessed
    pub const D: u64 = 1 << 7; // Dirty
}

/// HHDM virtual base — matches AArch64's value (upper half, first
/// non-kernel L3 slot). See `crate::boot::info().hhdm_offset`.
pub const HHDM_OFFSET: u64 = 0xffff_8000_0000_0000;

/// `satp` MODE field for Sv48 = 9 (see RISC-V privileged spec).
const SATP_MODE_SV48: u64 = 9 << 60;

/// Fill the three boot page tables and return the `satp` value.
///
/// Called from `_start` (assembly) while running at physical
/// addresses with paging disabled. Writes to the static tables via
/// PC-relative addressing (which gives physical addresses before
/// paging, equal to the linker-assigned VMAs minus the kernel
/// offset, because of `AT()` in the linker script).
///
/// Returns the `satp` value to write — `(MODE_SV48 << 60) | root_PPN`.
///
/// # Safety
/// - Called exactly once from `_start` before any other hart runs.
/// - Must execute while paging is disabled.
/// - The linker placed BOOT_L3 / BOOT_L2_IDENTITY / BOOT_L2_KERNEL
///   at 4 KiB alignment (via `repr(align(4096))`); this is required
///   for PTE encoding.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn riscv64_fill_boot_page_tables() -> u64 {
    // Sanity: make sure we only ever run this once. The AtomicBool is
    // stored at a static address; pre-paging, PC-relative gives its
    // physical address (via the AT offset). Writes to it work the
    // same way.
    static FILLED: AtomicBool = AtomicBool::new(false);
    if FILLED.swap(true, Ordering::AcqRel) {
        // Already filled — shouldn't happen, but park defensively.
        loop {
            // SAFETY: wfi is safe at S-mode.
            unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
        }
    }

    // Physical addresses of the static tables. Pre-paging, taking a
    // static's address gives its physical address (because PC-relative
    // addressing computes from the current physical PC, and AT() in
    // the linker script offsets the LMA relative to the VMA by a
    // constant that `la` recovers correctly).
    let l3_phys = &raw const BOOT_L3 as u64;
    let l2_id_phys = &raw const BOOT_L2_IDENTITY as u64;
    let l2_kern_phys = &raw const BOOT_L2_KERNEL as u64;

    // Build L2_IDENTITY: 512 gigapage leaves mapping physical
    // 0..512 GiB. Each entry: PTE points to PA = (i * 1 GiB) with
    // RWX+G+A+D+V flags (leaf, global, pre-accessed to avoid A-bit
    // fault on first access).
    //
    // SAFETY: static mut array, exclusive access during single-hart boot.
    unsafe {
        let l2_id = &mut (*(&raw mut BOOT_L2_IDENTITY)).0;
        let mut i = 0;
        while i < 512 {
            // PPN of 1 GiB-aligned physical address (i * 0x40000000 >> 12 = i << 18)
            let ppn = (i as u64) << 18;
            l2_id[i] = (ppn << 10) | pte::V | pte::R | pte::W | pte::X | pte::G | pte::A | pte::D;
            i += 1;
        }
    }

    // Build L2_KERNEL: one gigapage at index 510 mapping virtual
    // 0xffffffff80000000 -> physical 0x80000000. PPN = 0x80000.
    //
    // SAFETY: same as above.
    unsafe {
        let l2_k = &mut (*(&raw mut BOOT_L2_KERNEL)).0;
        let kernel_gigapage_ppn: u64 = 0x80000; // 0x8000_0000 >> 12
        l2_k[510] = (kernel_gigapage_ppn << 10)
            | pte::V | pte::R | pte::W | pte::X | pte::G | pte::A | pte::D;
    }

    // Build L3 root:
    //   L3[0]   -> L2_IDENTITY (identity map)
    //   L3[256] -> L2_IDENTITY (HHDM, same table)
    //   L3[511] -> L2_KERNEL
    //
    // Non-leaf entries carry only V bit (R=W=X=0 signals "pointer to
    // next-level table"). G is set so all address spaces see the
    // mapping (no ASID in play yet).
    //
    // SAFETY: static mut, single-hart boot.
    unsafe {
        let l3 = &mut (*(&raw mut BOOT_L3)).0;
        let l2_id_pte = (l2_id_phys >> 12) << 10 | pte::V;
        let l2_k_pte = (l2_kern_phys >> 12) << 10 | pte::V;
        l3[0] = l2_id_pte;
        l3[256] = l2_id_pte;
        l3[511] = l2_k_pte;
    }

    // Compute satp. Mode=9 (Sv48), ASID=0, PPN=l3_phys >> 12.
    SATP_MODE_SV48 | (l3_phys >> 12)
}

// ============================================================================
// Assembly entry: _start
// ============================================================================
//
// SAFETY (the global_asm block):
// - `_start` is the ELF entry declared in linker-riscv64.ld. OpenSBI
//   jumps here in S-mode with paging disabled and a0/a1 set per the
//   SBI spec.
// - No Rust runtime is active yet — allocator uninit, statics not
//   yet zeroed by a boot loader (we rely on .bss being placed in
//   PT_LOAD :data, which on QEMU is allocated as zero pages).
// - We touch only:
//     * BOOT_STACK (fixed .bss array) via `la`
//     * riscv64_fill_boot_page_tables (Rust function)
//     * kmain_riscv64_vaddr (.quad in .rodata holding absolute
//       virtual address of kmain_riscv64)
//     * kmain_riscv64 (Rust function, reached via the loaded
//       virtual address)
// - `wfi`, `csrci sstatus, _`, `csrw satp, _`, `sfence.vma` are all
//   safe S-mode instructions.
// - Hart-id parking ("only hart 0 boots") matches QEMU virt's default;
//   Phase R-5 will read the BSP hart id from the DTB instead.
core::arch::global_asm!(
    ".section .text.boot, \"ax\"",
    ".global _start",
    ".type _start, @function",
    "_start:",
    // Disable S-mode interrupts (SIE = bit 1 of sstatus).
    "csrci sstatus, 0x2",
    // Park any hart that isn't hart 0 (Phase R-5 reads BSP from DTB).
    "bnez a0, .Lpark_hart",
    // Preserve OpenSBI-provided args in callee-saved regs across the
    // Rust call below. s0 = hart_id, s1 = dtb_phys.
    "mv s0, a0",
    "mv s1, a1",
    // Set up boot stack: sp = &BOOT_STACK + BOOT_STACK_SIZE.
    // RISC-V stacks grow downward; sp points one past the top.
    "la t0, {boot_stack}",
    "li t1, {boot_stack_size}",
    "add sp, t0, t1",
    // Zero frame pointer per ABI (entry frame has no caller).
    "mv fp, zero",

    // Call Rust to fill the Sv48 boot page tables and get the satp value.
    // Return value: a0 = satp value.
    "call riscv64_fill_boot_page_tables",
    "mv t2, a0",                    // t2 = satp to write

    // Load absolute virtual address of kmain_riscv64 from the
    // .rodata quad (linker stored the full 64-bit VMA there). We
    // load it *before* enabling paging — the load goes through the
    // physical address of the quad (via `la`, which is PC-relative
    // and gives the physical equivalent pre-paging).
    "la t1, {kmain_vaddr_holder}",  // t1 = physical addr of .quad
    "ld t3, 0(t1)",                 // t3 = virtual addr of kmain_riscv64

    // Restore OpenSBI args for the Rust call below.
    "mv a0, s0",                    // a0 = hart_id
    "mv a1, s1",                    // a1 = dtb_phys

    // Enable Sv48 paging.
    "csrw satp, t2",
    "sfence.vma",

    // Promote sp from its pre-paging physical identity form (low VA
    // 0x80340xxx via L0[0]) to the higher-half kernel VA form
    // (0xffffffff_80340xxx via L0[511]). Add the VMA–LMA offset
    // (0xffffffff_00000000) that the linker script encodes. Without
    // this, sp stays in the low identity window — fine as long as
    // the active satp has L0[0] pointing at L2_IDENTITY, but broken
    // the instant `create_process_page_table` hands us a root that
    // only copies L0[256..512] (the kernel half). The first
    // context switch to a user task would leave sp pointing at an
    // unmapped address in the new satp.
    "li t4, -1",
    "slli t4, t4, 32",              // t4 = 0xffffffff00000000
    "add sp, sp, t4",               // sp now higher-half kernel VA

    // At this point paging is on and sp is higher-half. PC is still
    // at a low physical address, but L3[0] identity-maps that range,
    // so the next instruction executes. Now absolute-jump to
    // kmain_riscv64's higher-half virtual address.
    "jr t3",
    // Unreachable — kmain_riscv64 is `-> !`.

    ".Lpark_hart:",
    "wfi",
    "j .Lpark_hart",

    boot_stack = sym BOOT_STACK,
    boot_stack_size = const BOOT_STACK_SIZE,
    kmain_vaddr_holder = sym KMAIN_RISCV64_VADDR,
);

// `.quad kmain_riscv64` — the linker fills in the absolute virtual
// address of kmain_riscv64 at build time (0xffffffff802XXXXX). _start
// loads this 8-byte value *before* enabling paging, so the subsequent
// `jr` hits the right higher-half PC.
//
// Rust expresses this as a pointer to an extern function resolved at
// link time. We can't just write `&kmain_riscv64 as u64` because that
// requires `extern "C" fn(u64, u64) -> !` to be a first-class type;
// instead we declare the extern and take its address through a static.
extern "C" {
    #[allow(dead_code)]
    fn kmain_riscv64(hart_id: u64, dtb_phys: u64) -> !;
}

/// Absolute virtual address of `kmain_riscv64`, resolved by the
/// linker. `_start` loads this *before* writing `satp` so it can jump
/// to the higher-half PC once paging is on.
#[unsafe(link_section = ".rodata.boot")]
#[unsafe(no_mangle)]
static KMAIN_RISCV64_VADDR: unsafe extern "C" fn(u64, u64) -> ! = kmain_riscv64;
