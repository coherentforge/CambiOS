/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024-2026 Jason Ricca */

/* CambiOS Microkernel linker script for OpenSBI + S-mode stub (riscv64gc).
 *
 * Phase R-2 layout (higher-half kernel at Sv48 virtual addresses):
 *
 *   VMA (virtual, linker-assigned):  0xffffffff80200000 + kernel size
 *   LMA (physical, OpenSBI load):    0x80200000        + kernel size
 *
 *   The kernel is linked at the higher-half virtual address
 *   0xffffffff80200000 but OpenSBI loads it to physical 0x80200000
 *   (OpenSBI occupies 0x80000000..0x80200000 on QEMU virt). The
 *   `AT(. - 0xffffffff00000000)` expression computes each section's
 *   LMA as `VMA - 0xffffffff_00000000`, which for the kernel base
 *   gives 0x80200000. This is the standard "identity offset" trick
 *   for higher-half kernels.
 *
 *   The `_start` boot stub (defined in arch/riscv64/entry.rs) runs at
 *   the physical address (paging off) and uses PC-relative addressing,
 *   so code that would nominally access virtual 0xffffffff802XXXXX
 *   instead accesses physical 0x802XXXXX via the loaded PC. After
 *   the boot trampoline writes `satp` to enable Sv48 with identity +
 *   HHDM + higher-half kernel mappings, code transitions to executing
 *   at the higher-half virtual address via an absolute jump to
 *   `kmain_riscv64`.
 *
 *   Kernel Sv48 mapping (set up in entry.rs::_start):
 *     L3[0]   -> L2_identity (identity-maps low physical 0..512 GiB)
 *     L3[256] -> L2_identity (HHDM at 0xffff800000000000, same table)
 *     L3[511] -> L2_kernel   (L2_kernel[510] gigapages to physical 0x80000000)
 *
 *   HHDM offset (used by io, memory, etc.): 0xffff800000000000
 *
 * No Limine `.requests` sections — Limine does not support RISC-V.
 * BootInfo is populated from the DTB OpenSBI passes in a1.
 *
 * ENTRY(_start) places the ELF e_entry field at whatever physical
 * address _start resolves to (= 0x80200000 via the AT expression).
 */

OUTPUT_FORMAT(elf64-littleriscv)
OUTPUT_ARCH(riscv)
ENTRY(_start)

PHDRS
{
    text    PT_LOAD;
    rodata  PT_LOAD;
    data    PT_LOAD;
}

SECTIONS
{
    /* Higher-half VMA. LMA is VMA - 0xffffffff00000000 = 0x80200000 at start. */
    . = 0xffffffff80200000;

    .text : AT(. - 0xffffffff00000000) {
        /* _start must be first — it's the ELF e_entry (= physical 0x80200000). */
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : AT(. - 0xffffffff00000000) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : AT(. - 0xffffffff00000000) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } :data

    /* BSS last in :data so it doesn't occupy space in the loaded image. */
    .bss : AT(. - 0xffffffff00000000) {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    } :data

    _kernel_end = .;
    /* Note: we do *not* export an absolute _kernel_end_phys symbol —
     * that would be a low (~0x80XXXXXX) absolute value which Rust
     * can't PC-relative-address from the higher-half kernel (the
     * 32-bit displacement range doesn't span 0x7FFFFFFF...). Rust
     * derives the physical end in code: `_kernel_end - 0xffffffff00000000`.
     */

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.riscv.attributes)
        *(.comment)
    }
}
