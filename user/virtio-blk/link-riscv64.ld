/* Copyright (C) 2024-2026 Jason Ricca. All rights reserved. */

/* CambiOS user-space ELF linker script (virtio-blk, RISC-V)
 *
 * Places code at 0x400000 (USER_CODE_VADDR).
 * Produces a minimal static ELF64 binary.
 *
 * .got is placed in .data so it's in a writable PT_LOAD segment.
 */
OUTPUT_FORMAT("elf64-littleriscv")
ENTRY(_start)

SECTIONS
{
    . = 0x400000;

    .text : {
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
        *(.got .got.*)
        *(.sdata .sdata.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.gnu.hash)
        *(.riscv.attributes)
    }
}
