/* Copyright (C) 2024-2026 Jason Ricca. All rights reserved. */

/* CambiOS user-space ELF linker script (AArch64)
 *
 * Places code at 0x400000 (USER_CODE_VADDR).
 * Produces a minimal static ELF64 binary.
 */
OUTPUT_FORMAT("elf64-littleaarch64")
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

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
    }
}
