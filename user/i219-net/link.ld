/* Copyright (C) 2024-2026 Jason Ricca. All rights reserved. */

/* CambiOS user-space ELF linker script (i219-net driver, x86_64)
 *
 * Places code at 0x400000 (USER_CODE_VADDR).
 * .got is placed in .data on a separate page to avoid RX/RW conflicts.
 */
OUTPUT_FORMAT("elf64-x86-64")
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
    }

    .bss : {
        *(.bss .bss.*)
    }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.note.*)
    }
}
