/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024-2026 Jason Ricca */

/* CambiOS user-space ELF linker script (audit-tail, x86_64)
 *
 * Places code at 0x400000 (USER_CODE_VADDR).
 * .got placed in .data so it lives in a writable PT_LOAD segment
 * (avoids page-permission conflicts when .got shares a page with
 * .text/.rodata).
 */
OUTPUT_FORMAT("elf64-x86-64")
ENTRY(_start)

SECTIONS
{
    . = 0x400000;

    .text : {
        *(.text .text.*)
    }

    . = ALIGN(4096);

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
        *(.note*)
        *(.eh_frame*)
        *(.gnu.hash)
    }
}
