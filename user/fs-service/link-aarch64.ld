/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024-2026 Jason Ricca */

/* CambiOS user-space ELF linker script (fs-service, AArch64)
 *
 * Places code at 0x400000 (USER_CODE_VADDR).
 * Produces a minimal static ELF64 binary.
 *
 * .got is placed in .data so it's in a writable PT_LOAD segment.
 * This avoids page permission conflicts when .got shares a page
 * with .text/.rodata (kernel ELF loader maps per-segment permissions).
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
