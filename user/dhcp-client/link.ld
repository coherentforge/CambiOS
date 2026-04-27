/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024-2026 Jason Ricca */

/* CambiOS user-space ELF linker script (dhcp-client, x86_64) */
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
        *(.eh_frame)
        *(.note.*)
    }
}
