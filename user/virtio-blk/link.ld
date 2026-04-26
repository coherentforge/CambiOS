/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024-2026 Jason Ricca */

/* User-space linker script for virtio-blk driver.
   Same layout as fs-service / virtio-net: code at 0x400000, data on separate page. */

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

    /* Force .data onto a new page so .got gets RW, not RX */
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
