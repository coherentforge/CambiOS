/* Copyright (C) 2024-2026 Jason Ricca. All rights reserved. */

/* User-space linker script for UDP stack service.
   Same layout as fs-service: code at 0x400000, data on separate page. */

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
