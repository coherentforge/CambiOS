/* Copyright (C) 2024-2026 Jason Ricca. All rights reserved. */

/* CambiOS user-space ELF linker script (riscv64gc)
 *
 * Places code at 0x400000 (USER_CODE_VADDR), same as the x86_64 and
 * AArch64 user layouts so user programs share a single virtual-address
 * convention across architectures. Produces a minimal static ELF64.
 *
 * `ALIGN(0x1000)` before each section keeps PT_LOAD segments 4 KiB
 * aligned — the kernel's loader uses one page per segment-permission
 * combination, and overlapping segment permissions on the same page
 * would take the first segment's permission (ADR-004 / loader note).
 */
OUTPUT_FORMAT("elf64-littleriscv")
ENTRY(_start)

SECTIONS
{
    . = 0x400000;

    .text : {
        *(.text .text.*)
    }

    . = ALIGN(0x1000);
    .rodata : {
        *(.rodata .rodata.*)
    }

    . = ALIGN(0x1000);
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
