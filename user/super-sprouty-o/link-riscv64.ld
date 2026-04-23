/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024-2026 Jason Ricca */

/* CambiOS user-space ELF linker script (super-sprouty-o, RISC-V) — ADR-011/012.
 * Matches the shape used by user/pong/link-riscv64.ld and siblings:
 * .sdata/.sbss folded into .data/.bss, .riscv.attributes discarded. */

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
