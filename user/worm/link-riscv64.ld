/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024-2026 Jason Ricca */

/* CambiOS user-space ELF linker script (worm, RISC-V) — ADR-011/012.
 * Matches the shape used by user/virtio-net/link-riscv64.ld:
 * .sdata/.sbss folded into .data/.bss, .riscv.attributes discarded. */

OUTPUT_FORMAT("elf64-littleriscv")
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
