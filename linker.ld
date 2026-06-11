/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024-2026 Jason Ricca */

/* CambiOS Microkernel linker script for Limine bootloader (x86-64) */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    text    PT_LOAD;
    rodata  PT_LOAD;
    data    PT_LOAD;
}

SECTIONS
{
    /* Higher-half kernel: top 2GiB of virtual address space (Limine spec) */
    . = 0xffffffff80000000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)

        /* GOT and relocation-read-only sections. relocation-model=static means
         * no runtime dynamic linker, so the GOT is filled at link time; but a
         * dependency object can still emit a GOTPCREL relocation, which makes
         * LLD materialize a small .got. LLD marks .got writable, so it lives in
         * the already-writable :data segment — placing it in :rodata would
         * taint that segment's read-only flag (W^X downgrade). Naming the
         * sections here stops LLD from orphaning .got to the kernel base, where
         * it overlaps .text. */
        *(.got .got.*)
        *(.got.plt .got.plt.*)
        *(.data.rel.ro .data.rel.ro.*)

        /* Limine request sections — bootloader scans these */
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
    } :data

    /* BSS must be last in :data to avoid zeros in binary */
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
