/* Copyright (C) 2024-2026 Jason Ricca. All rights reserved. */

/*
 * CambiOS user-space test program — "hello" module (riscv64)
 *
 * Loaded into U-mode at virtual address 0x400000 by the kernel's
 * ELF loader. Exercises the R-4 U-mode path end-to-end: syscalls
 * via `ecall` trap into S-mode, the trap vector's sscratch/tp
 * swap swings PerCpu into tp, the kernel dispatcher handles the
 * request, `sret` returns to the next user instruction (sepc+4).
 *
 * Syscall convention (RISC-V, matching Linux's ABI):
 *   a7 = syscall number
 *   a0 = arg1, a1 = arg2, a2 = arg3
 *   a3 = arg4, a4 = arg5, a5 = arg6
 *   a0 = return value
 *
 * Syscall numbers used here (see src/syscalls/mod.rs):
 *   0 = SYS_EXIT
 *   7 = SYS_YIELD
 *   8 = SYS_GETPID
 *  10 = SYS_PRINT
 *
 * All four are on the identity-gate-exempt list, so this program
 * runs without a bound Principal.
 */

.global _start
.section .text

_start:
    /* SYS_GETPID (8) — get our process ID (result lands in a0). */
    li  a7, 8
    ecall

    /* Loop counter in s0 (callee-saved) — three prints then exit. */
    li  s0, 3

.Lloop:
    /* SYS_PRINT (10) — a0 = buf, a1 = len.
     *
     * RISC-V `li` doesn't take a symbol operand the way AArch64's
     * `ldr x1, =sym` does, so we hardcode the length and verify
     * statically below. `la` for the address stays pseudo-op since
     * medium code model handles the pcrel reach. */
    la  a0, msg
    li  a1, 43
    li  a7, 10
    ecall

    /* SYS_YIELD (7) — hand back the quantum; scheduler picks the
       next Ready task (idle if none else). */
    li  a7, 7
    ecall

    addi s0, s0, -1
    bnez s0, .Lloop

    /* SYS_EXIT (0) — clean exit; scheduler reaps the task. */
    li  a0, 0
    li  a7, 0
    ecall

    /* Should not reach here; defensive wfi loop if the kernel
       ever fails to reap us. */
1:  wfi
    j   1b

.section .rodata
msg:
    .ascii "[Module] Hello from boot module (riscv64)!\n"
msg_end:
/* Static assertion: if we miscount the hardcoded length in .Lloop,
 * the assembler errors out here rather than letting a runtime bug
 * reach QEMU. */
.if (msg_end - msg) != 43
.error "hello-riscv64: msg length in .Lloop (43) out of sync with msg bytes"
.endif
