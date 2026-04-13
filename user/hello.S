/* Copyright (C) 2024-2026 Jason Ricca. All rights reserved. */

// CambiOS user-space test program — "hello" module
//
// Loaded by Limine as a boot module, executed in ring 3.
// Uses CambiOS syscalls via the SYSCALL instruction.
//
// Syscall convention (x86_64):
//   rax = syscall number
//   rdi = arg1, rsi = arg2, rdx = arg3
//   rcx = arg4, r8  = arg5, r9  = arg6
//
// Syscall numbers:
//   0 = Exit, 7 = Yield, 8 = GetPid, 10 = Print

.global _start
.section .text

_start:
    // SYS_GETPID (8) — get our process ID
    movq $8, %rax
    syscall
    // rax now holds our PID

    // Print message 3 times, yielding between each
    movq $3, %r12       // loop counter

.loop:
    // SYS_PRINT (10) — print the message
    leaq msg(%rip), %rdi
    movq $msg_len, %rsi
    movq $10, %rax
    syscall

    // SYS_YIELD (7) — give up time slice
    movq $7, %rax
    syscall

    decq %r12
    jnz .loop

    // SYS_EXIT (0) — clean exit
    xorq %rdi, %rdi
    movq $0, %rax
    syscall

.section .rodata
msg:
    .ascii "[Module] Hello from boot module!\n"
msg_end:
.set msg_len, msg_end - msg
