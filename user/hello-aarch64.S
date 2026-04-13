/* Copyright (C) 2024-2026 Jason Ricca. All rights reserved. */

// CambiOS user-space test program — "hello" module (AArch64)
//
// Loaded by Limine as a boot module, executed at EL0.
// Uses CambiOS syscalls via the SVC instruction.
//
// Syscall convention (AArch64):
//   x8 = syscall number
//   x0 = arg1, x1 = arg2, x2 = arg3
//   x3 = arg4, x4 = arg5, x5 = arg6
//   x0 = return value
//
// Syscall numbers:
//   0 = Exit, 7 = Yield, 8 = GetPid, 10 = Print

.global _start
.section .text

_start:
    // SYS_GETPID (8) — get our process ID
    mov x8, #8
    svc #0
    // x0 now holds our PID

    // Print message 3 times, yielding between each
    mov x19, #3          // loop counter (callee-saved)

.loop:
    // SYS_PRINT (10) — print the message
    adr x0, msg          // buffer pointer (PC-relative)
    ldr x1, =msg_len     // buffer length
    mov x8, #10
    svc #0

    // SYS_YIELD (7) — give up time slice
    mov x8, #7
    svc #0

    subs x19, x19, #1
    b.ne .loop

    // SYS_EXIT (0) — clean exit
    mov x0, #0
    mov x8, #0
    svc #0

.section .rodata
msg:
    .ascii "[Module] Hello from boot module!\n"
msg_end:
.set msg_len, msg_end - msg
