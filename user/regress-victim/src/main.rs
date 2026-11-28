// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors

//! regress-victim — the regression probe's hostile child (ADR-040
//! § Sequencing).
//!
//! The probe spawns this program, waits for it to say it is listening,
//! and sends it one byte naming a hostile instruction sequence: one a
//! program can execute in ring 3 and that once halted the whole kernel, or
//! once ran when it must not (x87 with no FP state saved, `rdtsc`, `sidt`).
//! On riscv64 the one mode sets `tp`, which the trap vector once left in
//! `sscratch` for the kernel to trust, then faults. This program executes
//! the sequence; the modes are per architecture (`execute`). For most
//! modes a correct kernel reaps it for the fault; for the nested-task and
//! GS modes a correct kernel lets it finish and exit 0. The probe checks
//! which happened and that the kernel kept running.
//!
//! The mode arrives over IPC because `SYS_SPAWN` carries only a name: one
//! program can then serve every hostile stage instead of one crate per
//! instruction.
//!
//! Handshake: the entry macro registers [`VICTIM_ENDPOINT`] and pings init;
//! this program writes `READY` to the probe's endpoint, then blocks on its
//! own endpoint for the mode byte. The manifest row carries the `regress`
//! profile only, so no shipping image contains this program. Anyone who can
//! send to its endpoint chooses which fault it takes, which is all it does.

#![no_std]
#![no_main]

use cambios_libsys as sys;

/// ARCHITECTURAL: this program's endpoint (manifest.toml reserves it to the
/// `regress-victim` row).
const VICTIM_ENDPOINT: u32 = 60;

/// ARCHITECTURAL: the regression probe's endpoint (its manifest row).
const PROBE_ENDPOINT: u32 = 59;

/// What this program sends the probe once it is listening.
const READY: &[u8] = b"victim-ready";

/// Mode bytes, shared with `user/regression-probe` (keep the two in step).
/// 1-10 are x86_64 instruction sequences, 11 is riscv64's.
#[cfg(target_arch = "x86_64")]
const MODE_UD: u8 = 1;
#[cfg(target_arch = "x86_64")]
const MODE_SS: u8 = 2;
#[cfg(target_arch = "x86_64")]
const MODE_ICEBP: u8 = 3;
#[cfg(target_arch = "x86_64")]
const MODE_TF: u8 = 4;
#[cfg(target_arch = "x86_64")]
const MODE_NT: u8 = 5;
#[cfg(target_arch = "x86_64")]
const MODE_GS_SYSCALL: u8 = 6;
#[cfg(target_arch = "x86_64")]
const MODE_GS_TICK: u8 = 7;
#[cfg(target_arch = "x86_64")]
const MODE_X87: u8 = 8;
#[cfg(target_arch = "x86_64")]
const MODE_RDTSC: u8 = 9;
#[cfg(target_arch = "x86_64")]
const MODE_SIDT: u8 = 10;
#[cfg(target_arch = "riscv64")]
const MODE_TP_REAP: u8 = 11;

/// ARCHITECTURAL: the kernel GDT's user data selector (index 3, RPL 3; see
/// `.claude/rules/x86_64.md`). Ring 3 may load it into GS, which in 64-bit
/// mode sets GS's base to the descriptor's base, 0.
#[cfg(target_arch = "x86_64")]
const USER_DATA_SELECTOR: u16 = 0x1B;

/// TUNING: countdown iterations per spin chunk in the GS tick mode. Long
/// enough that the first chunk usually spans a timer tick (tens of ms
/// under QEMU's TCG emulation, about 15 ms at 5 GHz), short enough that
/// the tick check between chunks ends the mode soon after the ticks land.
#[cfg(target_arch = "x86_64")]
const GS_TICK_SPIN: u64 = 1 << 26;

/// TUNING: ticks (10 ms each) that must pass while the GS tick mode spins
/// in ring 3. A periodic local timer that advanced the clock this far has
/// interrupted this CPU in ring 3 at least once.
#[cfg(target_arch = "x86_64")]
const GS_TICK_MIN_TICKS: u64 = 3;

/// SCAFFOLDING: bound on spin chunks in the GS tick mode, so the mode
/// ends even if the clock stops.
/// Why: Convention 8 bounded iteration; 64 chunks is seconds under TCG.
/// Replace when: a ring-3 tick counter makes the clock check unnecessary.
#[cfg(target_arch = "x86_64")]
const GS_TICK_MAX_CHUNKS: u32 = 64;

/// TUNING: pages (16 MiB) the riscv64 `tp` mode maps before it faults. The
/// reap unmaps them one by one, each with a TLB shootdown, with
/// interrupts on, so it spans timer ticks under QEMU; a kernel that kept
/// the program's `tp` in `sscratch` takes one of those ticks through the
/// user-entry branch (the sandbox review's reproduction, 2026-11-24).
#[cfg(target_arch = "riscv64")]
const TP_REAP_PAGES: u32 = 4096;

/// TUNING: ticks (10 ms each) the 16 MiB mapping must take for the `tp`
/// mode to count. The reap unmaps the same pages one by one, each with a
/// TLB shootdown, so a mapping that spanned a tick says the reap will
/// too; one that did not says the stage would pass on any kernel, the
/// tick that once took the program's `tp` as the per-CPU pointer never
/// having come, and the mode exits 8 instead of faulting.
#[cfg(target_arch = "riscv64")]
const TP_REAP_MIN_MAP_TICKS: u64 = 1;

cambios_libsys_rt::service_main! {
    name: "REGRESS-VICTIM",
    endpoint: VICTIM_ENDPOINT,
    main: run,
}

fn run() -> ! {
    if sys::write(PROBE_ENDPOINT, READY) < 0 {
        sys::print(b"[REGRESS-VICTIM] could not reach the probe\r\n");
        sys::exit(3);
    }
    let mut buf = [0u8; 96];
    let mode = match sys::recv_verified(VICTIM_ENDPOINT, &mut buf) {
        Some(msg) => msg.payload().first().copied().unwrap_or(0),
        None => {
            sys::print(b"[REGRESS-VICTIM] no mode message\r\n");
            sys::exit(4);
        }
    };
    execute(mode);
    sys::print(b"[REGRESS-VICTIM] BUG: the instruction did not fault\r\n");
    sys::exit(2)
}

/// Run the x86_64 sequence `mode` names. Returns only when a sequence that
/// must fault did not.
#[cfg(target_arch = "x86_64")]
fn execute(mode: u8) {
    match mode {
        MODE_UD => {
            sys::print(b"[REGRESS-VICTIM] ud2\r\n");
            // SAFETY: deliberately faults. `ud2` is an invalid opcode in
            // every mode; the kernel must reap this program for it.
            unsafe { core::arch::asm!("ud2", options(nomem, nostack)) };
        }
        MODE_SS => {
            sys::print(b"[REGRESS-VICTIM] push through a non-canonical stack pointer\r\n");
            // SAFETY: deliberately faults. A push through a non-canonical
            // RSP faults before any memory is written (#SS on Intel
            // hardware; QEMU's TCG raises #GP). The program
            // never returns from here, so the clobbered stack pointer is
            // never used again.
            unsafe {
                core::arch::asm!(
                    "mov rsp, {bad}",
                    "push rax",
                    bad = in(reg) 0x8000_0000_0000_0000u64,
                    options(noreturn),
                )
            };
        }
        MODE_ICEBP => {
            sys::print(b"[REGRESS-VICTIM] int1\r\n");
            // SAFETY: deliberately faults. `int1` (0xF1, ICEBP) raises a
            // debug exception (#DB) from ring 3 regardless of the gate's
            // privilege level.
            unsafe { core::arch::asm!(".byte 0xf1", options(nomem, nostack)) };
        }
        MODE_TF => {
            sys::print(b"[REGRESS-VICTIM] trap flag set across syscall\r\n");
            // SAFETY: deliberately faults. Setting TF from ring 3 is legal;
            // the CPU waits one instruction after POPF before it starts
            // single-stepping, so the first trap lands after `syscall`. A kernel that masks TF
            // on entry runs the syscall and returns with the caller's TF
            // restored, and the next user instruction raises #DB in ring 3.
            // The registers the CPU and the kernel stub clobber are declared.
            unsafe {
                core::arch::asm!(
                    "pushfq",
                    "or qword ptr [rsp], 0x100",
                    "popfq",
                    "syscall",
                    inout("rax") sys::SyscallNumber::GetTime as u64 => _,
                    out("rcx") _,
                    out("r11") _,
                    out("rdi") _,
                    out("rsi") _,
                    out("rdx") _,
                    out("r8") _,
                    out("r9") _,
                    out("r10") _,
                )
            };
        }
        MODE_NT => {
            sys::print(b"[REGRESS-VICTIM] nested-task flag set across a yielding syscall\r\n");
            // SAFETY: sets NT (bit 14), which ring 3 may change with POPF.
            // NT has no effect in ring 3 here; the test is whether the
            // kernel carries it into ring 0, where an `iretq` with NT set
            // faults. The stack is balanced (pushfq / popfq).
            unsafe {
                core::arch::asm!(
                    "pushfq",
                    "or qword ptr [rsp], 0x4000",
                    "popfq",
                )
            };
            sys::yield_now();
            sys::yield_now();
            sys::print(b"[REGRESS-VICTIM] yielded with NT set; exiting normally\r\n");
            sys::exit(0);
        }
        MODE_GS_SYSCALL => {
            sys::print(b"[REGRESS-VICTIM] mov gs, then a syscall\r\n");
            load_user_gs();
            let _ = sys::get_time();
            sys::print(b"[REGRESS-VICTIM] the syscall returned; exiting normally\r\n");
            sys::exit(0);
        }
        MODE_GS_TICK => {
            sys::print(b"[REGRESS-VICTIM] mov gs, then timer ticks in ring 3\r\n");
            let start = sys::get_time();
            load_user_gs();
            // No syscall until the first chunk ends: the ticks that land
            // during it interrupt ring 3 with the GS base this program set.
            for _ in 0..GS_TICK_MAX_CHUNKS {
                spin(GS_TICK_SPIN);
                if sys::get_time().wrapping_sub(start) >= GS_TICK_MIN_TICKS {
                    sys::print(b"[REGRESS-VICTIM] ticks taken in ring 3; exiting normally\r\n");
                    sys::exit(0);
                }
            }
            sys::print(b"[REGRESS-VICTIM] the clock did not advance while spinning\r\n");
            sys::exit(6);
        }
        MODE_X87 => {
            sys::print(b"[REGRESS-VICTIM] fld1 (x87)\r\n");
            // SAFETY: deliberately faults: with CR0.EM set an x87
            // instruction raises #NM. On a kernel that leaves EM clear,
            // `fld1` pushes 1.0 onto the x87 stack and `fstp st(0)` pops
            // it, so the x87 stack is as it was; no memory is touched.
            unsafe {
                core::arch::asm!("fld1", "fstp st(0)", out("st(0)") _, options(nomem, nostack))
            };
        }
        MODE_RDTSC => {
            sys::print(b"[REGRESS-VICTIM] rdtsc\r\n");
            // SAFETY: deliberately faults: with CR4.TSD set `rdtsc` is #GP
            // outside ring 0. Otherwise it writes EDX:EAX, both declared.
            unsafe {
                core::arch::asm!(
                    "rdtsc",
                    out("eax") _,
                    out("edx") _,
                    options(nomem, nostack, preserves_flags),
                )
            };
        }
        MODE_SIDT => {
            sys::print(b"[REGRESS-VICTIM] sidt\r\n");
            let mut idtr = [0u8; 10];
            // SAFETY: deliberately faults: with CR4.UMIP set `sidt` is #GP
            // outside ring 0. Otherwise it stores the 10-byte IDTR image
            // (limit, base) into `idtr`, a local buffer of exactly that size.
            unsafe {
                core::arch::asm!(
                    "sidt [{}]",
                    in(reg) idtr.as_mut_ptr(),
                    options(nostack, preserves_flags),
                )
            };
            core::hint::black_box(&idtr);
        }
        _ => unknown_mode(),
    }
}

/// Run the riscv64 sequence `mode` names. Returns only when a sequence that
/// must fault did not.
#[cfg(target_arch = "riscv64")]
fn execute(mode: u8) {
    match mode {
        MODE_TP_REAP => {
            sys::print(b"[REGRESS-VICTIM] map 16 MiB, set tp, then fault\r\n");
            let start = sys::get_time();
            if sys::allocate(TP_REAP_PAGES) <= 0 {
                sys::print(b"[REGRESS-VICTIM] allocate failed\r\n");
                sys::exit(7);
            }
            let map_ticks = sys::get_time().wrapping_sub(start);
            print_ticks(b"[REGRESS-VICTIM] mapping took ", map_ticks);
            if map_ticks < TP_REAP_MIN_MAP_TICKS {
                sys::print(b"[REGRESS-VICTIM] the mapping did not span a tick; the reap would not either\r\n");
                sys::exit(8);
            }
            // SAFETY: deliberately faults. `tp` is an ordinary user
            // register (the thread pointer; this program has no
            // thread-local storage) and nothing runs after this block, so
            // the value written to it is never used here. The store to
            // address 16 faults (page 0 is never mapped), and the kernel
            // must reap the program with `tp` still holding 0xdead0000.
            unsafe {
                core::arch::asm!("li tp, 0xdead0000", "sd zero, 16(zero)", options(noreturn, nostack))
            };
        }
        _ => unknown_mode(),
    }
}

/// Print `prefix`, a tick count in decimal, and " tick(s)".
#[cfg(target_arch = "riscv64")]
fn print_ticks(prefix: &[u8], ticks: u64) {
    // 20 digits hold any u64; filled from the right.
    let mut digits = [b'0'; 20];
    let mut i = digits.len();
    let mut n = ticks;
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    sys::print(prefix);
    sys::print(&digits[i..]);
    sys::print(b" tick(s)\r\n");
}

fn unknown_mode() -> ! {
    sys::print(b"[REGRESS-VICTIM] unknown mode\r\n");
    sys::exit(5)
}

/// Load [`USER_DATA_SELECTOR`] into GS from ring 3. A kernel that trusts
/// whatever GS base is live when it enters ring 0 then addresses its
/// per-CPU block at 0.
#[cfg(target_arch = "x86_64")]
fn load_user_gs() {
    // SAFETY: loads a selector ring 3 may load (a DPL-3 data descriptor);
    // it sets GS's base to 0, and this program never addresses through GS.
    unsafe {
        core::arch::asm!(
            "mov gs, {sel:x}",
            sel = in(reg) USER_DATA_SELECTOR,
            options(nomem, nostack, preserves_flags),
        )
    };
}

/// Count `n` down to zero in a register: ring-3 time with no syscall.
#[cfg(target_arch = "x86_64")]
fn spin(n: u64) {
    // SAFETY: a register-only loop; it touches no memory and no stack.
    unsafe {
        core::arch::asm!(
            "2:",
            "dec {n}",
            "jnz 2b",
            n = inout(reg) n => _,
            options(nomem, nostack),
        )
    };
}
