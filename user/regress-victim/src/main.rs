// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors

//! regress-victim — the regression probe's hostile child (ADR-040
//! § Sequencing).
//!
//! The probe spawns this program, waits for it to say it is listening,
//! and sends it one byte naming a hostile instruction: one a program can
//! execute in ring 3 and that once halted the whole kernel. This program
//! executes it. A correct kernel reaps it for the fault, and the probe
//! checks that it was reaped and that the kernel kept running.
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
const MODE_UD: u8 = 1;
const MODE_SS: u8 = 2;
const MODE_ICEBP: u8 = 3;

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
        _ => {
            sys::print(b"[REGRESS-VICTIM] unknown mode\r\n");
            sys::exit(5);
        }
    }
    sys::print(b"[REGRESS-VICTIM] BUG: the instruction did not fault\r\n");
    sys::exit(2)
}
