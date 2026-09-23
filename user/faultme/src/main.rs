// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! faultme — the ADR-019 fault-reap fixture.
//!
//! An on-demand manifest entry (`faultme` at the shell) whose entire job
//! is to take a user-mode page fault. The kernel must reap it exactly
//! like a clean exit — parent unblocked, resources reclaimed, a
//! `proc.faulted` audit event — and the system must carry on. Running
//! it twice in a row is the leak test: the second spawn reuses what the
//! first one's reap freed.
//!
//! Page 0 is never mapped in a CambiOS user address space (code starts
//! at 0x400000), so a store there faults on every architecture.

#![no_std]
#![no_main]

use cambios_libsys as sys;

cambios_libsys_rt::service_main! {
    name: "FAULTME",
    main: run,
}

fn run() -> ! {
    sys::print(b"[FAULTME] about to store to an unmapped page on purpose\r\n");
    // On-demand app: the readiness ping is fire-and-forget, init discards it.
    cambios_libsys_rt::ready();

    let unmapped = 0x10 as *mut u32;
    // SAFETY: deliberately NOT safe — this store must fault. The pointer
    // targets page 0, which the loader never maps, so the only possible
    // outcome is a page fault the kernel turns into a reap. Nothing is
    // read back; no other memory is touched.
    unsafe { core::ptr::write_volatile(unmapped, 0xDEAD_BEEF) };

    sys::print(b"[FAULTME] BUG: the store did not fault\r\n");
    sys::exit(2)
}
