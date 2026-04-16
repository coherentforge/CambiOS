// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS compositor — Phase Scanout-1 scaffold (ADR-014).
//!
//! What this binary does today:
//!
//! - Registers `COMPOSITOR_ENDPOINT = 28` so a future scanout-driver can
//!   send hotplug / frame-displayed events here.
//! - Logs a boot banner naming itself.
//! - Selects a `ScanoutBackend` — for Scanout-1 always `HeadlessBackend`
//!   because no scanout-driver service exists yet.
//! - Enters the no-op render loop: yield, drain incoming IPC (currently
//!   nothing arrives), repeat.
//!
//! What this binary explicitly does NOT do:
//!
//! - No hardware access, no `MapMmio`, no `MapFramebuffer`, no `AllocDma`.
//!   The compositor's complete kernel-syscall surface is `RegisterEndpoint`,
//!   `Print`, `Yield`, `RecvMsg`/`Write`, `Channel*`, `GetTime`. If any
//!   future change adds a hardware syscall here, the modular boundary
//!   from ADR-014 has been violated.
//! - No client surface channels yet. Lands when the protocol-side
//!   handshake plus a scanout-driver exists to render to (Scanout-2/3).
//! - No window state, no focus, no input routing. Same — those land when
//!   there is somewhere to draw and someone to draw for.
//!
//! The point of Scanout-1 is to prove the process scaffold loads, registers
//! the endpoint, and idles cleanly without disturbing the rest of the boot.

#![no_std]
#![no_main]
// Phase Scanout-1 scaffold: most of `scanout.rs` (trait surface, wire-format
// types, capability-negotiation enums) exists today as the protocol contract
// from ADR-014. Real consumers — `VirtioGpuBackend`, `IntelGpuBackend`,
// `LimineFbBackend` — land in Scanout-2 onward and will exercise it. Until
// then `HeadlessBackend` is the only impl, so `dead_code` flags everything
// else. Re-enable the lint once the first non-headless backend ships.
#![allow(dead_code)]

use arcos_libsys as sys;

mod scanout;

use scanout::{COMPOSITOR_ENDPOINT, HeadlessBackend, ScanoutBackend};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[COMPOSITOR] Phase Scanout-1 scaffold (ADR-014)\r\n");

    let rc = sys::register_endpoint(COMPOSITOR_ENDPOINT);
    if rc < 0 {
        sys::log_error(b"COMPOSITOR", b"failed to register endpoint 28");
        sys::exit(1);
    }
    sys::print(b"[COMPOSITOR] registered endpoint 28\r\n");

    // For Scanout-1, no scanout-driver exists yet, so we go straight to
    // headless. When scanout-drivers ship (Scanout-2 onward), this becomes
    // a wait-for-handshake-then-bind sequence per ADR-014 § Connection
    // topology, with `SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS` governing
    // when the headless fallback fires.
    let mut backend: HeadlessBackend = HeadlessBackend::new();
    sys::print(b"[COMPOSITOR] headless mode (no scanout-driver bound)\r\n");

    // Release the next boot module from its BootGate. Our "initial setup"
    // is endpoint registration + backend selection, both done above.
    // Without this call the boot chain stalls here and the shell never
    // starts. Per the kernel's sequential-startup contract (see the
    // limine.conf comment + kernel docs for SYS_MODULE_READY).
    sys::module_ready();

    // The no-op render loop. For Scanout-1 there is nothing to render —
    // no clients are connected, the headless backend has zero displays,
    // and no events arrive. The loop exists so the process stays alive
    // (a singleton-by-Principal compositor that exits would force any
    // future scanout-driver to crash on first message). When real work
    // exists, this loop becomes:
    //   1. drain client window-mgmt IPC (RecvMsg on COMPOSITOR_ENDPOINT)
    //   2. drain scanout-driver events (backend.poll_event())
    //   3. composite dirty windows per output
    //   4. backend.submit_frame() per dirty output
    //   5. yield (or sleep until next frame deadline)
    loop {
        let _ = backend.poll_event();   // None today; will be the event drain
        sys::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"COMPOSITOR", b"panic");
    sys::exit(255);
}
