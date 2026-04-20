// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS compositor — Phase Scanout-2 (ADR-014).
//!
//! What this binary does today:
//!
//! - Registers `COMPOSITOR_ENDPOINT = 28` so the bound scanout-driver
//!   can send hotplug / frame-displayed events here.
//! - Performs the protocol handshake with the active scanout-driver:
//!   sends `RegisterCompositor` to `SCANOUT_DRIVER_ENDPOINT`, awaits
//!   `WelcomeCompositor` + `DisplayConnected`, attaches to the scanout
//!   channel, builds a `LimineFbBackend` (or falls back to
//!   `HeadlessBackend` if the handshake fails).
//! - Paints a single throwaway "first-pixels" test frame: fill the
//!   scanout buffer with a known color, submit a `FrameReady`, await
//!   the `FrameDisplayed` ack. Validates the end-to-end frame path.
//! - Enters the idle loop: poll for events, yield.
//!
//! What this binary explicitly does NOT do:
//!
//! - No hardware access. The compositor's complete kernel-syscall
//!   surface is `RegisterEndpoint`, `Print`, `Yield`, `RecvMsg`/`Write`,
//!   `Channel*`, `GetTime`. If any future change adds a hardware
//!   syscall here, the modular boundary from ADR-014 has been violated.
//! - No client surface channels yet. Lands when libgui clients exist.
//! - No window state, no focus, no input routing, no real composition
//!   path — those land with the first GUI client.

#![no_std]
#![no_main]
#![deny(unsafe_code)]
// Phase Scanout-2: most of `scanout.rs` (full trait surface, wire-format
// re-exports) exists today as the protocol contract. Real consumers
// — `VirtioGpuBackend`, `IntelGpuBackend`, full client surface plumbing
// — land in Scanout-3+ and will exercise it. Until then unused
// re-exports trip dead-code warnings; muted here.
#![allow(dead_code)]

use arcos_libsys as sys;
use arcos_libscanout::{
    decode_display_connected, encode_register_compositor, MsgTag,
    COMPOSITOR_ENDPOINT, SCANOUT_DRIVER_ENDPOINT,
};

mod scanout;
use scanout::{
    Backend, HeadlessBackend, LimineFbBackend, ScanoutBackend, ScanoutBuffer, ScanoutEvent,
};

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[COMPOSITOR] Phase Scanout-2 (ADR-014)\r\n");

    if sys::register_endpoint(COMPOSITOR_ENDPOINT) < 0 {
        sys::log_error(b"COMPOSITOR", b"register_endpoint(28) failed");
        sys::exit(1);
    }
    sys::print(b"[COMPOSITOR] registered endpoint 28\r\n");

    // Release boot gate. Shell and any other downstream module can come
    // up in parallel with the scanout handshake below.
    sys::module_ready();

    let mut backend = match handshake_with_scanout_driver() {
        Some(b) => {
            sys::print(b"[COMPOSITOR] backend bound: scanout-limine\r\n");
            b
        }
        None => {
            sys::print(b"[COMPOSITOR] handshake failed; falling back to headless\r\n");
            Backend::Headless(HeadlessBackend::new())
        }
    };

    // Throwaway first-pixels test: only fires for the LimineFbBackend
    // path. Validates the entire compositor → channel → driver memcpy →
    // FB → FrameDisplayed ack chain end-to-end. Headless skips it
    // (nothing to draw to).
    if let Backend::Limine(ref mut limine) = backend {
        run_first_pixels_test(limine);
    }

    // Render loop. Drains scanout-driver events (FrameDisplayed acks
    // mostly), no client surfaces yet, no actual composition, no
    // resubmits. The point is to stay alive — singleton compositor that
    // exits would force scanout-driver to crash on its next message.
    loop {
        let _ = backend.poll_event();
        sys::yield_now();
    }
}

// ============================================================================
// Handshake
// ============================================================================

/// Try to pair with the active scanout-driver. Returns `Some(Backend)`
/// on success; `None` if any step of the protocol failed (driver not
/// listening, malformed reply, channel attach denied).
///
/// Today only the `LimineFbBackend` is built — when virtio-gpu / Intel
/// land, the `WelcomeCompositor` reply gains a backend-kind hint and
/// this function fans out by kind.
fn handshake_with_scanout_driver() -> Option<Backend> {
    // 1. Send RegisterCompositor to the driver's endpoint.
    let mut send_buf = [0u8; 16];
    let n = encode_register_compositor(&mut send_buf)?;
    let rc = sys::write(SCANOUT_DRIVER_ENDPOINT, &send_buf[..n]);
    if rc < 0 {
        sys::print(b"[COMPOSITOR] write to scanout-driver failed\r\n");
        return None;
    }
    sys::print(b"[COMPOSITOR] sent RegisterCompositor\r\n");

    // 2. Block-recv WelcomeCompositor. Boot-gate ordering guarantees
    //    the driver registered SCANOUT_DRIVER_ENDPOINT before we sent,
    //    so blocking is fine. Future runtime hotplug will need a
    //    timed handshake (SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS) —
    //    out of scope for v0.
    let mut welcome_buf = [0u8; 320];
    let welcome = sys::recv_verified(COMPOSITOR_ENDPOINT, &mut welcome_buf)?;
    if !is_tagged(welcome.payload(), MsgTag::WelcomeCompositor) {
        sys::print(b"[COMPOSITOR] expected WelcomeCompositor, got other tag\r\n");
        return None;
    }
    sys::print(b"[COMPOSITOR] received WelcomeCompositor\r\n");

    // 3. Block-recv DisplayConnected (driver sends it immediately
    //    after Welcome in the v0 protocol).
    let mut display_buf = [0u8; 320];
    let display_msg = sys::recv_verified(COMPOSITOR_ENDPOINT, &mut display_buf)?;
    let (info, channel_id) = decode_display_connected(display_msg.payload())?;
    sys::print(b"[COMPOSITOR] received DisplayConnected\r\n");

    // 4. Attach to the scanout channel. Driver created it with role =
    //    Consumer (creator reads); compositor as peer gets RW.
    let vaddr_or_err = sys::channel_attach(channel_id);
    if vaddr_or_err < 0 {
        sys::print(b"[COMPOSITOR] channel_attach failed\r\n");
        return None;
    }
    let vaddr = vaddr_or_err as u64;

    let scanout = ScanoutBuffer {
        display_id: info.display_id,
        geometry: info.geometry,
        format: info.format,
        vaddr,
        channel_id,
    };

    Some(Backend::Limine(LimineFbBackend::from_handshake(info, scanout)))
}

fn is_tagged(payload: &[u8], expected: MsgTag) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let Ok(bytes) = payload[0..4].try_into() else { return false };
    u32::from_le_bytes(bytes) == expected.as_u32()
}

// ============================================================================
// First-pixels test (Step 7 / Scanout-2 acceptance)
// ============================================================================

/// Fill the scanout buffer with a known color, submit FrameReady, wait
/// for FrameDisplayed. Single-shot validation of the entire compositor
/// → channel → scanout-driver memcpy → FB → ack chain.
///
/// Color is bright cyan (R=0x00, G=0xB0, B=0xFF) packed into XRGB8888
/// using shifts the Limine FB advertises (R<<16, G<<8, B<<0). Visual
/// verification requires a QEMU display backend (`-display gtk` or
/// VNC); the default `-display none` configuration validates the
/// memcpy + ack but doesn't show pixels.
fn run_first_pixels_test(backend: &mut LimineFbBackend) {
    sys::print(b"[COMPOSITOR] painting test frame (cyan)\r\n");

    let scanout = backend.scanout;
    let pitch_pixels = (scanout.geometry.pitch / 4) as usize;
    let width = scanout.geometry.width as usize;
    let height = scanout.geometry.height as usize;

    // XRGB8888 with Limine's standard mask layout (R<<16, G<<8, B<<0).
    // cyan-ish pure — 0x00B0FF — chosen to be visibly non-default.
    let cyan: u32 = (0x00 << 16) | (0xB0 << 8) | 0xFF;

    // SAFETY:
    // - scanout.vaddr is the compositor's mapping of the scanout
    //   channel, returned by sys::channel_attach. Valid for
    //   `pitch * height` bytes of write access until channel_close
    //   (which we never call).
    // - We bound y < height and x < width, and pitch_pixels >= width
    //   (pitch is in bytes ≥ width * 4), so all writes stay within the
    //   mapped region.
    // - write_volatile prevents the compiler from eliding the writes
    //   (the channel is a different process's read-side; from this
    //   process's POV the compiler sees no observers and would
    //   otherwise dead-code the loop).
    #[allow(unsafe_code)]
    unsafe {
        let base = scanout.vaddr as *mut u32;
        for y in 0..height {
            let row = base.add(y * pitch_pixels);
            for x in 0..width {
                row.add(x).write_volatile(cyan);
            }
        }
    }

    sys::print(b"[COMPOSITOR] submitting FrameReady (full surface)\r\n");
    if backend.submit_frame(scanout.display_id, &[]).is_err() {
        sys::print(b"[COMPOSITOR] submit_frame failed\r\n");
        return;
    }

    // Wait for FrameDisplayed. ~1000 yields with no ack ≈ stall —
    // useful diagnostic, not a real timeout (real backpressure logic
    // lands with sustained rendering).
    for _ in 0..1000 {
        if let Some(ScanoutEvent::FrameDisplayed { .. }) = backend.poll_event() {
            sys::print(b"[COMPOSITOR] FrameDisplayed received -- first-pixels test PASSED\r\n");
            return;
        }
        sys::yield_now();
    }
    sys::print(b"[COMPOSITOR] FrameDisplayed timeout -- test INCONCLUSIVE\r\n");
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"COMPOSITOR", b"panic");
    sys::exit(255);
}
