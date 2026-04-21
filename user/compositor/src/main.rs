// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS compositor — Phase Scanout-3 (ADR-011 § surface channel + ADR-014).
//!
//! What this binary does today:
//!
//! - Registers `COMPOSITOR_ENDPOINT = 28` — single endpoint shared by
//!   the scanout-driver (tag prefix 0x20xx) and clients (tag prefix
//!   0x30xx). Incoming messages are dispatched by tag high nibble.
//! - Performs the protocol handshake with the active scanout-driver:
//!   sends `RegisterCompositor` to `SCANOUT_DRIVER_ENDPOINT`, awaits
//!   `WelcomeCompositor` + `DisplayConnected`, attaches to the scanout
//!   channel, builds a `LimineFbBackend` (or falls back to
//!   `HeadlessBackend`).
//! - Paints a single throwaway "first-pixels" test frame: fills the
//!   scanout buffer with a known color, submits a `FrameReady`,
//!   awaits the `FrameDisplayed` ack. End-to-end validation of the
//!   back path.
//! - Enters the main dispatch loop:
//!     * `try_recv_msg` on ep28
//!     * peek tag direction: 0x2x → scanout-driver event (backend
//!       decodes), 0x3x → client request (windows::dispatch)
//!     * on client FrameReady, blit surface into scanout + forward
//!       `FrameReady` downstream to the scanout-driver
//!
//! What this binary explicitly does NOT do:
//!
//! - No hardware access. The compositor's complete kernel-syscall
//!   surface is `RegisterEndpoint`, `Print`, `Yield`, `RecvMsg`/`Write`,
//!   `Channel*`, `GetTime`. If any future change adds a hardware
//!   syscall here, the modular boundary from ADR-014 has been violated.
//! - No z-order, no focus, no input routing, no damage-tracked partial
//!   composition — those land in Scanout-4+. Scanout-3 is: one window,
//!   full-surface blit, prove the pipe.

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
mod windows;
use scanout::{
    Backend, HeadlessBackend, LimineFbBackend, ScanoutBackend, ScanoutBuffer, ScanoutEvent,
};
use windows::{handle_client_payload, WindowTable, WindowView};

/// Maximum IPC receive buffer size for the main dispatch loop.
/// Sized to hold the largest libgui-proto message (FrameReady with
/// 16 damage rects = 144 bytes) plus the 36-byte `recv_msg` header.
/// 320 bytes leaves room to grow.
const DISPATCH_BUFFER_BYTES: usize = 320;

/// Bytes the kernel prepends to a `recv_msg` / `try_recv_msg` result:
/// 32-byte sender_principal + 4-byte from_endpoint.
const RECV_HEADER_BYTES: usize = 36;

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[COMPOSITOR] Phase Scanout-2 (ADR-014)\r\n");

    if sys::register_endpoint(COMPOSITOR_ENDPOINT) < 0 {
        sys::log_error(b"COMPOSITOR", b"register_endpoint(28) failed");
        sys::exit(1);
    }
    sys::print(b"[COMPOSITOR] registered endpoint 28\r\n");

    // Boot-gate ordering: do the scanout handshake BEFORE calling
    // `module_ready()`. Downstream modules include hello-window
    // (Scanout-3), which immediately sends `CreateWindow` to ep28 —
    // if it arrives while we're blocked in `recv_verified` for
    // `WelcomeCompositor`, the handshake reads the client message
    // instead of the scanout-driver's reply and fails with
    // "expected WelcomeCompositor, got other tag". Serialising the
    // gate resolves the race; shell is a leaf that doesn't touch the
    // compositor so the ~1 handshake RTT delay is harmless.
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
    let mut window_table = WindowTable::new();
    if let Backend::Limine(ref mut limine) = backend {
        run_first_pixels_test(limine);
    }

    // Release the boot gate now. hello-window and any other clients
    // can start sending CreateWindow messages; the dispatch loop is
    // next.
    sys::module_ready();

    // Main dispatch loop. Drains scanout-driver events (FrameDisplayed
    // acks today, hotplug in future) *and* client requests
    // (CreateWindow, FrameReady, DestroyWindow) — both arrive on ep28,
    // distinguished by MsgTag high nibble.
    //
    // Scanout-3c: on client FrameReady we blit the surface into the
    // scanout buffer and forward FrameReady to the scanout-driver.
    // v0 is single-window, no z-order, no damage tracking — full
    // surface copy every frame.
    loop {
        let outcome = pump_dispatch_once(&mut backend, &mut window_table);
        if let DispatchOutcome::ClientFrame(view) = outcome {
            composite_and_present(&mut backend, &view);
        }
        sys::yield_now();
    }
}

// ============================================================================
// Dispatch
// ============================================================================

/// One tick's worth of work from the central dispatch. Returned by
/// [`pump_dispatch_once`] so the caller decides what to do next
/// (composite, log, etc.) without pushing composition state down into
/// either protocol module.
#[derive(Clone, Copy, Debug)]
enum DispatchOutcome {
    Idle,
    ScanoutEvent(ScanoutEvent),
    /// Client submitted a FrameReady — this is the window whose
    /// surface should now be blitted into the scanout buffer.
    ClientFrame(WindowView),
}

/// Core dispatch tick: try to pull one message from `COMPOSITOR_ENDPOINT`
/// and route it by tag direction. Non-blocking.
fn pump_dispatch_once<B: ScanoutBackend>(
    backend: &mut B,
    window_table: &mut WindowTable,
) -> DispatchOutcome {
    let mut buf = [0u8; DISPATCH_BUFFER_BYTES];
    let n = sys::try_recv_msg(COMPOSITOR_ENDPOINT, &mut buf);
    if n <= 0 {
        return DispatchOutcome::Idle;
    }
    let total = n as usize;
    if total < RECV_HEADER_BYTES + 4 {
        return DispatchOutcome::Idle;
    }
    let mut sender_principal = [0u8; 32];
    sender_principal.copy_from_slice(&buf[0..32]);
    let from_endpoint = match buf[32..36].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return DispatchOutcome::Idle,
    };
    let payload = &buf[RECV_HEADER_BYTES..total];

    let tag_raw = match payload[0..4].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return DispatchOutcome::Idle,
    };
    // High nibble of the tag. Symmetric with libscanout's 0x10xx/0x20xx
    // and libgui-proto's 0x30xx/0x40xx.
    match tag_raw >> 12 {
        0x2 => match backend.handle_scanout_payload(payload) {
            Some(evt) => DispatchOutcome::ScanoutEvent(evt),
            None => DispatchOutcome::Idle,
        },
        0x3 => match handle_client_payload(payload, &sender_principal, from_endpoint, window_table) {
            Some(view) => DispatchOutcome::ClientFrame(view),
            None => DispatchOutcome::Idle,
        },
        _ => DispatchOutcome::Idle,
    }
}

// ============================================================================
// Composite + present
// ============================================================================

/// Blit a window's surface into the bound scanout buffer and forward
/// a `FrameReady` to the scanout-driver. v0 is:
///
/// - Single window, origin-aligned (blits to (0,0) in scanout).
/// - Full-surface copy (no damage tracking).
/// - Destination clipped to the intersection of window geometry and
///   scanout geometry; anything past the scanout edge is dropped.
/// - Pixel format is assumed compatible (XRGB8888 for both surface
///   and scanout). Format-mismatch swizzling lands once virtio-gpu /
///   Intel backends advertise alternate formats.
///
/// Only meaningful against a `Backend::Limine` backend today; headless
/// has no scanout buffer to blit to.
fn composite_and_present(backend: &mut Backend, view: &WindowView) {
    let scanout = match backend {
        Backend::Limine(b) => b.scanout,
        Backend::Headless(_) => return,
    };
    blit_surface_to_scanout(view, &scanout);
    if backend.submit_frame(scanout.display_id, &[]).is_err() {
        sys::print(b"[COMPOSITOR] submit_frame (client) failed\r\n");
        return;
    }
    sys::print(b"[COMPOSITOR] composited client frame\r\n");
}

/// Copy a window surface (XRGB8888, pitch bytes per row) into the
/// scanout buffer at origin (0, 0). Both mappings are owned by this
/// process via channel_attach, so direct pointer writes are safe; the
/// kernel enforced RW on the channel mapping at attach time.
fn blit_surface_to_scanout(view: &WindowView, scanout: &ScanoutBuffer) {
    let sw = view.width as usize;
    let sh = view.height as usize;
    let src_pitch_pixels = (view.pitch / 4) as usize;

    let dst_w = scanout.geometry.width as usize;
    let dst_h = scanout.geometry.height as usize;
    let dst_pitch_pixels = (scanout.geometry.pitch / 4) as usize;

    let copy_w = sw.min(dst_w);
    let copy_h = sh.min(dst_h);

    // SAFETY:
    // - `view.surface_vaddr` was obtained from `channel_create`
    //   (compositor is Consumer, maps RW). Valid for `pitch × height`
    //   bytes.
    // - `scanout.vaddr` was obtained from `channel_attach` on the
    //   scanout channel (compositor peer, maps RW). Valid for
    //   `pitch × height` bytes.
    // - Bounded loops: `copy_h ≤ dst_h ≤ scanout height`,
    //   `copy_w ≤ dst_w ≤ scanout width`, and src strides are the
    //   client's declared pitch/height — the compositor trusted the
    //   declared geometry when allocating the channel, and the kernel
    //   enforced the channel size bound.
    // - `write_volatile` is used because the source and destination
    //   are shared memory; the compiler must not re-order or elide.
    #[allow(unsafe_code)]
    unsafe {
        let src_base = view.surface_vaddr as *const u32;
        let dst_base = scanout.vaddr as *mut u32;
        for y in 0..copy_h {
            let src_row = src_base.add(y * src_pitch_pixels);
            let dst_row = dst_base.add(y * dst_pitch_pixels);
            for x in 0..copy_w {
                let pixel = core::ptr::read_volatile(src_row.add(x));
                core::ptr::write_volatile(dst_row.add(x), pixel);
            }
        }
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
    // lands with sustained rendering). We use a disposable
    // WindowTable here; the test runs before any clients exist, so
    // no client payloads are possible.
    let mut scratch_table = WindowTable::new();
    for _ in 0..1000 {
        if let DispatchOutcome::ScanoutEvent(ScanoutEvent::FrameDisplayed { .. }) =
            pump_dispatch_once(backend, &mut scratch_table)
        {
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
