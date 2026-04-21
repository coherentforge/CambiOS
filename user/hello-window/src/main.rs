// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS hello-window — Phase Scanout-3 (ADR-011).
//!
//! First GUI client. Minimum-viable client that proves the end-to-end
//! pipe from a userspace application through the compositor to pixels
//! on the display. The contract:
//!
//! 1. `_start` → register endpoint 29 (so the compositor can reply),
//!    signal `module_ready`.
//! 2. Send [`CreateWindow`] to the compositor's well-known endpoint
//!    (`COMPOSITOR_ENDPOINT = 28`). Request a 640×480 window — small
//!    enough to not cover the whole QEMU FB so the cyan "first-pixels"
//!    test frame underneath stays visible (useful debug cue).
//! 3. Block on [`recv_verified`] for [`WelcomeClient`]. Extract
//!    `window_id`, `channel_id`, and surface geometry.
//! 4. [`channel_attach`] the surface channel. Surface is
//!    `ChannelRole::Consumer` from the compositor's perspective, so
//!    we're the Producer → map is writable.
//! 5. Fill the surface with a solid color (bright green 0x00C800 in
//!    XRGB8888).
//! 6. Send [`FrameReady`] — no damage rects = "full surface dirty".
//! 7. Idle loop. Real clients redraw; this one drew once.
//!
//! What this binary explicitly does NOT do:
//!
//! - No widgets, no layout, no text. libgui wraps this protocol in
//!   widget-tree semantics later.
//! - No input handling. Scanout-3 doesn't wire input; nothing drives
//!   a mouse cursor yet.
//! - No graceful shutdown. Process stays alive so the window stays
//!   visible — exiting would close the channel and the compositor
//!   would tear the window down.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libgui_proto::{
    decode_welcome_client, encode_create_window, encode_frame_ready, COMPOSITOR_ENDPOINT,
};
use arcos_libsys as sys;

/// This client's reply endpoint. The kernel's `REPLY_ENDPOINT`
/// registry records the first endpoint a process registers and uses
/// it as the `from_endpoint` on outbound messages — so the compositor
/// gets this number stamped on every CreateWindow / FrameReady we
/// send, and replies land back here.
///
/// SCAFFOLDING: hard-coded endpoint numbers for demo clients are a
/// v0 shortcut. Real clients will pick an endpoint from a dynamic
/// pool when the user-space endpoint service lands.
/// Replace when: first non-boot-module GUI client needs a window.
const HELLO_WINDOW_ENDPOINT: u32 = 29;

/// Target window dimensions (pixels). 640×480 chosen to fit within
/// the QEMU default 1280×800 FB with the cyan "first-pixels" cyan
/// frame still visible around it — a useful visual cue when
/// debugging.
const WINDOW_WIDTH: u32 = 640;
const WINDOW_HEIGHT: u32 = 480;

/// Bright green in XRGB8888: R=0x00, G=0xC8, B=0x00 packed as
/// `(R << 16) | (G << 8) | B`. Saturated-but-not-neon, easy to pick
/// out against a cyan or black background.
const FILL_COLOR: u32 = (0x00 << 16) | (0xC8 << 8) | 0x00;

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[HELLO-WINDOW] Phase Scanout-3 (ADR-011)\r\n");

    if sys::register_endpoint(HELLO_WINDOW_ENDPOINT) < 0 {
        sys::log_error(b"HELLO-WINDOW", b"register_endpoint(29) failed");
        sys::exit(1);
    }
    sys::print(b"[HELLO-WINDOW] registered endpoint 29\r\n");

    // Release the boot gate. hello-window is a leaf client — no other
    // module waits on us — so signalling ready immediately unblocks
    // the next module in BOOT_MODULE_ORDER.
    sys::module_ready();

    // --- 1. Send CreateWindow ---
    let mut send_buf = [0u8; 16];
    let n = match encode_create_window(&mut send_buf, WINDOW_WIDTH, WINDOW_HEIGHT) {
        Some(n) => n,
        None => {
            sys::print(b"[HELLO-WINDOW] encode_create_window failed\r\n");
            sys::exit(1);
        }
    };
    if sys::write(COMPOSITOR_ENDPOINT, &send_buf[..n]) < 0 {
        sys::print(b"[HELLO-WINDOW] write CreateWindow failed\r\n");
        sys::exit(1);
    }
    sys::print(b"[HELLO-WINDOW] sent CreateWindow 640x480\r\n");

    // --- 2. Block for WelcomeClient ---
    let mut recv_buf = [0u8; 128];
    let welcome = match sys::recv_verified(HELLO_WINDOW_ENDPOINT, &mut recv_buf) {
        Some(v) => v,
        None => {
            sys::print(b"[HELLO-WINDOW] recv_verified failed\r\n");
            sys::exit(1);
        }
    };
    let msg = match decode_welcome_client(welcome.payload()) {
        Some(m) => m,
        None => {
            sys::print(b"[HELLO-WINDOW] decode_welcome_client failed\r\n");
            sys::exit(1);
        }
    };
    sys::print(b"[HELLO-WINDOW] received WelcomeClient\r\n");

    // --- 3. Attach to surface channel ---
    let vaddr_or_err = sys::channel_attach(msg.channel_id);
    if vaddr_or_err < 0 {
        sys::print(b"[HELLO-WINDOW] channel_attach failed\r\n");
        sys::exit(1);
    }
    let surface_vaddr = vaddr_or_err as u64;
    sys::print(b"[HELLO-WINDOW] attached surface channel\r\n");

    // --- 4. Paint the surface solid green ---
    // SAFETY:
    // - `surface_vaddr` is this process's mapping of the surface
    //   channel, returned by `channel_attach`. The peer role
    //   (compositor created as Consumer, we're the Producer) grants
    //   us RW access for the full size agreed at create time.
    // - Pitch × height is the bound the compositor allocated,
    //   advertised back to us in WelcomeClient. Loops are bounded by
    //   it.
    // - `write_volatile` prevents the compiler from eliding the
    //   fill — the compositor reads this memory from another
    //   process, and from our POV there's no local observer.
    let pitch_pixels = (msg.pitch / 4) as usize;
    let width = msg.width as usize;
    let height = msg.height as usize;
    #[allow(unsafe_code)]
    unsafe {
        let base = surface_vaddr as *mut u32;
        for y in 0..height {
            let row = base.add(y * pitch_pixels);
            for x in 0..width {
                row.add(x).write_volatile(FILL_COLOR);
            }
        }
    }
    sys::print(b"[HELLO-WINDOW] surface painted green\r\n");

    // --- 5. Submit FrameReady (full surface dirty) ---
    let mut fr_buf = [0u8; 32];
    let n = match encode_frame_ready(&mut fr_buf, msg.window_id, /* seq */ 0, &[]) {
        Some(n) => n,
        None => {
            sys::print(b"[HELLO-WINDOW] encode_frame_ready failed\r\n");
            sys::exit(1);
        }
    };
    if sys::write(COMPOSITOR_ENDPOINT, &fr_buf[..n]) < 0 {
        sys::print(b"[HELLO-WINDOW] write FrameReady failed\r\n");
        sys::exit(1);
    }
    sys::print(b"[HELLO-WINDOW] sent FrameReady -- window should now be visible\r\n");

    // --- 6. Idle forever ---
    // Keep the channel alive so the surface stays readable by the
    // compositor. A real client re-draws on events; we drew once.
    loop {
        sys::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"HELLO-WINDOW", b"panic");
    sys::exit(255);
}
