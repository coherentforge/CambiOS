// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS hello-window — first `arcos-libgui` client (ADR-011).
//!
//! Post-libgui-v0 form: the compositor handshake, channel attach,
//! pixel fill, and FrameReady submit are all one call each through
//! `arcos-libgui`. Previously this binary open-coded the protocol
//! (~100 lines of `sys::write` / `sys::recv_verified` / manual
//! pointer fill); now it's ~20 lines of libgui calls and exercises
//! every v0 primitive (rect fill, line, text, tile grid).
//!
//! Visible behaviour is unchanged: a 640×480 window filled with
//! bright green over the compositor's test frame, now with a few
//! extra visual proof-points (a white border line, an "HELLO LIBGUI"
//! text label, and a small 4×3 tile grid) so a regression in any
//! libgui primitive is visible without opening the debugger.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libgui::{Client, Color, Rect, TileGrid};
use arcos_libsys as sys;

const HELLO_WINDOW_ENDPOINT: u32 = 29;
const WINDOW_WIDTH: u32 = 640;
const WINDOW_HEIGHT: u32 = 480;

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[HELLO-WINDOW] libgui v0 client\r\n");

    // hello-window is a leaf boot module — release the boot gate
    // immediately so the next module (shell) can start, in parallel
    // with our compositor handshake. (`libgui::Client` intentionally
    // does NOT call `module_ready`; that's a boot-ordering concern
    // orthogonal to what libgui wraps.)
    sys::module_ready();

    let mut client = match Client::open(WINDOW_WIDTH, WINDOW_HEIGHT, HELLO_WINDOW_ENDPOINT) {
        Ok(c) => c,
        Err(_) => {
            sys::log_error(b"HELLO-WINDOW", b"Client::open failed");
            sys::exit(1);
        }
    };
    sys::print(b"[HELLO-WINDOW] window opened, drawing\r\n");

    let w = client.width();
    let h = client.height();
    {
        let mut surf = client.surface_mut();

        // Fill background bright green (preserves the visual
        // contract from the open-coded Scanout-3 hello-window).
        surf.clear(Color::rgb(0x00, 0xC8, 0x00));

        // White border — exercises draw_line on long horizontals
        // and verticals.
        surf.draw_line(0, 0, (w - 1) as i32, 0, Color::WHITE);
        surf.draw_line(0, (h - 1) as i32, (w - 1) as i32, (h - 1) as i32, Color::WHITE);
        surf.draw_line(0, 0, 0, (h - 1) as i32, Color::WHITE);
        surf.draw_line((w - 1) as i32, 0, (w - 1) as i32, (h - 1) as i32, Color::WHITE);

        // Inset black panel behind the text so glyphs are readable
        // against the green.
        surf.fill_rect(Rect { x: 16, y: 16, w: 120, h: 32 }, Color::BLACK);
        surf.draw_text_builtin(24, 24, "HELLO LIBGUI", Color::WHITE);

        // A small 4×3 tile grid below — the "I could build Tree on
        // top of this" canary. Each tile filled red, outlined white.
        let grid = TileGrid::new(16, 64, 24, 24, 4, 3, 4);
        for (_col, _row, rect) in grid.iter() {
            surf.fill_rect(rect, Color::RED);
            let x0 = rect.x as i32;
            let y0 = rect.y as i32;
            let x1 = x0 + rect.w as i32 - 1;
            let y1 = y0 + rect.h as i32 - 1;
            surf.draw_line(x0, y0, x1, y0, Color::WHITE);
            surf.draw_line(x0, y1, x1, y1, Color::WHITE);
            surf.draw_line(x0, y0, x0, y1, Color::WHITE);
            surf.draw_line(x1, y0, x1, y1, Color::WHITE);
        }
    }

    if client.submit_full().is_err() {
        sys::log_error(b"HELLO-WINDOW", b"submit_full failed");
        sys::exit(1);
    }
    sys::print(b"[HELLO-WINDOW] frame submitted -- window visible\r\n");

    // Idle forever — keep the surface channel alive so the
    // compositor can keep reading it. A real app with an event
    // loop would redraw on events; v0 drew once.
    loop {
        sys::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"HELLO-WINDOW", b"panic");
    sys::exit(255);
}
