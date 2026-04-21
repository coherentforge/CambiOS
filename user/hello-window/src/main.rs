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

use arcos_libgui::{button, Client, Color, EventType, InputEvent, Rect, TileGrid};
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

    // Event loop — poll for input events from the compositor and
    // log them to serial. This is the libgui v0 event-loop shape:
    // drain events in a tight inner loop, yield when idle. A real app
    // re-draws on events; Tree will.
    //
    // Logging format (observable in `make run-gui` serial):
    //   [HW] K:down hid=0x04 mod=0x02     # 'A' with LeftShift
    //   [HW] K:up   hid=0x04 mod=0x00
    //   [HW] Pmove dx=3 dy=-2
    //   [HW] Pbtn  buttons=0x01            # left button down
    sys::print(b"[HELLO-WINDOW] entering event loop\r\n");
    loop {
        let mut drained = false;
        while let Some(ev) = client.poll_event() {
            drained = true;
            log_event(&ev);
        }
        if !drained {
            sys::yield_now();
        }
    }
}

fn log_event(ev: &InputEvent) {
    match ev.event_type {
        EventType::KeyDown => {
            sys::print(b"[HW] K:down hid=");
            print_hex(ev.keyboard().keycode as u64);
            sys::print(b" mod=");
            print_hex(ev.keyboard().modifiers as u64);
            sys::print(b"\r\n");
        }
        EventType::KeyUp => {
            sys::print(b"[HW] K:up   hid=");
            print_hex(ev.keyboard().keycode as u64);
            sys::print(b"\r\n");
        }
        EventType::KeyRepeat => {
            sys::print(b"[HW] K:rep  hid=");
            print_hex(ev.keyboard().keycode as u64);
            sys::print(b"\r\n");
        }
        EventType::PointerMove => {
            let p = ev.pointer();
            sys::print(b"[HW] Pmove dx=");
            print_int(p.dx as i64);
            sys::print(b" dy=");
            print_int(p.dy as i64);
            sys::print(b"\r\n");
        }
        EventType::PointerButton => {
            let p = ev.pointer();
            sys::print(b"[HW] Pbtn  buttons=");
            print_hex(p.buttons as u64);
            if p.buttons & button::LEFT != 0 {
                sys::print(b" (left)");
            }
            sys::print(b"\r\n");
        }
        EventType::PointerScroll => {
            let p = ev.pointer();
            sys::print(b"[HW] Pscroll sy=");
            print_int(p.scroll_y as i64);
            sys::print(b"\r\n");
        }
        _ => {}
    }
}

fn print_hex(v: u64) {
    sys::print(b"0x");
    let mut buf = [0u8; 16];
    let mut n = v;
    for i in 0..16 {
        let nib = (n & 0xF) as u8;
        buf[15 - i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        n >>= 4;
    }
    // Trim leading zeros for readability, but keep at least two digits.
    let mut start = 0;
    while start < 14 && buf[start] == b'0' {
        start += 1;
    }
    sys::print(&buf[start..]);
}

fn print_int(v: i64) {
    if v < 0 {
        sys::print(b"-");
        print_u64_dec((-v) as u64);
    } else {
        print_u64_dec(v as u64);
    }
}

fn print_u64_dec(n: u64) {
    if n == 0 {
        sys::print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut m = n;
    let mut len = 0;
    while m > 0 {
        buf[len] = b'0' + (m % 10) as u8;
        m /= 10;
        len += 1;
    }
    let mut out = [0u8; 20];
    for i in 0..len {
        out[i] = buf[len - 1 - i];
    }
    sys::print(&out[..len]);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"HELLO-WINDOW", b"panic");
    sys::exit(255);
}
