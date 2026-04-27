// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Tree — first-party Minesweeper-homage app (ADR-011 stack,
//! ADR-012 input, libgui v0). A 9×9 plot of grass; dig up the dirt,
//! avoid the trees. Reveals a tree: boo — deforestation. Reveals
//! every non-tree cell: ahh — reforestation. Press R or Escape to
//! restart.
//!
//! Long-term vision captured to keep v0 choices honest: on a
//! successful solve, Tree fades into an immersive 3D forest that
//! fills the display. V0 does not do any of that — but the layering
//! (pure `game` module, separate `render`, main.rs as orchestration)
//! is chosen so a future 3D renderer can replace `render::draw`
//! without touching game logic.
//! Revisit when: the 2D game is played end-to-end enough that a
//! second visible reward beyond the end-state text panel is
//! observably missing, AND there's a 3D renderer to swap in.
//!
//! ## V0 control flow
//!
//! 1. Handshake via `libgui::Client::open(352, 392, TREE_ENDPOINT)`.
//! 2. Draw initial frame, submit.
//! 3. Loop:
//!    - Drain all `client.poll_event()`s into state changes.
//!    - Recompute hovered tile from accumulated cursor position.
//!    - If state (board / hover / cursor location) changed since the
//!      last draw, redraw + `submit_full()`.
//!    - If no events drained, `sys::yield_now()`.
//!
//! ## No new kernel syscalls
//!
//! Per ADR-011 the stack goal is to prove real apps work over libgui
//! + libsys. Tree must not introduce a kernel-side change to ship.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use cambios_libgui::{button, modifier, Client, EventType, InputEvent};
use cambios_libsys as sys;

mod game;
mod render;
mod sprites;

use game::{Board, RevealOutcome, State};

const TREE_ENDPOINT: u32 = 31;

/// HID usage codes we care about. Full evdev→HID table lives in
/// `user/virtio-input/src/evdev.rs`; we re-declare only the two we
/// bind (plus R as a value) to keep the driver-app coupling narrow.
mod keys {
    pub const R: u32 = 0x15;
    pub const ESCAPE: u32 = 0x29;
    // Exit: Ctrl+Q returns control to the shell that spawned us.
    pub const Q: u32 = 0x14;
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[TREE] booting\r\n");

    // Leaf boot module — release the boot gate immediately, before
    // the compositor handshake. hello-window does the same; lets the
    // next module in limine.conf (shell) start in parallel with our
    // CreateWindow round-trip.
    sys::module_ready();

    let mut client = match Client::open(render::WINDOW_W, render::WINDOW_H, TREE_ENDPOINT) {
        Ok(c) => c,
        Err(_) => {
            sys::log_error(b"TREE", b"Client::open failed");
            sys::exit(1);
        }
    };
    sys::print(b"[TREE] window opened\r\n");

    // Seed the board RNG from time+pid so reboots don't all produce
    // the same board. Both calls are cheap and non-blocking.
    let seed = sys::get_time() ^ ((sys::get_pid() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut board = Board::new(seed);

    // Cursor is integrated from relative PointerMove deltas; QEMU's
    // virtio-mouse is a relative device. Start in window center;
    // clamp to window bounds on every update.
    let mut cursor_x: i32 = render::WINDOW_W as i32 / 2;
    let mut cursor_y: i32 = render::WINDOW_H as i32 / 2;

    // Last-drawn hovered tile + cursor pixel position; comparing
    // against the current frame's values decides whether a
    // PointerMove needs a redraw. Initialised from the first paint
    // so the loop's first iteration only redraws if something
    // actually moved.
    let mut last_hovered = tile_at_cursor(cursor_x, cursor_y);
    let mut last_cursor = (cursor_x, cursor_y);

    // Initial paint.
    redraw(&mut client, &board, last_hovered, last_cursor);

    sys::print(b"[TREE] entering event loop\r\n");
    loop {
        let mut changed = false;
        let mut drained = false;
        while let Some(ev) = client.poll_event() {
            drained = true;
            if handle_event(&ev, &mut board, &mut cursor_x, &mut cursor_y, &client) {
                changed = true;
            }
        }

        let hovered = tile_at_cursor(cursor_x, cursor_y);
        let cursor_moved = (cursor_x, cursor_y) != last_cursor;
        let hover_moved = hovered != last_hovered;

        if changed || cursor_moved || hover_moved {
            redraw(&mut client, &board, hovered, (cursor_x, cursor_y));
            last_hovered = hovered;
            last_cursor = (cursor_x, cursor_y);
        }

        if !drained {
            sys::yield_now();
        }
    }
}

/// Apply one input event to the game + cursor state. Returns true if
/// the *board* state changed (reveal, flag, reset) — cursor and hover
/// movement are tracked separately so a bare mouse wiggle doesn't
/// force a game-state redraw flag, though it does still produce a
/// visual redraw because the crosshair / hover outline moved.
fn handle_event(
    ev: &InputEvent,
    board: &mut Board,
    cursor_x: &mut i32,
    cursor_y: &mut i32,
    client: &Client,
) -> bool {
    match ev.event_type {
        EventType::PointerMove => {
            let p = ev.pointer();
            *cursor_x = (*cursor_x + p.dx).clamp(0, render::WINDOW_W as i32 - 1);
            *cursor_y = (*cursor_y + p.dy).clamp(0, render::WINDOW_H as i32 - 1);
            false
        }
        EventType::PointerButton => {
            // PointerPayload.buttons is the live button mask. The
            // driver emits this event on every press AND release; v0
            // only acts on presses. We infer press vs release by
            // comparing the new mask against our last-seen mask —
            // but for simplicity of v0 we just react to "the target
            // button is currently down" and rely on the fact that a
            // single tap is a down-then-up pair which produces two
            // PointerButton events; the second has that button bit
            // clear so we won't re-trigger. If auto-repeat-on-hold
            // becomes a problem we add edge tracking.
            let p = ev.pointer();

            // End-state right-click resets, regardless of cursor
            // position. No flag / reveal semantics apply to a frozen
            // board, and right-click is the thumb-reachable button
            // that pairs naturally with R / Escape for "I'm done
            // looking, give me a new game."
            if p.buttons & button::RIGHT != 0 && board.state() != State::Playing {
                board.reset();
                return true;
            }

            let hovered = tile_at_cursor(*cursor_x, *cursor_y);
            let (col, row) = match hovered {
                Some(v) => v,
                None => return false,
            };
            let mut changed = false;
            if p.buttons & button::LEFT != 0 {
                match board.reveal(row, col) {
                    RevealOutcome::NoChange => {}
                    _ => changed = true,
                }
            } else if p.buttons & button::RIGHT != 0 {
                match board.toggle_flag(row, col) {
                    game::FlagOutcome::Toggled => changed = true,
                    game::FlagOutcome::NoChange => {}
                }
            }
            changed
        }
        EventType::KeyDown | EventType::KeyRepeat => {
            let k = ev.keyboard();
            if k.keycode == keys::Q
                && k.modifiers & (modifier::LEFT_CTRL | modifier::RIGHT_CTRL) != 0
            {
                client.close();
                sys::exit(0);
            }
            if k.keycode == keys::R || k.keycode == keys::ESCAPE {
                // Reset in every state — including mid-game. No
                // confirmation prompt; R is cheap to re-press.
                board.reset();
                return true;
            }
            false
        }
        _ => false,
    }
}

fn tile_at_cursor(cursor_x: i32, cursor_y: i32) -> Option<(u8, u8)> {
    render::tile_at(cursor_x, cursor_y)
}

fn redraw(
    client: &mut Client,
    board: &Board,
    hovered: Option<(u8, u8)>,
    cursor: (i32, i32),
) {
    {
        let mut surf = client.surface_mut();
        render::draw(&mut surf, board, hovered, cursor);
    }
    if client.submit_full().is_err() {
        sys::log_error(b"TREE", b"submit_full failed");
        // Keep running — a dropped submit is recoverable on the next
        // redraw. Exit only on unrecoverable handshake failure.
    }
}

// Ensure the `State` import isn't pruned; main.rs doesn't match on
// it directly (render.rs does), but keeping the use statement silent
// the dead_code lint if we reference it in logging later.
#[allow(dead_code)]
const _: State = State::Playing;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"TREE", b"panic");
    sys::exit(255);
}
