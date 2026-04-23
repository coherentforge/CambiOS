// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Super Sprouty-O — fourth first-party HN-launch mini-game
//! (ADR-011 stack, ADR-012 input, libgui v0 + FrameClock + blit_bitmap_sub).
//!
//! Single-level scrolling platformer: a gardener-character called
//! Sprouty plants seeds through a reforested world, dodges invasive
//! weeds, and reaches a young flowering tree at level end. Original
//! art, original character, original level — no Nintendo IP references
//! (per HN launch plan: Nintendo IP is unusable and pattern-matching to
//! Mario is the whole launch risk).
//!
//! ## Session 2 state (this commit)
//!
//! - 64-wide scrolling level with three pits.
//! - Player physics: horizontal accel + friction, gravity, jump.
//! - AABB-vs-tilemap collision (axis-separated sweep; standing / walls
//!   / ceilings / walking-off-ledge all handled).
//! - Camera follows player, clamped to level bounds.
//! - Held-key left / right, SPACE to jump, ESC to quit.
//!
//! Still to land in Session 2: weed-walker enemy (2d), pit death +
//! lose overlay + R-restart (2e). After those: Session 3 polish.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

mod render;
mod sprites;

use arcos_libgui::{Bitmap, Client, EventType, FrameClock, InputEvent};
use arcos_libsys as sys;
use arcos_super_sprouty_o::{
    game::{Game, Input},
    level,
};

/// IPC endpoint. `MAX_ENDPOINTS` is a SCAFFOLDING bound of 32 in
/// [src/ipc/mod.rs], so valid IDs are 0..=31. 22 is free under the
/// current allocation (16=FS, 17=KS, 18=shell, 19=pong, 20=virtio-net,
/// 21=udp-stack, 24/25/26=virtio-blk, 27=scanout-driver, 28=compositor,
/// 29=worm/hello-window, 30=input, 31=tree).
///
/// Revisit when: MAX_ENDPOINTS is raised — super-sprouty-o moves to
/// its class-grouped slot (34) alongside Tree=31 / Worm=32 / Pong=33.
const SPROUTY_ENDPOINT: u32 = 22;

/// TUNING: physics tick interval in kernel ticks (1 tick = 10 ms at
/// 100 Hz). 3 → 30 ms → 33 FPS — first game past pong's 20 FPS, first
/// stress-test of the compositor + scanout path above that rate. If
/// the Session-3 live FPS counter shows sustained <30 fps, fall back
/// to 5 ticks (20 FPS, matching pong) is a one-line change.
const STEP_TICKS: u64 = 3;

/// USB HID usage codes. Full evdev→HID table in
/// `user/virtio-input/src/evdev.rs`; redeclared here for the codes
/// this game cares about, same locality discipline as tree/worm/pong.
mod keys {
    pub const LEFT: u32 = 0x50;
    pub const RIGHT: u32 = 0x4F;
    pub const A: u32 = 0x04;
    pub const D: u32 = 0x07;
    pub const SPACE: u32 = 0x2C;
    pub const UP: u32 = 0x52;
    pub const W: u32 = 0x1A;
    pub const R: u32 = 0x15;
    pub const ESCAPE: u32 = 0x29;
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[SPROUTY] booting\r\n");

    // Leaf boot module — release the boot gate immediately.
    sys::module_ready();

    let mut client = match Client::open(level::SURFACE_W, level::SURFACE_H, SPROUTY_ENDPOINT) {
        Ok(c) => c,
        Err(e) => {
            let tag: &[u8] = match e {
                arcos_libgui::ClientError::RegisterEndpointFailed(_) => b"register_endpoint",
                arcos_libgui::ClientError::EncodeCreateWindow => b"encode_create_window",
                arcos_libgui::ClientError::CreateWindowWriteFailed(_) => b"create_window_write",
                arcos_libgui::ClientError::RecvVerifiedFailed => b"recv_verified",
                arcos_libgui::ClientError::DecodeWelcome => b"decode_welcome",
                arcos_libgui::ClientError::ChannelAttachFailed(_) => b"channel_attach",
                arcos_libgui::ClientError::EncodeFrameReady => b"encode_frame_ready",
                arcos_libgui::ClientError::FrameReadyWriteFailed(_) => b"frame_ready_write",
            };
            sys::log_error(b"SPROUTY", tag);
            sys::exit(1);
        }
    };
    sys::print(b"[SPROUTY] window opened\r\n");

    let sheet = sprites::sheet();
    let mut game = Game::new();
    let mut input = Input::default();

    let mut clock = FrameClock::new(STEP_TICKS);
    clock.seed(sys::get_time());

    redraw(&mut client, &sheet, &game);

    sys::print(b"[SPROUTY] entering event loop\r\n");
    loop {
        let mut drained = false;
        while let Some(ev) = client.poll_event() {
            drained = true;
            match handle_event(&ev, &mut input) {
                EventResult::Quit => {
                    sys::print(b"[SPROUTY] exiting\r\n");
                    sys::exit(0);
                }
                EventResult::Restart => {
                    game.reset();
                    clock.seed(sys::get_time());
                }
                EventResult::Continue => {}
            }
        }

        let tick = clock.tick(sys::get_time());
        if tick {
            game.tick(&mut input);
            redraw(&mut client, &sheet, &game);
        }

        if !drained && !tick {
            sys::yield_now();
        }
    }
}

/// Outcome of consuming one input event.
enum EventResult {
    Continue,
    Restart,
    Quit,
}

/// Apply one input event + decide whether it triggers quit / restart.
fn handle_event(ev: &InputEvent, input: &mut Input) -> EventResult {
    match ev.event_type {
        EventType::KeyDown | EventType::KeyRepeat => {
            let k = ev.keyboard();
            match k.keycode {
                keys::LEFT | keys::A => {
                    input.left_held = true;
                    EventResult::Continue
                }
                keys::RIGHT | keys::D => {
                    input.right_held = true;
                    EventResult::Continue
                }
                keys::SPACE | keys::UP | keys::W => {
                    // Edge trigger: set once on KeyDown; OS KeyRepeat
                    // also sets it, but tick consumes it and the
                    // on-ground guard in game prevents airborne
                    // double-jumps.
                    input.jump_pressed = true;
                    EventResult::Continue
                }
                keys::R => EventResult::Restart,
                keys::ESCAPE => EventResult::Quit,
                _ => EventResult::Continue,
            }
        }
        EventType::KeyUp => {
            let k = ev.keyboard();
            match k.keycode {
                keys::LEFT | keys::A => {
                    input.left_held = false;
                }
                keys::RIGHT | keys::D => {
                    input.right_held = false;
                }
                _ => {}
            }
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

fn redraw(client: &mut Client, sheet: &Bitmap, game: &Game) {
    {
        let mut surf = client.surface_mut();
        render::draw(&mut surf, sheet, game);
    }
    if client.submit_full().is_err() {
        sys::log_error(b"SPROUTY", b"submit_full failed");
        // Recoverable on the next frame.
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"SPROUTY", b"panic");
    sys::exit(255);
}
