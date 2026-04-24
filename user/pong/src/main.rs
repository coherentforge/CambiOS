// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Pong — third first-party app (ADR-011 stack, ADR-012
//! input, libgui v0 + FrameClock). Single-player vs AI with
//! continuous-motion physics on the Tree/Worm shared garden palette.
//!
//! ## What's new vs Worm
//!
//! - **Continuous physics.** Ball and paddles live in 8-bit subpixel
//!   space; each tick advances by a velocity rather than a fixed
//!   grid cell. AABB collision against paddles + walls.
//! - **FrameClock consumer.** This is the second libgui::FrameClock
//!   consumer (worm is the first — though worm still runs its
//!   ad-hoc tick-gate loop, pending a later pass during which the
//!   parallel arch-parity thread is off the critical path). The
//!   extraction justified itself with two planned consumers; the
//!   migration of worm lands in a follow-up commit.
//! - **Held-key tracking.** Paddle input is directional-hold rather
//!   than turn-queueing. `up_held` / `down_held` bools flip on
//!   KeyDown / KeyUp and are sampled on each physics tick.
//!
//! ## V0 control flow
//!
//! 1. Handshake via `libgui::Client::open(WINDOW_W, WINDOW_H, PONG_ENDPOINT)`.
//! 2. Seed a Pong game.
//! 3. Paint initial frame (shows READY... overlay for the serve delay).
//! 4. Loop:
//!    - Drain events (update held keys, handle R / ESC to reset).
//!    - If not in MatchOver, the frame clock ticks and physics advances.
//!    - Redraw any tick that changed visible state.
//!    - Yield when idle.
//!
//! ## No new kernel syscalls
//!
//! Same as Tree and Worm — `sys::get_time`, `sys::yield_now`,
//! `sys::get_pid`, `Client::open`, `Client::poll_event`,
//! `Client::submit_full`. FrameClock lives entirely in userspace.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libgui::{modifier, Client, EventType, FrameClock, InputEvent};
use arcos_libsys as sys;
use arcos_pong::game::{PaddleMotion, Pong, State};

mod render;

/// Pong's IPC endpoint. `MAX_ENDPOINTS` is a SCAFFOLDING bound of 32
/// (valid IDs 0..=31), so the class-grouped plan from the HN-launch
/// sequencing (Tree=31, Worm=32, Pong=33, Mario=34) can't land until
/// the bound is bumped. 19 is genuinely free in the current scheme
/// (16=FS, 17=KS, 18=shell, 20=net, 21=UDP, 22/23=policy, 24..26=blk,
/// 27=scanout-driver, 28=compositor, 29=worm/hello-window, 30=input,
/// 31=tree). Worm chose 29 by squeezing between compositor + input;
/// Pong chooses 19 because that's a truly unused slot, which means
/// running pong alongside any future dev-only module doesn't collide
/// with 29.
///
/// Revisit when: MAX_ENDPOINTS is raised kernel-side — Pong moves to
/// the class-grouped slot (33) with Worm + Mario at 32 + 34.
const PONG_ENDPOINT: u32 = 19;

/// USB HID usage codes. Full evdev→HID table in
/// `user/virtio-input/src/evdev.rs`; only the codes Pong cares about
/// are redeclared here, same locality discipline as Worm + Tree.
mod keys {
    // Movement: W/S canonical, Up/Down as a fallback for players who
    // reach for the arrow cluster.
    pub const UP: u32 = 0x52;
    pub const DOWN: u32 = 0x51;
    pub const W: u32 = 0x1A;
    pub const S: u32 = 0x16;
    // Exit: Ctrl+Q returns control to the shell that spawned us.
    pub const Q: u32 = 0x14;
    // Reset.
    pub const R: u32 = 0x15;
    pub const ESCAPE: u32 = 0x29;
}

/// TUNING: physics tick interval, in kernel ticks (1 tick = 10 ms at
/// 100 Hz). 5 → 50 ms → 20 FPS. Worm runs at 20 ticks / 200 ms because
/// grid-stepped games don't benefit from sub-half-second frames; Pong
/// is continuous and needs the higher rate for the ball to read as
/// motion rather than as a slideshow.
///
/// Not 60 FPS. The compositor path hasn't been profiled at sustained
/// high frame rates — the HN-launch plan calls this out as Pong's
/// stress-test territory. 20 FPS is defensible for v0: ball at
/// 7–11 px/tick → 140–220 px/sec, readable motion. If the scanout
/// profiling pass (post-v0) shows 60 FPS headroom, tune this down to
/// 1 or 2 ticks.
const STEP_TICKS: u64 = 5;

/// Player input state: separate flags for each direction so we
/// correctly handle the W-held-while-S-pressed-then-released case
/// (the alternative — a single `motion` enum updated on each
/// keydown/keyup — forgets the older still-held key). Both-held
/// cancels; prevents the paddle from drifting when the player rests
/// both thumbs on the keys.
#[derive(Default)]
struct Input {
    up_held: bool,
    down_held: bool,
}

impl Input {
    fn motion(&self) -> PaddleMotion {
        match (self.up_held, self.down_held) {
            (true, false) => PaddleMotion::Up,
            (false, true) => PaddleMotion::Down,
            _ => PaddleMotion::None,
        }
    }
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[PONG] booting\r\n");

    // Leaf boot module — release the boot gate immediately so
    // downstream modules (shell, anything after pong in the manifest)
    // don't block on our compositor round-trip.
    sys::module_ready();

    let mut client = match Client::open(render::WINDOW_W, render::WINDOW_H, PONG_ENDPOINT) {
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
            sys::log_error(b"PONG", tag);
            sys::exit(1);
        }
    };
    sys::print(b"[PONG] window opened\r\n");

    // Same seed shape as Tree + Worm — time XOR (pid * PHI) so
    // distinct launches get distinct serves.
    let seed = sys::get_time() ^ ((sys::get_pid() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut pong = Pong::new(seed);
    let mut input = Input::default();

    let mut clock = FrameClock::new(STEP_TICKS);
    clock.seed(sys::get_time());

    redraw(&mut client, &pong);

    sys::print(b"[PONG] entering event loop\r\n");
    loop {
        let mut dirty = false;
        let mut drained = false;
        while let Some(ev) = client.poll_event() {
            drained = true;
            if handle_event(&ev, &mut pong, &mut input, &mut clock, &client) {
                dirty = true;
            }
        }

        // Physics tick — only advance when there's game to run. In
        // MatchOver, the frame is a static tableau.
        if !matches!(pong.state(), State::MatchOver { .. })
            && clock.tick(sys::get_time())
            && pong.step(input.motion())
        {
            dirty = true;
        }

        if dirty {
            redraw(&mut client, &pong);
        }

        if !drained && !dirty {
            sys::yield_now();
        }
    }
}

/// Apply one input event. Returns true iff the event changed visible
/// state immediately (reset fired) — paddle-key changes don't
/// repaint until the next physics tick, but the held-flag flip is
/// always applied here.
fn handle_event(
    ev: &InputEvent,
    pong: &mut Pong,
    input: &mut Input,
    clock: &mut FrameClock,
    client: &Client,
) -> bool {
    match ev.event_type {
        EventType::KeyDown | EventType::KeyRepeat => {
            let k = ev.keyboard();
            if k.keycode == keys::Q
                && k.modifiers & (modifier::LEFT_CTRL | modifier::RIGHT_CTRL) != 0
            {
                client.close();
                sys::exit(0);
            }
            match k.keycode {
                keys::W | keys::UP => {
                    input.up_held = true;
                    false
                }
                keys::S | keys::DOWN => {
                    input.down_held = true;
                    false
                }
                keys::R | keys::ESCAPE => {
                    pong.reset();
                    clock.seed(sys::get_time());
                    true
                }
                _ => false,
            }
        }
        EventType::KeyUp => {
            let k = ev.keyboard();
            match k.keycode {
                keys::W | keys::UP => {
                    input.up_held = false;
                    false
                }
                keys::S | keys::DOWN => {
                    input.down_held = false;
                    false
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn redraw(client: &mut Client, pong: &Pong) {
    {
        let mut surf = client.surface_mut();
        render::draw(&mut surf, pong);
    }
    if client.submit_full().is_err() {
        sys::log_error(b"PONG", b"submit_full failed");
        // Recoverable on the next frame. Exit only on unrecoverable
        // handshake failure.
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"PONG", b"panic");
    sys::exit(255);
}
