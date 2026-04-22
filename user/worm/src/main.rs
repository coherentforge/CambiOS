// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Worm — second first-party app (ADR-011 stack, ADR-012
//! input, libgui v0). Classic snake on a 20×15 grid of dirt: eat
//! sprouts, grow longer, don't hit the walls or your own body.
//!
//! ## Shared world with Tree
//!
//! Worm plays on the same palette as Tree's revealed-dirt tiles, and
//! eats the same green sprouts Tree's grass-tuft pixels suggest. Run
//! as sibling apps, they read as two views of one garden. The palette
//! re-use is by copy, not by shared module — libgui doesn't have a
//! palette crate yet and Worm is not the right trigger to extract
//! one. If game 3 (Pong) reaches for the same tones, that is the
//! extraction moment.
//!
//! ## The new primitive: self-driven tick
//!
//! Tree only redraws on input events. Worm is the first app that
//! needs a **frame clock** — the worm advances every ~100 ms whether
//! or not the player has pressed a key. The pattern is ad-hoc in this
//! file, not extracted to libgui, because it has exactly one consumer
//! and the launch plan calls out Pong (game 3) as the second-consumer
//! trigger for any libgui-level tick abstraction.
//!
//! The kernel's `SYS_GET_TIME` returns ticks, and the scheduler runs
//! at 100 Hz, so 1 tick = 10 ms. All pacing here is in ticks.
//!
//! ## V0 control flow
//!
//! 1. Handshake via `libgui::Client::open(WINDOW_W, WINDOW_H, WORM_ENDPOINT)`.
//! 2. Seed a Worm.
//! 3. Paint initial frame.
//! 4. Loop:
//!    - Drain events (direction queue, reset key, right-click-to-reset when dead).
//!    - If in Playing state and the frame clock has ticked, call
//!      `worm.step()` and mark the frame dirty.
//!    - If anything dirtied the frame, redraw + submit.
//!    - If nothing happened this iteration, `sys::yield_now()`.
//!
//! ## No new kernel syscalls
//!
//! Per ADR-011, every new first-party app must run over libgui +
//! libsys as-is. Worm touches only `sys::get_time`, `sys::yield_now`,
//! `sys::get_pid`, `Client::open`, `Client::poll_event`, and
//! `Client::submit_full` — nothing the Tree session didn't already
//! require.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libgui::{button, Client, EventType, InputEvent};
use arcos_libsys as sys;
use arcos_worm::game::{Direction, State, StepOutcome, Worm};

mod render;

/// Worm's IPC endpoint. The launch-plan direction is "one endpoint
/// per app, grouped by class" (Tree=31, Worm=32, Pong=33, Mario=34),
/// but the kernel's `MAX_ENDPOINTS` is currently a SCAFFOLDING bound
/// of 32 — endpoint IDs are 0..=31, so 32 is out of range and
/// `register_endpoint(32)` fails. Worm sits at 29 (free between
/// compositor=28 and compositor-input=30) until the bound is bumped
/// per docs/ASSUMPTIONS.md's replacement trigger ("first service that
/// needs >32 endpoints"). When MAX_ENDPOINTS grows, move Worm to the
/// planned slot and group by app class.
///
/// Revisit when: MAX_ENDPOINTS is raised kernel-side — Worm + Pong +
/// Mario all move to their class-grouped IDs at that point.
const WORM_ENDPOINT: u32 = 29;

/// USB HID usage codes we bind. Full evdev→HID table lives in
/// `user/virtio-input/src/evdev.rs`; we re-declare only the ones the
/// Worm listens for, same locality principle as Tree.
mod keys {
    // Movement — arrows + WASD, double-bound.
    pub const LEFT: u32 = 0x50;
    pub const RIGHT: u32 = 0x4F;
    pub const UP: u32 = 0x52;
    pub const DOWN: u32 = 0x51;
    pub const W: u32 = 0x1A;
    pub const A: u32 = 0x04;
    pub const S: u32 = 0x16;
    pub const D: u32 = 0x07;
    // Reset.
    pub const R: u32 = 0x15;
    pub const ESCAPE: u32 = 0x29;
}

/// Frame-clock tick count, in kernel ticks. 20 ticks at 100 Hz =
/// 200 ms = 5 moves/sec — the Nokia / classic-arcade Snake baseline.
///
/// TUNING ladder (landed via playtest):
///   100 ms — "too fast" (initial ship)
///   120 ms — "full throttle, no curve" (what 8.3/sec felt like)
///   200 ms — current. 5 moves/sec. Canonical Snake feel.
///
/// V0 has no speedup curve. An earlier version scaled tick interval
/// by score (`step_ticks = max(5, base - score/5)`), but a gentler
/// start just handed the player the same "too fast" after ~10 food.
/// The score-progression polish is deferred: Revisit when post-launch
/// playtesters ask for it AND someone names the target end-game tick
/// the player wants to reach.
const STEP_TICKS: u64 = 20;

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[WORM] booting\r\n");

    // Leaf boot module — release the boot gate immediately, before
    // the compositor handshake. Matches Tree / hello-window; lets
    // the next module in limine.conf (shell) start in parallel with
    // our CreateWindow round-trip.
    sys::module_ready();

    let mut client = match Client::open(render::WINDOW_W, render::WINDOW_H, WORM_ENDPOINT) {
        Ok(c) => c,
        Err(e) => {
            // Log the specific variant — narrows boot-path debugging
            // from "something in Client::open" to a named failure.
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
            sys::log_error(b"WORM", tag);
            sys::exit(1);
        }
    };
    sys::print(b"[WORM] window opened\r\n");

    // Same seed shape as Tree: time XOR (pid * PHI) so independent
    // reboots don't produce identical boards and two worms running
    // at once (not currently supported, but Phase 2 will) don't
    // agree on food placement.
    let seed = sys::get_time() ^ ((sys::get_pid() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut worm = Worm::new(seed);

    redraw(&mut client, &worm);
    let mut last_step_tick = sys::get_time();

    sys::print(b"[WORM] entering event loop\r\n");
    loop {
        let mut dirty = false;
        let mut drained = false;
        while let Some(ev) = client.poll_event() {
            drained = true;
            if handle_event(&ev, &mut worm) {
                dirty = true;
            }
        }

        // Frame clock. Only ticks in Playing state; in Dead state the
        // worm is a tableau and ticking is wasted work (and would
        // also mask the death moment under a re-submitted identical
        // frame). A fresh reset resets `last_step_tick` so the
        // player gets a full grace interval on the first move of a
        // new game.
        if worm.state() == State::Playing {
            let now = sys::get_time();
            if now.saturating_sub(last_step_tick) >= STEP_TICKS {
                let outcome = worm.step();
                last_step_tick = now;
                if !matches!(outcome, StepOutcome::NoOp) {
                    dirty = true;
                }
            }
        }

        if dirty {
            redraw(&mut client, &worm);
        }

        if !drained && !dirty {
            sys::yield_now();
        }
    }
}

/// Apply one input event to the worm. Returns true if something
/// visibly changed (reset fired, or a direction was queued — the
/// latter doesn't repaint until the next step, but queuing it is
/// input-layer work we don't want to retry later).
fn handle_event(ev: &InputEvent, worm: &mut Worm) -> bool {
    match ev.event_type {
        EventType::PointerButton => {
            // End-state right-click resets. During play, pointer has
            // no semantics — worm is keyboard-driven.
            let p = ev.pointer();
            if worm.state() != State::Playing && p.buttons & button::RIGHT != 0 {
                worm.reset();
                return true;
            }
            false
        }
        EventType::KeyDown | EventType::KeyRepeat => {
            let k = ev.keyboard();
            match k.keycode {
                keys::LEFT | keys::A => {
                    worm.set_pending_direction(Direction::Left);
                    false
                }
                keys::RIGHT | keys::D => {
                    worm.set_pending_direction(Direction::Right);
                    false
                }
                keys::UP | keys::W => {
                    worm.set_pending_direction(Direction::Up);
                    false
                }
                keys::DOWN | keys::S => {
                    worm.set_pending_direction(Direction::Down);
                    false
                }
                keys::R | keys::ESCAPE => {
                    worm.reset();
                    true
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn redraw(client: &mut Client, worm: &Worm) {
    {
        let mut surf = client.surface_mut();
        render::draw(&mut surf, worm);
    }
    if client.submit_full().is_err() {
        sys::log_error(b"WORM", b"submit_full failed");
        // Keep running — a dropped submit is recoverable on the
        // next redraw. Exit only on unrecoverable handshake failure.
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"WORM", b"panic");
    sys::exit(255);
}
