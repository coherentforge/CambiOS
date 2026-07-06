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
//! ## Self-driven tick
//!
//! Tree only redraws on input events. Worm advances every ~200 ms
//! whether or not the player has pressed a key, via
//! `libgui::FrameClock` — the same fixed-interval gate Pong uses.
//! The pattern was ad-hoc here through Worm's launch and extracted
//! to libgui when Pong became the second consumer (Convention 9).
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

use cambios_libgui::{button, modifier, Client, EventType, FrameClock, InputEvent};
use cambios_libsys as sys;
use cambios_worm::game::{Direction, State, StepOutcome, Worm};

mod render;

/// Worm's window input endpoint. Games sit at the top of the now-64-wide
/// endpoint space (Tree=61, Worm=62, Sprouty=63), deliberately above the
/// boot-service band (14..=33). The old launch-plan slots (Tree=31,
/// Worm=32, Pong=33, Mario=34) were eaten by services that grew into that
/// range (usb-host=31, fde-mount=32, ccid=33), so class-grouping moved to
/// the high end. Worm previously sat at 29, which aliases hello-window's
/// endpoint — it only worked because hello-window is disabled in
/// limine.conf. Endpoint IDs are ad-hoc `const u32`s with no
/// kernel-enforced ownership; ADR-018's reservation table is the
/// structural fix.
/// Revisit when: ADR-018's endpoint reservation table lands — hand-picked
/// game endpoints move under manifest-declared reservations.
const WORM_ENDPOINT: u32 = 62;

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
    // Exit: Ctrl+Q returns control to the shell that spawned us.
    pub const Q: u32 = 0x14;
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

cambios_libsys_rt::service_main! {
    name: "WORM",
    main: run,
}

fn run() -> ! {
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
                cambios_libgui::ClientError::RegisterEndpointFailed(_) => b"register_endpoint",
                cambios_libgui::ClientError::EncodeCreateWindow => b"encode_create_window",
                cambios_libgui::ClientError::CreateWindowWriteFailed(_) => b"create_window_write",
                cambios_libgui::ClientError::RecvVerifiedFailed => b"recv_verified",
                cambios_libgui::ClientError::DecodeWelcome => b"decode_welcome",
                cambios_libgui::ClientError::ChannelAttachFailed(_) => b"channel_attach",
                cambios_libgui::ClientError::EncodeFrameReady => b"encode_frame_ready",
                cambios_libgui::ClientError::FrameReadyWriteFailed(_) => b"frame_ready_write",
                cambios_libgui::ClientError::EncodeRequestResize => b"encode_request_resize",
                cambios_libgui::ClientError::RequestResizeWriteFailed(_) => b"request_resize_write",
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
    let mut clock = FrameClock::new(STEP_TICKS);
    clock.seed(sys::get_time());

    sys::print(b"[WORM] entering event loop\r\n");
    loop {
        let mut dirty = false;
        let mut drained = false;
        // Resize is ignored here (no `take_resize_pending()` call).
        // libgui's `poll_event` consumes `WindowResized` and re-attaches
        // the surface; on grow, the unrendered area is black until the
        // next full redraw.
        while let Some(ev) = client.poll_event() {
            drained = true;
            if handle_event(&ev, &mut worm, &client) {
                dirty = true;
            }
        }

        // Only tick in Playing state; in Dead state the worm is a
        // tableau and ticking is wasted work (and would also mask
        // the death moment under a re-submitted identical frame).
        if worm.state() == State::Playing && clock.tick(sys::get_time()) {
            let outcome = worm.step();
            if !matches!(outcome, StepOutcome::NoOp) {
                dirty = true;
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
fn handle_event(ev: &InputEvent, worm: &mut Worm, client: &Client) -> bool {
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
            if k.keycode == keys::Q
                && k.modifiers & (modifier::LEFT_CTRL | modifier::RIGHT_CTRL) != 0
            {
                client.close();
                sys::exit(0);
            }
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

