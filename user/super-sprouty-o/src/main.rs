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
//! ## Session 1b scope (this commit)
//!
//! - Crate scaffold matching pong template (Cargo.toml + 3-arch linker
//!   scripts + lib.rs stub).
//! - Endpoint 22 registration, 33 FPS FrameClock (3 kernel ticks).
//! - Empty sky-blue window; ESC exits. No sprites, no physics, no
//!   input beyond ESC.
//!
//! Follow-on sessions add: sprite sheet + static render (1c);
//! physics + AABB tile collision + camera + weeds (Session 2); seeds
//! + sprout-seed power-up + goal tree + animations + live FPS counter
//! (Session 3).

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use arcos_libgui::{Client, Color, EventType, FrameClock, InputEvent};
use arcos_libsys as sys;

/// Surface dimensions. 480×320 matches pong's court; at 32×32 tiles
/// this gives a 15-tile-wide × 10-tile-tall viewport for Session 1c+.
const WINDOW_W: u32 = 480;
const WINDOW_H: u32 = 320;

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
    pub const ESCAPE: u32 = 0x29;
}

/// Placeholder sky palette. Session 3 locks the earth-tone palette
/// across Sprouty / ground / weed / seed / goal-tree.
const SKY: Color = Color::rgb(0x87, 0xCE, 0xEB);

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::print(b"[SPROUTY] booting\r\n");

    // Leaf boot module — release the boot gate immediately so anything
    // after super-sprouty-o in the manifest (shell) doesn't block on
    // the compositor round-trip.
    sys::module_ready();

    let mut client = match Client::open(WINDOW_W, WINDOW_H, SPROUTY_ENDPOINT) {
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

    let mut clock = FrameClock::new(STEP_TICKS);
    clock.seed(sys::get_time());

    redraw(&mut client);

    sys::print(b"[SPROUTY] entering event loop\r\n");
    loop {
        let mut drained = false;
        while let Some(ev) = client.poll_event() {
            drained = true;
            if handle_event(&ev) {
                sys::print(b"[SPROUTY] exiting\r\n");
                sys::exit(0);
            }
        }

        // Session 1b has no dynamic state; the tick still drives a
        // redraw each interval so the scanout path sees the intended
        // 33 FPS workload. From Session 1c onward the tick advances
        // animation / physics too.
        let tick = clock.tick(sys::get_time());
        if tick {
            redraw(&mut client);
        }

        if !drained && !tick {
            sys::yield_now();
        }
    }
}

/// Apply one input event. Returns `true` iff the event should
/// terminate the program (Session 1b: ESC only).
fn handle_event(ev: &InputEvent) -> bool {
    if matches!(ev.event_type, EventType::KeyDown) {
        let k = ev.keyboard();
        if k.keycode == keys::ESCAPE {
            return true;
        }
    }
    false
}

fn redraw(client: &mut Client) {
    {
        let mut surf = client.surface_mut();
        surf.clear(SKY);
    }
    if client.submit_full().is_err() {
        sys::log_error(b"SPROUTY", b"submit_full failed");
        // Recoverable on the next frame; exit only on unrecoverable
        // handshake failure.
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::log_error(b"SPROUTY", b"panic");
    sys::exit(255);
}
