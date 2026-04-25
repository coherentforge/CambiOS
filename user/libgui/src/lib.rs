// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS GUI client library — v0 (ADR-011 / ADR-014 client side).
//!
//! Wraps `arcos-libgui-proto`'s wire format in a thin, opinionated API
//! that does the handshake, hands back a safe `Surface`, and submits
//! `FrameReady` when the caller is done drawing. Scope matches the
//! scanout protocol's v0: no input events, no widget tree, no layout,
//! no focus, no animation loop. This is the drawing substrate a real
//! application sits on; later passes add event delivery (when
//! virtio-input lands) and widget semantics.
//!
//! ## Shape
//!
//! ```ignore
//! use arcos_libgui::{Client, Color, Rect, TileGrid};
//!
//! let mut client = Client::open(640, 480, MY_ENDPOINT).unwrap();
//! let surf = client.surface_mut();
//! surf.clear(Color::rgb(0x20, 0x30, 0x40));
//! surf.fill_rect(Rect::new(10, 10, 100, 50), Color::rgb(0xC8, 0, 0));
//! surf.draw_text(16, 16, "HELLO", Color::WHITE);
//! client.submit_full();
//! ```
//!
//! ## Layering
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │ application                                   │
//! ├──────────────────────────────────────────────┤
//! │ arcos-libgui     (this crate — Surface,       │
//! │                   primitives, Client, font)   │
//! ├──────────────────────────────────────────────┤
//! │ arcos-libgui-proto (wire format, endpoints)   │
//! ├──────────────────────────────────────────────┤
//! │ arcos-libsys     (raw syscalls)               │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! What this crate explicitly does NOT contain:
//!
//! - Input events / dispatch — lands with virtio-input.
//! - Widget tree, layout, focus, event routing — widget toolkit
//!   layered on top of this crate in a future pass.
//! - Damage-aware partial redraws — the v0 `submit()` passes the
//!   caller's rect list through verbatim; the compositor composites
//!   the full surface anyway (per libgui-proto comments).
//! - HiDPI / backing-scale — apps draw in pixels, not points, until
//!   the compositor learns backing scale (post-v1 per ADR-011).
//! - TrueType fonts, subpixel rendering, alpha blending — XRGB8888
//!   opaque only.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod bitmap;
pub mod client;
pub mod font;
pub mod font_aa;
pub mod frame_clock;
pub mod surface;
pub mod tile_grid;

pub use bitmap::Bitmap;
pub use client::{Client, ClientError};
pub use font::{Font, BUILTIN_FONT_8X8};
pub use font_aa::{AntialiasedFont, BUILTIN_FONT_JBM};
pub use frame_clock::FrameClock;
pub use surface::Surface;
pub use tile_grid::TileGrid;

// Re-export Rect from libgui-proto so callers have one Rect type to
// work with (damage lists on `Client::submit` take `&[Rect]` of the
// same shape).
pub use arcos_libgui_proto::Rect;

// Re-export input types so a client doesn't need a second crate dep
// for `Client::poll_event()`. When virtio-input land ships, clients
// write `use arcos_libgui::{InputEvent, EventType, modifier, button}`.
pub use arcos_libgui_proto::InputEvent;
pub use arcos_libinput_proto::{
    button, modifier, DeviceClass, EventType, KeyboardPayload, PointerPayload,
};

/// XRGB8888 color. `A` byte is always 0 (the top 8 bits of the u32
/// are unused by the scanout; keeping them zero avoids accidental
/// alpha semantics leaking in when the format grows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Color(pub u32);

impl Color {
    pub const BLACK: Self = Self(0x0000_0000);
    pub const WHITE: Self = Self(0x00FF_FFFF);
    pub const RED: Self = Self(0x00FF_0000);
    pub const GREEN: Self = Self(0x0000_FF00);
    pub const BLUE: Self = Self(0x0000_00FF);

    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self(((r as u32) << 16) | ((g as u32) << 8) | (b as u32))
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}
