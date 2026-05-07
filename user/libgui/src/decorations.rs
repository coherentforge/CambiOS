// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Client-side window decorations (Tier 1 movable-windows pass).
//!
//! Per the decoration model pinned in
//! `~/.claude/plans/how-heavy-a-lift-expressive-wand.md`: client-side
//! decorations + 1px server-painted focus border + (future)
//! Principal-badge HUD. The server-painted focus border lives in the
//! compositor; this module owns the client-painted title bar.
//!
//! v1 minimum: a solid-color strip at the top of the surface that
//! serves as the drag region. No title text, no close button — those
//! land in a follow-up pass alongside a libgui font primitive that
//! the title bar can render and a `RequestClose` wire message that
//! a close-button click would synthesize.
//!
//! ## Shape
//!
//! ```ignore
//! let region = decorate(client.surface_mut(), TITLE_DEFAULT_COLOR);
//! // `region` is the top `TITLE_BAR_HEIGHT` rows in window-local
//! // coordinates. libgui's drag-tracking helper uses it to decide
//! // when a click should start a drag.
//! ```

use crate::{Color, Surface};
use cambios_libgui_proto::Rect;

/// ARCHITECTURAL: title bar height in pixels for v1 client-side
/// decorations. All libgui-decorated windows reserve the top
/// `TITLE_BAR_HEIGHT` rows for the title bar; their drawable region
/// for application content is `(0, TITLE_BAR_HEIGHT, width, height)`.
/// Changing this is a visual-design decision affecting every
/// libgui-decorated client; v1 picks 24 (compact, fits future 16px
/// title text + 4px padding top/bottom).
pub const TITLE_BAR_HEIGHT: u32 = 24;

/// ARCHITECTURAL: default title-bar fill color (XRGB8888). Picked for
/// contrast against the existing CambiOS color palette + reasonable
/// visibility on both light and dark client surfaces. Clients that
/// want a different hue pass `decorate_with_color`.
pub const TITLE_DEFAULT_COLOR: Color = Color(0x00_2A_3A_5E); // dark navy

/// Drag region in window-local coordinates. Returned by
/// [`decorate`] / [`decorate_with_color`]. The libgui drag-tracking
/// helper inside `Client::poll_event` checks pointer-button events
/// against this rect to decide whether to synthesize `DragWindowBy`
/// messages instead of forwarding the events to the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DragRegion {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl DragRegion {
    /// Whether `(px, py)` (window-local pointer coords) lies inside
    /// the rect.
    pub fn contains(&self, px: i32, py: i32) -> bool {
        let right = self.x + self.width as i32;
        let bottom = self.y + self.height as i32;
        px >= self.x && px < right && py >= self.y && py < bottom
    }
}

/// Paint the v1 title bar at the top of `surface` with the default
/// color and return the drag region (top `TITLE_BAR_HEIGHT` rows).
///
/// Idempotent — calling this every frame before drawing the
/// application's content is the recommended pattern (cheap; lets the
/// app overwrite the bar's pixels with content if it wants and
/// re-paint the title on the next frame). The drag region itself is
/// purely advisory metadata used by the drag-tracking helper.
pub fn decorate(surface: &mut Surface) -> DragRegion {
    decorate_with_color(surface, TITLE_DEFAULT_COLOR)
}

/// Variant of [`decorate`] that takes a custom title-bar color.
pub fn decorate_with_color(surface: &mut Surface, color: Color) -> DragRegion {
    let w = surface.width();
    let h = TITLE_BAR_HEIGHT.min(surface.height());
    surface.fill_rect(
        Rect {
            x: 0,
            y: 0,
            w: w as u16,
            h: h as u16,
        },
        color,
    );
    DragRegion {
        x: 0,
        y: 0,
        width: w,
        height: h,
    }
}
