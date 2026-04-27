// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Worm renderer — consumes a `game::Worm` and paints a full frame to
//! a `libgui::Surface`.
//!
//! Full-surface redraw on every call. Damage-tracked partial redraw
//! is out of scope for v0 (the compositor composites the whole
//! surface regardless of FrameReady damage list, per libgui-proto).
//! Revisit when: compositor profiling shows frame build as a cost.

use cambios_libgui::{Color, Rect, Surface, TileGrid};

use cambios_worm::game::{Direction, State, Worm, COLS, ROWS};

// --- window / grid geometry ---
//
// 24 px side margins + 20 × 18 px cells = 24 + 360 + 24 = 408 wide.
// 40 px status bar + 24 px top margin + 15 × 18 px cells + 26 px
// bottom margin = 40 + 24 + 270 + 26 = 360 tall.
pub const WINDOW_W: u32 = 408;
pub const WINDOW_H: u32 = 360;

pub const TILE_PX: u16 = 18;
pub const BOARD_ORIGIN_X: i32 = 24;
pub const BOARD_ORIGIN_Y: i32 = 64;

pub const STATUS_BAR_H: u32 = 40;

// --- palette — same earth-tone family as Tree, shifted where the
// worm needs to read as a worm-not-dirt. See the session brief in the
// `user/worm/src/main.rs` header for the "shared world" rationale.

const COLOR_BG: Color = Color::rgb(0x1E, 0x2A, 0x14); // Tree: deep forest floor
const COLOR_STATUS_BG: Color = Color::rgb(0x2B, 0x1C, 0x0E); // Tree: darker dirt
const COLOR_FIELD: Color = Color::rgb(0x8B, 0x5A, 0x2B); // Tree: dirt — the worm's world
const COLOR_FIELD_DARK: Color = Color::rgb(0x5B, 0x3A, 0x1B); // Tree: dirt edge
const COLOR_FIELD_SPECK: Color = Color::rgb(0x6A, 0x3F, 0x1A); // Tree: pebble

// Worm pinkish-brown — an earthworm on dirt. Distinct from the
// dirt tones so the worm is unambiguously visible against COLOR_FIELD
// without leaving the earth-tone family.
const COLOR_WORM_BODY: Color = Color::rgb(0xB0, 0x5A, 0x3C);
const COLOR_WORM_HEAD: Color = Color::rgb(0xD0, 0x70, 0x50);
const COLOR_WORM_SEGMENT_EDGE: Color = Color::rgb(0x7A, 0x3A, 0x22);
const COLOR_WORM_EYE: Color = Color::WHITE;

// Food = green sprout, drawn with Tree's grass palette so the worm's
// food and Tree's grass tuft read as the same biosphere.
const COLOR_FOOD_LEAF: Color = Color::rgb(0x78, 0xA8, 0x48); // Tree: grass tuft
const COLOR_FOOD_STEM: Color = Color::rgb(0x3E, 0x6A, 0x2A); // Tree: grass dark

const COLOR_TEXT: Color = Color::WHITE;
const COLOR_TITLE: Color = Color::rgb(0xB0, 0xE0, 0x90); // Tree title tint

pub fn grid() -> TileGrid {
    TileGrid::new(
        BOARD_ORIGIN_X,
        BOARD_ORIGIN_Y,
        TILE_PX,
        TILE_PX,
        COLS as u16,
        ROWS as u16,
        /* gap */ 0,
    )
}

/// Draw one full frame representing the worm's current state.
pub fn draw(surf: &mut Surface, worm: &Worm) {
    surf.clear(COLOR_BG);
    draw_status_bar(surf, worm);
    draw_field(surf);

    let tg = grid();

    // Food first — the worm segment draw-over will occlude it if the
    // worm somehow sits on its own food (can't happen mid-game but
    // the invariant is robust against an edge case where food is
    // placed and then the worm's head moves onto it in the same
    // frame).
    let (fc, fr) = worm.food_cell();
    if let Some(rect) = tg.tile_rect(fc as u16, fr as u16) {
        draw_food_tile(surf, rect);
    }

    // Body — head last so it paints over body-drawn-color if there's
    // ever visual overlap (there isn't with current geometry, but
    // ordering head-last makes the direction indicator always win).
    let mut is_head = true;
    for (col, row) in worm.body_iter() {
        let rect = match tg.tile_rect(col as u16, row as u16) {
            Some(r) => r,
            None => continue,
        };
        if is_head {
            draw_worm_head(surf, rect, worm.direction());
            is_head = false;
        } else {
            draw_worm_body_segment(surf, rect);
        }
    }

    if worm.state() == State::Dead {
        draw_end_panel(surf);
    }
}

fn draw_status_bar(surf: &mut Surface, worm: &Worm) {
    surf.fill_rect(
        Rect { x: 0, y: 0, w: WINDOW_W as u16, h: STATUS_BAR_H as u16 },
        COLOR_STATUS_BG,
    );

    surf.draw_text_builtin(16, 16, "WORM", COLOR_TITLE);

    // "SCORE N" right-aligned. Score is bounded by GRID_SIZE = 300.
    let mut buf = [0u8; 16];
    let n = format_score(&mut buf, worm.score());
    let label = core::str::from_utf8(&buf[..n]).unwrap_or("SCORE ?");
    let label_w = n as i32 * 8;
    surf.draw_text_builtin(
        WINDOW_W as i32 - 16 - label_w,
        16,
        label,
        COLOR_TEXT,
    );
}

/// Draw the dirt playing field with a scatter of pebble specks for
/// texture — same look as Tree's revealed-dirt tiles. Deterministic
/// (row/col-derived) so the texture is stable across frames.
fn draw_field(surf: &mut Surface) {
    // Single flat dirt background under the tile grid area.
    surf.fill_rect(
        Rect {
            x: BOARD_ORIGIN_X as u16,
            y: BOARD_ORIGIN_Y as u16,
            w: (COLS as u32 * TILE_PX as u32) as u16,
            h: (ROWS as u32 * TILE_PX as u32) as u16,
        },
        COLOR_FIELD,
    );
    // Subtle outline so the field visually separates from the status
    // bar + surrounding margin without needing a second-pass texture.
    outline_rect(
        surf,
        Rect {
            x: BOARD_ORIGIN_X as u16,
            y: BOARD_ORIGIN_Y as u16,
            w: (COLS as u32 * TILE_PX as u32) as u16,
            h: (ROWS as u32 * TILE_PX as u32) as u16,
        },
        COLOR_FIELD_DARK,
    );

    // Scatter specks — 3 per cell, rotated. Same offsets + technique
    // as Tree's fill_dirt_tile, inlined to avoid a cross-crate
    // dependency on Tree's render module.
    const SPECK_OFFSETS: [(u8, u8); 8] = [
        (3, 4), (11, 2), (5, 12), (14, 9),
        (8, 6), (2, 13), (15, 14), (10, 15),
    ];
    for row in 0..ROWS {
        for col in 0..COLS {
            let base_x = BOARD_ORIGIN_X + col as i32 * TILE_PX as i32;
            let base_y = BOARD_ORIGIN_Y + row as i32 * TILE_PX as i32;
            let rot = ((row as usize).wrapping_mul(7).wrapping_add((col as usize).wrapping_mul(13)))
                % SPECK_OFFSETS.len();
            for i in 0..3 {
                let (dx, dy) = SPECK_OFFSETS[(rot + i) % SPECK_OFFSETS.len()];
                surf.set_pixel(base_x + dx as i32, base_y + dy as i32, COLOR_FIELD_SPECK);
            }
        }
    }
}

fn draw_worm_body_segment(surf: &mut Surface, rect: Rect) {
    // Solid fill with 1px dark edge so segments read as a connected
    // worm rather than a line of identical tiles.
    surf.fill_rect(rect, COLOR_WORM_BODY);
    outline_rect(surf, rect, COLOR_WORM_SEGMENT_EDGE);
}

fn draw_worm_head(surf: &mut Surface, rect: Rect, dir: Direction) {
    surf.fill_rect(rect, COLOR_WORM_HEAD);
    outline_rect(surf, rect, COLOR_WORM_SEGMENT_EDGE);
    draw_head_eyes(surf, rect, dir);
}

/// Paint two 2x2 pixel eyes on the leading edge of the head, picked
/// by direction. Gives the worm a clear facing so the player can
/// read "which end is moving" at a glance.
fn draw_head_eyes(surf: &mut Surface, rect: Rect, dir: Direction) {
    let x0 = rect.x as i32;
    let y0 = rect.y as i32;
    let w = rect.w as i32;
    let h = rect.h as i32;
    // Eye centers: offset from the two perpendicular edges of the
    // leading edge. With 18px tiles, an eye at (5, 4) and (13, 4)
    // sits comfortably in the upper-third of the tile when facing
    // Up, and flips for the other three directions.
    let ((ex0, ey0), (ex1, ey1)) = match dir {
        Direction::Right => ((x0 + w - 5, y0 + 4), (x0 + w - 5, y0 + h - 6)),
        Direction::Left => ((x0 + 3, y0 + 4), (x0 + 3, y0 + h - 6)),
        Direction::Up => ((x0 + 4, y0 + 3), (x0 + w - 6, y0 + 3)),
        Direction::Down => ((x0 + 4, y0 + h - 5), (x0 + w - 6, y0 + h - 5)),
    };
    draw_eye_dot(surf, ex0, ey0);
    draw_eye_dot(surf, ex1, ey1);
}

fn draw_eye_dot(surf: &mut Surface, x: i32, y: i32) {
    // 2x2 eye.
    surf.set_pixel(x, y, COLOR_WORM_EYE);
    surf.set_pixel(x + 1, y, COLOR_WORM_EYE);
    surf.set_pixel(x, y + 1, COLOR_WORM_EYE);
    surf.set_pixel(x + 1, y + 1, COLOR_WORM_EYE);
}

/// Food tile — a green sprout on the dirt. Four-leaf bud centered on
/// the tile, stem dot below.
fn draw_food_tile(surf: &mut Surface, rect: Rect) {
    let x0 = rect.x as i32;
    let y0 = rect.y as i32;
    let w = rect.w as i32;
    let h = rect.h as i32;
    // Inner leaf body: a centered rectangle, slightly inset.
    let leaf = Rect {
        x: (x0 + 4) as u16,
        y: (y0 + 3) as u16,
        w: (w - 8) as u16,
        h: (h - 8) as u16,
    };
    surf.fill_rect(leaf, COLOR_FOOD_LEAF);
    // Stem — a short vertical line from the bud down to the tile
    // floor, suggesting a sprout anchored in the dirt.
    let stem_x = x0 + w / 2;
    for sy in (y0 + h - 5)..(y0 + h - 1) {
        surf.set_pixel(stem_x, sy, COLOR_FOOD_STEM);
    }
    // A single highlight pixel in the leaf — not a reflection, just
    // breaks up the flat color at 18px scale.
    surf.set_pixel(x0 + 6, y0 + 5, Color::rgb(0xA0, 0xD0, 0x70));
}

fn draw_end_panel(surf: &mut Surface) {
    let panel_w: u16 = 280;
    let panel_h: u16 = 72;
    let x = ((WINDOW_W as i32) - panel_w as i32) / 2;
    let y = ((WINDOW_H as i32) - panel_h as i32) / 2;
    // Shadow.
    surf.fill_rect(
        Rect { x: (x + 3) as u16, y: (y + 3) as u16, w: panel_w, h: panel_h },
        Color::rgb(0x08, 0x08, 0x08),
    );
    surf.fill_rect(
        Rect { x: x as u16, y: y as u16, w: panel_w, h: panel_h },
        Color::BLACK,
    );
    let border = Color::rgb(0xFF, 0x80, 0x80);
    outline_rect(
        surf,
        Rect { x: x as u16, y: y as u16, w: panel_w, h: panel_h },
        border,
    );
    outline_rect(
        surf,
        Rect { x: (x + 2) as u16, y: (y + 2) as u16, w: panel_w - 4, h: panel_h - 4 },
        border,
    );

    // "THE WORM RETURNS" — Worm's equivalent of Tree's reforestation
    // / deforestation reveal. Death is where the worm goes back to
    // the soil.
    let msg = "THE WORM RETURNS";
    let msg_w = msg.len() as i32 * 8;
    let msg_x = x + (panel_w as i32 - msg_w) / 2;
    let msg_y = y + 20;
    surf.draw_text_builtin(msg_x, msg_y, msg, border);

    let hint = "PRESS R TO RESTART";
    let hint_w = hint.len() as i32 * 8;
    let hint_x = x + (panel_w as i32 - hint_w) / 2;
    let hint_y = y + 44;
    surf.draw_text_builtin(hint_x, hint_y, hint, COLOR_TEXT);
}

// --- primitives ---

fn outline_rect(surf: &mut Surface, rect: Rect, color: Color) {
    let x0 = rect.x as i32;
    let y0 = rect.y as i32;
    let x1 = x0 + rect.w as i32 - 1;
    let y1 = y0 + rect.h as i32 - 1;
    surf.draw_line(x0, y0, x1, y0, color);
    surf.draw_line(x0, y1, x1, y1, color);
    surf.draw_line(x0, y0, x0, y1, color);
    surf.draw_line(x1, y0, x1, y1, color);
}

/// Format "SCORE N" into buf without heap / itoa / format!. Bounded
/// by GRID_SIZE so N fits in 3 digits; the buf is 16 bytes which
/// comfortably holds "SCORE " (6) + 3 digits.
fn format_score(buf: &mut [u8; 16], score: u32) -> usize {
    let prefix = b"SCORE ";
    let mut n = 0usize;
    for &b in prefix {
        buf[n] = b;
        n += 1;
    }
    n += write_u32(&mut buf[n..], score);
    n
}

fn write_u32(buf: &mut [u8], mut v: u32) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 10];
    let mut i = 0;
    while v > 0 {
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    for k in 0..i {
        buf[k] = digits[i - 1 - k];
    }
    i
}
