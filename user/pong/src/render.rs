// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Pong renderer — consumes a `game::Pong` and paints a full frame.
//!
//! Full-surface redraw every call; damage tracking deferred (same
//! rationale as worm + tree — compositor composites the whole
//! surface regardless of FrameReady damage list). Revisit when the
//! compositor profiles frame build as a cost.
//!
//! ## Tree-world theme
//!
//! Continuation of the palette worm established (which already
//! borrowed from tree): earth tones + grass greens. Paddles are
//! cross-sections of logs (wood body + bark striations); ball is an
//! acorn (oak body + amber cap); playing field is grass (worm's
//! `COLOR_FOOD_LEAF` + `COLOR_FOOD_STEM` tones). Centerline is a
//! dashed row of dark grass tufts.
//!
//! The palette-by-copy-not-by-module convention from worm carries
//! over: the three games share a visual world but libgui doesn't
//! have a palette crate yet, and three consumers is still at the
//! "two's a coincidence, three's a pattern" boundary. If Mario
//! picks up the same tones the extraction trigger fires and the
//! colours move into a shared module.

use cambios_libgui::{Color, Rect, Surface};

use cambios_pong::game::{
    Ball, Paddle, Pong, Side, State, BALL_SIZE, COURT_H, COURT_W, LEFT_PADDLE_X, PADDLE_H,
    PADDLE_W, RIGHT_PADDLE_X, WIN_SCORE,
};

// --- window geometry ---

pub const WINDOW_W: u32 = COURT_W as u32;
pub const WINDOW_H: u32 = COURT_H as u32 + STATUS_BAR_H as u32;
pub const STATUS_BAR_H: u16 = 40;

/// Court origin on the window surface. Game coordinates (0, 0) map
/// to (0, STATUS_BAR_H) in pixel space.
pub const COURT_ORIGIN_X: i32 = 0;
pub const COURT_ORIGIN_Y: i32 = STATUS_BAR_H as i32;

// --- palette (Tree + Worm shared garden) ---

// Forest floor — the deep backdrop.
const COLOR_BG: Color = Color::rgb(0x1E, 0x2A, 0x14);
// Dirt — status bar.
const COLOR_STATUS_BG: Color = Color::rgb(0x2B, 0x1C, 0x0E);

// Grass field — borrowed from worm's food tiles. The lighter
// grass is the court itself; darker grass is striation + centerline.
const COLOR_GRASS: Color = Color::rgb(0x4F, 0x7A, 0x32);
const COLOR_GRASS_DARK: Color = Color::rgb(0x3E, 0x6A, 0x2A);
const COLOR_GRASS_TUFT: Color = Color::rgb(0x78, 0xA8, 0x48);

// Log paddles — wood tones. Warmer than worm's dirt so paddles read
// against the grass (dirt-on-grass would blend).
const COLOR_LOG_BODY: Color = Color::rgb(0xA8, 0x72, 0x3A);
const COLOR_LOG_BARK: Color = Color::rgb(0x5C, 0x3A, 0x1E);
const COLOR_LOG_CAP_LIGHT: Color = Color::rgb(0xC8, 0x92, 0x5A);

// Acorn ball.
const COLOR_ACORN_BODY: Color = Color::rgb(0x8B, 0x5A, 0x2B);
const COLOR_ACORN_CAP: Color = Color::rgb(0xC8, 0xA0, 0x68);
const COLOR_ACORN_CAP_SHADOW: Color = Color::rgb(0x8A, 0x6A, 0x38);
const COLOR_ACORN_STEM: Color = Color::rgb(0x4A, 0x2F, 0x18);

const COLOR_TEXT: Color = Color::WHITE;
const COLOR_TITLE: Color = Color::rgb(0xB0, 0xE0, 0x90);
const COLOR_WIN_BANNER: Color = Color::rgb(0xFF, 0xC8, 0x80);

// --- top-level ---

pub fn draw(surf: &mut Surface, pong: &Pong) {
    surf.clear(COLOR_BG);
    draw_court(surf);
    draw_centerline(surf);
    draw_log_paddle(surf, LEFT_PADDLE_X, pong.left_paddle());
    draw_log_paddle(surf, RIGHT_PADDLE_X, pong.right_paddle());
    draw_acorn(surf, pong.ball());
    draw_status_bar(surf, pong);

    match pong.state() {
        State::Serving { ticks_remaining, .. } => {
            draw_serve_overlay(surf, ticks_remaining);
        }
        State::MatchOver { winner } => {
            draw_match_over(surf, winner);
        }
        State::Playing => {}
    }
}

// --- status bar ---

fn draw_status_bar(surf: &mut Surface, pong: &Pong) {
    surf.fill_rect(
        Rect { x: 0, y: 0, w: WINDOW_W as u16, h: STATUS_BAR_H },
        COLOR_STATUS_BG,
    );

    // "LEFT: N" flush-left, "PONG" centered, "RIGHT: N" flush-right.
    let left_text = format_score_label(b"LEFT", pong.left_score());
    draw_bytes(surf, 16, 16, &left_text, COLOR_TEXT);

    let title = "PONG";
    let title_w = title.len() as i32 * 8;
    let title_x = (WINDOW_W as i32 - title_w) / 2;
    surf.draw_text_builtin(title_x, 16, title, COLOR_TITLE);

    let right_text = format_score_label(b"RIGHT", pong.right_score());
    let right_w = right_text_len(&right_text) as i32 * 8;
    draw_bytes(
        surf,
        WINDOW_W as i32 - 16 - right_w,
        16,
        &right_text,
        COLOR_TEXT,
    );
}

// --- court ---

fn draw_court(surf: &mut Surface) {
    surf.fill_rect(
        Rect {
            x: COURT_ORIGIN_X as u16,
            y: COURT_ORIGIN_Y as u16,
            w: COURT_W as u16,
            h: COURT_H as u16,
        },
        COLOR_GRASS,
    );

    // Scatter grass tufts for texture — same technique as worm's
    // dirt-speck scatter. Deterministic (row/col-derived) so the
    // texture doesn't shimmer across frames.
    const TUFT_OFFSETS: [(u8, u8); 8] = [
        (3, 4), (11, 2), (5, 12), (14, 9),
        (8, 6), (2, 13), (15, 14), (10, 15),
    ];
    let tile = 16_i32;
    let cols = COURT_W / tile;
    let rows = COURT_H / tile;
    for row in 0..rows {
        for col in 0..cols {
            let base_x = COURT_ORIGIN_X + col * tile;
            let base_y = COURT_ORIGIN_Y + row * tile;
            let rot = ((row as usize).wrapping_mul(7).wrapping_add((col as usize).wrapping_mul(13)))
                % TUFT_OFFSETS.len();
            for i in 0..2 {
                let (dx, dy) = TUFT_OFFSETS[(rot + i) % TUFT_OFFSETS.len()];
                surf.set_pixel(base_x + dx as i32, base_y + dy as i32, COLOR_GRASS_TUFT);
            }
        }
    }
}

/// Dashed vertical line down the middle of the court — darker grass
/// tufts, 6 px dash + 6 px gap.
fn draw_centerline(surf: &mut Surface) {
    let cx = COURT_ORIGIN_X + COURT_W / 2;
    let dash_h = 6_i32;
    let gap_h = 6_i32;
    let mut y = COURT_ORIGIN_Y;
    let end = COURT_ORIGIN_Y + COURT_H;
    while y < end {
        let segment_end = (y + dash_h).min(end);
        surf.fill_rect(
            Rect {
                x: (cx - 1) as u16,
                y: y as u16,
                w: 3,
                h: (segment_end - y) as u16,
            },
            COLOR_GRASS_DARK,
        );
        y += dash_h + gap_h;
    }
}

// --- paddle (log) ---

/// A log viewed from the end: wood body + two dark bark striations +
/// bright highlight stripe for grain. `game_x` is the paddle's left
/// edge in game coordinates.
fn draw_log_paddle(surf: &mut Surface, game_x: i32, paddle: &Paddle) {
    let x = COURT_ORIGIN_X + game_x;
    let y = COURT_ORIGIN_Y + paddle.y_px();
    let rect = Rect { x: x as u16, y: y as u16, w: PADDLE_W as u16, h: PADDLE_H as u16 };

    surf.fill_rect(rect, COLOR_LOG_BODY);

    // Bark striations — two horizontal dark bands break the flat
    // body up so the paddle reads as a log rather than a painted rect.
    let stripe_h: u16 = 2;
    let stripe1_y = y + PADDLE_H / 4;
    let stripe2_y = y + 3 * PADDLE_H / 4;
    surf.fill_rect(
        Rect { x: x as u16, y: stripe1_y as u16, w: PADDLE_W as u16, h: stripe_h },
        COLOR_LOG_BARK,
    );
    surf.fill_rect(
        Rect { x: x as u16, y: stripe2_y as u16, w: PADDLE_W as u16, h: stripe_h },
        COLOR_LOG_BARK,
    );

    // Grain highlight — 1 px bright line running vertically just
    // left of center.
    let grain_x = x + PADDLE_W / 2 - 2;
    surf.draw_line(grain_x, y + 2, grain_x, y + PADDLE_H - 3, COLOR_LOG_CAP_LIGHT);

    // Dark bark outline on the two long edges (top and bottom caps
    // stay flat — logs viewed end-on).
    outline_rect(surf, rect, COLOR_LOG_BARK);
}

// --- ball (acorn) ---

/// 12×12 acorn. Top ~1/3 is the cap (tan with shadow lip), bottom
/// ~2/3 is the nut body (oak). A small stem dot sits on top, a
/// highlight pixel on the body.
fn draw_acorn(surf: &mut Surface, ball: &Ball) {
    let x = COURT_ORIGIN_X + ball.x_px();
    let y = COURT_ORIGIN_Y + ball.y_px();
    let w = BALL_SIZE;
    let h = BALL_SIZE;

    // Nut body — round-ish by chopping corners.
    surf.fill_rect(
        Rect { x: (x + 1) as u16, y: (y + 5) as u16, w: (w - 2) as u16, h: (h - 5) as u16 },
        COLOR_ACORN_BODY,
    );
    // Widen the body on one row to get a rounded silhouette.
    surf.fill_rect(
        Rect { x: x as u16, y: (y + 6) as u16, w: w as u16, h: 4 },
        COLOR_ACORN_BODY,
    );
    // Taper the bottom.
    surf.fill_rect(
        Rect { x: (x + 2) as u16, y: (y + h - 1) as u16, w: (w - 4) as u16, h: 1 },
        COLOR_ACORN_BODY,
    );

    // Cap — wider than the nut, sits on top.
    surf.fill_rect(
        Rect { x: x as u16, y: (y + 2) as u16, w: w as u16, h: 3 },
        COLOR_ACORN_CAP,
    );
    // Cap lip — thin shadow line where cap meets nut.
    surf.draw_line(x, y + 5, x + w - 1, y + 5, COLOR_ACORN_CAP_SHADOW);
    // Cap crosshatch — two diagonal dark pixels that suggest scales.
    surf.set_pixel(x + 3, y + 3, COLOR_ACORN_CAP_SHADOW);
    surf.set_pixel(x + 7, y + 3, COLOR_ACORN_CAP_SHADOW);

    // Stem — single dark pixel on top of the cap.
    surf.set_pixel(x + w / 2, y + 1, COLOR_ACORN_STEM);
    surf.set_pixel(x + w / 2, y, COLOR_ACORN_STEM);

    // Highlight on the nut body — diagonal 2 px gleam.
    surf.set_pixel(x + 3, y + 7, COLOR_ACORN_CAP);
    surf.set_pixel(x + 4, y + 8, COLOR_ACORN_CAP);
}

// --- overlays ---

fn draw_serve_overlay(surf: &mut Surface, ticks_remaining: u64) {
    // Centered "READY..." during the last 400ms countdown. A future
    // polish pass might animate a growing acorn; v0 stays minimal.
    let msg = if ticks_remaining > 20 { "READY..." } else { "SERVE!" };
    let msg_w = msg.len() as i32 * 8;
    let cx = (WINDOW_W as i32 - msg_w) / 2;
    let cy = COURT_ORIGIN_Y + COURT_H / 2 - 30;
    surf.draw_text_builtin(cx, cy, msg, COLOR_TITLE);
}

fn draw_match_over(surf: &mut Surface, winner: Side) {
    let panel_w: u16 = 320;
    let panel_h: u16 = 88;
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
    outline_rect(
        surf,
        Rect { x: x as u16, y: y as u16, w: panel_w, h: panel_h },
        COLOR_WIN_BANNER,
    );
    outline_rect(
        surf,
        Rect { x: (x + 2) as u16, y: (y + 2) as u16, w: panel_w - 4, h: panel_h - 4 },
        COLOR_WIN_BANNER,
    );

    let banner = "MATCH OVER";
    let banner_w = banner.len() as i32 * 8;
    surf.draw_text_builtin(
        x + (panel_w as i32 - banner_w) / 2,
        y + 16,
        banner,
        COLOR_WIN_BANNER,
    );

    let winner_line = match winner {
        Side::Left => "LEFT WINS",
        Side::Right => "RIGHT WINS",
    };
    let w_w = winner_line.len() as i32 * 8;
    surf.draw_text_builtin(
        x + (panel_w as i32 - w_w) / 2,
        y + 36,
        winner_line,
        COLOR_TEXT,
    );

    let hint = "PRESS R TO RESTART";
    let hint_w = hint.len() as i32 * 8;
    surf.draw_text_builtin(
        x + (panel_w as i32 - hint_w) / 2,
        y + 60,
        hint,
        COLOR_TEXT,
    );
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

/// Format "<label>: <N>" into a fixed buffer. Scores bounded by
/// WIN_SCORE so N is always 1 digit; label is 4 or 5 chars. Total ≤ 8.
fn format_score_label(label: &[u8], score: u8) -> [u8; 16] {
    debug_assert!(label.len() <= 8);
    debug_assert!(score <= WIN_SCORE);
    let mut out = [0u8; 16];
    let mut n = 0;
    for &b in label {
        out[n] = b;
        n += 1;
    }
    out[n] = b':';
    n += 1;
    out[n] = b' ';
    n += 1;
    out[n] = b'0' + score;
    // Remaining bytes stay zero (array was default-initialised) so
    // the renderer can walk until the first NUL.
    out
}

fn right_text_len(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

/// Draw a byte slice, stopping at the first NUL.
fn draw_bytes(surf: &mut Surface, x: i32, y: i32, buf: &[u8], color: Color) {
    let len = right_text_len(buf);
    if let Ok(s) = core::str::from_utf8(&buf[..len]) {
        surf.draw_text_builtin(x, y, s, color);
    }
}
