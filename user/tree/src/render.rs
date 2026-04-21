// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Tree renderer — consumes a `game::Board` + hover index + cursor
//! position and paints a full frame to a `libgui::Surface`.
//!
//! Full-surface redraw on every call. Damage-tracked partial redraw
//! is deferred (ADR-014's compositor already composites the whole
//! surface regardless of the FrameReady damage list, per libgui-proto).
//! Revisit when: compositor profiling shows frame build as a cost, OR
//! a second app with a larger surface ships.

use arcos_libgui::{Color, Rect, Surface, TileGrid};

use crate::game::{Board, Cell, State, BOARD_SIZE, MINE_COUNT};

// --- window / layout geometry (const so the caller can query) ---

pub const WINDOW_W: u32 = 352;
pub const WINDOW_H: u32 = 392;

/// Pixels per tile edge.
pub const TILE_PX: u16 = 32;
/// Gap between adjacent tiles.
pub const TILE_GAP: u16 = 2;
/// Top-left pixel of the top-left tile (board origin).
pub const BOARD_ORIGIN_X: i32 = 24;
pub const BOARD_ORIGIN_Y: i32 = 64;

/// Height of the top status bar ("Flags 3/10" readout).
pub const STATUS_BAR_H: u32 = 40;

// --- palette ---

const COLOR_BG: Color = Color::rgb(0x1E, 0x2A, 0x14); // deep forest-floor
const COLOR_STATUS_BG: Color = Color::rgb(0x2B, 0x1C, 0x0E); // darker dirt
const COLOR_GRASS: Color = Color::rgb(0x5A, 0x8F, 0x3E); // covered tile
const COLOR_GRASS_DARK: Color = Color::rgb(0x3E, 0x6A, 0x2A); // shade for grass edges
const COLOR_GRASS_HOVER: Color = Color::rgb(0xC8, 0xE8, 0xA0); // hovered-tile outline
const COLOR_DIRT: Color = Color::rgb(0x8B, 0x5A, 0x2B); // revealed non-mine
const COLOR_DIRT_DARK: Color = Color::rgb(0x5B, 0x3A, 0x1B); // dirt edge
const COLOR_TREE_GONE: Color = Color::rgb(0x4A, 0x2B, 0x14); // revealed mine (lost)
const COLOR_FLAG: Color = Color::rgb(0xE8, 0xD8, 0x2E); // flag glyph
const COLOR_TEXT: Color = Color::WHITE;

// Classic minesweeper adjacency digit palette.
fn digit_color(count: u8) -> Color {
    match count {
        1 => Color::rgb(0x20, 0x60, 0xE0), // blue
        2 => Color::rgb(0x20, 0x80, 0x20), // green
        3 => Color::rgb(0xE0, 0x30, 0x30), // red
        4 => Color::rgb(0x20, 0x20, 0x80), // navy
        5 => Color::rgb(0x80, 0x20, 0x20), // dark red
        6 => Color::rgb(0x20, 0x80, 0x80), // teal
        7 => Color::BLACK,
        8 => Color::rgb(0x60, 0x60, 0x60),
        _ => Color::WHITE,
    }
}

pub fn grid() -> TileGrid {
    TileGrid::new(
        BOARD_ORIGIN_X,
        BOARD_ORIGIN_Y,
        TILE_PX,
        TILE_PX,
        BOARD_SIZE as u16,
        BOARD_SIZE as u16,
        TILE_GAP,
    )
}

/// Reverse hit-test: given pixel coords in surface space, return the
/// (col, row) of the tile if any, else None. libgui::TileGrid doesn't
/// expose hit_test in v0 — we do it locally; promote if a second
/// consumer lands.
pub fn tile_at(px: i32, py: i32) -> Option<(u8, u8)> {
    let rel_x = px - BOARD_ORIGIN_X;
    let rel_y = py - BOARD_ORIGIN_Y;
    if rel_x < 0 || rel_y < 0 {
        return None;
    }
    let stride = TILE_PX as i32 + TILE_GAP as i32;
    let col_full = rel_x / stride;
    let row_full = rel_y / stride;
    let col_in = rel_x % stride;
    let row_in = rel_y % stride;
    if col_in >= TILE_PX as i32 || row_in >= TILE_PX as i32 {
        // Gap between tiles — not on any tile.
        return None;
    }
    if col_full >= BOARD_SIZE as i32 || row_full >= BOARD_SIZE as i32 {
        return None;
    }
    Some((col_full as u8, row_full as u8))
}

/// Draw one full frame representing `board` + hover + cursor state.
pub fn draw(
    surf: &mut Surface,
    board: &Board,
    hovered: Option<(u8, u8)>,
    cursor: (i32, i32),
) {
    surf.clear(COLOR_BG);
    draw_status_bar(surf, board);

    let tg = grid();
    for row in 0..BOARD_SIZE {
        for col in 0..BOARD_SIZE {
            let rect = match tg.tile_rect(col as u16, row as u16) {
                Some(r) => r,
                None => continue,
            };
            draw_tile(surf, board, row, col, rect);
        }
    }

    if let Some((hc, hr)) = hovered {
        if let Some(rect) = tg.tile_rect(hc as u16, hr as u16) {
            outline_rect(surf, rect, COLOR_GRASS_HOVER);
        }
    }

    match board.state() {
        State::Won => draw_end_panel(surf, "AHH - REFORESTATION", Color::rgb(0xA0, 0xFF, 0xA0)),
        State::Lost => draw_end_panel(surf, "BOO - DEFORESTATION", Color::rgb(0xFF, 0x80, 0x80)),
        State::Playing => {}
    }

    // Tiny cursor crosshair so the player sees where the pointer is
    // when it's hovering over the gap between tiles or the status bar
    // (the hovered-tile outline only fires over tiles). Small enough
    // not to obscure content; QEMU cursor is invisible so this is the
    // only feedback.
    draw_cursor(surf, cursor);
}

fn draw_status_bar(surf: &mut Surface, board: &Board) {
    surf.fill_rect(
        Rect { x: 0, y: 0, w: WINDOW_W as u16, h: STATUS_BAR_H as u16 },
        COLOR_STATUS_BG,
    );
    // "FLAGS N/10" — uppercase because the built-in font's lowercase
    // glyphs are blank placeholders (see libgui::font).
    let mut buf = [0u8; 16];
    let n = format_flags(&mut buf, board.flags_placed(), MINE_COUNT);
    let label = core::str::from_utf8(&buf[..n]).unwrap_or("FLAGS ?");
    surf.draw_text_builtin(16, 16, label, COLOR_TEXT);

    // "TREE" title on the right as a visual anchor.
    let title = "TREE";
    let title_w = title.len() as i32 * 8;
    surf.draw_text_builtin(
        WINDOW_W as i32 - 16 - title_w,
        16,
        title,
        Color::rgb(0xB0, 0xE0, 0x90),
    );
}

fn draw_tile(surf: &mut Surface, board: &Board, row: u8, col: u8, rect: Rect) {
    let cell = board.cell(row, col);
    let is_mine = board.is_mine(row, col);
    let state = board.state();

    match cell {
        Cell::Covered => {
            // On loss, reveal un-flagged mines so the player sees
            // where they were. Matches minesweeper convention.
            if state == State::Lost && is_mine {
                surf.fill_rect(rect, COLOR_TREE_GONE);
                outline_rect_inset(surf, rect, COLOR_DIRT_DARK);
                draw_centered_char(surf, rect, b'T', Color::rgb(0xE0, 0x40, 0x40));
            } else {
                surf.fill_rect(rect, COLOR_GRASS);
                outline_rect_inset(surf, rect, COLOR_GRASS_DARK);
            }
        }
        Cell::Flagged => {
            surf.fill_rect(rect, COLOR_GRASS);
            outline_rect_inset(surf, rect, COLOR_GRASS_DARK);
            // On loss, show wrong flags with a different mark — but
            // for v0 keep it simple: flag is always the F glyph.
            draw_centered_char(surf, rect, b'F', COLOR_FLAG);
        }
        Cell::Revealed => {
            if is_mine {
                // The tile the player actually dug up to end the game.
                surf.fill_rect(rect, COLOR_TREE_GONE);
                outline_rect_inset(surf, rect, COLOR_DIRT_DARK);
                draw_centered_char(surf, rect, b'T', Color::rgb(0xFF, 0x30, 0x30));
            } else {
                surf.fill_rect(rect, COLOR_DIRT);
                outline_rect_inset(surf, rect, COLOR_DIRT_DARK);
                let adj = board.adjacent(row, col);
                if adj > 0 {
                    draw_centered_char(surf, rect, b'0' + adj, digit_color(adj));
                }
            }
        }
    }
}

fn draw_end_panel(surf: &mut Surface, message: &str, text_color: Color) {
    let panel_w: u16 = 280;
    let panel_h: u16 = 72;
    let x = ((WINDOW_W as i32) - panel_w as i32) / 2;
    let y = ((WINDOW_H as i32) - panel_h as i32) / 2;
    // Shadow for separation from the board.
    surf.fill_rect(
        Rect { x: (x + 3) as u16, y: (y + 3) as u16, w: panel_w, h: panel_h },
        Color::rgb(0x08, 0x08, 0x08),
    );
    surf.fill_rect(
        Rect { x: x as u16, y: y as u16, w: panel_w, h: panel_h },
        Color::BLACK,
    );
    // Double border for a little weight.
    outline_rect(
        surf,
        Rect { x: x as u16, y: y as u16, w: panel_w, h: panel_h },
        text_color,
    );
    outline_rect(
        surf,
        Rect { x: (x + 2) as u16, y: (y + 2) as u16, w: panel_w - 4, h: panel_h - 4 },
        text_color,
    );

    let msg_w = message.len() as i32 * 8;
    let msg_x = x + (panel_w as i32 - msg_w) / 2;
    let msg_y = y + 20;
    surf.draw_text_builtin(msg_x, msg_y, message, text_color);

    let hint = "PRESS R TO RESTART";
    let hint_w = hint.len() as i32 * 8;
    let hint_x = x + (panel_w as i32 - hint_w) / 2;
    let hint_y = y + 44;
    surf.draw_text_builtin(hint_x, hint_y, hint, COLOR_TEXT);
}

fn draw_cursor(surf: &mut Surface, cursor: (i32, i32)) {
    let (cx, cy) = cursor;
    // 7-pixel crosshair.
    surf.draw_line(cx - 3, cy, cx + 3, cy, COLOR_TEXT);
    surf.draw_line(cx, cy - 3, cx, cy + 3, COLOR_TEXT);
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

fn outline_rect_inset(surf: &mut Surface, rect: Rect, color: Color) {
    // Same as outline_rect; name signals "interior separator line, not
    // a hover indicator." Kept as a separate name so a future polish
    // pass (e.g. two-tone bevel) has an obvious call site.
    outline_rect(surf, rect, color);
}

/// Draw a single glyph centered inside `rect`. 8×8 built-in font.
fn draw_centered_char(surf: &mut Surface, rect: Rect, ch: u8, color: Color) {
    let glyph_w = 8i32;
    let glyph_h = 8i32;
    let x = rect.x as i32 + (rect.w as i32 - glyph_w) / 2;
    let y = rect.y as i32 + (rect.h as i32 - glyph_h) / 2;
    let s = [ch, 0];
    let text = core::str::from_utf8(&s[..1]).unwrap_or("?");
    surf.draw_text_builtin(x, y, text, color);
}

/// Format "FLAGS N/M" into buf without heap / itoa / format!. Returns
/// bytes written. Always fits in 16 bytes for N, M in 0..=99.
fn format_flags(buf: &mut [u8; 16], placed: u8, total: u8) -> usize {
    let prefix = b"FLAGS ";
    let mut n = 0usize;
    for &b in prefix {
        buf[n] = b;
        n += 1;
    }
    n += write_u8(&mut buf[n..], placed);
    buf[n] = b'/';
    n += 1;
    n += write_u8(&mut buf[n..], total);
    n
}

fn write_u8(buf: &mut [u8], mut v: u8) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 3];
    let mut i = 0;
    while v > 0 {
        digits[i] = b'0' + (v % 10);
        v /= 10;
        i += 1;
    }
    // Reverse into buf.
    for k in 0..i {
        buf[k] = digits[i - 1 - k];
    }
    i
}
