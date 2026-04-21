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
use crate::sprites;

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
const COLOR_GRASS_TUFT: Color = Color::rgb(0x78, 0xA8, 0x48); // grass tuft highlight
const COLOR_GRASS_HOVER: Color = Color::rgb(0xC8, 0xE8, 0xA0); // hovered-tile outline
const COLOR_DIRT: Color = Color::rgb(0x8B, 0x5A, 0x2B); // revealed non-mine
const COLOR_DIRT_DARK: Color = Color::rgb(0x5B, 0x3A, 0x1B); // dirt edge
const COLOR_DIRT_SPECK_LIGHT: Color = Color::rgb(0xB0, 0x7C, 0x40); // lighter pebble
const COLOR_DIRT_SPECK_DARK: Color = Color::rgb(0x6A, 0x3F, 0x1A); // darker pebble
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

    // "TREE" title on the left as the app identifier.
    surf.draw_text_builtin(16, 16, "TREE", Color::rgb(0xB0, 0xE0, 0x90));

    // "FLAGS N/10" on the right. Uppercase because the built-in
    // font's lowercase glyphs are blank placeholders (see libgui::font).
    //
    // On a win, display MINE_COUNT/MINE_COUNT regardless of how many
    // flags the player actually placed: a win implies every mine was
    // accounted for (9 dug-around trees + 1 implicitly-identified
    // last tree). Without the override, a player who solved without
    // needing to flag the last mine sees "FLAGS 9/10" under the
    // reforestation banner and it feels incomplete.
    let displayed_flags = match board.state() {
        State::Won => MINE_COUNT,
        _ => board.flags_placed(),
    };
    let mut buf = [0u8; 16];
    let n = format_flags(&mut buf, displayed_flags, MINE_COUNT);
    let label = core::str::from_utf8(&buf[..n]).unwrap_or("FLAGS ?");
    let label_w = n as i32 * 8;
    surf.draw_text_builtin(
        WINDOW_W as i32 - 16 - label_w,
        16,
        label,
        COLOR_TEXT,
    );
}

fn draw_tile(surf: &mut Surface, board: &Board, row: u8, col: u8, rect: Rect) {
    let cell = board.cell(row, col);
    let is_mine = board.is_mine(row, col);
    let state = board.state();

    // End-state overrides for mine tiles. Once the game is over, the
    // board is a tableau (forest on win, graveyard on loss) rather
    // than an interactive surface — every mine displays its final
    // form regardless of whether the player flagged it, revealed it,
    // or left it covered. Flagged non-mines fall through to the
    // normal cell-state branch (their seeds just never grew).
    if is_mine {
        match state {
            State::Won => {
                fill_grass_tile(surf, rect, row, col);
                sprites::draw_centered(
                    surf,
                    rect.x as i32,
                    rect.y as i32,
                    TILE_PX,
                    &sprites::TREE,
                );
                return;
            }
            State::Lost => {
                fill_dirt_tile(surf, rect, row, col);
                sprites::draw_centered(
                    surf,
                    rect.x as i32,
                    rect.y as i32,
                    TILE_PX,
                    &sprites::STUMP,
                );
                return;
            }
            State::Playing => {}
        }
    }

    match cell {
        Cell::Covered => {
            fill_grass_tile(surf, rect, row, col);
        }
        Cell::Flagged => {
            fill_grass_tile(surf, rect, row, col);
            // Planted seed — on win, this gets overridden above to
            // show a full TREE. Here we render the "waiting to grow"
            // state.
            sprites::draw_centered(
                surf,
                rect.x as i32,
                rect.y as i32,
                TILE_PX,
                &sprites::SEED,
            );
        }
        Cell::Revealed => {
            // is_mine mid-play (the clicked mine that ended the game)
            // is already handled in the end-state branch above when
            // state transitions to Lost. Reaching here with
            // is_mine == true would mean "game in progress AND this
            // cell holds a revealed mine," which is unreachable in
            // the current state machine. Silence the warning by
            // falling through to the dirt branch.
            fill_dirt_tile(surf, rect, row, col);
            let adj = board.adjacent(row, col);
            if adj > 0 {
                draw_centered_char(surf, rect, b'0' + adj, digit_color(adj));
            }
        }
    }
}

// ============================================================================
// Tile ground textures. Each tile gets a handful of deterministic
// noise pixels derived from its (row, col) position — so the texture
// is stable across redraws (no shimmer), varies between adjacent
// tiles (no visible tiling), and costs nothing to compute. 12 fixed
// intra-tile offsets, rotated per tile to pick different subsets.
// ============================================================================

/// Intra-tile (dx, dy) offsets for ground noise. All values in
/// [2, TILE_PX-2] so noise never bleeds into the edge outline.
const NOISE_OFFSETS: [(u8, u8); 12] = [
    (4, 5),  (11, 3),  (19, 7),  (24, 14),
    (3, 18), (8, 24),  (15, 20), (22, 25),
    (6, 13), (13, 11), (20, 16), (17, 27),
];

fn fill_grass_tile(surf: &mut Surface, rect: Rect, row: u8, col: u8) {
    surf.fill_rect(rect, COLOR_GRASS);
    outline_rect_inset(surf, rect, COLOR_GRASS_DARK);

    // 4 tufts per tile. Each tuft is a 2px vertical tick in a darker
    // green, suggesting a blade of grass catching light differently.
    let base_x = rect.x as i32;
    let base_y = rect.y as i32;
    let rot = ((row as usize).wrapping_mul(7).wrapping_add((col as usize).wrapping_mul(13))) % NOISE_OFFSETS.len();
    for i in 0..4 {
        let (dx, dy) = NOISE_OFFSETS[(rot + i) % NOISE_OFFSETS.len()];
        let x = base_x + dx as i32;
        let y = base_y + dy as i32;
        surf.set_pixel(x, y, COLOR_GRASS_TUFT);
        surf.set_pixel(x, y + 1, COLOR_GRASS_TUFT);
    }
}

fn fill_dirt_tile(surf: &mut Surface, rect: Rect, row: u8, col: u8) {
    surf.fill_rect(rect, COLOR_DIRT);
    outline_rect_inset(surf, rect, COLOR_DIRT_DARK);

    // 6 specks per tile — mix of lighter and darker pebble tones.
    // Reuses NOISE_OFFSETS rotated by a different stride so grass
    // and dirt textures don't visually align across reveal events.
    let base_x = rect.x as i32;
    let base_y = rect.y as i32;
    let rot = ((row as usize).wrapping_mul(11).wrapping_add((col as usize).wrapping_mul(5))) % NOISE_OFFSETS.len();
    for i in 0..6 {
        let (dx, dy) = NOISE_OFFSETS[(rot + i) % NOISE_OFFSETS.len()];
        let x = base_x + dx as i32;
        let y = base_y + dy as i32;
        let c = if i & 1 == 0 { COLOR_DIRT_SPECK_LIGHT } else { COLOR_DIRT_SPECK_DARK };
        surf.set_pixel(x, y, c);
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
