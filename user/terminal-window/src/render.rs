// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Render path: blit dirty grid rows into the libgui [`Surface`] using
//! the 8×8 builtin font pixel-doubled to 16×16, plus a block caret at
//! the cursor position.
//!
//! Free function form rather than a method on a stateful struct so the
//! caller can split its `&mut self` borrows across `Client`, `Grid`,
//! and the small render state without fighting the borrow checker.
//!
//! ## Scaling
//!
//! libgui's `BUILTIN_FONT_8X8` is hand-drawn at 8×8. Rendered at native
//! resolution against a 1024×768 scanout, the resulting 128×96 grid
//! looks like a low-res framebuffer rather than a terminal — every
//! character occupies a tiny corner of an enormous window. Real
//! terminals at this window size land near 80×24 with substantial
//! glyph weight. We split the difference: render each 8×8 glyph as a
//! 16×16 block (each font pixel becomes a 2×2 destination square),
//! sit it inside a 16×32 cell, and drop to a 64×24 grid. That's 2×
//! integer scale — pixel-aligned, no anti-aliasing, exact font shape
//! preserved — and the result reads as the iconic 80×25 mode the
//! glyphs were originally drawn for.

use arcos_libgui::{font::BUILTIN_FONT_8X8, Color, Rect, Surface};

use crate::grid::{Grid, COLS, VISIBLE_ROWS};

/// Integer pixel-scale factor applied to the source 8×8 font when
/// blitting. Each font pixel becomes a `SCALE × SCALE` destination
/// block. 2 is the smallest value that meaningfully enlarges the
/// glyphs; the next step (3) overshoots the 1024×768 scanout when
/// combined with the 64-column grid.
pub const SCALE: u16 = 2;
/// Source font glyph width — fixed by `BUILTIN_FONT_8X8`.
pub const GLYPH_W: u16 = 8;
/// Source font glyph height — fixed by `BUILTIN_FONT_8X8`.
pub const GLYPH_H: u16 = 8;
/// Visible glyph extent on the destination surface, after 2× scale.
pub const SCALED_GLYPH_W: u16 = GLYPH_W * SCALE; // 16
pub const SCALED_GLYPH_H: u16 = GLYPH_H * SCALE; // 16
/// Cell width = scaled glyph width. No horizontal padding between
/// columns; characters sit flush, like every classic terminal.
pub const CELL_W: u16 = SCALED_GLYPH_W; // 16
/// Cell height with leading above + below the glyph. 32 = 16 px glyph
/// in the middle, 8 px above, 8 px below. 1024×768 / (16×32) =
/// 64 cols × 24 rows — the classic terminal aspect.
pub const CELL_H: u16 = 32;
/// Top-of-cell padding before the scaled glyph starts. `(CELL_H -
/// SCALED_GLYPH_H) / 2`, hand-evaluated so the const is `pub` for
/// any caller doing pixel math against the rendered grid.
pub const GLYPH_TOP_PAD: u16 = (CELL_H - SCALED_GLYPH_H) / 2; // 8

/// Background color (filled before each row's text is drawn).
const BG: Color = Color(0x00_00_00_00);
/// Foreground color (text glyph color).
const FG: Color = Color(0x00_CC_CC_CC);
/// Caret color — block-style; covers the cell at the cursor.
const CARET: Color = Color(0x00_FF_FF_FF);

/// Per-frame state retained between renders so the prior caret cell
/// can be wiped on cursor moves.
#[derive(Clone, Copy)]
pub struct RenderState {
    pub last_cursor_col: u16,
    pub last_cursor_row: u16,
    pub first_paint: bool,
}

impl RenderState {
    pub const fn new() -> Self {
        Self {
            last_cursor_col: 0,
            last_cursor_row: 0,
            first_paint: true,
        }
    }
}

impl Default for RenderState {
    fn default() -> Self {
        Self::new()
    }
}

/// Re-blit dirty rows + cursor caret. Clears the grid's dirty bits on
/// the way out so the next frame only redraws actual changes.
pub fn render(surf: &mut Surface, grid: &mut Grid, state: &mut RenderState) {
    let (cx, cy) = grid.cursor();

    // Make sure the row holding the previous caret position gets a
    // re-render so the stale white block is wiped, even if no cell
    // content changed there.
    let cursor_moved =
        cx != state.last_cursor_col || cy != state.last_cursor_row || state.first_paint;
    if cursor_moved {
        grid.mark_row_dirty(state.last_cursor_row as usize);
        grid.mark_row_dirty(cy as usize);
        state.first_paint = false;
    }

    for row in 0..VISIBLE_ROWS {
        if grid.is_dirty(row) {
            draw_row(surf, grid, row);
        }
    }

    draw_caret(surf, cx, cy);

    grid.clear_dirty();
    state.last_cursor_col = cx;
    state.last_cursor_row = cy;
}

/// Re-render row `row` as a single horizontal strip: fill BG over the
/// full cell height, then blit the row's glyphs at 2× scale into the
/// cell's glyph-data band (`GLYPH_TOP_PAD` px below the cell top).
fn draw_row(surf: &mut Surface, grid: &Grid, row: usize) {
    let cell_y = (row as u16) * CELL_H;

    surf.fill_rect(
        Rect {
            x: 0,
            y: cell_y,
            w: (COLS as u16) * CELL_W,
            h: CELL_H,
        },
        BG,
    );

    let glyph_y = (cell_y + GLYPH_TOP_PAD) as i32;
    for c in 0..COLS {
        let b = grid.cell(c, row);
        let ch = if (0x20..=0x7E).contains(&b) { b } else { b' ' };
        let glyph_x = (c as i32) * (CELL_W as i32);
        draw_glyph_scaled(surf, glyph_x, glyph_y, ch, FG);
    }
}

/// Blit a single 8×8 font glyph at `SCALE` integer scale: each set
/// font pixel becomes a `SCALE × SCALE` square in the destination
/// surface. Background is left untouched — `draw_row` is responsible
/// for the BG fill that happens before this is called.
fn draw_glyph_scaled(surf: &mut Surface, x: i32, y: i32, ch: u8, color: Color) {
    let rows = match BUILTIN_FONT_8X8.glyph(ch) {
        Some(r) => r,
        None => return,
    };
    let scale = SCALE as i32;
    for (row_i, &byte) in rows.iter().enumerate() {
        let py = y + (row_i as i32) * scale;
        for col in 0..(GLYPH_W as i32) {
            let bit = 7 - col;
            if (byte >> bit) & 1 == 1 {
                let px = x + col * scale;
                // Pixel-double in both axes.
                for dy in 0..scale {
                    for dx in 0..scale {
                        surf.set_pixel(px + dx, py + dy, color);
                    }
                }
            }
        }
    }
}

/// Stamp a block caret over the cell at `(col, row)`. Caret covers the
/// full cell (CELL_W × CELL_H) so it reads as a contiguous block
/// cursor without a horizontal stripe through it.
fn draw_caret(surf: &mut Surface, col: u16, row: u16) {
    let x = col * CELL_W;
    let y = row * CELL_H;
    surf.fill_rect(
        Rect {
            x,
            y,
            w: CELL_W,
            h: CELL_H,
        },
        CARET,
    );
}
