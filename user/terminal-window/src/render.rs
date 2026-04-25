// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Render path: blit dirty grid rows into the libgui [`Surface`] using
//! the 8×8 builtin font, plus a block caret at the cursor position.
//!
//! Free function form rather than a method on a stateful struct so the
//! caller can split its `&mut self` borrows across `Client`, `Grid`,
//! and the small render state without fighting the borrow checker.

use arcos_libgui::{Color, Rect, Surface};

use crate::grid::{Grid, COLS, VISIBLE_ROWS};

/// Glyph cell width in pixels — fixed by the builtin 8×8 font.
pub const GLYPH_W: u16 = 8;
/// Glyph cell height in pixels — fixed by the builtin 8×8 font.
pub const GLYPH_H: u16 = 8;

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

/// Re-render row `row` as a single horizontal strip: fill BG, then
/// blit the entire row of cells through the builtin 8×8 font.
fn draw_row(surf: &mut Surface, grid: &Grid, row: usize) {
    let y = (row as u16) * GLYPH_H;

    surf.fill_rect(
        Rect {
            x: 0,
            y,
            w: (COLS as u16) * GLYPH_W,
            h: GLYPH_H,
        },
        BG,
    );

    // Build a contiguous &str of the row's printable bytes for
    // `draw_text_builtin`. The grid only ever stores ASCII (we
    // sanitise non-printable on write_byte) but defensively replace
    // any rogue byte with a space so `from_utf8_unchecked` is sound.
    let mut buf = [b' '; COLS];
    for c in 0..COLS {
        let b = grid.cell(c, row);
        buf[c] = if (0x20..=0x7E).contains(&b) { b } else { b' ' };
    }
    // SAFETY: every byte is in 0x20..=0x7E, which is valid UTF-8.
    let text = unsafe { core::str::from_utf8_unchecked(&buf) };
    surf.draw_text_builtin(0, y as i32, text, FG);
}

/// Stamp a block caret over the cell at `(col, row)`.
fn draw_caret(surf: &mut Surface, col: u16, row: u16) {
    let x = col * GLYPH_W;
    let y = row * GLYPH_H;
    surf.fill_rect(
        Rect {
            x,
            y,
            w: GLYPH_W,
            h: GLYPH_H,
        },
        CARET,
    );
}
