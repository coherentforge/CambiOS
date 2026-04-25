// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Render path: blit dirty grid rows into the libgui [`Surface`] using
//! the antialiased JetBrains Mono font, plus a block caret at the
//! cursor position.
//!
//! Free function form rather than a method on a stateful struct so the
//! caller can split its `&mut self` borrows across `Client`, `Grid`,
//! and the small render state without fighting the borrow checker.
//!
//! ## Why JetBrains Mono
//!
//! Earlier passes of this file rendered through libgui's hand-drawn
//! `BUILTIN_FONT_8X8` — first at native scale (squished), then at 2×
//! integer scale (readable but visibly retro). Both are 1-bit-per-pixel
//! masks; a "modern terminal" look needs antialiased glyphs, which
//! means a real font.
//!
//! `BUILTIN_FONT_JBM` is JetBrains Mono Regular pre-rasterized into a
//! 16×32 cell at host build time by `tools/bake-font` (the TTF lives
//! under `assets/fonts/`, never enters the kernel image). Each glyph
//! pixel is an alpha 0..=255; the renderer alpha-blends each opaque-ish
//! pixel against the surface background. Cell layout is the same 16×32
//! we already had for the 2× scaled bitmap — so the grid stays at
//! 64×24 and the rest of the world doesn't notice the swap.

use arcos_libgui::{font_aa::BUILTIN_FONT_JBM, Color, Rect, Surface};

use crate::grid::{Grid, COLS, VISIBLE_ROWS};

/// Cell width = font cell width (advance is monospace in JBM, baked
/// into a 16-px slot). Pinned to the const baked into the font data so
/// any future re-bake at a different cell size lights this up at
/// compile time rather than silently mis-rendering.
pub const CELL_W: u16 = BUILTIN_FONT_JBM.cell_w;
/// Cell height = font cell height. 32 px in the current bake.
pub const CELL_H: u16 = BUILTIN_FONT_JBM.cell_h;

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
/// full cell band, then blit each cell's glyph through the AA font.
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

    // The glyph cell already includes built-in vertical leading from
    // the bake step (ascent + descent + balanced top/bottom margin),
    // so we draw the glyph at the cell origin — no extra
    // GLYPH_TOP_PAD shift here.
    let glyph_y = cell_y as i32;
    for c in 0..COLS {
        let b = grid.cell(c, row);
        let ch = if (0x20..=0x7E).contains(&b) { b } else { b' ' };
        let glyph_x = (c as i32) * (CELL_W as i32);
        // Single-glyph blit through draw_text_aa with a 1-byte slice.
        // SAFETY: `ch` is in 0x20..=0x7E, guaranteed valid UTF-8.
        let s = unsafe { core::str::from_utf8_unchecked(core::slice::from_ref(&ch)) };
        surf.draw_text_aa(glyph_x, glyph_y, s, FG, &BUILTIN_FONT_JBM);
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
