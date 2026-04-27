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

use cambios_libgui::{font_aa::BUILTIN_FONT_JBM, Color, Rect, Surface};

use crate::grid::{Cell, Grid, ATTR_BOLD, ATTR_DIM, COLS, FG_DEFAULT, VISIBLE_ROWS};

/// Cell width = font cell width (advance is monospace in JBM, baked
/// into a 16-px slot). Pinned to the const baked into the font data so
/// any future re-bake at a different cell size lights this up at
/// compile time rather than silently mis-rendering.
pub const CELL_W: u16 = BUILTIN_FONT_JBM.cell_w;
/// Cell height = font cell height. 32 px in the current bake.
pub const CELL_H: u16 = BUILTIN_FONT_JBM.cell_h;

/// Background color (filled before each row's text is drawn).
/// Matches `--bg-0` from `coherentforge.com/cambios/css/style.css` so
/// the terminal's body shares the visual identity of the splash and
/// the published site — a deliberate dark blue-black, not pure black.
const BG: Color = Color(0x00_0c_0e_11);

/// Default foreground (the unstyled prompt color). Matches `--fg-0`
/// from the site's stylesheet — slightly cool off-white. Resolved by
/// `resolve_color` as the `FG_DEFAULT` base before dim/bold modifiers.
const FG_PLAIN: Color = Color(0x00_e2_e4_e8);

/// Caret color — block-style; covers the cell at the cursor. Pure
/// white reads against `BG` more cleanly than `FG_PLAIN` would,
/// signaling "this cell is active" rather than "this cell has text."
const CARET: Color = Color(0x00_FF_FF_FF);

// ─── ANSI 8-color palette ────────────────────────────────────────
//
// Standard VGA-compatible 8-color values; readable on a black
// background. The `cambios-style` crate only emits red / green /
// yellow / cyan + default + dim/bold on top, but the full table is
// here so unhandled SGR codes still resolve cleanly.

const PALETTE_BLACK:   Color = Color(0x00_00_00_00);
const PALETTE_RED:     Color = Color(0x00_CC_00_00);
const PALETTE_GREEN:   Color = Color(0x00_00_CC_00);
const PALETTE_YELLOW:  Color = Color(0x00_CC_CC_00);
const PALETTE_BLUE:    Color = Color(0x00_44_88_FF); // softened — pure blue is unreadable on black
const PALETTE_MAGENTA: Color = Color(0x00_CC_00_CC);
const PALETTE_CYAN:    Color = Color(0x00_00_CC_CC);
const PALETTE_WHITE:   Color = Color(0x00_CC_CC_CC);

/// Resolve a `(fg_idx, attrs)` pair into the RGBA color the renderer
/// will pass to `draw_text_aa`. `dim` halves brightness; `bold`
/// brightens to the high-intensity variant. Both attributes can apply
/// at once; bold then dim cancels the bold step (matches xterm).
fn resolve_color(fg: u8, attrs: u8) -> Color {
    let base = match fg {
        30 => PALETTE_BLACK,
        31 => PALETTE_RED,
        32 => PALETTE_GREEN,
        33 => PALETTE_YELLOW,
        34 => PALETTE_BLUE,
        35 => PALETTE_MAGENTA,
        36 => PALETTE_CYAN,
        37 => PALETTE_WHITE,
        FG_DEFAULT => FG_PLAIN,
        _ => FG_PLAIN, // unknown — fail soft to default
    };

    let dim_only = (attrs & ATTR_DIM) != 0;
    let bold_only = (attrs & ATTR_BOLD) != 0 && !dim_only;

    if dim_only {
        scale_brightness(base, 1, 2) // 50%
    } else if bold_only {
        scale_brightness(base, 5, 4).clamp_8bit() // 125%, clamped
    } else {
        base
    }
}

/// Scale every channel of a Color by `num/den` (saturating). Pure
/// integer math; no floating point.
fn scale_brightness(c: Color, num: u32, den: u32) -> Color {
    let raw = c.0;
    let r = ((raw >> 16) & 0xFF) as u32;
    let g = ((raw >> 8) & 0xFF) as u32;
    let b = (raw & 0xFF) as u32;
    let r2 = (r * num / den).min(0xFF);
    let g2 = (g * num / den).min(0xFF);
    let b2 = (b * num / den).min(0xFF);
    Color((r2 << 16) | (g2 << 8) | b2)
}

/// Identity helper that lets the bold path read more naturally
/// (`scale_brightness(...).clamp_8bit()`); `scale_brightness` already
/// clamps internally, so this is just a fluent no-op for readability.
trait ColorClamp {
    fn clamp_8bit(self) -> Self;
}

impl ColorClamp for Color {
    fn clamp_8bit(self) -> Self {
        self
    }
}

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
/// full cell band, then blit each cell's glyph through the AA font
/// using a color resolved from the cell's `(fg, attrs)` pair.
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
        let cell: Cell = grid.cell(c, row);
        let glyph = if (0x20..=0x7E).contains(&cell.glyph) {
            cell.glyph
        } else {
            b' '
        };
        let glyph_x = (c as i32) * (CELL_W as i32);
        // Single-glyph blit through draw_text_aa with a 1-byte slice.
        // SAFETY: `glyph` is in 0x20..=0x7E, guaranteed valid UTF-8.
        let s = unsafe { core::str::from_utf8_unchecked(core::slice::from_ref(&glyph)) };
        let color = resolve_color(cell.fg, cell.attrs);
        surf.draw_text_aa(glyph_x, glyph_y, s, color, &BUILTIN_FONT_JBM);
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
