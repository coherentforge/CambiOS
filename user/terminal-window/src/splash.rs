// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Boot splash — a centered "CambiOS" title rendered into the
//! compositor surface before the terminal REPL takes over.
//!
//! Three frames, ~1.6 s total:
//!
//! 1. **Hold-in (1.2 s):** title in dim cyan on black. Long enough for
//!    a hands-on observer to register it, short enough to not feel
//!    held.
//! 2. **Highlight (200 ms):** title flashed to white. Visual punctuation
//!    that the boot sequence has succeeded.
//! 3. **Wipe (200 ms):** clear to black. Avoids a hard cut from
//!    splash-text to terminal grid.
//!
//! Drawing happens directly on the libgui [`Surface`] — the `Grid`
//! layer (which is sized for monospace 16×32 cells) is bypassed so
//! the title can render at 4× scale without retrofitting Grid for
//! variable cell sizes.
//!
//! Sleep is implemented by polling `sys::get_time()` (kernel ticks at
//! 100 Hz) and `sys::yield_now()` so the scheduler keeps cooperative
//! control during the splash window.

use cambios_libgui::{font_aa::AntialiasedFont, font_aa::BUILTIN_FONT_JBM, Color, Surface};
use cambios_libsys as sys;

use crate::gui_backend::GuiBackend;

/// SCAFFOLDING: title scaling factor. The font's native cell is 16×32
/// (per `BUILTIN_FONT_JBM`); 4× = 64×128 cell, which puts a 7-char
/// "CambiOS" at 448×128 — centered cleanly in the 1024×768 window
/// with ~290 px margin on each side and prominent enough that a
/// hands-on observer reads it from a meter away.
/// Why: hands-on demo proportions; bigger feels theatrical, smaller
/// feels lost.
/// Replace when: the window dimensions become queryable at runtime
/// or the font bake re-runs at a different cell size.
const TITLE_SCALE: i32 = 4;

const TITLE_TEXT: &str = "CambiOS";

/// TUNING: hold-in duration in kernel ticks (100 Hz → 1 tick = 10 ms).
/// 1.2 seconds is the demo sweet spot — long enough to register, short
/// enough that the user isn't tapping the keyboard waiting.
const HOLD_TICKS: u64 = 120;

/// TUNING: highlight (white flash) duration. ~200 ms reads as
/// "punctuation," not as a separate event.
const HIGHLIGHT_TICKS: u64 = 20;

/// TUNING: black-frame wipe duration before the terminal banner. ~200 ms
/// gives the eye a moment to reset before text re-appears.
const WIPE_TICKS: u64 = 20;

const BG: Color = Color(0x00_00_00_00);
const CYAN_TITLE: Color = Color(0x00_00_CC_CC);
const WHITE_HIGHLIGHT: Color = Color(0x00_CC_CC_CC);

/// Run the full splash sequence: render → hold → highlight → wipe.
/// Blocks the calling task for ~1.6 s. Returns when the surface has
/// been cleared to BG and the post-splash banner is safe to write
/// through the Grid path.
pub fn show(backend: &mut GuiBackend) {
    let win_w = backend.client().width() as i32;
    let win_h = backend.client().height() as i32;
    let font = &BUILTIN_FONT_JBM;

    let cell_w = font.cell_w as i32 * TITLE_SCALE;
    let cell_h = font.cell_h as i32 * TITLE_SCALE;
    let text_w = (TITLE_TEXT.len() as i32) * cell_w;
    let x = (win_w - text_w) / 2;
    let y = (win_h - cell_h) / 2;

    paint_title(backend, x, y, CYAN_TITLE, font);
    sleep_ticks(HOLD_TICKS);

    paint_title(backend, x, y, WHITE_HIGHLIGHT, font);
    sleep_ticks(HIGHLIGHT_TICKS);

    paint_blank(backend);
    sleep_ticks(WIPE_TICKS);
}

/// Clear the surface to BG and stamp the title text in `color` at
/// `(x, y)` (top-left of first glyph cell). Submits a full FrameReady
/// so the compositor blits the surface to the scanout.
fn paint_title(backend: &mut GuiBackend, x: i32, y: i32, color: Color, font: &AntialiasedFont) {
    {
        let mut surf = backend.client_mut().surface_mut();
        surf.clear(BG);
        draw_text_scaled(&mut surf, x, y, TITLE_TEXT, TITLE_SCALE, color, font);
    }
    let _ = backend.client_mut().submit_full();
}

/// Clear the surface to BG and submit. Used as the wipe frame
/// between the splash and the terminal banner.
fn paint_blank(backend: &mut GuiBackend) {
    {
        let mut surf = backend.client_mut().surface_mut();
        surf.clear(BG);
    }
    let _ = backend.client_mut().submit_full();
}

/// Draw `text` at `(x, y)` with each glyph pixel stamped as a
/// `scale × scale` block of pixels. Pure surface manipulation; no
/// allocation. Alpha is preserved per-source-pixel so the
/// antialiasing baked into the font survives the upscale.
///
/// libgui's `draw_text_aa` is fixed at 1× scale; this is the
/// terminal-window-specific version that lets the splash look big
/// without changing the libgui API. If a second consumer ever wants
/// scaled text (a full-screen game title, a pause overlay), this
/// graduates into libgui as `draw_text_aa_scaled`.
fn draw_text_scaled(
    surf: &mut Surface<'_>,
    x: i32,
    y: i32,
    text: &str,
    scale: i32,
    color: Color,
    font: &AntialiasedFont,
) {
    let cw = font.cell_w as i32;
    let ch = font.cell_h as i32;
    let mut pen_x = x;

    for &b in text.as_bytes() {
        if let Some(glyph) = font.glyph(b) {
            for row in 0..ch {
                let row_off = (row as usize) * (cw as usize);
                for col in 0..cw {
                    let alpha = glyph[row_off + col as usize];
                    if alpha == 0 {
                        continue;
                    }
                    let dx = pen_x + col * scale;
                    let dy = y + row * scale;
                    stamp_block(surf, dx, dy, scale, color, alpha);
                }
            }
        }
        pen_x += cw * scale;
    }
}

/// Stamp a `scale × scale` block of pixels at `(x, y)` with `color`
/// blended at `alpha`. Inlined so the hot inner loop in
/// `draw_text_scaled` doesn't pay a call cost per pixel.
#[inline]
fn stamp_block(surf: &mut Surface<'_>, x: i32, y: i32, scale: i32, color: Color, alpha: u8) {
    if alpha == 0xFF {
        for sy in 0..scale {
            for sx in 0..scale {
                surf.set_pixel(x + sx, y + sy, color);
            }
        }
    } else {
        for sy in 0..scale {
            for sx in 0..scale {
                surf.blend_pixel(x + sx, y + sy, color, alpha);
            }
        }
    }
}

/// Cooperative sleep — yield until `n` kernel ticks have elapsed.
/// `sys::get_time()` returns monotonic ticks (10 ms each at 100 Hz);
/// the loop checks the deadline before each yield so an early-wake
/// (e.g., scheduler decided to run us anyway) doesn't undershoot.
fn sleep_ticks(n: u64) {
    let deadline = sys::get_time().saturating_add(n);
    while sys::get_time() < deadline {
        sys::yield_now();
    }
}
