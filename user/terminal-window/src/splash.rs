// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Boot splash — a centered "CambiOS™" wordmark rendered into the
//! compositor surface before the terminal REPL takes over.
//!
//! Visual identity matches the published site at
//! `coherentforge.com/cambios`:
//!
//! - Background `#0c0e11` (`--bg-0` from the site's CSS — a very dark
//!   blue-black, not pure black).
//! - "Cambi" and "™" in `#e2e4e8` (`--fg-0`, the slightly cool off-white
//!   the site uses for primary text).
//! - "OS" in `#e85d3a` (`--accent`, the orange the site uses for brand
//!   emphasis — same span that the site's `<span>OS</span>` carries).
//!
//! The trademark glyph U+2122 isn't in the ASCII font bake, so we
//! render literal "TM" at half scale aligned to the top of the title
//! cell — which is the standard typographic treatment for a
//! trademark superscript anyway.
//!
//! Two frames, ~2.2 s total:
//!
//! 1. **Hold (2.0 s):** wordmark on `--bg-0`. 2 s is the demo sweet
//!    spot per direct user feedback — long enough to register and read
//!    the colors deliberately, short enough that the user isn't
//!    waiting on it.
//! 2. **Wipe (200 ms):** clear to `--bg-0`. Avoids a hard cut from
//!    splash-text to terminal grid; the terminal banner then writes
//!    over the same dark background, so the seam is invisible.
//!
//! Drawing happens directly on the libgui [`Surface`] — the `Grid`
//! layer (sized for monospace 16×32 cells) is bypassed so the title
//! can render at 4× scale without retrofitting Grid for variable cell
//! sizes. Sleep is implemented by polling `sys::get_time()` (kernel
//! ticks at 100 Hz) and `sys::yield_now()` so the scheduler keeps
//! cooperative control during the splash window.

use cambios_libgui::{font_aa::AntialiasedFont, font_aa::BUILTIN_FONT_JBM, Color, Surface};
use cambios_libsys as sys;

use crate::gui_backend::GuiBackend;

/// SCAFFOLDING: title scaling factor. The font's native cell is 16×32
/// (per `BUILTIN_FONT_JBM`); 4× = 64×128 cell, which puts a 7-glyph
/// "CambiOS" at 448×128 — centered cleanly in the 1024×768 window
/// with ~290 px margin on each side, prominent enough that a hands-on
/// observer reads it from a meter away. The trademark "TM" superscript
/// at half this scale sits in the top-right of the cell band like a
/// proper typographic ™.
/// Why: hands-on demo proportions; bigger feels theatrical, smaller
/// feels lost.
/// Replace when: the window dimensions become queryable at runtime
/// or the font bake re-runs at a different cell size.
const TITLE_SCALE: i32 = 4;

const TM_SCALE: i32 = 2;

const PART_CAMBI: &str = "Cambi";
const PART_OS: &str = "OS";
const PART_TM: &str = "TM";

/// TUNING: hold duration in kernel ticks (100 Hz → 1 tick = 10 ms).
/// 2.0 s per direct user feedback (was 1.2 s in the first cut, felt
/// rushed). Long enough that the eye reads "Cambi**OS**™" and absorbs
/// the wordmark color split deliberately, short enough that the user
/// is not waiting.
const HOLD_TICKS: u64 = 200;

/// TUNING: black-frame wipe duration before the terminal banner.
/// ~200 ms gives the eye a moment to reset before text reappears.
const WIPE_TICKS: u64 = 20;

// Site palette (`coherentforge.com/cambios/css/style.css`).
const BG_0: Color = Color(0x00_0c_0e_11);
const FG_0: Color = Color(0x00_e2_e4_e8);
const ACCENT: Color = Color(0x00_e8_5d_3a);

/// Run the full splash sequence: render → hold → wipe. Blocks the
/// calling task for ~2.2 s. Returns when the surface has been
/// cleared to `--bg-0` and the post-splash banner is safe to write
/// through the Grid path.
pub fn show(backend: &mut GuiBackend) {
    let win_w = backend.client().width() as i32;
    let win_h = backend.client().height() as i32;
    let font = &BUILTIN_FONT_JBM;

    let cw = font.cell_w as i32;
    let ch = font.cell_h as i32;

    // Title geometry, derived so the three parts (Cambi / OS / TM)
    // line up against a single baseline. Widths are computed from
    // glyph counts × scaled cell width; total width centers in the
    // window. The TM superscript sits flush with the title's left
    // edge of its own slot at half scale.
    let cambi_w = (PART_CAMBI.len() as i32) * cw * TITLE_SCALE;
    let os_w = (PART_OS.len() as i32) * cw * TITLE_SCALE;
    let tm_w = (PART_TM.len() as i32) * cw * TM_SCALE;
    let total_w = cambi_w + os_w + tm_w;
    let title_x = (win_w - total_w) / 2;
    let title_y = (win_h - ch * TITLE_SCALE) / 2;

    let cambi_x = title_x;
    let os_x = cambi_x + cambi_w;
    // The TM glyph block sits flush with the top of the title cell —
    // the standard "raised" superscript position. At half scale the
    // glyph cell is half the height of the surrounding letters; the
    // top edges align with the title's top.
    let tm_x = os_x + os_w;
    let tm_y = title_y;

    paint_wordmark(
        backend,
        font,
        cambi_x,
        os_x,
        tm_x,
        title_y,
        tm_y,
    );
    sleep_ticks(HOLD_TICKS);

    paint_blank(backend);
    sleep_ticks(WIPE_TICKS);
}

/// Clear the surface to `--bg-0` and stamp the three-part wordmark
/// in matching colors. Submits a full FrameReady so the compositor
/// blits the surface to the scanout.
fn paint_wordmark(
    backend: &mut GuiBackend,
    font: &AntialiasedFont,
    cambi_x: i32,
    os_x: i32,
    tm_x: i32,
    title_y: i32,
    tm_y: i32,
) {
    {
        let mut surf = backend.client_mut().surface_mut();
        surf.clear(BG_0);
        draw_text_scaled(&mut surf, cambi_x, title_y, PART_CAMBI, TITLE_SCALE, FG_0, font);
        draw_text_scaled(&mut surf, os_x, title_y, PART_OS, TITLE_SCALE, ACCENT, font);
        draw_text_scaled(&mut surf, tm_x, tm_y, PART_TM, TM_SCALE, FG_0, font);
    }
    let _ = backend.client_mut().submit_full();
}

/// Clear the surface to `--bg-0` and submit. Used as the wipe frame
/// between the splash and the terminal banner.
fn paint_blank(backend: &mut GuiBackend) {
    {
        let mut surf = backend.client_mut().surface_mut();
        surf.clear(BG_0);
    }
    let _ = backend.client_mut().submit_full();
}

/// Draw `text` at `(x, y)` with each glyph pixel stamped as a
/// `scale × scale` block of pixels. Pure surface manipulation; no
/// allocation. Alpha is preserved per-source-pixel so the
/// antialiasing baked into the font survives the upscale.
///
/// libgui's `draw_text_aa` is fixed at 1× scale; this is the
/// terminal-window-specific version that lets the splash render at
/// whatever scale the wordmark needs without changing the libgui API.
/// If a second consumer ever wants scaled text (a full-screen game
/// title, a pause overlay), this graduates into libgui as
/// `draw_text_aa_scaled`.
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
