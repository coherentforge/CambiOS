// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Boot splash + persistent watermark.
//!
//! Visual identity matches the published site at
//! `coherentforge.com/cambios`:
//!
//! - Background `#0c0e11` (`--bg-0` — a very dark blue-black).
//! - "Cambi" and "TM" in `#e2e4e8` (`--fg-0`).
//! - "OS" in `#e85d3a` (`--accent`).
//!
//! The U+2122 ™ glyph isn't in the ASCII font bake, so we render
//! literal "TM" at half scale aligned to the top of the title cell —
//! the standard typographic treatment for a trademark superscript.
//!
//! ## Three phases (~2.6 s total)
//!
//! 1. **Hold (2.0 s)** — full wordmark `Cambi`**OS**`TM` at 4× scale,
//!    centered, full opacity on `--bg-0`.
//! 2. **Recede-to-watermark (~600 ms)** — wordmark animates from
//!    centered/4×/full-opacity to bottom-right/1×/~16%-opacity. Over
//!    the same window the "TM" cross-fades to invisible (a watermark
//!    drops the trademark; ™ is appropriate for the marketing
//!    wordmark, distracting on an ambient brand mark). The "increase
//!    in resolution" effect falls out for free: at 4× each glyph
//!    pixel is a 4×4 block (visibly chunky); at 1× each glyph pixel
//!    is a single antialiased pixel (sharp).
//! 3. **Steady state** — the small wordmark sits in the corner as a
//!    persistent watermark behind the live terminal grid. Drawing
//!    happens via the watermark band in [`crate::render`]: every
//!    dirty terminal row that intersects the watermark's y range
//!    re-stamps the watermark slice into its BG band before the
//!    cell glyphs draw on top. Conceptual z-index: watermark below,
//!    terminal above; same compositing semantics as a real layered
//!    z-stack, scoped to a single libgui surface.
//!
//! ## Conceptual z-index, not architectural z-index
//!
//! A "real" z-index — separate compositor layers, alpha-blended in
//! hardware — would be cleaner but requires non-trivial compositor
//! work (terminal-window opens two windows, compositor stacks them
//! with per-pixel alpha) and a two-buffer in-process model needs ~6 MB
//! that does not fit in the userspace heap. Re-stamping the watermark
//! per dirty row is the practical equivalent for a single window;
//! a follow-up can graduate to true layered windows when the
//! compositor's stacking story matures.

use cambios_libgui::{font_aa::AntialiasedFont, font_aa::BUILTIN_FONT_JBM, Color, Surface};
use cambios_libsys as sys;

use crate::gui_backend::GuiBackend;
use crate::render;

/// SCAFFOLDING: title scaling factor at the start of the splash. The
/// font's native cell is 16×32; 4× = 64×128 cell, which puts a
/// 7-glyph "CambiOS" at 448×128 — centered cleanly in the 1024×768
/// window with ~290 px margin on each side. Why: hands-on demo
/// proportions; bigger feels theatrical, smaller feels lost. Replace
/// when: the window dimensions become queryable at runtime or the
/// font bake re-runs at a different cell size.
const TITLE_SCALE: i32 = 4;

/// Half-scale for the trademark superscript during the hold frame.
const TM_SCALE: i32 = 2;

const PART_CAMBI: &[u8] = b"Cambi";
const PART_OS: &[u8] = b"OS";
const PART_TM: &[u8] = b"TM";

/// TUNING: hold duration in kernel ticks (100 Hz → 10 ms each).
/// 2.0 s per direct user feedback. Long enough to absorb the wordmark
/// color split deliberately, short enough that the user is not
/// waiting on it.
const HOLD_TICKS: u64 = 200;

/// TUNING: number of frames in the recede-to-watermark transition.
/// 12 frames at 5 ticks each = 600 ms total; smooth enough to read as
/// motion rather than a jump-cut, fast enough to feel responsive.
const TRANSITION_FRAMES: u32 = 12;
const TRANSITION_FRAME_TICKS: u64 = 5;

/// During recede, the "TM" cross-fades to invisible over a fraction of
/// the transition. 1/3 of the frames means TM is gone by frame 4 of 12,
/// the same beat at which the title scale-step drops from 4× to 3×.
const TM_FADE_FRAMES: u32 = TRANSITION_FRAMES / 3;

/// TUNING: watermark opacity in steady state. ~16 % of full intensity.
/// Visible enough to read on `--bg-0` and recognize from a couple of
/// meters away, recessive enough that the eye doesn't compete with
/// terminal content. Replace when: a follow-up A/B run shows a
/// different number reads better in actual demo lighting.
pub(crate) const WATERMARK_ALPHA: u8 = 0x28;

/// Watermark margin from window edges in pixels.
const WATERMARK_MARGIN: i32 = 16;

// Site palette (`coherentforge.com/cambios/css/style.css`).
pub(crate) const BG_0: Color = Color(0x00_0c_0e_11);
pub(crate) const FG_0: Color = Color(0x00_e2_e4_e8);
pub(crate) const ACCENT: Color = Color(0x00_e8_5d_3a);

/// Run the full splash sequence: hold → recede → steady. Blocks the
/// calling task for ~2.6 s. Returns once the watermark layer has been
/// stamped at its final corner position and the render path has been
/// told to preserve it on subsequent terminal redraws.
pub fn show(backend: &mut GuiBackend) {
    let win_w = backend.client().width() as i32;
    let win_h = backend.client().height() as i32;
    let font = &BUILTIN_FONT_JBM;

    // Watermark final geometry — bottom-right corner with a uniform
    // margin. Computed once, used both for the recede animation's
    // target frame and for the steady-state render-path coordination.
    let wm_x = win_w - watermark_total_w(font) - WATERMARK_MARGIN;
    let wm_y = win_h - (font.cell_h as i32) - WATERMARK_MARGIN;

    // Phase 1 — Hold the full wordmark for 2 s.
    paint_full_wordmark(backend, font);
    sleep_ticks(HOLD_TICKS);

    // Phase 2 — Recede to watermark over ~600 ms. 12 frames; each
    // interpolates scale, position, alpha; "TM" cross-fades to 0 in
    // the first third of the transition.
    let centered_x = (win_w - full_wordmark_total_w(font)) / 2;
    let centered_y = (win_h - (font.cell_h as i32) * TITLE_SCALE) / 2;
    for frame in 0..=TRANSITION_FRAMES {
        let t_num = frame;
        let t_den = TRANSITION_FRAMES;
        let scale = lerp_scale(TITLE_SCALE, 1, t_num, t_den);
        let alpha = lerp_u8(0xFF, WATERMARK_ALPHA, t_num, t_den);
        let x = lerp_i32(centered_x, wm_x, t_num, t_den);
        let y = lerp_i32(centered_y, wm_y, t_num, t_den);
        let tm_alpha = if frame >= TM_FADE_FRAMES {
            0
        } else {
            // Fade from 0xFF at frame 0 to 0 at frame TM_FADE_FRAMES.
            lerp_u8(0xFF, 0, frame, TM_FADE_FRAMES)
        };
        paint_recede_frame(backend, font, x, y, scale, alpha, tm_alpha);
        sleep_ticks(TRANSITION_FRAME_TICKS);
    }

    // Phase 3 — Hand the watermark over to the render path. From here,
    // every dirty terminal row that intersects the watermark's y range
    // re-stamps the watermark slice into its BG band before drawing
    // cell glyphs. Geometry passes through the render module's
    // `enable_watermark` so the row-fill path knows where to draw.
    render::enable_watermark(wm_x, wm_y);
}

/// Pixel width of the centered wordmark on the hold frame
/// (Cambi + OS + TM superscript).
fn full_wordmark_total_w(font: &AntialiasedFont) -> i32 {
    let cw = font.cell_w as i32;
    let body = ((PART_CAMBI.len() + PART_OS.len()) as i32) * cw * TITLE_SCALE;
    let tm = (PART_TM.len() as i32) * cw * TM_SCALE;
    body + tm
}

/// Pixel width of the steady-state watermark (Cambi + OS, no TM).
fn watermark_total_w(font: &AntialiasedFont) -> i32 {
    ((PART_CAMBI.len() + PART_OS.len()) as i32) * (font.cell_w as i32)
}

/// Phase 1 frame: clear and stamp the centered wordmark at full
/// opacity, with TM superscript visible.
fn paint_full_wordmark(backend: &mut GuiBackend, font: &AntialiasedFont) {
    let win_w = backend.client().width() as i32;
    let win_h = backend.client().height() as i32;
    let cw = font.cell_w as i32;

    let cambi_w = (PART_CAMBI.len() as i32) * cw * TITLE_SCALE;
    let os_w = (PART_OS.len() as i32) * cw * TITLE_SCALE;
    let tm_w = (PART_TM.len() as i32) * cw * TM_SCALE;
    let total_w = cambi_w + os_w + tm_w;
    let title_x = (win_w - total_w) / 2;
    let title_y = (win_h - (font.cell_h as i32) * TITLE_SCALE) / 2;

    let cambi_x = title_x;
    let os_x = cambi_x + cambi_w;
    let tm_x = os_x + os_w;
    let tm_y = title_y;

    {
        let mut surf = backend.client_mut().surface_mut();
        surf.clear(BG_0);
        draw_text_scaled(&mut surf, cambi_x, title_y, PART_CAMBI, TITLE_SCALE, FG_0, font);
        draw_text_scaled(&mut surf, os_x, title_y, PART_OS, TITLE_SCALE, ACCENT, font);
        draw_text_scaled(&mut surf, tm_x, tm_y, PART_TM, TM_SCALE, FG_0, font);
    }
    let _ = backend.client_mut().submit_full();
}

/// Phase 2 frame: clear and stamp the wordmark at an interpolated
/// scale / position / alpha. TM is rendered if `tm_alpha > 0` (early
/// frames of the transition); dropped completely afterward.
fn paint_recede_frame(
    backend: &mut GuiBackend,
    font: &AntialiasedFont,
    x: i32,
    y: i32,
    scale: i32,
    alpha: u8,
    tm_alpha: u8,
) {
    let cw = font.cell_w as i32;
    let cambi_w = (PART_CAMBI.len() as i32) * cw * scale;

    let fg_dim = blend_toward(FG_0, BG_0, alpha);
    let accent_dim = blend_toward(ACCENT, BG_0, alpha);

    {
        let mut surf = backend.client_mut().surface_mut();
        surf.clear(BG_0);
        draw_text_scaled(&mut surf, x, y, PART_CAMBI, scale, fg_dim, font);
        draw_text_scaled(&mut surf, x + cambi_w, y, PART_OS, scale, accent_dim, font);

        if tm_alpha > 0 {
            // Keep the TM at half the active scale during the cross-
            // fade so it stays in proportion to the shrinking title.
            let tm_scale = (scale / 2).max(1);
            let tm_dim = blend_toward(FG_0, BG_0, tm_alpha);
            let os_w = (PART_OS.len() as i32) * cw * scale;
            let tm_x = x + cambi_w + os_w;
            // TM y-anchor: top of the active cell band — same proportional
            // superscript position as the hold frame.
            draw_text_scaled(&mut surf, tm_x, y, PART_TM, tm_scale, tm_dim, font);
        }
    }
    let _ = backend.client_mut().submit_full();
}

// ─── Numeric helpers ──────────────────────────────────────────────

/// Stepped linear interpolation between two integer scale values.
/// Picks an integer scale (no sub-pixel scaling — `draw_text_scaled`
/// requires integer steps); steps proportionally with the transition
/// progress so 4 → 1 over 12 frames hits 4 / 3 / 2 / 1 cleanly.
fn lerp_scale(from: i32, to: i32, t: u32, span: u32) -> i32 {
    if span == 0 {
        return to;
    }
    let raw = (from as i64) - (((from - to) as i64) * (t as i64) / (span as i64));
    (raw as i32).max(to.min(from)).min(from.max(to))
}

fn lerp_u8(from: u8, to: u8, t: u32, span: u32) -> u8 {
    if span == 0 {
        return to;
    }
    let from_i = from as i32;
    let to_i = to as i32;
    let raw = from_i + (to_i - from_i) * (t as i32) / (span as i32);
    raw.clamp(0, 0xFF) as u8
}

fn lerp_i32(from: i32, to: i32, t: u32, span: u32) -> i32 {
    if span == 0 {
        return to;
    }
    from + (to - from) * (t as i32) / (span as i32)
}

/// Linear blend of `color` toward `bg` at the given `intensity`.
/// `intensity = 0xFF` returns `color` unchanged; `0x00` returns `bg`.
/// Used to fake a per-glyph alpha by pre-mixing the foreground toward
/// the background — the AA blit only carries one alpha channel
/// (the glyph mask), so the effective opacity needs to come from the
/// color itself.
pub(crate) fn blend_toward(color: Color, bg: Color, intensity: u8) -> Color {
    let i = intensity as u32;
    let inv = (255 - i) as u32;
    let cr = (color.0 >> 16) & 0xFF;
    let cg = (color.0 >> 8) & 0xFF;
    let cb = color.0 & 0xFF;
    let br = (bg.0 >> 16) & 0xFF;
    let bgg = (bg.0 >> 8) & 0xFF;
    let bb = bg.0 & 0xFF;
    let rr = ((cr * i + br * inv) / 255).min(0xFF);
    let rg = ((cg * i + bgg * inv) / 255).min(0xFF);
    let rb = ((cb * i + bb * inv) / 255).min(0xFF);
    Color((rr << 16) | (rg << 8) | rb)
}

// ─── Drawing primitives ──────────────────────────────────────────

/// Draw `text` at `(x, y)` with each glyph pixel stamped as a
/// `scale × scale` block. Pure surface manipulation; no allocation.
/// Alpha is preserved per-source-pixel so the antialiasing baked into
/// the font survives the upscale.
pub(crate) fn draw_text_scaled(
    surf: &mut Surface<'_>,
    x: i32,
    y: i32,
    text: &[u8],
    scale: i32,
    color: Color,
    font: &AntialiasedFont,
) {
    let cw = font.cell_w as i32;
    let ch = font.cell_h as i32;
    let mut pen_x = x;

    for &b in text {
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
fn sleep_ticks(n: u64) {
    let deadline = sys::get_time().saturating_add(n);
    while sys::get_time() < deadline {
        sys::yield_now();
    }
}
