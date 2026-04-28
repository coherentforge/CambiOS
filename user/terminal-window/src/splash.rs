// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Boot splash on the back layer of a two-layer compositor stack.
//!
//! [`run`] opens a back-layer window (z=0, opaque), renders the
//! "CambiOS™" wordmark on it, runs the recede animation that shrinks
//! the wordmark to a centered low-opacity watermark, and returns the
//! still-alive [`Client`] to the caller. The caller keeps that client
//! alive for the life of the process so the watermark stays mapped
//! and the compositor keeps the back layer in its window table.
//!
//! The terminal grid then opens a front layer (z=1, alpha-blend) on
//! top via [`crate::gui_backend::GuiBackend::open_layer`]. The front
//! layer's BG fill is fully transparent, so wherever a cell has no
//! glyph the back layer's watermark shows through. Wherever a cell
//! has a glyph the compositor alpha-blends the (opaque) glyph over
//! the watermark.
//!
//! Visual identity matches the published site at
//! `coherentforge.com/cambios`:
//!
//! - Background `#0c0e11` (`--bg-0`).
//! - "Cambi" / "TM" in `#e2e4e8` (`--fg-0`).
//! - "OS" in `#e85d3a` (`--accent`).
//!
//! ## Three phases (~3.6 s total)
//!
//! 1. **Hold (2.0 s)** — full wordmark `Cambi`**OS**`TM` at 4× scale,
//!    centered, full opacity on `--bg-0`.
//! 2. **Recede-to-watermark (~1.0 s, 100 frames)** — wordmark animates
//!    from 4×/full-opacity to 1×/25%-opacity, staying centered. Over
//!    the same window the "TM" cross-fades to invisible in the first
//!    third (a watermark drops the trademark; ™ is appropriate for
//!    the marketing wordmark, distracting on an ambient brand mark).
//! 3. **Steady state** — the small wordmark sits centered on the back
//!    layer at 25% intensity. The front layer (created by the caller
//!    after [`run`] returns) renders the live terminal grid in front
//!    of it. Cells without text leave the watermark fully visible
//!    through the alpha-blend; cells with text composite on top.

use cambios_libgui::{font_aa::AntialiasedFont, font_aa::BUILTIN_FONT_JBM, Client, ClientError, Color, Surface};
use cambios_libsys as sys;

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
/// 100 frames at 1 tick each = 1000 ms total. Saturates the kernel
/// timer (100 Hz) for maximum smoothness; the integer scale steps
/// (4 / 3 / 2 / 1) remain visible but the surrounding continuous
/// motion makes them subordinate.
const TRANSITION_FRAMES: u32 = 100;
const TRANSITION_FRAME_TICKS: u64 = 1;

/// During recede, the "TM" cross-fades to invisible over the first
/// third of the transition.
const TM_FADE_FRAMES: u32 = TRANSITION_FRAMES / 3;

/// TUNING: watermark opacity in steady state. 25% of full intensity
/// (0x40 / 0xFF) — calibrated under direct user review against the
/// dark-blue-black `--bg-0` background. Replace when: a follow-up
/// A/B run shows a different number reads better in actual demo
/// lighting.
const WATERMARK_ALPHA: u8 = 0x40;

// Site palette (`coherentforge.com/cambios/css/style.css`).
const BG_0: Color = Color(0x00_0c_0e_11);
const FG_0: Color = Color(0x00_e2_e4_e8);
const ACCENT: Color = Color(0x00_e8_5d_3a);

/// Open a back-layer window, run the splash sequence on it, and
/// return the still-alive [`Client`] so the caller can keep the
/// watermark mapped behind the front layer.
///
/// `width` / `height` are the back-layer pixel dimensions — should
/// match the front-layer dimensions so the watermark and terminal
/// grid line up exactly. `my_endpoint` is the back layer's reply
/// endpoint (must not collide with the front layer's endpoint —
/// each layer needs its own).
pub fn run(width: u32, height: u32, my_endpoint: u32) -> Result<Client, ClientError> {
    let mut back = Client::open_layer(width, height, my_endpoint, 0, false)?;

    let win_w = back.width() as i32;
    let win_h = back.height() as i32;
    let font = &BUILTIN_FONT_JBM;
    let cw = font.cell_w as i32;

    // Title geometry for the hold frame — three parts (Cambi / OS / TM)
    // share a single baseline.
    let cambi_w = (PART_CAMBI.len() as i32) * cw * TITLE_SCALE;
    let os_w = (PART_OS.len() as i32) * cw * TITLE_SCALE;
    let tm_w = (PART_TM.len() as i32) * cw * TM_SCALE;
    let total_full_w = cambi_w + os_w + tm_w;
    let centered_x = (win_w - total_full_w) / 2;
    let centered_y = (win_h - (font.cell_h as i32) * TITLE_SCALE) / 2;

    // Watermark final geometry — centered on the back layer (no TM,
    // 1× scale).
    let wm_total_w = ((PART_CAMBI.len() + PART_OS.len()) as i32) * cw;
    let wm_x = (win_w - wm_total_w) / 2;
    let wm_y = (win_h - (font.cell_h as i32)) / 2;

    // Phase 1 — Hold the full wordmark for 2 s.
    paint_full_wordmark(&mut back, font, centered_x, centered_y);
    sleep_ticks(HOLD_TICKS);

    // Phase 2 — Recede to watermark over ~1.0 s. Per frame: linear
    // interpolate scale (integer-stepped), opacity, position; TM
    // cross-fades out in first third.
    for frame in 0..=TRANSITION_FRAMES {
        let scale = lerp_scale(TITLE_SCALE, 1, frame, TRANSITION_FRAMES);
        let alpha = lerp_u8(0xFF, WATERMARK_ALPHA, frame, TRANSITION_FRAMES);
        let x = lerp_i32(centered_x, wm_x, frame, TRANSITION_FRAMES);
        let y = lerp_i32(centered_y, wm_y, frame, TRANSITION_FRAMES);
        let tm_alpha = if frame >= TM_FADE_FRAMES {
            0
        } else {
            lerp_u8(0xFF, 0, frame, TM_FADE_FRAMES)
        };
        paint_recede_frame(&mut back, font, x, y, scale, alpha, tm_alpha);
        sleep_ticks(TRANSITION_FRAME_TICKS);
    }

    // Phase 3 — leave the watermark drawn on the back surface and
    // return. The caller holds `back` alive for the duration of the
    // process; the watermark stays mapped, the compositor keeps the
    // back-layer window in its table, and the front layer (when the
    // caller opens it) alpha-blends on top.
    Ok(back)
}

fn paint_full_wordmark(client: &mut Client, font: &AntialiasedFont, x: i32, y: i32) {
    let cw = font.cell_w as i32;
    let cambi_w = (PART_CAMBI.len() as i32) * cw * TITLE_SCALE;
    let os_w = (PART_OS.len() as i32) * cw * TITLE_SCALE;
    {
        let mut surf = client.surface_mut();
        surf.clear(BG_0);
        draw_text_scaled(&mut surf, x, y, PART_CAMBI, TITLE_SCALE, FG_0, font);
        draw_text_scaled(&mut surf, x + cambi_w, y, PART_OS, TITLE_SCALE, ACCENT, font);
        draw_text_scaled(
            &mut surf,
            x + cambi_w + os_w,
            y,
            PART_TM,
            TM_SCALE,
            FG_0,
            font,
        );
    }
    let _ = client.submit_full();
}

fn paint_recede_frame(
    client: &mut Client,
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
        let mut surf = client.surface_mut();
        surf.clear(BG_0);
        draw_text_scaled(&mut surf, x, y, PART_CAMBI, scale, fg_dim, font);
        draw_text_scaled(&mut surf, x + cambi_w, y, PART_OS, scale, accent_dim, font);

        if tm_alpha > 0 {
            let tm_scale = (scale / 2).max(1);
            let tm_dim = blend_toward(FG_0, BG_0, tm_alpha);
            let os_w = (PART_OS.len() as i32) * cw * scale;
            let tm_x = x + cambi_w + os_w;
            draw_text_scaled(&mut surf, tm_x, y, PART_TM, tm_scale, tm_dim, font);
        }
    }
    let _ = client.submit_full();
}

// ─── Numeric helpers ──────────────────────────────────────────────

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
/// Used to fake per-glyph opacity through the AA blit which only
/// carries the glyph mask alpha — the effective opacity comes from
/// the resolved color itself. Back-layer surface is XRGB (alpha byte
/// ignored by the compositor's blit path), so the high byte is left
/// at 0 throughout.
fn blend_toward(color: Color, bg: Color, intensity: u8) -> Color {
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

fn draw_text_scaled(
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

fn sleep_ticks(n: u64) {
    let deadline = sys::get_time().saturating_add(n);
    while sys::get_time() < deadline {
        sys::yield_now();
    }
}
