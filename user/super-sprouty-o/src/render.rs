// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O rendering.
//!
//! Session 3 shape: sky clear → visible tile layer (ground + planted
//! platform) → goal → seeds → weeds → Sprouty → HUD (seeds + power-up
//! indicator + live FPS) → win / lose overlay. Seeds, goal, and the
//! planted platform render as colored rects instead of sprite cells
//! for now — the sheet grows to cover them in a follow-up when the
//! kernel `iretq` GPF for larger .rodata is resolved.

use cambios_libgui::{Bitmap, Color, Rect, Surface};
use cambios_super_sprouty_o::game::{Game, Status};
use cambios_super_sprouty_o::level::{self, GOAL_COL, GOAL_ROW, LEVEL, SURFACE_H, SURFACE_W, TILE_SIZE};

use crate::sprites::{GROUND, SPROUTY_IDLE, TRANSPARENT, WEED};

const SKY: Color = Color::rgb(0x87, 0xCE, 0xEB);

// --- Placeholder palettes for Session-3 entities (sprite cells land later) ---
const SEED_FILL: Color = Color::rgb(0xFF, 0xEB, 0x3B); // yellow
const SEED_OUTLINE: Color = Color::rgb(0x8B, 0x5A, 0x2B); // brown
const GOAL_TRUNK: Color = Color::rgb(0x6D, 0x4C, 0x41);
const GOAL_BLOSSOM: Color = Color::rgb(0xF4, 0x8F, 0xB1);
const PLANTED_FILL: Color = Color::rgb(0x8B, 0xC3, 0x4A); // light leaf-green
const PLANTED_EDGE: Color = Color::rgb(0x55, 0x8B, 0x2F);

const HUD_BG: Color = Color::rgb(0x1A, 0x2A, 0x1A);
const HUD_TEXT: Color = Color::rgb(0xFF, 0xFF, 0xFF);
const HUD_ACCENT: Color = Color::rgb(0xFF, 0xEB, 0x3B);

const LOSE_BG: Color = Color::rgb(0x1A, 0x1A, 0x1A);
const LOSE_TEXT: Color = Color::rgb(0xFF, 0xFF, 0xFF);
const WIN_BG: Color = Color::rgb(0x2E, 0x7D, 0x32);
const WIN_TEXT: Color = Color::rgb(0xFF, 0xFF, 0xFF);

pub fn draw(surf: &mut Surface, sheet: &Bitmap, game: &Game) {
    surf.clear(SKY);

    // Tile layer (authored ground + planted platform).
    let (c_start, c_end) = level::visible_range(game.camera_x);
    let mut r = 0;
    while r < level::LEVEL_ROWS {
        let mut c = c_start;
        while c < c_end {
            if LEVEL[r][c] == level::GROUND {
                let (sx, sy, sw, sh) = GROUND;
                surf.blit_bitmap_sub(
                    (c as i32) * (TILE_SIZE as i32) - game.camera_x,
                    (r as i32) * (TILE_SIZE as i32),
                    sheet, sx, sy, sw, sh, None,
                );
            }
            c += 1;
        }
        r += 1;
    }
    if let Some(p) = game.planted {
        draw_planted_tile(surf, p.col, p.row, game.camera_x);
    }

    // Goal (placeholder colored rect until the sprite cell lands).
    draw_goal(surf, game.camera_x);

    // Seeds (placeholder colored circles-ish).
    for slot in game.seeds.iter() {
        if let Some(s) = slot {
            draw_seed(surf, s.x, s.y, game.camera_x);
        }
    }

    // Weeds.
    for slot in game.weeds.iter() {
        if let Some(w) = slot {
            let (sx, sy, sw, sh) = WEED;
            surf.blit_bitmap_sub(
                w.x - game.camera_x, w.y,
                sheet, sx, sy, sw, sh, Some(TRANSPARENT),
            );
        }
    }

    // Sprouty.
    let (sx, sy, sw, sh) = SPROUTY_IDLE;
    surf.blit_bitmap_sub(
        game.player.x - game.camera_x,
        game.player.y,
        sheet, sx, sy, sw, sh, Some(TRANSPARENT),
    );

    // HUD — always on top of game, below overlays.
    draw_hud(surf, game);

    match game.status {
        Status::Dead => draw_lose_overlay(surf),
        Status::Won => draw_win_overlay(surf),
        Status::Playing => {}
    }
}

fn draw_planted_tile(surf: &mut Surface, col: i32, row: i32, camera_x: i32) {
    let x = col * TILE_SIZE as i32 - camera_x;
    let y = row * TILE_SIZE as i32;
    if let Some(rect) = small_rect(x, y, TILE_SIZE as i16, TILE_SIZE as i16) {
        surf.fill_rect(rect, PLANTED_FILL);
    }
    // 2-px edge for visual contrast against authored ground.
    if let Some(rect) = small_rect(x, y, TILE_SIZE as i16, 2) {
        surf.fill_rect(rect, PLANTED_EDGE);
    }
}

fn draw_goal(surf: &mut Surface, camera_x: i32) {
    let x = GOAL_COL * TILE_SIZE as i32 - camera_x;
    let y = GOAL_ROW * TILE_SIZE as i32;
    // Trunk down the middle.
    if let Some(r) = small_rect(x + 12, y + 18, 8, 14) {
        surf.fill_rect(r, GOAL_TRUNK);
    }
    // Blossom canopy — three stacked bands of pink.
    if let Some(r) = small_rect(x + 6, y + 2, 20, 6) {
        surf.fill_rect(r, GOAL_BLOSSOM);
    }
    if let Some(r) = small_rect(x + 4, y + 8, 24, 6) {
        surf.fill_rect(r, GOAL_BLOSSOM);
    }
    if let Some(r) = small_rect(x + 8, y + 14, 16, 6) {
        surf.fill_rect(r, GOAL_BLOSSOM);
    }
}

fn draw_seed(surf: &mut Surface, sx: i32, sy: i32, camera_x: i32) {
    let x = sx - camera_x;
    let y = sy;
    // 12×12 centered in the 32×32 cell, with a 1-px brown outline.
    if let Some(r) = small_rect(x + 10, y + 10, 12, 12) {
        surf.fill_rect(r, SEED_OUTLINE);
    }
    if let Some(r) = small_rect(x + 11, y + 11, 10, 10) {
        surf.fill_rect(r, SEED_FILL);
    }
}

fn draw_hud(surf: &mut Surface, game: &Game) {
    // Top-left: seeds counter + (if held) sprout-seed indicator.
    let mut buf = [b' '; 32];
    let seed_s = format_hud_seeds(&mut buf, game.seeds_collected);
    // Dark strip behind the text so it stays readable over any background.
    surf.fill_rect(Rect { x: 4, y: 4, w: 140, h: 14 }, HUD_BG);
    surf.draw_text_builtin(8, 8, seed_s, HUD_TEXT);

    if game.player.has_sprout_seed {
        surf.fill_rect(Rect { x: 4, y: 20, w: 140, h: 14 }, HUD_BG);
        surf.draw_text_builtin(8, 24, "seed ready: DOWN", HUD_ACCENT);
    }

    // Bottom-right: "XX fps"
    let mut fps_buf = [b' '; 8];
    let fps_s = format_hud_fps(&mut fps_buf, game.fps.fps());
    // "XX fps" = 6 chars × 8 px/char = 48 px wide.
    let fps_x = SURFACE_W as i32 - 52;
    let fps_y = SURFACE_H as i32 - 14;
    surf.fill_rect(
        Rect { x: (fps_x - 4) as u16, y: (fps_y - 2) as u16, w: 56, h: 14 },
        HUD_BG,
    );
    surf.draw_text_builtin(fps_x, fps_y, fps_s, HUD_TEXT);
}

fn draw_lose_overlay(surf: &mut Surface) {
    const BANNER_W: u16 = 380;
    const BANNER_H: u16 = 100;
    const BANNER_X: u16 = (SURFACE_W as u16 - BANNER_W) / 2;
    const BANNER_Y: u16 = 110;
    surf.fill_rect(
        Rect { x: BANNER_X, y: BANNER_Y, w: BANNER_W, h: BANNER_H },
        LOSE_BG,
    );
    let title = "WILTED";
    let subtitle = "press R to try again";
    let title_x = (SURFACE_W as i32 - (title.len() as i32) * 8) / 2;
    let subtitle_x = (SURFACE_W as i32 - (subtitle.len() as i32) * 8) / 2;
    surf.draw_text_builtin(title_x, 135, title, LOSE_TEXT);
    surf.draw_text_builtin(subtitle_x, 165, subtitle, LOSE_TEXT);
}

fn draw_win_overlay(surf: &mut Surface) {
    const BANNER_W: u16 = 380;
    const BANNER_H: u16 = 100;
    const BANNER_X: u16 = (SURFACE_W as u16 - BANNER_W) / 2;
    const BANNER_Y: u16 = 110;
    surf.fill_rect(
        Rect { x: BANNER_X, y: BANNER_Y, w: BANNER_W, h: BANNER_H },
        WIN_BG,
    );
    let title = "YOUR GROVE BLOOMS";
    let subtitle = "press R to play again";
    let title_x = (SURFACE_W as i32 - (title.len() as i32) * 8) / 2;
    let subtitle_x = (SURFACE_W as i32 - (subtitle.len() as i32) * 8) / 2;
    surf.draw_text_builtin(title_x, 135, title, WIN_TEXT);
    surf.draw_text_builtin(subtitle_x, 165, subtitle, WIN_TEXT);
}

/// Safe Rect constructor that clips negative or oversized values and
/// returns None when the rect would collapse. Spares every call site
/// from repeating the bounds-check boilerplate.
fn small_rect(x: i32, y: i32, w: i16, h: i16) -> Option<Rect> {
    if w <= 0 || h <= 0 {
        return None;
    }
    let (rx, rw) = clamp_axis(x, w, SURFACE_W as i32);
    let (ry, rh) = clamp_axis(y, h, SURFACE_H as i32);
    if rw == 0 || rh == 0 {
        return None;
    }
    Some(Rect { x: rx as u16, y: ry as u16, w: rw, h: rh })
}

/// Clip a 1-D axis: returns (start, length) inside [0, bound).
fn clamp_axis(pos: i32, len: i16, bound: i32) -> (i32, u16) {
    let start = pos.max(0);
    let end = (pos + len as i32).min(bound);
    if end <= start {
        (0, 0)
    } else {
        (start, (end - start) as u16)
    }
}

/// Format `"seeds: N"` into `buf`. Assumes N ≤ 99; higher values clamp.
fn format_hud_seeds(buf: &mut [u8; 32], n: u32) -> &str {
    let prefix = b"seeds: ";
    buf[..prefix.len()].copy_from_slice(prefix);
    let n = n.min(99);
    let tens = (n / 10) as u8;
    let ones = (n % 10) as u8;
    let mut write_pos = prefix.len();
    if tens > 0 {
        buf[write_pos] = b'0' + tens;
        write_pos += 1;
    }
    buf[write_pos] = b'0' + ones;
    write_pos += 1;
    core::str::from_utf8(&buf[..write_pos]).unwrap_or("seeds: ?")
}

/// Format `"NN fps"` into `buf`. Assumes NN ≤ 99; higher values clamp.
fn format_hud_fps(buf: &mut [u8; 8], fps: u32) -> &str {
    let fps = fps.min(99);
    let tens = (fps / 10) as u8;
    let ones = (fps % 10) as u8;
    buf[0] = b'0' + tens;
    buf[1] = b'0' + ones;
    buf[2] = b' ';
    buf[3] = b'f';
    buf[4] = b'p';
    buf[5] = b's';
    core::str::from_utf8(&buf[..6]).unwrap_or("?? fps")
}
