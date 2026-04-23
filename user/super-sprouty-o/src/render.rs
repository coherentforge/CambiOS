// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O rendering.
//!
//! Session 2 final shape: sky clear → visible tile layer → weeds →
//! Sprouty → lose overlay (when `Status::Dead`). All entities drawn
//! with `blit_bitmap_sub` from the 3-cell sprite sheet; world-space
//! coordinates are offset by `camera_x` to land in the viewport.

use arcos_libgui::{Bitmap, Color, Rect, Surface};
use arcos_super_sprouty_o::game::{Game, Status};
use arcos_super_sprouty_o::level::{self, LEVEL, SURFACE_W, TILE_SIZE};

use crate::sprites::{GROUND, SPROUTY_IDLE, TRANSPARENT, WEED};

/// Sky clear color.
const SKY: Color = Color::rgb(0x87, 0xCE, 0xEB);

/// Lose-overlay background — dark slate for readability against sky.
const OVERLAY_BG: Color = Color::rgb(0x1A, 0x1A, 0x1A);
const OVERLAY_TEXT: Color = Color::rgb(0xFF, 0xFF, 0xFF);

pub fn draw(surf: &mut Surface, sheet: &Bitmap, game: &Game) {
    surf.clear(SKY);

    // Tile layer.
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
                    sheet,
                    sx, sy, sw, sh,
                    None,
                );
            }
            c += 1;
        }
        r += 1;
    }

    // Weeds.
    for slot in game.weeds.iter() {
        if let Some(w) = slot {
            let (sx, sy, sw, sh) = WEED;
            surf.blit_bitmap_sub(
                w.x - game.camera_x,
                w.y,
                sheet,
                sx, sy, sw, sh,
                Some(TRANSPARENT),
            );
        }
    }

    // Sprouty.
    let (sx, sy, sw, sh) = SPROUTY_IDLE;
    surf.blit_bitmap_sub(
        game.player.x - game.camera_x,
        game.player.y,
        sheet,
        sx, sy, sw, sh,
        Some(TRANSPARENT),
    );

    if game.status == Status::Dead {
        draw_lose_overlay(surf);
    }
}

/// Dark centered banner with "WILTED" + restart hint. No alpha channel
/// in libgui, so this is a solid-fill banner over the frozen scene.
fn draw_lose_overlay(surf: &mut Surface) {
    // Banner: roughly 380 × 100 centered on the 480 × 320 viewport.
    const BANNER_W: u16 = 380;
    const BANNER_H: u16 = 100;
    const BANNER_X: u16 = (SURFACE_W as u16 - BANNER_W) / 2;
    const BANNER_Y: u16 = 110;
    surf.fill_rect(
        Rect { x: BANNER_X, y: BANNER_Y, w: BANNER_W, h: BANNER_H },
        OVERLAY_BG,
    );

    // Builtin 8×8 font: 1 char = 8 px wide.
    let title = "WILTED";
    let subtitle = "press R to try again";
    let title_x = (SURFACE_W as i32 - (title.len() as i32) * 8) / 2;
    let subtitle_x = (SURFACE_W as i32 - (subtitle.len() as i32) * 8) / 2;
    surf.draw_text_builtin(title_x, 135, title, OVERLAY_TEXT);
    surf.draw_text_builtin(subtitle_x, 165, subtitle, OVERLAY_TEXT);
}
