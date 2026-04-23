// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O rendering — Session 1c draws a static scene:
//! sky clear + bottom-row ground tiles + a single Sprouty idle sprite
//! standing on the ground. Session 2 wires the camera scroll and
//! dynamic entity placement through the same entry point.

use arcos_libgui::{Bitmap, Color, Surface};

use crate::level::{self, LEVEL, LEVEL_COLS, LEVEL_ROWS, TILE_SIZE};
use crate::sprites::{GROUND, SPROUTY_IDLE, TRANSPARENT};

/// Sky clear color (palette index 1 in the sprite sheet).
const SKY: Color = Color::rgb(0x87, 0xCE, 0xEB);

/// Sprouty's Session-1c resting tile. Row 8 places his feet on row 9
/// (the ground row).
const SPROUTY_COL: u32 = 4;
const SPROUTY_ROW: u32 = 8;

pub fn draw(surf: &mut Surface, sheet: &Bitmap) {
    surf.clear(SKY);

    // Tile layer — every non-air cell.
    let mut r = 0;
    while r < LEVEL_ROWS {
        let mut c = 0;
        while c < LEVEL_COLS {
            let tile = LEVEL[r][c];
            if tile == level::GROUND {
                let (sx, sy, sw, sh) = GROUND;
                surf.blit_bitmap_sub(
                    (c as u32 * TILE_SIZE) as i32,
                    (r as u32 * TILE_SIZE) as i32,
                    sheet,
                    sx, sy, sw, sh,
                    None, // ground cell is fully opaque
                );
            }
            c += 1;
        }
        r += 1;
    }

    // Sprouty — color-keyed so sky shows through the leaf/body gaps.
    let (sx, sy, sw, sh) = SPROUTY_IDLE;
    surf.blit_bitmap_sub(
        (SPROUTY_COL * TILE_SIZE) as i32,
        (SPROUTY_ROW * TILE_SIZE) as i32,
        sheet,
        sx, sy, sw, sh,
        Some(TRANSPARENT),
    );
}
