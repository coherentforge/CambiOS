// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Tree tile sprites — 16×16 palette-indexed pictograms.
//!
//! Not real emojis. libgui's built-in font is ASCII 8×8 monochrome;
//! colour-emoji support would need UTF-8 glyph decoding + a multi-KB
//! glyph table, out of scope for v0. These are hand-drawn pictograms
//! that read as "seed", "tree", "stump" at tile scale — closer to
//! early-90s Minesweeper sprites than iOS emoji.
//!
//! ## Format
//!
//! Each sprite is a fixed 16×16 grid of palette indices (one byte per
//! pixel). Index 0 is transparent — the surface shows through, so
//! the underlying grass / dirt tile is the sprite's background.
//! Indices 1..=7 each pick a palette colour from the sprite's own
//! `palette: [Color; 8]` array.
//!
//! `draw_centered` blits the sprite into the middle of a tile rect.
//! 16×16 sprite inside a 32×32 tile leaves 8px margin on every side,
//! which reads cleanly as an icon on a textured background without
//! touching the tile's edge lines.

use arcos_libgui::{Color, Surface};

/// 16 pixels per edge — sized to fit centered in a 32-px tile with
/// room for the grass/dirt ground showing through.
pub const SPRITE_EDGE: usize = 16;

/// Palette-indexed 16×16 sprite. Index 0 is transparent.
pub struct Sprite {
    pub palette: [Color; 8],
    pub pixels: [u8; SPRITE_EDGE * SPRITE_EDGE],
}

/// Blit `sprite` centered inside a tile whose top-left is at
/// (`tile_x`, `tile_y`) with edge length `tile_edge`.
pub fn draw_centered(surf: &mut Surface, tile_x: i32, tile_y: i32, tile_edge: u16, sprite: &Sprite) {
    let sx = tile_x + (tile_edge as i32 - SPRITE_EDGE as i32) / 2;
    let sy = tile_y + (tile_edge as i32 - SPRITE_EDGE as i32) / 2;
    for row in 0..SPRITE_EDGE {
        for col in 0..SPRITE_EDGE {
            let idx = sprite.pixels[row * SPRITE_EDGE + col];
            if idx == 0 {
                continue;
            }
            surf.set_pixel(
                sx + col as i32,
                sy + row as i32,
                sprite.palette[idx as usize],
            );
        }
    }
}

// ============================================================================
// SEED — shown on flagged tiles. Two-leaf sprout emerging from an
// oval acorn-like body. Reads as "something planted, about to grow."
// ============================================================================
//
// Palette:
//   1 = dark brown   (seed outline / stem)
//   2 = light brown  (seed body)
//   3 = dark green   (sprout leaves)
pub const SEED: Sprite = Sprite {
    palette: [
        Color::BLACK,                         // 0 transparent
        Color::rgb(0x5B, 0x3A, 0x1B),         // 1 dark brown
        Color::rgb(0xC8, 0x8A, 0x4A),         // 2 light brown
        Color::rgb(0x3E, 0x6A, 0x2A),         // 3 dark green
        Color::BLACK, Color::BLACK, Color::BLACK, Color::BLACK,
    ],
    pixels: [
        // row 0
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        // row 1
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        // row 2
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        // row 3 — sprout tip
        0,0,0,0, 0,0,0,3, 0,0,0,0, 0,0,0,0,
        // row 4 — leaves opening
        0,0,0,0, 0,0,3,0, 3,0,0,0, 0,0,0,0,
        // row 5 — leaves full
        0,0,0,0, 0,3,3,3, 3,3,0,0, 0,0,0,0,
        // row 6 — leaves tapering
        0,0,0,0, 0,0,3,3, 3,0,0,0, 0,0,0,0,
        // row 7 — stem
        0,0,0,0, 0,0,0,1, 1,0,0,0, 0,0,0,0,
        // row 8 — stem enters seed
        0,0,0,0, 0,0,0,1, 1,0,0,0, 0,0,0,0,
        // row 9 — seed top row
        0,0,0,0, 0,1,1,1, 1,1,0,0, 0,0,0,0,
        // row 10
        0,0,0,0, 1,2,2,2, 2,2,1,0, 0,0,0,0,
        // row 11
        0,0,0,1, 2,2,2,2, 2,2,2,1, 0,0,0,0,
        // row 12
        0,0,0,1, 2,2,2,2, 2,2,2,1, 0,0,0,0,
        // row 13
        0,0,0,1, 2,2,2,2, 2,2,2,1, 0,0,0,0,
        // row 14
        0,0,0,0, 1,2,2,2, 2,2,1,0, 0,0,0,0,
        // row 15
        0,0,0,0, 0,1,1,1, 1,1,0,0, 0,0,0,0,
    ],
};

// ============================================================================
// TREE — shown on mine tiles after a win. Pointed conifer canopy
// with a trunk + flared base. Big enough to read as a full tree at
// tile scale, not just a bush.
// ============================================================================
//
// Palette:
//   1 = dark brown      (trunk)
//   3 = dark canopy     (base canopy colour)
//   4 = canopy highlight (slightly lighter — left side shading)
pub const TREE: Sprite = Sprite {
    palette: [
        Color::BLACK,
        Color::rgb(0x5B, 0x3A, 0x1B),         // 1 dark brown trunk
        Color::BLACK,                         // 2 unused
        Color::rgb(0x2E, 0x5A, 0x1E),         // 3 dark canopy
        Color::rgb(0x5A, 0x8F, 0x3E),         // 4 canopy highlight
        Color::BLACK, Color::BLACK, Color::BLACK,
    ],
    pixels: [
        // row 0 — apex
        0,0,0,0, 0,0,0,0, 3,0,0,0, 0,0,0,0,
        // row 1
        0,0,0,0, 0,0,0,4, 3,3,0,0, 0,0,0,0,
        // row 2
        0,0,0,0, 0,0,0,4, 3,3,3,0, 0,0,0,0,
        // row 3
        0,0,0,0, 0,0,4,4, 3,3,3,3, 0,0,0,0,
        // row 4
        0,0,0,0, 0,4,4,3, 3,3,3,3, 3,0,0,0,
        // row 5
        0,0,0,0, 4,4,3,3, 3,3,3,3, 3,3,0,0,
        // row 6
        0,0,0,4, 4,3,3,3, 3,3,3,3, 3,3,3,0,
        // row 7 — widest canopy row
        0,0,4,4, 3,3,3,3, 3,3,3,3, 3,3,3,3,
        // row 8
        0,0,0,4, 4,3,3,3, 3,3,3,3, 3,3,3,0,
        // row 9
        0,0,0,0, 4,4,3,3, 3,3,3,3, 3,3,0,0,
        // row 10 — canopy tapers
        0,0,0,0, 0,4,3,3, 3,3,3,3, 3,0,0,0,
        // row 11 — trunk start
        0,0,0,0, 0,0,0,1, 1,1,0,0, 0,0,0,0,
        // row 12
        0,0,0,0, 0,0,0,1, 1,1,0,0, 0,0,0,0,
        // row 13
        0,0,0,0, 0,0,0,1, 1,1,0,0, 0,0,0,0,
        // row 14 — flared base
        0,0,0,0, 0,0,1,1, 1,1,1,0, 0,0,0,0,
        // row 15
        0,0,0,0, 0,1,1,1, 1,1,1,1, 0,0,0,0,
    ],
};

// ============================================================================
// STUMP — shown on mine tiles after a loss. Short cut-off trunk
// with a lighter-brown cut face on top, revealing a single dark
// ring (dot in the middle for the pith). Reads as "dead tree."
// ============================================================================
//
// Palette:
//   1 = dark brown  (trunk outline / bark)
//   5 = medium brown (cut-edge shading, matches dirt colour)
//   6 = light brown  (cut face - growth rings)
//   7 = darkest brown (pith at ring center)
pub const STUMP: Sprite = Sprite {
    palette: [
        Color::BLACK,
        Color::rgb(0x5B, 0x3A, 0x1B),         // 1 dark bark
        Color::BLACK,                         // 2 unused
        Color::BLACK,                         // 3 unused
        Color::BLACK,                         // 4 unused
        Color::rgb(0x8B, 0x5A, 0x2B),         // 5 medium brown (edge)
        Color::rgb(0xC8, 0x8A, 0x4A),         // 6 cut face
        Color::rgb(0x3A, 0x20, 0x10),         // 7 pith
    ],
    pixels: [
        // row 0
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        // row 1
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        // row 2
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        // row 3
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        // row 4 — cut top starts
        0,0,0,0, 0,0,5,5, 5,5,5,0, 0,0,0,0,
        // row 5
        0,0,0,0, 0,5,6,6, 6,6,6,5, 0,0,0,0,
        // row 6
        0,0,0,0, 5,6,6,6, 6,6,6,6, 5,0,0,0,
        // row 7 — cut face with pith
        0,0,0,0, 5,6,6,6, 7,6,6,6, 5,0,0,0,
        // row 8
        0,0,0,0, 5,6,6,6, 6,6,6,6, 5,0,0,0,
        // row 9
        0,0,0,0, 0,5,6,6, 6,6,6,5, 0,0,0,0,
        // row 10 — cut edge closes
        0,0,0,0, 0,0,5,5, 5,5,5,0, 0,0,0,0,
        // row 11 — trunk starts (bark)
        0,0,0,0, 0,1,1,1, 1,1,1,1, 0,0,0,0,
        // row 12
        0,0,0,0, 0,1,1,1, 1,1,1,1, 0,0,0,0,
        // row 13
        0,0,0,0, 0,1,1,1, 1,1,1,1, 0,0,0,0,
        // row 14 — roots splay
        0,0,0,0, 1,1,1,1, 1,1,1,1, 1,0,0,0,
        // row 15
        0,0,0,1, 1,1,1,1, 1,1,1,1, 1,1,0,0,
    ],
};
