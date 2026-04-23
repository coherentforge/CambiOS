// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O static tilemap — Session 1c.
//!
//! 15 cols × 10 rows (= the full 480×320 viewport at 32px tiles). Top
//! 9 rows sky (0), bottom row solid ground (1).
//!
//! Session 2 extends this to a ~64-wide scrolling level with pits,
//! enemy spawns, seed pickups, and the goal-tree marker tile, plus a
//! `visible_range(camera_x)` helper for render culling.

/// Tile edge length in pixels. Matches `sprites::CELL`.
pub const TILE_SIZE: u32 = 32;

/// Viewport width in tiles.
pub const LEVEL_COLS: usize = 15;

/// Viewport height in tiles.
pub const LEVEL_ROWS: usize = 10;

/// Tile ids. Session 2 grows this set (weed spawn, seed, goal tree).
pub const AIR: u8 = 0;
pub const GROUND: u8 = 1;

/// Session-1c level geometry. Bottom row solid ground, rest sky.
pub static LEVEL: [[u8; LEVEL_COLS]; LEVEL_ROWS] = [
    [AIR; LEVEL_COLS],
    [AIR; LEVEL_COLS],
    [AIR; LEVEL_COLS],
    [AIR; LEVEL_COLS],
    [AIR; LEVEL_COLS],
    [AIR; LEVEL_COLS],
    [AIR; LEVEL_COLS],
    [AIR; LEVEL_COLS],
    [AIR; LEVEL_COLS],
    [GROUND; LEVEL_COLS],
];
