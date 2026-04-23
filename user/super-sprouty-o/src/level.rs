// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O tilemap + viewport constants + visibility culling.
//!
//! Session 2a widens the level from the 1c viewport slab (15×10) to a
//! 64-wide scrollable strip with a few pits. Later sessions add
//! elevation (platforms in the air), enemy spawn markers, seed
//! pickups, and the goal-tree tile.
//!
//! Coordinate conventions:
//! - Tile indices `(col, row)` are unsigned grid positions.
//! - World-space pixels measure from `(0, 0)` at the level's top-left.
//! - `camera_x` is the world-space x of the viewport's left edge,
//!   clamped to `[0, LEVEL_PX_W - SURFACE_W]`.

/// Tile edge length in pixels. Matches `sprites::CELL`.
pub const TILE_SIZE: u32 = 32;

/// Viewport width in pixels (compositor window size).
pub const SURFACE_W: u32 = 480;

/// Viewport height in pixels.
pub const SURFACE_H: u32 = 320;

/// Level width in tiles. 64 cols × 32 px/tile = 2048 px world.
pub const LEVEL_COLS: usize = 64;

/// Level height in tiles. Equal to viewport rows — no vertical scroll
/// in v0; the whole column height is always visible.
pub const LEVEL_ROWS: usize = 10;

/// Tile IDs. Session 2a ships two (AIR, GROUND); Session 3 extends
/// with seed / goal-tree markers.
pub const AIR: u8 = 0;
pub const GROUND: u8 = 1;

// Short aliases for the level-data table below — table readability
// collapses hard without them.
const A: u8 = AIR;
const G: u8 = GROUND;

/// Static level geometry. Row 0 is the top (sky). Row 9 is the ground
/// row, broken by three pits at [15..17], [30..32], [47..50].
pub static LEVEL: [[u8; LEVEL_COLS]; LEVEL_ROWS] = [
    [A; LEVEL_COLS], // row 0 (top)
    [A; LEVEL_COLS],
    [A; LEVEL_COLS],
    [A; LEVEL_COLS],
    [A; LEVEL_COLS],
    [A; LEVEL_COLS],
    [A; LEVEL_COLS],
    [A; LEVEL_COLS],
    [A; LEVEL_COLS], // row 8
    [
        // cols  0..14 — flat ground (15 tiles)
        G, G, G, G, G, G, G, G, G, G, G, G, G, G, G,
        // cols 15..16 — first pit (2 tiles)
        A, A,
        // cols 17..29 — ground (13 tiles)
        G, G, G, G, G, G, G, G, G, G, G, G, G,
        // cols 30..31 — second pit (2 tiles)
        A, A,
        // cols 32..46 — ground (15 tiles)
        G, G, G, G, G, G, G, G, G, G, G, G, G, G, G,
        // cols 47..49 — third pit (3 tiles)
        A, A, A,
        // cols 50..63 — ground (14 tiles)
        G, G, G, G, G, G, G, G, G, G, G, G, G, G,
    ],
];

/// Weed-walker spawn positions (world pixels, top-left). One per
/// ground strip except the final one (kept weed-free as breathing room
/// before Session 3's goal tree).
pub static WEED_SPAWNS: &[(i32, i32)] = &[
    (8 * TILE_SIZE as i32, 8 * TILE_SIZE as i32),  // mid-strip 0 (cols 0..14)
    (23 * TILE_SIZE as i32, 8 * TILE_SIZE as i32), // mid-strip 1 (cols 17..29)
    (39 * TILE_SIZE as i32, 8 * TILE_SIZE as i32), // mid-strip 2 (cols 32..46)
];

/// Tile at `(col, row)`. Out-of-range coords return AIR — outside the
/// authored level is treated as open sky / fall-into-pit, not error.
pub fn tile_at(col: i32, row: i32) -> u8 {
    if col < 0 || row < 0 {
        return AIR;
    }
    let (c, r) = (col as usize, row as usize);
    if c >= LEVEL_COLS || r >= LEVEL_ROWS {
        return AIR;
    }
    LEVEL[r][c]
}

/// Range of tile columns visible in the viewport given `camera_x`.
/// Returns `(start_col, end_col)` half-open: iterate `start..end`. Both
/// endpoints are clamped to `[0, LEVEL_COLS]`.
///
/// A tile is "visible" iff its pixel span overlaps the viewport pixel
/// span `[camera_x, camera_x + SURFACE_W)`. Because tile `c` spans
/// `[c * TILE_SIZE, (c + 1) * TILE_SIZE)`, the visible column range is
/// `floor(camera_x / TILE_SIZE) .. ceil((camera_x + SURFACE_W) / TILE_SIZE)`.
pub fn visible_range(camera_x: i32) -> (usize, usize) {
    let cam = if camera_x < 0 { 0 } else { camera_x as u32 };
    let end_px = cam.saturating_add(SURFACE_W);
    let start = (cam / TILE_SIZE) as usize;
    // Ceiling division: (n + d - 1) / d
    let end = ((end_px + TILE_SIZE - 1) / TILE_SIZE) as usize;
    let start_c = if start > LEVEL_COLS { LEVEL_COLS } else { start };
    let end_c = if end > LEVEL_COLS { LEVEL_COLS } else { end };
    (start_c, end_c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_row_widths_are_64() {
        // The compiler enforces LEVEL_COLS = 64 per inner array; this
        // is a belt-and-braces runtime check that the human-authored
        // ground row matches.
        for row in LEVEL.iter() {
            assert_eq!(row.len(), LEVEL_COLS);
        }
    }

    #[test]
    fn ground_row_pit_layout() {
        // Session-2a spec: exactly three pits at [15..17], [30..32], [47..50].
        let ground = &LEVEL[9];
        for c in 0..LEVEL_COLS {
            let expected = match c {
                15 | 16 => AIR,
                30 | 31 => AIR,
                47 | 48 | 49 => AIR,
                _ => GROUND,
            };
            assert_eq!(ground[c], expected, "col {} mismatch", c);
        }
    }

    #[test]
    fn other_rows_are_all_air() {
        for r in 0..9 {
            for c in 0..LEVEL_COLS {
                assert_eq!(LEVEL[r][c], AIR, "expected AIR at ({},{})", c, r);
            }
        }
    }

    #[test]
    fn tile_at_handles_oob() {
        assert_eq!(tile_at(-1, 0), AIR);
        assert_eq!(tile_at(0, -1), AIR);
        assert_eq!(tile_at(LEVEL_COLS as i32, 0), AIR);
        assert_eq!(tile_at(0, LEVEL_ROWS as i32), AIR);
    }

    #[test]
    fn tile_at_ground_row() {
        assert_eq!(tile_at(0, 9), GROUND);
        assert_eq!(tile_at(15, 9), AIR); // first pit
        assert_eq!(tile_at(16, 9), AIR);
        assert_eq!(tile_at(17, 9), GROUND);
        assert_eq!(tile_at(63, 9), GROUND);
    }

    #[test]
    fn visible_range_at_zero() {
        // Viewport 480 px / 32 px tile = 15 tile columns, starting at 0.
        assert_eq!(visible_range(0), (0, 15));
    }

    #[test]
    fn visible_range_shifted_one_tile() {
        // camera_x=32 → tile 1 at viewport left; tile 16 at viewport right.
        assert_eq!(visible_range(32), (1, 16));
    }

    #[test]
    fn visible_range_sub_tile_offset_includes_partial_tiles() {
        // camera_x=16 → partial tile 0 on left + partial tile 15 on right.
        // Range covers tiles 0..16 (both partially visible).
        assert_eq!(visible_range(16), (0, 16));
    }

    #[test]
    fn visible_range_clamps_to_level_end() {
        // Level is 64 * 32 = 2048 px wide. Viewport at max (2048 - 480 = 1568)
        // sees the last 15 tiles — cols 49..64.
        assert_eq!(visible_range(1568), (49, 64));
    }

    #[test]
    fn visible_range_past_level_clamps() {
        // Out of bounds camera shouldn't crash or produce garbage.
        assert_eq!(visible_range(100_000), (LEVEL_COLS, LEVEL_COLS));
    }

    #[test]
    fn visible_range_negative_camera_pins_to_zero() {
        // Clamp negative inputs (shouldn't happen in practice; camera
        // is always clamped by Game::clamp_camera, but be total).
        assert_eq!(visible_range(-100), (0, 15));
    }
}
