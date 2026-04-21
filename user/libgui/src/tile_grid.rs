// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Rectangular tile grid — geometry only.
//!
//! A `TileGrid` describes a 2D array of equal-sized cells at a
//! fixed offset on a surface, with optional inter-tile spacing. It
//! converts `(col, row)` indices into pixel `Rect`s that can be
//! passed straight to `Surface::fill_rect` or `Surface::draw_text`.
//!
//! v0 does NOT include `hit_test` (pixel→tile lookup) — that only
//! makes sense paired with an input event type, and the wire format
//! for input lands in the virtio-input session. When it does, the
//! natural place for `hit_test` is here.

use arcos_libgui_proto::Rect;

/// Layout of an equally-spaced grid of tiles on a surface.
///
/// `origin_x` / `origin_y` is the top-left pixel of the top-left
/// tile. `gap` is the number of pixels between adjacent tiles on
/// each axis (0 = tiles are flush). Each tile is
/// `tile_w × tile_h` pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TileGrid {
    pub origin_x: i32,
    pub origin_y: i32,
    pub tile_w: u16,
    pub tile_h: u16,
    pub cols: u16,
    pub rows: u16,
    pub gap: u16,
}

impl TileGrid {
    pub const fn new(
        origin_x: i32,
        origin_y: i32,
        tile_w: u16,
        tile_h: u16,
        cols: u16,
        rows: u16,
        gap: u16,
    ) -> Self {
        Self {
            origin_x,
            origin_y,
            tile_w,
            tile_h,
            cols,
            rows,
            gap,
        }
    }

    /// Pixel bounds of the (col, row) tile. Returns `None` if the
    /// indices are out of range. Coordinates are clamped to `u16`
    /// via `saturating_cast`; callers drawing at large origins
    /// should watch for that edge.
    pub fn tile_rect(&self, col: u16, row: u16) -> Option<Rect> {
        if col >= self.cols || row >= self.rows {
            return None;
        }
        let stride_x = self.tile_w as i32 + self.gap as i32;
        let stride_y = self.tile_h as i32 + self.gap as i32;
        let x = self.origin_x + col as i32 * stride_x;
        let y = self.origin_y + row as i32 * stride_y;
        Some(Rect {
            x: saturating_i32_to_u16(x),
            y: saturating_i32_to_u16(y),
            w: self.tile_w,
            h: self.tile_h,
        })
    }

    /// Total pixel footprint of the grid (origin to bottom-right
    /// tile's bottom-right corner). Useful for sizing a window to
    /// fit a grid exactly.
    pub fn total_width(&self) -> u32 {
        if self.cols == 0 {
            return 0;
        }
        (self.cols as u32) * (self.tile_w as u32)
            + (self.cols.saturating_sub(1) as u32) * (self.gap as u32)
    }

    pub fn total_height(&self) -> u32 {
        if self.rows == 0 {
            return 0;
        }
        (self.rows as u32) * (self.tile_h as u32)
            + (self.rows.saturating_sub(1) as u32) * (self.gap as u32)
    }

    /// Iterate `(col, row, Rect)` over every tile in row-major order.
    pub fn iter(&self) -> impl Iterator<Item = (u16, u16, Rect)> + '_ {
        (0..self.rows).flat_map(move |r| {
            (0..self.cols).map(move |c| {
                // find_slot-style — unwrap is infallible because
                // (c, r) are within (cols, rows) by construction.
                let rect = self.tile_rect(c, r).expect("bounded indices");
                (c, r, rect)
            })
        })
    }
}

fn saturating_i32_to_u16(v: i32) -> u16 {
    if v < 0 {
        0
    } else if v > u16::MAX as i32 {
        u16::MAX
    } else {
        v as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_tile_no_gap() {
        let g = TileGrid::new(10, 20, 8, 8, 1, 1, 0);
        let r = g.tile_rect(0, 0).unwrap();
        assert_eq!(r, Rect { x: 10, y: 20, w: 8, h: 8 });
        assert!(g.tile_rect(1, 0).is_none());
        assert!(g.tile_rect(0, 1).is_none());
    }

    #[test]
    fn flush_grid_stride_is_tile_size() {
        let g = TileGrid::new(0, 0, 10, 5, 4, 3, 0);
        assert_eq!(g.tile_rect(0, 0).unwrap(), Rect { x: 0, y: 0, w: 10, h: 5 });
        assert_eq!(g.tile_rect(3, 0).unwrap(), Rect { x: 30, y: 0, w: 10, h: 5 });
        assert_eq!(g.tile_rect(0, 2).unwrap(), Rect { x: 0, y: 10, w: 10, h: 5 });
        assert_eq!(g.tile_rect(3, 2).unwrap(), Rect { x: 30, y: 10, w: 10, h: 5 });
    }

    #[test]
    fn gap_stride_is_tile_plus_gap() {
        let g = TileGrid::new(0, 0, 8, 8, 3, 3, 2);
        assert_eq!(g.tile_rect(0, 0).unwrap(), Rect { x: 0, y: 0, w: 8, h: 8 });
        assert_eq!(g.tile_rect(1, 0).unwrap(), Rect { x: 10, y: 0, w: 8, h: 8 });
        assert_eq!(g.tile_rect(2, 1).unwrap(), Rect { x: 20, y: 10, w: 8, h: 8 });
    }

    #[test]
    fn total_size_with_no_gap() {
        let g = TileGrid::new(0, 0, 8, 8, 4, 3, 0);
        assert_eq!(g.total_width(), 32);
        assert_eq!(g.total_height(), 24);
    }

    #[test]
    fn total_size_with_gap() {
        let g = TileGrid::new(0, 0, 8, 8, 4, 3, 2);
        // 4 tiles × 8 px + 3 gaps × 2 px = 38
        assert_eq!(g.total_width(), 38);
        // 3 tiles × 8 px + 2 gaps × 2 px = 28
        assert_eq!(g.total_height(), 28);
    }

    #[test]
    fn empty_grid_sizes_to_zero() {
        let g = TileGrid::new(0, 0, 8, 8, 0, 0, 2);
        assert_eq!(g.total_width(), 0);
        assert_eq!(g.total_height(), 0);
    }

    #[test]
    fn iter_walks_every_tile_row_major() {
        let g = TileGrid::new(5, 5, 4, 4, 2, 2, 1);
        let collected: Vec<_> = g.iter().collect();
        assert_eq!(collected.len(), 4);
        assert_eq!(collected[0].0, 0); // (col, row, _)
        assert_eq!(collected[0].1, 0);
        assert_eq!(collected[1], (1, 0, Rect { x: 10, y: 5, w: 4, h: 4 }));
        assert_eq!(collected[2], (0, 1, Rect { x: 5, y: 10, w: 4, h: 4 }));
        assert_eq!(collected[3], (1, 1, Rect { x: 10, y: 10, w: 4, h: 4 }));
    }

    #[test]
    fn negative_origin_clamps_in_rect() {
        let g = TileGrid::new(-5, -5, 8, 8, 1, 1, 0);
        let r = g.tile_rect(0, 0).unwrap();
        assert_eq!(r.x, 0);
        assert_eq!(r.y, 0);
    }
}
