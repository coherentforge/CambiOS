// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! 32bpp XRGB bitmap source for `Surface::blit_bitmap`.
//!
//! Borrows its pixel data — the caller owns the backing `&[u32]`.
//! There is no Bitmap allocation, decompression, or format
//! conversion in v0; a sprite is whatever the app already has in
//! `.rodata` or a heap buffer it populated itself.
//!
//! For 1bpp sprites (e.g. a tiny flag icon), the caller can expand
//! them to 32bpp at build time or at startup; a future pass may add
//! `draw_1bpp` on Surface if the conversion ever becomes a hot path.

/// A 32bpp XRGB pixel source. Row-major, no padding — `data.len()`
/// must equal `width * height`.
#[derive(Clone, Copy)]
pub struct Bitmap<'a> {
    pub width: u32,
    pub height: u32,
    pub data: &'a [u32],
}

impl<'a> Bitmap<'a> {
    /// Construct and verify. Returns `None` if `data.len() != w*h`.
    pub fn new(width: u32, height: u32, data: &'a [u32]) -> Option<Self> {
        if data.len() != (width as usize) * (height as usize) {
            return None;
        }
        Some(Self {
            width,
            height,
            data,
        })
    }

    #[inline]
    pub fn pixel(&self, x: u32, y: u32) -> u32 {
        // Caller is the drawing primitive, which already bounds-checks.
        // Keep this inlined and panic-free in debug too — `get` keeps
        // us on the safe side if a caller slips up.
        *self.data.get((y as usize) * (self.width as usize) + (x as usize)).unwrap_or(&0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_mismatch_rejected() {
        assert!(Bitmap::new(2, 2, &[1, 2, 3]).is_none());
        assert!(Bitmap::new(2, 2, &[1, 2, 3, 4, 5]).is_none());
        assert!(Bitmap::new(2, 2, &[1, 2, 3, 4]).is_some());
    }

    #[test]
    fn pixel_lookup() {
        let data = [10u32, 11, 12, 13];
        let b = Bitmap::new(2, 2, &data).unwrap();
        assert_eq!(b.pixel(0, 0), 10);
        assert_eq!(b.pixel(1, 0), 11);
        assert_eq!(b.pixel(0, 1), 12);
        assert_eq!(b.pixel(1, 1), 13);
        assert_eq!(b.pixel(10, 10), 0); // out-of-bounds → 0
    }
}
