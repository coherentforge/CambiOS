// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! `Surface` — safe drawing API over a XRGB8888 pixel buffer.
//!
//! Internally a raw pointer + geometry; externally a safe API. All
//! pixel writes go through `write_volatile` so the compiler doesn't
//! elide stores (the compositor reads this memory from a different
//! process, so from the client's POV there's no local observer).
//!
//! ## Pixel buffer ownership
//!
//! The Surface does not own its backing bytes. The backing comes
//! from a compositor surface channel (mapped into the client
//! address space by `channel_attach`) or, in tests, a borrowed
//! `&mut [u32]`. Lifetime `'a` encodes "this Surface is valid for
//! as long as the backing is mapped and unique."
//!
//! ## Pitch vs. width
//!
//! The compositor tells the client both `width` (logical pixels
//! per row) and `pitch` (bytes per row). For XRGB8888 they happen
//! to satisfy `pitch == width * 4` for v0 surfaces (no scanline
//! padding), but code here uses the pitch explicitly so a later
//! compositor with padded rows works without changes.
//!
//! ## Clipping
//!
//! Every drawing primitive clips to `[0, width) × [0, height)`.
//! Out-of-bounds pixels are silently discarded. This keeps the
//! API total — callers don't need bounds-math helpers.

use core::marker::PhantomData;

use crate::Color;
use cambios_libgui_proto::Rect;

/// A mutable view over a XRGB8888 pixel buffer.
///
/// Construct via [`Surface::from_raw`] (unsafe; for channel-mapped
/// memory) or [`Surface::from_slice`] (safe; for a borrowed
/// `&mut [u32]`, used in tests and for in-process scratch buffers).
pub struct Surface<'a> {
    base: *mut u32,
    pitch_pixels: usize,
    width: u32,
    height: u32,
    _marker: PhantomData<&'a mut [u32]>,
}

impl<'a> Surface<'a> {
    /// Build a Surface from a raw pixel pointer + geometry.
    ///
    /// # Safety
    /// - `base` must point to at least `pitch_pixels * height` u32s
    ///   of memory valid for reads and writes for `'a`.
    /// - The caller must ensure no other `Surface` or `&mut`
    ///   references alias this buffer for `'a` (shared-memory channel
    ///   mappings with a remote reader are fine because the remote
    ///   reader is not a Rust reference — `write_volatile` is the
    ///   synchronisation primitive).
    /// - `pitch_pixels >= width`.
    pub unsafe fn from_raw(
        base: *mut u32,
        pitch_pixels: usize,
        width: u32,
        height: u32,
    ) -> Self {
        Self {
            base,
            pitch_pixels,
            width,
            height,
            _marker: PhantomData,
        }
    }

    /// Build a Surface from a borrowed slice. Convenient for tests
    /// and for in-process scratch buffers (e.g. offscreen compose
    /// before a single blit_bitmap). Panics in `debug_assertions` if
    /// `buf.len() < pitch_pixels * height`.
    pub fn from_slice(
        buf: &'a mut [u32],
        pitch_pixels: usize,
        width: u32,
        height: u32,
    ) -> Self {
        debug_assert!(buf.len() >= pitch_pixels * height as usize);
        debug_assert!(pitch_pixels >= width as usize);
        // SAFETY: we just checked the slice covers the advertised
        // region and the slice's lifetime `'a` is what's attached to
        // the returned Surface; aliasing is prevented by the `&mut`
        // input — no other reference can exist for `'a`.
        unsafe { Self::from_raw(buf.as_mut_ptr(), pitch_pixels, width, height) }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn pitch_pixels(&self) -> usize {
        self.pitch_pixels
    }

    /// Set a single pixel. Out-of-bounds silently dropped.
    #[inline]
    pub fn set_pixel(&mut self, x: i32, y: i32, color: Color) {
        if x < 0 || y < 0 {
            return;
        }
        let ux = x as u32;
        let uy = y as u32;
        if ux >= self.width || uy >= self.height {
            return;
        }
        // SAFETY: `ux < width <= pitch_pixels` and `uy < height`, so
        // `offset < pitch_pixels * height`, within the caller's
        // promised buffer. Volatile write for the reasons in the
        // module docstring.
        unsafe {
            let off = (uy as usize) * self.pitch_pixels + (ux as usize);
            self.base.add(off).write_volatile(color.as_u32());
        }
    }

    /// Blend `color` onto the pixel at `(x, y)` with `alpha` (0 = no
    /// change, 255 = fully replace). Reads the existing pixel,
    /// linear-interpolates each XRGB8888 channel, writes the result.
    /// Out-of-bounds silently dropped.
    ///
    /// Used by the antialiased font path
    /// ([`crate::font_aa::AntialiasedFont`]). Slower than `set_pixel`
    /// because it requires a destination read; callers should fast-path
    /// alpha == 0 (skip) and alpha == 255 (use `set_pixel`) before
    /// invoking this.
    #[inline]
    pub fn blend_pixel(&mut self, x: i32, y: i32, color: Color, alpha: u8) {
        if x < 0 || y < 0 {
            return;
        }
        let ux = x as u32;
        let uy = y as u32;
        if ux >= self.width || uy >= self.height {
            return;
        }
        // SAFETY: bounds checked above; `pitch_pixels >= width` is the
        // module-level invariant. Volatile read+write to keep the
        // compositor's view of shared memory coherent.
        unsafe {
            let off = (uy as usize) * self.pitch_pixels + (ux as usize);
            let p = self.base.add(off);
            let bg = p.read_volatile();
            let a = alpha as u32;
            let inv = 255 - a;
            let fg = color.as_u32();
            // Per-channel lerp, XRGB8888 layout. The X channel stays 0
            // (Color::as_u32 keeps the high byte clear).
            let br = (((fg >> 16) & 0xFF) * a + ((bg >> 16) & 0xFF) * inv) / 255;
            let bg_g = (((fg >> 8) & 0xFF) * a + ((bg >> 8) & 0xFF) * inv) / 255;
            let bb = ((fg & 0xFF) * a + (bg & 0xFF) * inv) / 255;
            let blended = (br << 16) | (bg_g << 8) | bb;
            p.write_volatile(blended);
        }
    }

    /// Fill the entire surface with one color.
    pub fn clear(&mut self, color: Color) {
        self.fill_rect(
            Rect {
                x: 0,
                y: 0,
                w: self.width as u16,
                h: self.height as u16,
            },
            color,
        );
    }

    /// Fill a rectangle. Clipped to surface bounds.
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        let (x0, y0, x1, y1) = match clip_rect(rect, self.width, self.height) {
            Some(c) => c,
            None => return,
        };
        let c = color.as_u32();
        for y in y0..y1 {
            // SAFETY: `y < height` and `x0..x1` within `[0, width)`;
            // offsets bounded by `pitch_pixels * height`.
            unsafe {
                let row = self.base.add(y * self.pitch_pixels);
                for x in x0..x1 {
                    row.add(x).write_volatile(c);
                }
            }
        }
    }

    /// Draw a line from (x0,y0) to (x1,y1) using Bresenham. Endpoints
    /// inclusive. Out-of-bounds pixels are clipped individually
    /// (cheap; simpler than Cohen–Sutherland for the tiny lines
    /// libgui is drawing).
    pub fn draw_line(&mut self, mut x0: i32, mut y0: i32, x1: i32, y1: i32, color: Color) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;
        loop {
            self.set_pixel(x0, y0, color);
            if x0 == x1 && y0 == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x0 += sx;
            }
            if e2 <= dx {
                err += dx;
                y0 += sy;
            }
        }
    }

    /// Blit a bitmap's opaque pixels at (x, y). See
    /// [`crate::Bitmap`] for the source format — 32bpp XRGB; a
    /// source pixel equal to `transparent` is skipped (acts as a
    /// mask), any other pixel is written. Pass `None` for no
    /// transparency (opaque rectangular blit).
    pub fn blit_bitmap(
        &mut self,
        x: i32,
        y: i32,
        bitmap: &crate::Bitmap,
        transparent: Option<Color>,
    ) {
        let t = transparent.map(|c| c.as_u32());
        for by in 0..bitmap.height {
            let dy = y + by as i32;
            if dy < 0 || (dy as u32) >= self.height {
                continue;
            }
            for bx in 0..bitmap.width {
                let dx = x + bx as i32;
                if dx < 0 || (dx as u32) >= self.width {
                    continue;
                }
                let src = bitmap.pixel(bx, by);
                if let Some(tc) = t {
                    if src == tc {
                        continue;
                    }
                }
                // SAFETY: bounds checked above.
                unsafe {
                    let off = (dy as usize) * self.pitch_pixels + (dx as usize);
                    self.base.add(off).write_volatile(src);
                }
            }
        }
    }

    /// Blit a sub-rectangle of a bitmap (sprite-sheet cell) onto the
    /// surface at `(dst_x, dst_y)`. The `(src_x, src_y, src_w, src_h)`
    /// tuple selects the cell within `bitmap`. Source is clipped to
    /// bitmap bounds; destination is clipped to surface bounds. Color-key
    /// transparency matches [`blit_bitmap`]: if `transparent` is
    /// `Some(c)`, source pixels equal to `c` are skipped.
    pub fn blit_bitmap_sub(
        &mut self,
        dst_x: i32,
        dst_y: i32,
        bitmap: &crate::Bitmap,
        src_x: u32,
        src_y: u32,
        src_w: u32,
        src_h: u32,
        transparent: Option<Color>,
    ) {
        let t = transparent.map(|c| c.as_u32());
        // Clip source rect to bitmap bounds (saturating_add avoids
        // overflow when a caller passes u32::MAX-ish src_w/src_h).
        let sx_end = src_x.saturating_add(src_w).min(bitmap.width);
        let sy_end = src_y.saturating_add(src_h).min(bitmap.height);
        if src_x >= sx_end || src_y >= sy_end {
            return;
        }
        for by in src_y..sy_end {
            let dy = dst_y + (by - src_y) as i32;
            if dy < 0 || (dy as u32) >= self.height {
                continue;
            }
            for bx in src_x..sx_end {
                let dx = dst_x + (bx - src_x) as i32;
                if dx < 0 || (dx as u32) >= self.width {
                    continue;
                }
                let src = bitmap.pixel(bx, by);
                if let Some(tc) = t {
                    if src == tc {
                        continue;
                    }
                }
                // SAFETY: bounds checked above.
                unsafe {
                    let off = (dy as usize) * self.pitch_pixels + (dx as usize);
                    self.base.add(off).write_volatile(src);
                }
            }
        }
    }
}

/// Clip `rect` to `[0, width) × [0, height)`. Returns the clipped
/// bounds as `(x0, y0, x1, y1)` half-open (x1/y1 exclusive) in
/// pixel-index space, or `None` if the rect is fully outside or
/// degenerate.
fn clip_rect(rect: Rect, width: u32, height: u32) -> Option<(usize, usize, usize, usize)> {
    if rect.w == 0 || rect.h == 0 {
        return None;
    }
    // Widen to u32 to avoid u16 overflow when adding w/h.
    let rx = rect.x as u32;
    let ry = rect.y as u32;
    let rw = rect.w as u32;
    let rh = rect.h as u32;
    if rx >= width || ry >= height {
        return None;
    }
    let x1 = core::cmp::min(rx + rw, width) as usize;
    let y1 = core::cmp::min(ry + rh, height) as usize;
    let x0 = rx as usize;
    let y0 = ry as usize;
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    Some((x0, y0, x1, y1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_surface(w: u32, h: u32) -> (Vec<u32>, u32, u32) {
        (vec![0u32; (w * h) as usize], w, h)
    }

    #[test]
    fn fill_rect_inside() {
        let (mut buf, w, h) = make_surface(8, 8);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.fill_rect(Rect { x: 2, y: 2, w: 3, h: 3 }, Color::WHITE);
        // row 2, cols 2..5 white
        for y in 0..h {
            for x in 0..w {
                let expected = if (2..5).contains(&x) && (2..5).contains(&y) {
                    Color::WHITE.as_u32()
                } else {
                    0
                };
                assert_eq!(buf[(y * w + x) as usize], expected, "pixel ({},{})", x, y);
            }
        }
    }

    #[test]
    fn fill_rect_clips_right_and_bottom() {
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.fill_rect(Rect { x: 2, y: 2, w: 10, h: 10 }, Color::RED);
        // Only the 2x2 bottom-right corner should be painted.
        for y in 0..h {
            for x in 0..w {
                let expected = if x >= 2 && y >= 2 { Color::RED.as_u32() } else { 0 };
                assert_eq!(buf[(y * w + x) as usize], expected);
            }
        }
    }

    #[test]
    fn fill_rect_zero_size_noop() {
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.fill_rect(Rect { x: 1, y: 1, w: 0, h: 5 }, Color::RED);
        s.fill_rect(Rect { x: 1, y: 1, w: 5, h: 0 }, Color::RED);
        assert!(buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn fill_rect_fully_outside_noop() {
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.fill_rect(Rect { x: 100, y: 100, w: 3, h: 3 }, Color::RED);
        assert!(buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn clear_paints_every_pixel() {
        let (mut buf, w, h) = make_surface(5, 3);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.clear(Color::rgb(0x11, 0x22, 0x33));
        let c = Color::rgb(0x11, 0x22, 0x33).as_u32();
        assert!(buf.iter().all(|&p| p == c));
    }

    #[test]
    fn set_pixel_out_of_bounds_drops() {
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.set_pixel(-1, 0, Color::RED);
        s.set_pixel(0, -1, Color::RED);
        s.set_pixel(4, 0, Color::RED);
        s.set_pixel(0, 4, Color::RED);
        assert!(buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn draw_line_horizontal() {
        let (mut buf, w, h) = make_surface(8, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.draw_line(1, 2, 6, 2, Color::WHITE);
        for x in 0..w {
            for y in 0..h {
                let lit = (1..=6).contains(&x) && y == 2;
                let expected = if lit { Color::WHITE.as_u32() } else { 0 };
                assert_eq!(buf[(y * w + x) as usize], expected, "({},{})", x, y);
            }
        }
    }

    #[test]
    fn draw_line_vertical() {
        let (mut buf, w, h) = make_surface(4, 8);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.draw_line(2, 1, 2, 6, Color::WHITE);
        for x in 0..w {
            for y in 0..h {
                let lit = x == 2 && (1..=6).contains(&y);
                let expected = if lit { Color::WHITE.as_u32() } else { 0 };
                assert_eq!(buf[(y * w + x) as usize], expected, "({},{})", x, y);
            }
        }
    }

    #[test]
    fn draw_line_diagonal_endpoints() {
        let (mut buf, w, h) = make_surface(8, 8);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.draw_line(0, 0, 7, 7, Color::WHITE);
        // The two endpoints must be lit — Bresenham's defining property.
        assert_ne!(buf[0], 0);
        assert_ne!(buf[7 * 8 + 7], 0);
        // The main diagonal must be lit.
        for i in 0..8 {
            assert_eq!(buf[(i * 8 + i) as usize], Color::WHITE.as_u32());
        }
    }

    #[test]
    fn draw_line_reversed_endpoints() {
        // Same line, reversed start/end — must produce the same set
        // of lit pixels (symmetric property).
        let (mut a, w, h) = make_surface(6, 6);
        let (mut b, _, _) = make_surface(6, 6);
        let mut sa = Surface::from_slice(&mut a, w as usize, w, h);
        sa.draw_line(1, 4, 4, 1, Color::WHITE);
        let mut sb = Surface::from_slice(&mut b, w as usize, w, h);
        sb.draw_line(4, 1, 1, 4, Color::WHITE);
        assert_eq!(a, b);
    }

    #[test]
    fn draw_line_clips_off_surface() {
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        // Line that goes well past the right edge — shouldn't crash
        // and should lit only the in-bounds pixels.
        s.draw_line(0, 0, 100, 0, Color::WHITE);
        for x in 0..w {
            assert_eq!(buf[x as usize], Color::WHITE.as_u32());
        }
    }

    #[test]
    fn pitch_larger_than_width() {
        // Simulate a surface whose pitch > width (padded scanlines).
        let pitch = 8usize;
        let w = 4u32;
        let h = 3u32;
        let mut buf = vec![0u32; pitch * h as usize];
        let mut s = Surface::from_slice(&mut buf, pitch, w, h);
        s.fill_rect(Rect { x: 0, y: 0, w: 4, h: 3 }, Color::WHITE);
        // Lit pixels are only in cols 0..4 of each row — cols 4..8
        // (padding) must remain zero.
        for y in 0..h as usize {
            for x in 0..pitch {
                let expected = if x < w as usize { Color::WHITE.as_u32() } else { 0 };
                assert_eq!(buf[y * pitch + x], expected, "pixel ({},{})", x, y);
            }
        }
    }

    #[test]
    fn blit_bitmap_sub_happy_path() {
        // Sheet with four distinct 2x2 cells packed into a 4x4 bitmap:
        //   cell (0,0) = 1s, cell (1,0) = 2s, cell (0,1) = 3s, cell (1,1) = 4s.
        let sheet_data: [u32; 16] = [
            1, 1, 2, 2,
            1, 1, 2, 2,
            3, 3, 4, 4,
            3, 3, 4, 4,
        ];
        let sheet = crate::Bitmap::new(4, 4, &sheet_data).unwrap();
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        // Extract cell (1,1) — the 4s — and stamp at (0,0).
        s.blit_bitmap_sub(0, 0, &sheet, 2, 2, 2, 2, None);
        assert_eq!(buf[0], 4);
        assert_eq!(buf[1], 4);
        assert_eq!(buf[w as usize], 4);
        assert_eq!(buf[w as usize + 1], 4);
        // Rest untouched.
        for (i, &p) in buf.iter().enumerate() {
            if !matches!(i, 0 | 1 | 4 | 5) {
                assert_eq!(p, 0, "pixel idx {} should be 0", i);
            }
        }
    }

    #[test]
    fn blit_bitmap_sub_transparency_color_key() {
        // 2x2 bitmap: two opaque pixels and two magenta (transparent) pixels.
        let magenta = Color::rgb(0xFF, 0x00, 0xFF).as_u32();
        let white = Color::WHITE.as_u32();
        let sheet_data = [white, magenta, magenta, white];
        let sheet = crate::Bitmap::new(2, 2, &sheet_data).unwrap();
        let (mut buf, w, h) = make_surface(2, 2);
        // Pre-fill so we can tell "skipped" from "written".
        for p in buf.iter_mut() {
            *p = 0xDEADBEEF;
        }
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.blit_bitmap_sub(0, 0, &sheet, 0, 0, 2, 2, Some(Color::rgb(0xFF, 0x00, 0xFF)));
        assert_eq!(buf[0], white);
        assert_eq!(buf[1], 0xDEADBEEF, "magenta skipped");
        assert_eq!(buf[2], 0xDEADBEEF, "magenta skipped");
        assert_eq!(buf[3], white);
    }

    #[test]
    fn blit_bitmap_sub_clips_dst_right_and_bottom() {
        let sheet_data = [1u32; 16]; // 4x4 of 1s
        let sheet = crate::Bitmap::new(4, 4, &sheet_data).unwrap();
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        // Blit 4x4 at (2,2) on a 4x4 surface — only bottom-right 2x2 lands.
        s.blit_bitmap_sub(2, 2, &sheet, 0, 0, 4, 4, None);
        for y in 0..h {
            for x in 0..w {
                let expected = if x >= 2 && y >= 2 { 1 } else { 0 };
                assert_eq!(buf[(y * w + x) as usize], expected, "({},{})", x, y);
            }
        }
    }

    #[test]
    fn blit_bitmap_sub_clips_dst_left_and_top() {
        let sheet_data = [1u32; 16];
        let sheet = crate::Bitmap::new(4, 4, &sheet_data).unwrap();
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        // Blit 4x4 at (-2,-2) — only top-left 2x2 lands.
        s.blit_bitmap_sub(-2, -2, &sheet, 0, 0, 4, 4, None);
        for y in 0..h {
            for x in 0..w {
                let expected = if x < 2 && y < 2 { 1 } else { 0 };
                assert_eq!(buf[(y * w + x) as usize], expected, "({},{})", x, y);
            }
        }
    }

    #[test]
    fn blit_bitmap_sub_clips_src_to_bitmap_bounds() {
        // 3x3 bitmap, caller asks for a 5x5 sub-rect from (0,0).
        // Only the 3x3 inside the bitmap is read; result is that full
        // 3x3 lands at (0,0).
        let sheet_data = [7u32; 9];
        let sheet = crate::Bitmap::new(3, 3, &sheet_data).unwrap();
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.blit_bitmap_sub(0, 0, &sheet, 0, 0, 5, 5, None);
        for y in 0..h {
            for x in 0..w {
                let expected = if x < 3 && y < 3 { 7 } else { 0 };
                assert_eq!(buf[(y * w + x) as usize], expected, "({},{})", x, y);
            }
        }
    }

    #[test]
    fn blit_bitmap_sub_src_origin_outside_bitmap_noop() {
        let sheet_data = [1u32; 4];
        let sheet = crate::Bitmap::new(2, 2, &sheet_data).unwrap();
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        // Source origin (5,5) is past the 2x2 bitmap — nothing reads, nothing writes.
        s.blit_bitmap_sub(0, 0, &sheet, 5, 5, 2, 2, None);
        assert!(buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn blit_bitmap_sub_zero_size_noop() {
        let sheet_data = [1u32; 4];
        let sheet = crate::Bitmap::new(2, 2, &sheet_data).unwrap();
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.blit_bitmap_sub(0, 0, &sheet, 0, 0, 0, 2, None);
        s.blit_bitmap_sub(0, 0, &sheet, 0, 0, 2, 0, None);
        assert!(buf.iter().all(|&p| p == 0));
    }

    #[test]
    fn blit_bitmap_sub_partial_src_near_bitmap_edge() {
        // 4x4 bitmap, ask for a 3x3 sub-rect starting at (2,2).
        // Only the bottom-right 2x2 of the bitmap exists; it lands
        // at dst (0,0) as a 2x2 patch, the "missing" third row/col
        // writes nothing.
        let sheet_data: [u32; 16] = [
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 9, 9,
            0, 0, 9, 9,
        ];
        let sheet = crate::Bitmap::new(4, 4, &sheet_data).unwrap();
        let (mut buf, w, h) = make_surface(4, 4);
        let mut s = Surface::from_slice(&mut buf, w as usize, w, h);
        s.blit_bitmap_sub(0, 0, &sheet, 2, 2, 3, 3, None);
        for y in 0..h {
            for x in 0..w {
                let expected = if x < 2 && y < 2 { 9 } else { 0 };
                assert_eq!(buf[(y * w + x) as usize], expected, "({},{})", x, y);
            }
        }
    }
}
