// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Framebuffer text console — the boot/emergency console on a monitor.
//!
//! The kernel's console has always been the serial port. On a machine
//! with no serial cable attached, nothing is visible: not the boot log,
//! not a typed `[BOOT FAIL]`, not the shell prompt. This module mirrors
//! every `println!` (kernel and `SYS_PRINT` alike) onto the bootloader-
//! provided linear framebuffer as text, so a monitor shows what the
//! serial port shows. It is an *I/O device* in the same sense the UART
//! is — not part of the graphics stack ([ADR-011]: drivers and the
//! compositor live in userspace; the kernel owns no graphics). The one
//! point of contact with the graphics stack is ownership: the first
//! successful `SYS_MAP_FRAMEBUFFER` hands the display to userspace and
//! this console goes [`State::Released`] for good — the kernel never
//! draws over a scanout driver.
//!
//! ## Design
//!
//! - **Pure core, thin shell.** [`Grid`] is a character grid + cursor +
//!   ANSI-escape stripper with no pixels at all; [`render`] turns grid
//!   cells into pixels through [`PixelSink`], a bounded `(x, y, argb)`
//!   writer. Host tests drive both over a `Vec<u32>`. The only `unsafe`
//!   is the one volatile store into the mapped framebuffer.
//! - **No framebuffer reads.** Real framebuffers are uncached/write-
//!   combined memory: reads are an order of magnitude slower than
//!   writes, so the classic `memmove` scroll is the wrong tool. The grid
//!   is the source of truth; a scroll re-renders rows from it (writes
//!   only), and scrolls happen a quarter-screen at a time so the cost is
//!   amortized over many lines.
//! - **Glyphs** are the hand-drawn 8×8 ASCII face libgui ships, scaled
//!   2× to 16×16 cells so a 1080p panel reads at arm's length. The bitmap
//!   is duplicated here rather than shared because the kernel cannot
//!   depend on a userspace crate.
//!   Revisit when: a second kernel consumer of a font appears (a shared
//!   `cambios-font` crate à la `cambios-abi` is the shape).
//! - **Escapes.** The shell styles its prompt with CSI sequences
//!   (`ESC [ … m`). The grid parses `ESC [ params final` and discards
//!   it, so color codes never render as glyph soup. Cursor-movement
//!   escapes are discarded too (the prompt redraw after backspace is
//!   approximated by backspace handling, not by honoring `ESC [ K`).
//!
//! ## Pixel formats
//!
//! 32 bits per pixel with arbitrary channel shifts (the Limine/GOP
//! norm). Anything else leaves the console [`State::Inactive`] with the
//! reason printed to serial — never a wrong-stride write into memory
//! whose layout we did not understand.
//!
//! [ADR-011]: ../../docs/adr/011-graphics-architecture-and-scaling.md

use crate::boot::FramebufferInfo;
use crate::IrqSpinlock;

// ============================================================================
// Bounds
// ============================================================================

/// HARDWARE: the built-in face is 8 pixels wide per glyph (bit 7 =
/// leftmost); fixed by the bitmap below.
pub const GLYPH_W: u32 = 8;
/// HARDWARE: the built-in face is 8 rows per glyph; fixed by the bitmap.
pub const GLYPH_H: u32 = 8;
/// TUNING: integer scale applied to the 8×8 face. 2 → 16×16 cells, ~120
/// columns on a 1920-wide panel; readable at a desk, dense enough for a
/// boot log. 1 would be unreadable on 4K, 3 wastes a 1024-wide panel.
pub const SCALE: u32 = 2;
/// SCAFFOLDING: grid capacity in columns. 256 × 16 px = 4096 px wide,
/// i.e. a 4K panel at SCALE 2 fits exactly; wider panels clamp (the
/// right margin is simply unused). Cost is the `cells` array below.
/// Replace when: a panel wider than 4096 px at SCALE 2 is a target.
pub const MAX_COLS: usize = 256;
/// SCAFFOLDING: grid capacity in rows. 160 × 16 px = 2560 px tall —
/// 4K (2160) fits with margin; taller clamps. `cells` is
/// `MAX_COLS × MAX_ROWS` = 40 KiB of .bss, const-initialized in place.
/// Replace when: a panel taller than 2560 px at SCALE 2 is a target.
pub const MAX_ROWS: usize = 160;
/// TUNING: rows re-rendered per scroll event. Scrolling redraws the
/// whole grid (no framebuffer reads — see module doc), so scrolling one
/// line at a time would redraw the screen per line; a quarter of the
/// visible rows amortizes that to one redraw per ~16 lines on 1080p.
pub const SCROLL_DIVISOR: usize = 4;

/// ARCHITECTURAL: ASCII printable range the face covers; bytes outside
/// render as the replacement glyph (`?`).
const FIRST_GLYPH: u8 = 0x20;
const NUM_GLYPHS: usize = 96;

// ============================================================================
// The face (identical bytes to user/libgui/src/font.rs)
// ============================================================================

#[rustfmt::skip]
const FONT_8X8_DATA: [u8; 96 * 8] = [
    // 0x20 ' '
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x21 '!'
    0x30, 0x30, 0x30, 0x30, 0x00, 0x30, 0x30, 0x00,
    // 0x22 '"'
    0x6C, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x23 '#'
    0x6C, 0x6C, 0xFE, 0x6C, 0xFE, 0x6C, 0x6C, 0x00,
    // 0x24 '$'
    0x18, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00,
    // 0x25 '%'
    0x62, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x46, 0x00,
    // 0x26 '&'
    0x38, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0x76, 0x00,
    // 0x27 '\''
    0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x28 '('
    0x18, 0x30, 0x30, 0x30, 0x30, 0x30, 0x18, 0x00,
    // 0x29 ')'
    0x30, 0x18, 0x18, 0x18, 0x18, 0x18, 0x30, 0x00,
    // 0x2A '*'
    0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00,
    // 0x2B '+'
    0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00,
    // 0x2C ','
    0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30,
    // 0x2D '-'
    0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00,
    // 0x2E '.'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18,
    // 0x2F '/'
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00,
    // 0x30 '0'
    0x3C, 0x66, 0x6E, 0x7E, 0x76, 0x66, 0x3C, 0x00,
    // 0x31 '1'
    0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00,
    // 0x32 '2'
    0x3C, 0x66, 0x06, 0x1C, 0x30, 0x60, 0x7E, 0x00,
    // 0x33 '3'
    0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00,
    // 0x34 '4'
    0x0E, 0x1E, 0x36, 0x66, 0x7E, 0x06, 0x06, 0x00,
    // 0x35 '5'
    0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00,
    // 0x36 '6'
    0x3C, 0x66, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00,
    // 0x37 '7'
    0x7E, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00,
    // 0x38 '8'
    0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00,
    // 0x39 '9'
    0x3C, 0x66, 0x66, 0x3E, 0x06, 0x66, 0x3C, 0x00,
    // 0x3A ':'
    0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00,
    // 0x3B ';'
    0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x30, 0x00,
    // 0x3C '<'
    0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00,
    // 0x3D '='
    0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00,
    // 0x3E '>'
    0x60, 0x30, 0x18, 0x0C, 0x18, 0x30, 0x60, 0x00,
    // 0x3F '?'
    0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00,
    // 0x40 '@'
    0x3C, 0x66, 0x6E, 0x6A, 0x6E, 0x60, 0x3C, 0x00,
    // 0x41 'A'
    0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00,
    // 0x42 'B'
    0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00,
    // 0x43 'C'
    0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00,
    // 0x44 'D'
    0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00,
    // 0x45 'E'
    0x7E, 0x60, 0x60, 0x78, 0x60, 0x60, 0x7E, 0x00,
    // 0x46 'F'
    0x7E, 0x60, 0x60, 0x78, 0x60, 0x60, 0x60, 0x00,
    // 0x47 'G'
    0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3C, 0x00,
    // 0x48 'H'
    0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00,
    // 0x49 'I'
    0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00,
    // 0x4A 'J'
    0x0E, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00,
    // 0x4B 'K'
    0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00,
    // 0x4C 'L'
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00,
    // 0x4D 'M'
    0xC3, 0xE7, 0xFF, 0xDB, 0xC3, 0xC3, 0xC3, 0x00,
    // 0x4E 'N'
    0x63, 0x73, 0x7B, 0x6F, 0x67, 0x63, 0x63, 0x00,
    // 0x4F 'O'
    0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00,
    // 0x50 'P'
    0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00,
    // 0x51 'Q'
    0x3C, 0x66, 0x66, 0x66, 0x6C, 0x3C, 0x06, 0x00,
    // 0x52 'R'
    0x7C, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x00,
    // 0x53 'S'
    0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00,
    // 0x54 'T'
    0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00,
    // 0x55 'U'
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00,
    // 0x56 'V'
    0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00,
    // 0x57 'W'
    0xC3, 0xC3, 0xC3, 0xDB, 0xFF, 0xE7, 0xC3, 0x00,
    // 0x58 'X'
    0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00,
    // 0x59 'Y'
    0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00,
    // 0x5A 'Z'
    0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00,
    // 0x5B '['
    0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00,
    // 0x5C '\\'
    0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x00,
    // 0x5D ']'
    0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00,
    // 0x5E '^'
    0x18, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x5F '_'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E,
    // 0x60 '`'
    0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x61..=0x7A lowercase. Hand-drawn at 8×8 to give terminal-window
    // a readable shell prompt. Descenders (g, j, p, q, y) use row 7 —
    // they bleed into the next cell row's blank top, which is fine for
    // the v0 grid renderer (cells aren't separated by extra space).
    0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00, // a
    0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00, // b
    0x00, 0x00, 0x3C, 0x66, 0x60, 0x66, 0x3C, 0x00, // c
    0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00, // d
    0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00, // e
    0x1C, 0x36, 0x30, 0x78, 0x30, 0x30, 0x30, 0x00, // f
    0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x7C, // g (descender)
    0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00, // h
    0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00, // i
    0x06, 0x00, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, // j (descender)
    0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x00, // k
    0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, // l
    0x00, 0x00, 0x66, 0xFF, 0xFF, 0xDB, 0xC3, 0x00, // m
    0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00, // n
    0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00, // o
    0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, // p (descender)
    0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06, // q (descender)
    0x00, 0x00, 0x7C, 0x66, 0x60, 0x60, 0x60, 0x00, // r
    0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00, // s
    0x18, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x0E, 0x00, // t
    0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00, // u
    0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00, // v
    0x00, 0x00, 0xC3, 0xC3, 0xDB, 0xFF, 0x66, 0x00, // w
    0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00, // x
    0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x7C, // y (descender)
    0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00, // z
    // 0x7B '{'
    0x0C, 0x18, 0x18, 0x30, 0x18, 0x18, 0x0C, 0x00,
    // 0x7C '|'
    0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00,
    // 0x7D '}'
    0x30, 0x18, 0x18, 0x0C, 0x18, 0x18, 0x30, 0x00,
    // 0x7E '~'
    0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x7F DEL  — blank (control char, never rendered)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Glyph bitmap for `byte`, or the `?` glyph for anything the face
/// does not cover (control bytes never reach here; the grid filters).
fn glyph(byte: u8) -> &'static [u8] {
    let idx = if (FIRST_GLYPH..FIRST_GLYPH + NUM_GLYPHS as u8).contains(&byte) {
        (byte - FIRST_GLYPH) as usize
    } else {
        (b'?' - FIRST_GLYPH) as usize
    };
    let start = idx * GLYPH_H as usize;
    &FONT_8X8_DATA[start..start + GLYPH_H as usize]
}

// ============================================================================
// Pure core: the character grid
// ============================================================================

/// Where the escape-sequence parser is between bytes. Exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscState {
    /// Plain text.
    Text,
    /// Saw `ESC`; the next byte decides.
    Esc,
    /// Inside `ESC [ …`; discard until a final byte in `0x40..=0x7E`.
    Csi,
}

/// What [`Grid::feed`] asks the renderer to do after consuming a byte.
/// The grid never draws; it reports the minimal redraw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redraw {
    /// Nothing visible changed (escape byte, no-op).
    None,
    /// One cell changed: redraw `(col, row)`.
    Cell { col: usize, row: usize },
    /// Rows scrolled: redraw every row.
    All,
}

/// Character grid with a cursor and an escape stripper. Pure state; no
/// pixels. Sized by the SCAFFOLDING bounds above; the live `cols`/`rows`
/// are the panel's capacity clamped to them.
pub struct Grid {
    cols: usize,
    rows: usize,
    cur_col: usize,
    cur_row: usize,
    esc: EscState,
    cells: [[u8; MAX_COLS]; MAX_ROWS],
}

impl Grid {
    /// Const-constructible so the static below is initialized in place
    /// (.bss), never built on a stack (Convention 4).
    pub const fn new() -> Self {
        Self {
            cols: 0,
            rows: 0,
            cur_col: 0,
            cur_row: 0,
            esc: EscState::Text,
            cells: [[b' '; MAX_COLS]; MAX_ROWS],
        }
    }

    /// Set the live geometry (clamped to capacity) and clear.
    pub fn reset(&mut self, cols: usize, rows: usize) {
        self.cols = cols.min(MAX_COLS);
        self.rows = rows.min(MAX_ROWS);
        self.cur_col = 0;
        self.cur_row = 0;
        self.esc = EscState::Text;
        for row in self.cells.iter_mut() {
            for c in row.iter_mut() {
                *c = b' ';
            }
        }
    }

    pub fn cols(&self) -> usize { self.cols }
    pub fn rows(&self) -> usize { self.rows }
    pub fn cursor(&self) -> (usize, usize) { (self.cur_col, self.cur_row) }
    pub fn cell(&self, col: usize, row: usize) -> u8 { self.cells[row][col] }

    /// Consume one byte; report what to redraw. Bounded: at most one
    /// scroll per call, and a scroll touches ≤ `rows` rows.
    pub fn feed(&mut self, byte: u8) -> Redraw {
        if self.cols == 0 || self.rows == 0 {
            return Redraw::None;
        }
        match self.esc {
            EscState::Esc => {
                self.esc = if byte == b'[' { EscState::Csi } else { EscState::Text };
                return Redraw::None;
            }
            EscState::Csi => {
                if (0x40..=0x7E).contains(&byte) {
                    self.esc = EscState::Text;
                }
                return Redraw::None;
            }
            EscState::Text => {}
        }
        match byte {
            0x1B => {
                self.esc = EscState::Esc;
                Redraw::None
            }
            b'\n' => self.newline(),
            b'\r' => {
                self.cur_col = 0;
                Redraw::None
            }
            0x08 => {
                // Backspace: step back and blank the cell (the shell's
                // line editor emits BS SP BS; blanking here makes the
                // two renderings agree).
                if self.cur_col > 0 {
                    self.cur_col -= 1;
                }
                self.cells[self.cur_row][self.cur_col] = b' ';
                Redraw::Cell { col: self.cur_col, row: self.cur_row }
            }
            // UTF-8: a lead byte becomes one replacement glyph and its
            // continuation bytes are dropped, so a multi-byte character
            // (the boot log's ✓ / → / —) occupies one cell, not three.
            0xC0..=0xFF => self.put(b'?'),
            0x80..=0xBF => Redraw::None,
            b'\t' => {
                // Advance to the next multiple of 8, writing spaces.
                let target = ((self.cur_col / 8) + 1) * 8;
                let mut last = Redraw::None;
                while self.cur_col < target && self.cur_col < self.cols {
                    last = self.put(b' ');
                }
                last
            }
            0x00..=0x1F | 0x7F => Redraw::None,
            _ => self.put(byte),
        }
    }

    fn put(&mut self, byte: u8) -> Redraw {
        if self.cur_col >= self.cols {
            // Wrap before writing so the last column is never skipped.
            let scrolled = self.newline();
            self.cells[self.cur_row][self.cur_col] = byte;
            let col = self.cur_col;
            self.cur_col += 1;
            return match scrolled {
                Redraw::All => Redraw::All,
                _ => Redraw::Cell { col, row: self.cur_row },
            };
        }
        self.cells[self.cur_row][self.cur_col] = byte;
        let r = Redraw::Cell { col: self.cur_col, row: self.cur_row };
        self.cur_col += 1;
        r
    }

    /// Move to the start of the next row, scrolling a block of rows up
    /// when the bottom is reached.
    fn newline(&mut self) -> Redraw {
        self.cur_col = 0;
        if self.cur_row + 1 < self.rows {
            self.cur_row += 1;
            return Redraw::None;
        }
        let by = (self.rows / SCROLL_DIVISOR).max(1);
        // Shift rows up by `by`; blank the tail. Bounded by `rows`.
        for r in 0..self.rows {
            if r + by < self.rows {
                self.cells[r] = self.cells[r + by];
            } else {
                self.cells[r] = [b' '; MAX_COLS];
            }
        }
        self.cur_row = self.rows - by;
        Redraw::All
    }
}

impl Default for Grid {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// Pure core: rendering through a pixel sink
// ============================================================================

/// A bounded destination for pixels. The framebuffer implements it with
/// one volatile store; tests implement it over a `Vec<u32>`.
pub trait PixelSink {
    /// Store `argb` (already packed for the device) at `(x, y)`.
    /// Callers only pass in-range coordinates; implementations may
    /// still bounds-check.
    fn put(&mut self, x: u32, y: u32, packed: u32);
}

/// Device pixel packing derived from the boot-reported channel masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packing {
    pub r_shift: u8,
    pub g_shift: u8,
    pub b_shift: u8,
}

impl Packing {
    /// Pack 8-bit channels into the device word. Mask sizes other than
    /// 8 are truncated to their top bits (8-bit panels are the norm).
    pub const fn pack(&self, r: u8, g: u8, b: u8) -> u32 {
        ((r as u32) << self.r_shift) | ((g as u32) << self.g_shift) | ((b as u32) << self.b_shift)
    }
}

/// Console colors (8-bit channels, packed per device at init).
pub const FG: (u8, u8, u8) = (0xE6, 0xE6, 0xE6);
pub const BG: (u8, u8, u8) = (0x10, 0x12, 0x18);

/// Draw one cell: the glyph for `byte` scaled by `SCALE`, over an
/// opaque background. Writes exactly `(GLYPH_W × GLYPH_H × SCALE²)`
/// pixels — bounded, no reads.
pub fn render_cell<S: PixelSink>(sink: &mut S, col: usize, row: usize, byte: u8, fg: u32, bg: u32) {
    let bits = glyph(byte);
    let x0 = col as u32 * GLYPH_W * SCALE;
    let y0 = row as u32 * GLYPH_H * SCALE;
    for gy in 0..GLYPH_H {
        let line = bits[gy as usize];
        for gx in 0..GLYPH_W {
            let on = line & (0x80 >> gx) != 0;
            let color = if on { fg } else { bg };
            for sy in 0..SCALE {
                for sx in 0..SCALE {
                    sink.put(x0 + gx * SCALE + sx, y0 + gy * SCALE + sy, color);
                }
            }
        }
    }
}

/// Apply a [`Redraw`] against the grid. `All` redraws every live cell
/// (`cols × rows` renders — the scroll cost the module doc describes).
pub fn render<S: PixelSink>(sink: &mut S, grid: &Grid, what: Redraw, fg: u32, bg: u32) {
    match what {
        Redraw::None => {}
        Redraw::Cell { col, row } => render_cell(sink, col, row, grid.cell(col, row), fg, bg),
        Redraw::All => {
            for row in 0..grid.rows() {
                for col in 0..grid.cols() {
                    render_cell(sink, col, row, grid.cell(col, row), fg, bg);
                }
            }
        }
    }
}

// ============================================================================
// The device: a mapped 32-bpp linear framebuffer
// ============================================================================

/// The kernel's view of the boot framebuffer. `base` is the HHDM virtual
/// address of the first pixel; Limine maps the framebuffer into the HHDM
/// on x86_64 and the kernel keeps Limine's upper-half page tables, so
/// the mapping is live for the kernel's lifetime.
#[derive(Debug, Clone, Copy)]
pub struct LinearFb {
    base: *mut u8,
    width: u32,
    height: u32,
    pitch: u32,
    packing: Packing,
}

// SAFETY: the pointer is a kernel-mapped MMIO/HHDM address valid for the
// kernel's lifetime; all access goes through the `FBCON` spinlock.
unsafe impl Send for LinearFb {}

impl PixelSink for LinearFb {
    #[inline]
    fn put(&mut self, x: u32, y: u32, packed: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let off = y as usize * self.pitch as usize + x as usize * 4;
        // `off` is inside `pitch × height`: both coordinates were bounds-
        // checked above and the 32-bpp precondition (4 bytes per pixel) is
        // enforced at `init`. wrapping_add keeps the address arithmetic
        // safe; the volatile store is the one unsafe operation.
        let dst = self.base.wrapping_add(off) as *mut u32;
        // SAFETY: `dst` lies within the framebuffer the bootloader
        // reported (see the bounds argument above), `base` is its live
        // HHDM mapping for the kernel's lifetime, and this is a volatile
        // 4-byte store to device memory with no aliasing Rust reference.
        unsafe { core::ptr::write_volatile(dst, packed) };
    }
}

/// Console lifecycle. Exhaustive; no boolean flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No usable framebuffer (none reported, or an unsupported pixel
    /// format). Output goes to serial only.
    Inactive,
    /// Mirroring console output onto the panel.
    Active,
    /// Userspace mapped the framebuffer (`SYS_MAP_FRAMEBUFFER`); the
    /// kernel never draws again this boot.
    Released,
}

/// Why `init` left the console inactive — printed to serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    NoFramebuffer,
    /// Only 32-bpp panels are supported.
    UnsupportedBpp(u16),
    /// Narrower than one cell.
    TooSmall,
}

struct Console {
    state: State,
    fb: Option<LinearFb>,
    fg: u32,
    bg: u32,
    grid: Grid,
}

impl Console {
    const fn new() -> Self {
        Self { state: State::Inactive, fb: None, fg: 0, bg: 0, grid: Grid::new() }
    }
}

/// Independent lock domain (like `SERIAL1`): taken by `io::print` after
/// the serial guard is dropped, by `init` during single-threaded boot,
/// and by `release` from the map-framebuffer syscall. Never held with
/// any hierarchy lock. An `IrqSpinlock` because `println!` runs from
/// every context including exception handlers: a plain spinlock here
/// deadlocks the moment an interrupt whose handler prints lands on the
/// CPU mid-render (interrupts are masked for the duration of a print).
/// The `Console` is const-initialized in place (40 KiB grid in .bss) —
/// never constructed on a stack.
static FBCON: IrqSpinlock<Console> = IrqSpinlock::new(Console::new());

/// Geometry check shared by `init` and the tests.
pub fn geometry(fb: &FramebufferInfo) -> Result<(usize, usize, Packing), InitError> {
    if fb.bpp != 32 {
        return Err(InitError::UnsupportedBpp(fb.bpp));
    }
    let cell = GLYPH_W * SCALE;
    let cols = (fb.width / cell) as usize;
    let rows = (fb.height / (GLYPH_H * SCALE)) as usize;
    if cols == 0 || rows == 0 {
        return Err(InitError::TooSmall);
    }
    Ok((
        cols,
        rows,
        Packing { r_shift: fb.red_mask_shift, g_shift: fb.green_mask_shift, b_shift: fb.blue_mask_shift },
    ))
}

/// Bring the console up on framebuffer 0, if the boot protocol reported
/// one we can drive. Single-threaded boot, after `boot::populate`.
/// Clears the panel to the background and starts mirroring. Returns
/// `Err` (and stays `Inactive`) rather than ever drawing into a
/// framebuffer whose layout is not understood.
pub fn init() -> Result<(usize, usize), InitError> {
    let info = crate::boot::info();
    let fb = info.framebuffers().next().ok_or(InitError::NoFramebuffer)?;
    let (cols, rows, packing) = geometry(fb)?;
    let base = (fb.phys_addr + crate::hhdm_offset()) as *mut u8;
    let mut dev = LinearFb { base, width: fb.width, height: fb.height, pitch: fb.pitch, packing };
    let fg = packing.pack(FG.0, FG.1, FG.2);
    let bg = packing.pack(BG.0, BG.1, BG.2);
    // Clear the whole panel (writes only; bounded by width × height).
    for y in 0..fb.height {
        for x in 0..fb.width {
            dev.put(x, y, bg);
        }
    }
    let mut con = FBCON.lock();
    con.grid.reset(cols, rows);
    con.fg = fg;
    con.bg = bg;
    con.fb = Some(dev);
    con.state = State::Active;
    Ok((cols, rows))
}

/// `fmt::Write` over a locked console: feeds bytes to the grid and
/// renders each reported redraw into the device.
struct Writer<'a> {
    con: &'a mut Console,
    dev: LinearFb,
}

impl core::fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let (fg, bg) = (self.con.fg, self.con.bg);
        for &b in s.as_bytes() {
            let what = self.con.grid.feed(b);
            render(&mut self.dev, &self.con.grid, what, fg, bg);
        }
        Ok(())
    }
}

/// Mirror formatted output onto the panel. No-op unless `Active`.
/// Called by `io::print` with the serial guard already released; takes
/// the console lock once per call.
pub fn print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let mut con = FBCON.lock();
    if con.state != State::Active {
        return;
    }
    let Some(dev) = con.fb else { return };
    let _ = write!(Writer { con: &mut con, dev }, "{}", args);
}

/// Best-effort variant for interrupt context: drops the output if the
/// console is held by another CPU instead of spinning.
pub fn try_print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let Some(mut con) = FBCON.try_lock() else { return };
    if con.state != State::Active {
        return;
    }
    let Some(dev) = con.fb else { return };
    let _ = write!(Writer { con: &mut con, dev }, "{}", args);
}

/// Mirror a plain string onto the panel (same contract as [`print`]).
pub fn write_str(s: &str) {
    print(format_args!("{}", s));
}

/// Userspace has taken the display (first successful
/// `SYS_MAP_FRAMEBUFFER`). Irreversible for this boot.
pub fn release() {
    let mut con = FBCON.lock();
    if con.state == State::Active {
        con.state = State::Released;
    }
}

/// Current lifecycle state (diagnostics / tests).
pub fn state() -> State {
    FBCON.lock().state
}

// ============================================================================
// Tests (host): pure grid + renderer over a Vec<u32>
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct Canvas {
        w: u32,
        h: u32,
        px: alloc::vec::Vec<u32>,
    }

    impl Canvas {
        fn new(w: u32, h: u32) -> Self {
            Self { w, h, px: alloc::vec![0; (w * h) as usize] }
        }
        fn at(&self, x: u32, y: u32) -> u32 {
            self.px[(y * self.w + x) as usize]
        }
    }

    impl PixelSink for Canvas {
        fn put(&mut self, x: u32, y: u32, packed: u32) {
            if x < self.w && y < self.h {
                self.px[(y * self.w + x) as usize] = packed;
            }
        }
    }

    fn grid(cols: usize, rows: usize) -> Grid {
        let mut g = Grid::new();
        g.reset(cols, rows);
        g
    }

    fn feed_str(g: &mut Grid, s: &str) -> Redraw {
        let mut last = Redraw::None;
        for &b in s.as_bytes() {
            last = g.feed(b);
        }
        last
    }

    fn row_text(g: &Grid, row: usize) -> alloc::string::String {
        (0..g.cols()).map(|c| g.cell(c, row) as char).collect()
    }

    #[test]
    fn text_lands_in_cells_and_advances_cursor() {
        let mut g = grid(10, 3);
        assert_eq!(g.feed(b'H'), Redraw::Cell { col: 0, row: 0 });
        assert_eq!(g.feed(b'i'), Redraw::Cell { col: 1, row: 0 });
        assert_eq!(g.cursor(), (2, 0));
        assert_eq!(&row_text(&g, 0)[..2], "Hi");
    }

    #[test]
    fn newline_and_carriage_return() {
        let mut g = grid(10, 3);
        feed_str(&mut g, "ab\r\ncd");
        assert_eq!(&row_text(&g, 0)[..2], "ab");
        assert_eq!(&row_text(&g, 1)[..2], "cd");
        assert_eq!(g.cursor(), (2, 1));
        // CR alone rewinds the column without moving down.
        feed_str(&mut g, "\rX");
        assert_eq!(&row_text(&g, 1)[..2], "Xd");
    }

    #[test]
    fn long_line_wraps_without_dropping_the_last_column() {
        let mut g = grid(4, 3);
        feed_str(&mut g, "abcdef");
        assert_eq!(&row_text(&g, 0), "abcd");
        assert_eq!(&row_text(&g, 1)[..2], "ef");
    }

    #[test]
    fn scroll_shifts_a_quarter_block_and_reports_all() {
        let mut g = grid(4, 8); // scroll block = 2 rows
        for i in 0..8 {
            feed_str(&mut g, &alloc::format!("{}", i));
            if i < 7 {
                assert_eq!(g.feed(b'\n'), Redraw::None);
            }
        }
        // Cursor on the last row; the next newline scrolls by 2.
        assert_eq!(g.cursor(), (1, 7));
        assert_eq!(g.feed(b'\n'), Redraw::All);
        assert_eq!(g.cursor(), (0, 6));
        assert_eq!(&row_text(&g, 0)[..1], "2");
        assert_eq!(&row_text(&g, 5)[..1], "7");
        assert_eq!(row_text(&g, 6).trim(), "");
        assert_eq!(row_text(&g, 7).trim(), "");
    }

    #[test]
    fn csi_escapes_are_swallowed_whole() {
        let mut g = grid(16, 2);
        // The shell's styled prompt shape: dim, reset, 36;2m, reset.
        feed_str(&mut g, "\x1b[2mcambios\x1b[0m\x1b[36;2m@\x1b[0m>");
        assert_eq!(&row_text(&g, 0)[..9], "cambios@>");
        assert_eq!(g.cursor(), (9, 0));
        // A lone ESC followed by a non-'[' byte is dropped with that byte.
        feed_str(&mut g, "\x1bZq");
        assert_eq!(&row_text(&g, 0)[..10], "cambios@>q");
    }

    #[test]
    fn backspace_blanks_and_steps_back() {
        let mut g = grid(8, 1);
        feed_str(&mut g, "abc\x08");
        assert_eq!(g.cursor(), (2, 0));
        assert_eq!(&row_text(&g, 0)[..3], "ab ");
        // At column 0 it stays put.
        let mut g2 = grid(8, 1);
        g2.feed(0x08);
        assert_eq!(g2.cursor(), (0, 0));
    }

    #[test]
    fn tab_advances_to_next_stop() {
        let mut g = grid(16, 1);
        feed_str(&mut g, "a\tb");
        assert_eq!(g.cursor(), (9, 0));
        assert_eq!(g.cell(8, 0), b'b');
    }

    #[test]
    fn multibyte_utf8_renders_as_one_replacement_cell() {
        let mut g = grid(16, 1);
        feed_str(&mut g, "a✓b→c");
        assert_eq!(&row_text(&g, 0)[..5], "a?b?c");
        assert_eq!(g.cursor(), (5, 0));
    }

    #[test]
    fn control_bytes_and_zero_geometry_are_noops() {
        let mut g = grid(4, 2);
        assert_eq!(g.feed(0x07), Redraw::None);
        assert_eq!(g.cursor(), (0, 0));
        let mut z = Grid::new(); // cols = rows = 0
        assert_eq!(z.feed(b'x'), Redraw::None);
    }

    #[test]
    fn render_cell_paints_the_scaled_glyph_and_background() {
        let packing = Packing { r_shift: 16, g_shift: 8, b_shift: 0 };
        let fg = packing.pack(0xFF, 0xFF, 0xFF);
        let bg = packing.pack(0, 0, 0);
        let mut c = Canvas::new(64, 32);
        render_cell(&mut c, 1, 1, b'!', fg, bg);
        let bits = glyph(b'!');
        // Every pixel of the cell matches the scaled bitmap; outside is untouched (0).
        for gy in 0..GLYPH_H {
            for gx in 0..GLYPH_W {
                let on = bits[gy as usize] & (0x80 >> gx) != 0;
                for sy in 0..SCALE {
                    for sx in 0..SCALE {
                        let x = 16 + gx * SCALE + sx;
                        let y = 16 + gy * SCALE + sy;
                        assert_eq!(c.at(x, y), if on { fg } else { bg }, "pixel ({x},{y})");
                    }
                }
            }
        }
        assert_eq!(c.at(0, 0), 0);
        assert_eq!(c.at(15, 15), 0);
        // '!' has lit pixels; the background color must differ from fg.
        assert!(bits.iter().any(|&b| b != 0));
    }

    #[test]
    fn unknown_bytes_render_as_question_mark_and_space_is_blank() {
        assert_eq!(glyph(0xFF), glyph(b'?'));
        assert!(glyph(b' ').iter().all(|&b| b == 0));
    }

    #[test]
    fn geometry_rejects_unsupported_panels() {
        let mut fb = FramebufferInfo {
            phys_addr: 0, width: 1024, height: 768, pitch: 4096, bpp: 32,
            red_mask_size: 8, red_mask_shift: 16, green_mask_size: 8, green_mask_shift: 8,
            blue_mask_size: 8, blue_mask_shift: 0,
        };
        assert_eq!(geometry(&fb).unwrap(), (64, 48, Packing { r_shift: 16, g_shift: 8, b_shift: 0 }));
        fb.bpp = 24;
        assert_eq!(geometry(&fb).unwrap_err(), InitError::UnsupportedBpp(24));
        fb.bpp = 32;
        fb.width = 8;
        assert_eq!(geometry(&fb).unwrap_err(), InitError::TooSmall);
        // A 4K panel clamps to the grid capacity rather than overflowing.
        fb.width = 7680;
        fb.height = 4320;
        let (cols, rows, _) = geometry(&fb).unwrap();
        let mut g = Grid::new();
        g.reset(cols, rows);
        assert_eq!(g.cols(), MAX_COLS);
        assert_eq!(g.rows(), MAX_ROWS);
    }

    #[test]
    fn packing_honors_channel_shifts() {
        let bgr = Packing { r_shift: 0, g_shift: 8, b_shift: 16 };
        assert_eq!(bgr.pack(0x11, 0x22, 0x33), 0x0033_2211);
        let rgb = Packing { r_shift: 16, g_shift: 8, b_shift: 0 };
        assert_eq!(rgb.pack(0x11, 0x22, 0x33), 0x0011_2233);
    }
}
