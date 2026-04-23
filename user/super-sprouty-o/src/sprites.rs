// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O sprite sheet.
//!
//! 96×32 XRGB8888 strip of three 32×32 cells:
//! - Cell 0 (cols 0..32): Sprouty idle
//! - Cell 1 (cols 32..64): ground tile (grass top + dirt)
//! - Cell 2 (cols 64..96): weed-walker (enemy, Session 2d)
//!
//! Session 3 extends rightward: Sprouty walk-0 / walk-1 / jump, weed
//! walk-1, seed, goal tree. Final sheet size is reserved at 256×32.
//!
//! Pixels are authored as ASCII art — one char per pixel, one palette
//! index per char — and expanded to u32 at compile time. Keeps the
//! sprite source readable/editable without a separate asset pipeline.

use arcos_libgui::{Bitmap, Color};

/// Cell size. Each sheet cell is a square of this side, in pixels.
pub const CELL: u32 = 32;

/// Sheet geometry (3 cells wide × 1 tall).
pub const SHEET_W: u32 = CELL * 3;
pub const SHEET_H: u32 = CELL;

/// Color-key transparency value. Pure magenta — chosen to not match
/// any natural sprite color, so `blit_bitmap_sub(..., Some(TRANSPARENT))`
/// lets the background (sky) show through.
pub const TRANSPARENT: Color = Color::rgb(0xFF, 0x00, 0xFF);

/// 16-entry palette. Indices 11..16 reserved for Session 3 growth
/// (seed yellow, goal-tree trunk + blossom, lose-overlay colors).
const PALETTE: [u32; 16] = [
    0x00FF_00FF, // 0: transparent (magenta — color-key)
    0x0087_CEEB, // 1: sky (unused in sprites; background clear color)
    0x008B_5A2B, // 2: dirt brown
    0x004C_AF50, // 3: grass green
    0x0066_BB6A, // 4: Sprouty body (light green)
    0x002E_7D32, // 5: Sprouty leaf (dark green)
    0x004E_342E, // 6: stem / dark brown
    0x00FF_FFFF, // 7: eye white
    0x0021_2121, // 8: eye pupil
    0x008E_2D2D, // 9: weed body (dark red)
    0x004A_0000, // 10: weed outline / thorn (very dark red)
    0, 0, 0, 0, 0,
];

/// Cell 0 — Sprouty idle. Legend:
///   `.` transparent  `L` body  `G` dark leaf  `=` stem
///   `o` eye white    `O` eye pupil
const SPROUTY_ART: [[u8; CELL as usize]; CELL as usize] = [
    *b"................................", //  0
    *b"................................", //  1
    *b"................................", //  2
    *b"................................", //  3
    *b"...............GG...............", //  4
    *b"..............GGGG..............", //  5
    *b".............GGGGGG.............", //  6
    *b"..............GGGG..............", //  7
    *b"...............==...............", //  8
    *b"...............==...............", //  9
    *b"............LLLLLLLL............", // 10
    *b"..........LLLLLLLLLLLL..........", // 11
    *b".........LLLLLLLLLLLLLL.........", // 12
    *b"........LLLLLLLLLLLLLLLL........", // 13
    *b"........LLooLLLLLLLLooLL........", // 14
    *b"........LLOOLLLLLLLLOOLL........", // 15
    *b"........LLLLLLLLLLLLLLLL........", // 16
    *b"........LLLLLLLLLLLLLLLL........", // 17
    *b"........LLLLLLLLLLLLLLLL........", // 18
    *b"........LLLLLLLLLLLLLLLL........", // 19
    *b".........LLLLLLLLLLLLLL.........", // 20
    *b"..........LLLLLLLLLLLL..........", // 21
    *b"...........LLL....LLL...........", // 22
    *b"...........LL......LL...........", // 23
    *b"...........LL......LL...........", // 24
    *b"...........LL......LL...........", // 25
    *b"..........LLL......LLL..........", // 26
    *b"................................", // 27
    *b"................................", // 28
    *b"................................", // 29
    *b"................................", // 30
    *b"................................", // 31
];

/// Cell 2 — weed-walker. `T` thorn/outline, `W` body, `o` eye white,
/// `O` eye pupil.
const WEED_ART: [[u8; CELL as usize]; CELL as usize] = [
    *b"................................", //  0
    *b"................................", //  1
    *b"................................", //  2
    *b"................................", //  3
    *b".............TT.................", //  4
    *b"..........TT.TT.TT..............", //  5
    *b"...........TTTTTTTT.............", //  6
    *b"..........TWWWWWWWWWT...........", //  7
    *b".........TWWooWWWWooWT..........", //  8
    *b".........TWWOOWWWWOOWT..........", //  9
    *b".........TWWWWWWWWWWWT..........", // 10
    *b".........TWWWTTTTTTWWT..........", // 11
    *b".........TWWWWWWWWWWWT..........", // 12
    *b"..........TWWWWWWWWWT...........", // 13
    *b"...........TWWWWWWWT............", // 14
    *b"............TTTTTTT.............", // 15
    *b"............TT...TT.............", // 16
    *b"............TT...TT.............", // 17
    *b"............TT...TT.............", // 18
    *b"...........TTT...TTT............", // 19
    *b"................................", // 20
    *b"................................", // 21
    *b"................................", // 22
    *b"................................", // 23
    *b"................................", // 24
    *b"................................", // 25
    *b"................................", // 26
    *b"................................", // 27
    *b"................................", // 28
    *b"................................", // 29
    *b"................................", // 30
    *b"................................", // 31
];

/// Cell 1 — ground tile. `+` grass, `#` dirt.
const GROUND_ART: [[u8; CELL as usize]; CELL as usize] = [
    *b"++++++++++++++++++++++++++++++++",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
    *b"################################",
];

/// Combine three 32×32 ASCII cells into a 96×32 ASCII sheet, row-major.
const fn combine3(
    a: &[[u8; 32]; 32],
    b: &[[u8; 32]; 32],
    c: &[[u8; 32]; 32],
) -> [u8; 32 * 96] {
    let mut out = [0u8; 32 * 96];
    let mut r = 0;
    while r < 32 {
        let mut k = 0;
        while k < 32 {
            out[r * 96 + k] = a[r][k];
            out[r * 96 + 32 + k] = b[r][k];
            out[r * 96 + 64 + k] = c[r][k];
            k += 1;
        }
        r += 1;
    }
    out
}

/// Map one ASCII byte to a palette index. Unknown chars → 0
/// (transparent). Typos become visible sky holes rather than compile
/// errors — easier to catch during sprite authoring.
const fn ascii_to_palette(b: u8) -> usize {
    match b {
        b'.' => 0,
        b'#' => 2,
        b'+' => 3,
        b'L' => 4,
        b'G' => 5,
        b'=' => 6,
        b'o' => 7,
        b'O' => 8,
        b'W' => 9,
        b'T' => 10,
        _ => 0,
    }
}

/// Expand the ASCII sheet to XRGB8888 pixels at compile time.
const fn expand(art: &[u8; 32 * 96]) -> [u32; 32 * 96] {
    let mut out = [0u32; 32 * 96];
    let mut i = 0;
    while i < 32 * 96 {
        out[i] = PALETTE[ascii_to_palette(art[i])];
        i += 1;
    }
    out
}

const SHEET_ART: [u8; 32 * 96] = combine3(&SPROUTY_ART, &GROUND_ART, &WEED_ART);

/// Expanded sheet: 96×32 XRGB8888 pixels in `.rodata`.
pub static SHEET_PIXELS: [u32; 32 * 96] = expand(&SHEET_ART);

// Belt-and-braces: catch any future drift between CELL / SHEET_W /
// SHEET_H and the actual buffer size at compile time, before it can
// fool the `.expect()` in `sheet()` below into running.
const _: () = {
    assert!(SHEET_PIXELS.len() == (SHEET_W * SHEET_H) as usize);
};

/// Borrow the shared sprite sheet as a Bitmap.
pub fn sheet() -> Bitmap<'static> {
    // Unreachable: dimensions checked by the `const _` assertion above.
    Bitmap::new(SHEET_W, SHEET_H, &SHEET_PIXELS).expect("sheet dims match buffer")
}

/// Sub-rect for Sprouty idle (sheet cell 0).
pub const SPROUTY_IDLE: (u32, u32, u32, u32) = (0, 0, CELL, CELL);

/// Sub-rect for the ground tile (sheet cell 1).
pub const GROUND: (u32, u32, u32, u32) = (CELL, 0, CELL, CELL);

/// Sub-rect for the weed-walker (sheet cell 2).
pub const WEED: (u32, u32, u32, u32) = (CELL * 2, 0, CELL, CELL);
