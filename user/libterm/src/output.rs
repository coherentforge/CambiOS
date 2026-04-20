// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! ANSI output helpers: cursor positioning, screen/line clearing, colors
//! and styles. These write directly through a [`Backend`] — they don't
//! cache any state, so emitting a redundant sequence is cheap but always
//! safe.

use crate::backend::Backend;

/// Foreground / background color.
///
/// Values are standard ANSI (3-bit) color codes. Callers that want 256-color
/// or truecolor can emit raw sequences via [`Backend::write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Black = 0,
    Red = 1,
    Green = 2,
    Yellow = 3,
    Blue = 4,
    Magenta = 5,
    Cyan = 6,
    White = 7,
    Default = 9,
}

fn write_uint(backend: &mut impl Backend, mut n: u32) {
    // Max value: u32::MAX = 4_294_967_295 → 10 digits.
    let mut buf = [0u8; 10];
    if n == 0 {
        backend.write(b"0");
        return;
    }
    let mut len = 0;
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    // Reverse in place.
    let (mut i, mut j) = (0, len - 1);
    while i < j {
        buf.swap(i, j);
        i += 1;
        j -= 1;
    }
    backend.write(&buf[..len]);
}

/// Move cursor to a 1-indexed `(row, col)`. Passes values as-is to the
/// terminal; 0 is treated as 1 by most terminals. Callers should pass
/// 1-based coordinates.
pub fn cursor_to(backend: &mut impl Backend, row: u16, col: u16) {
    backend.write(b"\x1b[");
    write_uint(backend, row as u32);
    backend.write(b";");
    write_uint(backend, col as u32);
    backend.write(b"H");
}

/// Move cursor left by `n` columns. A `n == 0` is a no-op (no sequence
/// is emitted).
pub fn cursor_left(backend: &mut impl Backend, n: u16) {
    if n == 0 {
        return;
    }
    backend.write(b"\x1b[");
    write_uint(backend, n as u32);
    backend.write(b"D");
}

/// Move cursor right by `n` columns. A `n == 0` is a no-op.
pub fn cursor_right(backend: &mut impl Backend, n: u16) {
    if n == 0 {
        return;
    }
    backend.write(b"\x1b[");
    write_uint(backend, n as u32);
    backend.write(b"C");
}

/// Clear the entire screen and home the cursor.
pub fn clear_screen(backend: &mut impl Backend) {
    backend.write(b"\x1b[2J\x1b[H");
}

/// Clear from the cursor to end of line.
pub fn clear_to_eol(backend: &mut impl Backend) {
    backend.write(b"\x1b[K");
}

/// Clear the entire line the cursor is on, leaving the cursor position
/// intact.
pub fn clear_line(backend: &mut impl Backend) {
    backend.write(b"\x1b[2K");
}

/// Move the cursor to column 1 of the current line.
pub fn cursor_to_col1(backend: &mut impl Backend) {
    backend.write(b"\r");
}

/// Hide the cursor. Pair with [`show_cursor`] to avoid leaving the cursor
/// hidden across program exit.
pub fn hide_cursor(backend: &mut impl Backend) {
    backend.write(b"\x1b[?25l");
}

pub fn show_cursor(backend: &mut impl Backend) {
    backend.write(b"\x1b[?25h");
}

/// Emit SGR reset (turns off bold, underline, reverse, any color).
pub fn reset_style(backend: &mut impl Backend) {
    backend.write(b"\x1b[0m");
}

pub fn set_bold(backend: &mut impl Backend) {
    backend.write(b"\x1b[1m");
}

pub fn set_reverse(backend: &mut impl Backend) {
    backend.write(b"\x1b[7m");
}

pub fn set_underline(backend: &mut impl Backend) {
    backend.write(b"\x1b[4m");
}

pub fn set_fg(backend: &mut impl Backend, color: Color) {
    backend.write(b"\x1b[3");
    write_uint(backend, color as u32);
    backend.write(b"m");
}

pub fn set_bg(backend: &mut impl Backend, color: Color) {
    backend.write(b"\x1b[4");
    write_uint(backend, color as u32);
    backend.write(b"m");
}
