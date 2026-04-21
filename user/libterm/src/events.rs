// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Terminal event types.
//!
//! Closed enums with explicit variants — no trait objects, no open-ended
//! extension points. Consumers match exhaustively. See CLAUDE.md
//! "Formal Verification" rule: invariants encoded in types.

/// A single keystroke emitted by the parser.
///
/// `Char(u8)` carries an un-interpreted byte for printable ASCII. Multi-byte
/// UTF-8 sequences arrive as successive `Char` bytes; callers that care about
/// grapheme clusters must buffer themselves. Named variants are emitted for
/// recognized control sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable byte or control byte below 0x20 that is not one of the
    /// named variants below. Callers typically treat this as text input.
    Char(u8),
    /// Carriage return or line feed.
    Enter,
    /// ASCII 0x08 or 0x7F.
    Backspace,
    /// ASCII 0x09.
    Tab,
    /// A lone ESC (0x1B) that did not begin a recognized sequence, emitted
    /// after the parser's deadline expires.
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PgUp,
    PgDn,
    Delete,
    Insert,
    /// Function key F1..F12. The byte is the function-key number.
    F(u8),
    /// Ctrl-A..Ctrl-Z as 1..26. Ctrl-@ (0) and Ctrl-[ (27 = ESC) are not
    /// reachable via this variant — ESC routes to the parser state machine,
    /// and Ctrl-@ is rare. Callers treat this as an activation chord.
    Ctrl(u8),
    /// Alt-<byte>: ESC followed by a printable byte within the same burst.
    /// The byte is the payload character.
    Alt(u8),
    /// Shift-Tab (CSI Z). Emitted separately from Tab so callers can bind
    /// backward-completion or reverse-cycle.
    ShiftTab,
}

/// Signals delivered to the event loop, distinct from keystrokes.
///
/// Today only `Interrupt` is synthesized (from Ctrl-C). `Suspend` and
/// `Quit` are reserved for future job-control work; emitting them is
/// a no-op today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    Interrupt,
    Suspend,
    Quit,
}

/// One poll result from [`crate::Terminal::next_event`].
///
/// `Timeout` means the caller-supplied deadline elapsed with no complete
/// event. `Resize` is currently never emitted (serial terminal has a fixed
/// 80x24 geometry); the variant is reserved for the future framebuffer
/// backend and for eventual terminal-window-size reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Key(Key),
    Resize(u16, u16),
    Signal(Sig),
    Timeout,
}
