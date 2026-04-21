// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! ANSI input parser — byte-in, [`Key`]-out state machine.
//!
//! The state machine is explicitly enumerated and transitions are a free
//! function, [`step`]. [`Parser`] is a thin wrapper that owns the state.
//! This split serves two goals:
//!
//! - Formal-verification readiness: [`step`] is a pure total function of
//!   `(ParserState, u8) -> (ParserState, Option<Key>)`. It never reads or
//!   writes anything outside its arguments. Its behavior is a finite table
//!   of transitions, suitable as a verification target.
//! - Ergonomics: consumers use [`Parser`] to avoid threading state manually.
//!
//! # Covered sequences
//!
//! CSI (`ESC [ … final`):
//!   A/B/C/D = Up/Down/Right/Left,
//!   H/F     = Home/End (also `1~`/`4~`),
//!   `2~`    = Insert,
//!   `3~`    = Delete,
//!   `5~`    = PgUp,
//!   `6~`    = PgDn,
//!   `7~`    = Home (old xterm),
//!   `8~`    = End (old xterm),
//!   `11~`–`15~`, `17~`–`21~`, `23~`, `24~` = F1–F12,
//!   Z       = ShiftTab.
//!
//! SS3 (`ESC O …`): P/Q/R/S = F1/F2/F3/F4, H/F = Home/End.
//!
//! Lone `ESC` (no continuation) is handled by the caller via
//! [`Parser::flush_on_timeout`] — the parser itself never emits
//! `Key::Escape` from [`Parser::step`] (because another byte may still be
//! in flight).

use crate::events::Key;

/// Maximum parameters buffered in a CSI sequence.
///
/// SCAFFOLDING: all recognized terminal sequences use at most 2 parameters
/// today. Keeping 4 gives headroom for future modifier-encoded sequences
/// (e.g., `CSI 1 ; 5 A` for Shift-Up). Bounded by design per the
/// Formal-Verification rule.
/// Why: allows `ESC [ a ; b ; c ; d FINAL` forms without heap.
/// Replace when: a real sequence needs more than 4 params — not foreseen.
const CSI_MAX_PARAMS: usize = 4;

/// Explicit parser state.
///
/// `Csi` carries an inline fixed-size param buffer. `nparams` counts the
/// parameters that have been opened (either by a digit or a `;` separator);
/// the currently-accumulating parameter lives at index `nparams - 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserState {
    Ground,
    Escape,
    Csi {
        params: [u16; CSI_MAX_PARAMS],
        nparams: usize,
    },
    Ss3,
}

impl ParserState {
    /// Returns true if the parser is mid-sequence (not at [`Ground`]).
    ///
    /// Used by [`crate::Terminal`] to decide whether to wait for a
    /// continuation byte versus emit a lone [`Key::Escape`] on timeout.
    #[inline]
    pub fn is_pending(&self) -> bool {
        !matches!(self, ParserState::Ground)
    }
}

/// Pure transition function: `(state, byte) -> (new_state, maybe_event)`.
///
/// No I/O, no allocation, bounded work per call. All paths terminate.
///
/// Unrecognized bytes within a sequence reset the parser to [`Ground`]
/// without emitting an event — this matches how xterm handles malformed
/// input. Callers that want stricter diagnostics can wrap this function
/// and log resets.
pub fn step(state: ParserState, byte: u8) -> (ParserState, Option<Key>) {
    match state {
        ParserState::Ground => step_ground(byte),
        ParserState::Escape => step_escape(byte),
        ParserState::Csi { params, nparams } => step_csi(params, nparams, byte),
        ParserState::Ss3 => step_ss3(byte),
    }
}

fn step_ground(byte: u8) -> (ParserState, Option<Key>) {
    match byte {
        0x1B => (ParserState::Escape, None),
        b'\r' | b'\n' => (ParserState::Ground, Some(Key::Enter)),
        0x08 | 0x7F => (ParserState::Ground, Some(Key::Backspace)),
        b'\t' => (ParserState::Ground, Some(Key::Tab)),
        // Ctrl-A..Ctrl-Z live at 0x01..0x1A. Skip 0x09 (Tab), 0x0A/0x0D (Enter),
        // 0x08 (Backspace), 0x1B (Escape) — already handled above.
        1..=7 | 11 | 12 | 14..=26 => (ParserState::Ground, Some(Key::Ctrl(byte))),
        // Printable bytes (0x20..0x7E) and high bytes (0x80+, UTF-8 continuation)
        // pass through as Char.
        _ => (ParserState::Ground, Some(Key::Char(byte))),
    }
}

fn step_escape(byte: u8) -> (ParserState, Option<Key>) {
    match byte {
        b'[' => (
            ParserState::Csi {
                params: [0; CSI_MAX_PARAMS],
                nparams: 0,
            },
            None,
        ),
        b'O' => (ParserState::Ss3, None),
        // ESC ESC: treat as lone-Escape followed by a new Escape. The first
        // ESC is emitted here; the second starts a fresh sequence.
        0x1B => (ParserState::Escape, Some(Key::Escape)),
        // Any other printable byte after ESC is Alt-<byte>.
        0x20..=0x7E => (ParserState::Ground, Some(Key::Alt(byte))),
        // Non-printable that isn't a recognized sequence-starter: drop to
        // Ground and emit a lone Escape (conservative — matches nano behavior
        // when nothing structured follows).
        _ => (ParserState::Ground, Some(Key::Escape)),
    }
}

fn step_csi(
    mut params: [u16; CSI_MAX_PARAMS],
    mut nparams: usize,
    byte: u8,
) -> (ParserState, Option<Key>) {
    // Invariant while in Csi:
    //   `nparams` counts parameters that have been opened (started by a digit
    //   or a ';'). The currently-accumulating parameter lives at index
    //   `nparams - 1` when `nparams > 0`. A digit when `nparams == 0` opens
    //   slot 0 implicitly.
    match byte {
        b'0'..=b'9' => {
            if nparams == 0 {
                nparams = 1;
            }
            let slot = nparams - 1;
            if slot < CSI_MAX_PARAMS {
                let d = (byte - b'0') as u16;
                // Saturating to avoid overflow on adversarial input. Real
                // parameters are < 10000.
                params[slot] = params[slot].saturating_mul(10).saturating_add(d);
            }
            (ParserState::Csi { params, nparams }, None)
        }
        b';' => {
            // Open a new parameter slot. If an initial `;` arrives before any
            // digit, treat it as "param 0 was empty" by counting it.
            if nparams == 0 {
                nparams = 1;
            }
            if nparams < CSI_MAX_PARAMS {
                nparams += 1;
                // params[nparams - 1] is already 0 from the initial state.
            }
            // If we'd exceed capacity, stay at the last slot — extra params
            // are silently dropped.
            (ParserState::Csi { params, nparams }, None)
        }
        // Final bytes in the range `@`..`~` dispatch the sequence.
        0x40..=0x7E => (ParserState::Ground, dispatch_csi(&params, nparams, byte)),
        // Anything else in a CSI is malformed — reset quietly.
        _ => (ParserState::Ground, None),
    }
}

fn dispatch_csi(params: &[u16; CSI_MAX_PARAMS], nparams: usize, final_byte: u8) -> Option<Key> {
    let p0 = if nparams == 0 { 0 } else { params[0] };
    match final_byte {
        b'A' => Some(Key::Up),
        b'B' => Some(Key::Down),
        b'C' => Some(Key::Right),
        b'D' => Some(Key::Left),
        b'H' => Some(Key::Home),
        b'F' => Some(Key::End),
        b'Z' => Some(Key::ShiftTab),
        b'~' => match p0 {
            1 | 7 => Some(Key::Home),
            2 => Some(Key::Insert),
            3 => Some(Key::Delete),
            4 | 8 => Some(Key::End),
            5 => Some(Key::PgUp),
            6 => Some(Key::PgDn),
            11 => Some(Key::F(1)),
            12 => Some(Key::F(2)),
            13 => Some(Key::F(3)),
            14 => Some(Key::F(4)),
            15 => Some(Key::F(5)),
            17 => Some(Key::F(6)),
            18 => Some(Key::F(7)),
            19 => Some(Key::F(8)),
            20 => Some(Key::F(9)),
            21 => Some(Key::F(10)),
            23 => Some(Key::F(11)),
            24 => Some(Key::F(12)),
            _ => None,
        },
        _ => None,
    }
}

fn step_ss3(byte: u8) -> (ParserState, Option<Key>) {
    let key = match byte {
        b'P' => Some(Key::F(1)),
        b'Q' => Some(Key::F(2)),
        b'R' => Some(Key::F(3)),
        b'S' => Some(Key::F(4)),
        b'H' => Some(Key::Home),
        b'F' => Some(Key::End),
        _ => None,
    };
    (ParserState::Ground, key)
}

/// Stateful wrapper around [`step`].
///
/// This is the type consumers interact with. Internally it stores the
/// current [`ParserState`] and delegates to the pure transition function.
#[derive(Debug, Clone, Copy)]
pub struct Parser {
    state: ParserState,
}

impl Parser {
    pub const fn new() -> Self {
        Self {
            state: ParserState::Ground,
        }
    }

    /// Feed one byte, returning the event emitted (if any).
    #[inline]
    pub fn step(&mut self, byte: u8) -> Option<Key> {
        let (next, key) = step(self.state, byte);
        self.state = next;
        key
    }

    /// Called when the caller's deadline expires while the parser is
    /// mid-sequence. Emits a lone [`Key::Escape`] if the parser was in
    /// [`ParserState::Escape`]; otherwise returns `None` and resets to
    /// [`ParserState::Ground`] (a half-parsed CSI/SS3 is discarded).
    pub fn flush_on_timeout(&mut self) -> Option<Key> {
        let emit = matches!(self.state, ParserState::Escape);
        self.state = ParserState::Ground;
        if emit { Some(Key::Escape) } else { None }
    }

    #[inline]
    pub fn is_pending(&self) -> bool {
        self.state.is_pending()
    }

    #[inline]
    pub fn state(&self) -> ParserState {
        self.state
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a sequence of bytes through a fresh parser and collect every
    /// emitted key.
    fn drive(bytes: &[u8]) -> alloc::vec::Vec<Key> {
        let mut p = Parser::new();
        let mut out = alloc::vec::Vec::new();
        for &b in bytes {
            if let Some(k) = p.step(b) {
                out.push(k);
            }
        }
        out
    }

    #[test]
    fn printable_ascii_passes_through() {
        assert_eq!(drive(b"abc"), vec![Key::Char(b'a'), Key::Char(b'b'), Key::Char(b'c')]);
    }

    #[test]
    fn enter_variants() {
        assert_eq!(drive(b"\r"), vec![Key::Enter]);
        assert_eq!(drive(b"\n"), vec![Key::Enter]);
    }

    #[test]
    fn backspace_variants() {
        assert_eq!(drive(b"\x08"), vec![Key::Backspace]);
        assert_eq!(drive(b"\x7F"), vec![Key::Backspace]);
    }

    #[test]
    fn tab_is_distinct_from_ctrl_i() {
        // 0x09 is Tab; must not be reported as Ctrl('I' - '@' = 9).
        assert_eq!(drive(b"\x09"), vec![Key::Tab]);
    }

    #[test]
    fn ctrl_letters() {
        // Ctrl-A = 1, Ctrl-C = 3, Ctrl-Z = 26. Ctrl-M (13) is Enter; Ctrl-I (9) is Tab.
        assert_eq!(drive(&[1, 3, 26]), vec![Key::Ctrl(1), Key::Ctrl(3), Key::Ctrl(26)]);
    }

    #[test]
    fn arrows() {
        assert_eq!(drive(b"\x1b[A"), vec![Key::Up]);
        assert_eq!(drive(b"\x1b[B"), vec![Key::Down]);
        assert_eq!(drive(b"\x1b[C"), vec![Key::Right]);
        assert_eq!(drive(b"\x1b[D"), vec![Key::Left]);
    }

    #[test]
    fn home_end_both_forms() {
        assert_eq!(drive(b"\x1b[H"), vec![Key::Home]);
        assert_eq!(drive(b"\x1b[F"), vec![Key::End]);
        assert_eq!(drive(b"\x1b[1~"), vec![Key::Home]);
        assert_eq!(drive(b"\x1b[4~"), vec![Key::End]);
        assert_eq!(drive(b"\x1b[7~"), vec![Key::Home]);
        assert_eq!(drive(b"\x1b[8~"), vec![Key::End]);
    }

    #[test]
    fn insert_delete_pgup_pgdn() {
        assert_eq!(drive(b"\x1b[2~"), vec![Key::Insert]);
        assert_eq!(drive(b"\x1b[3~"), vec![Key::Delete]);
        assert_eq!(drive(b"\x1b[5~"), vec![Key::PgUp]);
        assert_eq!(drive(b"\x1b[6~"), vec![Key::PgDn]);
    }

    #[test]
    fn shift_tab() {
        assert_eq!(drive(b"\x1b[Z"), vec![Key::ShiftTab]);
    }

    #[test]
    fn function_keys_ss3() {
        assert_eq!(drive(b"\x1bOP"), vec![Key::F(1)]);
        assert_eq!(drive(b"\x1bOQ"), vec![Key::F(2)]);
        assert_eq!(drive(b"\x1bOR"), vec![Key::F(3)]);
        assert_eq!(drive(b"\x1bOS"), vec![Key::F(4)]);
    }

    #[test]
    fn function_keys_csi_tilde() {
        assert_eq!(drive(b"\x1b[11~"), vec![Key::F(1)]);
        assert_eq!(drive(b"\x1b[15~"), vec![Key::F(5)]);
        assert_eq!(drive(b"\x1b[24~"), vec![Key::F(12)]);
    }

    #[test]
    fn ss3_home_end() {
        assert_eq!(drive(b"\x1bOH"), vec![Key::Home]);
        assert_eq!(drive(b"\x1bOF"), vec![Key::End]);
    }

    #[test]
    fn alt_chord() {
        assert_eq!(drive(b"\x1ba"), vec![Key::Alt(b'a')]);
        assert_eq!(drive(b"\x1bz"), vec![Key::Alt(b'z')]);
    }

    #[test]
    fn esc_esc_emits_lone_escape_then_opens_new_sequence() {
        // First ESC alone, followed by ESC[A, should emit Escape then Up.
        assert_eq!(drive(b"\x1b\x1b[A"), vec![Key::Escape, Key::Up]);
    }

    #[test]
    fn lone_esc_waits_for_timeout() {
        // A single ESC with no follow-up must NOT emit anything from step().
        let mut p = Parser::new();
        assert_eq!(p.step(0x1B), None);
        assert!(p.is_pending());
        assert_eq!(p.flush_on_timeout(), Some(Key::Escape));
        assert!(!p.is_pending());
    }

    #[test]
    fn partial_csi_discarded_on_timeout() {
        // ESC [ then a flush (no final byte) resets parser silently.
        let mut p = Parser::new();
        p.step(0x1B);
        p.step(b'[');
        assert!(p.is_pending());
        assert_eq!(p.flush_on_timeout(), None);
        assert!(!p.is_pending());
    }

    #[test]
    fn malformed_csi_resets_quietly() {
        // ESC [ <garbage> drops to ground with no emission.
        assert_eq!(drive(b"\x1b[\x01"), vec![]);
    }

    #[test]
    fn csi_multi_params_tolerated() {
        // Modifier-encoded Up: ESC [ 1 ; 5 A. We ignore modifier and still emit Up.
        assert_eq!(drive(b"\x1b[1;5A"), vec![Key::Up]);
    }

    #[test]
    fn csi_saturating_digits_do_not_panic() {
        // Adversarial long digit run: saturate instead of overflow.
        let mut input = alloc::vec::Vec::new();
        input.extend_from_slice(b"\x1b[");
        for _ in 0..50 { input.push(b'9'); }
        input.push(b'~');
        // Whatever param we end up with is an unknown mapping — must be empty,
        // not a panic or overflow.
        assert_eq!(drive(&input), vec![]);
    }

    #[test]
    fn pure_step_does_not_touch_outside_args() {
        // Calling the free step() with the same (state, byte) must always
        // yield the same (next, key). Purity sanity check.
        let (s1, k1) = step(ParserState::Ground, b'a');
        let (s2, k2) = step(ParserState::Ground, b'a');
        assert_eq!(s1, s2);
        assert_eq!(k1, k2);
    }
}
