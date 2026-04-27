// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Keystroke → byte encoder for the GUI terminal backend.
//!
//! Translates `cambios-libinput-proto::InputEvent`s (as delivered by the
//! compositor via `libgui::Client::poll_event`) into the byte stream
//! that `libterm`'s parser already knows how to decode. This is the
//! **ENCODE** direction — libterm's parser is the DECODE direction.
//! Together they complete the loop:
//!
//! ```text
//!   real keyboard  →  virtio-input  →  compositor  →  InputEvent
//!                                                       │ (this file)
//!                                                       ↓
//!                                                 bytes (ASCII + ANSI
//!                                                        escape seqs)
//!                                                       │
//!                                                       ↓
//!                                                 libterm::Parser
//!                                                       │
//!                                                       ↓
//!                                                 libterm::Key
//! ```
//!
//! Net new code is this file. Every byte this file emits is already
//! covered by a test in `user/libterm/src/parser.rs::tests`.
//!
//! ## Priority order
//!
//! 1. Ignore `KeyUp` and non-keyboard events.
//! 2. Ctrl chord: ctrl + letter → 0x01..0x1A; a handful of named
//!    control byte combinations (ctrl-space/@, ctrl-[, ctrl-\, ctrl-]).
//! 3. Named keys by HID usage code (arrows, Home/End/PgUp/PgDn, F1–F12,
//!    Enter, Tab, Backspace, Escape, Insert, Delete, Shift-Tab).
//! 4. Alt chord: alt + printable ASCII → `ESC <byte>` (meta-prefix).
//! 5. Fallback: `unicode` field if it's printable ASCII.
//! 6. Otherwise: no bytes.
//!
//! ## Pure function
//!
//! `encode_key_event` is a pure total function of `InputEvent`. No I/O,
//! no allocation, bounded output (<= 16 bytes). Suitable for formal
//! verification. Host-testable.

use cambios_libinput_proto::{modifier, DeviceClass, EventType, InputEvent};

/// Output of a single encode. Fixed-capacity byte buffer.
///
/// Longest real sequence we emit today is `ESC [ 24 ~` (5 bytes, F12)
/// or `ESC ESC [ A` (4 bytes, Alt-Up — not currently emitted but
/// leaves headroom). Cap at 16 for safety plus future growth (e.g.,
/// modifier-encoded `CSI 1 ; 5 A` for Shift-Up).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedBytes {
    buf: [u8; 16],
    len: u8,
}

impl EncodedBytes {
    pub const EMPTY: Self = Self {
        buf: [0; 16],
        len: 0,
    };

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= 16);
        let mut out = Self::EMPTY;
        let n = bytes.len().min(16);
        out.buf[..n].copy_from_slice(&bytes[..n]);
        out.len = n as u8;
        out
    }

    fn one(b: u8) -> Self {
        Self::from_bytes(&[b])
    }
}

/// Encode a single compositor-delivered [`InputEvent`] into the byte
/// stream expected by `libterm::Parser`. Returns [`EncodedBytes::EMPTY`]
/// when the event produces no bytes (key-up, non-keyboard, unmapped key).
pub fn encode_key_event(event: &InputEvent) -> EncodedBytes {
    // ------------------------------------------------------------------
    // Phase 1: ignore everything that is not a typing-ish keyboard down.
    // ------------------------------------------------------------------
    if event.device_class != DeviceClass::Keyboard {
        return EncodedBytes::EMPTY;
    }
    match event.event_type {
        EventType::KeyDown | EventType::KeyRepeat => {}
        // KeyUp is never typed into a shell; ignore outright.
        _ => return EncodedBytes::EMPTY,
    }

    let kb = event.keyboard();
    let keycode = kb.keycode as u8; // HID usage codes are 1 byte for all keys we care about.
    let mods = kb.modifiers;
    let ctrl = (mods & (modifier::LEFT_CTRL | modifier::RIGHT_CTRL)) != 0;
    let alt = (mods & (modifier::LEFT_ALT | modifier::RIGHT_ALT)) != 0;
    let shift = (mods & (modifier::LEFT_SHIFT | modifier::RIGHT_SHIFT)) != 0;

    // ------------------------------------------------------------------
    // Phase 2: Ctrl chord. Takes precedence over named-key lookup for
    // the letter range because ctrl+m and ctrl+i would otherwise be
    // indistinguishable from Enter/Tab and we want ctrl semantics.
    // ------------------------------------------------------------------
    if ctrl {
        // HID usage 0x04..=0x1D is a..z. Ctrl-A = 0x01, ... Ctrl-Z = 0x1A.
        if (0x04..=0x1D).contains(&keycode) {
            return EncodedBytes::one(keycode - 0x04 + 0x01);
        }
        // A handful of standard ctrl-punctuation bytes.
        match keycode {
            0x2C => return EncodedBytes::one(0x00), // Ctrl-Space / Ctrl-@ → NUL
            0x2F => return EncodedBytes::one(0x1B), // Ctrl-[ → ESC
            0x31 => return EncodedBytes::one(0x1C), // Ctrl-\ → FS
            0x30 => return EncodedBytes::one(0x1D), // Ctrl-] → GS
            _ => {}
        }
        // Ctrl + other key: fall through to named-key / unicode paths
        // so ctrl+Enter still submits, ctrl+arrow still moves, etc.
    }

    // ------------------------------------------------------------------
    // Phase 3: Named keys by HID usage code.
    // ------------------------------------------------------------------
    match keycode {
        0x28 => return EncodedBytes::one(b'\r'), // Enter
        0x29 => return EncodedBytes::one(0x1B),  // Escape
        0x2A => return EncodedBytes::one(0x7F),  // Backspace (DEL; libterm maps 0x08 and 0x7F both to Key::Backspace)
        0x2B => {
            // Tab / Shift-Tab
            return if shift {
                EncodedBytes::from_bytes(b"\x1b[Z")
            } else {
                EncodedBytes::one(b'\t')
            };
        }

        // F1..F4 — SS3 form (matches xterm-compatible terminals).
        0x3A => return EncodedBytes::from_bytes(b"\x1bOP"),
        0x3B => return EncodedBytes::from_bytes(b"\x1bOQ"),
        0x3C => return EncodedBytes::from_bytes(b"\x1bOR"),
        0x3D => return EncodedBytes::from_bytes(b"\x1bOS"),

        // F5..F12 — CSI <n> ~ form (also xterm-compatible; libterm
        // decodes the same number values).
        0x3E => return EncodedBytes::from_bytes(b"\x1b[15~"), // F5
        0x3F => return EncodedBytes::from_bytes(b"\x1b[17~"), // F6
        0x40 => return EncodedBytes::from_bytes(b"\x1b[18~"), // F7
        0x41 => return EncodedBytes::from_bytes(b"\x1b[19~"), // F8
        0x42 => return EncodedBytes::from_bytes(b"\x1b[20~"), // F9
        0x43 => return EncodedBytes::from_bytes(b"\x1b[21~"), // F10
        0x44 => return EncodedBytes::from_bytes(b"\x1b[23~"), // F11
        0x45 => return EncodedBytes::from_bytes(b"\x1b[24~"), // F12

        // Navigation cluster.
        0x49 => return EncodedBytes::from_bytes(b"\x1b[2~"), // Insert
        0x4A => return EncodedBytes::from_bytes(b"\x1b[H"),  // Home
        0x4B => return EncodedBytes::from_bytes(b"\x1b[5~"), // PageUp
        0x4C => return EncodedBytes::from_bytes(b"\x1b[3~"), // Delete
        0x4D => return EncodedBytes::from_bytes(b"\x1b[F"),  // End
        0x4E => return EncodedBytes::from_bytes(b"\x1b[6~"), // PageDown

        // Arrows.
        0x4F => return EncodedBytes::from_bytes(b"\x1b[C"), // Right
        0x50 => return EncodedBytes::from_bytes(b"\x1b[D"), // Left
        0x51 => return EncodedBytes::from_bytes(b"\x1b[B"), // Down
        0x52 => return EncodedBytes::from_bytes(b"\x1b[A"), // Up

        _ => {}
    }

    // ------------------------------------------------------------------
    // Phase 4: Alt chord. If alt is held AND we have a printable unicode
    // codepoint, emit `ESC <byte>` (xterm's 8-bit meta-prefix). libterm
    // decodes this to `Key::Alt(byte)`.
    // ------------------------------------------------------------------
    if alt {
        if let Some(b) = printable_ascii(kb.unicode) {
            let mut buf = [0u8; 2];
            buf[0] = 0x1B;
            buf[1] = b;
            return EncodedBytes::from_bytes(&buf);
        }
        // Alt held but no printable — nothing to emit.
        return EncodedBytes::EMPTY;
    }

    // ------------------------------------------------------------------
    // Phase 5: Plain printable unicode (driver-translated, layout-aware).
    // ------------------------------------------------------------------
    if let Some(b) = printable_ascii(kb.unicode) {
        return EncodedBytes::one(b);
    }

    // ------------------------------------------------------------------
    // Phase 6: No bytes for this event.
    // ------------------------------------------------------------------
    EncodedBytes::EMPTY
}

/// Classify a unicode codepoint as a single printable ASCII byte.
/// Returns `None` for control, non-ASCII, or out-of-range codepoints.
/// Multi-byte UTF-8 is deliberately not emitted in v1 — libterm's
/// `Key::Char(u8)` passes raw bytes through, but driver-level locale
/// translation to UTF-8 is a post-v1 concern.
fn printable_ascii(codepoint: u32) -> Option<u8> {
    if codepoint >= 0x20 && codepoint <= 0x7E {
        Some(codepoint as u8)
    } else {
        None
    }
}

// ============================================================================
// Tests — round-trip through libterm's parser to prove the byte stream
// decodes back to the exact Key the user pressed.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cambios_libinput_proto::{KeyboardPayload, EVENT_SIZE, SIGNATURE_BLOCK_SIZE};
    use cambios_libterm::parser::Parser;
    use cambios_libterm::Key;

    fn keydown(keycode: u32, modifiers: u16, unicode: u32) -> InputEvent {
        InputEvent::key(
            EventType::KeyDown,
            /* device_id */ 1,
            /* seq */ 0,
            /* ts */ 0,
            KeyboardPayload { keycode, modifiers, unicode },
        )
    }

    fn keyup(keycode: u32) -> InputEvent {
        InputEvent::key(
            EventType::KeyUp,
            1,
            0,
            0,
            KeyboardPayload { keycode, modifiers: 0, unicode: 0 },
        )
    }

    /// Feed bytes into libterm's parser and collect every Key it emits.
    /// Flushes at the end to capture a lone-ESC that wasn't followed by
    /// a continuation byte.
    fn decode(bytes: &[u8]) -> alloc::vec::Vec<Key> {
        let mut p = Parser::new();
        let mut out = alloc::vec::Vec::new();
        for &b in bytes {
            if let Some(k) = p.step(b) {
                out.push(k);
            }
        }
        if let Some(k) = p.flush_on_timeout() {
            out.push(k);
        }
        out
    }

    // ---- Printable ASCII --------------------------------------------------

    #[test]
    fn letter_without_modifiers_emits_unicode() {
        // HID 0x04 = 'a'. Driver sets unicode = 'a'.
        let ev = keydown(0x04, 0, b'a' as u32);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), b"a");
        assert_eq!(decode(enc.as_slice()), vec![Key::Char(b'a')]);
    }

    #[test]
    fn shift_letter_via_driver_translated_unicode() {
        // Shift+A: driver sees shift and writes unicode='A'.
        let ev = keydown(0x04, modifier::LEFT_SHIFT, b'A' as u32);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), b"A");
        assert_eq!(decode(enc.as_slice()), vec![Key::Char(b'A')]);
    }

    // ---- KeyUp dropped ----------------------------------------------------

    #[test]
    fn keyup_emits_nothing() {
        let ev = keyup(0x04);
        assert!(encode_key_event(&ev).is_empty());
    }

    // ---- Enter / Tab / Backspace / Escape --------------------------------

    #[test]
    fn enter_key() {
        let ev = keydown(0x28, 0, 0);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), b"\r");
        assert_eq!(decode(enc.as_slice()), vec![Key::Enter]);
    }

    #[test]
    fn tab_key() {
        let ev = keydown(0x2B, 0, 0);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), b"\t");
        assert_eq!(decode(enc.as_slice()), vec![Key::Tab]);
    }

    #[test]
    fn shift_tab_key() {
        let ev = keydown(0x2B, modifier::LEFT_SHIFT, 0);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), b"\x1b[Z");
        assert_eq!(decode(enc.as_slice()), vec![Key::ShiftTab]);
    }

    #[test]
    fn backspace_key() {
        let ev = keydown(0x2A, 0, 0);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), &[0x7F]);
        assert_eq!(decode(enc.as_slice()), vec![Key::Backspace]);
    }

    #[test]
    fn escape_key_without_followup_emits_bare_esc() {
        // Bare Escape press — libterm needs a flush_on_timeout to emit it.
        let ev = keydown(0x29, 0, 0);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), &[0x1B]);
        assert_eq!(decode(enc.as_slice()), vec![Key::Escape]);
    }

    // ---- Arrows -----------------------------------------------------------

    #[test]
    fn arrow_keys() {
        let cases = [
            (0x52u32, Key::Up),
            (0x51, Key::Down),
            (0x50, Key::Left),
            (0x4F, Key::Right),
        ];
        for (kc, expected) in cases {
            let ev = keydown(kc, 0, 0);
            let enc = encode_key_event(&ev);
            assert!(!enc.is_empty(), "keycode {kc:#x} encoded nothing");
            assert_eq!(decode(enc.as_slice()), vec![expected]);
        }
    }

    // ---- Navigation cluster ----------------------------------------------

    #[test]
    fn home_end_pgup_pgdn_insert_delete() {
        let cases: &[(u32, Key)] = &[
            (0x4A, Key::Home),
            (0x4D, Key::End),
            (0x4B, Key::PgUp),
            (0x4E, Key::PgDn),
            (0x49, Key::Insert),
            (0x4C, Key::Delete),
        ];
        for &(kc, expected) in cases {
            let ev = keydown(kc, 0, 0);
            let enc = encode_key_event(&ev);
            assert_eq!(decode(enc.as_slice()), vec![expected]);
        }
    }

    // ---- Function keys ----------------------------------------------------

    #[test]
    fn function_keys_f1_through_f12() {
        for i in 0..12u32 {
            let keycode = 0x3A + i;
            let ev = keydown(keycode, 0, 0);
            let enc = encode_key_event(&ev);
            assert!(!enc.is_empty(), "F{} encoded nothing", i + 1);
            assert_eq!(decode(enc.as_slice()), vec![Key::F((i + 1) as u8)]);
        }
    }

    // ---- Ctrl chords ------------------------------------------------------

    #[test]
    fn ctrl_letters_cover_a_to_z() {
        for letter in 0u8..26 {
            let keycode = 0x04 + letter as u32;
            let ev = keydown(keycode, modifier::LEFT_CTRL, 0);
            let enc = encode_key_event(&ev);
            let byte = letter + 0x01;
            assert_eq!(enc.as_slice(), &[byte]);
            // Ctrl-M (byte 0x0D) and Ctrl-J (byte 0x0A) decode to Enter;
            // Ctrl-I (byte 0x09) decodes to Tab; Ctrl-H (byte 0x08) decodes
            // to Backspace. For all others, we expect Key::Ctrl(byte).
            let expected = match byte {
                0x08 | 0x7F => Key::Backspace,
                0x09 => Key::Tab,
                0x0A | 0x0D => Key::Enter,
                _ => Key::Ctrl(byte),
            };
            assert_eq!(decode(enc.as_slice()), vec![expected]);
        }
    }

    #[test]
    fn ctrl_c_is_control_3() {
        // HID 'c' = 0x06. Ctrl-C = 0x03. libterm's shell uses this for
        // signal-like abort.
        let ev = keydown(0x06, modifier::LEFT_CTRL, 0);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), &[0x03]);
        assert_eq!(decode(enc.as_slice()), vec![Key::Ctrl(3)]);
    }

    #[test]
    fn ctrl_right_ctrl_equivalent() {
        // Either LEFT_CTRL or RIGHT_CTRL should trigger the ctrl path.
        let ev = keydown(0x06, modifier::RIGHT_CTRL, 0);
        assert_eq!(encode_key_event(&ev).as_slice(), &[0x03]);
    }

    #[test]
    fn ctrl_space_is_nul() {
        let ev = keydown(0x2C, modifier::LEFT_CTRL, 0);
        assert_eq!(encode_key_event(&ev).as_slice(), &[0x00]);
    }

    #[test]
    fn ctrl_bracket_is_esc() {
        let ev = keydown(0x2F, modifier::LEFT_CTRL, 0);
        assert_eq!(encode_key_event(&ev).as_slice(), &[0x1B]);
    }

    // ---- Alt chords -------------------------------------------------------

    #[test]
    fn alt_b_emits_meta_prefix() {
        // HID 'b' = 0x05. Driver with alt held would set unicode='b'.
        let ev = keydown(0x05, modifier::LEFT_ALT, b'b' as u32);
        let enc = encode_key_event(&ev);
        assert_eq!(enc.as_slice(), b"\x1bb");
        assert_eq!(decode(enc.as_slice()), vec![Key::Alt(b'b')]);
    }

    #[test]
    fn alt_without_printable_emits_nothing() {
        // Alt + unknown key = no output.
        let ev = keydown(0x99, modifier::LEFT_ALT, 0);
        assert!(encode_key_event(&ev).is_empty());
    }

    // ---- Non-keyboard ignored --------------------------------------------

    #[test]
    fn pointer_event_emits_nothing() {
        let mut ev = keydown(0x04, 0, b'a' as u32);
        ev.device_class = DeviceClass::Pointer;
        assert!(encode_key_event(&ev).is_empty());
    }

    // ---- Unmapped keys ----------------------------------------------------

    #[test]
    fn totally_unknown_keycode_emits_nothing() {
        // HID usage 0xDE is reserved / device-specific.
        let ev = keydown(0xDE, 0, 0);
        assert!(encode_key_event(&ev).is_empty());
    }

    #[test]
    fn unicode_of_zero_with_no_named_key_emits_nothing() {
        // Driver couldn't translate, not a named key — drop.
        let ev = keydown(0x99, 0, 0);
        assert!(encode_key_event(&ev).is_empty());
    }

    #[test]
    fn non_ascii_unicode_emits_nothing_v1() {
        // Latin-1 'é' = U+00E9. v1 policy: ASCII only.
        let ev = keydown(0x08, 0, 0x00E9);
        assert!(encode_key_event(&ev).is_empty());
    }

    // ---- KeyRepeat treated as KeyDown ------------------------------------

    #[test]
    fn key_repeat_emits_same_as_keydown() {
        let mut ev = keydown(0x04, 0, b'a' as u32);
        ev.event_type = EventType::KeyRepeat;
        assert_eq!(encode_key_event(&ev).as_slice(), b"a");
    }

    // ---- Bounds / signature preserved in InputEvent ----------------------

    #[test]
    fn signature_block_presence_does_not_affect_encoding() {
        // Whether or not the event is tier-2-signed, encoding ignores
        // signature_block. The Hub verifies upstream.
        let mut ev = keydown(0x04, 0, b'a' as u32);
        for i in 0..SIGNATURE_BLOCK_SIZE {
            ev.signature_block[i] = 0xFF;
        }
        assert_eq!(encode_key_event(&ev).as_slice(), b"a");
    }

    // ---- Envelope size sanity check --------------------------------------

    #[test]
    fn event_envelope_fits_the_wire_spec() {
        // Sanity check that the constant used for buffer sizing stays
        // within the wire-format envelope. If this ever fails we've
        // drifted from ADR-012.
        assert_eq!(EVENT_SIZE, 96);
    }
}
