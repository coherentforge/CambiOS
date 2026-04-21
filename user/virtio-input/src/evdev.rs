// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Linux evdev event codes + translation to USB HID usage codes.
//!
//! virtio-input's wire format is Linux's `struct input_event` verbatim
//! (spec §5.8): a three-field tuple `{type, code, value}` where
//! `code` lives in the Linux evdev namespace (`KEY_A = 30`, etc.).
//! ADR-012 § KeyboardPayload commits the OS to USB HID usage codes
//! in `InputEvent.keycode` regardless of transport. Drivers translate.
//!
//! This table covers the keys a Tree-era app realistically reaches for
//! (digits, letters, arrows, Space, Enter, Escape, Tab, Backspace,
//! modifiers, F1-F10, punctuation that appears on a QWERTY layout).
//! Codes outside the table pass through unchanged — clients get the
//! raw evdev code, which is still useful for logging and for
//! experimental keys before the translation table grows.
//!
//! Revisit when: a client needs a key that's visibly wrong (escape
//! not escaping, etc.) — add the row; the translation surface is
//! additive, not load-bearing.

// ============================================================================
// Event types (§5.8 / `input-event-codes.h`)
// ============================================================================

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;

// ============================================================================
// Relative axes (for EV_REL — mouse)
// ============================================================================

pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;

// ============================================================================
// Mouse buttons (EV_KEY with BTN_* codes, range 0x110..)
// ============================================================================

pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const BTN_SIDE: u16 = 0x113;
pub const BTN_EXTRA: u16 = 0x114;

// ============================================================================
// Keyboard class-detection probes (EV_KEY codes we use to decide
// "does this virtio-input device look like a keyboard")
// ============================================================================

pub const KEY_A: u16 = 30;
pub const KEY_SPACE: u16 = 57;

// ============================================================================
// Modifier key evdev codes (for tracking modifier state)
// ============================================================================

pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_RIGHTSHIFT: u16 = 54;
pub const KEY_LEFTALT: u16 = 56;
pub const KEY_RIGHTCTRL: u16 = 97;
pub const KEY_RIGHTALT: u16 = 100;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;

// ============================================================================
// evdev → USB HID translation
// ============================================================================

/// Translate an evdev keyboard code to its USB HID usage code. Returns
/// the raw evdev code when unmapped — callers can log the raw value
/// to spot missing table entries.
pub fn evdev_to_hid(code: u16) -> u32 {
    match code {
        // Row 1: Escape + F-keys
        1 => 0x29,  // KEY_ESC → Keyboard Escape
        59 => 0x3A, // F1
        60 => 0x3B, // F2
        61 => 0x3C, // F3
        62 => 0x3D, // F4
        63 => 0x3E, // F5
        64 => 0x3F, // F6
        65 => 0x40, // F7
        66 => 0x41, // F8
        67 => 0x42, // F9
        68 => 0x43, // F10
        87 => 0x44, // F11
        88 => 0x45, // F12

        // Digits row
        2 => 0x1E,  // 1
        3 => 0x1F,  // 2
        4 => 0x20,  // 3
        5 => 0x21,  // 4
        6 => 0x22,  // 5
        7 => 0x23,  // 6
        8 => 0x24,  // 7
        9 => 0x25,  // 8
        10 => 0x26, // 9
        11 => 0x27, // 0
        12 => 0x2D, // -
        13 => 0x2E, // =
        14 => 0x2A, // Backspace

        // QWERTY top row
        15 => 0x2B, // Tab
        16 => 0x14, // Q
        17 => 0x1A, // W
        18 => 0x08, // E
        19 => 0x15, // R
        20 => 0x17, // T
        21 => 0x1C, // Y
        22 => 0x18, // U
        23 => 0x0C, // I
        24 => 0x12, // O
        25 => 0x13, // P
        26 => 0x2F, // [
        27 => 0x30, // ]
        28 => 0x28, // Enter

        // Home row
        29 => 0xE0, // LeftCtrl
        30 => 0x04, // A
        31 => 0x16, // S
        32 => 0x07, // D
        33 => 0x09, // F
        34 => 0x0A, // G
        35 => 0x0B, // H
        36 => 0x0D, // J
        37 => 0x0E, // K
        38 => 0x0F, // L
        39 => 0x33, // ;
        40 => 0x34, // '
        41 => 0x35, // `

        // Bottom row
        42 => 0xE1, // LeftShift
        43 => 0x31, // \
        44 => 0x1D, // Z
        45 => 0x1B, // X
        46 => 0x06, // C
        47 => 0x19, // V
        48 => 0x05, // B
        49 => 0x11, // N
        50 => 0x10, // M
        51 => 0x36, // ,
        52 => 0x37, // .
        53 => 0x38, // /
        54 => 0xE5, // RightShift
        55 => 0x55, // Numpad *

        56 => 0xE2, // LeftAlt
        57 => 0x2C, // Space
        58 => 0x39, // CapsLock

        // Editing / navigation block
        97 => 0xE4,  // RightCtrl
        100 => 0xE6, // RightAlt
        102 => 0x4A, // Home
        103 => 0x52, // Up
        104 => 0x4B, // PageUp
        105 => 0x50, // Left
        106 => 0x4F, // Right
        107 => 0x4D, // End
        108 => 0x51, // Down
        109 => 0x4E, // PageDown
        110 => 0x49, // Insert
        111 => 0x4C, // Delete
        125 => 0xE3, // LeftMeta / LeftGUI
        126 => 0xE7, // RightMeta / RightGUI

        // Unmapped → passthrough.
        _ => code as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_keys_map_correctly() {
        assert_eq!(evdev_to_hid(30), 0x04); // A
        assert_eq!(evdev_to_hid(57), 0x2C); // Space
        assert_eq!(evdev_to_hid(28), 0x28); // Enter
        assert_eq!(evdev_to_hid(1), 0x29); // Escape
        assert_eq!(evdev_to_hid(105), 0x50); // Left arrow
    }

    #[test]
    fn unmapped_passes_through() {
        assert_eq!(evdev_to_hid(0x9999), 0x9999);
    }
}
