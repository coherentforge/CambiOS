// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! CambiOS input wire format (ADR-012).
//!
//! Drivers → compositor (today) → clients (today) speak this format
//! from day one. Locked before the first driver so PS/2- or virtio-
//! input-shaped assumptions cannot leak into later consumers. When
//! the Input Hub (ADR-012 Input-2) lands, it slots in between driver
//! and compositor without a protocol revision; when signed-carrier
//! hardware (ADR-012 Input-5) lands, the `signature_block` already
//! reserved by this crate starts carrying data without a format
//! change.
//!
//! ## 96-byte event envelope
//!
//! ```text
//! offset  size  field
//! 0       1     event_type     (EventType discriminant)
//! 1       1     device_class   (DeviceClass discriminant)
//! 2       4     device_id      (Hub- or driver-assigned, stable across hotplug)
//! 6       2     seq            (rolling per-device sequence)
//! 8       8     timestamp_ticks (kernel get_time tick at driver-observed moment)
//! 16     40     payload        (class-specific; see KeyboardPayload / PointerPayload)
//! 56     40     signature_block (zeroed for tier 0/1; populated tier ≥ 2 per ADR-012)
//! 96      —     (event end)
//! ```
//!
//! Two events fit in a 256-byte control-IPC slot (96 + 96 + 4-byte tag
//! ≤ 256), which matches ADR-012's batching rationale. This crate
//! decodes and encodes one event at a time; framing multiple events
//! into one IPC send is a driver-level choice (v0 virtio-input sends
//! one event per IPC message for simplicity).
//!
//! ## What this crate does NOT contain
//!
//! - IPC transport / endpoints — those are compositor / Hub concerns
//!   and live in `libgui-proto` (for compositor→client forwarding)
//!   and a future `libinput-hub-proto` when the Hub lands.
//! - Trust-tier policy — the 2-bit tier lives out-of-band in
//!   Hub→consumer metadata (ADR-012 § Trust tiers); the wire format
//!   itself just preserves the signature_block so verification can
//!   happen upstream.
//! - Keycode translation tables — drivers are responsible for
//!   producing USB HID usage codes in `KeyboardPayload.keycode`, not
//!   transport-native scancodes. See `evdev::EVDEV_TO_HID` in the
//!   virtio-input driver for the first table.
//! - Tablet / touch / controller / sensor payloads — reserved in
//!   ADR-012 but not defined here until the first driver for each
//!   class ships. Skip test hooks when the next step consumes them.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

// ============================================================================
// Wire-format constants (ADR-012 § Event wire format)
// ============================================================================

/// ARCHITECTURAL: total size of one encoded event in bytes. Fixed by
/// ADR-012 so two events fit in a 256-byte control-IPC slot (96×2 +
/// 4-byte message tag ≤ 256).
pub const EVENT_SIZE: usize = 96;

/// ARCHITECTURAL: size of the class-specific payload region.
pub const PAYLOAD_SIZE: usize = 40;

/// ARCHITECTURAL: size of the signature block. Zero for tier 0/1;
/// populated from tier 2 onward per ADR-012 § Signed input.
pub const SIGNATURE_BLOCK_SIZE: usize = 40;

// Field offsets within the 96-byte envelope.
const OFF_EVENT_TYPE: usize = 0;
const OFF_DEVICE_CLASS: usize = 1;
const OFF_DEVICE_ID: usize = 2;
const OFF_SEQ: usize = 6;
const OFF_TIMESTAMP: usize = 8;
const OFF_PAYLOAD: usize = 16;
const OFF_SIGNATURE: usize = 56;

// ============================================================================
// Enums — event_type and device_class
// ============================================================================

/// Event type discriminant. Values fixed by ADR-012 § Event wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    KeyDown = 0x01,
    KeyUp = 0x02,
    KeyRepeat = 0x03,

    PointerMove = 0x10,
    PointerButton = 0x11,
    PointerScroll = 0x12,

    ButtonDown = 0x20,
    ButtonUp = 0x21,
    ButtonRepeat = 0x22,

    Axis = 0x30,
    TabletTilt = 0x31,
    TabletPressure = 0x32,

    TouchBegin = 0x40,
    TouchMove = 0x41,
    TouchEnd = 0x42,

    DeviceAdded = 0x80,
    DeviceRemoved = 0x81,
    DeviceTrustChange = 0x82,
}

impl EventType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::KeyDown),
            0x02 => Some(Self::KeyUp),
            0x03 => Some(Self::KeyRepeat),
            0x10 => Some(Self::PointerMove),
            0x11 => Some(Self::PointerButton),
            0x12 => Some(Self::PointerScroll),
            0x20 => Some(Self::ButtonDown),
            0x21 => Some(Self::ButtonUp),
            0x22 => Some(Self::ButtonRepeat),
            0x30 => Some(Self::Axis),
            0x31 => Some(Self::TabletTilt),
            0x32 => Some(Self::TabletPressure),
            0x40 => Some(Self::TouchBegin),
            0x41 => Some(Self::TouchMove),
            0x42 => Some(Self::TouchEnd),
            0x80 => Some(Self::DeviceAdded),
            0x81 => Some(Self::DeviceRemoved),
            0x82 => Some(Self::DeviceTrustChange),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Device class discriminant. ADR-012 § Event wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceClass {
    Keyboard = 0x01,
    Pointer = 0x02,
    Controller = 0x03,
    Tablet = 0x04,
    Touch = 0x05,
    Sensor = 0x06,
    Accessibility = 0x07,
    Generic = 0xFF,
}

impl DeviceClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Keyboard),
            0x02 => Some(Self::Pointer),
            0x03 => Some(Self::Controller),
            0x04 => Some(Self::Tablet),
            0x05 => Some(Self::Touch),
            0x06 => Some(Self::Sensor),
            0x07 => Some(Self::Accessibility),
            0xFF => Some(Self::Generic),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// Modifier + button bitfields
// ============================================================================

/// Modifier bits for `KeyboardPayload.modifiers`. Matches the USB HID
/// modifier byte layout so HID usage codes in `keycode` line up.
pub mod modifier {
    pub const LEFT_CTRL: u16 = 0x0001;
    pub const LEFT_SHIFT: u16 = 0x0002;
    pub const LEFT_ALT: u16 = 0x0004;
    pub const LEFT_GUI: u16 = 0x0008;
    pub const RIGHT_CTRL: u16 = 0x0010;
    pub const RIGHT_SHIFT: u16 = 0x0020;
    pub const RIGHT_ALT: u16 = 0x0040;
    pub const RIGHT_GUI: u16 = 0x0080;
    pub const CAPS_LOCK: u16 = 0x0100;
    pub const NUM_LOCK: u16 = 0x0200;
    pub const SCROLL_LOCK: u16 = 0x0400;
}

/// Pointer button bits for `PointerPayload.buttons`. One bit per
/// button; a set bit means "currently pressed" for move events and
/// "transitioning to pressed/released" for a `PointerButton` event
/// (paired with `EventType::PointerButton` and the target bit in
/// `PointerPayload.buttons` toggled on/off).
pub mod button {
    pub const LEFT: u16 = 0x0001;
    pub const RIGHT: u16 = 0x0002;
    pub const MIDDLE: u16 = 0x0004;
    pub const SIDE: u16 = 0x0008;
    pub const EXTRA: u16 = 0x0010;
}

// ============================================================================
// Class-specific payloads
// ============================================================================

/// Keyboard payload (40 bytes). Fields at defined offsets within the
/// payload region; remaining bytes are zeroed padding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyboardPayload {
    /// USB HID usage code (not transport-native scancode). Drivers
    /// translate from their native space (evdev, PS/2 set 1, ...) into
    /// this canonical space so the compositor + clients see one code
    /// vocabulary regardless of transport.
    pub keycode: u32,
    /// Bit-OR of `modifier::*` flags live at the moment this event
    /// fired. Clients that care about "ctrl+c" check modifier bits
    /// rather than tracking shift/ctrl state themselves.
    pub modifiers: u16,
    /// Translated Unicode codepoint, if the driver has enough info to
    /// produce one (layout-aware). Zero when the driver only knows the
    /// physical key. libgui clients prefer this for text input;
    /// game-style input prefers `keycode`.
    pub unicode: u32,
}

/// Pointer payload (40 bytes). Used for mouse move + button + scroll.
/// Coordinates are driver-normalized: `dx` / `dy` are relative
/// movement deltas for relative pointers (mouse), or absolute
/// positions when the driver advertises an absolute pointer (tablet /
/// touchscreen — handled by separate classes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointerPayload {
    /// Relative x delta for a `PointerMove`; the pointer's x position
    /// at the moment of a `PointerButton` event (driver-tracked).
    pub dx: i32,
    /// Relative y delta for a `PointerMove`; the pointer's y position
    /// at the moment of a `PointerButton` event (driver-tracked).
    pub dy: i32,
    /// Bit-OR of `button::*` — the full live button mask at the
    /// moment the event fired. On a `PointerButton` event the changed
    /// button is both in this mask (pressed) or not (released); the
    /// direction is the `event_type` (ButtonDown / ButtonUp at the
    /// outer envelope level would use those tags, but pointer buttons
    /// live under `PointerButton` and the mask encodes the state).
    pub buttons: u16,
    /// Horizontal scroll ticks (positive = right).
    pub scroll_x: i16,
    /// Vertical scroll ticks (positive = down).
    pub scroll_y: i16,
}

// ============================================================================
// High-level InputEvent + encoders / decoders
// ============================================================================

/// Decoded form of a single 96-byte input event. Class-specific
/// payload is a flat union rather than an enum — the wire format's
/// `payload` region is a fixed 40 bytes regardless of class, and
/// encoding into a Rust enum would burn a discriminant byte inside
/// the already-tight envelope. Callers switch on `event_type` /
/// `device_class` and read the matching payload accessor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputEvent {
    pub event_type: EventType,
    pub device_class: DeviceClass,
    pub device_id: u32,
    pub seq: u16,
    pub timestamp_ticks: u64,
    /// Raw 40-byte class payload. Access via [`InputEvent::keyboard`]
    /// / [`InputEvent::pointer`] helpers.
    pub payload: [u8; PAYLOAD_SIZE],
    /// 40-byte signature_block. Zero for tier 0/1. Not interpreted by
    /// this crate; the Hub / signature-verify service reads it.
    pub signature_block: [u8; SIGNATURE_BLOCK_SIZE],
}

impl InputEvent {
    /// Decode the payload as a `KeyboardPayload`. Caller should verify
    /// `device_class == Keyboard` before trusting the result.
    pub fn keyboard(&self) -> KeyboardPayload {
        let p = &self.payload;
        KeyboardPayload {
            keycode: u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
            modifiers: u16::from_le_bytes([p[4], p[5]]),
            unicode: u32::from_le_bytes([p[6], p[7], p[8], p[9]]),
        }
    }

    /// Decode the payload as a `PointerPayload`.
    pub fn pointer(&self) -> PointerPayload {
        let p = &self.payload;
        PointerPayload {
            dx: i32::from_le_bytes([p[0], p[1], p[2], p[3]]),
            dy: i32::from_le_bytes([p[4], p[5], p[6], p[7]]),
            buttons: u16::from_le_bytes([p[8], p[9]]),
            scroll_x: i16::from_le_bytes([p[10], p[11]]),
            scroll_y: i16::from_le_bytes([p[12], p[13]]),
        }
    }

    /// Build a keyboard event — convenience constructor for drivers.
    pub fn key(
        event_type: EventType,
        device_id: u32,
        seq: u16,
        timestamp_ticks: u64,
        kbd: KeyboardPayload,
    ) -> Self {
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload[0..4].copy_from_slice(&kbd.keycode.to_le_bytes());
        payload[4..6].copy_from_slice(&kbd.modifiers.to_le_bytes());
        payload[6..10].copy_from_slice(&kbd.unicode.to_le_bytes());
        Self {
            event_type,
            device_class: DeviceClass::Keyboard,
            device_id,
            seq,
            timestamp_ticks,
            payload,
            signature_block: [0u8; SIGNATURE_BLOCK_SIZE],
        }
    }

    /// Build a pointer event — convenience constructor for drivers.
    pub fn pointer_event(
        event_type: EventType,
        device_id: u32,
        seq: u16,
        timestamp_ticks: u64,
        ptr: PointerPayload,
    ) -> Self {
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload[0..4].copy_from_slice(&ptr.dx.to_le_bytes());
        payload[4..8].copy_from_slice(&ptr.dy.to_le_bytes());
        payload[8..10].copy_from_slice(&ptr.buttons.to_le_bytes());
        payload[10..12].copy_from_slice(&ptr.scroll_x.to_le_bytes());
        payload[12..14].copy_from_slice(&ptr.scroll_y.to_le_bytes());
        Self {
            event_type,
            device_class: DeviceClass::Pointer,
            device_id,
            seq,
            timestamp_ticks,
            payload,
            signature_block: [0u8; SIGNATURE_BLOCK_SIZE],
        }
    }
}

/// Encode an event into the 96-byte wire format. Returns `Some(96)`
/// on success; `None` if the buffer is too small.
pub fn encode_event(buf: &mut [u8], event: &InputEvent) -> Option<usize> {
    if buf.len() < EVENT_SIZE {
        return None;
    }
    buf[OFF_EVENT_TYPE] = event.event_type.as_u8();
    buf[OFF_DEVICE_CLASS] = event.device_class.as_u8();
    buf[OFF_DEVICE_ID..OFF_DEVICE_ID + 4].copy_from_slice(&event.device_id.to_le_bytes());
    buf[OFF_SEQ..OFF_SEQ + 2].copy_from_slice(&event.seq.to_le_bytes());
    buf[OFF_TIMESTAMP..OFF_TIMESTAMP + 8]
        .copy_from_slice(&event.timestamp_ticks.to_le_bytes());
    buf[OFF_PAYLOAD..OFF_PAYLOAD + PAYLOAD_SIZE].copy_from_slice(&event.payload);
    buf[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_BLOCK_SIZE]
        .copy_from_slice(&event.signature_block);
    Some(EVENT_SIZE)
}

/// Decode a 96-byte event. Returns `None` if the buffer is too short
/// or the `event_type` / `device_class` discriminants are unknown.
pub fn decode_event(buf: &[u8]) -> Option<InputEvent> {
    if buf.len() < EVENT_SIZE {
        return None;
    }
    let event_type = EventType::from_u8(buf[OFF_EVENT_TYPE])?;
    let device_class = DeviceClass::from_u8(buf[OFF_DEVICE_CLASS])?;
    let device_id = u32::from_le_bytes([
        buf[OFF_DEVICE_ID],
        buf[OFF_DEVICE_ID + 1],
        buf[OFF_DEVICE_ID + 2],
        buf[OFF_DEVICE_ID + 3],
    ]);
    let seq = u16::from_le_bytes([buf[OFF_SEQ], buf[OFF_SEQ + 1]]);
    let timestamp_ticks = u64::from_le_bytes([
        buf[OFF_TIMESTAMP],
        buf[OFF_TIMESTAMP + 1],
        buf[OFF_TIMESTAMP + 2],
        buf[OFF_TIMESTAMP + 3],
        buf[OFF_TIMESTAMP + 4],
        buf[OFF_TIMESTAMP + 5],
        buf[OFF_TIMESTAMP + 6],
        buf[OFF_TIMESTAMP + 7],
    ]);
    let mut payload = [0u8; PAYLOAD_SIZE];
    payload.copy_from_slice(&buf[OFF_PAYLOAD..OFF_PAYLOAD + PAYLOAD_SIZE]);
    let mut signature_block = [0u8; SIGNATURE_BLOCK_SIZE];
    signature_block.copy_from_slice(&buf[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_BLOCK_SIZE]);
    Some(InputEvent {
        event_type,
        device_class,
        device_id,
        seq,
        timestamp_ticks,
        payload,
        signature_block,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_sizes_match_spec() {
        assert_eq!(EVENT_SIZE, 96);
        assert_eq!(PAYLOAD_SIZE, 40);
        assert_eq!(SIGNATURE_BLOCK_SIZE, 40);
        assert_eq!(OFF_PAYLOAD, 16);
        assert_eq!(OFF_SIGNATURE, 56);
        assert_eq!(OFF_SIGNATURE + SIGNATURE_BLOCK_SIZE, 96);
    }

    #[test]
    fn keyboard_event_roundtrip() {
        let ev = InputEvent::key(
            EventType::KeyDown,
            /* device_id */ 7,
            /* seq */ 42,
            /* ts */ 0xCAFE_BABE,
            KeyboardPayload {
                keycode: 0x04, // HID usage for 'A'
                modifiers: modifier::LEFT_SHIFT,
                unicode: b'A' as u32,
            },
        );
        let mut buf = [0u8; EVENT_SIZE];
        let n = encode_event(&mut buf, &ev).unwrap();
        assert_eq!(n, EVENT_SIZE);
        let decoded = decode_event(&buf).unwrap();
        assert_eq!(decoded, ev);
        assert_eq!(decoded.keyboard().keycode, 0x04);
        assert_eq!(decoded.keyboard().modifiers, modifier::LEFT_SHIFT);
        assert_eq!(decoded.keyboard().unicode, b'A' as u32);
    }

    #[test]
    fn pointer_event_roundtrip() {
        let ev = InputEvent::pointer_event(
            EventType::PointerMove,
            /* device_id */ 11,
            /* seq */ 1,
            /* ts */ 100,
            PointerPayload {
                dx: -3,
                dy: 7,
                buttons: button::LEFT | button::MIDDLE,
                scroll_x: 0,
                scroll_y: -2,
            },
        );
        let mut buf = [0u8; EVENT_SIZE];
        encode_event(&mut buf, &ev).unwrap();
        let decoded = decode_event(&buf).unwrap();
        assert_eq!(decoded.pointer().dx, -3);
        assert_eq!(decoded.pointer().dy, 7);
        assert_eq!(decoded.pointer().buttons, button::LEFT | button::MIDDLE);
        assert_eq!(decoded.pointer().scroll_y, -2);
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let buf = [0u8; EVENT_SIZE - 1];
        assert!(decode_event(&buf).is_none());
    }

    #[test]
    fn decode_rejects_bad_event_type() {
        let mut buf = [0u8; EVENT_SIZE];
        // Valid DeviceClass (Keyboard=0x01) but bogus event_type (0x99).
        buf[OFF_EVENT_TYPE] = 0x99;
        buf[OFF_DEVICE_CLASS] = DeviceClass::Keyboard.as_u8();
        assert!(decode_event(&buf).is_none());
    }

    #[test]
    fn decode_rejects_bad_device_class() {
        let mut buf = [0u8; EVENT_SIZE];
        buf[OFF_EVENT_TYPE] = EventType::KeyDown.as_u8();
        buf[OFF_DEVICE_CLASS] = 0xAA;
        assert!(decode_event(&buf).is_none());
    }

    #[test]
    fn signature_block_is_preserved() {
        // Tier-2 caller fills the signature_block; encode/decode must
        // pass those 40 bytes through unchanged.
        let mut ev = InputEvent::key(
            EventType::KeyDown,
            1,
            1,
            0,
            KeyboardPayload::default(),
        );
        for i in 0..SIGNATURE_BLOCK_SIZE {
            ev.signature_block[i] = (i as u8).wrapping_mul(7);
        }
        let mut buf = [0u8; EVENT_SIZE];
        encode_event(&mut buf, &ev).unwrap();
        let decoded = decode_event(&buf).unwrap();
        assert_eq!(decoded.signature_block, ev.signature_block);
    }

    #[test]
    fn two_events_fit_in_one_ipc_slot() {
        // ADR-012 rationale: 96 × 2 = 192 bytes, leaves 64 bytes for
        // a batching header if ever added. Sanity check the math.
        assert!(EVENT_SIZE * 2 <= 256);
    }
}
