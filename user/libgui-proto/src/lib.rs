// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS client ↔ compositor protocol (ADR-011 § surface channel).
//!
//! Shared by `user/compositor` and every GUI client
//! (`user/hello-window` in Scanout-3; future `user/libgui` will wrap
//! this in a friendlier widget-tree API).
//!
//! ## Shape of the protocol
//!
//! 1. Client registers its own endpoint (so the compositor can reply)
//!    and calls [`encode_create_window`], sending the result to
//!    [`COMPOSITOR_ENDPOINT`].
//! 2. Compositor allocates a shared-memory surface channel
//!    (`ChannelRole::Consumer` — compositor reads, client writes),
//!    assigns a `window_id`, and replies with
//!    [`encode_welcome_client`] carrying `(window_id, channel_id,
//!    geometry)`.
//! 3. Client attaches to the channel (`sys::channel_attach`), draws
//!    into the shared memory, and calls [`encode_frame_ready`] with
//!    optional damage rects.
//! 4. Compositor composites the client's surface into its per-output
//!    scanout buffer and forwards a [scanout FrameReady][scanout-fr] to
//!    the scanout-driver.
//!
//! [scanout-fr]: https://doc-link-deferred-until-libscanout-is-published
//!
//! ## What this crate explicitly does NOT contain
//!
//! - Window-state / z-order / focus logic — those are compositor
//!   internals (the compositor is the *single place* that knows those
//!   things).
//! - Widget / layout / text-rendering APIs — those belong in the
//!   future `user/libgui`, built on top of this protocol.
//! - IPC transport — both sides talk via `arcos-libsys`'s
//!   `write` / `recv_msg` primitives; this crate just defines what
//!   the payloads look like.
//! - `user/libscanout`'s scanout-side types — that's the compositor's
//!   *back* side (to the driver); this is its *front* side (to
//!   clients). Duplicated `Rect` / `PixelFormat` kept intentionally:
//!   the two protocols evolve on different clocks, and coupling the
//!   crates would force lockstep version bumps forever.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub use arcos_libinput_proto::{InputEvent, EVENT_SIZE as INPUT_EVENT_SIZE};

// ============================================================================
// Endpoints
// ============================================================================

/// Compositor's control endpoint — scanout-driver messages (0x20xx),
/// client messages (0x30xx), and compositor replies (0x40xx) all flow
/// here.
///
/// Kept duplicated from `arcos_libscanout::COMPOSITOR_ENDPOINT` rather
/// than cross-imported so libgui-proto keeps its single dependency
/// (`arcos-libinput-proto`, added for InputEvent forwarding) minimal.
pub const COMPOSITOR_ENDPOINT: u32 = 28;

/// Compositor's *input* endpoint — ADR-012 Input-1 path. virtio-input
/// (and any future PS/2 / USB HID / Bluetooth driver) sends
/// normalised `InputEvent`s here, 96 bytes per message, raw — no
/// wrapping tag, because this endpoint only carries input events.
///
/// When the Input Hub (ADR-012 Input-2) lands this number moves to
/// the Hub; the compositor connects to the Hub as a consumer and
/// keeps the same routing code.
pub const COMPOSITOR_INPUT_ENDPOINT: u32 = 30;

// ============================================================================
// Bounds
// ============================================================================

/// SCAFFOLDING: maximum concurrent windows across all clients.
/// Why: Hello-window exercises 1. A real desktop workload ("3+ apps
/// with multiple toolbar/dialog windows each") has ~10 concurrent
/// windows; a power-user workload runs 20-30. 32 = ~3× headroom over
/// the 10-window baseline per Convention 8, and the compositor-side
/// WindowTable at 32 slots costs ~2 KiB — trivial.
/// Replace when: first workload opens >8 windows (triggers the
/// "healthy ≤25% utilization" bar).
pub const MAX_WINDOWS: usize = 32;

/// SCAFFOLDING: max damage rects per client FrameReady. Matches
/// `arcos_libscanout::MAX_DAMAGE_RECTS_PER_FRAME` so a compositor-side
/// rect list can proxy straight through to the scanout-driver's
/// FrameReady without re-sizing. Replace when: the scanout-side bound
/// changes.
pub const MAX_DAMAGE_RECTS_PER_FRAME: usize = 16;

/// ARCHITECTURAL: maximum protocol message size in bytes, bounded by
/// the kernel's 256-byte control IPC payload. Implementations SHOULD
/// size receive buffers at this and reject anything larger.
pub const MAX_MESSAGE_SIZE: usize = 256;

/// SCAFFOLDING: maximum supported window dimension (either axis).
/// Why: caps the compositor's channel-allocation request for a
/// single window to something sane. 8192×8192 XRGB8888 = 256 MiB
/// which exactly matches `MAX_CHANNEL_PAGES` in the kernel (ADR-005).
/// Anything larger would need multi-channel surfaces — not a v0
/// concern. Replace when: a real workload needs per-window surfaces
/// above 8K on a side.
pub const MAX_WINDOW_DIMENSION: u32 = 8192;

// ============================================================================
// Wire-format types
// ============================================================================

/// Damage rectangle in window-local pixel coordinates. Identical
/// shape to `arcos_libscanout::Rect` but intentionally re-declared
/// (see module docstring).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// Pixel format for a client surface. Values chosen to match
/// `arcos_libscanout::PixelFormat` discriminants so the compositor
/// can pass a client's format through to the scanout-driver without
/// a lookup table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PixelFormat {
    Xrgb8888 = 0,
    Bgra8888 = 1,
    Argb2_10_10_10 = 2,
}

impl PixelFormat {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Xrgb8888),
            1 => Some(Self::Bgra8888),
            2 => Some(Self::Argb2_10_10_10),
            _ => None,
        }
    }
}

/// Errors from a client ↔ compositor operation. Returned in
/// [`encode_error_response`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GuiError {
    /// Compositor has reached [`MAX_WINDOWS`].
    TooManyWindows = 1,
    /// Requested window width/height is 0 or exceeds
    /// [`MAX_WINDOW_DIMENSION`].
    InvalidDimensions = 2,
    /// `window_id` in request does not refer to a live window owned
    /// by the caller's Principal.
    NoSuchWindow = 3,
    /// Message could not be decoded (unknown tag, truncated payload,
    /// invalid enum discriminant).
    InvalidMessage = 4,
    /// Compositor is tearing down and no longer accepting requests.
    CompositorShuttingDown = 5,
    /// Surface channel could not be allocated (kernel-side resource
    /// exhaustion — e.g. `MAX_CHANNELS` hit).
    SurfaceAllocFailed = 6,
}

impl GuiError {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::TooManyWindows),
            2 => Some(Self::InvalidDimensions),
            3 => Some(Self::NoSuchWindow),
            4 => Some(Self::InvalidMessage),
            5 => Some(Self::CompositorShuttingDown),
            6 => Some(Self::SurfaceAllocFailed),
            _ => None,
        }
    }
}

// ============================================================================
// Protocol messages
// ============================================================================

/// Wire-format tag identifying a protocol message. First 4 bytes of
/// every payload, little-endian. Client → compositor tags are 0x30xx;
/// compositor → client tags are 0x40xx. The high byte is a
/// direction-check hint, symmetric with libscanout's 0x10xx / 0x20xx.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MsgTag {
    // Client → compositor (0x30xx)
    CreateWindow = 0x3001,
    FrameReady = 0x3010,
    DestroyWindow = 0x3020,

    // Compositor → client (0x40xx)
    WelcomeClient = 0x4001,
    WindowClosed = 0x4010,
    ErrorResponse = 0x4020,
    /// Input event forwarded from the compositor to the focused window.
    /// Payload is the 96-byte [`InputEvent`] wire format defined by
    /// `arcos-libinput-proto` (ADR-012).
    InputEvent = 0x4030,
}

impl MsgTag {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x3001 => Some(Self::CreateWindow),
            0x3010 => Some(Self::FrameReady),
            0x3020 => Some(Self::DestroyWindow),
            0x4001 => Some(Self::WelcomeClient),
            0x4010 => Some(Self::WindowClosed),
            0x4020 => Some(Self::ErrorResponse),
            0x4030 => Some(Self::InputEvent),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

// ----------------------------------------------------------------------------
// Encoders / decoders
//
// Bytes are little-endian throughout. Encoders return the number of
// bytes written; decoders return None on malformed input (truncation,
// unknown discriminant, wrong tag).
// ----------------------------------------------------------------------------

/// `CreateWindow` — client → compositor.
/// Layout: `[tag:4][width:4][height:4]` = 12 bytes.
pub fn encode_create_window(buf: &mut [u8], width: u32, height: u32) -> Option<usize> {
    if buf.len() < 12 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::CreateWindow.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(&width.to_le_bytes());
    buf[8..12].copy_from_slice(&height.to_le_bytes());
    Some(12)
}

pub fn decode_create_window(buf: &[u8]) -> Option<(u32, u32)> {
    if buf.len() < 12
        || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::CreateWindow.as_u32()
    {
        return None;
    }
    Some((
        u32::from_le_bytes(buf[4..8].try_into().ok()?),
        u32::from_le_bytes(buf[8..12].try_into().ok()?),
    ))
}

/// Decoded form of [`encode_welcome_client`]. Separate struct rather
/// than a tuple because callers read most fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WelcomeClientMsg {
    pub window_id: u32,
    pub channel_id: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u16,
    pub format: PixelFormat,
}

/// `WelcomeClient` — compositor → client (reply to CreateWindow).
/// Layout: `[tag:4][window_id:4][channel_id:8][width:4][height:4]
///          [pitch:4][bpp:2][format:1][pad:1]` = 32 bytes.
#[allow(clippy::too_many_arguments)]
pub fn encode_welcome_client(
    buf: &mut [u8],
    window_id: u32,
    channel_id: u64,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u16,
    format: PixelFormat,
) -> Option<usize> {
    if buf.len() < 32 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::WelcomeClient.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(&window_id.to_le_bytes());
    buf[8..16].copy_from_slice(&channel_id.to_le_bytes());
    buf[16..20].copy_from_slice(&width.to_le_bytes());
    buf[20..24].copy_from_slice(&height.to_le_bytes());
    buf[24..28].copy_from_slice(&pitch.to_le_bytes());
    buf[28..30].copy_from_slice(&bpp.to_le_bytes());
    buf[30] = format as u8;
    buf[31] = 0;
    Some(32)
}

pub fn decode_welcome_client(buf: &[u8]) -> Option<WelcomeClientMsg> {
    if buf.len() < 32
        || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::WelcomeClient.as_u32()
    {
        return None;
    }
    let window_id = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let channel_id = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    let width = u32::from_le_bytes(buf[16..20].try_into().ok()?);
    let height = u32::from_le_bytes(buf[20..24].try_into().ok()?);
    let pitch = u32::from_le_bytes(buf[24..28].try_into().ok()?);
    let bpp = u16::from_le_bytes(buf[28..30].try_into().ok()?);
    let format = PixelFormat::from_u8(buf[30])?;
    Some(WelcomeClientMsg {
        window_id,
        channel_id,
        width,
        height,
        pitch,
        bpp,
        format,
    })
}

/// `FrameReady` — client → compositor.
/// Layout: `[tag:4][window_id:4][seq:4][damage_count:4][rects: N × 8]`.
/// `damage_count == 0` means "full surface dirty" (no rects follow).
/// Same shape as `arcos_libscanout::encode_frame_ready` but the 4-byte
/// id field is the `window_id`, not a `display_id`.
pub fn encode_frame_ready(
    buf: &mut [u8],
    window_id: u32,
    seq: u32,
    damage: &[Rect],
) -> Option<usize> {
    if damage.len() > MAX_DAMAGE_RECTS_PER_FRAME {
        return None;
    }
    let needed = 16 + damage.len() * 8;
    if buf.len() < needed {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::FrameReady.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(&window_id.to_le_bytes());
    buf[8..12].copy_from_slice(&seq.to_le_bytes());
    buf[12..16].copy_from_slice(&(damage.len() as u32).to_le_bytes());
    for (i, rect) in damage.iter().enumerate() {
        let off = 16 + i * 8;
        buf[off..off + 2].copy_from_slice(&rect.x.to_le_bytes());
        buf[off + 2..off + 4].copy_from_slice(&rect.y.to_le_bytes());
        buf[off + 4..off + 6].copy_from_slice(&rect.w.to_le_bytes());
        buf[off + 6..off + 8].copy_from_slice(&rect.h.to_le_bytes());
    }
    Some(needed)
}

/// Returns `(window_id, seq, damage_count)`. Caller reads the rects
/// via [`read_damage_rect`].
pub fn decode_frame_ready_header(buf: &[u8]) -> Option<(u32, u32, usize)> {
    if buf.len() < 16
        || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::FrameReady.as_u32()
    {
        return None;
    }
    let window_id = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let seq = u32::from_le_bytes(buf[8..12].try_into().ok()?);
    let damage_count = u32::from_le_bytes(buf[12..16].try_into().ok()?) as usize;
    if damage_count > MAX_DAMAGE_RECTS_PER_FRAME {
        return None;
    }
    if buf.len() < 16 + damage_count * 8 {
        return None;
    }
    Some((window_id, seq, damage_count))
}

/// Read the `index`-th damage rect from a `FrameReady` payload.
/// Caller is responsible for ensuring `index < damage_count` from
/// [`decode_frame_ready_header`].
pub fn read_damage_rect(buf: &[u8], index: usize) -> Option<Rect> {
    let off = 16 + index * 8;
    if buf.len() < off + 8 {
        return None;
    }
    Some(Rect {
        x: u16::from_le_bytes(buf[off..off + 2].try_into().ok()?),
        y: u16::from_le_bytes(buf[off + 2..off + 4].try_into().ok()?),
        w: u16::from_le_bytes(buf[off + 4..off + 6].try_into().ok()?),
        h: u16::from_le_bytes(buf[off + 6..off + 8].try_into().ok()?),
    })
}

/// `DestroyWindow` — client → compositor.
/// Layout: `[tag:4][window_id:4]` = 8 bytes.
pub fn encode_destroy_window(buf: &mut [u8], window_id: u32) -> Option<usize> {
    if buf.len() < 8 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::DestroyWindow.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(&window_id.to_le_bytes());
    Some(8)
}

pub fn decode_destroy_window(buf: &[u8]) -> Option<u32> {
    if buf.len() < 8
        || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::DestroyWindow.as_u32()
    {
        return None;
    }
    Some(u32::from_le_bytes(buf[4..8].try_into().ok()?))
}

/// `WindowClosed` — compositor → client. Notification that the
/// compositor has torn down a window (client-initiated or forced).
/// Layout: `[tag:4][window_id:4]` = 8 bytes.
pub fn encode_window_closed(buf: &mut [u8], window_id: u32) -> Option<usize> {
    if buf.len() < 8 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::WindowClosed.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(&window_id.to_le_bytes());
    Some(8)
}

pub fn decode_window_closed(buf: &[u8]) -> Option<u32> {
    if buf.len() < 8
        || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::WindowClosed.as_u32()
    {
        return None;
    }
    Some(u32::from_le_bytes(buf[4..8].try_into().ok()?))
}

/// `ErrorResponse` — compositor → client, on a failed request.
/// Layout: `[tag:4][error:1][pad:3]` = 8 bytes.
pub fn encode_error_response(buf: &mut [u8], error: GuiError) -> Option<usize> {
    if buf.len() < 8 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::ErrorResponse.as_u32().to_le_bytes());
    buf[4] = error as u8;
    buf[5..8].copy_from_slice(&[0, 0, 0]);
    Some(8)
}

pub fn decode_error_response(buf: &[u8]) -> Option<GuiError> {
    if buf.len() < 8
        || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::ErrorResponse.as_u32()
    {
        return None;
    }
    GuiError::from_u8(buf[4])
}

/// `InputEvent` — compositor → client. Layout:
/// `[tag:4][event:96]` = 100 bytes total. The 96-byte payload is the
/// libinput-proto wire format unchanged (ADR-012) — the compositor
/// forwards driver events verbatim plus the tag.
pub fn encode_input_event(buf: &mut [u8], event: &InputEvent) -> Option<usize> {
    if buf.len() < 4 + INPUT_EVENT_SIZE {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::InputEvent.as_u32().to_le_bytes());
    arcos_libinput_proto::encode_event(&mut buf[4..4 + INPUT_EVENT_SIZE], event)?;
    Some(4 + INPUT_EVENT_SIZE)
}

pub fn decode_input_event(buf: &[u8]) -> Option<InputEvent> {
    if buf.len() < 4 + INPUT_EVENT_SIZE
        || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::InputEvent.as_u32()
    {
        return None;
    }
    arcos_libinput_proto::decode_event(&buf[4..4 + INPUT_EVENT_SIZE])
}

// ============================================================================
// Tests — protocol round-trips
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_window_roundtrip() {
        let mut buf = [0u8; 16];
        let n = encode_create_window(&mut buf, 640, 480).unwrap();
        assert_eq!(n, 12);
        let (w, h) = decode_create_window(&buf).unwrap();
        assert_eq!((w, h), (640, 480));
    }

    #[test]
    fn welcome_client_roundtrip() {
        let mut buf = [0u8; 64];
        let n = encode_welcome_client(
            &mut buf,
            /* window_id */ 3,
            /* channel_id */ 0xAAAA_BBBB_CCCC_DDDD,
            /* width */ 400,
            /* height */ 300,
            /* pitch */ 1600,
            /* bpp */ 32,
            PixelFormat::Xrgb8888,
        )
        .unwrap();
        assert_eq!(n, 32);
        let m = decode_welcome_client(&buf).unwrap();
        assert_eq!(m.window_id, 3);
        assert_eq!(m.channel_id, 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(m.width, 400);
        assert_eq!(m.height, 300);
        assert_eq!(m.pitch, 1600);
        assert_eq!(m.bpp, 32);
        assert_eq!(m.format, PixelFormat::Xrgb8888);
    }

    #[test]
    fn frame_ready_with_damage_roundtrip() {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let damage = [
            Rect { x: 5, y: 10, w: 80, h: 60 },
            Rect { x: 100, y: 120, w: 40, h: 30 },
        ];
        let n = encode_frame_ready(&mut buf, /* window_id */ 7, /* seq */ 11, &damage).unwrap();
        assert_eq!(n, 16 + damage.len() * 8);
        let (window_id, seq, count) = decode_frame_ready_header(&buf).unwrap();
        assert_eq!(window_id, 7);
        assert_eq!(seq, 11);
        assert_eq!(count, damage.len());
        for (i, expected) in damage.iter().enumerate() {
            assert_eq!(read_damage_rect(&buf, i).unwrap(), *expected);
        }
    }

    #[test]
    fn frame_ready_full_surface_zero_rects() {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let n = encode_frame_ready(&mut buf, 0, 0, &[]).unwrap();
        assert_eq!(n, 16);
        let (_, _, count) = decode_frame_ready_header(&buf).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn frame_ready_rejects_too_many_rects() {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let damage = [Rect { x: 0, y: 0, w: 1, h: 1 }; MAX_DAMAGE_RECTS_PER_FRAME + 1];
        assert!(encode_frame_ready(&mut buf, 0, 0, &damage).is_none());
    }

    #[test]
    fn destroy_window_roundtrip() {
        let mut buf = [0u8; 16];
        let n = encode_destroy_window(&mut buf, 0xFEED).unwrap();
        assert_eq!(n, 8);
        let id = decode_destroy_window(&buf).unwrap();
        assert_eq!(id, 0xFEED);
    }

    #[test]
    fn window_closed_roundtrip() {
        let mut buf = [0u8; 16];
        let n = encode_window_closed(&mut buf, 42).unwrap();
        assert_eq!(n, 8);
        let id = decode_window_closed(&buf).unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn error_response_roundtrip() {
        for e in [
            GuiError::TooManyWindows,
            GuiError::InvalidDimensions,
            GuiError::NoSuchWindow,
            GuiError::InvalidMessage,
            GuiError::CompositorShuttingDown,
            GuiError::SurfaceAllocFailed,
        ] {
            let mut buf = [0u8; 16];
            let n = encode_error_response(&mut buf, e).unwrap();
            assert_eq!(n, 8);
            let decoded = decode_error_response(&buf).unwrap();
            assert_eq!(decoded, e);
        }
    }

    #[test]
    fn decode_rejects_wrong_tag() {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        encode_create_window(&mut buf, 100, 100).unwrap();
        // Try to decode as WelcomeClient
        assert!(decode_welcome_client(&buf).is_none());
        // Try to decode as FrameReady
        assert!(decode_frame_ready_header(&buf).is_none());
    }

    #[test]
    fn msg_tag_direction_bytes_are_distinct() {
        // High nibble 0x3 = client → compositor, 0x4 = compositor → client
        for tag in [MsgTag::CreateWindow, MsgTag::FrameReady, MsgTag::DestroyWindow] {
            assert_eq!(tag.as_u32() >> 12, 3, "client→compositor tag {:?} wrong direction", tag);
        }
        for tag in [
            MsgTag::WelcomeClient,
            MsgTag::WindowClosed,
            MsgTag::ErrorResponse,
            MsgTag::InputEvent,
        ] {
            assert_eq!(tag.as_u32() >> 12, 4, "compositor→client tag {:?} wrong direction", tag);
        }
    }

    #[test]
    fn input_event_roundtrip() {
        use arcos_libinput_proto::{EventType, KeyboardPayload};
        let ev = InputEvent::key(
            EventType::KeyDown,
            /* device_id */ 1,
            /* seq */ 99,
            /* ts */ 0x12345,
            KeyboardPayload {
                keycode: 0x04,
                modifiers: 0,
                unicode: 0,
            },
        );
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let n = encode_input_event(&mut buf, &ev).unwrap();
        assert_eq!(n, 4 + INPUT_EVENT_SIZE);
        let decoded = decode_input_event(&buf).unwrap();
        assert_eq!(decoded, ev);
    }

    #[test]
    fn input_event_rejects_wrong_tag() {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        encode_welcome_client(&mut buf, 1, 1, 1, 1, 4, 32, PixelFormat::Xrgb8888).unwrap();
        assert!(decode_input_event(&buf).is_none());
    }

    #[test]
    fn bounds_match_libscanout_where_shared() {
        // MAX_MESSAGE_SIZE and MAX_DAMAGE_RECTS_PER_FRAME must stay in
        // sync with libscanout so compositor-side rect lists pass
        // through unchanged. If libscanout bumps either, bump here.
        assert_eq!(MAX_MESSAGE_SIZE, 256);
        assert_eq!(MAX_DAMAGE_RECTS_PER_FRAME, 16);
    }
}
