// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS compositor ↔ scanout-driver protocol (ADR-014).
//!
//! Shared by `user/compositor` and every `user/scanout-*` implementation.
//! Holds:
//!
//! - Endpoint numbers (`SCANOUT_DRIVER_ENDPOINT`, `COMPOSITOR_ENDPOINT`)
//! - Bound constants (`MAX_DISPLAYS_PER_DRIVER`, `MAX_DAMAGE_RECTS_PER_FRAME`,
//!   `SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS`)
//! - Wire-format types (`DisplayInfo`, `Geometry`, `Mode`, `PixelFormat`,
//!   `Rect`, `DisplayState`)
//! - Protocol message tags + packed payload encoders/decoders
//!
//! What this crate explicitly does NOT contain:
//!
//! - The `ScanoutBackend` trait or any concrete backend impl — those are
//!   the *consumer side* (compositor only) and live in `user/compositor`.
//! - Compositor-internal types like `ScanoutBuffer` (which holds a
//!   process-local vaddr) — also compositor-only.
//! - IPC transport — both sides talk through `cambios-libsys`'s
//!   `write` / `recv_msg` primitives; this crate just defines what the
//!   payloads look like.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

// ============================================================================
// Endpoints (well-known, per ADR-014 § Endpoints)
// ============================================================================

/// IPC endpoint where scanout-drivers receive control messages from the
/// compositor (RegisterCompositor, FrameReady, RequestModeChange).
/// The active scanout-driver registers this endpoint at boot.
pub const SCANOUT_DRIVER_ENDPOINT: u32 = 27;

/// IPC endpoint where the compositor receives scanout-driver async events
/// (WelcomeCompositor, DisplayConnected, FrameDisplayed).
/// The compositor registers this endpoint at boot.
pub const COMPOSITOR_ENDPOINT: u32 = 28;

// ============================================================================
// Bounds (per ADR-014 § Reserved bounds)
// ============================================================================

/// SCAFFOLDING: max physical displays a single scanout-driver advertises.
/// Practical-ceiling bound — matches `MAX_FRAMEBUFFERS = 8` in
/// `src/boot/mod.rs`. Even pro multi-monitor rigs cap around 6, and the
/// graphics subsystem isn't being built to drive 32 displays. Replace
/// when BootInfo's MAX_FRAMEBUFFERS grows or a real workload appears
/// with >6 displays driven by one driver.
pub const MAX_DISPLAYS_PER_DRIVER: usize = 8;

/// SCAFFOLDING: max damage rects per FrameReady message. 16 rects ×
/// 8 B (`Rect` packed) = 128 B, leaves ~120 B for the message envelope
/// in the 256-byte control IPC. Above 16 rects compositors send "full
/// surface dirty" — strict upper bound that simple drivers can rely on.
pub const MAX_DAMAGE_RECTS_PER_FRAME: usize = 16;

/// TUNING: ticks the compositor waits at startup for a scanout-driver
/// to register before falling back to `HeadlessBackend`.
/// 500 ticks @ 100 Hz = 5 s. Generous on QEMU, tight-but-usable on
/// bare-metal. Revisit on first real-hardware bring-up.
pub const SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS: u64 = 500;

// ============================================================================
// Wire-format types
// ============================================================================

/// Display lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DisplayState {
    Disconnected = 0,
    Connected = 1,
}

impl DisplayState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Disconnected),
            1 => Some(Self::Connected),
            _ => None,
        }
    }
}

/// Pixel format advertised by a scanout-driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PixelFormat {
    /// 32-bit XRGB8888, no alpha — most common linear FB / virtio-gpu format.
    Xrgb8888 = 0,
    /// 32-bit BGRA8888 — alternate channel order.
    Bgra8888 = 1,
    /// 32-bit ARGB2_10_10_10 — HDR10-class wide gamut.
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

/// Geometry of a display's current scan mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Geometry {
    pub width: u32,
    pub height: u32,
    /// Bytes per scanline (≥ width × bpp/8; may be padded for alignment).
    pub pitch: u32,
    /// Bits per pixel.
    pub bpp: u16,
}

/// One mode in a display's mode list.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    pub refresh_hz: u16,
    pub format: PixelFormat,
}

/// Display advertisement — one per active output.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DisplayInfo {
    pub display_id: u32,
    pub state: DisplayState,
    pub geometry: Geometry,
    /// Per-display backing scale factor × 100 (1×=100, 2×=200, 1.25×=125).
    pub backing_scale: u16,
    pub refresh_hz: u16,
    pub format: PixelFormat,
    /// Bitfield: bit 0 = HDR10, bit 1 = VRR, bit 2 = partial-update support, ...
    pub capabilities: u32,
    /// Blake3 of full EDID, for stable identity across hotplug cycles.
    pub edid_hash: [u8; 32],
}

/// Damage rectangle in display-local coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// Errors from compositor → scanout-driver operations. Both sides
/// agree on this set — shared so error semantics don't diverge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ScanoutError {
    NoSuchDisplay = 1,
    ModeRejected = 2,
    FrameDropped = 3,
    TransportFailed = 4,
    Headless = 5,
    InvalidMessage = 6,
    NotRegistered = 7,
}

impl ScanoutError {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::NoSuchDisplay),
            2 => Some(Self::ModeRejected),
            3 => Some(Self::FrameDropped),
            4 => Some(Self::TransportFailed),
            5 => Some(Self::Headless),
            6 => Some(Self::InvalidMessage),
            7 => Some(Self::NotRegistered),
            _ => None,
        }
    }
}

// ============================================================================
// Protocol messages
// ============================================================================

/// Wire-format tag identifying a protocol message. First 4 bytes of every
/// message, little-endian. Compositor → driver tags are 0x10xx, driver →
/// compositor tags are 0x20xx — high byte tells you the direction so a
/// stray message in the wrong queue is recognizable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MsgTag {
    // Compositor → scanout-driver
    RegisterCompositor = 0x1001,
    FrameReady = 0x1010,
    RequestModeChange = 0x1020,
    ReleaseScanoutBuffer = 0x1030,

    // Scanout-driver → compositor
    WelcomeCompositor = 0x2001,
    DisplayConnected = 0x2010,
    DisplayDisconnected = 0x2011,
    DisplayModeChanged = 0x2012,
    FrameDisplayed = 0x2020,
    FrameDropped = 0x2021,
    ModeRejected = 0x2030,
}

impl MsgTag {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x1001 => Some(Self::RegisterCompositor),
            0x1010 => Some(Self::FrameReady),
            0x1020 => Some(Self::RequestModeChange),
            0x1030 => Some(Self::ReleaseScanoutBuffer),
            0x2001 => Some(Self::WelcomeCompositor),
            0x2010 => Some(Self::DisplayConnected),
            0x2011 => Some(Self::DisplayDisconnected),
            0x2012 => Some(Self::DisplayModeChanged),
            0x2020 => Some(Self::FrameDisplayed),
            0x2021 => Some(Self::FrameDropped),
            0x2030 => Some(Self::ModeRejected),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Maximum protocol message size in bytes — bounded by the kernel's
/// 256-byte control IPC payload. Implementers SHOULD size receive
/// buffers at this and reject anything larger.
pub const MAX_MESSAGE_SIZE: usize = 256;

// ----------------------------------------------------------------------------
// Encode/decode helpers
//
// Bytes are little-endian throughout. Encoders return the number of
// bytes written; decoders take a byte slice and return None on malformed
// input (truncation, unknown enum discriminant, mismatched tag).
// ----------------------------------------------------------------------------

/// `RegisterCompositor` — compositor → driver, no payload beyond the tag.
/// Sender Principal (stamped by the kernel) is what authorizes the driver
/// to bind to this compositor.
pub fn encode_register_compositor(buf: &mut [u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::RegisterCompositor.as_u32().to_le_bytes());
    Some(4)
}

/// `WelcomeCompositor` — driver → compositor.
/// `capabilities` is a forward-compat bitfield (no flags defined in v0;
/// drivers set 0).
pub fn encode_welcome_compositor(buf: &mut [u8], capabilities: u32) -> Option<usize> {
    if buf.len() < 8 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::WelcomeCompositor.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(&capabilities.to_le_bytes());
    Some(8)
}

pub fn decode_welcome_compositor(buf: &[u8]) -> Option<u32> {
    if buf.len() < 8 || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::WelcomeCompositor.as_u32() {
        return None;
    }
    Some(u32::from_le_bytes(buf[4..8].try_into().ok()?))
}

/// `DisplayConnected` — driver → compositor. Carries the new display's
/// `DisplayInfo` and the channel ID the compositor will attach to for
/// scanout-buffer access.
///
/// Layout: `[tag:4][channel_id:8][display_id:4][state:1][bbp:2pad?][...]`
/// — kept fully packed via field-wise encoding rather than `repr(C)`
/// memcpy so endian discipline is explicit.
pub fn encode_display_connected(
    buf: &mut [u8],
    info: &DisplayInfo,
    scanout_channel_id: u64,
) -> Option<usize> {
    if buf.len() < 80 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::DisplayConnected.as_u32().to_le_bytes());
    buf[4..12].copy_from_slice(&scanout_channel_id.to_le_bytes());
    write_display_info(&mut buf[12..], info)?;
    Some(80) // 4 (tag) + 8 (channel_id) + 68 (display_info) = 80
}

pub fn decode_display_connected(buf: &[u8]) -> Option<(DisplayInfo, u64)> {
    if buf.len() < 80 || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::DisplayConnected.as_u32() {
        return None;
    }
    let channel_id = u64::from_le_bytes(buf[4..12].try_into().ok()?);
    let info = read_display_info(&buf[12..])?;
    Some((info, channel_id))
}

/// `FrameReady` — compositor → driver.
/// Layout: `[tag:4][display_id:4][seq:4][damage_count:4][rects: damage_count × 8]`
/// `damage_count == 0` means "full surface dirty" (no rects follow).
/// Driver may use damage as a hint or ignore it.
pub fn encode_frame_ready(
    buf: &mut [u8],
    display_id: u32,
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
    buf[4..8].copy_from_slice(&display_id.to_le_bytes());
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

/// Decode a `FrameReady` message.
///
/// Returns `(display_id, seq, damage_count)` on success. The caller can
/// then read `damage_count` rectangles from `buf[16..]` via
/// [`read_damage_rect`].
pub fn decode_frame_ready_header(buf: &[u8]) -> Option<(u32, u32, usize)> {
    if buf.len() < 16 || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::FrameReady.as_u32() {
        return None;
    }
    let display_id = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let seq = u32::from_le_bytes(buf[8..12].try_into().ok()?);
    let damage_count = u32::from_le_bytes(buf[12..16].try_into().ok()?) as usize;
    if damage_count > MAX_DAMAGE_RECTS_PER_FRAME {
        return None;
    }
    if buf.len() < 16 + damage_count * 8 {
        return None;
    }
    Some((display_id, seq, damage_count))
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

/// `FrameDisplayed` — driver → compositor.
/// Layout: `[tag:4][display_id:4][seq:4][present_time_ticks:8]`
pub fn encode_frame_displayed(
    buf: &mut [u8],
    display_id: u32,
    seq: u32,
    present_time_ticks: u64,
) -> Option<usize> {
    if buf.len() < 20 {
        return None;
    }
    buf[..4].copy_from_slice(&MsgTag::FrameDisplayed.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(&display_id.to_le_bytes());
    buf[8..12].copy_from_slice(&seq.to_le_bytes());
    buf[12..20].copy_from_slice(&present_time_ticks.to_le_bytes());
    Some(20)
}

pub fn decode_frame_displayed(buf: &[u8]) -> Option<(u32, u32, u64)> {
    if buf.len() < 20 || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MsgTag::FrameDisplayed.as_u32() {
        return None;
    }
    Some((
        u32::from_le_bytes(buf[4..8].try_into().ok()?),
        u32::from_le_bytes(buf[8..12].try_into().ok()?),
        u64::from_le_bytes(buf[12..20].try_into().ok()?),
    ))
}

// ----------------------------------------------------------------------------
// DisplayInfo packed encoding (68 bytes)
// ----------------------------------------------------------------------------
//
// Field-wise encoding (not memcpy of repr(C)) so the wire format is
// explicit and endian-safe across whatever target each side runs on.

const DISPLAY_INFO_BYTES: usize = 68;

fn write_display_info(buf: &mut [u8], info: &DisplayInfo) -> Option<()> {
    if buf.len() < DISPLAY_INFO_BYTES {
        return None;
    }
    buf[0..4].copy_from_slice(&info.display_id.to_le_bytes());
    buf[4] = info.state as u8;
    // 3 bytes pad to align Geometry to a u32 offset
    buf[5..8].copy_from_slice(&[0, 0, 0]);
    buf[8..12].copy_from_slice(&info.geometry.width.to_le_bytes());
    buf[12..16].copy_from_slice(&info.geometry.height.to_le_bytes());
    buf[16..20].copy_from_slice(&info.geometry.pitch.to_le_bytes());
    buf[20..22].copy_from_slice(&info.geometry.bpp.to_le_bytes());
    buf[22..24].copy_from_slice(&info.backing_scale.to_le_bytes());
    buf[24..26].copy_from_slice(&info.refresh_hz.to_le_bytes());
    buf[26] = info.format as u8;
    buf[27] = 0; // pad
    buf[28..32].copy_from_slice(&info.capabilities.to_le_bytes());
    buf[32..64].copy_from_slice(&info.edid_hash);
    buf[64..68].copy_from_slice(&[0, 0, 0, 0]); // reserved
    Some(())
}

fn read_display_info(buf: &[u8]) -> Option<DisplayInfo> {
    if buf.len() < DISPLAY_INFO_BYTES {
        return None;
    }
    let display_id = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    let state = DisplayState::from_u8(buf[4])?;
    let geometry = Geometry {
        width: u32::from_le_bytes(buf[8..12].try_into().ok()?),
        height: u32::from_le_bytes(buf[12..16].try_into().ok()?),
        pitch: u32::from_le_bytes(buf[16..20].try_into().ok()?),
        bpp: u16::from_le_bytes(buf[20..22].try_into().ok()?),
    };
    let backing_scale = u16::from_le_bytes(buf[22..24].try_into().ok()?);
    let refresh_hz = u16::from_le_bytes(buf[24..26].try_into().ok()?);
    let format = PixelFormat::from_u8(buf[26])?;
    let capabilities = u32::from_le_bytes(buf[28..32].try_into().ok()?);
    let mut edid_hash = [0u8; 32];
    edid_hash.copy_from_slice(&buf[32..64]);
    Some(DisplayInfo {
        display_id,
        state,
        geometry,
        backing_scale,
        refresh_hz,
        format,
        capabilities,
        edid_hash,
    })
}

// ============================================================================
// Tests — protocol round-trips
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_display_info() -> DisplayInfo {
        DisplayInfo {
            display_id: 7,
            state: DisplayState::Connected,
            geometry: Geometry {
                width: 1920,
                height: 1080,
                pitch: 7680,
                bpp: 32,
            },
            backing_scale: 200,
            refresh_hz: 120,
            format: PixelFormat::Xrgb8888,
            capabilities: 0b101,
            edid_hash: [0xAB; 32],
        }
    }

    #[test]
    fn register_compositor_roundtrip_tag_only() {
        let mut buf = [0u8; 16];
        let n = encode_register_compositor(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(MsgTag::from_u32(u32::from_le_bytes(buf[0..4].try_into().unwrap())),
                   Some(MsgTag::RegisterCompositor));
    }

    #[test]
    fn welcome_compositor_roundtrip() {
        let mut buf = [0u8; 16];
        let n = encode_welcome_compositor(&mut buf, 0xDEAD_BEEF).unwrap();
        assert_eq!(n, 8);
        let caps = decode_welcome_compositor(&buf).unwrap();
        assert_eq!(caps, 0xDEAD_BEEF);
    }

    #[test]
    fn display_connected_roundtrip() {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let info = sample_display_info();
        let n = encode_display_connected(&mut buf, &info, 0x1234_5678_ABCD_EF01).unwrap();
        assert_eq!(n, 80);
        let (decoded, channel_id) = decode_display_connected(&buf).unwrap();
        assert_eq!(channel_id, 0x1234_5678_ABCD_EF01);
        assert_eq!(decoded.display_id, info.display_id);
        assert_eq!(decoded.state, info.state);
        assert_eq!(decoded.geometry, info.geometry);
        assert_eq!(decoded.backing_scale, info.backing_scale);
        assert_eq!(decoded.refresh_hz, info.refresh_hz);
        assert_eq!(decoded.format, info.format);
        assert_eq!(decoded.capabilities, info.capabilities);
        assert_eq!(decoded.edid_hash, info.edid_hash);
    }

    #[test]
    fn frame_ready_roundtrip_with_damage() {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let damage = [
            Rect { x: 10, y: 20, w: 100, h: 50 },
            Rect { x: 200, y: 300, w: 80, h: 40 },
        ];
        let n = encode_frame_ready(&mut buf, 7, 42, &damage).unwrap();
        assert_eq!(n, 16 + damage.len() * 8);
        let (display_id, seq, count) = decode_frame_ready_header(&buf).unwrap();
        assert_eq!(display_id, 7);
        assert_eq!(seq, 42);
        assert_eq!(count, damage.len());
        for (i, expected) in damage.iter().enumerate() {
            assert_eq!(read_damage_rect(&buf, i).unwrap(), *expected);
        }
    }

    #[test]
    fn frame_ready_full_surface_dirty_zero_rects() {
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
    fn frame_displayed_roundtrip() {
        let mut buf = [0u8; 32];
        let n = encode_frame_displayed(&mut buf, 9, 17, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(n, 20);
        let (display_id, seq, time) = decode_frame_displayed(&buf).unwrap();
        assert_eq!(display_id, 9);
        assert_eq!(seq, 17);
        assert_eq!(time, 0x1122_3344_5566_7788);
    }

    #[test]
    fn decode_rejects_wrong_tag() {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        encode_welcome_compositor(&mut buf, 0).unwrap();
        // Try to decode as DisplayConnected
        assert!(decode_display_connected(&buf).is_none());
    }

    #[test]
    fn msg_tag_direction_bytes_are_distinct() {
        // High byte 0x10 = compositor → driver, 0x20 = driver → compositor
        for tag in [
            MsgTag::RegisterCompositor,
            MsgTag::FrameReady,
            MsgTag::RequestModeChange,
            MsgTag::ReleaseScanoutBuffer,
        ] {
            assert_eq!(tag.as_u32() >> 12, 1, "compositor→driver tag {:?} wrong direction byte", tag);
        }
        for tag in [
            MsgTag::WelcomeCompositor,
            MsgTag::DisplayConnected,
            MsgTag::DisplayDisconnected,
            MsgTag::DisplayModeChanged,
            MsgTag::FrameDisplayed,
            MsgTag::FrameDropped,
            MsgTag::ModeRejected,
        ] {
            assert_eq!(tag.as_u32() >> 12, 2, "driver→compositor tag {:?} wrong direction byte", tag);
        }
    }
}
