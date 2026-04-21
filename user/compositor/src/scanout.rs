// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Compositor-internal scanout abstraction — Phase Scanout-1 (ADR-014).
//!
//! Wire-format types, message tags, and bound constants live in
//! `arcos-libscanout` (shared with every `user/scanout-*` implementation).
//! This module owns:
//!
//! - The `ScanoutBackend` trait — the compositor's *consumer-side*
//!   abstraction over whichever scanout-driver is bound.
//! - `ScanoutBuffer` — process-local handle to a mapped scanout region
//!   (carries the compositor's vaddr; not on the wire).
//! - `HeadlessBackend` — the no-display fallback used when no
//!   scanout-driver registers within the handshake timeout.
//!
//! Per ADR-014, future implementors (`VirtioGpuBackend`, `IntelGpuBackend`,
//! `LimineFbBackend`) live alongside but each is a thin IPC client over
//! `arcos-libscanout`'s wire encoders. Compositor uses `Box<dyn
//! ScanoutBackend>` chosen at startup probe — userspace dyn dispatch
//! explicitly allowed (verification scope is the kernel, not userspace).

// Re-export everything compositor consumers need so they can import from
// a single place. Keeps the `use scanout::Foo` surface stable as
// libscanout grows. Some re-exports are unused by main.rs today (Phase
// Scanout-1 only consumes COMPOSITOR_ENDPOINT + ScanoutBackend +
// HeadlessBackend); they exist as the consumer-facing surface for the
// LimineFbBackend impl that lands next.
#[allow(unused_imports)]
pub use arcos_libscanout::{
    DisplayInfo, DisplayState, Geometry, MAX_DAMAGE_RECTS_PER_FRAME, MAX_DISPLAYS_PER_DRIVER,
    Mode, MsgTag, PixelFormat, Rect, SCANOUT_DRIVER_ENDPOINT, SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS,
    ScanoutError,
    COMPOSITOR_ENDPOINT,
};

// ============================================================================
// Compositor-side types (not on the wire)
// ============================================================================

/// Async event surfaced from a backend's `poll_event`.
///
/// Modeled compositor-side rather than as a wire type because it carries
/// process-local state (the compositor's mapping of newly-arrived
/// scanout buffers, etc.). When a backend decodes a libscanout protocol
/// message, it translates into this enum for the compositor to consume.
#[derive(Clone, Copy, Debug)]
pub enum ScanoutEvent {
    DisplayConnected { info: DisplayInfo, scanout_channel_id: u64 },
    DisplayDisconnected { display_id: u32 },
    DisplayModeChanged { info: DisplayInfo, new_scanout_channel_id: u64 },
    FrameDisplayed { display_id: u32, seq: u32, present_time_ticks: u64 },
    FrameDropped { display_id: u32, seq: u32 },
}

/// Handle to a scanout buffer mapped into the compositor's address space.
/// The buffer is allocated by the scanout-driver (it knows hardware
/// constraints — alignment, GPU-visible memory) and shared via a channel.
#[derive(Clone, Copy, Debug)]
pub struct ScanoutBuffer {
    pub display_id: u32,
    pub geometry: Geometry,
    pub format: PixelFormat,
    /// User vaddr of the mapped scanout region (compositor writes here).
    pub vaddr: u64,
    /// Channel ID for teardown / re-attach.
    pub channel_id: u64,
}

// ============================================================================
// ScanoutBackend trait
// ============================================================================

/// What the compositor can ask of any scanout-driver.
///
/// Implemented by `HeadlessBackend` (no-display fallback) and, in
/// future, per-backend IPC client structs (`VirtioGpuBackend`,
/// `IntelGpuBackend`, `LimineFbBackend`). The compositor uses
/// `Box<dyn ScanoutBackend>` — see ADR-014 § "Trait abstraction in the
/// compositor (userspace dyn dispatch)".
pub trait ScanoutBackend {
    /// All currently-connected displays this backend knows about.
    fn enumerate_displays(&self) -> &[DisplayInfo];

    /// Attach to a display's scanout buffer and return a handle to the
    /// mapped region. Driver allocates; compositor writes.
    fn attach_scanout(&mut self, display_id: u32) -> Result<ScanoutBuffer, ScanoutError>;

    /// Tell the driver this frame is ready, optionally with damage
    /// rects. `damage` is a *hint*, not a constraint; conformant
    /// drivers may ignore it and do full-frame flips. If
    /// `damage.len() > MAX_DAMAGE_RECTS_PER_FRAME`, compositor MUST
    /// send "full surface dirty" instead.
    fn submit_frame(&mut self, display_id: u32, damage: &[Rect]) -> Result<(), ScanoutError>;

    /// Feed a scanout-driver message (already received from the
    /// compositor endpoint, with the 36-byte IPC header stripped) into
    /// this backend. Returns a decoded event on success, `None` if the
    /// payload is malformed or of a tag this backend doesn't consume.
    ///
    /// Scanout-3 split this out of the old `poll_event()`: the
    /// compositor now owns the `try_recv_msg` loop at ep28 (it has to,
    /// so client messages reach the client dispatch path) and hands
    /// scanout-direction payloads down.
    fn handle_scanout_payload(&mut self, payload: &[u8]) -> Option<ScanoutEvent>;

    /// Request a mode change for a display (e.g. user resized
    /// resolution). Driver responds asynchronously with
    /// `ScanoutEvent::DisplayModeChanged` (success) or `ModeRejected`.
    fn request_mode(&mut self, display_id: u32, mode: Mode) -> Result<(), ScanoutError>;
}

// ============================================================================
// HeadlessBackend — the no-display fallback
// ============================================================================

/// The fallback backend when no scanout-driver registers within
/// `SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS`. Compositor remains alive,
/// silently swallows all display operations. Useful for headless
/// servers, CI, and pre-driver bring-up.
pub struct HeadlessBackend;

impl HeadlessBackend {
    pub const fn new() -> Self {
        HeadlessBackend
    }
}

impl Default for HeadlessBackend {
    fn default() -> Self { Self::new() }
}

impl ScanoutBackend for HeadlessBackend {
    fn enumerate_displays(&self) -> &[DisplayInfo] {
        &[]
    }

    fn attach_scanout(&mut self, _display_id: u32) -> Result<ScanoutBuffer, ScanoutError> {
        Err(ScanoutError::Headless)
    }

    fn submit_frame(&mut self, _display_id: u32, _damage: &[Rect]) -> Result<(), ScanoutError> {
        Err(ScanoutError::Headless)
    }

    fn handle_scanout_payload(&mut self, _payload: &[u8]) -> Option<ScanoutEvent> {
        None
    }

    fn request_mode(&mut self, _display_id: u32, _mode: Mode) -> Result<(), ScanoutError> {
        Err(ScanoutError::Headless)
    }
}

// ============================================================================
// LimineFbBackend — Phase Scanout-2 fallback (talks to user/scanout-limine)
// ============================================================================

use arcos_libscanout::{
    decode_frame_displayed, encode_frame_ready,
};
use arcos_libsys as sys;

/// IPC client for `user/scanout-limine`.
///
/// Holds the displays advertised at handshake time and the scanout buffer
/// the compositor writes pixels into. `submit_frame` encodes a
/// `FrameReady` and sends it to `SCANOUT_DRIVER_ENDPOINT`; `poll_event`
/// non-blocking-recvs from `COMPOSITOR_ENDPOINT` and decodes any
/// driver-side events (today: `FrameDisplayed` only — full hotplug
/// path lands once dynamic display add/remove is exercised).
pub struct LimineFbBackend {
    /// The single scanout buffer this backend owns. Limine fallback is
    /// single-display by construction; multi-display lands with
    /// virtio-gpu / Intel where it actually matters.
    pub scanout: ScanoutBuffer,
    displays: [DisplayInfo; 1],
    next_seq: u32,
    /// Latest received FrameDisplayed seq, for back-pressure / diagnostics.
    pub last_displayed_seq: Option<u32>,
    /// Latest received present time, for animation-clock alignment.
    pub last_present_time: u64,
}

impl LimineFbBackend {
    /// Build from the handshake reply: the `DisplayConnected`
    /// `DisplayInfo` and the channel ID, which the compositor has
    /// already attached (`SYS_CHANNEL_ATTACH`) to obtain the scanout
    /// vaddr.
    pub fn from_handshake(info: DisplayInfo, scanout: ScanoutBuffer) -> Self {
        Self {
            scanout,
            displays: [info],
            next_seq: 0,
            last_displayed_seq: None,
            last_present_time: 0,
        }
    }
}

impl ScanoutBackend for LimineFbBackend {
    fn enumerate_displays(&self) -> &[DisplayInfo] {
        &self.displays
    }

    fn attach_scanout(&mut self, display_id: u32) -> Result<ScanoutBuffer, ScanoutError> {
        if display_id != self.scanout.display_id {
            return Err(ScanoutError::NoSuchDisplay);
        }
        Ok(self.scanout)
    }

    fn submit_frame(&mut self, display_id: u32, damage: &[Rect]) -> Result<(), ScanoutError> {
        if display_id != self.scanout.display_id {
            return Err(ScanoutError::NoSuchDisplay);
        }
        let mut buf = [0u8; arcos_libscanout::MAX_MESSAGE_SIZE];
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        // If damage exceeds the per-frame cap, send "full surface dirty"
        // (zero rects) per ADR-014 § Reserved bounds.
        let used_damage: &[Rect] = if damage.len() > MAX_DAMAGE_RECTS_PER_FRAME {
            &[]
        } else {
            damage
        };

        let n = encode_frame_ready(&mut buf, display_id, seq, used_damage)
            .ok_or(ScanoutError::InvalidMessage)?;
        let rc = sys::write(SCANOUT_DRIVER_ENDPOINT, &buf[..n]);
        if rc < 0 {
            return Err(ScanoutError::TransportFailed);
        }
        Ok(())
    }

    fn handle_scanout_payload(&mut self, payload: &[u8]) -> Option<ScanoutEvent> {
        if payload.len() < 4 {
            return None;
        }
        let tag_bytes: [u8; 4] = payload[0..4].try_into().ok()?;
        let tag = MsgTag::from_u32(u32::from_le_bytes(tag_bytes))?;
        match tag {
            MsgTag::FrameDisplayed => {
                let (display_id, seq, present_time) = decode_frame_displayed(payload)?;
                self.last_displayed_seq = Some(seq);
                self.last_present_time = present_time;
                Some(ScanoutEvent::FrameDisplayed { display_id, seq, present_time_ticks: present_time })
            }
            // Other event types (DisplayConnected/Disconnected/etc.)
            // not handled in v0 — single-display, no hotplug. Drop
            // silently rather than fail loudly.
            _ => None,
        }
    }

    fn request_mode(&mut self, _display_id: u32, _mode: Mode) -> Result<(), ScanoutError> {
        // Limine FB has no mode change. Real backends (virtio-gpu,
        // intel) implement this.
        Err(ScanoutError::ModeRejected)
    }
}

// ============================================================================
// Backend dispatch
// ============================================================================

/// Runtime backend selection. Enum dispatch today (only Headless +
/// Limine known); will become `Box<dyn ScanoutBackend>` per ADR-014 once
/// virtio-gpu / Intel land and a heap allocator is wired in user-space.
pub enum Backend {
    Headless(HeadlessBackend),
    Limine(LimineFbBackend),
}

impl ScanoutBackend for Backend {
    fn enumerate_displays(&self) -> &[DisplayInfo] {
        match self {
            Self::Headless(b) => b.enumerate_displays(),
            Self::Limine(b) => b.enumerate_displays(),
        }
    }

    fn attach_scanout(&mut self, display_id: u32) -> Result<ScanoutBuffer, ScanoutError> {
        match self {
            Self::Headless(b) => b.attach_scanout(display_id),
            Self::Limine(b) => b.attach_scanout(display_id),
        }
    }

    fn submit_frame(&mut self, display_id: u32, damage: &[Rect]) -> Result<(), ScanoutError> {
        match self {
            Self::Headless(b) => b.submit_frame(display_id, damage),
            Self::Limine(b) => b.submit_frame(display_id, damage),
        }
    }

    fn handle_scanout_payload(&mut self, payload: &[u8]) -> Option<ScanoutEvent> {
        match self {
            Self::Headless(b) => b.handle_scanout_payload(payload),
            Self::Limine(b) => b.handle_scanout_payload(payload),
        }
    }

    fn request_mode(&mut self, display_id: u32, mode: Mode) -> Result<(), ScanoutError> {
        match self {
            Self::Headless(b) => b.request_mode(display_id, mode),
            Self::Limine(b) => b.request_mode(display_id, mode),
        }
    }
}
