// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Scanout-driver protocol types and backend trait — Phase Scanout-1 (ADR-014).
//!
//! The compositor talks to whichever scanout-driver service has registered
//! through this trait. Backends implement `ScanoutBackend` and translate
//! the trait calls into IPC messages on `SCANOUT_DRIVER_ENDPOINT`. The
//! compositor itself never touches hardware — see ADR-014 § Module Boundary.
//!
//! This file holds:
//! - Wire-format types shared with every scanout-driver
//! - The `ScanoutBackend` trait the compositor uses internally
//! - `HeadlessBackend` — the no-display fallback, used when no
//!   scanout-driver registers within `SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS`

// ============================================================================
// Bounds
// ============================================================================

/// SCAFFOLDING: max physical displays a single scanout-driver advertises.
/// Why: matches `MAX_FRAMEBUFFERS = 8` in [src/boot/mod.rs] (BootInfo) — the
///      compositor can't be told about more displays than the boot protocol
///      can hold, and the realistic ceiling for a single workstation
///      (consumer + pro multi-monitor rigs cap around 6) is well within 8.
///      This is a *practical-ceiling* bound, not a v1-estimate-times-4 bound:
///      we are not building a graphics subsystem to drive 32 displays.
/// Replace when: BootInfo's MAX_FRAMEBUFFERS grows for multi-monitor reasons,
///      or a real workload appears with >6 displays driven by one driver.
///      Multi-driver topologies (integrated + discrete GPU) deferred to a
///      future ADR per ADR-014 § Open Questions.
pub const MAX_DISPLAYS_PER_DRIVER: usize = 8;

/// SCAFFOLDING: max damage rects per FrameReady message.
/// Why: must fit in the 256-byte control IPC payload alongside the message
///      header (display_id, msg type, sequence). 16 rects × 12 B (x,y,w,h
///      as u16 each) = 192 B leaves ~60 B for the envelope. Above 16 rects
///      the compositor sends "full surface dirty" — strict upper bound that
///      simple drivers (Limine fallback) can rely on.
/// Replace when: never expected to. Compositors aggregate damage when they
///      have many small rects; full-surface fallback handles the worst case.
pub const MAX_DAMAGE_RECTS_PER_FRAME: usize = 16;

/// TUNING: ticks the compositor waits at startup for a scanout-driver to
/// register before falling back to `HeadlessBackend`.
/// Trades: time-to-headless-fallback vs. time-for-driver-init. QEMU drivers
/// come up in milliseconds; bare-metal drivers may need PCI probe + EDID
/// I²C reads + GPU firmware load. 500 ticks @ 100 Hz = 5 s, generous on
/// QEMU and tight-but-usable on real hardware.
/// Revisit: first bare-metal Intel-UHD bring-up — measure observed init,
/// set timeout to ~3× observed median.
pub const SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS: u64 = 500;

// ============================================================================
// Endpoint constants (well-known, see ADR-014 § Endpoints)
// ============================================================================

/// IPC endpoint where scanout-drivers receive control messages from the
/// compositor (RegisterCompositor, RequestScanoutBuffer, FrameReady, ...).
/// The active scanout-driver registers this endpoint at boot.
pub const SCANOUT_DRIVER_ENDPOINT: u32 = 27;

/// IPC endpoint where the compositor receives scanout-driver async events
/// (WelcomeCompositor, DisplayConnected, FrameDisplayed, ...). The
/// compositor registers this endpoint at boot — singleton-by-Principal.
pub const COMPOSITOR_ENDPOINT: u32 = 28;

// ============================================================================
// Wire-format types (shared with every scanout-driver implementation)
// ============================================================================

/// Display lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DisplayState {
    Disconnected = 0,
    Connected = 1,
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

/// Geometry of a display's current scan mode.
#[derive(Clone, Copy, Debug)]
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
///
/// Sent by the scanout-driver at handshake and on hotplug. Compositor reads
/// this to lay out windows and choose backing-scale per display.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DisplayInfo {
    pub display_id: u32,
    pub state: DisplayState,
    pub geometry: Geometry,
    /// Per-display backing scale factor × 100 (1×=100, 2×=200, fractional 1.25×=125).
    pub backing_scale: u16,
    pub refresh_hz: u16,
    pub format: PixelFormat,
    /// Bitfield: bit 0 = HDR10, bit 1 = VRR, bit 2 = partial-update support, ...
    pub capabilities: u32,
    /// Blake3 of full EDID, for stable identity across reboots / hotplug cycles.
    pub edid_hash: [u8; 32],
}

/// Damage rectangle in display-local coordinates (post-composition pixels).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
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

/// Errors from `ScanoutBackend` operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanoutError {
    /// No display with the given id is currently attached.
    NoSuchDisplay,
    /// Mode was rejected by the driver (unsupported by hardware / EDID).
    ModeRejected,
    /// Frame submitted while a previous frame for this display is still
    /// in flight — driver applies back-pressure. Compositor should slow
    /// its render loop.
    FrameDropped,
    /// IPC transport failure (driver unreachable, capability lost, etc.).
    TransportFailed,
    /// Backend is in headless mode — no displays exist.
    Headless,
}

/// Asynchronous event from the scanout-driver.
#[derive(Clone, Copy, Debug)]
pub enum ScanoutEvent {
    DisplayConnected { info: DisplayInfo, scanout_channel_id: u64 },
    DisplayDisconnected { display_id: u32 },
    DisplayModeChanged { info: DisplayInfo, new_scanout_channel_id: u64 },
    FrameDisplayed { display_id: u32, present_time_ticks: u64 },
}

// ============================================================================
// ScanoutBackend trait — the compositor's internal abstraction
// ============================================================================

/// What the compositor can ask of any scanout-driver.
///
/// Implemented by `HeadlessBackend` (no-display fallback) and, in future,
/// per-backend IPC client structs (`VirtioGpuBackend`, `IntelGpuBackend`,
/// `LimineFbBackend`). The compositor uses dyn dispatch on
/// `Box<dyn ScanoutBackend>` — see ADR-014 § "Trait abstraction in the
/// compositor (userspace dyn dispatch)" for the rationale.
pub trait ScanoutBackend {
    /// All currently-connected displays this backend knows about.
    fn enumerate_displays(&self) -> &[DisplayInfo];

    /// Attach to a display's scanout buffer and return a handle to the
    /// mapped region. Driver allocates; compositor writes.
    fn attach_scanout(&mut self, display_id: u32) -> Result<ScanoutBuffer, ScanoutError>;

    /// Tell the driver this frame is ready, optionally with damage rects.
    /// `damage` is a *hint*, not a constraint; conformant drivers may ignore
    /// it and do full-frame flips. If `damage.len() > MAX_DAMAGE_RECTS_PER_FRAME`,
    /// compositor MUST send "full surface dirty" instead.
    fn submit_frame(&mut self, display_id: u32, damage: &[Rect]) -> Result<(), ScanoutError>;

    /// Non-blocking poll for a scanout event (hotplug, ack, mode change).
    fn poll_event(&mut self) -> Option<ScanoutEvent>;

    /// Request a mode change for a display (e.g. user resized resolution).
    /// Driver responds asynchronously with `DisplayModeChanged` (success)
    /// or `ModeRejected` error.
    fn request_mode(&mut self, display_id: u32, mode: Mode) -> Result<(), ScanoutError>;
}

// ============================================================================
// HeadlessBackend — the no-display fallback
// ============================================================================

/// The fallback backend when no scanout-driver registers within
/// `SCANOUT_DRIVER_HANDSHAKE_TIMEOUT_TICKS`. Compositor remains alive,
/// accepts client connections (future), and silently swallows all
/// display operations. Useful for headless servers, CI, and pre-driver
/// bring-up.
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

    fn poll_event(&mut self) -> Option<ScanoutEvent> {
        None
    }

    fn request_mode(&mut self, _display_id: u32, _mode: Mode) -> Result<(), ScanoutError> {
        Err(ScanoutError::Headless)
    }
}
