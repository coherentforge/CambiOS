// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Compositor-internal window management — Phase Scanout-3 (ADR-011).
//!
//! Wire-format types for the client ↔ compositor protocol live in
//! `arcos-libgui-proto`; this module is the compositor's *server-side*
//! state — the `WindowTable` of live windows, surface-channel
//! ownership, and the message dispatch the main loop calls into.
//!
//! ## Scope of v0
//!
//! - Fixed `[Option<Window>; MAX_WINDOWS]` table (no heap in userspace
//!   yet; same pattern the kernel uses for process tables).
//! - One surface channel per window, `ChannelRole::Consumer` (creator
//!   reads = compositor; peer writes = client).
//! - `window_id`s are monotonic `u32`s, never reused within a boot
//!   (32-bit counter ≈ 7 years at 20 new windows/sec, out-of-scope to
//!   worry about yet).
//! - No z-order, no focus, no damage tracking — landing in Scanout-4+.
//!   `CreateWindow` / `FrameReady` / `DestroyWindow` is the v0
//!   verification surface.
//!
//! The back-side (compositor → scanout-driver) lives in `scanout.rs`;
//! this module never talks to a `ScanoutBackend` — the render-loop glue
//! in `main.rs` is what ties front and back together each frame.

use arcos_libgui_proto::{
    decode_create_window, decode_destroy_window, decode_frame_ready_header, encode_error_response,
    encode_welcome_client, GuiError, MsgTag, PixelFormat, MAX_WINDOWS, MAX_WINDOW_DIMENSION,
};
use arcos_libsys as sys;

/// Role discriminant accepted by `SYS_CHANNEL_CREATE`. Consumer =
/// creator reads (compositor), peer writes (client). Numeric constant
/// rather than an import because libsys exposes channel_create as
/// `role: u32` (no enum type).
const CHANNEL_ROLE_CONSUMER: u32 = 1;

/// Bytes per pixel for v0 surfaces. XRGB8888 is the only format the
/// compositor advertises to clients today; richer negotiation lands
/// with HDR.
const SURFACE_BPP: u16 = 32;
const SURFACE_BYTES_PER_PIXEL: u32 = 4;
const PAGE_SIZE: u32 = 4096;

/// One entry in the compositor's window table.
///
/// `Copy` so `[Option<Window>; MAX_WINDOWS]` can be zero-initialised
/// via `[None; MAX_WINDOWS]`; all fields are plain values, no
/// destructors to run at the moment.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    pub window_id: u32,
    /// Client Principal that created this window. Future authz
    /// (can-this-process-destroy-that-window) compares against this.
    pub owner_principal: [u8; 32],
    /// Endpoint the compositor replies to (REPLY_ENDPOINT of the
    /// client at CreateWindow time).
    pub client_endpoint: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub surface_channel_id: u64,
    /// Compositor's mapping of the surface channel (client writes
    /// here via its own mapping; we read/composite from here).
    pub surface_vaddr: u64,
    /// Sequence of the last FrameReady the client sent, for
    /// diagnostics / future damage-aggregation.
    pub last_client_seq: u32,
}

/// Fixed-size slab of live windows + a monotonic id counter.
///
/// Scanout-3 never frees from the middle of the table except via
/// `DestroyWindow`; there's no handle-table reuse policy yet. When
/// the `next_window_id` counter wraps it skips 0 (reserved as
/// "invalid / no window").
pub struct WindowTable {
    windows: [Option<Window>; MAX_WINDOWS],
    next_window_id: u32,
}

impl WindowTable {
    pub const fn new() -> Self {
        Self {
            windows: [None; MAX_WINDOWS],
            next_window_id: 1,
        }
    }

    /// Allocate a fresh `window_id`, skipping 0 on wrap.
    fn alloc_window_id(&mut self) -> u32 {
        let id = self.next_window_id;
        let next = self.next_window_id.wrapping_add(1);
        self.next_window_id = if next == 0 { 1 } else { next };
        id
    }

    fn find_slot(&self) -> Option<usize> {
        self.windows.iter().position(Option::is_none)
    }

    /// Lookup a live window by id. Returns the slot index so callers
    /// can mutate state without re-scanning.
    fn find_window(&self, window_id: u32) -> Option<usize> {
        self.windows.iter().position(|w| match w {
            Some(w) => w.window_id == window_id,
            None => false,
        })
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut Window> {
        self.windows.get_mut(idx).and_then(|w| w.as_mut())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Window> {
        self.windows.iter().filter_map(Option::as_ref)
    }
}

// ============================================================================
// Client message dispatch
// ============================================================================

/// Dispatch a client-direction payload (tag high nibble 0x3). Called
/// by main.rs after it peeks the tag. `sender_principal` is the
/// kernel-stamped identity from the `recv_msg` header;
/// `from_endpoint` is the client's reply endpoint.
///
/// Never blocks, never allocates (beyond the fixed table). On any
/// client error, sends an `ErrorResponse` back to `from_endpoint`
/// and returns.
pub fn handle_client_payload(
    payload: &[u8],
    sender_principal: &[u8; 32],
    from_endpoint: u32,
    window_table: &mut WindowTable,
) -> Option<WindowView> {
    if payload.len() < 4 {
        send_error(from_endpoint, GuiError::InvalidMessage);
        return None;
    }
    let tag_bytes: [u8; 4] = payload[0..4].try_into().ok()?;
    let tag = match MsgTag::from_u32(u32::from_le_bytes(tag_bytes)) {
        Some(t) => t,
        None => {
            send_error(from_endpoint, GuiError::InvalidMessage);
            return None;
        }
    };
    match tag {
        MsgTag::CreateWindow => {
            handle_create_window(payload, sender_principal, from_endpoint, window_table);
            None
        }
        MsgTag::FrameReady => {
            handle_frame_ready(payload, sender_principal, from_endpoint, window_table)
        }
        MsgTag::DestroyWindow => {
            handle_destroy_window(payload, sender_principal, from_endpoint, window_table);
            None
        }
        // 0x40xx tags (compositor → client) must never arrive here.
        MsgTag::WelcomeClient | MsgTag::WindowClosed | MsgTag::ErrorResponse => {
            send_error(from_endpoint, GuiError::InvalidMessage);
            None
        }
    }
}

fn handle_create_window(
    payload: &[u8],
    sender_principal: &[u8; 32],
    from_endpoint: u32,
    window_table: &mut WindowTable,
) {
    let (width, height) = match decode_create_window(payload) {
        Some(t) => t,
        None => {
            send_error(from_endpoint, GuiError::InvalidMessage);
            return;
        }
    };

    if width == 0 || height == 0 || width > MAX_WINDOW_DIMENSION || height > MAX_WINDOW_DIMENSION {
        send_error(from_endpoint, GuiError::InvalidDimensions);
        return;
    }

    let slot_idx = match window_table.find_slot() {
        Some(i) => i,
        None => {
            send_error(from_endpoint, GuiError::TooManyWindows);
            return;
        }
    };

    // Allocate the surface channel. pitch = width × 4 (XRGB8888, no
    // scanline padding). size_pages rounds up to a page boundary.
    let pitch = width * SURFACE_BYTES_PER_PIXEL;
    let bytes = (pitch as u64) * (height as u64);
    let size_pages = ((bytes + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as u32;

    let mut surface_vaddr: u64 = 0;
    let rc = sys::channel_create(size_pages, sender_principal, CHANNEL_ROLE_CONSUMER, &mut surface_vaddr);
    if rc < 0 {
        send_error(from_endpoint, GuiError::SurfaceAllocFailed);
        return;
    }
    let channel_id = rc as u64;

    let window_id = window_table.alloc_window_id();
    window_table.windows[slot_idx] = Some(Window {
        window_id,
        owner_principal: *sender_principal,
        client_endpoint: from_endpoint,
        width,
        height,
        pitch,
        surface_channel_id: channel_id,
        surface_vaddr,
        last_client_seq: 0,
    });

    sys::print(b"[COMPOSITOR] window created\r\n");

    // Send WelcomeClient reply.
    let mut reply = [0u8; 64];
    let n = match encode_welcome_client(
        &mut reply,
        window_id,
        channel_id,
        width,
        height,
        pitch,
        SURFACE_BPP,
        PixelFormat::Xrgb8888,
    ) {
        Some(n) => n,
        None => return, // Buffer too small — impossible for a 32-byte message
    };
    let _ = sys::write(from_endpoint, &reply[..n]);
}

fn handle_frame_ready(
    payload: &[u8],
    sender_principal: &[u8; 32],
    from_endpoint: u32,
    window_table: &mut WindowTable,
) -> Option<WindowView> {
    let (window_id, seq, _damage_count) = match decode_frame_ready_header(payload) {
        Some(t) => t,
        None => {
            send_error(from_endpoint, GuiError::InvalidMessage);
            return None;
        }
    };

    let slot = match window_table.find_window(window_id) {
        Some(s) => s,
        None => {
            send_error(from_endpoint, GuiError::NoSuchWindow);
            return None;
        }
    };

    // Ownership check — only the creating Principal may drive a
    // window. Once real multi-tenant clients exist this is the
    // spoofing defense.
    let w = match window_table.get_mut(slot) {
        Some(w) => w,
        None => return None,
    };
    if &w.owner_principal != sender_principal {
        send_error(from_endpoint, GuiError::NoSuchWindow);
        return None;
    }
    w.last_client_seq = seq;

    // Damage rects are parsed/ignored for v0 — we composite the full
    // surface every frame. Per-rect composition lands in Scanout-4
    // with damage tracking. Keeping the decode path exercised so the
    // wire protocol ages in the real message flow.
    Some(WindowView::from(&*w))
}

fn handle_destroy_window(
    payload: &[u8],
    sender_principal: &[u8; 32],
    from_endpoint: u32,
    window_table: &mut WindowTable,
) {
    let window_id = match decode_destroy_window(payload) {
        Some(id) => id,
        None => {
            send_error(from_endpoint, GuiError::InvalidMessage);
            return;
        }
    };

    let slot = match window_table.find_window(window_id) {
        Some(s) => s,
        None => {
            send_error(from_endpoint, GuiError::NoSuchWindow);
            return;
        }
    };

    let channel_id = {
        let w = match window_table.get_mut(slot) {
            Some(w) => w,
            None => return,
        };
        if &w.owner_principal != sender_principal {
            send_error(from_endpoint, GuiError::NoSuchWindow);
            return;
        }
        w.surface_channel_id
    };

    let _ = sys::channel_close(channel_id);
    window_table.windows[slot] = None;
}

// ============================================================================
// Helpers
// ============================================================================

/// Best-effort error response. If the encode or write fails, log it
/// but don't propagate — an error-on-error is the compositor's fault,
/// not the client's, and there's nothing sensible to surface back.
fn send_error(from_endpoint: u32, error: GuiError) {
    let mut buf = [0u8; 16];
    if let Some(n) = encode_error_response(&mut buf, error) {
        let _ = sys::write(from_endpoint, &buf[..n]);
    }
}

/// Snapshot of a window as the render path wants to consume it. Kept
/// separate from `Window` (internal table state) so the render path
/// doesn't reach into the table. Returned from `handle_client_payload`
/// on a successful FrameReady — main.rs takes this and does the
/// surface → scanout blit + downstream FrameReady submit.
#[derive(Clone, Copy, Debug)]
pub struct WindowView {
    pub window_id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub surface_vaddr: u64,
}

impl From<&Window> for WindowView {
    fn from(w: &Window) -> Self {
        Self {
            window_id: w.window_id,
            width: w.width,
            height: w.height,
            pitch: w.pitch,
            surface_vaddr: w.surface_vaddr,
        }
    }
}
