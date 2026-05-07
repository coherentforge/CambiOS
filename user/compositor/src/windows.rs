// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Compositor-internal window management — Phase Scanout-3 (ADR-011).
//!
//! Wire-format types for the client ↔ compositor protocol live in
//! `cambios-libgui-proto`; this module is the compositor's *server-side*
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

use cambios_libgui_proto::{
    decode_create_window, decode_destroy_window, decode_frame_ready_header, encode_error_response,
    encode_welcome_client, GuiError, MsgTag, PixelFormat, MAX_WINDOWS, MAX_WINDOW_DIMENSION,
};
use cambios_libsys as sys;

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
    /// Top-left position in scanout coordinates. New windows land at
    /// `(0, 0)` today; movement comes via the `DragWindowBy` wire
    /// message (libgui-proto). Signed because partial off-screen
    /// placement is allowed (negative values clip the window's left/
    /// top edges in the blit; positive values past the scanout edge
    /// clip the right/bottom).
    pub x: i32,
    pub y: i32,
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
    /// Z-order rank within the same-client back-to-front stack —
    /// 0 = back, larger = front. v0 supports same-client layering
    /// only (e.g., terminal-window's watermark + terminal pair); a
    /// future window-manager service handles cross-client stacking.
    pub z_order: u8,
    /// Cross-client front ordering. Assigned monotonically at
    /// `CreateWindow` time and bumped to the next value on
    /// raise-to-front (pointer click, future explicit raise API).
    /// `composite_and_present` sorts back-to-front ascending by this
    /// field; `front()` returns the live window with the highest
    /// `front_seq`. Replaces the original cross-client purpose of
    /// `z_order`; `z_order` continues to express same-client layering
    /// as a tie-breaker is left unused for v1 — same-client raise
    /// preservation is a known v1 limitation (terminal-window's
    /// watermark + text layers can split across other windows after
    /// a click on just one of them).
    pub front_seq: u32,
    /// True if the surface's high byte is alpha — compositor blends
    /// this window over whatever sits below in the stack rather than
    /// overwriting. False for the legacy XRGB-overwrite path.
    pub alpha_blend: bool,
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
    /// Monotonic counter feeding `Window::front_seq`. Skip 0 on wrap
    /// — same convention as `next_window_id`. Bumped both at create
    /// (so new windows naturally land in front of older ones) and at
    /// raise-on-click (so the clicked window comes to front).
    next_front_seq: u32,
}

impl WindowTable {
    pub const fn new() -> Self {
        Self {
            windows: [None; MAX_WINDOWS],
            next_window_id: 1,
            next_front_seq: 1,
        }
    }

    /// Allocate a fresh `window_id`, skipping 0 on wrap.
    fn alloc_window_id(&mut self) -> u32 {
        let id = self.next_window_id;
        let next = self.next_window_id.wrapping_add(1);
        self.next_window_id = if next == 0 { 1 } else { next };
        id
    }

    /// Allocate the next `front_seq` value. Same wrap discipline as
    /// `alloc_window_id`. Used at create-time and on raise-on-click.
    pub fn alloc_front_seq(&mut self) -> u32 {
        let s = self.next_front_seq;
        let next = self.next_front_seq.wrapping_add(1);
        self.next_front_seq = if next == 0 { 1 } else { next };
        s
    }

    /// Raise a window to the front by bumping its `front_seq` to the
    /// next monotonic value. No-op if the window id is unknown.
    pub fn raise(&mut self, window_id: u32) {
        if let Some(idx) = self.find_window(window_id) {
            let seq = self.alloc_front_seq();
            if let Some(w) = self.get_mut(idx) {
                w.front_seq = seq;
            }
        }
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

    /// Pick the front-most live window — highest `front_seq` wins,
    /// ties broken by table order (first-live-in-table). Used for
    /// input routing: the front window receives forwarded events;
    /// back layers (e.g. terminal-window's watermark canvas) are
    /// render-only and never receive input.
    pub fn front(&self) -> Option<&Window> {
        self.iter().max_by_key(|w| w.front_seq)
    }

    /// Hit-test a screen-absolute point against live windows from
    /// front-most to back-most. Returns the window id of the first
    /// rect that contains the point, or `None` if the point lies
    /// outside every window. Used by `pump_input_once` for
    /// raise-on-click on `PointerButton` events.
    pub fn hit_test(&self, screen_x: i32, screen_y: i32) -> Option<u32> {
        // Collect live windows + sort descending by front_seq so we
        // try the front-most candidate first. Bounded array, no
        // allocation.
        let mut sorted: [Option<&Window>; MAX_WINDOWS] = [None; MAX_WINDOWS];
        let mut count = 0usize;
        for w in self.iter() {
            if count < MAX_WINDOWS {
                sorted[count] = Some(w);
                count += 1;
            }
        }
        // Insertion sort descending by front_seq.
        for i in 1..count {
            let mut j = i;
            while j > 0 {
                let lo = sorted[j - 1].unwrap().front_seq;
                let hi = sorted[j].unwrap().front_seq;
                if hi > lo {
                    sorted.swap(j, j - 1);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
        for slot in sorted[..count].iter() {
            let w = slot.unwrap();
            let right = w.x + w.width as i32;
            let bottom = w.y + w.height as i32;
            if screen_x >= w.x && screen_x < right && screen_y >= w.y && screen_y < bottom {
                return Some(w.window_id);
            }
        }
        None
    }

    /// Drop windows whose surface channel is in a teardown-terminal
    /// state.
    ///
    /// The userspace half of ADR-007 Divergence 7 (tombstone-on-
    /// revoke). When a libgui client exits without sending an
    /// explicit `DestroyWindow`, the kernel revokes the surface
    /// channel and remaps the compositor's RO mapping to a shared
    /// zero page. Reads no longer fault, but the WindowTable still
    /// holds the dead entry — subsequent composite passes blit
    /// zeros from the tombstone forever (visual artifact, not a
    /// crash). This pass calls `sys::channel_info` on each live
    /// window and drops any whose channel has transitioned to
    /// `Revoking` / `Revoked` / `Closed`, or whose channel id is
    /// stale (`channel_info` returns negative when the slot has been
    /// freed and the generation bumped).
    ///
    /// **Does NOT reap `AwaitingAttach` channels** — that's the
    /// transient pre-`Active` state between
    /// `compositor: channel_create` and `client: channel_attach`,
    /// during which the WindowTable entry already exists but the
    /// client hasn't received `WelcomeClient` yet. Reaping here
    /// would drop windows the moment they're created and trigger
    /// the `composite_blank_and_present` "last window gone" path on
    /// the very next iteration, blanking the scanout to black.
    /// Observed first under `play super-sprouty-o → Ctrl+Q` where
    /// terminal-window's reopen path created a new (still-AwaitingAttach)
    /// window and reap immediately dropped it.
    ///
    /// Bounded cost: one syscall per live window, plus one
    /// 46-byte stack buffer. Called once per main-loop iteration so
    /// dead windows are reaped within one frame of the client exit.
    /// Returns the count reaped (0 in steady state).
    pub fn reap_dead_channels(&mut self) -> usize {
        let mut info = [0u8; 46];
        let mut reaped = 0usize;
        for slot in self.windows.iter_mut() {
            if let Some(w) = slot.as_ref() {
                let rc = sys::channel_info(w.surface_channel_id, &mut info);
                let dead = if rc == 0 {
                    // info[0] is the ChannelState discriminant.
                    // AwaitingAttach + Active are alive; everything
                    // else is mid- or post-teardown.
                    matches!(
                        info[0],
                        sys::CHANNEL_STATE_REVOKING
                            | sys::CHANNEL_STATE_REVOKED
                            | sys::CHANNEL_STATE_CLOSED
                    )
                } else {
                    // channel id stale (slot freed + generation bumped) —
                    // treat as dead, the client is gone.
                    true
                };
                if dead {
                    *slot = None;
                    reaped += 1;
                }
            }
        }
        reaped
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
        MsgTag::DragWindowBy => {
            handle_drag_window_by(payload, sender_principal, from_endpoint, window_table);
            None
        }
        // 0x40xx tags (compositor → client) must never arrive here.
        MsgTag::WelcomeClient
        | MsgTag::WindowClosed
        | MsgTag::ErrorResponse
        | MsgTag::InputEvent => {
            send_error(from_endpoint, GuiError::InvalidMessage);
            None
        }
    }
}

/// Apply a client-requested window translation. The client sends
/// this when the user drags inside the title bar (libgui's
/// `decorate()` drag region); compositor adjusts the window's
/// `(x, y)` and the next composite picks up the new position.
///
/// Authority: only the window's owning Principal may move it.
/// Future authz hardening can add an "is the requesting endpoint
/// the same one CreateWindow used" check; today the kernel-stamped
/// `sender_principal` ownership match is sufficient.
fn handle_drag_window_by(
    payload: &[u8],
    sender_principal: &[u8; 32],
    from_endpoint: u32,
    window_table: &mut WindowTable,
) {
    let (window_id, dx, dy) = match cambios_libgui_proto::decode_drag_window_by(payload) {
        Some(t) => t,
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
    let w = match window_table.get_mut(slot) {
        Some(w) => w,
        None => {
            send_error(from_endpoint, GuiError::NoSuchWindow);
            return;
        }
    };
    if &w.owner_principal != sender_principal {
        // Same convention as `handle_frame_ready`: a foreign-Principal
        // request to manipulate a window is reported as
        // `NoSuchWindow` (the docs explicitly call this case out).
        send_error(from_endpoint, GuiError::NoSuchWindow);
        return;
    }
    w.x = w.x.saturating_add(dx);
    w.y = w.y.saturating_add(dy);
}

fn handle_create_window(
    payload: &[u8],
    sender_principal: &[u8; 32],
    from_endpoint: u32,
    window_table: &mut WindowTable,
) {
    let req = match decode_create_window(payload) {
        Some(r) => r,
        None => {
            send_error(from_endpoint, GuiError::InvalidMessage);
            return;
        }
    };
    let width = req.width;
    let height = req.height;
    // Reply routing: prefer the explicit `reply_endpoint` from the
    // payload (multi-layer clients need this — the kernel-stamped
    // `from_endpoint` is sticky to the FIRST register_endpoint call
    // and won't match the layer's actual endpoint). Legacy clients
    // pass 0 to mean "use the kernel-stamped sender" — same shape as
    // pre-z-index single-window CreateWindow.
    let reply_to = if req.reply_endpoint != 0 {
        req.reply_endpoint
    } else {
        from_endpoint
    };

    if width == 0 || height == 0 || width > MAX_WINDOW_DIMENSION || height > MAX_WINDOW_DIMENSION {
        send_error(reply_to, GuiError::InvalidDimensions);
        return;
    }

    let slot_idx = match window_table.find_slot() {
        Some(i) => i,
        None => {
            send_error(reply_to, GuiError::TooManyWindows);
            return;
        }
    };

    // Allocate the surface channel. pitch = width × 4 (XRGB8888 or
    // ARGB8888 — same byte layout, only the high-byte interpretation
    // changes per the window's `alpha_blend` flag). size_pages rounds
    // up to a page boundary.
    let pitch = width * SURFACE_BYTES_PER_PIXEL;
    let bytes = (pitch as u64) * (height as u64);
    let size_pages = ((bytes + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as u32;

    let mut surface_vaddr: u64 = 0;
    let rc = sys::channel_create(size_pages, sender_principal, CHANNEL_ROLE_CONSUMER, &mut surface_vaddr);
    if rc < 0 {
        send_error(reply_to, GuiError::SurfaceAllocFailed);
        return;
    }
    let channel_id = rc as u64;

    let window_id = window_table.alloc_window_id();
    let front_seq = window_table.alloc_front_seq();
    window_table.windows[slot_idx] = Some(Window {
        window_id,
        owner_principal: *sender_principal,
        // Store the explicit reply endpoint so input forwarding +
        // future protocol replies route to the layer's own queue,
        // not to whatever the kernel happened to stamp first.
        client_endpoint: reply_to,
        // New windows land at scanout origin in v1. The
        // `DragWindowBy` wire message (libgui-proto) lets clients
        // move themselves; future placement policy (e.g.
        // "stagger by N pixels per new window") is a follow-up.
        x: 0,
        y: 0,
        width,
        height,
        pitch,
        surface_channel_id: channel_id,
        surface_vaddr,
        last_client_seq: 0,
        z_order: req.z_order,
        front_seq,
        alpha_blend: req.alpha_blend,
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
    let _ = sys::write(reply_to, &reply[..n]);
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
    /// Top-left position in scanout coordinates (mirrored from
    /// `Window::{x, y}` so the blit functions don't need a
    /// `&WindowTable` borrow).
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub surface_vaddr: u64,
}

impl From<&Window> for WindowView {
    fn from(w: &Window) -> Self {
        Self {
            window_id: w.window_id,
            x: w.x,
            y: w.y,
            width: w.width,
            height: w.height,
            pitch: w.pitch,
            surface_vaddr: w.surface_vaddr,
        }
    }
}
