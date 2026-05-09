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

use alloc::vec::Vec;
use cambios_libgui_proto::{
    decode_create_window, decode_destroy_window, decode_frame_ready_header,
    decode_request_resize, encode_error_response, encode_welcome_client, encode_window_resized,
    GuiError, MsgTag, PixelFormat, MAX_WINDOWS, MAX_WINDOW_DIMENSION,
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

/// SCAFFOLDING: maximum requested linger duration in milliseconds.
/// Compositor silently clamps `DestroyWindow.linger_ms` to this cap.
/// Why: lingering windows occupy a slot in `WindowTable.lingerers`
/// and a backing pixel buffer on the compositor's heap. A bound caps
/// blast radius if a client requests an unreasonable duration. 5 s
/// covers the v1-endgame consumers we know — splash transitions
/// (~800 ms typical), app-quit fade-out (~300 ms), graceful-crash
/// cushion (~1-3 s). Suspend / resume / minimize-to-taskbar do not
/// fit the "hold for N ms then reap" shape and will design their
/// own primitive when they land.
/// Replace when: a real consumer surfaces a linger request between
/// 5 and 30 s and the use case is genuinely "show a frozen frame
/// for that long" rather than a different lifecycle entirely.
const MAX_LINGER_MS: u32 = 5_000;

/// SCAFFOLDING: max concurrent lingerers.
/// Why: each lingerer holds a pixel-sized backing buffer
/// (width × height × 4 B). On a 16 MiB compositor heap with the
/// v1 typical lingerer ~1-3 MiB, 4 concurrent fits comfortably.
/// `try_reserve_exact` on the buffer alloc is the heap-side bound;
/// this constant is the structural bound on the side-list itself.
/// Replace when: heap grows to a size where >4 simultaneous
/// transitions become routine (multi-app launch sequences,
/// virtual-desktop swipe-out, expose / mission-control batch
/// minimize) — at that point this becomes a TUNING value rather
/// than a structural cap.
const MAX_LINGERERS: usize = 4;

/// Kernel timer tick rate is 100 Hz (CLAUDE.md § Timer / Preemptive
/// Scheduling). Each `sys::get_time` tick is 10 ms.
const MS_PER_TICK: u64 = 10;

/// Convert a millisecond duration to ticks, rounding up so the
/// caller never gets shorter than the requested duration.
fn ms_to_ticks(ms: u32) -> u64 {
    (ms as u64 + MS_PER_TICK - 1) / MS_PER_TICK
}

/// Which edge or corner of a window an active resize-drag is anchored
/// to. Returned by `WindowTable::hit_test_resize`; consumed by
/// `main.rs::commit_resize_drag` to compute the pending dimensions
/// from a pointer delta. Pure pure pure — no associated data, just the
/// shape of the gesture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeEdge {
    Top,
    Bottom,
    Left,
    Right,
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
}

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

/// One window held in linger state — its owner sent
/// `DestroyWindow { linger_ms > 0 }` and the compositor copied the
/// surface's last-rendered pixels into a private buffer so the
/// frame outlives the client's exit. Detached from the active
/// `windows[]` table — lingerers are excluded from focus, input,
/// and hit-test, but still composited from the backing buffer
/// until `deadline_ticks` elapses.
pub struct LingerEntry {
    /// Snapshot of the window at destroy-with-linger time. Geometry,
    /// `front_seq` (so layering is preserved), `alpha_blend`,
    /// `owner_principal` (diagnostic). `surface_channel_id` is a
    /// stale breadcrumb — the channel was closed when the entry was
    /// created; do not use it for I/O.
    pub window: Window,
    /// Owned copy of the window's last-rendered pixels. Length is
    /// `width * height` u32 entries. Heap-allocated; data pointer
    /// is stable for the entry's lifetime — no push / reserve is
    /// performed after the initial fill, so `Vec::as_ptr` returns
    /// the same address across composite passes.
    pub pixels: Vec<u32>,
    /// Tick (per `sys::get_time`) at which this entry should be
    /// reaped. `WindowTable::reap_expired_lingers` drops entries
    /// whose deadline has passed.
    pub deadline_ticks: u64,
}

/// Fixed-size slab of live windows + a monotonic id counter.
///
/// Scanout-3 never frees from the middle of the table except via
/// `DestroyWindow`; there's no handle-table reuse policy yet. When
/// the `next_window_id` counter wraps it skips 0 (reserved as
/// "invalid / no window").
pub struct WindowTable {
    windows: [Option<Window>; MAX_WINDOWS],
    /// Side-list of windows in linger state. Bounded by
    /// `MAX_LINGERERS` (structural) and the compositor heap
    /// (per-buffer). Composite path walks both `windows[]` (active)
    /// and `lingerers` (held frames) sorted by `front_seq`.
    lingerers: Vec<LingerEntry>,
    next_window_id: u32,
    /// Monotonic counter feeding `Window::front_seq`. Skip 0 on wrap
    /// — same convention as `next_window_id`. Bumped both at create
    /// (so new windows naturally land in front of older ones) and at
    /// raise-on-click (so the clicked window comes to front).
    next_front_seq: u32,
}

impl WindowTable {
    pub fn new() -> Self {
        Self {
            windows: [None; MAX_WINDOWS],
            lingerers: Vec::new(),
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

    /// Iterate windows currently in linger state (post-destroy,
    /// pre-deadline). Composited but not focusable, not input-routed,
    /// not hit-tested. Used by the render path to blit lingerers from
    /// their backing buffers alongside active windows.
    pub fn iter_lingerers(&self) -> impl Iterator<Item = &LingerEntry> {
        self.lingerers.iter()
    }

    /// True if any window — active or lingering — is currently
    /// visible. Drives the main loop's blank-vs-composite decision:
    /// a tick with no active windows but live lingerers should still
    /// composite (the held frames are pixels worth showing).
    pub fn has_visible(&self) -> bool {
        self.iter().next().is_some() || !self.lingerers.is_empty()
    }

    /// Pick the front-most live window — highest `front_seq` wins,
    /// ties broken by table order (first-live-in-table). Used for
    /// input routing: the front window receives forwarded events;
    /// back layers (e.g. terminal-window's watermark canvas) are
    /// render-only and never receive input.
    pub fn front(&self) -> Option<&Window> {
        self.iter().max_by_key(|w| w.front_seq)
    }

    /// Front-to-back snapshot of the live windows into a fixed-size
    /// array. Shared by `hit_test` and `hit_test_resize` — both walk
    /// the table front-most first. Bounded by `MAX_WINDOWS`, no
    /// allocation. Returns the populated count.
    fn snapshot_front_to_back<'a>(
        &'a self,
        sorted: &mut [Option<&'a Window>; MAX_WINDOWS],
    ) -> usize {
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
        count
    }

    /// Hit-test a screen-absolute point against live windows from
    /// front-most to back-most. Returns the window id of the first
    /// rect that contains the point, or `None` if the point lies
    /// outside every window. Used by `pump_input_once` for
    /// raise-on-click on `PointerButton` events.
    pub fn hit_test(&self, screen_x: i32, screen_y: i32) -> Option<u32> {
        let mut sorted: [Option<&Window>; MAX_WINDOWS] = [None; MAX_WINDOWS];
        let count = self.snapshot_front_to_back(&mut sorted);
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

    /// Hit-test a screen-absolute point for a resize-grab edge on the
    /// front-most window only. Returns `(window_id, edge)` if the
    /// point lies within the front-most window's
    /// `RESIZE_GRAB_PX`-thick edge band; `None` otherwise — including
    /// when the click is on a *back* window's exposed area.
    ///
    /// Why front-only (not "first-hit walking front-to-back"):
    /// matches the focus border's visual contract — only the
    /// front-most window shows the amber outline, so only it should
    /// be resizable. A click outside the front window's rect, even
    /// if it lands on a back window's exposed edge band, returns
    /// `None`. To resize a back window, raise it first
    /// (raise-on-click on the back window's content area).
    ///
    /// This rule prevents the v1 failure where a small front window
    /// (e.g. tree game at 352×392) sits over a full-screen back
    /// window (e.g. terminal-window's 1024×768 watermark). With
    /// front-to-back walking, dragging anywhere near the screen
    /// border would hit the watermark's edge and the compositor
    /// would tear down the watermark's surface channel — not what
    /// the user expected, and on the second resize the watermark
    /// channel happened to be the kernel's lowest channel id (the
    /// scanout channel between compositor and scanout-driver in some
    /// boot orderings), at which point the entire display path
    /// faulted.
    ///
    /// Title-bar drag (top 4 px of a libgui-decorated window) is
    /// therefore unreachable from the topmost row of pixels; users
    /// grabbing the title bar click 4+ px below the top edge.
    /// UX-acceptable trade for v1.
    pub fn hit_test_resize(
        &self,
        screen_x: i32,
        screen_y: i32,
        grab_px: i32,
    ) -> Option<(u32, ResizeEdge)> {
        let front = self.front()?;
        let right = front.x + front.width as i32;
        let bottom = front.y + front.height as i32;
        if screen_x < front.x
            || screen_x >= right
            || screen_y < front.y
            || screen_y >= bottom
        {
            return None;
        }
        let near_left = screen_x - front.x < grab_px;
        let near_right = right - 1 - screen_x < grab_px;
        let near_top = screen_y - front.y < grab_px;
        let near_bottom = bottom - 1 - screen_y < grab_px;
        let edge = match (near_top, near_bottom, near_left, near_right) {
            (true, _, true, _) => ResizeEdge::TopLeft,
            (true, _, _, true) => ResizeEdge::TopRight,
            (_, true, true, _) => ResizeEdge::BottomLeft,
            (_, true, _, true) => ResizeEdge::BottomRight,
            (true, _, _, _) => ResizeEdge::Top,
            (_, true, _, _) => ResizeEdge::Bottom,
            (_, _, true, _) => ResizeEdge::Left,
            (_, _, _, true) => ResizeEdge::Right,
            _ => return None,
        };
        Some((front.window_id, edge))
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

    /// Drop lingerers whose deadline has elapsed. Called once per
    /// main-loop iteration alongside `reap_dead_channels`. The
    /// `now_ticks` argument is read from `sys::get_time` by the
    /// caller so this method stays a pure data transform on
    /// `WindowTable` (verifier-friendly: no syscall side-effects).
    /// Returns the count reaped.
    ///
    /// Vec<LingerEntry>::retain shrinks in place, so per-entry
    /// cost is O(1) amortised. The dropped `LingerEntry` runs its
    /// destructor — frees the backing pixel buffer back to the
    /// compositor heap.
    pub fn reap_expired_lingers(&mut self, now_ticks: u64) -> usize {
        let before = self.lingerers.len();
        self.lingerers.retain(|e| now_ticks < e.deadline_ticks);
        before - self.lingerers.len()
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
        MsgTag::RequestResize => {
            handle_request_resize(payload, sender_principal, from_endpoint, window_table);
            None
        }
        // 0x40xx tags (compositor → client) must never arrive here.
        MsgTag::WelcomeClient
        | MsgTag::WindowClosed
        | MsgTag::ErrorResponse
        | MsgTag::InputEvent
        | MsgTag::WindowResized => {
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

/// Reallocate a window's surface at new dimensions, optionally moving
/// it to a new top-left position. The trusted core of the resize
/// flow — auth/decode happens in callers.
///
/// Callers:
/// - [`handle_request_resize`] — client `RequestResize` (the auth
///   check verifies `sender_principal == owner_principal` first).
/// - `main.rs::commit_resize_drag` — compositor-initiated edge-grab
///   (no Principal check; compositor is the trusted authority for
///   edge-drag UX).
///
/// `new_x`/`new_y = Some` updates the window's screen position
/// atomically with the dimension change — needed when the drag-anchor
/// is the top or left edge (the OPPOSITE corner stays fixed, so the
/// top-left moves). `None` leaves position unchanged.
///
/// Flow:
/// 1. Validate dimensions against `MAX_WINDOW_DIMENSION`.
/// 2. `channel_begin_teardown(old, Close)` — kernel transitions the
///    old surface channel to `Revoking` and arm-quiesces the peer.
///    Returns `1` (Quiesce-in-flight) for `Active` channels; `0`
///    (already finished) for the `AwaitingAttach` short-circuit.
/// 3. `channel_create` a fresh surface sized for `(new_w × new_h)`.
/// 4. Send `WindowResized` to the client's reply endpoint. The client
///    closes its old mapping (returns `InvalidState` because the slot
///    is `Revoking` — libgui ignores it) and attaches the new channel.
/// 5. Update the `Window` record (channel id / vaddr / w / h / pitch /
///    optionally x / y) for subsequent composite passes.
/// 6. `channel_complete_teardown` — unmaps both sides, frees pages,
///    wakes any quiesce-parked task. Skipped on the
///    `AwaitingAttach` short-circuit.
///
/// Failure modes:
/// - `Err(InvalidDimensions)` — caller decides where to send the error.
/// - `Err(NoSuchWindow)` — window id was reaped between caller's check
///   and this call (rare; benign in edge-drag).
/// - `Err(SurfaceAllocFailed)` — kernel rejected `begin_teardown` or
///   `channel_create`. On `channel_create` failure we still call
///   `complete_teardown` so the slot is freed; the client's old
///   surface vaddr becomes a tombstone (window effectively dead, same
///   shape as a normal teardown).
pub fn commit_window_resize(
    window_table: &mut WindowTable,
    window_id: u32,
    new_w: u32,
    new_h: u32,
    new_x: Option<i32>,
    new_y: Option<i32>,
) -> Result<(), GuiError> {
    if new_w == 0
        || new_h == 0
        || new_w > MAX_WINDOW_DIMENSION
        || new_h > MAX_WINDOW_DIMENSION
    {
        return Err(GuiError::InvalidDimensions);
    }

    let slot = window_table.find_window(window_id).ok_or(GuiError::NoSuchWindow)?;
    let (old_channel_id, owner_principal) = {
        let w = window_table.get_mut(slot).ok_or(GuiError::NoSuchWindow)?;
        (w.surface_channel_id, w.owner_principal)
    };

    let begin_rc = sys::channel_begin_teardown(old_channel_id, sys::TEARDOWN_KIND_CLOSE);
    if begin_rc < 0 {
        return Err(GuiError::SurfaceAllocFailed);
    }
    let needs_complete = begin_rc == 1;

    let new_pitch = new_w * SURFACE_BYTES_PER_PIXEL;
    let new_bytes = (new_pitch as u64) * (new_h as u64);
    let new_size_pages = ((new_bytes + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as u32;
    let mut new_surface_vaddr: u64 = 0;
    let create_rc = sys::channel_create(
        new_size_pages,
        &owner_principal,
        CHANNEL_ROLE_CONSUMER,
        &mut new_surface_vaddr,
    );
    if create_rc < 0 {
        if needs_complete {
            let _ = sys::channel_complete_teardown(old_channel_id, sys::TEARDOWN_KIND_CLOSE);
        }
        return Err(GuiError::SurfaceAllocFailed);
    }
    let new_channel_id = create_rc as u64;

    // Read client_endpoint AFTER the kernel calls — if the slot was
    // reaped between find_window and now (unlikely; channel_create
    // succeeded), the get_mut below also returns None and we skip the
    // notify. The realloc succeeded but the window is gone; the new
    // channel will be revoked by normal teardown.
    let client_endpoint = window_table
        .get_mut(slot)
        .map(|w| w.client_endpoint)
        .unwrap_or(0);

    if client_endpoint != 0 {
        let mut reply = [0u8; 32];
        if let Some(n) = encode_window_resized(
            &mut reply,
            window_id,
            new_w,
            new_h,
            new_pitch,
            new_channel_id,
        ) {
            let _ = sys::write(client_endpoint, &reply[..n]);
        }
    }

    if let Some(w) = window_table.get_mut(slot) {
        w.surface_channel_id = new_channel_id;
        w.surface_vaddr = new_surface_vaddr;
        w.width = new_w;
        w.height = new_h;
        w.pitch = new_pitch;
        if let Some(nx) = new_x {
            w.x = nx;
        }
        if let Some(ny) = new_y {
            w.y = ny;
        }
    }

    if needs_complete {
        let _ = sys::channel_complete_teardown(old_channel_id, sys::TEARDOWN_KIND_CLOSE);
    }

    Ok(())
}

/// Client-initiated resize via `RequestResize`. Decodes, runs the
/// auth check (sender_principal must equal owner_principal), and
/// delegates the actual realloc to [`commit_window_resize`]. Errors
/// before commit go to `from_endpoint` (the kernel-stamped reply
/// target before ownership is established); errors during commit go
/// to the window's recorded `client_endpoint` — unified error
/// reporting since both endpoints route to the owning client by then.
fn handle_request_resize(
    payload: &[u8],
    sender_principal: &[u8; 32],
    from_endpoint: u32,
    window_table: &mut WindowTable,
) {
    let (window_id, new_w, new_h) = match decode_request_resize(payload) {
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
    let client_endpoint = {
        let w = match window_table.get_mut(slot) {
            Some(w) => w,
            None => return,
        };
        if &w.owner_principal != sender_principal {
            send_error(from_endpoint, GuiError::NoSuchWindow);
            return;
        }
        w.client_endpoint
    };

    if let Err(e) = commit_window_resize(window_table, window_id, new_w, new_h, None, None) {
        // InvalidDimensions is a client mistake — route to the
        // pre-auth reply endpoint so the client sees it on its first
        // message exchange. SurfaceAllocFailed is a kernel/compositor
        // failure observed post-auth — route to the recorded endpoint.
        let target = match e {
            GuiError::InvalidDimensions => from_endpoint,
            _ => client_endpoint,
        };
        send_error(target, e);
    }
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
    let (window_id, linger_ms) = match decode_destroy_window(payload) {
        Some(pair) => pair,
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

    // Validate ownership and snapshot the fields the linger path
    // needs while the borrow is still scoped tight.
    let snapshot = {
        let w = match window_table.get_mut(slot) {
            Some(w) => w,
            None => return,
        };
        if &w.owner_principal != sender_principal {
            send_error(from_endpoint, GuiError::NoSuchWindow);
            return;
        }
        *w
    };

    if linger_ms == 0 || !try_promote_to_lingerer(window_table, &snapshot, linger_ms) {
        // Immediate teardown: either the client asked for it
        // (linger_ms = 0), or the linger promotion failed (cap hit
        // or backing-buffer alloc failed). Falling through to the
        // immediate path is the right user-visible behavior in both
        // cases — linger is a best-effort hint, not a guarantee.
        let _ = sys::channel_close(snapshot.surface_channel_id);
        window_table.windows[slot] = None;
        return;
    }

    // Linger promotion succeeded. The lingerer owns the pixels now;
    // detach the slot and close the channel. The compositor's RO
    // mapping of the channel is no longer needed — composite reads
    // from `LingerEntry.pixels` until the deadline.
    let _ = sys::channel_close(snapshot.surface_channel_id);
    window_table.windows[slot] = None;
}

/// Attempt to copy the window's surface pixels into a fresh
/// backing buffer and push a `LingerEntry`. Returns `true` if
/// the lingerer was registered, `false` if the cap was hit or
/// allocation failed (caller falls back to immediate teardown).
///
/// `linger_ms` is clamped to `MAX_LINGER_MS` before deadline
/// computation so a misbehaving client can't keep a slot longer
/// than v1 policy allows.
#[allow(unsafe_code)]
fn try_promote_to_lingerer(
    window_table: &mut WindowTable,
    window: &Window,
    linger_ms: u32,
) -> bool {
    if window_table.lingerers.len() >= MAX_LINGERERS {
        return false;
    }

    let pixel_count = (window.width as usize) * (window.height as usize);
    if pixel_count == 0 {
        return false;
    }

    let mut pixels: Vec<u32> = Vec::new();
    if pixels.try_reserve_exact(pixel_count).is_err() {
        return false;
    }

    let pitch_pixels = (window.pitch / SURFACE_BYTES_PER_PIXEL) as usize;
    let row_pixels = window.width as usize;

    // SAFETY: `window.surface_vaddr` is the compositor's RO mapping
    // of the surface channel — set by `commit_window_resize` /
    // `handle_create_window` to point at `pitch * height` bytes of
    // mapped, attached, non-revoked memory (we are still holding
    // the channel; the close happens after this function returns
    // successfully). The read window is bounded:
    //   row in 0..height
    //   col in 0..width
    //   offset = row * pitch_pixels + col, with pitch_pixels >= width
    // so byte offset < height * pitch <= channel mapped extent.
    // `read_volatile` matches the existing `blit_surface_to_scanout`
    // contract — prevents reorder around the live channel reads.
    unsafe {
        let src_base = window.surface_vaddr as *const u32;
        for row in 0..(window.height as usize) {
            let row_base = src_base.add(row * pitch_pixels);
            for col in 0..row_pixels {
                pixels.push(core::ptr::read_volatile(row_base.add(col)));
            }
        }
    }

    let clamped = linger_ms.min(MAX_LINGER_MS);
    let deadline = sys::get_time().saturating_add(ms_to_ticks(clamped));

    window_table.lingerers.push(LingerEntry {
        window: *window,
        pixels,
        deadline_ticks: deadline,
    });
    true
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
