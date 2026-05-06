// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! `Client` — compositor handshake + frame submission wrapper.
//!
//! Collapses the raw libgui-proto handshake (register endpoint →
//! CreateWindow → recv WelcomeClient → channel_attach) into a
//! single `Client::open` call, hands back a [`Surface`] that
//! references the attached channel memory, and exposes `submit*`
//! helpers that encode and send `FrameReady`.
//!
//! A `Client` does NOT call `sys::module_ready()` — that signal
//! belongs to boot-gate ordering, which only boot modules care
//! about. The caller decides when (if ever) to release its boot
//! gate. Same rationale as libsys: single-responsibility wrappers
//! don't hide protocol primitives.

use cambios_libgui_proto::{
    decode_input_event, decode_welcome_client, encode_create_window, encode_destroy_window,
    encode_frame_ready, InputEvent, MsgTag, Rect, WelcomeClientMsg, COMPOSITOR_ENDPOINT,
    MAX_MESSAGE_SIZE,
};
use cambios_libsys as sys;

use crate::Surface;

/// Bytes the kernel prepends to a `recv_msg` / `try_recv_msg` result:
/// 32-byte sender_principal + 4-byte from_endpoint.
const RECV_HEADER_BYTES: usize = 36;

/// Reasons `Client::open` can fail. The kernel error code is folded
/// into the enum where it exists so callers can log root cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// `sys::register_endpoint` returned a non-zero error code.
    RegisterEndpointFailed(i64),
    /// CreateWindow encode failed — should never happen with the
    /// built-in 16-byte send buffer; surfaced for completeness.
    EncodeCreateWindow,
    /// `sys::write(COMPOSITOR_ENDPOINT, …)` returned an error code.
    CreateWindowWriteFailed(i64),
    /// `recv_verified` returned `None` (empty queue, short message,
    /// or anonymous sender).
    RecvVerifiedFailed,
    /// The compositor's reply was a non-WelcomeClient payload or
    /// otherwise malformed.
    DecodeWelcome,
    /// `sys::channel_attach` returned a negative error code.
    ChannelAttachFailed(i64),
    /// FrameReady encode failed — damage list too long or output
    /// buffer too small.
    EncodeFrameReady,
    /// `sys::write(COMPOSITOR_ENDPOINT, …)` returned an error code
    /// from a later FrameReady.
    FrameReadyWriteFailed(i64),
}

/// A live connection to the compositor for one window. Holds the
/// attached surface mapping; drops to leave the channel attached
/// (explicit teardown is out of scope for v0 — see the v0 scope
/// notes in `lib.rs`).
///
/// Layered windows: `z_order` and `alpha_blend` are recorded so a
/// `reopen` after `close` re-issues CreateWindow with the same
/// stacking semantics.
pub struct Client {
    my_endpoint: u32,
    window_id: u32,
    channel_id: u64,
    surface_vaddr: u64,
    width: u32,
    height: u32,
    pitch: u32,
    next_seq: u32,
    z_order: u8,
    alpha_blend: bool,
}

impl Client {
    /// Convenience: open a single opaque window at z=0. The classic
    /// pre-z-index call shape — every existing libgui consumer (games,
    /// hello-window, terminal-window before layering) calls this and
    /// gets the same behavior as before.
    pub fn open(
        window_width: u32,
        window_height: u32,
        my_endpoint: u32,
    ) -> Result<Self, ClientError> {
        Self::open_layer(window_width, window_height, my_endpoint, 0, false)
    }

    /// Complete the compositor handshake for a layered window and
    /// return a ready-to-draw Client.
    ///
    /// `z_order` ranks this window in the compositor's back-to-front
    /// stack (0 = back, larger = front). `alpha_blend = true` asks
    /// the compositor to interpret the surface's high-byte alpha
    /// channel and blend over the windows below; `false` (the
    /// default for [`Client::open`]) uses XRGB-overwrite semantics.
    ///
    /// `my_endpoint` is the caller's endpoint — must not already be
    /// registered by this process. A multi-layer client (e.g.
    /// terminal-window's back+front) uses one endpoint per layer so
    /// each layer's WelcomeClient round-trip routes back to the
    /// matching `open_layer` call.
    pub fn open_layer(
        window_width: u32,
        window_height: u32,
        my_endpoint: u32,
        z_order: u8,
        alpha_blend: bool,
    ) -> Result<Self, ClientError> {
        // 1. Register our reply endpoint.
        let rc = sys::register_endpoint(my_endpoint);
        if rc < 0 {
            return Err(ClientError::RegisterEndpointFailed(rc));
        }

        // 2. Send CreateWindow with layer parameters. `my_endpoint`
        //    flows into the message as `reply_endpoint` so the
        //    compositor's WelcomeClient lands on this layer's
        //    endpoint regardless of which endpoint this process
        //    registered first (the kernel-stamped sender is sticky
        //    on first-register; multi-layer clients need explicit
        //    routing per handshake).
        let mut send_buf = [0u8; 20];
        let n = encode_create_window(
            &mut send_buf,
            window_width,
            window_height,
            z_order,
            alpha_blend,
            my_endpoint,
        )
        .ok_or(ClientError::EncodeCreateWindow)?;
        let rc = sys::write(COMPOSITOR_ENDPOINT, &send_buf[..n]);
        if rc < 0 {
            return Err(ClientError::CreateWindowWriteFailed(rc));
        }

        // 3. Block for WelcomeClient.
        let mut recv_buf = [0u8; MAX_MESSAGE_SIZE + 36]; // +36 for the verified header
        let welcome = sys::recv_verified(my_endpoint, &mut recv_buf)
            .ok_or(ClientError::RecvVerifiedFailed)?;
        let msg = decode_welcome_client(welcome.payload()).ok_or(ClientError::DecodeWelcome)?;

        // 4. Attach the surface channel.
        let rc = sys::channel_attach(msg.channel_id);
        if rc < 0 {
            return Err(ClientError::ChannelAttachFailed(rc));
        }
        let surface_vaddr = rc as u64;

        Ok(Self {
            my_endpoint,
            window_id: msg.window_id,
            channel_id: msg.channel_id,
            surface_vaddr,
            width: msg.width,
            height: msg.height,
            pitch: msg.pitch,
            next_seq: 0,
            z_order,
            alpha_blend,
        })
    }

    /// Re-open a window after a prior [`Client::close`].
    ///
    /// Same as [`Client::open_layer`] except `register_endpoint` is
    /// skipped: the kernel-side endpoint stays registered for the
    /// lifetime of the process, so a single `register_endpoint` at
    /// startup covers any number of close/reopen cycles. Used by
    /// `terminal-window`'s `/play` flow: close window before spawning
    /// a game (so the game can claim "first live window" focus),
    /// then reopen when control returns from `wait_task`. The
    /// previous z_order / alpha_blend are preserved so reopening a
    /// layered window does not silently demote it to z=0/opaque.
    pub fn reopen(
        window_width: u32,
        window_height: u32,
        my_endpoint: u32,
    ) -> Result<Self, ClientError> {
        Self::reopen_layer(window_width, window_height, my_endpoint, 0, false)
    }

    /// Re-open a previously-closed layered window with explicit
    /// `z_order` / `alpha_blend`. Use the bare [`Client::reopen`] for
    /// the classic single-opaque case.
    pub fn reopen_layer(
        window_width: u32,
        window_height: u32,
        my_endpoint: u32,
        z_order: u8,
        alpha_blend: bool,
    ) -> Result<Self, ClientError> {
        // Send CreateWindow with the same explicit reply_endpoint
        // routing as `open_layer` — required for multi-layer clients
        // whose sticky kernel-stamped sender doesn't match this
        // layer's endpoint.
        let mut send_buf = [0u8; 20];
        let n = encode_create_window(
            &mut send_buf,
            window_width,
            window_height,
            z_order,
            alpha_blend,
            my_endpoint,
        )
        .ok_or(ClientError::EncodeCreateWindow)?;
        let rc = sys::write(COMPOSITOR_ENDPOINT, &send_buf[..n]);
        if rc < 0 {
            return Err(ClientError::CreateWindowWriteFailed(rc));
        }

        // Block for WelcomeClient, draining stale messages.
        //
        // Unlike `open_layer` (where the endpoint was just registered
        // and the queue is empty), `reopen_layer` runs after the
        // process has been live — typically after a full game
        // lifecycle (close → spawn → wait_task → reopen). The
        // endpoint queue can hold stale messages that the compositor
        // forwarded during the game's lifetime: most commonly
        // `InputEvent`s routed to the focused window before
        // `backend.close()` ran, plus any input events the compositor
        // forwards in the brief window between this CreateWindow
        // landing in the compositor's queue and the
        // WelcomeClient landing back in ours. Without filtering, the
        // first `recv_verified` returns one of those, fails
        // `decode_welcome_client`, and reopen aborts with
        // `ClientError::DecodeWelcome` — the failure mode observed
        // for `play super-sprouty-o → Ctrl+Q` post-tombstone-fix.
        //
        // The kernel guarantees per-endpoint FIFO delivery, so the
        // stale messages (queued first) are seen before the
        // WelcomeClient. Drain non-WelcomeClient payloads in a
        // bounded loop until we find ours. The bound is generous —
        // ADR-005's per-endpoint queue caps at 16 messages, and we
        // also cover input forwards arriving in-flight while
        // draining; 32 leaves headroom without enabling an infinite
        // loop on a kernel bug. Anonymous-sender / short-message /
        // syscall-error returns from `recv_verified` propagate as
        // `RecvVerifiedFailed` — those are not "stale" and not
        // recoverable here.
        let mut recv_buf = [0u8; MAX_MESSAGE_SIZE + 36];
        const MAX_DRAIN: usize = 32;
        let mut found: Option<WelcomeClientMsg> = None;
        for _ in 0..MAX_DRAIN {
            let welcome = sys::recv_verified(my_endpoint, &mut recv_buf)
                .ok_or(ClientError::RecvVerifiedFailed)?;
            if let Some(msg) = decode_welcome_client(welcome.payload()) {
                found = Some(msg);
                break;
            }
            // Non-WelcomeClient payload — discard and continue. The
            // VerifiedMessage borrow on `recv_buf` ends at the
            // bottom of this iteration, so the next `recv_verified`
            // can re-borrow.
        }
        let msg = found.ok_or(ClientError::DecodeWelcome)?;

        // Attach the new surface channel.
        let rc = sys::channel_attach(msg.channel_id);
        if rc < 0 {
            return Err(ClientError::ChannelAttachFailed(rc));
        }
        let surface_vaddr = rc as u64;

        Ok(Self {
            my_endpoint,
            window_id: msg.window_id,
            channel_id: msg.channel_id,
            surface_vaddr,
            width: msg.width,
            height: msg.height,
            pitch: msg.pitch,
            next_seq: 0,
            z_order,
            alpha_blend,
        })
    }

    /// Z-order rank within the compositor's back-to-front stack —
    /// 0 is the back, larger is the front. Recorded at open time so
    /// `reopen_layer` can preserve it without the caller threading it
    /// through.
    pub fn z_order(&self) -> u8 {
        self.z_order
    }

    /// True if this client opened with alpha blending requested. The
    /// compositor honors the surface's high-byte alpha channel only
    /// when this flag is set.
    pub fn alpha_blend(&self) -> bool {
        self.alpha_blend
    }

    /// Tell the compositor we're done with this window so it can drop
    /// our Window entry and stop routing input to our endpoint.
    /// Compositor's DestroyWindow handler (handle_destroy_window in
    /// user/compositor/src/windows.rs) closes the surface channel and
    /// clears the table slot; after that, "first live window" focus
    /// transfers to whoever's next on screen.
    ///
    /// Best-effort fire-and-forget. Callers are typically about to
    /// sys::exit, so we don't wait for an ACK and don't surface
    /// encode/write failures. If the send is dropped (contention,
    /// encode failure), the compositor holds a stale window entry
    /// until some later cleanup -- not fatal, but the next game
    /// won't get focus until the compositor learns we're gone.
    ///
    /// Takes &self rather than self so callers can invoke it from
    /// inside a poll_event borrow; the Client is normally dropped
    /// immediately afterward via sys::exit anyway.
    pub fn close(&self) {
        let mut buf = [0u8; 16];
        if let Some(n) = encode_destroy_window(&mut buf, self.window_id) {
            let _ = sys::write(COMPOSITOR_ENDPOINT, &buf[..n]);
        }
    }

    pub fn window_id(&self) -> u32 {
        self.window_id
    }

    pub fn channel_id(&self) -> u64 {
        self.channel_id
    }

    pub fn endpoint(&self) -> u32 {
        self.my_endpoint
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// Borrow the surface mutably for a drawing pass. The returned
    /// `Surface` is valid until the borrow ends; drop it before
    /// calling `submit_*` (the borrow checker will enforce this
    /// because `submit_*` takes `&mut self`).
    pub fn surface_mut(&mut self) -> Surface<'_> {
        // SAFETY:
        // - `surface_vaddr` is the caller's own mapping of the
        //   surface channel, returned by `channel_attach`, and is
        //   valid for the lifetime of `self`.
        // - `pitch / 4` gives pitch in u32 pixels; XRGB8888 / ARGB8888
        //   are 4 bytes per pixel.
        // - `&mut self` ensures no other Rust reference to the
        //   Surface exists for the borrow.
        // - The compositor reads the same memory from another
        //   process; `Surface::set_pixel` uses `write_volatile` to
        //   keep stores observable.
        // ARGB mode is selected when this client opened with
        // `alpha_blend=true` so `blend_pixel` writes ARGB instead of
        // pre-blending inside the surface — required for layered
        // windows where the eventual composition happens in the
        // compositor.
        let pitch_pixels = (self.pitch / 4) as usize;
        let base = self.surface_vaddr as *mut u32;
        unsafe {
            if self.alpha_blend {
                Surface::from_raw_argb(base, pitch_pixels, self.width, self.height)
            } else {
                Surface::from_raw(base, pitch_pixels, self.width, self.height)
            }
        }
    }

    /// Submit a FrameReady with an explicit damage list. Empty list
    /// means "full surface dirty" (matches the compositor's current
    /// behavior — damage is a hint, full-surface is always legal).
    pub fn submit(&mut self, damage: &[Rect]) -> Result<(), ClientError> {
        // 4-byte tag + 4 window_id + 4 seq + 4 damage_count + 8 per
        // rect. With MAX_DAMAGE_RECTS_PER_FRAME = 16 that's
        // 16 + 128 = 144 bytes, safely under MAX_MESSAGE_SIZE.
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let n = encode_frame_ready(&mut buf, self.window_id, self.next_seq, damage)
            .ok_or(ClientError::EncodeFrameReady)?;
        let rc = sys::write(COMPOSITOR_ENDPOINT, &buf[..n]);
        if rc < 0 {
            return Err(ClientError::FrameReadyWriteFailed(rc));
        }
        self.next_seq = self.next_seq.wrapping_add(1);
        Ok(())
    }

    /// Submit a FrameReady marking the full surface dirty. Shortcut
    /// for `submit(&[])`.
    pub fn submit_full(&mut self) -> Result<(), ClientError> {
        self.submit(&[])
    }

    /// Non-blocking poll for a single compositor message. Returns
    /// `Some(InputEvent)` if a forwarded driver event is waiting;
    /// `None` on empty queue, malformed header, or any non-input
    /// compositor message (`WindowClosed`, `ErrorResponse`).
    ///
    /// Call this repeatedly from the client's event loop, typically
    /// interleaved with `sys::yield_now()` between drain cycles so
    /// the scheduler can run other tasks while input is idle.
    ///
    /// v0 does not handle `WindowClosed` — a real app would want to
    /// learn its window went away. Added when the first app actually
    /// destroys / re-creates windows at runtime.
    pub fn poll_event(&mut self) -> Option<InputEvent> {
        // 36-byte recv header + 4-byte tag + 96-byte event = 136 B.
        // Round up to 160 for slack against future tag variants.
        let mut buf = [0u8; 160];
        let n = sys::try_recv_msg(self.my_endpoint, &mut buf);
        if n <= 0 {
            return None;
        }
        let total = n as usize;
        if total < RECV_HEADER_BYTES + 4 {
            return None;
        }
        let payload = &buf[RECV_HEADER_BYTES..total];
        let tag_bytes: [u8; 4] = payload[0..4].try_into().ok()?;
        let tag = MsgTag::from_u32(u32::from_le_bytes(tag_bytes))?;
        match tag {
            MsgTag::InputEvent => decode_input_event(payload),
            // WindowClosed / ErrorResponse arrive on the same endpoint;
            // v0 silently drops them. Future: surface via a separate
            // `poll_notification()` or a combined `poll_message()`.
            _ => None,
        }
    }
}
