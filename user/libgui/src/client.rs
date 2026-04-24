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

use arcos_libgui_proto::{
    decode_input_event, decode_welcome_client, encode_create_window, encode_destroy_window,
    encode_frame_ready, InputEvent, MsgTag, Rect, COMPOSITOR_ENDPOINT, MAX_MESSAGE_SIZE,
};
use arcos_libsys as sys;

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
pub struct Client {
    my_endpoint: u32,
    window_id: u32,
    channel_id: u64,
    surface_vaddr: u64,
    width: u32,
    height: u32,
    pitch: u32,
    next_seq: u32,
}

impl Client {
    /// Complete the compositor handshake and return a ready-to-draw
    /// Client.
    ///
    /// `window_width` / `window_height` are the requested pixel
    /// dimensions (libgui-proto bounds apply —
    /// `MAX_WINDOW_DIMENSION` from that crate).
    /// `my_endpoint` is the caller's endpoint — must not already be
    /// registered by this process.
    pub fn open(
        window_width: u32,
        window_height: u32,
        my_endpoint: u32,
    ) -> Result<Self, ClientError> {
        // 1. Register our reply endpoint.
        let rc = sys::register_endpoint(my_endpoint);
        if rc < 0 {
            return Err(ClientError::RegisterEndpointFailed(rc));
        }

        // 2. Send CreateWindow.
        let mut send_buf = [0u8; 16];
        let n = encode_create_window(&mut send_buf, window_width, window_height)
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
        })
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
        // - `pitch / 4` gives pitch in u32 pixels; XRGB8888 is 4
        //   bytes per pixel.
        // - `&mut self` ensures no other Rust reference to the
        //   Surface exists for the borrow.
        // - The compositor reads the same memory from another
        //   process; `Surface::set_pixel` uses `write_volatile` to
        //   keep stores observable.
        unsafe {
            Surface::from_raw(
                self.surface_vaddr as *mut u32,
                (self.pitch / 4) as usize,
                self.width,
                self.height,
            )
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
