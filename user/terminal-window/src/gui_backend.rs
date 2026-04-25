// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! `GuiBackend` — adapter from `libgui::Client` + `Grid` to `libterm::Backend`.
//!
//! Responsibilities:
//!
//! 1. **Input direction**: pull `InputEvent`s from the compositor via
//!    `Client::poll_event`, run them through [`encoder::encode_key_event`],
//!    queue the resulting bytes, and serve them one at a time when
//!    `libterm::Terminal` calls `poll_byte`.
//! 2. **Output direction**: forward bytes from `Backend::write` straight
//!    into the [`Grid`]'s ANSI state machine.
//! 3. **Render hook**: just before yielding to wait for fresh input
//!    (i.e., when `poll_byte` is about to return `None`), if the grid
//!    has dirty rows, blit them through the [`render`] module and
//!    submit a `FrameReady`. This is the minimum-friction way to ride
//!    libterm's existing polling loop without changing the trait — the
//!    UI updates as soon as input is consumed, and idle yields don't
//!    re-submit unchanged frames.
//!
//! Dependency layering: this module sits in the `terminal-window` crate
//! and depends on `arcos-libterm` (Backend trait), `arcos-libgui`
//! (Client + Surface), `arcos-libinput-proto` (InputEvent), and the
//! sibling `encoder`, `grid`, and `render` modules. libterm itself does
//! NOT depend on libgui — keeping it that way preserves libterm's
//! reusability for non-GUI consumers (the original SerialBackend).

use arcos_libgui::{Client, ClientError};
use arcos_libterm::Backend;

use crate::encoder::{encode_key_event, EncodedBytes};
use crate::grid::{Grid, VISIBLE_ROWS};
use crate::render;

/// Maximum bytes a single `InputEvent` can encode to. Matches
/// [`EncodedBytes`]'s buffer.
const MAX_ENCODED_LEN: usize = 16;

pub struct GuiBackend {
    client: Client,
    grid: Grid,
    render_state: render::RenderState,
    /// Bytes queued from the most recent encoded event, waiting to be
    /// served byte-at-a-time by `poll_byte`.
    pending: [u8; MAX_ENCODED_LEN],
    pending_head: u8,
    pending_tail: u8,
}

impl GuiBackend {
    /// Open a new compositor window and wire it to a fresh `Grid`.
    /// `width` / `height` are pixel dimensions; `my_endpoint` is the
    /// caller process's reply endpoint (compositor will route input
    /// events here).
    pub fn open(width: u32, height: u32, my_endpoint: u32) -> Result<Self, ClientError> {
        let client = Client::open(width, height, my_endpoint)?;
        Ok(Self {
            client,
            grid: Grid::new(),
            render_state: render::RenderState::new(),
            pending: [0; MAX_ENCODED_LEN],
            pending_head: 0,
            pending_tail: 0,
        })
    }

    pub fn grid(&self) -> &Grid {
        &self.grid
    }

    pub fn grid_mut(&mut self) -> &mut Grid {
        &mut self.grid
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn client_mut(&mut self) -> &mut Client {
        &mut self.client
    }

    /// Tear down our compositor window. Best-effort fire-and-forget.
    /// After `close()`, the compositor's "first live window" focus
    /// transfers to whichever window is next on screen — this is the
    /// load-bearing call that lets a spawned game receive input.
    ///
    /// Pair with [`GuiBackend::reopen`] when control returns to us
    /// (e.g., after `wait_task` on a spawned game completes).
    pub fn close(&mut self) {
        self.client.close();
    }

    /// Re-open the compositor window after a prior `close`. Builds a
    /// fresh `Client` for the same endpoint and re-attaches the surface
    /// channel. The grid's text contents survive the round-trip, so
    /// the next render restores the prompt and any visible scrollback.
    ///
    /// This is the libgui addition this crate motivates — see
    /// `Client::reopen` in the libgui draft.
    pub fn reopen(&mut self) -> Result<(), ClientError> {
        let width = self.client.width();
        let height = self.client.height();
        let endpoint = self.client.endpoint();
        // The endpoint is already registered with the kernel — reopen
        // skips re-register.
        let new_client = Client::reopen(width, height, endpoint)?;
        self.client = new_client;
        self.grid.mark_all_dirty();
        Ok(())
    }

    /// Render any dirty rows into the surface and submit a `FrameReady`.
    /// No-op if nothing is dirty.
    pub fn render_if_dirty(&mut self) {
        let mut any_dirty = false;
        for r in 0..VISIBLE_ROWS {
            if self.grid.is_dirty(r) {
                any_dirty = true;
                break;
            }
        }
        if !any_dirty {
            return;
        }
        {
            let mut surf = self.client.surface_mut();
            render::render(&mut surf, &mut self.grid, &mut self.render_state);
        }
        // FrameReady is best-effort: if the compositor is wedged we'll
        // surface the failure later through the normal IPC error path.
        let _ = self.client.submit_full();
    }

    /// Force a full redraw on the next render cycle. Useful after
    /// reopening a window (the surface is fresh).
    pub fn invalidate_all(&mut self) {
        self.grid.mark_all_dirty();
        self.render_state.first_paint = true;
    }

    fn try_dequeue_byte(&mut self) -> Option<u8> {
        if self.pending_head < self.pending_tail {
            let b = self.pending[self.pending_head as usize];
            self.pending_head += 1;
            Some(b)
        } else {
            None
        }
    }

    fn enqueue(&mut self, encoded: &EncodedBytes) {
        let bytes = encoded.as_slice();
        let n = bytes.len().min(MAX_ENCODED_LEN);
        self.pending[..n].copy_from_slice(&bytes[..n]);
        self.pending_head = 0;
        self.pending_tail = n as u8;
    }
}

impl Backend for GuiBackend {
    fn poll_byte(&mut self) -> Option<u8> {
        // 1. Drain any in-flight encoded sequence first.
        if let Some(b) = self.try_dequeue_byte() {
            return Some(b);
        }

        // 2. Pull events from the compositor until we get one that
        //    encodes to non-empty bytes (skip e.g. KeyUp).
        while let Some(event) = self.client.poll_event() {
            let enc = encode_key_event(&event);
            if !enc.is_empty() {
                self.enqueue(&enc);
                return self.try_dequeue_byte();
            }
        }

        // 3. About to yield — flush any pending UI updates so the user
        //    sees them. This is the only render hook libterm gives us
        //    without changing its API.
        self.render_if_dirty();

        None
    }

    fn write(&mut self, bytes: &[u8]) {
        self.grid.write_bytes(bytes);
    }

    fn size(&self) -> (u16, u16) {
        self.grid.size()
    }
}
