// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Byte-level transport abstraction.
//!
//! A [`Backend`] is the seam between libterm's parser/terminal layer and
//! whatever actually carries bytes in and out. Today that is the serial
//! console via `cambios_libsys`. A future framebuffer backend (post-Scanout-2)
//! implements the same trait using glyph blits and the input-hub event
//! stream — consumer code (shell, editor, man) does not change.
//!
//! The trait intentionally uses static dispatch via a type parameter on
//! [`crate::Terminal`]. Dynamic dispatch is avoided to keep future
//! verification tractable — see CLAUDE.md's Formal-Verification rule.

use cambios_libsys as sys;

/// Byte-level terminal transport.
///
/// Implementors must be non-blocking on [`Self::poll_byte`] — the
/// [`crate::Terminal`] layer drives polling explicitly. Writes may block
/// briefly (e.g., kernel serial TX drain) but must not indefinitely stall.
pub trait Backend {
    /// Try to read one byte. Returns `None` if no input is available.
    fn poll_byte(&mut self) -> Option<u8>;

    /// Write bytes to the output. Must be complete or error; no partial
    /// writes visible to the caller.
    fn write(&mut self, bytes: &[u8]);

    /// Terminal geometry as `(cols, rows)`.
    fn size(&self) -> (u16, u16);
}

/// Serial-console backend for v1.
///
/// Wraps `cambios_libsys::console_read` (non-blocking 1-byte poll) and
/// `cambios_libsys::print`. Reports a fixed `(80, 24)` geometry — QEMU's
/// serial console has no real size query, and every downstream tool
/// (shell, nano-style editor, man pager) already wraps/paginates defensively.
pub struct SerialBackend;

impl SerialBackend {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SerialBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for SerialBackend {
    fn poll_byte(&mut self) -> Option<u8> {
        let mut buf = [0u8; 1];
        let n = sys::console_read(&mut buf);
        if n > 0 { Some(buf[0]) } else { None }
    }

    fn write(&mut self, bytes: &[u8]) {
        // SYS_PRINT is capped at 256 bytes per call (src/syscalls/dispatcher.rs
        // handle_print). Chunk longer payloads.
        let mut off = 0;
        while off < bytes.len() {
            let end = core::cmp::min(off + 256, bytes.len());
            sys::print(&bytes[off..end]);
            off = end;
        }
    }

    fn size(&self) -> (u16, u16) {
        // ARCHITECTURAL: QEMU serial console is dimensionless; we pick
        // the de-facto 80x24 every terminal program assumes. A future
        // framebuffer backend reports real glyph geometry.
        (80, 24)
    }
}
