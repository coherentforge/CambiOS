// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Terminal: composes a [`Backend`] with the [`Parser`] and exposes an
//! event-polling API that resolves the lone-ESC ambiguity via caller-
//! supplied deadlines.

use cambios_libsys as sys;

use crate::backend::Backend;
use crate::events::Event;
use crate::parser::Parser;

/// System timer frequency in Hz. 100 Hz today (10 ms per tick).
/// Updates to this must match `src/scheduler/timer.rs`.
pub const TICKS_PER_SEC: u64 = 100;

/// Default ESC-timeout when a lone ESC is not followed by a continuation
/// byte. 50 ms = 5 ticks at 100 Hz. Matches nano's posture.
pub const DEFAULT_ESC_TIMEOUT_MS: u64 = 50;

/// Helper: convert a millisecond duration into a tick count.
#[inline]
pub const fn ms_to_ticks(ms: u64) -> u64 {
    (ms * TICKS_PER_SEC + 999) / 1000
}

/// Current monotonic tick count (wraps `cambios_libsys::get_time`).
#[inline]
pub fn now_ticks() -> u64 {
    sys::get_time()
}

pub struct Terminal<B: Backend> {
    backend: B,
    parser: Parser,
}

impl<B: Backend> Terminal<B> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            parser: Parser::new(),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn size(&self) -> (u16, u16) {
        self.backend.size()
    }

    /// Direct write to the backend. Use the helpers in [`crate::output`]
    /// for cursor positioning, clearing, and style.
    pub fn write(&mut self, bytes: &[u8]) {
        self.backend.write(bytes);
    }

    /// Poll for one event, returning no later than `deadline_ticks` (an
    /// absolute tick count from [`now_ticks`]).
    ///
    /// Behavior:
    /// - Returns as soon as the parser emits a [`Key`].
    /// - If the deadline expires and the parser is waiting for a
    ///   continuation byte after a lone `ESC`, emits [`Key::Escape`].
    /// - Any other deadline expiry returns [`Event::Timeout`].
    /// - Between polls, yields to the scheduler.
    pub fn next_event(&mut self, deadline_ticks: u64) -> Event {
        loop {
            if let Some(byte) = self.backend.poll_byte() {
                if let Some(key) = self.parser.step(byte) {
                    return Event::Key(key);
                }
                // Parser consumed the byte but is still mid-sequence — keep
                // polling without yielding (continuation bytes typically
                // arrive back-to-back in the same serial burst).
                continue;
            }

            if now_ticks() >= deadline_ticks {
                if let Some(key) = self.parser.flush_on_timeout() {
                    return Event::Key(key);
                }
                return Event::Timeout;
            }

            sys::yield_now();
        }
    }

    /// Convenience: block until a key arrives, never timing out on a lone
    /// ESC. Internally polls with an indefinite outer loop, using the
    /// default ESC timeout so a lone ESC still surfaces promptly.
    pub fn next_event_blocking(&mut self) -> Event {
        loop {
            let deadline = now_ticks().saturating_add(ms_to_ticks(DEFAULT_ESC_TIMEOUT_MS));
            match self.next_event(deadline) {
                Event::Timeout => {
                    // No complete event yet; loop and keep waiting.
                    continue;
                }
                other => return other,
            }
        }
    }
}
