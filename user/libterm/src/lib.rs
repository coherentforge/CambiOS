// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS user-space terminal abstraction.
//!
//! Provides:
//! - Event types ([`Key`], [`Event`]) that the shell/editor/man consume.
//! - An ANSI input parser implemented as a pure state-machine ([`parser`])
//!   — byte-in, event-out, no I/O, suitable for formal verification.
//! - A [`Backend`] trait that abstracts the byte-level transport. Today the
//!   only backend is [`SerialBackend`] (wraps `arcos_libsys::console_read`
//!   and `arcos_libsys::print`). A `FbBackend` can replace it post-Scanout-2
//!   without changing consumer code.
//! - A [`Terminal`] that composes a backend with the parser and exposes
//!   `next_event(deadline_ticks)` — the lone-ESC ambiguity is resolved via
//!   a caller-provided deadline measured in 10ms ticks.
//! - ANSI output helpers (cursor positioning, clear, color, style).
//! - A [`LineEditor`] with emacs-style bindings and bounded history.
//!
//! The parser is pure and has `#[cfg(test)]` coverage runnable on host
//! (`cargo test`). Everything else is bare-metal-only and expects the
//! consumer crate to provide a panic handler.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod events;
pub mod parser;

#[cfg(not(test))]
pub mod backend;
#[cfg(not(test))]
pub mod output;
#[cfg(not(test))]
pub mod terminal;
#[cfg(not(test))]
pub mod line_editor;

pub use events::{Event, Key, Sig};
pub use parser::{Parser, ParserState};

#[cfg(not(test))]
pub use backend::{Backend, SerialBackend};
#[cfg(not(test))]
pub use terminal::Terminal;
#[cfg(not(test))]
pub use line_editor::LineEditor;
