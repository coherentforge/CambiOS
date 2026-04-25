// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! `terminal-window` — GUI-hosted shell terminal.
//!
//! libgui client that opens a window, renders a 80x30 character grid
//! with the 8x8 builtin font, and drives `libterm`'s `Terminal` over a
//! `GuiBackend` adapter. Replaces the serial shell as the primary
//! user-facing surface.
//!
//! See `[plan](../../../.claude/plans/hi-let-s-talk-about-scalable-sketch.md)`
//! § "Revision: Terminal-in-Window (GUI-primary UX)" for the design.
//!
//! ## Modules
//!
//! - [`encoder`] — pure `InputEvent` → ANSI byte encoder. Host-tested
//!   round-trip against libterm's parser.
//! - [`grid`] — text grid + ANSI output state machine, dirty-row
//!   tracking. Host-tested.
//! - [`gui_backend`] — adapter implementing `libterm::Backend` over a
//!   live `libgui::Client` and `Grid`.
//! - [`render`] — 8x8 glyph blit per dirty row + cursor caret.
//!
//! `gui_backend` and `render` are bare-metal-only (use libgui/libsys
//! syscalls). The host test target compiles only the pure modules
//! (`encoder`, `grid`).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod encoder;
pub mod grid;

#[cfg(not(test))]
pub mod render;
#[cfg(not(test))]
pub mod gui_backend;
