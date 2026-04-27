// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS userspace terminal styling.
//!
//! Two modules:
//!
//! - [`style`]: semantic ANSI-styling functions. Each takes a `&str`
//!   and returns a [`style::Styled`] wrapper whose `Display` impl
//!   emits the right escape sequences. No allocation, no globals.
//!
//! - [`format`]: structured-output helpers. [`format::principal_short`]
//!   produces a short did:key identifier for prompts and listings;
//!   [`format::key_value`] lays out a padded `key: value` line for
//!   help / info dumps.
//!
//! Composition reads like English at the call site:
//!
//! ```ignore
//! use cambios_style::{format, style};
//!
//! write!(out, "{}@{}:{}> ",
//!     style::dim("cambios"),
//!     style::principal(format::principal_short(&pubkey).as_str()),
//!     style::time("13:42"))?;
//! ```
//!
//! The palette is 16-color VGA-safe so output renders correctly on
//! every terminal back to VT100 (QEMU serial, real hardware tty,
//! and the in-tree compositor renderer). Color is hardcoded on for
//! v0; `NO_COLOR` honoring is a follow-up — `Revisit when:` the
//! first NO_COLOR consumer surfaces (e.g., a non-interactive pipe
//! or a monochrome terminal target).
//!
//! Verification posture: every escape sequence is a `const &'static
//! str`. The semantic functions are pure transformations of `&str`;
//! no I/O, no globals, no state. Host-runnable tests assert exact
//! byte sequences.

#![cfg_attr(not(test), no_std)]

pub mod format;
pub mod style;
