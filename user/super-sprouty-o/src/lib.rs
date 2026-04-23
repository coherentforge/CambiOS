// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O library crate — exposes pure-logic modules so
//! physics, collision, camera math, and level helpers are host-testable
//! via `cargo test --lib --target x86_64-apple-darwin`, same split
//! pattern as pong + worm.
//!
//! - [`level`]: static tilemap + viewport constants + visible-range
//!   culling math (Session 2a onward).
//! - [`game`]: player / weed / camera state and the deterministic tick
//!   function (Session 2b onward).

#![cfg_attr(not(test), no_std)]

pub mod game;
pub mod level;
