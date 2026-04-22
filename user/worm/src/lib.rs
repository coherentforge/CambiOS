// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Worm lib entry — exposes the pure-logic `game` module for host
//! unit-testing via `cargo test --lib --target x86_64-apple-darwin`.
//!
//! The bin crate (`main.rs` + `render.rs`) consumes these types
//! through the lib. Keeping `game` in a library lets its tests run
//! on the host without the `no_main` + `no_std` attrs on `main.rs`
//! breaking the test harness build — same pattern libgui /
//! libinput-proto / libgui-proto use.

#![cfg_attr(not(test), no_std)]

pub mod game;
