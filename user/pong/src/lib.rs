// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Pong lib entry — exposes the pure-logic `game` module for host
//! unit-testing via `cargo test --lib --target x86_64-apple-darwin`.
//!
//! Same library-split pattern as worm: the bin crate (`main.rs` +
//! `render.rs`) consumes these types through the lib, so `game`'s
//! tests can run on the host without `no_main` + `no_std` attrs on
//! `main.rs` breaking the test harness build.

#![cfg_attr(not(test), no_std)]

pub mod game;
