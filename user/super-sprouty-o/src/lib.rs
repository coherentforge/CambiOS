// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Super Sprouty-O lib entry — will expose pure-logic game + level
//! modules for host unit-testing via `cargo test --lib --target
//! x86_64-apple-darwin`, same split pattern as worm + pong. Game logic
//! lands in Session 2 (physics, AABB tile collision, camera, weed AI);
//! this stub exists so the crate auto-detects both bin + lib targets
//! from day one.

#![cfg_attr(not(test), no_std)]
