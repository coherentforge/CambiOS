// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Library crate for `cambios-key-store-service`.
//!
//! Houses the testable building blocks the service binary composes:
//! today, the PIV backend abstraction. The binary at `src/main.rs` uses
//! these types but its own boot-and-service-loop logic is not exported
//! through the library surface.

#![no_std]
#![deny(unsafe_code)]

#[cfg(test)]
extern crate std;

#[cfg(feature = "dev-piv")]
pub mod piv;
