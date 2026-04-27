// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kernel time-of-day. See [ADR-022](../../docs/adr/022-wall-clock-time.md)
//! for the design rationale; the implementation lives in [`wallclock`].

pub mod wallclock;

pub use wallclock::{get, set, source_tag};
