// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS init (PID 1) — supervisor logic (ADR-018 § 4).
//!
//! This library crate holds init's pure decision core; the binary
//! target (`src/main.rs`) is the thin syscall shell around it. The
//! split is the house sans-IO pattern (BuddyAllocator is the kernel
//! template): every ordering and failure path in the supervisor runs
//! as a host unit test against synthetic manifests, and the shell
//! contributes nothing but syscalls.
//!
//! Init's security posture makes this a low-stakes component to
//! iterate on, by construction: grants, endpoint reservations, and
//! identity were transcribed by the kernel before init's first
//! instruction. A buggy supervisor can mis-order or refuse to spawn;
//! it cannot mis-grant.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod engine;
