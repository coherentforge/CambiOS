// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Syscall definitions and numbers
//!
//! Defines the syscall ABI and interfaces that userspace drivers use
//! to request kernel services.
//!
//! As of the syscall-abi-crate refactor, the ABI types
//! ([`SyscallNumber`], [`SyscallError`], [`SyscallArgs`],
//! [`SyscallResult`]) live in the standalone `arcos-abi` crate so
//! they can be shared with userspace (`arcos-libsys`) without
//! duplication. This module re-exports them so existing kernel call
//! sites — `use crate::syscalls::SyscallNumber` and friends — keep
//! compiling unchanged.

pub mod dispatcher;
pub mod user_slice;
pub mod userspace;

#[cfg(fuzzing)]
pub mod fuzz_fixture;

pub use user_slice::{UserReadSlice, UserWriteSlice};

// Re-export the ABI surface from arcos-abi so kernel call sites
// continue to use `crate::syscalls::SyscallNumber`, etc. unchanged.
// The single source of truth lives in `arcos-abi/src/lib.rs`; tests
// for identity-gating completeness, exempt-set membership, and
// `from_u64` round-trip live there too.
pub use arcos_abi::{SyscallNumber, SyscallError, SyscallArgs, SyscallResult};
