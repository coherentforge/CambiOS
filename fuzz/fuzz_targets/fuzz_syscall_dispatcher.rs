// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Fuzz target: `SyscallDispatcher::dispatch` (Tier 1 step B,
//! ~/.claude/plans/scope-tier-2-also-prancy-manatee.md).
//!
//! Drives random `(syscall_num, 6 × u64 args)` tuples through the
//! kernel's syscall dispatch front-end. Catches panics, OOB reads,
//! and arithmetic overflows on the dispatcher routing path and as
//! deep into individual handlers as the minimal kernel fixture
//! supports.
//!
//! Input layout: 56 bytes.
//!   [ 0.. 8] u64 syscall_num
//!   [ 8..16] u64 arg1
//!   [16..24] u64 arg2
//!   [24..32] u64 arg3
//!   [32..40] u64 arg4
//!   [40..48] u64 arg5
//!   [48..56] u64 arg6
//!
//! Pointer-shaped args reach handler-side validation before any
//! deref. The fixture uses `cr3 = 0`, so any user-pointer page-walk
//! early-rejects via `UserReadSlice` / `UserWriteSlice`. Handlers
//! that need IPC / scheduler / frame-allocator state return typed
//! errors when those subsystems are uninitialized.

#![no_main]

use libfuzzer_sys::fuzz_target;

use arcos_core::syscalls::dispatcher::SyscallDispatcher;
use arcos_core::syscalls::fuzz_fixture::KernelFixture;
use arcos_core::syscalls::SyscallArgs;

const INPUT_LEN: usize = 56;

fuzz_target!(|data: &[u8]| {
    if data.len() < INPUT_LEN {
        return;
    }

    let mut buf = [0u8; INPUT_LEN];
    buf.copy_from_slice(&data[..INPUT_LEN]);

    let syscall_num = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let arg1 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let arg2 = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let arg3 = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let arg4 = u64::from_le_bytes(buf[32..40].try_into().unwrap());
    let arg5 = u64::from_le_bytes(buf[40..48].try_into().unwrap());
    let arg6 = u64::from_le_bytes(buf[48..56].try_into().unwrap());
    let args = SyscallArgs::new(arg1, arg2, arg3, arg4, arg5, arg6);

    let fixture = KernelFixture::minimal();
    let ctx = fixture.ctx();

    let _ = SyscallDispatcher::dispatch(syscall_num, args, ctx);
});
