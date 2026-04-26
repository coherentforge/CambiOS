// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Fuzzing-only kernel state fixture.
//!
//! Bridges libfuzzer-driven fuzz targets (under `fuzz/`) to
//! [`SyscallDispatcher::dispatch`]. The dispatcher reads
//! `crate::CAPABILITY_MANAGER` and `crate::policy::policy_check`
//! before any handler runs; without a populated `CapabilityManager`,
//! every dispatch attempt panics on the `lock()` of an
//! uninitialized `Option<Box<…>>`.
//!
//! [`KernelFixture::minimal`] populates the smallest viable kernel
//! state for the dispatch front-end:
//!
//! - `CAPABILITY_MANAGER` populated via [`CapabilityManager::new_for_test`].
//! - One process registered (slot 1, generation 0).
//! - That process bound to a deterministic non-zero `Principal`.
//!
//! The policy service is left in its default state
//! (`POLICY_SERVICE_READY = false`), so `policy_check` falls through
//! to `Allow`; per-CPU audit buffers are `const`-initialized; and
//! [`crate::audit::emit`] is a no-op under `cfg(fuzzing)`. No
//! IPC/scheduler/frame-allocator setup — handlers that require
//! those return typed errors rather than panic, which is the
//! property we are fuzzing for.
//!
//! Idempotent: subsequent calls re-use the existing fixture without
//! re-registering. This lets the same libfuzzer worker drive many
//! `dispatch()` iterations without leaking handles between runs.

use crate::ipc::{Principal, ProcessId};
use crate::ipc::capability::CapabilityManager;
use crate::scheduler::TaskId;
use crate::syscalls::dispatcher::SyscallContext;

/// Slot used for the fixture's single registered process.
const FIXTURE_SLOT: u32 = 1;
/// Generation for the fixture process. Slot 1 is fresh under the fixture's
/// `CapabilityManager`, so generation 0 is the only valid value.
const FIXTURE_GENERATION: u32 = 0;
/// Task id assigned to the fixture process. Not load-bearing for the
/// dispatcher front-end (no scheduler is initialized), but handlers that
/// inspect `ctx.task_id` need a stable non-zero value.
const FIXTURE_TASK: u32 = 1;

/// Deterministic non-zero Principal so the identity gate inside
/// [`SyscallDispatcher::dispatch`] does not short-circuit identity-required
/// syscalls. The bytes are arbitrary; only "non-zero" matters.
const FIXTURE_PRINCIPAL_BYTES: [u8; 32] = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
];

/// Initialized kernel state for fuzz-driven dispatch invocations.
pub struct KernelFixture {
    process_id: ProcessId,
    task_id: TaskId,
}

impl KernelFixture {
    /// Initialize the smallest viable kernel state.
    ///
    /// Must be called before the first `SyscallDispatcher::dispatch` call.
    /// Idempotent — repeated calls observe the existing state and return
    /// a fresh handle to it.
    pub fn minimal() -> Self {
        let pid = ProcessId::new(FIXTURE_SLOT, FIXTURE_GENERATION);
        let principal = Principal::from_public_key(FIXTURE_PRINCIPAL_BYTES);

        // Populate CAPABILITY_MANAGER if absent. The lock is uncontended in
        // a libfuzzer worker; a Spinlock is fine.
        let mut guard = crate::CAPABILITY_MANAGER.lock();
        if guard.is_none() {
            let mut mgr = CapabilityManager::new_for_test();
            // `register_process` errors on already-registered slot; we just
            // confirmed `is_none()` so the slot is fresh.
            let _ = mgr.register_process(pid);
            let _ = mgr.bind_principal(pid, principal);
            *guard = Some(mgr);
        }
        drop(guard);

        Self {
            process_id: pid,
            task_id: TaskId(FIXTURE_TASK),
        }
    }

    /// `SyscallContext` for the fixture process.
    ///
    /// `cr3 = 0` — the dispatcher front-end does not page-walk; handlers
    /// that try to read user buffers will reject the zero CR3 via
    /// `UserReadSlice` / `UserWriteSlice`. That is the desired
    /// behavior for fuzzing dispatch routing.
    ///
    /// `caller_principal` is left `None`; the dispatcher overwrites it on
    /// entry by re-resolving from `CAPABILITY_MANAGER`.
    pub fn ctx(&self) -> SyscallContext {
        SyscallContext {
            process_id: self.process_id,
            task_id: self.task_id,
            cr3: 0,
            caller_principal: None,
        }
    }
}
