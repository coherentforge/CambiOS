// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Lazy disk-store gate — vestigial after ADR-032 stream A A-v.d.
//!
//! Pre-A-v.d, this module ran the virtio-blk handshake on the first
//! `SYS_OBJ_*` syscall and swapped `OBJECT_STORE` from RAM to a
//! disk-backed store. With FDE-by-default per [ADR-032
//! § Architecture](../../../docs/adr/032-full-disk-encryption-below-substrate.md),
//! that swap moved into `SYS_INSTALL_MASTER_KEY`'s handler — disk
//! mount requires the master key, which has to come through that
//! syscall, so the lazy trigger is no longer load-bearing.
//!
//! What stays:
//!
//! - [`ensure_disk_store`] still exists so the five `SYS_OBJ_*`
//!   call sites in [crate::syscalls::dispatcher] don't need to
//!   change; calling it is now a cheap atomic fast-path check.
//! - [`mark_disk_store_installed`] is called by
//!   `handle_install_master_key` after it installs the
//!   `LazyDisk` variant; flips the readiness flag so future
//!   `ensure_disk_store` calls early-out.
//!
//! Without `SYS_INSTALL_MASTER_KEY`, `OBJECT_STORE` stays on its
//! boot-initialized `Ram` variant indefinitely (degraded mode —
//! objects exist but don't persist across reboots). This is the
//! correct FDE-by-default posture: if no master key has been
//! handed to the kernel, the kernel does **not** mount the raw
//! disk unencrypted.

use core::sync::atomic::{AtomicBool, Ordering};

/// Atomic flag: `true` once `SYS_INSTALL_MASTER_KEY` has installed
/// the disk-backed `LazyDisk` variant of `OBJECT_STORE`. Toggled
/// only by [`mark_disk_store_installed`]; observed by
/// [`ensure_disk_store`] as a cheap fast-path gate.
static DISK_STORE_READY: AtomicBool = AtomicBool::new(false);

/// Cheap fast-path: returns immediately if the disk store has been
/// installed, or unconditionally if it hasn't (no work to do —
/// kernel stays on RAM). The five `SYS_OBJ_*` dispatcher arms call
/// this before acquiring `OBJECT_STORE`; pre-A-v.d the call did
/// work, post-A-v.d it's a fence.
///
/// Left in place rather than removed so the dispatcher call sites
/// don't need to change in lockstep with this commit — they can
/// be cleaned up at a future tidy pass once the FDE flow is
/// fully landed.
pub fn ensure_disk_store() {
    let _ = DISK_STORE_READY.load(Ordering::Acquire);
}

/// Flip the readiness flag. Called by `handle_install_master_key`
/// after the `LazyDisk` variant is in place.
pub fn mark_disk_store_installed() {
    DISK_STORE_READY.store(true, Ordering::Release);
}
