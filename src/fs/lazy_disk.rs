// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Lazy-initialized disk-backed ObjectStore swap.
//!
//! At boot, `OBJECT_STORE` holds a `RamObjectStore` (in-memory, fast, no IPC).
//! On the first `SYS_OBJ_*` syscall, `ensure_disk_store()` is called **before**
//! acquiring the `OBJECT_STORE` lock. It handshakes with the user-space
//! virtio-blk driver over IPC (which yields the calling task), creates a
//! `DiskObjectStore`, and swaps it in under the lock. Subsequent calls see
//! the disk store and skip the handshake (atomic fast path).
//!
//! ## Why not hold OBJECT_STORE across the handshake?
//!
//! `VirtioBlkDevice::call` yields the calling task via `yield_save_and_switch`.
//! Holding a `Spinlock` across a yield violates the spinlock contract — the
//! scheduler may migrate the lock holder or allow another task to spin on the
//! same lock indefinitely. In practice, holding `OBJECT_STORE` across the
//! handshake caused a permanent stall: the calling task yielded inside the
//! IPC poll loop, virtio-blk processed the message and replied, but the
//! calling task was never re-scheduled because the spinlock interaction
//! prevented the scheduler from picking it up correctly.
//!
//! The fix: handshake first (no locks held), then install under lock (fast,
//! no IPC, no yield).

use core::sync::atomic::{AtomicBool, Ordering};

use crate::fs::disk::DiskObjectStore;
use crate::fs::virtio_blk_device::VirtioBlkDevice;

/// Atomic flag: `true` once the disk store has been successfully installed
/// in `OBJECT_STORE`. Fast-path check — avoids re-entering the handshake
/// on every subsequent syscall.
static DISK_STORE_READY: AtomicBool = AtomicBool::new(false);

/// Ensure the disk-backed `ObjectStore` is installed. Must be called
/// **without** holding `OBJECT_STORE`. No-op after the first successful
/// call (atomic fast path).
///
/// On failure (driver not available, device error, format failure), the
/// existing `RamObjectStore` remains — arcobj commands work but objects
/// don't persist across reboots.
pub fn ensure_disk_store() {
    if DISK_STORE_READY.load(Ordering::Acquire) {
        return;
    }

    // Phase 1: handshake + open, no locks held. IPC yields are safe here.
    let mut device = VirtioBlkDevice::new();
    if device.ensure_handshake().is_err() {
        // Driver not available (e.g., AArch64 with no virtio-blk device).
        // Mark ready so we don't retry on every syscall.
        DISK_STORE_READY.store(true, Ordering::Release);
        crate::println!("  [ObjectStore] disk handshake failed, staying on RAM store");
        return;
    }

    let capacity = device.capacity_blocks_cached();
    let store = match DiskObjectStore::open_or_format(device, capacity) {
        Ok(s) => s,
        Err(e) => {
            DISK_STORE_READY.store(true, Ordering::Release);
            crate::println!("  [ObjectStore] disk open/format failed ({:?}), staying on RAM store", e);
            return;
        }
    };

    // Phase 2: install under lock (fast — no IPC, no yield).
    // Wraps the disk store in the `LazyDisk` variant of `ObjectStoreBackend`
    // (enum-dispatch shim per ADR-003 § Divergence) — no `dyn` trait object.
    {
        let mut guard = crate::OBJECT_STORE.lock();
        *guard = Some(crate::fs::ObjectStoreBackend::LazyDisk(
            alloc::boxed::Box::new(store),
        ));
    }

    DISK_STORE_READY.store(true, Ordering::Release);
    crate::println!("  [ObjectStore] disk store active (capacity {} blocks)", capacity);
}
