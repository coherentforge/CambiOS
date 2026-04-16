// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Lazy-initialized disk-backed ObjectStore wrapper.
//!
//! Phase 4a.iii installs a `DiskObjectStore<VirtioBlkDevice>` as the kernel's
//! `OBJECT_STORE` backing. Construction requires reading the superblock, which
//! requires the virtio-blk user-space driver to be already running so it can
//! answer the handshake IPC. That condition is not met at `object_store_init`
//! time — drivers come up with the scheduler, after `object_store_init` has
//! already wired the store.
//!
//! `LazyDiskStore` defers the handshake + `open_or_format` to the first
//! `ObjectStore` method call. By that point the caller is a user task making
//! a `SYS_OBJ_*` syscall, which is exactly the context `VirtioBlkDevice::call`
//! needs — a valid `TaskId` to block on `MessageWait(25)` and yield.
//!
//! On every subsequent call the wrapper is a zero-cost pass-through to the
//! inner `DiskObjectStore`.

extern crate alloc;
use alloc::vec::Vec;

use crate::fs::disk::DiskObjectStore;
use crate::fs::virtio_blk_device::VirtioBlkDevice;
use crate::fs::{CambiObject, ObjectMeta, ObjectStore, StoreError};

pub struct LazyDiskStore {
    inner: Option<DiskObjectStore<VirtioBlkDevice>>,
    capacity_slots: u64,
}

impl LazyDiskStore {
    pub fn new(capacity_slots: u64) -> Self {
        Self {
            inner: None,
            capacity_slots,
        }
    }

    /// Perform the first-time handshake + superblock read. Must be called
    /// from a user-task syscall context (needs a current task for
    /// `VirtioBlkDevice::call` to block on `MessageWait(25)`).
    fn ensure(&mut self) -> Result<(), StoreError> {
        if self.inner.is_some() {
            return Ok(());
        }
        let device = VirtioBlkDevice::new();
        let store = DiskObjectStore::open_or_format(device, self.capacity_slots)?;
        self.inner = Some(store);
        Ok(())
    }
}

impl ObjectStore for LazyDiskStore {
    fn get(&mut self, hash: &[u8; 32]) -> Result<CambiObject, StoreError> {
        self.ensure()?;
        self.inner.as_mut().unwrap().get(hash)
    }

    fn put(&mut self, object: CambiObject) -> Result<[u8; 32], StoreError> {
        self.ensure()?;
        self.inner.as_mut().unwrap().put(object)
    }

    fn delete(&mut self, hash: &[u8; 32]) -> Result<(), StoreError> {
        self.ensure()?;
        self.inner.as_mut().unwrap().delete(hash)
    }

    fn list(&mut self) -> Result<Vec<([u8; 32], ObjectMeta)>, StoreError> {
        self.ensure()?;
        self.inner.as_mut().unwrap().list()
    }

    fn count(&self) -> usize {
        self.inner.as_ref().map(|s| s.count()).unwrap_or(0)
    }
}
