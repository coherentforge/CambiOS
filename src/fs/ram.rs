// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! RAM-backed ObjectStore implementation
//!
//! Fixed-capacity (256 objects), heap-allocated, linear scan.
//! Phase 0: no crypto verification, no disk persistence.
//! Suitable for kernel integration testing and early user-space modules.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::alloc::{alloc, Layout};

use super::{CambiObject, ObjectStore, ObjectMeta, StoreError, content_hash};

/// SCAFFOLDING: maximum number of objects in the RAM store.
/// Why: Phase 0 RAM-backed store with a fixed-capacity array. Linear scan for
///      get/delete/list is fine at this size.
/// Replace when: persistent ObjectStore (Phase 4) lands — that backend will be
///      dynamically sized and this constant goes away. Until then, the first
///      time we want to store > 256 objects this is the wall. See docs/ASSUMPTIONS.md.
pub const MAX_OBJECTS: usize = 256;

/// RAM-backed ObjectStore.
///
/// Stores up to `MAX_OBJECTS` CambiObjects in a heap-allocated array.
/// Linear scan for get/delete/list — fine for Phase 0 testing.
///
/// Heap-allocated via `new_boxed()` to avoid stack overflow (matches
/// existing kernel conventions for large structs).
pub struct RamObjectStore {
    /// Object slots. `Some(obj)` = occupied, `None` = free.
    objects: [Option<CambiObject>; MAX_OBJECTS],
    /// Number of stored objects.
    count: usize,
}

impl RamObjectStore {
    /// Create a new empty RAM store directly on the heap.
    ///
    /// Uses manual allocation because the struct is too large for the
    /// 256KB boot stack. Returns `None` if the heap is exhausted.
    pub fn new_boxed() -> Option<Box<Self>> {
        let layout = Layout::new::<Self>();
        // SAFETY: Layout is non-zero-sized (contains array of 256 Option<CambiObject>).
        let ptr = unsafe { alloc(layout) as *mut Self };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: We write every field before constructing the Box.
        // Cannot use alloc_zeroed because Option<CambiObject> contains Vec<u8>
        // (a fat pointer) — zeroed memory is not valid for Option<Vec>.
        // Instead, write None to each slot explicitly.
        for i in 0..MAX_OBJECTS {
            // SAFETY: ptr is valid, non-null. Accessing objects[i] field.
            let slot = unsafe { core::ptr::addr_of_mut!((*ptr).objects[i]) };
            // SAFETY: slot is a valid pointer within the allocated layout.
            unsafe { slot.write(None) };
        }
        // SAFETY: ptr is valid — accessing count field.
        let count_ptr = unsafe { core::ptr::addr_of_mut!((*ptr).count) };
        // SAFETY: count_ptr is valid — writing initial count.
        unsafe { count_ptr.write(0) };
        // SAFETY: All fields initialized. ptr was allocated with the correct layout.
        Some(unsafe { Box::from_raw(ptr) })
    }

    /// Find the slot index for an object by content hash.
    fn find_index(&self, hash: &[u8; 32]) -> Option<usize> {
        for i in 0..MAX_OBJECTS {
            if let Some(ref obj) = self.objects[i] {
                if obj.content_hash == *hash {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Find the first free slot.
    fn find_free_slot(&self) -> Option<usize> {
        self.objects.iter().position(|slot| slot.is_none())
    }

    /// Current capacity remaining.
    pub fn remaining(&self) -> usize {
        MAX_OBJECTS - self.count
    }
}

impl ObjectStore for RamObjectStore {
    fn get(&mut self, hash: &[u8; 32]) -> Result<CambiObject, StoreError> {
        let idx = self.find_index(hash).ok_or(StoreError::NotFound)?;
        self.objects[idx]
            .as_ref()
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    fn put(&mut self, object: CambiObject) -> Result<[u8; 32], StoreError> {
        // Verify content_hash matches actual content
        let computed = content_hash(&object.content);
        if computed != object.content_hash {
            return Err(StoreError::InvalidObject);
        }

        // Check if object already exists (content-addressed = idempotent put)
        if self.find_index(&object.content_hash).is_some() {
            return Ok(object.content_hash);
        }

        let slot = self.find_free_slot().ok_or(StoreError::CapacityExceeded)?;
        let hash = object.content_hash;
        self.objects[slot] = Some(object);
        self.count += 1;
        Ok(hash)
    }

    fn delete(&mut self, hash: &[u8; 32]) -> Result<(), StoreError> {
        let idx = self.find_index(hash).ok_or(StoreError::NotFound)?;
        self.objects[idx] = None;
        self.count -= 1;
        Ok(())
    }

    fn list(&mut self) -> Result<Vec<([u8; 32], ObjectMeta)>, StoreError> {
        let mut result = Vec::with_capacity(self.count);
        for i in 0..MAX_OBJECTS {
            if let Some(ref obj) = self.objects[i] {
                result.push((
                    obj.content_hash,
                    ObjectMeta {
                        owner: obj.owner,
                        author: obj.author,
                        created_at: obj.created_at,
                        content_len: obj.content.len(),
                    },
                ));
            }
        }
        Ok(result)
    }

    fn count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::Principal;

    fn make_store() -> Box<RamObjectStore> {
        RamObjectStore::new_boxed().expect("test: failed to allocate RamObjectStore")
    }

    fn make_object(data: &[u8]) -> CambiObject {
        let author = Principal::from_public_key([1u8; 32]);
        CambiObject::new(author, data.to_vec(), 100)
    }

    #[test]
    fn test_put_and_get() {
        let mut store = make_store();
        let obj = make_object(b"hello world");
        let hash = store.put(obj).unwrap();

        let retrieved = store.get(&hash).unwrap();
        assert_eq!(retrieved.content, b"hello world");
        assert_eq!(retrieved.author, [1u8; 32]);
        assert_eq!(retrieved.owner, [1u8; 32]);
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_get_not_found() {
        let mut store = make_store();
        let fake_hash = [0xFFu8; 32];
        assert_eq!(store.get(&fake_hash), Err(StoreError::NotFound));
    }

    #[test]
    fn test_put_idempotent() {
        let mut store = make_store();
        let obj1 = make_object(b"same content");
        let obj2 = make_object(b"same content");

        let hash1 = store.put(obj1).unwrap();
        let hash2 = store.put(obj2).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(store.count(), 1); // Only stored once
    }

    #[test]
    fn test_put_invalid_hash() {
        let mut store = make_store();
        let mut obj = make_object(b"data");
        obj.content_hash = [0u8; 32]; // Wrong hash

        assert_eq!(store.put(obj), Err(StoreError::InvalidObject));
    }

    #[test]
    fn test_delete() {
        let mut store = make_store();
        let obj = make_object(b"deleteme");
        let hash = store.put(obj).unwrap();

        assert_eq!(store.count(), 1);
        store.delete(&hash).unwrap();
        assert_eq!(store.count(), 0);
        assert_eq!(store.get(&hash), Err(StoreError::NotFound));
    }

    #[test]
    fn test_delete_not_found() {
        let mut store = make_store();
        let fake = [0xAAu8; 32];
        assert_eq!(store.delete(&fake), Err(StoreError::NotFound));
    }

    #[test]
    fn test_list() {
        let mut store = make_store();
        let obj1 = make_object(b"alpha");
        let obj2 = make_object(b"beta");

        let hash1 = store.put(obj1).unwrap();
        let hash2 = store.put(obj2).unwrap();

        let listing = store.list().unwrap();
        assert_eq!(listing.len(), 2);

        let hashes: Vec<[u8; 32]> = listing.iter().map(|(h, _)| *h).collect();
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));

        // Verify metadata
        for (_, meta) in &listing {
            assert_eq!(meta.author, [1u8; 32]);
            assert_eq!(meta.owner, [1u8; 32]);
            assert_eq!(meta.created_at, 100);
        }
    }

    #[test]
    fn test_list_empty() {
        let mut store = make_store();
        let listing = store.list().unwrap();
        assert!(listing.is_empty());
    }

    #[test]
    fn test_capacity_exhaustion() {
        let mut store = make_store();

        // Fill to capacity
        for i in 0..MAX_OBJECTS {
            let data = alloc::format!("object-{}", i);
            let obj = make_object(data.as_bytes());
            store.put(obj).unwrap();
        }
        assert_eq!(store.count(), MAX_OBJECTS);
        assert_eq!(store.remaining(), 0);

        // One more should fail
        let overflow = make_object(b"overflow");
        assert_eq!(store.put(overflow), Err(StoreError::CapacityExceeded));
    }

    #[test]
    fn test_delete_then_reuse_slot() {
        let mut store = make_store();

        let obj1 = make_object(b"first");
        let hash1 = store.put(obj1).unwrap();
        assert_eq!(store.count(), 1);

        store.delete(&hash1).unwrap();
        assert_eq!(store.count(), 0);

        // Should be able to insert again
        let obj2 = make_object(b"second");
        store.put(obj2).unwrap();
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_author_preserved_through_store() {
        let mut store = make_store();
        let author = Principal::from_public_key([0xAA; 32]);
        let owner = Principal::from_public_key([0xBB; 32]);
        let obj = CambiObject::new_with_owner(author, owner, alloc::vec![1, 2, 3], 42);
        let hash = store.put(obj).unwrap();

        let retrieved = store.get(&hash).unwrap();
        assert_eq!(retrieved.author, [0xAA; 32]); // Author preserved
        assert_eq!(retrieved.owner, [0xBB; 32]);   // Owner preserved
        assert_ne!(retrieved.author, retrieved.owner); // Distinct
    }

    #[test]
    fn test_remaining_tracks_correctly() {
        let mut store = make_store();
        assert_eq!(store.remaining(), MAX_OBJECTS);

        let obj = make_object(b"test");
        let hash = store.put(obj).unwrap();
        assert_eq!(store.remaining(), MAX_OBJECTS - 1);

        store.delete(&hash).unwrap();
        assert_eq!(store.remaining(), MAX_OBJECTS);
    }
}
