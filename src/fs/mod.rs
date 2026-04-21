// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS Object Store — content-addressed signed object storage
//!
//! The native CambiOS storage model. Files are not bytes-at-a-path; they are
//! content-addressed signed objects with an immutable author, a transferable
//! owner, and a cryptographic signature tying content to controller.
//!
//! Phase 1B: Real crypto. Content hashing uses Blake3. Signatures use
//! Ed25519 and are verified on retrieval.
//!
//! The interfaces defined here are permanent. The implementations evolve.

pub mod block;
pub mod disk;
#[cfg(not(test))]
pub mod lazy_disk;
pub mod ram;
#[cfg(not(test))]
pub mod virtio_blk_device;

/// Test-mode stub for lazy_disk. The real module performs IPC handshake
/// with the user-space virtio-blk driver; in host tests neither IPC nor
/// the driver exists, so syscall-handler tests get a no-op.
#[cfg(test)]
pub mod lazy_disk {
    pub fn ensure_disk_store() {
        // No-op: tests use RamObjectStore directly.
    }
}

extern crate alloc;
use alloc::vec::Vec;
use crate::ipc::Principal;

// ============================================================================
// Content hashing (Blake3 — cryptographic, 256-bit)
// ============================================================================

/// Blake3 content hash producing a 32-byte (256-bit) output.
///
/// Blake3 is a cryptographic hash function: collision-resistant, preimage-
/// resistant, and extremely fast. Used as the content address for CambiObjects.
pub fn content_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

// ============================================================================
// Ed25519 signature operations
// ============================================================================

/// Sign content with an Ed25519 secret key. Returns a 64-byte signature.
///
/// `secret_key_bytes` is the 64-byte Ed25519 secret key (seed || public key).
/// Deterministic signing (no noise) — same input always produces the same signature.
pub fn sign_content(secret_key_bytes: &[u8; 64], content: &[u8]) -> SignatureBytes {
    let sk = ed25519_compact::SecretKey::new(*secret_key_bytes);
    let sig = sk.sign(content, None);
    let mut data = [0u8; 64];
    data.copy_from_slice(sig.as_ref());
    SignatureBytes { data }
}

/// Verify an Ed25519 signature over content using the signer's public key.
///
/// Returns `true` if the signature is valid, `false` otherwise.
/// A zeroed (empty) signature always fails verification.
pub fn verify_signature(public_key: &[u8; 32], content: &[u8], signature: &SignatureBytes) -> bool {
    // Empty signatures always fail
    if signature.data == [0u8; 64] {
        return false;
    }
    let pk = ed25519_compact::PublicKey::new(*public_key);
    let sig = ed25519_compact::Signature::new(signature.data);
    pk.verify(content, &sig).is_ok()
}

/// Derive an Ed25519 keypair from a 32-byte seed.
///
/// Returns (public_key: [u8; 32], secret_key: [u8; 64]).
/// The secret key is 64 bytes: seed || public_key (Ed25519 convention).
pub fn keypair_from_seed(seed: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
    let ed_seed = ed25519_compact::Seed::new(*seed);
    let kp = ed25519_compact::KeyPair::from_seed(ed_seed);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.pk.as_ref());
    let mut sk = [0u8; 64];
    sk.copy_from_slice(kp.sk.as_ref());
    (pk, sk)
}

// ============================================================================
// Signature types
// ============================================================================

/// Signature algorithm tag. Phase 1B uses Ed25519.
/// ML-DSA-65 (post-quantum) is Phase 1.5+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureAlgo {
    Ed25519 = 0,
    MlDsa65 = 1,
}

/// Signature bytes. Fixed at 64 bytes for Ed25519.
/// Phase 1.5+ extends to variable-length for ML-DSA (3293 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBytes {
    /// Ed25519 signature (64 bytes). Zeroed = unsigned.
    pub data: [u8; 64],
}

impl SignatureBytes {
    pub const EMPTY: Self = SignatureBytes { data: [0u8; 64] };

    /// Returns true if the signature is empty (all zeros = unsigned).
    pub fn is_empty_sig(&self) -> bool {
        self.data == [0u8; 64]
    }
}

// ============================================================================
// Object capabilities (ACL)
// ============================================================================

/// Maximum capabilities (ACL entries) per object.
pub const MAX_OBJECT_CAPS: usize = 8;

/// Rights a Principal has on an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRights {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl ObjectRights {
    pub const NONE: Self = ObjectRights { read: false, write: false, execute: false };
    pub const READ_ONLY: Self = ObjectRights { read: true, write: false, execute: false };
    pub const READ_WRITE: Self = ObjectRights { read: true, write: true, execute: false };
    pub const FULL: Self = ObjectRights { read: true, write: true, execute: true };
}

/// A single ACL entry: a Principal and its rights on an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectCapability {
    pub principal: Principal,
    pub rights: ObjectRights,
    /// Optional expiry (monotonic ticks). None = no expiry.
    pub expiry: Option<u64>,
}

/// Capability set for an object — bounded array of ACL entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectCapSet {
    caps: [Option<ObjectCapability>; MAX_OBJECT_CAPS],
    count: u8,
}

impl Default for ObjectCapSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectCapSet {
    pub const fn new() -> Self {
        ObjectCapSet {
            caps: [None; MAX_OBJECT_CAPS],
            count: 0,
        }
    }

    /// Grant rights to a Principal. Updates existing entry if present.
    pub fn grant(&mut self, principal: Principal, rights: ObjectRights, expiry: Option<u64>) -> Result<(), StoreError> {
        // Update existing
        for i in 0..self.count as usize {
            if let Some(ref mut cap) = self.caps[i] {
                if cap.principal == principal {
                    cap.rights = rights;
                    cap.expiry = expiry;
                    return Ok(());
                }
            }
        }
        // Add new
        if self.count as usize >= MAX_OBJECT_CAPS {
            return Err(StoreError::CapacityExceeded);
        }
        self.caps[self.count as usize] = Some(ObjectCapability { principal, rights, expiry });
        self.count += 1;
        Ok(())
    }

    /// Check if a Principal has the required rights.
    pub fn check(&self, principal: &Principal, required: ObjectRights) -> bool {
        for i in 0..self.count as usize {
            if let Some(ref cap) = self.caps[i] {
                if cap.principal == *principal {
                    return (!required.read || cap.rights.read)
                        && (!required.write || cap.rights.write)
                        && (!required.execute || cap.rights.execute);
                }
            }
        }
        false
    }

    /// Number of active ACL entries.
    pub fn len(&self) -> usize {
        self.count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over the active capabilities (skipping empty slots).
    pub fn iter(&self) -> impl Iterator<Item = &ObjectCapability> {
        self.caps[..self.count as usize]
            .iter()
            .filter_map(|slot| slot.as_ref())
    }
}

// ============================================================================
// CambiObject — the fundamental storage unit
// ============================================================================

/// An CambiObject is the native CambiOS storage unit: a content-addressed,
/// signed, ownership-tracked object.
///
/// - `author` is immutable: set at creation, records who made this.
/// - `owner` is transferable: the current controller who signs the object.
/// - `content_hash` is the object's address (content-derived).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CambiObject {
    /// Content hash — the object's unique address (Blake3).
    pub content_hash: [u8; 32],
    /// Creator's public key — IMMUTABLE after creation. Historical fact.
    pub author: [u8; 32],
    /// Current controller's public key — transferable via OwnershipTransfer.
    pub owner: [u8; 32],
    /// Signature algorithm used.
    pub sig_algo: SignatureAlgo,
    /// Owner's Ed25519 signature over content. Verified on retrieval.
    pub signature: SignatureBytes,
    /// Access control list.
    pub capabilities: ObjectCapSet,
    /// Hash of parent object (provenance chain). None = root object.
    pub lineage: Option<[u8; 32]>,
    /// Creation timestamp (monotonic ticks from kernel timer).
    pub created_at: u64,
    /// The actual content bytes.
    pub content: Vec<u8>,
}

impl CambiObject {
    /// Create a new CambiObject. The author is set here and cannot be changed.
    ///
    /// `content_hash` is computed from `content`. `owner` defaults to `author`
    /// (creator is controller unless ownership is explicitly transferred).
    pub fn new(author: Principal, content: Vec<u8>, created_at: u64) -> Self {
        let hash = content_hash(&content);
        CambiObject {
            content_hash: hash,
            author: author.public_key,
            owner: author.public_key, // Creator is initial owner
            sig_algo: SignatureAlgo::Ed25519,
            signature: SignatureBytes::EMPTY,
            capabilities: ObjectCapSet::new(),
            lineage: None,
            created_at,
            content,
        }
    }

    /// Create with explicit owner (different from author).
    pub fn new_with_owner(
        author: Principal,
        owner: Principal,
        content: Vec<u8>,
        created_at: u64,
    ) -> Self {
        let hash = content_hash(&content);
        CambiObject {
            content_hash: hash,
            author: author.public_key,
            owner: owner.public_key,
            sig_algo: SignatureAlgo::Ed25519,
            signature: SignatureBytes::EMPTY,
            capabilities: ObjectCapSet::new(),
            lineage: None,
            created_at,
            content,
        }
    }

    /// Set lineage (parent hash) for provenance tracking.
    pub fn with_lineage(mut self, parent_hash: [u8; 32]) -> Self {
        self.lineage = Some(parent_hash);
        self
    }

    /// Get the author as a Principal.
    pub fn author_principal(&self) -> Principal {
        Principal::from_public_key(self.author)
    }

    /// Get the owner as a Principal.
    pub fn owner_principal(&self) -> Principal {
        Principal::from_public_key(self.owner)
    }
}

// ============================================================================
// Object metadata (lightweight, for listings)
// ============================================================================

/// Lightweight metadata for object listings — avoids loading full content.
#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub owner: [u8; 32],
    pub author: [u8; 32],
    pub created_at: u64,
    pub content_len: usize,
}

// ============================================================================
// ObjectStore trait
// ============================================================================

/// Errors from object store operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// Object not found by hash.
    NotFound,
    /// Store is at capacity (RAM store limit).
    CapacityExceeded,
    /// Object failed validation (bad hash, invalid fields).
    InvalidObject,
    /// Caller lacks permission for this operation.
    PermissionDenied,
    /// Signature verification failed (tampered or unsigned object).
    InvalidSignature,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Object not found"),
            Self::CapacityExceeded => write!(f, "Store capacity exceeded"),
            Self::InvalidObject => write!(f, "Invalid object"),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
        }
    }
}

/// The ObjectStore trait — the VFS abstraction for CambiOS.
///
/// Not a traditional block-device filesystem. Every backing store
/// (RAM, disk, sovereign cloud, P2P) implements this trait.
///
/// `get` returns an owned `CambiObject`. A disk-backed store cannot honor a
/// borrowed return without leaking page-cache policy into the trait; the
/// kernel-side caller already copies content into a bounded kernel buffer
/// before writing to userspace, so owning the return is effectively free for
/// the small objects the v1 syscall path permits.
///
/// `get` and `list` take `&mut self` because any non-memory-backed store
/// mutates internal queue state on reads (virtio descriptor rings, bounce
/// buffers, cache bookkeeping). Callers serialize access through the
/// `OBJECT_STORE` spinlock.
pub trait ObjectStore {
    /// Retrieve an object by content hash.
    fn get(&mut self, hash: &[u8; 32]) -> Result<CambiObject, StoreError>;

    /// Store an object. Returns the content hash (the object's address).
    /// The store verifies `content_hash` matches the content on put.
    fn put(&mut self, object: CambiObject) -> Result<[u8; 32], StoreError>;

    /// Delete an object by content hash.
    fn delete(&mut self, hash: &[u8; 32]) -> Result<(), StoreError>;

    /// List all objects with lightweight metadata. Disk-backed stores may
    /// return zero-filled `ObjectMeta` (the hash is authoritative; callers
    /// that need metadata call `get`).
    fn list(&mut self) -> Result<Vec<([u8; 32], ObjectMeta)>, StoreError>;

    /// Number of objects currently stored.
    fn count(&self) -> usize;
}

// ============================================================================
// ObjectStoreBackend — enum-dispatch shim for the kernel-side OBJECT_STORE
// ============================================================================
//
// The trait above is the *specification* — what every backend must implement.
// `ObjectStoreBackend` is the *impl shim* used at the kernel `OBJECT_STORE`
// static. It exists to satisfy CLAUDE.md's Formal Verification rule against
// `dyn` dispatch on kernel hot paths (every SYS_OBJ_* syscall touches this
// store). See ADR-003 § Divergence for the full decision rationale.
//
// Each backend lives behind a `Box<T>` so the per-variant memory cost stays
// off the boot stack. Adding a new backend = one new variant + one new arm
// per delegated method — closed-world, exhaustive, monomorphized.
//
// Test mode (`cfg(test)`) excludes the LazyDisk variant because
// `VirtioBlkDevice` is not available in host tests; tests construct
// only `Ram`.

/// Enum-dispatch shim for `ObjectStore` backends installed at the kernel-side
/// `OBJECT_STORE` static. See module-level note above.
pub enum ObjectStoreBackend {
    /// In-RAM, fixed-capacity store. Boot default; persistent only across
    /// the kernel's lifetime.
    Ram(alloc::boxed::Box<ram::RamObjectStore>),

    /// Disk-backed store fronted by the user-space virtio-blk driver. Swapped
    /// in by `lazy_disk::ensure_disk_store` on first `SYS_OBJ_*` call.
    #[cfg(not(test))]
    LazyDisk(alloc::boxed::Box<disk::DiskObjectStore<virtio_blk_device::VirtioBlkDevice>>),
}

impl ObjectStore for ObjectStoreBackend {
    fn get(&mut self, hash: &[u8; 32]) -> Result<CambiObject, StoreError> {
        match self {
            Self::Ram(s) => s.get(hash),
            #[cfg(not(test))]
            Self::LazyDisk(s) => s.get(hash),
        }
    }

    fn put(&mut self, object: CambiObject) -> Result<[u8; 32], StoreError> {
        match self {
            Self::Ram(s) => s.put(object),
            #[cfg(not(test))]
            Self::LazyDisk(s) => s.put(object),
        }
    }

    fn delete(&mut self, hash: &[u8; 32]) -> Result<(), StoreError> {
        match self {
            Self::Ram(s) => s.delete(hash),
            #[cfg(not(test))]
            Self::LazyDisk(s) => s.delete(hash),
        }
    }

    fn list(&mut self) -> Result<Vec<([u8; 32], ObjectMeta)>, StoreError> {
        match self {
            Self::Ram(s) => s.list(),
            #[cfg(not(test))]
            Self::LazyDisk(s) => s.list(),
        }
    }

    fn count(&self) -> usize {
        match self {
            Self::Ram(s) => s.count(),
            #[cfg(not(test))]
            Self::LazyDisk(s) => s.count(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_equality() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let p1 = Principal::from_public_key(key_a);
        let p2 = Principal::from_public_key(key_a);
        let p3 = Principal::from_public_key(key_b);

        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_principal_zero() {
        let zero = Principal::ZERO;
        assert!(zero.is_zero());

        let non_zero = Principal::from_public_key([42u8; 32]);
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_principal_debug_display() {
        use alloc::format;
        let p = Principal::from_public_key([0xAB; 32]);
        let dbg = format!("{:?}", p);
        assert!(dbg.contains("abababab"));

        let disp = format!("{}", p);
        assert!(disp.contains("abababab"));
    }

    #[test]
    fn test_content_hash_deterministic() {
        let data = b"hello world";
        let h1 = content_hash(data);
        let h2 = content_hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_different_data() {
        let h1 = content_hash(b"hello");
        let h2 = content_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_content_hash_empty() {
        let h = content_hash(b"");
        // Blake3 of empty input is a specific non-zero value
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn test_content_hash_is_blake3() {
        // Verify we're using Blake3 by comparing with the known hash
        let h = content_hash(b"hello world");
        let expected = *blake3::hash(b"hello world").as_bytes();
        assert_eq!(h, expected);
    }

    #[test]
    fn test_keypair_from_seed_deterministic() {
        let seed = [42u8; 32];
        let (pk1, sk1) = keypair_from_seed(&seed);
        let (pk2, sk2) = keypair_from_seed(&seed);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn test_sign_and_verify() {
        let seed = [1u8; 32];
        let (pk, sk) = keypair_from_seed(&seed);
        let content = b"CambiOS signed object content";

        let sig = sign_content(&sk, content);
        assert!(!sig.is_empty_sig());
        assert!(verify_signature(&pk, content, &sig));
    }

    #[test]
    fn test_verify_wrong_content_fails() {
        let seed = [1u8; 32];
        let (pk, sk) = keypair_from_seed(&seed);

        let sig = sign_content(&sk, b"original");
        assert!(!verify_signature(&pk, b"tampered", &sig));
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (_, sk) = keypair_from_seed(&[1u8; 32]);
        let (wrong_pk, _) = keypair_from_seed(&[2u8; 32]);

        let sig = sign_content(&sk, b"data");
        assert!(!verify_signature(&wrong_pk, b"data", &sig));
    }

    #[test]
    fn test_verify_empty_signature_fails() {
        let (pk, _) = keypair_from_seed(&[1u8; 32]);
        assert!(!verify_signature(&pk, b"data", &SignatureBytes::EMPTY));
    }

    #[test]
    fn test_sign_deterministic() {
        let seed = [1u8; 32];
        let (_, sk) = keypair_from_seed(&seed);
        let content = b"same content";

        let sig1 = sign_content(&sk, content);
        let sig2 = sign_content(&sk, content);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_arc_object_creation() {
        let author = Principal::from_public_key([1u8; 32]);
        let content = alloc::vec![10, 20, 30];
        let obj = CambiObject::new(author, content.clone(), 1000);

        assert_eq!(obj.author, [1u8; 32]);
        assert_eq!(obj.owner, [1u8; 32]); // Owner defaults to author
        assert_eq!(obj.content, content);
        assert_eq!(obj.created_at, 1000);
        assert_eq!(obj.content_hash, content_hash(&content));
        assert!(obj.lineage.is_none());
    }

    #[test]
    fn test_arc_object_author_immutability() {
        // CambiObject.author is pub but the constructor sets it.
        // The design invariant: author is set at creation and should never
        // be modified. This test documents the expectation. Enforcement
        // is at the ObjectStore level (put() preserves author).
        let author = Principal::from_public_key([1u8; 32]);
        let obj = CambiObject::new(author, alloc::vec![42], 0);
        assert_eq!(obj.author, [1u8; 32]);
        assert_eq!(obj.author_principal(), author);
    }

    #[test]
    fn test_arc_object_with_different_owner() {
        let author = Principal::from_public_key([1u8; 32]);
        let owner = Principal::from_public_key([2u8; 32]);
        let obj = CambiObject::new_with_owner(author, owner, alloc::vec![99], 500);

        assert_eq!(obj.author, [1u8; 32]);
        assert_eq!(obj.owner, [2u8; 32]);
        assert_ne!(obj.author, obj.owner);
    }

    #[test]
    fn test_arc_object_lineage() {
        let author = Principal::from_public_key([1u8; 32]);
        let parent_hash = [0xFFu8; 32];
        let obj = CambiObject::new(author, alloc::vec![1, 2, 3], 0)
            .with_lineage(parent_hash);

        assert_eq!(obj.lineage, Some(parent_hash));
    }

    #[test]
    fn test_object_cap_set_grant_check() {
        let mut caps = ObjectCapSet::new();
        let p1 = Principal::from_public_key([1u8; 32]);
        let p2 = Principal::from_public_key([2u8; 32]);

        caps.grant(p1, ObjectRights::READ_ONLY, None).unwrap();

        assert!(caps.check(&p1, ObjectRights::READ_ONLY));
        assert!(!caps.check(&p1, ObjectRights::READ_WRITE)); // No write
        assert!(!caps.check(&p2, ObjectRights::READ_ONLY)); // Not granted
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn test_object_cap_set_update_existing() {
        let mut caps = ObjectCapSet::new();
        let p = Principal::from_public_key([1u8; 32]);

        caps.grant(p, ObjectRights::READ_ONLY, None).unwrap();
        assert!(!caps.check(&p, ObjectRights::READ_WRITE));

        // Upgrade to read-write
        caps.grant(p, ObjectRights::READ_WRITE, None).unwrap();
        assert!(caps.check(&p, ObjectRights::READ_WRITE));
        assert_eq!(caps.len(), 1); // Still one entry, not two
    }

    #[test]
    fn test_object_cap_set_capacity() {
        let mut caps = ObjectCapSet::new();
        for i in 0..MAX_OBJECT_CAPS {
            let p = Principal::from_public_key([i as u8; 32]);
            caps.grant(p, ObjectRights::READ_ONLY, None).unwrap();
        }

        // One more should fail
        let overflow = Principal::from_public_key([0xFF; 32]);
        assert_eq!(
            caps.grant(overflow, ObjectRights::READ_ONLY, None),
            Err(StoreError::CapacityExceeded)
        );
    }

    #[test]
    fn test_signature_algo_values() {
        assert_eq!(SignatureAlgo::Ed25519 as u8, 0);
        assert_eq!(SignatureAlgo::MlDsa65 as u8, 1);
    }
}
