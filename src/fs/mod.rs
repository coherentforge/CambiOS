//! ArcOS Object Store — content-addressed signed object storage
//!
//! The native ArcOS storage model. Files are not bytes-at-a-path; they are
//! content-addressed signed objects with an immutable author, a transferable
//! owner, and a cryptographic signature tying content to controller.
//!
//! Phase 0: No real crypto. Content hashing uses FNV-1a (placeholder for
//! Blake3 in Phase 1). Signatures are present but not verified.
//!
//! The interfaces defined here are permanent. The implementations evolve.

pub mod ram;

extern crate alloc;
use alloc::vec::Vec;
use crate::ipc::Principal;

// ============================================================================
// Content hashing (Phase 0: FNV-1a placeholder, Phase 1: Blake3)
// ============================================================================

/// FNV-1a hash producing a 32-byte output by running four independent
/// FNV-1a-64 passes with different initial seeds, then concatenating.
///
/// This is NOT cryptographic. It is a Phase 0 placeholder for Blake3.
/// It exists solely to populate content_hash fields so the object model
/// can be exercised end-to-end before real crypto crates are integrated.
pub fn content_hash(data: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    // Four FNV-1a-64 passes with different seeds to fill 32 bytes
    const SEEDS: [u64; 4] = [
        0xcbf29ce484222325, // standard FNV offset basis
        0x6c62272e07bb0142,
        0x340c3e82a0e3b351,
        0xaf63bd4c8601b7df,
    ];
    for (i, &seed) in SEEDS.iter().enumerate() {
        let mut h = seed;
        for &byte in data {
            h ^= byte as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        result[i * 8..(i + 1) * 8].copy_from_slice(&h.to_le_bytes());
    }
    result
}

// ============================================================================
// Signature types (Phase 0: stored but not verified)
// ============================================================================

/// Signature algorithm tag. Phase 0 only uses Ed25519.
/// ML-DSA-65 (post-quantum) is Phase 1.5+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureAlgo {
    Ed25519 = 0,
    MlDsa65 = 1,
}

/// Signature bytes. Fixed at 64 bytes for Ed25519 in Phase 0.
/// Phase 1.5+ extends to variable-length for ML-DSA (3293 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBytes {
    /// Ed25519 signature (64 bytes). Zeroed = unsigned (Phase 0 default).
    pub data: [u8; 64],
}

impl SignatureBytes {
    pub const EMPTY: Self = SignatureBytes { data: [0u8; 64] };
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
}

// ============================================================================
// ArcObject — the fundamental storage unit
// ============================================================================

/// An ArcObject is the native ArcOS storage unit: a content-addressed,
/// signed, ownership-tracked object.
///
/// - `author` is immutable: set at creation, records who made this.
/// - `owner` is transferable: the current controller who signs the object.
/// - `content_hash` is the object's address (content-derived).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcObject {
    /// Content hash — the object's unique address (FNV-1a Phase 0, Blake3 Phase 1).
    pub content_hash: [u8; 32],
    /// Creator's public key — IMMUTABLE after creation. Historical fact.
    pub author: [u8; 32],
    /// Current controller's public key — transferable via OwnershipTransfer.
    pub owner: [u8; 32],
    /// Signature algorithm used.
    pub sig_algo: SignatureAlgo,
    /// Owner's signature over content (Phase 0: zeroed / not verified).
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

impl ArcObject {
    /// Create a new ArcObject. The author is set here and cannot be changed.
    ///
    /// `content_hash` is computed from `content`. `owner` defaults to `author`
    /// (creator is controller unless ownership is explicitly transferred).
    pub fn new(author: Principal, content: Vec<u8>, created_at: u64) -> Self {
        let hash = content_hash(&content);
        ArcObject {
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
        ArcObject {
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
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Object not found"),
            Self::CapacityExceeded => write!(f, "Store capacity exceeded"),
            Self::InvalidObject => write!(f, "Invalid object"),
            Self::PermissionDenied => write!(f, "Permission denied"),
        }
    }
}

/// The ObjectStore trait — the VFS abstraction for ArcOS.
///
/// Not a traditional block-device filesystem. Every backing store
/// (RAM, disk, sovereign cloud, P2P) implements this trait.
///
/// Phase 0: RamObjectStore. Phase 1+: disk-backed, networked.
pub trait ObjectStore {
    /// Retrieve an object by content hash.
    fn get(&self, hash: &[u8; 32]) -> Result<&ArcObject, StoreError>;

    /// Store an object. Returns the content hash (the object's address).
    /// The store verifies `content_hash` matches the content on put.
    fn put(&mut self, object: ArcObject) -> Result<[u8; 32], StoreError>;

    /// Delete an object by content hash.
    fn delete(&mut self, hash: &[u8; 32]) -> Result<(), StoreError>;

    /// List all objects with lightweight metadata.
    fn list(&self) -> Result<Vec<([u8; 32], ObjectMeta)>, StoreError>;

    /// Number of objects currently stored.
    fn count(&self) -> usize;
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
        // Should not be all zeros (FNV seeds are non-zero)
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn test_arc_object_creation() {
        let author = Principal::from_public_key([1u8; 32]);
        let content = alloc::vec![10, 20, 30];
        let obj = ArcObject::new(author, content.clone(), 1000);

        assert_eq!(obj.author, [1u8; 32]);
        assert_eq!(obj.owner, [1u8; 32]); // Owner defaults to author
        assert_eq!(obj.content, content);
        assert_eq!(obj.created_at, 1000);
        assert_eq!(obj.content_hash, content_hash(&content));
        assert!(obj.lineage.is_none());
    }

    #[test]
    fn test_arc_object_author_immutability() {
        // ArcObject.author is pub but the constructor sets it.
        // The design invariant: author is set at creation and should never
        // be modified. This test documents the expectation. Enforcement
        // is at the ObjectStore level (put() preserves author).
        let author = Principal::from_public_key([1u8; 32]);
        let obj = ArcObject::new(author, alloc::vec![42], 0);
        assert_eq!(obj.author, [1u8; 32]);
        assert_eq!(obj.author_principal(), author);
    }

    #[test]
    fn test_arc_object_with_different_owner() {
        let author = Principal::from_public_key([1u8; 32]);
        let owner = Principal::from_public_key([2u8; 32]);
        let obj = ArcObject::new_with_owner(author, owner, alloc::vec![99], 500);

        assert_eq!(obj.author, [1u8; 32]);
        assert_eq!(obj.owner, [2u8; 32]);
        assert_ne!(obj.author, obj.owner);
    }

    #[test]
    fn test_arc_object_lineage() {
        let author = Principal::from_public_key([1u8; 32]);
        let parent_hash = [0xFFu8; 32];
        let obj = ArcObject::new(author, alloc::vec![1, 2, 3], 0)
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
