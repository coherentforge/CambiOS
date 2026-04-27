// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS filesystem-service client.
//!
//! This is the forward-contract API: the shape every field of a real
//! CambiObject will have, even where the v1 backing is a stub. When
//! fs-service gains persistent storage, signed PUTs, and lineage
//! propagation, this crate does not change — only fs-service's internals
//! do.
//!
//! # Operations
//!
//! - [`open`] — read an object's content by name.
//! - [`save`] — create/replace an object; returns its content hash.
//! - [`stat`] — read an object's metadata.
//! - [`list`] — enumerate objects by optional name prefix.
//! - [`remove`] — unbind a name (underlying CambiObject survives).
//! - [`rename`] — rebind a name.
//! - [`grant`] / [`transfer`] — forward-contract stubs; return
//!   [`FsError::NotImplemented`] in v1.
//!
//! # v1 caps (see `proto.rs`)
//!
//! - Names ≤ 64 bytes.
//! - Object content ≤ 200 bytes (single-message wire format). Chunked
//!   PUT/GET land in a future phase without API churn.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Re-export the wire-format module so libfs clients have a single
/// import path (`libfs::proto`). Server processes that want only the
/// constants (without libfs's alloc dependency) can depend on the
/// `cambios-libfs-proto` crate directly.
pub use cambios_libfs_proto as proto;

pub use proto::ContentType;

use proto::{
    get_u32_le, put_u32_le, CMD_GET_BY_NAME, CMD_GRANT, CMD_LIST_NAMED, CMD_PUT_BY_NAME,
    CMD_REMOVE, CMD_RENAME, CMD_STAT, CMD_TRANSFER, MAX_CONTENT_LEN, MAX_NAME_LEN, MSG_CAP,
    STATUS_ALREADY_EXISTS, STATUS_DENIED, STATUS_FULL, STATUS_INVALID, STATUS_NOT_FOUND,
    STATUS_NOT_IMPLEMENTED, STATUS_OK, STATUS_TOO_LARGE,
};
#[cfg(not(test))]
use proto::FS_ENDPOINT;

// ============================================================================
// Public types
// ============================================================================

/// Object-rights enum — forward-contract for the eventual ACL model.
/// v1 passes these bytes through `grant` / `transfer` but rejects the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRights {
    Read,
    Write,
    Share,
    Transfer,
}

impl ObjectRights {
    pub const fn to_u8(self) -> u8 {
        match self {
            ObjectRights::Read => 1,
            ObjectRights::Write => 2,
            ObjectRights::Share => 3,
            ObjectRights::Transfer => 4,
        }
    }
}

/// Metadata returned by [`stat`] and [`list`].
///
/// Forward-compatible shape. v1 stubs fill `author == owner`, empty
/// signature, and `is_public = true` until the real identity/ACL system
/// catches up — but every field has a place now, so the migration is a
/// drop-in server change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub name: String,
    pub hash: [u8; 32],
    pub size: usize,
    /// Immutable Ed25519 public key of the object's creator.
    pub author: [u8; 32],
    /// Current owner's Ed25519 public key — equal to author until ownership
    /// transfer lands.
    pub owner: [u8; 32],
    pub content_type: ContentType,
    /// Hash of the parent object this one was derived from (e.g., the
    /// source of a `cp` or an earlier save of the same file).
    pub lineage_parent: Option<[u8; 32]>,
    /// v1 stub: `true` means unrestricted read. Real per-principal ACLs
    /// replace this when the ACL system lands.
    pub is_public: bool,
}

/// Errors returned by every libfs operation.
///
/// `TransportError` catches any failure where the service did not respond
/// at all (e.g., endpoint not registered, kernel rejected the write, or
/// reply timed out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    Full,
    Denied,
    Invalid,
    TooLarge,
    AlreadyExists,
    NotImplemented,
    /// The fs-service could not be reached or returned a malformed reply.
    TransportError,
    /// Argument exceeded a documented cap (name, content, prefix).
    ArgTooLong,
}

fn status_to_error(status: u8) -> FsError {
    match status {
        STATUS_NOT_FOUND => FsError::NotFound,
        STATUS_FULL => FsError::Full,
        STATUS_DENIED => FsError::Denied,
        STATUS_INVALID => FsError::Invalid,
        STATUS_TOO_LARGE => FsError::TooLarge,
        STATUS_ALREADY_EXISTS => FsError::AlreadyExists,
        STATUS_NOT_IMPLEMENTED => FsError::NotImplemented,
        _ => FsError::TransportError,
    }
}

// ============================================================================
// Transport
// ============================================================================

#[cfg(not(test))]
use cambios_libsys as sys;

#[cfg(not(test))]
use core::sync::atomic::{AtomicU32, Ordering};

/// The caller process's reply endpoint — must be set via [`init`] before
/// any libfs operation is invoked. A value of `0` indicates uninitialized.
#[cfg(not(test))]
static REPLY_ENDPOINT: AtomicU32 = AtomicU32::new(0);

/// Initialize libfs with the caller's reply endpoint.
///
/// The caller must have already registered `reply_endpoint` via
/// `sys::register_endpoint` — fs-service sends its reply to that endpoint
/// and libfs reads it there via `recv_verified`.
///
/// Typical boot-module shape:
/// ```ignore
/// const MY_EP: u32 = 42;
/// sys::register_endpoint(MY_EP);
/// libfs::init(MY_EP);
/// sys::module_ready();
/// // ... libfs::open / save / ... ready for use.
/// ```
#[cfg(not(test))]
pub fn init(reply_endpoint: u32) {
    REPLY_ENDPOINT.store(reply_endpoint, Ordering::Relaxed);
}

/// Send `req` to fs-service, block until the reply arrives, and copy it
/// into `resp_out`. Returns the reply length (excluding the 36-byte IPC
/// envelope the kernel prepends).
#[cfg(not(test))]
fn round_trip(req: &[u8], resp_out: &mut [u8; MSG_CAP]) -> Result<usize, FsError> {
    let ep = REPLY_ENDPOINT.load(Ordering::Relaxed);
    if ep == 0 {
        // Caller forgot `libfs::init(...)`. Fail loudly rather than hang.
        return Err(FsError::TransportError);
    }

    if sys::write(FS_ENDPOINT, req) < 0 {
        return Err(FsError::TransportError);
    }

    // Bounded poll with yield; 200 iterations is ample for a local IPC
    // round-trip even with fs-service having to be scheduled.
    let mut buf = [0u8; MSG_CAP];
    for _ in 0..200 {
        if let Some(msg) = sys::recv_verified(ep, &mut buf) {
            let payload = msg.payload();
            if payload.len() > resp_out.len() {
                return Err(FsError::TransportError);
            }
            resp_out[..payload.len()].copy_from_slice(payload);
            return Ok(payload.len());
        }
        sys::yield_now();
    }
    Err(FsError::TransportError)
}

// Test-mode transport: route through a thread-local mock. Tests that
// exercise libfs's codec paths don't need real IPC — they verify that
// libfs encodes requests correctly and decodes responses faithfully.
#[cfg(test)]
mod test_transport;
#[cfg(test)]
use test_transport::round_trip;
#[cfg(test)]
mod tests;

// ============================================================================
// Public operations
// ============================================================================

/// Read an object's content by name.
pub fn open(name: &str) -> Result<Vec<u8>, FsError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(FsError::ArgTooLong);
    }

    // Request: [CMD_GET_BY_NAME][name_len:1][name:N]
    let mut req = [0u8; MSG_CAP];
    req[0] = CMD_GET_BY_NAME;
    req[1] = name_bytes.len() as u8;
    req[2..2 + name_bytes.len()].copy_from_slice(name_bytes);
    let req_len = 2 + name_bytes.len();

    let mut resp = [0u8; MSG_CAP];
    let n = round_trip(&req[..req_len], &mut resp)?;
    if n < 1 {
        return Err(FsError::TransportError);
    }
    match resp[0] {
        STATUS_OK => {
            // Response: [status:1][size:4 LE][hash:32][content:N]
            if n < 1 + 4 + 32 {
                return Err(FsError::TransportError);
            }
            let size = get_u32_le(&resp, 1) as usize;
            let content_start = 1 + 4 + 32;
            let content = &resp[content_start..n];
            if content.len() != size {
                // v1: single-message wire format — content must fully fit.
                // A partial response means the object exceeded MAX_CONTENT_LEN
                // on the server side.
                return Err(FsError::TooLarge);
            }
            Ok(content.to_vec())
        }
        s => Err(status_to_error(s)),
    }
}

/// Create or replace an object by name. Returns the content hash.
pub fn save(
    name: &str,
    bytes: &[u8],
    parent: Option<[u8; 32]>,
    content_type: Option<ContentType>,
) -> Result<[u8; 32], FsError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(FsError::ArgTooLong);
    }
    if bytes.len() > MAX_CONTENT_LEN {
        return Err(FsError::TooLarge);
    }

    // Request:
    //   [CMD_PUT_BY_NAME][name_len:1][has_parent:1][parent:32][content_type:1]
    //   [content_len:4 LE][name:N][content:M]
    let mut req = [0u8; MSG_CAP];
    req[0] = CMD_PUT_BY_NAME;
    req[1] = name_bytes.len() as u8;
    req[2] = if parent.is_some() { 1 } else { 0 };
    if let Some(p) = parent {
        req[3..3 + 32].copy_from_slice(&p);
    }
    req[35] = content_type.unwrap_or(ContentType::None).to_u8();
    put_u32_le(&mut req, 36, bytes.len() as u32);
    let header_len = 40;
    req[header_len..header_len + name_bytes.len()].copy_from_slice(name_bytes);
    let content_start = header_len + name_bytes.len();
    req[content_start..content_start + bytes.len()].copy_from_slice(bytes);
    let req_len = content_start + bytes.len();

    let mut resp = [0u8; MSG_CAP];
    let n = round_trip(&req[..req_len], &mut resp)?;
    if n < 1 {
        return Err(FsError::TransportError);
    }
    match resp[0] {
        STATUS_OK => {
            if n < 1 + 32 {
                return Err(FsError::TransportError);
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&resp[1..33]);
            Ok(hash)
        }
        s => Err(status_to_error(s)),
    }
}

/// Read an object's metadata.
pub fn stat(name: &str) -> Result<ObjectInfo, FsError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(FsError::ArgTooLong);
    }

    let mut req = [0u8; MSG_CAP];
    req[0] = CMD_STAT;
    req[1] = name_bytes.len() as u8;
    req[2..2 + name_bytes.len()].copy_from_slice(name_bytes);
    let req_len = 2 + name_bytes.len();

    let mut resp = [0u8; MSG_CAP];
    let n = round_trip(&req[..req_len], &mut resp)?;
    if n < 1 {
        return Err(FsError::TransportError);
    }
    match resp[0] {
        STATUS_OK => decode_stat_response(&resp[..n]),
        s => Err(status_to_error(s)),
    }
}

fn decode_stat_response(resp: &[u8]) -> Result<ObjectInfo, FsError> {
    use proto::*;
    if resp.len() < STAT_FIXED_LEN {
        return Err(FsError::TransportError);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&resp[STAT_OFF_HASH..STAT_OFF_HASH + 32]);
    let mut author = [0u8; 32];
    author.copy_from_slice(&resp[STAT_OFF_AUTHOR..STAT_OFF_AUTHOR + 32]);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&resp[STAT_OFF_OWNER..STAT_OFF_OWNER + 32]);
    let size = get_u32_le(resp, STAT_OFF_SIZE) as usize;
    let content_type = ContentType::from_u8(resp[STAT_OFF_CONTENT_TYPE]);
    let has_lineage = resp[STAT_OFF_HAS_LINEAGE] != 0;
    let lineage_parent = if has_lineage {
        let mut lp = [0u8; 32];
        lp.copy_from_slice(&resp[STAT_OFF_LINEAGE_PARENT..STAT_OFF_LINEAGE_PARENT + 32]);
        Some(lp)
    } else {
        None
    };
    let is_public = resp[STAT_OFF_ACL_IS_PUBLIC] != 0;
    let name_len = resp[STAT_OFF_NAME_LEN] as usize;
    if STAT_OFF_NAME + name_len > resp.len() {
        return Err(FsError::TransportError);
    }
    let name_bytes = &resp[STAT_OFF_NAME..STAT_OFF_NAME + name_len];
    let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| FsError::TransportError)?;
    Ok(ObjectInfo {
        name,
        hash,
        size,
        author,
        owner,
        content_type,
        lineage_parent,
        is_public,
    })
}

/// Enumerate objects whose name starts with the given prefix (empty prefix
/// lists all). The v1 server returns up to a few entries per call and a
/// cursor; this helper loops until fully drained.
pub fn list(prefix: Option<&str>) -> Result<Vec<ObjectInfo>, FsError> {
    let prefix_bytes = prefix.map(|s| s.as_bytes()).unwrap_or(&[]);
    if prefix_bytes.len() > MAX_NAME_LEN {
        return Err(FsError::ArgTooLong);
    }

    let mut out = Vec::new();
    let mut cursor: u32 = 0;
    loop {
        let mut req = [0u8; MSG_CAP];
        req[0] = CMD_LIST_NAMED;
        put_u32_le(&mut req, 1, cursor);
        req[5] = prefix_bytes.len() as u8;
        req[6..6 + prefix_bytes.len()].copy_from_slice(prefix_bytes);
        let req_len = 6 + prefix_bytes.len();

        let mut resp = [0u8; MSG_CAP];
        let n = round_trip(&req[..req_len], &mut resp)?;
        if n < 1 {
            return Err(FsError::TransportError);
        }
        if resp[0] != STATUS_OK {
            return Err(status_to_error(resp[0]));
        }
        // Response: [status:1][count:1][next_cursor:4 LE][entry][entry]...
        //   entry = [name_len:1][name:N]
        if n < 6 {
            return Err(FsError::TransportError);
        }
        let count = resp[1] as usize;
        let next_cursor = get_u32_le(&resp, 2);

        let mut off = 6;
        for _ in 0..count {
            if off >= n {
                return Err(FsError::TransportError);
            }
            let name_len = resp[off] as usize;
            off += 1;
            if off + name_len > n {
                return Err(FsError::TransportError);
            }
            let name_bytes = &resp[off..off + name_len];
            off += name_len;
            let name = String::from_utf8(name_bytes.to_vec())
                .map_err(|_| FsError::TransportError)?;
            // LIST returns names only; fetch metadata via stat().
            let info = stat(&name)?;
            out.push(info);
        }

        if next_cursor == 0 {
            break;
        }
        cursor = next_cursor;
    }
    Ok(out)
}

/// Unbind a name. The underlying CambiObject is not deleted — it persists
/// in the object store until garbage-collected.
pub fn remove(name: &str) -> Result<(), FsError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(FsError::ArgTooLong);
    }
    let mut req = [0u8; MSG_CAP];
    req[0] = CMD_REMOVE;
    req[1] = name_bytes.len() as u8;
    req[2..2 + name_bytes.len()].copy_from_slice(name_bytes);
    let req_len = 2 + name_bytes.len();

    let mut resp = [0u8; MSG_CAP];
    let n = round_trip(&req[..req_len], &mut resp)?;
    if n < 1 {
        return Err(FsError::TransportError);
    }
    match resp[0] {
        STATUS_OK => Ok(()),
        s => Err(status_to_error(s)),
    }
}

/// Rebind a name. Fails with `NotFound` if `old` doesn't exist, or
/// `AlreadyExists` if `new` is already bound.
pub fn rename(old: &str, new: &str) -> Result<(), FsError> {
    let old_bytes = old.as_bytes();
    let new_bytes = new.as_bytes();
    if old_bytes.len() > MAX_NAME_LEN || new_bytes.len() > MAX_NAME_LEN {
        return Err(FsError::ArgTooLong);
    }
    let mut req = [0u8; MSG_CAP];
    req[0] = CMD_RENAME;
    req[1] = old_bytes.len() as u8;
    req[2..2 + old_bytes.len()].copy_from_slice(old_bytes);
    let new_len_off = 2 + old_bytes.len();
    req[new_len_off] = new_bytes.len() as u8;
    req[new_len_off + 1..new_len_off + 1 + new_bytes.len()].copy_from_slice(new_bytes);
    let req_len = new_len_off + 1 + new_bytes.len();

    let mut resp = [0u8; MSG_CAP];
    let n = round_trip(&req[..req_len], &mut resp)?;
    if n < 1 {
        return Err(FsError::TransportError);
    }
    match resp[0] {
        STATUS_OK => Ok(()),
        s => Err(status_to_error(s)),
    }
}

/// Grant an object right to another principal.
///
/// **v1 stub.** Always returns [`FsError::NotImplemented`]. The server
/// accepts the request, validates the shape, and rejects — this is the
/// forward contract; callers can already build `grant` flows.
pub fn grant(
    name: &str,
    to: &[u8; 32],
    rights: ObjectRights,
) -> Result<(), FsError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(FsError::ArgTooLong);
    }
    let mut req = [0u8; MSG_CAP];
    req[0] = CMD_GRANT;
    req[1] = name_bytes.len() as u8;
    req[2] = rights.to_u8();
    req[3..3 + 32].copy_from_slice(to);
    let name_off = 3 + 32;
    req[name_off..name_off + name_bytes.len()].copy_from_slice(name_bytes);
    let req_len = name_off + name_bytes.len();

    let mut resp = [0u8; MSG_CAP];
    let n = round_trip(&req[..req_len], &mut resp)?;
    if n < 1 {
        return Err(FsError::TransportError);
    }
    match resp[0] {
        STATUS_OK => Ok(()),
        s => Err(status_to_error(s)),
    }
}

/// Transfer ownership. **v1 stub** — returns [`FsError::NotImplemented`].
pub fn transfer(name: &str, to: &[u8; 32]) -> Result<(), FsError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(FsError::ArgTooLong);
    }
    let mut req = [0u8; MSG_CAP];
    req[0] = CMD_TRANSFER;
    req[1] = name_bytes.len() as u8;
    req[2..2 + 32].copy_from_slice(to);
    let name_off = 2 + 32;
    req[name_off..name_off + name_bytes.len()].copy_from_slice(name_bytes);
    let req_len = name_off + name_bytes.len();

    let mut resp = [0u8; MSG_CAP];
    let n = round_trip(&req[..req_len], &mut resp)?;
    if n < 1 {
        return Err(FsError::TransportError);
    }
    match resp[0] {
        STATUS_OK => Ok(()),
        s => Err(status_to_error(s)),
    }
}
