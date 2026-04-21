// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Wire-format constants and helpers shared between the libfs client and
//! fs-service.
//!
//! Single source of truth. Dependency-free (`no_std`, no alloc, no libsys)
//! so the no-heap fs-service and the heap-using libfs client both depend
//! on it without pulling each other's transitive deps.

#![no_std]

// ============================================================================
// Endpoint
// ============================================================================

/// The fs-service IPC endpoint. Hard-coded across the system.
pub const FS_ENDPOINT: u32 = 16;

// ============================================================================
// Caps
// ============================================================================

/// Maximum length of an object name (in bytes).
///
/// SCAFFOLDING: Name layer is stubbed in-memory; this cap keeps wire frames
/// well under the 256-byte control-IPC limit with room for the header
/// payload on every op. Real naming will persist on disk and may want
/// longer names (path-like / URI-like). 64 is enough for v1 test fixtures.
/// Why: stat response fits [status:1][hash:32][author:32][owner:32][size:4]
///       [content_type:1][has_lineage:1][lineage:32][acl:1][name_len:1]
///       [name:N] = 137 + N, need ≤ 256 → N ≤ 119; pick 64 for headroom.
/// Replace when: real name system lands; first user hits the cap with a
/// path-shaped name.
pub const MAX_NAME_LEN: usize = 64;

/// Maximum content bytes per PUT_BY_NAME / bytes-per-chunk for GET_BY_NAME.
///
/// SCAFFOLDING: Single-message-per-op wire format in v1. Client bytes fit
/// in one control frame. Upgrading to chunked transfer is a wire-format
/// addition (new opcodes) without breaking callers that stay inside this
/// cap.
/// Why: 256 byte IPC - 1 status - 32 hash - 8 metadata bytes ≈ 215 bytes.
/// Replace when: the nano-style editor (Phase 6) ships with its 64 KiB
/// cap — at which point introduce CMD_PUT_BY_NAME_BEGIN/CHUNK/COMMIT and
/// CMD_GET_BY_NAME windowed reads; libfs `open`/`save` hide the change.
pub const MAX_CONTENT_LEN: usize = 200;

/// Fixed per-message IPC size limit in CambiOS control IPC.
pub const MSG_CAP: usize = 256;

// ============================================================================
// Opcodes (request byte 0)
// ============================================================================

// Existing hash-addressed ops (unchanged):
pub const CMD_PUT: u8 = 1;
pub const CMD_GET: u8 = 2;
pub const CMD_DELETE: u8 = 3;
pub const CMD_LIST: u8 = 4;

// New name-binding ops:
pub const CMD_GET_BY_NAME: u8 = 5;
pub const CMD_PUT_BY_NAME: u8 = 6;
pub const CMD_STAT: u8 = 7;
pub const CMD_LIST_NAMED: u8 = 8;
pub const CMD_REMOVE: u8 = 9;
pub const CMD_RENAME: u8 = 10;
pub const CMD_GRANT: u8 = 11;
pub const CMD_TRANSFER: u8 = 12;

// ============================================================================
// Status codes (response byte 0)
// ============================================================================

pub const STATUS_OK: u8 = 0;
pub const STATUS_NOT_FOUND: u8 = 1;
pub const STATUS_FULL: u8 = 2;
pub const STATUS_DENIED: u8 = 3;
pub const STATUS_INVALID: u8 = 4;
pub const STATUS_NOT_IMPLEMENTED: u8 = 5;
pub const STATUS_TOO_LARGE: u8 = 6;
pub const STATUS_ALREADY_EXISTS: u8 = 7;

// ============================================================================
// Content type tag (1 byte)
// ============================================================================

pub const CT_NONE: u8 = 0;
pub const CT_PLAIN_TEXT: u8 = 1;
pub const CT_OCTET_STREAM: u8 = 2;
// Reserve upper bits for future MIME-ish categories (image/audio/video).

/// Best-effort content-type classification. The v1 stub stores this byte
/// alongside the object and echoes it back on stat. Real MIME-shape
/// decisions are post-v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    None,
    PlainText,
    OctetStream,
    /// Forward-compatible — any value the server returns that this library
    /// doesn't know how to name. The byte is preserved so callers can round-trip.
    Unknown(u8),
}

impl ContentType {
    pub const fn to_u8(self) -> u8 {
        match self {
            ContentType::None => CT_NONE,
            ContentType::PlainText => CT_PLAIN_TEXT,
            ContentType::OctetStream => CT_OCTET_STREAM,
            ContentType::Unknown(b) => b,
        }
    }

    pub const fn from_u8(b: u8) -> Self {
        match b {
            CT_NONE => ContentType::None,
            CT_PLAIN_TEXT => ContentType::PlainText,
            CT_OCTET_STREAM => ContentType::OctetStream,
            other => ContentType::Unknown(other),
        }
    }
}

// ============================================================================
// Fixed offsets for STAT response
// ============================================================================
//
// Wire layout (after [status:1]):
//   [hash:32][author:32][owner:32][size:4 LE][content_type:1]
//   [has_lineage:1][lineage_parent:32][acl_is_public:1][name_len:1][name:N]
//
// Total fixed: 32+32+32+4+1+1+32+1+1 = 136 bytes. Plus status = 137.
// Plus name: up to MAX_NAME_LEN = 64 → full response ≤ 201 bytes.

pub const STAT_OFF_HASH:           usize = 1;
pub const STAT_OFF_AUTHOR:         usize = 33;
pub const STAT_OFF_OWNER:          usize = 65;
pub const STAT_OFF_SIZE:           usize = 97;
pub const STAT_OFF_CONTENT_TYPE:   usize = 101;
pub const STAT_OFF_HAS_LINEAGE:    usize = 102;
pub const STAT_OFF_LINEAGE_PARENT: usize = 103;
pub const STAT_OFF_ACL_IS_PUBLIC:  usize = 135;
pub const STAT_OFF_NAME_LEN:       usize = 136;
pub const STAT_OFF_NAME:           usize = 137;

/// Size in bytes of the fixed portion of a STAT response (excluding
/// variable-length `name` suffix).
pub const STAT_FIXED_LEN: usize = 137;

// ============================================================================
// Helper: little-endian read/write for integer fields
// ============================================================================

#[inline]
pub fn put_u32_le(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn get_u32_le(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(b)
}

#[inline]
pub fn put_u16_le(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn get_u16_le(buf: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    b.copy_from_slice(&buf[off..off + 2]);
    u16::from_le_bytes(b)
}
