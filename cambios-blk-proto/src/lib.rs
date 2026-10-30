// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! The block-driver IPC seam — one wire format, many drivers.
//!
//! The kernel keeps objects on a disk by delegating every block I/O to
//! "the block driver" over IPC (ADR-010 § Divergence 2): a small command
//! on [`BLK_KERNEL_CMD_ENDPOINT`], a reply on [`BLK_KERNEL_RESP_ENDPOINT`],
//! and a single 4 KiB page the driver owns and the kernel reaches through
//! the HHDM for the data. Which driver serves the seam is a manifest
//! profile decision: virtio-blk under QEMU, nvme on the Dell 3630, ahci
//! on SATA machines. They share nothing but this crate, so the kernel's
//! `BlockDriverClient` and every driver encode and decode the same bytes
//! from the same definitions.
//!
//! Two sides, two endpoints:
//!
//! **Endpoint 24 — user-facing (identity-verified via `recv_verified`).**
//!   Request:  `[cmd:1][args...]`
//!   Response: `[status:1][data...]`
//!   Commands: [`CMD_READ_BLOCK`] / [`CMD_WRITE_BLOCK`] (reserved —
//!   drivers answer [`STATUS_UNIMPLEMENTED`]; the kernel path is the
//!   consumer), [`CMD_FLUSH`] → `[status]`, [`CMD_GET_CAPACITY`] →
//!   `[status][sectors_512:8]`, [`CMD_GET_STATUS`] → `[status][alive:1]`.
//!
//! **Endpoint 26 — kernel-only (raw `recv_msg`; replies to 25).**
//!   Kernel-origin messages carry no sender Principal, which
//!   `recv_verified` rejects; trust is conferred by endpoint choice. Only
//!   the kernel sends on 26 and only the kernel receives on 25 (the
//!   dispatcher's write intercept). Commands:
//!   [`KCMD_HANDSHAKE`] → `[status][shared_page_paddr:8]`,
//!   [`KCMD_READ_BLOCK`] / [`KCMD_WRITE_BLOCK`] `[kcmd][lba:8]` →
//!   `[status]` (data via the shared page), [`KCMD_FLUSH`] → `[status]`,
//!   [`KCMD_CAPACITY`] → `[status][sectors_512:8]`.
//!
//! Units: the kernel block is [`LOGICAL_BLOCK_SIZE`] (4 KiB, the on-disk
//! format's block); capacity is always reported in 512-byte sectors
//! ([`SECTOR_SIZE`]) whatever the device's native LBA size, because
//! virtio-blk defined it that way first and the kernel divides.

#![no_std]

// ============================================================================
// Endpoints
// ============================================================================

/// User-facing block endpoint. Endpoint 22/23 are the policy service's;
/// the block driver takes 24.
pub const BLK_ENDPOINT: u32 = 24;
/// Kernel's reply endpoint: the dispatcher intercepts writes here and
/// hands them to `BlockDriverClient`'s poll; no user task may read it.
pub const BLK_KERNEL_RESP_ENDPOINT: u32 = 25;
/// Kernel-only command endpoint; the driver polls it with a raw receive.
pub const BLK_KERNEL_CMD_ENDPOINT: u32 = 26;

// ============================================================================
// User-facing commands (endpoint 24)
// ============================================================================

pub const CMD_READ_BLOCK: u8 = 1;
pub const CMD_WRITE_BLOCK: u8 = 2;
pub const CMD_FLUSH: u8 = 3;
pub const CMD_GET_CAPACITY: u8 = 4;
pub const CMD_GET_STATUS: u8 = 5;

// ============================================================================
// Kernel-only commands (endpoint 26)
// ============================================================================

pub const KCMD_HANDSHAKE: u8 = 1;
pub const KCMD_READ_BLOCK: u8 = 2;
pub const KCMD_WRITE_BLOCK: u8 = 3;
pub const KCMD_FLUSH: u8 = 4;
pub const KCMD_CAPACITY: u8 = 5;

// ============================================================================
// Status byte (first byte of every reply, both endpoints)
// ============================================================================

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERROR: u8 = 1;
/// The driver found no device; every request answers this at once so
/// callers fail fast instead of timing out.
pub const STATUS_NO_DEVICE: u8 = 2;
/// The device stopped responding after bring-up (fatal controller
/// status, lost completion); requests are refused, not retried.
pub const STATUS_DEVICE_DEAD: u8 = 3;
pub const STATUS_UNIMPLEMENTED: u8 = 4;

// ============================================================================
// Units
// ============================================================================

/// HARDWARE: the capacity unit on the wire — 512-byte sectors, as
/// virtio-blk's `capacity` field defines them, regardless of the
/// device's native LBA size.
pub const SECTOR_SIZE: usize = 512;
/// ARCHITECTURAL: the kernel's block — the on-disk format's `BLOCK_SIZE`
/// (ADR-010) and the size of the shared data page.
pub const LOGICAL_BLOCK_SIZE: usize = 4096;
/// 512-byte sectors per kernel block.
pub const SECTORS_PER_LOGICAL_BLOCK: u64 = (LOGICAL_BLOCK_SIZE / SECTOR_SIZE) as u64;

// ============================================================================
// Fixed encodings
// ============================================================================

/// `[kcmd:1][lba:8]`.
pub const LBA_REQUEST_LEN: usize = 9;
/// `[status:1][u64:8]` — handshake (shared-page paddr) and capacity replies.
pub const U64_REPLY_LEN: usize = 9;

/// Build a kernel-command request carrying a 64-bit LBA (read / write).
pub fn encode_lba_request(kcmd: u8, lba: u64) -> [u8; LBA_REQUEST_LEN] {
    let mut req = [0u8; LBA_REQUEST_LEN];
    req[0] = kcmd;
    req[1..9].copy_from_slice(&lba.to_le_bytes());
    req
}

/// The LBA of a read / write request, or `None` if the payload is short.
/// The caller has already dispatched on `payload[0]`.
pub fn decode_lba_request(payload: &[u8]) -> Option<u64> {
    if payload.len() < LBA_REQUEST_LEN {
        return None;
    }
    let mut lba = [0u8; 8];
    lba.copy_from_slice(&payload[1..9]);
    Some(u64::from_le_bytes(lba))
}

/// Write `[status][value:8]` into `out`; returns the bytes written (9),
/// or 1 with only the status when `out` cannot hold the value — the
/// receiver then sees a short reply and treats it as an error.
pub fn encode_u64_reply(status: u8, value: u64, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    out[0] = status;
    if out.len() < U64_REPLY_LEN {
        return 1;
    }
    out[1..9].copy_from_slice(&value.to_le_bytes());
    U64_REPLY_LEN
}

/// `(status, value)` from a `[status][value:8]` reply, or `None` if short.
pub fn decode_u64_reply(resp: &[u8]) -> Option<(u8, u64)> {
    if resp.len() < U64_REPLY_LEN {
        return None;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&resp[1..9]);
    Some((resp[0], u64::from_le_bytes(v)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lba_request_round_trips() {
        let req = encode_lba_request(KCMD_READ_BLOCK, 0x0123_4567_89AB_CDEF);
        assert_eq!(req[0], KCMD_READ_BLOCK);
        assert_eq!(decode_lba_request(&req), Some(0x0123_4567_89AB_CDEF));
        assert_eq!(decode_lba_request(&req[..8]), None);
    }

    #[test]
    fn u64_reply_round_trips_and_truncates_loudly() {
        let mut out = [0u8; 16];
        assert_eq!(encode_u64_reply(STATUS_OK, 42, &mut out), U64_REPLY_LEN);
        assert_eq!(decode_u64_reply(&out), Some((STATUS_OK, 42)));
        let mut short = [0u8; 4];
        assert_eq!(encode_u64_reply(STATUS_OK, 42, &mut short), 1);
        assert_eq!(decode_u64_reply(&short), None);
        assert_eq!(encode_u64_reply(STATUS_OK, 42, &mut []), 0);
    }

    #[test]
    fn units_agree() {
        assert_eq!(SECTORS_PER_LOGICAL_BLOCK, 8);
        assert_eq!(LOGICAL_BLOCK_SIZE % SECTOR_SIZE, 0);
    }
}
