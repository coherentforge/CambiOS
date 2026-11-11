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
//!   `recv_verified` rejects; the driver trusts 26 because the manifest
//!   reserves it to the driver's row and nobody else can send to a
//!   kernel-consumed queue. In the other direction the kernel trusts
//!   nothing by endpoint: a write to 25 is accepted only from the
//!   process whose Principal is the manifest's reservation owner of 25,
//!   and every reply must echo the tag of the request it answers.
//!
//!   Request:  `[kcmd:1][tag:4 LE][args...]`
//!   Reply:    `[status:1][tag:4 LE][data...]`
//!
//!   The tag is the kernel's per-request counter. A reply with a tag the
//!   kernel is not waiting for is a stale answer to a request that timed
//!   out and is discarded, so the kernel never takes the previous
//!   request's reply for this one's. Every reply echoes the tag, the
//!   no-device and error replies included; an untagged reply is a reply
//!   to nothing and the kernel waits out its budget. Commands:
//!   [`KCMD_HANDSHAKE`] → `[status][tag][shared_page_paddr:8]`,
//!   [`KCMD_READ_BLOCK`] / [`KCMD_WRITE_BLOCK`] `[kcmd][tag][lba:8]` →
//!   `[status][tag]` (data via the shared page), [`KCMD_FLUSH`] →
//!   `[status][tag]`, [`KCMD_CAPACITY`] → `[status][tag][sectors_512:8]`.
//!
//!   The shared page the handshake names must be one the kernel itself
//!   handed the driver through `SYS_ALLOC_DMA`; the kernel checks the
//!   address against that record before it copies a byte through it.
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
// Fixed encodings — user-facing endpoint 24 (untagged)
// ============================================================================

/// `[status:1][u64:8]` — the endpoint-24 capacity reply.
pub const U64_REPLY_LEN: usize = 9;

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

// ============================================================================
// Fixed encodings — kernel endpoints 26 / 25 (tagged)
// ============================================================================

/// ARCHITECTURAL: the request tag is a 32-bit little-endian counter.
/// One request is in flight at a time (the kernel serializes the seam),
/// so a tag collides with a stale reply only after 2^32 requests have
/// passed it; the width is what makes "a matching tag is this request's
/// reply" an argument instead of a probability.
pub const TAG_LEN: usize = 4;
/// `[kcmd:1][tag:4]` — every kernel request begins with this.
pub const KREQUEST_HEADER_LEN: usize = 1 + TAG_LEN;
/// `[status:1][tag:4]` — every kernel reply begins with this.
pub const KREPLY_HEADER_LEN: usize = 1 + TAG_LEN;
/// `[kcmd:1][tag:4][lba:8]`.
pub const KLBA_REQUEST_LEN: usize = KREQUEST_HEADER_LEN + 8;
/// `[status:1][tag:4][u64:8]` — handshake (shared-page paddr) and
/// capacity replies.
pub const KU64_REPLY_LEN: usize = KREPLY_HEADER_LEN + 8;

/// A decoded kernel request: the command, the tag the reply must echo,
/// and the command's arguments after the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelRequest<'a> {
    pub kcmd: u8,
    pub tag: u32,
    pub args: &'a [u8],
}

/// A decoded kernel reply: the status, the echoed tag, and the data
/// after the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelReply<'a> {
    pub status: u8,
    pub tag: u32,
    pub data: &'a [u8],
}

/// Split a kernel request into header and arguments, or `None` if the
/// payload is shorter than the header.
pub fn decode_kernel_request(payload: &[u8]) -> Option<KernelRequest<'_>> {
    if payload.len() < KREQUEST_HEADER_LEN {
        return None;
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&payload[1..KREQUEST_HEADER_LEN]);
    Some(KernelRequest {
        kcmd: payload[0],
        tag: u32::from_le_bytes(tag),
        args: &payload[KREQUEST_HEADER_LEN..],
    })
}

/// Build a kernel request with no arguments (handshake, flush, capacity).
pub fn encode_kernel_request(kcmd: u8, tag: u32) -> [u8; KREQUEST_HEADER_LEN] {
    let mut req = [0u8; KREQUEST_HEADER_LEN];
    req[0] = kcmd;
    req[1..KREQUEST_HEADER_LEN].copy_from_slice(&tag.to_le_bytes());
    req
}

/// Build a kernel request carrying a 64-bit LBA (read / write).
pub fn encode_klba_request(kcmd: u8, tag: u32, lba: u64) -> [u8; KLBA_REQUEST_LEN] {
    let mut req = [0u8; KLBA_REQUEST_LEN];
    req[..KREQUEST_HEADER_LEN].copy_from_slice(&encode_kernel_request(kcmd, tag));
    req[KREQUEST_HEADER_LEN..].copy_from_slice(&lba.to_le_bytes());
    req
}

/// The LBA from a read / write request's `args`, or `None` if short.
pub fn decode_lba_args(args: &[u8]) -> Option<u64> {
    if args.len() < 8 {
        return None;
    }
    let mut lba = [0u8; 8];
    lba.copy_from_slice(&args[..8]);
    Some(u64::from_le_bytes(lba))
}

/// Write `[status][tag]` into `out`; returns the bytes written (5), or 0
/// when `out` cannot hold the header (nothing is written: a reply that
/// cannot carry its tag answers nothing).
pub fn encode_kstatus_reply(status: u8, tag: u32, out: &mut [u8]) -> usize {
    if out.len() < KREPLY_HEADER_LEN {
        return 0;
    }
    out[0] = status;
    out[1..KREPLY_HEADER_LEN].copy_from_slice(&tag.to_le_bytes());
    KREPLY_HEADER_LEN
}

/// Write `[status][tag][value:8]` into `out`; returns the bytes written
/// (13), or the header alone (5) when `out` cannot hold the value — the
/// kernel then sees a short reply and treats it as an error — or 0 when
/// not even the header fits.
pub fn encode_ku64_reply(status: u8, tag: u32, value: u64, out: &mut [u8]) -> usize {
    let n = encode_kstatus_reply(status, tag, out);
    if n == 0 || out.len() < KU64_REPLY_LEN {
        return n;
    }
    out[KREPLY_HEADER_LEN..KU64_REPLY_LEN].copy_from_slice(&value.to_le_bytes());
    KU64_REPLY_LEN
}

/// Split a kernel reply into header and data, or `None` if shorter than
/// the header.
pub fn decode_kernel_reply(resp: &[u8]) -> Option<KernelReply<'_>> {
    if resp.len() < KREPLY_HEADER_LEN {
        return None;
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&resp[1..KREPLY_HEADER_LEN]);
    Some(KernelReply {
        status: resp[0],
        tag: u32::from_le_bytes(tag),
        data: &resp[KREPLY_HEADER_LEN..],
    })
}

/// The `u64` from a reply's `data`, or `None` if short.
pub fn decode_u64_data(data: &[u8]) -> Option<u64> {
    if data.len() < 8 {
        return None;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&data[..8]);
    Some(u64::from_le_bytes(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_request_round_trips() {
        let req = encode_klba_request(KCMD_READ_BLOCK, 0xDEAD_BEEF, 0x0123_4567_89AB_CDEF);
        assert_eq!(req.len(), KLBA_REQUEST_LEN);
        let d = decode_kernel_request(&req).unwrap();
        assert_eq!(d.kcmd, KCMD_READ_BLOCK);
        assert_eq!(d.tag, 0xDEAD_BEEF);
        assert_eq!(decode_lba_args(d.args), Some(0x0123_4567_89AB_CDEF));
        // A request short of its LBA decodes as a request with short args.
        let d = decode_kernel_request(&req[..KREQUEST_HEADER_LEN + 7]).unwrap();
        assert_eq!(decode_lba_args(d.args), None);
        // Shorter than the header is not a request at all.
        assert_eq!(decode_kernel_request(&req[..KREQUEST_HEADER_LEN - 1]), None);

        let bare = encode_kernel_request(KCMD_FLUSH, 7);
        let d = decode_kernel_request(&bare).unwrap();
        assert_eq!((d.kcmd, d.tag, d.args.len()), (KCMD_FLUSH, 7, 0));
    }

    #[test]
    fn kernel_reply_echoes_tag_and_truncates_loudly() {
        let mut out = [0u8; 16];
        assert_eq!(encode_ku64_reply(STATUS_OK, 42, 0x55, &mut out), KU64_REPLY_LEN);
        let r = decode_kernel_reply(&out[..KU64_REPLY_LEN]).unwrap();
        assert_eq!((r.status, r.tag), (STATUS_OK, 42));
        assert_eq!(decode_u64_data(r.data), Some(0x55));

        assert_eq!(encode_kstatus_reply(STATUS_ERROR, 42, &mut out), KREPLY_HEADER_LEN);
        let r = decode_kernel_reply(&out[..KREPLY_HEADER_LEN]).unwrap();
        assert_eq!((r.status, r.tag, r.data.len()), (STATUS_ERROR, 42, 0));
        assert_eq!(decode_u64_data(r.data), None);

        // Room for the header but not the value: header only, and the
        // kernel sees short data.
        let mut short = [0u8; 8];
        assert_eq!(encode_ku64_reply(STATUS_OK, 42, 0x55, &mut short), KREPLY_HEADER_LEN);
        assert_eq!(decode_u64_data(decode_kernel_reply(&short[..5]).unwrap().data), None);
        // No room for the header: nothing written.
        let mut tiny = [0u8; 4];
        assert_eq!(encode_kstatus_reply(STATUS_OK, 42, &mut tiny), 0);
        assert_eq!(encode_ku64_reply(STATUS_OK, 42, 0x55, &mut tiny), 0);
        assert_eq!(decode_kernel_reply(&tiny), None);
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
