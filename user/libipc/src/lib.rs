// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS IPC stdlib — L1 of the native app framework (ADR-037).
//!
//! Three pieces, replacing what every service hand-rolls today:
//!
//! - [`ServiceError`] / [`Result`]: one shared status vocabulary. The
//!   wire codes are byte-identical to `libfs-proto`'s `STATUS_*` set —
//!   the largest established one — so the eventual fs-service port is a
//!   mapping no-op. Services that reinvented their own `u8` sets
//!   converge onto this as they port (ADR-037 Phase 1+).
//! - [`Reader`] / [`Writer`]: bounds-checked little-endian cursors over
//!   payload bytes. These replace the `from_le_bytes`/`to_le_bytes` +
//!   manual-slicing sites (measured in the hundreds across `user/`)
//!   with `?`-able typed reads. [`MessageExt::reader`] hangs a `Reader`
//!   off every [`VerifiedMessage`].
//! - [`Handler`] + [`ServiceLoop`]: the recv → dispatch → yield shell of
//!   every service's main loop, **monomorphized** (`ServiceLoop<H>`,
//!   no `Box<dyn>` — the no-trait-objects rule holds in userspace
//!   framework code too). Receives via `recv_verified` only: the
//!   identity-gate invariant is structural, not per-service diligence.
//!
//! The `Encode`/`Decode` derive the ADR discusses is deliberately absent.
//! Revisit when: a second real request/response struct needs it (the
//! second-consumer discriminator; ADR-037 L1).

#![no_std]
#![forbid(unsafe_code)]

use cambios_libsys as sys;
pub use cambios_libsys::VerifiedMessage;

// ============================================================================
// ServiceError — the shared status vocabulary
// ============================================================================

/// One error vocabulary for service request handling.
///
/// Wire codes match `libfs-proto`'s `STATUS_*` constants byte-for-byte
/// (`STATUS_OK = 0` is not an error — it is `Ok(())`). `Malformed` is
/// the semantic name for the wire's `STATUS_INVALID = 4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceError {
    /// Named object / resource does not exist. (wire: 1)
    NotFound = 1,
    /// Resource exhausted — table full, queue full, no space. (wire: 2)
    Full = 2,
    /// Authorization failure. (wire: 3)
    Denied = 3,
    /// Request failed to parse — short payload, bad field, bad tag.
    /// (wire: 4, `STATUS_INVALID`)
    Malformed = 4,
    /// Recognized but unimplemented operation. (wire: 5)
    NotImplemented = 5,
    /// Payload or object exceeds a size bound. (wire: 6)
    TooLarge = 6,
    /// Create-exclusive target already exists. (wire: 7)
    AlreadyExists = 7,
}

/// `Result` alias every framework service uses for request handling.
pub type Result<T> = core::result::Result<T, ServiceError>;

impl ServiceError {
    /// The stable wire code (the `libfs-proto` `STATUS_*` value).
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Parse a wire code. `0` (`STATUS_OK`) is not an error, so it — and
    /// anything unassigned — returns `None`.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::NotFound),
            2 => Some(Self::Full),
            3 => Some(Self::Denied),
            4 => Some(Self::Malformed),
            5 => Some(Self::NotImplemented),
            6 => Some(Self::TooLarge),
            7 => Some(Self::AlreadyExists),
            _ => None,
        }
    }

    /// Human-readable name, for serial diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::Full => "full",
            Self::Denied => "denied",
            Self::Malformed => "malformed",
            Self::NotImplemented => "not-implemented",
            Self::TooLarge => "too-large",
            Self::AlreadyExists => "already-exists",
        }
    }
}

// ============================================================================
// Reader / Writer — bounds-checked little-endian payload cursors
// ============================================================================

/// Bounds-checked little-endian read cursor over a payload slice.
///
/// Every read advances the cursor; underrun returns
/// [`ServiceError::Malformed`], so field extraction is a chain of `?`s
/// instead of `try_into` + manual slicing.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading at the front of `buf`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Consume and return the next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(ServiceError::Malformed);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Consume all remaining bytes.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }

    /// Read a `u8`.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

/// Bounds-checked little-endian write cursor over a reply buffer.
///
/// Every write advances the cursor; overflow returns
/// [`ServiceError::TooLarge`]. [`Writer::len`] is the number of bytes
/// written — send with `&buf[..w.len()]`.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Start writing at the front of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes written so far.
    pub const fn len(&self) -> usize {
        self.pos
    }

    /// True if nothing has been written yet.
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Append raw bytes.
    pub fn put_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.buf.len() - self.pos < bytes.len() {
            return Err(ServiceError::TooLarge);
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    /// Append a `u8`.
    pub fn put_u8(&mut self, v: u8) -> Result<()> {
        self.put_bytes(&[v])
    }

    /// Append a little-endian `u16`.
    pub fn put_u16(&mut self, v: u16) -> Result<()> {
        self.put_bytes(&v.to_le_bytes())
    }

    /// Append a little-endian `u32`.
    pub fn put_u32(&mut self, v: u32) -> Result<()> {
        self.put_bytes(&v.to_le_bytes())
    }

    /// Append a little-endian `u64`.
    pub fn put_u64(&mut self, v: u64) -> Result<()> {
        self.put_bytes(&v.to_le_bytes())
    }
}

// ============================================================================
// MessageExt — typed payload access on VerifiedMessage
// ============================================================================

/// Extension for [`VerifiedMessage`]: typed payload reading.
pub trait MessageExt {
    /// A [`Reader`] positioned at the start of the payload.
    fn reader(&self) -> Reader<'_>;
}

impl MessageExt for VerifiedMessage<'_> {
    fn reader(&self) -> Reader<'_> {
        Reader::new(self.payload())
    }
}

// ============================================================================
// Handler + ServiceLoop — the recv → dispatch → yield shell
// ============================================================================

/// Per-request dispatch. Implementations parse the payload (via
/// [`MessageExt::reader`]), act, and send any replies themselves
/// (`sys::write` to a fixed endpoint or to `msg.from_endpoint()`).
///
/// Returning `Err` drops the request: the loop neither replies nor
/// logs. Malformed traffic from a hostile peer must not become a serial
/// log flood, and security-relevant events are the kernel audit ring's
/// job, not stdout's (the 2026-05-10 backpressure-mislabel lesson).
pub trait Handler {
    /// Handle one verified message.
    fn handle(&mut self, msg: &VerifiedMessage<'_>) -> Result<()>;
}

/// Receive buffer size covering a full message: 36-byte header
/// (32 sender principal + 4 from-endpoint) + 256-byte maximum control
/// payload (ADR-005). Matches `recv_verified`'s documented sizing.
pub const RECV_BUF_SIZE: usize = 292;

/// The steady-state service loop: `recv_verified` → [`Handler::handle`]
/// → yield when idle. Monomorphized over `H` — no dynamic dispatch.
///
/// Receives **only** via `recv_verified`: a service built on this loop
/// structurally cannot accept anonymous-sender messages.
pub struct ServiceLoop<H: Handler> {
    endpoint: u32,
    handler: H,
}

impl<H: Handler> ServiceLoop<H> {
    /// A loop serving `endpoint` with `handler`.
    pub const fn new(endpoint: u32, handler: H) -> Self {
        Self { endpoint, handler }
    }

    /// Run forever. Empty queue (or anonymous / short message — both
    /// also `None` from `recv_verified`) yields the CPU; handler errors
    /// drop the request (see [`Handler`]).
    pub fn run(mut self) -> ! {
        let mut buf = [0u8; RECV_BUF_SIZE];
        loop {
            match sys::recv_verified(self.endpoint, &mut buf) {
                Some(msg) => {
                    let _ = self.handler.handle(&msg);
                }
                None => sys::yield_now(),
            }
        }
    }
}

// ============================================================================
// Host tests (ADR-037 verification posture: thorough host tests for the
// pure logic — parsing, status round-trips. The loop itself is proven by
// its consumers under QEMU; it is syscall-bound and non-terminating.)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_reads_all_widths_le() {
        let buf = [
            0xAA, // u8
            0x01, 0x02, // u16 = 0x0201
            0x01, 0x02, 0x03, 0x04, // u32 = 0x04030201
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // u64
        ];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 0xAA);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert_eq!(r.u32().unwrap(), 0x0403_0201);
        assert_eq!(r.u64().unwrap(), 0x0807_0605_0403_0201);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn reader_underrun_is_malformed_and_does_not_advance() {
        let buf = [1u8, 2, 3];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u32(), Err(ServiceError::Malformed));
        // Failed read must not consume — the 3 bytes are still there.
        assert_eq!(r.remaining(), 3);
        assert_eq!(r.take(3).unwrap(), &[1, 2, 3]);
        assert_eq!(r.u8(), Err(ServiceError::Malformed));
    }

    #[test]
    fn reader_take_and_rest() {
        let buf = [1u8, 2, 3, 4, 5];
        let mut r = Reader::new(&buf);
        assert_eq!(r.take(2).unwrap(), &[1, 2]);
        assert_eq!(r.rest(), &[3, 4, 5]);
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.rest(), &[] as &[u8]);
    }

    #[test]
    fn writer_round_trips_through_reader() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        w.put_u8(0xAB).unwrap();
        w.put_u16(0xBEEF).unwrap();
        w.put_u32(0xDEAD_BEEF).unwrap();
        w.put_u64(0x0123_4567_89AB_CDEF).unwrap();
        w.put_bytes(b"xyz").unwrap();
        let n = w.len();
        assert_eq!(n, 1 + 2 + 4 + 8 + 3);

        let mut r = Reader::new(&buf[..n]);
        assert_eq!(r.u8().unwrap(), 0xAB);
        assert_eq!(r.u16().unwrap(), 0xBEEF);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 0x0123_4567_89AB_CDEF);
        assert_eq!(r.rest(), b"xyz");
    }

    #[test]
    fn writer_overflow_is_too_large_and_does_not_write() {
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        w.put_u32(7).unwrap();
        assert_eq!(w.put_u8(1), Err(ServiceError::TooLarge));
        assert_eq!(w.len(), 4);
        // Exact-fit boundary: a fresh writer over 8 bytes takes a u64.
        let mut buf8 = [0u8; 8];
        let mut w8 = Writer::new(&mut buf8);
        w8.put_u64(u64::MAX).unwrap();
        assert_eq!(w8.put_bytes(&[]), Ok(())); // zero-length always fits
    }

    #[test]
    fn service_error_wire_codes_are_libfs_proto_stable() {
        // These are wire-frozen against libfs-proto's STATUS_* set.
        assert_eq!(ServiceError::NotFound.code(), 1);
        assert_eq!(ServiceError::Full.code(), 2);
        assert_eq!(ServiceError::Denied.code(), 3);
        assert_eq!(ServiceError::Malformed.code(), 4);
        assert_eq!(ServiceError::NotImplemented.code(), 5);
        assert_eq!(ServiceError::TooLarge.code(), 6);
        assert_eq!(ServiceError::AlreadyExists.code(), 7);
    }

    #[test]
    fn service_error_round_trips_and_rejects_unassigned() {
        for code in 1u8..=7 {
            let e = ServiceError::from_code(code).unwrap();
            assert_eq!(e.code(), code);
            assert!(!e.name().is_empty());
        }
        assert_eq!(ServiceError::from_code(0), None); // STATUS_OK is not an error
        for code in 8u8..=255 {
            assert_eq!(ServiceError::from_code(code), None);
        }
    }
}
