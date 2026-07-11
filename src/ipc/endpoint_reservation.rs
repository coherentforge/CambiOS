// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Endpoint reservation table (ADR-018 § 5, migration step 3).
//!
//! Maps each endpoint id to either `Unreserved` (first-come
//! registration, today's behavior) or `Reserved(aid)` (only the
//! Principal with that AID may `SYS_REGISTER_ENDPOINT` it). Populated
//! once at boot by the kernel's manifest transcription (migration
//! step 4) from the ARCSIG-verified manifest blob; empty when no
//! manifest module is present, which leaves every endpoint
//! `Unreserved` and behavior identical to the pre-manifest kernel.
//!
//! # Lifecycle and locking
//!
//! `ENDPOINT_RESERVATIONS` follows the `BOOTSTRAP_PRINCIPAL` pattern:
//! written once during single-threaded boot (before any user task
//! runs), read-only thereafter, **not part of the lock hierarchy**.
//! The internal `Spinlock` exists only because the table is larger
//! than a hardware atomic. Callers must never hold it across another
//! lock acquisition — every public accessor locks, copies out, and
//! unlocks before returning (see `handle_register_endpoint`, which
//! reads the reservation *before* taking `CAPABILITY_MANAGER`).
//!
//! # Verification stance
//!
//! `EndpointReservationTable` is pure bookkeeping over a fixed-size
//! array — host-testable, no allocation, no `unsafe`, O(1) lookups,
//! bounded install loop driven by the (already bounded) manifest
//! entry count. The BuddyAllocator template applied to a table.

use super::MAX_ENDPOINTS;

/// One endpoint's reservation state. Explicit enum rather than a
/// zero-AID sentinel: the unreserved case is unrepresentable as a
/// Principal value, per the "invariants encoded in types" rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointReservation {
    /// Any Principal may register this endpoint (first-come).
    Unreserved,
    /// Only the Principal with this AID may register this endpoint.
    Reserved([u8; 32]),
}

/// Typed installation failures, surfaced to the boot path as
/// `BootError` variants by the manifest transcription (step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationError {
    /// Endpoint id ≥ `MAX_ENDPOINTS` — the manifest names an endpoint
    /// the kernel's endpoint space cannot hold.
    OutOfRange(u32),
    /// The endpoint already carries a reservation. Duplicate
    /// reservations are a manifest-validation error the build tool and
    /// parser both reject; hitting this at install time means the
    /// transcription caller has a bug.
    AlreadyReserved(u32),
    /// The all-zero AID is the "unbound Principal" sentinel throughout
    /// the kernel; reserving an endpoint to it would make the
    /// reservation unclaimable and is always a caller bug.
    ZeroAid(u32),
}

/// Pure reservation bookkeeping. Sized by `MAX_ENDPOINTS` —
/// ARCHITECTURAL lockstep, not an independent bound: an endpoint that
/// exists is reservable, and endpoints the table cannot describe do
/// not exist.
pub struct EndpointReservationTable {
    slots: [EndpointReservation; MAX_ENDPOINTS],
}

impl Default for EndpointReservationTable {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointReservationTable {
    pub const fn new() -> Self {
        Self { slots: [EndpointReservation::Unreserved; MAX_ENDPOINTS] }
    }

    /// Reserve `endpoint` for `aid`. Boot-path only (transcription).
    pub fn install(&mut self, endpoint: u32, aid: [u8; 32]) -> Result<(), ReservationError> {
        if endpoint as usize >= MAX_ENDPOINTS {
            return Err(ReservationError::OutOfRange(endpoint));
        }
        if aid == [0u8; 32] {
            return Err(ReservationError::ZeroAid(endpoint));
        }
        match self.slots[endpoint as usize] {
            EndpointReservation::Reserved(_) => Err(ReservationError::AlreadyReserved(endpoint)),
            EndpointReservation::Unreserved => {
                self.slots[endpoint as usize] = EndpointReservation::Reserved(aid);
                Ok(())
            }
        }
    }

    /// The AID that owns `endpoint`, or `None` if unreserved or out of
    /// range (out-of-range ids are rejected upstream by the syscall's
    /// existing bounds check; treating them as unreserved here keeps
    /// this function total).
    pub fn owner(&self, endpoint: u32) -> Option<[u8; 32]> {
        match self.slots.get(endpoint as usize) {
            Some(EndpointReservation::Reserved(aid)) => Some(*aid),
            _ => None,
        }
    }

    /// Number of reserved slots (diagnostics / boot banner).
    pub fn count_reserved(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, EndpointReservation::Reserved(_)))
            .count()
    }
}

/// Global reservation table. See the module docs for the
/// `BOOTSTRAP_PRINCIPAL`-pattern lifecycle (write-once at boot,
/// read-only after, outside the lock hierarchy).
pub struct EndpointReservations {
    inner: crate::arch::spinlock::Spinlock<EndpointReservationTable>,
}

impl Default for EndpointReservations {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointReservations {
    pub const fn new() -> Self {
        Self { inner: crate::arch::spinlock::Spinlock::new(EndpointReservationTable::new()) }
    }

    /// Boot-path install (manifest transcription, single-threaded).
    pub fn install(&self, endpoint: u32, aid: [u8; 32]) -> Result<(), ReservationError> {
        self.inner.lock().install(endpoint, aid)
    }

    /// The owning AID for `endpoint`, copied out under a brief
    /// self-contained lock — never call while holding another lock.
    pub fn owner(&self, endpoint: u32) -> Option<[u8; 32]> {
        self.inner.lock().owner(endpoint)
    }

    /// Reserved-slot count (diagnostics / boot banner).
    pub fn count_reserved(&self) -> usize {
        self.inner.lock().count_reserved()
    }

    /// Scoped access to the inner table for the boot-time manifest
    /// transcription (`crate::manifest`), which populates via the
    /// pure, host-tested table helpers. Single-threaded boot only;
    /// the closure must not acquire any other lock.
    pub(crate) fn with_table<R>(&self, f: impl FnOnce(&mut EndpointReservationTable) -> R) -> R {
        f(&mut self.inner.lock())
    }
}

/// The kernel-wide endpoint reservation table. Empty (all
/// `Unreserved`) until the boot-time manifest transcription populates
/// it; empty table ⇒ `SYS_REGISTER_ENDPOINT` behaves exactly as it
/// did before ADR-018.
pub static ENDPOINT_RESERVATIONS: EndpointReservations = EndpointReservations::new();

#[cfg(test)]
mod tests {
    use super::*;

    fn aid(tag: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = tag;
        a
    }

    #[test]
    fn new_table_is_all_unreserved() {
        let t = EndpointReservationTable::new();
        for ep in 0..MAX_ENDPOINTS as u32 {
            assert_eq!(t.owner(ep), None);
        }
        assert_eq!(t.count_reserved(), 0);
    }

    #[test]
    fn install_then_owner_round_trips() {
        let mut t = EndpointReservationTable::new();
        t.install(16, aid(1)).unwrap();
        t.install(17, aid(2)).unwrap();
        assert_eq!(t.owner(16), Some(aid(1)));
        assert_eq!(t.owner(17), Some(aid(2)));
        assert_eq!(t.owner(18), None);
        assert_eq!(t.count_reserved(), 2);
    }

    #[test]
    fn install_rejects_out_of_range() {
        let mut t = EndpointReservationTable::new();
        assert_eq!(
            t.install(MAX_ENDPOINTS as u32, aid(1)),
            Err(ReservationError::OutOfRange(MAX_ENDPOINTS as u32))
        );
        assert_eq!(t.install(u32::MAX, aid(1)), Err(ReservationError::OutOfRange(u32::MAX)));
    }

    #[test]
    fn install_rejects_double_reservation() {
        let mut t = EndpointReservationTable::new();
        t.install(16, aid(1)).unwrap();
        assert_eq!(t.install(16, aid(1)), Err(ReservationError::AlreadyReserved(16)));
        assert_eq!(t.install(16, aid(2)), Err(ReservationError::AlreadyReserved(16)));
        // Original owner unchanged.
        assert_eq!(t.owner(16), Some(aid(1)));
    }

    #[test]
    fn install_rejects_zero_aid() {
        let mut t = EndpointReservationTable::new();
        assert_eq!(t.install(16, [0u8; 32]), Err(ReservationError::ZeroAid(16)));
        assert_eq!(t.owner(16), None);
    }

    #[test]
    fn owner_out_of_range_is_none() {
        let t = EndpointReservationTable::new();
        assert_eq!(t.owner(u32::MAX), None);
    }

    #[test]
    fn global_wrapper_round_trips() {
        // Exercises the Spinlock wrapper shape on a local instance
        // (the real global is boot-written; tests never touch it).
        let g = EndpointReservations::new();
        g.install(30, aid(9)).unwrap();
        assert_eq!(g.owner(30), Some(aid(9)));
        assert_eq!(g.owner(31), None);
        assert_eq!(g.count_reserved(), 1);
    }
}
