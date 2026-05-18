// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Inert PIV backend.
//!
//! Selected in default builds (no `dev-piv` feature) and intended as the
//! stand-in for stream B's USB-CCID transport while that work is in
//! flight. Every operation returns `PivError::NotPresent` so callers
//! receive a uniform "no card" wire status — matching real-PIV
//! behaviour when no card is in the reader.
//!
//! Revisit when: stream B's `CcidPivBackend` lands and
//! `piv::ActiveBackend` switches between SwPiv / CcidPiv / Inert at
//! runtime instead of pure-cfg compile-time selection.
//!
//! Health is `NotPresent`. List-slots returns an empty list (no slots
//! reachable). PIN verify, sign, decrypt, attest, get-pubkey all return
//! the same NotPresent status. No state, no allocations.

use super::PivBackend;
use cambios_libsys::keystore::{
    Ed25519Signature, MAX_PIV_SLOTS, PivAlgo, PivError, PivHealthState, PivPubkey, PivSlot,
    PivSlotInfo, PivSlotList,
};

pub struct InertPivBackend;

impl InertPivBackend {
    pub const fn new() -> Self {
        InertPivBackend
    }
}

impl Default for InertPivBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PivBackend for InertPivBackend {
    fn health(&self) -> PivHealthState {
        PivHealthState::NotPresent
    }

    fn verify_pin(&mut self, _pin: &[u8]) -> Result<(), PivError> {
        Err(PivError::NotPresent)
    }

    fn list_slots(&self) -> PivSlotList {
        PivSlotList {
            count: 0,
            entries: [PivSlotInfo {
                slot: PivSlot::Authentication,
                algo: PivAlgo::Ed25519,
                populated: false,
            }; MAX_PIV_SLOTS],
        }
    }

    fn get_pubkey(&self, _slot: PivSlot) -> Result<PivPubkey, PivError> {
        Err(PivError::NotPresent)
    }

    fn sign(&self, _slot: PivSlot, _msg: &[u8]) -> Result<Ed25519Signature, PivError> {
        Err(PivError::NotPresent)
    }

    fn decrypt(
        &self,
        _slot: PivSlot,
        _wrapped: &[u8],
        _out: &mut [u8],
    ) -> Result<usize, PivError> {
        Err(PivError::NotPresent)
    }

    fn attest(&self, _slot: PivSlot, _out: &mut [u8]) -> Result<usize, PivError> {
        Err(PivError::NotPresent)
    }
}
