// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! PIV backend abstraction.
//!
//! `PivBackend` is the trait the key-store-service IPC dispatcher will
//! call into (substage A-iii). Today only one impl exists,
//! `sw::SwPivBackend`, gated behind `feature = "dev-piv"`. The future
//! `CcidPivBackend` (stream B, USB-CCID transport) will implement the
//! same trait so the dispatcher's dispatch logic does not change when
//! the real backend lands.
//!
//! See ADR-032 § Migration Path step 2 and
//! `notes/yubikey-stream-a-handoff.md`.

use cambios_libsys::keystore::{
    Ed25519Signature, PivError, PivHealthState, PivPubkey, PivSlot, PivSlotList,
};

pub mod sw;

/// Operations every PIV backend must support. Wire-format mapping is
/// 1:1 with `cambios_libsys::keystore`'s codec.
pub trait PivBackend {
    fn health(&self) -> PivHealthState;
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), PivError>;
    fn list_slots(&self) -> PivSlotList;
    fn get_pubkey(&self, slot: PivSlot) -> Result<PivPubkey, PivError>;
    fn sign(&self, slot: PivSlot, msg: &[u8]) -> Result<Ed25519Signature, PivError>;
    fn decrypt(
        &self,
        slot: PivSlot,
        wrapped: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PivError>;
    fn attest(&self, slot: PivSlot, out: &mut [u8]) -> Result<usize, PivError>;
}
