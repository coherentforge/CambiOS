// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Vault initialization.
//!
//! The bootstrap entry's `KeyHandle` is selected at compile time based on
//! the active PIV backend: `DevPiv` under `--features dev-piv`,
//! `Sentinel` otherwise. The dispatch primitives (`sign_with` /
//! `decrypt_with`, arriving in 1C-C) stay backend-agnostic — they look
//! up the handle and hit `None` slots structurally as `TokenAbsent`,
//! never branching on which backend is live.

use super::{HardwareDeviceId, KeyHandle, Vault, AID};
#[cfg(feature = "dev-piv")]
use cambios_libsys::keystore::PivSlot;

/// Build the bootstrap entry's `KeyHandle` for the active PIV backend.
#[cfg(feature = "dev-piv")]
pub fn bootstrap_key_handle() -> KeyHandle {
    KeyHandle {
        device_id: HardwareDeviceId::DevPiv,
        sign_slot: Some(PivSlot::Signature),
        decrypt_slot: Some(PivSlot::KeyManagement),
    }
}

#[cfg(not(feature = "dev-piv"))]
pub fn bootstrap_key_handle() -> KeyHandle {
    KeyHandle {
        device_id: HardwareDeviceId::Sentinel,
        sign_slot: None,
        decrypt_slot: None,
    }
}

/// Manifest-listed services whose derived AIDs the vault recognizes as
/// callers (keyless entries — they may ask, they hold no keys). Names
/// must match `manifest.toml` entries; the derivation is
/// `blake3(SERVICE_AID_DOMAIN_TAG || name)`, same as build-manifest's.
/// Today: fde-mount, whose `decrypt_with` unlocks the disk — after the
/// ADR-018 cutover it calls as its derived AID, not as bootstrap.
const CALLER_SERVICES: &[&[u8]] = &[b"fde-mount"];

/// Derive a manifest service AID: `blake3(SERVICE_AID_DOMAIN_TAG || name)`.
fn derive_service_aid(name: &[u8]) -> AID {
    let mut hasher = blake3::Hasher::new();
    hasher.update(cambios_manifest::SERVICE_AID_DOMAIN_TAG.as_bytes());
    hasher.update(name);
    *hasher.finalize().as_bytes()
}

/// Construct the v1 vault: one entry mapping `bootstrap_aid` to the
/// active backend's `KeyHandle`, plus keyless caller entries for the
/// services in [`CALLER_SERVICES`]. The context map starts empty.
pub fn init_vault(bootstrap_aid: AID) -> Vault {
    let mut vault = Vault::new(bootstrap_aid, bootstrap_key_handle());
    for name in CALLER_SERVICES {
        // Directory capacity is 16 and CALLER_SERVICES is 1; a full
        // directory here would be a build-time configuration bug, and
        // the vault still serves the bootstrap entry, so ignore.
        let _ = vault.register_caller(derive_service_aid(name));
    }
    vault
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_produces_bootstrap_entry() {
        let bootstrap: AID = [0xCC; 32];
        let vault = init_vault(bootstrap);
        assert_eq!(vault.bootstrap_aid(), &bootstrap);
        let entry = vault.entry_for(&bootstrap).expect("bootstrap entry present");
        assert_eq!(entry.aid, bootstrap);
    }

    #[test]
    fn init_registers_fde_mount_as_keyless_caller() {
        let bootstrap: AID = [0xCC; 32];
        let vault = init_vault(bootstrap);
        let fde_aid = derive_service_aid(b"fde-mount");
        // Recognized as caller...
        assert_eq!(vault.authorize(&fde_aid), Ok(()));
        // ...but holds no key material as a target.
        let entry = vault.entry_for(&fde_aid).expect("fde-mount entry present");
        assert!(entry.key_handle.sign_slot.is_none());
        assert!(entry.key_handle.decrypt_slot.is_none());
    }

    #[test]
    fn derived_caller_can_target_bootstrap_key() {
        // The load-bearing post-cutover flow: caller = fde-mount's
        // derived AID, target = bootstrap (the operator's disk key).
        // resolve_decrypt must pass authorize and reach the bootstrap
        // entry's handle (slot presence depends on the active backend).
        let bootstrap: AID = [0xCC; 32];
        let vault = init_vault(bootstrap);
        let fde_aid = derive_service_aid(b"fde-mount");
        let r = vault.resolve_decrypt(&fde_aid, &bootstrap);
        // Sentinel backend: authorized but keyless → TokenAbsent.
        // Dev-piv backend: authorized with a live slot → Ok.
        #[cfg(not(feature = "dev-piv"))]
        assert_eq!(r, Err(crate::vault::VaultError::TokenAbsent));
        #[cfg(feature = "dev-piv")]
        assert!(r.is_ok());
    }

    #[cfg(not(feature = "dev-piv"))]
    #[test]
    fn default_build_uses_sentinel_handle() {
        let handle = bootstrap_key_handle();
        assert_eq!(handle.device_id, HardwareDeviceId::Sentinel);
        assert!(handle.sign_slot.is_none());
        assert!(handle.decrypt_slot.is_none());
    }

    #[cfg(feature = "dev-piv")]
    #[test]
    fn dev_piv_build_uses_dev_piv_handle() {
        let handle = bootstrap_key_handle();
        assert_eq!(handle.device_id, HardwareDeviceId::DevPiv);
        assert_eq!(handle.sign_slot, Some(PivSlot::Signature));
        assert_eq!(handle.decrypt_slot, Some(PivSlot::KeyManagement));
    }
}
