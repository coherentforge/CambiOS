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

/// Construct the v1 vault: one entry mapping `bootstrap_aid` to the
/// active backend's `KeyHandle`. The context map starts empty.
pub fn init_vault(bootstrap_aid: AID) -> Vault {
    Vault::new(bootstrap_aid, bootstrap_key_handle())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_produces_single_entry_vault() {
        let bootstrap: AID = [0xCC; 32];
        let vault = init_vault(bootstrap);
        assert_eq!(vault.bootstrap_aid(), &bootstrap);
        let entry = vault.entry_for(&bootstrap).expect("bootstrap entry present");
        assert_eq!(entry.aid, bootstrap);
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
