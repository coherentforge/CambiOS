// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Multi-Principal vault data model.
//!
//! Per ADR-033, `user/key-store-service` at endpoint 17 *is* the
//! multi-Principal vault — the directory of `AID → hardware-key-slot`
//! bindings the human-↔-Principals mapping lives in. This module
//! defines the types and trust-boundary check; the IPC primitives
//! that consume them (`bind_for_spawn`, `sign_with`, `decrypt_with`)
//! arrive in later 1C stages.
//!
//! The vault holds bookkeeping only. Private keys live in hardware
//! silicon (YubiKey-class PIV slots) and never enter the vault's
//! address space; the `KeyHandle` is the pointer-into-hardware.

use cambios_libsys::keystore::PivSlot;
pub use cambios_libsys::vault::VaultError;

pub mod init;

// ============================================================================
// Bounds
// ============================================================================

/// Max distinct AIDs the vault can hold. v1 single-Principal practice uses one
/// entry (bootstrap); headroom covers the identity.md primary+backup model
/// plus a handful of additional contexts before per-context KDF plurality
/// lands. Revisit when a user provisions more than 16 hardware-key-rooted
/// AIDs in practice.
pub const MAX_VAULT_ENTRIES: usize = 16;

/// Max context-label → AID bindings. v1 leaves this empty (bind_for_spawn
/// falls back to bootstrap on miss). 8 covers the canonical contexts
/// (work / personal / social / banking / ...) when context binding lands.
/// Revisit when a UX flow needs to populate more than 8 entries.
pub const MAX_CONTEXTS: usize = 8;

/// Max context-label byte length. Typical labels ("social", "work",
/// "banking_app") are short ASCII; 32 is comfortable headroom.
/// Revisit when a real labeling convention forces a longer ceiling.
pub const MAX_CONTEXT_LABEL_LEN: usize = 32;

// ============================================================================
// Types
// ============================================================================

/// 32-byte Autonomic Identifier per ADR-025. In v1 the bytes coincide with
/// an Ed25519 public key; v1.5+ rebases to `blake3(inception_event_log[0])`
/// without changing the type.
pub type AID = [u8; 32];

/// Opaque hardware-token identifier. Reserved for richer discrimination
/// (USB serial, vendor-defined identifier, logical provisioning tag) when
/// real hardware enrollment lands; v1 carries only the two backends the
/// service compiles against today.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HardwareDeviceId {
    /// No hardware bound. `sign_slot` / `decrypt_slot` are `None`; vault
    /// dispatch returns `TokenAbsent` for any operation that needs silicon.
    Sentinel,
    /// Software-emulated PIV backend bound at compile time via
    /// `--features dev-piv`. The service's `SwPivBackend` answers slot
    /// operations from the dev-piv DPIV bundle.
    DevPiv,
}

/// Pointer-into-hardware: which device, which slot for sign, which for
/// decrypt. The slot fields are `Option` so the `Sentinel` backend can
/// represent "no key here" without a runtime branch inside `sign_with` /
/// `decrypt_with` — dispatch hits `None` and returns `TokenAbsent`
/// structurally.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyHandle {
    pub device_id: HardwareDeviceId,
    pub sign_slot: Option<PivSlot>,
    pub decrypt_slot: Option<PivSlot>,
}

/// One entry in the vault directory. Per ADR-033, v1 carries
/// `aid + key_handle`; `InceptionEvent` and `RotationEvent` arrive with
/// the first key-rotation consumer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VaultEntry {
    pub aid: AID,
    pub key_handle: KeyHandle,
}

/// One `context_label → AID` binding in the context map. The label is a
/// fixed-size buffer with an explicit length so the surrounding
/// `[Option<ContextMapEntry>; MAX_CONTEXTS]` stays `Copy` for `no_std` use
/// without an allocator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ContextMapEntry {
    pub label: [u8; MAX_CONTEXT_LABEL_LEN],
    pub label_len: u8,
    pub aid: AID,
}

// `VaultError` is shared with clients via `cambios_libsys::vault::VaultError`
// (re-exported above). Server-side code only ever returns the wire-mappable
// variants (`NotAuthorized` through `InvalidPayload`); the local-only
// `WireFormat` / `Ipc` variants exist on the type for client codec/IPC
// failures and are never produced here.

/// How `bind_for_spawn` resolved the requested context. Internal to the
/// vault module: the wire response only carries the AID. The dispatch
/// arm in `main.rs` inspects this to decide whether to emit the
/// `[VAULT][FALLBACK]` log line per D4 of the 1C overview plan.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BindSource {
    /// `context` was found in the vault's `context_map`.
    ContextMatch,
    /// `context` was not bound; the v1 vault returned the bootstrap AID.
    BootstrapFallback,
}

/// What `bind_for_spawn` returns: the chosen AID plus how it was chosen.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BindResult {
    pub aid: AID,
    pub source: BindSource,
}

// ============================================================================
// Vault
// ============================================================================

/// The vault. Holds the bootstrap AID separately so the authorize() check
/// has it without scanning entries; in v1 the bootstrap AID is also
/// entries[0], so the distinction is degenerate but the structure is the
/// v1.5+ shape.
pub struct Vault {
    bootstrap_aid: AID,
    entries: [Option<VaultEntry>; MAX_VAULT_ENTRIES],
    /// Empty in v1. Populated when a context-binding API surfaces (1C-B+).
    context_map: [Option<ContextMapEntry>; MAX_CONTEXTS],
}

impl Vault {
    /// Construct a new vault with the bootstrap AID + a single entry
    /// binding the bootstrap AID to the supplied KeyHandle. Context map
    /// is empty.
    pub fn new(bootstrap_aid: AID, bootstrap_key_handle: KeyHandle) -> Self {
        let mut entries: [Option<VaultEntry>; MAX_VAULT_ENTRIES] =
            [None; MAX_VAULT_ENTRIES];
        entries[0] = Some(VaultEntry {
            aid: bootstrap_aid,
            key_handle: bootstrap_key_handle,
        });
        Vault {
            bootstrap_aid,
            entries,
            context_map: [None; MAX_CONTEXTS],
        }
    }

    pub fn bootstrap_aid(&self) -> &AID {
        &self.bootstrap_aid
    }

    /// Trust-boundary check per ADR-033 § 4. Recognized callers are
    /// (a) the bootstrap Principal, (b) any AID in the vault's directory.
    /// Anything else gets `NotAuthorized`. Called by every vault IPC
    /// dispatch arm; factored into the vault module so the three arms
    /// (1C-B bind_for_spawn, 1C-C sign_with + decrypt_with) share one
    /// authority check.
    pub fn authorize(&self, caller_aid: &AID) -> Result<(), VaultError> {
        if caller_aid == &self.bootstrap_aid {
            return Ok(());
        }
        for entry in self.entries.iter().flatten() {
            if &entry.aid == caller_aid {
                return Ok(());
            }
        }
        Err(VaultError::NotAuthorized)
    }

    /// Look up the directory entry for an AID. Returns `None` on miss.
    pub fn entry_for(&self, aid: &AID) -> Option<&VaultEntry> {
        self.entries.iter().flatten().find(|e| &e.aid == aid)
    }

    /// Look up an AID by context label. Returns `None` on miss; the
    /// `bind_for_spawn` caller falls back to the bootstrap AID per D4.
    pub fn aid_for_context(&self, label: &[u8]) -> Option<AID> {
        if label.is_empty() || label.len() > MAX_CONTEXT_LABEL_LEN {
            return None;
        }
        for entry in self.context_map.iter().flatten() {
            let stored = &entry.label[..entry.label_len as usize];
            if stored == label {
                return Some(entry.aid);
            }
        }
        None
    }

    /// Vault primitive per ADR-033 § 2: parent processes call this
    /// before invoking `SYS_SPAWN` to learn which AID the child should
    /// be bound to.
    ///
    /// Flow:
    ///   1. `authorize(caller_aid)?` — only recognized callers proceed.
    ///   2. `aid_for_context(context)` — if matched, return it with
    ///      `BindSource::ContextMatch`.
    ///   3. Otherwise (v1: always, since the context_map is empty),
    ///      return the bootstrap AID with `BindSource::BootstrapFallback`.
    ///      The dispatch arm uses the `BootstrapFallback` source to emit
    ///      a `[VAULT][FALLBACK]` log line; the wire response carries
    ///      only the AID.
    pub fn bind_for_spawn(
        &self,
        caller_aid: &AID,
        context: &[u8],
    ) -> Result<BindResult, VaultError> {
        self.authorize(caller_aid)?;
        if let Some(aid) = self.aid_for_context(context) {
            Ok(BindResult { aid, source: BindSource::ContextMatch })
        } else {
            Ok(BindResult {
                aid: self.bootstrap_aid,
                source: BindSource::BootstrapFallback,
            })
        }
    }

    /// Resolve `target_aid` to its signing slot for `sign_with`.
    ///
    /// Flow:
    ///   1. `authorize(caller_aid)?`.
    ///   2. `entry_for(target_aid)?` → `AidNotFound` on miss.
    ///   3. `entry.key_handle.sign_slot` → `TokenAbsent` if `None`.
    ///
    /// Returns the PIV slot the dispatch arm should drive via the
    /// active backend.
    pub fn resolve_sign(
        &self,
        caller_aid: &AID,
        target_aid: &AID,
    ) -> Result<PivSlot, VaultError> {
        self.authorize(caller_aid)?;
        let entry = self.entry_for(target_aid).ok_or(VaultError::AidNotFound)?;
        entry.key_handle.sign_slot.ok_or(VaultError::TokenAbsent)
    }

    /// Resolve `target_aid` to its decryption (KeyManagement) slot for
    /// `decrypt_with`. Same shape as `resolve_sign` against the
    /// `decrypt_slot` field.
    pub fn resolve_decrypt(
        &self,
        caller_aid: &AID,
        target_aid: &AID,
    ) -> Result<PivSlot, VaultError> {
        self.authorize(caller_aid)?;
        let entry = self.entry_for(target_aid).ok_or(VaultError::AidNotFound)?;
        entry.key_handle.decrypt_slot.ok_or(VaultError::TokenAbsent)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn aid(byte: u8) -> AID {
        [byte; 32]
    }

    fn sentinel_handle() -> KeyHandle {
        KeyHandle {
            device_id: HardwareDeviceId::Sentinel,
            sign_slot: None,
            decrypt_slot: None,
        }
    }

    fn dev_piv_handle() -> KeyHandle {
        KeyHandle {
            device_id: HardwareDeviceId::DevPiv,
            sign_slot: Some(PivSlot::Signature),
            decrypt_slot: Some(PivSlot::KeyManagement),
        }
    }

    #[test]
    fn new_vault_holds_bootstrap_entry() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, dev_piv_handle());
        assert_eq!(vault.bootstrap_aid(), &bootstrap);
        let entry = vault.entry_for(&bootstrap).expect("bootstrap entry");
        assert_eq!(entry.aid, bootstrap);
        assert_eq!(entry.key_handle, dev_piv_handle());
    }

    #[test]
    fn authorize_accepts_bootstrap() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        assert_eq!(vault.authorize(&bootstrap), Ok(()));
    }

    #[test]
    fn authorize_accepts_entry_aid() {
        // Sanity: an AID present in entries (which in v1 is the bootstrap AID
        // populated by Vault::new) authorizes via the entries scan as well as
        // the bootstrap fast-path.
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        // Bootstrap fast-path is the v1 path; an entry-scan-only path opens
        // when entries[1..] starts holding non-bootstrap AIDs (post-v1).
        assert_eq!(vault.authorize(&bootstrap), Ok(()));
    }

    #[test]
    fn authorize_rejects_unrecognized() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        let stranger = aid(0xBB);
        assert_eq!(vault.authorize(&stranger), Err(VaultError::NotAuthorized));
    }

    #[test]
    fn entry_for_returns_none_on_miss() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        let stranger = aid(0xBB);
        assert!(vault.entry_for(&stranger).is_none());
    }

    #[test]
    fn aid_for_context_returns_none_on_empty_map() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        assert!(vault.aid_for_context(b"social").is_none());
    }

    #[test]
    fn aid_for_context_rejects_invalid_label_lengths() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        assert!(vault.aid_for_context(b"").is_none());
        let too_long = [b'x'; MAX_CONTEXT_LABEL_LEN + 1];
        assert!(vault.aid_for_context(&too_long).is_none());
    }

    /// Test helper: populate one `context_map` slot. The runtime
    /// context-binding API lives in a later stage when a UX flow
    /// surfaces; for now tests need a way to exercise the
    /// `ContextMatch` branch of `bind_for_spawn`.
    fn insert_context(vault: &mut Vault, label: &[u8], aid_value: AID) {
        for slot in vault.context_map.iter_mut() {
            if slot.is_none() {
                let mut buf = [0u8; MAX_CONTEXT_LABEL_LEN];
                buf[..label.len()].copy_from_slice(label);
                *slot = Some(ContextMapEntry {
                    label: buf,
                    label_len: label.len() as u8,
                    aid: aid_value,
                });
                return;
            }
        }
        panic!("context_map full");
    }

    #[test]
    fn bind_for_spawn_falls_back_to_bootstrap_on_empty_context_map() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        let result = vault.bind_for_spawn(&bootstrap, b"social").unwrap();
        assert_eq!(result.aid, bootstrap);
        assert_eq!(result.source, BindSource::BootstrapFallback);
    }

    #[test]
    fn bind_for_spawn_falls_back_on_empty_label() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        let result = vault.bind_for_spawn(&bootstrap, b"").unwrap();
        assert_eq!(result.aid, bootstrap);
        assert_eq!(result.source, BindSource::BootstrapFallback);
    }

    #[test]
    fn bind_for_spawn_rejects_unauthorized_caller() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        let stranger = aid(0xBB);
        assert_eq!(
            vault.bind_for_spawn(&stranger, b"social"),
            Err(VaultError::NotAuthorized),
        );
    }

    #[test]
    fn bind_for_spawn_returns_context_match_when_label_is_bound() {
        let bootstrap = aid(0xAA);
        let work_aid = aid(0xCC);
        let mut vault = Vault::new(bootstrap, sentinel_handle());
        insert_context(&mut vault, b"work", work_aid);

        let result = vault.bind_for_spawn(&bootstrap, b"work").unwrap();
        assert_eq!(result.aid, work_aid);
        assert_eq!(result.source, BindSource::ContextMatch);

        // Untouched context still falls back.
        let other = vault.bind_for_spawn(&bootstrap, b"social").unwrap();
        assert_eq!(other.aid, bootstrap);
        assert_eq!(other.source, BindSource::BootstrapFallback);
    }

    // ------------------------------------------------------------------
    // resolve_sign / resolve_decrypt
    // ------------------------------------------------------------------

    #[test]
    fn resolve_sign_returns_slot_for_bootstrap_entry_with_dev_piv_handle() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, dev_piv_handle());
        assert_eq!(
            vault.resolve_sign(&bootstrap, &bootstrap),
            Ok(PivSlot::Signature),
        );
    }

    #[test]
    fn resolve_decrypt_returns_slot_for_bootstrap_entry_with_dev_piv_handle() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, dev_piv_handle());
        assert_eq!(
            vault.resolve_decrypt(&bootstrap, &bootstrap),
            Ok(PivSlot::KeyManagement),
        );
    }

    #[test]
    fn resolve_sign_returns_token_absent_for_sentinel_handle() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        assert_eq!(
            vault.resolve_sign(&bootstrap, &bootstrap),
            Err(VaultError::TokenAbsent),
        );
    }

    #[test]
    fn resolve_decrypt_returns_token_absent_for_sentinel_handle() {
        let bootstrap = aid(0xAA);
        let vault = Vault::new(bootstrap, sentinel_handle());
        assert_eq!(
            vault.resolve_decrypt(&bootstrap, &bootstrap),
            Err(VaultError::TokenAbsent),
        );
    }

    #[test]
    fn resolve_sign_returns_aid_not_found_for_unknown_target() {
        let bootstrap = aid(0xAA);
        let stranger = aid(0xBB);
        let vault = Vault::new(bootstrap, dev_piv_handle());
        assert_eq!(
            vault.resolve_sign(&bootstrap, &stranger),
            Err(VaultError::AidNotFound),
        );
    }

    #[test]
    fn resolve_decrypt_returns_aid_not_found_for_unknown_target() {
        let bootstrap = aid(0xAA);
        let stranger = aid(0xBB);
        let vault = Vault::new(bootstrap, dev_piv_handle());
        assert_eq!(
            vault.resolve_decrypt(&bootstrap, &stranger),
            Err(VaultError::AidNotFound),
        );
    }

    #[test]
    fn resolve_sign_rejects_unauthorized_caller() {
        let bootstrap = aid(0xAA);
        let stranger = aid(0xBB);
        let vault = Vault::new(bootstrap, dev_piv_handle());
        assert_eq!(
            vault.resolve_sign(&stranger, &bootstrap),
            Err(VaultError::NotAuthorized),
        );
    }

    #[test]
    fn resolve_decrypt_rejects_unauthorized_caller() {
        let bootstrap = aid(0xAA);
        let stranger = aid(0xBB);
        let vault = Vault::new(bootstrap, dev_piv_handle());
        assert_eq!(
            vault.resolve_decrypt(&stranger, &bootstrap),
            Err(VaultError::NotAuthorized),
        );
    }
}
