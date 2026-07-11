// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Boot-manifest transcription (ADR-018 § 5, migration step 4).
//!
//! The kernel *transcribes* the manifest's security sections —
//! endpoint reservations and the per-module (AID, grants) spawn table
//! — into write-once kernel tables during boot-module load, before
//! any user task exists. It never *interprets* the manifest's policy
//! sections (`depends_on`, lifetimes, backoff): those are init's
//! (ADR-026 transcribe-don't-interpret, applied to boot config).
//!
//! Flow, called from `load_boot_modules` when a module named
//! [`cambios_manifest::MANIFEST_MODULE_NAME`] appears:
//!
//! 1. Verify the blob's ARCSIG trailer against the bootstrap pubkey
//!    (the same trailer scheme signed ELFs use — [ADR-004] Div. 1).
//! 2. Structurally validate via [`cambios_manifest::Manifest::parse`]
//!    (total validator) + [`cambios_manifest::validate_unique`].
//! 3. Populate [`ENDPOINT_RESERVATIONS`] (init's endpoint from the
//!    header, then every entry's reserved endpoints) and
//!    [`SPAWN_GRANTS`] (module name → AID + grants, consumed by
//!    `handle_spawn`'s manifest branch at migration step 5).
//!
//! A **present-but-invalid** manifest is a fatal [`BootError`] —
//! booting permissively on corrupt security configuration would be
//! the vulnerability. An **absent** manifest module leaves both
//! tables empty, which is behavior-identical to the pre-ADR-018
//! kernel.
//!
//! Both tables follow the `BOOTSTRAP_PRINCIPAL` lifecycle: written
//! once here (single-threaded boot), read-only thereafter, outside
//! the lock hierarchy. The populate helpers take `&mut` table
//! references so the pure logic is host-testable on local instances;
//! only the thin boot wrapper touches the globals.
//!
//! [`ENDPOINT_RESERVATIONS`]: crate::ipc::endpoint_reservation::ENDPOINT_RESERVATIONS
//! [ADR-004]: ../../docs/adr/004-cryptographic-integrity.md

use crate::boot::error::BootError;
use crate::ipc::endpoint_reservation::EndpointReservationTable;
use cambios_manifest::{
    validate_unique, CapabilityGrant, Manifest, GRANTS_MAX, MAX_MANIFEST_ENTRIES,
    MODULE_NAME_MAX,
};

/// One transcribed spawn-table row: the AID the kernel binds and the
/// grants it installs when init spawns this module (step 5).
#[derive(Clone, Copy)]
pub struct SpawnGrantEntry {
    name: [u8; MODULE_NAME_MAX],
    name_len: u8,
    aid: [u8; 32],
    grants: [Option<CapabilityGrant>; GRANTS_MAX],
}

impl SpawnGrantEntry {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn aid(&self) -> &[u8; 32] {
        &self.aid
    }

    /// Iterator over the declared grants (dense prefix of the array).
    pub fn grants(&self) -> impl Iterator<Item = CapabilityGrant> + '_ {
        self.grants.iter().filter_map(|g| *g)
    }
}

/// Errors from spawn-table population. Boot-fatal via
/// [`BootError::ManifestTranscriptionFailed`]; the duplicate case is
/// unreachable after `validate_unique` and exists so the table's own
/// invariant does not depend on its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnTableError {
    Full,
    DuplicateName,
    NameTooLong,
}

/// Per-module spawn-grant table: module name → (AID, grants).
/// Capacity is `MAX_MANIFEST_ENTRIES` — the manifest is the only
/// writer, so the bounds are the wire format's bounds.
pub struct SpawnGrantTable {
    entries: [Option<SpawnGrantEntry>; MAX_MANIFEST_ENTRIES],
    count: usize,
}

impl Default for SpawnGrantTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SpawnGrantTable {
    pub const fn new() -> Self {
        Self { entries: [const { None }; MAX_MANIFEST_ENTRIES], count: 0 }
    }

    /// Install one row. Grants beyond `GRANTS_MAX` cannot occur (the
    /// wire parser bounds them); the iterator is trusted to be the
    /// parser's projection.
    pub fn install(
        &mut self,
        name: &[u8],
        aid: [u8; 32],
        grants: impl Iterator<Item = CapabilityGrant>,
    ) -> Result<(), SpawnTableError> {
        if name.len() > MODULE_NAME_MAX {
            return Err(SpawnTableError::NameTooLong);
        }
        if self.lookup(name).is_some() {
            return Err(SpawnTableError::DuplicateName);
        }
        if self.count >= MAX_MANIFEST_ENTRIES {
            return Err(SpawnTableError::Full);
        }
        let mut entry = SpawnGrantEntry {
            name: [0u8; MODULE_NAME_MAX],
            name_len: name.len() as u8,
            aid,
            grants: [const { None }; GRANTS_MAX],
        };
        entry.name[..name.len()].copy_from_slice(name);
        for (slot, grant) in entry.grants.iter_mut().zip(grants) {
            *slot = Some(grant);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Linear name lookup (bounded by `MAX_MANIFEST_ENTRIES`; used at
    /// `SYS_SPAWN`, where the module-registry lookup beside it is the
    /// same shape and cost).
    pub fn lookup(&self, name: &[u8]) -> Option<&SpawnGrantEntry> {
        self.entries[..self.count]
            .iter()
            .flatten()
            .find(|e| e.name() == name)
    }

    pub fn count(&self) -> usize {
        self.count
    }
}

/// Global spawn-grant table. `BOOTSTRAP_PRINCIPAL` lifecycle: written
/// once at single-threaded boot by [`transcribe_manifest_module`],
/// read-only thereafter, NOT in the lock hierarchy — every accessor
/// is a self-contained lock-copy-unlock; never call while holding
/// another lock.
pub struct SpawnGrants {
    inner: crate::arch::spinlock::Spinlock<SpawnGrantTable>,
}

impl Default for SpawnGrants {
    fn default() -> Self {
        Self::new()
    }
}

impl SpawnGrants {
    pub const fn new() -> Self {
        Self { inner: crate::arch::spinlock::Spinlock::new(SpawnGrantTable::new()) }
    }

    /// Copy out the row for `name`, if the manifest declared one.
    pub fn lookup(&self, name: &[u8]) -> Option<SpawnGrantEntry> {
        self.inner.lock().lookup(name).copied()
    }

    pub fn count(&self) -> usize {
        self.inner.lock().count()
    }

    fn with_table<R>(&self, f: impl FnOnce(&mut SpawnGrantTable) -> R) -> R {
        f(&mut self.inner.lock())
    }
}

pub static SPAWN_GRANTS: SpawnGrants = SpawnGrants::new();

// ============================================================================
// Transcription
// ============================================================================

/// Validate a signature-stripped manifest payload: structural parse
/// (total validator) + cross-record uniqueness. Pure; host-tested.
fn validate_payload(payload: &[u8]) -> Result<Manifest<'_>, BootError> {
    let m = match Manifest::parse(payload) {
        Ok(m) => m,
        Err(e) => {
            crate::println!("    ✗ manifest parse failed: {:?}", e);
            return Err(BootError::ManifestMalformed);
        }
    };
    if let Err(e) = validate_unique(&m) {
        crate::println!("    ✗ manifest cross-record validation failed: {:?}", e);
        return Err(BootError::ManifestInconsistent);
    }
    Ok(m)
}

/// Populate an endpoint-reservation table from a validated manifest:
/// init's endpoint (from the header) plus every entry's reserved
/// endpoints. Pure; host-tested on local tables. Returns the number
/// of reservations installed.
fn populate_reservations(
    m: &Manifest<'_>,
    table: &mut EndpointReservationTable,
) -> Result<usize, BootError> {
    let mut installed = 0usize;
    if let Err(e) = table.install(m.init_endpoint(), m.init_aid()) {
        crate::println!("    ✗ init-endpoint reservation failed: {:?}", e);
        return Err(BootError::ManifestTranscriptionFailed);
    }
    installed += 1;
    for i in 0..m.entry_count() {
        let entry = match m.entry(i) {
            Some(e) => e,
            None => continue, // unreachable: i < entry_count
        };
        let aid = entry.principal();
        for ep in entry.reserved_endpoints() {
            if let Err(e) = table.install(ep, aid) {
                crate::println!(
                    "    ✗ reservation install failed for endpoint {}: {:?}",
                    ep, e
                );
                return Err(BootError::ManifestTranscriptionFailed);
            }
            installed += 1;
        }
    }
    Ok(installed)
}

/// Populate a spawn-grant table from a validated manifest. Pure;
/// host-tested on local tables. Returns the number of rows installed.
fn populate_spawn_grants(
    m: &Manifest<'_>,
    table: &mut SpawnGrantTable,
) -> Result<usize, BootError> {
    for i in 0..m.entry_count() {
        let entry = match m.entry(i) {
            Some(e) => e,
            None => continue, // unreachable: i < entry_count
        };
        if let Err(e) =
            table.install(entry.module_name().as_bytes(), entry.principal(), entry.grants())
        {
            crate::println!(
                "    ✗ spawn-table install failed for '{}': {:?}",
                entry.module_name(), e
            );
            return Err(BootError::ManifestTranscriptionFailed);
        }
    }
    Ok(m.entry_count())
}

/// Verify + transcribe the boot-manifest module into the global
/// enforcement tables. Called from `load_boot_modules` during
/// single-threaded boot; a `Err` return is boot-fatal (routed to
/// `boot_failed` by the caller).
///
/// Returns `(spawn_rows, reservations)` for the boot banner.
pub fn transcribe_manifest_module(
    blob: &[u8],
    bootstrap_pubkey: &[u8; 32],
) -> Result<(usize, usize), BootError> {
    use crate::crypto::{self, PublicKeyRef, SignatureAlgo, SignatureRef};
    use crate::loader::{parse_signature_trailer, TrailerStatus};

    // Step 1: ARCSIG verification — same trailer scheme as signed
    // ELFs; the signed message is blake3(payload).
    let payload = match parse_signature_trailer(blob) {
        TrailerStatus::V1Ed25519 { elf: payload, sig } => {
            let hash = blake3::hash(payload);
            let ok = crypto::verify(
                SignatureAlgo::Ed25519,
                PublicKeyRef::Ed25519(bootstrap_pubkey),
                hash.as_bytes(),
                SignatureRef::Ed25519(&sig),
            );
            if !ok {
                crate::println!("    ✗ manifest ARCSIG signature does not verify");
                return Err(BootError::ManifestSignatureInvalid);
            }
            payload
        }
        TrailerStatus::Absent => {
            crate::println!("    ✗ manifest module has no ARCSIG trailer");
            return Err(BootError::ManifestSignatureInvalid);
        }
        TrailerStatus::Unsupported { version, algo } => {
            crate::println!(
                "    ✗ manifest trailer (version {}, algo {}) unsupported",
                version, algo
            );
            return Err(BootError::ManifestSignatureInvalid);
        }
    };

    // Step 2: structural + cross-record validation.
    let m = validate_payload(payload)?;

    // Step 3: populate the write-once tables (single-threaded boot;
    // one global locked at a time).
    let reservations = crate::ipc::endpoint_reservation::ENDPOINT_RESERVATIONS
        .with_table(|t| populate_reservations(&m, t))?;
    let spawn_rows = SPAWN_GRANTS.with_table(|t| populate_spawn_grants(&m, t))?;

    Ok((spawn_rows, reservations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cambios_manifest::{emit_manifest, emitted_size, EntryDef, Rights, ServiceLifetime};

    fn aid(tag: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = tag;
        a
    }

    fn sample_blob() -> Vec<u8> {
        const FS_GRANTS: [CapabilityGrant; 2] = [
            CapabilityGrant::Endpoint { endpoint: 16, rights: Rights::RECEIVE },
            CapabilityGrant::AllEndpoints { rights: Rights::SEND },
        ];
        let defs = [EntryDef {
            module_name: "fs-service",
            principal: aid(2),
            reserved_endpoints: &[16],
            grants: &FS_GRANTS,
            lifetime: ServiceLifetime::OneShot,
            depends_on: &[],
        }];
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        buf
    }

    #[test]
    fn populate_reservations_installs_header_and_entries() {
        let blob = sample_blob();
        let m = validate_payload(&blob).unwrap();
        let mut table = EndpointReservationTable::new();
        let n = populate_reservations(&m, &mut table).unwrap();
        assert_eq!(n, 2); // init ep 1 + fs ep 16
        assert_eq!(table.owner(1), Some(aid(0xEE)));
        assert_eq!(table.owner(16), Some(aid(2)));
        assert_eq!(table.owner(17), None);
    }

    #[test]
    fn populate_spawn_grants_round_trips() {
        let blob = sample_blob();
        let m = validate_payload(&blob).unwrap();
        let mut table = SpawnGrantTable::new();
        assert_eq!(populate_spawn_grants(&m, &mut table).unwrap(), 1);
        let row = table.lookup(b"fs-service").unwrap();
        assert_eq!(row.aid(), &aid(2));
        let grants: Vec<CapabilityGrant> = row.grants().collect();
        assert_eq!(grants.len(), 2);
        assert_eq!(
            grants[0],
            CapabilityGrant::Endpoint { endpoint: 16, rights: Rights::RECEIVE }
        );
        assert!(table.lookup(b"nonexistent").is_none());
    }

    #[test]
    fn validate_payload_rejects_garbage_and_truncation() {
        assert_eq!(validate_payload(&[0u8; 8]).unwrap_err(), BootError::ManifestMalformed);
        let mut blob = sample_blob();
        blob[0] = b'X';
        assert_eq!(validate_payload(&blob).unwrap_err(), BootError::ManifestMalformed);
    }

    #[test]
    fn populate_reservations_rejects_init_endpoint_collision_defensively() {
        // validate_unique catches this upstream; the populate helper's
        // own error path fires if a caller skips validation.
        let defs = [EntryDef {
            module_name: "evil",
            principal: aid(3),
            reserved_endpoints: &[1], // collides with init's endpoint
            grants: &[],
            lifetime: ServiceLifetime::OneShot,
            depends_on: &[],
        }];
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        let m = Manifest::parse(&buf).unwrap(); // structurally fine
        let mut table = EndpointReservationTable::new();
        assert_eq!(
            populate_reservations(&m, &mut table).unwrap_err(),
            BootError::ManifestTranscriptionFailed
        );
    }

    #[test]
    fn spawn_table_rejects_duplicates_and_overflow_name() {
        let mut t = SpawnGrantTable::new();
        t.install(b"a", aid(1), core::iter::empty()).unwrap();
        assert_eq!(
            t.install(b"a", aid(2), core::iter::empty()),
            Err(SpawnTableError::DuplicateName)
        );
        let long = [b'x'; MODULE_NAME_MAX + 1];
        assert_eq!(
            t.install(&long, aid(3), core::iter::empty()),
            Err(SpawnTableError::NameTooLong)
        );
        assert_eq!(t.count(), 1);
    }
}
