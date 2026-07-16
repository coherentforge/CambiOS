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
//!    (total validator) + [`cambios_manifest::validate_unique`] +
//!    zero-AID rejection.
//! 3. Populate [`ENDPOINT_RESERVATIONS`] (init's endpoint from the
//!    header, then every entry's reserved endpoints) and
//!    [`SPAWN_GRANTS`] (module name → AID + grants, transcribed into
//!    kernel types and rights-normalized by
//!    [`SpawnGrantTable::install`]).
//!
//! `handle_spawn`'s manifest arm consumes the spawn table: when the
//! caller [`is_init_process`] and the manifest declared the module,
//! [`install_manifest_row`] installs exactly the row's grants and
//! binds the row's AID. The arm is dormant until migration step 7
//! creates init and calls [`set_init_process`].
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
use crate::ipc::capability::{CapabilityError, CapabilityKind, CapabilityManager};
use crate::ipc::endpoint_reservation::EndpointReservationTable;
use crate::ipc::{CapabilityRights, EndpointId, Principal, ProcessId, MAX_ENDPOINTS};
use cambios_manifest::{
    system_caps, validate_unique, CapabilityGrant, Manifest, Rights, GRANTS_MAX,
    MAX_MANIFEST_ENTRIES, MODULE_NAME_MAX,
};

/// A manifest grant transcribed into kernel types: wire system-cap
/// identifiers resolved to [`CapabilityKind`], endpoint numbers
/// bounds-checked against [`MAX_ENDPOINTS`], and rights normalized
/// (see [`SpawnGrantTable::install`]). Applying one cannot fail for
/// mapping reasons — an unmappable wire grant was boot-fatal at
/// transcription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscribedGrant {
    /// Rights on one endpoint. After normalization, `rights` is the
    /// union of the entry's declared rights for this endpoint AND any
    /// `AllEndpoints` rights — pre-unioned because the kernel's
    /// per-process `grant()` REPLACES rights on regrant rather than
    /// merging, so a narrow grant applied after the wide one must
    /// already carry the wide bits or they are lost.
    Endpoint { endpoint: EndpointId, rights: CapabilityRights },
    /// Rights on every endpoint. At most one per row after
    /// normalization (multiple wire declarations union).
    AllEndpoints { rights: CapabilityRights },
    /// A system capability, resolved from its wire identifier.
    System { kind: CapabilityKind },
}

/// Wire rights → kernel rights. Field-for-field; both are the same
/// four-bit lattice.
fn kernel_rights(r: Rights) -> CapabilityRights {
    CapabilityRights {
        send: r.send,
        receive: r.receive,
        delegate: r.delegate,
        revoke: r.revoke,
    }
}

/// Union of two rights sets (grants are additive permissions).
fn rights_union(a: CapabilityRights, b: CapabilityRights) -> CapabilityRights {
    CapabilityRights {
        send: a.send || b.send,
        receive: a.receive || b.receive,
        delegate: a.delegate || b.delegate,
        revoke: a.revoke || b.revoke,
    }
}

/// Wire system-capability identifier → [`CapabilityKind`]. Total on
/// `u32`; `None` for identifiers the kernel does not know. The wire
/// side is append-only (`system_caps` doc), so this match only ever
/// gains arms; the `system_caps_map_exhaustively` test fails at PR
/// time if the wire crate gains a kind this mapping hasn't.
fn kernel_system_kind(kind: u32) -> Option<CapabilityKind> {
    Some(match kind {
        system_caps::CREATE_PROCESS => CapabilityKind::CreateProcess,
        system_caps::CREATE_CHANNEL => CapabilityKind::CreateChannel,
        system_caps::LEGACY_PORT_IO => CapabilityKind::LegacyPortIo,
        system_caps::MAP_FRAMEBUFFER => CapabilityKind::MapFramebuffer,
        system_caps::LARGE_CHANNEL => CapabilityKind::LargeChannel,
        system_caps::EMIT_INPUT_AUDIT => CapabilityKind::EmitInputAudit,
        system_caps::AUDIT_CONSUMER => CapabilityKind::AuditConsumer,
        system_caps::SET_WALLCLOCK => CapabilityKind::SetWallclock,
        system_caps::CREATE_CLUSTER => CapabilityKind::CreateCluster,
        system_caps::CLUSTER_REVOKE => CapabilityKind::ClusterRevoke,
        _ => return None,
    })
}

/// One transcribed spawn-table row: the AID the kernel binds and the
/// kernel-typed grants it installs when init spawns this module
/// (step 5).
#[derive(Clone, Copy)]
pub struct SpawnGrantEntry {
    name: [u8; MODULE_NAME_MAX],
    name_len: u8,
    aid: [u8; 32],
    /// Normalized dense prefix, ordered: the `AllEndpoints` grant (if
    /// any) first, then `Endpoint` grants (unique targets, pre-unioned
    /// rights), then `System` grants. The wide-before-narrow order and
    /// the pre-union together make application order-insensitive under
    /// replace-on-regrant semantics.
    grants: [Option<TranscribedGrant>; GRANTS_MAX],
}

impl SpawnGrantEntry {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn aid(&self) -> &[u8; 32] {
        &self.aid
    }

    /// Iterator over the transcribed grants (dense prefix of the array).
    pub fn grants(&self) -> impl Iterator<Item = TranscribedGrant> + '_ {
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
    /// A `System` grant's wire identifier has no `CapabilityKind`
    /// mapping. The parser bounds identifiers to `system_caps::MAX`,
    /// so this fires only if the wire crate gains a kind the kernel
    /// mapping hasn't (the `system_caps_map_exhaustively` test turns
    /// that drift into a host-test failure before it can boot-fail).
    UnknownSystemKind(u32),
    /// An `Endpoint` grant targets an endpoint at or above
    /// `MAX_ENDPOINTS`. The wire format cannot bound this (the limit
    /// is kernel configuration), so it is checked here.
    EndpointOutOfRange(u32),
    /// More than `GRANTS_MAX` distinct grants after normalization.
    /// Unreachable from the wire parser (which bounds declarations to
    /// `GRANTS_MAX`, and normalization only merges); exists so the
    /// fold is total for any iterator.
    TooManyGrants,
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

    /// Transcribe wire grants into kernel types and install one row.
    /// Grants beyond `GRANTS_MAX` cannot occur (the wire parser bounds
    /// them); the iterator is trusted to be the parser's projection.
    ///
    /// Normalization (grants are additive permissions — a rights SET
    /// per endpoint, so multiple declarations union):
    /// 1. All `AllEndpoints` declarations union into at most one.
    /// 2. `Endpoint` declarations with the same target union; each
    ///    then unions in the `AllEndpoints` rights, because the
    ///    kernel's `grant()` replaces rights on regrant (a narrow
    ///    grant applied after the wide loop would otherwise drop the
    ///    wide bits on its endpoint — and the emitter writes narrow
    ///    grants BEFORE the wide one, the worst order for replace
    ///    semantics).
    /// 3. `System` identifiers resolve to [`CapabilityKind`]
    ///    exhaustively; unknown values are typed rejects (boot-fatal
    ///    upstream).
    ///
    /// Normalization only merges, so the transcribed count never
    /// exceeds the wire count.
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

        // Fold the wire grants into normalized accumulators. All
        // bounds are wire-format bounds (≤ GRANTS_MAX declarations).
        let mut wide: Option<CapabilityRights> = None;
        let mut endpoints: [Option<(EndpointId, CapabilityRights)>; GRANTS_MAX] =
            [None; GRANTS_MAX];
        let mut systems: [Option<CapabilityKind>; GRANTS_MAX] = [None; GRANTS_MAX];
        let mut n_endpoints = 0usize;
        let mut n_systems = 0usize;
        for grant in grants {
            match grant {
                CapabilityGrant::AllEndpoints { rights } => {
                    let r = kernel_rights(rights);
                    wide = Some(match wide {
                        Some(w) => rights_union(w, r),
                        None => r,
                    });
                }
                CapabilityGrant::Endpoint { endpoint, rights } => {
                    if endpoint as usize >= MAX_ENDPOINTS {
                        return Err(SpawnTableError::EndpointOutOfRange(endpoint));
                    }
                    let ep = EndpointId(endpoint);
                    let r = kernel_rights(rights);
                    match endpoints[..n_endpoints]
                        .iter_mut()
                        .flatten()
                        .find(|(e, _)| *e == ep)
                    {
                        Some((_, existing)) => *existing = rights_union(*existing, r),
                        None => {
                            if n_endpoints >= GRANTS_MAX {
                                return Err(SpawnTableError::TooManyGrants);
                            }
                            endpoints[n_endpoints] = Some((ep, r));
                            n_endpoints += 1;
                        }
                    }
                }
                CapabilityGrant::System { kind } => {
                    let k = kernel_system_kind(kind)
                        .ok_or(SpawnTableError::UnknownSystemKind(kind))?;
                    if !systems[..n_systems].iter().flatten().any(|s| *s == k) {
                        if n_systems >= GRANTS_MAX {
                            return Err(SpawnTableError::TooManyGrants);
                        }
                        systems[n_systems] = Some(k);
                        n_systems += 1;
                    }
                }
            }
        }

        // Emit in the order the entry's doc comment promises:
        // wide → per-endpoint (with wide bits unioned in) → system.
        // The total bound makes every `grants[out]` write provably
        // in-range; for parser iterators it also follows from
        // "normalization only merges" (each emitted grant consumed at
        // least one of ≤ GRANTS_MAX wire declarations).
        if wide.is_some() as usize + n_endpoints + n_systems > GRANTS_MAX {
            return Err(SpawnTableError::TooManyGrants);
        }
        let mut entry = SpawnGrantEntry {
            name: [0u8; MODULE_NAME_MAX],
            name_len: name.len() as u8,
            aid,
            grants: [const { None }; GRANTS_MAX],
        };
        entry.name[..name.len()].copy_from_slice(name);
        let mut out = 0usize;
        if let Some(rights) = wide {
            entry.grants[out] = Some(TranscribedGrant::AllEndpoints { rights });
            out += 1;
        }
        for &(endpoint, rights) in endpoints[..n_endpoints].iter().flatten() {
            let rights = match wide {
                Some(w) => rights_union(rights, w),
                None => rights,
            };
            entry.grants[out] = Some(TranscribedGrant::Endpoint { endpoint, rights });
            out += 1;
        }
        for &kind in systems[..n_systems].iter().flatten() {
            entry.grants[out] = Some(TranscribedGrant::System { kind });
            out += 1;
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

/// Apply one spawn-table row to a freshly registered process: install
/// exactly the row's grants, then bind the row's AID as the process
/// Principal (ADR-018 § 4 — the manifest signature is the
/// authorization; no blanket endpoint loop, no inherited system caps).
///
/// Caller holds `CAPABILITY_MANAGER` (level 4) and nothing else; this
/// function takes no locks. Two passes because the per-process
/// `grant()` replaces rights on regrant: the wide grant must land
/// before the per-endpoint ones (which already carry the wide bits —
/// see [`SpawnGrantTable::install`]), and the pass split keeps that
/// true even if a future edit reorders the row's storage.
///
/// Every call here is structurally infallible for a transcribed row
/// on a fresh process (mapping errors were boot-fatal; the update
/// path in `grant()` is capacity-exempt; a fresh process has no bound
/// Principal), so an `Err` return means a kernel invariant broke —
/// the caller reports it loudly rather than swallowing it.
pub fn install_manifest_row(
    cap_mgr: &mut CapabilityManager,
    process_id: ProcessId,
    row: &SpawnGrantEntry,
) -> Result<(), CapabilityError> {
    for grant in row.grants() {
        if let TranscribedGrant::AllEndpoints { rights } = grant {
            for ep in 0..MAX_ENDPOINTS as u32 {
                cap_mgr.grant_capability(process_id, EndpointId(ep), rights)?;
            }
        }
    }
    for grant in row.grants() {
        match grant {
            TranscribedGrant::AllEndpoints { .. } => {}
            TranscribedGrant::Endpoint { endpoint, rights } => {
                cap_mgr.grant_capability(process_id, endpoint, rights)?;
            }
            TranscribedGrant::System { kind } => {
                cap_mgr.grant_system_capability(process_id, kind)?;
            }
        }
    }
    cap_mgr.bind_principal(process_id, Principal::from_aid(*row.aid()))
}

// ============================================================================
// Init identity
// ============================================================================

/// Init's manifest-declared identity, captured at transcription: the
/// AID the kernel binds to PID 1 and the endpoint init listens on
/// (both from the verified header — the manifest signature is the
/// authorization, ADR-018 § 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitIdentity {
    pub aid: [u8; 32],
    pub endpoint: u32,
}

/// `BOOTSTRAP_PRINCIPAL` lifecycle: written once by
/// [`transcribe_manifest_module`] during single-threaded boot,
/// read-only thereafter, outside the lock hierarchy. `None` means no
/// manifest was transcribed — the boot path must not create init.
static INIT_MANIFEST_IDENTITY: crate::arch::spinlock::Spinlock<Option<InitIdentity>> =
    crate::arch::spinlock::Spinlock::new(None);

/// The identity the kernel binds when it creates init, if a manifest
/// declared one this boot.
pub fn init_identity() -> Option<InitIdentity> {
    *INIT_MANIFEST_IDENTITY.lock()
}

/// The init process's kernel identity (ADR-018 § 4). `BOOTSTRAP_PRINCIPAL`
/// lifecycle: written exactly once when the kernel creates init during
/// single-threaded boot (migration step 7), read-only thereafter,
/// outside the lock hierarchy — the accessors are self-contained
/// lock-copy-unlock and are never called with another lock held.
///
/// `None` until step 7 lands, which keeps `handle_spawn`'s manifest
/// branch provably dead: no caller can equal an identity that is never
/// set. `ProcessId` equality includes the generation counter, so if
/// init ever exits and its slot is reused, the new occupant does not
/// inherit init's spawn authority.
static INIT_PROCESS: crate::arch::spinlock::Spinlock<Option<ProcessId>> =
    crate::arch::spinlock::Spinlock::new(None);

/// Error from [`set_init_process`]: init is created exactly once, at
/// boot; a second call is a kernel bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitAlreadySet;

/// Record init's ProcessId. Write-once; called by the boot path when
/// it creates init (migration step 7 — no caller exists before then).
pub fn set_init_process(pid: ProcessId) -> Result<(), InitAlreadySet> {
    let mut slot = INIT_PROCESS.lock();
    if slot.is_some() {
        return Err(InitAlreadySet);
    }
    *slot = Some(pid);
    Ok(())
}

/// Is `pid` the init process? `false` for every caller until step 7
/// sets the identity. Generation-aware (see [`INIT_PROCESS`]).
pub fn is_init_process(pid: ProcessId) -> bool {
    *INIT_PROCESS.lock() == Some(pid)
}

// ============================================================================
// Transcription
// ============================================================================

/// Validate a signature-stripped manifest payload: structural parse
/// (total validator) + cross-record uniqueness + no zero AIDs. Pure;
/// host-tested.
///
/// The zero-AID check exists because step 5 *binds* manifest AIDs as
/// process Principals, and the all-zero value is the kernel's
/// `Principal::ZERO` "no identity" sentinel — a signed manifest
/// carrying it would mint processes that alias the sentinel. Derived
/// AIDs are blake3 outputs, so the rejection costs nothing real.
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
    if m.init_aid() == [0u8; 32] {
        crate::println!("    ✗ manifest init AID is the zero sentinel");
        return Err(BootError::ManifestInconsistent);
    }
    for i in 0..m.entry_count() {
        if let Some(entry) = m.entry(i) {
            if entry.principal() == [0u8; 32] {
                crate::println!(
                    "    ✗ manifest entry '{}' AID is the zero sentinel",
                    entry.module_name()
                );
                return Err(BootError::ManifestInconsistent);
            }
        }
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

    // Step 4: capture init's identity for the boot path's PID-1
    // creation (same write-once discipline as the tables above).
    *INIT_MANIFEST_IDENTITY.lock() =
        Some(InitIdentity { aid: m.init_aid(), endpoint: m.init_endpoint() });

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
    fn populate_spawn_grants_transcribes_and_normalizes() {
        let blob = sample_blob();
        let m = validate_payload(&blob).unwrap();
        let mut table = SpawnGrantTable::new();
        assert_eq!(populate_spawn_grants(&m, &mut table).unwrap(), 1);
        let row = table.lookup(b"fs-service").unwrap();
        assert_eq!(row.aid(), &aid(2));
        // Wire order was narrow-then-wide (the emitter's real order);
        // the transcribed row is normalized: wide first, then the
        // endpoint grant carrying declared ∪ wide rights.
        let grants: Vec<TranscribedGrant> = row.grants().collect();
        assert_eq!(grants.len(), 2);
        assert_eq!(
            grants[0],
            TranscribedGrant::AllEndpoints {
                rights: CapabilityRights { send: true, receive: false, delegate: false, revoke: false },
            }
        );
        assert_eq!(
            grants[1],
            TranscribedGrant::Endpoint {
                endpoint: EndpointId(16),
                rights: CapabilityRights { send: true, receive: true, delegate: false, revoke: false },
            }
        );
        assert!(table.lookup(b"nonexistent").is_none());
    }

    #[test]
    fn system_caps_map_exhaustively() {
        // Every assigned wire identifier must resolve to a
        // CapabilityKind; a wire-side append without a kernel mapping
        // fails here at PR time instead of boot-failing later.
        for kind in 0..=system_caps::MAX {
            assert!(
                kernel_system_kind(kind).is_some(),
                "wire system-cap id {} has no CapabilityKind mapping",
                kind
            );
        }
        assert_eq!(kernel_system_kind(system_caps::MAX + 1), None);
        assert_eq!(
            kernel_system_kind(system_caps::CREATE_PROCESS),
            Some(CapabilityKind::CreateProcess)
        );
        assert_eq!(
            kernel_system_kind(system_caps::CLUSTER_REVOKE),
            Some(CapabilityKind::ClusterRevoke)
        );
    }

    #[test]
    fn install_rejects_unknown_system_kind_and_oob_endpoint() {
        let mut t = SpawnGrantTable::new();
        assert_eq!(
            t.install(
                b"a",
                aid(1),
                core::iter::once(CapabilityGrant::System { kind: system_caps::MAX + 7 }),
            ),
            Err(SpawnTableError::UnknownSystemKind(system_caps::MAX + 7))
        );
        assert_eq!(
            t.install(
                b"a",
                aid(1),
                core::iter::once(CapabilityGrant::Endpoint {
                    endpoint: MAX_ENDPOINTS as u32,
                    rights: Rights::RECEIVE,
                }),
            ),
            Err(SpawnTableError::EndpointOutOfRange(MAX_ENDPOINTS as u32))
        );
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn install_unions_duplicate_targets() {
        let mut t = SpawnGrantTable::new();
        t.install(
            b"svc",
            aid(1),
            [
                CapabilityGrant::Endpoint { endpoint: 5, rights: Rights::RECEIVE },
                CapabilityGrant::Endpoint { endpoint: 5, rights: Rights::SEND },
                CapabilityGrant::AllEndpoints { rights: Rights::SEND },
                CapabilityGrant::AllEndpoints {
                    rights: Rights { send: false, receive: false, delegate: true, revoke: false },
                },
                CapabilityGrant::System { kind: system_caps::CREATE_CHANNEL },
                CapabilityGrant::System { kind: system_caps::CREATE_CHANNEL },
            ]
            .into_iter(),
        )
        .unwrap();
        let row = t.lookup(b"svc").unwrap();
        let grants: Vec<TranscribedGrant> = row.grants().collect();
        // Two AllEndpoints union to one; two Endpoint{5} union to one
        // (and pick up the wide bits); duplicate System dedups.
        assert_eq!(grants.len(), 3);
        assert_eq!(
            grants[0],
            TranscribedGrant::AllEndpoints {
                rights: CapabilityRights { send: true, receive: false, delegate: true, revoke: false },
            }
        );
        assert_eq!(
            grants[1],
            TranscribedGrant::Endpoint {
                endpoint: EndpointId(5),
                rights: CapabilityRights { send: true, receive: true, delegate: true, revoke: false },
            }
        );
        assert_eq!(
            grants[2],
            TranscribedGrant::System { kind: CapabilityKind::CreateChannel }
        );
    }

    #[test]
    fn install_manifest_row_applies_exactly_the_row() {
        use crate::ipc::capability::CapabilityManager;

        let blob = sample_blob();
        let m = validate_payload(&blob).unwrap();
        let mut table = SpawnGrantTable::new();
        populate_spawn_grants(&m, &mut table).unwrap();
        let row = table.lookup(b"fs-service").unwrap();

        let mut cap_mgr = CapabilityManager::new_for_test();
        let pid = ProcessId::new(3, 0);
        cap_mgr.register_process(pid).unwrap();
        install_manifest_row(&mut cap_mgr, pid, row).unwrap();

        // Own endpoint: receive (narrow) AND send (wide, unioned) —
        // the replace-on-regrant hazard this exists to prevent.
        let receive = CapabilityRights { send: false, receive: true, delegate: false, revoke: false };
        let send = CapabilityRights { send: true, receive: false, delegate: false, revoke: false };
        assert!(cap_mgr.verify_access(pid, EndpointId(16), receive).is_ok());
        assert!(cap_mgr.verify_access(pid, EndpointId(16), send).is_ok());
        // Every other endpoint: send yes (wide), receive no.
        assert!(cap_mgr.verify_access(pid, EndpointId(17), send).is_ok());
        assert!(cap_mgr.verify_access(pid, EndpointId(17), receive).is_err());
        assert!(cap_mgr.verify_access(pid, EndpointId(0), send).is_ok());
        // No system caps beyond the row (fs-service declares none),
        // and the entry AID — not bootstrap — is the bound Principal.
        assert!(!cap_mgr.has_system_capability(pid, CapabilityKind::CreateProcess).unwrap());
        assert!(!cap_mgr.has_system_capability(pid, CapabilityKind::CreateChannel).unwrap());
        assert_eq!(cap_mgr.get_principal(pid).unwrap().aid(), &aid(2));
    }

    #[test]
    fn install_manifest_row_narrow_update_survives_full_table() {
        use crate::ipc::capability::{CapabilityManager, MAX_CAPS_PER_PROCESS};

        // The wide loop grants MAX_ENDPOINTS caps; the per-endpoint
        // pass then relies on grant()'s update-before-capacity-check
        // path. This pins the MAX_ENDPOINTS == MAX_CAPS_PER_PROCESS
        // lockstep the capability-table SCAFFOLDING comment names.
        assert_eq!(MAX_ENDPOINTS, MAX_CAPS_PER_PROCESS);

        let mut t = SpawnGrantTable::new();
        t.install(
            b"svc",
            aid(9),
            [
                CapabilityGrant::AllEndpoints { rights: Rights::SEND },
                CapabilityGrant::Endpoint { endpoint: 40, rights: Rights::RECEIVE },
            ]
            .into_iter(),
        )
        .unwrap();
        let row = t.lookup(b"svc").unwrap();

        let mut cap_mgr = CapabilityManager::new_for_test();
        let pid = ProcessId::new(4, 1);
        cap_mgr.register_process(pid).unwrap();
        install_manifest_row(&mut cap_mgr, pid, row).unwrap();

        let receive = CapabilityRights { send: false, receive: true, delegate: false, revoke: false };
        assert!(cap_mgr.verify_access(pid, EndpointId(40), receive).is_ok());
    }

    #[test]
    fn validate_payload_rejects_zero_aids() {
        // Zero entry AID.
        let defs = [EntryDef {
            module_name: "zeroed",
            principal: [0u8; 32],
            reserved_endpoints: &[16],
            grants: &[],
            lifetime: ServiceLifetime::OneShot,
            depends_on: &[],
        }];
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        assert_eq!(validate_payload(&buf).unwrap_err(), BootError::ManifestInconsistent);

        // Zero init AID.
        let defs = [EntryDef {
            module_name: "ok",
            principal: aid(2),
            reserved_endpoints: &[16],
            grants: &[],
            lifetime: ServiceLifetime::OneShot,
            depends_on: &[],
        }];
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest([0u8; 32], 1, &defs, &mut buf).unwrap();
        assert_eq!(validate_payload(&buf).unwrap_err(), BootError::ManifestInconsistent);
    }

    #[test]
    fn init_gate_is_dead_until_set_and_generation_aware() {
        // Unset: nobody is init — the step-5 spawn branch is dead code
        // until step 7 records init's identity.
        let pid = ProcessId::new(1, 0);
        assert!(!is_init_process(pid));

        // Set: exact (slot, generation) matches; a reused slot with a
        // bumped generation does not inherit init's spawn authority.
        set_init_process(pid).unwrap();
        assert!(is_init_process(pid));
        assert!(!is_init_process(ProcessId::new(1, 1)));
        assert!(!is_init_process(ProcessId::new(2, 0)));

        // Write-once: a second set is a kernel bug.
        assert_eq!(set_init_process(ProcessId::new(2, 0)), Err(InitAlreadySet));
        assert!(is_init_process(pid));
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
