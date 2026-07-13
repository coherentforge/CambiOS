// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS boot-manifest wire format ([ADR-018]).
//!
//! One crate, three consumers:
//!
//! - the **kernel** transcribes the manifest's security sections
//!   (endpoint reservations, per-module AID + capability grants) into
//!   write-once enforcement tables at boot;
//! - **init** (PID 1) parses the same blob for its policy sections
//!   (`depends_on` DAG, lifetime / restart parameters);
//! - **tools/build-manifest** emits the blob from the endpoint-registry
//!   source artifact and signs it (ARCSIG, outside this crate).
//!
//! The parser is a *total validator*: [`Manifest::parse`] range-checks
//! every offset, length byte, tag, and string reference up front, in
//! one bounded pass, so the accessor views that follow are infallible
//! projections (`Option` only for out-of-range indices). There is no
//! `unsafe`, no `transmute`, no allocation: all field access is
//! explicit little-endian byte reads at named offsets. This is the
//! BuddyAllocator template applied to parsing — pure logic, host-
//! testable, a future Kani target ("parsed views ≡ well-formed blob").
//!
//! Trailing bytes after the declared regions are ignored, so callers
//! may hand the parser a blob with or without its ARCSIG trailer;
//! signature verification happens *before* parsing, in the kernel's
//! existing trailer path ([ADR-004] § Divergence 1).
//!
//! [ADR-018]: ../../docs/adr/018-init-process-and-boot-manifest.md
//! [ADR-004]: ../../docs/adr/004-cryptographic-integrity.md

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

// ============================================================================
// Wire constants and bounds
// ============================================================================

/// Magic bytes at offset 0 of every manifest blob.
pub const MAGIC: [u8; 8] = *b"CBOSMANI";

/// Wire-format version this crate reads and writes.
pub const VERSION: u32 = 1;

/// Boot-module name the kernel recognizes as the manifest blob
/// (`strip_module_name` output for `boot():/boot/manifest.bin` —
/// only the `.elf` suffix is stripped, so the `.bin` stays).
pub const MANIFEST_MODULE_NAME: &str = "manifest.bin";

/// Fixed user-space virtual address at which the kernel maps the
/// manifest blob read-only into init's address space (ADR-018 § 6).
/// Chosen clear of the user code base (0x400000) and the user stack
/// top (0x800000).
pub const MANIFEST_USER_VADDR: u64 = 0x0100_0000;

/// Default endpoint init listens on for readiness pings. The header's
/// `init_endpoint` field carries the authoritative value (v1 build
/// tooling always writes 1); endpoint 0 is structurally unusable —
/// it is the kernel's `REPLY_ENDPOINT` "unset" sentinel.
pub const INIT_ENDPOINT: u32 = 1;

/// First payload byte of the readiness ping a spawned service sends
/// to init's endpoint once its endpoints are registered (ADR-018 § 4
/// — emitted where `SYS_MODULE_READY` is emitted today, swapped at
/// migration step 8). *Which service* is ready comes from the
/// kernel-stamped `sender_principal`, never from the payload; the tag
/// only distinguishes ready pings from future message kinds on the
/// same endpoint.
pub const READY_PING_TAG: u8 = 0x01;

/// Domain-separation tag for v1 service-AID derivation:
/// `aid = blake3(SERVICE_AID_DOMAIN_TAG || module_name)`.
/// Derivation itself lives in tools/build-manifest (this crate is
/// dependency-free); the tag is here so any consumer can re-derive.
pub const SERVICE_AID_DOMAIN_TAG: &str = "cambios:v1:service-aid:";

/// Domain-separation tag for the v1 init AID:
/// `init_aid = blake3(INIT_AID_DOMAIN_TAG)`.
pub const INIT_AID_DOMAIN_TAG: &str = "cambios:v1:init-aid";

/// SCAFFOLDING: maximum manifest entries a blob may declare.
/// Why: bounds the kernel spawn-grant table, init's DAG scratch arrays,
///      and the parser's cross-record validation loops. Sized for the
///      v1-endgame boot-service count (~30: today's 17 spawned services
///      plus input-hub, net diversification, AI watcher, win-compat
///      services) at ≤25% utilization per ASSUMPTIONS.md.
/// Replace when: MAX_BOOT_MODULES (src/boot/mod.rs + src/boot_modules.rs,
///      128 since migration step 4) moves — the two stay in lockstep;
///      a manifest can never describe more modules than the registry
///      can load.
pub const MAX_MANIFEST_ENTRIES: usize = 128;

/// SCAFFOLDING: maximum reserved endpoints per manifest entry.
/// Why: largest observed owner is virtio-blk with 3 (24/25/26);
///      v1-endgame per-service estimate is 4 at ≤25% utilization.
/// Replace when: a manifest entry legitimately needs a 17th endpoint.
pub const RESERVED_ENDPOINTS_MAX: usize = 16;

/// SCAFFOLDING: maximum capability grants per manifest entry.
/// Why: structurally coupled, not workload-scaled — the narrow-receive
///      default grants one `Endpoint{receive}` per reserved endpoint
///      (≤ RESERVED_ENDPOINTS_MAX) plus one `AllEndpoints{send}` plus
///      a handful of System grants (10 kinds exist today).
/// Replace when: RESERVED_ENDPOINTS_MAX grows past 16 or the System
///      capability count approaches 15.
pub const GRANTS_MAX: usize = 32;

/// SCAFFOLDING: maximum direct dependencies per manifest entry.
/// Why: observed direct-dependency fan-in today is ≤3 (the limine.conf
///      ordering comments); v1-endgame estimate 4 at ≤25% utilization.
/// Replace when: a real service legitimately declares a 17th direct
///      dependency (likely a smell — consider an intermediate target).
pub const DEPS_MAX: usize = 16;

/// SCAFFOLDING: maximum module-name length in bytes.
/// Why: lockstep with `MAX_NAME_LEN = 64` in src/boot_modules.rs — a
///      manifest name must be findable in the boot-module registry.
/// Replace when: boot_modules::MAX_NAME_LEN changes (move together).
pub const MODULE_NAME_MAX: usize = 64;

// ----------------------------------------------------------------------------
// Fixed layout: header
// ----------------------------------------------------------------------------

/// Header length in bytes. Layout (all integers little-endian):
///
/// | offset | size | field           |
/// |--------|------|-----------------|
/// | 0      | 8    | magic           |
/// | 8      | 4    | version         |
/// | 12     | 4    | entry_count     |
/// | 16     | 4    | entries_offset  |
/// | 20     | 4    | strings_offset  |
/// | 24     | 4    | strings_len     |
/// | 28     | 4    | init_endpoint   |
/// | 32     | 32   | init_aid        |
pub const HEADER_LEN: usize = 64;

const OFF_VERSION: usize = 8;
const OFF_ENTRY_COUNT: usize = 12;
const OFF_ENTRIES_OFFSET: usize = 16;
const OFF_STRINGS_OFFSET: usize = 20;
const OFF_STRINGS_LEN: usize = 24;
const OFF_INIT_ENDPOINT: usize = 28;
const OFF_INIT_AID: usize = 32;

// ----------------------------------------------------------------------------
// Fixed layout: entry
// ----------------------------------------------------------------------------

/// Entry record length in bytes. Layout (all integers little-endian):
///
/// | offset | size | field                                      |
/// |--------|------|--------------------------------------------|
/// | 0      | 32   | principal (AID, ADR-025)                   |
/// | 32     | 8    | module_name_ref (offset u32, len u32)      |
/// | 40     | 64   | reserved_endpoints `[u32; 16]`             |
/// | 104    | 1    | reserved_endpoints_len                     |
/// | 105    | 1    | granted_capabilities_len                   |
/// | 106    | 1    | depends_on_len                             |
/// | 107    | 1    | (pad, must be 0)                           |
/// | 108    | 16   | lifetime (see `LIFETIME_*` offsets)        |
/// | 124    | 256  | granted_capabilities `[grant 8B; 32]`      |
/// | 380    | 128  | depends_on `[StringRef 8B; 16]`            |
/// | 508    | 20   | reserved (must be 0 in v1)                 |
pub const ENTRY_LEN: usize = 528;

/// ARCHITECTURAL: upper bound on a well-formed manifest payload,
/// fully derived from the wire bounds above — header, a full entry
/// region, and a strings region where every entry carries a
/// maximum-length name plus `DEPS_MAX` maximum-length dependency
/// references with zero interning. Both sides of the boot contract
/// consume it: the kernel bounds its read-only mapping of the blob
/// into init (ADR-018 § 6, migration step 7), and init clamps the
/// header-declared extent before forming its parse slice — a slice
/// must never extend past the mapped region, however trustworthy the
/// header. Changes only when the constituent bounds do.
pub const MANIFEST_MAX_BYTES: usize = HEADER_LEN
    + MAX_MANIFEST_ENTRIES * ENTRY_LEN
    + MAX_MANIFEST_ENTRIES * MODULE_NAME_MAX * (1 + DEPS_MAX);

const E_OFF_PRINCIPAL: usize = 0;
const E_OFF_NAME_REF: usize = 32;
const E_OFF_ENDPOINTS: usize = 40;
const E_OFF_ENDPOINTS_LEN: usize = 104;
const E_OFF_GRANTS_LEN: usize = 105;
const E_OFF_DEPS_LEN: usize = 106;
const E_OFF_PAD: usize = 107;
const E_OFF_LIFETIME: usize = 108;
const E_OFF_GRANTS: usize = 124;
const E_OFF_DEPS: usize = 380;
const E_OFF_RESERVED: usize = 508;

/// Lifetime sub-record layout, relative to `E_OFF_LIFETIME`:
/// tag u8 @0, pad u8 @1 (0), max_restarts u16 @2, initial_delay_ms
/// u32 @4, max_delay_ms u32 @8, failure_window_ms u32 @12.
const L_OFF_TAG: usize = 0;
const L_OFF_PAD: usize = 1;
const L_OFF_MAX_RESTARTS: usize = 2;
const L_OFF_INITIAL_DELAY: usize = 4;
const L_OFF_MAX_DELAY: usize = 8;
const L_OFF_FAILURE_WINDOW: usize = 12;

const LIFETIME_TAG_ONESHOT: u8 = 0;
const LIFETIME_TAG_PERSISTENT: u8 = 1;

/// Grant sub-record layout (8 bytes): kind u8 @0, rights u8 @1,
/// pad u16 @2 (0), target u32 @4.
pub const GRANT_LEN: usize = 8;
const G_OFF_KIND: usize = 0;
const G_OFF_RIGHTS: usize = 1;
const G_OFF_PAD: usize = 2;
const G_OFF_TARGET: usize = 4;

const GRANT_KIND_ENDPOINT: u8 = 0;
const GRANT_KIND_ALL_ENDPOINTS: u8 = 1;
const GRANT_KIND_SYSTEM: u8 = 2;

/// StringRef (8 bytes): offset u32 (relative to the strings region
/// start), len u32.
pub const STRING_REF_LEN: usize = 8;

// ============================================================================
// Wire-stable system-capability identifiers
// ============================================================================

/// Wire identifiers for `CapabilityGrant::System` targets. These are
/// the manifest's stable numbering; the kernel maps them exhaustively
/// onto its `CapabilityKind` at transcription time and rejects unknown
/// values with a typed boot error. Append-only: never renumber, never
/// reuse (same discipline as syscall slots).
pub mod system_caps {
    pub const CREATE_PROCESS: u32 = 0;
    pub const CREATE_CHANNEL: u32 = 1;
    pub const LEGACY_PORT_IO: u32 = 2;
    pub const MAP_FRAMEBUFFER: u32 = 3;
    pub const LARGE_CHANNEL: u32 = 4;
    pub const EMIT_INPUT_AUDIT: u32 = 5;
    pub const AUDIT_CONSUMER: u32 = 6;
    pub const SET_WALLCLOCK: u32 = 7;
    pub const CREATE_CLUSTER: u32 = 8;
    pub const CLUSTER_REVOKE: u32 = 9;

    /// Highest assigned identifier. `Manifest::parse` rejects System
    /// grants above this; bump when appending a new kind.
    pub const MAX: u32 = CLUSTER_REVOKE;
}

// ============================================================================
// Parsed value types
// ============================================================================

/// Endpoint rights bits carried by a grant. Wire encoding: bit 0 =
/// send, bit 1 = receive, bit 2 = delegate, bit 3 = revoke; bits 4-7
/// must be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights {
    pub send: bool,
    pub receive: bool,
    pub delegate: bool,
    pub revoke: bool,
}

impl Rights {
    pub const SEND: Rights = Rights { send: true, receive: false, delegate: false, revoke: false };
    pub const RECEIVE: Rights = Rights { send: false, receive: true, delegate: false, revoke: false };

    /// Decode from the wire byte. `None` if any reserved bit (4-7) is set.
    pub const fn from_bits(bits: u8) -> Option<Rights> {
        if bits & 0xF0 != 0 {
            return None;
        }
        Some(Rights {
            send: bits & 0x01 != 0,
            receive: bits & 0x02 != 0,
            delegate: bits & 0x04 != 0,
            revoke: bits & 0x08 != 0,
        })
    }

    pub const fn to_bits(self) -> u8 {
        (self.send as u8)
            | ((self.receive as u8) << 1)
            | ((self.delegate as u8) << 2)
            | ((self.revoke as u8) << 3)
    }
}

/// One capability grant, as declared by a manifest entry (ADR-018 § 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityGrant {
    /// Rights on one named endpoint.
    Endpoint { endpoint: u32, rights: Rights },
    /// Rights on every endpoint. v1 services carry
    /// `AllEndpoints { send }` (replies target clients' self-chosen
    /// reply endpoints, which cannot be pre-declared).
    AllEndpoints { rights: Rights },
    /// A system capability; `kind` is a [`system_caps`] identifier.
    System { kind: u32 },
}

/// Lifecycle policy for a manifest entry — interpreted by init only;
/// the kernel ignores it (ADR-018 § 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceLifetime {
    OneShot,
    Persistent {
        initial_delay_ms: u32,
        max_delay_ms: u32,
        max_restarts: u16,
        failure_window_ms: u32,
    },
}

// ============================================================================
// Errors
// ============================================================================

/// Per-entry structural defects, reported with the entry index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    /// `reserved_endpoints_len` exceeds `RESERVED_ENDPOINTS_MAX`.
    EndpointsLen(u8),
    /// `granted_capabilities_len` exceeds `GRANTS_MAX`.
    GrantsLen(u8),
    /// `depends_on_len` exceeds `DEPS_MAX`.
    DepsLen(u8),
    /// Module-name StringRef is outside the strings region.
    NameRefRange,
    /// Module name is empty.
    NameEmpty,
    /// Module name exceeds `MODULE_NAME_MAX`.
    NameTooLong,
    /// Module name is not valid UTF-8.
    NameUtf8,
    /// A `depends_on` StringRef is outside the strings region.
    DepRefRange(u8),
    /// A `depends_on` name is empty, too long, or not valid UTF-8.
    DepName(u8),
    /// A grant's kind byte is not a known discriminant (grant index
    /// carried, like the other Grant* variants).
    GrantKind(u8),
    /// A grant's rights byte has reserved bits set, or a System
    /// grant carries a nonzero rights byte.
    GrantRights(u8),
    /// A grant's target is invalid for its kind (unknown System id,
    /// or nonzero AllEndpoints target).
    GrantTarget(u8),
    /// The grant's pad bytes are nonzero.
    GrantPad(u8),
    /// Lifetime tag byte is not a known discriminant.
    LifetimeTag(u8),
    /// OneShot lifetime carries nonzero restart fields, or the
    /// lifetime pad byte is nonzero.
    LifetimeFields,
    /// Entry pad or reserved bytes are nonzero.
    PadNonZero,
}

/// Structural defects of the blob as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    /// Shorter than `HEADER_LEN`.
    TooShort,
    BadMagic,
    /// Unknown version (found value carried).
    BadVersion(u32),
    /// `entry_count` exceeds `MAX_MANIFEST_ENTRIES`.
    TooManyEntries(u32),
    /// Entries region overlaps the header, overflows, or exceeds the blob.
    EntriesRange,
    /// Strings region overlaps the entries region, overflows, or
    /// exceeds the blob.
    StringsRange,
    /// `init_endpoint` is 0 (the kernel's REPLY_ENDPOINT sentinel —
    /// structurally unusable as a real endpoint).
    InitEndpointZero,
    /// A per-entry defect, with the entry index.
    Entry(u32, EntryError),
}

/// Cross-record validation defects (see [`validate_unique`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateError {
    /// Two entries share a module name (indices carried).
    DuplicateName(u32, u32),
    /// The same endpoint is reserved twice (endpoint carried) —
    /// including a collision with the header's `init_endpoint`.
    DuplicateEndpoint(u32),
}

/// Dependency-graph defects (see [`topo_order`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagError {
    /// An entry's dependency names no manifest entry
    /// (entry index, dep index carried).
    UnknownDep(u32, u8),
    /// The dependency graph has a cycle reachable from the carried
    /// entry index.
    Cycle(u32),
}

// ============================================================================
// Parser
// ============================================================================

#[inline]
fn read_u32(bytes: &[u8], off: usize) -> u32 {
    // Caller guarantees off + 4 <= bytes.len(); the slice-index panic
    // path is unreachable for validated offsets and acceptable in this
    // crate (not kernel context; the kernel calls only through
    // `Manifest::parse`, which bounds every offset before use).
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

#[inline]
fn read_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

/// A parsed, fully validated manifest. Construction via
/// [`Manifest::parse`] proves every accessor's preconditions; the view
/// methods after that are infallible projections.
#[derive(Clone, Copy)]
pub struct Manifest<'a> {
    bytes: &'a [u8],
    entry_count: u32,
    entries_offset: u32,
    strings_offset: u32,
    strings_len: u32,
    init_endpoint: u32,
}

impl core::fmt::Debug for Manifest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Manifest")
            .field("entry_count", &self.entry_count)
            .field("init_endpoint", &self.init_endpoint)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for EntryView<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EntryView")
            .field("module_name", &self.module_name())
            .finish_non_exhaustive()
    }
}


impl<'a> Manifest<'a> {
    /// Parse and validate a manifest blob. Total: on `Ok`, every entry,
    /// grant, lifetime, and string reference has been range-checked and
    /// decoded once. Trailing bytes (e.g. an ARCSIG trailer) are
    /// ignored. Signature verification is the caller's job and happens
    /// *before* this.
    pub fn parse(bytes: &'a [u8]) -> Result<Manifest<'a>, ManifestError> {
        if bytes.len() < HEADER_LEN {
            return Err(ManifestError::TooShort);
        }
        if bytes[0..8] != MAGIC {
            return Err(ManifestError::BadMagic);
        }
        let version = read_u32(bytes, OFF_VERSION);
        if version != VERSION {
            return Err(ManifestError::BadVersion(version));
        }
        let entry_count = read_u32(bytes, OFF_ENTRY_COUNT);
        if entry_count as usize > MAX_MANIFEST_ENTRIES {
            return Err(ManifestError::TooManyEntries(entry_count));
        }
        let entries_offset = read_u32(bytes, OFF_ENTRIES_OFFSET);
        let strings_offset = read_u32(bytes, OFF_STRINGS_OFFSET);
        let strings_len = read_u32(bytes, OFF_STRINGS_LEN);
        let init_endpoint = read_u32(bytes, OFF_INIT_ENDPOINT);
        if init_endpoint == 0 {
            return Err(ManifestError::InitEndpointZero);
        }

        // Entries region: starts at or after the header, bounded
        // arithmetic, fits in the blob.
        let entries_size = (entry_count as u64) * (ENTRY_LEN as u64);
        let entries_end = entries_offset as u64 + entries_size;
        if (entries_offset as usize) < HEADER_LEN || entries_end > bytes.len() as u64 {
            return Err(ManifestError::EntriesRange);
        }

        // Strings region: starts at or after the entries end, fits in
        // the blob. (Zero-length strings region is legal for an
        // entry-free manifest.)
        let strings_end = strings_offset as u64 + strings_len as u64;
        if (strings_offset as u64) < entries_end || strings_end > bytes.len() as u64 {
            return Err(ManifestError::StringsRange);
        }

        let m = Manifest { bytes, entry_count, entries_offset, strings_offset, strings_len, init_endpoint };

        // Validate every entry once, so the views are infallible.
        for i in 0..entry_count {
            m.validate_entry(i).map_err(|e| ManifestError::Entry(i, e))?;
        }
        Ok(m)
    }

    /// Blob-absolute byte offset of entry `i`'s record. Caller
    /// guarantees `i < entry_count` (proven at parse for internal use).
    #[inline]
    fn entry_base(&self, i: u32) -> usize {
        self.entries_offset as usize + (i as usize) * ENTRY_LEN
    }

    /// Resolve a StringRef at blob-absolute offset `ref_off` into the
    /// strings region. Structural checks only; UTF-8 is separate.
    fn resolve_ref(&self, ref_off: usize) -> Option<&'a [u8]> {
        let s_off = read_u32(self.bytes, ref_off) as u64;
        let s_len = read_u32(self.bytes, ref_off + 4) as u64;
        if s_off + s_len > self.strings_len as u64 {
            return None;
        }
        let abs = self.strings_offset as usize + s_off as usize;
        Some(&self.bytes[abs..abs + s_len as usize])
    }

    fn validate_entry(&self, i: u32) -> Result<(), EntryError> {
        let base = self.entry_base(i);
        let b = self.bytes;

        let ep_len = b[base + E_OFF_ENDPOINTS_LEN];
        if ep_len as usize > RESERVED_ENDPOINTS_MAX {
            return Err(EntryError::EndpointsLen(ep_len));
        }
        let grants_len = b[base + E_OFF_GRANTS_LEN];
        if grants_len as usize > GRANTS_MAX {
            return Err(EntryError::GrantsLen(grants_len));
        }
        let deps_len = b[base + E_OFF_DEPS_LEN];
        if deps_len as usize > DEPS_MAX {
            return Err(EntryError::DepsLen(deps_len));
        }
        if b[base + E_OFF_PAD] != 0 {
            return Err(EntryError::PadNonZero);
        }
        if b[base + E_OFF_RESERVED..base + ENTRY_LEN].iter().any(|&x| x != 0) {
            return Err(EntryError::PadNonZero);
        }

        // Module name: in range, non-empty, bounded, UTF-8.
        let name = self
            .resolve_ref(base + E_OFF_NAME_REF)
            .ok_or(EntryError::NameRefRange)?;
        if name.is_empty() {
            return Err(EntryError::NameEmpty);
        }
        if name.len() > MODULE_NAME_MAX {
            return Err(EntryError::NameTooLong);
        }
        if core::str::from_utf8(name).is_err() {
            return Err(EntryError::NameUtf8);
        }

        // Dependencies: each ref in range, non-empty, bounded, UTF-8.
        for d in 0..deps_len {
            let ref_off = base + E_OFF_DEPS + (d as usize) * STRING_REF_LEN;
            let dep = self.resolve_ref(ref_off).ok_or(EntryError::DepRefRange(d))?;
            if dep.is_empty() || dep.len() > MODULE_NAME_MAX || core::str::from_utf8(dep).is_err() {
                return Err(EntryError::DepName(d));
            }
        }

        // Grants: known kind, clean rights bits, kind-consistent target,
        // zero pad.
        for g in 0..grants_len {
            let g_off = base + E_OFF_GRANTS + (g as usize) * GRANT_LEN;
            let kind = b[g_off + G_OFF_KIND];
            let rights = b[g_off + G_OFF_RIGHTS];
            let pad = read_u16(b, g_off + G_OFF_PAD);
            let target = read_u32(b, g_off + G_OFF_TARGET);
            if pad != 0 {
                return Err(EntryError::GrantPad(g));
            }
            match kind {
                GRANT_KIND_ENDPOINT => {
                    if Rights::from_bits(rights).is_none() {
                        return Err(EntryError::GrantRights(g));
                    }
                }
                GRANT_KIND_ALL_ENDPOINTS => {
                    if Rights::from_bits(rights).is_none() {
                        return Err(EntryError::GrantRights(g));
                    }
                    if target != 0 {
                        return Err(EntryError::GrantTarget(g));
                    }
                }
                GRANT_KIND_SYSTEM => {
                    if rights != 0 {
                        return Err(EntryError::GrantRights(g));
                    }
                    if target > system_caps::MAX {
                        return Err(EntryError::GrantTarget(g));
                    }
                }
                _ => return Err(EntryError::GrantKind(g)),
            }
        }

        // Lifetime: known tag; OneShot must carry zeroed fields; the
        // pad byte must be zero for both tags.
        let l = base + E_OFF_LIFETIME;
        if b[l + L_OFF_PAD] != 0 {
            return Err(EntryError::LifetimeFields);
        }
        match b[l + L_OFF_TAG] {
            LIFETIME_TAG_ONESHOT => {
                let all_zero = read_u16(b, l + L_OFF_MAX_RESTARTS) == 0
                    && read_u32(b, l + L_OFF_INITIAL_DELAY) == 0
                    && read_u32(b, l + L_OFF_MAX_DELAY) == 0
                    && read_u32(b, l + L_OFF_FAILURE_WINDOW) == 0;
                if !all_zero {
                    return Err(EntryError::LifetimeFields);
                }
            }
            LIFETIME_TAG_PERSISTENT => {}
            other => return Err(EntryError::LifetimeTag(other)),
        }
        Ok(())
    }

    pub fn entry_count(&self) -> usize {
        self.entry_count as usize
    }

    /// AID the kernel binds to PID 1 (init).
    pub fn init_aid(&self) -> [u8; 32] {
        let mut aid = [0u8; 32];
        aid.copy_from_slice(&self.bytes[OFF_INIT_AID..OFF_INIT_AID + 32]);
        aid
    }

    /// Endpoint init listens on for readiness pings (never 0).
    pub fn init_endpoint(&self) -> u32 {
        self.init_endpoint
    }

    /// View of entry `i`; `None` past `entry_count`.
    pub fn entry(&self, i: usize) -> Option<EntryView<'a>> {
        if i >= self.entry_count as usize {
            return None;
        }
        Some(EntryView { m: *self, base: self.entry_base(i as u32) })
    }

    /// Linear name lookup (bounded by `MAX_MANIFEST_ENTRIES`).
    pub fn find_by_name(&self, name: &str) -> Option<(usize, EntryView<'a>)> {
        for i in 0..self.entry_count as usize {
            // Unwrap-free: i < entry_count by loop bound.
            if let Some(e) = self.entry(i) {
                if e.module_name() == name {
                    return Some((i, e));
                }
            }
        }
        None
    }
}

/// Infallible projection over one validated entry record.
#[derive(Clone, Copy)]
pub struct EntryView<'a> {
    m: Manifest<'a>,
    base: usize,
}

impl<'a> EntryView<'a> {
    /// The 32-byte AID (ADR-025) this service runs as.
    pub fn principal(&self) -> [u8; 32] {
        let mut aid = [0u8; 32];
        let off = self.base + E_OFF_PRINCIPAL;
        aid.copy_from_slice(&self.m.bytes[off..off + 32]);
        aid
    }

    /// Module name (validated UTF-8 at parse).
    pub fn module_name(&self) -> &'a str {
        // Validated at parse; the fallback arm is unreachable but kept
        // total so this crate stays panic-free on its public surface.
        let bytes = self.m.resolve_ref(self.base + E_OFF_NAME_REF).unwrap_or(&[]);
        core::str::from_utf8(bytes).unwrap_or("")
    }

    pub fn reserved_endpoints_len(&self) -> usize {
        self.m.bytes[self.base + E_OFF_ENDPOINTS_LEN] as usize
    }

    /// Reserved endpoint `j`; `None` past the declared length.
    pub fn reserved_endpoint(&self, j: usize) -> Option<u32> {
        if j >= self.reserved_endpoints_len() {
            return None;
        }
        Some(read_u32(self.m.bytes, self.base + E_OFF_ENDPOINTS + j * 4))
    }

    /// Iterator over the declared reserved endpoints.
    pub fn reserved_endpoints(&self) -> impl Iterator<Item = u32> + 'a {
        let v = *self;
        (0..v.reserved_endpoints_len()).filter_map(move |j| v.reserved_endpoint(j))
    }

    pub fn grants_len(&self) -> usize {
        self.m.bytes[self.base + E_OFF_GRANTS_LEN] as usize
    }

    /// Grant `j`; `None` past the declared length. Total for validated
    /// records: every decode arm was proven at parse.
    pub fn grant(&self, j: usize) -> Option<CapabilityGrant> {
        if j >= self.grants_len() {
            return None;
        }
        let b = self.m.bytes;
        let off = self.base + E_OFF_GRANTS + j * GRANT_LEN;
        let rights = Rights::from_bits(b[off + G_OFF_RIGHTS])?;
        let target = read_u32(b, off + G_OFF_TARGET);
        match b[off + G_OFF_KIND] {
            GRANT_KIND_ENDPOINT => Some(CapabilityGrant::Endpoint { endpoint: target, rights }),
            GRANT_KIND_ALL_ENDPOINTS => Some(CapabilityGrant::AllEndpoints { rights }),
            GRANT_KIND_SYSTEM => Some(CapabilityGrant::System { kind: target }),
            _ => None,
        }
    }

    /// Iterator over the declared grants.
    pub fn grants(&self) -> impl Iterator<Item = CapabilityGrant> + 'a {
        let v = *self;
        (0..v.grants_len()).filter_map(move |j| v.grant(j))
    }

    pub fn lifetime(&self) -> ServiceLifetime {
        let b = self.m.bytes;
        let l = self.base + E_OFF_LIFETIME;
        match b[l + L_OFF_TAG] {
            LIFETIME_TAG_PERSISTENT => ServiceLifetime::Persistent {
                max_restarts: read_u16(b, l + L_OFF_MAX_RESTARTS),
                initial_delay_ms: read_u32(b, l + L_OFF_INITIAL_DELAY),
                max_delay_ms: read_u32(b, l + L_OFF_MAX_DELAY),
                failure_window_ms: read_u32(b, l + L_OFF_FAILURE_WINDOW),
            },
            // Tag validated at parse; anything else decodes as OneShot
            // to keep the projection total.
            _ => ServiceLifetime::OneShot,
        }
    }

    pub fn depends_on_len(&self) -> usize {
        self.m.bytes[self.base + E_OFF_DEPS_LEN] as usize
    }

    /// Dependency name `j`; `None` past the declared length.
    pub fn depends_on(&self, j: usize) -> Option<&'a str> {
        if j >= self.depends_on_len() {
            return None;
        }
        let bytes = self.m.resolve_ref(self.base + E_OFF_DEPS + j * STRING_REF_LEN)?;
        core::str::from_utf8(bytes).ok()
    }
}

// ============================================================================
// Cross-record validation (shared by build-manifest, kernel, init)
// ============================================================================

/// Reject duplicate module names and duplicate endpoint reservations
/// (including collisions with the header's `init_endpoint`). Bounded
/// O(n²) over ≤ `MAX_MANIFEST_ENTRIES` entries / their endpoint lists;
/// runs once per boot on the kernel side.
pub fn validate_unique(m: &Manifest<'_>) -> Result<(), ValidateError> {
    let n = m.entry_count();
    for i in 0..n {
        let ei = match m.entry(i) {
            Some(e) => e,
            None => continue,
        };
        for k in (i + 1)..n {
            if let Some(ek) = m.entry(k) {
                if ei.module_name() == ek.module_name() {
                    return Err(ValidateError::DuplicateName(i as u32, k as u32));
                }
            }
        }
    }
    // Endpoint uniqueness across every entry + init's own endpoint.
    for i in 0..n {
        let ei = match m.entry(i) {
            Some(e) => e,
            None => continue,
        };
        for j in 0..ei.reserved_endpoints_len() {
            let ep = match ei.reserved_endpoint(j) {
                Some(ep) => ep,
                None => continue,
            };
            if ep == m.init_endpoint() {
                return Err(ValidateError::DuplicateEndpoint(ep));
            }
            // Later occurrences within the same entry…
            for j2 in (j + 1)..ei.reserved_endpoints_len() {
                if ei.reserved_endpoint(j2) == Some(ep) {
                    return Err(ValidateError::DuplicateEndpoint(ep));
                }
            }
            // …and in every later entry.
            for k in (i + 1)..n {
                if let Some(ek) = m.entry(k) {
                    for j2 in 0..ek.reserved_endpoints_len() {
                        if ek.reserved_endpoint(j2) == Some(ep) {
                            return Err(ValidateError::DuplicateEndpoint(ep));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Payload extent declared by a manifest header: the end of the
/// strings region, which parse guarantees is the last region. For
/// consumers that receive the blob through a page-granular mapping
/// (init at `MANIFEST_USER_VADDR`) and must size their parse slice
/// before [`Manifest::parse`] can run — a Rust slice must never
/// extend past the mapped object, however little of it the parser
/// reads, so "parse with a max-size window" is not an option.
///
/// `header` needs only the first [`HEADER_LEN`] bytes (always mapped:
/// any blob shorter than its own header was rejected by the kernel's
/// boot-time verification). Validates magic, version, and the header
/// fields' internal consistency (mirroring `parse`'s region-ordering
/// checks, minus the blob-length checks that need the full slice) and
/// caps the result at [`MANIFEST_MAX_BYTES`] — a header declaring
/// more than the wire format allows is malformed, and the cap is what
/// lets the caller trust the extent enough to build a slice from it.
/// `None` on any inconsistency.
pub fn payload_extent(header: &[u8]) -> Option<usize> {
    if header.len() < HEADER_LEN {
        return None;
    }
    if header[0..8] != MAGIC {
        return None;
    }
    if read_u32(header, OFF_VERSION) != VERSION {
        return None;
    }
    let entry_count = read_u32(header, OFF_ENTRY_COUNT);
    if entry_count as usize > MAX_MANIFEST_ENTRIES {
        return None;
    }
    let entries_offset = read_u32(header, OFF_ENTRIES_OFFSET);
    let strings_offset = read_u32(header, OFF_STRINGS_OFFSET);
    let strings_len = read_u32(header, OFF_STRINGS_LEN);
    let entries_end = entries_offset as u64 + (entry_count as u64) * (ENTRY_LEN as u64);
    if (entries_offset as usize) < HEADER_LEN || (strings_offset as u64) < entries_end {
        return None;
    }
    let extent = strings_offset as u64 + strings_len as u64;
    if extent > MANIFEST_MAX_BYTES as u64 {
        return None;
    }
    Some(extent as usize)
}

/// Topologically sort the entries by `depends_on` (dependencies first).
/// Writes entry indices into `out` (which must hold at least
/// `m.entry_count()` slots) and returns the count. Iterative DFS with
/// fixed-size state — no recursion, no allocation. Also the cycle /
/// unknown-dependency validator: init calls this for its spawn order;
/// `build-manifest` calls it to reject bad manifests at build time.
pub fn topo_order(m: &Manifest<'_>, out: &mut [u16]) -> Result<usize, DagError> {
    let n = m.entry_count();
    debug_assert!(out.len() >= n);

    // 0 = unvisited, 1 = on the current DFS path, 2 = emitted.
    let mut state = [0u8; MAX_MANIFEST_ENTRIES];
    // Explicit DFS stack of (entry index, next dependency cursor).
    let mut stack = [(0u16, 0u8); MAX_MANIFEST_ENTRIES];
    let mut emitted = 0usize;

    for root in 0..n {
        if state[root] != 0 {
            continue;
        }
        let mut sp = 0usize;
        stack[sp] = (root as u16, 0);
        state[root] = 1;
        loop {
            let (idx, cursor) = stack[sp];
            let entry = match m.entry(idx as usize) {
                Some(e) => e,
                None => break, // unreachable: idx < n by construction
            };
            if (cursor as usize) < entry.depends_on_len() {
                stack[sp].1 += 1;
                let dep_name = match entry.depends_on(cursor as usize) {
                    Some(d) => d,
                    None => return Err(DagError::UnknownDep(idx as u32, cursor)),
                };
                let (dep_idx, _) = m
                    .find_by_name(dep_name)
                    .ok_or(DagError::UnknownDep(idx as u32, cursor))?;
                match state[dep_idx] {
                    0 => {
                        sp += 1;
                        // sp < n always: the path holds distinct entries.
                        stack[sp] = (dep_idx as u16, 0);
                        state[dep_idx] = 1;
                    }
                    1 => return Err(DagError::Cycle(dep_idx as u32)),
                    _ => {} // already emitted — fine
                }
            } else {
                state[idx as usize] = 2;
                out[emitted] = idx;
                emitted += 1;
                if sp == 0 {
                    break;
                }
                sp -= 1;
            }
        }
    }
    Ok(emitted)
}

// ============================================================================
// Emission (build-manifest + tests)
// ============================================================================

/// Source description of one entry for [`emit_manifest`].
#[derive(Clone, Copy)]
pub struct EntryDef<'a> {
    pub module_name: &'a str,
    pub principal: [u8; 32],
    pub reserved_endpoints: &'a [u32],
    pub grants: &'a [CapabilityGrant],
    pub lifetime: ServiceLifetime,
    pub depends_on: &'a [&'a str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    TooManyEntries,
    NameEmpty(usize),
    NameTooLong(usize),
    TooManyEndpoints(usize),
    TooManyGrants(usize),
    TooManyDeps(usize),
    /// Entry `.0`'s dependency `.1` names no entry in the set —
    /// dependency validity is checked at emit time for free, because
    /// dep StringRefs alias the referenced entry's name string.
    UnknownDep(usize, usize),
    /// A System grant carries an unknown [`system_caps`] id, or an
    /// AllEndpoints grant carries a nonzero target (unreachable via
    /// the typed enum; kept for wire-level completeness).
    BadGrant(usize, usize),
    InitEndpointZero,
    /// Output buffer shorter than [`emitted_size`].
    BufferTooSmall,
}

/// Exact blob size (without ARCSIG trailer) `emit_manifest` will
/// produce for `entries`.
pub fn emitted_size(entries: &[EntryDef<'_>]) -> Result<usize, EmitError> {
    if entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(EmitError::TooManyEntries);
    }
    let mut strings = 0usize;
    for (i, e) in entries.iter().enumerate() {
        if e.module_name.is_empty() {
            return Err(EmitError::NameEmpty(i));
        }
        if e.module_name.len() > MODULE_NAME_MAX {
            return Err(EmitError::NameTooLong(i));
        }
        strings += e.module_name.len();
    }
    Ok(HEADER_LEN + entries.len() * ENTRY_LEN + strings)
}

fn write_u32(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u16(out: &mut [u8], off: usize, v: u16) {
    out[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// Serialize a manifest blob (without ARCSIG trailer) into `out`.
/// Returns the number of bytes written. The strings region holds each
/// entry's module name exactly once, in entry order; `depends_on`
/// references alias the *referenced entry's* name string, so an
/// unknown dependency is an emit-time error rather than a latent blob
/// defect.
pub fn emit_manifest(
    init_aid: [u8; 32],
    init_endpoint: u32,
    entries: &[EntryDef<'_>],
    out: &mut [u8],
) -> Result<usize, EmitError> {
    let total = emitted_size(entries)?;
    if init_endpoint == 0 {
        return Err(EmitError::InitEndpointZero);
    }
    if out.len() < total {
        return Err(EmitError::BufferTooSmall);
    }

    let entries_offset = HEADER_LEN;
    let strings_offset = HEADER_LEN + entries.len() * ENTRY_LEN;

    // Zero the whole output region first: pad + reserved fields and
    // unused array slots are all defined-zero on the wire.
    out[..total].fill(0);

    // Strings region + per-entry name refs (relative to region start).
    let mut name_refs = [(0u32, 0u32); MAX_MANIFEST_ENTRIES];
    let mut cursor = 0usize;
    for (i, e) in entries.iter().enumerate() {
        let bytes = e.module_name.as_bytes();
        out[strings_offset + cursor..strings_offset + cursor + bytes.len()].copy_from_slice(bytes);
        name_refs[i] = (cursor as u32, bytes.len() as u32);
        cursor += bytes.len();
    }

    // Header.
    out[0..8].copy_from_slice(&MAGIC);
    write_u32(out, OFF_VERSION, VERSION);
    write_u32(out, OFF_ENTRY_COUNT, entries.len() as u32);
    write_u32(out, OFF_ENTRIES_OFFSET, entries_offset as u32);
    write_u32(out, OFF_STRINGS_OFFSET, strings_offset as u32);
    write_u32(out, OFF_STRINGS_LEN, cursor as u32);
    write_u32(out, OFF_INIT_ENDPOINT, init_endpoint);
    out[OFF_INIT_AID..OFF_INIT_AID + 32].copy_from_slice(&init_aid);

    // Entries.
    for (i, e) in entries.iter().enumerate() {
        let base = entries_offset + i * ENTRY_LEN;
        if e.reserved_endpoints.len() > RESERVED_ENDPOINTS_MAX {
            return Err(EmitError::TooManyEndpoints(i));
        }
        if e.grants.len() > GRANTS_MAX {
            return Err(EmitError::TooManyGrants(i));
        }
        if e.depends_on.len() > DEPS_MAX {
            return Err(EmitError::TooManyDeps(i));
        }

        out[base + E_OFF_PRINCIPAL..base + E_OFF_PRINCIPAL + 32].copy_from_slice(&e.principal);
        write_u32(out, base + E_OFF_NAME_REF, name_refs[i].0);
        write_u32(out, base + E_OFF_NAME_REF + 4, name_refs[i].1);

        for (j, &ep) in e.reserved_endpoints.iter().enumerate() {
            write_u32(out, base + E_OFF_ENDPOINTS + j * 4, ep);
        }
        out[base + E_OFF_ENDPOINTS_LEN] = e.reserved_endpoints.len() as u8;
        out[base + E_OFF_GRANTS_LEN] = e.grants.len() as u8;
        out[base + E_OFF_DEPS_LEN] = e.depends_on.len() as u8;

        let l = base + E_OFF_LIFETIME;
        match e.lifetime {
            ServiceLifetime::OneShot => out[l + L_OFF_TAG] = LIFETIME_TAG_ONESHOT,
            ServiceLifetime::Persistent {
                initial_delay_ms,
                max_delay_ms,
                max_restarts,
                failure_window_ms,
            } => {
                out[l + L_OFF_TAG] = LIFETIME_TAG_PERSISTENT;
                write_u16(out, l + L_OFF_MAX_RESTARTS, max_restarts);
                write_u32(out, l + L_OFF_INITIAL_DELAY, initial_delay_ms);
                write_u32(out, l + L_OFF_MAX_DELAY, max_delay_ms);
                write_u32(out, l + L_OFF_FAILURE_WINDOW, failure_window_ms);
            }
        }

        for (j, g) in e.grants.iter().enumerate() {
            let g_off = base + E_OFF_GRANTS + j * GRANT_LEN;
            match *g {
                CapabilityGrant::Endpoint { endpoint, rights } => {
                    out[g_off + G_OFF_KIND] = GRANT_KIND_ENDPOINT;
                    out[g_off + G_OFF_RIGHTS] = rights.to_bits();
                    write_u32(out, g_off + G_OFF_TARGET, endpoint);
                }
                CapabilityGrant::AllEndpoints { rights } => {
                    out[g_off + G_OFF_KIND] = GRANT_KIND_ALL_ENDPOINTS;
                    out[g_off + G_OFF_RIGHTS] = rights.to_bits();
                }
                CapabilityGrant::System { kind } => {
                    if kind > system_caps::MAX {
                        return Err(EmitError::BadGrant(i, j));
                    }
                    out[g_off + G_OFF_KIND] = GRANT_KIND_SYSTEM;
                    write_u32(out, g_off + G_OFF_TARGET, kind);
                }
            }
        }

        for (j, dep) in e.depends_on.iter().enumerate() {
            let target = entries
                .iter()
                .position(|t| t.module_name == *dep)
                .ok_or(EmitError::UnknownDep(i, j))?;
            let ref_off = base + E_OFF_DEPS + j * STRING_REF_LEN;
            write_u32(out, ref_off, name_refs[target].0);
            write_u32(out, ref_off + 4, name_refs[target].1);
        }
    }

    Ok(total)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn aid(tag: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = tag;
        a[31] = tag;
        a
    }

    /// A representative three-service manifest: fs depends on blk,
    /// shell depends on fs. Mirrors the narrow-receive/wildcard-send
    /// default grant posture.
    fn sample_defs() -> [EntryDef<'static>; 3] {
        const BLK_GRANTS: [CapabilityGrant; 3] = [
            CapabilityGrant::Endpoint { endpoint: 24, rights: Rights::RECEIVE },
            CapabilityGrant::Endpoint { endpoint: 26, rights: Rights::RECEIVE },
            CapabilityGrant::AllEndpoints { rights: Rights::SEND },
        ];
        const FS_GRANTS: [CapabilityGrant; 2] = [
            CapabilityGrant::Endpoint { endpoint: 16, rights: Rights::RECEIVE },
            CapabilityGrant::AllEndpoints { rights: Rights::SEND },
        ];
        const SHELL_GRANTS: [CapabilityGrant; 3] = [
            CapabilityGrant::Endpoint { endpoint: 18, rights: Rights::RECEIVE },
            CapabilityGrant::AllEndpoints { rights: Rights::SEND },
            CapabilityGrant::System { kind: system_caps::CREATE_PROCESS },
        ];
        [
            EntryDef {
                module_name: "virtio-blk",
                principal: aid(1),
                reserved_endpoints: &[24, 25, 26],
                grants: &BLK_GRANTS,
                lifetime: ServiceLifetime::Persistent {
                    initial_delay_ms: 100,
                    max_delay_ms: 5000,
                    max_restarts: 5,
                    failure_window_ms: 60_000,
                },
                depends_on: &[],
            },
            EntryDef {
                module_name: "fs-service",
                principal: aid(2),
                reserved_endpoints: &[16],
                grants: &FS_GRANTS,
                lifetime: ServiceLifetime::Persistent {
                    initial_delay_ms: 100,
                    max_delay_ms: 5000,
                    max_restarts: 5,
                    failure_window_ms: 60_000,
                },
                depends_on: &["virtio-blk"],
            },
            EntryDef {
                module_name: "shell",
                principal: aid(3),
                reserved_endpoints: &[18],
                grants: &SHELL_GRANTS,
                lifetime: ServiceLifetime::OneShot,
                depends_on: &["fs-service"],
            },
        ]
    }

    fn build_sample() -> Vec<u8> {
        let defs = sample_defs();
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        let n = emit_manifest(aid(0xEE), INIT_ENDPOINT, &defs, &mut buf).unwrap();
        assert_eq!(n, buf.len());
        buf
    }

    // ---------------- round-trip ----------------

    #[test]
    fn round_trip_header() {
        let blob = build_sample();
        let m = Manifest::parse(&blob).unwrap();
        assert_eq!(m.entry_count(), 3);
        assert_eq!(m.init_endpoint(), INIT_ENDPOINT);
        assert_eq!(m.init_aid(), aid(0xEE));
    }

    #[test]
    fn round_trip_entries() {
        let blob = build_sample();
        let m = Manifest::parse(&blob).unwrap();

        let blk = m.entry(0).unwrap();
        assert_eq!(blk.module_name(), "virtio-blk");
        assert_eq!(blk.principal(), aid(1));
        assert_eq!(blk.reserved_endpoints().collect::<Vec<_>>(), vec![24, 25, 26]);
        assert_eq!(blk.depends_on_len(), 0);
        assert_eq!(
            blk.lifetime(),
            ServiceLifetime::Persistent {
                initial_delay_ms: 100,
                max_delay_ms: 5000,
                max_restarts: 5,
                failure_window_ms: 60_000,
            }
        );
        assert_eq!(
            blk.grant(0),
            Some(CapabilityGrant::Endpoint { endpoint: 24, rights: Rights::RECEIVE })
        );
        assert_eq!(blk.grant(2), Some(CapabilityGrant::AllEndpoints { rights: Rights::SEND }));
        assert_eq!(blk.grant(3), None);

        let shell = m.entry(2).unwrap();
        assert_eq!(shell.lifetime(), ServiceLifetime::OneShot);
        assert_eq!(shell.depends_on(0), Some("fs-service"));
        assert_eq!(
            shell.grant(2),
            Some(CapabilityGrant::System { kind: system_caps::CREATE_PROCESS })
        );
        assert_eq!(m.entry(3).map(|e| e.module_name().to_owned()), None);
    }

    #[test]
    fn find_by_name_hits_and_misses() {
        let blob = build_sample();
        let m = Manifest::parse(&blob).unwrap();
        assert_eq!(m.find_by_name("fs-service").unwrap().0, 1);
        assert!(m.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn trailing_bytes_ignored() {
        let mut blob = build_sample();
        blob.extend_from_slice(&[0xAB; 72]); // fake ARCSIG-sized trailer
        let m = Manifest::parse(&blob).unwrap();
        assert_eq!(m.entry_count(), 3);
        assert_eq!(m.entry(1).unwrap().module_name(), "fs-service");
    }

    #[test]
    fn payload_extent_matches_emitted_size_from_header_alone() {
        let blob = build_sample();
        // Full blob and header-only slice agree — init reads only the
        // first HEADER_LEN mapped bytes before sizing its parse slice.
        assert_eq!(payload_extent(&blob), Some(blob.len()));
        assert_eq!(payload_extent(&blob[..HEADER_LEN]), Some(blob.len()));
        // The extent-sized slice parses.
        let extent = payload_extent(&blob[..HEADER_LEN]).unwrap();
        assert!(Manifest::parse(&blob[..extent]).is_ok());

        // Empty manifest: extent is exactly the header.
        let mut buf = vec![0u8; emitted_size(&[]).unwrap()];
        let n = emit_manifest(aid(9), 1, &[], &mut buf).unwrap();
        assert_eq!(payload_extent(&buf), Some(n));
    }

    #[test]
    fn payload_extent_rejects_malformed_headers() {
        let blob = build_sample();
        assert_eq!(payload_extent(&blob[..HEADER_LEN - 1]), None); // short
        let mut b = blob.clone();
        b[0] = b'X';
        assert_eq!(payload_extent(&b), None); // magic
        let mut b = blob.clone();
        b[OFF_VERSION] = 0xFF;
        assert_eq!(payload_extent(&b), None); // version
        let mut b = blob.clone();
        b[OFF_ENTRY_COUNT..OFF_ENTRY_COUNT + 4]
            .copy_from_slice(&(MAX_MANIFEST_ENTRIES as u32 + 1).to_le_bytes());
        assert_eq!(payload_extent(&b), None); // entry_count over max
        let mut b = blob.clone();
        b[OFF_STRINGS_OFFSET..OFF_STRINGS_OFFSET + 4].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(payload_extent(&b), None); // strings before entries end
        let mut b = blob.clone();
        b[OFF_STRINGS_LEN..OFF_STRINGS_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(payload_extent(&b), None); // extent past MANIFEST_MAX_BYTES
    }

    #[test]
    fn manifest_max_bytes_bounds_a_maximal_manifest() {
        // 128 entries, every name at MODULE_NAME_MAX, every entry
        // carrying DEPS_MAX dependency references — the worst case the
        // wire bounds permit must fit under MANIFEST_MAX_BYTES.
        let names: Vec<String> = (0..MAX_MANIFEST_ENTRIES)
            .map(|i| format!("{:0>width$}", i, width = MODULE_NAME_MAX))
            .collect();
        let mut defs: Vec<EntryDef> = Vec::new();
        let mut dep_lists: Vec<Vec<&str>> = Vec::new();
        for i in 0..MAX_MANIFEST_ENTRIES {
            let start = i.saturating_sub(DEPS_MAX);
            dep_lists.push(names[start..i].iter().map(|s| s.as_str()).collect());
        }
        for i in 0..MAX_MANIFEST_ENTRIES {
            defs.push(EntryDef {
                module_name: &names[i],
                principal: aid((i + 1) as u8),
                reserved_endpoints: &[],
                grants: &[],
                lifetime: ServiceLifetime::OneShot,
                depends_on: &dep_lists[i],
            });
        }
        let size = emitted_size(&defs).unwrap();
        assert!(
            size <= MANIFEST_MAX_BYTES,
            "maximal manifest {} exceeds MANIFEST_MAX_BYTES {}",
            size,
            MANIFEST_MAX_BYTES
        );
        let mut buf = vec![0u8; size];
        let n = emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        assert_eq!(payload_extent(&buf[..HEADER_LEN]), Some(n));
    }

    #[test]
    fn empty_manifest_round_trips() {
        let mut buf = vec![0u8; emitted_size(&[]).unwrap()];
        let n = emit_manifest(aid(9), 1, &[], &mut buf).unwrap();
        assert_eq!(n, HEADER_LEN);
        let m = Manifest::parse(&buf).unwrap();
        assert_eq!(m.entry_count(), 0);
        assert!(validate_unique(&m).is_ok());
        let mut order = [0u16; MAX_MANIFEST_ENTRIES];
        assert_eq!(topo_order(&m, &mut order).unwrap(), 0);
    }

    // ---------------- structural rejection ----------------

    #[test]
    fn rejects_short_and_bad_magic_and_version() {
        assert_eq!(Manifest::parse(&[0u8; 10]).unwrap_err(), ManifestError::TooShort);

        let mut blob = build_sample();
        blob[0] = b'X';
        assert_eq!(Manifest::parse(&blob).unwrap_err(), ManifestError::BadMagic);

        let mut blob = build_sample();
        blob[OFF_VERSION] = 2;
        assert_eq!(Manifest::parse(&blob).unwrap_err(), ManifestError::BadVersion(2));
    }

    #[test]
    fn rejects_entry_count_overflow() {
        let mut blob = build_sample();
        write_u32(&mut blob, OFF_ENTRY_COUNT, (MAX_MANIFEST_ENTRIES + 1) as u32);
        assert_eq!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::TooManyEntries((MAX_MANIFEST_ENTRIES + 1) as u32)
        );
    }

    #[test]
    fn rejects_entries_region_out_of_range() {
        let mut blob = build_sample();
        // Claim one more entry than the blob holds: region overruns.
        write_u32(&mut blob, OFF_ENTRY_COUNT, 4);
        assert_eq!(Manifest::parse(&blob).unwrap_err(), ManifestError::EntriesRange);

        let mut blob = build_sample();
        write_u32(&mut blob, OFF_ENTRIES_OFFSET, 8); // inside header
        assert_eq!(Manifest::parse(&blob).unwrap_err(), ManifestError::EntriesRange);
    }

    #[test]
    fn rejects_strings_region_out_of_range() {
        let mut blob = build_sample();
        let strings_offset = read_u32(&blob, OFF_STRINGS_OFFSET);
        write_u32(&mut blob, OFF_STRINGS_LEN, 1 << 24); // overruns blob
        assert_eq!(Manifest::parse(&blob).unwrap_err(), ManifestError::StringsRange);

        let mut blob = build_sample();
        // Strings overlapping the entries region is rejected.
        write_u32(&mut blob, OFF_STRINGS_OFFSET, strings_offset - 1);
        assert_eq!(Manifest::parse(&blob).unwrap_err(), ManifestError::StringsRange);
    }

    #[test]
    fn rejects_init_endpoint_zero() {
        let defs = sample_defs();
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        assert_eq!(
            emit_manifest(aid(0), 0, &defs, &mut buf).unwrap_err(),
            EmitError::InitEndpointZero
        );
        // And on the parse side, via a hand-corrupted header.
        let mut blob = build_sample();
        write_u32(&mut blob, OFF_INIT_ENDPOINT, 0);
        assert_eq!(Manifest::parse(&blob).unwrap_err(), ManifestError::InitEndpointZero);
    }

    fn entry_base(i: usize) -> usize {
        HEADER_LEN + i * ENTRY_LEN
    }

    #[test]
    fn rejects_bad_length_bytes() {
        let mut blob = build_sample();
        blob[entry_base(0) + E_OFF_ENDPOINTS_LEN] = (RESERVED_ENDPOINTS_MAX + 1) as u8;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::EndpointsLen(_))
        ));

        let mut blob = build_sample();
        blob[entry_base(1) + E_OFF_GRANTS_LEN] = (GRANTS_MAX + 1) as u8;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(1, EntryError::GrantsLen(_))
        ));

        let mut blob = build_sample();
        blob[entry_base(2) + E_OFF_DEPS_LEN] = (DEPS_MAX + 1) as u8;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(2, EntryError::DepsLen(_))
        ));
    }

    #[test]
    fn rejects_bad_string_refs() {
        let mut blob = build_sample();
        // Point entry 0's name past the strings region.
        write_u32(&mut blob, entry_base(0) + E_OFF_NAME_REF, 1 << 20);
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::NameRefRange)
        ));

        let mut blob = build_sample();
        // Zero-length name.
        write_u32(&mut blob, entry_base(0) + E_OFF_NAME_REF + 4, 0);
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::NameEmpty)
        ));

        let mut blob = build_sample();
        // Dep ref of entry 1 out of range.
        write_u32(&mut blob, entry_base(1) + E_OFF_DEPS, 1 << 20);
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(1, EntryError::DepRefRange(0))
        ));
    }

    #[test]
    fn rejects_bad_utf8_name() {
        let mut blob = build_sample();
        let strings_offset = read_u32(&blob, OFF_STRINGS_OFFSET) as usize;
        blob[strings_offset] = 0xFF; // corrupt first byte of "virtio-blk"
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::NameUtf8)
        ));
    }

    #[test]
    fn rejects_bad_grants() {
        let mut blob = build_sample();
        blob[entry_base(0) + E_OFF_GRANTS + G_OFF_KIND] = 7;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::GrantKind(0))
        ));

        let mut blob = build_sample();
        blob[entry_base(0) + E_OFF_GRANTS + G_OFF_RIGHTS] = 0xF0;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::GrantRights(0))
        ));

        let mut blob = build_sample();
        // System grant with unknown id: shell's grant index 2.
        write_u32(
            &mut blob,
            entry_base(2) + E_OFF_GRANTS + 2 * GRANT_LEN + G_OFF_TARGET,
            system_caps::MAX + 1,
        );
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(2, EntryError::GrantTarget(2))
        ));

        let mut blob = build_sample();
        blob[entry_base(0) + E_OFF_GRANTS + G_OFF_PAD] = 1;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::GrantPad(0))
        ));
    }

    #[test]
    fn rejects_bad_lifetime() {
        let mut blob = build_sample();
        blob[entry_base(0) + E_OFF_LIFETIME + L_OFF_TAG] = 9;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::LifetimeTag(9))
        ));

        let mut blob = build_sample();
        // Shell is OneShot; nonzero restart fields must be rejected.
        write_u32(&mut blob, entry_base(2) + E_OFF_LIFETIME + L_OFF_INITIAL_DELAY, 7);
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(2, EntryError::LifetimeFields)
        ));
    }

    #[test]
    fn rejects_nonzero_pad_and_reserved() {
        let mut blob = build_sample();
        blob[entry_base(0) + E_OFF_PAD] = 1;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(0, EntryError::PadNonZero)
        ));

        let mut blob = build_sample();
        blob[entry_base(1) + E_OFF_RESERVED + 5] = 1;
        assert!(matches!(
            Manifest::parse(&blob).unwrap_err(),
            ManifestError::Entry(1, EntryError::PadNonZero)
        ));
    }

    // ---------------- cross-record validation ----------------

    #[test]
    fn validate_unique_accepts_sample() {
        let blob = build_sample();
        let m = Manifest::parse(&blob).unwrap();
        assert!(validate_unique(&m).is_ok());
    }

    #[test]
    fn validate_unique_rejects_duplicate_endpoint() {
        let mut defs = sample_defs();
        defs[1].reserved_endpoints = &[24]; // collides with virtio-blk
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        let m = Manifest::parse(&buf).unwrap();
        assert_eq!(validate_unique(&m).unwrap_err(), ValidateError::DuplicateEndpoint(24));
    }

    #[test]
    fn validate_unique_rejects_init_endpoint_collision() {
        let mut defs = sample_defs();
        defs[2].reserved_endpoints = &[INIT_ENDPOINT];
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), INIT_ENDPOINT, &defs, &mut buf).unwrap();
        let m = Manifest::parse(&buf).unwrap();
        assert_eq!(
            validate_unique(&m).unwrap_err(),
            ValidateError::DuplicateEndpoint(INIT_ENDPOINT)
        );
    }

    #[test]
    fn validate_unique_rejects_duplicate_name() {
        let mut defs = sample_defs();
        defs[2].module_name = "fs-service";
        defs[2].depends_on = &[]; // avoid self-dep noise
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        let m = Manifest::parse(&buf).unwrap();
        assert_eq!(validate_unique(&m).unwrap_err(), ValidateError::DuplicateName(1, 2));
    }

    // ---------------- DAG ----------------

    #[test]
    fn topo_order_dependencies_first() {
        let blob = build_sample();
        let m = Manifest::parse(&blob).unwrap();
        let mut order = [0u16; MAX_MANIFEST_ENTRIES];
        let n = topo_order(&m, &mut order).unwrap();
        assert_eq!(n, 3);
        let pos = |idx: u16| order[..n].iter().position(|&x| x == idx).unwrap();
        // blk (0) before fs (1) before shell (2).
        assert!(pos(0) < pos(1));
        assert!(pos(1) < pos(2));
    }

    #[test]
    fn topo_order_detects_cycle() {
        // fs -> blk and blk -> fs.
        let mut defs = sample_defs();
        defs[0].depends_on = &["fs-service"];
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        let m = Manifest::parse(&buf).unwrap();
        let mut order = [0u16; MAX_MANIFEST_ENTRIES];
        assert!(matches!(topo_order(&m, &mut order).unwrap_err(), DagError::Cycle(_)));
    }

    #[test]
    fn topo_order_detects_self_cycle() {
        let mut defs = sample_defs();
        defs[0].depends_on = &["virtio-blk"];
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        emit_manifest(aid(0xEE), 1, &defs, &mut buf).unwrap();
        let m = Manifest::parse(&buf).unwrap();
        let mut order = [0u16; MAX_MANIFEST_ENTRIES];
        assert_eq!(topo_order(&m, &mut order).unwrap_err(), DagError::Cycle(0));
    }

    #[test]
    fn topo_order_unknown_dep_via_corruption() {
        // emit_manifest rejects unknown deps, so corrupt a valid blob:
        // repoint shell's dep ref at the strings bytes of "shell"
        // itself is still a *known* name; instead shrink the dep name
        // by one byte so it no longer matches any entry.
        let mut blob = build_sample();
        // shell's dep 0 ref: shorten "fs-service" -> "fs-servic".
        let ref_off = entry_base(2) + E_OFF_DEPS + 4;
        let cur_len = read_u32(&blob, ref_off);
        write_u32(&mut blob, ref_off, cur_len - 1);
        let m = Manifest::parse(&blob).unwrap();
        let mut order = [0u16; MAX_MANIFEST_ENTRIES];
        assert_eq!(topo_order(&m, &mut order).unwrap_err(), DagError::UnknownDep(2, 0));
    }

    // ---------------- emit-side rejection ----------------

    #[test]
    fn emit_rejects_unknown_dep() {
        let mut defs = sample_defs();
        defs[2].depends_on = &["no-such-module"];
        let mut buf = vec![0u8; emitted_size(&defs).unwrap()];
        assert_eq!(
            emit_manifest(aid(0), 1, &defs, &mut buf).unwrap_err(),
            EmitError::UnknownDep(2, 0)
        );
    }

    #[test]
    fn emit_rejects_small_buffer_and_long_name() {
        let defs = sample_defs();
        let mut buf = vec![0u8; emitted_size(&defs).unwrap() - 1];
        assert_eq!(
            emit_manifest(aid(0), 1, &defs, &mut buf).unwrap_err(),
            EmitError::BufferTooSmall
        );

        let long = core::str::from_utf8(&[b'a'; MODULE_NAME_MAX + 1]).unwrap().to_owned();
        let defs2 = [EntryDef {
            module_name: &long,
            principal: aid(1),
            reserved_endpoints: &[],
            grants: &[],
            lifetime: ServiceLifetime::OneShot,
            depends_on: &[],
        }];
        assert_eq!(emitted_size(&defs2).unwrap_err(), EmitError::NameTooLong(0));
    }

    // ---------------- layout invariants ----------------

    #[test]
    fn layout_constants_are_consistent() {
        // Entry sub-regions tile the record exactly.
        assert_eq!(E_OFF_ENDPOINTS + RESERVED_ENDPOINTS_MAX * 4, E_OFF_ENDPOINTS_LEN);
        assert_eq!(E_OFF_LIFETIME + 16, E_OFF_GRANTS);
        assert_eq!(E_OFF_GRANTS + GRANTS_MAX * GRANT_LEN, E_OFF_DEPS);
        assert_eq!(E_OFF_DEPS + DEPS_MAX * STRING_REF_LEN, E_OFF_RESERVED);
        assert_eq!(E_OFF_RESERVED + 20, ENTRY_LEN);
        // Header init AID is the trailing field.
        assert_eq!(OFF_INIT_AID + 32, HEADER_LEN);
    }

    #[test]
    fn rights_bits_round_trip() {
        for bits in 0u8..=0x0F {
            let r = Rights::from_bits(bits).unwrap();
            assert_eq!(r.to_bits(), bits);
        }
        assert!(Rights::from_bits(0x10).is_none());
        assert!(Rights::from_bits(0xFF).is_none());
    }
}
