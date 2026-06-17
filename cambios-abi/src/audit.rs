// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! Audit event taxonomy — the canonical, wire-stable vocabulary of
//! kernel audit events (ADR-007).
//!
//! This module is the single source of truth for the audit event
//! taxonomy. Both the kernel (producer of `RawAuditEvent`) and the
//! audit consumer (`user/audit-tail`) depend on it, so there is exactly
//! one definition of:
//!
//! - the `AuditEventKind` discriminants (byte 0 of the wire record),
//! - the canonical `domain.action` name of each event,
//! - the coarse [`AuditClass`] each event belongs to (encoded in the
//!   flags byte so a consumer can filter without a decode table),
//! - the per-event argument schema (documentation),
//! - the flags-byte layout (sampled bit + class bits).
//!
//! The human-readable taxonomy doc at `docs/generated/audit-taxonomy.md`
//! is *generated* from [`TAXONOMY`] — it is never hand-maintained, so it
//! cannot drift from this definition. ADR-007 carries the *categories
//! and rationale* (the durable decision); the *list of variants* lives
//! here and in the generated doc. Durable artifacts carry decisions;
//! generated artifacts carry enumerations.
//!
//! # Wire stability
//!
//! Discriminants are permanent. Once a value is assigned it is never
//! reused — old stored audit logs and replay harnesses reference it.
//! A removed event's number is retired, not recycled (same discipline
//! as [`crate::SyscallNumber`]). New events take the next free value.
//! [`AUDIT_TAXONOMY_VERSION`] bumps on every add or rename so a consumer
//! reading a stored log (or attached across an upgrade) can select the
//! matching name table; it is surfaced to userspace via `SYS_AUDIT_INFO`.
//!
//! # The macro
//!
//! [`audit_taxonomy!`] takes the table once and emits the enum, the
//! `name()` / `class()` / `args_doc()` / `from_u8()` methods, and the
//! [`TAXONOMY`] slice. The match arms and the slice are generated from
//! the same input, so they are guaranteed consistent — a property the
//! test suite re-checks. This is what makes a second representation
//! (and therefore drift) impossible.

/// Coarse event class — the security-relevant bucket an event belongs
/// to. Encoded in [`bits 1..=3`](AUDIT_CLASS_MASK) of the flags byte so
/// a consumer can answer "security events only" with a masked compare,
/// no decode table required.
///
/// The class is a property of the *event kind*, fixed at the definition
/// site (see [`AuditEventKind::class`]); it is never chosen at the
/// emit call site. This is what makes the 2026-05-10 backpressure
/// mislabel (operational drop emitted as a `cap.denied`) structurally
/// hard to reproduce: a `Meta` event cannot be confused with a
/// `Security` event because neither the name nor the class is picked
/// per-call.
///
/// Finer-grained than class is the `domain` — the prefix of the
/// `domain.action` name (`cap`, `ipc`, `chan`, ...). Domain is the
/// human label; class is the on-wire filter.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditClass {
    /// Authorization / integrity decisions: capability grant/revoke/deny,
    /// policy + syscall denial, signed-binary verify. The bucket the AI
    /// watcher and policy service care about first.
    Security = 0,
    /// High-volume message flow (`ipc.*`). Sampled, not every occurrence.
    Dataflow = 1,
    /// Resource create/destroy: process, channel, cluster lifecycle.
    Lifecycle = 2,
    /// Threat-model context that is *not* itself a security decision
    /// input (e.g. window-focus transitions). Observable trail, not
    /// an authorization signal.
    Context = 3,
    /// AI watcher anomaly flags.
    Anomaly = 4,
    /// Audit-internal: dropped-event reports and kernel-invariant
    /// witnesses. Operational, never an authorization signal.
    Meta = 5,
}

impl AuditClass {
    /// Lowercase canonical name, used by the generated doc and the
    /// consumer's renderer.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Dataflow => "dataflow",
            Self::Lifecycle => "lifecycle",
            Self::Context => "context",
            Self::Anomaly => "anomaly",
            Self::Meta => "meta",
        }
    }

    /// Decode a class from its raw discriminant. `None` for an unknown
    /// value (forward-compatible: a consumer reading a newer log treats
    /// an unknown class as opaque rather than misclassifying it).
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Security),
            1 => Some(Self::Dataflow),
            2 => Some(Self::Lifecycle),
            3 => Some(Self::Context),
            4 => Some(Self::Anomaly),
            5 => Some(Self::Meta),
            _ => None,
        }
    }

    /// Extract the class from a raw flags byte (bits 1..=3). `None` if
    /// those bits hold a value with no assigned class.
    pub const fn from_flags(flags: u8) -> Option<Self> {
        Self::from_u8((flags & AUDIT_CLASS_MASK) >> AUDIT_CLASS_SHIFT)
    }
}

/// Flag: this event was generated via sampling (not every occurrence).
/// Bit 0 of the flags byte.
///
/// ARCHITECTURAL: wire-format bit. Changing it is an ABI break, not a
/// value bump.
pub const FLAG_SAMPLED: u8 = 0x01;

/// ARCHITECTURAL: bit offset of the [`AuditClass`] field within the
/// flags byte. The class occupies bits 1..=3 (3 bits, 6 classes today,
/// headroom to 8). Wire-format constant.
pub const AUDIT_CLASS_SHIFT: u8 = 1;

/// ARCHITECTURAL: mask selecting the [`AuditClass`] bits (1..=3) of the
/// flags byte. Bits 4..=7 remain reserved. Wire-format constant.
pub const AUDIT_CLASS_MASK: u8 = 0b0000_1110;

/// Build the flags byte from the sampled bit and an event class.
///
/// The kernel's event builders call this so every event carries its
/// class without the call site choosing it: the class comes from
/// [`AuditEventKind::class`].
#[inline]
pub const fn flags_with_class(sampled: bool, class: AuditClass) -> u8 {
    let s = if sampled { FLAG_SAMPLED } else { 0 };
    s | ((class as u8) << AUDIT_CLASS_SHIFT)
}

/// One row of the audit taxonomy. The generated doc and the consumer's
/// renderer iterate [`TAXONOMY`]; nothing hand-maintains a second copy.
#[derive(Debug, Clone, Copy)]
pub struct AuditTaxonomyEntry {
    /// Wire discriminant (byte 0 of `RawAuditEvent`).
    pub discriminant: u8,
    /// Canonical `domain.action` name (e.g. `cap.granted`).
    pub name: &'static str,
    /// Coarse class (also encoded in the flags byte at emit time).
    pub class: AuditClass,
    /// Human-readable argument schema for the event-specific slots.
    pub args_doc: &'static str,
}

/// Define the audit taxonomy once; emit the enum, the lookup methods,
/// and the [`TAXONOMY`] slice from a single table.
///
/// Each row is `Variant = discriminant => "domain.action", Class, "args";`
/// with optional doc comments that ride onto the enum variant.
macro_rules! audit_taxonomy {
    (
        $(
            $(#[$meta:meta])*
            $variant:ident = $disc:literal => $name:literal, $class:ident, $args:literal ;
        )+
    ) => {
        /// Audit event kind discriminant — byte 0 of the `RawAuditEvent`
        /// wire format. See the [module docs](self) for the taxonomy
        /// contract; values are permanent and never reused.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum AuditEventKind {
            $( $(#[$meta])* $variant = $disc, )+
        }

        impl AuditEventKind {
            /// Canonical `domain.action` name.
            pub const fn name(self) -> &'static str {
                match self { $( Self::$variant => $name, )+ }
            }

            /// Coarse [`AuditClass`] this event belongs to. Fixed at the
            /// definition site — the emit path reads it, never overrides it.
            pub const fn class(self) -> AuditClass {
                match self { $( Self::$variant => AuditClass::$class, )+ }
            }

            /// Human-readable argument schema for the event-specific slots.
            pub const fn args_doc(self) -> &'static str {
                match self { $( Self::$variant => $args, )+ }
            }

            /// Decode a kind from its wire discriminant. `None` for an
            /// unassigned or retired value — a consumer reading a newer
            /// log treats unknown kinds as opaque rather than guessing.
            pub const fn from_u8(v: u8) -> Option<Self> {
                match v {
                    $( $disc => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }

        /// The complete audit taxonomy, in discriminant order. The
        /// generated doc and the consumer's renderer are the only
        /// consumers; nothing maintains a parallel copy.
        pub const TAXONOMY: &[AuditTaxonomyEntry] = &[
            $( AuditTaxonomyEntry {
                discriminant: $disc,
                name: $name,
                class: AuditClass::$class,
                args_doc: $args,
            }, )+
        ];
    };
}

audit_taxonomy! {
    /// After a successful `RegisterEndpoint` or capability delegation.
    CapabilityGranted = 0 => "cap.granted", Security,
        "subject=grantor object=endpoint arg0=grantee arg1=rights";

    /// After a successful `revoke()` or `revoke_all_for_process()`.
    CapabilityRevoked = 1 => "cap.revoked", Security,
        "subject=revoker object=endpoint arg0=holder";

    /// When a capability check returns `PermissionDenied` (cap-table layer).
    CapabilityDenied = 2 => "cap.denied", Security,
        "subject=caller object=endpoint";

    /// After successful IPC send (sampled, not every send).
    IpcSend = 3 => "ipc.send", Dataflow,
        "subject=sender object=endpoint arg0=payload_len";

    /// After successful IPC recv (sampled).
    IpcRecv = 4 => "ipc.recv", Dataflow,
        "subject=receiver object=endpoint arg0=payload_len";

    /// After `SYS_CHANNEL_CREATE` succeeds.
    ChannelCreated = 5 => "chan.created", Lifecycle,
        "subject=creator object=channel arg0=size_pages";

    /// After `SYS_CHANNEL_ATTACH` succeeds.
    ChannelAttached = 6 => "chan.attached", Lifecycle,
        "subject=attacher object=channel";

    /// After channel close (any path).
    ChannelClosed = 7 => "chan.closed", Lifecycle,
        "subject=closer object=channel arg0=bytes_transferred arg1=lifetime_ticks";

    /// When the interceptor / policy service denies a syscall (policy layer).
    SyscallDenied = 8 => "enforce.syscall_denied", Security,
        "subject=caller arg0=syscall_number";

    /// After `BinaryVerifier::verify()` succeeds.
    BinaryLoaded = 9 => "loader.binary_loaded", Security,
        "subject=0(kernel) arg0=binary_size arg1..arg3=content_hash[0..24]";

    /// After `BinaryVerifier::verify()` fails.
    BinaryRejected = 10 => "loader.binary_rejected", Security,
        "subject=0(kernel) arg0=rejection_reason";

    /// After process creation.
    ProcessCreated = 11 => "proc.created", Lifecycle,
        "subject=pid object=parent_pid";

    /// After process exit.
    ProcessTerminated = 12 => "proc.terminated", Lifecycle,
        "subject=pid arg0=exit_code arg1=runtime_ticks";

    /// When the policy service is consulted (sampled). A *consultation
    /// record*, not a denial — the decision is in `arg1`. The two true
    /// denials are `cap.denied` and `enforce.syscall_denied`.
    PolicyQuery = 13 => "enforce.policy_query", Security,
        "subject=queried_pid arg0=syscall_number arg1=allowed(0|1)";

    /// Reserved for future AI watcher anomaly flagging.
    AnomalyHook = 14 => "ai.anomaly_hook", Anomaly,
        "reserved for AI watcher anomaly flagging";

    /// Synthetic: reports accumulated drops from a staging buffer.
    AuditDropped = 15 => "meta.audit_dropped", Meta,
        "subject=0(kernel) arg0=dropped_count arg1=cpu_id";

    /// Compositor reports a window-focus transition (T-7 Phase A,
    /// docs/threat-model.md). Emitted via `SYS_AUDIT_EMIT_INPUT_FOCUS`
    /// whenever the focused window changes — including initial focus and
    /// focus loss when the last live window exits.
    ///
    /// The 24-byte owner-principal prefix in `arg1..arg3` is **not a
    /// security-decision input**: it is grindable at ~2^96 work, far
    /// below the full-AID collision floor. Any authorization decision
    /// keyed on "the focused window belongs to Principal X" must resolve
    /// the full 32-byte Principal via the process table
    /// (`SYS_GET_PROCESS_PRINCIPAL`), never reconstruct it from this prefix.
    InputFocusChange = 16 => "ui.input_focus_change", Context,
        "subject=compositor object=new_window_id arg0=old_window_id arg1..arg3=new_owner_principal[0..24]";

    /// After `SYS_CLUSTER_CREATE` succeeds (ADR-027). Emitted once the
    /// cluster record is in `Forming` state.
    ClusterCreated = 17 => "cluster.created", Lifecycle,
        "subject=creator object=cluster_id arg0=policy arg1=member_count";

    /// After cluster revoke completes (ADR-027 Decision 3). Emitted from
    /// both the explicit `SYS_CLUSTER_REVOKE` path and the exit-path
    /// auto-revoke; `arg2` carries a `CLUSTER_REVOKE_REASON_*`
    /// discriminant distinguishing the two.
    ClusterRevoked = 18 => "cluster.revoked", Lifecycle,
        "subject=initiator object=cluster_id arg0=member_count arg1=channel_count arg2=reason";

    /// After `SYS_CHANNEL_BEGIN_TEARDOWN` succeeds on an `Active` channel
    /// (ADR-027 Phase 1 quiesce protocol). Marks the start of the
    /// two-phase teardown window. Not emitted on the `AwaitingAttach`
    /// short-circuit path (that single-step close reports as `chan.closed`).
    ChannelTeardownStarted = 19 => "chan.teardown.started", Lifecycle,
        "subject=initiator object=channel arg0=teardown_kind(0=Close,1=Revoke)";

    /// After `SYS_CHANNEL_COMPLETE_TEARDOWN` succeeds. Slot freed, both
    /// sides unmapped, any quiesced peer woken. Pairs with the matching
    /// `chan.teardown.started`.
    ChannelTeardownCompleted = 20 => "chan.teardown.completed", Lifecycle,
        "subject=completer object=channel arg0=teardown_kind(0=Close,1=Revoke) arg1=num_pages";

    /// Defense-in-depth witness (ADR-034 §3): `reclaim_process_page_tables`
    /// was asked to free a page-table root that is still this CPU's active
    /// CR3/satp/TTBR0. Never fires in correct operation — emitting it
    /// means a regression reintroduced the active-root self-free. The
    /// reclaim refuses (frees nothing); a `debug_assert!` additionally
    /// fast-fails dev builds.
    ReapWouldFreeActiveRoot = 21 => "meta.reap_would_free_active_root", Meta,
        "subject=0(kernel) arg0=active_root_phys";
}

/// Number of assigned audit event kinds. Derived from [`TAXONOMY`] —
/// not a hand-maintained count.
pub const AUDIT_EVENT_KIND_COUNT: usize = TAXONOMY.len();

/// Monotonic taxonomy version. Bump on every event add or `domain.action`
/// rename so a consumer reading a stored log — or attached across a
/// kernel upgrade — selects the matching name table. Surfaced to
/// userspace via `SYS_AUDIT_INFO`.
///
/// Not a bound: this is a wire-protocol version counter, expected to
/// grow monotonically as the taxonomy evolves. The append-only
/// discriminant rule (see module docs) is the structural guarantee;
/// this version is the advisory hint.
pub const AUDIT_TAXONOMY_VERSION: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    /// Discriminants are wire format: pin the endpoints and the count so
    /// a reorder or accidental renumber fails CI.
    #[test]
    fn discriminants_pinned() {
        assert_eq!(AuditEventKind::CapabilityGranted as u8, 0);
        assert_eq!(AuditEventKind::AuditDropped as u8, 15);
        assert_eq!(AuditEventKind::InputFocusChange as u8, 16);
        assert_eq!(AuditEventKind::ReapWouldFreeActiveRoot as u8, 21);
        assert_eq!(AUDIT_EVENT_KIND_COUNT, 22);
    }

    /// TAXONOMY is dense and ordered: entry `i` has discriminant `i`,
    /// and its row agrees with the enum's own `name`/`class`/`args_doc`.
    /// This is the anti-drift check — the macro emits the methods and the
    /// slice from one input, and this proves they stayed consistent.
    #[test]
    fn taxonomy_matches_methods_and_is_dense() {
        for (i, entry) in TAXONOMY.iter().enumerate() {
            assert_eq!(entry.discriminant as usize, i, "TAXONOMY not dense/ordered at {i}");
            let kind = AuditEventKind::from_u8(entry.discriminant)
                .expect("every TAXONOMY discriminant decodes");
            assert_eq!(kind.name(), entry.name);
            assert_eq!(kind.class(), entry.class);
            assert_eq!(kind.args_doc(), entry.args_doc);
        }
    }

    #[test]
    fn from_u8_round_trips_and_rejects_gaps() {
        for entry in TAXONOMY {
            let kind = AuditEventKind::from_u8(entry.discriminant).unwrap();
            assert_eq!(kind as u8, entry.discriminant);
        }
        assert!(AuditEventKind::from_u8(AUDIT_EVENT_KIND_COUNT as u8).is_none());
        assert!(AuditEventKind::from_u8(255).is_none());
    }

    /// Names are a `domain.action` vocabulary: lowercase, dotted, unique.
    #[test]
    fn names_are_well_formed_and_unique() {
        for entry in TAXONOMY {
            let name = entry.name;
            assert!(name.contains('.'), "{name} has no domain.action separator");
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_'),
                "{name} is not lowercase domain.action",
            );
            // domain is the prefix before the first '.': non-empty.
            assert!(!name.split('.').next().unwrap().is_empty(), "{name} empty domain");
        }
        for (i, a) in TAXONOMY.iter().enumerate() {
            for b in &TAXONOMY[i + 1..] {
                assert_ne!(a.name, b.name, "duplicate name {}", a.name);
            }
        }
    }

    /// The denial-union answer to discussion point 2: exactly two events
    /// are denials (cap-table layer + policy layer); policy_query is a
    /// consultation record, not a denial.
    #[test]
    fn denials_are_exactly_two_named_events() {
        let denials = TAXONOMY
            .iter()
            .filter(|e| e.name.ends_with(".denied") || e.name.ends_with("_denied"))
            .count();
        assert_eq!(denials, 2);
        assert_eq!(AuditEventKind::CapabilityDenied.name(), "cap.denied");
        assert_eq!(AuditEventKind::SyscallDenied.name(), "enforce.syscall_denied");
        // A consultation, not a denial.
        assert_eq!(AuditEventKind::PolicyQuery.name(), "enforce.policy_query");
    }

    /// Class round-trips through the flags byte without colliding with
    /// the sampled bit or the reserved bits.
    #[test]
    fn class_packs_into_flags() {
        for entry in TAXONOMY {
            let class = entry.class;
            // class discriminant must fit the 3-bit field.
            assert!((class as u8) <= (AUDIT_CLASS_MASK >> AUDIT_CLASS_SHIFT));
            let f = flags_with_class(true, class);
            assert_eq!(f & FLAG_SAMPLED, FLAG_SAMPLED);
            assert_eq!(AuditClass::from_flags(f), Some(class));
            let f0 = flags_with_class(false, class);
            assert_eq!(f0 & FLAG_SAMPLED, 0);
            assert_eq!(AuditClass::from_flags(f0), Some(class));
        }
    }

    #[test]
    fn class_field_does_not_overlap_sampled_bit() {
        assert_eq!(AUDIT_CLASS_MASK & FLAG_SAMPLED, 0);
    }

    #[test]
    fn version_is_pinned() {
        assert_eq!(AUDIT_TAXONOMY_VERSION, 1);
    }
}
