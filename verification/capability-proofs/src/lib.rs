// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kani proof harnesses for the kernel's capability manager.
//!
//! Proves soundness of the zero-trust capability check at its core:
//! grant/revoke state is correctly reflected by `verify_access`, revocation
//! is atomic and effective, rights cannot be escalated through delegation,
//! and stale `ProcessId` references (wrong generation) are always rejected.
//!
//! The proven module (`src/ipc/capability.rs`) is included via `#[path]` —
//! no fork, no copy. Because `capability.rs` imports
//! `crate::ipc::{ProcessId, EndpointId, CapabilityRights, Principal}` and
//! references `crate::ipc::interceptor::{IpcInterceptor, InterceptDecision}`,
//! we provide minimal stubs for those names in this crate's `ipc` module
//! so the include resolves. The stubs are drop-in replacements — same
//! public API surface the kernel's own `src/ipc/mod.rs` exposes.
//!
//! The audit-emit path in `CapabilityManager::revoke` is guarded by
//! `#[cfg(not(any(test, fuzzing)))]`; `build.rs` sets `--cfg fuzzing`
//! so that branch is compiled out and we do not drag the kernel's
//! `crate::audit` / `crate::scheduler` graphs into the proof crate.
//!
//! Run with `cargo kani` from this directory.

extern crate alloc;

pub mod ipc {
    //! Minimal stand-ins for the `crate::ipc` names that
    //! `src/ipc/capability.rs` imports. Public API matches the kernel
    //! definitions closely enough that `capability.rs` compiles unchanged.

    /// Message endpoint identifier — mirrors `src/ipc/mod.rs`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct EndpointId(pub u32);

    /// Process identifier with generation counter (Phase 3.2c, ADR-008).
    /// Encodes `(slot_index: u32, generation: u32)` in a single `u64`.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct ProcessId(u64);

    impl ProcessId {
        #[inline]
        pub const fn new(slot: u32, generation: u32) -> Self {
            ProcessId((slot as u64) | ((generation as u64) << 32))
        }
        #[inline]
        pub const fn slot(&self) -> u32 {
            self.0 as u32
        }
        #[inline]
        pub const fn generation(&self) -> u32 {
            (self.0 >> 32) as u32
        }
        #[inline]
        pub const fn as_raw(&self) -> u64 {
            self.0
        }
        #[inline]
        pub const fn from_raw(raw: u64) -> Self {
            ProcessId(raw)
        }
    }

    impl core::fmt::Debug for ProcessId {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "ProcessId(slot={}, gen={})", self.slot(), self.generation())
        }
    }

    /// Ed25519 public-key identity — mirrors `src/ipc/mod.rs`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct Principal {
        pub public_key: [u8; 32],
    }

    impl Principal {
        pub const fn from_public_key(key: [u8; 32]) -> Self {
            Principal { public_key: key }
        }
        pub const ZERO: Self = Principal { public_key: [0u8; 32] };
        pub fn is_zero(&self) -> bool {
            self.public_key == [0u8; 32]
        }
    }

    impl core::fmt::Debug for Principal {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "Principal(...)")
        }
    }

    /// IPC capability rights — mirrors `src/ipc/mod.rs`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CapabilityRights {
        pub send: bool,
        pub receive: bool,
        pub delegate: bool,
        pub revoke: bool,
    }

    impl CapabilityRights {
        pub const EMPTY: Self = CapabilityRights {
            send: false,
            receive: false,
            delegate: false,
            revoke: false,
        };
        pub const FULL: Self = CapabilityRights {
            send: true,
            receive: true,
            delegate: true,
            revoke: true,
        };
        pub const SEND_ONLY: Self = CapabilityRights {
            send: true,
            receive: false,
            delegate: false,
            revoke: false,
        };
        pub const RECV_ONLY: Self = CapabilityRights {
            send: false,
            receive: true,
            delegate: false,
            revoke: false,
        };
    }

    /// Interceptor stub. `src/ipc/capability.rs` accepts
    /// `Option<&dyn IpcInterceptor>` in `delegate_capability_with_interceptor`.
    /// The proofs always pass `None`, but the trait must exist so the
    /// type signature resolves and the `use InterceptDecision;` inside
    /// the function body type-checks.
    pub mod interceptor {
        use super::{CapabilityRights, EndpointId, ProcessId};

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum DenyReason {
            Other,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum InterceptDecision {
            Allow,
            Deny(DenyReason),
        }

        pub trait IpcInterceptor: Send + Sync {
            fn on_delegate(
                &self,
                source: ProcessId,
                target: ProcessId,
                endpoint: EndpointId,
                rights: CapabilityRights,
            ) -> InterceptDecision;
        }
    }

    // The proven kernel source is re-exported from `crate::_capability_src`
    // (declared at the crate root below). Declaring `mod capability` here
    // would force `#[path]` resolution through a non-existent `src/ipc/`
    // directory in this crate; keeping the `#[path]` include at the crate
    // root sidesteps that while still letting callers use the expected
    // `crate::ipc::capability::...` import.
    pub use crate::_capability_src as capability;
}

// Proven kernel source, included verbatim. Declared at the crate root so
// `#[path]` resolves against `<crate>/src/`, matching the buddy-/elf-/frame-
// proofs convention. Re-exported through `crate::ipc::capability` above so
// `src/ipc/capability.rs`'s internal `crate::ipc::{...}` imports still
// resolve to this crate's `ipc` stub module.
#[path = "../../../src/ipc/capability.rs"]
pub mod _capability_src;

#[cfg(kani)]
mod proofs {
    use super::ipc::capability::*;
    use super::ipc::{CapabilityRights, EndpointId, Principal, ProcessId};
    extern crate alloc;
    use alloc::boxed::Box;

    // ========================================================================
    // Tier A — `ProcessCapabilities` invariants
    //
    // The inner capability table is a pure state machine with no
    // `&'static mut [...]` dependency. Harnesses exercise it directly.
    // ========================================================================

    /// P3.1 — `verify_access` on a fresh table rejects every endpoint.
    ///
    /// For any symbolic endpoint and symbolic required rights,
    /// `verify_access` on an empty `ProcessCapabilities` returns
    /// `Err(AccessDenied)`. This is the base case that makes the
    /// capability check sound: without a grant, access is denied.
    #[kani::proof]
    fn proof_verify_access_empty_table_denies() {
        let caps = ProcessCapabilities::new(ProcessId::new(1, 0));
        let endpoint = EndpointId(kani::any());
        let required = any_rights();

        assert!(matches!(
            caps.verify_access(endpoint, required),
            Err(CapabilityError::AccessDenied)
        ));
    }

    /// P3.2 — `grant(ep, rights)` followed by `verify_access(ep, rights)`
    /// succeeds. The composition property: a granted capability is
    /// immediately visible to the check.
    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_grant_then_verify_access_succeeds() {
        let mut caps = ProcessCapabilities::new(ProcessId::new(1, 0));
        let endpoint = EndpointId(kani::any());
        let rights = any_rights();

        caps.grant(endpoint, rights).unwrap();
        assert!(caps.verify_access(endpoint, rights).is_ok());
    }

    /// P3.3 — After `revoke(ep)` succeeds, `verify_access(ep, any_rights)`
    /// returns `Err(AccessDenied)`. Revocation is effective immediately
    /// and leaves no residual rights.
    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_revoke_denies_future_access() {
        let mut caps = ProcessCapabilities::new(ProcessId::new(1, 0));
        let endpoint = EndpointId(kani::any());
        let rights = any_rights();

        caps.grant(endpoint, rights).unwrap();
        caps.revoke(endpoint).unwrap();

        let check = any_rights();
        assert!(matches!(
            caps.verify_access(endpoint, check),
            Err(CapabilityError::AccessDenied)
        ));
    }

    /// P3.4 — `revoke` on an endpoint the process never held returns
    /// `Err(EndpointNotFound)` and leaves the table unchanged.
    #[kani::proof]
    fn proof_revoke_absent_endpoint_errors() {
        let mut caps = ProcessCapabilities::new(ProcessId::new(1, 0));
        let endpoint = EndpointId(kani::any());
        let count_before = caps.capability_count();

        assert!(matches!(
            caps.revoke(endpoint),
            Err(CapabilityError::EndpointNotFound)
        ));
        assert_eq!(caps.capability_count(), count_before);
    }

    /// P3.5 — A second `grant` on the same endpoint upgrades the rights
    /// in place and does not increment `count`. This is the existing-
    /// endpoint branch at capability.rs:154-162.
    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_grant_same_endpoint_upgrades_rights() {
        let mut caps = ProcessCapabilities::new(ProcessId::new(1, 0));
        let endpoint = EndpointId(kani::any());

        caps.grant(endpoint, CapabilityRights::SEND_ONLY).unwrap();
        assert_eq!(caps.capability_count(), 1);

        // Upgrade to FULL — same endpoint, broader rights.
        caps.grant(endpoint, CapabilityRights::FULL).unwrap();
        assert_eq!(caps.capability_count(), 1);

        // verify_access now accepts FULL rights.
        assert!(caps.verify_access(endpoint, CapabilityRights::FULL).is_ok());
    }

    /// P3.6 — `capability_count()` never exceeds the table capacity (32)
    /// across a single grant/revoke. The table bounds are enforced by
    /// the `self.count >= 32` check in `grant`; this proof witnesses
    /// that the `count` field actually respects the cap.
    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_count_bounded_after_ops() {
        let mut caps = ProcessCapabilities::new(ProcessId::new(1, 0));
        let endpoint = EndpointId(kani::any());

        // A single grant either succeeds (count == 1) or is irrelevant.
        let _ = caps.grant(endpoint, CapabilityRights::SEND_ONLY);
        assert!(caps.capability_count() <= 32);

        // A revoke never takes count past the cap either.
        let _ = caps.revoke(endpoint);
        assert!(caps.capability_count() <= 32);
    }

    /// P3.7 — When the table is full (`count == 32`) and the endpoint is
    /// not already present, `grant` returns `Err(CapabilityFull)` without
    /// mutating state.
    ///
    /// We construct a full table by granting 32 distinct endpoints, then
    /// attempt a 33rd grant with a fresh endpoint. The scan-for-existing
    /// loop inside `grant` terminates before the capacity check only
    /// when the endpoint matches an existing entry; the fresh-endpoint
    /// case exercises the capacity-reject branch directly.
    #[kani::proof]
    #[kani::unwind(34)]
    fn proof_grant_at_capacity_rejects_new_endpoint() {
        let mut caps = ProcessCapabilities::new(ProcessId::new(1, 0));

        // Fill the table with 32 distinct endpoints (indices 0..32).
        for i in 0..32u32 {
            caps.grant(EndpointId(i), CapabilityRights::SEND_ONLY).unwrap();
        }
        assert_eq!(caps.capability_count(), 32);

        // A fresh endpoint (index 100) is rejected.
        assert!(matches!(
            caps.grant(EndpointId(100), CapabilityRights::SEND_ONLY),
            Err(CapabilityError::CapabilityFull)
        ));
        assert_eq!(caps.capability_count(), 32);
    }

    // ========================================================================
    // Tier B — `CapabilityManager` cross-process properties
    //
    // Construct a small manager via `Box::leak` on an `alloc::vec::Vec`,
    // analogous to the kernel's `new_for_test_with_capacity` (which is
    // `#[cfg(test)]`-gated, so unavailable to this crate). Slot counts
    // are bounded small for tractability; the proven properties are
    // quantified over state, not state size.
    // ========================================================================

    /// Construct a 4-slot `CapabilityManager` from a leaked `Box<[...]>`,
    /// matching `from_object_slice`'s `&'static mut [Option<ProcessCapabilities>]`
    /// contract.
    fn make_manager(slots: usize) -> Box<CapabilityManager> {
        let mut v: alloc::vec::Vec<Option<ProcessCapabilities>> =
            alloc::vec::Vec::with_capacity(slots);
        for _ in 0..slots {
            v.push(None);
        }
        let boxed: Box<[Option<ProcessCapabilities>]> = v.into_boxed_slice();
        let slice: &'static mut [Option<ProcessCapabilities>] = Box::leak(boxed);
        CapabilityManager::from_object_slice(slice).unwrap()
    }

    /// P3.9 — `lookup` (via `verify_access`) rejects any `ProcessId` whose
    /// generation does not match the generation stored when the slot was
    /// registered. Stale references cannot silently target a re-used
    /// slot. Phase 3.2c / ADR-008 § Open Problem 9.
    ///
    /// Unwind covers: `make_manager` init loop (3 iterations) and
    /// `verify_access`'s capability scan (up to `count` iterations, here 1).
    #[kani::proof]
    #[kani::unwind(5)]
    fn proof_stale_generation_rejected() {
        let mut mgr = make_manager(3);
        let registered = ProcessId::new(1, 0);
        mgr.register_process(registered).unwrap();
        mgr.grant_capability(registered, EndpointId(5), CapabilityRights::SEND_ONLY)
            .unwrap();

        // Stale ProcessId — same slot, different generation.
        let stale_gen: u32 = kani::any();
        kani::assume(stale_gen != 0);
        let stale = ProcessId::new(1, stale_gen);

        let result = mgr.verify_access(stale, EndpointId(5), CapabilityRights::SEND_ONLY);
        assert!(matches!(result, Err(CapabilityError::ProcessNotFound)));
    }

    /// P3.10 — `delegate_capability` refuses to delegate when the source
    /// does not hold the `delegate` right, returning
    /// `Err(AccessDenied)`. No rights flow to the target.
    ///
    /// Note the error is `AccessDenied`, not `InvalidOperation`: the
    /// `can_delegate` path (capability.rs:219-226) calls `verify_access`
    /// with `required.delegate = true`, which returns `AccessDenied`
    /// when the held cap lacks that bit. The plan's P3.10 line — "source
    /// lacks `delegate` ⇒ `Err(InvalidOperation)`" — was written from the
    /// "delegating-more-than-owned" branch (lines 233-244, which returns
    /// `InvalidOperation`); that's a distinct path. The no-escalation
    /// property is proven separately below.
    #[kani::proof]
    #[kani::unwind(5)]
    fn proof_delegate_without_delegate_right_denied() {
        let mut mgr = make_manager(3);
        let source = ProcessId::new(1, 0);
        let target = ProcessId::new(2, 0);
        mgr.register_process(source).unwrap();
        mgr.register_process(target).unwrap();

        // Source has send+receive but no delegate.
        let owned = CapabilityRights {
            send: true,
            receive: true,
            delegate: false,
            revoke: false,
        };
        mgr.grant_capability(source, EndpointId(7), owned).unwrap();

        let result = mgr.delegate_capability(source, target, EndpointId(7), owned);
        assert!(matches!(result, Err(CapabilityError::AccessDenied)));

        // Target has not gained any right to EndpointId(7).
        let check = mgr.verify_access(target, EndpointId(7), CapabilityRights::SEND_ONLY);
        assert!(matches!(check, Err(CapabilityError::AccessDenied)));
    }

    /// P3.10b — `delegate_capability` refuses to grant rights the source
    /// does not hold, even when the source has the `delegate` right.
    /// This is the "no-escalation" property from ADR-007 / ADR-000:
    /// delegation is monotone-shrinking, never rights-amplifying.
    #[kani::proof]
    #[kani::unwind(5)]
    fn proof_delegate_cannot_escalate_rights() {
        let mut mgr = make_manager(3);
        let source = ProcessId::new(1, 0);
        let target = ProcessId::new(2, 0);
        mgr.register_process(source).unwrap();
        mgr.register_process(target).unwrap();

        // Source has send + delegate but NOT receive.
        let owned = CapabilityRights {
            send: true,
            receive: false,
            delegate: true,
            revoke: false,
        };
        mgr.grant_capability(source, EndpointId(7), owned).unwrap();

        // Attempt to delegate send + receive — receive is not owned.
        let attempted = CapabilityRights {
            send: true,
            receive: true,
            delegate: false,
            revoke: false,
        };
        let result = mgr.delegate_capability(source, target, EndpointId(7), attempted);
        assert!(matches!(result, Err(CapabilityError::InvalidOperation)));

        // Target still has no access to EndpointId(7).
        let check = mgr.verify_access(target, EndpointId(7), CapabilityRights::SEND_ONLY);
        assert!(matches!(check, Err(CapabilityError::AccessDenied)));
    }

    /// P3.11 — `revoke_all_for_process` clears every endpoint capability
    /// and every system capability flag in one shot. After the call,
    /// any `verify_access` on any endpoint returns `Err(AccessDenied)`,
    /// and every system-cap query returns `Ok(false)`.
    #[kani::proof]
    #[kani::unwind(34)]
    fn proof_revoke_all_clears_endpoints_and_system_caps() {
        let mut mgr = make_manager(3);
        let pid = ProcessId::new(1, 0);
        mgr.register_process(pid).unwrap();
        mgr.grant_capability(pid, EndpointId(10), CapabilityRights::FULL).unwrap();
        mgr.grant_capability(pid, EndpointId(11), CapabilityRights::SEND_ONLY).unwrap();
        mgr.grant_system_capability(pid, CapabilityKind::CreateProcess).unwrap();
        mgr.grant_system_capability(pid, CapabilityKind::CreateChannel).unwrap();
        mgr.grant_system_capability(pid, CapabilityKind::LegacyPortIo).unwrap();
        mgr.grant_system_capability(pid, CapabilityKind::MapFramebuffer).unwrap();
        mgr.grant_system_capability(pid, CapabilityKind::LargeChannel).unwrap();

        let count = mgr.revoke_all_for_process(pid).unwrap();
        assert_eq!(count, 2);

        // Endpoint capabilities gone.
        let ep: u32 = kani::any();
        let probe = mgr.verify_access(pid, EndpointId(ep), CapabilityRights::SEND_ONLY);
        assert!(matches!(probe, Err(CapabilityError::AccessDenied)));

        // All five system-cap flags cleared.
        assert_eq!(
            mgr.has_system_capability(pid, CapabilityKind::CreateProcess).unwrap(),
            false
        );
        assert_eq!(
            mgr.has_system_capability(pid, CapabilityKind::CreateChannel).unwrap(),
            false
        );
        assert_eq!(
            mgr.has_system_capability(pid, CapabilityKind::LegacyPortIo).unwrap(),
            false
        );
        assert_eq!(
            mgr.has_system_capability(pid, CapabilityKind::MapFramebuffer).unwrap(),
            false
        );
        assert_eq!(
            mgr.has_system_capability(pid, CapabilityKind::LargeChannel).unwrap(),
            false
        );
    }

    /// P3.12 — `revoke(holder, endpoint, revoker, bootstrap)` with
    /// `revoker != bootstrap` returns `Err(AccessDenied)` and leaves the
    /// holder's capability intact. The Phase 3.1 authority model
    /// (bootstrap-only) is enforced before any table mutation.
    #[kani::proof]
    #[kani::unwind(5)]
    fn proof_revoke_non_bootstrap_rejected() {
        let mut mgr = make_manager(3);
        let holder = ProcessId::new(1, 0);
        let endpoint = EndpointId(7);
        mgr.register_process(holder).unwrap();
        mgr.grant_capability(holder, endpoint, CapabilityRights::SEND_ONLY).unwrap();

        let bootstrap = Principal::from_public_key([0xAA; 32]);
        // Symbolic attacker principal, constrained to differ from bootstrap.
        let attacker_byte: u8 = kani::any();
        kani::assume(attacker_byte != 0xAA);
        let attacker = Principal::from_public_key([attacker_byte; 32]);

        let result = mgr.revoke(holder, endpoint, attacker, bootstrap);
        assert!(matches!(result, Err(CapabilityError::AccessDenied)));

        // Holder's capability is still present.
        assert!(mgr
            .verify_access(holder, endpoint, CapabilityRights::SEND_ONLY)
            .is_ok());
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    fn any_rights() -> CapabilityRights {
        CapabilityRights {
            send: kani::any(),
            receive: kani::any(),
            delegate: kani::any(),
            revoke: kani::any(),
        }
    }
}
