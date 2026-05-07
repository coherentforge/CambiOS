// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Service-cluster policy module (ADR-027 § Decision 2).
//!
//! Closed-world `(ClusterPolicy, ClusterRole)` → cap-set mapping +
//! per-policy member-departure decisions. The kernel calls
//! [`caps_for_role`] at member-join to know which caps to promote
//! into the joining member's `ProcessCapabilities`, at cluster-revoke
//! to know which caps to remove, and [`on_member_depart`] to decide
//! whether a joined-member's exit should tear the cluster down.
//!
//! V1 ships with a deliberately empty `caps_for_role` table — the real
//! cap shapes live in the rendering-limb pairwise handshakes today
//! (`RegisterCompositor` / `WelcomeCompositor` / `DisplayConnected`)
//! and will be migrated into this table during the rendering-limb
//! migration commit. With the empty table, cluster join + revoke wire
//! up end-to-end but cap promotion is a no-op — no userspace consumer
//! relies on cluster-promoted caps yet.
//!
//! `on_member_depart` IS populated for v1: RenderingLimb's policy is
//! "any departure tears down the limb" per
//! [ADR-027 § Migration Path step 7](../../docs/adr/027-service-clusters.md).

use crate::ipc::{CapabilityRights, EndpointId};
use crate::ipc::cluster::{ClusterPolicy, ClusterRole};

/// Per-policy decision returned by [`on_member_depart`] when a joined
/// member's process has exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterDepartureAction {
    /// Cluster continues operating with one fewer joined member.
    /// Used for cluster types whose policy tolerates partial
    /// membership.
    Continue,
    /// Cluster must be torn down. The exit handler drives the same
    /// teardown sequence as `SYS_CLUSTER_REVOKE` (begin → per-channel
    /// teardown → cap revoke → complete).
    RevokeCluster,
}

/// Caps to promote into a member's `ProcessCapabilities` at join time
/// (and to remove at cluster-revoke time).
///
/// V1 stub: returns an empty slice for every `(policy, role)` pair.
/// Cluster join therefore wires up state-machine + identity
/// verification end-to-end without actually granting caps. The real
/// cap shapes are encoded today in the rendering-limb pairwise
/// control-IPC handshakes (`RegisterCompositor` / `WelcomeCompositor`
/// / `DisplayConnected`) between compositor, scanout-virtio-gpu, and
/// virtio-input; reading them off is the migration commit's job, and
/// landing the real table during migration ensures the populated
/// entries match what userspace actually consumes.
//
// Deferred: populate the rendering-limb cap table.
// Why: substrate not built — needs SYS_CHANNEL_CREATE cluster_id arg.
// Revisit when: SYS_CHANNEL_CREATE gains a cluster_id arg (so channels
//      can be auto-attached at create time) AND the existing pairwise
//      handshakes' cap tokens are due to be stripped.
pub fn caps_for_role(
    _policy: ClusterPolicy,
    _role: ClusterRole,
) -> &'static [(EndpointId, CapabilityRights)] {
    &[]
}

/// Decide what to do when a joined member's process exits while the
/// cluster is `Active` (or `Forming`).
///
/// RenderingLimb: any departure is fatal — compositor, scanout, and
/// input are co-load-bearing for the rendering pipeline; losing one
/// breaks the others' invariants. The exit handler tears down the
/// whole limb so survivors are not left with stale references to the
/// departed peer.
pub fn on_member_depart(
    policy: ClusterPolicy,
    _role: ClusterRole,
) -> ClusterDepartureAction {
    match policy {
        ClusterPolicy::RenderingLimb => ClusterDepartureAction::RevokeCluster,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_for_role_v1_stub_returns_empty() {
        assert!(caps_for_role(ClusterPolicy::RenderingLimb, ClusterRole::Compositor).is_empty());
        assert!(caps_for_role(ClusterPolicy::RenderingLimb, ClusterRole::Scanout).is_empty());
        assert!(caps_for_role(ClusterPolicy::RenderingLimb, ClusterRole::Input).is_empty());
    }

    #[test]
    fn rendering_limb_departure_is_fatal() {
        assert_eq!(
            on_member_depart(ClusterPolicy::RenderingLimb, ClusterRole::Compositor),
            ClusterDepartureAction::RevokeCluster,
        );
        assert_eq!(
            on_member_depart(ClusterPolicy::RenderingLimb, ClusterRole::Scanout),
            ClusterDepartureAction::RevokeCluster,
        );
        assert_eq!(
            on_member_depart(ClusterPolicy::RenderingLimb, ClusterRole::Input),
            ClusterDepartureAction::RevokeCluster,
        );
    }
}
