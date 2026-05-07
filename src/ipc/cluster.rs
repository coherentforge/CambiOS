// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Service clusters — kernel-arbitrated, identity-bound channel meshes
//! (ADR-027).
//!
//! A cluster is a thin bookkeeping object that wraps a manifest of
//! expected members + the channels those members compose. The kernel
//! touches a cluster exactly four times in its lifetime: at create
//! (manifest registered), at member-join (Principal verified), at
//! member-depart (process-exit cleanup notifies the cluster), and at
//! cluster-revoke (every cluster channel atomically torn down).
//! Between those four touches members operate on the existing channel
//! and control-IPC primitives (ADR-005) unchanged.
//!
//! This module contains the **pure bookkeeping** types and the
//! [`ClusterManager`] state machine. It does NOT touch capabilities,
//! channels, scheduler state, or page tables — those side-effects are
//! the responsibility of the syscall handlers wired in a follow-up
//! commit. The cap-promotion, per-channel teardown, and TLB shootdown
//! all live in the surrounding handler that orchestrates a cluster
//! operation.
//!
//! See [ADR-027](../../docs/adr/027-service-clusters.md) for the
//! design.

use alloc::vec::Vec;
use crate::ipc::{ProcessId, Principal};
use crate::ipc::channel::ChannelId;

// ============================================================================
// Constants
// ============================================================================

/// SCAFFOLDING: maximum concurrent service clusters.
/// Why: ADR-027 § Architecture — v1 endgame ~4–8 (rendering, storage,
///      audio, init coordinator), 4× headroom = 32. Memory cost
///      (32 × Option<ClusterRecord>) is well under 64 KiB.
/// Replace when: per-user-session clusters or hot-pluggable cluster
///      instantiation push past 32 live clusters. See
///      docs/ASSUMPTIONS.md.
pub const MAX_CLUSTERS: usize = 32;

/// SCAFFOLDING: maximum members per cluster.
/// Why: ADR-027 § Architecture — v1 endgame ~4–8 per cluster
///      (rendering=3 today, storage~2, audio TBD), 4× headroom = 32.
/// Replace when: a single cluster type exceeds ~8 distinct roles
///      (e.g. multi-display rendering limb with one scanout-driver per
///      display). Replacement bound tracks the largest single cluster's
///      member count, not the sum. See docs/ASSUMPTIONS.md.
pub const MAX_CLUSTER_MEMBERS: usize = 32;

/// SCAFFOLDING: maximum channels attached to one cluster.
/// Why: ADR-027 § Architecture — v1 endgame ~4–8 per cluster
///      (rendering ~6: scanout + per-window surfaces + input queue),
///      4× headroom = 32.
/// Replace when: a cluster type exceeds ~8 internal channels (e.g.
///      scanout limb owning one channel per display). Cap relaxation
///      needs a verification pass on cluster-revoke timing
///      (MAX_CLUSTER_CHANNELS × per-channel-revoke cost). See
///      docs/ASSUMPTIONS.md.
pub const MAX_CLUSTER_CHANNELS: usize = 32;

// ============================================================================
// ClusterId
// ============================================================================

/// Unique cluster identifier with generation counter.
///
/// Encodes `(index: u32, generation: u32)` in a single `u64`, matching
/// the [`ChannelId`] / [`crate::ipc::ProcessId`] layout so the three
/// types share the same encoding pattern and syscall wire format.
///
/// # Invariants (for formal verification)
///
/// - `index < MAX_CLUSTERS` for every live ClusterId.
/// - Two ClusterIds are equal iff both index and generation match.
/// - A ClusterId whose generation does not match the current slot
///   generation is *stale* and must be rejected by every lookup.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClusterId(u64);

impl ClusterId {
    #[inline]
    pub const fn new(index: u32, generation: u32) -> Self {
        ClusterId((index as u64) | ((generation as u64) << 32))
    }

    #[inline]
    pub const fn index(&self) -> u32 {
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
        ClusterId(raw)
    }
}

impl core::fmt::Debug for ClusterId {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "ClusterId(idx={}, gen={})", self.index(), self.generation())
    }
}

// ============================================================================
// ClusterPolicy + ClusterRole
// ============================================================================

/// Cluster policy — names the cluster type and (with the role) keys
/// into the fixed cap-promotion table at member-join time
/// (ADR-027 Decision 2).
///
/// V1 ships only `RenderingLimb`. `StorageLimb` and `AudioLimb`
/// variants will land when their respective subsystems do; the policy
/// ↔ role pairing is made exhaustive and type-checked from day one
/// via [`ClusterPolicy::role_is_valid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterPolicy {
    /// Rendering limb: compositor + scanout-driver(s) + input device(s).
    RenderingLimb = 0,
    // StorageLimb reserved (ADR-027 § Migration Path step 8).
    // AudioLimb    reserved (ADR-027 § Migration Path step 9).
}

impl ClusterPolicy {
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(ClusterPolicy::RenderingLimb),
            _ => None,
        }
    }

    /// Whether the named role belongs to this cluster's policy.
    ///
    /// Closed-world pattern match per ADR-027 Decision 2 — every
    /// `(ClusterPolicy, ClusterRole)` pair is exhaustively classified
    /// here. Adding a new policy adds a match arm; adding a new role
    /// adds a column — both forms are caught by the compiler if the
    /// other side is not updated.
    pub const fn role_is_valid(&self, role: ClusterRole) -> bool {
        match self {
            ClusterPolicy::RenderingLimb => matches!(
                role,
                ClusterRole::Compositor | ClusterRole::Scanout | ClusterRole::Input
            ),
        }
    }
}

/// Role of a member within a cluster.
///
/// Roles are flat (not nested per policy) so the syscall wire format
/// is one `u32`. Validity of a `(ClusterPolicy, ClusterRole)` pair is
/// checked by [`ClusterPolicy::role_is_valid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterRole {
    /// RenderingLimb compositor (canonical endpoint 28).
    Compositor = 0,
    /// RenderingLimb scanout driver (canonical endpoint 27).
    Scanout = 1,
    /// RenderingLimb input device (canonical endpoint 30).
    Input = 2,
}

impl ClusterRole {
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(ClusterRole::Compositor),
            1 => Some(ClusterRole::Scanout),
            2 => Some(ClusterRole::Input),
            _ => None,
        }
    }
}

// ============================================================================
// State machines
// ============================================================================

/// Cluster lifecycle state machine.
///
/// Transitions are strictly forward:
/// `Forming → Active → Revoking → Revoked`
///
/// `Forming → Active` fires automatically when the last expected
/// member joins. `Active → Revoking` fires when a syscall handler (or
/// process-exit cleanup) calls [`ClusterManager::begin_revoke`].
/// `Revoking → Revoked` fires on [`ClusterManager::complete_revoke`]
/// and frees the slot (bumping the generation).
///
/// `Forming → Revoking` is also valid: a cluster can be torn down
/// before all expected members have joined (e.g. boot failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterState {
    Forming,
    Active,
    Revoking,
    Revoked,
}

/// Member lifecycle within a cluster.
///
/// Transitions are strictly forward:
/// `Expected → Joined → Departed`
///
/// `Expected` is the initial state written at [`ClusterManager::create`]
/// when the manifest is registered. `Joined` is the state after
/// [`ClusterManager::join`] verifies the caller's Principal and binds
/// a `ProcessId`. `Departed` is set by
/// [`ClusterManager::mark_member_departed`] when the joined process
/// exits while the cluster persists. Departure does *not* automatically
/// transition the cluster — the cluster-revoke decision is policy
/// (lives in the syscall handler / cluster-policy module that the
/// follow-up commit adds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberState {
    Expected,
    Joined,
    Departed,
}

// ============================================================================
// ClusterError
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterError {
    /// No free slots in the cluster table.
    TableFull,
    /// The ClusterId does not refer to a valid cluster (index out of
    /// range or generation mismatch).
    NotFound,
    /// The cluster is not in the expected state for this operation.
    InvalidState,
    /// The named role does not belong to this cluster's policy.
    RoleNotInPolicy,
    /// The named role has no expected-member slot in this cluster.
    /// (Member was never declared in the manifest.)
    RoleNotExpected,
    /// The role's expected member already joined.
    RoleAlreadyJoined,
    /// The caller's Principal does not match the manifest's expected
    /// Principal for the named role.
    PrincipalMismatch,
    /// The cluster's expected-member list is full.
    MembersFull,
    /// The cluster's channel list is full.
    ChannelsFull,
    /// Internal invariant violation. Surfaces as a typed error rather
    /// than a panic, per CLAUDE.md's no-panic kernel rule.
    InternalInvariant,
}

impl core::fmt::Display for ClusterError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::TableFull         => write!(f, "Cluster table full"),
            Self::NotFound          => write!(f, "Cluster not found"),
            Self::InvalidState      => write!(f, "Cluster in invalid state for operation"),
            Self::RoleNotInPolicy   => write!(f, "Role does not belong to this cluster's policy"),
            Self::RoleNotExpected   => write!(f, "Role has no expected-member slot in this cluster"),
            Self::RoleAlreadyJoined => write!(f, "Role's expected member has already joined"),
            Self::PrincipalMismatch => write!(f, "Principal does not match expected member for role"),
            Self::MembersFull       => write!(f, "Cluster expected-member list is full"),
            Self::ChannelsFull      => write!(f, "Cluster channel list is full"),
            Self::InternalInvariant => write!(f, "Cluster manager internal invariant violation"),
        }
    }
}

// ============================================================================
// ClusterMember + ClusterRecord
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct ClusterMember {
    pub principal: Principal,
    pub role: ClusterRole,
    pub joined_pid: Option<ProcessId>,
    pub state: MemberState,
}

/// Per-cluster kernel state. Stored in the [`ClusterManager`] table.
///
/// # Invariants (for formal verification)
///
/// - `id.index() < MAX_CLUSTERS` and `id.generation()` matches the
///   slot's generation counter at all live points.
/// - State transitions are strictly forward: Forming → Active →
///   Revoking → Revoked, plus the Forming → Revoking shortcut.
/// - `members[i].state == Joined` implies `members[i].joined_pid` is
///   `Some`.
/// - All non-`None` entries in `channels` refer to channels the
///   cluster's members have attached via
///   [`ClusterManager::attach_channel`].
//
// Deferred: `kernel_signature: [u8; 64]`.
// Why: ADR-027 § Decision 1 specifies a kernel-signed cluster record
//      analogous to channel records. Today neither cluster nor channel
//      records carry an in-memory signature — the manager + generation
//      counter is the in-kernel integrity story, and the kernel never
//      hands a record across an untrusted boundary in raw form.
// Revisit when: the first cross-boundary cluster-record carrier lands
//      (e.g. a userspace cluster-info read that needs forgery
//      resistance beyond manager bookkeeping, or a snapshot-restore
//      path).
#[derive(Debug)]
pub struct ClusterRecord {
    pub id: ClusterId,
    pub state: ClusterState,
    pub policy: ClusterPolicy,
    pub creator_pid: ProcessId,
    pub members: [Option<ClusterMember>; MAX_CLUSTER_MEMBERS],
    pub channels: [Option<ChannelId>; MAX_CLUSTER_CHANNELS],
    pub created_at_tick: u64,
}

/// Snapshot returned by [`ClusterManager::begin_revoke`]. Carries the
/// fields the syscall handler needs to drive cluster teardown
/// (member pids for cap revoke, channel ids for per-channel teardown)
/// without holding the `CLUSTER_MANAGER` lock across the per-channel
/// teardown transactions.
///
/// After fan-out completes the handler calls
/// [`ClusterManager::complete_revoke`] to free the cluster slot.
#[derive(Debug, Clone, Copy)]
pub struct RevokingClusterSnapshot {
    pub id: ClusterId,
    pub policy: ClusterPolicy,
    pub creator_pid: ProcessId,
    /// Joined members' pids by manifest slot index. `None` for
    /// Expected (never joined) or Departed (joined then exited).
    pub joined_member_pids: [Option<ProcessId>; MAX_CLUSTER_MEMBERS],
    /// Channels attached to the cluster.
    pub channels: [Option<ChannelId>; MAX_CLUSTER_CHANNELS],
}

// ============================================================================
// ClusterCreateParams
// ============================================================================

/// Parameters for [`ClusterManager::create`].
///
/// `expected_members` lists the manifest's `(Principal, role)` pairs.
/// The slot index in this array becomes the manifest slot for the
/// resulting `ClusterMember`. Empty (`None`) entries are skipped.
///
/// `create` re-checks every named role against the policy per
/// kernel-no-trust discipline; the syscall handler's pre-check is an
/// optimization, not a substitute.
pub struct ClusterCreateParams {
    pub policy: ClusterPolicy,
    pub creator_pid: ProcessId,
    pub created_at_tick: u64,
    pub expected_members: [Option<(Principal, ClusterRole)>; MAX_CLUSTER_MEMBERS],
}

// ============================================================================
// ClusterManager
// ============================================================================

/// Cluster manager — manages the global cluster table.
///
/// Pure bookkeeping: tracks cluster records, enforces state
/// transitions, validates policy ↔ role pairings and member
/// principals. Does NOT promote capabilities, allocate channels, or
/// drive teardown side-effects — those are the syscall handlers'
/// responsibility.
///
/// Lock position: 5 in the global hierarchy (between
/// `CAPABILITY_MANAGER(4)` and `CHANNEL_MANAGER(6)` per ADR-027
/// § Architecture). Plain `Spinlock` — never held in ISR context.
pub struct ClusterManager {
    clusters: [Option<ClusterRecord>; MAX_CLUSTERS],
    /// Per-slot generation counter. Incremented on
    /// [`ClusterManager::complete_revoke`] so stale ClusterIds are
    /// rejected by [`ClusterManager::get`].
    generations: [u32; MAX_CLUSTERS],
    /// Number of slots currently Forming, Active, or Revoking.
    count: usize,
}

impl Default for ClusterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterManager {
    pub const fn new() -> Self {
        ClusterManager {
            clusters: [const { None }; MAX_CLUSTERS],
            generations: [0u32; MAX_CLUSTERS],
            count: 0,
        }
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        MAX_CLUSTERS
    }

    fn find_free_slot(&self) -> Option<usize> {
        self.clusters.iter().position(|slot| slot.is_none())
    }

    fn lookup(&self, id: ClusterId) -> Result<&ClusterRecord, ClusterError> {
        let idx = id.index() as usize;
        if idx >= MAX_CLUSTERS {
            return Err(ClusterError::NotFound);
        }
        let record = self.clusters[idx]
            .as_ref()
            .ok_or(ClusterError::NotFound)?;
        if record.id != id {
            return Err(ClusterError::NotFound);
        }
        Ok(record)
    }

    fn lookup_mut(&mut self, id: ClusterId) -> Result<&mut ClusterRecord, ClusterError> {
        let idx = id.index() as usize;
        if idx >= MAX_CLUSTERS {
            return Err(ClusterError::NotFound);
        }
        let record = self.clusters[idx]
            .as_mut()
            .ok_or(ClusterError::NotFound)?;
        if record.id != id {
            return Err(ClusterError::NotFound);
        }
        Ok(record)
    }

    /// Create a new cluster in `Forming` state with the given manifest.
    ///
    /// Validates that every declared role belongs to the policy
    /// (returns `RoleNotInPolicy` on the first mismatch). Finds a free
    /// table slot, writes the record, returns the `ClusterId`.
    pub fn create(&mut self, params: ClusterCreateParams) -> Result<ClusterId, ClusterError> {
        for slot in params.expected_members.iter() {
            if let Some((_, role)) = slot {
                if !params.policy.role_is_valid(*role) {
                    return Err(ClusterError::RoleNotInPolicy);
                }
            }
        }

        let idx = self.find_free_slot().ok_or(ClusterError::TableFull)?;
        let generation = self.generations[idx];
        let id = ClusterId::new(idx as u32, generation);

        let mut members: [Option<ClusterMember>; MAX_CLUSTER_MEMBERS] =
            [const { None }; MAX_CLUSTER_MEMBERS];
        for (i, slot) in params.expected_members.iter().enumerate() {
            if let Some((principal, role)) = slot {
                members[i] = Some(ClusterMember {
                    principal: *principal,
                    role: *role,
                    joined_pid: None,
                    state: MemberState::Expected,
                });
            }
        }

        self.clusters[idx] = Some(ClusterRecord {
            id,
            state: ClusterState::Forming,
            policy: params.policy,
            creator_pid: params.creator_pid,
            members,
            channels: [const { None }; MAX_CLUSTER_CHANNELS],
            created_at_tick: params.created_at_tick,
        });
        self.count += 1;
        Ok(id)
    }

    /// Member join.
    ///
    /// Verifies the caller's Principal matches the manifest's expected
    /// Principal for the named role, transitions that member from
    /// `Expected` → `Joined`, binds the caller's `ProcessId`. If all
    /// expected members are now `Joined`, auto-promotes the cluster
    /// `Forming` → `Active`.
    ///
    /// Cluster must be in `Forming` or `Active`. Re-joining (member
    /// already in `Joined`) returns `RoleAlreadyJoined`. A `Departed`
    /// member cannot rejoin (forward-only state).
    pub fn join(
        &mut self,
        cluster_id: ClusterId,
        role: ClusterRole,
        caller_principal: Principal,
        caller_pid: ProcessId,
    ) -> Result<&ClusterRecord, ClusterError> {
        let record = self.lookup_mut(cluster_id)?;
        match record.state {
            ClusterState::Forming | ClusterState::Active => {}
            ClusterState::Revoking | ClusterState::Revoked => {
                return Err(ClusterError::InvalidState);
            }
        }

        let member_idx = record
            .members
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|m| m.role == role))
            .ok_or(ClusterError::RoleNotExpected)?;

        // Validate phase (read-only).
        {
            let member = record.members[member_idx]
                .as_ref()
                .ok_or(ClusterError::InternalInvariant)?;
            if member.principal != caller_principal {
                return Err(ClusterError::PrincipalMismatch);
            }
            match member.state {
                MemberState::Expected => {}
                MemberState::Joined => return Err(ClusterError::RoleAlreadyJoined),
                MemberState::Departed => return Err(ClusterError::InvalidState),
            }
        }

        // Mutate phase.
        {
            let member = record.members[member_idx]
                .as_mut()
                .ok_or(ClusterError::InternalInvariant)?;
            member.joined_pid = Some(caller_pid);
            member.state = MemberState::Joined;
        }

        // Auto-promote Forming → Active when last Expected becomes Joined.
        let any_expected = record.members.iter().any(|slot| {
            slot.as_ref().is_some_and(|m| m.state == MemberState::Expected)
        });
        if !any_expected && record.state == ClusterState::Forming {
            record.state = ClusterState::Active;
        }

        self.clusters[cluster_id.index() as usize]
            .as_ref()
            .ok_or(ClusterError::InternalInvariant)
    }

    /// Mark the joined member identified by `departed_pid` as
    /// `Departed`. Used by process-exit cleanup.
    ///
    /// The cluster-revoke decision (RenderingLimb's policy is "any
    /// departure tears down the limb") lives in the syscall handler /
    /// cluster-policy module — this method only updates bookkeeping.
    ///
    /// Returns `NotFound` if no joined member with `departed_pid` is
    /// present in the cluster. Cluster must be `Forming` or `Active`
    /// (departure during `Revoking`/`Revoked` is the cluster-revoke
    /// path's responsibility, not the per-member exit path's).
    pub fn mark_member_departed(
        &mut self,
        cluster_id: ClusterId,
        departed_pid: ProcessId,
    ) -> Result<(), ClusterError> {
        let record = self.lookup_mut(cluster_id)?;
        match record.state {
            ClusterState::Forming | ClusterState::Active => {}
            ClusterState::Revoking | ClusterState::Revoked => {
                return Err(ClusterError::InvalidState);
            }
        }

        let mut found = false;
        for slot in record.members.iter_mut() {
            if let Some(member) = slot.as_mut() {
                if member.state == MemberState::Joined
                    && member.joined_pid == Some(departed_pid)
                {
                    member.state = MemberState::Departed;
                    found = true;
                }
            }
        }
        if !found {
            return Err(ClusterError::NotFound);
        }
        Ok(())
    }

    /// Walk every cluster and mark `pid` `Departed` everywhere it's a
    /// joined member. Returns the list of affected cluster ids so the
    /// caller (process-exit cleanup) can fan out per-cluster
    /// policy decisions (typically: revoke the cluster).
    ///
    /// Slot generation is *not* bumped here — the cluster lifecycle
    /// continues; only the member's per-cluster state changes.
    pub fn mark_departed_for_process(&mut self, pid: ProcessId) -> Vec<ClusterId> {
        let mut affected: Vec<ClusterId> = Vec::new();

        for slot in self.clusters.iter_mut() {
            let Some(record) = slot.as_mut() else {
                continue;
            };
            match record.state {
                ClusterState::Forming | ClusterState::Active => {}
                ClusterState::Revoking | ClusterState::Revoked => continue,
            }
            let mut changed = false;
            for member_slot in record.members.iter_mut() {
                if let Some(member) = member_slot.as_mut() {
                    if member.state == MemberState::Joined
                        && member.joined_pid == Some(pid)
                    {
                        member.state = MemberState::Departed;
                        changed = true;
                    }
                }
            }
            if changed {
                affected.push(record.id);
            }
        }

        affected
    }

    /// Attach a channel id to the cluster's channel list. The syscall
    /// handler that allocated the channel calls this so cluster revoke
    /// knows what to tear down.
    ///
    /// Allowed in `Forming` and `Active` (a member that joined early
    /// can already be creating channels even before peers join).
    pub fn attach_channel(
        &mut self,
        cluster_id: ClusterId,
        channel_id: ChannelId,
    ) -> Result<(), ClusterError> {
        let record = self.lookup_mut(cluster_id)?;
        match record.state {
            ClusterState::Forming | ClusterState::Active => {}
            ClusterState::Revoking | ClusterState::Revoked => {
                return Err(ClusterError::InvalidState);
            }
        }
        let slot = record.channels.iter_mut().find(|c| c.is_none());
        match slot {
            Some(s) => {
                *s = Some(channel_id);
                Ok(())
            }
            None => Err(ClusterError::ChannelsFull),
        }
    }

    /// Begin cluster revoke. Transitions `Forming`|`Active` →
    /// `Revoking` and returns a [`RevokingClusterSnapshot`] for the
    /// caller to drive per-channel teardown + cap revoke without
    /// holding the cluster-manager lock.
    ///
    /// The slot stays held — `join`, `attach_channel`,
    /// `mark_member_departed` against the cluster all return
    /// `InvalidState` until [`complete_revoke`] frees the slot.
    pub fn begin_revoke(
        &mut self,
        cluster_id: ClusterId,
    ) -> Result<RevokingClusterSnapshot, ClusterError> {
        let record = self.lookup_mut(cluster_id)?;
        match record.state {
            ClusterState::Forming | ClusterState::Active => {}
            ClusterState::Revoking | ClusterState::Revoked => {
                return Err(ClusterError::InvalidState);
            }
        }

        let mut joined_pids: [Option<ProcessId>; MAX_CLUSTER_MEMBERS] =
            [None; MAX_CLUSTER_MEMBERS];
        for (i, slot) in record.members.iter().enumerate() {
            if let Some(member) = slot {
                if member.state == MemberState::Joined {
                    joined_pids[i] = member.joined_pid;
                }
            }
        }

        let snapshot = RevokingClusterSnapshot {
            id: record.id,
            policy: record.policy,
            creator_pid: record.creator_pid,
            joined_member_pids: joined_pids,
            channels: record.channels,
        };
        record.state = ClusterState::Revoking;
        Ok(snapshot)
    }

    /// Complete cluster revoke. Cluster must be in `Revoking`. Frees
    /// the slot, bumps the generation, returns the drained
    /// [`ClusterRecord`] with `state = Revoked`.
    pub fn complete_revoke(
        &mut self,
        cluster_id: ClusterId,
    ) -> Result<ClusterRecord, ClusterError> {
        let record = self.lookup_mut(cluster_id)?;
        if record.state != ClusterState::Revoking {
            return Err(ClusterError::InvalidState);
        }
        let idx = cluster_id.index() as usize;
        let mut taken = self.clusters[idx]
            .take()
            .ok_or(ClusterError::InternalInvariant)?;
        taken.state = ClusterState::Revoked;
        self.count -= 1;
        self.generations[idx] = self.generations[idx].wrapping_add(1);
        Ok(taken)
    }

    /// Read-only access to a cluster record.
    pub fn get(&self, cluster_id: ClusterId) -> Result<&ClusterRecord, ClusterError> {
        self.lookup(cluster_id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_principal(byte: u8) -> Principal {
        Principal::from_public_key([byte; 32])
    }

    fn test_pid(slot: u32) -> ProcessId {
        ProcessId::new(slot, 0)
    }

    fn test_channel_id(idx: u32) -> ChannelId {
        ChannelId::new(idx, 0)
    }

    /// Build the canonical RenderingLimb manifest used by most tests.
    /// compositor=0xC0, scanout=0xCA, input=0x10.
    fn rendering_limb_params(creator_pid: ProcessId) -> ClusterCreateParams {
        let mut expected: [Option<(Principal, ClusterRole)>; MAX_CLUSTER_MEMBERS] =
            [None; MAX_CLUSTER_MEMBERS];
        expected[0] = Some((test_principal(0xC0), ClusterRole::Compositor));
        expected[1] = Some((test_principal(0xCA), ClusterRole::Scanout));
        expected[2] = Some((test_principal(0x10), ClusterRole::Input));
        ClusterCreateParams {
            policy: ClusterPolicy::RenderingLimb,
            creator_pid,
            created_at_tick: 100,
            expected_members: expected,
        }
    }

    fn create_rendering_limb(mgr: &mut ClusterManager) -> ClusterId {
        mgr.create(rendering_limb_params(test_pid(1))).unwrap()
    }

    fn join_all_rendering_limb_members(mgr: &mut ClusterManager, id: ClusterId) {
        mgr.join(id, ClusterRole::Compositor, test_principal(0xC0), test_pid(10))
            .unwrap();
        mgr.join(id, ClusterRole::Scanout, test_principal(0xCA), test_pid(11))
            .unwrap();
        mgr.join(id, ClusterRole::Input, test_principal(0x10), test_pid(12))
            .unwrap();
    }

    // -- ClusterId encoding --

    #[test]
    fn test_cluster_id_encoding_round_trip() {
        let id = ClusterId::new(7, 42);
        assert_eq!(id.index(), 7);
        assert_eq!(id.generation(), 42);

        let raw = id.as_raw();
        let restored = ClusterId::from_raw(raw);
        assert_eq!(restored, id);
    }

    #[test]
    fn test_cluster_id_max_values() {
        let id = ClusterId::new(u32::MAX, u32::MAX);
        assert_eq!(id.index(), u32::MAX);
        assert_eq!(id.generation(), u32::MAX);
    }

    // -- ClusterRole / ClusterPolicy --

    #[test]
    fn test_cluster_role_from_u32() {
        assert_eq!(ClusterRole::from_u32(0), Some(ClusterRole::Compositor));
        assert_eq!(ClusterRole::from_u32(1), Some(ClusterRole::Scanout));
        assert_eq!(ClusterRole::from_u32(2), Some(ClusterRole::Input));
        assert_eq!(ClusterRole::from_u32(3), None);
        assert_eq!(ClusterRole::from_u32(u32::MAX), None);
    }

    #[test]
    fn test_cluster_policy_from_u32() {
        assert_eq!(
            ClusterPolicy::from_u32(0),
            Some(ClusterPolicy::RenderingLimb)
        );
        assert_eq!(ClusterPolicy::from_u32(1), None);
    }

    #[test]
    fn test_rendering_limb_accepts_its_three_roles() {
        let p = ClusterPolicy::RenderingLimb;
        assert!(p.role_is_valid(ClusterRole::Compositor));
        assert!(p.role_is_valid(ClusterRole::Scanout));
        assert!(p.role_is_valid(ClusterRole::Input));
    }

    // -- ClusterManager::create --

    #[test]
    fn test_create_basic() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);

        assert_eq!(id.index(), 0);
        assert_eq!(id.generation(), 0);
        assert_eq!(mgr.count(), 1);

        let record = mgr.get(id).unwrap();
        assert_eq!(record.state, ClusterState::Forming);
        assert_eq!(record.policy, ClusterPolicy::RenderingLimb);
        assert_eq!(record.creator_pid, test_pid(1));
        assert_eq!(record.created_at_tick, 100);

        // Three Expected members; the rest of the slots are empty.
        let live: Vec<_> = record.members.iter().filter_map(|m| m.as_ref()).collect();
        assert_eq!(live.len(), 3);
        for m in &live {
            assert_eq!(m.state, MemberState::Expected);
            assert_eq!(m.joined_pid, None);
        }
    }

    #[test]
    fn test_create_returns_unique_ids() {
        let mut mgr = ClusterManager::new();
        let id1 = create_rendering_limb(&mut mgr);
        let id2 = mgr.create(rendering_limb_params(test_pid(2))).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(id1.index(), 0);
        assert_eq!(id2.index(), 1);
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn test_create_table_full() {
        let mut mgr = ClusterManager::new();
        for i in 0..MAX_CLUSTERS {
            mgr.create(rendering_limb_params(test_pid(i as u32))).unwrap();
        }
        assert_eq!(mgr.count(), MAX_CLUSTERS);
        assert_eq!(
            mgr.create(rendering_limb_params(test_pid(99))).err(),
            Some(ClusterError::TableFull)
        );
    }

    // ClusterPolicy::role_is_valid currently has no false branch
    // exercised by a real role variant — every variant is a valid
    // RenderingLimb role. The closed-world test above (and the
    // exhaustive match in role_is_valid) guarantees the check fires
    // structurally. When StorageLimb / AudioLimb roles land, add a
    // RoleNotInPolicy negative test that mixes a storage role into a
    // rendering-limb manifest.

    // -- ClusterManager::join --

    #[test]
    fn test_join_basic_transitions_member_to_joined() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);

        mgr.join(id, ClusterRole::Compositor, test_principal(0xC0), test_pid(10))
            .unwrap();

        let record = mgr.get(id).unwrap();
        // Cluster still Forming — two members still Expected.
        assert_eq!(record.state, ClusterState::Forming);

        let comp = record
            .members
            .iter()
            .find_map(|m| m.as_ref().filter(|m| m.role == ClusterRole::Compositor))
            .unwrap();
        assert_eq!(comp.state, MemberState::Joined);
        assert_eq!(comp.joined_pid, Some(test_pid(10)));
    }

    #[test]
    fn test_join_last_expected_member_promotes_cluster_to_active() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);

        mgr.join(id, ClusterRole::Compositor, test_principal(0xC0), test_pid(10))
            .unwrap();
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Forming);
        mgr.join(id, ClusterRole::Scanout, test_principal(0xCA), test_pid(11))
            .unwrap();
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Forming);
        mgr.join(id, ClusterRole::Input, test_principal(0x10), test_pid(12))
            .unwrap();
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Active);
    }

    #[test]
    fn test_join_wrong_principal_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);

        assert_eq!(
            mgr.join(id, ClusterRole::Compositor, test_principal(0xFF), test_pid(10))
                .err(),
            Some(ClusterError::PrincipalMismatch)
        );
        // Member still Expected.
        let record = mgr.get(id).unwrap();
        let comp = record
            .members
            .iter()
            .find_map(|m| m.as_ref().filter(|m| m.role == ClusterRole::Compositor))
            .unwrap();
        assert_eq!(comp.state, MemberState::Expected);
    }

    #[test]
    fn test_join_role_not_expected_rejected() {
        let mut mgr = ClusterManager::new();
        // Create a manifest with only Compositor + Scanout — no Input.
        let mut expected: [Option<(Principal, ClusterRole)>; MAX_CLUSTER_MEMBERS] =
            [None; MAX_CLUSTER_MEMBERS];
        expected[0] = Some((test_principal(0xC0), ClusterRole::Compositor));
        expected[1] = Some((test_principal(0xCA), ClusterRole::Scanout));
        let id = mgr
            .create(ClusterCreateParams {
                policy: ClusterPolicy::RenderingLimb,
                creator_pid: test_pid(1),
                created_at_tick: 0,
                expected_members: expected,
            })
            .unwrap();

        assert_eq!(
            mgr.join(id, ClusterRole::Input, test_principal(0x10), test_pid(12))
                .err(),
            Some(ClusterError::RoleNotExpected)
        );
    }

    #[test]
    fn test_join_already_joined_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        mgr.join(id, ClusterRole::Compositor, test_principal(0xC0), test_pid(10))
            .unwrap();

        assert_eq!(
            mgr.join(id, ClusterRole::Compositor, test_principal(0xC0), test_pid(20))
                .err(),
            Some(ClusterError::RoleAlreadyJoined)
        );
    }

    #[test]
    fn test_join_during_revoking_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        let _ = mgr.begin_revoke(id).unwrap();

        assert_eq!(
            mgr.join(id, ClusterRole::Compositor, test_principal(0xC0), test_pid(10))
                .err(),
            Some(ClusterError::InvalidState)
        );
    }

    #[test]
    fn test_join_stale_id_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        let _ = mgr.begin_revoke(id).unwrap();
        mgr.complete_revoke(id).unwrap();

        assert_eq!(
            mgr.join(id, ClusterRole::Compositor, test_principal(0xC0), test_pid(10))
                .err(),
            Some(ClusterError::NotFound)
        );
    }

    #[test]
    fn test_join_after_member_departed_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id);
        mgr.mark_member_departed(id, test_pid(10)).unwrap();

        // Re-join attempt for Departed member is forward-only forbidden.
        assert_eq!(
            mgr.join(id, ClusterRole::Compositor, test_principal(0xC0), test_pid(20))
                .err(),
            Some(ClusterError::InvalidState)
        );
    }

    // -- ClusterManager::mark_member_departed --

    #[test]
    fn test_mark_departed_basic() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id);

        mgr.mark_member_departed(id, test_pid(11)).unwrap();
        let record = mgr.get(id).unwrap();
        assert_eq!(record.state, ClusterState::Active); // unchanged
        let scanout = record
            .members
            .iter()
            .find_map(|m| m.as_ref().filter(|m| m.role == ClusterRole::Scanout))
            .unwrap();
        assert_eq!(scanout.state, MemberState::Departed);
    }

    #[test]
    fn test_mark_departed_unknown_pid_returns_not_found() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id);

        assert_eq!(
            mgr.mark_member_departed(id, test_pid(99)).err(),
            Some(ClusterError::NotFound)
        );
    }

    #[test]
    fn test_mark_departed_during_revoking_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id);
        let _ = mgr.begin_revoke(id).unwrap();

        assert_eq!(
            mgr.mark_member_departed(id, test_pid(11)).err(),
            Some(ClusterError::InvalidState)
        );
    }

    #[test]
    fn test_mark_departed_for_process_walks_all_clusters() {
        let mut mgr = ClusterManager::new();
        let id1 = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id1);
        // Second cluster: pid 11 is a member of *only* the first.
        let id2 = mgr.create(rendering_limb_params(test_pid(2))).unwrap();
        mgr.join(id2, ClusterRole::Compositor, test_principal(0xC0), test_pid(20))
            .unwrap();

        let affected = mgr.mark_departed_for_process(test_pid(11));
        assert_eq!(affected, alloc::vec![id1]);

        // pid 20 → only id2.
        let affected2 = mgr.mark_departed_for_process(test_pid(20));
        assert_eq!(affected2, alloc::vec![id2]);

        // pid 999 → none.
        let none = mgr.mark_departed_for_process(test_pid(999));
        assert!(none.is_empty());
    }

    // -- ClusterManager::attach_channel --

    #[test]
    fn test_attach_channel_during_active() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id);

        mgr.attach_channel(id, test_channel_id(7)).unwrap();
        let record = mgr.get(id).unwrap();
        assert_eq!(record.channels[0], Some(test_channel_id(7)));
    }

    #[test]
    fn test_attach_channel_during_forming() {
        // Allowed: a member that joined early may already be creating
        // channels even before peers join.
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        mgr.attach_channel(id, test_channel_id(3)).unwrap();
        let record = mgr.get(id).unwrap();
        assert_eq!(record.channels[0], Some(test_channel_id(3)));
        assert_eq!(record.state, ClusterState::Forming);
    }

    #[test]
    fn test_attach_channel_during_revoking_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id);
        let _ = mgr.begin_revoke(id).unwrap();

        assert_eq!(
            mgr.attach_channel(id, test_channel_id(7)).err(),
            Some(ClusterError::InvalidState)
        );
    }

    #[test]
    fn test_attach_channel_full() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        for i in 0..MAX_CLUSTER_CHANNELS {
            mgr.attach_channel(id, test_channel_id(i as u32)).unwrap();
        }
        assert_eq!(
            mgr.attach_channel(id, test_channel_id(99)).err(),
            Some(ClusterError::ChannelsFull)
        );
    }

    // -- ClusterManager::begin_revoke / complete_revoke --

    #[test]
    fn test_begin_revoke_from_active_returns_snapshot() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id);
        mgr.attach_channel(id, test_channel_id(7)).unwrap();
        mgr.attach_channel(id, test_channel_id(8)).unwrap();

        let snap = mgr.begin_revoke(id).unwrap();
        assert_eq!(snap.id, id);
        assert_eq!(snap.policy, ClusterPolicy::RenderingLimb);
        assert_eq!(snap.creator_pid, test_pid(1));
        assert_eq!(snap.joined_member_pids[0], Some(test_pid(10)));
        assert_eq!(snap.joined_member_pids[1], Some(test_pid(11)));
        assert_eq!(snap.joined_member_pids[2], Some(test_pid(12)));
        assert_eq!(snap.channels[0], Some(test_channel_id(7)));
        assert_eq!(snap.channels[1], Some(test_channel_id(8)));

        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Revoking);
        // Slot still occupied — count unchanged.
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_begin_revoke_from_forming_allowed() {
        // Cluster torn down before all members joined (e.g. boot failure).
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);

        let snap = mgr.begin_revoke(id).unwrap();
        // Only-Expected members surface as None in joined_member_pids.
        assert!(snap.joined_member_pids.iter().all(|p| p.is_none()));
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Revoking);
    }

    #[test]
    fn test_begin_revoke_during_revoking_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        let _ = mgr.begin_revoke(id).unwrap();

        assert_eq!(
            mgr.begin_revoke(id).err(),
            Some(ClusterError::InvalidState)
        );
    }

    #[test]
    fn test_begin_revoke_after_complete_returns_not_found() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        let _ = mgr.begin_revoke(id).unwrap();
        mgr.complete_revoke(id).unwrap();

        assert_eq!(
            mgr.begin_revoke(id).err(),
            Some(ClusterError::NotFound)
        );
    }

    #[test]
    fn test_complete_revoke_after_begin_yields_revoked_record() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        join_all_rendering_limb_members(&mut mgr, id);
        let _ = mgr.begin_revoke(id).unwrap();

        let record = mgr.complete_revoke(id).unwrap();
        assert_eq!(record.state, ClusterState::Revoked);
        assert_eq!(record.policy, ClusterPolicy::RenderingLimb);
        assert_eq!(mgr.count(), 0);
        // Slot freed; old id is stale.
        assert_eq!(mgr.get(id).err(), Some(ClusterError::NotFound));
    }

    #[test]
    fn test_complete_revoke_without_begin_rejected() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);

        assert_eq!(
            mgr.complete_revoke(id).err(),
            Some(ClusterError::InvalidState)
        );
        // Cluster unchanged.
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Forming);
    }

    #[test]
    fn test_complete_revoke_double_call_returns_not_found() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        let _ = mgr.begin_revoke(id).unwrap();
        mgr.complete_revoke(id).unwrap();

        assert_eq!(
            mgr.complete_revoke(id).err(),
            Some(ClusterError::NotFound)
        );
    }

    // -- Slot reuse + generation counter --

    #[test]
    fn test_slot_reuse_after_complete_revoke_bumps_generation() {
        let mut mgr = ClusterManager::new();
        let id1 = create_rendering_limb(&mut mgr);
        assert_eq!(id1.generation(), 0);

        let _ = mgr.begin_revoke(id1).unwrap();
        mgr.complete_revoke(id1).unwrap();

        let id2 = create_rendering_limb(&mut mgr);
        assert_eq!(id2.index(), 0);
        assert_eq!(id2.generation(), 1);
        assert_ne!(id1, id2);

        // Stale id1 rejected on every method.
        assert_eq!(mgr.get(id1).err(), Some(ClusterError::NotFound));
        assert_eq!(mgr.begin_revoke(id1).err(), Some(ClusterError::NotFound));
        assert_eq!(
            mgr.attach_channel(id1, test_channel_id(0)).err(),
            Some(ClusterError::NotFound)
        );
    }

    #[test]
    fn test_revoking_holds_slot_against_create() {
        // Slot stays occupied during Revoking; the count remains
        // accurate so create() against a full table returns TableFull
        // rather than silently stealing the in-flight slot.
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        let _ = mgr.begin_revoke(id).unwrap();

        for i in 1..MAX_CLUSTERS {
            mgr.create(rendering_limb_params(test_pid(i as u32))).unwrap();
        }
        assert_eq!(mgr.count(), MAX_CLUSTERS);
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Revoking);

        assert_eq!(
            mgr.create(rendering_limb_params(test_pid(99))).err(),
            Some(ClusterError::TableFull)
        );
    }

    // -- Full lifecycle --

    #[test]
    fn test_full_lifecycle_create_join_attach_revoke() {
        let mut mgr = ClusterManager::new();
        let id = create_rendering_limb(&mut mgr);
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Forming);

        join_all_rendering_limb_members(&mut mgr, id);
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Active);

        mgr.attach_channel(id, test_channel_id(7)).unwrap();
        mgr.attach_channel(id, test_channel_id(8)).unwrap();

        let snap = mgr.begin_revoke(id).unwrap();
        assert_eq!(snap.channels[0], Some(test_channel_id(7)));
        assert_eq!(snap.channels[1], Some(test_channel_id(8)));
        assert_eq!(mgr.get(id).unwrap().state, ClusterState::Revoking);

        let record = mgr.complete_revoke(id).unwrap();
        assert_eq!(record.state, ClusterState::Revoked);
        assert_eq!(mgr.count(), 0);
    }
}
