// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Shared-memory data channels (Phase 3.2d.i, ADR-005).
//!
//! A channel is a region of physical memory that the kernel maps into two
//! processes' address spaces, with a capability that records the
//! relationship: which two principals are connected, in which direction,
//! with what size. The kernel touches a channel exactly four times in its
//! lifetime: create, attach, close, revoke. Between those four kernel
//! touches the bytes flow directly through the shared mapping at full
//! memory bandwidth.
//!
//! This module contains the **pure bookkeeping** types and the
//! `ChannelManager` state machine. It does NOT touch page tables, the
//! frame allocator, or TLB shootdown — those side-effects are the
//! responsibility of the syscall handlers in `src/syscalls/dispatcher.rs`
//! that orchestrate the full create/attach/close/revoke flows.
//!
//! See [ADR-005](../../docs/adr/005-ipc-primitives-control-and-bulk.md)
//! for the design.

use alloc::vec::Vec;
use crate::ipc::{ProcessId, Principal};

// ============================================================================
// Constants
// ============================================================================

/// SCAFFOLDING: maximum number of concurrent channels.
/// Why: bounded table for verification. Sized for the v1 endgame target of a
///      multi-monitor 4K@120Hz compositor (see ADR-011): ~6 scanout channels
///      (3 displays × front/back) + ~30 window surface channels + ~10 GPU
///      command/memory channels + non-GUI services (current 7 boot modules
///      × ~2 data paths each) = ~60 active channels at v1 endgame. 4×
///      headroom over that estimate puts the ceiling at 256.
///      Memory cost: 256 × size_of::<Option<ChannelRecord>>() ≈ 256 × ~160 B
///      ≈ 40 KiB. Negligible.
/// Replace when: the first service needs more than ~4 simultaneous
///      channels and the table fills up, OR when multi-monitor + many-client
///      graphics workloads exceed 60 active channels. See docs/ASSUMPTIONS.md.
pub const MAX_CHANNELS: usize = 256;

/// SCAFFOLDING: soft cap on channel size in pages (256 MiB = 65536 pages).
/// Why: bounds the physical memory a single channel can consume. Sized for
///      the v1 endgame graphics target (ADR-011): a full-screen window
///      surface on a 4K display at 2× Retina backing scale is an 8K backing
///      store = 128 MiB at 32bpp, 256 MiB at 64bpp HDR. 256 MiB per channel
///      accommodates this with no further headroom — multi-monitor workloads
///      use multiple channels (one per display scanout, one per window
///      surface). This is a soft cap (ceiling), not always-allocated;
///      typical channel sizes remain in the single-digit MiB range.
/// Replace when: HDR + supersampling beyond 2× backing scale on 5K/8K
///      displays pushes single-surface size past 256 MiB. The tier-aware
///      policy service (Phase 3.4) and a future `LargeChannel` capability
///      should gate these allocations before the ceiling rises further.
///      See docs/ASSUMPTIONS.md.
pub const MAX_CHANNEL_PAGES: u32 = 65536;

/// ARCHITECTURAL: minimum channel size is one page (4 KiB).
/// Channels smaller than a page would defeat the purpose — the kernel
/// copy overhead for the 256-byte control IPC is already amortized over
/// a single page.
pub const MIN_CHANNEL_PAGES: u32 = 1;

// ============================================================================
// ChannelId
// ============================================================================

/// Unique channel identifier with generation counter.
///
/// Encodes `(index: u32, generation: u32)` in a single `u64`, matching
/// the `ProcessId` layout so the two types share the same encoding
/// pattern and syscall wire format.
///
/// # Layout
///
/// - Bits  0..31: `index` (slot in the channel table)
/// - Bits 32..63: `generation` (incremented each time a slot is reused)
///
/// # Invariants (for formal verification)
///
/// - `index < MAX_CHANNELS` for every live ChannelId.
/// - Two ChannelIds are equal iff both index and generation match.
/// - A ChannelId whose generation does not match the current slot
///   generation is *stale* and must be rejected by every lookup.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChannelId(u64);

impl ChannelId {
    /// Create a ChannelId from index and generation counter.
    #[inline]
    pub const fn new(index: u32, generation: u32) -> Self {
        ChannelId((index as u64) | ((generation as u64) << 32))
    }

    /// Slot index (array index into the channel table).
    #[inline]
    pub const fn index(&self) -> u32 {
        self.0 as u32
    }

    /// Generation counter (incremented on slot reuse).
    #[inline]
    pub const fn generation(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Raw u64 for syscall wire format.
    #[inline]
    pub const fn as_raw(&self) -> u64 {
        self.0
    }

    /// Reconstruct from raw u64 (syscall boundary).
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        ChannelId(raw)
    }
}

impl core::fmt::Debug for ChannelId {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "ChannelId(idx={}, gen={})", self.index(), self.generation())
    }
}

// ============================================================================
// ChannelRole
// ============================================================================

/// Role of a process in a channel, determining the mapping permissions.
///
/// Per ADR-005 §"Data Channels":
/// - **Producer** creates the channel and gets a RW mapping (writes data).
/// - **Consumer** attaches and gets a RO mapping (reads data).
/// - **Bidirectional** gives both sides RW (rare, explicit opt-in).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRole {
    /// Creator writes, peer reads. Creator mapping = RW, peer = RO.
    Producer = 0,
    /// Creator reads, peer writes. Creator mapping = RO, peer = RW.
    Consumer = 1,
    /// Both sides RW. Explicit opt-in for bidirectional data flow.
    Bidirectional = 2,
}

impl ChannelRole {
    /// Convert from raw u32 (syscall boundary).
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(ChannelRole::Producer),
            1 => Some(ChannelRole::Consumer),
            2 => Some(ChannelRole::Bidirectional),
            _ => None,
        }
    }

    /// Whether the creator side has write access.
    pub const fn creator_writable(&self) -> bool {
        match self {
            ChannelRole::Producer => true,
            ChannelRole::Consumer => false,
            ChannelRole::Bidirectional => true,
        }
    }

    /// Whether the peer side has write access.
    pub const fn peer_writable(&self) -> bool {
        match self {
            ChannelRole::Producer => false,
            ChannelRole::Consumer => true,
            ChannelRole::Bidirectional => true,
        }
    }
}

// ============================================================================
// ChannelState
// ============================================================================

/// Channel lifecycle state machine.
///
/// Transitions are strictly forward:
/// `AwaitingAttach → Active → {Closed, Revoked}`
///
/// `AwaitingAttach` can also transition directly to `Closed` (if the
/// creator closes before the peer attaches) or `Revoked` (if a third
/// party revokes before attach).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Created by one process, awaiting the peer's `SYS_CHANNEL_ATTACH`.
    AwaitingAttach,
    /// Both processes attached, data can flow.
    Active,
    /// Force-closed by a third party (revocation or process exit).
    Revoked,
    /// Gracefully closed by one of the channel's endpoints.
    Closed,
}

// ============================================================================
// ChannelError
// ============================================================================

/// Errors from channel operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// No free slots in the channel table.
    TableFull,
    /// The ChannelId does not refer to a valid channel (index out of
    /// range or generation mismatch).
    NotFound,
    /// The channel is not in the expected state for this operation.
    InvalidState,
    /// The caller's Principal does not match the named peer.
    PrincipalMismatch,
    /// Frame allocator failed to provide the requested pages.
    AllocationFailed,
    /// Page table mapping failed.
    MappingFailed,
    /// The requested size is invalid (0, not page-aligned, exceeds cap).
    InvalidSize,
    /// The channel is already attached by the peer.
    AlreadyAttached,
    /// Permission denied (wrong authority for close/revoke).
    PermissionDenied,
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::TableFull => write!(f, "Channel table full"),
            Self::NotFound => write!(f, "Channel not found"),
            Self::InvalidState => write!(f, "Channel in invalid state for operation"),
            Self::PrincipalMismatch => write!(f, "Principal does not match channel peer"),
            Self::AllocationFailed => write!(f, "Channel memory allocation failed"),
            Self::MappingFailed => write!(f, "Channel page mapping failed"),
            Self::InvalidSize => write!(f, "Invalid channel size"),
            Self::AlreadyAttached => write!(f, "Channel already attached"),
            Self::PermissionDenied => write!(f, "Permission denied"),
        }
    }
}

// ============================================================================
// ChannelRecord
// ============================================================================

/// Per-channel kernel state. Stored in the ChannelManager's table.
///
/// # Invariants (for formal verification)
///
/// - `physical_base` is page-aligned and was allocated via
///   `FrameAllocator::allocate_contiguous(num_pages)`.
/// - `num_pages >= MIN_CHANNEL_PAGES && num_pages <= MAX_CHANNEL_PAGES`.
/// - `creator_pid` is a valid ProcessId at the time of creation.
/// - `peer_pid` is `None` until ATTACH, then a valid ProcessId.
/// - State transitions are strictly forward: AwaitingAttach → Active →
///   {Closed, Revoked}. No backward transitions.
/// - `creator_vaddr` and `peer_vaddr` are page-aligned user-space
///   addresses within the respective process's VMA tracker, or 0 if
///   not yet mapped.
#[derive(Debug)]
pub struct ChannelRecord {
    /// Unique identifier (index + generation).
    pub id: ChannelId,
    /// Current lifecycle state.
    pub state: ChannelState,
    /// Data flow direction / access permissions.
    pub role: ChannelRole,
    /// Principal of the creator (set at create time, immutable).
    pub creator_principal: Principal,
    /// Principal of the intended peer (set at create time, immutable).
    pub peer_principal: Principal,
    /// Creator's ProcessId (for unmap on close/revoke).
    pub creator_pid: ProcessId,
    /// Peer's ProcessId (set on attach, None until then).
    pub peer_pid: Option<ProcessId>,
    /// Physical base address of the shared memory region.
    pub physical_base: u64,
    /// Size of the shared region in 4 KiB pages.
    pub num_pages: u32,
    /// Virtual address mapped in creator's address space.
    pub creator_vaddr: u64,
    /// Virtual address mapped in peer's address space (0 until attach).
    pub peer_vaddr: u64,
    /// Tick at which the channel was created (for telemetry).
    pub created_at_tick: u64,
}

/// Parameters for [`ChannelManager::create`].
///
/// Groups the arguments that describe a new channel. The syscall
/// handler builds this after physical allocation + VMA mapping, then
/// passes it to `create` for bookkeeping.
pub struct ChannelCreateParams {
    pub creator_principal: Principal,
    pub peer_principal: Principal,
    pub creator_pid: ProcessId,
    pub role: ChannelRole,
    pub num_pages: u32,
    pub physical_base: u64,
    pub creator_vaddr: u64,
    pub created_at_tick: u64,
}

// ============================================================================
// ChannelManager
// ============================================================================

/// Channel manager — manages the global channel table.
///
/// Pure bookkeeping: tracks channel records, enforces state transitions,
/// validates principals. Does NOT allocate frames, map pages, or perform
/// TLB shootdowns — those are the syscall handler's responsibility.
///
/// Lock position: 5 in the global hierarchy (Phase 3.2d.iii).
/// Stored in `Spinlock<Option<Box<ChannelManager>>>`.
pub struct ChannelManager {
    /// Channel table. `None` = free slot.
    channels: [Option<ChannelRecord>; MAX_CHANNELS],
    /// Per-slot generation counter. Incremented when a slot is freed
    /// (close or revoke), so stale ChannelIds are rejected.
    generations: [u32; MAX_CHANNELS],
    /// Number of slots currently occupied (Active or AwaitingAttach).
    count: usize,
}

impl Default for ChannelManager {
    fn default() -> Self { Self::new() }
}

impl ChannelManager {
    /// Create an empty channel manager.
    pub const fn new() -> Self {
        ChannelManager {
            channels: [const { None }; MAX_CHANNELS],
            generations: [0u32; MAX_CHANNELS],
            count: 0,
        }
    }

    /// Number of active channels.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Number of slots in the table.
    #[inline]
    pub const fn capacity(&self) -> usize {
        MAX_CHANNELS
    }

    /// Find a free slot by linear scan.
    fn find_free_slot(&self) -> Option<usize> {
        self.channels.iter().position(|slot| slot.is_none())
    }

    /// Look up a channel by ChannelId, with generation validation.
    fn lookup(&self, id: ChannelId) -> Result<&ChannelRecord, ChannelError> {
        let idx = id.index() as usize;
        if idx >= MAX_CHANNELS {
            return Err(ChannelError::NotFound);
        }
        let record = self.channels[idx]
            .as_ref()
            .ok_or(ChannelError::NotFound)?;
        if record.id != id {
            return Err(ChannelError::NotFound);
        }
        Ok(record)
    }

    /// Mutable variant of [`lookup`].
    fn lookup_mut(&mut self, id: ChannelId) -> Result<&mut ChannelRecord, ChannelError> {
        let idx = id.index() as usize;
        if idx >= MAX_CHANNELS {
            return Err(ChannelError::NotFound);
        }
        let record = self.channels[idx]
            .as_mut()
            .ok_or(ChannelError::NotFound)?;
        if record.id != id {
            return Err(ChannelError::NotFound);
        }
        Ok(record)
    }

    /// Create a new channel record in `AwaitingAttach` state.
    ///
    /// The caller (syscall handler) is responsible for:
    /// 1. Allocating physical frames via `FrameAllocator::allocate_contiguous`
    /// 2. Mapping those frames into the creator's address space
    /// 3. Passing the resulting `physical_base` and `creator_vaddr` here
    ///
    /// This method only does bookkeeping: finds a slot, writes the record,
    /// returns the ChannelId. If this returns `Err`, the caller must unwind
    /// its frame allocation and VMA reservation.
    pub fn create(
        &mut self,
        params: ChannelCreateParams,
    ) -> Result<ChannelId, ChannelError> {
        if !(MIN_CHANNEL_PAGES..=MAX_CHANNEL_PAGES).contains(&params.num_pages) {
            return Err(ChannelError::InvalidSize);
        }

        let idx = self.find_free_slot().ok_or(ChannelError::TableFull)?;
        let generation = self.generations[idx];
        let id = ChannelId::new(idx as u32, generation);

        self.channels[idx] = Some(ChannelRecord {
            id,
            state: ChannelState::AwaitingAttach,
            role: params.role,
            creator_principal: params.creator_principal,
            peer_principal: params.peer_principal,
            creator_pid: params.creator_pid,
            peer_pid: None,
            physical_base: params.physical_base,
            num_pages: params.num_pages,
            creator_vaddr: params.creator_vaddr,
            peer_vaddr: 0,
            created_at_tick: params.created_at_tick,
        });
        self.count += 1;

        Ok(id)
    }

    /// Transition a channel from `AwaitingAttach` to `Active`.
    ///
    /// Validates that:
    /// - The channel exists and generation matches
    /// - The channel is in `AwaitingAttach` state
    /// - The `peer_principal` matches what was specified at create time
    ///
    /// The caller is responsible for mapping pages into the peer's address
    /// space and passing the resulting `peer_vaddr` here.
    ///
    /// Returns a reference to the updated record on success.
    pub fn attach(
        &mut self,
        channel_id: ChannelId,
        peer_principal: Principal,
        peer_pid: ProcessId,
        peer_vaddr: u64,
    ) -> Result<&ChannelRecord, ChannelError> {
        let record = self.lookup_mut(channel_id)?;

        if record.state != ChannelState::AwaitingAttach {
            return Err(ChannelError::InvalidState);
        }
        if record.peer_pid.is_some() {
            return Err(ChannelError::AlreadyAttached);
        }
        if record.peer_principal != peer_principal {
            return Err(ChannelError::PrincipalMismatch);
        }

        record.peer_pid = Some(peer_pid);
        record.peer_vaddr = peer_vaddr;
        record.state = ChannelState::Active;

        // Re-borrow as shared (the mutable borrow above is consumed by
        // the state mutation; this re-borrow is valid because we return
        // a shared reference).
        Ok(self.channels[channel_id.index() as usize]
            .as_ref()
            .expect("channel was just set to Some"))
    }

    /// Close a channel gracefully.
    ///
    /// Either the creator or the peer may close. The channel must be in
    /// `AwaitingAttach` or `Active` state.
    ///
    /// Returns the full `ChannelRecord` so the caller can unmap pages
    /// from both processes' address spaces and free the physical frames.
    /// The slot is freed (set to `None`) and the generation incremented.
    pub fn close(
        &mut self,
        channel_id: ChannelId,
        caller_pid: ProcessId,
    ) -> Result<ChannelRecord, ChannelError> {
        let record = self.lookup_mut(channel_id)?;

        match record.state {
            ChannelState::AwaitingAttach | ChannelState::Active => {}
            ChannelState::Closed | ChannelState::Revoked => {
                return Err(ChannelError::InvalidState);
            }
        }

        // Verify the caller is one of the channel's endpoints.
        let is_creator = record.creator_pid == caller_pid;
        let is_peer = record.peer_pid == Some(caller_pid);
        if !is_creator && !is_peer {
            return Err(ChannelError::PermissionDenied);
        }

        // Take the record out, mark it Closed, free the slot.
        let idx = channel_id.index() as usize;
        let mut taken = self.channels[idx]
            .take()
            .expect("lookup_mut succeeded, so slot is Some");
        taken.state = ChannelState::Closed;
        self.count -= 1;
        self.generations[idx] = self.generations[idx].wrapping_add(1);

        Ok(taken)
    }

    /// Force-close (revoke) a channel.
    ///
    /// Unlike `close()`, this does not check caller identity — it is
    /// used by process exit cleanup and by the bootstrap/policy
    /// authority path. The caller is responsible for authority checks
    /// before calling this.
    ///
    /// Returns the full `ChannelRecord` for the caller to perform
    /// unmap + frame free. The slot is freed and generation incremented.
    pub fn revoke(
        &mut self,
        channel_id: ChannelId,
    ) -> Result<ChannelRecord, ChannelError> {
        // Verify the channel exists and generation matches.
        let _ = self.lookup(channel_id)?;

        let idx = channel_id.index() as usize;
        let mut taken = self.channels[idx]
            .take()
            .expect("lookup succeeded, so slot is Some");

        match taken.state {
            ChannelState::Closed | ChannelState::Revoked => {
                // Put it back — already terminal.
                self.channels[idx] = Some(taken);
                return Err(ChannelError::InvalidState);
            }
            ChannelState::AwaitingAttach | ChannelState::Active => {}
        }

        taken.state = ChannelState::Revoked;
        self.count -= 1;
        self.generations[idx] = self.generations[idx].wrapping_add(1);

        Ok(taken)
    }

    /// Read-only access to a channel record.
    pub fn get(&self, channel_id: ChannelId) -> Result<&ChannelRecord, ChannelError> {
        self.lookup(channel_id)
    }

    /// Revoke all channels involving a given ProcessId (as creator or peer).
    ///
    /// Used by the process exit cleanup path (`handle_exit`). Returns the
    /// list of revoked records so the caller can unmap pages and free
    /// frames for each.
    ///
    /// The returned records have `state = Revoked`. Slots are freed and
    /// generations incremented. The Vec is heap-allocated: returning a
    /// fixed-size `[Option<ChannelRecord>; MAX_CHANNELS]` here would put
    /// tens of KiB on the caller's kernel stack (MAX_CHANNELS × ~140 B),
    /// and with 8 KiB kernel stacks that overflows into adjacent kernel
    /// heap — which held the exiting CPU's scheduler. Heap-allocate.
    pub fn revoke_all_for_process(
        &mut self,
        pid: ProcessId,
    ) -> Vec<ChannelRecord> {
        let mut revoked: Vec<ChannelRecord> = Vec::new();

        for idx in 0..MAX_CHANNELS {
            let dominated = if let Some(record) = &self.channels[idx] {
                let dominated = record.creator_pid == pid
                    || record.peer_pid == Some(pid);
                let terminal = matches!(
                    record.state,
                    ChannelState::Closed | ChannelState::Revoked
                );
                dominated && !terminal
            } else {
                false
            };

            if dominated {
                if let Some(mut taken) = self.channels[idx].take() {
                    taken.state = ChannelState::Revoked;
                    self.count -= 1;
                    self.generations[idx] = self.generations[idx].wrapping_add(1);
                    revoked.push(taken);
                }
            }
        }

        revoked
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

    // -- ChannelId encoding --

    #[test]
    fn test_channel_id_encoding_round_trip() {
        let id = ChannelId::new(42, 7);
        assert_eq!(id.index(), 42);
        assert_eq!(id.generation(), 7);

        let raw = id.as_raw();
        let restored = ChannelId::from_raw(raw);
        assert_eq!(restored, id);
        assert_eq!(restored.index(), 42);
        assert_eq!(restored.generation(), 7);
    }

    #[test]
    fn test_channel_id_generation_zero() {
        let id = ChannelId::new(5, 0);
        assert_eq!(id.index(), 5);
        assert_eq!(id.generation(), 0);
    }

    #[test]
    fn test_channel_id_max_values() {
        let id = ChannelId::new(u32::MAX, u32::MAX);
        assert_eq!(id.index(), u32::MAX);
        assert_eq!(id.generation(), u32::MAX);
    }

    // -- ChannelRole --

    #[test]
    fn test_channel_role_from_u32() {
        assert_eq!(ChannelRole::from_u32(0), Some(ChannelRole::Producer));
        assert_eq!(ChannelRole::from_u32(1), Some(ChannelRole::Consumer));
        assert_eq!(ChannelRole::from_u32(2), Some(ChannelRole::Bidirectional));
        assert_eq!(ChannelRole::from_u32(3), None);
        assert_eq!(ChannelRole::from_u32(u32::MAX), None);
    }

    #[test]
    fn test_channel_role_permissions() {
        assert!(ChannelRole::Producer.creator_writable());
        assert!(!ChannelRole::Producer.peer_writable());

        assert!(!ChannelRole::Consumer.creator_writable());
        assert!(ChannelRole::Consumer.peer_writable());

        assert!(ChannelRole::Bidirectional.creator_writable());
        assert!(ChannelRole::Bidirectional.peer_writable());
    }

    // -- ChannelManager: create --

    fn create_basic(mgr: &mut ChannelManager) -> ChannelId {
        mgr.create(ChannelCreateParams {
            creator_principal: test_principal(0xAA),
            peer_principal: test_principal(0xBB),
            creator_pid: test_pid(1),
            role: ChannelRole::Producer,
            num_pages: 4,
            physical_base: 0x100_0000,
            creator_vaddr: 0x1000_0000,
            created_at_tick: 100,
        })
        .unwrap()
    }

    #[test]
    fn test_create_basic() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        assert_eq!(id.index(), 0);
        assert_eq!(id.generation(), 0);
        assert_eq!(mgr.count(), 1);

        let record = mgr.get(id).unwrap();
        assert_eq!(record.state, ChannelState::AwaitingAttach);
        assert_eq!(record.role, ChannelRole::Producer);
        assert_eq!(record.creator_principal, test_principal(0xAA));
        assert_eq!(record.peer_principal, test_principal(0xBB));
        assert_eq!(record.creator_pid, test_pid(1));
        assert_eq!(record.peer_pid, None);
        assert_eq!(record.num_pages, 4);
        assert_eq!(record.physical_base, 0x100_0000);
        assert_eq!(record.creator_vaddr, 0x1000_0000);
        assert_eq!(record.peer_vaddr, 0);
        assert_eq!(record.created_at_tick, 100);
    }

    #[test]
    fn test_create_returns_unique_ids() {
        let mut mgr = ChannelManager::new();
        let id1 = create_basic(&mut mgr);
        let id2 = mgr
            .create(ChannelCreateParams {
                creator_principal: test_principal(0xCC),
                peer_principal: test_principal(0xDD),
                creator_pid: test_pid(2),
                role: ChannelRole::Consumer,
                num_pages: 1,
                physical_base: 0x200_0000,
                creator_vaddr: 0x2000_0000,
                created_at_tick: 200,
            })
            .unwrap();

        assert_ne!(id1, id2);
        assert_eq!(id1.index(), 0);
        assert_eq!(id2.index(), 1);
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn test_create_table_full() {
        let mut mgr = ChannelManager::new();
        for i in 0..MAX_CHANNELS {
            mgr.create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xBB),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: 1,
                physical_base: (i as u64) * 0x1000,
                creator_vaddr: 0x1000_0000 + (i as u64) * 0x1000,
                created_at_tick: 0,
            })
            .unwrap();
        }

        assert_eq!(mgr.count(), MAX_CHANNELS);
        assert_eq!(
            mgr.create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xBB),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: 1,
                physical_base: 0xDEAD_0000,
                creator_vaddr: 0x9000_0000,
                created_at_tick: 0,
            })
            .err(),
            Some(ChannelError::TableFull)
        );
    }

    #[test]
    fn test_create_invalid_size_zero() {
        let mut mgr = ChannelManager::new();
        assert_eq!(
            mgr.create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xBB),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: 0,
                physical_base: 0x100_0000,
                creator_vaddr: 0x1000_0000,
                created_at_tick: 0,
            })
            .err(),
            Some(ChannelError::InvalidSize)
        );
    }

    #[test]
    fn test_create_invalid_size_exceeds_cap() {
        let mut mgr = ChannelManager::new();
        assert_eq!(
            mgr.create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xBB),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: MAX_CHANNEL_PAGES + 1,
                physical_base: 0x100_0000,
                creator_vaddr: 0x1000_0000,
                created_at_tick: 0,
            })
            .err(),
            Some(ChannelError::InvalidSize)
        );
    }

    /// Exercises the new 256 MiB (65536-page) ceiling raised for the v1
    /// endgame graphics target (ADR-011). A create at exactly
    /// `MAX_CHANNEL_PAGES` must be accepted — anything less means the
    /// ceiling isn't actually reachable.
    #[test]
    fn test_create_at_max_pages_succeeds() {
        let mut mgr = ChannelManager::new();
        let id = mgr
            .create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xBB),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: MAX_CHANNEL_PAGES,
                physical_base: 0x100_0000,
                creator_vaddr: 0x1000_0000,
                created_at_tick: 0,
            })
            .unwrap();
        let record = mgr.get(id).unwrap();
        assert_eq!(record.num_pages, MAX_CHANNEL_PAGES);
    }

    // -- ChannelManager: attach --

    #[test]
    fn test_attach_basic() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        let record = mgr
            .attach(id, test_principal(0xBB), test_pid(2), 0x2000_0000)
            .unwrap();
        assert_eq!(record.state, ChannelState::Active);
        assert_eq!(record.peer_pid, Some(test_pid(2)));
        assert_eq!(record.peer_vaddr, 0x2000_0000);
    }

    #[test]
    fn test_attach_wrong_principal() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        assert_eq!(
            mgr.attach(id, test_principal(0xFF), test_pid(2), 0x2000_0000)
                .err(),
            Some(ChannelError::PrincipalMismatch)
        );
        // Channel still in AwaitingAttach.
        assert_eq!(mgr.get(id).unwrap().state, ChannelState::AwaitingAttach);
    }

    #[test]
    fn test_attach_wrong_state() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        // Attach once (succeeds).
        mgr.attach(id, test_principal(0xBB), test_pid(2), 0x2000_0000)
            .unwrap();

        // Attach again — channel is Active, not AwaitingAttach.
        assert_eq!(
            mgr.attach(id, test_principal(0xBB), test_pid(3), 0x3000_0000)
                .err(),
            Some(ChannelError::InvalidState)
        );
    }

    #[test]
    fn test_attach_not_found() {
        let mgr = ChannelManager::new();
        let bogus = ChannelId::new(99, 0);
        assert_eq!(
            mgr.get(bogus).err(),
            Some(ChannelError::NotFound)
        );
    }

    #[test]
    fn test_attach_stale_generation() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        // Close the channel (frees the slot, bumps generation).
        mgr.close(id, test_pid(1)).unwrap();

        // Try to attach with the old ChannelId — stale generation.
        assert_eq!(
            mgr.attach(id, test_principal(0xBB), test_pid(2), 0x2000_0000)
                .err(),
            Some(ChannelError::NotFound)
        );
    }

    // -- ChannelManager: close --

    #[test]
    fn test_close_by_creator() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        let record = mgr.close(id, test_pid(1)).unwrap();
        assert_eq!(record.state, ChannelState::Closed);
        assert_eq!(mgr.count(), 0);
        // Slot is freed — lookup with old id fails.
        assert_eq!(mgr.get(id).err(), Some(ChannelError::NotFound));
    }

    #[test]
    fn test_close_by_peer() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);
        mgr.attach(id, test_principal(0xBB), test_pid(2), 0x2000_0000)
            .unwrap();

        let record = mgr.close(id, test_pid(2)).unwrap();
        assert_eq!(record.state, ChannelState::Closed);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_close_awaiting_attach() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        // Creator closes before peer attaches — valid.
        let record = mgr.close(id, test_pid(1)).unwrap();
        assert_eq!(record.state, ChannelState::Closed);
    }

    #[test]
    fn test_close_by_stranger_rejected() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        // PID 99 is neither creator nor peer.
        assert_eq!(
            mgr.close(id, test_pid(99)).err(),
            Some(ChannelError::PermissionDenied)
        );
        // Channel still exists.
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_close_already_closed() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);
        mgr.close(id, test_pid(1)).unwrap();

        // Second close — slot is freed, generation bumped, old id is stale.
        assert_eq!(mgr.close(id, test_pid(1)).err(), Some(ChannelError::NotFound));
    }

    // -- ChannelManager: revoke --

    #[test]
    fn test_revoke_active() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);
        mgr.attach(id, test_principal(0xBB), test_pid(2), 0x2000_0000)
            .unwrap();

        let record = mgr.revoke(id).unwrap();
        assert_eq!(record.state, ChannelState::Revoked);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_revoke_awaiting_attach() {
        let mut mgr = ChannelManager::new();
        let id = create_basic(&mut mgr);

        let record = mgr.revoke(id).unwrap();
        assert_eq!(record.state, ChannelState::Revoked);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_revoke_not_found() {
        let mut mgr = ChannelManager::new();
        assert_eq!(
            mgr.revoke(ChannelId::new(0, 0)).err(),
            Some(ChannelError::NotFound)
        );
    }

    // -- ChannelManager: slot reuse + generation --

    #[test]
    fn test_slot_reuse_with_generation() {
        let mut mgr = ChannelManager::new();
        let id1 = create_basic(&mut mgr);
        assert_eq!(id1.index(), 0);
        assert_eq!(id1.generation(), 0);

        // Close frees the slot and bumps generation.
        mgr.close(id1, test_pid(1)).unwrap();
        assert_eq!(mgr.count(), 0);

        // Next create reuses slot 0 with generation 1.
        let id2 = create_basic(&mut mgr);
        assert_eq!(id2.index(), 0);
        assert_eq!(id2.generation(), 1);
        assert_ne!(id1, id2);

        // Old id1 is stale.
        assert_eq!(mgr.get(id1).err(), Some(ChannelError::NotFound));
        // New id2 works.
        assert_eq!(mgr.get(id2).unwrap().state, ChannelState::AwaitingAttach);
    }

    // -- ChannelManager: revoke_all_for_process --

    #[test]
    fn test_revoke_all_for_process_as_creator() {
        let mut mgr = ChannelManager::new();
        let _id1 = mgr
            .create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xBB),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: 1,
                physical_base: 0x100_0000,
                creator_vaddr: 0x1000_0000,
                created_at_tick: 0,
            })
            .unwrap();
        let _id2 = mgr
            .create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xCC),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: 2,
                physical_base: 0x200_0000,
                creator_vaddr: 0x2000_0000,
                created_at_tick: 0,
            })
            .unwrap();
        // A channel owned by someone else.
        let _id3 = mgr
            .create(ChannelCreateParams {
                creator_principal: test_principal(0xDD),
                peer_principal: test_principal(0xEE),
                creator_pid: test_pid(3),
                role: ChannelRole::Producer,
                num_pages: 1,
                physical_base: 0x300_0000,
                creator_vaddr: 0x3000_0000,
                created_at_tick: 0,
            })
            .unwrap();
        assert_eq!(mgr.count(), 3);

        let revoked = mgr.revoke_all_for_process(test_pid(1));
        assert_eq!(revoked.len(), 2);
        assert_eq!(revoked[0].state, ChannelState::Revoked);
        assert_eq!(revoked[1].state, ChannelState::Revoked);
        // The third channel (owned by pid 3) is untouched.
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_revoke_all_for_process_as_peer() {
        let mut mgr = ChannelManager::new();
        let id = mgr
            .create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xBB),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: 1,
                physical_base: 0x100_0000,
                creator_vaddr: 0x1000_0000,
                created_at_tick: 0,
            })
            .unwrap();
        mgr.attach(id, test_principal(0xBB), test_pid(2), 0x2000_0000)
            .unwrap();
        assert_eq!(mgr.count(), 1);

        // Revoke all for the peer (pid 2).
        let revoked = mgr.revoke_all_for_process(test_pid(2));
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].state, ChannelState::Revoked);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_revoke_all_for_process_empty() {
        let mut mgr = ChannelManager::new();
        let revoked = mgr.revoke_all_for_process(test_pid(99));
        assert_eq!(revoked.len(), 0);
    }

    #[test]
    fn test_revoke_all_for_process_preserves_others() {
        let mut mgr = ChannelManager::new();
        let _victim = mgr
            .create(ChannelCreateParams {
                creator_principal: test_principal(0xAA),
                peer_principal: test_principal(0xBB),
                creator_pid: test_pid(1),
                role: ChannelRole::Producer,
                num_pages: 1,
                physical_base: 0x100_0000,
                creator_vaddr: 0x1000_0000,
                created_at_tick: 0,
            })
            .unwrap();
        let bystander = mgr
            .create(ChannelCreateParams {
                creator_principal: test_principal(0xCC),
                peer_principal: test_principal(0xDD),
                creator_pid: test_pid(3),
                role: ChannelRole::Producer,
                num_pages: 1,
                physical_base: 0x200_0000,
                creator_vaddr: 0x2000_0000,
                created_at_tick: 0,
            })
            .unwrap();
        assert_eq!(mgr.count(), 2);

        mgr.revoke_all_for_process(test_pid(1));

        // Bystander untouched.
        assert_eq!(mgr.count(), 1);
        assert_eq!(
            mgr.get(bystander).unwrap().state,
            ChannelState::AwaitingAttach
        );
    }
}
