// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS syscall ABI surface.
//!
//! This is the contract layer between the kernel and userspace:
//! `SyscallNumber` (the wire-stable enumeration of every syscall),
//! `SyscallError` (the negative-return error codes), `SyscallArgs`
//! (the abstract 6-arg shape that arch-specific entry stubs decode
//! into), and `SyscallResult` (the kernel-side handler return type).
//!
//! Both the kernel (`cambios`) and userspace libsys (`cambios-libsys`)
//! depend on this crate so there is exactly one source of truth for
//! syscall numbering. Drift between userspace and kernel ABI tables
//! is the failure mode this crate exists to remove.
//!
//! # Stability
//!
//! Syscall numbers are *permanent*. Once a slot is assigned (or
//! reserved per ADR), it is never reused. New syscalls take the next
//! free slot above the current high-water mark. This file is the
//! enforcement point — adding a variant here requires the matching
//! `from_u64` arm and (per the test suite below) round-trip
//! coverage.
//!
//! `no_std`, no dependencies. Permissively licensed (MPL-2.0) so
//! non-Rust / non-AGPL clients can consume the contract without
//! licensing friction.
//!
//! # `[u8; 32]` for Principal values
//!
//! Several ABI types in this crate carry Principal-shaped fields as raw
//! `[u8; 32]` rather than a typed `Principal` newtype. The kernel's
//! `Principal` lives in `src/ipc/mod.rs` and has not yet been promoted
//! to this crate per ADR-024 § Open Questions row 2 ("a stable
//! Principal representation"). Until that promotion lands, content
//! hashes and Principal AIDs share the same raw shape; the field name
//! (`hash` vs `principal` vs `owner`) is the distinguisher. Replace
//! when ADR-024 Open Questions row 2 closes.

#![cfg_attr(not(test), no_std)]

/// Syscall numbers — must match userspace convention.
///
/// `repr(u64)` is the wire ABI: the value the architecture-specific
/// entry stub places in the syscall-number register (RAX on x86-64,
/// X8 on AArch64, A7 on RISC-V) maps directly to a variant via
/// [`SyscallNumber::from_u64`].
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    /// exit(code: i32) -> !
    /// Terminate the calling process
    Exit = 0,

    /// write(endpoint: u32, buffer: *const u8, len: usize) -> isize
    /// Send data through an endpoint
    Write = 1,

    /// read(endpoint: u32, buffer: *mut u8, len: usize) -> isize
    /// Receive data from an endpoint
    Read = 2,

    /// allocate(size: usize, flags: u32) -> *mut u8
    /// Allocate memory for this process
    Allocate = 3,

    /// free(ptr: *mut u8, size: usize) -> i32
    /// Free previously allocated memory
    Free = 4,

    /// wait_irq(irq_number: u32) -> i32
    /// Wait for a specific interrupt to fire
    WaitIrq = 5,

    /// register_endpoint(endpoint_id: u32, flags: u32) -> i32
    /// Register a message endpoint
    RegisterEndpoint = 6,

    /// yield_cpu() -> i32
    /// Voluntarily yield to scheduler
    Yield = 7,

    /// get_pid() -> u32
    /// Get current process ID
    GetPid = 8,

    /// get_time() -> u64
    /// Get current system time (ticks)
    GetTime = 9,

    /// print(buffer: *const u8, len: usize) -> isize
    /// Print a string to the kernel serial console (for debugging)
    Print = 10,

    /// bind_principal(process_id: u32, pubkey_ptr: *const u8, pubkey_len: u32) -> i32
    /// Bind a cryptographic Principal to a process. Restricted to the bootstrap
    /// Principal (identity service). pubkey_len must be 32.
    BindPrincipal = 11,

    /// get_principal(out_buf: *mut u8, buf_len: u32) -> i32
    /// Read the calling process's bound Principal (32-byte public key).
    /// Returns 32 on success, or error if no Principal is bound.
    GetPrincipal = 12,

    /// recv_msg(endpoint: u32, buf: *mut u8, buf_len: usize) -> isize
    /// Receive an IPC message with sender identity.
    /// Writes to buf: [sender_principal:32][from_endpoint:4][payload:N]
    /// Returns total bytes written (>= 36), 0 if no message, or negative error.
    RecvMsg = 13,

    /// obj_put(content_ptr: *const u8, content_len: usize, out_hash: *mut u8) -> isize
    /// Store a CambiObject. Author/owner = caller's Principal.
    /// Writes 32-byte content hash to out_hash. Returns 0 or negative error.
    ObjPut = 14,

    /// obj_get(hash_ptr: *const u8, out_buf: *mut u8, out_buf_len: usize) -> isize
    /// Retrieve object content by hash. Returns bytes written or negative error.
    ObjGet = 15,

    /// obj_delete(hash_ptr: *const u8) -> isize
    /// Delete an object. Only the owner can delete. Returns 0 or negative error.
    ObjDelete = 16,

    /// obj_list(out_buf: *mut u8, out_buf_len: usize) -> isize
    /// List object hashes. Writes packed 32-byte hashes. Returns count of objects.
    ObjList = 17,

    /// claim_bootstrap_key(out_sk_ptr: *mut u8) -> isize
    /// One-shot: writes the 64-byte bootstrap Ed25519 secret key to the caller's
    /// buffer and zeroes the kernel's copy. Restricted to bootstrap Principal.
    /// Returns 64 on success, negative error if already claimed or unauthorized.
    ClaimBootstrapKey = 18,

    /// obj_put_signed(content_ptr: *const u8, content_len: usize, sig_ptr: *const u8, out_hash: *mut u8) -> isize
    /// Store a pre-signed CambiObject. Kernel verifies the Ed25519 signature
    /// against the caller's Principal before storing. Returns 0 or negative error.
    ObjPutSigned = 19,

    /// map_mmio(phys_addr: u64, num_pages: u32) -> u64
    /// Map device MMIO into the calling process's address space with uncacheable
    /// attributes. Returns user-space virtual address, or negative error.
    /// Kernel validates the physical address is not in RAM regions.
    MapMmio = 20,

    /// alloc_dma(num_pages: u32, flags: u32) -> (vaddr: u64, paddr: u64)
    /// Allocate physically contiguous DMA-capable pages with guard pages on
    /// both sides. Returns user vaddr in the return value, writes paddr to
    /// the u64 pointed to by arg3. Flags reserved for future IOMMU hints.
    AllocDma = 21,

    /// device_info(index: u32, out_buf: *mut u8, buf_len: u32) -> i32
    /// Query PCI device info by index. Writes a fixed-format device descriptor
    /// to out_buf. Returns 0 on success, negative error if index out of range.
    DeviceInfo = 22,

    /// port_io(port: u16, value: u32, flags: u32) -> u32
    /// Read or write an x86 I/O port. The kernel validates the port is within
    /// a PCI device's I/O BAR range.
    /// flags bit 0: direction (0=read, 1=write)
    /// flags bits 2:1: width (0=byte, 1=word, 2=dword)
    /// Returns: read value (for reads), 0 (for writes), or negative error.
    PortIo = 23,

    /// console_read(buf: *mut u8, max_len: usize) -> isize
    /// Read bytes from the serial console into buf. Returns the number of
    /// bytes read (0 if no data available). Non-blocking (polling mode).
    ConsoleRead = 24,

    /// spawn(name_ptr: *const u8, name_len: usize) -> isize
    /// Spawn a boot module by name. Returns the new task ID on success,
    /// or negative error. The spawned task's parent is the caller.
    Spawn = 25,

    /// wait_task(child_task_id: u32) -> isize
    /// Block until the specified child task exits. Returns the child's
    /// exit code. Only the parent (spawner) can wait on a child.
    WaitTask = 26,

    /// revoke_capability(target_process_id: u32, endpoint_id: u32) -> i32
    /// Revoke a capability held by another process on a given endpoint.
    /// Per ADR-007 §"Who can revoke", Phase 3.1 restricts this to the bootstrap
    /// Principal; other authority paths (original grantor, holder of `revoke`
    /// right, policy service) land in Phase 3.4.
    ///
    /// Args are `(target_process_id, endpoint_id)` in Phase 3.1 for simplicity.
    /// Phase 3.2d refactors this to a single `CapabilityHandle` once channels
    /// force a system-wide capability registry into existence.
    ///
    /// Returns 0 on success, negative error code on failure.
    RevokeCapability = 27,

    /// channel_create(size_pages: u32, peer_principal_ptr: *const u8, role: u32,
    ///                out_vaddr_ptr: *mut u64) -> i64
    /// Create a shared-memory channel with `size_pages` pages. The peer's
    /// 32-byte Principal is read from `peer_principal_ptr`. `role` selects
    /// Producer(0)/Consumer(1)/Bidirectional(2). The creator's mapping
    /// virtual address is written to `out_vaddr_ptr`. Returns the ChannelId
    /// (>= 0) on success, or a negative error code.
    /// Requires `CreateChannel` system capability.
    ChannelCreate = 28,

    /// channel_attach(channel_id: u64) -> i64
    /// Attach to an existing channel as the named peer. Kernel verifies
    /// the caller's Principal matches the peer_principal specified at
    /// create time. Returns the user-space virtual address of the shared
    /// region on success, or a negative error code.
    ChannelAttach = 29,

    /// channel_close(channel_id: u64) -> i32
    /// Close a channel. Unmaps the shared region from both processes,
    /// issues TLB shootdown, and frees the physical pages. Only the
    /// creator or peer may call this. Returns 0 on success.
    ChannelClose = 30,

    /// channel_revoke(channel_id: u64) -> i32
    /// Force-close a channel from a third party (bootstrap/policy
    /// authority). Same teardown as close but no caller-identity check.
    /// Returns 0 on success.
    ChannelRevoke = 31,

    /// channel_info(channel_id: u64, out_buf: *mut u8, buf_len: u32) -> i32
    /// Read channel metadata (size, state, principals, byte counters)
    /// into a user buffer. Returns 0 on success.
    ChannelInfo = 32,

    /// audit_attach() -> i64
    /// Attach as the audit ring consumer. Maps the kernel's audit ring
    /// pages read-only into the caller's address space. Returns the
    /// user-space virtual address on success.
    /// Capability-gated on `CapabilityKind::AuditConsumer` (ADR-023).
    AuditAttach = 33,

    /// audit_info(out_buf: *mut u8, buf_len: u32) -> i32
    /// Read audit ring statistics (total produced, total dropped,
    /// capacity, consumer attached, per-CPU staging occupancy) into
    /// a user buffer. Any process may call.
    AuditInfo = 34,

    /// map_framebuffer(index: u32, out_desc: *mut u8, desc_len: u32) -> i32
    /// Map a Limine-reported framebuffer (selected by zero-based
    /// `index`) into the calling process and write a 32-byte
    /// `FramebufferDescriptor` to `out_desc`:
    ///   { vaddr: u64, width: u32, height: u32, pitch: u32, bpp: u16,
    ///     red_size: u8, red_shift: u8,
    ///     green_size: u8, green_shift: u8,
    ///     blue_size: u8, blue_shift: u8, _reserved: u8 }
    /// Returns 0 on success.
    /// Capability-gated: requires `CapabilityKind::MapFramebuffer`.
    /// Phase GUI-0 ([ADR-011](docs/adr/011-graphics-architecture-and-scaling.md)).
    MapFramebuffer = 35,
    /// SYS_MODULE_READY (36): signal that this boot module has finished
    /// initialization. The kernel's boot-release chain advances: the next
    /// module in `BOOT_MODULE_ORDER` (if any) is unblocked from
    /// `BlockReason::BootGate` so it can run its own `_start`.
    /// No arguments, no return payload (returns 0).
    /// Intentionally identity-exempt — boot modules can call this before
    /// the rest of the trusted-service chain is up (e.g., key-store
    /// isn't needed for signing a no-op call).
    ModuleReady = 36,
    /// SYS_TRY_RECV_MSG (37): non-blocking variant of RecvMsg. Returns 0
    /// immediately if no message is queued, instead of parking the task
    /// on `MessageWait(endpoint)`. Required for services that must poll
    /// multiple endpoints (e.g., virtio-blk: ep24 user, ep26 kernel) —
    /// blocking recv on one endpoint would miss wakes on the other.
    /// Arg layout matches RecvMsg: arg1=endpoint, arg2=user_buf, arg3=buf_len.
    /// Returns: bytes received (>=36 for header + payload) or 0 if empty.
    TryRecvMsg = 37,

    /// SYS_VIRTIO_MODERN_CAPS (38): return the kernel-parsed virtio-modern
    /// PCI capabilities for a given device index (virtio spec §4.1.4).
    /// Needed by modern virtio-pci drivers (virtio-gpu, future virtio
    /// devices) to discover the (BAR, offset) locations of the common,
    /// notify, ISR, and device-specific config regions without touching
    /// PCI configuration space themselves.
    ///
    /// Args: arg1 = device_index (u32), arg2 = out_buf (user ptr),
    ///       arg3 = buf_len (usize; must equal
    ///              `size_of::<pci::VirtioModernCaps>()` = 64).
    ///
    /// Writes a 64-byte `VirtioModernCaps` structure to `out_buf`.
    /// `caps.present == 0` means the device is not a virtio-modern
    /// device (caller must check before using the cap fields).
    /// Returns 0 on success, negative error on invalid index / buffer.
    ///
    /// Identity-required but not capability-gated: same privacy class
    /// as `DeviceInfo` (information-disclosure only; no MMIO mapping,
    /// no config-space writes). Built on ADR-020 `UserWriteSlice` from
    /// day one.
    VirtioModernCaps = 38,

    /// SYS_SET_WALLCLOCK (39): publish a Unix-seconds baseline + a
    /// trust-source tag describing where the time came from. Only
    /// `udp-stack` holds the gating capability today; future signed-time
    /// services or peer-attestation collectors would also receive it
    /// (ADR-022 § 4 reservation table).
    ///
    /// Args: arg1 = unix_secs (u64), arg2 = source_tag (low byte; see
    ///       ADR-022 § 4 for the canonical tag → trust-source map).
    ///
    /// Capability-gated on `CapabilityKind::SetWallclock`. Anonymous
    /// senders rejected (Frame B identity gate).
    ///
    /// Returns 0 on success, `PermissionDenied` without the capability.
    SetWallclock = 39,

    /// SYS_GET_WALLCLOCK (40): read the current Unix-seconds baseline
    /// projected to "now" via the kernel tick counter. Returns 0
    /// before any successful `SetWallclock` (boot state — display
    /// surfaces fall back to the timeless prompt). Lock-free,
    /// wait-free, callable from any context.
    ///
    /// Joins the unidentified-allowed exempt set alongside
    /// `GetTime` / `GetPid` / `Print`: rendering the clock from a
    /// not-yet-bound boot module is fine, and there is no integrity
    /// surface to protect on a *read* of a value the kernel
    /// already chose to publish.
    ///
    /// No args.
    ///
    /// Returns Unix seconds (u64; 0 = unset sentinel).
    GetWallclock = 40,

    /// SYS_AUDIT_EMIT_INPUT_FOCUS (41): compositor reports a window-focus
    /// transition into the kernel audit ring (T-7 Phase A,
    /// docs/threat-model.md). Lets the audit consumer observe focus
    /// changes — including initial focus and focus loss — so a
    /// focus-hijack attack ("malicious app spawned before key-store
    /// passphrase prompt") leaves a trail.
    ///
    /// Args: arg1 = new_window_id (u32), arg2 = old_window_id (u32; 0
    ///       if no prior focus), arg3 = user vaddr of 32-byte new owner
    ///       Principal (zero bytes when focus was lost).
    ///
    /// Capability-gated on `CapabilityKind::EmitInputAudit`. Granted to
    /// all spawned boot modules today (parallel CreateProcess /
    /// CreateChannel pattern); narrows to compositor-only when an
    /// identity-aware grant flow lands.
    ///
    /// Returns 0 on success, `PermissionDenied` without the capability,
    /// `InvalidArg` on a bad user pointer.
    AuditEmitInputFocus = 41,

    /// SYS_GET_PROCESS_PRINCIPAL (42): resolve a `ProcessId` to its bound
    /// 32-byte Principal. Lets an audit consumer render `subject_pid`
    /// fields from `RawAuditEvent` as `did:key:z6Mk…` without widening
    /// the 64-byte event format.
    ///
    /// Args: arg1 = target ProcessId raw (u64; encodes slot + generation
    ///       per ADR-008), arg2 = out_buf (user ptr to 32-byte buffer),
    ///       arg3 = buf_len (must equal 32).
    ///
    /// Capability-gated on `CapabilityKind::AuditConsumer`. Same gating
    /// posture as `SYS_AUDIT_ATTACH`: if you can read events you can
    /// resolve the principals they reference. Future `ProcessIntrospect`
    /// cap may decouple if a non-audit consumer (GUI window-owner
    /// labeling, win-compat) needs principal lookup without ring access.
    ///
    /// Lookup chain: live process table first (`CapabilityManager::
    /// get_principal`), falls back to a recent-exits ring on the process
    /// table for principals of processes that have already exited but
    /// whose `subject_pid` may still be referenced by buffered events.
    ///
    /// Returns 32 on success (bytes written), `PermissionDenied` without
    /// the capability, or `InvalidArg` on bad user pointer / buf_len /
    /// unknown target (no principal bound to the live process and no
    /// matching entry in the recent-exits ring).
    GetProcessPrincipal = 42,

    /// SYS_CHANNEL_QUIESCE_ACK (43): cooperative ack of a pending
    /// channel revoke (ADR-027 Phase 1 quiesce protocol; ADR-027
    /// Decision 5 — same syscall serves cluster-shaped revoke at
    /// post-HN). Signals to the kernel that the caller has stopped
    /// reading from the channel and the kernel may proceed with the
    /// unmap + TLB shootdown immediately rather than waiting for the
    /// scheduler-side quiesce hook to fire at the next preempt.
    ///
    /// Args: arg1 = channel_id (u64; `ChannelId::as_raw()`).
    ///
    /// Identity-required: yes. Caller must hold a Principal that
    /// matches `record.peer_principal` of the channel being revoked
    /// (the channel must be in `Revoking` state). The kernel then
    /// blocks the caller in `BlockReason::ChannelQuiesceWait` until
    /// `complete_teardown` finishes, at which point the syscall
    /// returns 0.
    ///
    /// Returns 0 on the wake after teardown completes,
    /// `PermissionDenied` without identity / wrong peer Principal,
    /// `InvalidArg` for stale channel id / wrong state.
    ///
    /// In v1 the kernel-side scheduler hook
    /// (`Scheduler::try_park_current_for_quiesce` →
    /// `BlockReason::ChannelQuiesceWait`) catches the peer at next
    /// timer ISR within ≤10ms; userspace cooperation is therefore
    /// optional for correctness. The slot is reserved + handled now
    /// so cluster cooperation (post-HN, ADR-027 Decisions 1-3) plugs
    /// in without needing a new syscall.
    ChannelQuiesceAck = 43,

    /// SYS_CLUSTER_CREATE (44): create a `Forming` cluster from a
    /// `ClusterPolicy` manifest naming expected member Principals and
    /// roles. Caller becomes the cluster's creator and receives a
    /// `ClusterId` for subsequent ops. See [ADR-027](../docs/adr/027-service-clusters.md)
    /// Decision 1 + § Syscalls.
    ///
    /// Caller must hold `CapabilityKind::CreateCluster` (granted to
    /// `init` at boot per ADR-027 § Migration Path step 6 and the
    /// surrounding boot manifest, [ADR-018](../docs/adr/018-init-process-and-boot-manifest.md)).
    ///
    /// Args: TBD with handler implementation. Conceptual shape per
    /// ADR-027 § Architecture: policy + manifest of (Principal, role)
    /// pairs. Wire format (inline vs userspace-pointer-to-params)
    /// lands with the dispatcher commit.
    ///
    /// Returns: ClusterId (`u64` raw form) on success;
    /// `PermissionDenied` without the cap or identity;
    /// `InvalidArg` for an unknown policy or a manifest entry whose
    /// role does not belong to the policy.
    ///
    /// Identity-required: yes. Slot reserved here per ADR-027 § Syscalls
    /// (renumbered from the original 41 reservation per the Divergence
    /// appendix landing in the same chain — slots 41/42/43 already
    /// shipped as `AuditEmitInputFocus` / `GetProcessPrincipal` /
    /// `ChannelQuiesceAck`). Handler lands in the dispatcher migration
    /// commit alongside the cluster-policy + cap-promotion wiring.
    /// Until then the dispatcher returns `Enosys` so userspace cannot
    /// accidentally consume the slot before the protocol is hooked up.
    ClusterCreate = 44,

    /// SYS_CLUSTER_JOIN (45): join a `Forming` or `Active` cluster as
    /// a named role. Kernel verifies the caller's bound Principal
    /// matches the manifest's expected Principal for that role,
    /// transitions the member from `Expected` → `Joined`, and promotes
    /// the role's pre-computed cap set into `ProcessCapabilities`.
    /// Auto-promotes the cluster `Forming` → `Active` when the last
    /// expected member joins.
    ///
    /// Cap promotion is closed-world per ADR-027 Decision 2: each
    /// `(ClusterPolicy, ClusterRole)` pair maps to a fixed cap set
    /// hardcoded in the kernel cluster-policy module. No
    /// caller-supplied cap list — that's the verification-friendly
    /// shape.
    ///
    /// Args: TBD with handler. Conceptual shape: `cluster_id` (u64
    /// raw form) + `role` (u32). Wire format lands with the dispatcher
    /// commit.
    ///
    /// Returns: 0 on success; `PermissionDenied` for Principal
    /// mismatch or absent identity; `InvalidArg` for stale
    /// `cluster_id`, `Revoking`/`Revoked` cluster, an already-joined
    /// role, or a role that has no expected-member slot in the
    /// manifest.
    ///
    /// Identity-required: yes. Slot reserved here per ADR-027 §
    /// Syscalls (renumber per the Divergence appendix). Handler stub
    /// returns `Enosys` until the dispatcher migration commit.
    ClusterJoin = 45,

    /// SYS_CLUSTER_REVOKE (46): tear down an `Active` (or `Forming`)
    /// cluster. Caller must be the cluster's creator or hold
    /// `CapabilityKind::ClusterRevoke` (granted at join to the
    /// coordinator role per ADR-027 Decision 2 — typically the
    /// compositor in the rendering limb).
    ///
    /// Per the v1 stance documented in the ADR-027 Divergence
    /// appendix landing in this chain (path A — advisory quiesce),
    /// cluster revoke composes per-channel revoke and inherits
    /// tombstone-on-revoke semantics from
    /// [ADR-007](../docs/adr/007-capability-revocation-and-telemetry.md)
    /// Divergence 7. The wider quiesce-then-atomic-revoke protocol
    /// from ADR-027 § Decision 3 step 2 becomes load-bearing under
    /// SMP RW peer mappings (post-v1) and is reservable via the
    /// existing `ChannelQuiesceAck = 43`.
    ///
    /// Args: TBD with handler. Conceptual shape: `cluster_id` (u64
    /// raw form).
    ///
    /// Returns: 0 on success; `PermissionDenied` without authority;
    /// `InvalidArg` for stale or already-`Revoked` cluster.
    ///
    /// Identity-required: yes. Slot reserved here per ADR-027 §
    /// Syscalls (renumber per the Divergence appendix). Handler stub
    /// returns `Enosys` until the dispatcher migration commit.
    ClusterRevoke = 46,

    /// SYS_CLUSTER_INFO (47): read cluster metadata (state,
    /// member list, channel ids, policy) into a caller-supplied
    /// buffer. Read-only; does not transition state.
    ///
    /// Args: TBD with handler. Conceptual shape: `cluster_id` (u64),
    /// `user_buf` (u64), `buf_len` (u64). Wire format mirrors
    /// `SYS_CHANNEL_INFO`.
    ///
    /// Returns: bytes written on success; `InvalidArg` for stale
    /// cluster_id or undersize buffer; `PermissionDenied` without
    /// identity.
    ///
    /// Identity-required: yes. Slot reserved here per ADR-027 §
    /// Syscalls (renumber per the Divergence appendix). Handler stub
    /// returns `Enosys` until the dispatcher migration commit.
    ClusterInfo = 47,

    /// SYS_CHANNEL_BEGIN_TEARDOWN (48): start the two-phase teardown
    /// of a channel (ADR-027 Phase 1). Must be paired with a
    /// matching `SYS_CHANNEL_COMPLETE_TEARDOWN` carrying the same
    /// `kind`. The intervening window is when the caller arranges
    /// peer cooperation — for resize, sends a fresh
    /// `WindowResized` to the client; for cluster revoke, walks the
    /// member set; for forced revoke, gives the kernel time to
    /// quiesce the peer task before unmap.
    ///
    /// Args: arg1 = channel_id (u64; `ChannelId::as_raw()`),
    ///       arg2 = kind (u8 in low byte: 0 = Close, 1 = Revoke).
    ///
    /// On `Active` channels the kernel transitions to `Revoking`,
    /// arms quiesce on the peer (parks Running peer at next ISR /
    /// yield, parks Ready peer synchronously, no-op for already-
    /// off-CPU peer), and returns 1 to signal "quiesce in flight".
    /// On `AwaitingAttach` channels (no peer to quiesce) the kernel
    /// short-circuits the slot to the terminal state, runs unmap
    /// inline, and returns 0 — a subsequent `complete_teardown`
    /// is rejected with `InvalidArg` (slot already gone).
    ///
    /// Authority: caller must be the channel's creator or peer
    /// (same shape as `ChannelClose`). Bootstrap-Principal authority
    /// continues to use `ChannelRevoke` (single-phase) for forced
    /// teardown; this two-phase API is for cooperative teardown
    /// initiated by an endpoint.
    ///
    /// Returns: 0 (Immediate, slot already torn down), 1 (Quiesce,
    /// peer arming in flight, must call complete_teardown next),
    /// `PermissionDenied` if not an endpoint, `InvalidArg` for
    /// stale id / wrong state.
    ChannelBeginTeardown = 48,

    /// SYS_CHANNEL_COMPLETE_TEARDOWN (49): finish the two-phase
    /// teardown started by `SYS_CHANNEL_BEGIN_TEARDOWN`. Channel
    /// must be in `Revoking` and the same `kind` must be passed.
    /// The kernel completes the slot transition (terminal state
    /// per `kind`), unmaps both sides via `teardown_channel_mappings`,
    /// frees physical pages, and wakes any task parked in
    /// `Blocked(ChannelQuiesceWait(channel_id))` so it returns from
    /// its `SYS_CHANNEL_QUIESCE_ACK`.
    ///
    /// Args: arg1 = channel_id (u64), arg2 = kind (u8 low byte).
    ///
    /// Authority: same as `ChannelBeginTeardown` — endpoint of the
    /// channel. The `Revoking` state guarantees no other endpoint
    /// can call `attach`/`close`/`revoke` between the two phases.
    ///
    /// Returns: 0 on success, `InvalidArg` for stale id / wrong
    /// state / kind-mismatch.
    ChannelCompleteTeardown = 49,

    /// SYS_CAMBIO (50): seal a POSIX file as a content-addressed
    /// CambiObject (ADR-028 § Decision 3 — the file → object seam).
    ///
    /// Slot reserved here; handler not yet wired. The dispatcher
    /// returns `Enosys` until the seam-syscall migration step lands
    /// per ADR-028 § Migration Path step 6. Same pre-implementation
    /// posture as ADR-022's wallclock pair (commit f045e44).
    ///
    /// Args (per ADR-028 § Decision 3 table): arg1 = `FileDescriptor`
    /// of the source POSIX file, arg2 = optional delegated signing
    /// Principal (0 = caller, current-Principal default per ADR-028
    /// § Open Questions row 3), arg3 = optional parent-hash for
    /// lineage (zero bytes = no lineage), arg4 = flags (bit 0 =
    /// `AndDelete` — non-destructive default per ADR-028 § Open
    /// Questions).
    ///
    /// Returns: 32-byte content hash on success, negative error
    /// otherwise. Snapshot-consistent view of the source per ADR-029's
    /// per-inode CoW (Decision 2); concurrent writes during the seal
    /// go to new blocks via CoW.
    ///
    /// Identity-required: yes. Original ADR draft placed this at slot
    /// 48; renumbered to 50 because ADR-027 two-phase channel teardown
    /// (commit f21d667) landed slots 48/49 between ADR-028's drafting
    /// and ratification.
    Cambio = 50,

    /// SYS_REGALO (51): publish a CambiObject at a user-chosen POSIX
    /// path as a read-only alias (ADR-028 § Decision 3 — the object →
    /// file-view seam).
    ///
    /// Slot reserved here; handler not yet wired (returns `Enosys`).
    /// Sequenced after ADR-029 (the path resolver lives in the POSIX
    /// path-namespace surface per ADR-028 § Migration Path step 7).
    ///
    /// Args (per ADR-028 § Decision 3 table): arg1 = 32-byte object
    /// hash ptr, arg2 = user-chosen path ptr, arg3 = path length.
    ///
    /// Returns: `RegaloId` (revocable, per-process namespace) on
    /// success, negative error otherwise.
    ///
    /// Identity-required: yes. Original ADR draft placed this at slot
    /// 49; renumbered to 51 per the same f21d667 reservation pressure
    /// noted on `Cambio`.
    Regalo = 51,

    /// SYS_STREAM (52): open a Stream cap on a {CambiObject,
    /// FileDescriptor} source per ADR-028 § Decision 3 and ADR-030's
    /// full cap-shape structure.
    ///
    /// Slot reserved here; handler not yet wired (returns `Enosys`).
    /// Sequenced after ADR-030 cap-shape definitions (ADR-028 §
    /// Migration Path step 8).
    ///
    /// Args (per ADR-028 § Decision 3 + ADR-030 § Decision 2):
    /// arg1 = `StreamSource` discriminant + payload (object hash or
    /// FileDescriptor), arg2 = peer Principal ptr, arg3 = pointer to
    /// caller-built `StreamCapShape`.
    ///
    /// Returns: `StreamEndpoint` (Producer side, per ADR-030 §
    /// Decision 3 — Stream is one-way; Bidirectional is structurally
    /// absent) on success, negative error otherwise.
    ///
    /// Identity-required: yes. Original ADR draft placed this at slot
    /// 50; renumbered to 52 per the same f21d667 reservation pressure
    /// noted on `Cambio`.
    Stream = 52,

    // ========================================================================
    // ADR-029 POSIX file storage syscall reservations (slots 53-72)
    // ========================================================================
    //
    // 20 syscalls per ADR-029 § Decision 4: file/directory operations
    // (53-67), metadata (68-69), ACL (70-72). All identity-required.
    // Original ADR draft placed these at 51-70; renumbered to 53-72
    // per ADR-029 § Context — slots 48/49 had shipped as the two-phase
    // channel teardown pair, and slots 50/51/52 went to ADR-028's
    // storage seam syscalls (Cambio / Regalo / Stream), so the
    // POSIX range shifts by 2.
    //
    // Slot reservations only; the dispatcher routes them to
    // Enosys-returning stubs until the POSIX backend lands per ADR-029
    // § Migration Path steps 4-9.
    //
    // The full per-syscall behavior (flags, return values, capability
    // chain) lives in ADR-029 § Decision 4's table; rustdoc here
    // points back rather than duplicating that table.

    /// SYS_FILE_OPEN (53): open a POSIX path for read or write.
    /// Returns a `FileDescriptor` whose `FileBacking` is set by the
    /// path resolver (per ADR-028 § Decision 2). Flags include
    /// `O_RDONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`,
    /// `O_CONSISTENT_SNAPSHOT` (frozen view per ADR-029 § Decision 2).
    /// Identity-required: yes.
    FileOpen = 53,

    /// SYS_FILE_CREATE (54): equivalent to `O_CREAT | O_EXCL`.
    /// Returns a `FileDescriptor`. Identity-required: yes.
    FileCreate = 54,

    /// SYS_FILE_CLOSE (55): drop the descriptor; decrement
    /// `cow_refcount` if it pointed at a frozen view.
    /// Identity-required: yes.
    FileClose = 55,

    /// SYS_FILE_READ (56): read up to `MAX_FILE_IO_BYTES_PER_CALL = 1
    /// MiB` (SCAFFOLDING per ADR-029 § Decision 4) bytes from the
    /// descriptor's current offset. Identity-required: yes.
    FileRead = 56,

    /// SYS_FILE_WRITE (57): write up to `MAX_FILE_IO_BYTES_PER_CALL`
    /// bytes; triggers per-inode CoW per ADR-029 § Decision 2 when
    /// modifying an existing block. Identity-required: yes.
    FileWrite = 57,

    /// SYS_FILE_SEEK (58): update the descriptor's offset.
    /// Identity-required: yes.
    FileSeek = 58,

    /// SYS_FILE_TRUNCATE (59): update `size_bytes`; free extents
    /// beyond the new size (refcount-checked). Identity-required: yes.
    FileTruncate = 59,

    /// SYS_FILE_RENAME (60): atomic per ADR-029 § Decision 5 (single
    /// journal record). Cross-backend rename returns `EXDEV`.
    /// Identity-required: yes.
    FileRename = 60,

    /// SYS_FILE_UNLINK (61): decrement `link_count`; free the inode
    /// iff `link_count == 0 && open_descriptor_count == 0`.
    /// Identity-required: yes.
    FileUnlink = 61,

    /// SYS_FILE_LINK (62): create a new directory entry pointing at
    /// an existing inode; increment `link_count`.
    /// Identity-required: yes.
    FileLink = 62,

    /// SYS_FILE_SYMLINK (63): create a Symlink inode whose first
    /// extent holds the target string. Identity-required: yes.
    FileSymlink = 63,

    /// SYS_MKDIR (64): allocate a Directory inode; initialize empty
    /// directory contents. Identity-required: yes.
    Mkdir = 64,

    /// SYS_RMDIR (65): free a Directory inode iff it has no entries.
    /// Identity-required: yes.
    Rmdir = 65,

    /// SYS_OPENDIR (66): open a directory; returns a `FileDescriptor`
    /// flavor (per ADR-029 § Decision 4 — Directory backing).
    /// Identity-required: yes.
    Opendir = 66,

    /// SYS_READDIR (67): iterate entries in a directory descriptor.
    /// Identity-required: yes.
    Readdir = 67,

    /// SYS_STAT (68): return a `FileMetadata` struct (kind, size,
    /// owner, mtime, ctime, link_count). Identity-required: yes.
    Stat = 68,

    /// SYS_FSYNC (69): force journal flush + data CoW commits to
    /// durable storage. Identity-required: yes.
    Fsync = 69,

    /// SYS_ACL_GRANT (70): add a `(Principal, Rights, expiry)` row to
    /// an inode's ACL; owner-only. Returns `ENOSPC` if the inline ACL
    /// (capped at `MAX_INODE_ACL_ENTRIES = 16`) is full — multi-
    /// Principal workloads route through ADR-027 cluster delegation
    /// per ADR-029 § Decision 3. Identity-required: yes.
    AclGrant = 70,

    /// SYS_ACL_REVOKE (71): remove a row by Principal; owner-only.
    /// Identity-required: yes.
    AclRevoke = 71,

    /// SYS_ACL_LIST (72): return the ACL contents for inspection.
    /// Identity-required: yes.
    AclList = 72,
}

impl SyscallNumber {
    /// Returns `true` for syscalls that require the caller to have a bound,
    /// non-zero Principal. Unidentified processes may only use the exempt
    /// set: Exit, Yield, GetPid, GetTime, GetWallclock, Print, GetPrincipal,
    /// ModuleReady.
    ///
    /// This is the kernel-side half of the "identity is load-bearing" invariant.
    /// The userspace half is `recv_verified()` in libsys, which rejects
    /// anonymous IPC senders. Together they ensure a stripped-security kernel
    /// fork cannot run the standard userspace ecosystem.
    pub const fn requires_identity(&self) -> bool {
        matches!(self,
            Self::Write | Self::Read | Self::RecvMsg | Self::TryRecvMsg |
            Self::Allocate | Self::Free |
            Self::RegisterEndpoint |
            Self::WaitIrq | Self::MapMmio | Self::AllocDma |
            Self::DeviceInfo | Self::PortIo |
            Self::ObjPut | Self::ObjGet | Self::ObjDelete |
            Self::ObjList | Self::ObjPutSigned |
            Self::BindPrincipal | Self::ClaimBootstrapKey |
            Self::Spawn | Self::WaitTask |
            Self::ConsoleRead |
            Self::RevokeCapability |
            Self::ChannelCreate | Self::ChannelAttach |
            Self::ChannelClose | Self::ChannelRevoke | Self::ChannelInfo |
            Self::AuditAttach | Self::AuditInfo |
            Self::MapFramebuffer |
            Self::VirtioModernCaps |
            Self::AuditEmitInputFocus |
            Self::GetProcessPrincipal |
            Self::SetWallclock |
            Self::ChannelQuiesceAck |
            Self::ChannelBeginTeardown | Self::ChannelCompleteTeardown |
            Self::ClusterCreate | Self::ClusterJoin |
            Self::ClusterRevoke | Self::ClusterInfo |
            Self::Cambio | Self::Regalo | Self::Stream |
            Self::FileOpen | Self::FileCreate | Self::FileClose |
            Self::FileRead | Self::FileWrite | Self::FileSeek |
            Self::FileTruncate | Self::FileRename | Self::FileUnlink |
            Self::FileLink | Self::FileSymlink |
            Self::Mkdir | Self::Rmdir |
            Self::Opendir | Self::Readdir |
            Self::Stat | Self::Fsync |
            Self::AclGrant | Self::AclRevoke | Self::AclList
        )
    }

    /// Convert a u64 to a syscall number. Returns `None` for unassigned
    /// or reserved-but-not-implemented slots (e.g., 39/40 per ADR-022).
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(Self::Exit),
            1 => Some(Self::Write),
            2 => Some(Self::Read),
            3 => Some(Self::Allocate),
            4 => Some(Self::Free),
            5 => Some(Self::WaitIrq),
            6 => Some(Self::RegisterEndpoint),
            7 => Some(Self::Yield),
            8 => Some(Self::GetPid),
            9 => Some(Self::GetTime),
            10 => Some(Self::Print),
            11 => Some(Self::BindPrincipal),
            12 => Some(Self::GetPrincipal),
            13 => Some(Self::RecvMsg),
            14 => Some(Self::ObjPut),
            15 => Some(Self::ObjGet),
            16 => Some(Self::ObjDelete),
            17 => Some(Self::ObjList),
            18 => Some(Self::ClaimBootstrapKey),
            19 => Some(Self::ObjPutSigned),
            20 => Some(Self::MapMmio),
            21 => Some(Self::AllocDma),
            22 => Some(Self::DeviceInfo),
            23 => Some(Self::PortIo),
            24 => Some(Self::ConsoleRead),
            25 => Some(Self::Spawn),
            26 => Some(Self::WaitTask),
            27 => Some(Self::RevokeCapability),
            28 => Some(Self::ChannelCreate),
            29 => Some(Self::ChannelAttach),
            30 => Some(Self::ChannelClose),
            31 => Some(Self::ChannelRevoke),
            32 => Some(Self::ChannelInfo),
            33 => Some(Self::AuditAttach),
            34 => Some(Self::AuditInfo),
            35 => Some(Self::MapFramebuffer),
            36 => Some(Self::ModuleReady),
            37 => Some(Self::TryRecvMsg),
            38 => Some(Self::VirtioModernCaps),
            39 => Some(Self::SetWallclock),
            40 => Some(Self::GetWallclock),
            41 => Some(Self::AuditEmitInputFocus),
            42 => Some(Self::GetProcessPrincipal),
            43 => Some(Self::ChannelQuiesceAck),
            44 => Some(Self::ClusterCreate),
            45 => Some(Self::ClusterJoin),
            46 => Some(Self::ClusterRevoke),
            47 => Some(Self::ClusterInfo),
            48 => Some(Self::ChannelBeginTeardown),
            49 => Some(Self::ChannelCompleteTeardown),
            50 => Some(Self::Cambio),
            51 => Some(Self::Regalo),
            52 => Some(Self::Stream),
            53 => Some(Self::FileOpen),
            54 => Some(Self::FileCreate),
            55 => Some(Self::FileClose),
            56 => Some(Self::FileRead),
            57 => Some(Self::FileWrite),
            58 => Some(Self::FileSeek),
            59 => Some(Self::FileTruncate),
            60 => Some(Self::FileRename),
            61 => Some(Self::FileUnlink),
            62 => Some(Self::FileLink),
            63 => Some(Self::FileSymlink),
            64 => Some(Self::Mkdir),
            65 => Some(Self::Rmdir),
            66 => Some(Self::Opendir),
            67 => Some(Self::Readdir),
            68 => Some(Self::Stat),
            69 => Some(Self::Fsync),
            70 => Some(Self::AclGrant),
            71 => Some(Self::AclRevoke),
            72 => Some(Self::AclList),
            _ => None,
        }
    }
}

/// Arguments passed via registers on x86-64.
///
/// Field naming is arch-neutral (`arg1..arg6`); each architecture's
/// syscall entry stub is responsible for loading these from its own
/// register convention. The comments below give the x86-64 mapping
/// (System V ABI, modulo R10 for arg4 because SYSCALL clobbers RCX
/// with RIP). AArch64 uses X0..X5; RISC-V uses A0..A5.
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    pub arg1: u64,  // x86-64: rdi
    pub arg2: u64,  // x86-64: rsi
    pub arg3: u64,  // x86-64: rdx
    pub arg4: u64,  // x86-64: r10 (not rcx — see reference_x86_64_syscall_r10)
    pub arg5: u64,  // x86-64: r8
    pub arg6: u64,  // x86-64: r9
}

impl SyscallArgs {
    /// Create syscall arguments from register values
    pub fn new(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> Self {
        SyscallArgs {
            arg1, arg2, arg3, arg4, arg5, arg6,
        }
    }

    /// Get first argument as u32
    pub fn arg1_u32(&self) -> u32 {
        self.arg1 as u32
    }

    /// Get second argument as u32
    pub fn arg2_u32(&self) -> u32 {
        self.arg2 as u32
    }

    /// Get first argument as pointer
    pub fn arg1_ptr<T>(&self) -> *const T {
        self.arg1 as *const T
    }

    /// Get first argument as mutable pointer
    pub fn arg1_mut_ptr<T>(&self) -> *mut T {
        self.arg1 as *mut T
    }

    /// Get second argument as pointer
    pub fn arg2_ptr<T>(&self) -> *const T {
        self.arg2 as *const T
    }

    /// Get second argument as mutable pointer
    pub fn arg2_mut_ptr<T>(&self) -> *mut T {
        self.arg2 as *mut T
    }

    /// Get argument as usize (common for sizes)
    pub fn arg_usize(&self, n: usize) -> usize {
        match n {
            1 => self.arg1 as usize,
            2 => self.arg2 as usize,
            3 => self.arg3 as usize,
            4 => self.arg4 as usize,
            5 => self.arg5 as usize,
            6 => self.arg6 as usize,
            _ => 0,
        }
    }
}

/// Syscall error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SyscallError {
    /// Operation succeeded (0)
    Success = 0,

    /// Invalid argument
    InvalidArg = -1,

    /// Permission denied
    PermissionDenied = -2,

    /// Out of memory
    OutOfMemory = -3,

    /// Endpoint not found
    EndpointNotFound = -4,

    /// Operation would block
    WouldBlock = -5,

    /// Interrupted by signal (future)
    Interrupted = -6,

    /// Unknown syscall
    Enosys = -38,
}

impl SyscallError {
    /// Convert to signed integer for return value
    pub fn as_i64(&self) -> i64 {
        *self as i32 as i64
    }
}

/// Result type for syscall implementations
pub type SyscallResult = Result<u64, SyscallError>;

// ============================================================================
// Storage-stack handle types (ADR-028 § Decision 1)
// ============================================================================
//
// Three distinct handle types — no polymorphic `Storage` trait, no
// `From` impls between handle types. The kernel returns one of these
// three from any syscall whose return shape is "a storage handle";
// userspace cannot reconstruct one type from another's bits. See
// ADR-028 § Decision 1 and § Verification Stance.

/// CambiObject handle. Returned by `SYS_OBJ_PUT` / `SYS_OBJ_GET` /
/// `SYS_OBJ_LIST` (per ADR-003) and by `SYS_CAMBIO` (per ADR-028
/// § Decision 3).
///
/// Opaque newtype around the kernel-issued identifiers — userspace
/// cannot construct one without going through the syscall ABI.
/// Generation counter rejects stale or fabricated handles at use per
/// ADR-028 § Threat Model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectHandle {
    hash: [u8; 32],
    rights: ObjectRights,
    generation: u32,
}

impl ObjectHandle {
    /// Kernel-only constructor. Userspace receives `ObjectHandle`
    /// values across the syscall ABI but cannot synthesize them — the
    /// type discipline (handle-type-decided-at-syscall) is a static
    /// property of the API surface per ADR-028 § Verification Stance.
    pub const fn new(hash: [u8; 32], rights: ObjectRights, generation: u32) -> Self {
        Self { hash, rights, generation }
    }

    pub const fn hash(&self) -> [u8; 32] { self.hash }
    pub const fn rights(&self) -> ObjectRights { self.rights }
    pub const fn generation(&self) -> u32 { self.generation }
}

/// POSIX file descriptor. Returned by `SYS_FILE_OPEN` / `SYS_FILE_CREATE`
/// (per ADR-029) and by the path resolver when a path resolves to the
/// canonical `/co/<hex-hash>` mount or a REGALO alias (per ADR-028
/// § Decision 2).
///
/// Opaque newtype, kernel-only constructor. Carries a `FileBacking` tag
/// set at open time and immutable for the handle's lifetime, indicating
/// whether the descriptor points at a mutable POSIX file (ADR-029) or
/// an immutable CambiObject view. Writes against an `ObjectView`
/// backing terminate uniformly in `EROFS` before any backend operation
/// runs; the path-shaped contract is uniform across backings. See
/// ADR-028 § Decision 1 for why two backings on one descriptor type is
/// *not* the cross-model polymorphism the synthesis excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDescriptor {
    fd: u32,
    rights: FileRights,
    backing: FileBacking,
    generation: u32,
}

impl FileDescriptor {
    /// Kernel-only constructor; see `ObjectHandle::new`.
    pub const fn new(fd: u32, rights: FileRights, backing: FileBacking, generation: u32) -> Self {
        Self { fd, rights, backing, generation }
    }

    pub const fn fd(&self) -> u32 { self.fd }
    pub const fn rights(&self) -> FileRights { self.rights }
    pub const fn backing(&self) -> FileBacking { self.backing }
    pub const fn generation(&self) -> u32 { self.generation }
}

/// Stream cap endpoint. Returned by `SYS_STREAM` per ADR-028 + ADR-030.
///
/// Per ADR-028 § Decision 5 (the asymmetry): no `From` impl to or from
/// `ObjectHandle` / `FileDescriptor`, and no inverse seam syscall reads
/// a `StreamEndpoint` back into addressable storage. The structural
/// one-way property of Stream is encoded in the type discipline as
/// well as in the runtime dispatch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamEndpoint {
    stream_id: u32,
    role: StreamRole,
    generation: u32,
}

impl StreamEndpoint {
    /// Kernel-only constructor; see `ObjectHandle::new`.
    pub const fn new(stream_id: u32, role: StreamRole, generation: u32) -> Self {
        Self { stream_id, role, generation }
    }

    pub const fn stream_id(&self) -> u32 { self.stream_id }
    pub const fn role(&self) -> StreamRole { self.role }
    pub const fn generation(&self) -> u32 { self.generation }
}

/// Rights bitfield on `ObjectHandle`. Bit 0 = Read, bit 1 = Write,
/// bit 2 = Execute.
///
/// Hand-rolled `repr(transparent)` newtype to keep `cambios-abi`
/// zero-dep. Same pattern is reused for `FileRights` (ADR-028
/// § Decision 1) and `Rights` (ADR-029 § Decision 3 inode ACL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ObjectRights(u8);

impl ObjectRights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const NONE: Self = Self(0);

    pub const fn from_bits(bits: u8) -> Self { Self(bits) }
    pub const fn bits(&self) -> u8 { self.0 }
    pub const fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }
    pub const fn union(&self, other: Self) -> Self { Self(self.0 | other.0) }
}

/// Rights bitfield on `FileDescriptor`. Same bit layout as
/// `ObjectRights`. Hand-rolled per the pattern set on `ObjectRights`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct FileRights(u8);

impl FileRights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const NONE: Self = Self(0);

    pub const fn from_bits(bits: u8) -> Self { Self(bits) }
    pub const fn bits(&self) -> u8 { self.0 }
    pub const fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }
    pub const fn union(&self, other: Self) -> Self { Self(self.0 | other.0) }
}

/// Stream cap role per ADR-030 § Decision 3. Stream is one-way by
/// construction — ADR-005's `Bidirectional` channel role is
/// structurally absent on Streams. `SYS_STREAM` rejects an attempt to
/// base a Stream on a Bidirectional channel with `InvalidArg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamRole {
    Producer = 0,
    Consumer = 1,
}

/// `FileDescriptor` backing per ADR-028 § Decision 1. Resolved at
/// `SYS_FILE_OPEN` / path-resolve time and immutable for the
/// descriptor's lifetime; subsequent operations branch on this tag
/// without re-resolving.
///
/// Writes against `ObjectView` backings terminate uniformly in `EROFS`
/// before any backend operation runs (ADR-028 § Threat Model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBacking {
    /// Mutable POSIX file in the POSIX file backend (ADR-029).
    Posix,
    /// Immutable CambiObject view; bytes resolved via the ObjectStore
    /// on each read. The `hash` field is a content hash, not a
    /// Principal AID (see top-of-file note on `[u8; 32]` shape).
    ObjectView { hash: [u8; 32], source: ViewSource },
}

/// How a CambiObject view was reached. Discriminates the two
/// path-resolution outcomes that produce a `FileBacking::ObjectView`
/// per ADR-028 § Decision 2 path-namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewSource {
    /// Reached via the `/co/<hex-hash>` canonical mount. Path is
    /// content-derived; the resolver hex-decodes the hash and looks
    /// up the object directly.
    Canonical,
    /// Reached via a REGALO alias. Path is user-chosen and lives in
    /// the calling process's REGALO alias table.
    Regalo(RegaloId),
}

/// REGALO alias identifier. Per-process namespace, kernel-issued,
/// revocable per ADR-028 § Decision 2. Opaque newtype matching the
/// `ChannelId` / `ClusterId` pattern already in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RegaloId(u32);

impl RegaloId {
    pub const fn new(raw: u32) -> Self { Self(raw) }
    pub const fn raw(&self) -> u32 { self.0 }
}

// ============================================================================
// POSIX file storage types (ADR-029 § Architecture)
// ============================================================================
//
// On-disk inode shape (per ADR-029 § Decision 1) plus the kernel-side
// frozen-view handle (per ADR-029 § Decision 2 — CoW snapshot for
// CAMBIO). The on-disk byte layout in ADR-029 § Decision 1's tables is
// packed; the Rust types here use natural alignment and the kernel
// translates between them with explicit byte reads (per ADR-029
// § Architecture's "on-disk vs in-memory layout" note).

/// SCAFFOLDING: maximum number of contiguous extents per POSIX inode.
/// Why: per ADR-029 § Decision 1 the inode header reserves 192 bytes
///      for `extents` (16 entries × 12 bytes on-disk). The bound is
///      the on-disk inode-format slot count, mirroring the
///      MAX_OBJECT_CAPS / MAX_CONTENT_BYTES_ON_DISK precedent in
///      docs/ASSUMPTIONS.md.
/// Replace when: growing this requires a new inode-format version
///      bump (the on-disk layout reserves exactly 16 slots). The
///      observable trigger for that bump is the first widespread
///      EFRAGMENTED failure on an aged disk per ADR-029 § Open
///      Questions ("Defragmenter / compaction tool"). Until then,
///      16 extents per inode is the v1 endgame bound — large files
///      land in fewer-larger extents via the contiguous allocator,
///      not by raising the count.
pub const MAX_EXTENTS_PER_INODE: usize = 16;

/// SCAFFOLDING: maximum number of inline ACL entries per POSIX inode.
/// Why: per ADR-029 § Decision 1 the inode header reserves 704 bytes
///      for `acl` (16 entries × 44 bytes packed). The bound is the
///      inline-ACL slot count; multi-Principal workloads route
///      through ADR-027 cluster delegation rather than wider inline
///      ACL per ADR-029 § Decision 3. Same SCAFFOLDING shape as
///      MAX_OBJECT_CAPS = 8 in docs/ASSUMPTIONS.md (peer on-disk
///      ACL slot count for CambiObjects).
/// Replace when: growing this requires a new inode-format version
///      bump (the on-disk layout reserves exactly 16 slots). Trigger:
///      a workload appears where cluster delegation is structurally
///      wrong for the access pattern per ADR-029 § Open Questions
///      ("ACL extension blocks").
pub const MAX_INODE_ACL_ENTRIES: usize = 16;

/// POSIX inode kind per ADR-029 § Decision 1. Regular file, directory,
/// or symbolic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InodeKind {
    Regular = 0,
    Directory = 1,
    Symlink = 2,
}

/// One contiguous run of blocks on disk. ADR-029 § Decision 1 caps
/// each inode at `MAX_EXTENTS_PER_INODE` of these.
///
/// On-disk layout is packed at 12 bytes; the Rust struct here is
/// naturally aligned (16 bytes). The kernel uses explicit byte reads
/// when serializing per ADR-029 § Architecture's "on-disk vs
/// in-memory layout" note — `mem::transmute` is not safe across the
/// alignment gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub start_lba: u64,
    pub block_count: u32,
}

/// Rights bitfield on a POSIX inode ACL entry. Bit 0 = Read, bit 1 =
/// Write, bit 2 = Execute, per ADR-029 § Decision 3.
///
/// Hand-rolled per the pattern set by `ObjectRights` and `FileRights`
/// in commit 1. cambios-abi stays zero-dep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Rights(u8);

impl Rights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const NONE: Self = Self(0);

    pub const fn from_bits(bits: u8) -> Self { Self(bits) }
    pub const fn bits(&self) -> u8 { self.0 }
    pub const fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }
    pub const fn union(&self, other: Self) -> Self { Self(self.0 | other.0) }
}

/// One row in a POSIX inode's inline ACL per ADR-029 § Decision 3.
///
/// The `principal` field is a 32-byte AID per the top-of-file note
/// (Principal newtype promotion deferred). `expiry` is monotonic
/// ticks; `None` means no expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclEntry {
    pub principal: [u8; 32],
    pub rights: Rights,
    pub expiry: Option<u64>,
}

/// POSIX inode (on-disk record) per ADR-029 § Decision 1.
///
/// Identity-keyed by `InodeId` in the kernel; this struct is the
/// header-block contents (4 KiB on disk, header fields + extents +
/// inline ACL). The reserved tail block (LBA `2 + 2*i + 1`) is
/// zero-filled in v1 per ADR-029 § Decision 1.
///
/// `owner` is a 32-byte AID per the top-of-file note. `extents` and
/// `acl` use `Option<T>` slots so empty positions are explicit; the
/// active count is given by `extent_count` / `acl_count` (the kernel
/// maintains the invariant that `Some(...)` entries are contiguous
/// from index 0).
///
/// `PartialEq` / `Eq` are derived to support test equality and the
/// canonical-form claim "same logical inode → same bytes → same
/// hash" (see ADR-029 § Divergence 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixInode {
    pub magic: [u8; 8],
    pub kind: InodeKind,
    pub size_bytes: u64,
    pub created_at: u64,
    pub modified_at: u64,
    pub owner: [u8; 32],
    pub link_count: u32,
    pub cow_refcount: u32,
    pub extents: [Option<Extent>; MAX_EXTENTS_PER_INODE],
    pub acl: [Option<AclEntry>; MAX_INODE_ACL_ENTRIES],
}

/// Kernel-issued inode identifier. Opaque newtype matching the
/// `ChannelId` / `ClusterId` / `RegaloId` pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct InodeId(u64);

impl InodeId {
    pub const fn new(raw: u64) -> Self { Self(raw) }
    pub const fn raw(&self) -> u64 { self.0 }
}

/// Frozen view of a POSIX inode's extent list. Per ADR-029 § Decision
/// 2: held by CAMBIO syscall handlers and by `FileDescriptor`s opened
/// with `O_CONSISTENT_SNAPSHOT`. Reading through the frozen extents
/// gives snapshot-consistent bytes even while concurrent writers
/// allocate new blocks via CoW.
///
/// `view_id` is unique within an inode's frozen-view set; the kernel
/// maintains a per-inode `cow_refcount` (in `PosixInode`) tracking
/// how many frozen views currently reference this inode.
#[derive(Debug, Clone, Copy)]
pub struct FrozenInodeView {
    pub inode_id: InodeId,
    pub frozen_extents: [Option<Extent>; MAX_EXTENTS_PER_INODE],
    pub view_id: u32,
    pub created_at: u64,
}

// ============================================================================
// Stream cap-shape types (ADR-030)
// ============================================================================
//
// A Stream is what an ADR-005 channel is when its cap shape declares
// it ephemeral. The substrate carries bytes through the existing
// memory-mapped page ring; this cap-shape annotation parameterizes
// the substrate at open time (fan-out cap, buffer-max watermark,
// rewind window, lifetime bounds) and constrains the runtime path at
// boundary events (open / attach / send-permission / close). There is
// no per-byte kernel check on the data path; the kernel touches bytes
// only at boundary events.
//
// `StreamCapShape` is the cap-shape annotation; `StreamState` is the
// kernel-side bookkeeping; `StreamLifecycleState` + `CloseReason`
// drive the close path. All five types are ABI-visible because the
// channel record (kernel state) and userspace cap-shape builders both
// reference them.

/// Stream cap shape per ADR-030 § Decision 1. Carries the ephemerality
/// bounds the kernel enforces at boundary events. Validity constraints
/// (§ Decision 1) are checked at `SYS_STREAM` open; userspace builders
/// (`libstream` per ADR-028) run the same checks at compile/link time.
///
/// Once attached to a channel record, the cap shape is immutable for
/// the stream's lifetime per ADR-030 § Why Not Other Options option B
/// (mutable cap shapes break the cap-shape-invariant property).
///
/// Fields are public — userspace builds these from caller-side
/// arguments. The kernel inspects them at open time but does not
/// modify them after attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCapShape {
    /// Required for any Stream cap. A `StreamCapShape` with
    /// `consume = false` is not a Stream cap and is rejected with
    /// `InvalidArg` per ADR-030 § Decision 1.
    pub consume: bool,

    /// Maximum backward-seek window in bytes from the receiver's
    /// current read position. 0 = pure forward-only; >0 = receiver
    /// may re-read up to N bytes back. Bounded by
    /// `MAX_STREAM_RECEIVER_BUFFER` SCAFFOLDING at open time (bound
    /// lands kernel-side with the handler in a later session).
    pub rewind_window: u64,

    /// Maximum receiver-side buffering, in bytes. Parameterizes the
    /// channel substrate's flow-control watermark (per ADR-005).
    /// 0 = zero-buffer flow control (sender blocks until previous
    /// write fully drained); >0 = bounded in-flight headroom. When
    /// `buffer_max == 0`, `rewind_window` must also be 0 per
    /// § Decision 1 (zero-buffer flow control retains no history).
    pub buffer_max: u64,

    /// Maximum simultaneous receivers per ADR-030 § Decision 1.
    /// 1 = one-shot stream; >1 = fan-out. Slot reclaimed on detach.
    /// Bounded by `MAX_STREAM_FAN_OUT` SCAFFOLDING at open time.
    pub fan_out_count: u32,

    /// Total bytes the sender may transmit before kernel force-close.
    /// 0 = unbounded (use `lifetime_duration` or sender-driven close).
    /// Bounded by `MAX_STREAM_LIFETIME_BYTES` SCAFFOLDING.
    pub lifetime_bytes: u64,

    /// Maximum stream duration in monotonic ticks before force-close.
    /// 0 = unbounded. Bounded by `MAX_STREAM_LIFETIME_DURATION_TICKS`
    /// SCAFFOLDING.
    pub lifetime_duration: u64,

    /// Lifecycle-event granularity per ADR-030 § Decision 1. Tri-state
    /// (`Off` / `Lifecycle` / `Detailed`) rather than boolean so
    /// forensics workloads can opt into richer signal without a future
    /// ABI change. `STREAM_OPENED` is always emitted regardless of
    /// this knob (compliance baseline).
    pub audit_lifecycle: AuditLifecyclePolicy,

    /// If true, the kernel verifies `sender_principal` equals the cap
    /// creator's Principal on every `SYS_CHANNEL_WRITE`. Used for
    /// signed-carrier flows where the sender's identity is per-byte
    /// load-bearing. Off by default — leaves the per-write 32-byte
    /// equality check out of the data path for non-signed-carrier
    /// workloads (ADR-030 § Decision 2 row 3 + § Threat Model).
    pub sender_principal_required: bool,
}

/// Audit policy for Stream lifecycle events per ADR-030 § Decision 1.
/// Per-byte audit is structurally absent (auditing every write would
/// defeat the ephemerality property); this knob controls the
/// granularity of lifecycle-event emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditLifecyclePolicy {
    /// Only `STREAM_OPENED` fires. Minimum-compliance footprint —
    /// the open event is the load-bearing audit signal for any
    /// cap-shape granted.
    Off = 0,
    /// Standard lifecycle events: `STREAM_OPENED`, `STREAM_ATTACHED`,
    /// `STREAM_DETACHED`, `STREAM_CLOSED`. Default for v1 workloads.
    Lifecycle = 1,
    /// Lifecycle events plus richer per-event payload (cap-shape diff
    /// at attach, cluster membership at the time, drain statistics at
    /// close). For forensics or compliance-heavy workloads.
    Detailed = 2,
}

/// Per-stream runtime bookkeeping attached to the channel record per
/// ADR-030 § Architecture. Updated on every `SYS_CHANNEL_WRITE`
/// (bytes_sent), every attach/detach (active_receiver_count), and
/// when the lifecycle transitions (state).
#[derive(Debug, Clone, Copy)]
pub struct StreamState {
    pub opened_at_tick: u64,
    pub bytes_sent: u64,
    pub active_receiver_count: u32,
    pub state: StreamLifecycleState,
}

/// Stream lifecycle state machine per ADR-030 § Decision 4.
/// Strictly forward: `Active → Closing → Closed`. No backward
/// transitions; the `Closing` arm carries the close reason and the
/// drain-deadline tick for the passive drain wait.
#[derive(Debug, Clone, Copy)]
pub enum StreamLifecycleState {
    Active,
    Closing { reason: CloseReason, drain_deadline_tick: u64 },
    Closed,
}

/// Reason a Stream transitioned to `Closing`. Carried in the
/// `STREAM_CLOSED` audit event payload per ADR-030 § Decision 5.
/// One event covers all close paths; no separate
/// `STREAM_LIFETIME_EXHAUSTED` / `STREAM_FORCE_CLOSED` events.
///
/// `audit_ref` in `KernelForce` is `u64` rather than a typed
/// `AuditEventId` per ADR-007 — the audit-ID type has not yet been
/// promoted to `cambios-abi`. Replace when: a second ABI consumer of
/// AuditEventId appears, or ADR-007 promotes the type.
#[derive(Debug, Clone, Copy)]
pub enum CloseReason {
    SenderClosed,
    LifetimeBytesExhausted,
    LifetimeDurationExhausted,
    AllReceiversDetached,
    KernelForce { audit_ref: u64 },
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::SyscallNumber;

    /// The exempt set: syscalls that do NOT require identity.
    /// These are the only operations an unidentified process can perform.
    const EXEMPT: &[SyscallNumber] = &[
        SyscallNumber::Exit,
        SyscallNumber::Yield,
        SyscallNumber::GetPid,
        SyscallNumber::GetTime,
        SyscallNumber::Print,
        SyscallNumber::GetPrincipal,
        // `ModuleReady` is called by every boot module at the end of its
        // own init, including modules that run before the key-store /
        // identity infrastructure is fully up. Making it identity-gated
        // would create a bootstrap circular dependency.
        SyscallNumber::ModuleReady,
        // `GetWallclock` is a *read* of a value the kernel already chose
        // to publish — there is no integrity surface to protect, and
        // pre-bind boot modules legitimately need to render the clock.
        SyscallNumber::GetWallclock,
    ];

    #[test]
    fn exempt_syscalls_do_not_require_identity() {
        for &num in EXEMPT {
            assert!(
                !num.requires_identity(),
                "{:?} should be exempt from identity requirement",
                num,
            );
        }
    }

    #[test]
    fn identity_required_syscalls_are_gated() {
        // Every syscall NOT in the exempt set must require identity.
        let all = [
            SyscallNumber::Exit, SyscallNumber::Write, SyscallNumber::Read,
            SyscallNumber::Allocate, SyscallNumber::Free, SyscallNumber::WaitIrq,
            SyscallNumber::RegisterEndpoint, SyscallNumber::Yield,
            SyscallNumber::GetPid, SyscallNumber::GetTime, SyscallNumber::Print,
            SyscallNumber::BindPrincipal, SyscallNumber::GetPrincipal,
            SyscallNumber::RecvMsg, SyscallNumber::ObjPut, SyscallNumber::ObjGet,
            SyscallNumber::ObjDelete, SyscallNumber::ObjList,
            SyscallNumber::ClaimBootstrapKey, SyscallNumber::ObjPutSigned,
            SyscallNumber::MapMmio, SyscallNumber::AllocDma,
            SyscallNumber::DeviceInfo, SyscallNumber::PortIo,
            SyscallNumber::ConsoleRead, SyscallNumber::Spawn,
            SyscallNumber::WaitTask, SyscallNumber::RevokeCapability,
            SyscallNumber::ChannelCreate, SyscallNumber::ChannelAttach,
            SyscallNumber::ChannelClose, SyscallNumber::ChannelRevoke,
            SyscallNumber::ChannelInfo, SyscallNumber::AuditAttach,
            SyscallNumber::AuditInfo,
            SyscallNumber::MapFramebuffer, SyscallNumber::ModuleReady,
            SyscallNumber::TryRecvMsg, SyscallNumber::VirtioModernCaps,
            SyscallNumber::SetWallclock, SyscallNumber::GetWallclock,
            SyscallNumber::AuditEmitInputFocus,
            SyscallNumber::GetProcessPrincipal,
            SyscallNumber::ChannelQuiesceAck,
            SyscallNumber::ClusterCreate, SyscallNumber::ClusterJoin,
            SyscallNumber::ClusterRevoke, SyscallNumber::ClusterInfo,
            SyscallNumber::ChannelBeginTeardown,
            SyscallNumber::ChannelCompleteTeardown,
            SyscallNumber::Cambio,
            SyscallNumber::Regalo,
            SyscallNumber::Stream,
            SyscallNumber::FileOpen, SyscallNumber::FileCreate,
            SyscallNumber::FileClose, SyscallNumber::FileRead,
            SyscallNumber::FileWrite, SyscallNumber::FileSeek,
            SyscallNumber::FileTruncate, SyscallNumber::FileRename,
            SyscallNumber::FileUnlink, SyscallNumber::FileLink,
            SyscallNumber::FileSymlink,
            SyscallNumber::Mkdir, SyscallNumber::Rmdir,
            SyscallNumber::Opendir, SyscallNumber::Readdir,
            SyscallNumber::Stat, SyscallNumber::Fsync,
            SyscallNumber::AclGrant, SyscallNumber::AclRevoke,
            SyscallNumber::AclList,
        ];

        for &num in &all {
            let is_exempt = EXEMPT.contains(&num);
            assert_eq!(
                num.requires_identity(),
                !is_exempt,
                "{:?}: requires_identity()={} but exempt={}",
                num,
                num.requires_identity(),
                is_exempt,
            );
        }
    }

    #[test]
    fn exempt_set_is_minimal() {
        // The exempt set must be exactly 8 syscalls (Exit, Yield, GetPid,
        // GetTime, Print, GetPrincipal, ModuleReady, GetWallclock). If
        // this test fails, someone added a new exempt syscall — that
        // requires justification.
        assert_eq!(EXEMPT.len(), 8, "exempt set size changed — review required");
    }

    #[test]
    fn all_syscall_numbers_covered() {
        // Verify from_u64 round-trips for all defined values, ensuring
        // no gap in the requires_identity() match. ADR-022 wallclock
        // pair (39/40) lands inside the contiguous 0..=52 sweep.
        // ADR-027 cluster-handle reservations (44..=47), the two-phase
        // channel-teardown pair (48 ChannelBeginTeardown, 49
        // ChannelCompleteTeardown), ADR-028 storage seam syscalls
        // (50 Cambio, 51 Regalo, 52 Stream), and ADR-029 POSIX file
        // syscalls (53..=72: FileOpen..AclList) round out the current
        // high-water mark.
        for i in 0..=72u64 {
            let num = SyscallNumber::from_u64(i);
            assert!(num.is_some(), "from_u64({}) returned None", i);
            let _ = num.unwrap().requires_identity();
        }
    }
}
