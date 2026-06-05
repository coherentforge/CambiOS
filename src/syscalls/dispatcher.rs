// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Syscall dispatcher and handlers
//!
//! Routes syscalls from userspace to kernel handlers with zero-trust
//! interceptor pre-check. All handlers that touch user memory perform
//! page-table walks through the process's CR3 via HHDM.

use crate::syscalls::{SyscallNumber, SyscallArgs, SyscallResult, SyscallError};
use super::user_slice::{MAX_USER_BUFFER, USER_SPACE_END, UserReadSlice, UserWriteSlice};
use crate::scheduler::TaskId;
use crate::ipc::ProcessId;
// `ObjectStore` trait must be in scope so method calls (`put`/`get`/etc.) on
// `ObjectStoreBackend` resolve via its `impl ObjectStore for ObjectStoreBackend`
// (ADR-003 § Divergence). Previously implicit when `OBJECT_STORE` was a
// `Box<dyn ObjectStore>`; now required because dispatch is monomorphized.
#[allow(unused_imports)]
use crate::fs::ObjectStore;

/// Syscall handler context
///
/// Passed to each syscall handler to give it access to kernel state.
/// `caller_principal` is resolved once in `dispatch()` and carried through
/// to all handlers — eliminates redundant CAPABILITY_MANAGER lock acquisitions.
pub struct SyscallContext {
    /// Calling process ID
    pub process_id: ProcessId,
    /// Calling task ID
    pub task_id: TaskId,
    /// Process page table (CR3). 0 = kernel task (no user address space).
    pub cr3: u64,
    /// The caller's bound Principal, resolved once at dispatch entry.
    /// `None` means the process has no bound Principal (anonymous).
    pub caller_principal: Option<crate::ipc::Principal>,
}

// ============================================================================
// User-space buffer helpers
// ============================================================================

/// HARDWARE: x86 IDT has 256 entries; vectors 0-31 are CPU exceptions, 32-223 are
/// device IRQs, 224-255 are reserved for APIC/IPI. SYS_WAIT_IRQ accepts < 224.
const MAX_DEVICE_IRQ: u32 = 224;

/// SCAFFOLDING: max inline content for SYS_OBJ_PUT / SYS_OBJ_PUT_SIGNED.
/// The length guard and the on-stack `kbuf` staging buffer both reference this
/// one const, so "guard length ≤ buffer length" holds by construction — that
/// closes the kbuf-overrun panic where the guard had drifted to
/// `MAX_USER_BUFFER` (16384) while `kbuf` stayed 4096.
/// Why: an inline syscall buffer tracks the kernel-stack budget
/// (`KERNEL_STACK_SIZE` = 32 KiB), NOT `MAX_CONTENT_BYTES_ON_DISK`, which grows
/// to multi-block for v2 records. Full rationale in docs/ASSUMPTIONS.md.
/// Replace when: a channel-based bulk obj_put path (ADR-005) lands.
const OBJ_PUT_MAX_CONTENT: usize = 4096;

// ============================================================================
// Tombstone page (ADR-007 Divergence entry 7)
// ============================================================================

/// Physical base of the kernel-owned tombstone zero page used by
/// [`SyscallDispatcher::teardown_channel_mappings`] to remap revoked
/// RO peer mappings instead of unmapping them. Set once at boot via
/// [`init_tombstone`]; read on every channel teardown. 0 = uninit.
///
/// ADR-007 Divergence entry 7 documents the decision rationale. The
/// concrete shape: one global RO 4 KiB page, allocated from the frame
/// allocator, zeroed once at init, never freed. All revoked RO peer
/// mappings point at it; reads return zeros without faulting,
/// closing the open compositor #PF on clean client exit.
///
/// `AtomicU64` so the read on the teardown hot path is lock-free; the
/// store happens once at boot before any process can revoke.
static TOMBSTONE_PHYS_BASE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Read the tombstone page's physical base. Returns 0 if uninit
/// (boot-order bug — `init_tombstone` should fire before any channel
/// can revoke). Callers fall back to unmap-on-revoke when 0, which
/// re-exposes the HN-blocker fault but keeps the kernel functional.
#[inline]
pub fn tombstone_phys_base() -> u64 {
    TOMBSTONE_PHYS_BASE.load(core::sync::atomic::Ordering::Acquire)
}

/// Allocate the global tombstone page. Idempotent — call once during
/// boot after `FRAME_ALLOCATOR` is live, before any process can revoke
/// a channel.
///
/// On allocation failure (frame allocator out of memory, which would
/// itself be a fatal boot condition), logs a warning and returns
/// `false`; subsequent revokes fall back to unmap-on-revoke (the
/// pre-tombstone behavior). On success the tombstone phys base is
/// published via `Release` so the lock-free reads on the teardown
/// hot path observe it.
pub fn init_tombstone() -> bool {
    if TOMBSTONE_PHYS_BASE.load(core::sync::atomic::Ordering::Acquire) != 0 {
        return true; // already initialised
    }
    let phys_base = {
        let mut fa = crate::FRAME_ALLOCATOR.lock();
        match fa.allocate_contiguous(1) {
            Ok(frame) => frame.addr,
            Err(_) => {
                crate::println!(
                    "WARN: tombstone allocation failed; channel revoke falls back to unmap-on-revoke (ADR-007 Divergence entry 7)"
                );
                return false;
            }
        }
    };
    // Zero the page. The frame allocator does not guarantee zeroed
    // pages, and the tombstone's whole point is "reads return zeros."
    let virt = phys_base + crate::hhdm_offset();
    // SAFETY: `phys_base` was just allocated from the frame allocator
    // and is exclusively owned by us; HHDM maps it to a valid kernel
    // VA for the entire 4 KiB page; no other CPU has observed
    // `TOMBSTONE_PHYS_BASE` yet (we have not stored it), so no
    // concurrent reader can reach this memory via the tombstone path.
    unsafe {
        core::ptr::write_bytes(virt as *mut u8, 0, 4096);
    }
    TOMBSTONE_PHYS_BASE.store(phys_base, core::sync::atomic::Ordering::Release);
    crate::println!("✓ Tombstone page allocated at phys {:#x}", phys_base);
    true
}

// ============================================================================
// Dispatcher
// ============================================================================
//
// User-buffer validation + page-walk helpers live in `super::user_slice`.
// The `UserReadSlice<'ctx>` / `UserWriteSlice<'ctx>` imports above are
// the only path handlers have to user memory; raw `(addr, len)` pairs
// cannot cross the module boundary.

/// Dispatcher that routes syscalls to handlers
pub struct SyscallDispatcher;

impl SyscallDispatcher {
    /// Dispatch a syscall to its handler
    ///
    /// Pipeline: parse number → resolve principal → policy check →
    /// identity gate → handler dispatch.
    pub fn dispatch(
        syscall_num: u64,
        args: SyscallArgs,
        mut ctx: SyscallContext,
    ) -> SyscallResult {
        let num = match SyscallNumber::from_u64(syscall_num) {
            Some(n) => n,
            None => return Err(SyscallError::Enosys),
        };

        // Resolve the caller's Principal once. Every handler reads
        // ctx.caller_principal instead of re-acquiring CAPABILITY_MANAGER.
        ctx.caller_principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            cap_guard.as_ref().and_then(|cm| cm.get_principal(ctx.process_id).ok())
        };

        // Identity gate: syscalls that require a bound, non-zero Principal
        // are rejected for anonymous processes. Unidentified processes can
        // only Exit, Yield, GetPid, GetTime, Print, and GetPrincipal.
        //
        // This is the kernel-side enforcement of "no ID, no participation."
        // A stripped kernel fork that removes this gate still faces the
        // userspace half (recv_verified in libsys rejects anonymous senders).
        if num.requires_identity() {
            match &ctx.caller_principal {
                Some(p) if !p.is_zero() => {} // identified — proceed
                _ => {
                    crate::audit::emit(crate::audit::RawAuditEvent::syscall_denied(
                        ctx.process_id, syscall_num, crate::audit::now(), 0,
                    ));
                    return Err(SyscallError::PermissionDenied);
                }
            }
        }

        // Policy service pre-dispatch check (ADR-006).
        // Replaces the old IPC_MANAGER → interceptor → on_syscall path.
        // May block the calling task on a cache miss (upcall to user-space
        // policy service). Falls back to Allow if the policy service is
        // unavailable.
        {
            use crate::ipc::interceptor::InterceptDecision;
            let decision = crate::policy::policy_check(
                ctx.process_id,
                ctx.task_id,
                ctx.cr3,
                syscall_num as u32,
            );
            if let InterceptDecision::Deny(_) = decision {
                crate::audit::emit(crate::audit::RawAuditEvent::syscall_denied(
                    ctx.process_id, syscall_num, crate::audit::now(), 0,
                ));
                return Err(SyscallError::PermissionDenied);
            }
        }

        match num {
            SyscallNumber::Exit => Self::handle_exit(args, &ctx),
            SyscallNumber::Write => Self::handle_write(args, &ctx),
            SyscallNumber::Read => Self::handle_read(args, &ctx),
            SyscallNumber::Allocate => Self::handle_allocate(args, &ctx),
            SyscallNumber::Free => Self::handle_free(args, &ctx),
            SyscallNumber::WaitIrq => Self::handle_wait_irq(args, &ctx),
            SyscallNumber::RegisterEndpoint => Self::handle_register_endpoint(args, &ctx),
            SyscallNumber::Yield => Self::handle_yield(args, &ctx),
            SyscallNumber::GetPid => Self::handle_get_pid(args, &ctx),
            SyscallNumber::GetTime => Self::handle_get_time(args, &ctx),
            SyscallNumber::Print => Self::handle_print(args, &ctx),
            SyscallNumber::BindPrincipal => Self::handle_bind_principal(args, &ctx),
            SyscallNumber::GetPrincipal => Self::handle_get_principal(args, &ctx),
            SyscallNumber::RecvMsg => Self::handle_recv_msg(args, &ctx),
            SyscallNumber::TryRecvMsg => Self::handle_try_recv_msg(args, &ctx),
            SyscallNumber::ObjPut => Self::handle_obj_put(args, &ctx),
            SyscallNumber::ObjGet => Self::handle_obj_get(args, &ctx),
            SyscallNumber::ObjDelete => Self::handle_obj_delete(args, &ctx),
            SyscallNumber::ObjList => Self::handle_obj_list(args, &ctx),
            SyscallNumber::ObjPutSigned => Self::handle_obj_put_signed(args, &ctx),
            SyscallNumber::MapMmio => Self::handle_map_mmio(args, &ctx),
            SyscallNumber::AllocDma => Self::handle_alloc_dma(args, &ctx),
            SyscallNumber::DeviceInfo => Self::handle_device_info(args, &ctx),
            SyscallNumber::PortIo => Self::handle_port_io(args, &ctx),
            SyscallNumber::ConsoleRead => Self::handle_console_read(args, &ctx),
            SyscallNumber::Spawn => Self::handle_spawn(args, &ctx),
            SyscallNumber::WaitTask => Self::handle_wait_task(args, &ctx),
            SyscallNumber::RevokeCapability => Self::handle_revoke_capability(args, &ctx),

            // Shared-memory channels (ADR-005)
            SyscallNumber::ChannelCreate => Self::handle_channel_create(args, &ctx),
            SyscallNumber::ChannelAttach => Self::handle_channel_attach(args, &ctx),
            SyscallNumber::ChannelClose => Self::handle_channel_close(args, &ctx),
            SyscallNumber::ChannelRevoke => Self::handle_channel_revoke(args, &ctx),
            SyscallNumber::ChannelInfo => Self::handle_channel_info(args, &ctx),

            // Audit infrastructure (ADR-007)
            SyscallNumber::AuditAttach => Self::handle_audit_attach(args, &ctx),
            SyscallNumber::AuditInfo => Self::handle_audit_info(args, &ctx),

            // Graphics primitives (ADR-011)
            SyscallNumber::MapFramebuffer => Self::handle_map_framebuffer(args, &ctx),
            SyscallNumber::ModuleReady => Self::handle_module_ready(args, &ctx),

            // Virtio-modern PCI capability discovery (ADR-014)
            SyscallNumber::VirtioModernCaps => Self::handle_virtio_modern_caps(args, &ctx),

            // ADR-022: wall-clock time. SetWallclock is capability-gated
            // (only udp-stack today); GetWallclock is unidentified-allowed.
            SyscallNumber::SetWallclock => Self::handle_set_wallclock(args, &ctx),
            SyscallNumber::GetWallclock => Self::handle_get_wallclock(args, &ctx),

            // T-7 Phase A (docs/threat-model.md): compositor reports
            // window-focus transitions into the audit ring.
            SyscallNumber::AuditEmitInputFocus =>
                Self::handle_audit_emit_input_focus(args, &ctx),

            // Audit consumer principal lookup. Resolves a `subject_pid`
            // from a buffered audit event to the bound 32-byte Principal
            // for did:key rendering. Capability-gated on AuditConsumer.
            SyscallNumber::GetProcessPrincipal =>
                Self::handle_get_process_principal(args, &ctx),

            // ADR-027 Phase 1: per-channel quiesce cooperative ack.
            // Cooperative path the libgui resize flow does not invoke
            // (resize relies on advisory cooperation — client willingly
            // closes its side after WindowResized), but a forced-revoke
            // / cluster-revoke / process-exit consumer can call to park
            // itself synchronously and return cleanly when
            // `complete_teardown` wakes it.
            SyscallNumber::ChannelQuiesceAck =>
                Self::handle_channel_quiesce_ack(args, &ctx),

            // ADR-027 Phase 1 two-phase teardown — substrate for
            // resize, cluster revoke, and forced-revoke flows. The
            // pair brackets the kernel-side quiesce window; the
            // libgui resize handler is the first real consumer, with
            // forced-teardown / cluster-revoke migrating off the
            // single-phase `ChannelClose` path as ADR-027 phases land.
            SyscallNumber::ChannelBeginTeardown =>
                Self::handle_channel_begin_teardown(args, &ctx),
            SyscallNumber::ChannelCompleteTeardown =>
                Self::handle_channel_complete_teardown(args, &ctx),

            // ADR-027 cluster handles. Wire to ClusterManager
            // (src/ipc/cluster.rs) + cluster_policy
            // (src/ipc/cluster_policy.rs). Cap promotion is a no-op
            // in v1 (cluster_policy::caps_for_role returns empty);
            // the rendering-limb migration commit populates it.
            SyscallNumber::ClusterCreate => Self::handle_cluster_create(args, &ctx),
            SyscallNumber::ClusterJoin => Self::handle_cluster_join(args, &ctx),
            SyscallNumber::ClusterRevoke => Self::handle_cluster_revoke(args, &ctx),
            SyscallNumber::ClusterInfo => Self::handle_cluster_info(args, &ctx),

            // ADR-028 storage seam syscalls — slots 50/51/52 reserved.
            // Handlers are stubs returning Enosys until the seam-syscall
            // migration steps land (ADR-028 § Migration Path steps 6-8);
            // the cap-shape semantics for Stream are deferred to ADR-030.
            SyscallNumber::Cambio => Self::handle_cambio(args, &ctx),
            SyscallNumber::Regalo => Self::handle_regalo(args, &ctx),
            SyscallNumber::Stream => Self::handle_stream(args, &ctx),

            // ADR-029 POSIX file storage syscalls — slots 53-72 reserved.
            // All 20 route through a single Enosys stub until the POSIX
            // backend lands (ADR-029 § Migration Path steps 4-9). Per-
            // syscall behavior is specified in ADR-029 § Decision 4's
            // table; one stub here avoids 20 lines of boilerplate while
            // the backend isn't written.
            SyscallNumber::FileOpen | SyscallNumber::FileCreate
            | SyscallNumber::FileClose | SyscallNumber::FileRead
            | SyscallNumber::FileWrite | SyscallNumber::FileSeek
            | SyscallNumber::FileTruncate | SyscallNumber::FileRename
            | SyscallNumber::FileUnlink | SyscallNumber::FileLink
            | SyscallNumber::FileSymlink
            | SyscallNumber::Mkdir | SyscallNumber::Rmdir
            | SyscallNumber::Opendir | SyscallNumber::Readdir
            | SyscallNumber::Stat | SyscallNumber::Fsync
            | SyscallNumber::AclGrant | SyscallNumber::AclRevoke
            | SyscallNumber::AclList => Self::handle_posix_stub(args, &ctx),
            SyscallNumber::VerifyVolumeHeader => {
                Self::handle_verify_volume_header(args, &ctx)
            }
            SyscallNumber::ReadVolumeHeader => {
                Self::handle_read_volume_header(args, &ctx)
            }
            SyscallNumber::InstallMasterKey => {
                Self::handle_install_master_key(args, &ctx)
            }
        }
    }

    // ========================================================================
    // Process lifecycle
    // ========================================================================

    /// SYS_EXIT: Terminate the calling task.
    ///
    /// Marks the task as Terminated, then yields to the scheduler via
    /// `yield_save_and_switch`. The Terminated task is never re-scheduled,
    /// so the yield effectively does not return.
    fn handle_exit(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let exit_code = args.arg1_u32();

        // Lock ordering: PER_CPU_SCHEDULER(1) — no higher locks held.
        //
        // We do three things atomically under the scheduler lock:
        //   1. Mark the task Terminated + record exit_code and parent.
        //   2. Call `purge_task` to establish the invariant that no
        //      scheduler-held state still references this TaskId. Before
        //      this step existed, the scheduler's `current_task` still
        //      pointed at the exiting task and stale `ready_queues[band]`
        //      entries relied on lazy cleanup during the next `schedule()`
        //      pop — a window during which concurrent teardown (below)
        //      could page-fault the next `Scheduler::schedule` call.
        //   3. Capture the parent TaskId for wake-up outside the lock.
        // ADR-034 §3: also capture the kernel stack to defer, and record
        // whether THIS call won the Running->Terminated transition. Only the
        // winner enqueues the self-referential set (enqueue-once) — a
        // double-exit or a fault racing a clean exit must not enqueue the
        // root/stack twice (a double-free).
        let (parent_to_wake, kstack_to_reclaim, won_transition) = {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_mut() {
                let (parent, kstack, won) = if let Some(task) =
                    sched.get_task_mut_pub(ctx.task_id)
                {
                    let already_terminated =
                        task.state == crate::scheduler::TaskState::Terminated;
                    task.state = crate::scheduler::TaskState::Terminated;
                    task.exit_code = exit_code;
                    // kernel_stack_top is 0 for the idle task (boot stack);
                    // user tasks carry a heap-allocated stack to free.
                    let kstack = if already_terminated { 0 } else { task.kernel_stack_top };
                    (task.parent_task, kstack, !already_terminated)
                } else {
                    (None, 0, false)
                };
                sched.purge_task(ctx.task_id);
                (parent, kstack, won)
            } else {
                (None, 0, false)
            }
        };


        // ADR-034 Phase B: latch this task's exit status into the global ring
        // BEFORE waking the parent. The parent's SYS_WAIT_TASK reads the code
        // from here keyed by (slot, generation) once the reaper has freed the
        // slot, and the record-then-wake order is what closes the lost-wakeup
        // window: a parent that re-checks the ring under its scheduler lock
        // (the lock the wake below must take) either sees this record or has
        // not yet blocked. Recorded once, by the transition winner.
        if won_transition {
            crate::record_task_exit(ctx.task_id, exit_code as i32, parent_to_wake);
        }

        // Wake the parent iff it is blocked waiting on THIS child (ADR-034
        // Phase B selective wake). A parent waiting on a different child, or
        // not waiting, is left alone — this child's exit is already latched in
        // the ring above for later collection. Must follow the ring record.
        if let Some(parent_id) = parent_to_wake {
            crate::wake_child_waiter(parent_id, ctx.task_id.slot());
        }

        // Reclaim capability table entries for the exiting process.
        // Lock ordering: CAPABILITY_MANAGER(4) — SCHEDULER(1) was already
        // released above, so we can safely acquire a higher-numbered lock.
        //
        // Per ADR-007 §"What this gives us", process exit invokes
        // revoke_all_for_process() to prevent stale capabilities from
        // accumulating in the capability table.
        let revoked_count = {
            let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
            if let Some(cap_mgr) = cap_guard.as_mut() {
                let count = cap_mgr.revoke_all_for_process(ctx.process_id).unwrap_or(0);
                // Drop the ProcessCapabilities table entry. Without this,
                // the next spawn into the same pid slot sees
                // register_process fail (slot already Some), grant_capability
                // fails (caller's ProcessId generation doesn't match the
                // stale entry's), and the new process boots with no caps.
                // Observable symptom before this fix: second `play <game>`
                // logged "ERROR: register_endpoint" and exit(1).
                let _ = cap_mgr.unregister_process(ctx.process_id);
                count
            } else {
                0
            }
        };

        // Clear this pid slot's reply-endpoint registration. REPLY_ENDPOINT
        // is set by register_endpoint via compare_exchange(0, ep), which
        // silently fails if a stale non-zero remains from a previous
        // process in this slot. The new process then has handle_write
        // stamp outgoing messages with the OLD process's reply endpoint,
        // so replies route to a queue nobody reads -- the new process
        // blocks forever on recv. Observable symptom before this fix:
        // game B after game A in the same pid slot rendered nothing and
        // was completely unresponsive (Ctrl+Q dead) because Client::open
        // never received Welcome.
        let slot = ctx.process_id.slot() as usize;
        if slot < crate::REPLY_ENDPOINT.len() {
            crate::REPLY_ENDPOINT[slot].store(0, core::sync::atomic::Ordering::Release);
        }


        // Revoke all channels the exiting process is
        // party to (as creator or peer). For each revoked channel, unmap
        // pages from the surviving peer, issue TLB shootdown, and free
        // the physical frames.
        //
        // Lock ordering: CHANNEL_MANAGER(5) → PROCESS_TABLE(6) →
        // FRAME_ALLOCATOR(7). CAPABILITY_MANAGER(4) was released above.
        let channels_revoked = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            if let Some(chan_mgr) = chan_guard.as_mut() {
                let revoked = chan_mgr.revoke_all_for_process(ctx.process_id);
                drop(chan_guard); // release CHANNEL_MANAGER(5) before PROCESS_TABLE(6)

                let count = revoked.len();
                for record in revoked.iter() {
                    Self::teardown_channel_mappings(record);
                }
                count
            } else {
                drop(chan_guard);
                0
            }
        };

        // ADR-027: cluster-departure cleanup. For every cluster the
        // exiting process was a joined member of, mark its member-state
        // Departed and consult the policy (cluster_policy::on_member_depart)
        // to decide whether the whole cluster must be torn down. For
        // RenderingLimb v1 the policy is "any departure is fatal" — the
        // surviving members lose their peer's mappings and need to bring
        // the limb back up cleanly. Empty for processes that aren't in
        // any cluster (the common case).
        //
        // Lock ordering: CLUSTER_MANAGER(5) released before
        // do_cluster_revoke re-acquires it + downstream locks. Sits
        // between channel cleanup (just above) and process-resource
        // reclaim (just below) — same shape as channels.
        let clusters_to_revoke: alloc::vec::Vec<crate::ipc::cluster::ClusterId> = {
            use crate::ipc::cluster::MemberState;
            use crate::ipc::cluster_policy::ClusterDepartureAction;

            let mut guard = crate::CLUSTER_MANAGER.lock();
            if let Some(mgr) = guard.as_mut() {
                let cluster_ids = mgr.mark_departed_for_process(ctx.process_id);
                let mut to_revoke = alloc::vec::Vec::new();
                for id in cluster_ids {
                    if let Ok(record) = mgr.get(id) {
                        // Find the now-Departed member with our pid;
                        // could be matched on multiple roles in
                        // theory (v1 disallows; check all anyway).
                        for member_slot in record.members.iter() {
                            if let Some(member) = member_slot.as_ref() {
                                if member.state == MemberState::Departed
                                    && member.joined_pid == Some(ctx.process_id)
                                    && matches!(
                                        crate::ipc::cluster_policy::on_member_depart(
                                            record.policy,
                                            member.role,
                                        ),
                                        ClusterDepartureAction::RevokeCluster
                                    ) {
                                        to_revoke.push(id);
                                        break; // one revoke per cluster
                                    }
                            }
                        }
                    }
                }
                to_revoke
            } else {
                alloc::vec::Vec::new()
            }
        }; // drop CLUSTER_MANAGER

        for id in &clusters_to_revoke {
            Self::do_cluster_revoke(
                *id,
                ctx.process_id,
                crate::audit::CLUSTER_REVOKE_REASON_MEMBER_EXIT,
            );
        }

        // Reclaim process resources: VMA regions, page table frames, heap.
        //
        // `destroy_process` calls `reclaim_user_vmas` (unmaps VMA-tracked
        // pages, frees frames), then `reclaim_process_page_tables` (frees
        // PML4/intermediate PT frames), then `reclaim_heap` (frees
        // contiguous heap region).
        //
        // Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7), valid.
        // `deferred_root` is the page-table root `destroy_process` chose NOT
        // to free inline (it is the dying task's active CR3/satp/TTBR0). It is
        // handed to the reaper below. `None` for a kernel task or an
        // already-reaped slot.
        let (heap_reclaimed, deferred_root) = {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            if let Some(pt) = pt_guard.as_mut() {
                if pt.slot_occupied(ctx.process_id) {
                    // Record the exiting process's Principal in the
                    // recent-exits ring before destroy_process bumps the
                    // generation. SYS_GET_PROCESS_PRINCIPAL falls back
                    // to this ring when an audit consumer queries a
                    // subject_pid whose process has already exited.
                    // Skipped when caller_principal is None (process
                    // never bound an identity — nothing to resolve).
                    if let Some(p) = ctx.caller_principal {
                        pt.record_exit(ctx.process_id, p);
                    }
                    let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
                    let root = pt.destroy_process(ctx.process_id, &mut fa_guard);
                    (true, root)
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            }
        };


        crate::audit::emit(crate::audit::RawAuditEvent::process_terminated(
            ctx.process_id, exit_code as i32, 0, crate::audit::now(), 0,
        ));

        crate::println!(
            "  [Exit] pid={} task={} code={} (reclaimed {} cap(s), {} chan(s), {} cluster(s){})",
            ctx.process_id.slot(),
            ctx.task_id.slot(),
            exit_code,
            revoked_count,
            channels_revoked,
            clusters_to_revoke.len(),
            if heap_reclaimed { ", heap+vma+pt" } else { "" }
        );

        // ADR-034 §3: defer the self-referential set — the page-table root
        // this CPU still runs through (CR3/satp/TTBR0) and the kernel stack it
        // still stands on — to this CPU's reaper. Both are in use *right now*;
        // freeing the root inline is the confirmed triple-fault, and the stack
        // can't free itself. `reaper::drain_local()` frees them from the idle
        // loop after the terminal yield below switches the CPU off them.
        //
        // Pushed under the per-CPU queue lock alone — every hierarchy lock was
        // released above, so this is not a lower-while-holding-higher
        // inversion. Safe to enqueue here because `purge_task` cleared
        // `current_task`, so the timer ISR takes its no-switch path
        // (`time_slice_expired()` is false with no current task): the dying
        // task is never involuntarily switched away between this push and the
        // terminal yield, so the item is durable before any context switch.
        // Enqueue-once: gated on winning the Running->Terminated transition.
        // Enqueue whenever we won the transition and this is a real task: even
        // a kernel task with no per-process root and no heap stack still owns a
        // scheduler slot the reaper must reclaim (ADR-034 Phase B). The idle
        // task never exits, so it never reaches here, but guard anyway.
        if won_transition && !ctx.task_id.is_idle() {
            let item = crate::reaper::ReclaimItem {
                root_phys: deferred_root.unwrap_or(0),
                kstack_top: kstack_to_reclaim,
                task_id: ctx.task_id,
            };
            if crate::local_reclaim_queue().lock().push(item).is_err() {
                // Structurally impossible (queue sized to MAX_TASKS, ADR-034
                // §5). If it ever happens, degrade to a bounded leak — the
                // resources stay allocated (as before ADR-034) but the kernel
                // stays live. Never panic or block in the death path.
                crate::println!(
                    "  [Exit] WARN: reclaim queue full; leaking root={:#x} kstack={:#x}",
                    item.root_phys,
                    item.kstack_top
                );
            }
        }

        // Yield to next task. Terminated tasks are never re-scheduled,
        // so this loop effectively does not return.
        loop {
            // SAFETY: We are on the kernel stack, scheduler lock is not held.
            // Yield switches to the next runnable task; terminated tasks are
            // never re-enqueued so this loop does not return.
            unsafe { crate::arch::yield_save_and_switch(); }
        }
    }

    /// SYS_MODULE_READY (36): advance the sequential boot-release chain.
    ///
    /// Called by each boot module's `_start` after it has finished init
    /// (endpoint registration, state setup, any other one-shot work) and
    /// is about to enter its service loop. The handler advances the
    /// `BOOT_MODULE_ORDER` cursor and wakes the next module in the
    /// roster, which was parked in `BlockReason::BootGate` by
    /// `load_boot_modules`.
    ///
    /// No arguments, no return payload. Identity-exempt (see
    /// `SyscallNumber::requires_identity`).
    ///
    /// Idempotent: if the chain is already complete or the calling task
    /// isn't a boot module, the call is a no-op.
    fn handle_module_ready(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        let next_tid = {
            let mut order = crate::BOOT_MODULE_ORDER.lock();
            order.advance()
        };
        if let Some(tid) = next_tid {
            crate::wake_task_on_cpu(tid);
        }
        Ok(0)
    }

    // ========================================================================
    // IPC: Write / Read
    // ========================================================================

    /// SYS_WRITE: Send data through an IPC endpoint.
    ///
    /// Args: arg1 = endpoint_id, arg2 = buffer (user vaddr), arg3 = len
    ///
    /// Pipeline: validate args → read user buffer → create Message →
    /// capability check + interceptor check → IPC enqueue.
    fn handle_write(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();
        let user_buf = args.arg2;
        let len = args.arg_usize(3);

        if len == 0 {
            return Ok(0);
        }
        if len > 256 {
            return Err(SyscallError::InvalidArg);
        }

        // Read user buffer into kernel. ADR-020 Phase B: typed
        // UserReadSlice replaces the raw (addr, len) pair.
        let slice = UserReadSlice::validate(ctx, user_buf, len)?;
        let mut kbuf = [0u8; 256];
        slice.read_into(&mut kbuf[..len])?;

        // Virtio-blk kernel response endpoint: writes here
        // skip the capability check and land in SHARDED_IPC. The kernel is
        // the only consumer; trust is by endpoint choice (mirror of the
        // POLICY_RESP_ENDPOINT pattern below). Note: NO scheduler wake —
        // `VirtioBlkDevice::call` polls for the reply on the same endpoint
        // after its wake-driver send, so an extra wake here is redundant
        // and (empirically) provokes a subtle interaction that stalls the
        // driver's own virtqueue self-test. The blocked kernel task on
        // MessageWait(25) will still resume when its timer slice runs.
        /// ARCHITECTURAL: endpoint 25 is the virtio-blk kernel→driver
        /// response slot in the CambiOS IPC number-space. The userspace
        /// driver recognizes it by number, so changing it is an ABI
        /// break coordinated across `user/virtio-blk` and every kernel
        /// callsite that sends to it.
        const BLK_KERNEL_RESP_ENDPOINT: u32 = 25;
        if endpoint_id == BLK_KERNEL_RESP_ENDPOINT {
            let ep = crate::ipc::EndpointId(endpoint_id);
            let mut msg = crate::ipc::Message::new(
                crate::ipc::EndpointId(ctx.process_id.slot()),
                ep,
            );
            if msg.set_payload(&kbuf[..len]).is_err() {
                return Err(SyscallError::InvalidArg);
            }
            if crate::SHARDED_IPC.send_message(ep, msg).is_err() {
                return Err(SyscallError::OutOfMemory);
            }
            return Ok(len as u64);
        }

        // Policy response interception — before any lock acquisition.
        // Writes to POLICY_RESP_ENDPOINT are consumed by the kernel (never
        // enter the IPC queue). Only the policy service may write here.
        if endpoint_id == crate::policy::POLICY_RESP_ENDPOINT {
            let expected_pid = crate::POLICY_SERVICE_PID.load(core::sync::atomic::Ordering::Acquire);
            if ctx.process_id.as_raw() != expected_pid {
                return Err(SyscallError::PermissionDenied);
            }
            if let Some((query_id, allowed)) = crate::policy::parse_response(&kbuf[..len]) {
                let task_id = {
                    let mut router = crate::POLICY_ROUTER.lock();
                    router.complete_query(query_id)
                };
                // POLICY_ROUTER lock dropped before scheduler wake
                if let Some(tid) = task_id {
                    let val = if allowed {
                        crate::policy::DECISION_ALLOW
                    } else {
                        crate::policy::DECISION_DENY
                    };
                    crate::policy::POLICY_DECISIONS[tid.slot() as usize]
                        .store(val, core::sync::atomic::Ordering::Release);
                    crate::wake_task_on_cpu(tid);
                }
                return Ok(len as u64);
            }
            return Err(SyscallError::InvalidArg);
        }

        // Build IPC message. `from` is the sender's reply endpoint (the
        // first endpoint they registered), so receivers can route replies
        // via `msg.from_endpoint()`. Falls back to the process slot if
        // the sender has never registered an endpoint.
        let endpoint = crate::ipc::EndpointId(endpoint_id);
        let slot = ctx.process_id.slot() as usize;
        let reply_ep = if slot < crate::REPLY_ENDPOINT.len() {
            crate::REPLY_ENDPOINT[slot].load(core::sync::atomic::Ordering::Acquire)
        } else {
            0
        };
        let from_ep = if reply_ep != 0 { reply_ep } else { ctx.process_id.slot() };
        let mut msg = crate::ipc::Message::new(
            crate::ipc::EndpointId(from_ep),
            endpoint,
        );
        if msg.set_payload(&kbuf[..len]).is_err() {
            return Err(SyscallError::InvalidArg);
        }

        // Lock ordering: IPC_MANAGER(3) → CAPABILITY_MANAGER(4)
        let mut ipc_guard = crate::IPC_MANAGER.lock();
        let cap_guard = crate::CAPABILITY_MANAGER.lock();

        let ipc_mgr = ipc_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
        let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

        // Distinguish security-relevant denials (capability + interceptor)
        // from operational backpressure (QueueFull). The audit ring is for
        // security events; logging queue-full as CapabilityDenied flooded
        // the ring during boot when a busy receiver (e.g., terminal-window
        // doing initial render) couldn't drain its 16-deep input queue
        // fast enough to absorb virtio-input's PointerMove stream — every
        // overflow showed up as a fake cap-denied event in audit-tail and
        // saturated serial. Operational errors return an EAGAIN-shaped
        // status so the caller can react, but no audit emit.
        match ipc_mgr.send_message_with_capability(ctx.process_id, endpoint, msg, cap_mgr) {
            Ok(()) => {}
            Err(crate::ipc::IpcError::PermissionDenied) => {
                crate::audit::emit(crate::audit::RawAuditEvent::capability_denied(
                    ctx.process_id, endpoint, crate::audit::now(), 0,
                ));
                return Err(SyscallError::PermissionDenied);
            }
            Err(crate::ipc::IpcError::QueueFull) => {
                return Err(SyscallError::OutOfMemory);
            }
            Err(_) => {
                return Err(SyscallError::InvalidArg);
            }
        }

        // Drop IPC/capability locks before acquiring scheduler (lock ordering)
        drop(cap_guard);
        drop(ipc_guard);

        // Audit: sampled IPC send event
        {
            use core::sync::atomic::{AtomicU32, Ordering};
            static IPC_SEND_COUNTER: AtomicU32 = AtomicU32::new(0);
            let sample = IPC_SEND_COUNTER.fetch_add(1, Ordering::Relaxed);
            if sample.is_multiple_of(crate::audit::AUDIT_IPC_SAMPLE_RATE) {
                crate::audit::emit(crate::audit::RawAuditEvent::ipc_send(
                    ctx.process_id, endpoint, len, crate::audit::now(), 0,
                ));
            }
        }

        // Wake any tasks blocked waiting for a message on this endpoint.
        // Lock ordering: PER_CPU_SCHEDULER(1) — no higher locks held.
        {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_mut() {
                sched.wake_message_waiters(endpoint_id);
            }
        }

        Ok(len as u64)
    }

    /// SYS_READ: Receive data from an IPC endpoint.
    ///
    /// Args: arg1 = endpoint_id, arg2 = buffer (user vaddr), arg3 = max_len
    ///
    /// Pipeline: capability check + interceptor check → IPC dequeue →
    /// write payload to user buffer. Returns bytes read (0 if queue empty).
    fn handle_read(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();
        let user_buf = args.arg2;
        let max_len = args.arg_usize(3);

        if max_len == 0 {
            return Ok(0);
        }
        if max_len > 256 {
            return Err(SyscallError::InvalidArg);
        }

        let endpoint = crate::ipc::EndpointId(endpoint_id);

        // Lock ordering: IPC_MANAGER(3) → CAPABILITY_MANAGER(4)
        let mut ipc_guard = crate::IPC_MANAGER.lock();
        let cap_guard = crate::CAPABILITY_MANAGER.lock();

        let ipc_mgr = ipc_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
        let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

        let msg = match ipc_mgr.recv_message_with_capability(ctx.process_id, endpoint, cap_mgr) {
            Ok(m) => m,
            Err(_) => {
                crate::audit::emit(crate::audit::RawAuditEvent::capability_denied(
                    ctx.process_id, endpoint, crate::audit::now(), 0,
                ));
                return Err(SyscallError::PermissionDenied);
            }
        };

        // Drop locks before touching page tables
        drop(cap_guard);
        drop(ipc_guard);

        match msg {
            Some(msg) => {
                let payload = msg.payload();
                let copy_len = core::cmp::min(payload.len(), max_len);

                // ADR-020 Phase B: validate the exact write amount, not
                // the user-supplied max_len — the slice type represents
                // "the N bytes we will actually write."
                let slice = UserWriteSlice::validate(ctx, user_buf, copy_len)?;
                slice.write_from(&payload[..copy_len])?;

                // Audit: sampled IPC recv event
                {
                    use core::sync::atomic::{AtomicU32, Ordering};
                    static IPC_RECV_COUNTER: AtomicU32 = AtomicU32::new(0);
                    let sample = IPC_RECV_COUNTER.fetch_add(1, Ordering::Relaxed);
                    if sample.is_multiple_of(crate::audit::AUDIT_IPC_SAMPLE_RATE) {
                        crate::audit::emit(crate::audit::RawAuditEvent::ipc_recv(
                            ctx.process_id, endpoint, copy_len, crate::audit::now(), 0,
                        ));
                    }
                }

                Ok(copy_len as u64)
            }
            None => Ok(0), // No message available
        }
    }

    // ========================================================================
    // Endpoint management
    // ========================================================================

    /// SYS_REGISTER_ENDPOINT: Register a message endpoint for this process.
    ///
    /// Args: arg1 = endpoint_id, arg2 = flags (reserved)
    ///
    /// Grants the calling process full capabilities (send/recv/delegate)
    /// on the specified endpoint.
    fn handle_register_endpoint(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();

        if endpoint_id >= crate::ipc::MAX_ENDPOINTS as u32 {
            return Err(SyscallError::EndpointNotFound);
        }

        let endpoint = crate::ipc::EndpointId(endpoint_id);

        // Lock ordering: CAPABILITY_MANAGER(4)
        let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
        let cap_mgr = cap_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        cap_mgr
            .grant_capability(ctx.process_id, endpoint, crate::ipc::CapabilityRights::FULL)
            .map_err(|_| SyscallError::PermissionDenied)?;

        crate::audit::emit(crate::audit::RawAuditEvent::capability_granted(
            ctx.process_id, ctx.process_id, endpoint, 0x0F, crate::audit::now(), 0,
        ));

        // Record the first-registered endpoint as this process's reply
        // endpoint. Subsequent register_endpoint calls do not overwrite
        // it — the first one wins. Receivers use msg.from_endpoint() to
        // route replies back to a queue the sender actually listens on.
        let slot = ctx.process_id.slot() as usize;
        if slot < crate::REPLY_ENDPOINT.len() {
            let _ = crate::REPLY_ENDPOINT[slot].compare_exchange(
                0,
                endpoint_id,
                core::sync::atomic::Ordering::Release,
                core::sync::atomic::Ordering::Relaxed,
            );
        }

        Ok(0)
    }

    // ========================================================================
    // Memory management
    // ========================================================================

    /// SYS_ALLOCATE: Allocate memory for process.
    ///
    /// Args: arg1 = size, arg2 = flags (reserved)
    ///
    /// Allocates a virtual address region via the process VMA tracker,
    /// allocates physical frames, maps them into the process address space,
    /// and returns the user virtual address.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    ///
    /// Performance: data frames are allocated from the per-CPU cache
    /// (no global lock). FRAME_ALLOCATOR is only locked briefly for
    /// map_page() calls that may need intermediate page table frames.
    fn handle_allocate(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let size = args.arg_usize(1);

        // SCAFFOLDING: per-call size cap is 64 MiB.
        // Why: enables large general-purpose allocations (texture staging,
        //      software-renderer back buffers, font atlases) without forcing
        //      channel use. Sized for the v1 endgame graphics target (ADR-011).
        // Replace when: a legitimate workload needs > 64 MiB in a single
        //      allocate call. See docs/ASSUMPTIONS.md.
        if size == 0 || size > 64 * 1024 * 1024 {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let num_pages = size.div_ceil(4096) as u32;

        // Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .ok_or(SyscallError::InvalidArg)?;

        let base_vaddr = vma.allocate_region(num_pages).ok_or(SyscallError::OutOfMemory)?;

        let hhdm = crate::hhdm_offset();

        for i in 0..num_pages as usize {
            let page_vaddr = base_vaddr + (i as u64 * 4096);

            // Allocate data frame from per-CPU cache (fast path: no global lock)
            let frame = match crate::cached_allocate_frame() {
                Ok(f) => f,
                Err(_) => {
                    // Rollback: unmap already-mapped pages and free their frames
                    let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
                    for j in 0..i {
                        let rollback_vaddr = base_vaddr + (j as u64 * 4096);
                        // SAFETY: cr3 is valid, pages were just mapped above.
                        unsafe {
                            let mut pte = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                            if let Ok(freed) = crate::memory::paging::unmap_page(&mut pte, rollback_vaddr) {
                                let _ = fa_guard.free(freed);
                            }
                        }
                    }
                    // Remove the VMA entry we just created
                    if let Some(pt) = pt_guard.as_mut() {
                        if let Some(vma) = pt.vma_mut(ctx.process_id) {
                            vma.free_region(base_vaddr);
                        }
                    }
                    return Err(SyscallError::OutOfMemory);
                }
            };

            // Zero the frame
            // SAFETY: Freshly allocated frame, HHDM-mapped.
            unsafe {
                core::ptr::write_bytes((frame.addr + hhdm) as *mut u8, 0, 4096);
            }

            // Map into process page table
            // FRAME_ALLOCATOR only needed here for potential page table frame alloc
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            // SAFETY: cr3 is valid (non-zero, checked above). Frame is fresh.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_page(
                    &mut pt,
                    page_vaddr,
                    frame.addr,
                    crate::memory::paging::flags::user_rw(),
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
            drop(fa_guard); // Release between loop iterations
        }

        Ok(base_vaddr)
    }

    /// SYS_FREE: Free allocated memory.
    ///
    /// Args: arg1 = ptr (user vaddr), arg2 = size (ignored — VMA tracks actual size)
    ///
    /// Looks up the allocation in the process VMA tracker, unmaps all pages,
    /// returns physical frames to the allocator, and removes the VMA entry.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_free(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let ptr = args.arg1;

        if ptr == 0 {
            return Err(SyscallError::InvalidArg);
        }
        if ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma_entry = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .and_then(|vma| vma.free_region(ptr))
            .ok_or(SyscallError::InvalidArg)?;

        // Unmap each page and return frame to per-CPU cache (fast path)
        for i in 0..vma_entry.num_pages as u64 {
            let page_vaddr = vma_entry.base_vaddr + i * 4096;
            // SAFETY: cr3 is valid (non-zero, checked above). These pages were
            // mapped by handle_allocate and recorded in the VMA tracker.
            unsafe {
                let mut pte = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                if let Ok(freed_frame) = crate::memory::paging::unmap_page(&mut pte, page_vaddr) {
                    let _ = crate::cached_free_frame(freed_frame);
                }
            }
        }

        Ok(0)
    }

    // ========================================================================
    // Scheduling
    // ========================================================================

    /// SYS_YIELD: Voluntarily yield CPU to the scheduler.
    ///
    /// Performs an immediate voluntary context switch via `yield_save_and_switch`.
    /// The scheduler moves the Running task to Ready, picks the next task, and
    /// switches. When this task is re-scheduled, execution resumes here and
    /// returns Ok(0) to user space.
    fn handle_yield(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        // Don't change task state — yield_save_and_switch calls schedule(),
        // which correctly moves Running → Ready and re-enqueues.
        // SAFETY: We are on the kernel stack, scheduler lock is not held.
        unsafe { crate::arch::yield_save_and_switch(); }
        Ok(0)
    }

    /// SYS_WAIT_IRQ: Block until a specific hardware interrupt fires.
    ///
    /// Args: arg1 = irq_number
    ///
    /// Registers the task as the handler for the given IRQ (if not already
    /// registered), blocks until the IRQ fires, then returns. Uses the
    /// restart pattern: block → yield → return on wake.
    fn handle_wait_irq(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let irq_num = args.arg1_u32();

        if irq_num >= MAX_DEVICE_IRQ {
            return Err(SyscallError::InvalidArg);
        }

        // Register this task as the IRQ handler and pin to this CPU (one-time setup).
        // Lock ordering: PER_CPU_SCHEDULER(1) → INTERRUPT_ROUTER(8)
        {
            let mut sched_guard = crate::local_scheduler().lock();
            let mut router_guard = crate::INTERRUPT_ROUTER.lock();

            let irq = crate::interrupts::routing::IrqNumber(irq_num as u8);
            let _ = router_guard.register(irq, ctx.task_id, 128);

            if let Some(sched) = sched_guard.as_mut() {
                if let Some(task) = sched.get_task_mut_pub(ctx.task_id) {
                    task.pinned = true;
                }

                // Re-route device IRQ to this CPU via I/O APIC (x86_64) or GIC SPI (AArch64)
                #[cfg(target_arch = "x86_64")]
                {
                    // SAFETY: GS base is valid after percpu_init; reading APIC ID is a
                    // pure read from the per-CPU data structure.
                    let local_apic_id = unsafe {
                        crate::arch::x86_64::percpu::current_percpu().apic_id() as u8
                    };
                    // SAFETY: I/O APIC is initialized before user tasks run.
                    unsafe {
                        crate::arch::x86_64::ioapic::set_irq_destination(irq_num, local_apic_id);
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    if irq_num >= 32 {
                        // SAFETY: GIC distributor is initialized before user tasks run.
                        unsafe { crate::arch::aarch64::gic::enable_spi(irq_num); }
                    }
                }
            }
            // Drop locks before yield
        }

        // Block and yield. The device ISR wakes this task (IoWait → Ready).
        // CRITICAL: Disable interrupts before block_task to prevent the timer
        // ISR from seeing Blocked state before yield_save_and_switch saves context.
        // See handle_recv_msg for detailed race explanation.
        // SAFETY: Disabling interrupts is safe at kernel privilege level.
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
        {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_mut() {
                let _ = sched.block_task(
                    ctx.task_id,
                    crate::scheduler::BlockReason::IoWait(irq_num),
                );
            }
            // IrqSpinlock drop: restores IF to disabled (our cli)
        }
        // SAFETY: We are on the kernel stack, scheduler lock is not held.
        unsafe { crate::arch::yield_save_and_switch(); }
        // Woken by device ISR — IRQ has fired
        Ok(0)
    }

    // ========================================================================
    // Info syscalls
    // ========================================================================

    /// SYS_GET_PID: Get current process ID
    fn handle_get_pid(_args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        Ok(ctx.process_id.slot() as u64)
    }

    /// SYS_GET_TIME: Get system time in ticks
    fn handle_get_time(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        let ticks = crate::scheduler::Timer::get_ticks();
        Ok(ticks)
    }

    /// SYS_PRINT: Print a user-provided string to serial console.
    ///
    /// Args: arg1 = buffer pointer (user vaddr), arg2 = length
    fn handle_print(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let user_buf = args.arg1;
        let len = args.arg_usize(2);

        if len == 0 {
            return Ok(0);
        }
        if len > 256 {
            return Err(SyscallError::InvalidArg);
        }

        // ADR-020 Phase B: read user text via typed slice.
        let slice = UserReadSlice::validate(ctx, user_buf, len)?;
        let mut buf = [0u8; 256];
        slice.read_into(&mut buf[..len])?;

        for &byte in &buf[..len] {
            crate::io::print(format_args!("{}", byte as char));
        }

        Ok(len as u64)
    }

    // ========================================================================
    // Identity syscalls
    // ========================================================================

    /// SYS_BIND_PRINCIPAL: Bind a cryptographic Principal to a process.
    ///
    /// Args: arg1 = target process_id, arg2 = pubkey_ptr (user vaddr),
    ///        arg3 = pubkey_len (must be 32)
    ///
    /// Restricted: only the bootstrap Principal can call this. This is the
    /// identity service's privilege — it binds Principals to processes on
    /// behalf of the system.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) only.
    fn handle_bind_principal(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let target_pid = args.arg1_u32();
        let pubkey_ptr = args.arg2;
        let pubkey_len = args.arg_usize(3);

        // Public key must be exactly 32 bytes (Ed25519)
        if pubkey_len != 32 {
            return Err(SyscallError::InvalidArg);
        }

        // ADR-020 Phase B: read 32-byte public key via typed slice.
        let pubkey_slice = UserReadSlice::validate(ctx, pubkey_ptr, 32)?;
        let mut pubkey = [0u8; 32];
        pubkey_slice.read_into(&mut pubkey)?;

        // Restriction: only the bootstrap Principal can bind Principals.
        // caller_principal is already resolved by dispatch().
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        let caller = ctx.caller_principal.as_ref().ok_or(SyscallError::PermissionDenied)?;
        if *caller != bootstrap {
            return Err(SyscallError::PermissionDenied);
        }

        // Bind the Principal to the target process
        let target = ProcessId::new(target_pid, 0);
        let principal = crate::ipc::Principal::from_public_key(pubkey);

        let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
        let cap_mgr = cap_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        cap_mgr
            .bind_principal(target, principal)
            .map_err(|_| SyscallError::PermissionDenied)?;

        Ok(0)
    }

    /// SYS_GET_PRINCIPAL: Read the calling process's bound Principal.
    ///
    /// Args: arg1 = out_buf (user vaddr), arg2 = buf_len (must be >= 32)
    ///
    /// Writes 32 bytes of public key to the user buffer. Returns 32 on
    /// success, or error if no Principal is bound to this process.
    ///
    /// No lock needed — caller_principal resolved by dispatch().
    fn handle_get_principal(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let out_buf = args.arg1;
        let buf_len = args.arg_usize(2);

        if buf_len < 32 {
            return Err(SyscallError::InvalidArg);
        }

        // caller_principal already resolved by dispatch()
        let principal = ctx.caller_principal.as_ref().ok_or(SyscallError::InvalidArg)?;

        // ADR-020 Phase B: write 32-byte AID via typed slice.
        let out_slice = UserWriteSlice::validate(ctx, out_buf, 32)?;
        out_slice.write_from(principal.aid())?;

        Ok(32)
    }

    // ========================================================================
    // IPC: RecvMsg (identity-aware receive)
    // ========================================================================

    /// SYS_RECV_MSG: Receive an IPC message with sender identity metadata.
    ///
    /// Args: arg1 = endpoint_id, arg2 = buf (user vaddr), arg3 = buf_len
    ///
    /// Writes to buf: [sender_principal:32][from_endpoint_le:4][payload:N]
    /// Returns total bytes written (36 + payload_len), 0 if no message.
    ///
    /// Lock ordering: IPC_MANAGER(3) → CAPABILITY_MANAGER(4), then page tables.
    fn handle_recv_msg(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();
        let user_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        // Need at least 36 bytes for header (32 principal + 4 endpoint)
        if buf_len < 36 {
            return Err(SyscallError::InvalidArg);
        }

        let endpoint = crate::ipc::EndpointId(endpoint_id);

        // Restart loop: try to receive, block + yield if empty, re-check on wake.
        // Eliminates the two-step wake pattern — user space gets the message
        // directly without needing to retry.
        loop {
            // Lock ordering: IPC_MANAGER(3) → CAPABILITY_MANAGER(4)
            let msg = {
                let mut ipc_guard = crate::IPC_MANAGER.lock();
                let cap_guard = crate::CAPABILITY_MANAGER.lock();

                let ipc_mgr = ipc_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
                let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

                ipc_mgr
                    .recv_message_with_capability(ctx.process_id, endpoint, cap_mgr)
                    .map_err(|_| SyscallError::PermissionDenied)?
                // Drop IPC/capability locks here
            };

            // Virtio-blk kernel-command endpoint: kernel-origin
            // commands land in `SHARDED_IPC` (not `IPC_MANAGER`). Scoped
            // narrowly to endpoint 26 so other recv paths — which have no
            // reason to consult SHARDED_IPC today — are unaffected.
            /// ARCHITECTURAL: endpoint 26 is the virtio-blk kernel-command
            /// slot in the CambiOS IPC number-space; see
            /// `BLK_KERNEL_RESP_ENDPOINT` above for the ABI-break caveat.
            const BLK_KERNEL_CMD_ENDPOINT: u32 = 26;
            let msg = if endpoint_id == BLK_KERNEL_CMD_ENDPOINT {
                msg.or_else(|| crate::SHARDED_IPC.recv_message(endpoint))
            } else {
                msg
            };

            if let Some(msg) = msg {
                let payload = msg.payload();
                let payload_len = core::cmp::min(payload.len(), buf_len - 36);

                // Build response: [principal:32][from:4][payload:N]
                let mut header = [0u8; 36];

                if let Some(principal) = msg.sender_principal {
                    header[0..32].copy_from_slice(principal.aid());
                }
                header[32..36].copy_from_slice(&msg.from.0.to_le_bytes());

                // ADR-020 Phase B: header and payload are two separate
                // typed slices at adjacent addresses. Each validates its
                // own (addr, len) independently. `checked_add` is
                // defense-in-depth per docs/threat-model.md F3 —
                // practically safe because `validate` already rejects
                // `user_buf >= USER_SPACE_END` (< 2^47), but removes the
                // cross-function safety argument.
                let header_slice = UserWriteSlice::validate(ctx, user_buf, 36)?;
                header_slice.write_from(&header)?;
                if payload_len > 0 {
                    let payload_addr = user_buf
                        .checked_add(36)
                        .ok_or(SyscallError::InvalidArg)?;
                    let payload_slice =
                        UserWriteSlice::validate(ctx, payload_addr, payload_len)?;
                    payload_slice.write_from(&payload[..payload_len])?;
                }

                return Ok((36 + payload_len) as u64);
            }

            // No message — block and yield. The IPC send path
            // (handle_write) calls wake_message_waiters() after enqueue.
            //
            // CRITICAL: Disable interrupts BEFORE block_task to prevent a
            // race with the timer ISR. If the ISR fires between block_task
            // (state=Blocked) and yield_save_and_switch (saves saved_rsp),
            // the ISR skips saving RSP (because !Running), leaving stale
            // saved_rsp. When the task is later woken, iretq restores from
            // garbage → triple fault. cli ensures the ISR cannot observe
            // the Blocked state before yield saves the correct context.
            // IrqSpinlock preserves the disabled state on drop.
            // yield_save_and_switch also does cli (redundant) then saves
            // and switches. .Lyield_resume does sti on wake.
            // SAFETY: Disabling interrupts is safe at kernel privilege level.
            #[cfg(target_arch = "x86_64")]
            unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
            #[cfg(target_arch = "aarch64")]
            unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
            {
                let mut sched_guard = crate::local_scheduler().lock();
                if let Some(sched) = sched_guard.as_mut() {
                    let _ = sched.block_task(
                        ctx.task_id,
                        crate::scheduler::BlockReason::MessageWait(endpoint_id),
                    );
                }
                // IrqSpinlock drop: restores IF to our cli state (disabled)
            }
            // Interrupts still disabled — yield_save_and_switch saves
            // correct context before any ISR can see the Blocked state.
            // SAFETY: We are on the kernel stack, scheduler lock is not held.
            unsafe { crate::arch::yield_save_and_switch(); }
            // Woken — loop back and re-check the queue
        }
    }

    /// SYS_TRY_RECV_MSG (37): non-blocking variant of RecvMsg.
    ///
    /// Returns the bytes written on success (≥36 = 32-byte principal +
    /// 4-byte from-endpoint + payload), or 0 if the queue is empty.
    /// Does NOT block — services that poll multiple endpoints use this
    /// to avoid parking on one endpoint while another has a wake-up
    /// ready (virtio-blk: ep24 user, ep26 kernel).
    ///
    /// This mirrors `handle_recv_msg` but with the block-and-yield
    /// tail replaced by a bare `Ok(0)` return. Keep the two in sync if
    /// the header format or capability check changes.
    fn handle_try_recv_msg(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let endpoint_id = args.arg1_u32();
        let user_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        if buf_len < 36 {
            return Err(SyscallError::InvalidArg);
        }

        let endpoint = crate::ipc::EndpointId(endpoint_id);

        // Lock ordering matches handle_recv_msg: IPC_MANAGER(3) → CAPABILITY_MANAGER(4)
        let msg = {
            let mut ipc_guard = crate::IPC_MANAGER.lock();
            let cap_guard = crate::CAPABILITY_MANAGER.lock();

            let ipc_mgr = ipc_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

            ipc_mgr
                .recv_message_with_capability(ctx.process_id, endpoint, cap_mgr)
                .map_err(|_| SyscallError::PermissionDenied)?
        };

        // Virtio-blk kernel-command endpoint (same special case as handle_recv_msg)
        /// ARCHITECTURAL: endpoint 26 — see handle_recv_msg for the ABI
        /// caveat. Declared twice because both recv paths need the
        /// literal for the `if endpoint_id == …` guard.
        const BLK_KERNEL_CMD_ENDPOINT: u32 = 26;
        let msg = if endpoint_id == BLK_KERNEL_CMD_ENDPOINT {
            msg.or_else(|| crate::SHARDED_IPC.recv_message(endpoint))
        } else {
            msg
        };

        if let Some(msg) = msg {
            let payload = msg.payload();
            let payload_len = core::cmp::min(payload.len(), buf_len - 36);

            let mut header = [0u8; 36];
            if let Some(principal) = msg.sender_principal {
                header[0..32].copy_from_slice(principal.aid());
            }
            header[32..36].copy_from_slice(&msg.from.0.to_le_bytes());

            // ADR-020 Phase B: mirror handle_recv_msg — typed slices
            // per segment (header + payload). `checked_add` mirrors the
            // defense-in-depth in handle_recv_msg (docs/threat-model.md F3).
            let header_slice = UserWriteSlice::validate(ctx, user_buf, 36)?;
            header_slice.write_from(&header)?;
            if payload_len > 0 {
                let payload_addr = user_buf
                    .checked_add(36)
                    .ok_or(SyscallError::InvalidArg)?;
                let payload_slice =
                    UserWriteSlice::validate(ctx, payload_addr, payload_len)?;
                payload_slice.write_from(&payload[..payload_len])?;
            }

            Ok((36 + payload_len) as u64)
        } else {
            // Non-blocking: caller polls and decides what to do.
            Ok(0)
        }
    }

    // ========================================================================
    // ObjectStore syscalls
    // ========================================================================

    /// SYS_OBJ_PUT: Store a CambiObject in the object store.
    ///
    /// Args: arg1 = content_ptr (user vaddr), arg2 = content_len, arg3 = out_hash (user vaddr)
    ///
    /// Creates a CambiObject with author/owner = caller's Principal.
    /// Writes 32-byte content hash to out_hash. Returns 0 on success.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) then OBJECT_STORE(9) — sequential, not nested.
    fn handle_obj_put(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        // Ensure disk store is initialized (handshake outside lock).
        crate::fs::lazy_disk::ensure_disk_store();

        let content_ptr = args.arg1;
        let content_len = args.arg_usize(2);
        let out_hash = args.arg3;

        if content_len == 0 || content_len > OBJ_PUT_MAX_CONTENT {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // ADR-020 Phase B: read content via typed slice.
        let content_slice = UserReadSlice::validate(ctx, content_ptr, content_len)?;
        let mut kbuf = [0u8; OBJ_PUT_MAX_CONTENT];
        content_slice.read_into(&mut kbuf[..content_len])?;

        // caller_principal already resolved by dispatch(); identity gate
        // guarantees it's non-zero for this syscall.
        let principal = *ctx.caller_principal.as_ref().ok_or(SyscallError::PermissionDenied)?;

        // Get current time for created_at
        let ticks = crate::scheduler::Timer::get_ticks();

        // Create CambiObject with caller as author and owner
        let content_vec = {
            extern crate alloc;
            let mut v = alloc::vec::Vec::with_capacity(content_len);
            v.extend_from_slice(&kbuf[..content_len]);
            v
        };
        let obj = crate::fs::CambiObject::new(principal, content_vec, ticks);
        let hash = obj.content_hash;

        // Store in OBJECT_STORE (lock position 8)
        let mut store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        store.put(obj).map_err(|e| match e {
            crate::fs::StoreError::CapacityExceeded => SyscallError::OutOfMemory,
            crate::fs::StoreError::InvalidObject => SyscallError::InvalidArg,
            _ => SyscallError::InvalidArg,
        })?;
        drop(store_guard);

        // ADR-020 Phase B: write 32-byte hash via typed slice.
        let hash_slice = UserWriteSlice::validate(ctx, out_hash, 32)?;
        hash_slice.write_from(&hash)?;

        Ok(0)
    }

    /// SYS_OBJ_GET: Retrieve object content by content hash.
    ///
    /// Args: arg1 = hash_ptr (user vaddr, 32 bytes), arg2 = out_buf, arg3 = out_buf_len
    ///
    /// Returns bytes written on success, or negative error.
    /// Verifies the object's Ed25519 signature before returning content.
    /// Objects with empty (unsigned) signatures are returned without verification
    /// (graceful degradation for legacy/unsigned objects).
    ///
    /// Lock ordering: OBJECT_STORE(9) only.
    fn handle_obj_get(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        crate::fs::lazy_disk::ensure_disk_store();

        let hash_ptr = args.arg1;
        let out_buf = args.arg2;
        let out_buf_len = args.arg_usize(3);

        if out_buf_len == 0 || ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // ADR-020 Phase B: read 32-byte hash via typed slice.
        let hash_slice = UserReadSlice::validate(ctx, hash_ptr, 32)?;
        let mut hash = [0u8; 32];
        hash_slice.read_into(&mut hash)?;

        // Look up in OBJECT_STORE. The trait's `get` now returns an owned
        // CambiObject, so the lock can be released before signature
        // verification and the userspace write. Keeping the lock scope
        // minimal is a precondition for future disk-backed backends that
        // must not hold OBJECT_STORE across block I/O.
        let obj = {
            let mut store_guard = crate::OBJECT_STORE.lock();
            let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            store.get(&hash).map_err(|e| match e {
                crate::fs::StoreError::NotFound => SyscallError::EndpointNotFound,
                _ => SyscallError::InvalidArg,
            })?
        };

        // Verify signature if the object is signed (non-empty signature).
        // Unsigned objects (empty signature) are returned as-is for backward
        // compatibility — the caller can check the signature field if needed.
        // Routes through crate::crypto::verify (Step 4 / Change A) so v1.5
        // can swap in a per-record sig_algo dispatch with one match arm.
        if !obj.signature.is_empty_sig()
            && !crate::crypto::verify(
                crate::crypto::SignatureAlgo::Ed25519,
                crate::crypto::PublicKeyRef::Ed25519(&obj.owner),
                &obj.content,
                crate::crypto::SignatureRef::Ed25519(&obj.signature.data),
            ) {
                return Err(SyscallError::PermissionDenied);
            }

        let copy_len = core::cmp::min(obj.content.len(), out_buf_len);

        // ADR-020 Phase B: validate exact write amount.
        let out_slice = UserWriteSlice::validate(ctx, out_buf, copy_len)?;
        out_slice.write_from(&obj.content[..copy_len])?;

        Ok(copy_len as u64)
    }

    /// SYS_OBJ_DELETE: Delete an object from the store.
    ///
    /// Args: arg1 = hash_ptr (user vaddr, 32 bytes)
    ///
    /// Only the object's owner can delete. Returns 0 on success.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) then OBJECT_STORE(9) — sequential.
    fn handle_obj_delete(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        crate::fs::lazy_disk::ensure_disk_store();

        let hash_ptr = args.arg1;

        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // ADR-020 Phase B: read 32-byte hash via typed slice.
        let hash_slice = UserReadSlice::validate(ctx, hash_ptr, 32)?;
        let mut hash = [0u8; 32];
        hash_slice.read_into(&mut hash)?;

        // caller_principal already resolved by dispatch()
        let principal = ctx.caller_principal.as_ref().ok_or(SyscallError::PermissionDenied)?;

        // Check ownership then delete. `get` returns owned — ownership check
        // does not keep a borrow alive across the subsequent `delete` call.
        let mut store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;


        let obj = store.get(&hash).map_err(|_| SyscallError::EndpointNotFound)?;
        if obj.owner != *principal.aid() {
            return Err(SyscallError::PermissionDenied);
        }

        store.delete(&hash).map_err(|_| SyscallError::EndpointNotFound)?;

        Ok(0)
    }

    /// SYS_OBJ_LIST: List all object hashes in the store.
    ///
    /// Args: arg1 = out_buf (user vaddr), arg2 = out_buf_len
    ///
    /// Writes packed 32-byte hashes. Returns number of objects listed.
    ///
    /// Lock ordering: OBJECT_STORE(9) only.
    fn handle_obj_list(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        crate::fs::lazy_disk::ensure_disk_store();

        let out_buf = args.arg1;
        let out_buf_len = args.arg_usize(2);

        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let max_objects = out_buf_len / 32;
        if max_objects == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let mut store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        let listing = store.list().map_err(|_| SyscallError::InvalidArg)?;
        drop(store_guard);

        let count = core::cmp::min(listing.len(), max_objects);

        // ADR-020 Phase B: write each 32-byte hash via its own typed
        // slice at the per-index offset. The slice type doesn't support
        // partial / offset writes, so one slice per hash is the
        // natural shape; validation cost is tiny (cheap checks only).
        // `checked_add` on `out_buf + offset` is defense-in-depth
        // (docs/threat-model.md F3). Practically safe because `validate`
        // already rejects `out_buf >= USER_SPACE_END` and max_objects is
        // bounded, but removes the cross-function safety argument.
        for (i, (hash, _meta)) in listing.iter().take(count).enumerate() {
            let offset = (i * 32) as u64;
            let entry_addr = out_buf
                .checked_add(offset)
                .ok_or(SyscallError::InvalidArg)?;
            let hash_slice = UserWriteSlice::validate(ctx, entry_addr, 32)?;
            hash_slice.write_from(hash)?;
        }

        Ok(count as u64)
    }

    // ========================================================================
    // Key Store syscalls
    // ========================================================================

    /// SYS_OBJ_PUT_SIGNED: Store a pre-signed CambiObject.
    ///
    /// Args: arg1 = content_ptr, arg2 = content_len, arg3 = sig_ptr (64 bytes),
    ///        arg4 = out_hash_ptr (32 bytes)
    ///
    /// Like ObjPut but accepts a pre-computed Ed25519 signature. The kernel
    /// verifies the signature against the caller's Principal before storing.
    /// This is the path for signed objects when the key-store service holds
    /// the private key.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) then OBJECT_STORE(9) — sequential.
    fn handle_obj_put_signed(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        crate::fs::lazy_disk::ensure_disk_store();

        let content_ptr = args.arg1;
        let content_len = args.arg_usize(2);
        let sig_ptr = args.arg3;
        let out_hash = args.arg4;

        if content_len == 0 || content_len > OBJ_PUT_MAX_CONTENT {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // ADR-020 Phase B: three independent typed slices — content in,
        // signature in, hash out.
        let content_slice = UserReadSlice::validate(ctx, content_ptr, content_len)?;
        let mut kbuf = [0u8; OBJ_PUT_MAX_CONTENT];
        content_slice.read_into(&mut kbuf[..content_len])?;

        let sig_slice = UserReadSlice::validate(ctx, sig_ptr, 64)?;
        let mut sig_bytes = [0u8; 64];
        sig_slice.read_into(&mut sig_bytes)?;
        let signature = crate::fs::SignatureBytes { data: sig_bytes };

        // caller_principal already resolved by dispatch()
        let principal = *ctx.caller_principal.as_ref().ok_or(SyscallError::PermissionDenied)?;

        // Verify the signature against the caller's current key and content.
        // Routes through crate::crypto::verify (Step 4 / Change A); the
        // Principal accessor is `current_key_bytes()` (Step 5 / Change D),
        // whose body becomes a keystore lookup at v1.5 per ADR-025.
        if !crate::crypto::verify(
            crate::crypto::SignatureAlgo::Ed25519,
            crate::crypto::PublicKeyRef::Ed25519(principal.current_key_bytes()),
            &kbuf[..content_len],
            crate::crypto::SignatureRef::Ed25519(&signature.data),
        ) {
            return Err(SyscallError::PermissionDenied);
        }

        // Get current time for created_at
        let ticks = crate::scheduler::Timer::get_ticks();

        // Create CambiObject with the verified signature
        let content_vec = {
            extern crate alloc;
            let mut v = alloc::vec::Vec::with_capacity(content_len);
            v.extend_from_slice(&kbuf[..content_len]);
            v
        };
        let mut obj = crate::fs::CambiObject::new(principal, content_vec, ticks);
        obj.signature = signature;
        let hash = obj.content_hash;

        // Store in OBJECT_STORE (lock position 8)
        let mut store_guard = crate::OBJECT_STORE.lock();
        let store = store_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        store.put(obj).map_err(|e| match e {
            crate::fs::StoreError::CapacityExceeded => SyscallError::OutOfMemory,
            crate::fs::StoreError::InvalidObject => SyscallError::InvalidArg,
            _ => SyscallError::InvalidArg,
        })?;
        drop(store_guard);

        let hash_slice = UserWriteSlice::validate(ctx, out_hash, 32)?;
        hash_slice.write_from(&hash)?;

        Ok(0)
    }

    // ========================================================================
    // Device / DMA support
    // ========================================================================

    /// SYS_MAP_MMIO: Map device MMIO into user-space.
    ///
    /// Args: arg1 = physical address (page-aligned), arg2 = num_pages
    ///
    /// Maps a device MMIO region into the calling process with uncacheable
    /// page attributes. The kernel validates the physical address is not in
    /// a RAM region (only device MMIO ranges are permitted).
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_map_mmio(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let phys_addr = args.arg1;
        let num_pages = args.arg2_u32();

        // SCAFFOLDING: per-call MMIO mapping cap is 16384 pages (64 MiB).
        // Why: a 4K framebuffer at 32bpp is 8192 pages (32 MiB); HDR (64bpp)
        //      doubles that. Sized for the v1 endgame graphics target
        //      (ADR-011) — a single display's framebuffer fits in one call,
        //      with room for 5K headroom. Multi-monitor compositors use
        //      multiple MapMmio calls (one per display), so per-call ceiling
        //      at 64 MiB is sufficient.
        // Replace when: single-display HDR surfaces exceed 64 MiB, or a
        //      workload needs a single large MMIO region larger than that.
        //      See docs/ASSUMPTIONS.md.
        if num_pages == 0 || num_pages > 16384 {
            return Err(SyscallError::InvalidArg);
        }
        if phys_addr & 0xFFF != 0 {
            return Err(SyscallError::InvalidArg); // Must be page-aligned
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Security: reject mapping RAM regions as MMIO. The check
        // walks the recorded USABLE extents (populated from the Limine
        // memmap by add_region) and rejects any overlap. This permits
        // MMIO BARs that land *inside* the RAM address range — a real
        // shape on QEMU x86_64 with -m 4G, where the 32-bit PCI MMIO
        // hole at 0xFE000000-0xFEC00000 sits below the high RAM extent
        // starting at 0x100000000. The previous linear-ceiling check
        // (`phys_addr < total_count*4096`) rejected those legitimate
        // MMIO ranges.
        {
            let fa_guard = crate::FRAME_ALLOCATOR.lock();
            let map_len = (num_pages as u64).saturating_mul(4096);
            if fa_guard.is_ram_overlap(phys_addr, map_len) {
                return Err(SyscallError::PermissionDenied);
            }
        }

        // Allocate virtual address range via VMA tracker
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .ok_or(SyscallError::InvalidArg)?;

        let base_vaddr = vma
            .allocate_region(num_pages)
            .ok_or(SyscallError::OutOfMemory)?;

        // Map each page with uncacheable (MMIO) flags
        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
        for i in 0..num_pages as u64 {
            let page_vaddr = base_vaddr + i * 4096;
            let page_phys = phys_addr + i * 4096;

            // SAFETY: cr3 is valid, phys_addr is validated above.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_page(
                    &mut pt,
                    page_vaddr,
                    page_phys,
                    crate::memory::paging::flags::user_mmio(),
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
        }
        drop(fa_guard);
        drop(pt_guard);

        Ok(base_vaddr)
    }

    /// SYS_ALLOC_DMA: Allocate physically contiguous DMA-capable pages.
    ///
    /// Args: arg1 = num_pages, arg2 = flags (reserved), arg3 = out_paddr_ptr
    ///
    /// Allocates contiguous physical frames with guard pages (unmapped pages
    /// on both sides) to contain device overflows. Maps into the calling
    /// process and writes the physical address to *out_paddr_ptr.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_alloc_dma(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let num_pages = args.arg1_u32();
        let _flags = args.arg2_u32(); // Reserved for IOMMU hints
        let out_paddr_ptr = args.arg3;

        // SCAFFOLDING: per-call DMA allocation cap is 32768 pages (128 MiB).
        // Why: GPU command buffers and GPU-visible memory regions need
        //      physically-contiguous DMA backing well above virtio-net's
        //      64-page envelope. Sized for the v1 endgame graphics target
        //      (ADR-011). GiB-class GPU texture regions remain a future
        //      bump — higher limits interact with allocate_contiguous's
        //      linear-scan cost on the frame allocator bitmap.
        // Replace when: GPU driver work needs GiB-class single DMA
        //      allocations, at which point also revisit the
        //      allocate_contiguous algorithm. See docs/ASSUMPTIONS.md.
        if num_pages == 0 || num_pages > 32768 {
            return Err(SyscallError::InvalidArg);
        }
        if out_paddr_ptr == 0 || out_paddr_ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Allocate contiguous physical frames
        let base_frame = {
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            fa_guard
                .allocate_contiguous(num_pages as usize)
                .map_err(|_| SyscallError::OutOfMemory)?
        };
        let base_phys = base_frame.addr;

        // Allocate virtual address range: num_pages + 2 guard pages (before/after)
        let total_pages = num_pages + 2;
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .ok_or(SyscallError::InvalidArg)?;

        let region_vaddr = vma
            .allocate_region(total_pages)
            .ok_or(SyscallError::OutOfMemory)?;

        // The actual DMA mapping starts after the first guard page
        let dma_vaddr = region_vaddr + 4096;

        let hhdm = crate::hhdm_offset();
        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();

        // Map the DMA pages (guard pages at region_vaddr and region_vaddr + (num_pages+1)*4096
        // are left unmapped — any device overflow faults into unmapped memory)
        for i in 0..num_pages as u64 {
            let page_vaddr = dma_vaddr + i * 4096;
            let page_phys = base_phys + i * 4096;

            // Zero the frame
            // SAFETY: Freshly allocated contiguous frame, HHDM-mapped.
            unsafe {
                core::ptr::write_bytes((page_phys + hhdm) as *mut u8, 0, 4096);
            }

            // SAFETY: cr3 is valid, frame is fresh.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_page(
                    &mut pt,
                    page_vaddr,
                    page_phys,
                    crate::memory::paging::flags::user_rw(),
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
        }
        drop(fa_guard);
        drop(pt_guard);

        // ADR-020 Phase B: write 8-byte physical address via typed slice.
        let paddr_bytes = base_phys.to_le_bytes();
        let paddr_slice = UserWriteSlice::validate(ctx, out_paddr_ptr, 8)?;
        paddr_slice.write_from(&paddr_bytes)?;

        Ok(dma_vaddr)
    }

    /// SYS_MAP_FRAMEBUFFER: Map a Limine-reported framebuffer (selected by
    /// `index`) into the calling process's address space, and write a
    /// 32-byte `FramebufferDescriptor` to the user-provided output buffer.
    ///
    /// Args: arg1 = framebuffer_index (u32), arg2 = out_desc_ptr,
    ///       arg3 = out_desc_len (must be ≥ FB_DESC_SIZE)
    ///
    /// The kernel holds the physical framebuffer address; userspace never
    /// passes it in. This is the [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md)
    /// per-display scanout path: a multi-monitor compositor calls this once
    /// per display.
    ///
    /// Capability-gated: caller must hold
    /// `CapabilityKind::MapFramebuffer`. Without it, returns
    /// `PermissionDenied`.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) → PROCESS_TABLE(6) → FRAME_ALLOCATOR(7).
    fn handle_map_framebuffer(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let index = args.arg1_u32() as usize;
        let out_desc_ptr = args.arg2;
        let out_desc_len = args.arg_usize(3);

        /// Wire-format size of the descriptor written to userspace.
        /// ARCHITECTURAL: 32 bytes is the documented v1 layout — see the
        /// SyscallNumber::MapFramebuffer doc for the field map. Future
        /// extensions need a new syscall + cap, not a quiet size bump.
        const FB_DESC_SIZE: usize = 32;

        if out_desc_len < FB_DESC_SIZE {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Capability check.
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::PermissionDenied)?;
            let has_cap = cap_mgr
                .has_system_capability(
                    ctx.process_id,
                    crate::ipc::capability::CapabilityKind::MapFramebuffer,
                )
                .unwrap_or(false);
            if !has_cap {
                return Err(SyscallError::PermissionDenied);
            }
        }

        // Look up the requested framebuffer in the kernel-owned BootInfo.
        let info = crate::boot::info();
        let fb = info
            .framebuffers()
            .nth(index)
            .ok_or(SyscallError::InvalidArg)?;

        // Compute the framebuffer footprint in pages, page-aligning the
        // physical base just in case.
        let phys_base = fb.phys_addr & !0xFFF;
        let phys_offset_in_page = (fb.phys_addr & 0xFFF) as u64;
        let total_bytes = fb.size_bytes() + phys_offset_in_page;
        let num_pages = total_bytes.div_ceil(4096) as u32;

        // Allocate VMA region for the user-side mapping.
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let vma = pt_guard
            .as_mut()
            .and_then(|pt| pt.vma_mut(ctx.process_id))
            .ok_or(SyscallError::InvalidArg)?;
        let region_vaddr = vma
            .allocate_region(num_pages)
            .ok_or(SyscallError::OutOfMemory)?;

        // Map each page with uncacheable (MMIO) flags.
        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
        for i in 0..num_pages as u64 {
            let page_vaddr = region_vaddr + i * 4096;
            let page_phys = phys_base + i * 4096;

            // SAFETY: cr3 is valid; phys_base comes from BootInfo which
            // was populated from Limine's framebuffer response, and
            // framebuffer memory is outside the frame allocator's
            // tracked range (Limine reports it as Framebuffer, not Usable).
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_page(
                    &mut pt,
                    page_vaddr,
                    page_phys,
                    crate::memory::paging::flags::user_mmio(),
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
        }
        drop(fa_guard);
        drop(pt_guard);

        // The user vaddr is the start of the mapped region plus the
        // intra-page offset (preserves alignment to whatever Limine
        // returned, even though Limine's FB is page-aligned in practice).
        let user_vaddr = region_vaddr + phys_offset_in_page;

        // Build the 32-byte descriptor (little-endian, packed layout).
        let mut desc = [0u8; FB_DESC_SIZE];
        desc[0..8].copy_from_slice(&user_vaddr.to_le_bytes());
        desc[8..12].copy_from_slice(&fb.width.to_le_bytes());
        desc[12..16].copy_from_slice(&fb.height.to_le_bytes());
        desc[16..20].copy_from_slice(&fb.pitch.to_le_bytes());
        desc[20..22].copy_from_slice(&fb.bpp.to_le_bytes());
        desc[22] = fb.red_mask_size;
        desc[23] = fb.red_mask_shift;
        desc[24] = fb.green_mask_size;
        desc[25] = fb.green_mask_shift;
        desc[26] = fb.blue_mask_size;
        desc[27] = fb.blue_mask_shift;
        // desc[28..32] reserved (zeroed)

        // ADR-020 Phase B: write 32-byte framebuffer descriptor via typed slice.
        let desc_slice = UserWriteSlice::validate(ctx, out_desc_ptr, FB_DESC_SIZE)?;
        desc_slice.write_from(&desc)?;

        Ok(0)
    }

    /// SYS_DEVICE_INFO: Query PCI device info by index.
    ///
    /// Args: arg1 = device index, arg2 = out_buf ptr, arg3 = buf_len
    ///
    /// Writes a fixed-format device descriptor to the user buffer:
    ///   [vendor_id:2][device_id:2][class:1][subclass:1][bus:1][device:1]
    ///   [function:1][pad:1][bar_count:1][pad:1]
    ///   [bar0_addr:8][bar0_size:4][pad:4] × 6
    /// Total: 12 + 6×16 = 108 bytes
    ///
    /// Arch-agnostic: reads [`crate::pci::get_device`], which is populated
    /// from port-I/O mechanism 1 on x86_64 (`scan`), ECAM on aarch64, and
    /// either ECAM or virtio-mmio on riscv64 depending on what the boot
    /// path discovered.
    fn handle_device_info(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let index = args.arg1_u32() as usize;
        let out_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        /// ARCHITECTURAL: on-wire size of the `SYS_DEVICE_INFO` descriptor —
        /// 12-byte header + 6 × 16-byte BAR records. Every userspace
        /// consumer hard-codes this length; changing it is an ABI break.
        const DESCRIPTOR_SIZE: usize = 108;

        if buf_len < DESCRIPTOR_SIZE {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let dev = crate::pci::get_device(index).ok_or(SyscallError::InvalidArg)?;

        let mut desc = [0u8; DESCRIPTOR_SIZE];
        // Header: vendor, device, class, subclass, bus, dev, func, pad, bar_count, pad
        desc[0..2].copy_from_slice(&dev.vendor_id.to_le_bytes());
        desc[2..4].copy_from_slice(&dev.device_id.to_le_bytes());
        desc[4] = dev.class;
        desc[5] = dev.subclass;
        desc[6] = dev.bus;
        desc[7] = dev.device;
        desc[8] = dev.function;
        desc[9] = dev.prog_if;
        // Count non-zero BARs
        desc[10] = dev.bars.iter().filter(|&&b| b != 0).count() as u8;
        desc[11] = 0; // pad

        // BARs: 6 × [addr:8][size:4][is_io:1][pad:3]
        for i in 0..6 {
            let offset = 12 + i * 16;
            desc[offset..offset + 8].copy_from_slice(&dev.bars[i].to_le_bytes());
            desc[offset + 8..offset + 12].copy_from_slice(&dev.bar_sizes[i].to_le_bytes());
            desc[offset + 12] = if dev.bar_is_io[i] { 1 } else { 0 };
            // remaining pad bytes already zero
        }

        // ADR-020 Phase B: write 108-byte device descriptor via typed slice.
        let desc_slice = UserWriteSlice::validate(ctx, out_buf, DESCRIPTOR_SIZE)?;
        desc_slice.write_from(&desc)?;

        Ok(0)
    }

    /// SYS_VIRTIO_MODERN_CAPS: write kernel-parsed virtio-modern caps for a
    /// PCI device into a user buffer.
    ///
    /// Args: arg1 = device_index (u32), arg2 = out_buf (user vaddr),
    ///       arg3 = buf_len (usize, must equal
    ///              `size_of::<pci::VirtioModernCaps>()`).
    ///
    /// Writes the 64-byte `VirtioModernCaps` struct to `out_buf`. Returns
    /// 0 on success, `InvalidArg` on bad index or buffer. Uses ADR-020
    /// `UserWriteSlice` from day one — the `(addr, len)` pair is
    /// validated into a typed slice before any write.
    fn handle_virtio_modern_caps(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::syscalls::user_slice::UserWriteSlice;

        let index = args.arg1_u32() as usize;
        let out_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        /// ARCHITECTURAL: on-wire size of `VirtioModernCaps` as parsed
        /// by the kernel and consumed by userspace virtio-modern drivers.
        /// Tied to the layout of `crate::pci::VirtioModernCaps`; size
        /// changes are ABI breaks that require coordinated updates in
        /// every virtio-modern user-space transport.
        const CAPS_SIZE: usize = core::mem::size_of::<crate::pci::VirtioModernCaps>();
        if buf_len != CAPS_SIZE {
            return Err(SyscallError::InvalidArg);
        }

        // Typed-slice validation (ADR-020): cr3 non-zero, canonical range,
        // length bounds, no overflow. Consume below with `write_from`.
        let slice = UserWriteSlice::validate(ctx, out_buf, buf_len)?;

        let dev = crate::pci::get_device(index).ok_or(SyscallError::InvalidArg)?;
        let caps = dev.virtio_modern;

        // SAFETY: `VirtioModernCaps` is `#[repr(C)]` with plain u8 / u32
        // fields and fixed-size pad arrays; no padding reads uninitialized
        // memory, no references, no drop glue. Viewing as a byte slice of
        // its own size is well-defined. Borrow lifetime bounded by `caps`
        // on the local stack.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &caps as *const crate::pci::VirtioModernCaps as *const u8,
                CAPS_SIZE,
            )
        };
        slice.write_from(bytes)?;
        Ok(0)
    }

    /// SYS_PORT_IO: Validated port I/O from user-space.
    ///
    /// Args: arg1 = port (u16), arg2 = value (for writes), arg3 = flags
    ///   flags bit 0: 0=read, 1=write
    ///   flags bits 2:1: 0=byte, 1=word, 2=dword
    ///
    /// The kernel validates the port is within a PCI device's I/O BAR range
    /// before performing the operation. This prevents user-space from accessing
    /// arbitrary ports (PIC, PIT, PCI config space, etc.).
    #[cfg(target_arch = "x86_64")]
    fn handle_port_io(args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        let port = args.arg1 as u16;
        let value = args.arg2 as u32;
        let flags = args.arg3 as u32;
        let is_write = (flags & 1) != 0;
        let width = (flags >> 1) & 0x3; // 0=byte, 1=word, 2=dword

        // Validate port is within a PCI device I/O BAR
        if !crate::pci::is_port_in_pci_bar(port) {
            return Err(SyscallError::PermissionDenied);
        }

        // Validate width alignment
        match width {
            1 if port & 1 != 0 => return Err(SyscallError::InvalidArg), // word: 2-byte aligned
            2 if port & 3 != 0 => return Err(SyscallError::InvalidArg), // dword: 4-byte aligned
            0..=2 => {}
            _ => return Err(SyscallError::InvalidArg),
        }

        if is_write {
            match width {
                0 => {
                    // SAFETY: Port validated against PCI I/O BARs above.
                    let p = unsafe { crate::arch::x86_64::portio::Port8::new(port) };
                    p.write(value as u8);
                }
                1 => {
                    // SAFETY: Port validated, 2-byte aligned.
                    let p = unsafe { crate::arch::x86_64::portio::Port16::new(port) };
                    p.write(value as u16);
                }
                2 => {
                    // SAFETY: Port validated, 4-byte aligned. Use inline asm for 32-bit.
                    unsafe {
                        core::arch::asm!(
                            "out dx, eax",
                            in("dx") port,
                            in("eax") value,
                            options(nomem, nostack, preserves_flags),
                        );
                    }
                }
                _ => unreachable!(),
            }
            Ok(0)
        } else {
            let result = match width {
                0 => {
                    // SAFETY: Port validated against PCI I/O BARs above.
                    let p = unsafe { crate::arch::x86_64::portio::Port8::new(port) };
                    p.read() as u64
                }
                1 => {
                    // SAFETY: Port validated, 2-byte aligned.
                    let p = unsafe { crate::arch::x86_64::portio::Port16::new(port) };
                    p.read() as u64
                }
                2 => {
                    let v: u32;
                    // SAFETY: Port validated against PCI BAR, 4-byte aligned. 32-bit IN instruction.
                    unsafe {
                        core::arch::asm!(
                            "in eax, dx",
                            in("dx") port,
                            out("eax") v,
                            options(nomem, nostack, preserves_flags),
                        );
                    }
                    v as u64
                }
                _ => unreachable!(),
            };
            Ok(result)
        }
    }

    /// SYS_PORT_IO stub for non-x86_64 targets.
    #[cfg(not(target_arch = "x86_64"))]
    fn handle_port_io(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    // ========================================================================
    // Shell / interactive: ConsoleRead, Spawn, WaitTask
    // ========================================================================

    /// SYS_CONSOLE_READ: Read bytes from the serial console (polling mode).
    ///
    /// Args: arg1 = user buffer pointer, arg2 = max_len
    /// Returns: number of bytes read (0 if no data available)
    fn handle_console_read(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let user_buf = args.arg1;
        let max_len = args.arg_usize(2);

        if max_len == 0 {
            return Ok(0);
        }
        if max_len > MAX_USER_BUFFER {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Try to read one byte (polling — non-blocking)
        match crate::io::read_byte() {
            Some(byte) => {
                // ADR-020 Phase B: write single byte via typed slice.
                let kbuf = [byte];
                let slice = UserWriteSlice::validate(ctx, user_buf, 1)?;
                slice.write_from(&kbuf)?;
                Ok(1)
            }
            None => Ok(0),
        }
    }

    /// SYS_SPAWN: Spawn a boot module by name.
    ///
    /// Args: arg1 = name_ptr (user), arg2 = name_len
    /// Returns: new task ID on success, negative error otherwise.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7), then
    /// CAPABILITY_MANAGER(4) separately after dropping the first two.
    fn handle_spawn(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::loader::{self, SignedBinaryVerifier};
        use crate::scheduler::Priority;
        use crate::ipc::capability::CapabilityKind;

        let name_ptr = args.arg1;
        let name_len = args.arg_usize(2);

        if name_len == 0 || name_len > 64 {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // ADR-008: check CreateProcess authority before any resource
        // allocation. CAPABILITY_MANAGER lock level = 4, no other locks
        // held yet.
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            if let Some(cap_mgr) = cap_guard.as_ref() {
                let has_right = cap_mgr
                    .has_system_capability(ctx.process_id, CapabilityKind::CreateProcess)
                    .unwrap_or(false);
                if !has_right {
                    return Err(SyscallError::PermissionDenied);
                }
            }
        }

        // ADR-020 Phase B: read module name via typed slice.
        let name_slice = UserReadSlice::validate(ctx, name_ptr, name_len)?;
        let mut name_buf = [0u8; 64];
        name_slice.read_into(&mut name_buf[..name_len])?;
        let name = &name_buf[..name_len];

        // Look up module in boot module registry
        let (module_addr, module_size) = crate::BOOT_MODULE_REGISTRY
            .lock()
            .find_by_name(name)
            .ok_or(SyscallError::InvalidArg)?;

        // SAFETY: module_addr points to Limine EXECUTABLE_AND_MODULES memory,
        // which is valid for the kernel's lifetime via HHDM.
        let binary = unsafe { core::slice::from_raw_parts(module_addr, module_size) };

        // Use signed verifier with bootstrap key
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        let verifier = SignedBinaryVerifier::with_key(*bootstrap.current_key_bytes());


        // Lock ordering: SCHEDULER(1) → PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
        let mut sched_guard = crate::local_scheduler().lock();
        let mut pt_guard = crate::PROCESS_TABLE.lock();
        let mut fa_guard = crate::FRAME_ALLOCATOR.lock();

        let sched = sched_guard.as_mut().ok_or(SyscallError::OutOfMemory)?;
        let pt = pt_guard.as_mut().ok_or(SyscallError::OutOfMemory)?;

        // Process table allocates the slot internally;
        // ProcessId returned in the result.
        let result = loader::load_elf_process(
            binary,
            Priority::NORMAL,
            &verifier,
            pt,
            &mut fa_guard,
            sched,
        ).map_err(|_| SyscallError::OutOfMemory)?;
        let process_id = result.process_id;

        let new_task_id = result.task_id;

        // Set parent on the new task so handle_exit can wake us
        if let Some(task) = sched.get_task_mut_pub(new_task_id) {
            task.parent_task = Some(ctx.task_id);
        }

        // Register task in CPU map
        let cpu_id = {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: GS base is valid after percpu_init; pure read from per-CPU data.
            { unsafe { crate::arch::x86_64::percpu::current_percpu().cpu_id() } }
            #[cfg(target_arch = "aarch64")]
            // SAFETY: TPIDR_EL1 base is valid after percpu_init; pure read from per-CPU data.
            { unsafe { crate::arch::aarch64::percpu::current_percpu().cpu_id() } }
            #[cfg(target_arch = "riscv64")]
            // SAFETY: tp is valid after percpu_init; pure read from per-CPU data.
            { unsafe { crate::arch::riscv64::percpu::current_percpu().cpu_id() } }
        };
        crate::set_task_cpu(new_task_id.slot(), cpu_id as u16);

        // Drop all locks before acquiring CAPABILITY_MANAGER(4)
        // Note: CAPABILITY_MANAGER is level 4, lower than SCHEDULER(1), but
        // we already released SCHEDULER. The ordering constraint is about
        // simultaneous holding, not sequential acquisition.
        drop(sched_guard);
        drop(fa_guard);
        drop(pt_guard);

        // Register capabilities for the new process (CAPABILITY_MANAGER lock = level 4)
        {
            let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
            if let Some(cap_mgr) = cap_guard.as_mut() {
                let _ = cap_mgr.register_process(process_id);
                // Grant send/receive on all endpoints (spawned processes are trusted boot modules)
                for ep in 0..crate::ipc::MAX_ENDPOINTS as u32 {
                    let _ = cap_mgr.grant_capability(
                        process_id,
                        crate::ipc::EndpointId(ep),
                        crate::ipc::CapabilityRights { send: true, receive: true, delegate: false, revoke: false },
                    );
                }
                // ADR-008: spawned processes inherit CreateProcess
                // (trusted boot modules only for now).
                let _ = cap_mgr.grant_system_capability(
                    process_id,
                    CapabilityKind::CreateProcess,
                );
                // ADR-005: spawned processes may create channels.
                let _ = cap_mgr.grant_system_capability(
                    process_id,
                    CapabilityKind::CreateChannel,
                );
                // ADR-027: spawned processes may register service clusters
                // (same trust posture as CreateChannel — clusters are
                // bookkeeping over channels per ADR-027 § Decision 1).
                let _ = cap_mgr.grant_system_capability(
                    process_id,
                    CapabilityKind::CreateCluster,
                );
                // T-7 Phase A (docs/threat-model.md): only the compositor
                // gets EmitInputAudit. The cap was over-granted to every
                // spawned module in the original landing (mirroring
                // CreateProcess / CreateChannel) — security-review
                // 2026-04-25 caught the forgery surface that creates: any
                // shell-spawned app (games, terminal-window) holding the
                // cap could call SYS_AUDIT_EMIT_INPUT_FOCUS with an
                // arbitrary owner_principal, fabricating focus-transition
                // audit entries that look like legitimate compositor
                // emissions. Narrowing to name == "compositor" closes the
                // forgery vector now without waiting for Frame-B.
                if name == b"compositor" {
                    let _ = cap_mgr.grant_system_capability(
                        process_id,
                        CapabilityKind::EmitInputAudit,
                    );
                }
                // Bind bootstrap Principal
                if !bootstrap.is_zero() {
                    let _ = cap_mgr.bind_principal(process_id, bootstrap);
                }
            }
        }

        crate::audit::emit(crate::audit::RawAuditEvent::process_created(
            process_id, ctx.process_id, crate::audit::now(), 0,
        ));

        crate::println!(
            "  [Spawn] '{}' → task {} process {} (parent=task {})",
            core::str::from_utf8(name).unwrap_or("?"),
            new_task_id.slot(), process_id.slot(), ctx.task_id.slot()
        );

        // ADR-034 Phase B.4: return the full (slot, generation) handle. The
        // parent passes it back verbatim to SYS_WAIT_TASK, which keys the exit
        // ring by it — so a reaped+reused slot is detected by generation.
        Ok(new_task_id.as_raw())
    }

    /// SYS_WAIT_TASK: Block until a child task exits.
    ///
    /// Args: arg1 = child task ID
    /// Returns: child's exit code
    fn handle_wait_task(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::scheduler::BlockReason;

        // ADR-034 Phase B.4: the ABI carries the full (slot, generation) handle
        // the parent received from spawn. A child whose slot was reaped and
        // reused mismatches the generation and is detected, not silently
        // resolved to the new occupant.
        let child_id = crate::scheduler::TaskId::from_raw(args.arg1);
        let child_slot = child_id.slot();

        // Fast path: the child already exited. The global exit ring outlives
        // the reaper freeing the slot and is CPU-agnostic, so this covers a
        // child that exited on any CPU, before or after reaping.
        if let Some((code, parent)) = crate::lookup_task_exit(child_id) {
            if parent != Some(ctx.task_id) {
                return Err(SyscallError::PermissionDenied);
            }
            return Ok(code as u64);
        }

        // Not recorded as exited → the child should still be live. Resolve it
        // (possibly cross-CPU — the load balancer may have migrated it) to
        // authorize the caller and read its state.
        match crate::task_parent_and_state(child_id) {
            Some((parent, state, exit_code)) => {
                if parent != Some(ctx.task_id) {
                    return Err(SyscallError::PermissionDenied);
                }
                if state == crate::scheduler::TaskState::Terminated {
                    // Exited; the ring write just hasn't landed in our view.
                    // The live latched exit_code is authoritative.
                    return Ok(exit_code as u64);
                }
                // Alive → block below.
            }
            None => {
                // Not live. But the child may have exited AND been reaped in
                // the gap between the fast-path ring lookup above and this
                // resolve (interrupts are enabled here, so we can be preempted
                // for a full quantum, and the child's CPU reaps promptly from
                // its idle loop). The exit code is now only in the ring — the
                // slot is gone and its generation bumped — so re-check the ring
                // before declaring not-found, or a clean exit is reported as a
                // spurious error (the shell-waits-on-a-game common case).
                if let Some((code, parent)) = crate::lookup_task_exit(child_id) {
                    if parent != Some(ctx.task_id) {
                        return Err(SyscallError::PermissionDenied);
                    }
                    return Ok(code as u64);
                }
                // Genuinely unknown handle, or the exit aged out of the ring.
                return Err(SyscallError::InvalidArg);
            }
        }

        // Block until the child exits. H5: disable interrupts BEFORE marking
        // Blocked so neither the timer ISR nor the cross-CPU waker acts on a
        // half-set state; then re-check the ring UNDER our scheduler lock — the
        // lock `wake_child_waiter` must take — to close the lost-wakeup window.
        // handle_exit records the ring before waking us, so we either see the
        // record here (and skip blocking) or block and get woken; the wake
        // cannot run until we release this lock after blocking.
        // SAFETY: disabling interrupts is sound at kernel privilege; it is
        // re-enabled on the next task's restored context after the yield below
        // (or explicitly on the no-block return path).
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
        // SAFETY: as above; `daifset, #2` masks IRQ at EL1.
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }

        let raced_exit = {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(found) = crate::lookup_task_exit(child_id) {
                Some(found) // child exited between our resolve and now — don't block
            } else {
                if let Some(sched) = sched_guard.as_mut() {
                    let _ = sched.block_task(ctx.task_id, BlockReason::ChildWait(child_slot));
                }
                None
            }
            // IrqSpinlock drop: IF stays disabled (our cli is still in effect).
        };

        if let Some((code, parent)) = raced_exit {
            // We never blocked — restore interrupts and return.
            // SAFETY: re-enabling interrupts is sound at kernel privilege; it
            // pairs with the `cli` above on the path where we did not block,
            // restoring the interrupts-enabled state syscall handlers run in.
            #[cfg(target_arch = "x86_64")]
            unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
            // SAFETY: as above; `daifclr, #2` unmasks IRQ at EL1.
            #[cfg(target_arch = "aarch64")]
            unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)); }
            if parent != Some(ctx.task_id) {
                return Err(SyscallError::PermissionDenied);
            }
            return Ok(code as u64);
        }

        // Blocked. Yield; the child's exit (selective wake) sets us Ready.
        // yield re-enables interrupts via the next task's restored context.
        // SAFETY: scheduler lock released, on the kernel stack.
        unsafe { crate::arch::yield_save_and_switch(); }

        // Woken: the child has exited and recorded the ring. The selective
        // wake guarantees we are only woken for OUR child, so a single check
        // suffices — no spurious-sibling re-block loop.
        if let Some((code, parent)) = crate::lookup_task_exit(child_id) {
            if parent != Some(ctx.task_id) {
                return Err(SyscallError::PermissionDenied);
            }
            return Ok(code as u64);
        }

        // The exit aged out of the ring before we read it (a waiter slower than
        // TASK_EXIT_RING_SIZE subsequent exits — ADR-034 Residual Risks).
        // Typed not-found; preserves the pre-Phase-B "0 on missing" shape.
        Ok(0)
    }

    /// SYS_REVOKE_CAPABILITY: Revoke a capability held by another process on
    /// a given endpoint.
    ///
    /// Args: arg1 = target_process_id (u32), arg2 = endpoint_id (u32)
    ///
    /// Authority — v0 (per ADR-007 §"Who can revoke"):
    ///   Only the bootstrap Principal can call this. Matches the restriction
    ///   pattern of `handle_bind_principal`.
    ///
    /// Future work will relax this to also accept: the original grantor of the
    /// capability, and any process holding the `revoke` right on the endpoint
    /// (once the policy service exists as the mediator for those paths).
    ///
    /// The argument shape will refactor from `(pid, endpoint)` to a single
    /// `CapabilityHandle` once channels force a system-wide capability
    /// registry into existence.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) — no higher locks held.
    fn handle_revoke_capability(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let target_pid = crate::ipc::ProcessId::new(args.arg1_u32(), 0);
        let endpoint_id = crate::ipc::EndpointId(args.arg2_u32());

        // Read the bootstrap Principal once at the syscall boundary.
        // Passed into CapabilityManager::revoke() as the authority reference,
        // so the primitive stays testable without touching globals.
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();

        // Lock ordering: CAPABILITY_MANAGER(4)
        let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
        let cap_mgr = cap_guard.as_mut().ok_or(SyscallError::InvalidArg)?;

        // caller_principal already resolved by dispatch()
        let revoker_principal = *ctx.caller_principal.as_ref().ok_or(SyscallError::PermissionDenied)?;

        // Delegate to the primitive. revoke() performs the authority check
        // (revoker_principal == bootstrap) and the table mutation atomically
        // under the lock we hold.
        cap_mgr
            .revoke(target_pid, endpoint_id, revoker_principal, bootstrap)
            .map_err(|e| match e {
                crate::ipc::capability::CapabilityError::AccessDenied => SyscallError::PermissionDenied,
                crate::ipc::capability::CapabilityError::ProcessNotFound => SyscallError::InvalidArg,
                crate::ipc::capability::CapabilityError::EndpointNotFound => SyscallError::EndpointNotFound,
                _ => SyscallError::InvalidArg,
            })?;

        crate::println!(
            "  [RevokeCapability] caller_pid={} target_pid={} endpoint={} — revoked",
            ctx.process_id.slot(), target_pid.slot(), endpoint_id.0
        );

        Ok(0)
    }

    // ========================================================================
    // Shared-memory channels (ADR-005)
    // ========================================================================

    /// SYS_CHANNEL_CREATE: Create a shared-memory channel.
    ///
    /// Args: arg1 = size_pages, arg2 = peer_principal_ptr (*const u8, 32 bytes),
    ///       arg3 = role (0=Producer, 1=Consumer, 2=Bidirectional),
    ///       arg4 = out_vaddr_ptr (*mut u64, creator's mapping address)
    ///
    /// Returns: ChannelId (u64) on success, negative error on failure.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) → CHANNEL_MANAGER(5) →
    /// PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_channel_create(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::{ChannelRole, MAX_CHANNEL_PAGES, MIN_CHANNEL_PAGES};

        let size_pages = args.arg1_u32();
        let peer_principal_ptr = args.arg2;
        let role_raw = args.arg3 as u32;
        let out_vaddr_ptr = args.arg4;

        // --- Validate args ---
        if !(MIN_CHANNEL_PAGES..=MAX_CHANNEL_PAGES).contains(&size_pages) {
            return Err(SyscallError::InvalidArg);
        }
        let role = ChannelRole::from_u32(role_raw).ok_or(SyscallError::InvalidArg)?;
        if peer_principal_ptr == 0 || peer_principal_ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if out_vaddr_ptr == 0 || out_vaddr_ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // --- ADR-020 Phase B: read 32-byte peer Principal via typed slice ---
        let peer_slice = UserReadSlice::validate(ctx, peer_principal_ptr, 32)?;
        let mut peer_key = [0u8; 32];
        peer_slice.read_into(&mut peer_key)?;
        let peer_principal = crate::ipc::Principal::from_public_key(peer_key);

        // --- Check CreateChannel capability; principal from dispatch() ---
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

            let has_cap = cap_mgr
                .has_system_capability(ctx.process_id, crate::ipc::capability::CapabilityKind::CreateChannel)
                .map_err(|_| SyscallError::PermissionDenied)?;
            if !has_cap {
                return Err(SyscallError::PermissionDenied);
            }
        } // drop CAPABILITY_MANAGER(4)
        let creator_principal = *ctx.caller_principal.as_ref().ok_or(SyscallError::PermissionDenied)?;

        // --- Allocate contiguous physical frames ---
        let base_phys = {
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            fa_guard
                .allocate_contiguous(size_pages as usize)
                .map_err(|_| SyscallError::OutOfMemory)?
                .addr
        }; // drop FRAME_ALLOCATOR(7)

        // Zero the channel memory.
        let hhdm = crate::hhdm_offset();
        // SAFETY: Freshly allocated contiguous frames, HHDM-mapped, exclusive.
        unsafe {
            core::ptr::write_bytes(
                (base_phys + hhdm) as *mut u8,
                0,
                size_pages as usize * 4096,
            );
        }

        // --- Allocate VMA region + map into creator's page table ---
        let creator_vaddr = {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            let vma = pt_guard
                .as_mut()
                .and_then(|pt| pt.vma_mut(ctx.process_id))
                .ok_or(SyscallError::InvalidArg)?;

            let vaddr = vma
                .allocate_region(size_pages)
                .ok_or(SyscallError::OutOfMemory)?;

            // Map pages into creator's address space.
            let creator_flags = if role.creator_writable() {
                crate::memory::paging::flags::user_rw()
            } else {
                crate::memory::paging::flags::user_ro()
            };

            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            // SAFETY: ctx.cr3 is a valid PML4/L0 for this process.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_range(
                    &mut pt,
                    vaddr,
                    base_phys,
                    size_pages as usize,
                    creator_flags,
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
            drop(fa_guard);
            drop(pt_guard);
            vaddr
        };

        // --- Register in ChannelManager ---
        let tick = crate::scheduler::Timer::get_ticks();

        let channel_id = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            chan_mgr
                .create(crate::ipc::channel::ChannelCreateParams {
                    creator_principal,
                    peer_principal,
                    creator_pid: ctx.process_id,
                    role,
                    num_pages: size_pages,
                    physical_base: base_phys,
                    creator_vaddr,
                    created_at_tick: tick,
                })
                .map_err(|_| SyscallError::OutOfMemory)?
        }; // drop CHANNEL_MANAGER(5)

        // --- ADR-020 Phase B: write 8-byte creator_vaddr via typed slice ---
        let vaddr_bytes = creator_vaddr.to_le_bytes();
        let vaddr_slice = UserWriteSlice::validate(ctx, out_vaddr_ptr, 8)?;
        vaddr_slice.write_from(&vaddr_bytes)?;

        crate::audit::emit(crate::audit::RawAuditEvent::channel_created(
            ctx.process_id, channel_id.as_raw(), size_pages, crate::audit::now(), 0,
        ));

        crate::println!(
            "  [ChannelCreate] pid={} id={} pages={} role={:?} → vaddr={:#x}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            size_pages,
            role,
            creator_vaddr,
        );

        Ok(channel_id.as_raw())
    }

    /// SYS_CHANNEL_ATTACH: Attach to an existing channel as the named peer.
    ///
    /// Args: arg1 = channel_id (u64)
    ///
    /// Returns: user-space virtual address of the shared region, or negative error.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) → CHANNEL_MANAGER(5) →
    /// PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_channel_attach(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::ChannelId;

        let channel_id = ChannelId::from_raw(args.arg1);

        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // caller_principal already resolved by dispatch()
        let caller_principal = *ctx.caller_principal.as_ref().ok_or(SyscallError::PermissionDenied)?;

        // --- Read channel record to get physical_base, num_pages, role ---
        let (physical_base, num_pages, peer_writable) = {
            let chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            let record = chan_mgr.get(channel_id).map_err(|_| SyscallError::InvalidArg)?;

            // Verify state and principal before allocating anything.
            if record.state != crate::ipc::channel::ChannelState::AwaitingAttach {
                return Err(SyscallError::InvalidArg);
            }
            if record.peer_principal != caller_principal {
                return Err(SyscallError::PermissionDenied);
            }

            (record.physical_base, record.num_pages, record.role.peer_writable())
        }; // drop CHANNEL_MANAGER(5) — will re-acquire below for the attach mutation

        // --- Allocate VMA region + map into peer's page table ---
        let peer_vaddr = {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            let vma = pt_guard
                .as_mut()
                .and_then(|pt| pt.vma_mut(ctx.process_id))
                .ok_or(SyscallError::InvalidArg)?;

            let vaddr = vma
                .allocate_region(num_pages)
                .ok_or(SyscallError::OutOfMemory)?;

            let flags = if peer_writable {
                crate::memory::paging::flags::user_rw()
            } else {
                crate::memory::paging::flags::user_ro()
            };

            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            // SAFETY: ctx.cr3 is a valid PML4/L0 for the peer process.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_range(
                    &mut pt,
                    vaddr,
                    physical_base,
                    num_pages as usize,
                    flags,
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
            drop(fa_guard);
            drop(pt_guard);
            vaddr
        };

        // --- Finalize attach in ChannelManager ---
        {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            chan_mgr
                .attach(channel_id, caller_principal, ctx.process_id, peer_vaddr)
                .map_err(|_| SyscallError::InvalidArg)?;
        }

        crate::audit::emit(crate::audit::RawAuditEvent::channel_attached(
            ctx.process_id, channel_id.as_raw(), crate::audit::now(), 0,
        ));

        crate::println!(
            "  [ChannelAttach] pid={} channel={} → vaddr={:#x}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            peer_vaddr,
        );

        Ok(peer_vaddr)
    }

    /// SYS_CHANNEL_CLOSE: Close a channel gracefully.
    ///
    /// Args: arg1 = channel_id (u64)
    ///
    /// Lock ordering: CHANNEL_MANAGER(5) → PROCESS_TABLE(6) → FRAME_ALLOCATOR(7),
    /// then TLB shootdown (lock-free).
    fn handle_channel_close(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::ChannelId;

        let channel_id = ChannelId::from_raw(args.arg1);

        // --- Close in ChannelManager (returns the record) ---
        let record = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            chan_mgr
                .close(channel_id, ctx.process_id)
                .map_err(|e| match e {
                    crate::ipc::channel::ChannelError::PermissionDenied => SyscallError::PermissionDenied,
                    crate::ipc::channel::ChannelError::NotFound => SyscallError::InvalidArg,
                    _ => SyscallError::InvalidArg,
                })?
        }; // drop CHANNEL_MANAGER(5)

        // --- Unmap from both processes + free VMA slots ---
        Self::teardown_channel_mappings(&record);

        crate::audit::emit(crate::audit::RawAuditEvent::channel_closed(
            ctx.process_id, channel_id.as_raw(), 0, 0, crate::audit::now(), 0,
        ));

        crate::println!(
            "  [ChannelClose] pid={} channel={} pages={}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            record.num_pages,
        );

        Ok(0)
    }

    /// SYS_CHANNEL_REVOKE: Force-close a channel (bootstrap authority).
    ///
    /// Args: arg1 = channel_id (u64)
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) → CHANNEL_MANAGER(5) →
    /// PROCESS_TABLE(6) → FRAME_ALLOCATOR(7)
    fn handle_channel_revoke(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::ChannelId;

        let channel_id = ChannelId::from_raw(args.arg1);

        // --- Authority check: bootstrap Principal only (v0 pattern) ---
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        let caller_principal = ctx.caller_principal.as_ref().ok_or(SyscallError::PermissionDenied)?;
        if *caller_principal != bootstrap {
            return Err(SyscallError::PermissionDenied);
        }

        // --- Revoke in ChannelManager ---
        let record = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            chan_mgr
                .revoke(channel_id)
                .map_err(|_| SyscallError::InvalidArg)?
        }; // drop CHANNEL_MANAGER(5)

        // --- Teardown ---
        Self::teardown_channel_mappings(&record);

        crate::println!(
            "  [ChannelRevoke] pid={} channel={} pages={}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            record.num_pages,
        );

        Ok(0)
    }

    /// SYS_CHANNEL_BEGIN_TEARDOWN: start the two-phase teardown of a
    /// channel (ADR-027 Phase 1). Caller must be the channel's
    /// creator or peer (same auth as `channel_close`).
    ///
    /// Args: arg1 = channel_id (u64), arg2 = TeardownKind low byte
    /// (0 = Close, 1 = Revoke).
    ///
    /// Returns 0 on the `AwaitingAttach` short-circuit (slot torn
    /// down inline; subsequent `complete_teardown` will return
    /// `InvalidArg`), 1 on the `Active → Revoking` quiesce path
    /// (peer arming in flight; caller must drive the workflow that
    /// arranges the peer's cooperation, then call
    /// `complete_teardown`).
    ///
    /// Lock ordering: CHANNEL_MANAGER(6) → (drop) → optional
    /// `arm_quiesce_for_process` walk over PER_CPU_SCHEDULER(1)
    /// (acquired by the helper, never held with CHANNEL_MANAGER).
    /// On the `Immediate` arm: same teardown chain as
    /// `handle_channel_close` — PROCESS_TABLE(7) + FRAME_ALLOCATOR(8)
    /// inside `teardown_channel_mappings`, then TLB shootdown.
    fn handle_channel_begin_teardown(
        args: SyscallArgs,
        ctx: &SyscallContext,
    ) -> SyscallResult {
        use crate::ipc::channel::{ChannelId, TeardownKind, TeardownStart};

        let channel_id = ChannelId::from_raw(args.arg1);
        let kind = match args.arg2 & 0xFF {
            0 => TeardownKind::Close,
            1 => TeardownKind::Revoke,
            _ => return Err(SyscallError::InvalidArg),
        };
        let kind_u8 = (args.arg2 & 0xFF) as u8;

        let outcome = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            // Endpoint authority: same shape as handle_channel_close.
            // Look up the record once for the auth check before
            // mutating state — begin_teardown itself doesn't validate
            // the caller because the channel manager is pure
            // bookkeeping (kept arch-agnostic / verification-clean).
            let record = chan_mgr.get(channel_id)
                .map_err(|_| SyscallError::InvalidArg)?;
            let is_creator = record.creator_pid == ctx.process_id;
            let is_peer = record.peer_pid == Some(ctx.process_id);
            if !is_creator && !is_peer {
                return Err(SyscallError::PermissionDenied);
            }
            chan_mgr.begin_teardown(channel_id, kind)
                .map_err(|_| SyscallError::InvalidArg)?
        }; // drop CHANNEL_MANAGER(6)

        match outcome {
            TeardownStart::Immediate(record) => {
                let num_pages = record.num_pages;
                Self::teardown_channel_mappings(&record);
                crate::audit::emit(crate::audit::RawAuditEvent::channel_closed(
                    ctx.process_id,
                    channel_id.as_raw(),
                    0,
                    0,
                    crate::audit::now(),
                    0,
                ));
                crate::println!(
                    "  [ChannelBeginTeardown:Immediate] pid={} channel={} pages={}",
                    ctx.process_id.slot(),
                    channel_id.as_raw(),
                    num_pages,
                );
                Ok(0)
            }
            TeardownStart::Quiesce(snapshot) => {
                if let Some(peer_pid) = snapshot.peer_pid {
                    let _ = crate::arm_quiesce_for_process(peer_pid, channel_id.as_raw());
                }
                crate::audit::emit(crate::audit::RawAuditEvent::channel_teardown_started(
                    ctx.process_id,
                    channel_id.as_raw(),
                    kind_u8,
                    crate::audit::now(),
                    0,
                ));
                crate::println!(
                    "  [ChannelBeginTeardown:Quiesce] pid={} channel={} kind={}",
                    ctx.process_id.slot(),
                    channel_id.as_raw(),
                    kind_u8,
                );
                Ok(1)
            }
        }
    }

    /// SYS_CHANNEL_COMPLETE_TEARDOWN: finish the two-phase teardown
    /// started by `handle_channel_begin_teardown` (ADR-027 Phase 1).
    /// Channel must be in `Revoking`; same `kind` discriminant as the
    /// matching begin call.
    ///
    /// Args: arg1 = channel_id (u64), arg2 = TeardownKind low byte
    /// (0 = Close, 1 = Revoke).
    ///
    /// Lock ordering: CHANNEL_MANAGER(6) → (drop) → PROCESS_TABLE(7) +
    /// FRAME_ALLOCATOR(8) inside `teardown_channel_mappings`, then
    /// `wake_quiesce_for_channel` walks PER_CPU_SCHEDULER(1) (helper
    /// never holds it with anything else). Identical lock sequence
    /// to `handle_channel_close` plus the wake walk at the end.
    fn handle_channel_complete_teardown(
        args: SyscallArgs,
        ctx: &SyscallContext,
    ) -> SyscallResult {
        use crate::ipc::channel::{ChannelId, TeardownKind};

        let channel_id = ChannelId::from_raw(args.arg1);
        let kind = match args.arg2 & 0xFF {
            0 => TeardownKind::Close,
            1 => TeardownKind::Revoke,
            _ => return Err(SyscallError::InvalidArg),
        };
        let kind_u8 = (args.arg2 & 0xFF) as u8;

        let record = {
            let mut chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            // Endpoint authority — same as begin_teardown. The slot
            // is still occupied (Revoking holds the slot) so the
            // record is reachable; complete_teardown then takes it.
            let record = chan_mgr.get(channel_id)
                .map_err(|_| SyscallError::InvalidArg)?;
            let is_creator = record.creator_pid == ctx.process_id;
            let is_peer = record.peer_pid == Some(ctx.process_id);
            if !is_creator && !is_peer {
                return Err(SyscallError::PermissionDenied);
            }
            chan_mgr.complete_teardown(channel_id, kind)
                .map_err(|_| SyscallError::InvalidArg)?
        }; // drop CHANNEL_MANAGER(6)

        let num_pages = record.num_pages;
        Self::teardown_channel_mappings(&record);
        let woken = crate::wake_quiesce_for_channel(channel_id.as_raw());

        crate::audit::emit(crate::audit::RawAuditEvent::channel_teardown_completed(
            ctx.process_id,
            channel_id.as_raw(),
            kind_u8,
            num_pages,
            crate::audit::now(),
            0,
        ));
        crate::println!(
            "  [ChannelCompleteTeardown] pid={} channel={} pages={} woken={}",
            ctx.process_id.slot(),
            channel_id.as_raw(),
            num_pages,
            woken,
        );

        Ok(0)
    }

    /// SYS_CHANNEL_QUIESCE_ACK: cooperative-ack of a pending channel
    /// revoke (ADR-027 Phase 1). Caller voluntarily transitions its
    /// own task into `Blocked(ChannelQuiesceWait(channel_id))` and
    /// yields. The matching `complete_teardown` wakes the task by
    /// calling `wake_quiesce_for_channel`; the syscall returns 0 to
    /// the awoken task.
    ///
    /// Authority: caller's bound Principal must match
    /// `record.peer_principal` of the channel being revoked, AND the
    /// channel must currently be in `Revoking`. This is the cooperative
    /// path — the kernel-side `try_park_current_for_quiesce` hook
    /// catches a peer that did not voluntarily ack at the next ISR
    /// tick (≤ 10 ms at 100 Hz) regardless.
    ///
    /// Lock ordering: CHANNEL_MANAGER(6) → (drop) → PER_CPU_SCHEDULER(1)
    /// (block_task) → (drop) → yield_save_and_switch.
    fn handle_channel_quiesce_ack(
        args: SyscallArgs,
        ctx: &SyscallContext,
    ) -> SyscallResult {
        use crate::ipc::channel::{ChannelId, ChannelState};

        let channel_id = ChannelId::from_raw(args.arg1);

        // Authority + state precondition.
        {
            let chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            let record = chan_mgr.get(channel_id)
                .map_err(|_| SyscallError::InvalidArg)?;
            if record.state != ChannelState::Revoking {
                return Err(SyscallError::InvalidArg);
            }
            let caller = ctx.caller_principal.as_ref()
                .ok_or(SyscallError::PermissionDenied)?;
            if *caller != record.peer_principal {
                return Err(SyscallError::PermissionDenied);
            }
        } // drop CHANNEL_MANAGER(6)

        // Park ourselves and yield. Same disable-IF-before-block
        // pattern as handle_wait_irq / handle_recv_msg — the timer
        // ISR must not see Blocked state before
        // yield_save_and_switch saves the correct context.
        // SAFETY: kernel privilege; cli is local to this CPU.
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
        {
            let mut sched_guard = crate::local_scheduler().lock();
            if let Some(sched) = sched_guard.as_mut() {
                let _ = sched.block_task(
                    ctx.task_id,
                    crate::scheduler::BlockReason::ChannelQuiesceWait(channel_id.as_raw()),
                );
            }
            // IrqSpinlock drop preserves the cli we just issued.
        }
        // SAFETY: on kernel stack, no locks held.
        unsafe { crate::arch::yield_save_and_switch(); }
        // Woken by handle_channel_complete_teardown's
        // wake_quiesce_for_channel call. The channel slot is gone;
        // any subsequent surface access by the caller will fault on
        // the unmapped peer mapping unless they re-attach a fresh
        // channel first.
        Ok(0)
    }

    /// SYS_CHANNEL_INFO: Read channel metadata.
    ///
    /// Args: arg1 = channel_id (u64), arg2 = out_buf, arg3 = buf_len
    ///
    /// Writes a fixed-format descriptor to the user buffer:
    ///   [state:1][role:1][num_pages:4][creator_pid_slot:4][peer_pid_slot:4]
    ///   [creator_vaddr:8][peer_vaddr:8][physical_base:8][created_at_tick:8]
    /// Total: 46 bytes
    ///
    /// Lock ordering: CHANNEL_MANAGER(5) only.
    fn handle_channel_info(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::channel::ChannelId;

        let channel_id = ChannelId::from_raw(args.arg1);
        let out_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        if buf_len < 46 || out_buf == 0 || out_buf >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let mut info = [0u8; 46];

        {
            let chan_guard = crate::CHANNEL_MANAGER.lock();
            let chan_mgr = chan_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            let record = chan_mgr.get(channel_id).map_err(|_| SyscallError::InvalidArg)?;

            info[0] = record.state as u8;
            info[1] = record.role as u8;
            info[2..6].copy_from_slice(&record.num_pages.to_le_bytes());
            info[6..10].copy_from_slice(&record.creator_pid.slot().to_le_bytes());
            let peer_slot = record.peer_pid.map(|p| p.slot()).unwrap_or(u32::MAX);
            info[10..14].copy_from_slice(&peer_slot.to_le_bytes());
            info[14..22].copy_from_slice(&record.creator_vaddr.to_le_bytes());
            info[22..30].copy_from_slice(&record.peer_vaddr.to_le_bytes());
            info[30..38].copy_from_slice(&record.physical_base.to_le_bytes());
            info[38..46].copy_from_slice(&record.created_at_tick.to_le_bytes());
        } // drop CHANNEL_MANAGER(5)

        // ADR-020 Phase B: write 46-byte channel info via typed slice.
        let info_slice = UserWriteSlice::validate(ctx, out_buf, 46)?;
        info_slice.write_from(&info)?;

        Ok(0)
    }

    // ========================================================================
    // Channel teardown helper (shared by close, revoke, process exit)
    // ========================================================================

    /// Tear down a closed/revoked channel's mappings on both peers,
    /// issue TLB shootdowns, free VMA slots, and free the physical
    /// frames.
    ///
    /// Per ADR-007 Divergence entry 7 (tombstone-on-revoke), each
    /// side's mapping is handled per its writability:
    /// - **RO mapping** → unmap-then-remap to the kernel-owned
    ///   tombstone zero page. Subsequent reads return zeros instead
    ///   of faulting. Closes the HN-blocker compositor #PF on clean
    ///   client exit (first observed 2026-04-25).
    /// - **RW mapping** → unmap (existing behavior). Tombstone-as-RW
    ///   would need per-peer scratch pages; deferred per ADR-007
    ///   Divergence entry 8. Subsequent writes fault and the writer is
    ///   killed by the existing #PF handler — acceptable for the
    ///   catastrophic-state cases this covers (e.g., compositor →
    ///   scanout-driver where the consumer dies).
    ///
    /// Writability per side comes from `record.role`:
    /// - `Producer`: creator RW, peer RO
    /// - `Consumer`: creator RO, peer RW
    /// - `Bidirectional`: both RW
    ///
    /// Falls back to unmap-on-revoke when the tombstone wasn't
    /// allocated at boot (`init_tombstone` failed) — the kernel stays
    /// functional but the HN-blocker re-exposes.
    ///
    /// Lock ordering: PROCESS_TABLE(6) → FRAME_ALLOCATOR(7), then
    /// TLB shootdown (lock-free).
    ///
    /// Called after the ChannelManager lock has been released (the
    /// record is already taken out of the table).
    fn teardown_channel_mappings(record: &crate::ipc::channel::ChannelRecord) {
        let tombstone = tombstone_phys_base();
        let creator_writable = record.role.creator_writable();
        let peer_writable = record.role.peer_writable();

        let mut shootdown_creator = false;
        let mut shootdown_peer = false;

        {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            if let Some(pt) = pt_guard.as_mut() {
                // Creator side
                if record.creator_vaddr != 0 {
                    if let Some(vma) = pt.vma_mut(record.creator_pid) {
                        vma.free_region(record.creator_vaddr);
                    }
                    let creator_cr3 = pt.get_cr3(record.creator_pid);
                    if creator_cr3 != 0 {
                        // SAFETY: `creator_cr3` is a valid root page-table
                        // physical address obtained from the process table.
                        // The channel record was already taken out of
                        // `ChannelManager` so no other code path is mutating
                        // these PTEs concurrently. We hold PROCESS_TABLE +
                        // FRAME_ALLOCATOR for the duration of the walk.
                        unsafe {
                            let mut page_table =
                                crate::memory::paging::page_table_from_cr3(creator_cr3);
                            let remap_creator = !creator_writable && tombstone != 0;
                            for i in 0..record.num_pages as u64 {
                                let vaddr = record.creator_vaddr + i * 4096;
                                // Unmap original. Discard PhysFrame — the
                                // original frames are freed in bulk below
                                // via `free_contiguous`.
                                let _ = crate::memory::paging::unmap_page(&mut page_table, vaddr);
                                if remap_creator {
                                    // SAFETY: `tombstone` was allocated and
                                    // zeroed once at boot by `init_tombstone`;
                                    // `user_ro()` flags expose it as readable
                                    // but not writable to userspace; the PTE
                                    // was just unmapped above so map_page
                                    // does not collide.
                                    let _ = crate::memory::paging::map_page(
                                        &mut page_table,
                                        vaddr,
                                        tombstone,
                                        crate::memory::paging::flags::user_ro(),
                                        &mut fa_guard,
                                    );
                                }
                            }
                        }
                        shootdown_creator = true;
                    }
                }

                // Peer side (if attached)
                if record.peer_vaddr != 0 {
                    if let Some(peer_pid) = record.peer_pid {
                        if let Some(vma) = pt.vma_mut(peer_pid) {
                            vma.free_region(record.peer_vaddr);
                        }
                        let peer_cr3 = pt.get_cr3(peer_pid);
                        if peer_cr3 != 0 {
                            // SAFETY: same reasoning as creator side.
                            unsafe {
                                let mut page_table =
                                    crate::memory::paging::page_table_from_cr3(peer_cr3);
                                let remap_peer = !peer_writable && tombstone != 0;
                                for i in 0..record.num_pages as u64 {
                                    let vaddr = record.peer_vaddr + i * 4096;
                                    let _ = crate::memory::paging::unmap_page(
                                        &mut page_table,
                                        vaddr,
                                    );
                                    if remap_peer {
                                        // SAFETY: same as creator-side
                                        // remap above.
                                        let _ = crate::memory::paging::map_page(
                                            &mut page_table,
                                            vaddr,
                                            tombstone,
                                            crate::memory::paging::flags::user_ro(),
                                            &mut fa_guard,
                                        );
                                    }
                                }
                            }
                            shootdown_peer = true;
                        }
                    }
                }
            }
        } // drop FRAME_ALLOCATOR(7), then PROCESS_TABLE(6)

        // TLB shootdown for changed ranges (lock-free). Required
        // whether we tombstoned or unmapped — the PTE changed either
        // way and stale TLB entries must be invalidated.
        if shootdown_creator {
            // SAFETY: shootdown_range requires ring 0 and that the
            // page-table mutations above are already visible.
            unsafe {
                crate::arch::tlb_shootdown_range(record.creator_vaddr, record.num_pages);
            }
        }
        if shootdown_peer {
            // SAFETY: same preconditions.
            unsafe {
                crate::arch::tlb_shootdown_range(record.peer_vaddr, record.num_pages);
            }
        }

        // Free the original contiguous physical frames. The PTEs that
        // formerly pointed at them have been swapped to the tombstone
        // (RO sides) or unmapped (RW sides), so no live mapping
        // references this region anymore. The tombstone itself is
        // never freed.
        {
            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            let _ = fa_guard.free_contiguous(record.physical_base, record.num_pages as usize);
        }
    }

    // ========================================================================
    // Service clusters (ADR-027)
    // ========================================================================

    /// SYS_CLUSTER_CREATE (44): create a `Forming` cluster.
    ///
    /// Args:
    ///   arg1 = policy (u32; [`ClusterPolicy::from_u32`])
    ///   arg2 = members_user_ptr (u64; `*const ClusterMemberSpec`)
    ///   arg3 = member_count (u32; `≤ MAX_CLUSTER_MEMBERS`)
    ///
    /// Wire layout per member: `{ principal: [u8; 32], role: u32 }`
    /// = 36 bytes packed. Total user buffer = `36 × member_count`.
    ///
    /// Returns: `ClusterId` raw `u64` on success.
    ///
    /// Authority: `CapabilityKind::CreateCluster` OR bootstrap
    /// Principal (the bootstrap path is the v1 fallback until the
    /// boot manifest grants the cap to `init` — see ADR-027 §
    /// Migration Path step 6).
    ///
    /// Lock ordering: `CAPABILITY_MANAGER(4)` → `CLUSTER_MANAGER(5)`.
    fn handle_cluster_create(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::cluster::{
            ClusterCreateParams, ClusterPolicy, ClusterRole, MAX_CLUSTER_MEMBERS,
        };

        let policy_raw = args.arg1_u32();
        let members_ptr = args.arg2;
        let count = args.arg_usize(3);

        let policy = ClusterPolicy::from_u32(policy_raw).ok_or(SyscallError::InvalidArg)?;
        if count == 0 || count > MAX_CLUSTER_MEMBERS {
            return Err(SyscallError::InvalidArg);
        }
        if members_ptr == 0 || members_ptr >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Authority: CreateCluster cap OR bootstrap Principal.
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            let has_cap = cap_mgr
                .has_system_capability(
                    ctx.process_id,
                    crate::ipc::capability::CapabilityKind::CreateCluster,
                )
                .unwrap_or(false);
            if !has_cap {
                let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
                let caller_principal = ctx
                    .caller_principal
                    .as_ref()
                    .ok_or(SyscallError::PermissionDenied)?;
                if *caller_principal != bootstrap {
                    return Err(SyscallError::PermissionDenied);
                }
            }
        } // drop CAPABILITY_MANAGER

        // Read member array from user space (count-prefixed,
        // 36 bytes per entry — see Wire layout above). Copy into a
        // kernel-local buffer first to close TOCTOU on userspace
        // mutating between bounds-check and decode.
        /// ARCHITECTURAL: SYS_CLUSTER_CREATE per-member wire size.
        /// `{ principal: [u8; 32], role: u32 }` packed = 36 bytes.
        /// Changing this is a new syscall, not a size bump.
        const MEMBER_BYTES: usize = 36;
        let total_bytes = count * MEMBER_BYTES;
        if total_bytes > MAX_USER_BUFFER {
            return Err(SyscallError::InvalidArg);
        }
        let user_slice = UserReadSlice::validate(ctx, members_ptr, total_bytes)?;
        let mut buf = [0u8; MEMBER_BYTES * MAX_CLUSTER_MEMBERS];
        user_slice.read_into(&mut buf[..total_bytes])?;

        // Decode into ClusterCreateParams::expected_members. The
        // ClusterManager re-validates `(policy, role)` per
        // kernel-no-trust discipline.
        let mut expected_members: [Option<(crate::ipc::Principal, ClusterRole)>;
            MAX_CLUSTER_MEMBERS] = [None; MAX_CLUSTER_MEMBERS];
        for i in 0..count {
            let off = i * MEMBER_BYTES;
            let mut principal_bytes = [0u8; 32];
            principal_bytes.copy_from_slice(&buf[off..off + 32]);
            let role_raw = u32::from_le_bytes([
                buf[off + 32],
                buf[off + 33],
                buf[off + 34],
                buf[off + 35],
            ]);
            let role = ClusterRole::from_u32(role_raw).ok_or(SyscallError::InvalidArg)?;
            expected_members[i] = Some((
                crate::ipc::Principal::from_aid(principal_bytes),
                role,
            ));
        }

        let tick = crate::scheduler::Timer::get_ticks();

        let cluster_id = {
            let mut guard = crate::CLUSTER_MANAGER.lock();
            let mgr = guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            mgr.create(ClusterCreateParams {
                policy,
                creator_pid: ctx.process_id,
                created_at_tick: tick,
                expected_members,
            })
            .map_err(|_| SyscallError::InvalidArg)?
        }; // drop CLUSTER_MANAGER

        crate::audit::emit(crate::audit::RawAuditEvent::cluster_created(
            ctx.process_id,
            cluster_id.as_raw(),
            policy as u32,
            count as u32,
            crate::audit::now(),
            0,
        ));

        crate::println!(
            "  [ClusterCreate] pid={} policy={:?} members={} → id={:#x}",
            ctx.process_id.slot(),
            policy,
            count,
            cluster_id.as_raw(),
        );
        Ok(cluster_id.as_raw())
    }

    /// SYS_CLUSTER_JOIN (45): join a cluster as a named role.
    ///
    /// Args:
    ///   arg1 = cluster_id (u64; `ClusterId::as_raw`)
    ///   arg2 = role (u32; [`ClusterRole::from_u32`])
    ///
    /// Returns: 0 on success.
    ///
    /// Identity-required. Caller's bound Principal must match the
    /// manifest's expected Principal for the named role; kernel
    /// transitions the member `Expected` → `Joined` and (if last
    /// expected member just joined) auto-promotes the cluster
    /// `Forming` → `Active`.
    ///
    /// Lock ordering: `CLUSTER_MANAGER(5)` (state transition), released,
    /// then `CAPABILITY_MANAGER(4)` (cap promotion). Promotion-table is
    /// a no-op stub in v1; release-acquire respects 4 < 5 because the
    /// 5 borrow is dropped before 4 is taken.
    fn handle_cluster_join(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::cluster::{ClusterId, ClusterRole};

        let cluster_id = ClusterId::from_raw(args.arg1);
        let role_raw = args.arg2 as u32;
        let role = ClusterRole::from_u32(role_raw).ok_or(SyscallError::InvalidArg)?;

        let caller_principal = *ctx
            .caller_principal
            .as_ref()
            .ok_or(SyscallError::PermissionDenied)?;

        // Phase 1: cluster state transition under CLUSTER_MANAGER.
        let policy = {
            let mut guard = crate::CLUSTER_MANAGER.lock();
            let mgr = guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            let record = mgr
                .join(cluster_id, role, caller_principal, ctx.process_id)
                .map_err(|e| match e {
                    crate::ipc::cluster::ClusterError::PrincipalMismatch => {
                        SyscallError::PermissionDenied
                    }
                    _ => SyscallError::InvalidArg,
                })?;
            record.policy
        }; // drop CLUSTER_MANAGER

        // Phase 2: cap promotion under CAPABILITY_MANAGER.
        // V1 stub: caps_for_role returns empty. This loop runs zero
        // iterations until cluster_policy.rs is populated by the
        // rendering-limb migration commit.
        let caps_to_grant = crate::ipc::cluster_policy::caps_for_role(policy, role);
        if !caps_to_grant.is_empty() {
            let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_mut().ok_or(SyscallError::InvalidArg)?;
            for &(endpoint, rights) in caps_to_grant {
                let _ = cap_mgr.grant_capability(ctx.process_id, endpoint, rights);
            }
        }

        crate::println!(
            "  [ClusterJoin] pid={} cluster={:#x} role={:?}",
            ctx.process_id.slot(),
            cluster_id.as_raw(),
            role,
        );
        Ok(0)
    }

    /// SYS_CLUSTER_REVOKE (46): tear down a cluster.
    ///
    /// Args:
    ///   arg1 = cluster_id (u64)
    ///
    /// Returns: 0 on success.
    ///
    /// Authority: cluster's creator OR `CapabilityKind::ClusterRevoke`
    /// OR bootstrap Principal.
    ///
    /// Lock-acquisition: see [`Dispatcher::do_cluster_revoke`].
    fn handle_cluster_revoke(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::cluster::ClusterId;
        let cluster_id = ClusterId::from_raw(args.arg1);

        // Read creator_pid out under CLUSTER_MANAGER, release.
        let creator_pid = {
            let guard = crate::CLUSTER_MANAGER.lock();
            let mgr = guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            mgr.get(cluster_id)
                .map_err(|_| SyscallError::InvalidArg)?
                .creator_pid
        };

        let caller_principal = *ctx
            .caller_principal
            .as_ref()
            .ok_or(SyscallError::PermissionDenied)?;
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        let is_creator = ctx.process_id == creator_pid;
        let is_bootstrap = caller_principal == bootstrap;
        let has_cap = if !is_creator && !is_bootstrap {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            cap_mgr
                .has_system_capability(
                    ctx.process_id,
                    crate::ipc::capability::CapabilityKind::ClusterRevoke,
                )
                .unwrap_or(false)
        } else {
            false
        };
        if !is_creator && !is_bootstrap && !has_cap {
            return Err(SyscallError::PermissionDenied);
        }

        Self::do_cluster_revoke(
            cluster_id,
            ctx.process_id,
            crate::audit::CLUSTER_REVOKE_REASON_EXPLICIT,
        );

        crate::println!(
            "  [ClusterRevoke] pid={} cluster={:#x}",
            ctx.process_id.slot(),
            cluster_id.as_raw(),
        );
        Ok(0)
    }

    /// SYS_CLUSTER_INFO (47): read cluster metadata.
    ///
    /// Args:
    ///   arg1 = cluster_id (u64)
    ///   arg2 = out_buf (u64; user-space pointer)
    ///   arg3 = buf_len (u32; must be ≥ `CLUSTER_INFO_BYTES`)
    ///
    /// Wire layout (28 bytes, little-endian):
    /// `[state:u32][policy:u32][creator_pid_slot:u32]`
    /// `[joined_members:u32][active_channels:u32][created_at_tick:u64]`
    ///
    /// Returns: 0 on success.
    ///
    /// Lock ordering: `CLUSTER_MANAGER(5)` only.
    fn handle_cluster_info(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::cluster::{ClusterId, MemberState};

        /// ARCHITECTURAL: SYS_CLUSTER_INFO descriptor size.
        /// `[state:u32][policy:u32][creator_pid_slot:u32]`
        /// `[joined_members:u32][active_channels:u32][created_at_tick:u64]`
        /// = 28 bytes. Changing this is a new syscall, not a size bump.
        const CLUSTER_INFO_BYTES: usize = 28;

        let cluster_id = ClusterId::from_raw(args.arg1);
        let out_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        if buf_len < CLUSTER_INFO_BYTES || out_buf == 0 || out_buf >= USER_SPACE_END {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let mut info = [0u8; CLUSTER_INFO_BYTES];
        {
            let guard = crate::CLUSTER_MANAGER.lock();
            let mgr = guard.as_ref().ok_or(SyscallError::InvalidArg)?;
            let record = mgr.get(cluster_id).map_err(|_| SyscallError::InvalidArg)?;

            let joined_count = record
                .members
                .iter()
                .filter(|m| m.as_ref().is_some_and(|m| m.state == MemberState::Joined))
                .count() as u32;
            let active_channels = record.channels.iter().filter(|c| c.is_some()).count() as u32;

            info[0..4].copy_from_slice(&(record.state as u32).to_le_bytes());
            info[4..8].copy_from_slice(&(record.policy as u32).to_le_bytes());
            info[8..12].copy_from_slice(&record.creator_pid.slot().to_le_bytes());
            info[12..16].copy_from_slice(&joined_count.to_le_bytes());
            info[16..20].copy_from_slice(&active_channels.to_le_bytes());
            info[20..28].copy_from_slice(&record.created_at_tick.to_le_bytes());
        } // drop CLUSTER_MANAGER

        let info_slice = UserWriteSlice::validate(ctx, out_buf, CLUSTER_INFO_BYTES)?;
        info_slice.write_from(&info)?;
        Ok(0)
    }

    // ========================================================================
    // ADR-028 storage seam syscall stubs
    // ========================================================================
    //
    // SYS_CAMBIO (50), SYS_REGALO (51), and SYS_STREAM (52) are reserved
    // at the ABI surface but not yet implemented. The handlers return
    // Enosys until the seam-syscall migration steps land:
    //   - SYS_CAMBIO depends on ADR-029's FrozenInodeView (CoW snapshot)
    //     and the existing ObjectStore put path.
    //   - SYS_REGALO depends on ADR-029's path resolver + per-process
    //     REGALO alias table.
    //   - SYS_STREAM depends on ADR-030's StreamCapShape validity checks
    //     + ChannelRecord extension.

    /// Stub for SYS_CAMBIO. Returns `Enosys` until ADR-028 § Migration
    /// Path step 6 lands the seal-and-install handler.
    fn handle_cambio(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    /// Stub for SYS_REGALO. Returns `Enosys` until ADR-028 § Migration
    /// Path step 7 lands the alias-table writer + path resolver.
    fn handle_regalo(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    /// Stub for SYS_STREAM. Returns `Enosys` until ADR-028 § Migration
    /// Path step 8 lands the cap-shape attach + channel-record extension.
    fn handle_stream(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    /// Stub for ADR-029 POSIX file syscalls (slots 53-72). Returns
    /// `Enosys` until the POSIX backend lands per ADR-029 § Migration
    /// Path steps 4-9. Per-syscall semantics are in ADR-029 § Decision
    /// 4's table.
    fn handle_posix_stub(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    /// SYS_VERIFY_VOLUME_HEADER (73): verify a user-supplied volume
    /// header against the kernel-baked bootstrap pubkey per ADR-032
    /// § 4. The signed range, signature offset, and AID-equals-pubkey
    /// invariant all live in `crate::fs::crypto::header::verify_header`;
    /// the handler is bytes-in, status-out plumbing around it.
    ///
    /// Args: arg1 = user ptr to header bytes,
    ///       arg2 = header byte length (must equal the file's
    ///              `header_length` field at offset 8; bounded to
    ///              [HEADER_MIN_LEN, HEADER_MAX_LEN]).
    /// Returns: 0 on success; `InvalidArg` for structural failures
    ///          (bad magic, length out of bounds, slot_count > 16);
    ///          `PermissionDenied` for `volume_uuid` mismatch or
    ///          signature verification failure.
    ///
    /// Lock ordering: none — pure compute over a stack buffer.
    fn handle_verify_volume_header(
        args: SyscallArgs,
        ctx: &SyscallContext,
    ) -> SyscallResult {
        use crate::fs::crypto::header::{
            HeaderError, HEADER_MAX_LEN, HEADER_MIN_LEN, verify_header,
        };

        let header_ptr = args.arg1;
        let header_len = args.arg_usize(2);

        if !(HEADER_MIN_LEN..=HEADER_MAX_LEN).contains(&header_len) {
            return Err(SyscallError::InvalidArg);
        }
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Copy the user buffer into a kernel-local stack buffer.
        // HEADER_MAX_LEN is 4 KiB + change which is well within the
        // 256 KiB kernel boot stack.
        let header_slice = UserReadSlice::validate(ctx, header_ptr, header_len)?;
        let mut kbuf = [0u8; HEADER_MAX_LEN];
        header_slice.read_into(&mut kbuf[..header_len])?;

        // Bootstrap pubkey baked into the kernel by
        // `bootstrap_identity_init`; the BOOTSTRAP_PRINCIPAL singleton
        // stores it under the AID-equals-pubkey invariant per ADR-025.
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        let bootstrap_pubkey = bootstrap.current_key_bytes();

        match verify_header(&kbuf[..header_len], bootstrap_pubkey) {
            Ok(_header) => Ok(0),
            Err(HeaderError::BadLength)
            | Err(HeaderError::BadMagic)
            | Err(HeaderError::BadHeaderLength)
            | Err(HeaderError::SlotCountExceeds)
            | Err(HeaderError::BadSlotType)
            | Err(HeaderError::BadSlotClass)
            | Err(HeaderError::BadWrappedKeyLen) => Err(SyscallError::InvalidArg),
            Err(HeaderError::VolumeUuidMismatch)
            | Err(HeaderError::SignatureInvalid) => Err(SyscallError::PermissionDenied),
        }
    }

    /// SYS_READ_VOLUME_HEADER (74): copy LBA 0..=3 (16 KiB) of the
    /// on-disk FDE volume header into a user buffer via the kernel's
    /// virtio-blk kernel-cmd path per ADR-032 § Architecture. First
    /// step of stream A A-v.a's `fde-mount` unlock flow.
    ///
    /// Args: arg1 = user ptr to output buffer,
    ///       arg2 = output buffer byte length (must be >= 16384).
    /// Returns: 16384 (bytes written) on success;
    ///          `PermissionDenied` if caller is not the bootstrap
    ///          Principal; `InvalidArg` for buf_len too small or
    ///          missing user-space cr3; `Enosys` if virtio-blk's
    ///          kernel-cmd path isn't initialized yet (e.g., on
    ///          AArch64 with no virtio-blk device); `OutOfMemory`
    ///          if a block read fails mid-read.
    ///
    /// Authority: bootstrap-Principal-only. Reads raw disk bytes
    /// before any volume layer has authenticated them, so it must
    /// be tightly scoped to the signed `fde-mount` boot module.
    /// Same gating shape as `BindPrincipal`.
    ///
    /// Lock ordering: none directly. `VirtioBlkDevice::call`
    /// yields the calling task via `yield_save_and_switch` while
    /// waiting for the virtio-blk driver's reply — no kernel locks
    /// are held across the yield.
    ///
    /// Gated `#[cfg(not(test))]` because the kernel-side
    /// `crate::fs::virtio_blk_device` module is itself gated out of
    /// host test builds (see `src/fs/mod.rs`). The matching
    /// `#[cfg(test)]` stub below returns `Enosys`, so host syscall
    /// tests that route to dispatcher don't break.
    #[cfg(not(test))]
    fn handle_read_volume_header(
        args: SyscallArgs,
        ctx: &SyscallContext,
    ) -> SyscallResult {
        use crate::fs::block::{BLOCK_SIZE, Block, BlockDevice};
        use crate::fs::virtio_blk_device::VirtioBlkDevice;

        /// HARDWARE: ADR-032 § 4 reserves LBA 0..=3 (4 × 4 KiB = 16 KiB)
        /// for the volume header, even when the header_length field
        /// addresses fewer bytes. Reading the full reserved extent
        /// once means consumers don't need a multi-syscall protocol.
        const HEADER_BLOCKS: u64 = 4;
        const HEADER_BYTES: usize = (HEADER_BLOCKS as usize) * BLOCK_SIZE;

        let buf_ptr = args.arg1;
        let buf_len = args.arg_usize(2);

        if buf_len < HEADER_BYTES {
            return Err(SyscallError::InvalidArg);
        }
        // No explicit ctx.cr3 == 0 check here — UserWriteSlice::validate
        // below handles invalid user buffers (including cr3=0) uniformly.
        // The earlier explicit check fired in dev-piv boot before
        // BindPrincipal had stamped ctx.cr3 onto the syscall entry path;
        // surfaced at A-v.d.3 end-to-end as `read_volume_header: -1`.

        // Bootstrap-Principal-only — same gating shape as BindPrincipal.
        let caller = ctx
            .caller_principal
            .as_ref()
            .ok_or(SyscallError::PermissionDenied)?;
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        if *caller != bootstrap {
            return Err(SyscallError::PermissionDenied);
        }

        // Open the virtio-blk kernel-cmd channel. Per the
        // `lazy_disk` precedent, we do this without holding any
        // kernel locks (the IPC dance yields).
        let mut device = VirtioBlkDevice::new();
        if device.ensure_handshake().is_err() {
            return Err(SyscallError::Enosys);
        }

        // Read 16 KiB into a kernel-local stack buffer. 16 KiB is
        // well within the 256 KiB boot stack budget; per the
        // CLAUDE.md kernel stack guidance, we avoid heap allocation
        // for boot-path one-shots.
        let mut kbuf = [0u8; HEADER_BYTES];
        for lba in 0..HEADER_BLOCKS {
            let mut block: Block = [0u8; BLOCK_SIZE];
            if device.read_block(lba, &mut block).is_err() {
                return Err(SyscallError::OutOfMemory);
            }
            let start = (lba as usize) * BLOCK_SIZE;
            kbuf[start..start + BLOCK_SIZE].copy_from_slice(&block);
        }

        // Copy to user. UserWriteSlice handles cr3-aware page-walk
        // copy + length validation.
        let slice = UserWriteSlice::validate(ctx, buf_ptr, HEADER_BYTES)?;
        slice.write_from(&kbuf)?;

        Ok(HEADER_BYTES as u64)
    }

    /// Test-mode stub for `handle_read_volume_header`.
    ///
    /// The kernel-side `crate::fs::virtio_blk_device` module is gated
    /// out of host test builds (`#[cfg(not(test))]` on its declaration
    /// in `src/fs/mod.rs`) because the real adapter speaks IPC to the
    /// user-space virtio-blk driver — a runtime that doesn't exist
    /// under `cargo test`. Returning `Enosys` matches the behavior
    /// real callers see on a target without a virtio-blk device.
    #[cfg(test)]
    fn handle_read_volume_header(
        _args: SyscallArgs,
        _ctx: &SyscallContext,
    ) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    /// SYS_INSTALL_MASTER_KEY (75): receive the 64-byte XTS-AES-256
    /// FDE master key from `fde-mount` and install the
    /// `DiskObjectStore<EncryptedBlockDevice<VirtioBlkDevice>>` as
    /// the kernel's persistent ObjectStore backend. Stream A
    /// substage A-v.d per ADR-032 § Architecture.
    ///
    /// Args: arg1 = user ptr to master key (64 bytes);
    ///       arg2 = byte length (must equal 64).
    /// Returns: 0 on success.
    ///
    /// Authority: bootstrap-Principal-only. The master key
    /// unlocks every block of persistent state; gating must be
    /// as tight as `BindPrincipal`.
    ///
    /// Idempotency: one-shot. If `OBJECT_STORE` already holds a
    /// `LazyDisk` variant, the call fails `PermissionDenied`. The
    /// `Ram` initial-boot variant is upgraded; subsequent calls
    /// after a successful install also fail.
    ///
    /// Lock ordering: acquires `OBJECT_STORE(10)` at the end to
    /// install; `VirtioBlkDevice::ensure_handshake` and
    /// `DiskObjectStore::open_or_format` both yield (IPC + page-
    /// walk), so the lock is *not* held across either. Same
    /// pattern as `lazy_disk::ensure_disk_store` had.
    ///
    /// Master key hygiene: copied once from userspace into a
    /// kernel stack buffer; consumed by `EncryptedBlockDevice::new`
    /// (which materializes the AES round-key schedules);
    /// explicitly zeroed via `core::sync::atomic::compiler_fence` +
    /// volatile write before the function returns. The plaintext
    /// master never lives in any persistent kernel slot.
    #[cfg(not(test))]
    fn handle_install_master_key(
        args: SyscallArgs,
        ctx: &SyscallContext,
    ) -> SyscallResult {
        use crate::fs::block::{BlockDevice, OffsetBlockDevice, BLOCK_SIZE};
        use crate::fs::crypto::encrypted_device::{
            EncryptedBlockDevice, XTS_MASTER_KEY_LEN,
        };
        use crate::fs::disk::DiskObjectStore;
        use crate::fs::virtio_blk_device::VirtioBlkDevice;

        /// HARDWARE: ADR-032 § 4 reserves LBA 0..=3 (16 KiB) on the
        /// raw disk for the unencrypted, signed volume header. The
        /// substrate lives at LBA 4 and above; `OffsetBlockDevice`
        /// applies that shift so the substrate's `SUPERBLOCK_LBA = 0`
        /// addresses raw LBA 4, never aliasing the header.
        const FDE_SUBSTRATE_LBA_OFFSET: u64 = 4;

        // Bootstrap-Principal-only — same gating shape as
        // BindPrincipal / ReadVolumeHeader.
        let caller = ctx
            .caller_principal
            .as_ref()
            .ok_or(SyscallError::PermissionDenied)?;
        let bootstrap = crate::BOOTSTRAP_PRINCIPAL.load();
        if *caller != bootstrap {
            return Err(SyscallError::PermissionDenied);
        }

        let master_ptr = args.arg1;
        let master_len = args.arg_usize(2);
        if master_len != XTS_MASTER_KEY_LEN {
            return Err(SyscallError::InvalidArg);
        }

        // Idempotency check: refuse if a LazyDisk variant is
        // already installed. Reading the OBJECT_STORE state under
        // its lock; release before doing IPC work.
        {
            let guard = crate::OBJECT_STORE.lock();
            if matches!(*guard, Some(crate::fs::ObjectStoreBackend::LazyDisk(_))) {
                return Err(SyscallError::PermissionDenied);
            }
        }

        // Copy the master key from userspace into a kernel stack
        // buffer via UserReadSlice (handles cr3-aware page-walk +
        // length validation).
        let mut master_key = [0u8; XTS_MASTER_KEY_LEN];
        let slice = UserReadSlice::validate(ctx, master_ptr, XTS_MASTER_KEY_LEN)?;
        slice.read_into(&mut master_key)?;

        // Construct the inner virtio-blk device + handshake. No
        // kernel locks held; the IPC dance yields.
        let mut device = VirtioBlkDevice::new();
        if device.ensure_handshake().is_err() {
            Self::zeroize_master(&mut master_key);
            return Err(SyscallError::Enosys);
        }

        // Peek raw bytes at the substrate's data offset *before*
        // wrapping with the encrypted layer. ADR-032 § Architecture
        // stream A A-v.d.4: distinguishes "fresh-wrap, never
        // substrate-formatted" (zeros at raw FDE_SUBSTRATE_LBA_OFFSET)
        // from "previously substrate-formatted" (encrypted data
        // present). The wrong-master case is handled below by
        // `open_strict`'s loud refusal on Corrupt classify.
        let mut sb_raw = [0u8; BLOCK_SIZE];
        if device
            .read_block(FDE_SUBSTRATE_LBA_OFFSET, &mut sb_raw)
            .is_err()
        {
            Self::zeroize_master(&mut master_key);
            return Err(SyscallError::Enosys);
        }
        let is_fresh_wrap = sb_raw.iter().all(|&b| b == 0);

        // Wrap inner: OffsetBlockDevice shifts past the volume
        // header reserved region, then EncryptedBlockDevice
        // encrypts the substrate's view. After this line, the
        // master key has been folded into the AES round-key
        // schedules inside `cipher`; the original 64 bytes can
        // be wiped.
        let offset_dev = OffsetBlockDevice::new(device, FDE_SUBSTRATE_LBA_OFFSET);
        let substrate_capacity = offset_dev.capacity_blocks();
        let encrypted = EncryptedBlockDevice::new(offset_dev, &master_key);
        Self::zeroize_master(&mut master_key);

        // Build the substrate on top of the encrypted device.
        // Fresh-wrap → format(). Previously-formatted → open_strict()
        // which mounts on Valid superblock and refuses loudly on
        // Corrupt (= wrong master attempt). Either path may issue
        // further virtio-blk reads/writes; no kernel locks held.
        let store = if is_fresh_wrap {
            match DiskObjectStore::format_with_auto_geometry(encrypted, substrate_capacity) {
                Ok(s) => s,
                Err(_) => return Err(SyscallError::OutOfMemory),
            }
        } else {
            match DiskObjectStore::open_strict(encrypted) {
                Ok(s) => s,
                // Corrupt classify on a non-fresh wrap = wrong master
                // (or genuinely corrupt persistent data). Either way,
                // refuse loudly rather than silently overwrite.
                Err(_) => return Err(SyscallError::PermissionDenied),
            }
        };

        // Install under OBJECT_STORE lock (fast — no IPC, no
        // yield). The match arm catches a TOCTOU race where two
        // installs could try to install concurrently; we already
        // checked above but re-check here for safety.
        {
            let mut guard = crate::OBJECT_STORE.lock();
            if matches!(*guard, Some(crate::fs::ObjectStoreBackend::LazyDisk(_))) {
                return Err(SyscallError::PermissionDenied);
            }
            *guard = Some(crate::fs::ObjectStoreBackend::LazyDisk(
                alloc::boxed::Box::new(store),
            ));
        }

        // Flag the lazy-disk gate as ready so the legacy
        // ensure_disk_store() call sites become unconditional
        // fast-paths.
        crate::fs::lazy_disk::mark_disk_store_installed();

        Ok(0)
    }

    /// Test-mode stub for `handle_install_master_key`. The kernel-
    /// side `crate::fs::virtio_blk_device` module is gated out of
    /// host test builds (`#[cfg(not(test))]` on its declaration in
    /// `src/fs/mod.rs`); returning `Enosys` matches the no-virtio-blk
    /// behavior real callers see.
    #[cfg(test)]
    fn handle_install_master_key(
        _args: SyscallArgs,
        _ctx: &SyscallContext,
    ) -> SyscallResult {
        Err(SyscallError::Enosys)
    }

    /// Best-effort secure-zero of the master-key stack buffer.
    /// Volatile writes prevent dead-store elimination; the compiler
    /// fence forces the writes to happen-before any subsequent
    /// memory operation. Standard CRYPTO-301 hygiene pattern for
    /// kernels that don't carry the `zeroize` crate.
    #[cfg(not(test))]
    fn zeroize_master(buf: &mut [u8; 64]) {
        for b in buf.iter_mut() {
            // SAFETY: `b` is a unique mutable reference to a u8
            // that we own (kernel stack), and we write a fixed
            // valid value (0). The volatile attribute is the
            // load-bearing property here — preventing the
            // optimizer from eliding what looks like a dead store
            // to a buffer about to go out of scope.
            unsafe {
                core::ptr::write_volatile(b as *mut u8, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Drive a cluster's teardown — used by SYS_CLUSTER_REVOKE and by
    /// handle_exit's cluster-departure auto-revoke path. **Skips
    /// authority checks** — caller is responsible.
    ///
    /// Per ADR-027 Decision 3 + Divergence 2 (path A — advisory
    /// quiesce, leaning on tombstone-on-revoke from ADR-007 Divergence
    /// 7 for RO peer mappings):
    ///
    /// 1. **`begin_revoke`** under `CLUSTER_MANAGER(5)`: transition
    ///    `Active`|`Forming` → `Revoking`, snapshot member pids +
    ///    channel ids, release.
    /// 2. **Per-channel teardown** under `CHANNEL_MANAGER(6)` →
    ///    `PROCESS_TABLE(7)` → `FRAME_ALLOCATOR(8)`: drives each
    ///    channel through the existing revoke + unmap-or-tombstone
    ///    path.
    /// 3. **Cap revoke** under `CAPABILITY_MANAGER(4)`: for each
    ///    joined member, remove caps `caps_for_role` returned at
    ///    join. V1 stub returns empty, so this is a no-op until C7.
    ///    The 5-released-then-4-taken acquisition order respects
    ///    4 < 5 because step 1 already released `CLUSTER_MANAGER`.
    /// 4. **`complete_revoke`** under `CLUSTER_MANAGER(5)`: `Revoking`
    ///    → `Revoked`, free slot, bump generation.
    ///
    /// `CLUSTER_MANAGER` is *not* held across the per-channel fanout
    /// in step 2 — the snapshot pattern carries the data the loop
    /// needs.
    fn do_cluster_revoke(
        cluster_id: crate::ipc::cluster::ClusterId,
        initiator: crate::ipc::ProcessId,
        reason: u32,
    ) {
        // Step 1: begin_revoke + snapshot.
        let snapshot = {
            let mut guard = crate::CLUSTER_MANAGER.lock();
            match guard.as_mut() {
                Some(mgr) => match mgr.begin_revoke(cluster_id) {
                    Ok(snap) => snap,
                    Err(_) => return, // already Revoking/Revoked or stale id
                },
                None => return,
            }
        };

        // Step 2: per-channel teardown.
        for channel_id in snapshot.channels.iter().flatten() {
            let record = {
                let mut chan_guard = crate::CHANNEL_MANAGER.lock();
                match chan_guard.as_mut() {
                    Some(chan_mgr) => chan_mgr.revoke(*channel_id).ok(),
                    None => None,
                }
            };
            if let Some(record) = record {
                Self::teardown_channel_mappings(&record);
            }
        }

        // Step 3: cap revoke per joined member. V1 stub = no-op loop.
        // We re-look-up the cluster to find each member's role (the
        // snapshot only carries pids; role lives in
        // ClusterRecord.members[i] at the same index). The cluster is
        // in `Revoking` state so the lookup succeeds.
        for (i, pid_slot) in snapshot.joined_member_pids.iter().enumerate() {
            if let Some(pid) = pid_slot {
                let role = {
                    let guard = crate::CLUSTER_MANAGER.lock();
                    guard.as_ref().and_then(|mgr| {
                        mgr.get(cluster_id)
                            .ok()
                            .and_then(|rec| rec.members[i].as_ref().map(|m| m.role))
                    })
                };
                if let Some(role) = role {
                    let caps =
                        crate::ipc::cluster_policy::caps_for_role(snapshot.policy, role);
                    if !caps.is_empty() {
                        let mut cap_guard = crate::CAPABILITY_MANAGER.lock();
                        if let Some(cap_mgr) = cap_guard.as_mut() {
                            for &(endpoint, _rights) in caps {
                                let _ = cap_mgr.revoke_capability(*pid, endpoint);
                            }
                        }
                    }
                }
            }
        }

        // Step 4: complete_revoke.
        {
            let mut guard = crate::CLUSTER_MANAGER.lock();
            if let Some(mgr) = guard.as_mut() {
                let _ = mgr.complete_revoke(cluster_id);
            }
        }

        // Step 5: audit. Counts come from the snapshot — both arrays
        // are fixed-size with `Some` entries for live members /
        // attached channels.
        let member_count = snapshot
            .joined_member_pids
            .iter()
            .filter(|p| p.is_some())
            .count() as u32;
        let channel_count = snapshot
            .channels
            .iter()
            .filter(|c| c.is_some())
            .count() as u32;
        crate::audit::emit(crate::audit::RawAuditEvent::cluster_revoked(
            initiator,
            cluster_id.as_raw(),
            member_count,
            channel_count,
            reason,
            crate::audit::now(),
            0,
        ));
    }

    // ========================================================================
    // Audit infrastructure (ADR-007)
    // ========================================================================

    /// SYS_AUDIT_ATTACH: Attach as the audit ring consumer.
    ///
    /// Maps the kernel's audit ring pages read-only into the caller's
    /// address space. Returns the user-space virtual address.
    ///
    /// Capability-gated on `CapabilityKind::AuditConsumer`. Replaces the
    /// original bootstrap-Principal-only equality check (ADR-007 §"Audit
    /// channel boot sequence") with a delegated capability check, so a
    /// signed boot module like `audit-tail` (or a future kernelvisor)
    /// can hold its own Principal and still attach. The bootstrap path
    /// continues to work whenever the bootstrap-bound process is granted
    /// `AuditConsumer` at boot.
    ///
    /// Lock protocol (two-phase to avoid AUDIT_RING → PROCESS_TABLE):
    /// 1. CAPABILITY_MANAGER(4) → verify authority → release
    /// 2. AUDIT_RING → read phys_base, verify no consumer → release
    /// 3. PROCESS_TABLE(6) → allocate VMA → FRAME_ALLOCATOR(7) → map pages
    /// 4. AUDIT_RING → record consumer_pid + vaddr
    fn handle_audit_attach(_args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // --- Step 1: verify AuditConsumer system capability ---
        {
            use crate::ipc::capability::CapabilityKind;
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::PermissionDenied)?;
            let has_cap = cap_mgr
                .has_system_capability(ctx.process_id, CapabilityKind::AuditConsumer)
                .unwrap_or(false);
            if !has_cap {
                return Err(SyscallError::PermissionDenied);
            }
        }

        // --- Step 2: read ring metadata ---
        let (physical_base, page_count) = {
            let ring_guard = crate::AUDIT_RING.lock();
            let ring = ring_guard.as_ref().ok_or(SyscallError::InvalidArg)?;

            if ring.consumer_attached() {
                return Err(SyscallError::InvalidArg); // only one consumer
            }

            (ring.physical_base(), ring.page_count())
        }; // drop AUDIT_RING

        // --- Step 3: map pages into caller's address space ---
        let consumer_vaddr = {
            let mut pt_guard = crate::PROCESS_TABLE.lock();
            let vma = pt_guard
                .as_mut()
                .and_then(|pt| pt.vma_mut(ctx.process_id))
                .ok_or(SyscallError::InvalidArg)?;

            let vaddr = vma
                .allocate_region(page_count)
                .ok_or(SyscallError::OutOfMemory)?;

            let flags = crate::memory::paging::flags::user_ro();

            let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
            // SAFETY: ctx.cr3 is a valid PML4/L0 for this process.
            unsafe {
                let mut pt = crate::memory::paging::page_table_from_cr3(ctx.cr3);
                crate::memory::paging::map_range(
                    &mut pt,
                    vaddr,
                    physical_base,
                    page_count as usize,
                    flags,
                    &mut fa_guard,
                )
                .map_err(|_| SyscallError::OutOfMemory)?;
            }
            drop(fa_guard);
            drop(pt_guard);
            vaddr
        };

        // --- Step 4: record consumer in ring ---
        {
            let mut ring_guard = crate::AUDIT_RING.lock();
            if let Some(ring) = ring_guard.as_mut() {
                // Re-check: another attach may have raced between step 2 and 4.
                if ring.consumer_attached() {
                    // Undo: should unmap, but this race is extremely unlikely.
                    // For now, log and return error.
                    return Err(SyscallError::InvalidArg);
                }
                ring.set_consumer(ctx.process_id, consumer_vaddr);
            }
        }

        crate::println!(
            "  [AuditAttach] pid={} → vaddr={:#x} ({} pages)",
            ctx.process_id.slot(), consumer_vaddr, page_count,
        );

        Ok(consumer_vaddr)
    }

    /// SYS_GET_PROCESS_PRINCIPAL: resolve a `ProcessId` to its bound
    /// 32-byte Principal. See `SyscallNumber::GetProcessPrincipal` for
    /// the wire ABI.
    ///
    /// Lock protocol:
    /// 1. CAPABILITY_MANAGER(4) → cap check on caller → release
    /// 2. CAPABILITY_MANAGER(4) → live principal lookup → release
    /// 3. PROCESS_TABLE(6) → recent-exits ring lookup (only on miss) → release
    /// 4. Write to user buffer
    ///
    /// Step 1 and 2 acquire the same lock at different times rather than
    /// holding it across the dispatch — the cap check needs `ctx.process_id`,
    /// the live lookup needs the target `ProcessId` from arg1; both are
    /// table lookups so the cost is one atomic acquire each.
    fn handle_get_process_principal(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let target_pid_raw = args.arg1;
        let out_buf = args.arg2;
        let buf_len = args.arg_usize(3);

        if buf_len != 32 {
            return Err(SyscallError::InvalidArg);
        }

        // --- Step 1: cap check on the caller ---
        {
            use crate::ipc::capability::CapabilityKind;
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::PermissionDenied)?;
            let has_cap = cap_mgr
                .has_system_capability(ctx.process_id, CapabilityKind::AuditConsumer)
                .unwrap_or(false);
            if !has_cap {
                return Err(SyscallError::PermissionDenied);
            }
        }

        // --- Steps 2-3: principal lookup, live then recent-exits ---
        let target = crate::ipc::ProcessId::from_raw(target_pid_raw);

        let principal = {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            cap_guard.as_ref().and_then(|cm| cm.get_principal(target).ok())
        }
        .or_else(|| {
            let pt_guard = crate::PROCESS_TABLE.lock();
            pt_guard.as_ref().and_then(|pt| pt.lookup_recent_exit(target))
        })
        .ok_or(SyscallError::InvalidArg)?;

        // --- Step 4: write principal AID bytes to user buffer ---
        let out_slice = UserWriteSlice::validate(ctx, out_buf, 32)?;
        out_slice.write_from(principal.aid())?;

        Ok(32)
    }

    /// SYS_AUDIT_INFO: Read audit ring statistics.
    ///
    /// Writes a fixed-format stats buffer to the caller's user buffer.
    /// Any process may call (observability is not secret).
    ///
    /// Output format (48 bytes):
    /// ```text
    /// [0..8]   total_produced: u64
    /// [8..16]  total_dropped: u64
    /// [16..20] capacity: u32
    /// [20..21] consumer_attached: u8 (0 or 1)
    /// [21..24] reserved: [u8; 3]
    /// [24..28] online_cpus: u32
    /// [28..32] staging_buf_0_len: u32
    /// [32..36] staging_buf_1_len: u32
    /// [36..40] staging_buf_2_len: u32
    /// [40..44] staging_buf_3_len: u32
    /// [44..48] reserved: u32
    /// ```
    fn handle_audit_info(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        let out_buf = args.arg1;
        let buf_len = args.arg2 as u32;

        if buf_len < 48 || out_buf == 0 || ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        let mut stats = [0u8; 48];

        {
            let ring_guard = crate::AUDIT_RING.lock();
            if let Some(ring) = ring_guard.as_ref() {
                stats[0..8].copy_from_slice(&ring.total_produced().to_le_bytes());
                stats[8..16].copy_from_slice(&ring.total_dropped().to_le_bytes());
                stats[16..20].copy_from_slice(&ring.capacity().to_le_bytes());
                stats[20] = if ring.consumer_attached() { 1 } else { 0 };
            }
        }

        let online = crate::online_cpu_count() as u32;
        stats[24..28].copy_from_slice(&online.to_le_bytes());

        // Per-CPU staging buffer occupancy (first 4 CPUs)
        for cpu in 0..4usize {
            let len = if cpu < crate::MAX_CPUS {
                crate::PER_CPU_AUDIT_BUFFER[cpu].len() as u32
            } else {
                0
            };
            let offset = 28 + cpu * 4;
            stats[offset..offset + 4].copy_from_slice(&len.to_le_bytes());
        }

        // T-8 (docs/threat-model.md): drain-skip counter at offset 44..48.
        // Saturating u32 view of the AUDIT_DRAIN_SKIPS u64 — saturation at
        // u32::MAX is itself a loud signal ("drain has been contended at
        // least 4B times"). Lock-free atomic load, no AUDIT_RING needed.
        let skips_u64 = crate::AUDIT_DRAIN_SKIPS
            .load(core::sync::atomic::Ordering::Relaxed);
        let skips_u32 = if skips_u64 > u32::MAX as u64 {
            u32::MAX
        } else {
            skips_u64 as u32
        };
        stats[44..48].copy_from_slice(&skips_u32.to_le_bytes());

        // ADR-020 straggler caught during the user_slice relocation:
        // 48-byte audit stats via typed slice.
        let stats_slice = UserWriteSlice::validate(ctx, out_buf, 48)?;
        stats_slice.write_from(&stats)?;

        Ok(0)
    }

    /// SYS_AUDIT_EMIT_INPUT_FOCUS: compositor reports a window-focus
    /// transition into the kernel audit ring (T-7 Phase A,
    /// docs/threat-model.md).
    ///
    /// Args: arg1 = new_window_id (u32), arg2 = old_window_id (u32; 0
    ///       if no prior focus), arg3 = user vaddr of 32-byte new owner
    ///       Principal (zero bytes when focus was lost).
    ///
    /// Capability-gated on `CapabilityKind::EmitInputAudit`. Without
    /// the capability, returns `PermissionDenied`. Reads the 32-byte
    /// Principal via ADR-020 `UserReadSlice`.
    ///
    /// Lock ordering: CAPABILITY_MANAGER(4) only — released before
    /// `audit::emit()` (lock-free per-CPU SPSC).
    fn handle_audit_emit_input_focus(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::capability::CapabilityKind;

        let new_window_id = args.arg1_u32();
        let old_window_id = args.arg2_u32();
        let owner_principal_ptr = args.arg3;

        if ctx.cr3 == 0 {
            return Err(SyscallError::InvalidArg);
        }

        // Capability check: caller must hold EmitInputAudit. Granted
        // to spawned boot modules at handle_spawn time.
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::PermissionDenied)?;
            let has_cap = cap_mgr
                .has_system_capability(ctx.process_id, CapabilityKind::EmitInputAudit)
                .unwrap_or(false);
            if !has_cap {
                return Err(SyscallError::PermissionDenied);
            }
        } // drop CAPABILITY_MANAGER(4)

        // ADR-020: read 32-byte Principal via typed slice.
        let principal_slice = UserReadSlice::validate(ctx, owner_principal_ptr, 32)?;
        let mut owner_principal = [0u8; 32];
        principal_slice.read_into(&mut owner_principal)?;

        crate::audit::emit(crate::audit::RawAuditEvent::input_focus_change(
            ctx.process_id,
            new_window_id,
            old_window_id,
            owner_principal,
            crate::audit::now(),
            0,
        ));

        Ok(0)
    }

    /// SYS_SET_WALLCLOCK (39) — republish the kernel's Unix-seconds
    /// baseline. ADR-022 § 5: udp-stack queries NIST every 4h and calls
    /// this with the result. Capability-gated; anonymous senders rejected.
    ///
    /// Three plain stores in `time::wallclock::set`; no lock acquired,
    /// no IPC, no allocation — the handler is verification-friendly by
    /// construction.
    fn handle_set_wallclock(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
        use crate::ipc::capability::CapabilityKind;

        let unix_secs = args.arg1;
        let source_tag = (args.arg2 & 0xff) as u8;

        // Capability check: caller must hold SetWallclock. Granted only
        // to udp-stack at boot today.
        {
            let cap_guard = crate::CAPABILITY_MANAGER.lock();
            let cap_mgr = cap_guard.as_ref().ok_or(SyscallError::PermissionDenied)?;
            let has_cap = cap_mgr
                .has_system_capability(ctx.process_id, CapabilityKind::SetWallclock)
                .unwrap_or(false);
            if !has_cap {
                return Err(SyscallError::PermissionDenied);
            }
        } // drop CAPABILITY_MANAGER(4)

        crate::time::wallclock::set(unix_secs, source_tag);
        Ok(0)
    }

    /// SYS_GET_WALLCLOCK (40) — read the projected Unix-seconds value.
    /// Returns 0 before any successful `SetWallclock` (sentinel for "no
    /// time yet"). No capability check, no identity check; consumers
    /// that read what the kernel already chose to publish need no
    /// further authorization.
    fn handle_get_wallclock(_args: SyscallArgs, _ctx: &SyscallContext) -> SyscallResult {
        Ok(crate::time::wallclock::get())
    }
}

// ============================================================================
// Tests — Cut 1: validation surface
// ============================================================================
//
// These tests exercise every check that runs before a handler touches a
// kernel global. They cover:
//   - read_user_buffer / write_user_buffer early-exit guards (zero-len,
//     MAX_USER_BUFFER cap, USER_SPACE_END crossing, addr overflow, cr3=0).
//   - Handler-level argument validation (length bounds, key length,
//     buffer-size minimums).
//   - Pure handlers (handle_get_pid).
//
// Out of scope for this cut:
//   - Multi-page traversal inside read_user_buffer / write_user_buffer
//     (needs a fake translator — Cut 2).
//   - Handlers that call ensure_disk_store() or other global initializers
//     before validation (handle_obj_put/get/delete/list).
//   - Lock acquisition, IPC enqueue, and page-table-walk paths
//     (need fixture-initialized globals — Cut 3).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{Principal, ProcessId};
    use crate::scheduler::TaskId;

    /// Build a SyscallContext that handlers can read but that will fail
    /// any call into read_user_buffer / write_user_buffer (cr3=0).
    /// This isolates pre-globals validation paths.
    fn fake_ctx() -> SyscallContext {
        SyscallContext {
            process_id: ProcessId::new(7, 1),
            task_id: TaskId::new(3, 0),
            cr3: 0,
            caller_principal: Some(Principal::from_public_key([1u8; 32])),
        }
    }

    fn args(a1: u64, a2: u64, a3: u64) -> SyscallArgs {
        SyscallArgs::new(a1, a2, a3, 0, 0, 0)
    }

    // read_user_buffer / write_user_buffer early-exit guards relocated to
    // src/syscalls/user_slice.rs (per ADR-020) along with the helpers
    // themselves (now module-private there).

    // ---- handle_get_pid ----------------------------------------------------

    #[test]
    fn handle_get_pid_returns_ctx_slot() {
        // fake_ctx() has slot=7.
        let ctx = fake_ctx();
        assert_eq!(
            SyscallDispatcher::handle_get_pid(args(0, 0, 0), &ctx),
            Ok(7),
        );
    }

    // ---- handle_write validation -------------------------------------------

    #[test]
    fn handle_write_len_zero_returns_ok_zero() {
        let ctx = fake_ctx();
        // arg1=endpoint, arg2=user_buf, arg3=len=0.
        assert_eq!(
            SyscallDispatcher::handle_write(args(16, 0x1000, 0), &ctx),
            Ok(0),
        );
    }

    #[test]
    fn handle_write_len_over_256_returns_invalid() {
        let ctx = fake_ctx();
        assert_eq!(
            SyscallDispatcher::handle_write(args(16, 0x1000, 257), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    // ---- handle_print validation -------------------------------------------

    #[test]
    fn handle_print_len_zero_returns_ok_zero() {
        let ctx = fake_ctx();
        // arg1=user_buf, arg2=len=0.
        assert_eq!(
            SyscallDispatcher::handle_print(args(0x1000, 0, 0), &ctx),
            Ok(0),
        );
    }

    #[test]
    fn handle_print_len_over_256_returns_invalid() {
        let ctx = fake_ctx();
        assert_eq!(
            SyscallDispatcher::handle_print(args(0x1000, 257, 0), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    // ---- handle_bind_principal validation ----------------------------------

    #[test]
    fn handle_bind_principal_pubkey_len_zero_invalid() {
        let ctx = fake_ctx();
        // arg1=target_pid, arg2=pubkey_ptr, arg3=pubkey_len=0.
        assert_eq!(
            SyscallDispatcher::handle_bind_principal(args(1, 0x1000, 0), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn handle_bind_principal_pubkey_len_31_invalid() {
        let ctx = fake_ctx();
        assert_eq!(
            SyscallDispatcher::handle_bind_principal(args(1, 0x1000, 31), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn handle_bind_principal_pubkey_len_64_invalid() {
        let ctx = fake_ctx();
        // Common confusion with secret-key length — must still reject.
        assert_eq!(
            SyscallDispatcher::handle_bind_principal(args(1, 0x1000, 64), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    // ---- handle_get_principal validation -----------------------------------

    #[test]
    fn handle_get_principal_buf_zero_invalid() {
        let ctx = fake_ctx();
        // arg1=out_buf, arg2=buf_len=0.
        assert_eq!(
            SyscallDispatcher::handle_get_principal(args(0x1000, 0, 0), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn handle_get_principal_buf_31_invalid() {
        let ctx = fake_ctx();
        // 32-byte public key requires buf_len >= 32.
        assert_eq!(
            SyscallDispatcher::handle_get_principal(args(0x1000, 31, 0), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    // ---- handle_recv_msg / handle_try_recv_msg validation ------------------
    //
    // Cut 3a unlocked these: the host asm-stub block in arch/x86_64/mod.rs
    // (cfg(any(fuzzing, test))) provides `yield_save_and_switch` so handler
    // bodies referencing it now link in test builds. Validation paths still
    // exit before any asm symbol is invoked.

    #[test]
    fn handle_recv_msg_buf_below_header_invalid() {
        let ctx = fake_ctx();
        // 36 = 32-byte sender principal + 4-byte from_endpoint.
        // arg1=ep, arg2=buf, arg3=buf_len=35.
        assert_eq!(
            SyscallDispatcher::handle_recv_msg(args(16, 0x1000, 35), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    #[test]
    fn handle_try_recv_msg_buf_below_header_invalid() {
        let ctx = fake_ctx();
        assert_eq!(
            SyscallDispatcher::handle_try_recv_msg(args(16, 0x1000, 35), &ctx),
            Err(SyscallError::InvalidArg),
        );
    }

    // Multi-page copy_from_user_pages / copy_to_user_pages tests + the
    // FakeSpace fixture were relocated to src/syscalls/user_slice.rs
    // (per ADR-020).
}
