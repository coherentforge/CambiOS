// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! The one reap path (ADR-019 § Decision 1).
//!
//! A process dies either by calling `SYS_EXIT` or by taking a fault the
//! kernel cannot recover; from every observer's point of view the two
//! must look identical except for the recorded reason. [`reap_process`]
//! is that single routine — the ADR-034 exit sequence exactly as
//! `handle_exit` grew it, now callable from two entry points:
//!
//! 1. mark the task `Terminated` + `purge_task` under `SCHEDULER(1)`,
//!    winning the `Running → Terminated` transition at most once
//!    (enqueue-once — a fault racing a clean exit must not enqueue the
//!    root/stack twice);
//! 2. latch the exit record into `TASK_EXIT_RING` keyed by the
//!    generation-carrying task handle, then selectively wake a parent
//!    blocked on this child (record-then-wake closes the lost-wakeup
//!    window);
//! 3. inline reclamation: capability table + reply-endpoint slot,
//!    channels (with TLB shootdown), cluster departure, VMA frames +
//!    page tables + heap;
//! 4. audit;
//! 5. enqueue the self-referential set (page-table root, kernel stack,
//!    task slot) for this CPU's reaper ([`crate::reaper`], ADR-034).
//!
//! The caller then yields; a `Terminated` task is never re-scheduled.
//! `reap_process` does not yield itself so that both callers own their
//! terminal loop and neither can return into a dead context by mistake.
//!
//! Callable only with interrupts enabled: step 3 spins on cross-CPU TLB-
//! shootdown acknowledgements, and a masked CPU can neither acknowledge
//! nor be acknowledged (ADR-019 § Decision 6). The syscall path already
//! runs enabled; the fault path re-enables before calling (019.B).
//!
//! Lock ordering: every hierarchy lock is taken and released in turn —
//! `SCHEDULER(1)`, then `CAPABILITY_MANAGER(4)`, `CHANNEL_MANAGER(6)`,
//! `CLUSTER_MANAGER(5)` (released before `do_cluster_revoke` re-enters),
//! `PROCESS_TABLE(7) → FRAME_ALLOCATOR(8)`; the exit ring and the reaper
//! queue are their own domains, never held with a hierarchy lock.

use crate::ipc::{Principal, ProcessId};
use crate::scheduler::TaskId;
use crate::syscalls::dispatcher::SyscallDispatcher;

/// Why a process is being reaped (ADR-019 § Decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// The process called `SYS_EXIT` with this code.
    Exited(i32),
    /// The kernel killed the process for an unrecoverable user-mode
    /// fault. `fault_addr` is CR2 / FAR_EL1 / stval (the GPF arm on
    /// x86_64 carries the error code instead — there is no address);
    /// `pc` is RIP / ELR_EL1 / sepc at the fault.
    Faulted { kind: FaultKind, fault_addr: u64, pc: u64 },
}

/// The common fault vocabulary across the three architectures
/// (ADR-019 § Decision 2). `ArchSpecific` carries the architecture's
/// raw code for anything outside the common set, so every `match` on
/// this enum is exhaustive without dropping information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    PageFault,
    GeneralProtection,
    InvalidOpcode,
    /// Reserved for a future guard-page handler; no producer yet.
    StackOverflow,
    DivideByZero,
    /// x86 vector, aarch64 `ESR_EL1.EC`, or riscv64 `scause` code.
    ArchSpecific(u8),
}

impl FaultKind {
    /// Wire form for the audit event (`proc.faulted` arg0) and, from
    /// ADR-019 phase D, `ExitInfo`: common kinds are tags 0–4,
    /// `ArchSpecific` is tag 5 with the raw code in bits 8..16.
    pub const fn wire(self) -> u64 {
        match self {
            FaultKind::PageFault => 0,
            FaultKind::GeneralProtection => 1,
            FaultKind::InvalidOpcode => 2,
            FaultKind::StackOverflow => 3,
            FaultKind::DivideByZero => 4,
            FaultKind::ArchSpecific(raw) => 5 | ((raw as u64) << 8),
        }
    }
}

/// SCAFFOLDING: the exit code recorded in `TASK_EXIT_RING` for a
/// faulted process until ADR-019 phase D widens the ring entry to
/// `ExitInfo`. `i32::MIN` is deliberately not a value any process
/// passes to `SYS_EXIT`. A parent reading it through today's
/// `SYS_WAIT_TASK` sees "the child did not exit normally" and nothing
/// more — which is already the difference between a parent that
/// unblocks and one that waits forever.
/// Replace when: ADR-019 phase D lands (`ExitInfo` out-buffer).
pub const FAULTED_EXIT_CODE: i32 = i32::MIN;

/// Reap the current task on this CPU for a user-mode fault (ADR-019
/// § Decision 6 — the fault-handler entry point). Resolves the task,
/// its process, and its bound Principal, then runs [`reap_process`].
/// Returns `false` if this CPU has no current task with a process
/// (a user-mode fault with nobody to blame is a kernel invariant
/// violation; the caller halts).
///
/// The arch handler MUST re-enable interrupts before calling: the
/// reap spins on cross-CPU TLB-shootdown acknowledgements.
pub fn reap_faulting_current(kind: FaultKind, fault_addr: u64, pc: u64) -> bool {
    let Some((task_id, process_id)) = crate::current_task_process() else {
        return false;
    };
    let caller_principal = {
        let cap_guard = crate::CAPABILITY_MANAGER.lock();
        cap_guard.as_ref().and_then(|cm| cm.get_principal(process_id).ok())
    };
    crate::println!(
        "  [Fault] pid={} task={} {:?} at {:#x} (pc={:#x}) — reaping",
        process_id.slot(),
        task_id.slot(),
        kind,
        fault_addr,
        pc
    );
    reap_process(
        process_id,
        task_id,
        caller_principal,
        ExitReason::Faulted { kind, fault_addr, pc },
    );
    true
}

/// Reap `process_id` / `task_id` (the current task on this CPU) for
/// `reason`. `caller_principal` is the dying process's bound Principal
/// (`None` = never bound), recorded for post-exit audit resolution.
/// Returns to the caller, which must then yield forever.
pub fn reap_process(
    process_id: ProcessId,
    task_id: TaskId,
    caller_principal: Option<Principal>,
    reason: ExitReason,
) {
    // The ring carries an i32 until phase D; a fault records
    // `FAULTED_EXIT_CODE` so the parent still unblocks (Problem 2).
    let code = match reason {
        ExitReason::Exited(code) => code,
        ExitReason::Faulted { .. } => FAULTED_EXIT_CODE,
    };

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
                sched.get_task_mut_pub(task_id)
            {
                let already_terminated =
                    task.state == crate::scheduler::TaskState::Terminated;
                task.state = crate::scheduler::TaskState::Terminated;
                task.exit_code = code as u32;
                // kernel_stack_top is 0 for the idle task (boot stack);
                // user tasks carry a heap-allocated stack to free.
                let kstack = if already_terminated { 0 } else { task.kernel_stack_top };
                (task.parent_task, kstack, !already_terminated)
            } else {
                (None, 0, false)
            };
            sched.purge_task(task_id);
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
        crate::record_task_exit(task_id, code, parent_to_wake);
    }

    // Wake the parent iff it is blocked waiting on THIS child (ADR-034
    // Phase B selective wake). A parent waiting on a different child, or
    // not waiting, is left alone — this child's exit is already latched in
    // the ring above for later collection. Must follow the ring record.
    if let Some(parent_id) = parent_to_wake {
        crate::wake_child_waiter(parent_id, task_id.slot());
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
            let count = cap_mgr.revoke_all_for_process(process_id).unwrap_or(0);
            // Drop the ProcessCapabilities table entry. Without this,
            // the next spawn into the same pid slot sees
            // register_process fail (slot already Some), grant_capability
            // fails (caller's ProcessId generation doesn't match the
            // stale entry's), and the new process boots with no caps.
            // Observable symptom before this fix: second `play <game>`
            // logged "ERROR: register_endpoint" and exit(1).
            let _ = cap_mgr.unregister_process(process_id);
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
    let slot = process_id.slot() as usize;
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
            let revoked = chan_mgr.revoke_all_for_process(process_id);
            drop(chan_guard); // release CHANNEL_MANAGER(5) before PROCESS_TABLE(6)

            let count = revoked.len();
            for record in revoked.iter() {
                SyscallDispatcher::teardown_channel_mappings(record);
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
            let cluster_ids = mgr.mark_departed_for_process(process_id);
            let mut to_revoke = alloc::vec::Vec::new();
            for id in cluster_ids {
                if let Ok(record) = mgr.get(id) {
                    // Find the now-Departed member with our pid;
                    // could be matched on multiple roles in
                    // theory (v1 disallows; check all anyway).
                    for member_slot in record.members.iter() {
                        if let Some(member) = member_slot.as_ref() {
                            if member.state == MemberState::Departed
                                && member.joined_pid == Some(process_id)
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
        SyscallDispatcher::do_cluster_revoke(
            *id,
            process_id,
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
            if pt.slot_occupied(process_id) {
                // Record the exiting process's Principal in the
                // recent-exits ring before destroy_process bumps the
                // generation. SYS_GET_PROCESS_PRINCIPAL falls back
                // to this ring when an audit consumer queries a
                // subject_pid whose process has already exited.
                // Skipped when caller_principal is None (process
                // never bound an identity — nothing to resolve).
                if let Some(p) = caller_principal {
                    pt.record_exit(process_id, p);
                }
                let mut fa_guard = crate::FRAME_ALLOCATOR.lock();
                let root = pt.destroy_process(process_id, &mut fa_guard);
                (true, root)
            } else {
                (false, None)
            }
        } else {
            (false, None)
        }
    };


    // Distinct audit kinds so a supervisor can pattern-match on the
    // kind byte without inspecting exit-code bits (ADR-019 § Decision 3).
    match reason {
        ExitReason::Exited(code) => {
            crate::audit::emit(crate::audit::RawAuditEvent::process_terminated(
                process_id, code, 0, crate::audit::now(), 0,
            ));
        }
        ExitReason::Faulted { kind, fault_addr, pc } => {
            crate::audit::emit(crate::audit::RawAuditEvent::process_faulted(
                process_id, kind.wire(), fault_addr, pc, 0, crate::audit::now(), 0,
            ));
        }
    }

    let tag = match reason {
        ExitReason::Exited(_) => "Exit",
        ExitReason::Faulted { .. } => "Fault",
    };
    crate::println!(
        "  [{}] pid={} task={} code={} (reclaimed {} cap(s), {} chan(s), {} cluster(s){})",
        tag,
        process_id.slot(),
        task_id.slot(),
        code,
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
    if won_transition && !task_id.is_idle() {
        let item = crate::reaper::ReclaimItem {
            root_phys: deferred_root.unwrap_or(0),
            kstack_top: kstack_to_reclaim,
            task_id,
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
}
