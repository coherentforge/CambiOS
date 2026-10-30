// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Policy service kernel-side infrastructure (ADR-006).
//!
//! This module provides the kernel plumbing for the externalized policy service:
//!
//! - **PolicyRouter**: pending-query table that tracks syscall queries sent to
//!   the user-space policy service and awaiting responses.
//! - **PolicyCache**: per-CPU decision cache that avoids upcalls in steady state.
//! - **Wire format**: query/response message layout for the 256-byte IPC path.
//! - **`policy_check()`**: top-level function called from the syscall dispatcher,
//!   replacing the old `on_syscall` interceptor path.
//!
//! The policy service is a user-space process (endpoint 22) that receives
//! structured queries and returns Allow/Deny decisions. The kernel caches
//! decisions per-CPU and only upcalls on cache miss.
//!
//! **Fail closed.** Once the policy service has been identified
//! (`POLICY_SERVICE_READY`), every path that cannot obtain a decision —
//! pending table full, query queue full, response timeout — is a Deny,
//! audited as `SyscallDenied`, and never cached (the next attempt asks
//! again). Enforcement availability may degrade a service into retrying;
//! it may not degrade into permission. The one structural bypass is the
//! window before the policy service is listening on its query endpoint,
//! in which the only user task that has run is init spawning it (ADR-018
//! boot wave): there is no one to ask.

use crate::ipc::interceptor::InterceptDecision;
use crate::ipc::{EndpointId, Message, ProcessId};
use crate::scheduler::TaskId;
use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU8;

// ============================================================================
// Constants
// ============================================================================

/// ARCHITECTURAL: IPC endpoint where the policy service receives queries.
pub const POLICY_QUERY_ENDPOINT: u32 = 22;

/// ARCHITECTURAL: IPC endpoint where the kernel intercepts policy responses.
/// Writes to this endpoint are consumed by the kernel in `handle_write` —
/// they never enter the IPC queue.
pub const POLICY_RESP_ENDPOINT: u32 = 23;

/// Diagnostic counters for the policy upcall path, printed once by the
/// reschedule diagnostic: queries submitted to the service, answered by
/// it, and expired (woken to Deny). `expired` ≈ `submitted` means the
/// service never answers and every gated syscall costs the full
/// timeout — the shape the per-service boot times showed.
pub static POLICY_QUERIES_SUBMITTED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static POLICY_QUERIES_ANSWERED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static POLICY_QUERIES_EXPIRED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Upcalls re-submitted after an expiry (see `POLICY_UPCALL_ATTEMPTS`).
/// Non-zero on a healthy system means answers are arriving late or a
/// wake was lost — look before it becomes denials.
pub static POLICY_QUERIES_RETRIED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// TUNING: how many times `policy_check` re-submits a query whose answer
/// did not arrive within `POLICY_TIMEOUT_TICKS` before it denies. Fail
/// closed still means a Deny after the bound (3 s at 100 Hz); the retry
/// is the "a service retries" half of degrade-loudly, done where the
/// caller cannot tell a late answer from a real one — on the Dell 3630 a
/// single expiry killed terminal-window (its first `recv-msg` denied, it
/// exited, the GUI went black; 2026-10-29). One query is in flight per
/// task at any time, so the bound multiplies latency, not table load.
pub const POLICY_UPCALL_ATTEMPTS: u32 = 3;

/// TUNING: how many query expiries print a forensic line (what the
/// policy service was doing at that moment) before going quiet. Enough
/// to see a pattern off a photo of the panel; bounded so a dead policy
/// service cannot flood the console from the timer tick.
const EXPIRY_FORENSICS_MAX: u64 = 8;
static EXPIRY_FORENSICS_PRINTED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// TUNING: ticks before a pending policy query expires and the blocked
/// caller is woken with a Deny. At 100 Hz timer, 100 ticks = 1 second.
/// Long enough for the policy service to respond under normal conditions,
/// short enough that a hung policy service doesn't block tasks indefinitely
/// (they are denied, loudly, and may retry).
pub const POLICY_TIMEOUT_TICKS: u64 = 100;

/// TUNING: time-to-live for cached policy decisions (in ticks).
/// Same as timeout — 1 second at 100 Hz. Upcall at most once per second
/// per (process, syscall) pair in steady state.
pub const POLICY_TTL_TICKS: u64 = 100;

/// SCAFFOLDING: entries per CPU in the policy decision cache.
/// Why: 35 syscalls × ~10 processes = ~350 possible entries; 64 covers the
/// hot working set with eviction. Most workloads repeat a small subset.
/// Replace when: a single CPU routinely sees >50 distinct (process, syscall)
/// pairs within a TTL window.
pub const POLICY_CACHE_SIZE: usize = 64;

/// SCAFFOLDING: maximum concurrent pending policy queries.
/// Why: at most (num_cpus - 1) tasks can be blocked on PolicyWait simultaneously
/// (one CPU must run the policy service). 32 provides ~4× headroom for a
/// v1 system with up to 8 CPUs.
/// Replace when: systems with >8 CPUs routinely saturate the pending table.
pub const MAX_PENDING_QUERIES: usize = 32;

// ============================================================================
// Decision delivery (lock-free)
// ============================================================================

/// Per-task decision slots. The response handler writes before waking a task;
/// the woken task reads after resuming.
///
/// Values: 0 = no decision, 1 = Allow, 2 = Deny, 3 = expired by the sweep.
/// Anything but Allow/Deny is a Deny the caller does not cache.
pub static POLICY_DECISIONS: [AtomicU8; crate::MAX_TASKS] =
    [const { AtomicU8::new(0) }; crate::MAX_TASKS];

/// Decision values stored in POLICY_DECISIONS slots.
pub const DECISION_NONE: u8 = 0;
pub const DECISION_ALLOW: u8 = 1;
pub const DECISION_DENY: u8 = 2;
/// Written by the expiry sweep, under the waiter's scheduler lock, just
/// before it wakes the waiter.
pub const DECISION_EXPIRED: u8 = 3;

// ============================================================================
// Wire format
// ============================================================================

/// Build a policy query message for the policy service.
///
/// Query payload layout (48 bytes):
/// ```text
/// [0..8]   query_id: u64 (kernel-assigned monotonic)
/// [8..12]  caller_pid: u32 (ProcessId slot index)
/// [12..16] syscall_num: u32
/// [16..48] caller_principal: [u8; 32]
/// ```
pub fn build_query_message(
    query_id: u64,
    caller_pid: ProcessId,
    syscall_num: u32,
    caller_principal: &[u8; 32],
) -> Message {
    let mut msg = Message::new(
        EndpointId(POLICY_RESP_ENDPOINT),   // from: response endpoint
        EndpointId(POLICY_QUERY_ENDPOINT),  // to: query endpoint
    );
    // The kernel is the sender. Stamp the bootstrap Principal so the
    // policy service's verified receive (libipc `ServiceLoop`, which
    // drops anonymous messages by design) accepts the query. Without
    // this no query was ever answered: every gated syscall sat out the
    // full `POLICY_TIMEOUT_TICKS` and failed open — one second per
    // gated syscall, on QEMU and on the Dell 3630 alike (found
    // 2026-10-27 via the per-service boot times).
    #[cfg(not(test))]
    {
        msg.sender_principal = Some(crate::BOOTSTRAP_PRINCIPAL.load());
    }

    let mut payload = [0u8; 48];
    payload[0..8].copy_from_slice(&query_id.to_le_bytes());
    payload[8..12].copy_from_slice(&caller_pid.slot().to_le_bytes());
    payload[12..16].copy_from_slice(&syscall_num.to_le_bytes());
    payload[16..48].copy_from_slice(caller_principal);

    // SAFETY of unwrap: 48 < 256, set_payload cannot fail.
    let _ = msg.set_payload(&payload);
    msg
}

/// Parse a policy response from the user-space policy service.
///
/// Response payload layout (9 bytes):
/// ```text
/// [0..8]  query_id: u64
/// [8]     decision: u8 (0 = Allow, 1 = Deny)
/// ```
///
/// Returns `None` if the payload is too short or malformed.
pub fn parse_response(payload: &[u8]) -> Option<(u64, bool)> {
    if payload.len() < 9 {
        return None;
    }
    let query_id = u64::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
        payload[4], payload[5], payload[6], payload[7],
    ]);
    let allowed = payload[8] == 0; // 0 = Allow, anything else = Deny
    Some((query_id, allowed))
}

// ============================================================================
// PolicyRouter — pending query table
// ============================================================================

/// A pending policy query awaiting a response from the policy service.
#[derive(Debug, Clone, Copy)]
pub struct PendingQuery {
    pub query_id: u64,
    pub task_id: TaskId,
    pub submitted_at: u64,
}

/// Tracks policy queries that have been sent to the user-space policy service
/// and are awaiting responses.
///
/// # Locking
///
/// Protected by its own `Spinlock` (independent lock domain, like
/// `SHARDED_IPC.shards[*]`). The critical invariant: **never hold the
/// PolicyRouter lock while acquiring PER_CPU_SCHEDULER**. Enforced by API —
/// `complete_query` returns the TaskId to wake; the caller drops the lock
/// before waking.
///
/// # Verification properties
///
/// - `next_query_id` is monotonically increasing (never wraps in practice).
/// - `submit_query` fills the first `None` slot; returns `None` if full.
/// - `complete_query` removes exactly one entry matching query_id.
/// - `expire_stale` removes all entries older than `timeout` ticks.
pub struct PolicyRouter {
    pending: [Option<PendingQuery>; MAX_PENDING_QUERIES],
    next_query_id: u64,
}

impl Default for PolicyRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRouter {
    pub const fn new() -> Self {
        Self {
            pending: [None; MAX_PENDING_QUERIES],
            next_query_id: 1, // Start at 1; 0 is reserved/invalid
        }
    }

    /// Submit a new pending query. Returns the assigned query_id,
    /// or `None` if the pending table is full.
    pub fn submit_query(&mut self, task_id: TaskId, submitted_at: u64) -> Option<u64> {
        let slot = self.pending.iter().position(|e| e.is_none())?;
        let query_id = self.next_query_id;
        self.next_query_id += 1;
        self.pending[slot] = Some(PendingQuery {
            query_id,
            task_id,
            submitted_at,
        });
        Some(query_id)
    }

    /// Complete a pending query by query_id. Returns the TaskId of the
    /// blocked task to wake, or `None` if no matching query was found.
    ///
    /// The caller MUST drop the PolicyRouter lock before waking the task
    /// (two-phase pattern to avoid lock-ordering violation with scheduler).
    pub fn complete_query(&mut self, query_id: u64) -> Option<TaskId> {
        for slot in self.pending.iter_mut() {
            if let Some(pq) = slot {
                if pq.query_id == query_id {
                    let task_id = pq.task_id;
                    *slot = None;
                    return Some(task_id);
                }
            }
        }
        None
    }

    /// Pending queries older than `timeout` ticks, left in the table:
    /// `(query_id, task_id)` pairs, up to `MAX_PENDING_QUERIES`. The
    /// caller wakes each task without this lock held and then calls
    /// `remove_query` for the ones it managed to wake; the rest are
    /// reported again next tick.
    pub fn expired_queries(
        &self,
        current_tick: u64,
        timeout: u64,
    ) -> ([Option<(u64, TaskId)>; MAX_PENDING_QUERIES], usize) {
        let mut expired = [None; MAX_PENDING_QUERIES];
        let mut count = 0;
        for pq in self.pending.iter().flatten() {
            if current_tick.saturating_sub(pq.submitted_at) >= timeout && count < MAX_PENDING_QUERIES {
                expired[count] = Some((pq.query_id, pq.task_id));
                count += 1;
            }
        }
        (expired, count)
    }

    /// Remove a pending query by id without reporting its task.
    pub fn remove_query(&mut self, query_id: u64) {
        for slot in self.pending.iter_mut() {
            if matches!(slot, Some(pq) if pq.query_id == query_id) {
                *slot = None;
                return;
            }
        }
    }

    /// Find and remove all pending queries older than `timeout` ticks.
    /// Returns the TaskIds of expired queries (up to MAX_PENDING_QUERIES).
    ///
    /// The caller MUST drop the PolicyRouter lock before waking tasks.
    /// Kept for the unit tests; the ISR path uses `expired_queries` +
    /// `remove_query` so a task it cannot wake this tick stays pending.
    #[allow(dead_code)]
    pub fn expire_stale(
        &mut self,
        current_tick: u64,
        timeout: u64,
    ) -> ([Option<TaskId>; MAX_PENDING_QUERIES], usize) {
        let mut expired = [None; MAX_PENDING_QUERIES];
        let mut count = 0;
        for slot in self.pending.iter_mut() {
            if let Some(pq) = slot {
                if current_tick.saturating_sub(pq.submitted_at) >= timeout {
                    if count < MAX_PENDING_QUERIES {
                        expired[count] = Some(pq.task_id);
                        count += 1;
                    }
                    *slot = None;
                }
            }
        }
        (expired, count)
    }

    /// Number of currently pending queries.
    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.pending.iter().filter(|e| e.is_some()).count()
    }
}

// ============================================================================
// PolicyCache — per-CPU decision cache
// ============================================================================

/// A cached policy decision for a (process, syscall) pair.
#[derive(Debug, Clone, Copy)]
pub struct CacheEntry {
    pub process_slot: u32,
    pub syscall_num: u32,
    pub allowed: bool,
    pub inserted_at: u64,
}

/// Per-CPU policy decision cache. Avoids upcalls to the policy service in
/// the steady state — most syscalls are repeated patterns that hit the cache.
///
/// # Access pattern
///
/// Accessed only from the current CPU with interrupts disabled (same pattern
/// as `PER_CPU_AUDIT_BUFFER`). No lock needed.
///
/// # Verification properties
///
/// - `lookup` returns `None` if no entry matches or if the entry's TTL expired.
/// - `insert` overwrites the entry at the hash-indexed slot (open addressing).
/// - `invalidate_all` clears every slot.
pub struct PolicyCache {
    entries: [Option<CacheEntry>; POLICY_CACHE_SIZE],
}

impl Default for PolicyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyCache {
    pub const fn new() -> Self {
        Self {
            entries: [None; POLICY_CACHE_SIZE],
        }
    }

    /// Look up a cached decision for (process_slot, syscall_num).
    /// Returns `None` if not cached or if the entry expired.
    pub fn lookup(
        &self,
        process_slot: u32,
        syscall_num: u32,
        current_tick: u64,
        ttl: u64,
    ) -> Option<bool> {
        let idx = Self::index(process_slot, syscall_num);
        if let Some(entry) = &self.entries[idx] {
            if entry.process_slot == process_slot
                && entry.syscall_num == syscall_num
                && current_tick.saturating_sub(entry.inserted_at) < ttl
            {
                return Some(entry.allowed);
            }
        }
        None
    }

    /// Insert or update a cached decision.
    pub fn insert(
        &mut self,
        process_slot: u32,
        syscall_num: u32,
        allowed: bool,
        current_tick: u64,
    ) {
        let idx = Self::index(process_slot, syscall_num);
        self.entries[idx] = Some(CacheEntry {
            process_slot,
            syscall_num,
            allowed,
            inserted_at: current_tick,
        });
    }

    /// Clear all cached entries (used on cache invalidation).
    pub fn invalidate_all(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = None;
        }
    }

    /// Hash (process_slot, syscall_num) to a cache index.
    fn index(process_slot: u32, syscall_num: u32) -> usize {
        // Simple mixing hash — combine the two u32s and reduce mod cache size.
        // This is not cryptographic; it just needs to spread entries across slots.
        let h = (process_slot as usize).wrapping_mul(31)
            ^ (syscall_num as usize).wrapping_mul(127);
        h % POLICY_CACHE_SIZE
    }
}

/// Per-CPU policy cache wrapper with interior mutability.
///
/// Uses `UnsafeCell` because each CPU accesses only its own cache slot
/// (no concurrent access). Same pattern as `audit::buffer::StagingBuffer`.
pub struct PolicyCacheCell(UnsafeCell<PolicyCache>);

impl Default for PolicyCacheCell {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyCacheCell {
    pub const fn new() -> Self {
        Self(UnsafeCell::new(PolicyCache::new()))
    }

    /// Get a raw pointer to the inner cache.
    ///
    /// # Safety
    /// Caller must ensure exclusive per-CPU access (interrupts disabled
    /// or called only from the owning CPU's context). Dereference the
    /// pointer as shared (`&*`) for reads or mutable (`&mut *`) for writes.
    pub fn as_ptr(&self) -> *mut PolicyCache {
        self.0.get()
    }
}

// SAFETY: PolicyCacheCell contains only Copy types in an array of Option<CacheEntry>.
// Each CPU accesses only its own cell with interrupts disabled — no concurrent
// access. The `static` requires Sync, but the access pattern is strictly per-CPU.
unsafe impl Sync for PolicyCacheCell {}

// ============================================================================
// policy_check — called from syscall dispatcher (replaces on_syscall)
// ============================================================================

/// Top-level policy check called from the syscall dispatcher.
///
/// Replaces the old `IpcInterceptor::on_syscall()` path. Returns Allow/Deny
/// for the given (process, syscall) pair. May block the calling task if a
/// cache miss triggers an upcall to the user-space policy service.
///
/// # Fast-path bypasses (no locks)
///
/// - `POLICY_SERVICE_READY` is false → Allow. Structural: until the
///   policy service has registered its query endpoint the only user task
///   that has run is init, spawning it, and nothing can be asked (a query
///   sent earlier would be cleared by that registration — the nightly
///   boot-smoke's expired first query, 2026-10-30). The flag is never
///   cleared, so a policy service that later dies leaves enforcement on
///   (queries time out → Deny) until init restarts it.
/// - Caller is the policy service → Allow (reentrancy prevention)
/// - Caller is a kernel task (cr3 == 0) → Allow
///
/// # Fail closed
///
/// Pending table full and query queue full return
/// `Deny(SyscallNotPermitted)` at once. A response timeout re-submits
/// the query up to `POLICY_UPCALL_ATTEMPTS` times, then denies. The
/// dispatcher audits every Deny. None of these is cached — the next
/// call asks again.
///
/// # Cache path (per-CPU, interrupts disabled)
///
/// Checks `PER_CPU_POLICY_CACHE[cpu]` for a valid entry. If hit, returns
/// the cached decision without any IPC.
///
/// # Upcall path (cache miss)
///
/// Builds a PolicyQuery message, enqueues on endpoint 22, blocks the caller
/// with `BlockReason::PolicyWait(query_id)`, and yields. The policy service
/// responds on endpoint 23, which is intercepted in `handle_write` and wakes
/// the blocked task with the decision.
#[cfg(not(test))]
pub fn policy_check(
    process_id: ProcessId,
    task_id: TaskId,
    cr3: u64,
    syscall_num: u32,
) -> InterceptDecision {
    use crate::ipc::interceptor::DenyReason;
    use crate::scheduler::{BlockReason, Timer};
    use core::sync::atomic::Ordering;

    // --- Bypass checks (fast path, no locks) ---

    if !crate::POLICY_SERVICE_READY.load(Ordering::Acquire) {
        return InterceptDecision::Allow;
    }

    // Reentrancy prevention: the policy service's own syscalls skip the check
    if process_id.as_raw() == crate::POLICY_SERVICE_PID.load(Ordering::Acquire) {
        return InterceptDecision::Allow;
    }

    // Kernel tasks (cr3 == 0, no user address space) bypass policy
    if cr3 == 0 {
        return InterceptDecision::Allow;
    }

    // --- Per-CPU cache lookup (interrupts disabled for per-CPU access) ---

    let current_tick = Timer::get_ticks();

    // Read current CPU ID
    #[cfg(target_arch = "x86_64")]
    // SAFETY: GS base initialized after boot; cpu_id is a pure read.
    let cpu_id = unsafe { crate::arch::x86_64::percpu::current_cpu_id() } as usize;
    #[cfg(target_arch = "aarch64")]
    // SAFETY: TPIDR_EL1 initialized after boot; cpu_id is a pure read.
    let cpu_id = unsafe { crate::arch::aarch64::percpu::current_percpu().cpu_id() } as usize;
    #[cfg(target_arch = "riscv64")]
    // SAFETY: `tp` initialized after boot; cpu_id is a pure read.
    let cpu_id = unsafe { crate::arch::riscv64::percpu::current_percpu().cpu_id() } as usize;

    // Check cache (entries are per-CPU, accessed only from current CPU)
    // SAFETY: per-CPU access — we are running on this CPU. No concurrent
    // reader or writer can access this CPU's cache slot.
    if let Some(allowed) = unsafe { &*crate::PER_CPU_POLICY_CACHE[cpu_id].as_ptr() }.lookup(
        process_id.slot(),
        syscall_num,
        current_tick,
        POLICY_TTL_TICKS,
    ) {
        return if allowed {
            InterceptDecision::Allow
        } else {
            InterceptDecision::Deny(DenyReason::SyscallNotPermitted)
        };
    }

    // --- Cache miss: upcall to policy service ---

    // Look up caller's Principal (for the query message)
    let principal_bytes = {
        let cap_guard = crate::CAPABILITY_MANAGER.lock();
        if let Some(ref cap_mgr) = *cap_guard {
            if let Ok(p) = cap_mgr.get_principal(process_id) {
                *p.aid()
            } else {
                [0u8; 32]
            }
        } else {
            [0u8; 32]
        }
    };
    // CAPABILITY_MANAGER lock dropped

    // Upcall, with a bounded retry on expiry. Each attempt submits a
    // fresh query; a late answer to an earlier one finds its entry gone
    // (`complete_query` → None) and is dropped, never misattributed.
    let mut attempt: u32 = 0;
    let allowed = loop {
        // Allocate a pending-query slot
        let query_id = {
            let mut router = crate::POLICY_ROUTER.lock();
            match router.submit_query(task_id, Timer::get_ticks()) {
                Some(qid) => qid,
                None => {
                    // Pending table full — no way to ask, so no permission.
                    return InterceptDecision::Deny(DenyReason::SyscallNotPermitted);
                }
            }
        };
        POLICY_QUERIES_SUBMITTED.fetch_add(1, Ordering::Relaxed);
        // POLICY_ROUTER lock dropped

        // Build and send query message
        let msg = build_query_message(query_id, process_id, syscall_num, &principal_bytes);
        if crate::SHARDED_IPC
            .send_message(EndpointId(POLICY_QUERY_ENDPOINT), msg)
            .is_err()
        {
            // Queue full — withdraw the pending query; no decision, no permission.
            let mut router = crate::POLICY_ROUTER.lock();
            router.complete_query(query_id);
            return InterceptDecision::Deny(DenyReason::SyscallNotPermitted);
        }

        // Wake the policy service if it's blocked waiting for queries.
        // Plain-lock all-CPU wake: the prior try_lock loop could silently
        // skip a contended scheduler, losing the wake (see
        // wake_message_waiters_all_cpus). Syscall context — no lock held.
        crate::wake_message_waiters_all_cpus(POLICY_QUERY_ENDPOINT);

        // Block and yield — unless the answer has already landed.
        //
        // The decision check and the block are ONE critical section under
        // this CPU's scheduler lock (CLAUDE.md Blocking pattern: a condition
        // another CPU signals must be re-checked atomically with
        // block_task). The responder stores the decision and then takes this
        // same lock to wake us; if it ran between our send and our block,
        // its wake found us Running and did nothing — and complete_query had
        // already removed the query, so the expiry sweep could never rescue
        // us. Init slept forever in PolicyWait on the first boot that
        // delivered an answer (QEMU, two CPUs, 2026-10-27).
        //
        // CRITICAL: interrupts off BEFORE block_task, or the timer ISR can
        // see Blocked state before yield saves the correct context (see
        // handle_recv_msg). The IrqSpinlock restores the flags it saved, so
        // taking it after the disable keeps them off through the yield.
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Disabling interrupts is safe at kernel privilege level.
        unsafe {
            core::arch::asm!("cli", options(nomem, nostack));
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: Masking IRQs is safe at EL1.
        unsafe {
            core::arch::asm!("msr daifset, #2", options(nomem, nostack));
        }
        #[cfg(target_arch = "riscv64")]
        // SAFETY: `csrci sstatus, 2` clears SIE at S-mode; same contract as
        // the dispatcher's blocking sites.
        unsafe {
            core::arch::asm!("csrci sstatus, 2", options(nomem, nostack));
        }
        let blocked = {
            let mut guard = crate::local_scheduler().lock();
            if POLICY_DECISIONS[task_id.slot() as usize].load(Ordering::Acquire) == DECISION_NONE {
                match guard.as_mut() {
                    Some(sched) => sched.block_task(task_id, BlockReason::PolicyWait(query_id)).is_ok(),
                    None => false,
                }
            } else {
                false
            }
        };
        if blocked {
            // SAFETY: We are on the kernel stack, no locks held.
            unsafe {
                crate::arch::yield_save_and_switch();
            }
        } else {
            // The decision beat us to the block: no yield, so restore the
            // interrupt state the syscall path runs with.
            #[cfg(target_arch = "x86_64")]
            // SAFETY: Re-enabling interrupts is safe at kernel privilege level.
            unsafe {
                core::arch::asm!("sti", options(nomem, nostack));
            }
            #[cfg(target_arch = "aarch64")]
            // SAFETY: Unmasking IRQs is safe at EL1.
            unsafe {
                core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
            }
            #[cfg(target_arch = "riscv64")]
            // SAFETY: `csrsi sstatus, 2` sets SIE at S-mode.
            unsafe {
                core::arch::asm!("csrsi sstatus, 2", options(nomem, nostack));
            }
        }

        // --- Woken: read decision from POLICY_DECISIONS ---

        let decision_val = POLICY_DECISIONS[task_id.slot() as usize].swap(DECISION_NONE, Ordering::Acquire);
        let allowed = match decision_val {
            DECISION_ALLOW => true,
            DECISION_DENY => false,
            _ => {
                // Expired (or no decision at all): the policy service did
                // not answer in time. Re-submit up to the bound; then deny
                // without caching, so a recovered or restarted policy
                // service is consulted next time and a dead one keeps
                // denying instead of being promoted to permission.
                attempt += 1;
                if attempt < POLICY_UPCALL_ATTEMPTS {
                    POLICY_QUERIES_RETRIED.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                return InterceptDecision::Deny(DenyReason::SyscallNotPermitted);
            }
        };
        break allowed;
    };

    // Cache the answered result
    #[cfg(target_arch = "x86_64")]
    // SAFETY: per-CPU read — we're running on this CPU after wake.
    let wake_cpu = unsafe { crate::arch::x86_64::percpu::current_cpu_id() } as usize;
    #[cfg(target_arch = "aarch64")]
    // SAFETY: per-CPU read — we're running on this CPU after wake.
    let wake_cpu = unsafe { crate::arch::aarch64::percpu::current_percpu().cpu_id() } as usize;
    #[cfg(target_arch = "riscv64")]
    // SAFETY: per-CPU read — we're running on this CPU after wake.
    let wake_cpu = unsafe { crate::arch::riscv64::percpu::current_percpu().cpu_id() } as usize;

    // SAFETY: per-CPU access — we are running on this CPU after wake.
    // No concurrent reader or writer can access this CPU's cache slot.
    let cache = unsafe { &mut *crate::PER_CPU_POLICY_CACHE[wake_cpu].as_ptr() };
    cache.insert(process_id.slot(), syscall_num, allowed, Timer::get_ticks());

    if allowed {
        InterceptDecision::Allow
    } else {
        InterceptDecision::Deny(DenyReason::SyscallNotPermitted)
    }
}

/// Test stub — policy_check always returns Allow in test mode.
#[cfg(test)]
pub fn policy_check(
    _process_id: ProcessId,
    _task_id: TaskId,
    _cr3: u64,
    _syscall_num: u32,
) -> InterceptDecision {
    InterceptDecision::Allow
}

// ============================================================================
// expire_pending_queries — called from timer ISR
// ============================================================================

/// Expire stale pending policy queries and wake their blocked tasks; the
/// woken task finds no decision and denies (fail closed, uncached).
///
/// Called from the BSP timer ISR (100 Hz). Uses `try_lock` to avoid blocking
/// the ISR if the PolicyRouter lock is contended.
#[cfg(not(test))]
pub fn expire_pending_queries() {
    use crate::scheduler::Timer;
    use core::sync::atomic::Ordering;

    let current_tick = Timer::get_ticks();

    // Step 1: list expired queries under the PolicyRouter lock, leaving
    // them in the table.
    let (expired, count) = {
        let guard = match crate::POLICY_ROUTER.try_lock() {
            Some(g) => g,
            None => return, // Lock contended — skip this tick
        };
        guard.expired_queries(current_tick, POLICY_TIMEOUT_TICKS)
    };
    // PolicyRouter lock dropped here

    // Step 2: wake each waiter with a try_lock on its CPU's scheduler.
    // Selective: only a task actually Blocked on THIS query is woken,
    // its decision slot marked expired first under the same lock. A task
    // that submitted the query but has not blocked yet is left for the
    // next tick (it checks the slot atomically with its block, so the
    // slot must not be written out from under a later query).
    // This runs in the timer ISR: a blocking cross-CPU scheduler lock
    // here deadlocked against a CPU that held its own scheduler lock
    // while waiting for a lock this CPU's interrupted syscall held
    // (QEMU, six CPUs, 2026-10-27 — the shape became reachable once
    // spawn-time placement spread tasks across CPUs). A task whose CPU
    // is busy stays in the table and is retried next tick; a task
    // already Ready is a harmless no-op wake.
    for entry in expired.iter().take(count) {
        if let Some((qid, tid)) = *entry {
            let woke = crate::try_wake_policy_waiter(tid, qid, || {
                POLICY_DECISIONS[tid.slot() as usize].store(DECISION_EXPIRED, Ordering::Release);
            });
            if woke {
                // Forensics for the first few expiries: an expiry means the
                // policy service did not answer within the timeout, and the
                // useful question is what it was doing — Blocked (on what?),
                // Ready but not running (its CPU busy with whom?), or
                // Running (slow). Read under try_lock from the ISR; a
                // contended scheduler prints "?" rather than waiting.
                let n = EXPIRY_FORENSICS_PRINTED.fetch_add(1, Ordering::Relaxed);
                if n < EXPIRY_FORENSICS_MAX {
                    let raw = crate::POLICY_SERVICE_TASK.load(Ordering::Acquire);
                    let snap = if raw == u64::MAX {
                        None
                    } else {
                        crate::try_task_snapshot(TaskId::from_raw(raw))
                    };
                    match snap {
                        Some(sn) => {
                            crate::io::try_print(format_args!(
                                "[policy] expiry #{}: query {} from task {}; policy service {:?} reason {:?} on cpu {} (running there: {:?})\n",
                                n + 1, qid, tid.slot(), sn.state, sn.block_reason, sn.cpu,
                                sn.current_on_cpu.map(|t| t.slot()),
                            ));
                        }
                        None => {
                            crate::io::try_print(format_args!(
                                "[policy] expiry #{}: query {} from task {}; policy service state unavailable (lock held or task unknown)\n",
                                n + 1, qid, tid.slot(),
                            ));
                        }
                    }
                }
                POLICY_QUERIES_EXPIRED.fetch_add(1, Ordering::Relaxed);
                if let Some(mut guard) = crate::POLICY_ROUTER.try_lock() {
                    guard.remove_query(qid);
                }
                // A contended router lock leaves the entry for next tick:
                // the extra wake it will produce finds a Ready task and
                // does nothing.
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- PolicyRouter tests ---

    #[test]
    fn test_router_submit_and_complete() {
        let mut router = PolicyRouter::new();
        let qid = router.submit_query(TaskId::new(5, 0), 100).unwrap();
        assert_eq!(qid, 1);
        assert_eq!(router.pending_count(), 1);

        let tid = router.complete_query(qid);
        assert_eq!(tid, Some(TaskId::new(5, 0)));
        assert_eq!(router.pending_count(), 0);
    }

    #[test]
    fn test_router_complete_unknown_returns_none() {
        let mut router = PolicyRouter::new();
        assert_eq!(router.complete_query(999), None);
    }

    #[test]
    fn test_router_monotonic_query_ids() {
        let mut router = PolicyRouter::new();
        let q1 = router.submit_query(TaskId::new(1, 0), 0).unwrap();
        let q2 = router.submit_query(TaskId::new(2, 0), 0).unwrap();
        let q3 = router.submit_query(TaskId::new(3, 0), 0).unwrap();
        assert!(q1 < q2);
        assert!(q2 < q3);
    }

    #[test]
    fn test_router_capacity_full() {
        let mut router = PolicyRouter::new();
        for i in 0..MAX_PENDING_QUERIES as u32 {
            assert!(router.submit_query(TaskId::new(i, 0), 0).is_some());
        }
        // Table is full — next submit fails
        assert!(router.submit_query(TaskId::new(99, 0), 0).is_none());
    }

    #[test]
    fn test_router_slot_reuse_after_complete() {
        let mut router = PolicyRouter::new();
        // Fill the table
        let mut qids = [0u64; MAX_PENDING_QUERIES];
        for i in 0..MAX_PENDING_QUERIES {
            qids[i] = router.submit_query(TaskId::new(i as u32, 0), 0).unwrap();
        }
        // Full
        assert!(router.submit_query(TaskId::new(99, 0), 0).is_none());

        // Complete one — frees a slot
        router.complete_query(qids[0]);
        assert!(router.submit_query(TaskId::new(99, 0), 0).is_some());
    }

    #[test]
    fn test_router_expire_stale() {
        let mut router = PolicyRouter::new();
        let _q1 = router.submit_query(TaskId::new(1, 0), 10).unwrap();
        let _q2 = router.submit_query(TaskId::new(2, 0), 90).unwrap();
        let _q3 = router.submit_query(TaskId::new(3, 0), 250).unwrap();

        // Expire at tick 150 with timeout 100 — q1 (submitted at 10, age 140) is stale;
        // q2 (submitted at 90, age 60) and q3 (submitted at 250, future) are not.
        let (expired, count) = router.expire_stale(150, 100);
        assert_eq!(count, 1);
        assert_eq!(expired[0], Some(TaskId::new(1, 0)));
        assert_eq!(router.pending_count(), 2);

        // Expire at tick 300 — q2 (submitted at 90, age 210) is now stale
        let (expired, count) = router.expire_stale(300, 100);
        assert_eq!(count, 1);
        assert_eq!(expired[0], Some(TaskId::new(2, 0)));
        assert_eq!(router.pending_count(), 1);
    }

    #[test]
    fn test_router_expire_none_stale() {
        let mut router = PolicyRouter::new();
        let _q1 = router.submit_query(TaskId::new(1, 0), 100).unwrap();

        // Check at tick 150 with timeout 100 — not yet expired
        let (_, count) = router.expire_stale(150, 100);
        assert_eq!(count, 0);
        assert_eq!(router.pending_count(), 1);
    }

    // --- PolicyCache tests ---

    #[test]
    fn test_cache_hit_within_ttl() {
        let mut cache = PolicyCache::new();
        cache.insert(3, 7, true, 100);
        assert_eq!(cache.lookup(3, 7, 150, 100), Some(true));
    }

    #[test]
    fn test_cache_miss_after_ttl() {
        let mut cache = PolicyCache::new();
        cache.insert(3, 7, true, 100);
        // At tick 250 with TTL 100 — expired (250 - 100 = 150 >= 100)
        assert_eq!(cache.lookup(3, 7, 250, 100), None);
    }

    #[test]
    fn test_cache_miss_wrong_process() {
        let mut cache = PolicyCache::new();
        cache.insert(3, 7, true, 100);
        assert_eq!(cache.lookup(4, 7, 150, 100), None);
    }

    #[test]
    fn test_cache_miss_wrong_syscall() {
        let mut cache = PolicyCache::new();
        cache.insert(3, 7, true, 100);
        assert_eq!(cache.lookup(3, 8, 150, 100), None);
    }

    #[test]
    fn test_cache_deny_decision() {
        let mut cache = PolicyCache::new();
        cache.insert(5, 20, false, 100);
        assert_eq!(cache.lookup(5, 20, 150, 100), Some(false));
    }

    #[test]
    fn test_cache_overwrite_same_key() {
        let mut cache = PolicyCache::new();
        cache.insert(3, 7, true, 100);
        cache.insert(3, 7, false, 200);
        assert_eq!(cache.lookup(3, 7, 250, 100), Some(false));
    }

    #[test]
    fn test_cache_invalidate_all() {
        let mut cache = PolicyCache::new();
        cache.insert(1, 1, true, 100);
        cache.insert(2, 2, false, 100);
        cache.invalidate_all();
        assert_eq!(cache.lookup(1, 1, 150, 100), None);
        assert_eq!(cache.lookup(2, 2, 150, 100), None);
    }

    // --- Wire format tests ---

    #[test]
    fn test_build_query_message() {
        let principal = [0xABu8; 32];
        let msg = build_query_message(42, ProcessId::new(5, 0), 7, &principal);
        let p = msg.payload();
        assert_eq!(p.len(), 48);
        assert_eq!(u64::from_le_bytes(p[0..8].try_into().unwrap()), 42);
        assert_eq!(u32::from_le_bytes(p[8..12].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(p[12..16].try_into().unwrap()), 7);
        assert_eq!(&p[16..48], &[0xAB; 32]);
        assert_eq!(msg.from, EndpointId(POLICY_RESP_ENDPOINT));
        assert_eq!(msg.to, EndpointId(POLICY_QUERY_ENDPOINT));
    }

    #[test]
    fn test_parse_response_allow() {
        let mut payload = [0u8; 9];
        payload[0..8].copy_from_slice(&42u64.to_le_bytes());
        payload[8] = 0; // Allow
        let (qid, allowed) = parse_response(&payload).unwrap();
        assert_eq!(qid, 42);
        assert!(allowed);
    }

    #[test]
    fn test_parse_response_deny() {
        let mut payload = [0u8; 9];
        payload[0..8].copy_from_slice(&99u64.to_le_bytes());
        payload[8] = 1; // Deny
        let (qid, allowed) = parse_response(&payload).unwrap();
        assert_eq!(qid, 99);
        assert!(!allowed);
    }

    #[test]
    fn test_parse_response_too_short() {
        assert!(parse_response(&[0u8; 8]).is_none());
        assert!(parse_response(&[]).is_none());
    }
}
