# ADR-034: Deferred Reclamation of a Terminating Task's Self-Referential Resources

- **Status:** Accepted
- **Date:** 2026-06-03
- **Depends on:** [ADR-001](001-smp-scheduling-and-lock-hierarchy.md) (per-CPU scheduler, lock hierarchy), [ADR-008](008-boot-time-sized-object-tables.md) (per-process page tables + 4 MiB heaps, ProcessId generation counters)
- **Related:** [ADR-019](019-process-fault-reaping-and-peer-generation.md) (fault reaping — its fault path reuses this substrate; its deferred-queue rejection is reconciled below), [ADR-013](013-riscv64-architecture-support.md) (the riscv C1/H1 fold-ins live in its subsystem)
- **Supersedes:** N/A

## Scope Boundary (read this first)

This ADR defines how the kernel frees the resources a terminating task **cannot reclaim from its own running context** — the page-table root it executes through (CR3/satp/TTBR0), the kernel stack it stands on (RSP/SP), and the task slot/TCB it *is*. Everything else a dying task owns — capabilities, channels, clusters, VMA frames, the 4 MiB heap — continues to be reclaimed **inline** in the death path, unchanged. Only the irreducibly self-referential set is deferred.

| Concern | Owner |
|---|---|
| Reclaim caps / channels / clusters / VMAs / heap on death | **Inline death path** (handle_exit / fault reaper) — unchanged |
| Free the page-table root the CPU runs through | **This ADR (deferred reaper)** |
| Free the kernel stack the CPU stands on | **This ADR (deferred reaper)** |
| Free + recycle the task slot/TCB | **This ADR (deferred reaper)** |
| Guarantee no CPU is on a dead address space before it's freed | **This ADR (occupancy invariant + canonical kernel root)** |
| *Whether/when* to restart a dead service | [ADR-018](018-init-process-and-boot-manifest.md) (init, policy) |
| Distinguishing fault-kill from clean exit; peer-generation; *who triggers* the reap | [ADR-019](019-process-fault-reaping-and-peer-generation.md) |

## Context

A task dies by clean exit (`SYS_EXIT` → `handle_exit` → `ProcessTable::destroy_process`) or by fault ([ADR-019](019-process-fault-reaping-and-peer-generation.md), Proposed). Both run **in the dying task's own context** — a syscall or a fault taken while that task is current — so its page-table root is still loaded and its kernel stack is still in use. Today `destroy_process` reclaims everything inline, including the page-table root, which is the bug.

**Confirmed triple-fault (x86_64).** `reclaim_process_page_tables(desc.cr3, …)` runs at [dispatcher.rs:529](../../src/syscalls/dispatcher.rs#L529) while `CR3 == desc.cr3`, before the terminal yield at :557. `frame_alloc.free` zero-fills (zero-on-free, commit 318c1cd) the live PML4, unmapping the whole address space; the next TLB miss faults on an unmapped #PF handler → #DF → triple fault. A boot-time probe confirmed it directly (`RECLAIM-FREES-KERNEL-PT PML4=… is live active-PML4`) after first confirming every *static* kernel page-table frame was correctly reserved. Latent before zero-on-free (the freed frame kept valid bytes until reused); zero-on-free made it fatal.

**Kernel-stack leak (known).** STATUS.md: the 32 KiB kernel stack per task is never freed — *"can't free the stack you're running on. Requires scheduler-level deferred-dealloc."* Same root cause.

**Task-slot leak (HV1, correctness review 2026-06-03).** `purge_task` documents *"slot reuse is handled elsewhere"* — there is no elsewhere; `handle_exit` ends in `loop { yield }`. Every exit permanently consumes a per-CPU `MAX_TASKS` slot. Same root cause; and closing it **unmasks a latent UAF** (see Decision §4).

These are one problem: a task freeing resources it is actively using. They want one mechanism.

## Problem

Free the active page-table root (+ its intermediate frames), the active kernel stack, and the task slot **safely and SMP-correctly**, while: keeping bulk reclamation inline (per [ADR-019](019-process-fault-reaping-and-peer-generation.md)); never holding `SCHEDULER(1)` while taking `FRAME_ALLOCATOR(8)`; and never freeing a root/stack/slot any CPU is still using — **including** when the thread model later makes one address space resident on several CPUs at once (a non-negotiable v1 feature).

## Decision

### 1. The N-CPU address-space reclamation invariant (the load-bearing decision)

A process address space (PML4 / satp L0 / TTBR0 L0 root) is a refcounted, occupancy-tracked object. It is freed **only** when it is **(a) logically dead** — the owning process is Terminated and removed from every CPU's ready structures under `SCHEDULER(1)` *before* the address space is enqueued for reaping — **and (b) at zero CPU-occupancy**, where occupancy covers **two** reference classes:

1. **Hardware-root references** — no CPU's CR3/satp/TTBR0 register equals the root's physical address.
2. **HHDM-by-physical-address references** — no CPU is mid-walk of the root's frames via `page_table_from_cr3` during a peer/channel-teardown read. This class is **serialized by `FRAME_ALLOCATOR(8)`**: the reaper takes it to free, and every peer-table-by-phys walker holds it across the walk, so a free cannot interleave a walk.

The predicate **"free iff (logically-dead ∧ zero-occupancy)"** does not change when the thread model lands. Only the *occupancy source* changes: class (1), today structurally 0-after-yield (see §2), becomes a real `cpu_refs` atomic incremented/decremented at context switch. The **memory ordering** that is vacuous today becomes load-bearing then and is reserved now: (i) set dead-flag; (ii) schedule-onto-shared-AS does increment-then-recheck-dead (back off + decrement if already dead); (iii) switch-off performs the hardware root reload **then** release-decrements `cpu_refs`; (iv) the reaper frees only on an acquire-read of `(dead ∧ cpu_refs == 0)`. The "invariant does not change" claim is true for the predicate and the occupancy concept; it is the *ordering* that is the new post-threads content.

### 2. Canonical kernel root; the structural discharge today

`kernel_cr3()` returns the boot page-table root, wired at boot via `set_kernel_cr3` on every arch (x86_64 CR3 / aarch64 TTBR1 / riscv satp — the riscv wiring landed in Phase 0). The portable scheduler substitutes `kernel_cr3()` as the switch hint for kernel/idle tasks (`cr3 == 0`), so **every** context switch reloads the root. Therefore, in today's one-task-per-process model, the instant the owning task yields, no CPU is on its root — occupancy class (1) is structurally 0, with **no atomic on the hot path**. The `cpu_refs` atomic (§1) is the explicit discharge reserved for when one address space can be resident on multiple CPUs; we do not build it before the thread model, but the invariant and the reaper's free-condition are already written in occupancy terms so neither is torn down when it arrives.

### 3. Defer only the self-referential set; reap from a clean context

The death path reclaims caps/channels/clusters/VMAs/heap **inline, unchanged**. For the self-referential set it instead **captures, by value, at hand-off time** `{ root_phys, kernel_stack region, (cpu, slot) }` — never by re-resolving `desc.cr3` or `task.process_id` later, since the inline ProcessId generation bump may have invalidated/reused those ids — marks the task Terminated, enqueues, and yields.

**Per-CPU reapers.** A **per-CPU idle-loop reaper** (`reaper::drain_local`, run from each CPU's idle loop — *the vehicle diverged from the originally-specified dedicated task; see Divergence*) drains its CPU's bounded pending-reclaim queue in **normal context** (interrupts enabled, `SCHEDULER` not held). Per-CPU is deliberate: a dying task's slot lives in *its own* CPU's `PER_CPU_SCHEDULER`, so a same-CPU reaper frees it **locally** — no foreign-CPU `SCHEDULER` acquisition, which dissolves the cross-CPU-scheduler deadlock surface entirely. Frame frees go to the global `FRAME_ALLOCATOR`. The reaper frees, **by the values captured at hand-off**: the root + its intermediate frames (`reclaim_process_page_tables`, now operating on a non-active root), the kernel stack, and the local `(cpu, slot)` TCB. The three resources have **distinct lifetimes** and are freed independently: the root once occupancy is 0; the stack once no CPU's RSP/SP is within it; the slot as soon as it is drained (`Scheduler::reap_slot`) — its exit status was latched into the `TaskExitRing` at exit time (§4) so it is never pinned by a waiter; `reap_slot` frees it only if the slot still holds that exact `(slot, generation)` Terminated task (guarding double-drain or a slot already reused) and bumps the slot's generation under the same `SCHEDULER` lock so no `create_*_task` can grab it with the stale generation. *(Global-reaper-with-ascending-CPU-index is the fallback if per-CPU reapers prove too heavy; it reintroduces the foreign-`SCHEDULER` surface and must then follow the existing `migrate_task` ascending-index protocol.)*

**Enqueue-once.** Only the context that wins the `Running → Terminated` transition (published under `SCHEDULER(1)`) enqueues the self-referential set. A second enqueue — double-exit, or an [ADR-019](019-process-fault-reaping-and-peer-generation.md) fault racing a clean exit — would double-free the root/stack. The frame allocator's `is_set` pre-pass turns most double-frees into a typed `DoubleFree` (no corruption), but a free-then-realloc-then-free window is real, so single-enqueue is gated on the state transition, not left to the allocator to catch.

**Lock discipline.** `PER_CPU_RECLAIM_QUEUE[cpu]` is an **independent, non-nested per-CPU lock in the "Additional lock domains" class** (exactly like `PER_CPU_FRAME_CACHE`): acquired and released *in isolation*, never held while any hierarchy lock is held and vice-versa. The death path captures the set under `PROCESS_TABLE(7)`/`FRAME_ALLOCATOR(8)`, **releases them**, then pushes under the queue lock alone. The reaper pops under the queue lock alone, **releases it**, then takes `FRAME_ALLOCATOR(8)` for the frame frees and its own `SCHEDULER(1)` for the local slot free — sequentially, never nested, and if ever nested `SCHEDULER(1)` **before** `FRAME_ALLOCATOR(8)` (downward, valid). No path holds the queue lock together with any hierarchy lock; per-CPU isolation removes cross-CPU queue contention too.

**Wake discipline.** The death path **must not** wake the reaper while `PROCESS_TABLE`/`FRAME_ALLOCATOR` is held: waking takes `SCHEDULER(1)`, an acquire-lower-while-holding-higher inversion (the silent same-CPU hang). Preferred form is **no wake-on-enqueue at all** — the reaper polls each scheduler pass, and the dying task's terminal yield ([dispatcher.rs:557](../../src/syscalls/dispatcher.rs#L557)) is the natural reschedule point. The ISR / post-switch `try_lock` drain is **forbidden** in writing (cf. the H7 precedent: blocking locks taken from the BSP timer ISR deadlock).

**Release-build guard (not just `debug_assert`).** At the top of `reclaim_process_page_tables`, on every arch: `if active_root() == root_phys { audit::emit(ReapWouldFreeActiveRoot); return Err(WouldFreeActiveRoot) }` — in **both** profiles. `reclaim` is rare and already expensive (teardown), so the `Cr3::read` / satp / TTBR0 read is invisible cost, and it converts the release-build silent-corruption gap into a typed, audited refusal. A `debug_assert!` on top gives dev fast-fail. The check is the active-root witness **only**: it does *not* catch the riscv C1 class (a freed *intermediate* kernel table, not the active root — closed separately in Phase 0).

**The reaper is critical infrastructure.** It performs raw frame frees and gates all reclamation; a faulting reaper stalls every subsequent exit (via backpressure) system-wide. It must be the most `Result`-disciplined, panic-free code in the kernel — treated like the scheduler, not like a service.

**Peer-walk serialization (occupancy class 2).** Every peer-table-by-physical-address walker (`page_table_from_cr3` in a peer/channel-teardown read) **must hold `FRAME_ALLOCATOR(8)` across the walk**, since that is what excludes the reaper's free. This is load-bearing on SMP *today* (one CPU may peer-walk another's tables while that process exits), not only post-threads. Phase A **audits the current walkers** to confirm all comply; a Convention-9 trigger (second by-phys walker, or the thread model) promotes the convention to a type — a guard token on the walk API, encoding the invariant in the type rather than a comment.

### 4. Task slot is `(cpu, slot, generation)`; exit status is latched, not pinned

Closing the slot leak unmasks a UAF: `handle_wait_task` reads child `exit_code` post-yield by **bare slot index** with no generation, so a reaped+reused slot returns a different task's status. Resolution, all landing together (Phase B):

- Add a **TaskId generation counter** mirroring `ProcessId` (bumped on every slot free/reuse). Bare-`u32` `TaskId` + index-only `get_task_pub` cannot detect reuse.
- Latch `(slot, generation, exit_code)` into a bounded **`TaskExitRing`** under the same `SCHEDULER(1)` section that sets Terminated, so the reaper frees the TCB unconditionally (pinning until the parent reads reintroduces the leak for fork-and-forget / parent-exits-first — the shell+games common case). `WaitTask` reads from the ring keyed by `(TaskId, generation)`, returning a typed not-found on age-out (the `RecentExitsRing` / `SYS_GET_PROCESS_PRINCIPAL`-after-exit pattern, applied to task exit codes).
- **Co-fix H5:** `handle_wait_task` sets `Blocked` without cli-before-block ([dispatcher.rs:2503](../../src/syscalls/dispatcher.rs#L2503)); a prompt reaper widens the lost-wake window into "blocks forever holding an unreapable slot." Route through `block_task()` / disable interrupts before the Blocked write through the yield.
- The reaper frees the slot **locally** — the dying task enqueued to its own CPU's queue and a Terminated+purged task cannot migrate, so the slot lives on the reaper's CPU (no foreign-`SCHEDULER` acquisition, consistent with §3; *this corrects the originally-specified cross-CPU slot free — see Divergence*). `WaitTask` **does** resolve the child cross-CPU, but only for a *live* child the load balancer may have moved: `task_parent_and_state` reads `(parent, state)` via `PER_CPU_SCHEDULER[child_cpu]` through `TASK_CPU_MAP` (with a bounded retry across one in-flight migration) to authorize and decide whether to block. The exit *code* itself is read from the CPU-agnostic global `TaskExitRing` keyed by `(slot, generation)`, not from a per-CPU slot, so a child that exited on any CPU — including after its slot was reaped — is collected correctly.
- Preserve the exit-time record ordering (Principal → `RecentExitsRing` *before* the generation bump) so [ADR-019](019-process-fault-reaping-and-peer-generation.md) peer-generation and `SYS_GET_PROCESS_PRINCIPAL`-after-exit stay correct. The reaper writes **no** records, only frees captured resources.

### 5. Bounded queue — overflow is structurally impossible

Size each `PER_CPU_RECLAIM_QUEUE` for the per-CPU worst case (concurrent Terminated-but-unreaped tasks on that CPU ≤ its `MAX_TASKS`), Convention-8 tagged with an ASSUMPTIONS.md row. The full-queue contract is **backpressure**: the death path may **not** panic, block on a hierarchy lock, or free inline; on a full queue it spins on its own terminal yield to let the local reaper drain, then retries the enqueue (returning `Result`). So "the reaper is too slow" can never overflow the queue or lose reclamation — it degrades only to **bounded exit latency**. If that latency ever mattered, the levers, in order: **drain-all-per-pass** (one reaper wake empties the queue, absorbing a burst); the per-CPU reaper count (already the topology); and only as a blunt last resort, tick-rate (global scheduling overhead for a reaper-local problem).

## Per-arch disposition

| Arch | Active-root self-free | Canonical kernel root | riscv-only guards | Net |
|---|---|---|---|---|
| **x86_64** | **real** (the confirmed triple-fault) | already wired (`set_kernel_cr3` @ main.rs:330) | n/a | **Piece 3 deferral only** |
| **aarch64** | **absent** — TTBR0/TTBR1 split; user L0 upper half is always zero, kernel resolves via TTBR1 | already wired (TTBR1 @ main.rs:337) | n/a | deferral applies; record the **kernel-half-zero invariant** |
| **riscv64** | **real** (single satp carries the kernel half) | **wired in Phase 0** (H1) | **C1 walk-guard, Phase 0** | Phase 0 (done) + Piece 3 deferral |

**Recorded aarch64 invariant:** aarch64 user L0 must never carry kernel-half entries — the active-free brick returns the day a "unification" copies them. Needs a compile/boot assertion (open problem).

## Alternatives considered

- **Localized CR3-switch stopgap** (switch CR3 to the kernel root before the inline free). **Why not:** fixes only the page-table root, leaving the kernel-stack and slot leaks — two mechanisms for one root cause (the sawtooth). Its *action* is subsumed by §2; its *assert* is kept as the §3 guard.
- **Defer *bulk* reclamation to a scheduler-lock path** (the [ADR-019](019-process-fault-reaping-and-peer-generation.md) §"Why not" rejection). **Why not:** that path needs `CAPABILITY_MANAGER(4)…FRAME_ALLOCATOR(8)` and forces inversion/queues. **This ADR does not do that** — bulk reclaim stays inline; only the irreducible self-referential set is deferred, via a lock-isolated queue. ADR-019's rejection stands; this is a different, narrower deferral.
- **Full `cpu_refs` atomic now** (incremented every context switch). **Why not:** today redundant (§2 gives occupancy-0 structurally) and a hot-path atomic whose increment semantics would be guessed against a thread model that does not exist — building before the consumer. The invariant is N-shaped now; the atomic lands with its first real consumer.
- **Post-switch / ISR `try_lock` drain** (no reaper task). **Why not:** runs interrupts-disabled in ISR-adjacent context; taking `FRAME_ALLOCATOR` there is the blocking-lock-in-ISR hazard (H7). Kept only as a fallback if reaper latency ever proves unacceptable.

## Consequences

- Fixes the clean-exit triple-fault (x86_64 + riscv64).
- Closes the kernel-stack leak (STATUS.md) and the task-slot leak (HV1) in the same mechanism.
- Unblocks [ADR-019](019-process-fault-reaping-and-peer-generation.md): its fault reaper reuses the pending-reclaim queue for the self-referential set.
- Cost: per-CPU reaper tasks + a bounded per-CPU queue; bounded reclaim latency for the deferred set (the heap/caps/etc. are already freed inline). No new hierarchy lock; `PER_CPU_RECLAIM_QUEUE` is lock-isolated. One extra CR3/satp reload on switch-to-kernel-task where previously skipped — negligible.
- N-CPU-correct by construction; the thread model adds the `cpu_refs` atomic + a TLB shootdown-before-free, not a redesign.

## Relationship to ADR-019

[ADR-019](019-process-fault-reaping-and-peer-generation.md) (Proposed) owns *fault* reaping and *who/when* to reap. It assumes reaping reclaims resources; its inline-reap list includes page tables, which would inherit this triple-fault. ADR-034 supplies the **mechanism** for the self-referential subset so both the clean-exit path and ADR-019's fault path reclaim the root/stack/slot correctly. The two compose: ADR-019 triggers, ADR-034 reaps.

## Phasing

- **Phase 0 — DONE** (committed): riscv C1 walk-guard (`reclaim` walks 0..256) + riscv H1 canonical-satp wiring. Surgical, standalone; removes the catastrophic global-HHDM corruption and the satp UAF. The common active-root self-free remains (Phase A).
- **Phase A — DONE** (06eddd8): per-CPU reaper drain (idle-loop, *not a dedicated task — see Divergence*) + `PER_CPU_RECLAIM_QUEUE`; defer `{ root + intermediates + kernel stack }` (not the slot). Closes the x86_64 + riscv64 triple-fault and the kernel-stack leak. Adds the **release-build active-root guard** (§3), the **enqueue-once** state gate, and the **peer-walk `FRAME_ALLOCATOR` audit** (occupancy class 2). Uses the lock-isolated per-CPU queue (placement signed off).
- **Phase B — DONE** (B.1 3cea74e, B.2-B.4 b4d10e0): TaskId generation + `TaskExitRing` + `WaitTask` rewrite + H5 co-fix + **local** slot reclaim (*not cross-CPU — see Divergence*) + selective `ChildWait(slot)` wake. Extends the Phase A reaper; no tear-down. A 7-reviewer adversarial pass before landing fixed a HIGH (ring re-check on the resolve's not-found arm) + two LOWs and surfaced the global-slot-uniqueness gap below.

## Open Problems (Convention 9 triggers)

- `cpu_refs` atomic + the reserved memory ordering — **Revisit when** the thread model lands (first multi-thread-per-process spawn path).
- Explicit TLB shootdown-before-free in the reaper — **Revisit when** any address space is resident on more than one CPU simultaneously.
- TaskId-generation parity audit (every TaskId-keyed lookup, not just `WaitTask`) — **Revisit when** the generation field is added (Phase B), and again on a second cross-CPU TaskId lookup path.
- Reaper topology resolved to **per-CPU** (§3, dissolves the cross-CPU-`SCHEDULER` surface); the remaining tunable is the starvation bound — **Revisit when** a per-CPU queue high-watermark > 25% of its bound under any test workload.
- aarch64 kernel-half-zero enforcement (compile/boot assertion) — **Revisit when** any change touches `create_process_page_table`'s `#[cfg]` arms.

## Residual Risks

- The release-build guard (§3) catches the active-root case, but the *primary* correctness basis — the structural guarantee that Terminated-before-enqueue makes the dead root un-selectable — is still enforced by design + convention, not yet by proof. The CLAIMS.md target (below) closes it; until then a refactor that breaks the structure is caught only by the guard (active-root) plus debug-build CI, not by the type system.
- Occupancy class (2) is a required clause now (§3), but until the guard token is threaded through `page_table_from_cr3` it remains convention: a by-phys walker added without `FRAME_ALLOCATOR` breaks serialization silently. Phase A audits today's walkers; the Convention-9 trigger promotes it to a type.
- TaskId generation width / wraparound horizon must be Convention-8 tagged (Phase B): mirror `ProcessId`'s `u32`, name the horizon (2³² slot reuses, far beyond v1) in ASSUMPTIONS.md.
- `TaskExitRing` age-out is best-effort: a waiter slower than the ring's wrap misses the exit code (typed not-found) — the same contract as `RecentExitsRing` for Principal-after-exit. Size the ring; document the semantics so callers don't assume guaranteed delivery.
- [ADR-019](019-process-fault-reaping-and-peer-generation.md) fault-path capture compatibility: a faulting task's context differs from a clean `SYS_EXIT` (partial operations, fault frame); the substrate must capture `{ root, stack, slot }` correctly from the fault path. Tracked as an ADR-019 integration item.
- **Task slots are not a globally-arbitrated namespace** (surfaced by the Phase B adversarial review). Each per-CPU scheduler searches its *own* `tasks[]` for a free slot, so two CPUs running `SYS_SPAWN` concurrently can claim the same slot index — yielding two live tasks with an identical `(slot, generation)`, which this phase's reaper, exit ring, and generation guard all assume cannot happen. **Pre-existing** — the bare-`u32` `TaskId` already collided (mis-routed cross-CPU wakes via `TASK_CPU_MAP` last-writer-wins; `migrate_task_between` drops a task on accept-failure); Phase B inherits the "slots are global" assumption that `TASK_CPU_MAP` and migration already make, **without worsening** the danger. Not triggered by the current single-shell spawner; reachable on 2+ CPUs with concurrent cross-CPU spawns. **Fix:** a global task-slot allocator (an atomic free-list claimed before the per-CPU insert), landing as a focused follow-up; the deferral is recorded at `create_isr_task`. **Revisit when** a second concurrent cross-CPU `SYS_SPAWN` call site exists.
- *(Resolved, recorded for history: the cross-CPU foreign-`SCHEDULER` deadlock surface is dissolved by per-CPU reapers (§3) — not a residual risk under that topology.)*

## Verification hook (CLAIMS.md)

New invariant to add as a Gap and target (Verus/Kani): **"No CPU's active address-space root (CR3/satp/TTBR0) references a frame in the free pool, and a task's page-table root, kernel stack, and task slot are freed only from a context not executing on them."** The release-build active-root guard (§3) is the runtime witness; a proof is the static one.

## Divergence

The body above reflects the implemented design. The original wordings, with the date and commit where they changed, are preserved here.

- **Reaper vehicle: per-CPU idle-loop drain, not a dedicated reaper task** (2026-06-04, Phase A 06eddd8). §3 originally specified "a low-priority **per-CPU kernel reaper task**." It was implemented as `reaper::drain_local`, called from each CPU's existing idle loop (`microkernel_loop` + the AP loops). The safety properties §3 requires hold either way — normal context, interrupts enabled, `SCHEDULER` not held — but building a dedicated ring-0 kernel-task trampoline (the same triple-fault class this ADR fixes) bought no Phase-A correctness (queue overflow is structurally impossible and slots leak in Phase A regardless), so the drain logic lives in a reusable function any future vehicle reuses verbatim. Promotion to a dedicated low-priority task remains the latency lever (Open Problems). *Prior wording: "A low-priority **per-CPU kernel reaper task** drains its CPU's bounded pending-reclaim queue in **normal context** (interrupts enabled, `SCHEDULER` not held)."*

- **Slot reclaim is local, not cross-CPU** (2026-06-04, Phase B b4d10e0). With the per-CPU idle-loop reaper, the slot always lives on the reaper's own CPU (the dying task enqueued to its own CPU's queue; a Terminated+purged task cannot migrate), so the slot free is **local** — the same foreign-`SCHEDULER` dissolution §3 already describes. The cross-CPU resolution that *did* land is in `WaitTask`'s pre-block authorize/state check (`task_parent_and_state`), for a *live* child the load balancer may have moved; the exit *code* is read from the CPU-agnostic global `TaskExitRing`. *Prior wording (§4): "The reaper frees the slot **cross-CPU** (the child may have migrated) via `PER_CPU_SCHEDULER[child_cpu]` resolved through `TASK_CPU_MAP`; `WaitTask` must likewise resolve the child cross-CPU for both its pre-block check and post-yield read."*

- **Global task-slot uniqueness is assumed, not enforced** (2026-06-04, Phase B b4d10e0). §1/§4 treat the task slot as a global namespace (as do `TASK_CPU_MAP` and migration). The per-CPU-local allocator does not enforce it — recorded as a new Residual Risk and a Convention-9 deferral at `create_isr_task`. This is the gap between the ADR's assumption and the as-built allocator; the global task-slot allocator that closes it is the next focused change.
