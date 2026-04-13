<!--
doc_type: implementation_reference
owns: src/scheduler/
auto_refresh: required
last_synced_to_code: 2026-04-10
authoritative_for: scheduler internals, task lifecycle, time slicing, priority bands, blocking primitives, IPC integration with the scheduler
-->

# CambiOS Preemptive SMP Scheduler

> **Implementation reference.** This document describes what is currently in `src/scheduler/`. It is auto-refreshed when scheduler code changes (see `CLAUDE.md` § "Post-Change Review Protocol", Step 8). For the *decisions* behind the SMP architecture, see [ADR-001](../../docs/adr/001-smp-scheduling-and-lock-hierarchy.md).

## Overview

The CambiOS scheduler is a **per-CPU, preemptive, priority-band scheduler** with SMP task migration and load balancing. Each CPU runs its own independent scheduler instance — no global lock on the hot path. Tasks are assigned to a "home CPU" and can be migrated between CPUs by the load balancer or by IRQ affinity. Scheduling is O(1) within each CPU via per-priority-band ready queues.

The scheduler is wired to two context-switch paths:
1. **ISR-driven preemption** — the timer ISR saves the current task's full register state and restores the next task's, every 10ms
2. **Voluntary yield** (`yield_save_and_switch`) — syscall handlers (`SYS_EXIT`, `SYS_YIELD`, `SYS_RECV_MSG`, `SYS_WAIT_IRQ`) build a synthetic exception frame on the kernel stack and call into the scheduler

Both paths use the same `SavedContext` layout. From the scheduler's point of view, ISR preemption and voluntary yield are interchangeable — both deliver an `(old_rsp, new_rsp)` swap with the new task's `ContextSwitchHint` (kernel stack top + page table root).

## Architecture

The scheduler subsystem is three files:

| File | Responsibility |
|---|---|
| `task.rs` | `Task`, `TaskState`, `CpuContext`, `Priority`, `BlockReason`, `ScheduleError` |
| `timer.rs` | `Timer`, `TimerConfig`, `TimerState`, global `TICK_COUNT` atomic |
| `mod.rs` | `Scheduler`, ready queues, `on_timer_isr()`, `on_voluntary_yield()`, blocking/wake, migration |

### Key types (`task.rs`)

- **`TaskId(pub u32)`** — slot index in the scheduler's task array
- **`TaskState`** — five-state enum: `Ready`, `Running`, `Blocked`, `Terminated`, `Suspended`
- **`Priority(pub u8)`** — 0–255, with named constants `IDLE=0`, `LOW=64`, `NORMAL=128`, `HIGH=192`, `CRITICAL=255`
- **`BlockReason`** — why a task is `Blocked`: `MessageWait(EndpointId)`, `IoWait(irq)`, `TimerWait(ms)`, `SyncSendWait(ep)`, etc.
- **`CpuContext`** — `#[cfg(target_arch = "x86_64")]` and `#[cfg(target_arch = "aarch64")]` variants. x86_64 stores all 16 GPRs + RIP/RSP/RFLAGS. AArch64 stores callee-saved only (x19–x30, sp, pc, pstate); caller-saved go through `SavedContext` instead.
- **`Task`** — full metadata: state, context, priority, time slice, kernel stack top, `cr3` (page table root), `home_cpu`, `pinned`, `parent_task` (for `WaitTask`), `exit_code`, `saved_rsp` (pointer to `SavedContext` on this task's kernel stack)

### Per-CPU schedulers

`Scheduler` is **not** a global. It is held per-CPU in:

```rust
pub static PER_CPU_SCHEDULER: [IrqSpinlock<Option<Box<Scheduler>>>; MAX_CPUS]
```

Helpers in `lib.rs` resolve the calling CPU's scheduler via the per-CPU data pointer (GS base on x86_64, TPIDR_EL1 on AArch64):

- `local_scheduler()` — returns the calling CPU's `IrqSpinlock`
- `local_timer()` — returns the calling CPU's timer

The lock hierarchy puts `PER_CPU_SCHEDULER` at position 1 (innermost), so it must be acquired before any other system lock. See `CLAUDE.md` § "Lock Ordering" for the full hierarchy.

### `Scheduler` struct (`mod.rs`)

```rust
pub struct Scheduler {
    tasks: Vec<Option<Task>>,                           // MAX_TASKS slots
    ready_queues: [VecDeque<TaskId>; NUM_PRIORITY_BANDS], // 4 bands
    task_count: usize,
    runnable_count: usize,                              // Ready + Running, excluding idle
    current_task: Option<TaskId>,
    total_ticks: u64,
    state: SchedulerState,
}
```

The task array and ready queues are heap-allocated (`Vec<Option<Task>>` and `[VecDeque<TaskId>; 4]`). Only ~128 bytes of `Scheduler` metadata sits on the stack — safe for the 256 KB boot stack even at `MAX_TASKS = 256`.

## Constants

```rust
pub const MAX_TASKS: usize = 256;            // Per-CPU task pool size
const NUM_PRIORITY_BANDS: usize = 4;         // Ready queue bands
const MAX_CPUS: usize = 256;                 // Per-CPU scheduler array size
const DEFAULT_TIME_SLICE: u32 = 10;          // Ticks per quantum (10ms at 100Hz)
```

The 256-task limit is per-CPU, not global. With `MAX_CPUS = 256`, the system supports up to 65,536 tasks total across all CPUs in principle.

## Priority Bands

Priorities map to one of four bands via integer division:

```rust
fn priority_to_band(p: Priority) -> usize {
    (p.0 as usize / 64).min(NUM_PRIORITY_BANDS - 1)
}
```

| Band | Priority range | Task class |
|---|---|---|
| 0 | 0–63 | IDLE (idle task only, in practice) |
| 1 | 64–127 | LOW |
| 2 | 128–191 | NORMAL (default for new tasks) |
| 3 | 192–255 | HIGH + CRITICAL |

Each band has its own `VecDeque<TaskId>` ready queue. The scheduler picks the next task by checking bands from highest to lowest and popping the first non-empty queue. Within a band, scheduling is round-robin (FIFO).

## Time Slicing

The default time slice is **10 ticks (100ms at 100 Hz)** per task. Each timer tick decrements `time_remaining` on the running task. When it reaches zero, `time_slice_expired()` returns true and the next call to `schedule()` rotates to a new task.

The current time slice is reset to `time_slice` whenever a task is scheduled to run, including after a yield or wake.

## ISR-Driven Context Switch (Preemptive)

The portable hot path is `on_timer_isr()` in `mod.rs`:

```
Timer interrupt fires (vector 32 on x86_64, PPI 30 on AArch64)
    │
    ▼
arch-specific ASM stub: save all registers into SavedContext on the kernel stack
    │
    ▼
on_timer_isr(current_rsp) → (new_rsp, Option<ContextSwitchHint>)
    ├── local_timer().try_lock() → tick global TICK_COUNT
    ├── local_scheduler().try_lock()
    │       ├── wake_irq_waiters(0) → wake any IoWait(0) tasks (timer-blocked)
    │       ├── isr_tick_and_schedule(current_rsp)
    │       │       ├── decrement current task's time_remaining
    │       │       ├── if time_slice_expired: schedule()
    │       │       └── return either current_rsp (no switch) or next task's saved_rsp
    │       └── build ContextSwitchHint from new task's kernel_stack_top + cr3
    │
    ▼
arch-specific ASM stub:
    ├── if hint.kernel_stack_top != 0: set_kernel_stack(top) (TSS.RSP0 / per-CPU SP_EL1)
    ├── if hint.page_table_root != 0 and != current: write CR3 / TTBR0_EL1 + TLB shootdown
    ├── EOI to APIC / GIC
    ├── restore registers from new SavedContext
    └── iretq / eret → resume new task
```

`try_lock()` (rather than `lock()`) on both the timer and scheduler is essential: the ISR may preempt code that already holds those locks, and a blocking `lock()` would deadlock the CPU. If a `try_lock` fails the ISR skips that tick — the next one is 10 ms away.

## Voluntary Context Switch

`yield_save_and_switch()` is the kernel-side counterpart to ISR preemption. Syscall handlers that need to give up the CPU (`SYS_EXIT`, `SYS_YIELD`, `SYS_RECV_MSG`, `SYS_WAIT_IRQ`) call it. It builds a **synthetic** `SavedContext` on the kernel stack — identical layout to what the timer ISR would save — then calls into the scheduler:

```
Syscall handler decides to yield/block/exit
    │
    ▼
yield_save_and_switch() (assembly)
    ├── push all GPRs onto the kernel stack
    ├── push elr_el1 / saved RIP, spsr_el1 / saved RFLAGS, sp_el0 / user RSP
    ├── call yield_inner(current_rsp) → on_voluntary_yield()
    │       └── scheduler.voluntary_yield(current_rsp)
    │               (always saves current task's saved_rsp; selects next task)
    ├── arch-specific post-switch: kernel stack, page table, TLB
    ├── restore registers from next task's SavedContext
    └── eret / iretq → resume next task
```

Both x86_64 and AArch64 have full implementations. They share the `SavedContext` layout, the `ContextSwitchHint` plumbing, and the `on_voluntary_yield()` portable scheduler entry. The arch-specific differences are limited to the synthetic frame format (iretq vs eret) and the post-switch register writes (TSS.RSP0 vs SP_EL1, CR3 vs TTBR0_EL1).

The blocking pattern used by syscall handlers:

```rust
// Disable interrupts so the timer ISR can't see Blocked state
// before yield_save_and_switch saves the correct context.
unsafe { core::arch::asm!("cli"); }    // x86_64
// or: msr daifset, #2                  // AArch64

// Mark the task Blocked
local_scheduler().lock().as_mut().unwrap()
    .block_task(my_task_id, BlockReason::MessageWait(endpoint))?;

// Yield — saves context, schedules next task
unsafe { yield_save_and_switch(); }

// When we wake, re-check the condition (recv_msg restart loop, etc.)
```

## Blocking and Wake Primitives

`Scheduler` exposes:

| Method | Purpose |
|---|---|
| `block_task(task_id, BlockReason)` | Move a task from Ready/Running to Blocked. The idle task (slot 0) cannot be blocked. |
| `wake_task(task_id)` | Move a task from Blocked back to Ready, re-enqueuing it in its priority band. |
| `wake_irq_waiters(irq_number)` | Scan for tasks blocked with `BlockReason::IoWait(irq)` and wake them. Used by device ISRs. |
| `wake_message_waiters(endpoint)` | Scan for tasks blocked with `BlockReason::MessageWait(endpoint)` and wake them. Used by IPC send. |

Cross-CPU wake is mediated through `lib.rs` helpers:

- `wake_task_on_cpu(task_id)` — looks up the task's home CPU in the lock-free `TASK_CPU_MAP`, acquires that CPU's scheduler, and wakes the task
- `block_local_task(task_id, reason)` — always operates on the calling CPU's scheduler

The IPC layer uses these helpers exclusively — there is no hardcoded `PER_CPU_SCHEDULER[0]` access for cross-CPU wake. See [ADR-001](../../docs/adr/001-smp-scheduling-and-lock-hierarchy.md) § "Wake and block primitives."

## Task Migration and Load Balancing

`mod.rs` exposes migration primitives (`remove_task`, `accept_task`, `migrate_task_between`, `migrate_task`) and a push-based load balancer in `lib.rs::try_load_balance()`:

- Triggered from the BSP idle loop, throttled to once per second (100 ticks at 100 Hz)
- Samples each CPU's `active_runnable_count()` via `try_lock()` (non-blocking)
- If the spread between most- and least-loaded CPU is ≥ 2 tasks, picks one Ready task on the overloaded CPU and migrates it
- Migration acquires both schedulers' locks in ascending CPU-index order (to prevent A-B / B-A deadlock)

The idle task (slot 0) is never migrated — every CPU must keep its own fallback.

For the full migration design rationale, see [ADR-001](../../docs/adr/001-smp-scheduling-and-lock-hierarchy.md) § "Task Migration" and § "Load Balancing".

## Verification Invariants

The scheduler enforces the following invariants on every state transition. They are checked by `verify_invariants()` (called periodically from the idle loop) and by individual unit tests:

1. **Single Running task per CPU** — exactly one task in each per-CPU scheduler is in `Running` state at any time
2. **`current_task` consistency** — the per-CPU `current_task` matches the unique `Running` task in that scheduler
3. **`in_ready_queue` consistency** — `task.in_ready_queue == true` if and only if the task ID appears in one of the ready queue VecDeques (no duplicate enqueueing)
4. **Block reason consistency** — `state == Blocked` ⟺ `block_reason.is_some()`
5. **Idle task immutability** — slot 0 (idle task) is always present, never blocked, never migrated, never removed
6. **No transitions from Terminated** — once a task reaches `Terminated`, it cannot return to any other state
7. **Valid state transitions** — all transitions go through `TaskState::can_transition_to()`, which encodes the legal state machine
8. **Bounded `MAX_TASKS`** — `task_count <= MAX_TASKS` always; `task.id.0 < MAX_TASKS` always

These are the verification targets the scheduler is designed for. Several are checked at runtime via `verify_invariants()`. Others are encoded in the type system (`TaskState` is an enum, not a flag bitset; transitions go through `can_transition_to`). All are exercised by the unit test suite.

## Tests

35 unit tests cover the scheduler:

- 29 tests in `mod.rs`: scheduler creation, init, task lifecycle, schedule selection, time slice expiration, block/wake, IRQ wake, message wake, idle task immutability, remove/accept/migrate primitives, `active_runnable_count`, `pick_migratable_task`, invariants, IPC integration
- 6 tests in `timer.rs`: timer creation, init, configuration verification, frequency presets, tick counting, `ticks_to_ms` conversion

Test layer sits on the host (`x86_64-apple-darwin`) — no QEMU dependency, no x86 hardware features. Run with:

```bash
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin
```

The `RUST_MIN_STACK` is required because some scheduler tests allocate large `Vec` structures during `Scheduler::new()`.

## Cross-References

- **[ADR-001](../../docs/adr/001-smp-scheduling-and-lock-hierarchy.md)** — SMP scheduling decision rationale, lock hierarchy, migration design
- **[CLAUDE.md](../../CLAUDE.md) § "Lock Ordering"** — full lock hierarchy with the scheduler at position 1
- **[CLAUDE.md](../../CLAUDE.md) § "Timer / Preemptive Scheduling"** — APIC and ARM timer integration details
- **[CLAUDE.md](../../CLAUDE.md) § "Voluntary context switch"** — `yield_save_and_switch` implementation notes for both architectures
- **`src/arch/x86_64/mod.rs`** — x86_64 `SavedContext`, `timer_isr_inner`, `yield_save_and_switch`, `set_kernel_stack`
- **`src/arch/aarch64/mod.rs`** — AArch64 equivalents
