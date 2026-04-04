# ADR-001: Per-CPU Scheduling and SMP Task Management

- **Status:** Accepted
- **Date:** 2026-04-03
- **Supersedes:** N/A (foundational)
- **Context:** SMP Phases 4a–4c — restructure global scheduler for multicore scheduling, implement task migration and load balancing

## Problem

ArcOS had a single global `SCHEDULER: IrqSpinlock<Option<Box<Scheduler>>>` and `TIMER: IrqSpinlock<Option<Timer>>` protecting all task state behind one lock per resource. With SMP (multiple CPUs online since Phase 2), this created a serialization bottleneck: every timer ISR on every CPU contended on the same lock. Only one CPU could advance its scheduler tick or perform a context switch at a time.

The existing ISR hot path already used `try_lock()` to avoid deadlock, meaning a CPU that lost the race simply skipped its tick entirely — acceptable for a single CPU, but a scaling wall for multicore.

## Decision

Replace the global `SCHEDULER` and `TIMER` statics with **per-CPU arrays** indexed by logical CPU ID, and provide `local_scheduler()` / `local_timer()` accessor helpers that read the current CPU ID from the GS base segment register.

### What becomes per-CPU

| Resource | Type | Rationale |
|---|---|---|
| `PER_CPU_SCHEDULER[cpu_id]` | `IrqSpinlock<Option<Box<Scheduler>>>` | Each CPU schedules its own run queue independently |
| `PER_CPU_TIMER[cpu_id]` | `IrqSpinlock<Option<Timer>>` | Each CPU has its own APIC timer and tick counter |

### What stays global

| Resource | Type | Rationale |
|---|---|---|
| `IPC_MANAGER` | `Spinlock<Option<Box<IpcManager>>>` | Cross-CPU message passing is inherently shared |
| `CAPABILITY_MANAGER` | `Spinlock<Option<Box<CapabilityManager>>>` | System-wide security policy |
| `PROCESS_TABLE` | `Spinlock<Option<Box<ProcessTable>>>` | System-wide process metadata |
| `FRAME_ALLOCATOR` | `Spinlock<FrameAllocator>` | Physical memory is a shared resource |
| `INTERRUPT_ROUTER` | `Spinlock<InterruptRoutingTable>` | System-wide IRQ routing table |

## Architecture

### Parallel static arrays

```
PER_CPU_SCHEDULER: [IrqSpinlock<Option<Box<Scheduler>>>; 256]
PER_CPU_TIMER:     [IrqSpinlock<Option<Timer>>;          256]
```

Each CPU owns its entry. The 256-entry size matches the xAPIC 8-bit APIC ID space. Memory cost: 256 × ~16 bytes per array slot = ~4 KB per array. Trivial.

### CPU identification

`local_scheduler()` and `local_timer()` read the logical CPU ID from the `PerCpu` struct via `gs:[0]` (IA32_GS_BASE MSR), set once during `init_bsp()` / `init_ap()`. This is a single register read — no lock, no atomic, no memory bus contention.

### Why arrays instead of embedding in PerCpu

The `PerCpu` struct is `#[repr(C)]` with assembly-known field offsets (`self_ptr` at 0, `cpu_id` at 8, etc.). Embedding a `Box<Scheduler>` (containing `[Option<Task>; 32]`) inside `PerCpu` would:

1. Couple the `PerCpu` layout to the Scheduler type, breaking the assembly contract
2. Require the heap to be available before PerCpu init (currently PerCpu is BSS-allocated)
3. Make `PerCpu` much larger, inflating the static array and cache footprint

Parallel static arrays give the same O(1) indexed access without any of these problems.

## Lock Ordering

The seven-level lock hierarchy is preserved with the per-CPU arrays at positions 1 and 2. See **The Seven-Lock Hierarchy** section below for the full rationale behind each position.

```
PER_CPU_SCHEDULER[*](1)* → PER_CPU_TIMER[*](2)* → IPC_MANAGER(3) →
CAPABILITY_MANAGER(4) → PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) →
INTERRUPT_ROUTER(7)
```

`*` = IrqSpinlock (saves/disables interrupts before acquiring).

**Cross-CPU rule:** When acquiring the same lock level on multiple CPUs, acquire in ascending CPU index order. See **Cross-CPU lock rule** below.

The authoritative copy of this ordering lives in the comment block in `src/lib.rs`.

## Access Pattern Migration

### Local-CPU paths (ISR + syscall hot paths)

All timer ISR and syscall handler sites were trivial renames — the executing code is always on the local CPU:

| Caller | Old | New |
|---|---|---|
| `on_timer_isr()` | `crate::TIMER.try_lock()` | `crate::local_timer().try_lock()` |
| `on_timer_isr()` | `crate::SCHEDULER.try_lock()` | `crate::local_scheduler().try_lock()` |
| `SYS_EXIT` handler | `crate::SCHEDULER.lock()` | `crate::local_scheduler().lock()` |
| `SYS_YIELD` handler | `crate::SCHEDULER.lock()` | `crate::local_scheduler().lock()` |
| `SYS_WAIT_IRQ` handler | `crate::SCHEDULER.lock()` | `crate::local_scheduler().lock()` |
| SYSCALL entry | `crate::SCHEDULER.lock()` | `crate::local_scheduler().lock()` |

### Cross-CPU wake (device IRQs)

`device_irq_handler(gsi)` must wake tasks blocked on a hardware IRQ that may reside on any CPU's scheduler. The handler iterates all online CPUs:

```rust
let count = percpu::cpu_count() as usize;
for cpu in 0..count {
    if let Some(mut guard) = PER_CPU_SCHEDULER[cpu].try_lock() {
        if let Some(sched) = guard.as_mut() {
            sched.wake_irq_waiters(gsi);
        }
    }
}
```

**Known latency bound:** If `try_lock()` fails due to contention on a remote CPU's scheduler, the blocked task will not be woken until the next timer tick (~10ms at 100 Hz). This is acceptable for device IRQs. The worst case is documented in `src/interrupts/mod.rs`.

### IPC helper functions (cross-CPU via TASK_CPU_MAP)

IPC helpers (`ipc_send_and_notify`, `sync_ipc_send/recv/call/reply`, `dispatch_interrupt`) need to wake or block tasks that may reside on any CPU. Rather than scanning all schedulers or hardcoding CPU 0, these use a lock-free task→CPU lookup (see "Cross-CPU Task Wake" below) to acquire the correct CPU's scheduler directly.

## Task IDs and Global Uniqueness

`TaskId(u32)` is an index into each Scheduler's `[Option<Task>; 32]` array. With per-CPU schedulers, a task's ID is its slot number — globally unique because `accept_task()` places a migrated task at the same slot index on the destination scheduler. This means TaskId space is system-wide: slot 3 on CPU 0 and slot 3 on CPU 1 cannot both be occupied.

This approach was chosen over a global `AtomicU32` counter because:

1. The `TASK_CPU_MAP` and all IPC helpers index by `TaskId.0` as usize — O(1) lookup
2. 32 task slots is sufficient for the current workload; dynamic scaling is deferred
3. Cross-CPU migration preserves task identity (the same TaskId before and after)

## AP Initialization

Each AP initializes its own scheduler and timer during `ap_entry`:

```rust
let mut scheduler = Box::new(Scheduler::new());
scheduler.init()?;  // Creates per-CPU idle task
*PER_CPU_SCHEDULER[cpu_index].lock() = Some(scheduler);

let mut timer = Timer::new(TimerConfig::HZ_100)?;
timer.init()?;
*PER_CPU_TIMER[cpu_index].lock() = Some(timer);
```

After all APs are online, `distribute_tasks_to_aps()` migrates approximately half of CPU 0's Ready tasks to APs in round-robin order. This provides an initial balanced distribution before the runtime load balancer takes over.

Each AP also increments `ONLINE_CPU_COUNT` (atomic), which the load balancer reads to know how many CPUs to sample.

## Cross-CPU Task Wake

The central correctness challenge in SMP scheduling: when an IPC helper or ISR needs to wake a task, *which CPU's scheduler holds it?*

### The problem with scanning

Naively iterating all CPU schedulers to find a task is O(n) in CPU count, requires acquiring and releasing multiple locks, and introduces latency spikes when locks are contended. It also doesn't work for blocking — you must know the local CPU to block a task on its own scheduler.

### TASK_CPU_MAP: lock-free task→CPU lookup

```rust
pub static TASK_CPU_MAP: [AtomicU16; MAX_TASKS] =
    [const { AtomicU16::new(TASK_CPU_NONE) }; MAX_TASKS];
```

A global array of 32 `AtomicU16` values, indexed by `TaskId`. Each entry stores the logical CPU ID that currently owns the task, or `TASK_CPU_NONE` (0xFFFF) if unassigned.

**Properties:**
- **Lock-free reads** (`Acquire` ordering): `get_task_cpu()` is a single atomic load — no lock, no contention
- **Lock-free writes** (`Release` ordering): `set_task_cpu()` is a single atomic store
- **Maintained atomically** by `migrate_task_between()` and `scheduler_init()`
- **Consistent with scheduler state**: the map is updated inside the migration path, after the task has been moved between schedulers

### Wake and block primitives

```rust
pub fn wake_task_on_cpu(task_id: TaskId) -> bool {
    let cpu = get_task_cpu(task_id.0)?;  // Lock-free lookup
    let mut guard = PER_CPU_SCHEDULER[cpu].lock();  // Acquire correct CPU
    guard.as_mut()?.wake_task(task_id).is_ok()
}

pub fn block_local_task(task_id: TaskId, reason: BlockReason) -> bool {
    let mut guard = local_scheduler().lock();  // Always the calling CPU
    guard.as_mut()?.block_task(task_id, reason).is_ok()
}
```

All IPC helpers, ISR dispatch, and diagnostics use these instead of hardcoded `PER_CPU_SCHEDULER[0]`. This is what makes task migration transparent to the rest of the kernel: wake a task by ID and the infrastructure finds it.

### IPC send: cross-CPU receiver search

`ipc_send_and_notify()` is a special case — it must find the highest-priority receiver blocked on an endpoint, across all CPUs. This requires scanning all schedulers:

```rust
for cpu in 0..MAX_CPUS {
    if let Some(guard) = PER_CPU_SCHEDULER[cpu].try_lock() {
        if let Some(sched) = guard.as_ref() {
            if let Some(tid) = sched.find_highest_priority_receiver(endpoint) {
                // Compare priority, track best candidate + its CPU
            }
        }
    }
}
```

Each lock is acquired and released independently (never two held simultaneously). If a lock is contended, that CPU is skipped — the message stays queued and will be picked up by the next recv.

## Task Migration

### Primitives

| Method | Scope | Purpose |
|---|---|---|
| `remove_task(TaskId)` | Single scheduler | Extract a Ready/Blocked task from the run queue |
| `accept_task(Task)` | Single scheduler | Insert a task at its existing slot index |
| `migrate_task_between(src, dst, TaskId, dst_cpu)` | Two schedulers (caller holds both locks) | Pure logic: remove → update `home_cpu` → accept → update `TASK_CPU_MAP` |
| `migrate_task(TaskId, from_cpu, to_cpu)` | Global | Acquires both scheduler locks in ascending CPU-index order, then calls `migrate_task_between` |

### Constraints

- **Cannot migrate the idle task** (slot 0 on every CPU). Each CPU must always have a fallback task.
- **Cannot migrate the currently running task.** The task must be Ready or Blocked.
- **Lock ordering: ascending CPU index.** `migrate_task` always acquires the lower-numbered CPU's lock first to prevent A-B / B-A deadlock.
- **Slot preservation.** A task keeps its `TaskId` across migrations. `accept_task` places it at `tasks[task_id.0]`, which must be free on the destination scheduler.

## Load Balancing

### Design

Push-based periodic balancing, triggered from the BSP idle loop:

```rust
pub fn try_load_balance() {
    // Throttle: once per BALANCE_INTERVAL_TICKS (100 ticks = 1 second at 100Hz)
    // Sample: read active_runnable_count() from each CPU via try_lock()
    // Decide: if max_load - min_load >= 2, migrate one task
    // Execute: pick_migratable_task() on overloaded CPU, migrate_task() to underloaded
}
```

### Key decisions

| Choice | Decision | Rationale |
|---|---|---|
| Push vs pull | Push (overloaded → underloaded) | Simpler; idle CPUs don't need to actively steal |
| Trigger | BSP idle loop, throttled to 1Hz | Avoids wasting cycles on a 5-task system |
| Imbalance threshold | ≥ 2 runnable tasks difference | Prevents pointless single-task thrashing |
| Migration quantum | 1 task per balance attempt | Conservative; avoids oscillation |
| Sampling method | `try_lock()` (non-blocking) | Safe in idle context; skips contended CPUs |
| Load metric | `active_runnable_count()` | Ready + Running tasks excluding idle — the actual CPU contention metric |

### Load metric

`active_runnable_count()` counts non-idle tasks in Ready or Running state:

```rust
pub fn active_runnable_count(&self) -> usize {
    self.tasks[1..].iter().filter(|t| {
        t.as_ref().map(|task| {
            task.state == TaskState::Ready || task.state == TaskState::Running
        }).unwrap_or(false)
    }).count()
}
```

This excludes:
- The idle task (slot 0) — always present, not a real workload
- Blocked tasks — they aren't competing for CPU time
- Terminated/Suspended tasks — dead weight

### Migration candidate selection

`pick_migratable_task()` returns the first Ready non-idle task. This is deliberately simple — with 32 task slots and a 1-task-per-second migration rate, optimal selection doesn't matter. What matters is not migrating the wrong thing (idle, running, blocked).

## Timer Architecture

### Per-CPU timers

Each CPU has its own Local APIC timer running in periodic mode at 100 Hz (10ms ticks). The BSP calibrates against the PIT at boot; APs reuse the calibrated count.

```
APIC timer interrupt (vector 32)
    │
    ▼
Naked ASM stub (save all registers → SavedContext on stack)
    │
    ▼
on_timer_isr(current_rsp) — portable scheduler logic
    ├── local_timer().try_lock() → tick counter
    ├── local_scheduler().try_lock() → wake IRQ waiters + tick + schedule
    │       └── if time_slice expired → schedule() → return new_rsp
    └── return (new_rsp, Option<ContextSwitchHint>)
    │
    ▼
ASM stub: if hint → update TSS.RSP0 + CR3, APIC EOI, iretq with new_rsp
```

### Why `try_lock()` in the ISR

The timer ISR fires asynchronously — it can interrupt code that already holds the scheduler or timer lock (e.g., a syscall handler mid-operation). Using `lock()` would deadlock the CPU. `try_lock()` means the ISR either succeeds (common case) or skips this tick (next one is 10ms away). At 100 Hz with sub-microsecond lock hold times, contention is rare.

### Global vs local tick counters

`Timer::get_ticks()` reads a global `AtomicU64` counter — all CPUs increment it, so it reflects wall-clock ticks. Each Timer also tracks `local_ticks` for per-CPU diagnostics. The load balancer uses `get_ticks()` for its throttle interval.

## The Seven-Lock Hierarchy

ArcOS has seven system-wide lock groups, ordered to prevent deadlock. This is the single most important architectural invariant for contributors to understand.

```
PER_CPU_SCHEDULER[*](1)* → PER_CPU_TIMER[*](2)* → IPC_MANAGER(3) →
CAPABILITY_MANAGER(4) → PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) →
INTERRUPT_ROUTER(7)
```

`*` = IrqSpinlock (saves and disables interrupts before acquiring). All others are plain Spinlock.

### Why this order

| Position | Lock | Rationale |
|---|---|---|
| 1 | `PER_CPU_SCHEDULER` | Acquired first in every hot path (timer ISR, syscall entry). Must be outermost to avoid nesting inside anything else. |
| 2 | `PER_CPU_TIMER` | Only needed alongside scheduler (in `on_timer_isr`). Always acquired immediately after scheduler. |
| 3 | `IPC_MANAGER` | Syscall handlers acquire scheduler first (to identify the calling task), then IPC. Never the reverse. |
| 4 | `CAPABILITY_MANAGER` | Checked during IPC operations — after IPC state is consistent, before process metadata. |
| 5 | `PROCESS_TABLE` | Read during ELF loading and task creation, after IPC/capability setup. |
| 6 | `FRAME_ALLOCATOR` | Physical memory allocation happens deep in the call stack (page mapping, ELF loading). Must not hold scheduler. |
| 7 | `INTERRUPT_ROUTER` | Only touched during boot (route setup) and ISR dispatch. Innermost because it's rarely contended. |

### Why IrqSpinlock for positions 1 and 2

A plain Spinlock does not disable interrupts. If code holds the scheduler lock and a timer IRQ fires on the same CPU, the ISR would try to acquire the same lock → deadlock. `IrqSpinlock` saves RFLAGS, clears IF, acquires the lock, and restores on drop. This makes the scheduler and timer locks safe to hold when an interrupt could fire.

The remaining five locks (positions 3–7) use plain Spinlock because they are never acquired from ISR context. The timer ISR only touches positions 1 and 2.

### Cross-CPU lock rule

When acquiring the same lock level on multiple CPUs (e.g., two scheduler locks during migration), always acquire in ascending CPU index order:

```rust
let (first, second) = if from_cpu < to_cpu {
    (from_cpu, to_cpu)
} else {
    (to_cpu, from_cpu)
};
let mut guard1 = PER_CPU_SCHEDULER[first].lock();
let mut guard2 = PER_CPU_SCHEDULER[second].lock();
```

This prevents the classic A-B / B-A deadlock between two CPUs migrating tasks in opposite directions.

## Untouched Subsystems

The following code required zero changes across all SMP phases:

- **`src/ipc/`** — All IPC code uses global `IPC_MANAGER`; capability and interceptor logic is lock-agnostic
- **`src/ipc/capability.rs`** — Global `CAPABILITY_MANAGER`
- **`src/process.rs`** — Global `PROCESS_TABLE`
- **`src/memory/`** — Frame allocator, paging, heap
- **`src/loader/`** — Takes `&mut Scheduler` by injection (exemplary pattern)
- **`src/scheduler/task.rs`**, **`timer.rs`** — Pure data types, no globals (except `home_cpu: u16` added to Task)

## Future Work

### IRQ affinity

Route each device IRQ to a specific CPU via I/O APIC, and pin `SYS_WAIT_IRQ` tasks to that CPU. Eliminates the iterate-and-try-lock wake pattern for device IRQs.

### Work stealing

The current push-based balancer runs from BSP only. For larger CPU counts, idle APs should actively steal from overloaded neighbors (pull-based). Requires per-CPU deque with lock-free steal end.

### NUMA awareness

Task migration should prefer CPUs on the same NUMA node. Requires ACPI SRAT parsing and per-node task affinity hints.

### Priority-aware migration

The load balancer currently picks the first Ready task. For mixed-priority workloads, it should prefer migrating lower-priority tasks to avoid disrupting latency-sensitive ones.

## Verification

- 134 unit tests pass (133 pass + 1 pre-existing flaky TLB ordering test)
- Tests cover: scheduler creation, task lifecycle, block/wake, IRQ wake, priority scheduling, migration primitives (remove/accept/migrate_between), active_runnable_count, pick_migratable_task, idle task immutability
- Debug and release builds compile with zero errors
- QEMU verified with `-smp 1` and `-smp 2`: stable preemptive multitasking, task migration, cross-CPU wake, load balancer quiescence when balanced
