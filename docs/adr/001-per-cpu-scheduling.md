# ADR-001: Per-CPU Scheduling Architecture

- **Status:** Accepted
- **Date:** 2026-04-03
- **Context:** SMP Phase 4a — restructure global scheduler for multicore scheduling

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

The existing seven-level lock hierarchy is preserved with the per-CPU arrays slotting into positions 1 and 2:

```
PER_CPU_SCHEDULER[*](1) → PER_CPU_TIMER[*](2) → IPC_MANAGER(3) →
CAPABILITY_MANAGER(4) → PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) →
INTERRUPT_ROUTER(7)
```

**Additional per-CPU rule:** Never hold two different CPUs' scheduler (or timer) locks simultaneously. If cross-CPU access is required (e.g., task migration), acquire in ascending CPU index order to prevent A-B / B-A deadlocks.

This rule is documented in the authoritative comment block in `src/lib.rs`, not just here, so future contributors will see it at the point of use.

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

`device_irq_handler(gsi)` must wake tasks blocked on a hardware IRQ that may reside on any CPU's scheduler. Phase 4a iterates all online CPUs:

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

**Known latency bound:** If `try_lock()` fails due to contention on a remote CPU's scheduler, the blocked task will not be woken until the next timer tick (~10ms at 100 Hz). This is acceptable for most device IRQs. The worst case is documented in `src/interrupts/mod.rs` as a known limitation, not just an implementation detail.

### IPC helper functions (Phase 4a: BSP-only)

IPC helpers (`ipc_send_and_notify`, `sync_ipc_send/recv/call/reply`, `dispatch_interrupt`) acquire a scheduler lock after releasing `IPC_MANAGER` (sequential, never nested). During Phase 4a all tasks live on CPU 0(BSP), so these use `PER_CPU_SCHEDULER[0]` directly. When tasks migrate across CPUs in Phase 4b+, these will need a task-to-CPU lookup via `ProcessTable`.

## Task IDs

`TaskId(u32)` is currently a local index into each Scheduler's `[Option<Task>; 32]` array. With per-CPU schedulers, global uniqueness is required. The recommended approach (deferred to Phase 4b):

- Global `AtomicU32` counter assigns unique TaskIds
- `ProcessTable` (already global) maps `TaskId → cpu_id` for cross-CPU lookups
- Each `Scheduler` stores tasks by local slot index, but `task.id` is globally unique

Phase 4a defers this because all tasks remain on BSP, so IDs are already unique within the single scheduler instance.

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

This is deferred until Phase 4b (task migration + AP scheduling). Phase 4a validates the array restructuring in isolation from AP bringup.

## Untouched subsystems

The following code required zero changes:

- **`src/ipc/`** — All IPC code uses global `IPC_MANAGER`, no scheduler dependency
- **`src/ipc/capability.rs`** — Global `CAPABILITY_MANAGER`
- **`src/process.rs`** — Global `PROCESS_TABLE`
- **`src/memory/`** — Frame allocator, paging, heap
- **`src/loader/`** — Already takes `&mut Scheduler` by injection (exemplary pattern)
- **`src/scheduler/task.rs`**, **`timer.rs`** — Pure data types, no globals
- **All 114 unit tests** — They construct `Scheduler` locally, never touch globals

## Future work

### Phase 4b: IRQ affinity

Route each device IRQ to a specific CPU via I/O APIC, and ensure `SYS_WAIT_IRQ` pins the task to that CPU. Eliminates the cross-CPU iterate-and-try-lock wake pattern entirely.

### Phase 4b: Task migration

```rust
fn migrate_task(task_id: TaskId, from_cpu: usize, to_cpu: usize) {
    // Lock ordering: ascending CPU index
    let (first, second) = if from_cpu < to_cpu {
        (from_cpu, to_cpu)
    } else {
        (to_cpu, from_cpu)
    };
    let mut first_guard = PER_CPU_SCHEDULER[first].lock();
    let mut second_guard = PER_CPU_SCHEDULER[second].lock();
    // Remove from source, insert into destination
}
```

### Phase 4b: Per-CPU run queues with load balancing

Periodic work-stealing or push-based migration to balance load across CPUs.

### Phase 4b: IPC helper migration

Replace `PER_CPU_SCHEDULER[0]` in IPC helpers with task-to-CPU lookup via `ProcessTable`, enabling cross-CPU IPC wake without assuming BSP ownership.

## Verification

- 114/114 unit tests pass (tests construct `Scheduler` locally, never touch globals)
- Debug and release builds compile with zero errors
- QEMU boot with `-smp 2` produces identical output to `-smp 1` (pre-existing ACPI page fault is unrelated)
- The array restructuring was validated in isolation before AP scheduler bringup
