# Interrupt Routing System

## Overview

CambiOS implements **interrupt-driven task wakeup** through a routing system that maps hardware IRQs to driver tasks. When hardware asserts an interrupt, the kernel wakes any task blocked on that IRQ via the scheduler's `wake_irq_waiters()` mechanism. Drivers sleep until their interrupt fires — no polling, no spin-waiting.

This solves a critical problem in microkernel design:
- **Before**: Drivers poll or spin-wait for events (wastes CPU, kills thermal efficiency)
- **After**: Drivers block via `SYS_WAIT_IRQ`, sleep until their interrupt fires, and wake directly through the scheduler

## Interrupt Controller Architecture

CambiOS uses the **Local APIC** and **I/O APIC** exclusively. The legacy 8259 PIC is disabled at boot (remapped to vectors 0xF0-0xFF and fully masked).

| Controller | Role | Configured in |
|---|---|---|
| Local APIC | Timer interrupts (vector 32), IPI delivery, EOI | `arch/x86_64/apic.rs` |
| I/O APIC | Routes external device IRQs (vectors 33-56) to Local APICs | `arch/x86_64/ioapic.rs` |
| 8259 PIC | Disabled at boot. Not used. | `arch/x86_64/apic.rs:disable_pic()` |

### Vector Assignment

| Vector | Source | Handler |
|---|---|---|
| 0-31 | CPU exceptions | Exception handlers in IDT |
| 32 | Local APIC timer (100Hz periodic) | Naked asm stub → `timer_isr_inner` |
| 33-56 | Device IRQs via I/O APIC (GSI + 33) | Per-GSI `x86-interrupt` handlers |
| 0xFE | TLB shootdown IPI | `tlb_shootdown_isr` |
| 0xFF | APIC spurious interrupt | `spurious_interrupt` |

### Device IRQ Routing (I/O APIC)

Configured at boot by `ioapic::configure_device_irqs()`:

| Device | ISA IRQ | GSI | Vector | Handler |
|---|---|---|---|---|
| Keyboard | 1 | 1 | 34 | `device_irqs::gsi_1` |
| COM2/Serial | 3 | 3 | 36 | `device_irqs::gsi_3` |
| COM1/Serial | 4 | 4 | 37 | `device_irqs::gsi_4` |
| PS/2 Mouse | 12 | 12 | 45 | `device_irqs::gsi_12` |
| Primary IDE | 14 | 14 | 47 | `device_irqs::gsi_14` |
| Secondary IDE | 15 | 15 | 48 | `device_irqs::gsi_15` |

ACPI MADT interrupt source overrides are respected — the I/O APIC driver reads them during init and adjusts polarity and trigger mode per GSI.

## Signal Flows

### Timer Interrupt (Vector 32)

The timer drives preemptive scheduling. It does not go through the interrupt routing table.

```
Local APIC timer counts down to zero
    |
    v
CPU takes vector 32 interrupt
    |
    v
timer_isr_stub (naked asm in arch/x86_64/mod.rs)
    - Pushes all GPRs onto stack to form SavedContext
    - Passes current RSP to Rust function
    |
    v
timer_isr_inner(current_rsp) (arch/x86_64/mod.rs)
    |
    v
scheduler::on_timer_isr(current_rsp) (scheduler/mod.rs)
    - local_timer().try_lock() → tick counter
    - local_scheduler().try_lock() → wake IRQ 0 waiters + tick + schedule
    - If time slice expired → schedule() → return new RSP
    - Returns (new_rsp, Option<ContextSwitchHint>)
    |
    v
Back in timer_isr_inner:
    - If context switch: update TSS.RSP0, load new CR3
    - APIC EOI (apic::write_eoi())
    - iretq with new RSP (switches to new task)
```

Key details:
- Uses `try_lock()` on per-CPU scheduler — if contended, this tick is skipped (next one is 10ms away)
- Context switch is performed by the ISR itself (swap RSP, update TSS/CR3), not by a separate function
- Timer also wakes tasks blocked on IRQ 0 via `wake_irq_waiters(0)`

### Device Interrupt (Vectors 33-56)

Device IRQs wake the blocked driver task. With IRQ affinity, the interrupt is routed to the same CPU as the pinned driver task, enabling a targeted single-CPU wake.

```
Hardware asserts interrupt (e.g., keyboard key press)
    |
    v
I/O APIC routes to Local APIC on target CPU
    (with IRQ affinity: target = pinned driver's CPU)
    |
    v
CPU takes vector 33+GSI interrupt
    |
    v
device_irqs::gsi_N(InterruptStackFrame) (interrupts/mod.rs)
    - x86-interrupt calling convention
    - Calls device_irq_handler(gsi)
    |
    v
device_irq_handler(gsi) (interrupts/mod.rs)
    - Fast path (IRQ affinity):
        INTERRUPT_ROUTER.try_lock() → lookup(gsi) → handler_task
        TASK_CPU_MAP[task_id] → owning CPU
        PER_CPU_SCHEDULER[cpu].try_lock() → wake_irq_waiters(gsi)
    - Slow path (no registered handler or try_lock failed):
        Iterates all online CPUs:
            PER_CPU_SCHEDULER[cpu].try_lock() �� wake_irq_waiters(gsi)
    - APIC EOI (apic::write_eoi())
    |
    v
Blocked tasks on this IRQ transition: Blocked(IoWait(gsi)) → Ready
    |
    v
Next scheduler tick picks up the Ready task
```

Key details:
- When a driver registers via SYS_WAIT_IRQ, the I/O APIC entry is re-routed to the driver's CPU and the task is pinned
- The fast path uses INTERRUPT_ROUTER + TASK_CPU_MAP for O(1) targeted wake (no N-CPU scan)
- Falls back to all-CPU scan if no handler is registered or lock acquisition fails
- Uses `try_lock()` — if contended, the task is woken on the next timer tick (~10ms)
- APIC EOI is always sent, regardless of whether a task was woken

### SYS_WAIT_IRQ Syscall (Driver Side)

This is how user-space drivers register for and wait on hardware interrupts.

```
Driver task calls SYS_WAIT_IRQ(irq_number)
    |
    v
handle_wait_irq() in syscalls/dispatcher.rs
    |
    v
1. Read current CPU's APIC ID (via percpu GS base)
    |
    v
2. Register task with INTERRUPT_ROUTER
   INTERRUPT_ROUTER.lock() → register(irq, task_id, priority=128)
    |
    v
3. Pin task to current CPU (task.pinned = true)
    |
    v
4. Re-route I/O APIC entry to this CPU
   ioapic::set_irq_destination(gsi, local_apic_id)
    |
    v
5. Block calling task
   local_scheduler().lock() → block_task(task_id, BlockReason::IoWait(irq))
    |
    v
Task transitions: Running → Blocked(IoWait(irq))
    |
    v
[CPU runs other tasks or halts]
    |
    v
Hardware interrupt fires → device_irq_handler(gsi) → wake_irq_waiters(gsi)
    |
    v
Task transitions: Blocked → Ready → Running (on next schedule)
    |
    v
SYS_WAIT_IRQ returns to driver with success
```

## Core Components

### InterruptRoutingTable

Fixed-size table mapping up to 224 IRQs to driver tasks. Lives in `src/interrupts/routing.rs`.

```rust
pub struct InterruptRoutingTable {
    routes: [Option<InterruptRoute>; 224],
    entry_count: usize,
}
```

Each entry:

```rust
pub struct InterruptRoute {
    pub irq: IrqNumber,          // Which hardware IRQ (0-223)
    pub handler_task: TaskId,    // Which driver task handles it
    pub priority: u8,            // Handler priority (0-255)
    pub enabled: bool,           // Can be masked without removing
}
```

Methods:
- `register(irq, handler_task, priority)` — Add or update routing entry
- `unregister(irq)` — Remove routing entry
- `lookup(irq)` — Find handler for IRQ (returns None if unregistered or disabled)
- `verify_integrity()` — Audit that `entry_count` matches actual populated slots

Properties:
- **O(1) lookup** — direct array index by IRQ number
- **No dynamic allocation** — fixed 224-entry array
- **One handler per IRQ** — no chaining or sharing

### IrqNumber Constants

```rust
pub const TIMER: IrqNumber = IrqNumber(0);
pub const KEYBOARD: IrqNumber = IrqNumber(1);
pub const SERIAL1: IrqNumber = IrqNumber(4);
pub const NETWORK: IrqNumber = IrqNumber(11);
```

### InterruptContext

Interrupt metadata (defined but not currently used in the active interrupt path — retained for future IPC-based interrupt delivery):

```rust
pub struct InterruptContext {
    pub irq: IrqNumber,           // Which IRQ fired
    pub timestamp_ticks: u64,     // System ticks at fire time
    pub cpu_id: u32,              // Which CPU received it
    pub error_code: u64,          // Exception-specific (optional)
}
```

### Global Lock Position

`INTERRUPT_ROUTER` is at position 7 (lowest) in the lock hierarchy:

```
PER_CPU_SCHEDULER(1)* → PER_CPU_TIMER(2)* → IPC_MANAGER(3) →
CAPABILITY_MANAGER(4) → PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) →
INTERRUPT_ROUTER(7)
```

This means SYS_WAIT_IRQ can safely lock `PER_CPU_SCHEDULER` (position 1) then `INTERRUPT_ROUTER` (position 7) without violating ordering.

## SMP Considerations

### Per-CPU Schedulers

Each CPU has its own scheduler (`PER_CPU_SCHEDULER[cpu_id]`). Without IRQ affinity, device IRQ handlers must iterate all online CPUs to find blocked tasks, because a task may be on any CPU's run queue.

### IRQ Affinity (Implemented)

When a driver calls `SYS_WAIT_IRQ`, the syscall handler:
1. Pins the task to the current CPU (`task.pinned = true`)
2. Re-routes the I/O APIC entry to deliver the interrupt to this CPU (`set_irq_destination`)
3. The device ISR uses `INTERRUPT_ROUTER` + `TASK_CPU_MAP` for a targeted single-CPU wake

This eliminates the cross-CPU wake scan entirely. The load balancer (`pick_migratable_task`) respects the `pinned` flag and will not migrate affine tasks.

### Cross-CPU Wake Latency

For non-affine IRQs (no registered handler), the slow path scans all CPUs. If `try_lock()` fails on a remote CPU's scheduler, the blocked task is not woken until the next timer tick (~10ms at 100Hz).

### Timer IRQ Is Always Local

Each CPU's Local APIC timer fires on that CPU only. The timer ISR only touches `local_scheduler()` — no cross-CPU access needed.

## Verification Properties

### Determinism
- Routing table is fixed-size (224 entries max)
- Lookup is O(1) array access
- No dynamic allocation in the interrupt path
- `try_lock()` avoids deadlock — ISR either succeeds or skips (bounded latency)

### Safety
- IRQ numbers validated (0-223)
- One task per IRQ (no multiple handlers, no cascading)
- Tasks properly transition: Blocked(IoWait) → Ready → Running
- APIC EOI always sent, even if no task was woken
- Lock ordering preserved: scheduler (1) before router (7)

### Thermal Efficiency
- Drivers block via SYS_WAIT_IRQ — no polling loops
- CPUs execute HLT when idle (scheduler idle task)
- CPU only wakes on interrupt (timer tick or device IRQ)

## Performance Characteristics

| Metric | Value |
|---|---|
| IRQ lookup latency | O(1), single array index |
| Routing table memory | 224 x 16 bytes = 3.5 KB |
| Device ISR overhead (affine) | Single CPU try_lock (O(1) via TASK_CPU_MAP) |
| Device ISR overhead (non-affine) | Wake scan across N CPUs (try_lock per CPU) |
| Timer ISR overhead | Local only — single try_lock |
| Worst-case wake latency (affine) | Sub-tick (interrupt delivered to pinned CPU) |
| Worst-case wake latency (non-affine) | ~10ms (if remote scheduler lock is contended) |

## Future Extensions

1. **IPC-based interrupt delivery** — Currently, interrupt wakeup is a scheduler-level operation (Blocked → Ready). A richer model would deliver an `InterruptContext` message via IPC, giving the driver timestamp, CPU ID, and error code. The `InterruptContext` struct and `dispatch_interrupt()` function exist as scaffolding for this. Requires wiring IPC send into the device ISR path (carefully — IPC locks are position 3, must not be held when acquiring scheduler at position 1).

2. **IRQ sharing** — Multiple drivers per IRQ (chain of handlers). Needed for PCI shared interrupts. Requires changes to InterruptRoutingTable to store a list per IRQ slot.

3. **Interrupt coalescing** — For high-frequency IRQs (network, NVMe), coalesce multiple interrupts into a single wake to reduce ISR overhead.

4. **IRQ statistics** — Track interrupt counts, missed wakes (try_lock failures), and per-IRQ latency. Useful for diagnosing performance issues and tuning IRQ affinity.

## Files

| File | Contents |
|---|---|
| `src/interrupts/routing.rs` | InterruptRoutingTable, InterruptRoute, IrqNumber, InterruptContext |
| `src/interrupts/mod.rs` | IDT setup, exception handlers, device ISR handlers (gsi_0-23), `device_irq_handler()` |
| `src/arch/x86_64/apic.rs` | Local APIC driver (timer, EOI, PIC disable, IPI) |
| `src/arch/x86_64/ioapic.rs` | I/O APIC driver (device IRQ routing, redirection table) |
| `src/arch/x86_64/mod.rs` | `timer_isr_stub` (asm), `timer_isr_inner` (Rust) |
| `src/scheduler/mod.rs` | `on_timer_isr()`, `wake_irq_waiters()` |
| `src/syscalls/dispatcher.rs` | `handle_wait_irq()` (SYS_WAIT_IRQ implementation) |
| `src/acpi/mod.rs` | MADT parsing for I/O APIC addresses and interrupt source overrides |
