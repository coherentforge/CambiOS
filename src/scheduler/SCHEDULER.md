# ArcOS Tick-Based Scheduler

## Overview

The ArcOS scheduler implements **preemptive round-robin multitasking** with tick-based time slicing for the x86-64 microkernel. Each task gets a fixed time quantum before being preempted, enabling fair CPU sharing.

## Architecture

### Core Components

#### `task.rs` - Task Definition
Defines the task state machine and context structures:

- **`TaskState`** - Enum-based state machine with valid transitions:
  - `Ready` → `Running` (selected by scheduler)
  - `Running` → `Ready` (preempted or yields)
  - `Running` → `Blocked` (waits for I/O)
  - `Blocked` → `Ready` (event occurred)
  - Any → `Suspended` (debugger pause)
  - Valid → `Terminated` (task exit)

- **`CpuContext`** - Saves/restores CPU state for context switches:
  - General-purpose registers (RAX-R15)
  - Instruction pointer (RIP), stack pointer (RSP)
  - Flags register (RFLAGS) with interrupt enable flag

- **`Priority`** - Task priority levels:
  - `IDLE` (0) - Lowest
  - `LOW` (64)
  - `NORMAL` (128)
  - `HIGH` (192)
  - `CRITICAL` (255) - Highest

- **`Task`** - Complete task metadata:
  ```rust
  pub struct Task {
      id: TaskId,
      state: TaskState,
      context: CpuContext,
      priority: Priority,
      time_slice: u32,          // Quantum in ticks
      time_remaining: u32,      // Remaining in current slice
      schedule_count: u64,      // Times scheduled
  }
  ```

#### `mod.rs` - Scheduler
Implements the round-robin scheduling algorithm:

- **`Scheduler`** - Main scheduler structure:
  - Task pool: Up to 256 tasks
  - `current_task`: Currently running task ID
  - `ready_index`: Round-robin pointer
  - `total_ticks`: Global tick counter
  - `state`: Scheduler state (Uninitialized → Initialized → Running)

- **Invariants** (verified every 1000 ticks):
  - Exactly ONE task in `Running` state
  - `current_task` matches the running task
  - All Ready tasks have consistent state
  - No transitions from Terminated state

- **Key Methods**:
  - `init()` - Create idle task, set initial state
  - `create_task()` - Add new task to pool
  - `tick()` - Decrement time remaining, signal if expired
  - `schedule()` - Select next Ready task (round-robin)
  - `verify_invariants()` - Runtime scheduler verification

#### `timer.rs` - Timer Management
Handles timer interrupts and tick generation:

- **`Timer`** - Timer controller:
  - `TimerConfig` - Frequency and interval (100Hz or 1000Hz presets)
  - `TimerState` - Running/Stopped/Uninitialized
  - Global atomic tick counter: `TICK_COUNT`

- **`on_tick()`** - Called by timer ISR to:
  - Increment global and local tick counters
  - Trigger scheduler to check for preemption

- **Verified Configurations**:
  - **100 Hz** (10ms ticks) - Default for x86 PC
  - **1000 Hz** (1ms ticks) - High-resolution option

## Scheduling Algorithm: Round-Robin

### Time Slice Management

1. **Initialization**: Each task gets a `time_slice` (typically 10 ticks = 100ms at 100Hz)
2. **Running**: `time_remaining` decrements each tick while task is Running
3. **Expiration**: When `time_remaining == 0`, task is preempted
4. **Reset**: Task moved to Ready queue; next task's `time_remaining` reset

### Selection Policy

```
for each task in [ready_queue]:
    if task.state == Ready:
        task.state = Running
        task.schedule_count += 1
        return task.id
```

**Round-robin pointer** (`ready_index`) maintains fairness by cycling through task pool.

### Tick-Based Preemption

```
On each timer interrupt:
    1. scheduler.tick() → decrements current_task.time_remaining
    2. if time_slice_expired():
         - scheduler.schedule() → find next Ready task
         - Save preempted task context
         - Restore new task context
         - Jump to new task RIP
    3. Return from interrupt → resume task
```

## Integration with Microkernel

### Microkernel Main Loop

```rust
fn microkernel_loop() -> ! {
    loop {
        unsafe {
            // Simulate timer interrupt (real: triggered by hardware)
            if let Some(timer) = &mut TIMER {
                timer.on_tick();
            }

            // Check if context switch needed
            if let Some(preempted_task) = scheduler.tick() {
                // Current task preempted - find next ready task
                scheduler.schedule()?;
                // In real implementation: CPU context switch here
            }

            // Verify scheduler invariants periodically
            scheduler.verify_invariants()?;
        }

        hlt(); // Halt until next timer interrupt
    }
}
```

### Task Lifecycle

1. **Creation**: `scheduler.create_task(entry, stack, priority)` → task added to pool, state = Ready
2. **Selection**: Next tick, scheduler selects task → state = Running
3. **Running**: Task executes for its time slice (10 ticks)
4. **Preemption**: Time slice expires → state = Ready, next task selected
5. **Blocking**: Task waits for I/O → state = Blocked
6. **Unblocking**: Event occurs → state = Ready
7. **Termination**: Task completes → state = Terminated (no more scheduling)

## Verification Contracts

### Property: Single Running Task

```rust
// After every schedule():
let running_count = tasks.iter()
    .filter(|t| t.state == TaskState::Running)
    .count();
assert_eq!(running_count, 1);

// After every transition:
assert!(from_state.can_transition_to(to_state));
```

### Property: Time Fairness

With round-robin and equal time slices, each task gets ~equal CPU time over long periods:

```
Task CPU% ≈ time_slice / (time_slice * num_ready_tasks)
```

With 10ms time slice and 4 ready tasks: each task gets ~25% of CPU.

### Property: Scheduler Invariants

```rust
scheduler.verify_invariants() == Ok(()) ⟹
  ∃! task ∈ tasks : task.state = Running ∧
  current_task = Some(running_task.id) ∧
  ∀ task : previous_state.can_transition_to(current_state)
```

## Binary Artifacts

**Microkernel Size**: 26K (9.3K → 26K with scheduler)

Breakdown:
- Core scheduler: ~8KB
- Task structures: ~4KB
- Timer management: ~2KB
- State machines: ~2KB
- Overhead: ~4KB

## Current Limitations & Future Work

### Current
- No actual CPU context switching (saves but doesn't restore x86-64 registers)
- Timer is simulated (not connected to PIT/APIC)
- Maximum 256 tasks (configurable)
- No priority scheduling (round-robin only)
- No task blocking/wakeup mechanism

### Future
1. **Context Switching**
   - Implement actual x86-64 register save/restore
   - Integrate with interrupt handler
   - Test context switch correctness

2. **Timer Integration**
   - Connect to PIT (Programmable Interval Timer)
   - Or use APIC timer for modern systems
   - Handle real interrupts

3. **Advanced Scheduling**
   - Priority-aware scheduling
   - Multilevel feedback queues
   - CPU affinity for SMP

4. **IPC Integration**
   - Block task on message wait
   - Wake on message arrival
   - Integrate with capability system

5. **Formal Verification**
   - Prove scheduler invariants
   - Prove fairness properties
   - Verify state machine transitions

## Testing

The scheduler includes built-in unit tests:

```bash
cargo test --target x86_64-unknown-none
```

Tests verify:
- Scheduler creation and initialization
- Task creation
- Timer configuration
- State transitions

## References

- **Linux Kernel CFS**: Completely Fair Scheduler uses similar ideas
- **MINIX 3**: Microkernel with simple round-robin scheduler
- **seL4**: Verified microkernel with formal scheduling proofs
- x86-64 Context Manual: AMD64 Architecture Programmer's Manual Volume 2

## Code Organization

```
src/scheduler/
├── mod.rs          # Main Scheduler struct and algorithm
├── task.rs         # Task, TaskState, CpuContext definitions  
├── timer.rs        # Timer management and tick generation
└── [README.md]     # This file
```

## Scheduler Configuration Constants

```rust
const MAX_TASKS: usize = 256;           // Max tasks in system
const DEFAULT_TIME_SLICE: u32 = 10;     // Ticks per task
const TIMER_FREQUENCY: u32 = 100;       // Hz (100 = 10ms ticks)
const VERIFY_INTERVAL: u64 = 1000;      // Ticks between verification
```

Modify these in `src/scheduler/mod.rs` to tune behavior.
