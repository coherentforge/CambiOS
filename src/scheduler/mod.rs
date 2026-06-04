// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Round-robin scheduler for the microkernel
//!
//! Implements preemptive multitasking with tick-based time slicing.
//! Designed for verification with clear scheduling invariants.

pub mod task;
pub mod timer;

pub use task::{Task, TaskId, TaskState, Priority, CpuContext, ScheduleError, BlockReason};
pub use timer::{Timer, TimerConfig, AdaptiveTickMode};
use core::fmt;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use alloc::boxed::Box;

/// Platform-agnostic context switch info returned from `on_timer_isr`.
///
/// When a context switch occurs, the architecture-specific ISR uses this
/// to perform platform-specific post-switch work (e.g., update TSS/CR3
/// on x86, or TTBR0/SP_EL0 on ARM).
pub struct ContextSwitchHint {
    /// Kernel stack top for the new task (x86: TSS.RSP0, ARM: SP_EL1)
    pub kernel_stack_top: u64,
    /// Page table root for the new task (x86: CR3, ARM: TTBR0)
    /// 0 means use the kernel page table.
    pub page_table_root: u64,
}

/// Outcome of [`Scheduler::arm_quiesce`] (ADR-027 Phase 1).
///
/// Tells the syscall handler whether the peer task is already off-CPU
/// (the kernel may proceed with unmap immediately) or whether the
/// caller must wait for the next yield/preempt to park it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceArmResult {
    /// Task was `Ready`: parked synchronously into
    /// `Blocked(ChannelQuiesceWait(channel_id))`. Caller may proceed.
    ParkedNow,
    /// Task was `Running`: pending hint set on the task; the scheduler
    /// hook (`isr_tick_and_schedule` / `voluntary_yield`) will park it
    /// at the next yield/preempt (≤ one timer tick away).
    PendingOnYield,
    /// Task was already non-runnable (`Blocked` / `Terminated` /
    /// `Suspended`). No state change. Caller may proceed — the task
    /// is not running on any CPU.
    AlreadyOffCpu,
}

/// Portable timer ISR handler: tick timer + tick scheduler.
///
/// Called from architecture-specific timer ISR stubs. Returns the RSP to
/// restore, plus an optional `ContextSwitchHint` if a context switch occurred.
///
/// # Safety contract
/// Must be called from ISR context with interrupts disabled. The caller
/// is responsible for platform-specific post-switch work (TSS, page table,
/// EOI) based on the returned hint.
pub fn on_timer_isr(current_rsp: u64) -> (u64, Option<ContextSwitchHint>) {
    // Tick the timer (try_lock to avoid deadlock)
    if let Some(mut timer_guard) = crate::local_timer().try_lock() {
        if let Some(t) = timer_guard.as_mut() {
            t.on_tick();
        }
    }

    // Drain per-CPU audit staging buffers into the global ring (BSP only).
    // Must run after timer tick (uses Timer::get_ticks for timestamps)
    // and before scheduler tick (no locks held at this point).
    #[cfg(all(not(test), target_arch = "x86_64"))]
    {
        // SAFETY: GS base initialized after boot; cpu_id is a pure read.
        let cpu_id = unsafe { crate::arch::x86_64::percpu::current_cpu_id() };
        if cpu_id == 0 {
            crate::audit::drain::drain_tick();
            crate::policy::expire_pending_queries();
        }
    }
    #[cfg(all(not(test), target_arch = "aarch64"))]
    {
        // SAFETY: TPIDR_EL1 initialized after boot; cpu_id is a pure read.
        let cpu_id = unsafe { crate::arch::aarch64::percpu::current_percpu().cpu_id() };
        if cpu_id == 0 {
            crate::audit::drain::drain_tick();
            crate::policy::expire_pending_queries();
        }
    }
    #[cfg(all(not(test), target_arch = "riscv64"))]
    {
        // SAFETY: `tp` initialized after boot; cpu_id is a pure read.
        let cpu_id = unsafe { crate::arch::riscv64::percpu::current_percpu().cpu_id() };
        if cpu_id == 0 {
            crate::audit::drain::drain_tick();
            crate::policy::expire_pending_queries();
        }
    }

    // Tick scheduler and potentially switch tasks
    if let Some(mut sched_guard) = crate::local_scheduler().try_lock() {
        if let Some(sched) = sched_guard.as_mut() {
            // Wake any tasks blocked on the timer IRQ (IoWait(0))
            sched.wake_irq_waiters(0);

            let new_rsp = sched.isr_tick_and_schedule(current_rsp);

            if new_rsp != current_rsp {
                // Context switch occurred — collect platform hint
                let hint = sched.current_task_ref().map(|task| {
                    let page_table_root = if task.cr3 != 0 {
                        task.cr3
                    } else {
                        crate::kernel_cr3()
                    };
                    ContextSwitchHint {
                        kernel_stack_top: task.kernel_stack_top,
                        page_table_root,
                    }
                });
                (new_rsp, hint)
            } else {
                (current_rsp, None)
            }
        } else {
            (current_rsp, None)
        }
    } else {
        (current_rsp, None) // Lock contention — skip this tick
    }
}

/// Voluntary yield handler: save context and schedule next task.
///
/// Unlike `on_timer_isr`, this:
/// - Uses regular lock (not try_lock) — caller must not hold the scheduler lock
/// - Always saves current_rsp (even for Blocked/Terminated tasks)
/// - Does not tick the timer or wake IRQ waiters
/// - Does not send EOI (no hardware interrupt to acknowledge)
///
/// Called from `yield_save_and_switch` (assembly trampoline) with interrupts
/// disabled. The caller built a synthetic SavedContext on the kernel stack;
/// current_rsp points to it.
pub fn on_voluntary_yield(current_rsp: u64) -> (u64, Option<ContextSwitchHint>) {
    let mut sched_guard = crate::local_scheduler().lock();
    if let Some(sched) = sched_guard.as_mut() {
        let new_rsp = sched.voluntary_yield(current_rsp);

        if new_rsp != current_rsp {
            // Context switch occurred — collect platform hint
            let hint = sched.current_task_ref().map(|task| {
                let page_table_root = if task.cr3 != 0 {
                    task.cr3
                } else {
                    crate::kernel_cr3()
                };
                ContextSwitchHint {
                    kernel_stack_top: task.kernel_stack_top,
                    page_table_root,
                }
            });
            (new_rsp, hint)
        } else {
            (current_rsp, None)
        }
    } else {
        (current_rsp, None)
    }
}

/// SCAFFOLDING: maximum number of tasks per CPU.
/// Why: heap-allocated per-CPU; raised from 32 to support multi-core workloads.
///      Per-priority ready queues keep scheduling O(1) at this size.
/// Replace when: a single CPU is regularly seeing > 100 active tasks, or AI
///      inference services start spawning per-request worker tasks. Must stay
///      in sync with the `MAX_TASKS` re-export in lib.rs and `TASK_CPU_MAP`'s
///      array size. See docs/ASSUMPTIONS.md.
const MAX_TASKS: usize = 256;

/// ARCHITECTURAL: priority taxonomy is 4 bands — Idle / Low / Normal / High+Critical.
///
/// Band mapping: priority / 64 → band index (0..3).
///   Band 0: IDLE (priority 0-63)
///   Band 1: LOW  (priority 64-127)
///   Band 2: NORMAL (priority 128-191)
///   Band 3: HIGH + CRITICAL (priority 192-255)
const NUM_PRIORITY_BANDS: usize = 4;

/// Map a task priority to a ready-queue band index.
fn priority_to_band(p: Priority) -> usize {
    (p.0 as usize / 64).min(NUM_PRIORITY_BANDS - 1)
}

/// Scheduler state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerState {
    Uninitialized,
    Initialized,
    Running,
    Paused,
}

/// Priority-aware task scheduler with per-band ready queues.
///
/// Invariants:
/// - Exactly one task is Running (tracked by `current_task`)
/// - Ready tasks are enqueued in their priority band's VecDeque
/// - Timer ticks decrement `time_remaining` on the running task
/// - `runnable_count` tracks non-idle Ready + Running tasks
///
/// The task array is heap-allocated (Vec) so MAX_TASKS can scale without
/// risking stack overflow. Ready queues provide O(1) scheduling by popping
/// from the highest non-empty band.
pub struct Scheduler {
    /// All tasks indexed by TaskId (heap-allocated)
    tasks: Vec<Option<Task>>,
    /// Per-priority-band ready queues. Band 3 (highest) checked first.
    /// Uses lazy removal: stale entries (Blocked/Terminated) are skipped on pop.
    ready_queues: [VecDeque<TaskId>; NUM_PRIORITY_BANDS],
    /// Number of active tasks (present in the tasks array)
    task_count: usize,
    /// Number of non-idle runnable tasks (Ready + Running, excluding idle task 0)
    runnable_count: usize,
    /// Currently running task ID
    current_task: Option<TaskId>,
    /// Number of scheduler ticks
    total_ticks: u64,
    /// Scheduler state
    state: SchedulerState,
}

impl Scheduler {
    /// Create a new scheduler.
    ///
    /// The task Vec and ready-queue VecDeques are heap-allocated, so only
    /// ~128 bytes of Scheduler metadata lands on the stack. Safe for
    /// 256KB boot stacks even at MAX_TASKS=256+.
    pub fn new() -> Self {
        Scheduler {
            tasks: {
                let mut v = Vec::with_capacity(MAX_TASKS);
                v.resize_with(MAX_TASKS, || None);
                v
            },
            ready_queues: [
                VecDeque::with_capacity(MAX_TASKS),
                VecDeque::with_capacity(MAX_TASKS),
                VecDeque::with_capacity(MAX_TASKS),
                VecDeque::with_capacity(MAX_TASKS),
            ],
            task_count: 0,
            runnable_count: 0,
            current_task: None,
            total_ticks: 0,
            state: SchedulerState::Uninitialized,
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self { Self::new() }
}

impl Scheduler {
    /// Heap-allocate a Scheduler directly.
    ///
    /// Equivalent to `Box::new(Scheduler::new())` but makes the intent
    /// explicit: the Vec/VecDeque internals are on the heap, and the
    /// Scheduler metadata struct (~128 bytes) passes through the stack
    /// only briefly during the Box move.
    pub fn new_boxed() -> Box<Self> {
        Box::new(Self::new())
    }

    /// Initialize scheduler with idle task
    pub fn init(&mut self) -> Result<(), ScheduleError> {
        // Create idle task (always runnable, lowest priority)
        // Idle task MUST be always ready to service: blocking requires a ready task to exist.
        let mut idle_task = Task::new(
            TaskId::IDLE,
            0x100000,  // Placeholder entry point (idle task runs kmain's loop)
            0x200000,  // Placeholder stack (idle uses boot stack)
            Priority::IDLE,
        );
        // Mark idle task as Running since it IS executing right now (kmain)
        idle_task.state = TaskState::Running;

        self.tasks[0] = Some(idle_task);
        self.task_count = 1;
        self.current_task = Some(TaskId::IDLE);
        self.state = SchedulerState::Running;

        Ok(())
    }

    /// Create and add a new task
    pub fn create_task(
        &mut self,
        entry_point: u64,
        stack_pointer: u64,
        priority: Priority,
    ) -> Result<TaskId, ScheduleError> {
        // Find first free slot (skip slot 0 = idle task)
        let slot = (1..MAX_TASKS)
            .find(|&i| self.tasks[i].is_none())
            .ok_or(ScheduleError::NoReadyTasks)?;

        let task_id = TaskId::new(slot as u32, crate::task_generation(slot as u32));
        let mut task = Task::new(task_id, entry_point, stack_pointer, priority);
        task.in_ready_queue = true;

        let band = priority_to_band(priority);
        self.tasks[slot] = Some(task);
        self.task_count += 1;
        self.runnable_count += 1;
        self.ready_queues[band].push_back(task_id);

        Ok(task_id)
    }

    /// Create a task with a pre-initialized kernel stack for ISR-driven context switching
    ///
    /// The caller must allocate a kernel stack, set up an initial SavedContext
    /// on it, and pass the resulting saved_rsp. On first dispatch via iretq,
    /// the task starts at entry_point with RSP = stack_top.
    pub fn create_isr_task(
        &mut self,
        entry_point: u64,
        saved_rsp: u64,
        stack_top: u64,
        priority: Priority,
    ) -> Result<TaskId, ScheduleError> {
        // Find first free slot (skip slot 0 = idle task)
        let slot = (1..MAX_TASKS)
            .find(|&i| self.tasks[i].is_none())
            .ok_or(ScheduleError::NoReadyTasks)?;

        let task_id = TaskId::new(slot as u32, crate::task_generation(slot as u32));
        let mut task = Task::new_with_stack(task_id, entry_point, saved_rsp, stack_top, priority);
        task.in_ready_queue = true;

        let band = priority_to_band(priority);
        self.tasks[slot] = Some(task);
        self.task_count += 1;
        self.runnable_count += 1;
        self.ready_queues[band].push_back(task_id);

        Ok(task_id)
    }

    /// Handle a timer tick - check if current task's time slice expired
    pub fn tick(&mut self) -> Option<TaskId> {
        self.total_ticks += 1;

        // Decrement time remaining on current task
        if let Some(task_id) = self.current_task {
            if let Some(task) = self.get_task_mut(task_id) {
                task.tick();
            }
        }

        // Check if time slice expired
        if self.time_slice_expired() {
            Some(self.current_task.unwrap_or(TaskId::IDLE))
        } else {
            None
        }
    }

    /// Check if current task's time slice has expired
    fn time_slice_expired(&self) -> bool {
        if let Some(task_id) = self.current_task {
            if let Some(task) = self.get_task(task_id) {
                // Force reschedule if current task is no longer Running
                // (e.g., terminated via SYS_EXIT or killed by page fault)
                if task.state != TaskState::Running {
                    return true;
                }
                return task.time_slice_expired();
            }
        }
        false
    }

    /// Perform a context switch - select next ready task by priority
    ///
    /// Transitions scheduler to Running state on first invocation.
    pub fn schedule(&mut self) -> Result<TaskId, ScheduleError> {
        // Save current task state — push to ready queue if it was Running
        if let Some(task_id) = self.current_task {
            // Extract priority before mutating, to avoid overlapping borrows
            let enqueue_band = {
                if let Some(task) = self.tasks.get_mut(task_id.slot() as usize).and_then(|t| t.as_mut()) {
                    if task.state == TaskState::Running {
                        task.state = TaskState::Ready;
                        task.reset_time_slice();
                        if !task.in_ready_queue {
                            task.in_ready_queue = true;
                            Some(priority_to_band(task.priority))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(band) = enqueue_band {
                self.ready_queues[band].push_back(task_id);
            }
        }

        // Find next ready task (O(1) via priority queues)
        let next_task = self.find_next_ready_task()?;

        // Update task state
        if let Some(task) = self.get_task_mut(next_task) {
            task.state = TaskState::Running;
            task.schedule_count += 1;
        }

        self.current_task = Some(next_task);

        // Transition to Running state on first schedule
        if self.state == SchedulerState::Initialized {
            self.state = SchedulerState::Running;
        }

        Ok(next_task)
    }

    /// Find the next ready task using per-priority-band queues — O(1) amortized.
    ///
    /// Pops from the highest non-empty band. Stale entries (tasks that were
    /// blocked/terminated since being enqueued) are lazily skipped.
    /// Round-robin within each band is automatic: push_back on enqueue,
    /// pop_front on schedule.
    fn find_next_ready_task(&mut self) -> Result<TaskId, ScheduleError> {
        // Check bands from highest (3) to lowest (0)
        for band in (0..NUM_PRIORITY_BANDS).rev() {
            while let Some(tid) = self.ready_queues[band].pop_front() {
                let idx = tid.slot() as usize;
                if let Some(Some(task)) = self.tasks.get_mut(idx) {
                    if task.state == TaskState::Ready {
                        task.in_ready_queue = false;
                        return Ok(tid);
                    }
                    // Stale entry — task was blocked/terminated since enqueuing
                    task.in_ready_queue = false;
                }
            }
        }

        // Fallback: idle task (always ready as last resort)
        if let Some(Some(task)) = self.tasks.first() {
            if task.state == TaskState::Ready {
                return Ok(TaskId::IDLE);
            }
        }

        Err(ScheduleError::NoReadyTasks)
    }

    /// Get current running task id
    pub fn current_task(&self) -> Option<TaskId> {
        self.current_task
    }

    /// Get a reference to the current running task
    pub fn current_task_ref(&self) -> Option<&Task> {
        self.current_task.and_then(|id| self.get_task(id))
    }

    /// ISR-driven tick and schedule: called from the timer ISR inner handler.
    ///
    /// Saves the interrupted task's RSP, decrements its time slice, and if
    /// expired, performs a schedule and returns the new task's saved RSP.
    /// If no switch is needed, returns the same RSP.
    ///
    /// After `schedule()`, `next_task` is the post-switch current task — i.e.
    /// `self.current_task` has already been updated to `next_task`, so we read
    /// `saved_rsp` from the correct (incoming) task.
    ///
    /// This method combines tick + schedule into a single call for the ISR
    /// hot path, avoiding multiple lock acquisitions.
    ///
    /// # Safety contract
    /// Must only be called from ISR context with interrupts disabled (inside
    /// the timer ISR stub), since it mutates task state without additional
    /// locking beyond the Spinlock already held by the caller.
    pub fn isr_tick_and_schedule(&mut self, current_rsp: u64) -> u64 {
        self.total_ticks += 1;

        // Save current task's context RSP and tick its time slice.
        // Only save RSP for Running tasks — Blocked/Terminated tasks have a
        // synthetic SavedContext on their kernel stack that must be preserved
        // so they resume correctly when woken/re-scheduled.
        if let Some(task_id) = self.current_task {
            if let Some(task) = self.get_task_mut(task_id) {
                if task.state == TaskState::Running {
                    task.saved_rsp = current_rsp;
                }
                task.tick();
            }
        }

        // ADR-027 Phase 1 quiesce hook: if the current task has a pending
        // channel-quiesce hint, park it into Blocked(ChannelQuiesceWait)
        // before scheduling. Forces schedule() even when the time slice
        // hasn't expired — the parked task is no longer Running and must
        // not stay current.
        let quiesced = self.try_park_current_for_quiesce();

        // Check if time slice expired (or quiesce hook just parked the task)
        if !quiesced && !self.time_slice_expired() {
            return current_rsp; // No switch needed
        }

        // Time slice expired — select next task
        match self.schedule() {
            Ok(next_task) => {
                if let Some(task) = self.get_task(next_task) {
                    let rsp = task.saved_rsp;
                    if rsp == 0 {
                        crate::println!(
                            "\n!!! ZERO RSP: schedule picked task {} (state={:?}, kstack_top={:#x}, saved_rsp=0) !!!",
                            next_task.slot(), task.state, task.kernel_stack_top
                        );
                    }
                    rsp
                } else {
                    current_rsp // Shouldn't happen
                }
            }
            Err(_) => current_rsp, // Schedule failed, keep current
        }
    }

    /// Voluntary context switch — called from `on_voluntary_yield`.
    ///
    /// Always saves `current_rsp` to `task.saved_rsp`, regardless of task state.
    /// This is critical: the caller built a synthetic SavedContext on the kernel
    /// stack that must be preserved. Unlike `isr_tick_and_schedule`, which skips
    /// Blocked tasks (to preserve earlier synthetic contexts), this function
    /// always overwrites because the caller IS the one building the context.
    ///
    /// Unconditionally calls `schedule()` to select the next task.
    pub fn voluntary_yield(&mut self, current_rsp: u64) -> u64 {
        // Always save RSP — the caller built a SavedContext that must be
        // preserved for correct resumption regardless of task state.
        if let Some(task_id) = self.current_task {
            if let Some(task) = self.get_task_mut(task_id) {
                task.saved_rsp = current_rsp;
            }
        }

        // ADR-027 Phase 1 quiesce hook: park the current task into
        // Blocked(ChannelQuiesceWait) if its pending hint is set and
        // it's still Running. No-op if a syscall handler already
        // transitioned the task to Blocked (e.g. handle_recv_msg —
        // the existing block reason wins).
        self.try_park_current_for_quiesce();

        // Select next task
        match self.schedule() {
            Ok(next_task) => {
                if let Some(task) = self.get_task(next_task) {
                    let rsp = task.saved_rsp;
                    if rsp == 0 {
                        crate::println!(
                            "\n!!! ZERO RSP in voluntary_yield: task {} (state={:?}) !!!",
                            next_task.slot(), task.state
                        );
                    }
                    rsp
                } else {
                    current_rsp
                }
            }
            Err(_) => current_rsp, // No other task to run — resume current
        }
    }

    /// Get task by ID — O(1) slot indexing, then generation-validated.
    ///
    /// A `TaskId` whose slot was reclaimed and reused (the reaper bumped the
    /// generation, ADR-034 Phase B) mismatches the live task's generation and
    /// resolves to `None` rather than the new occupant — this is what closes
    /// the `SYS_WAIT_TASK` use-after-free as a structural class, at every
    /// lookup, not just one call site. (Today all generations are 0, so this
    /// is a no-op until the reaper starts bumping.)
    fn get_task(&self, id: TaskId) -> Option<&Task> {
        let task = self.tasks.get(id.slot() as usize)?.as_ref()?;
        if task.id.generation() == id.generation() { Some(task) } else { None }
    }

    /// Get mutable task by ID — O(1) slot indexing, then generation-validated
    /// (see [`Scheduler::get_task`]).
    fn get_task_mut(&mut self, id: TaskId) -> Option<&mut Task> {
        let task = self.tasks.get_mut(id.slot() as usize)?.as_mut()?;
        if task.id.generation() == id.generation() { Some(task) } else { None }
    }

    /// Public mutable task accessor (for setting process_id/CR3 after creation)
    pub fn get_task_mut_pub(&mut self, id: TaskId) -> Option<&mut Task> {
        self.get_task_mut(id)
    }

    /// Public read-only task accessor (for migration planning / diagnostics).
    pub fn get_task_pub(&self, id: TaskId) -> Option<&Task> {
        self.get_task(id)
    }

    /// Get scheduler statistics
    pub fn stats(&self) -> SchedulerStats {
        SchedulerStats {
            total_ticks: self.total_ticks,
            active_tasks: self.task_count,
            current_task: self.current_task,
            state: self.state,
        }
    }

    /// Block a task with the given reason
    ///
    /// Moves task from Running or Ready to Blocked state.
    /// If blocking the current running task, immediately reschedules.
    ///
    /// CRITICAL: Idle task (TaskId::0) MUST remain ready at all times.
    /// Blocking the idle task is a fatal error—it cuts off the fallback
    /// task that schedule() relies on to avoid NoReadyTasks.
    pub fn block_task(&mut self, task_id: TaskId, reason: BlockReason) -> Result<(), ScheduleError> {
        // Blocking pattern invariant (CLAUDE.md § Timer / Preemptive
        // Scheduling): interrupts must be disabled before block_task, or
        // the timer ISR can see Blocked state before yield saves the
        // correct context. Host stub returns false so this passes under
        // `cargo test --lib`.
        debug_assert!(
            !crate::arch::interrupts_enabled(),
            "block_task called with interrupts enabled — see CLAUDE.md blocking pattern",
        );
        // Safety check: never block idle task
        if task_id.is_idle() {
            return Err(ScheduleError::InvalidTaskState);
        }

        if let Some(task) = self.get_task_mut(task_id) {
            // Can only block Running or Ready tasks
            if task.state != TaskState::Running && task.state != TaskState::Ready {
                return Err(ScheduleError::InvalidTaskState);
            }

            task.state = TaskState::Blocked;
            task.block_reason = Some(reason);
            // in_ready_queue left as-is; stale entry cleaned lazily on pop
            self.runnable_count = self.runnable_count.saturating_sub(1);

            // The actual context switch is performed by the caller (e.g.,
            // suspend_to_kernel_stack in the syscall handler, or the timer
            // ISR detecting a non-Running current_task). Calling schedule()
            // here would change current_task without switching contexts,
            // desynchronizing the scheduler from the running CPU.
            Ok(())
        } else {
            Err(ScheduleError::TaskNotFound)
        }
    }

    /// Arm the per-channel quiesce protocol on a peer task (ADR-027 Phase 1).
    ///
    /// Called by the syscall handler that begins a channel teardown
    /// (`begin_teardown` returning `TeardownStart::Quiesce`) to make
    /// sure the peer task is not running on any CPU before the kernel
    /// unmaps its channel pages.
    ///
    /// Behavior depends on the task's current state:
    /// - `Running`: sets `pending_quiesce_channel = Some(channel_id_raw)`.
    ///   The scheduler hook (`try_park_current_for_quiesce`) parks the
    ///   task at next ISR tick or voluntary yield (≤ one tick = 10ms
    ///   at 100 Hz). Returns `PendingOnYield`.
    /// - `Ready`: parks synchronously into
    ///   `Blocked(ChannelQuiesceWait(channel_id_raw))`. Returns
    ///   `ParkedNow`. The hint field is left `None` because the task
    ///   never reaches the hook.
    /// - `Blocked` / `Terminated` / `Suspended`: no state change.
    ///   Returns `AlreadyOffCpu`. The task's existing block reason is
    ///   preserved (a peer already blocked on `MessageWait` etc. is
    ///   already off-CPU; the kernel's unmap is safe).
    ///
    /// Errors:
    /// - `TaskNotFound`: no task at that slot.
    /// - `InvalidTaskState`: caller passed `TaskId(0)` (idle task —
    ///   never blockable per `block_task`'s contract).
    ///
    /// `channel_id_raw` is `ChannelId::as_raw()`. Untyped here so this
    /// module stays free of `crate::ipc::channel` imports.
    pub fn arm_quiesce(
        &mut self,
        task_id: TaskId,
        channel_id_raw: u64,
    ) -> Result<QuiesceArmResult, ScheduleError> {
        if task_id.is_idle() {
            return Err(ScheduleError::InvalidTaskState);
        }
        let task = self.get_task_mut(task_id).ok_or(ScheduleError::TaskNotFound)?;
        match task.state {
            TaskState::Running => {
                task.pending_quiesce_channel = Some(channel_id_raw);
                Ok(QuiesceArmResult::PendingOnYield)
            }
            TaskState::Ready => {
                task.state = TaskState::Blocked;
                task.block_reason = Some(BlockReason::ChannelQuiesceWait(channel_id_raw));
                task.pending_quiesce_channel = None;
                // in_ready_queue left as-is; stale entry cleaned lazily on pop
                // (matches block_task's invariant).
                self.runnable_count = self.runnable_count.saturating_sub(1);
                Ok(QuiesceArmResult::ParkedNow)
            }
            TaskState::Blocked | TaskState::Terminated | TaskState::Suspended => {
                Ok(QuiesceArmResult::AlreadyOffCpu)
            }
        }
    }

    /// Find the `TaskId` of a task whose `process_id` matches the
    /// given `ProcessId`, if one is owned by this CPU's scheduler.
    ///
    /// Used by the cross-CPU `lib::arm_quiesce_for_process` helper to
    /// locate a peer task by its `ChannelRecord::peer_pid` without
    /// maintaining a global pid→task map. The kernel's task↔process
    /// linkage is 1:1 today, so the first match is the only match.
    /// O(MAX_TASKS) scan; called from the slow path
    /// (`SYS_CHANNEL_REVOKE`, process exit).
    pub fn find_task_for_process(
        &self,
        process_id: crate::ipc::ProcessId,
    ) -> Option<TaskId> {
        self.tasks.iter().find_map(|slot| {
            let task = slot.as_ref()?;
            if task.process_id == Some(process_id) {
                Some(task.id)
            } else {
                None
            }
        })
    }

    /// Combined lookup-and-arm: find the task owned by `process_id`
    /// in this scheduler, then call [`arm_quiesce`] on it. Returns
    /// `None` if no task in this scheduler matches.
    ///
    /// Both the lookup and the arm happen under the caller's already-
    /// held scheduler lock, so the task cannot be migrated or removed
    /// between the two steps.
    pub fn arm_quiesce_for_process(
        &mut self,
        process_id: crate::ipc::ProcessId,
        channel_id_raw: u64,
    ) -> Option<(TaskId, QuiesceArmResult)> {
        let task_id = self.find_task_for_process(process_id)?;
        let result = self.arm_quiesce(task_id, channel_id_raw).ok()?;
        Some((task_id, result))
    }

    /// Wake any task parked in `Blocked(ChannelQuiesceWait(channel_id_raw))`
    /// (ADR-027 Phase 1).
    ///
    /// Companion to [`arm_quiesce`]: when a `complete_teardown` finishes
    /// and the channel slot is gone, any peer that voluntarily acked via
    /// `SYS_CHANNEL_QUIESCE_ACK` (or that the scheduler hook parked at
    /// next ISR) must be moved back to `Ready` so its syscall can return.
    /// Tasks blocked on different channels are left untouched.
    ///
    /// Mirror of [`wake_message_waiters`] — same scan, different match
    /// arm. Index-based and uncapped (see `wake_irq_waiters`); the prior
    /// 8-slot staging array would have silently dropped a 9th waiter once
    /// process↔task became 1:N.
    ///
    /// Returns the number of tasks woken.
    pub fn wake_quiesce(&mut self, channel_id_raw: u64) -> usize {
        let mut woken = 0;

        for i in 0..self.tasks.len() {
            let mut to_enqueue: Option<(TaskId, usize)> = None;
            if let Some(task) = self.tasks[i].as_mut() {
                let matches = task.state == TaskState::Blocked
                    && matches!(
                        task.block_reason,
                        Some(BlockReason::ChannelQuiesceWait(c)) if c == channel_id_raw
                    );
                if matches {
                    task.state = TaskState::Ready;
                    task.block_reason = None;
                    task.pending_quiesce_channel = None;
                    task.reset_time_slice();
                    if !task.in_ready_queue {
                        task.in_ready_queue = true;
                        to_enqueue = Some((task.id, priority_to_band(task.priority)));
                    }
                    woken += 1;
                }
            }
            if let Some((tid, band)) = to_enqueue {
                self.ready_queues[band].push_back(tid);
            }
        }

        self.runnable_count += woken;
        woken
    }

    /// Scheduler hook fired from `isr_tick_and_schedule` and
    /// `voluntary_yield` (ADR-027 Phase 1).
    ///
    /// If the current task has a pending channel-quiesce hint AND is
    /// still `Running` (i.e. has not already been transitioned to
    /// `Blocked` by the syscall handler that's calling us), park it
    /// into `Blocked(ChannelQuiesceWait(id))`. Returns `true` if the
    /// task was parked — the caller must force a `schedule()` because
    /// the early-return based on time-slice is no longer correct.
    fn try_park_current_for_quiesce(&mut self) -> bool {
        let task_id = match self.current_task {
            Some(id) => id,
            None => return false,
        };
        // Idle task is never quiesced; defensive guard mirroring
        // block_task's TaskId(0) gate.
        if task_id.is_idle() {
            return false;
        }
        let task = match self.get_task_mut(task_id) {
            Some(t) => t,
            None => return false,
        };
        let channel = match task.pending_quiesce_channel.take() {
            Some(c) => c,
            None => return false,
        };
        if task.state != TaskState::Running {
            // Already blocked / terminated / suspended via another path
            // (handle_recv_msg, handle_exit, …). Hint cleared above; the
            // task's existing block_reason is preserved — a peer parked
            // on MessageWait is already off-CPU and the kernel's unmap
            // is safe; no need to overwrite the wake-path block reason
            // with ChannelQuiesceWait.
            return false;
        }
        task.state = TaskState::Blocked;
        task.block_reason = Some(BlockReason::ChannelQuiesceWait(channel));
        self.runnable_count = self.runnable_count.saturating_sub(1);
        true
    }

    /// Wake a blocked task
    ///
    /// Moves task from Blocked to Ready state.
    /// Returns the task ID of the task that was woken.
    pub fn wake_task(&mut self, task_id: TaskId) -> Result<TaskId, ScheduleError> {
        let band = {
            let task = self.get_task_mut(task_id).ok_or(ScheduleError::TaskNotFound)?;
            if task.state != TaskState::Blocked {
                return Err(ScheduleError::InvalidTaskState);
            }

            task.state = TaskState::Ready;
            task.block_reason = None;
            // ADR-027 Phase 1: clear any stale quiesce hint on every
            // Blocked → Ready transition. Defensive — if a Running task's
            // hint was set and the task transitioned to Blocked via a
            // different path (e.g., handle_recv_msg → MessageWait), the
            // hint outlives the parking attempt and would re-park the
            // task on the next Running run. Cleared here so post-wake
            // execution is hint-free regardless of the wake source.
            task.pending_quiesce_channel = None;
            task.reset_time_slice();
            let b = priority_to_band(task.priority);
            if !task.in_ready_queue {
                task.in_ready_queue = true;
                Some(b)
            } else {
                None
            }
        };

        if let Some(b) = band {
            self.ready_queues[b].push_back(task_id);
        }
        if !task_id.is_idle() {
            self.runnable_count += 1;
        }

        Ok(task_id)
    }

    /// Wake all tasks blocked on a specific hardware IRQ.
    ///
    /// Scans for tasks with `BlockReason::IoWait(irq)` and moves them from
    /// Blocked → Ready.  Called from ISR context when a hardware interrupt
    /// fires (e.g., timer ISR for IRQ 0, future I/O APIC handlers for
    /// device IRQs).
    ///
    /// Returns the number of tasks woken.
    pub fn wake_irq_waiters(&mut self, irq: u32) -> usize {
        // Index-based scan: mutate `self.tasks[i]` then push into
        // `self.ready_queues[band]` in disjoint, sequential field borrows.
        // This replaces a fixed 32-slot staging array whose overflow path
        // marked the 33rd+ matching task `Ready` + `in_ready_queue = true`
        // but never enqueued it — a permanent lost wakeup (and a broken
        // `in_ready_queue ⇔ present-in-a-ready-queue` invariant) once more
        // than 32 tasks blocked on one IRQ. There is no cap now.
        let mut woken = 0;

        for i in 0..self.tasks.len() {
            let mut to_enqueue: Option<(TaskId, usize)> = None;
            if let Some(task) = self.tasks[i].as_mut() {
                if task.state == TaskState::Blocked {
                    if let Some(BlockReason::IoWait(waiting_irq)) = task.block_reason {
                        if waiting_irq == irq {
                            task.state = TaskState::Ready;
                            task.block_reason = None;
                            task.pending_quiesce_channel = None; // ADR-027 hint cleanup
                            task.reset_time_slice();
                            if !task.in_ready_queue {
                                task.in_ready_queue = true;
                                to_enqueue = Some((task.id, priority_to_band(task.priority)));
                            }
                            woken += 1;
                        }
                    }
                }
            }
            if let Some((tid, band)) = to_enqueue {
                self.ready_queues[band].push_back(tid);
            }
        }

        self.runnable_count += woken;
        woken
    }

    /// Wake all tasks blocked waiting for a message on a specific endpoint.
    ///
    /// Scans for tasks with `BlockReason::MessageWait(endpoint)` and moves
    /// them from Blocked → Ready. Called from the IPC send path after a
    /// message is enqueued, so the receiver can pick it up.
    ///
    /// Returns the number of tasks woken.
    pub fn wake_message_waiters(&mut self, endpoint: u32) -> usize {
        // Index-based, uncapped: see `wake_irq_waiters` for why the prior
        // fixed 32-slot staging array dropped the 33rd+ waiter. A popular
        // service endpoint can have well over 32 receivers blocked on it.
        let mut woken = 0;

        for i in 0..self.tasks.len() {
            let mut to_enqueue: Option<(TaskId, usize)> = None;
            if let Some(task) = self.tasks[i].as_mut() {
                if task.state == TaskState::Blocked {
                    if let Some(BlockReason::MessageWait(ep)) = task.block_reason {
                        if ep == endpoint {
                            task.state = TaskState::Ready;
                            task.block_reason = None;
                            task.pending_quiesce_channel = None; // ADR-027 hint cleanup
                            task.reset_time_slice();
                            if !task.in_ready_queue {
                                task.in_ready_queue = true;
                                to_enqueue = Some((task.id, priority_to_band(task.priority)));
                            }
                            woken += 1;
                        }
                    }
                }
            }
            if let Some((tid, band)) = to_enqueue {
                self.ready_queues[band].push_back(tid);
            }
        }

        self.runnable_count += woken;
        woken
    }

    /// Find all tasks blocked on a specific endpoint (for message delivery)
    ///
    /// Scans all tasks and returns the highest-priority task awaiting
    /// messages on the given endpoint, if any.
    pub fn find_highest_priority_receiver(&self, endpoint: u32) -> Option<TaskId> {
        let mut highest_priority_task: Option<(TaskId, Priority)> = None;

        for task in self.tasks.iter().flatten() {
            if task.state == TaskState::Blocked {
                if let Some(BlockReason::MessageWait(ep)) = task.block_reason {
                    if ep == endpoint {
                        if let Some((_, current_priority)) = highest_priority_task {
                            if task.priority > current_priority {
                                highest_priority_task = Some((task.id, task.priority));
                            }
                        } else {
                            highest_priority_task = Some((task.id, task.priority));
                        }
                    }
                }
            }
        }

        highest_priority_task.map(|(id, _)| id)
    }

    /// Verify scheduler invariants.
    ///
    /// Uses `current_task` directly instead of scanning all tasks — O(1).
    pub fn verify_invariants(&self) -> Result<(), &'static str> {
        // Verify current_task exists and is Running
        match self.current_task {
            Some(task_id) => {
                match self.get_task(task_id) {
                    Some(task) if task.state == TaskState::Running => Ok(()),
                    Some(_) => Err("Scheduler invariant: current task not in Running state"),
                    None => Err("Scheduler invariant: current task id not found"),
                }
            }
            None => Err("Scheduler invariant: no current task set"),
        }
    }

    /// Perform real CPU context switch (jumps to next task, never returns)
    ///
    /// This function performs the actual x86-64 context switch:
    /// 1. Saves current task's CPU context (registers, RIP, RSP, RFLAGS)
    /// 2. Restores next task's CPU context
    /// 3. Jumps to next task's instruction pointer
    ///
    /// ## Usage
    /// This is for **explicit** (non-interrupt) context switches: voluntary yields,
    /// blocking syscalls, etc. For interrupt-driven preemption, the timer ISR
    /// (interrupts::timer_interrupt_handler) handles scheduling directly.
    ///
    /// ## Safety
    /// - Both task IDs must be valid
    /// - `from_task` must have its context saved before this call
    /// - `to_task` must have a valid, initialized CpuContext
    /// - This function does NOT return to the caller
    pub unsafe fn perform_context_switch(&mut self, from_task: TaskId, to_task: TaskId) -> ! {
        // Get mutable references to both task contexts
        let current_ctx = if let Some(task) = self.get_task_mut(from_task) {
            &mut task.context as *mut CpuContext
        } else {
            crate::halt();
        };

        let next_ctx = if let Some(task) = self.get_task(to_task) {
            &task.context as *const CpuContext
        } else {
            crate::halt();
        };

        // SAFETY: Both task contexts are valid — from_task was just saved,
        // to_task was initialized at creation. context_switch is an extern "C"
        // assembly function that saves/restores register state.
        unsafe { crate::arch::context_switch(current_ctx, next_ctx) };
    }

    /// Purge every scheduler-held reference to `task_id`.
    ///
    /// Called by the task-exit path (`handle_exit`) to establish the
    /// invariant that by the time the final `yield_save_and_switch` lets
    /// control return to `schedule()`, the scheduler contains zero
    /// references to the exiting task's TaskId.
    ///
    /// Before this helper existed, `handle_exit` relied on marking the
    /// task `Terminated` (but leaving it in the `tasks` array) and
    /// letting `find_next_ready_task`'s lazy-pop clean up ready-queue
    /// entries, while leaving `current_task` pointing at the exiting
    /// TaskId. Under concurrent teardown that left a window where the
    /// scheduler could dereference through the exiting task's slot in
    /// an inconsistent state.
    ///
    /// This helper closes that window by:
    /// - Clearing `current_task` if it matches — the scheduler now has
    ///   no current task on this CPU until the next `schedule()` picks
    ///   one (which will skip the `current_task` re-enqueue path
    ///   entirely because `current_task` is `None`).
    /// - Walking every priority band's ready queue and evicting any
    ///   entry equal to `task_id`. No more stale pops to worry about.
    /// - Clearing `task.in_ready_queue` on the slot itself so any
    ///   future re-enqueue sees a consistent starting state.
    /// - Decrementing `runnable_count` if the task was in a Ready state,
    ///   matching the bookkeeping `remove_task` does for the same
    ///   reason.
    ///
    /// Does NOT remove the task from the `tasks` array — `handle_exit`'s
    /// downstream cleanup path uses the task's state (process_id,
    /// parent_task, exit_code, kernel_stack_top) after calling this
    /// helper, and slot reuse is handled elsewhere.
    pub fn purge_task(&mut self, task_id: TaskId) {
        if self.current_task == Some(task_id) {
            self.current_task = None;
        }
        for band in 0..NUM_PRIORITY_BANDS {
            self.ready_queues[band].retain(|&tid| tid != task_id);
        }
        let idx = task_id.slot() as usize;
        if let Some(Some(task)) = self.tasks.get_mut(idx) {
            if task.in_ready_queue {
                task.in_ready_queue = false;
            }
            if task.state == TaskState::Ready {
                self.runnable_count = self.runnable_count.saturating_sub(1);
            }
        }
    }

    // ========================================================================
    // Task migration primitives
    // ========================================================================

    /// Remove a task from this scheduler's run queue, returning it.
    ///
    /// The task must be in Ready or Blocked state. Cannot remove the idle task
    /// (slot 0) or the currently running task.
    pub fn remove_task(&mut self, task_id: TaskId) -> Result<Task, ScheduleError> {
        // Never remove idle task
        if task_id.is_idle() {
            return Err(ScheduleError::InvalidTaskState);
        }
        // Cannot remove the currently running task
        if self.current_task == Some(task_id) {
            return Err(ScheduleError::InvalidTaskState);
        }

        let idx = task_id.slot() as usize;
        if idx >= self.tasks.len() {
            return Err(ScheduleError::TaskNotFound);
        }

        match self.tasks[idx].take() {
            Some(task) => {
                if task.state == TaskState::Running {
                    // Put it back — shouldn't remove Running tasks
                    self.tasks[idx] = Some(task);
                    return Err(ScheduleError::InvalidTaskState);
                }
                if task.state == TaskState::Ready {
                    self.runnable_count = self.runnable_count.saturating_sub(1);
                    // Stale queue entry cleaned lazily on pop
                }
                self.task_count -= 1;
                Ok(task)
            }
            None => Err(ScheduleError::TaskNotFound),
        }
    }

    /// Accept a task from another scheduler (migration target).
    ///
    /// Places the task at its existing slot index (`task.id.slot()`). The
    /// slot must be free on this scheduler. Migration preserves the full
    /// `TaskId` (slot + generation) — identity is stable across CPUs.
    pub fn accept_task(&mut self, task: Task) -> Result<TaskId, ScheduleError> {
        if task.state == TaskState::Running {
            return Err(ScheduleError::InvalidTaskState);
        }

        let idx = task.id.slot() as usize;
        if idx >= self.tasks.len() {
            return Err(ScheduleError::TaskNotFound);
        }
        if self.tasks[idx].is_some() {
            return Err(ScheduleError::InvalidTaskState);
        }

        let task_id = task.id;
        let is_ready = task.state == TaskState::Ready;
        let band = priority_to_band(task.priority);
        self.tasks[idx] = Some(task);
        self.task_count += 1;

        // Enqueue Ready tasks into the appropriate priority band
        if is_ready {
            if let Some(t) = self.tasks[idx].as_mut() {
                t.in_ready_queue = true;
            }
            self.ready_queues[band].push_back(task_id);
            self.runnable_count += 1;
        }
        Ok(task_id)
    }

    /// Get task count (number of active tasks in this scheduler).
    pub fn task_count(&self) -> usize {
        self.task_count
    }

    /// Dump every task slot's (id, state, in_ready_queue flag) to serial.
    /// Diagnostic-only; used by the idle-loop heartbeat when chasing a
    /// scheduler bug.
    pub fn debug_dump_tasks(&self) {
        crate::println!(
            "    tasks.len={} task_count={} current_task={:?} runnable_count={}",
            self.tasks.len(), self.task_count, self.current_task, self.runnable_count,
        );
        // Bound iteration to the first MAX_TASKS = 256 legitimate slots;
        // any corruption past that tells us the Vec buffer overflowed.
        let bound = core::cmp::min(self.tasks.len(), 16);
        let mut found = 0;
        for idx in 0..bound {
            if let Some(task) = self.tasks.get(idx).and_then(|s| s.as_ref()) {
                crate::println!(
                    "    slot {}: id={} state={:?} in_q={} band={} saved_rsp={:#x}",
                    idx,
                    task.id.slot(),
                    task.state,
                    task.in_ready_queue,
                    priority_to_band(task.priority),
                    task.saved_rsp,
                );
                found += 1;
                if found >= self.task_count { break; }
            }
        }
        for band in (0..NUM_PRIORITY_BANDS).rev() {
            crate::print!("    ready_queue[band {}] len={}:", band, self.ready_queues[band].len());
            for tid in self.ready_queues[band].iter() {
                crate::print!(" {}", tid.slot());
            }
            crate::println!();
        }
    }

    /// Count non-idle runnable tasks (Ready + Running, excluding idle task 0).
    ///
    /// O(1) — maintained incrementally by state-transition methods.
    pub fn active_runnable_count(&self) -> usize {
        self.runnable_count
    }

    /// Pick a Ready non-idle task suitable for migration.
    ///
    /// Peeks into ready queues (highest band first) for a non-pinned task.
    /// Does not dequeue — the load balancer will remove via `remove_task()`.
    pub fn pick_migratable_task(&self) -> Option<TaskId> {
        for band in (0..NUM_PRIORITY_BANDS).rev() {
            for tid in self.ready_queues[band].iter() {
                let idx = tid.slot() as usize;
                if idx == 0 { continue; } // skip idle
                if let Some(Some(task)) = self.tasks.get(idx) {
                    if task.state == TaskState::Ready && !task.pinned {
                        return Some(*tid);
                    }
                }
            }
        }
        None
    }
}

/// Migrate a task between two schedulers (pure logic, no locking).
///
/// Removes the task from `src`, updates its `home_cpu`, and inserts it
/// into `dst`. Both schedulers must be mutable-borrowed by the caller.
pub fn migrate_task_between(
    src: &mut Scheduler,
    dst: &mut Scheduler,
    task_id: TaskId,
    dst_cpu: u16,
) -> Result<(), ScheduleError> {
    let mut task = src.remove_task(task_id)?;
    task.home_cpu = dst_cpu;
    dst.accept_task(task)?;
    // Update global task→CPU map (lock-free)
    #[cfg(not(test))]
    crate::set_task_cpu(task_id.slot(), dst_cpu);
    Ok(())
}

/// Migrate a task between per-CPU schedulers using global locking.
///
/// Acquires both CPU schedulers in ascending CPU-index order to prevent
/// deadlock, then moves the task from `from_cpu` to `to_cpu`.
///
/// The task must be in Ready or Blocked state.
#[cfg(not(test))]
pub fn migrate_task(
    task_id: TaskId,
    from_cpu: usize,
    to_cpu: usize,
) -> Result<(), ScheduleError> {
    if from_cpu == to_cpu {
        return Ok(());
    }
    if from_cpu >= crate::MAX_CPUS || to_cpu >= crate::MAX_CPUS {
        return Err(ScheduleError::TaskNotFound);
    }

    // Lock ordering: always acquire lower CPU index first
    let (first, second) = if from_cpu < to_cpu {
        (from_cpu, to_cpu)
    } else {
        (to_cpu, from_cpu)
    };

    let mut guard1 = crate::PER_CPU_SCHEDULER[first].lock();
    let mut guard2 = crate::PER_CPU_SCHEDULER[second].lock();

    let (src, dst) = if from_cpu < to_cpu {
        (guard1.as_mut(), guard2.as_mut())
    } else {
        (guard2.as_mut(), guard1.as_mut())
    };

    let src = src.ok_or(ScheduleError::TaskNotFound)?;
    let dst = dst.ok_or(ScheduleError::TaskNotFound)?;

    migrate_task_between(src, dst, task_id, to_cpu as u16)
}

impl fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Scheduler")
            .field("task_count", &self.task_count)
            .field("current_task", &self.current_task)
            .field("state", &self.state)
            .field("total_ticks", &self.total_ticks)
            .finish()
    }
}

/// Scheduler statistics
#[derive(Debug, Clone, Copy)]
pub struct SchedulerStats {
    pub total_ticks: u64,
    pub active_tasks: usize,
    pub current_task: Option<TaskId>,
    pub state: SchedulerState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        let scheduler = Scheduler::new();
        assert_eq!(scheduler.state, SchedulerState::Uninitialized);
    }

    #[test]
    fn test_scheduler_init() {
        let mut scheduler = Scheduler::new();
        let result = scheduler.init();
        assert!(result.is_ok());
        assert_eq!(scheduler.state, SchedulerState::Running);
        assert_eq!(scheduler.task_count, 1);
    }

    #[test]
    fn test_create_task() {
        let mut scheduler = Scheduler::new();
        scheduler.init().unwrap();

        let task_id = scheduler.create_task(0x100000, 0x200000, Priority::NORMAL);
        assert!(task_id.is_ok());
        assert_eq!(scheduler.task_count, 2);
    }

    #[test]
    fn test_wake_irq_waiters_wakes_matching() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();

        // Block on IRQ 0
        sched.block_task(tid, BlockReason::IoWait(0)).unwrap();
        assert_eq!(sched.get_task(tid).unwrap().state, TaskState::Blocked);

        // Wake IRQ 0 waiters
        let woken = sched.wake_irq_waiters(0);
        assert_eq!(woken, 1);
        assert_eq!(sched.get_task(tid).unwrap().state, TaskState::Ready);
        assert!(sched.get_task(tid).unwrap().block_reason.is_none());
    }

    /// Regression for the lost-wakeup bug (F3): the wake path used a fixed
    /// 32-slot staging array, so the 33rd+ task blocked on one IRQ was
    /// marked `Ready` + `in_ready_queue = true` but never pushed onto a
    /// ready queue — a permanent lost wakeup, since `find_next_ready_task`
    /// only pops from the queues and `in_ready_queue = true` blocks any
    /// later re-enqueue. Reproduced with N > 32 tasks in the realistic
    /// "blocked while off the ready queue" state (the state a task reaches
    /// by running — hence being dequeued — then blocking).
    #[test]
    fn wake_irq_waiters_enqueues_every_waiter_past_old_staging_cap() {
        const N: usize = 40;
        let mut sched = Scheduler::new();
        sched.init().unwrap();

        let mut tids = alloc::vec::Vec::new();
        for _ in 0..N {
            tids.push(
                sched
                    .create_task(0x100000, 0x200000, Priority::NORMAL)
                    .unwrap(),
            );
        }

        // Model each task as Blocked-on-IRQ-5 and *off* every ready queue
        // (`in_ready_queue == false`), as if it had been scheduled (and so
        // dequeued) and then blocked.
        for q in sched.ready_queues.iter_mut() {
            q.clear();
        }
        for &tid in &tids {
            let t = sched.get_task_mut(tid).unwrap();
            t.state = TaskState::Blocked;
            t.block_reason = Some(BlockReason::IoWait(5));
            t.in_ready_queue = false;
        }

        let woken = sched.wake_irq_waiters(5);
        assert_eq!(woken, N, "every blocked waiter reported woken");

        // Load-bearing assertion: every woken task is actually enqueued.
        // Pre-fix this is 32 (the staging cap); the remaining 8 stay
        // Ready-but-unschedulable, absent from all queues.
        let queued: usize = sched.ready_queues.iter().map(|q| q.len()).sum();
        assert_eq!(queued, N, "every woken task is on a ready queue (no lost wakeup)");

        // `in_ready_queue` ⇔ present-in-a-ready-queue holds for all N.
        for &tid in &tids {
            let t = sched.get_task(tid).unwrap();
            assert_eq!(t.state, TaskState::Ready);
            assert!(t.in_ready_queue, "woken task marked present-in-queue");
        }
    }

    #[test]
    fn test_wake_irq_waiters_ignores_different_irq() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();

        // Block on IRQ 1 (keyboard)
        sched.block_task(tid, BlockReason::IoWait(1)).unwrap();

        // Wake IRQ 0 (timer) — should not wake this task
        let woken = sched.wake_irq_waiters(0);
        assert_eq!(woken, 0);
        assert_eq!(sched.get_task(tid).unwrap().state, TaskState::Blocked);
    }

    #[test]
    fn test_wake_irq_waiters_ignores_non_iowait() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();

        // Block on message wait (not IoWait)
        sched.block_task(tid, BlockReason::MessageWait(5)).unwrap();

        // Wake IRQ 5 — should not wake message-waiters
        let woken = sched.wake_irq_waiters(5);
        assert_eq!(woken, 0);
        assert_eq!(sched.get_task(tid).unwrap().state, TaskState::Blocked);
    }

    #[test]
    fn test_wake_irq_waiters_multiple_tasks() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let t2 = sched.create_task(0x200000, 0x300000, Priority::NORMAL).unwrap();
        let t3 = sched.create_task(0x300000, 0x400000, Priority::NORMAL).unwrap();

        // Block t1 and t3 on IRQ 4, t2 on IRQ 1
        sched.block_task(t1, BlockReason::IoWait(4)).unwrap();
        sched.block_task(t2, BlockReason::IoWait(1)).unwrap();
        sched.block_task(t3, BlockReason::IoWait(4)).unwrap();

        // Wake IRQ 4
        let woken = sched.wake_irq_waiters(4);
        assert_eq!(woken, 2);
        assert_eq!(sched.get_task(t1).unwrap().state, TaskState::Ready);
        assert_eq!(sched.get_task(t2).unwrap().state, TaskState::Blocked); // still blocked
        assert_eq!(sched.get_task(t3).unwrap().state, TaskState::Ready);
    }

    // ====================================================================
    // Task migration tests
    // ====================================================================

    #[test]
    fn test_remove_task_ready() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        assert_eq!(sched.task_count(), 2); // idle + 1

        let task = sched.remove_task(tid).unwrap();
        assert_eq!(task.id, tid);
        assert_eq!(task.state, TaskState::Ready);
        assert_eq!(sched.task_count(), 1); // idle only
        assert!(sched.get_task_pub(tid).is_none());
    }

    #[test]
    fn test_remove_task_blocked() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.block_task(tid, BlockReason::IoWait(1)).unwrap();

        let task = sched.remove_task(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
    }

    #[test]
    fn test_remove_idle_task_fails() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        assert!(sched.remove_task(TaskId::new(0, 0)).is_err());
    }

    #[test]
    fn test_remove_running_task_fails() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        // Idle task (0) is Running — current_task
        assert!(sched.remove_task(TaskId::new(0, 0)).is_err());
    }

    #[test]
    fn test_remove_nonexistent_task_fails() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        assert!(sched.remove_task(TaskId::new(5, 0)).is_err());
    }

    // ====================================================================
    // purge_task — exit-path scheduler reference cleanup
    // ====================================================================

    #[test]
    fn test_purge_task_clears_current_task() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        // Manually set current_task to the created task to simulate it
        // being the Running task on this CPU.
        sched.current_task = Some(tid);

        sched.purge_task(tid);
        assert!(sched.current_task.is_none());
    }

    #[test]
    fn test_purge_task_leaves_other_current_task_alone() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let keeper = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let doomed = sched.create_task(0x110000, 0x210000, Priority::NORMAL).unwrap();
        sched.current_task = Some(keeper);

        sched.purge_task(doomed);
        assert_eq!(sched.current_task, Some(keeper));
    }

    #[test]
    fn test_purge_task_removes_from_ready_queue() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        // create_task puts the task in Ready state and enqueues it.
        // Sanity-check: the task is in some ready queue.
        let total_before: usize = sched.ready_queues.iter().map(|q| q.len()).sum();
        assert!(total_before > 0);

        sched.purge_task(tid);

        // No ready_queues entry should still reference the purged TaskId.
        for band in 0..NUM_PRIORITY_BANDS {
            assert!(
                !sched.ready_queues[band].iter().any(|&t| t == tid),
                "band {} still contains purged tid {:?}",
                band,
                tid
            );
        }
    }

    #[test]
    fn test_purge_task_preserves_other_queue_entries() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let keeper = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let doomed = sched.create_task(0x110000, 0x210000, Priority::NORMAL).unwrap();

        sched.purge_task(doomed);

        // `keeper` must still be present somewhere in a ready queue.
        let keeper_still_queued = sched
            .ready_queues
            .iter()
            .any(|q| q.iter().any(|&t| t == keeper));
        assert!(keeper_still_queued, "keeper was accidentally purged");

        // And `doomed` is gone from every queue.
        for band in 0..NUM_PRIORITY_BANDS {
            assert!(!sched.ready_queues[band].iter().any(|&t| t == doomed));
        }
    }

    #[test]
    fn test_purge_task_decrements_runnable_count_for_ready_task() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let runnable_before = sched.runnable_count;
        assert!(runnable_before > 0);

        sched.purge_task(tid);
        assert_eq!(sched.runnable_count, runnable_before - 1);
    }

    #[test]
    fn test_purge_task_idempotent() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.current_task = Some(tid);

        // Two back-to-back purges must not panic or double-decrement anything.
        sched.purge_task(tid);
        let runnable_after_first = sched.runnable_count;
        sched.purge_task(tid);
        assert_eq!(sched.runnable_count, runnable_after_first);
        assert!(sched.current_task.is_none());
    }

    #[test]
    fn test_accept_task() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        assert_eq!(sched.task_count(), 1);

        let task = Task::new(TaskId::new(3, 0), 0x100000, 0x200000, Priority::NORMAL);
        let tid = sched.accept_task(task).unwrap();
        assert_eq!(tid, TaskId::new(3, 0));
        assert_eq!(sched.task_count(), 2);
        assert!(sched.get_task_pub(TaskId::new(3, 0)).is_some());
    }

    #[test]
    fn test_accept_task_slot_occupied_fails() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();

        // Try to accept a task at the same slot
        let task = Task::new(tid, 0x200000, 0x300000, Priority::NORMAL);
        assert!(sched.accept_task(task).is_err());
    }

    #[test]
    fn test_accept_running_task_fails() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();

        let mut task = Task::new(TaskId::new(5, 0), 0x100000, 0x200000, Priority::NORMAL);
        task.state = TaskState::Running;
        assert!(sched.accept_task(task).is_err());
    }

    #[test]
    fn test_migrate_task_between_schedulers() {
        let mut src = Scheduler::new();
        src.init().unwrap();
        let tid = src.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        assert_eq!(src.task_count(), 2);

        let mut dst = Scheduler::new();
        dst.init().unwrap();
        assert_eq!(dst.task_count(), 1);

        migrate_task_between(&mut src, &mut dst, tid, 1).unwrap();

        // Source lost the task
        assert_eq!(src.task_count(), 1);
        assert!(src.get_task_pub(tid).is_none());

        // Destination has it
        assert_eq!(dst.task_count(), 2);
        let migrated = dst.get_task_pub(tid).unwrap();
        assert_eq!(migrated.state, TaskState::Ready);
        assert_eq!(migrated.home_cpu, 1);
    }

    #[test]
    fn test_migrate_blocked_task() {
        let mut src = Scheduler::new();
        src.init().unwrap();
        let tid = src.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        src.block_task(tid, BlockReason::IoWait(4)).unwrap();

        let mut dst = Scheduler::new();
        dst.init().unwrap();

        migrate_task_between(&mut src, &mut dst, tid, 2).unwrap();

        let task = dst.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert_eq!(task.block_reason, Some(BlockReason::IoWait(4)));
        assert_eq!(task.home_cpu, 2);
    }

    #[test]
    fn test_migrate_preserves_task_properties() {
        let mut src = Scheduler::new();
        src.init().unwrap();
        let tid = src.create_isr_task(0xDEAD, 0xBEEF, 0xCAFE, Priority::HIGH).unwrap();

        let mut dst = Scheduler::new();
        dst.init().unwrap();

        migrate_task_between(&mut src, &mut dst, tid, 3).unwrap();

        let task = dst.get_task_pub(tid).unwrap();
        assert_eq!(task.priority, Priority::HIGH);
        assert_eq!(task.saved_rsp, 0xBEEF);
        assert_eq!(task.kernel_stack_top, 0xCAFE);
    }

    #[test]
    fn test_create_task_reuses_freed_slot() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();

        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let _t2 = sched.create_task(0x200000, 0x300000, Priority::NORMAL).unwrap();
        assert_eq!(sched.task_count(), 3);

        // Remove t1 (frees slot 1)
        sched.remove_task(t1).unwrap();
        assert_eq!(sched.task_count(), 2);

        // Next create should reuse slot 1
        let t3 = sched.create_task(0x300000, 0x400000, Priority::NORMAL).unwrap();
        assert_eq!(t3, TaskId::new(1, 0)); // Reused slot 1
        assert_eq!(sched.task_count(), 3);
    }

    #[test]
    fn test_migrate_idle_task_fails() {
        let mut src = Scheduler::new();
        src.init().unwrap();
        let mut dst = Scheduler::new();
        dst.init().unwrap();

        assert!(migrate_task_between(&mut src, &mut dst, TaskId::new(0, 0), 1).is_err());
    }

    #[test]
    fn test_active_runnable_count_empty() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        // Only idle task (slot 0) is Running — excluded from count
        assert_eq!(sched.active_runnable_count(), 0);
    }

    #[test]
    fn test_active_runnable_count_with_ready_tasks() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let _t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let _t2 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        // Idle=Running (excluded), t1=Ready, t2=Ready → 2
        assert_eq!(sched.active_runnable_count(), 2);
    }

    #[test]
    fn test_active_runnable_count_excludes_blocked() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let _t2 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.block_task(t1, BlockReason::IoWait(0)).unwrap();
        // t1=Blocked (excluded), t2=Ready → 1
        assert_eq!(sched.active_runnable_count(), 1);
    }

    #[test]
    fn test_pick_migratable_task_returns_ready() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let _t2 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        // Should pick the first Ready non-idle task
        let picked = sched.pick_migratable_task();
        assert!(picked == Some(t1));
    }

    #[test]
    fn test_pick_migratable_task_skips_blocked() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let t2 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.block_task(t1, BlockReason::IoWait(0)).unwrap();
        // t1 blocked, should pick t2
        assert_eq!(sched.pick_migratable_task(), Some(t2));
    }

    #[test]
    fn test_pick_migratable_task_none_when_only_idle() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        // Only idle task — nothing migratable
        assert_eq!(sched.pick_migratable_task(), None);
    }

    #[test]
    fn test_pick_migratable_task_none_when_all_blocked() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.block_task(t1, BlockReason::IoWait(0)).unwrap();
        assert_eq!(sched.pick_migratable_task(), None);
    }

    #[test]
    fn test_pick_migratable_task_skips_pinned() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let t2 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        // Pin t1 (IRQ affinity) — should be skipped
        if let Some(task) = sched.get_task_mut_pub(t1) {
            task.pinned = true;
        }
        // Should skip pinned t1 and pick t2
        assert_eq!(sched.pick_migratable_task(), Some(t2));
    }

    #[test]
    fn test_pick_migratable_task_none_when_all_pinned() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        if let Some(task) = sched.get_task_mut_pub(t1) {
            task.pinned = true;
        }
        // Only non-idle task is pinned — nothing migratable
        assert_eq!(sched.pick_migratable_task(), None);
    }

    // ========================================================================
    // ADR-027 Phase 1: per-channel quiesce protocol
    //
    // arm_quiesce sets a per-task hint when the peer is Running, parks
    // synchronously when Ready, and is a no-op (AlreadyOffCpu) when
    // already non-runnable. The scheduler hook in
    // isr_tick_and_schedule / voluntary_yield consumes the hint and
    // parks the task into Blocked(ChannelQuiesceWait). Wake paths
    // clear stale hints so a Running re-run never re-parks.
    // ========================================================================

    /// Arbitrary channel id used in the quiesce tests.
    const QUIESCE_TEST_CHANNEL_ID: u64 = 0x0000_0007_0000_0042;

    #[test]
    fn test_arm_quiesce_idle_task_rejected() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();

        assert_eq!(
            sched.arm_quiesce(TaskId::new(0, 0), QUIESCE_TEST_CHANNEL_ID),
            Err(ScheduleError::InvalidTaskState)
        );
    }

    #[test]
    fn test_arm_quiesce_unknown_task_rejected() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();

        assert_eq!(
            sched.arm_quiesce(TaskId::new(99, 0), QUIESCE_TEST_CHANNEL_ID),
            Err(ScheduleError::TaskNotFound)
        );
    }

    #[test]
    fn test_arm_quiesce_ready_parks_synchronously() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        // Task is Ready by construction; do not run schedule().
        assert_eq!(sched.get_task_pub(tid).unwrap().state, TaskState::Ready);

        let result = sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        assert_eq!(result, QuiesceArmResult::ParkedNow);

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert_eq!(
            task.block_reason,
            Some(BlockReason::ChannelQuiesceWait(QUIESCE_TEST_CHANNEL_ID))
        );
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_arm_quiesce_running_sets_hint_only() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        // Drive task to Running.
        sched.schedule().unwrap();
        assert_eq!(sched.current_task, Some(tid));
        assert_eq!(sched.get_task_pub(tid).unwrap().state, TaskState::Running);

        let result = sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        assert_eq!(result, QuiesceArmResult::PendingOnYield);

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Running);
        assert_eq!(task.block_reason, None);
        assert_eq!(task.pending_quiesce_channel, Some(QUIESCE_TEST_CHANNEL_ID));
    }

    #[test]
    fn test_arm_quiesce_blocked_returns_already_off_cpu() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.block_task(tid, BlockReason::MessageWait(5)).unwrap();

        let result = sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        assert_eq!(result, QuiesceArmResult::AlreadyOffCpu);

        // Existing block reason preserved — peer was already off-CPU on
        // a different wait, kernel proceeds with unmap; no overwrite.
        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert_eq!(task.block_reason, Some(BlockReason::MessageWait(5)));
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_wake_quiesce_wakes_matching_channel() {
        // Park a task in ChannelQuiesceWait(matching id) → wake_quiesce
        // moves it to Ready and re-enqueues into its priority band.
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        // Parked synchronously because Ready (not Running).
        assert_eq!(sched.get_task_pub(tid).unwrap().state, TaskState::Blocked);

        let woken = sched.wake_quiesce(QUIESCE_TEST_CHANNEL_ID);
        assert_eq!(woken, 1);
        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Ready);
        assert_eq!(task.block_reason, None);
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_wake_quiesce_ignores_different_channel() {
        // Task parked on channel A; wake_quiesce(B) is a no-op.
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();

        let other_channel: u64 = QUIESCE_TEST_CHANNEL_ID ^ 0xFFFF_FFFF_FFFF_FFFF;
        let woken = sched.wake_quiesce(other_channel);
        assert_eq!(woken, 0);
        assert_eq!(sched.get_task_pub(tid).unwrap().state, TaskState::Blocked);
    }

    #[test]
    fn test_wake_quiesce_ignores_non_quiesce_blocked() {
        // Task blocked on MessageWait must not be touched.
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.block_task(tid, BlockReason::MessageWait(5)).unwrap();

        let woken = sched.wake_quiesce(QUIESCE_TEST_CHANNEL_ID);
        assert_eq!(woken, 0);
        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert_eq!(task.block_reason, Some(BlockReason::MessageWait(5)));
    }

    #[test]
    fn test_voluntary_yield_parks_running_task_with_hint() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.schedule().unwrap();
        assert_eq!(sched.current_task, Some(tid));

        // Arm quiesce on Running task → hint set, state still Running.
        sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        assert_eq!(sched.get_task_pub(tid).unwrap().state, TaskState::Running);

        // Voluntary yield → hook parks the task.
        sched.voluntary_yield(0xDEAD_BEEF);

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert_eq!(
            task.block_reason,
            Some(BlockReason::ChannelQuiesceWait(QUIESCE_TEST_CHANNEL_ID))
        );
        // Hint consumed by hook.
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_isr_tick_parks_running_task_with_hint_before_slice_expiry() {
        // Quiesce hook must force a schedule() even when the time slice
        // hasn't expired — otherwise the parked task stays current.
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.schedule().unwrap();
        assert_eq!(sched.current_task, Some(tid));

        // Fresh time slice — slice not expired.
        assert_eq!(sched.get_task_pub(tid).unwrap().time_remaining, 10);

        sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();

        sched.isr_tick_and_schedule(0xDEAD_BEEF);

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert_eq!(
            task.block_reason,
            Some(BlockReason::ChannelQuiesceWait(QUIESCE_TEST_CHANNEL_ID))
        );
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_yield_without_hint_does_not_park() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.schedule().unwrap();
        assert_eq!(sched.current_task, Some(tid));

        // No arm_quiesce — voluntary_yield must not park.
        sched.voluntary_yield(0xDEAD_BEEF);

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.block_reason, None);
        // The yield itself doesn't transition state — voluntary_yield
        // saves rsp + reschedules; the task stays Running (or becomes
        // Ready when displaced) but is never Blocked without an
        // explicit reason.
        assert_ne!(task.state, TaskState::Blocked);
    }

    #[test]
    fn test_hook_skips_blocked_task_clears_stale_hint() {
        // Race shape commit 3 must tolerate: Running task's hint is
        // set, then another path transitions it to Blocked
        // (handle_recv_msg → MessageWait) before the hook fires. The
        // hook must consume the now-stale hint without overwriting
        // the wake-path block reason.
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.schedule().unwrap();
        assert_eq!(sched.current_task, Some(tid));

        sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        assert_eq!(
            sched.get_task_pub(tid).unwrap().pending_quiesce_channel,
            Some(QUIESCE_TEST_CHANNEL_ID)
        );

        // Different path moves task to Blocked(MessageWait).
        sched.block_task(tid, BlockReason::MessageWait(7)).unwrap();

        // Hook fires (e.g. via the next ISR tick on this CPU): clears
        // the hint, leaves block_reason = MessageWait intact.
        sched.isr_tick_and_schedule(0xDEAD_BEEF);

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert_eq!(task.block_reason, Some(BlockReason::MessageWait(7)));
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_wake_task_clears_pending_hint() {
        // Defense against stale hints surviving a Blocked→Ready→Running
        // round trip. wake_task must clear the hint so the next ISR
        // tick after the wake doesn't re-park the task.
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.schedule().unwrap();
        sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        sched.block_task(tid, BlockReason::MessageWait(7)).unwrap();
        // Hint still set on the Blocked task.
        assert_eq!(
            sched.get_task_pub(tid).unwrap().pending_quiesce_channel,
            Some(QUIESCE_TEST_CHANNEL_ID)
        );

        sched.wake_task(tid).unwrap();

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Ready);
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_wake_message_waiters_clears_pending_hint() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.schedule().unwrap();
        sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        sched.block_task(tid, BlockReason::MessageWait(11)).unwrap();
        assert_eq!(
            sched.get_task_pub(tid).unwrap().pending_quiesce_channel,
            Some(QUIESCE_TEST_CHANNEL_ID)
        );

        let woken = sched.wake_message_waiters(11);
        assert_eq!(woken, 1);

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Ready);
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_wake_irq_waiters_clears_pending_hint() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        sched.schedule().unwrap();
        sched.arm_quiesce(tid, QUIESCE_TEST_CHANNEL_ID).unwrap();
        sched.block_task(tid, BlockReason::IoWait(3)).unwrap();
        assert_eq!(
            sched.get_task_pub(tid).unwrap().pending_quiesce_channel,
            Some(QUIESCE_TEST_CHANNEL_ID)
        );

        let woken = sched.wake_irq_waiters(3);
        assert_eq!(woken, 1);

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Ready);
        assert_eq!(task.pending_quiesce_channel, None);
    }

    #[test]
    fn test_block_reason_channel_quiesce_wait_display() {
        // Display is consumed by audit / scheduler logging; pin the
        // format so the audit consumer can pattern-match if it grows
        // a quiesce-aware view.
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        write!(&mut buf, "{}", BlockReason::ChannelQuiesceWait(0x42)).unwrap();
        assert_eq!(buf, "ChannelQuiesceWait(66)");
    }

    #[test]
    fn test_find_task_for_process_matches() {
        use crate::ipc::ProcessId;
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let t1 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let t2 = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let pid_a = ProcessId::new(7, 0);
        let pid_b = ProcessId::new(8, 0);
        sched.get_task_mut_pub(t1).unwrap().process_id = Some(pid_a);
        sched.get_task_mut_pub(t2).unwrap().process_id = Some(pid_b);

        assert_eq!(sched.find_task_for_process(pid_a), Some(t1));
        assert_eq!(sched.find_task_for_process(pid_b), Some(t2));
    }

    #[test]
    fn test_find_task_for_process_returns_none_when_no_match() {
        use crate::ipc::ProcessId;
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let _t = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        // No task has process_id set — find_task_for_process scans for
        // the requested ProcessId and finds none.
        assert_eq!(
            sched.find_task_for_process(ProcessId::new(42, 0)),
            None
        );
    }

    #[test]
    fn test_arm_quiesce_for_process_runs_full_flow() {
        // arm_quiesce_for_process bridges ProcessId → TaskId → arm_quiesce
        // under one lock. Verify it picks the right task and returns
        // both the resolved id and the arm outcome.
        use crate::ipc::ProcessId;
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        let tid = sched.create_task(0x100000, 0x200000, Priority::NORMAL).unwrap();
        let pid = ProcessId::new(11, 0);
        sched.get_task_mut_pub(tid).unwrap().process_id = Some(pid);
        // Task is Ready by construction → ParkedNow.

        let result = sched.arm_quiesce_for_process(pid, QUIESCE_TEST_CHANNEL_ID);
        assert_eq!(result, Some((tid, QuiesceArmResult::ParkedNow)));

        let task = sched.get_task_pub(tid).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert_eq!(
            task.block_reason,
            Some(BlockReason::ChannelQuiesceWait(QUIESCE_TEST_CHANNEL_ID))
        );
    }

    #[test]
    fn test_arm_quiesce_for_process_unknown_pid_returns_none() {
        use crate::ipc::ProcessId;
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        // No task with this pid exists → None (semantically equivalent
        // to AlreadyOffCpu — the kernel proceeds with unmap).
        assert_eq!(
            sched.arm_quiesce_for_process(ProcessId::new(99, 0), QUIESCE_TEST_CHANNEL_ID),
            None
        );
    }
}
