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

/// Maximum number of tasks in the system.
///
/// Raised from 32 to 256 to support real multi-core workloads. The task array
/// is heap-allocated (Vec), so this does not risk stack overflow. Per-priority
/// ready queues keep scheduling O(1) despite the larger task count.
const MAX_TASKS: usize = 256;

/// Number of priority bands for the ready queues.
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
            TaskId(0),
            0x100000,  // Placeholder entry point (idle task runs kmain's loop)
            0x200000,  // Placeholder stack (idle uses boot stack)
            Priority::IDLE,
        );
        // Mark idle task as Running since it IS executing right now (kmain)
        idle_task.state = TaskState::Running;

        self.tasks[0] = Some(idle_task);
        self.task_count = 1;
        self.current_task = Some(TaskId(0));
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

        let task_id = TaskId(slot as u32);
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

        let task_id = TaskId(slot as u32);
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
            Some(self.current_task.unwrap_or(TaskId(0)))
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
                if let Some(task) = self.tasks.get_mut(task_id.0 as usize).and_then(|t| t.as_mut()) {
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
                let idx = tid.0 as usize;
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
        if let Some(Some(task)) = self.tasks.get(0) {
            if task.state == TaskState::Ready {
                return Ok(TaskId(0));
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

        // Save current task's context RSP and tick its time slice
        if let Some(task_id) = self.current_task {
            if let Some(task) = self.get_task_mut(task_id) {
                task.saved_rsp = current_rsp;
                task.tick();
            }
        }

        // Check if time slice expired
        if !self.time_slice_expired() {
            return current_rsp; // No switch needed
        }

        // Time slice expired — select next task
        match self.schedule() {
            Ok(next_task) => {
                if let Some(task) = self.get_task(next_task) {
                    task.saved_rsp
                } else {
                    current_rsp // Shouldn't happen
                }
            }
            Err(_) => current_rsp, // Schedule failed, keep current
        }
    }

    /// Get task by ID - O(1) direct indexing
    /// 
    /// TaskId is an index into the tasks array. Direct indexing is O(1).
    fn get_task(&self, id: TaskId) -> Option<&Task> {
        self.tasks.get(id.0 as usize)?.as_ref()
    }

    /// Get mutable task by ID - O(1) direct indexing
    fn get_task_mut(&mut self, id: TaskId) -> Option<&mut Task> {
        self.tasks.get_mut(id.0 as usize)?.as_mut()
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
        // Safety check: never block idle task
        if task_id == TaskId(0) {
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

            // If we blocked the current running task, reschedule immediately.
            if self.current_task == Some(task_id) {
                return self.schedule().map(|_| ());
            }

            Ok(())
        } else {
            Err(ScheduleError::TaskNotFound)
        }
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
        if task_id != TaskId(0) {
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
        // Collect task IDs + bands to enqueue (avoids borrow overlap with self.ready_queues)
        let mut to_enqueue: [(TaskId, usize); 32] = [(TaskId(0), 0); 32];
        let mut woken = 0;

        for slot in self.tasks.iter_mut() {
            if let Some(task) = slot {
                if task.state == TaskState::Blocked {
                    if let Some(BlockReason::IoWait(waiting_irq)) = task.block_reason {
                        if waiting_irq == irq {
                            task.state = TaskState::Ready;
                            task.block_reason = None;
                            task.reset_time_slice();
                            if !task.in_ready_queue {
                                task.in_ready_queue = true;
                                if woken < to_enqueue.len() {
                                    to_enqueue[woken] = (task.id, priority_to_band(task.priority));
                                }
                            }
                            woken += 1;
                        }
                    }
                }
            }
        }

        // Enqueue woken tasks into ready queues
        for i in 0..woken.min(to_enqueue.len()) {
            let (tid, band) = to_enqueue[i];
            self.ready_queues[band].push_back(tid);
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

        for task_opt in self.tasks.iter() {
            if let Some(task) = task_opt {
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

        // Perform the actual context switch via arch module
        crate::arch::context_switch(current_ctx, next_ctx);
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
        if task_id == TaskId(0) {
            return Err(ScheduleError::InvalidTaskState);
        }
        // Cannot remove the currently running task
        if self.current_task == Some(task_id) {
            return Err(ScheduleError::InvalidTaskState);
        }

        let idx = task_id.0 as usize;
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
    /// Places the task at its existing slot index (`task.id.0`). The slot
    /// must be free on this scheduler.
    pub fn accept_task(&mut self, task: Task) -> Result<TaskId, ScheduleError> {
        if task.state == TaskState::Running {
            return Err(ScheduleError::InvalidTaskState);
        }

        let idx = task.id.0 as usize;
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
                let idx = tid.0 as usize;
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
    crate::set_task_cpu(task_id.0, dst_cpu);
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
        assert!(sched.remove_task(TaskId(0)).is_err());
    }

    #[test]
    fn test_remove_running_task_fails() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        // Idle task (0) is Running — current_task
        assert!(sched.remove_task(TaskId(0)).is_err());
    }

    #[test]
    fn test_remove_nonexistent_task_fails() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        assert!(sched.remove_task(TaskId(5)).is_err());
    }

    #[test]
    fn test_accept_task() {
        let mut sched = Scheduler::new();
        sched.init().unwrap();
        assert_eq!(sched.task_count(), 1);

        let task = Task::new(TaskId(3), 0x100000, 0x200000, Priority::NORMAL);
        let tid = sched.accept_task(task).unwrap();
        assert_eq!(tid, TaskId(3));
        assert_eq!(sched.task_count(), 2);
        assert!(sched.get_task_pub(TaskId(3)).is_some());
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

        let mut task = Task::new(TaskId(5), 0x100000, 0x200000, Priority::NORMAL);
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
        assert_eq!(t3, TaskId(1)); // Reused slot 1
        assert_eq!(sched.task_count(), 3);
    }

    #[test]
    fn test_migrate_idle_task_fails() {
        let mut src = Scheduler::new();
        src.init().unwrap();
        let mut dst = Scheduler::new();
        dst.init().unwrap();

        assert!(migrate_task_between(&mut src, &mut dst, TaskId(0), 1).is_err());
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
}
