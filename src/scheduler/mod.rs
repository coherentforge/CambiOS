//! Round-robin scheduler for the microkernel
//!
//! Implements preemptive multitasking with tick-based time slicing.
//! Designed for verification with clear scheduling invariants.

pub mod task;
pub mod timer;

pub use task::{Task, TaskId, TaskState, Priority, CpuContext, ScheduleError, BlockReason};
pub use timer::{Timer, TimerConfig, AdaptiveTickMode};
use core::fmt;

/// Maximum number of tasks in the system
/// Maximum tasks in the system.
/// Kept at 32 to avoid huge stack allocations in Scheduler::new().
/// Can be made dynamic in the future with Box<[Option<Task>; N]>
const MAX_TASKS: usize = 32;

/// Scheduler state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerState {
    Uninitialized,
    Initialized,
    Running,
    Paused,
}

/// Round-robin task scheduler
///
/// Invariants:
/// - Exactly one task is Running
/// - All Ready tasks have consistent state
/// - Only Running task has access to CPU
/// - Timer ticks decrement time_remaining
pub struct Scheduler {
    /// All tasks in the system (dynamic storage)
    tasks: [Option<Task>; MAX_TASKS],
    /// Number of active tasks
    task_count: usize,
    /// Currently running task ID
    current_task: Option<TaskId>,
    /// Index for round-robin selection
    ready_index: usize,
    /// Number of scheduler ticks
    total_ticks: u64,
    /// Scheduler state
    state: SchedulerState,
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new() -> Self {
        Scheduler {
            tasks: [const { None }; MAX_TASKS],
            task_count: 0,
            current_task: None,
            ready_index: 0,
            total_ticks: 0,
            state: SchedulerState::Uninitialized,
        }
    }

    /// Initialize scheduler with idle task
    pub fn init(&mut self) -> Result<(), ScheduleError> {
        // Create idle task (always runnable, lowest priority)
        // Idle task MUST be always ready to service: blocking requires a ready task to exist.
        let idle_task = Task::new(
            TaskId(0),
            0x100000,  // Placeholder entry point
            0x200000,  // Placeholder stack
            Priority::IDLE,
        );

        self.tasks[0] = Some(idle_task);
        self.task_count = 1;
        self.current_task = Some(TaskId(0));
        self.state = SchedulerState::Initialized;
        // Note: state will transition to Running on first real scheduler invocation

        Ok(())
    }

    /// Create and add a new task
    pub fn create_task(
        &mut self,
        entry_point: u64,
        stack_pointer: u64,
        priority: Priority,
    ) -> Result<TaskId, ScheduleError> {
        if self.task_count >= MAX_TASKS {
            return Err(ScheduleError::NoReadyTasks);
        }

        let task_id = TaskId(self.task_count as u32);
        let task = Task::new(task_id, entry_point, stack_pointer, priority);

        self.tasks[self.task_count] = Some(task);
        self.task_count += 1;

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
                return task.time_slice_expired();
            }
        }
        false
    }

    /// Perform a context switch - select next ready task by priority
    /// 
    /// Transitions scheduler to Running state on first invocation.
    pub fn schedule(&mut self) -> Result<TaskId, ScheduleError> {
        // Save current task state
        if let Some(task_id) = self.current_task {
            if let Some(task) = self.get_task_mut(task_id) {
                if task.state == TaskState::Running {
                    task.state = TaskState::Ready;
                    task.reset_time_slice();
                }
            }
        }

        // Find next ready task
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

    /// Find the next ready task using priority-based selection
    /// 
    /// Algorithm:
    /// 1. Find the highest priority among all ready tasks
    /// 2. Round-robin within that priority level
    /// 3. Falls back to idle task (always ready) if nothing else found
    fn find_next_ready_task(&mut self) -> Result<TaskId, ScheduleError> {
        // First pass: find highest ready priority
        let mut max_priority: Option<Priority> = None;
        for task_opt in self.tasks.iter() {
            if let Some(task) = task_opt {
                if task.state == TaskState::Ready {
                    if let Some(current_max) = max_priority {
                        if task.priority > current_max {
                            max_priority = Some(task.priority);
                        }
                    } else {
                        max_priority = Some(task.priority);
                    }
                }
            }
        }

        // Second pass: round-robin within the highest priority band
        if let Some(target_priority) = max_priority {
            let mut attempts = 0;
            const MAX_ATTEMPTS: usize = MAX_TASKS * 2;

            loop {
                let index = (self.ready_index + attempts) % MAX_TASKS;

                if let Some(task) = &self.tasks[index] {
                    if task.state == TaskState::Ready && task.priority == target_priority {
                        self.ready_index = (index + 1) % MAX_TASKS;
                        return Ok(task.id);
                    }
                }

                attempts += 1;
                if attempts >= MAX_ATTEMPTS {
                    break;
                }
            }
        }

        // Fallback: idle task (always ready) if nothing else found
        if let Some(task) = self.get_task(TaskId(0)) {
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

    /// Get task by ID - O(1) direct indexing
    /// 
    /// TaskId is an index into the tasks array. Direct indexing is O(1).
    fn get_task(&self, id: TaskId) -> Option<&Task> {
        if id.0 as usize >= MAX_TASKS {
            return None;
        }
        self.tasks[id.0 as usize].as_ref()
    }

    /// Get mutable task by ID - O(1) direct indexing
    /// 
    /// TaskId is an index into the tasks array. Direct indexing is O(1).
    fn get_task_mut(&mut self, id: TaskId) -> Option<&mut Task> {
        if id.0 as usize >= MAX_TASKS {
            return None;
        }
        self.tasks[id.0 as usize].as_mut()
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

            // If we blocked the current running task, reschedule immediately.
            // This performs the logical state transition (picks next task).
            // The actual CPU context switch happens via:
            // - Timer ISR: next interrupt will restore the newly scheduled task
            // - Explicit switch: caller can invoke perform_context_switch after this
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
        if let Some(task) = self.get_task_mut(task_id) {
            if task.state != TaskState::Blocked {
                return Err(ScheduleError::InvalidTaskState);
            }

            task.state = TaskState::Ready;
            task.block_reason = None;
            task.reset_time_slice();

            Ok(task_id)
        } else {
            Err(ScheduleError::TaskNotFound)
        }
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

    /// Verify scheduler invariants
    pub fn verify_invariants(&self) -> Result<(), &'static str> {
        // Count running tasks - should be exactly 1
        let running_count = self
            .tasks
            .iter()
            .filter(|t| t.as_ref().map(|task| task.state == TaskState::Running).unwrap_or(false))
            .count();

        if running_count != 1 {
            return Err("Scheduler invariant: must have exactly one running task");
        }

        // Verify current_task matches RunningTask
        if let Some(task_id) = self.current_task {
            if let Some(task) = self.get_task(task_id) {
                if task.state != TaskState::Running {
                    return Err("Scheduler invariant: current task not in Running state");
                }
            } else {
                return Err("Scheduler invariant: current task id not found");
            }
        }

        Ok(())
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
        assert_eq!(scheduler.state, SchedulerState::Initialized);
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
}
