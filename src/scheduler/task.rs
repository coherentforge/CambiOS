//! Task and process definitions for the microkernel scheduler
//!
//! Defines task state, context, and lifecycle for verification-ready scheduling.

use core::fmt;
use crate::ipc::ProcessId;

/// Task/Process ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u32);

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Task({})", self.0)
    }
}

/// Task state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is ready to run
    Ready,
    /// Task is currently running on CPU
    Running,
    /// Task is blocked waiting for I/O or event
    Blocked,
    /// Task has finished, waiting cleanup
    Terminated,
    /// Task was suspended by debugger/management
    Suspended,
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TaskState::Ready => write!(f, "Ready"),
            TaskState::Running => write!(f, "Running"),
            TaskState::Blocked => write!(f, "Blocked"),
            TaskState::Terminated => write!(f, "Terminated"),
            TaskState::Suspended => write!(f, "Suspended"),
        }
    }
}

impl TaskState {
    /// Verify valid state transition
    pub fn can_transition_to(&self, next: TaskState) -> bool {
        match (self, next) {
            // Ready → Running (selected by scheduler)
            (TaskState::Ready, TaskState::Running) => true,
            // Running → Ready (preempted or yields)
            (TaskState::Running, TaskState::Ready) => true,
            // Running → Blocked (waits for event)
            (TaskState::Running, TaskState::Blocked) => true,
            // Blocked → Ready (event occurred)
            (TaskState::Blocked, TaskState::Ready) => true,
            // Running/Ready → Terminated (task exits)
            (TaskState::Running, TaskState::Terminated) => true,
            (TaskState::Ready, TaskState::Terminated) => true,
            (TaskState::Blocked, TaskState::Terminated) => true,
            // Suspended → Ready/Blocked (debugger resumes)
            (TaskState::Suspended, TaskState::Ready) => true,
            (TaskState::Suspended, TaskState::Blocked) => true,
            // Any → Suspended (debugger pauses)
            (s, TaskState::Suspended) if *s != TaskState::Terminated => true,
            // No transitions from Terminated
            (TaskState::Terminated, _) => false,
            // Invalid transitions
            _ => false,
        }
    }
}

/// CPU context for a task (register state)
///
/// Stores saved registers for context switching.
/// On x86-64, includes GPRs, RIP, RSP, and flags.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuContext {
    /// General purpose registers
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Instruction pointer
    pub rip: u64,
    /// Stack pointer
    pub rsp: u64,
    /// Flags register
    pub rflags: u64,
}

impl CpuContext {
    /// Create a new task context for given entry point and stack
    pub fn new(entry_point: u64, stack_pointer: u64) -> Self {
        CpuContext {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: entry_point,
            rsp: stack_pointer,
            rflags: 0x0202, // IF (interrupts enabled) and reserved bits
        }
    }

    /// Verify context is in valid state
    pub fn verify_integrity(&self) -> Result<(), &'static str> {
        if self.rip == 0 {
            return Err("RIP cannot be zero");
        }
        if self.rsp == 0 {
            return Err("RSP cannot be zero");
        }
        if (self.rflags & 0x0202) == 0 {
            return Err("IF flag must be set");
        }
        Ok(())
    }
}

/// Task priority level (higher = more important)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub u8);

impl Priority {
    pub const IDLE: Priority = Priority(0);
    pub const LOW: Priority = Priority(64);
    pub const NORMAL: Priority = Priority(128);
    pub const HIGH: Priority = Priority(192);
    pub const CRITICAL: Priority = Priority(255);
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0 => write!(f, "Idle"),
            64 => write!(f, "Low"),
            128 => write!(f, "Normal"),
            192 => write!(f, "High"),
            255 => write!(f, "Critical"),
            p => write!(f, "Priority({})", p),
        }
    }
}

/// Reason why a task is blocked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Waiting for async IPC message on endpoint
    MessageWait(u32),
    /// Sync IPC: sender blocked until receiver picks up message
    SyncSendWait(u32),
    /// Sync IPC: receiver blocked waiting for sender to deposit message
    SyncRecvWait(u32),
    /// Sync IPC: caller blocked waiting for reply after call()
    SyncReplyWait(u32),
    /// Waiting for I/O event
    IoWait(u32),
    /// Waiting for synchronization primitive (mutex, semaphore)
    SyncWait(u32),
    /// Waiting for timer expiration
    TimerWait(u64),
    /// Blocked by debugger
    DebuggerWait,
    /// Waiting for child process
    ChildWait,
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BlockReason::MessageWait(ep) => write!(f, "MessageWait({})", ep),
            BlockReason::SyncSendWait(ep) => write!(f, "SyncSendWait({})", ep),
            BlockReason::SyncRecvWait(ep) => write!(f, "SyncRecvWait({})", ep),
            BlockReason::SyncReplyWait(ep) => write!(f, "SyncReplyWait({})", ep),
            BlockReason::IoWait(fd) => write!(f, "IoWait({})", fd),
            BlockReason::SyncWait(id) => write!(f, "SyncWait({})", id),
            BlockReason::TimerWait(ms) => write!(f, "TimerWait({}ms)", ms),
            BlockReason::DebuggerWait => write!(f, "DebuggerWait"),
            BlockReason::ChildWait => write!(f, "ChildWait"),
        }
    }
}

/// Task metadata and state
#[derive(Clone)]
pub struct Task {
    pub id: TaskId,
    pub state: TaskState,
    pub context: CpuContext,
    pub priority: Priority,
    /// Time slice in timer ticks (for round-robin)
    pub time_slice: u32,
    /// Remaining time in current slice
    pub time_remaining: u32,
    /// Number of times scheduled
    pub schedule_count: u64,
    /// Reason why task is blocked (if state = Blocked)
    pub block_reason: Option<BlockReason>,
    /// Saved RSP pointing to SavedContext on kernel stack (for ISR-driven switching).
    /// 0 = task is currently running (no saved state yet).
    pub saved_rsp: u64,
    /// Top of allocated kernel stack (0 = boot stack / not heap-allocated)
    pub kernel_stack_top: u64,
    /// Owning process (for CR3 lookup on context switch). None = kernel task.
    pub process_id: Option<ProcessId>,
    /// Physical address of PML4 (cached from ProcessDescriptor). 0 = kernel page table.
    pub cr3: u64,
    /// Logical CPU index that currently owns this task (0 = BSP).
    pub home_cpu: u16,
}

impl Task {
    /// Create a new task
    pub fn new(id: TaskId, entry_point: u64, stack_pointer: u64, priority: Priority) -> Self {
        Task {
            id,
            state: TaskState::Ready,
            context: CpuContext::new(entry_point, stack_pointer),
            priority,
            time_slice: 10, // Default 10ms time slice (at 100Hz timer = 1 tick)
            time_remaining: 10,
            schedule_count: 0,
            block_reason: None,
            saved_rsp: 0,
            kernel_stack_top: 0,
            process_id: None,
            cr3: 0,
            home_cpu: 0,
        }
    }

    /// Create a task with a pre-initialized kernel stack for ISR-driven context switching
    pub fn new_with_stack(
        id: TaskId,
        entry_point: u64,
        saved_rsp: u64,
        kernel_stack_top: u64,
        priority: Priority,
    ) -> Self {
        Task {
            id,
            state: TaskState::Ready,
            context: CpuContext::new(entry_point, kernel_stack_top),
            priority,
            time_slice: 10,
            time_remaining: 10,
            schedule_count: 0,
            block_reason: None,
            saved_rsp,
            kernel_stack_top,
            process_id: None,
            cr3: 0,
            home_cpu: 0,
        }
    }

    /// Verify task integrity for scheduler
    pub fn verify_integrity(&self) -> Result<(), &'static str> {
        self.context.verify_integrity()?;

        match self.state {
            TaskState::Ready | TaskState::Running | TaskState::Blocked | TaskState::Suspended => {
                // Valid states
            }
            TaskState::Terminated => {
                // Cannot schedule terminated tasks
            }
        }

        Ok(())
    }

    /// Handle a timer tick for this task
    pub fn tick(&mut self) {
        if self.state == TaskState::Running && self.time_remaining > 0 {
            self.time_remaining -= 1;
        }
    }

    /// Check if time slice is exhausted
    pub fn time_slice_expired(&self) -> bool {
        self.state == TaskState::Running && self.time_remaining == 0
    }

    /// Reset time slice
    pub fn reset_time_slice(&mut self) {
        self.time_remaining = self.time_slice;
    }
}

/// Task scheduling error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleError {
    NoReadyTasks,
    InvalidTaskState,
    TaskNotFound,
    InvalidTransition,
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScheduleError::NoReadyTasks => write!(f, "No ready tasks available"),
            ScheduleError::InvalidTaskState => write!(f, "Task in invalid state"),
            ScheduleError::TaskNotFound => write!(f, "Task not found"),
            ScheduleError::InvalidTransition => write!(f, "Invalid state transition"),
        }
    }
}
