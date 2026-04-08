// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

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
/// Architecture-specific: each target defines the register set, but all
/// targets provide `new(entry_point, stack_pointer)` and `verify_integrity()`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[cfg(target_arch = "x86_64")]
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

/// CPU context for a task (AArch64 register state)
///
/// Stores callee-saved registers (x19-x30), SP, PC (ELR_EL1), and PSTATE
/// (SPSR_EL1). Caller-saved registers (x0-x18) are not preserved across
/// voluntary context switches (they are saved/restored by the ISR path in
/// SavedContext instead).
///
/// ## Register layout (offsets for assembly)
/// ```text
/// x19=0, x20=8, x21=16, x22=24, x23=32, x24=40, x25=48, x26=56,
/// x27=64, x28=72, x29(fp)=80, x30(lr)=88, sp=96, pc=104, pstate=112
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[cfg(target_arch = "aarch64")]
pub struct CpuContext {
    /// Callee-saved general purpose registers
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    /// Frame pointer (x29)
    pub x29: u64,
    /// Link register (x30) — return address
    pub x30: u64,
    /// Stack pointer
    pub sp: u64,
    /// Program counter (ELR_EL1 on exception entry)
    pub pc: u64,
    /// Processor state (SPSR_EL1 on exception entry)
    pub pstate: u64,
}

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "aarch64")]
impl CpuContext {
    /// Create a new task context for given entry point and stack
    pub fn new(entry_point: u64, stack_pointer: u64) -> Self {
        CpuContext {
            x19: 0, x20: 0, x21: 0, x22: 0,
            x23: 0, x24: 0, x25: 0, x26: 0,
            x27: 0, x28: 0,
            x29: 0,  // frame pointer
            x30: entry_point,  // LR — context_restore will branch here
            sp: stack_pointer,
            pc: entry_point,
            // EL0t: PSTATE with EL0, SP_EL0, interrupts enabled (DAIF clear)
            pstate: 0x0,
        }
    }

    /// Verify context is in valid state
    pub fn verify_integrity(&self) -> Result<(), &'static str> {
        if self.pc == 0 {
            return Err("PC cannot be zero");
        }
        if self.sp == 0 {
            return Err("SP cannot be zero");
        }
        Ok(())
    }
}

/// CpuContext compiled out — provide a fallback for test/other targets
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuContext {
    pub pc: u64,
    pub sp: u64,
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
impl CpuContext {
    pub fn new(entry_point: u64, stack_pointer: u64) -> Self {
        CpuContext { pc: entry_point, sp: stack_pointer }
    }
    pub fn verify_integrity(&self) -> Result<(), &'static str> {
        if self.pc == 0 { return Err("PC cannot be zero"); }
        if self.sp == 0 { return Err("SP cannot be zero"); }
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
    /// If true, task is pinned to home_cpu (IRQ affinity). Load balancer will not migrate.
    pub pinned: bool,
    /// If true, this task is currently in a ready queue. Prevents duplicate enqueuing.
    pub in_ready_queue: bool,
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
            pinned: false,
            in_ready_queue: false,
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
            pinned: false,
            in_ready_queue: false,
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
