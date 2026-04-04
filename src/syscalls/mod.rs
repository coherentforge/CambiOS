//! Syscall definitions and numbers
//!
//! Defines the syscall ABI and interfaces that userspace drivers use
//! to request kernel services.

pub mod dispatcher;
pub mod userspace;



/// Syscall numbers - must match userspace convention
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    /// exit(code: i32) -> !
    /// Terminate the calling process
    Exit = 0,

    /// write(endpoint: u32, buffer: *const u8, len: usize) -> isize
    /// Send data through an endpoint
    Write = 1,

    /// read(endpoint: u32, buffer: *mut u8, len: usize) -> isize
    /// Receive data from an endpoint
    Read = 2,

    /// allocate(size: usize, flags: u32) -> *mut u8
    /// Allocate memory for this process
    Allocate = 3,

    /// free(ptr: *mut u8, size: usize) -> i32
    /// Free previously allocated memory
    Free = 4,

    /// wait_irq(irq_number: u32) -> i32
    /// Wait for a specific interrupt to fire
    WaitIrq = 5,

    /// register_endpoint(endpoint_id: u32, flags: u32) -> i32
    /// Register a message endpoint
    RegisterEndpoint = 6,

    /// yield_cpu() -> i32
    /// Voluntarily yield to scheduler
    Yield = 7,

    /// get_pid() -> u32
    /// Get current process ID
    GetPid = 8,

    /// get_time() -> u64
    /// Get current system time (ticks)
    GetTime = 9,

    /// print(buffer: *const u8, len: usize) -> isize
    /// Print a string to the kernel serial console (for debugging)
    Print = 10,
}

impl SyscallNumber {
    /// Convert u64 to syscall number
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(Self::Exit),
            1 => Some(Self::Write),
            2 => Some(Self::Read),
            3 => Some(Self::Allocate),
            4 => Some(Self::Free),
            5 => Some(Self::WaitIrq),
            6 => Some(Self::RegisterEndpoint),
            7 => Some(Self::Yield),
            8 => Some(Self::GetPid),
            9 => Some(Self::GetTime),
            10 => Some(Self::Print),
            _ => None,
        }
    }
}

/// Arguments passed via registers on x86-64
/// 
/// x86-64 System V ABI syscall convention:
/// - RAX: syscall number (input), return value (output)
/// - RDI: first argument (typically fd or endpoint)
/// - RSI: second argument (typically buffer/pointer)
/// - RDX: third argument (typically size/count)
/// - RCX: fourth argument
/// - R8:  fifth argument
/// - R9:  sixth argument
/// - RBX, RBP, R12-R15: must be preserved by syscall handler
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    pub arg1: u64,  // rdi
    pub arg2: u64,  // rsi
    pub arg3: u64,  // rdx
    pub arg4: u64,  // rcx
    pub arg5: u64,  // r8
    pub arg6: u64,  // r9
}

impl SyscallArgs {
    /// Create syscall arguments from register values
    pub fn new(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> Self {
        SyscallArgs {
            arg1, arg2, arg3, arg4, arg5, arg6,
        }
    }

    /// Get first argument as u32
    pub fn arg1_u32(&self) -> u32 {
        self.arg1 as u32
    }

    /// Get second argument as u32
    pub fn arg2_u32(&self) -> u32 {
        self.arg2 as u32
    }

    /// Get first argument as pointer
    pub fn arg1_ptr<T>(&self) -> *const T {
        self.arg1 as *const T
    }

    /// Get first argument as mutable pointer
    pub fn arg1_mut_ptr<T>(&self) -> *mut T {
        self.arg1 as *mut T
    }

    /// Get second argument as pointer
    pub fn arg2_ptr<T>(&self) -> *const T {
        self.arg2 as *const T
    }

    /// Get second argument as mutable pointer
    pub fn arg2_mut_ptr<T>(&self) -> *mut T {
        self.arg2 as *mut T
    }

    /// Get argument as usize (common for sizes)
    pub fn arg_usize(&self, n: usize) -> usize {
        match n {
            1 => self.arg1 as usize,
            2 => self.arg2 as usize,
            3 => self.arg3 as usize,
            4 => self.arg4 as usize,
            5 => self.arg5 as usize,
            6 => self.arg6 as usize,
            _ => 0,
        }
    }
}

/// Syscall error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SyscallError {
    /// Operation succeeded (0)
    Success = 0,
    
    /// Invalid argument
    InvalidArg = -1,
    
    /// Permission denied
    PermissionDenied = -2,
    
    /// Out of memory
    OutOfMemory = -3,
    
    /// Endpoint not found
    EndpointNotFound = -4,
    
    /// Operation would block
    WouldBlock = -5,
    
    /// Interrupted by signal (future)
    Interrupted = -6,
    
    /// Unknown syscall
    Enosys = -38,
}

impl SyscallError {
    /// Convert to signed integer for return value
    pub fn as_i64(&self) -> i64 {
        *self as i32 as i64
    }
}

/// Result type for syscall implementations
pub type SyscallResult = Result<u64, SyscallError>;
