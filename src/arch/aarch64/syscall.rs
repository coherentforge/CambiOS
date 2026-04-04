//! Syscall entry — AArch64 scaffold
//!
//! AArch64 uses the SVC instruction (Supervisor Call) for syscalls, which
//! triggers a synchronous exception routed through VBAR_EL1. The exception
//! handler reads ESR_EL1 to identify the SVC, extracts arguments from
//! x0-x5, and dispatches to the kernel syscall handler.
//!
//! ## Register convention (Linux-compatible)
//! | Register | Purpose        |
//! |----------|----------------|
//! | x8       | Syscall number |
//! | x0-x5    | Arguments      |
//! | x0       | Return value   |

/// Initialize syscall handling.
///
/// On AArch64, this configures the VBAR_EL1 exception vector table
/// to route SVC exceptions to the kernel syscall dispatcher.
///
/// # Safety
/// Must be called during boot with interrupts masked.
pub unsafe fn init() {
    todo!("AArch64: configure VBAR_EL1 for SVC routing")
}
