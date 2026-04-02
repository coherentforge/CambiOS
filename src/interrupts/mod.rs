//! Interrupt handling subsystem
//!
//! Manages interrupt descriptor tables, exception handlers, interrupt routing,
//! PIC initialization, and PIT timer configuration.
//!
//! ## Interrupt Vectors
//! - 0-31: CPU exceptions (divide error, page fault, etc.)
//! - 32-39: Master PIC (IRQ 0-7) — timer at 32
//! - 40-47: Slave PIC (IRQ 8-15)
//! - 48+: Available for software interrupts / APIC

use x86_64::structures::idt::InterruptDescriptorTable;

pub mod routing;
pub mod pic;
pub mod pit;

pub use routing::{InterruptRoutingTable, InterruptRoute, IrqNumber, InterruptContext, InterruptRoutingError};
pub use pic::{PIC1_OFFSET, PIC2_OFFSET, TIMER_VECTOR};

static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

/// Exception types and their handlers
pub mod exceptions {
    use x86_64::structures::idt::InterruptStackFrame;

    /// Division by zero exception handler
    pub extern "x86-interrupt" fn divide_by_zero(stack_frame: InterruptStackFrame) {
        crate::println!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
        loop {}
    }

    /// General protection fault handler
    pub extern "x86-interrupt" fn general_protection_fault(
        stack_frame: InterruptStackFrame,
        error_code: u64,
    ) {
        crate::println!(
            "EXCEPTION: GENERAL PROTECTION FAULT (code: {:#x})\n{:#?}",
            error_code, stack_frame
        );
        loop {}
    }

    /// Page fault handler
    pub extern "x86-interrupt" fn page_fault(
        stack_frame: InterruptStackFrame,
        error_code: x86_64::structures::idt::PageFaultErrorCode,
    ) {
        crate::println!(
            "EXCEPTION: PAGE FAULT (code: {:#?})\n{:#?}",
            error_code, stack_frame
        );
        loop {}
    }

    /// Double fault handler (non-recoverable)
    pub extern "x86-interrupt" fn double_fault(
        stack_frame: InterruptStackFrame,
        error_code: u64,
    ) -> ! {
        crate::println!(
            "EXCEPTION: DOUBLE FAULT (code: {:#x})\n{:#?}",
            error_code, stack_frame
        );
        loop {}
    }
}

/// Initialize interrupt handling (exceptions only, no hardware interrupts yet)
///
/// Call `init_hardware_interrupts()` separately after kernel subsystems are ready.
pub unsafe fn init() {
    configure_idt();
    (*(&raw const IDT)).load();
}

/// Initialize hardware interrupts (PIC + PIT + timer IDT entry)
///
/// Must be called after scheduler, timer, and other subsystems are initialized.
/// Enables the PIT timer at the given frequency and unmasks IRQ 0.
///
/// # Safety
/// Must be called exactly once, after `init()` and subsystem initialization.
pub unsafe fn init_hardware_interrupts(timer_frequency_hz: u32) {
    // Remap PIC: IRQ 0-7 → vectors 32-39, IRQ 8-15 → vectors 40-47
    pic::init();

    // Register timer interrupt handler at vector 32 (IRQ 0)
    (&mut (*(&raw mut IDT)))[TIMER_VECTOR as usize]
        .set_handler_fn(timer_interrupt_handler);

    // Reload IDT with new entry
    (*(&raw const IDT)).load();

    // Configure PIT at requested frequency
    let divisor = pit::init(timer_frequency_hz);
    crate::println!("  ✓ PIT initialized: {}Hz (divisor {})", timer_frequency_hz, divisor);

    // Enable interrupts
    x86_64::instructions::interrupts::enable();
    crate::println!("  ✓ Hardware interrupts enabled");
}

/// Timer interrupt handler (vector 32, IRQ 0)
///
/// Called on every PIT tick. This is the preemption entry point:
/// 1. Signals the timer subsystem
/// 2. Ticks the scheduler's time accounting
/// 3. If time slice expired, performs logical scheduling (task state transitions)
/// 4. Sends EOI to PIC
///
/// Context switch integration:
/// This handler uses the `x86-interrupt` ABI, which means the compiler handles
/// register save/restore. For actual context switching (swapping which task runs),
/// the handler saves the preempted task's CpuContext and loads the next task's.
/// The `iretq` inserted by the compiler then returns to the NEW task's code.
///
/// NOTE: Currently performs logical scheduling only. Full register-level context
/// switching requires an assembly ISR stub (see arch::SavedContext) which will
/// replace this handler when userspace tasks are loaded.
extern "x86-interrupt" fn timer_interrupt_handler(
    _stack_frame: x86_64::structures::idt::InterruptStackFrame,
) {
    // Tick the timer (minimal scope)
    {
        let mut timer = crate::TIMER.lock();
        if let Some(t) = timer.as_mut() {
            t.on_tick();
        }
    }

    // Tick the scheduler and check for preemption
    {
        let mut scheduler = crate::SCHEDULER.lock();
        if let Some(sched) = scheduler.as_mut() {
            let needs_switch = sched.tick();

            if let Some(_preempted_task) = needs_switch {
                // Time slice expired — perform logical context switch
                match sched.schedule() {
                    Ok(_next_task) => {
                        // Logical switch done. Task state updated.
                        // When assembly ISR stub is integrated, this is where
                        // we'd swap SavedContext pointers for actual switching.
                    }
                    Err(_e) => {
                        // Schedule failed — leave current task running
                    }
                }
            }
        }
    }

    // Send End-of-Interrupt to PIC (MUST happen before iretq)
    unsafe {
        pic::send_eoi(0); // IRQ 0 = timer
    }
}

/// Configure the interrupt descriptor table
unsafe fn configure_idt() {
    (*(&raw mut IDT)).divide_error.set_handler_fn(exceptions::divide_by_zero);
    (*(&raw mut IDT)).general_protection_fault
        .set_handler_fn(exceptions::general_protection_fault);
    (*(&raw mut IDT)).page_fault.set_handler_fn(exceptions::page_fault);
    (*(&raw mut IDT)).double_fault.set_handler_fn(exceptions::double_fault);
}

/// Request interrupt with verification contract
pub fn request_interrupt(irq: u8) -> Result<(), InterruptError> {
    if irq < 16 {
        Ok(())
    } else {
        Err(InterruptError::InvalidIrq(irq))
    }
}

/// Interrupt subsystem errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptError {
    InvalidIrq(u8),
    AlreadyRegistered,
    NotInitialized,
}

/// Get current IDT state
pub fn idt_loaded() -> bool {
    true // Placeholder; in full implementation, track via atomic flag
}
