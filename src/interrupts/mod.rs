// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Interrupt handling subsystem
//!
//! Manages interrupt descriptor tables, exception handlers, and interrupt routing.
//!
//! ## Interrupt Vectors
//! - 0-31: CPU exceptions (divide error, page fault, etc.)
//! - 32: APIC timer (periodic, drives preemptive scheduling)
//! - 33-56: Device IRQs via I/O APIC (keyboard, serial, IDE, etc.)
//! - 0xFE: TLB shootdown IPI
//! - 0xFF: APIC spurious interrupt
//!
//! The 8259 PIC is remapped to 0xF0-0xFF and fully masked at boot.
//! All hardware interrupts are delivered through the Local APIC.

extern crate alloc;

#[cfg(target_arch = "x86_64")]
use x86_64::structures::idt::InterruptDescriptorTable;
use core::sync::atomic::{AtomicBool, Ordering};

pub mod routing;
#[cfg(target_arch = "x86_64")]
pub mod pic;
#[cfg(target_arch = "x86_64")]
pub mod pit;

pub use routing::{InterruptRoutingTable, InterruptRoute, IrqNumber, InterruptContext, InterruptRoutingError};

/// Interrupt descriptor table.
///
/// # Safety
/// Mutable static — all writes happen during single-threaded init (`init()`
/// and `init_hardware_interrupts()`) before interrupts are enabled, so no
/// concurrent access is possible. After `load()`, only the CPU reads it.
#[cfg(target_arch = "x86_64")]
static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

/// Tracks whether the IDT has been loaded (set once during `init()`).
#[cfg(target_arch = "x86_64")]
static IDT_LOADED: AtomicBool = AtomicBool::new(false);

/// Exception types and their handlers
#[cfg(target_arch = "x86_64")]
pub mod exceptions {
    use x86_64::structures::idt::InterruptStackFrame;

    /// Division by zero exception handler.
    ///
    /// User-mode: terminate the faulting task.
    /// Kernel-mode: unrecoverable — halt.
    pub extern "x86-interrupt" fn divide_by_zero(stack_frame: InterruptStackFrame) {
        let cs = stack_frame.code_segment;
        let is_user = (cs & 0x3) == 3;

        if is_user {
            if let Some(task_id) = crate::terminate_current_task() {
                crate::println!(
                    "  [DivZero] Task {} killed: RIP={:#x}",
                    task_id.0, stack_frame.instruction_pointer.as_u64()
                );
            }
        } else {
            crate::println!(
                "\n!!! KERNEL DIVIDE BY ZERO !!!\n{:#?}",
                stack_frame
            );
            crate::halt();
        }
    }

    /// General protection fault handler.
    ///
    /// User-mode GPF: terminate the faulting task.
    /// Kernel-mode GPF: unrecoverable — halt with diagnostics.
    pub extern "x86-interrupt" fn general_protection_fault(
        stack_frame: InterruptStackFrame,
        error_code: u64,
    ) {
        // CS RPL bits [1:0] indicate the privilege level of the interrupted code.
        // CPL=3 (user mode) if bits [1:0] of CS == 3.
        let cs = stack_frame.code_segment;
        let is_user = (cs & 0x3) == 3;

        if is_user {
            if let Some(task_id) = crate::terminate_current_task() {
                crate::println!(
                    "  [GPF] Task {} killed: code={:#x} RIP={:#x}",
                    task_id.0, error_code, stack_frame.instruction_pointer.as_u64()
                );
            }
        } else {
            crate::println!(
                "\n!!! KERNEL GPF !!!\n  Error code: {:#x}\n{:#?}",
                error_code, stack_frame
            );
            crate::halt();
        }
    }

    /// Page fault handler (vector 14).
    ///
    /// Distinguishes user-mode faults (terminate the offending task) from
    /// kernel-mode faults (unrecoverable — panic with diagnostics).
    ///
    /// ## Error code bits (x86_64)
    /// - Bit 0 (PRESENT): 0 = page not present, 1 = protection violation
    /// - Bit 1 (WRITE): 0 = read access, 1 = write access
    /// - Bit 2 (USER): 0 = kernel mode, 1 = user mode
    /// - Bit 4 (INSTRUCTION_FETCH): 1 = caused by instruction fetch
    pub extern "x86-interrupt" fn page_fault(
        stack_frame: InterruptStackFrame,
        error_code: x86_64::structures::idt::PageFaultErrorCode,
    ) {
        use x86_64::registers::control::Cr2;
        use x86_64::structures::idt::PageFaultErrorCode;

        let faulting_addr = Cr2::read_raw();
        let is_user = error_code.contains(PageFaultErrorCode::USER_MODE);
        let is_write = error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
        let is_present = error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
        let is_fetch = error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH);

        if is_user {
            // User-mode page fault: terminate the faulting task
            let fault_type = if is_present { "protection" } else { "not-present" };
            let access = if is_fetch { "execute" } else if is_write { "write" } else { "read" };

            if let Some(task_id) = crate::terminate_current_task() {
                crate::println!(
                    "  [PageFault] Task {} killed: {} {} at {:#x} (RIP={:#x})",
                    task_id.0, fault_type, access, faulting_addr, stack_frame.instruction_pointer.as_u64()
                );
            } else {
                crate::println!(
                    "  [PageFault] User fault at {:#x} but no current task to kill",
                    faulting_addr
                );
            }

            // Return from the handler — the task is now Terminated.
            // The next timer tick will context-switch to a Ready task.
            // The terminated task's iretq frame is still on the stack,
            // but the scheduler will never schedule it again.
        } else {
            // Kernel-mode page fault: unrecoverable — halt with diagnostics
            let fault_type = if is_present { "protection" } else { "not-present" };
            let access = if is_fetch { "execute" } else if is_write { "write" } else { "read" };

            crate::println!(
                "\n!!! KERNEL PAGE FAULT !!!\n  Address: {:#x}\n  Type: {} {}\n  Error code: {:?}\n{:#?}",
                faulting_addr, fault_type, access, error_code, stack_frame
            );
            crate::halt();
        }
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
        loop { x86_64::instructions::hlt(); }
    }

    /// APIC spurious interrupt handler.
    ///
    /// Per Intel SDM: do NOT send EOI for spurious interrupts.
    pub extern "x86-interrupt" fn spurious_interrupt(_stack_frame: InterruptStackFrame) {
        // Intentionally empty — no EOI
    }
}

/// Device IRQ handlers for I/O APIC-routed interrupts.
///
/// Each handler corresponds to a specific GSI (Global System Interrupt).
/// The vector number is DEVICE_VECTOR_BASE (33) + GSI.
/// Handlers wake tasks blocked via SYS_WAIT_IRQ and send APIC EOI.
#[cfg(target_arch = "x86_64")]
pub mod device_irqs {
    use x86_64::structures::idt::InterruptStackFrame;

    /// Common device IRQ handler — wakes blocked tasks and sends EOI.
    ///
    /// Called from each per-GSI ISR stub. If the IRQ has a registered handler
    /// (via SYS_WAIT_IRQ + interrupt routing table), uses TASK_CPU_MAP for a
    /// targeted single-CPU wake. Otherwise falls back to scanning all CPUs.
    ///
    /// IRQ affinity (set by SYS_WAIT_IRQ) routes the interrupt to the same
    /// CPU as the pinned driver task, so the targeted path is the common case
    /// for registered device IRQs.
    fn device_irq_handler(gsi: u32) {
        let mut woken = false;

        // Fast path: look up the registered handler task for this IRQ and
        // wake only on its owning CPU (avoids N-CPU scan).
        if let Some(router_guard) = crate::INTERRUPT_ROUTER.try_lock() {
            let irq = crate::interrupts::routing::IrqNumber(gsi as u8);
            if let Some(route) = router_guard.lookup(irq) {
                let task_id = route.handler_task;
                drop(router_guard);
                if let Some(cpu) = crate::get_task_cpu(task_id.0) {
                    let cpu = cpu as usize;
                    if let Some(mut sched_guard) = crate::PER_CPU_SCHEDULER[cpu].try_lock() {
                        if let Some(sched) = sched_guard.as_mut() {
                            sched.wake_irq_waiters(gsi);
                            woken = true;
                        }
                    }
                }
            }
        }

        // Slow path: no registered handler, or try_lock failed — scan all CPUs
        if !woken {
            let count = crate::arch::x86_64::percpu::cpu_count() as usize;
            for cpu in 0..count {
                if let Some(mut sched_guard) = crate::PER_CPU_SCHEDULER[cpu].try_lock() {
                    if let Some(sched) = sched_guard.as_mut() {
                        sched.wake_irq_waiters(gsi);
                    }
                }
            }
        }

        // EOI must always be sent, regardless of whether we woke a task
        // SAFETY: We are in an APIC-delivered interrupt handler.
        // The I/O APIC routes this interrupt through the Local APIC,
        // which requires EOI to clear the in-service bit.
        unsafe { crate::arch::x86_64::apic::write_eoi(); }
    }

    // Generate per-GSI ISR handlers via macro.
    // Each handler is a thin trampoline that calls device_irq_handler(N).
    macro_rules! device_isr {
        ($name:ident, $gsi:expr) => {
            pub extern "x86-interrupt" fn $name(_sf: InterruptStackFrame) {
                device_irq_handler($gsi);
            }
        };
    }

    // GSI 0 is the PIT timer (already handled by APIC timer), but we generate
    // a handler anyway for completeness (e.g., if I/O APIC IRQ 0 override exists).
    device_isr!(gsi_0,  0);
    device_isr!(gsi_1,  1);
    device_isr!(gsi_2,  2);
    device_isr!(gsi_3,  3);
    device_isr!(gsi_4,  4);
    device_isr!(gsi_5,  5);
    device_isr!(gsi_6,  6);
    device_isr!(gsi_7,  7);
    device_isr!(gsi_8,  8);
    device_isr!(gsi_9,  9);
    device_isr!(gsi_10, 10);
    device_isr!(gsi_11, 11);
    device_isr!(gsi_12, 12);
    device_isr!(gsi_13, 13);
    device_isr!(gsi_14, 14);
    device_isr!(gsi_15, 15);
    device_isr!(gsi_16, 16);
    device_isr!(gsi_17, 17);
    device_isr!(gsi_18, 18);
    device_isr!(gsi_19, 19);
    device_isr!(gsi_20, 20);
    device_isr!(gsi_21, 21);
    device_isr!(gsi_22, 22);
    device_isr!(gsi_23, 23);

    /// Array of device ISR function pointers, indexed by GSI.
    /// Used to register handlers in the IDT during init.
    pub const HANDLERS: [extern "x86-interrupt" fn(InterruptStackFrame); 24] = [
        gsi_0,  gsi_1,  gsi_2,  gsi_3,  gsi_4,  gsi_5,  gsi_6,  gsi_7,
        gsi_8,  gsi_9,  gsi_10, gsi_11, gsi_12, gsi_13, gsi_14, gsi_15,
        gsi_16, gsi_17, gsi_18, gsi_19, gsi_20, gsi_21, gsi_22, gsi_23,
    ];
}

/// Register device ISR handlers in the IDT for I/O APIC vectors.
///
/// Installs handlers for vectors DEVICE_VECTOR_BASE..DEVICE_VECTOR_BASE+24
/// (vectors 33-56), one per GSI.
///
/// # Safety
/// Must be called during single-threaded init before IDT reload.
#[cfg(target_arch = "x86_64")]
pub unsafe fn register_device_isrs() {
    use crate::arch::x86_64::ioapic::DEVICE_VECTOR_BASE;

    // SAFETY: Single-threaded init before IDT reload. IDT is a mutable static
    // but no concurrent access is possible with interrupts disabled.
    unsafe {
        let idt = &mut *(&raw mut IDT);
        for (gsi, handler) in device_irqs::HANDLERS.iter().enumerate() {
            let vector = DEVICE_VECTOR_BASE as usize + gsi;
            idt[vector].set_handler_fn(*handler);
        }
    }
}

/// Initialize interrupt handling (exceptions only, no hardware interrupts yet)
///
/// Call `init_hardware_interrupts()` separately after kernel subsystems are ready.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init() {
    // SAFETY: Single-threaded init — interrupts are disabled, no concurrent access.
    unsafe {
        configure_idt();
        (*(&raw const IDT)).load();
    }
    IDT_LOADED.store(true, Ordering::Release);
}

/// Initialize hardware interrupts (APIC timer, I/O APIC, device IRQs).
///
/// Replaces the legacy PIC/PIT with the Local APIC + I/O APIC:
/// 1. Disable PIC (remap to 0xF0-0xFF, mask all)
/// 2. Enable Local APIC + per-CPU data
/// 3. Parse ACPI MADT + initialize I/O APIC (if RSDP available)
/// 4. Register timer ISR, device ISRs, and spurious handler in IDT
/// 5. Allocate IST stack for double-fault handler
/// 6. Reload IDT, configure I/O APIC device IRQ routing
/// 7. Calibrate and start APIC timer
/// 8. Enable interrupts
///
/// # Arguments
/// - `timer_frequency_hz`: APIC timer frequency (typically 100 Hz)
/// - `rsdp_phys`: Physical address of ACPI RSDP (0 = skip I/O APIC setup)
///
/// # Safety
/// Must be called exactly once, after `init()` and subsystem initialization.
/// Kernel heap must be initialized (for IST stack allocation).
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_hardware_interrupts(timer_frequency_hz: u32, rsdp_phys: u64) {
    use crate::arch::x86_64::{apic, gdt, ioapic};

    // Step 1: Disable PIC — remap to 0xF0-0xFF and mask all lines
    // SAFETY: Called during single-threaded boot with interrupts disabled.
    unsafe { apic::disable_pic(); }
    crate::println!("  PIC disabled (remapped to 0xF0, masked)");

    // Step 2: Enable Local APIC
    // SAFETY: HHDM offset is set, single-threaded boot, interrupts disabled.
    unsafe { apic::detect_and_init().expect("APIC initialization failed"); }

    // Step 2b: Initialize per-CPU data for BSP
    // SAFETY: APIC is initialized (ID readable). Single-threaded boot, interrupts disabled.
    let bsp_apic_id = unsafe { apic::read_apic_id() };
    {
        // SAFETY: Single-threaded boot, BSP only, APIC ID is valid.
        unsafe { crate::arch::x86_64::percpu::init_bsp(bsp_apic_id); }
        crate::println!("  Per-CPU data initialized (BSP, APIC ID={})", bsp_apic_id);
    }

    // Step 3: Parse ACPI and initialize I/O APIC (if RSDP available)
    let acpi_info = if rsdp_phys != 0 {
        crate::println!("  Parsing ACPI tables (RSDP @ {:#x})...", rsdp_phys);
        // SAFETY: rsdp_phys is a valid RSDP address from Limine. Single-threaded boot.
        match unsafe { crate::acpi::parse_acpi(rsdp_phys) } {
            Ok(info) => {
                crate::println!(
                    "  MADT: {} I/O APIC(s), {} override(s), LAPIC @ {:#x}",
                    info.io_apic_count, info.override_count, info.local_apic_address
                );

                // Initialize the primary I/O APIC
                // SAFETY: ACPI info is valid, single-threaded boot.
                match unsafe { ioapic::init(&info) } {
                    Ok(()) => crate::println!("  ✓ I/O APIC initialized"),
                    Err(e) => crate::println!("  WARNING: I/O APIC init failed: {}", e),
                }

                Some(info)
            }
            Err(e) => {
                crate::println!("  WARNING: ACPI parse failed: {}", e);
                None
            }
        }
    } else {
        crate::println!("  No RSDP — skipping I/O APIC (device IRQs unavailable)");
        None
    };

    // Step 4a: Register timer ISR stub at vector 32
    extern "C" {
        fn timer_isr_stub();
    }
    // SAFETY: Single-threaded init. timer_isr_stub is our global_asm symbol.
    // IDT is a mutable static but no concurrent access with interrupts disabled.
    unsafe {
        (&mut (*(&raw mut IDT)))[apic::TIMER_VECTOR as usize]
            .set_handler_addr(x86_64::VirtAddr::new(timer_isr_stub as *const () as u64));
    }

    // Step 4b: Register spurious interrupt handler at vector 0xFF
    // SAFETY: Single-threaded init, within IDT bounds.
    unsafe {
        (&mut (*(&raw mut IDT)))[0xFF_usize]
            .set_handler_fn(exceptions::spurious_interrupt);
    }

    // Step 4c: Register device ISR handlers at vectors 33-56 (if I/O APIC available)
    if acpi_info.is_some() {
        // SAFETY: Single-threaded init, IDT not yet reloaded.
        unsafe { register_device_isrs(); }
        crate::println!("  Device ISR handlers registered (vectors 33-56)");
    }

    // Step 4d: Register TLB shootdown IPI handler at vector 0xFE
    // SAFETY: Single-threaded init, within IDT bounds.
    {
        use crate::arch::x86_64::tlb;
        unsafe {
            (&mut (*(&raw mut IDT)))[tlb::TLB_SHOOTDOWN_VECTOR as usize]
                .set_handler_fn(tlb::tlb_shootdown_isr);
        }
        crate::println!("  TLB shootdown handler registered (vector {:#x})", tlb::TLB_SHOOTDOWN_VECTOR);
    }

    // Step 5: Allocate IST stack for double-fault (4 KB)
    {
        use alloc::alloc::{alloc, Layout};
        const IST_STACK_SIZE: usize = 4096;
        let layout = Layout::from_size_align(IST_STACK_SIZE, 16)
            .expect("IST stack layout");
        // SAFETY: Kernel heap is initialized. Layout is valid.
        let ist_base = unsafe { alloc(layout) };
        if ist_base.is_null() {
            panic!("Failed to allocate double-fault IST stack");
        }
        let ist_top = ist_base as u64 + IST_STACK_SIZE as u64;

        // SAFETY: Interrupts disabled, single-threaded.
        unsafe { gdt::set_ist(0, ist_top); }

        // Wire double-fault IDT entry to use IST1 (hardware IST index 1 = TSS.ist[0])
        // SAFETY: Single-threaded init, IDT not yet reloaded.
        unsafe {
            (*(&raw mut IDT)).double_fault
                .set_handler_fn(exceptions::double_fault)
                .set_stack_index(0); // x86_64 crate: 0 maps to IST1
        }

        crate::println!("  IST1 (double-fault): {:#x}", ist_top);
    }

    // Step 6a: Reload IDT with all handlers (timer, device ISRs, exceptions)
    // SAFETY: IDT is fully configured. Reloading makes the CPU pick up all handlers.
    unsafe { (*(&raw const IDT)).load(); }

    // Step 6b: Configure I/O APIC device IRQ routing (after IDT loaded)
    if let Some(ref info) = acpi_info {
        // SAFETY: IDT loaded, I/O APIC initialized. Single-threaded boot.
        unsafe { ioapic::configure_device_irqs(info, bsp_apic_id as u8); }
        crate::println!("  ✓ Device IRQs routed via I/O APIC");
    }

    // Step 7: Calibrate and start APIC timer
    // SAFETY: APIC is enabled, PIC is disabled, interrupts still off.
    let _bus_freq = unsafe { apic::configure_timer(timer_frequency_hz) };

    // Step 8: Enable interrupts — all interrupt infrastructure is initialized.
    x86_64::instructions::interrupts::enable();
    crate::println!("  ✓ Interrupts enabled (APIC timer + device IRQs)");
}

/// Configure the interrupt descriptor table
///
/// # Safety
/// Must be called before `IDT.load()` and before interrupts are enabled.
/// All writes to the mutable static IDT happen here during single-threaded init.
#[cfg(target_arch = "x86_64")]
unsafe fn configure_idt() {
    // SAFETY: Single-threaded init — interrupts disabled, no concurrent IDT access.
    // Each set_handler_fn registers a valid extern "x86-interrupt" handler.
    unsafe {
        (*(&raw mut IDT)).divide_error.set_handler_fn(exceptions::divide_by_zero);
        (*(&raw mut IDT)).general_protection_fault
            .set_handler_fn(exceptions::general_protection_fault);
        (*(&raw mut IDT)).page_fault.set_handler_fn(exceptions::page_fault);
        (*(&raw mut IDT)).double_fault.set_handler_fn(exceptions::double_fault);
    }
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

/// Returns true if the IDT has been loaded via `init()`.
#[cfg(target_arch = "x86_64")]
pub fn idt_loaded() -> bool {
    IDT_LOADED.load(Ordering::Acquire)
}

/// Load the shared IDT on an Application Processor.
///
/// The IDT is configured once by the BSP during `init()` / `init_hardware_interrupts()`.
/// APs just need to execute `lidt` to point their IDTR at the same table.
///
/// # Safety
/// BSP must have fully configured and loaded the IDT before calling this.
/// Must be called with interrupts disabled.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_idt_ap() {
    // SAFETY: IDT is fully configured by BSP (IDT_LOADED is true).
    // The IDT is a global static — same virtual address on all CPUs.
    unsafe { (*(&raw const IDT)).load(); }
}
