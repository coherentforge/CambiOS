// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Interrupt handling subsystem
//!
//! On x86_64 every vector enters through one trap path ([ADR-040] § 3,
//! `arch::x86_64::trap`) and lands in [`x86_trap`], which decides what the
//! vector means:
//!
//! - 0-31: CPU exceptions. Every one has a decision ([ADR-040] § 4): from
//!   ring 3 the task is reaped ([ADR-019]); from ring 0 the CPU halts with a
//!   report; an NMI is logged and returns.
//! - 32: APIC timer (periodic, drives preemptive scheduling)
//! - 33-56: Device IRQs via I/O APIC, once the I/O APIC is routed
//! - 0xFD: reschedule IPI; 0xFE: TLB shootdown IPI
//! - 0xFF: APIC spurious interrupt (no EOI)
//! - anything else: unassigned, logged once per vector, acknowledged
//!
//! The 8259 PIC is remapped to 0xF0-0xFF and fully masked at boot.
//! All hardware interrupts are delivered through the Local APIC.
//!
//! [ADR-040]: ../../docs/adr/040-trap-entry-discipline.md
//! [ADR-019]: ../../docs/adr/019-process-fault-reaping-and-peer-generation.md

extern crate alloc;

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicBool, Ordering};

pub mod routing;
#[cfg(target_arch = "x86_64")]
pub mod pic;
#[cfg(target_arch = "x86_64")]
pub mod pit;

pub use routing::{InterruptRoutingTable, InterruptRoute, IrqNumber, InterruptContext, InterruptRoutingError};

/// Tracks whether the IDT has been loaded (set once during `init()`).
#[cfg(target_arch = "x86_64")]
static IDT_LOADED: AtomicBool = AtomicBool::new(false);

/// Set once the I/O APIC is initialized and the device vectors (33-56)
/// mean device interrupts. Until then those vectors are unassigned.
#[cfg(target_arch = "x86_64")]
static DEVICE_IRQS_LIVE: AtomicBool = AtomicBool::new(false);

/// The x86_64 trap dispatch ([ADR-040] § 3, § 4), called by the common trap
/// entry with interrupts disabled (every gate is an interrupt gate) on the
/// stack the CPU chose: the task's kernel stack from ring 3, the current
/// stack from ring 0, or an IST stack for NMI, #DF and #MC.
///
/// `ctx` is the `SavedContext` the entry built; `vector` and `error` are
/// copies of its two trap slots. Returns the stack pointer of the context
/// the common exit resumes: `ctx` itself, or another task's saved context
/// after the timer or reschedule handler switched.
///
/// [ADR-040]: ../../docs/adr/040-trap-entry-discipline.md
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "C" fn x86_trap(ctx: *mut crate::arch::x86_64::SavedContext, vector: u64, error: u64) -> u64 {
    use crate::arch::x86_64::{apic, ioapic, tlb, RESCHED_VECTOR};

    let rsp = ctx as u64;
    let Ok(vector) = u8::try_from(vector) else {
        // The stubs push 0-255 only: the entry read the wrong slot.
        exceptions::halt_bad_vector(vector)
    };
    let device_base = ioapic::DEVICE_VECTOR_BASE;
    let device_end = device_base as usize + ioapic::MAX_GSI_PINS;
    match vector {
        0..=31 => {
            // SAFETY: ctx is the SavedContext the common entry just built on
            // this stack; it stays in place for this call, and nothing else
            // refers to it while the handler reads it.
            let frame = unsafe { &*ctx };
            exceptions::handle(frame, vector, error);
            rsp
        }
        apic::TIMER_VECTOR => crate::arch::x86_64::timer_isr_inner(rsp),
        RESCHED_VECTOR => crate::arch::x86_64::resched_isr_inner(rsp),
        tlb::TLB_SHOOTDOWN_VECTOR => {
            tlb::tlb_shootdown_isr();
            rsp
        }
        // Intel SDM Vol. 3A § 11.9: no EOI for the spurious vector.
        apic::SPURIOUS_VECTOR => rsp,
        v if v >= device_base
            && (v as usize) < device_end
            && DEVICE_IRQS_LIVE.load(Ordering::Acquire) =>
        {
            device_irqs::device_irq_handler(u32::from(v - device_base));
            rsp
        }
        v => {
            unassigned_vector(v);
            rsp
        }
    }
}

/// ARCHITECTURAL: words of the once-per-vector log bitmap: 256 vectors at
/// 64 bits a word.
#[cfg(target_arch = "x86_64")]
const UNASSIGNED_SEEN_WORDS: usize = 4;

/// Vectors already reported as unassigned (one bit each), so a stray
/// source is logged once, not at its interrupt rate.
#[cfg(target_arch = "x86_64")]
static UNASSIGNED_SEEN: [core::sync::atomic::AtomicU64; UNASSIGNED_SEEN_WORDS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; UNASSIGNED_SEEN_WORDS];

/// A vector nothing claims ([ADR-040] § 3, stub obligation 7): log it the
/// first time, acknowledge it, return. It must not be mistaken for a fault
/// of whichever task was running.
///
/// [ADR-040]: ../../docs/adr/040-trap-entry-discipline.md
#[cfg(target_arch = "x86_64")]
fn unassigned_vector(vector: u8) {
    let bit = 1u64 << (vector % 64);
    if let Some(word) = UNASSIGNED_SEEN.get(usize::from(vector / 64)) {
        if word.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            let _ = crate::io::try_print(format_args!(
                "  [trap] vector {:#x} has no handler; acknowledged and ignored\n",
                vector
            ));
        }
    }
    // SAFETY: an external or IPI vector reaches here only with interrupts
    // enabled, which init_hardware_interrupts does after the Local APIC is
    // initialized; an EOI with nothing in service is ignored by the APIC.
    unsafe { crate::arch::x86_64::apic::write_eoi() };
}

/// The decisions for exception vectors 0-31 ([ADR-040] § 4).
///
/// [ADR-040]: ../../docs/adr/040-trap-entry-discipline.md
#[cfg(target_arch = "x86_64")]
pub mod exceptions {
    use crate::arch::x86_64::SavedContext;
    use crate::reap::FaultKind;

    /// The architectural name of exception `vector` (Intel SDM Vol. 3A
    /// Table 6-1; AMD APM Vol. 2 § 8.2 for 28-30).
    pub const fn name(vector: u8) -> &'static str {
        match vector {
            0 => "DIVIDE ERROR",
            1 => "DEBUG",
            2 => "NMI",
            3 => "BREAKPOINT",
            4 => "OVERFLOW",
            5 => "BOUND RANGE EXCEEDED",
            6 => "INVALID OPCODE",
            7 => "DEVICE NOT AVAILABLE",
            8 => "DOUBLE FAULT",
            9 => "COPROCESSOR SEGMENT OVERRUN",
            10 => "INVALID TSS",
            11 => "SEGMENT NOT PRESENT",
            12 => "STACK-SEGMENT FAULT",
            13 => "GENERAL PROTECTION",
            14 => "PAGE FAULT",
            16 => "x87 FLOATING-POINT",
            17 => "ALIGNMENT CHECK",
            18 => "MACHINE CHECK",
            19 => "SIMD FLOATING-POINT",
            20 => "VIRTUALIZATION",
            21 => "CONTROL PROTECTION",
            28 => "HYPERVISOR INJECTION",
            29 => "VMM COMMUNICATION",
            30 => "SECURITY",
            _ => "RESERVED",
        }
    }

    /// TUNING: `try_print` attempts a halting CPU makes before it gives up
    /// on its report. A report waits out another CPU's print this way, and
    /// does not hang when the lock's holder is the code this CPU
    /// interrupted (which a spinning `println!` would). About a millisecond
    /// of spinning on current hardware.
    const REPORT_ATTEMPTS: u32 = 1 << 20;

    /// Print a halting report without spinning on a lock forever.
    fn report(args: core::fmt::Arguments) {
        for _ in 0..REPORT_ATTEMPTS {
            if crate::io::try_print(args) {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// Reap the current user task for a fault and never return
    /// (ADR-019 § Decision 6). Runs on the faulting task's own kernel
    /// stack (the CPL3→0 transition loaded TSS RSP0; ADR-040 § 4 keeps every
    /// trap that reaches here off the IST stacks), so re-enabling
    /// interrupts here is exactly the syscall path's posture — and it is
    /// required: the reap spins on cross-CPU TLB-shootdown acks, which a
    /// masked CPU can neither send nor answer. The task is about to be
    /// marked Terminated, so nothing re-enters it; the terminal yield
    /// loop never returns. Callers must have read CR2 (page faults)
    /// before this, since a nested #PF would clobber it.
    fn reap_user_fault(kind: FaultKind, fault_addr: u64, pc: u64) -> ! {
        x86_64::instructions::interrupts::enable();
        if !crate::reap::reap_faulting_current(kind, fault_addr, pc) {
            // A user-mode fault with no current process is a broken
            // kernel invariant; iretq would re-fault at hardware speed.
            crate::println!(
                "\n!!! USER FAULT WITH NO CURRENT PROCESS !!!\n  {:?} at {:#x} (RIP={:#x})",
                kind, fault_addr, pc
            );
            crate::halt();
        }
        loop {
            // SAFETY: Kernel stack, scheduler lock not held. The task is
            // Terminated and never re-scheduled, so this does not return.
            unsafe { crate::arch::yield_save_and_switch(); }
        }
    }

    /// The decision for exception `vector` with error code `error` and the
    /// interrupted context `frame`. Returns only for an NMI.
    pub fn handle(frame: &SavedContext, vector: u8, error: u64) {
        match vector {
            2 => {
                nmi(frame);
                return;
            }
            // A double fault or machine check may have been caused by the
            // very state a report would read (the stack, per-CPU data), and
            // neither is the interrupted task's fault.
            8 | 18 => halt_with_report(frame, vector, error, 0, false),
            _ => {}
        }
        // CR2 before anything else: the code below could take a nested
        // page fault, which would overwrite it.
        let cr2 = if vector == 14 { x86_64::registers::control::Cr2::read_raw() } else { 0 };
        if frame.cs & 0x3 == 3 {
            let (kind, fault_addr) = match vector {
                0 => (FaultKind::DivideByZero, 0),
                6 => (FaultKind::InvalidOpcode, 0),
                // A #GP has no faulting address; its error code rides in
                // the fault_addr slot.
                13 => (FaultKind::GeneralProtection, error),
                14 => {
                    crate::println!(
                        "  [PageFault] user {} at {:#x} (RIP={:#x})",
                        page_fault_kind(error), cr2, frame.rip
                    );
                    (FaultKind::PageFault, cr2)
                }
                v => (FaultKind::ArchSpecific(v), error),
            };
            reap_user_fault(kind, fault_addr, frame.rip);
        }
        halt_with_report(frame, vector, error, cr2, true)
    }

    /// "protection write", "not-present read", ... from a #PF error code
    /// (bit 0 present, bit 1 write, bit 4 instruction fetch).
    fn page_fault_kind(error: u64) -> &'static str {
        let present = error & 0x1 != 0;
        let write = error & 0x2 != 0;
        let fetch = error & 0x10 != 0;
        match (present, fetch, write) {
            (true, true, _) => "protection execute",
            (true, false, true) => "protection write",
            (true, false, false) => "protection read",
            (false, true, _) => "not-present execute",
            (false, false, true) => "not-present write",
            (false, false, false) => "not-present read",
        }
    }

    /// An NMI is not the interrupted task's doing: log it and resume. Runs
    /// on the NMI IST stack, so it must not take an exception (the `iretq`
    /// of a nested one would re-enable NMIs, and a second NMI would reuse
    /// this stack) and must not switch tasks (ADR-040 § 4): one
    /// best-effort print, nothing else.
    fn nmi(frame: &SavedContext) {
        let _ = crate::io::try_print(format_args!(
            "[NMI] at RIP={:#x} CS={:#x}; resumed\n",
            frame.rip, frame.cs
        ));
    }

    /// Report an exception the kernel cannot recover from and halt this CPU.
    /// `with_per_cpu` adds the CPU and task (read through GS), which a
    /// double fault or machine check skips.
    fn halt_with_report(frame: &SavedContext, vector: u8, error: u64, cr2: u64, with_per_cpu: bool) -> ! {
        report(format_args!(
            "\nEXCEPTION: {} in ring {} (vector {}, error code {:#x})\n  RIP={:#x} CS={:#x} RFLAGS={:#x} RSP={:#x} SS={:#x}\n",
            name(vector), frame.cs & 0x3, vector, error,
            frame.rip, frame.cs, frame.rflags, frame.rsp, frame.ss
        ));
        if vector == 14 {
            report(format_args!("  page fault: {} at CR2={:#x}\n", page_fault_kind(error), cr2));
        }
        if with_per_cpu && crate::per_cpu_live() {
            // SAFETY: per_cpu_live() says this CPU's GS base was set (the
            // boot CPU in init_bsp; every AP initializes its own first).
            let cpu = unsafe { crate::arch::percpu::current_cpu_id() };
            let task = crate::local_scheduler().try_lock().and_then(|guard| {
                guard.as_ref().and_then(|s| s.current_task().map(|t| t.slot()))
            });
            report(format_args!("  CPU {} task {:?}\n", cpu, task));
        }
        crate::halt()
    }

    /// A trap whose vector slot held something no stub pushes.
    pub fn halt_bad_vector(vector: u64) -> ! {
        report(format_args!("\nEXCEPTION: trap entry read vector {:#x}, which no stub pushes\n", vector));
        crate::halt()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn every_architectural_exception_has_a_name() {
            for v in [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 28, 29, 30] {
                assert_ne!(name(v), "RESERVED", "vector {}", v);
            }
            for v in [15u8, 22, 23, 24, 25, 26, 27, 31] {
                assert_eq!(name(v), "RESERVED", "vector {}", v);
            }
        }

        #[test]
        fn page_fault_kind_decodes_the_error_bits() {
            assert_eq!(page_fault_kind(0x0), "not-present read");
            assert_eq!(page_fault_kind(0x2), "not-present write");
            assert_eq!(page_fault_kind(0x7), "protection write");
            assert_eq!(page_fault_kind(0x15), "protection execute");
            assert_eq!(page_fault_kind(0x10), "not-present execute");
        }
    }
}

/// Device IRQ handling for I/O APIC-routed interrupts.
///
/// The vector number is DEVICE_VECTOR_BASE (33) + GSI. The handler wakes
/// tasks blocked via SYS_WAIT_IRQ and sends APIC EOI.
#[cfg(target_arch = "x86_64")]
pub mod device_irqs {

    /// Common device IRQ handler — wakes blocked tasks and sends EOI.
    ///
    /// Called from `x86_trap` for vectors 33-56. If the IRQ has a registered handler
    /// (via SYS_WAIT_IRQ + interrupt routing table), uses TASK_CPU_MAP for a
    /// targeted single-CPU wake. Otherwise falls back to scanning all CPUs.
    ///
    /// IRQ affinity (set by SYS_WAIT_IRQ) routes the interrupt to the same
    /// CPU as the pinned driver task, so the targeted path is the common case
    /// for registered device IRQs.
    pub(crate) fn device_irq_handler(gsi: u32) {
        let mut woken = false;
        // Did the routing table name a driver for this GSI? `None` also
        // when the router lock was contended — in which case we must not
        // treat the IRQ as stray (see below).
        let mut registered: Option<bool> = None;

        // Fast path: look up the registered handler task for this IRQ and
        // wake only on its owning CPU (avoids N-CPU scan).
        if let Some(router_guard) = crate::INTERRUPT_ROUTER.try_lock() {
            let irq = crate::interrupts::routing::IrqNumber(gsi as u8);
            if let Some(route) = router_guard.lookup(irq) {
                registered = Some(true);
                let task_id = route.handler_task;
                drop(router_guard);
                if let Some(cpu) = crate::get_task_cpu(task_id.slot()) {
                    let cpu = cpu as usize;
                    if let Some(mut sched_guard) = crate::PER_CPU_SCHEDULER[cpu].try_lock() {
                        if let Some(sched) = sched_guard.as_mut() {
                            sched.wake_irq_waiters(gsi);
                            woken = true;
                        }
                    }
                }
            } else {
                registered = Some(false);
            }
        }

        // Slow path: no registered handler, or try_lock failed — scan all CPUs
        if !woken {
            let count = crate::arch::x86_64::percpu::cpu_count() as usize;
            for cpu in 0..count {
                if let Some(mut sched_guard) = crate::PER_CPU_SCHEDULER[cpu].try_lock() {
                    if let Some(sched) = sched_guard.as_mut() {
                        if sched.wake_irq_waiters(gsi) > 0 {
                            woken = true;
                        }
                    }
                }
            }
        }

        // Stray-interrupt storm protection. A level-triggered line that
        // no driver has claimed stays asserted after EOI and re-enters
        // this handler immediately, forever — the CPU never returns to
        // the context it interrupted. Real hardware does this (the Dell
        // Precision 3630's xHCI after RUN, 2026-10-22); QEMU never did.
        // If the routing table has no owner for the GSI and nobody was
        // woken, mask the pin; `SYS_WAIT_IRQ` unmasks it when a driver
        // registers. A contended router lock is NOT evidence of
        // strayness, so `None` leaves the pin alone.
        if registered == Some(false) && !woken {
            let idx = (gsi as usize).min(STRAY_IRQ_MASKED.len() - 1);
            // SAFETY: I/O APIC is initialized before device IRQs are
            // delivered; masking a pin from its own handler is the
            // documented way to quiesce a stray line.
            unsafe { crate::arch::x86_64::ioapic::mask_irq(gsi); }
            let prior = STRAY_IRQ_MASKED[idx].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if prior == 0 {
                // First time only; best-effort (never spins in a handler).
                crate::io::try_print(format_args!(
                    "  [IRQ] stray GSI {} (no driver registered) — masked until a driver claims it\n",
                    gsi
                ));
            }
        }

        // EOI must always be sent, regardless of whether we woke a task
        // SAFETY: We are in an APIC-delivered interrupt handler.
        // The I/O APIC routes this interrupt through the Local APIC,
        // which requires EOI to clear the in-service bit.
        unsafe { crate::arch::x86_64::apic::write_eoi(); }
    }

    /// Per-GSI count of stray-interrupt maskings (diagnostic; the first
    /// masking of each pin is logged). Sized to the I/O APIC's pins.
    /// HARDWARE: 24 redirection entries on the primary I/O APIC
    /// (`MAX_GSI_PINS`).
    static STRAY_IRQ_MASKED: [core::sync::atomic::AtomicU32; 24] =
        [const { core::sync::atomic::AtomicU32::new(0) }; 24];
}

/// Initialize interrupt handling: every IDT gate points at its trap stub
/// (ADR-040 § 3), so every exception has its decision from here on; the
/// hardware interrupt sources come up in `init_hardware_interrupts()`.
///
/// Call `init_hardware_interrupts()` separately after kernel subsystems are ready.
///
/// # Safety
///
/// Must be called once during single-threaded boot with interrupts disabled.
/// The IDT static is mutated and loaded into the CPU.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init() {
    // SAFETY: single-threaded boot, interrupts disabled (caller); no other
    // CPU has loaded the IDT.
    unsafe { crate::arch::x86_64::trap::init_idt() };
    IDT_LOADED.store(true, Ordering::Release);
}

/// Initialize hardware interrupts (APIC timer, I/O APIC, device IRQs).
///
/// Replaces the legacy PIC/PIT with the Local APIC + I/O APIC:
/// 1. Disable PIC (remap to 0xF0-0xFF, mask all)
/// 2. Enable Local APIC + per-CPU data
/// 3. Parse ACPI MADT + initialize I/O APIC (if RSDP available)
/// 4. Mark the device vectors live (the IDT already routes every vector
///    to `x86_trap`, set up by `init()`)
/// 5. Allocate the boot CPU's emergency stacks; point the NMI, #DF and #MC
///    gates at them
/// 6. Configure I/O APIC device IRQ routing
/// 7. Calibrate and start APIC timer
/// 8. Enable interrupts
///
/// # Arguments
/// - `timer_frequency_hz`: APIC timer frequency (typically 100 Hz)
/// - `rsdp_phys`: Physical address of ACPI RSDP (0 = skip I/O APIC setup)
///
/// # Safety
/// Must be called exactly once, after `init()` and subsystem initialization.
/// The frame allocator must be initialized (for the emergency stacks).
///
/// Returns `Err(BootError)` if any subsystem init step fails. `kmain`
/// dispatches to `boot::boot_failed` on error.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_hardware_interrupts(
    timer_frequency_hz: u32,
    rsdp_phys: u64,
) -> Result<(), crate::boot::BootError> {
    use crate::arch::x86_64::{apic, gdt, ioapic};
    use crate::boot::BootError;

    // Step 1: Disable PIC — remap to 0xF0-0xFF and mask all lines
    // SAFETY: Called during single-threaded boot with interrupts disabled.
    unsafe { apic::disable_pic(); }
    crate::println!("  PIC disabled (remapped to 0xF0, masked)");

    // Step 2: Enable Local APIC
    // SAFETY: HHDM offset is set, single-threaded boot, interrupts disabled.
    unsafe { apic::detect_and_init() }.map_err(|_| BootError::ApicInitFailed)?;

    // Step 2b: Initialize per-CPU data for BSP
    // SAFETY: APIC is initialized (ID readable). Single-threaded boot, interrupts disabled.
    let bsp_apic_id = unsafe { apic::read_apic_id() };
    {
        // SAFETY: Single-threaded boot, BSP only, APIC ID is valid.
        unsafe { crate::arch::x86_64::percpu::init_bsp(bsp_apic_id); }
        // The boot CPU can name itself from here on: spinlocks start
        // counting their holders (PREEMPT_DEPTH).
        crate::preempt_depth_go_live();
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

    // Step 4: The IDT already sends every vector to x86_trap (init()).
    // What changes now is what the device vectors mean: with an I/O APIC
    // they are device interrupts; without one they stay unassigned.
    if acpi_info.is_some() {
        DEVICE_IRQS_LIVE.store(true, Ordering::Release);
        crate::println!("  Device vectors 33-56 dispatch to the device IRQ handler");
    }

    // Step 5: The boot CPU's emergency stacks (ADR-040 § 7), then the three
    // gates that switch to them. Each AP allocates its own stacks in
    // `ap_entry` before it loads this IDT.
    {
        // SAFETY: on the boot CPU (index 0), interrupts disabled, after
        // gdt::init_for_cpu(0) and percpu::init_bsp (step 2b).
        unsafe { gdt::allocate_ist_stacks(0) }?;
        for slot in gdt::IstSlot::ALL {
            // SAFETY: single-threaded init, interrupts disabled; the boot
            // CPU's stack for this slot exists (above), and every AP
            // allocates its own before it loads the IDT (ap_entry).
            unsafe { crate::arch::x86_64::trap::set_gate_ist(slot.vector(), slot) };
        }
        crate::println!(
            "  Emergency stacks: {} x {} KiB (NMI, double fault, machine check)",
            gdt::IstSlot::ALL.len(),
            gdt::IST_STACK_PAGES * 4,
        );
    }

    // Step 6: Configure I/O APIC device IRQ routing
    if let Some(ref info) = acpi_info {
        // SAFETY: IDT loaded, I/O APIC initialized. Single-threaded boot.
        unsafe { ioapic::configure_device_irqs(info, bsp_apic_id as u8); }
        crate::println!("  ✓ Device IRQs routed via I/O APIC");
    }

    // Step 7: Calibrate and start APIC timer
    // SAFETY: APIC is enabled, PIC is disabled, interrupts still off.
    unsafe { apic::configure_timer(timer_frequency_hz) }
        .map_err(|_| BootError::ApicCalibrationFailed)?;

    // Step 8: Enable interrupts — all interrupt infrastructure is initialized.
    x86_64::instructions::interrupts::enable();
    crate::println!("  ✓ Interrupts enabled (APIC timer + device IRQs)");

    Ok(())
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
/// The IDT is built once by the BSP in `init()` (its IST gates in
/// `init_hardware_interrupts()`). APs execute `lidt` on the same table.
///
/// # Safety
/// BSP must have fully configured and loaded the IDT before calling this.
/// Must be called with interrupts disabled.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_idt_ap() {
    // SAFETY: the BSP built the IDT in init() (IDT_LOADED is true) and set
    // its IST gates; this AP allocated its emergency stacks first
    // (ap_entry); interrupts are disabled (caller).
    unsafe { crate::arch::x86_64::trap::load_idt() };
}
