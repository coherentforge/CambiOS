// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

//! CambiOS Microkernel Main
//!
//! Microkernel core with:
//! - Task/process scheduler (round-robin, preemptive)
//! - IPC message dispatcher
//! - Capability manager
//! - Driver and service coordination
//! - Hardware interrupt-driven preemption (APIC timer)
//!
//! Booted by Limine bootloader which provides:
//! - Higher-half direct mapping (HHDM)
//! - Physical memory map
//! - Framebuffer (optional)

extern crate cambios_core;
extern crate alloc;

// Lock hierarchy: canonical definition lives in `cambios_core::lib.rs`.
// CLAUDE.md § Lock Ordering documents the rule. Do not duplicate the
// hierarchy here — duplicates drift, and CLAUDE.md's Post-Change Review §3
// explicitly forbids it.

use alloc::boxed::Box;
use limine::BaseRevision;
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RsdpRequest,
    RequestsEndMarker, RequestsStartMarker, StackSizeRequest,
};
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::hlt;
use cambios_core::println;
use cambios_core::BOOT_MODULE_REGISTRY;
use cambios_core::scheduler::{Scheduler, Timer, TimerConfig, Priority, TaskId};
use cambios_core::ipc::{EndpointId, IpcManager, ProcessId, CapabilityRights};

// Use the global statics from the library crate
use cambios_core::{PER_CPU_SCHEDULER, PER_CPU_TIMER, IPC_MANAGER, CAPABILITY_MANAGER, PROCESS_TABLE, BOOTSTRAP_PRINCIPAL, OBJECT_STORE};



// ============================================================================
// Limine boot protocol requests
// ============================================================================

/// Base revision — must be supported by our version of the limine crate.
#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::new();

/// Request the higher-half direct map offset (physical memory accessible via HHDM).
#[used]
#[unsafe(link_section = ".requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

/// Request the physical memory map from the bootloader.
#[used]
#[unsafe(link_section = ".requests")]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

/// Request a framebuffer for early graphical output (optional).
#[used]
#[unsafe(link_section = ".requests")]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

/// Request the RSDP address from the bootloader (for ACPI table parsing).
#[used]
#[unsafe(link_section = ".requests")]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

/// Request SMP information — lists all CPUs, allows waking APs.
#[used]
#[unsafe(link_section = ".requests")]
static MP_REQUEST: MpRequest = MpRequest::new();

/// Request a 256KB kernel stack.
#[used]
#[unsafe(link_section = ".requests")]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new()
    .with_size(256 * 1024);

/// Request boot modules (ELF binaries loaded by Limine from boot media).
/// Modules are specified in limine.conf with `module_path` directives.
#[used]
#[unsafe(link_section = ".requests")]
static MODULE_REQUEST: ModuleRequest = ModuleRequest::new();

/// Limine requests section markers.
#[used]
#[unsafe(link_section = ".requests_start_marker")]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();
#[used]
#[unsafe(link_section = ".requests_end_marker")]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// Microkernel entry point (called by Limine bootloader).
///
/// Limine invokes this as a raw function pointer: `extern "C" fn() -> !`.
/// The `unsafe` qualifier only affects Rust-side callers — it does not change
/// the ABI or the generated symbol.  `#[unsafe(no_mangle)]` ensures the linker
/// symbol matches what limine.conf expects.
#[unsafe(no_mangle)]
unsafe extern "C" fn kmain() -> ! {
    // Disable interrupts immediately — no exception vector table is loaded yet.
    #[cfg(target_arch = "x86_64")]
    x86_64::instructions::interrupts::disable();
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Masking DAIF at EL1 boot is always safe. Limine should have
    // already done this, but be defensive.
    unsafe { core::arch::asm!("msr daifset, #0xf", options(nostack, nomem)); }

    // Store HHDM offset FIRST — AArch64 needs it for ALL MMIO addresses
    // (PL011 UART, GIC). Limine on AArch64 does NOT identity-map device MMIO
    // in TTBR0 — only RAM is identity-mapped. All MMIO must go through HHDM.
    //
    // This is the **only** place in the kernel that reads a Limine static
    // directly outside of `boot/limine.rs`. It's a chicken-and-egg case: HHDM
    // is needed for the AArch64 MMIO mapping that itself precedes serial
    // output, and `boot::limine::populate` (which logs warnings on truncation)
    // requires serial. The full BootInfo is populated below, after serial is
    // up — and the HHDM offset there is read from the same Limine response
    // for consistency. See `src/boot/mod.rs` for the abstraction rationale.
    if let Some(hhdm_response) = HHDM_REQUEST.get_response() {
        cambios_core::set_hhdm_offset(hhdm_response.offset());
    }

    // AArch64: Diagnose and map MMIO devices before any I/O.
    // Limine's HHDM only covers RAM, not device MMIO. Each unsafe scope
    // below is sized to the single operation it covers, with its own
    // SAFETY comment naming the specific invariants at play.
    #[cfg(target_arch = "aarch64")]
    {
        // Read TCR_EL1 to determine actual VA width.
        // SAFETY: Reading TCR_EL1 is valid at EL1 with no preconditions
        // beyond running at EL1, which is established by Limine on entry.
        let tcr: u64 = unsafe {
            let v: u64;
            core::arch::asm!("mrs {}, tcr_el1", out(reg) v, options(nostack, nomem));
            v
        };
        let t1sz = (tcr >> 16) & 0x3F;
        // VA bits for TTBR1 = 64 - T1SZ
        // If T1SZ=25 → 39-bit VA → TTBR1 covers 0xFFFFFF8000000000+
        // If T1SZ=16 → 48-bit VA → TTBR1 covers 0xFFFF000000000000+

        if t1sz > 16 {
            // Widen TCR_EL1.T1SZ to 16 (48-bit VA space) so the full HHDM
            // range is addressable.
            // SAFETY: Single-threaded boot, EL1. Widening T1SZ *enlarges*
            // (never shrinks) the addressable VA range, so no existing
            // TTBR1 mapping becomes invalid. The trailing ISB orders the
            // TCR write before any subsequent TTBR1 walk uses the wider VA.
            unsafe {
                let new_tcr = (tcr & !(0x3F << 16)) | (16 << 16);
                core::arch::asm!(
                    "msr tcr_el1, {}",
                    "isb",
                    in(reg) new_tcr,
                    options(nostack),
                );
            }
        }

        use cambios_core::memory::paging::early_map_mmio;

        // PL011 UART0 at 0x0900_0000 (QEMU virt). Failure is fatal: serial
        // is the only console, and we have no way to report why we failed.
        // SAFETY: Single-threaded early boot, HHDM offset stored above.
        // early_map_mmio uses bootstrap frames from kernel .bss (frame
        // allocator is not initialized yet) and writes leaf descriptors
        // into TTBR1 page tables Limine handed us.
        if unsafe { early_map_mmio(0x0900_0000) }.is_err() {
            // SAFETY: wfe is unconditionally legal at EL1.
            loop { unsafe { core::arch::asm!("wfe", options(nostack, nomem)); } }
        }

        // GIC Distributor at 0x0800_0000 (QEMU virt) — 64 KiB region (16 pages).
        // Failure is fatal: scheduling requires GIC for timer interrupts.
        for page in 0..16u64 {
            // SAFETY: same invariants as PL011 mapping above.
            if unsafe { early_map_mmio(0x0800_0000 + page * 0x1000) }.is_err() {
                // SAFETY: wfe is unconditionally legal at EL1.
                loop { unsafe { core::arch::asm!("wfe", options(nostack, nomem)); } }
            }
        }

        // GIC Redistributor at 0x080A_0000 (QEMU virt). Each CPU's GICR
        // frame is 128 KiB (0x20000 stride, two 64 KiB frames).
        // Map enough for 4 CPUs: 4 × 32 pages = 128 pages = 512 KiB.
        for page in 0..128u64 {
            // SAFETY: same invariants as PL011 mapping above.
            if unsafe { early_map_mmio(0x080A_0000 + page * 0x1000) }.is_err() {
                // SAFETY: wfe is unconditionally legal at EL1.
                loop { unsafe { core::arch::asm!("wfe", options(nostack, nomem)); } }
            }
        }
    }

    // Early diagnostic on AArch64: write to PL011 via HHDM to confirm entry.
    #[cfg(target_arch = "aarch64")]
    {
        let hhdm = cambios_core::hhdm_offset();
        let uart = (0x0900_0000u64 + hhdm) as *mut u8;
        // SAFETY: PL011 UART0 data register was mapped into HHDM by the
        // early_map_mmio call above, single-threaded boot, no concurrent
        // writers. write_volatile is the only operation that needs unsafe.
        unsafe { core::ptr::write_volatile(uart, b'K'); }
    }

    // Initialize serial output FIRST so panic messages are visible
    // SAFETY: Called once as the first init step. No other code accesses SERIAL1 yet.
    unsafe { cambios_core::io::init(); }

    // Verify Limine protocol is supported (panics with a message if not)
    if !BASE_REVISION.is_supported() {
        // Serial is up; print a named diagnostic before halting.
        println!("✗ Limine base revision not supported by this kernel — halting");
        cambios_core::halt();
    }

    println!("=== CambiOS Microkernel [v0.2.0] ===");
    println!("Booted via Limine\n");

    // Populate kernel-owned BootInfo from the Limine response statics.
    // After this call, the rest of the kernel reads `cambios_core::boot::info()`
    // and never touches `limine::*` types (modulo the AP-wakeup path in
    // `ap_entry`, which depends on Limine's MP active-wake mechanism and is
    // documented in src/boot/limine.rs as a deferred abstraction).
    // ADR-021 Phase 021.B.1: boot-adapter failures return BootError
    // rather than panicking. kmain returns `!` so we can't use `?`;
    // dispatch to boot_failed on error so the halt path is the single
    // typed boot-failure landing instead of a stack of .expect panics.
    cambios_core::boot::limine::populate(
        &HHDM_REQUEST,
        &MEMORY_MAP_REQUEST,
        &FRAMEBUFFER_REQUEST,
        &RSDP_REQUEST,
        &MODULE_REQUEST,
    )
    .unwrap_or_else(|err| cambios_core::boot::boot_failed(err));

    let hhdm_offset = cambios_core::hhdm_offset();
    println!("HHDM offset: {:#x}", hhdm_offset);

    // Report memory map (read from kernel-owned BootInfo, not Limine).
    let info = cambios_core::boot::info();
    let regions = info.memory_regions();
    println!("Memory map: {} entries", regions.len());
    for (i, region) in regions.iter().enumerate() {
        println!(
            "  [{:2}] {:#016x} - {:#016x} len={:#x} ({})",
            i,
            region.base,
            region.base + region.length,
            region.length,
            region.kind.as_str(),
        );
    }

    // Report framebuffers (multi-display-aware).
    let fb_count = info.framebuffers().count();
    if fb_count == 0 {
        println!("Framebuffers: none reported");
    } else {
        println!("Framebuffers: {} display(s)", fb_count);
        for (i, fb) in info.framebuffers().enumerate() {
            println!(
                "  [{}] {}x{} @ {:#x} pitch={} bpp={} format=R{}<<{} G{}<<{} B{}<<{}",
                i,
                fb.width,
                fb.height,
                fb.phys_addr,
                fb.pitch,
                fb.bpp,
                fb.red_mask_size, fb.red_mask_shift,
                fb.green_mask_size, fb.green_mask_shift,
                fb.blue_mask_size, fb.blue_mask_shift,
            );
        }
    }

    println!();

    // Initialize kernel heap allocator from Limine memory map
    init_kernel_heap();

    // Initialize physical frame allocator from Limine memory map
    init_frame_allocator();

    // Phase 3.2a (ADR-008): compute num_slots from the active tier policy
    // and allocate the kernel object table region BEFORE the process
    // table and capability manager are constructed — they both borrow
    // slice storage from this region.
    init_kernel_object_tables();

    // Phase 3.3 (ADR-007): allocate global audit ring buffer from frame
    // allocator BEFORE any process is created, so early boot events
    // (process creation, capability grants) are captured.
    audit_init();

    // Load our GDT (replaces Limine's) — must be before IDT and syscall init
    // On AArch64: no-op (EL1/EL0 managed via exception levels).
    // SAFETY: Single-threaded boot, interrupts disabled.
    unsafe { cambios_core::arch::gdt::init(); }
    println!("✓ GDT loaded (kernel CS={:#x}, SS={:#x})",
        cambios_core::arch::gdt::KERNEL_CS,
        cambios_core::arch::gdt::KERNEL_SS,
    );

    // Save the kernel page table root for restoring address space after user tasks
    {
        #[cfg(target_arch = "x86_64")]
        {
            let cr3: u64;
            // SAFETY: Reading CR3 is safe at ring 0. Returns the PML4 physical address.
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem)); }
            cambios_core::set_kernel_cr3(cr3);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let ttbr1: u64;
            // SAFETY: Reading TTBR1_EL1 is safe at EL1. This is the kernel page table.
            unsafe { core::arch::asm!("mrs {}, ttbr1_el1", out(reg) ttbr1, options(nostack, nomem)); }
            cambios_core::set_kernel_cr3(ttbr1);
        }
    }

    // Initialize exception/interrupt vector table
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Single-threaded boot, GDT already loaded. Sets up exception handlers.
        unsafe { cambios_core::interrupts::init(); }
        println!("✓ IDT loaded");
    }

    // Initialize SYSCALL/SYSRET MSRs (x86_64) or VBAR_EL1 exception vectors (AArch64)
    // SAFETY: GDT loaded, single-threaded boot.
    unsafe { cambios_core::arch::syscall::init(); }
    #[cfg(target_arch = "x86_64")]
    println!("✓ SYSCALL/SYSRET configured");
    #[cfg(target_arch = "aarch64")]
    println!("✓ Exception vector table loaded (VBAR_EL1)");

    // Initialize microkernel subsystems
    process_table_init();  // Must be before scheduler (user tasks need process table)
    ipc_init();
    capability_manager_init();
    bootstrap_identity_init();  // Must be after capability_manager_init (binds to processes)
    object_store_init();        // Must be after heap init (heap-allocated)
    scheduler_init();           // Must be after bootstrap_identity_init (boot modules need signing key)

    println!("✓ Task scheduler initialized");
    println!("✓ IPC subsystem ready");
    println!("✓ Capability manager ready");

    {
        let scheduler = PER_CPU_SCHEDULER[0].lock();
        if let Some(sched) = scheduler.as_ref() {
            let stats = sched.stats();
            println!(
                "\nScheduler: {} tasks, current: {:?}",
                stats.active_tasks, stats.current_task
            );
        }
    }

    println!("\nStarting scheduler event loop...\n");

    // Initialize hardware interrupts — architecture-specific
    println!("Initializing hardware interrupts...");

    #[cfg(target_arch = "x86_64")]
    {
        // x86_64: APIC timer + I/O APIC + device IRQs
        // Disables PIC, enables Local APIC, parses ACPI for I/O APIC,
        // calibrates APIC timer at 100Hz, routes device IRQs.
        let rsdp_phys = cambios_core::boot::info().rsdp_phys.unwrap_or(0);

        // Map ACPI physical memory into the HHDM before parsing.
        map_acpi_regions(rsdp_phys);

        // SAFETY: All subsystems initialized. HHDM offset is set.
        // ADR-021 Phase B.2: typed BootError propagation from the
        // interrupts subsystem (APIC init, IST stack alloc, APIC
        // calibration). kmain returns `!` so no `?`; dispatch to
        // boot_failed for the single typed halt path.
        unsafe {
            cambios_core::interrupts::init_hardware_interrupts(100, rsdp_phys)
                .unwrap_or_else(|err| cambios_core::boot::boot_failed(err));
        }
        println!("✓ APIC-driven scheduling active");

        // PCI bus scan — discover devices for user-space drivers
        // SAFETY: Single-threaded boot, interrupts just enabled but no PCI drivers yet.
        unsafe { cambios_core::pci::scan() };
        let pci_count = cambios_core::pci::device_count();
        println!("✓ PCI: {} device(s) discovered", pci_count);
        for i in 0..pci_count {
            if let Some(dev) = cambios_core::pci::get_device(i) {
                println!("  PCI {:02x}:{:02x}.{} — {:04x}:{:04x} class {:02x}:{:02x}",
                    dev.bus, dev.device, dev.function,
                    dev.vendor_id, dev.device_id,
                    dev.class, dev.subclass);
                for b in 0..6 {
                    if dev.bars[b] != 0 {
                        println!("    BAR{}: {:#x} size={} {}",
                            b, dev.bars[b], dev.bar_sizes[b],
                            if dev.bar_is_io[b] { "I/O" } else { "MMIO" });
                    }
                }
            }
        }
        println!();
    }

    #[cfg(target_arch = "aarch64")]
    {
        // AArch64: GIC + ARM Generic Timer
        // SAFETY: Single-threaded boot, interrupts masked. GIC MMIO at QEMU virt addresses.
        unsafe {
            // Read the BSP's MPIDR_EL1 for hardware affinity identification
            let bsp_mpidr: u64;
            core::arch::asm!("mrs {}, mpidr_el1", out(reg) bsp_mpidr, options(nostack, nomem));
            // Initialize per-CPU data (TPIDR_EL1) for BSP
            cambios_core::arch::aarch64::percpu::init_bsp(bsp_mpidr & 0xFF_FFFF);
            println!("  ✓ Per-CPU data initialized (BSP, MPIDR={:#x})", bsp_mpidr & 0xFF_FFFF);

            // Enable FP/NEON for EL0 and EL1 (CPACR_EL1.FPEN = 0b11).
            // Without this, FP/NEON instructions from EL0 trap with EC=0x0.
            // Rust-compiled user-space code uses NEON for zeroing (movi v0.2d).
            core::arch::asm!(
                "mrs {tmp}, cpacr_el1",
                "orr {tmp}, {tmp}, #(3 << 20)",   // FPEN = 0b11
                "msr cpacr_el1, {tmp}",
                "isb",
                tmp = out(reg) _,
            );

            // Initialize GIC CPU interface (ICC system registers)
            cambios_core::arch::aarch64::gic::init();
            println!("  ✓ GIC CPU interface enabled");

            // Initialize GIC Distributor (SPI routing, priorities)
            // QEMU virt physical addresses, translated through HHDM
            /// HARDWARE: ARM GICv3 Distributor base on QEMU `virt`.
            /// Platform-fixed by QEMU's `virt` machine; real hardware
            /// discovers this from the device tree or ACPI MADT.
            const GICD_PHYS: u64 = 0x0800_0000;
            /// HARDWARE: ARM GICv3 Redistributor base on QEMU `virt`.
            /// Platform-fixed by QEMU; see `GICD_PHYS` above.
            const GICR_PHYS: u64 = 0x080A_0000;
            let hhdm = cambios_core::hhdm_offset();
            cambios_core::arch::aarch64::gic::init_distributor(GICD_PHYS + hhdm);
            println!("  ✓ GIC Distributor initialized");

            // Initialize GIC Redistributor for BSP (PPI 30 = timer)
            cambios_core::arch::aarch64::gic::init_redistributor(GICR_PHYS + hhdm, 0);
            println!("  ✓ GIC Redistributor initialized (CPU 0)");

            // Start ARM Generic Timer at 100 Hz
            // ADR-021 Phase B.3: typed BootError propagation.
            cambios_core::arch::aarch64::timer::init(100)
                .unwrap_or_else(|err| cambios_core::boot::boot_failed(err));
            println!("  ✓ ARM Generic Timer started (100 Hz)");
        }
        println!("✓ GIC + timer scheduling active\n");

        // PCIe ECAM bring-up + PCI bus scan.
        //
        // QEMU `virt` (aarch64) publishes the high PCIe ECAM window at
        // phys 0x40_1000_0000 (256 GiB + 256 MiB). We map the first
        // 1 MiB — bus 0, the only bus QEMU populates — into TTBR1 via
        // the kernel frame allocator, then run the same arch-agnostic
        // `pci::scan` used on x86_64 (which walks the window through
        // the `config::read32` ECAM backend).
        //
        // After this call `SYS_DEVICE_INFO` surfaces real device
        // records; virtio-gpu-pci / virtio-keyboard-pci drivers'
        // discovery paths now find their devices without falling into
        // passive idle (which was the reason the aarch64 GUI boot chain
        // stalled at the compositor handshake).
        //
        // SCAFFOLDING: ECAM base hard-coded for QEMU `virt`. Real
        // hardware discovers this from ACPI MCFG (aarch64) or the
        // `/soc/pci` DTB node. See `docs/ASSUMPTIONS.md`; replace when
        // a non-QEMU aarch64 target boots or ADR-021 Phase C lands an
        // MCFG/DTB parser.
        /// SCAFFOLDING: QEMU `virt` aarch64 high PCIe ECAM base.
        /// Why: QEMU's `extended_memmap[VIRT_HIGH_PCIE_ECAM]` lands the
        ///      256 MiB ECAM window at 0x40_1000_0000 after the high
        ///      GIC redistributor. Matches the existing `GICD_PHYS` /
        ///      `GICR_PHYS` precedent — platform-fixed by QEMU.
        /// Replace when: an MCFG/DTB parser lands (ADR-021 Phase C) or a
        ///      non-QEMU aarch64 target boots. See docs/ASSUMPTIONS.md.
        const ECAM_PHYS_AARCH64: u64 = 0x40_1000_0000;
        /// SCAFFOLDING: QEMU publishes a 256 MiB ECAM window on aarch64.
        /// `pci::init_ecam` caps the actual mapping to bus 0 (1 MiB);
        /// passing the full advertised size keeps a future multi-bus
        /// change a single-line edit. Replace when: same trigger as
        /// `ECAM_PHYS_AARCH64`.
        const ECAM_SIZE_AARCH64: u64 = 256 * 1024 * 1024;
        // SAFETY: HHDM offset is set; FRAME_ALLOCATOR is live (init
        // ran above); kernel page table is active; single-threaded boot.
        unsafe {
            cambios_core::pci::init_ecam(ECAM_PHYS_AARCH64, ECAM_SIZE_AARCH64)
                .unwrap_or_else(|e| {
                    println!("✗ pci::init_ecam failed: {}", e);
                    cambios_core::halt();
                });
        }
        println!(
            "✓ PCIe ECAM mapped ({:#x}, bus 0 = 1 MiB)",
            ECAM_PHYS_AARCH64,
        );

        // SAFETY: single-threaded BSP boot, no PCI driver is running,
        // BAR sizing writes are safe before user space comes up.
        unsafe { cambios_core::pci::scan() };
        let pci_count = cambios_core::pci::device_count();
        println!("✓ PCI: {} device(s) discovered", pci_count);
        for i in 0..pci_count {
            if let Some(dev) = cambios_core::pci::get_device(i) {
                println!(
                    "  PCI {:02x}:{:02x}.{} — {:04x}:{:04x} class {:02x}:{:02x}",
                    dev.bus, dev.device, dev.function,
                    dev.vendor_id, dev.device_id,
                    dev.class, dev.subclass,
                );
                for b in 0..6 {
                    if dev.bars[b] != 0 {
                        println!(
                            "    BAR{}: {:#x} size={} {}",
                            b, dev.bars[b], dev.bar_sizes[b],
                            if dev.bar_is_io[b] { "I/O" } else { "MMIO" },
                        );
                    }
                }
            }
        }
        println!();
    }

    // ================================================================
    // Phase 2: Start Application Processors (SMP)
    // ================================================================
    println!("Starting application processors...");
    // SAFETY: All BSP subsystems initialized (GDT, IDT, APIC, scheduler, heap).
    // APs will load the shared IDT, initialize their own GDT/TSS, APIC, and percpu.
    unsafe { start_application_processors(); }

    // Distribute tasks across CPUs now that APs are online with schedulers
    distribute_tasks_to_aps();

    // Pre-set PerCpu.kernel_rsp0 for the first user task that will be dispatched
    // on this CPU. SYSCALL entry (syscall_entry) reads gs:[24] to switch to the
    // kernel stack. Without this, kernel_rsp0 stays 0 until the first timer-driven
    // context switch calls set_kernel_stack — but the user task may issue a SYSCALL
    // before then (e.g., if the timer ISR dispatches it and it runs immediately).
    #[cfg(target_arch = "x86_64")]
    {
        let guard = PER_CPU_SCHEDULER[0].lock();
        if let Some(sched) = guard.as_ref() {
            // Find the first Ready task with a non-zero kernel_stack_top
            for slot in 1..cambios_core::MAX_TASKS as u32 {
                if let Some(task) = sched.get_task_pub(TaskId(slot)) {
                    if task.kernel_stack_top != 0 {
                        // SAFETY: BSP percpu is initialized, interrupts may be
                        // enabled but we're the only code path accessing kernel_rsp0
                        // before the first context switch.
                        unsafe {
                            cambios_core::arch::x86_64::gdt::set_kernel_stack(task.kernel_stack_top);
                        }
                        break;
                    }
                }
            }
        }
    }

    // Enter idle loop — all scheduling is now interrupt-driven
    microkernel_loop();
}

// ============================================================================
// RISC-V kmain — separate entry from kmain() above (which expects Limine).
//
// `_start` (in src/arch/riscv64/entry.rs) calls this with the hart id
// and DTB physical address that OpenSBI passed in registers a0/a1.
// Phase R-1 keeps this minimal: install an empty BootInfo, bring up
// the NS16550 UART through direct MMIO, print a banner, halt. Phase
// R-2 grows real DTB parsing + paging + frame allocator init here.
// ============================================================================

/// RISC-V boot entry called from `_start` (arch/riscv64/entry.rs).
///
/// Receives `hart_id` (a0) and `dtb_phys` (a1) from OpenSBI.
///
/// By the time we get here, the boot trampoline has already enabled
/// Sv48 paging with:
///   - identity map 0..512 GiB (low half, L3[0])
///   - HHDM at 0xffff_8000_0000_0000 (L3[256], same L2 as identity)
///   - higher-half kernel at 0xffffffff80000000 (L3[511], L2[510])
///
/// So we are running at the higher-half VMA, UART MMIO is reachable
/// both via identity (low) and via HHDM, and taking `&` of any static
/// gives a higher-half virtual address. The kernel's portable code
/// assumes exactly this layout.
///
/// Phase R-2 expands this entry with: DTB parse → frame allocator →
/// kernel heap init. Phase R-3 continues with trap vector, timer,
/// scheduler. This function is the single continuation point for
/// Phase R-N growth; everything lands here first.
#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
unsafe extern "C" fn kmain_riscv64(hart_id: u64, dtb_phys: u64) -> ! {
    // HHDM offset set by the Sv48 boot trampoline in entry.rs. This
    // must match the `HHDM_OFFSET` constant there (and the L3[256]
    // index the boot table uses).
    cambios_core::set_hhdm_offset(cambios_core::arch::riscv64::entry::HHDM_OFFSET);

    // Bring up serial BEFORE boot::riscv::populate so any diagnostic
    // prints inside the DTB walker (warnings, overflow markers) land
    // on the console. SERIAL1 reaches NS16550 through HHDM now that
    // paging is on and HHDM_OFFSET is set.
    //
    // SAFETY: Called once as the first init step on this hart. No
    // other code accesses SERIAL1 yet.
    unsafe { cambios_core::io::init(); }

    // SAFETY: First-time install of BootInfo from the riscv boot
    // adapter. Walks the DTB OpenSBI handed us and populates memory
    // regions + reservations.
    unsafe { cambios_core::boot::riscv::populate(dtb_phys); }

    println!("=== CambiOS Microkernel [v0.2.0] (RISC-V Phase R-2) ===");
    println!(
        "Booted via OpenSBI on hart {}, DTB @ {:#x}",
        hart_id, dtb_phys
    );
    println!("Sv48 paging: kernel @ higher-half, HHDM @ {:#x}",
        cambios_core::arch::riscv64::entry::HHDM_OFFSET);

    // Quick sanity check that we're really at the higher-half VMA.
    // `kmain_riscv64 as u64` gives this function's virtual address; it
    // should start with 0xffffffff if paging + jump worked.
    let self_addr = kmain_riscv64 as *const () as u64;
    println!(
        "Self VA = {:#x} — higher-half: {}",
        self_addr,
        if (self_addr >> 32) == 0xffffffff { "OK" } else { "FAIL" }
    );

    println!();
    println!("Memory map from DTB:");
    for (i, region) in cambios_core::boot::info().memory_regions().iter().enumerate() {
        println!(
            "  [{}] {:#018x} - {:#018x} ({} KiB) {}",
            i,
            region.base,
            region.base + region.length,
            region.length / 1024,
            region.kind.as_str()
        );
    }
    println!();

    // Phase R-2.c: memory subsystem bring-up.
    // SAFETY: called once, single-hart, immediately after DTB populate.
    unsafe { cambios_core::memory::init(); }
    init_kernel_heap();
    init_frame_allocator();

    // Smoke-test: allocate a Box and verify the pointer + stored value.
    // Confirms the heap + allocator + paging are all wired correctly.
    {
        use alloc::boxed::Box;
        let boxed: Box<u64> = Box::new(0xCA_B1_05_DEADBEEFu64);
        let ptr = &*boxed as *const u64 as u64;
        println!("✓ Box::new: value {:#x} at vaddr {:#x}", *boxed, ptr);
        // Drop at end of scope returns memory to the allocator.
    }

    println!();
    println!("Phase R-2 milestone: Sv48 + higher-half + DTB + heap + Box::new OK.");

    // Phase R-4.b: kernel object tables + process table. Required by
    // `loader::load_elf_process` (allocates a process slot for hello-
    // riscv64). The portable helpers already know how to bring these
    // up — kmain_riscv64 just needs to call them after the frame
    // allocator is live and before any user task spawns.
    init_kernel_object_tables();
    process_table_init();

    // Phase R-3.f: per-hart data via `tp`. The scheduler and any
    // other portable code that reaches through `tp` (audit drain,
    // local_scheduler, local_timer) depend on a valid PerCpu
    // pointer; without this, the first timer ISR's
    // `scheduler::on_timer_isr` dereferences stale OpenSBI-left
    // garbage in `tp` and takes a load-access fault.
    //
    // SAFETY: single-hart boot, paging is active, no prior per-hart
    // code has run.
    unsafe {
        cambios_core::arch::riscv64::percpu::init_bsp(hart_id);
    }

    // Phase R-3.b+c: trap vector + SBI timer.
    //
    // Install the S-mode trap vector so any trap lands on our
    // handler. Then read the platform timebase from BootInfo (DTB
    // /cpus/timebase-frequency) and arm the first 100 Hz timer tick.
    // Finally flip sstatus.SIE to let the timer actually preempt the
    // WFI loop below.
    //
    // SAFETY: boot::install has populated BootInfo; the kernel stack
    // is set up; we're single-hart during boot; interrupts are still
    // masked on entry (we explicitly enable them below).
    unsafe {
        cambios_core::arch::riscv64::trap::install();
    }

    if let Some(tb) = cambios_core::boot::info().timer_base_frequency_hz {
        println!(
            "✓ DTB /cpus/timebase-frequency = {} Hz (from DTB)",
            tb
        );
    } else {
        println!("⚠ DTB did not report timebase-frequency — timer init will fail");
    }

    // SAFETY: trap vector just installed.
    // ADR-021 Phase B.3: typed BootError on missing timebase.
    let reload = unsafe { cambios_core::arch::riscv64::timer::init(100) }
        .unwrap_or_else(|err| cambios_core::boot::boot_failed(err));
    println!("✓ SBI timer armed at 100 Hz (reload = {} ticks)", reload);

    // Phase R-3.d: PLIC driver — init from DTB-reported MMIO range,
    // enable the console UART source, and record its IRQ number so
    // the trap handler's R-3.d inline RX diagnostic can match it.
    match cambios_core::boot::info().plic_mmio {
        Some((phys_base, size_bytes)) => {
            println!(
                "✓ DTB /soc/plic reg = {:#x}..{:#x} ({} KiB)",
                phys_base,
                phys_base + size_bytes,
                size_bytes / 1024,
            );
            // SAFETY: BootInfo was populated from the DTB; the PLIC
            // region is a real MMIO range and we're in single-hart
            // early boot with interrupts masked.
            // ADR-021 Phase B.3: typed BootError on implausible PLIC range.
            unsafe {
                cambios_core::arch::riscv64::plic::init(phys_base, size_bytes)
                    .unwrap_or_else(|_| {
                        cambios_core::boot::boot_failed(
                            cambios_core::boot::BootError::PlicInitFailed,
                        )
                    });
            }
            println!("✓ PLIC initialized (hart 0 S-mode, threshold=0, SEIE set)");

            if let Some(irq) = cambios_core::boot::info().console_irq {
                // SAFETY: PLIC init has published MMIO base; enable is
                // idempotent; source range bounded by MAX_SOURCES.
                unsafe { cambios_core::arch::riscv64::plic::enable_irq(irq); }
                cambios_core::arch::riscv64::plic::set_console_irq(irq);
                // SAFETY: UART MMIO was mapped by io::init; IER write
                // is single-byte at a fixed offset.
                unsafe { cambios_core::io::enable_console_rx_irq(); }
                println!(
                    "✓ Console IRQ {} armed (DTB /soc/serial/interrupts); \
                     NS16550 IER.ERBFI set",
                    irq,
                );
            } else {
                println!("⚠ DTB did not report /soc/serial/interrupts — \
                    no console RX IRQ");
            }
        }
        None => {
            println!("⚠ DTB did not report /soc/plic — skipping PLIC init, \
                sie.SEIE stays clear");
        }
    }

    // Phase R-6: virtio-mmio discovery. DTB populated BootInfo with
    // every `/soc/virtio_mmio@*` region; we now probe each one for
    // magic/version/device-id and synthesize a PCI-shaped entry in
    // the global device table so the unchanged `SYS_DEVICE_INFO`
    // syscall surfaces them to user-space drivers. Empty QEMU slots
    // (DeviceID == 0) silently drop out — see `pci::register_virtio_mmio`.
    //
    // SAFETY: HHDM is live, BootInfo is installed, no user task is
    // running yet, no other writer touches the pci table.
    {
        let mut registered = 0usize;
        for region in cambios_core::boot::info().virtio_mmio_devices() {
            // SAFETY: per-region invocation of the same precondition
            // asserted for the loop above; each `region` was supplied
            // by the boot-info adapter from the DTB-published list.
            unsafe {
                if cambios_core::pci::register_virtio_mmio(region.phys_base, region.size) {
                    registered += 1;
                }
            }
        }
        println!(
            "✓ Virtio-MMIO: {} device(s) registered (DTB advertised {})",
            registered,
            cambios_core::boot::info().virtio_mmio_devices().count(),
        );
        for i in 0..cambios_core::pci::device_count() {
            if let Some(dev) = cambios_core::pci::get_device(i) {
                println!(
                    "  virtio-mmio {:04x}:{:04x} BAR0={:#x} size={}",
                    dev.vendor_id,
                    dev.device_id,
                    dev.bars[0],
                    dev.bar_sizes[0],
                );
            }
        }
    }

    // Phase R-6: kernel subsystems that the portable load_boot_modules
    // path depends on. Same order as the x86_64/aarch64 call sequence
    // in the Limine boot path — ipc → caps → identity → object store.
    // Without these, SignedBinaryVerifier rejects every module because
    // BOOTSTRAP_PRINCIPAL is still zero, and capability binding for
    // kernel processes never happens.
    ipc_init();
    capability_manager_init();
    bootstrap_identity_init();
    object_store_init();

    // Phase R-3.f: scheduler + Timer object install. The Scheduler's
    // idle task (Task 0) is implicitly the kmain flow we're running —
    // `Scheduler::init` marks it Running and current. The first
    // timer IRQ will fill in its saved_rsp. scheduler_init_riscv64
    // also runs load_boot_modules against the fresh scheduler before
    // publishing it into PER_CPU_SCHEDULER[0].
    scheduler_init_riscv64();

    // Phase R-5.b: mark BSP online in the TLB-shootdown mask and
    // probe the SBI IPI extension (warn-only if absent — single-
    // hart boots never fire a cross-hart shootdown).
    cambios_core::arch::riscv64::tlb::mark_self_online(hart_id);
    let _ = cambios_core::arch::riscv64::tlb::probe_ipi_extension();

    // SAFETY: trap handler is live, per-hart state is initialized,
    // the timer is armed, the scheduler holds the idle task, and (if
    // the DTB reported them) PLIC + console IRQ are wired. Safe to
    // take interrupts now.
    unsafe {
        cambios_core::arch::riscv64::trap::enable_interrupts();
    }

    // Phase R-5.a: wake secondary harts via SBI HSM. Each AP runs
    // `_ap_start` → `kmain_riscv64_ap`, installs its own trap vector +
    // timer + scheduler, and signals AP_READY_COUNT. BSP blocks here
    // until every dispatched AP is online, so post-SMP init runs with
    // the full hart set available.
    // SAFETY: BSP per-hart state is fully initialized; SBI is ready;
    // any wakeup error is reported and continues.
    unsafe { start_application_processors(); }

    println!();
    println!("Phase R-6 milestone: SMP live + signed boot modules loaded from initrd.");
    println!("Each hart runs its own scheduler + timer; the BOOT_MODULE_ORDER chain");
    println!("releases services in roster order. Cross-hart TLB shootdowns fire");
    println!("organically from the loader path — every process exit unmaps its ELF");
    println!("segments + user stack, each unmap_page broadcasts the SBI IPI.");
    println!("Console RX still routed: press a key → '[R-3 RX] 0xNN'.");
    println!();

    // Idle loop: wfi parks the hart until the next interrupt. This
    // is the body of Task 0 (idle). When the scheduler preempts to
    // another task, the trap vector's `mv sp, a0 ; sret` swaps out
    // this stack; we resume here when the scheduler picks idle again.
    loop {
        // SAFETY: wfi is always legal in S-mode. On a hart with SIE
        // set, it blocks until the next interrupt (timer or external)
        // fires, at which point control re-enters the trap vector.
        unsafe { core::arch::asm!("wfi", options(nostack, nomem, preserves_flags)); }
    }
}

// ============================================================================
// Phase R-3.f — RISC-V scheduler integration + kernel ping task
// ============================================================================

/// Create the Scheduler + Timer and install them in PER_CPU[0].
///
/// Mirrors the x86_64 / AArch64 `scheduler_init`: builds the scheduler,
/// runs `load_boot_modules` against it (signed ELFs delivered via the
/// R-6 initrd path — see `src/boot/initrd.rs` + `src/boot/riscv.rs`
/// `/chosen` walker), then installs it into `PER_CPU_SCHEDULER[0]`.
#[cfg(target_arch = "riscv64")]
fn scheduler_init_riscv64() {
    let mut scheduler = Scheduler::new_boxed();
    if let Err(e) = scheduler.init() {
        println!("✗ Scheduler init failed: {:?}", e);
        cambios_core::halt();
    }
    // Register idle task (slot 0) in the global task→CPU map.
    cambios_core::set_task_cpu(0, 0);

    // Load signed boot modules from the initrd (BootInfo.modules).
    // `load_boot_modules` is arch-independent: same SignedBinaryVerifier,
    // same capability / BOOT_MODULE_ORDER wiring as x86_64 / aarch64.
    load_boot_modules(&mut scheduler);

    // Register every freshly-loaded task in the global task→CPU map
    // (everything on hart 0 for now; later passes migrate).
    for slot in 0..cambios_core::MAX_TASKS as u32 {
        if scheduler.get_task_pub(TaskId(slot)).is_some() {
            cambios_core::set_task_cpu(slot, 0);
        }
    }

    *PER_CPU_SCHEDULER[0].lock() = Some(scheduler);

    let mut timer = match Timer::new(TimerConfig::HZ_100) {
        Ok(t) => t,
        Err(e) => {
            println!("✗ Timer creation failed: {}", e);
            cambios_core::halt();
        }
    };
    if let Err(e) = timer.init() {
        println!("✗ Timer init failed: {}", e);
        cambios_core::halt();
    }
    *PER_CPU_TIMER[0].lock() = Some(timer);

    println!("✓ Scheduler + Timer installed on hart 0 (idle task = kmain idle loop)");
}

/// RISC-V AP entry (called from `_ap_start` after paging is enabled
/// and sp is in higher-half). Per-hart init mirrors the BSP flow:
/// percpu tp, trap vector, SBI timer, PER_CPU scheduler + Timer,
/// signal BSP, enable SIE, drop into idle wfi. No work is scheduled
/// on APs yet — R-5.a's milestone is that the hart comes online
/// cleanly; R-6 + user-space services will distribute load.
#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
unsafe extern "C" fn kmain_riscv64_ap(cpu_index: u64, hart_id: u64) -> ! {
    let cpu_idx = cpu_index as usize;

    // SAFETY: per-AP bring-up, all steps run exactly once per hart
    // in the defined order below. BSP has already initialized shared
    // hardware (PLIC, frame allocator, process table, heap); each
    // unsafe call sets up only this hart's private state (tp,
    // stvec, sie.STIE) or installs a per-hart scheduler instance.
    unsafe {
        // Step 1: per-hart data (writes tp + clears sscratch).
        cambios_core::arch::riscv64::percpu::init_ap(cpu_idx, hart_id);

        // Step 2: trap vector (per-hart stvec).
        cambios_core::arch::riscv64::trap::install();

        // Step 3: SBI timer — reads BootInfo for timebase, enables
        // sie.STIE, arms first tick.
        let _reload = cambios_core::arch::riscv64::timer::init(100);
    }

    // Step 4: per-hart scheduler + Timer. `local_scheduler()` /
    // `local_timer()` index PER_CPU_SCHEDULER / PER_CPU_TIMER by
    // `current_percpu().cpu_id()` — which we just set in init_ap.
    {
        use cambios_core::scheduler::{Scheduler, Timer, TimerConfig};

        let mut scheduler = Scheduler::new_boxed();
        if scheduler.init().is_err() {
            println!("⚠ AP cpu_idx={} hart={}: scheduler.init() failed", cpu_idx, hart_id);
        } else {
            cambios_core::set_task_cpu(0, cpu_idx as u16);
            *PER_CPU_SCHEDULER[cpu_idx].lock() = Some(scheduler);
        }

        match Timer::new(TimerConfig::HZ_100) {
            Ok(mut timer) => {
                let _ = timer.init();
                *PER_CPU_TIMER[cpu_idx].lock() = Some(timer);
            }
            Err(e) => println!(
                "⚠ AP cpu_idx={} hart={}: Timer::new failed: {}",
                cpu_idx, hart_id, e,
            ),
        }
    }

    // Step 5: mark this hart in the TLB-shootdown online mask. Must
    // happen before `enable_interrupts` so a shootdown IPI fired by
    // the BSP (mid-boot) lands on a ready handler — though in
    // practice shootdowns are rare during bring-up.
    cambios_core::arch::riscv64::tlb::mark_self_online(hart_id);

    // Step 6: signal BSP that this AP has fully initialized.
    AP_READY_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    cambios_core::ONLINE_CPU_COUNT.fetch_add(1, core::sync::atomic::Ordering::Release);

    println!("  ✓ AP hart={} cpu_idx={} online", hart_id, cpu_idx);

    // Step 7: enable SIE + SSIE and enter idle wfi. The scheduler
    // sits with just its idle task for R-5.a/b; R-6 + task migration
    // will fill it.
    // SAFETY: trap vector installed; PerCpu/timer/scheduler all live.
    unsafe { cambios_core::arch::riscv64::trap::enable_interrupts(); }
    loop {
        // SAFETY: wfi is always legal in S-mode with SIE set.
        unsafe { core::arch::asm!("wfi", options(nostack, nomem, preserves_flags)); }
    }
}

// ============================================================================
// Kernel heap initialization from Limine memory map
// ============================================================================

/// SCAFFOLDING: kernel heap size (4 MiB).
/// Why: sufficient for current kernel-level Box/Vec allocations; conscious upper
///      bound that makes memory accounting easy during early development.
/// Replace when: Phase 3 channels + audit ring buffers + larger capability tables
///      pressure this. First OOM in `Box::new()` is the signal. See docs/ASSUMPTIONS.md.
const KERNEL_HEAP_SIZE: u64 = 4 * 1024 * 1024;

/// Actual physical base chosen by init_kernel_heap(). Used by init_frame_allocator()
/// to reserve the correct region regardless of where RAM starts (x86: 0x200000,
/// AArch64 QEMU virt: somewhere above 0x4000_0000).
static KERNEL_HEAP_PHYS_BASE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Initialize the kernel heap allocator from the kernel-owned BootInfo
/// memory map (populated by `boot::limine::populate` at early boot).
///
/// Finds a large Usable physical region, converts it to a virtual address via
/// the HHDM offset, and hands it to the global allocator.
fn init_kernel_heap() {
    use cambios_core::boot::MemoryRegionKind;

    let info = cambios_core::boot::info();
    let hhdm_offset = info.hhdm_offset;

    // Find the largest Usable region that can hold our heap
    let mut best: Option<(u64, u64)> = None; // (base, length)
    for region in info.memory_regions() {
        if region.kind == MemoryRegionKind::Usable && region.length >= KERNEL_HEAP_SIZE {
            match best {
                Some((_, best_len)) if region.length <= best_len => {}
                _ => best = Some((region.base, region.length)),
            }
        }
    }

    let (phys_base, region_len) = match best {
        Some(pair) => pair,
        None => {
            println!("✗ No usable memory region large enough for kernel heap — halting");
            cambios_core::halt();
        }
    };
    // On boot protocols that deliver "full RAM as one Usable region +
    // overlay reservations" (the RISC-V DTB path), the chosen Usable
    // region can start inside OpenSBI / kernel-image / DTB territory.
    // Advance `phys_base` past any non-Usable region that *starts
    // within* our chosen span.
    //
    // Limine-populated BootInfo has non-overlapping Usable/non-Usable
    // regions, so this loop is a no-op in practice on x86/AArch64.
    let mut phys_base = phys_base;
    let mut region_len = region_len;
    loop {
        // Pick the *lowest-base* overlay inside our current span. Iterating
        // in array order would incorrectly skip past overlays near the end
        // of the span before handling the one at the start, collapsing the
        // big middle gap.
        let overlap = info
            .memory_regions()
            .iter()
            .filter(|r| {
                r.kind != MemoryRegionKind::Usable
                    && r.base >= phys_base
                    && r.base < phys_base + region_len
            })
            .min_by_key(|r| r.base);
        match overlap {
            Some(r) => {
                // Two cases:
                //  (a) overlay starts at phys_base → advance past its tail
                //  (b) overlay starts *after* phys_base → we have a usable
                //      gap before it. If that gap is big enough, clamp
                //      region_len to it and stop.
                if r.base > phys_base {
                    let gap = r.base - phys_base;
                    if gap >= KERNEL_HEAP_SIZE {
                        region_len = gap;
                        break;
                    }
                    // Gap too small — keep searching past the overlay.
                }
                let new_base = r.base + r.length;
                if new_base >= phys_base + region_len {
                    // Overlay runs off the end of our span — nothing left.
                    region_len = 0;
                    break;
                }
                region_len = (phys_base + region_len) - new_base;
                phys_base = new_base;
            }
            None => break,
        }
    }
    // 2 MiB alignment keeps things tidy for future large-page heap extension.
    let align: u64 = 0x20_0000;
    let aligned_base = (phys_base + align - 1) & !(align - 1);
    region_len = region_len.saturating_sub(aligned_base - phys_base);
    let phys_base = aligned_base;

    // Skip first 1MB of region to avoid any low-memory conflicts
    let safe_offset: u64 = 0x200000_u64.saturating_sub(phys_base);
    let phys_base = phys_base + safe_offset;
    let region_len = region_len - safe_offset;

    if region_len < KERNEL_HEAP_SIZE {
        println!(
            "✗ Largest usable region too small after skipping low memory \
             ({:#x} < {:#x}) — halting",
            region_len, KERNEL_HEAP_SIZE,
        );
        cambios_core::halt();
    }

    // Use only what we need from this region
    let heap_size = KERNEL_HEAP_SIZE as usize;
    let virt_base = phys_base as usize + hhdm_offset as usize;

    // Record the actual physical base so init_frame_allocator() can reserve it
    KERNEL_HEAP_PHYS_BASE.store(phys_base, core::sync::atomic::Ordering::Release);

    // SAFETY: virt_base is a valid writable address in the HHDM region, covering
    // heap_size bytes of usable physical memory reported by Limine. Called once.
    unsafe {
        cambios_core::KERNEL_HEAP.init(virt_base, heap_size);
    }

    let (used, free) = cambios_core::KERNEL_HEAP.stats();
    println!(
        "✓ Kernel heap: {} KB at virt {:#x} (phys {:#x}, region {} KB)",
        heap_size / 1024,
        virt_base,
        phys_base,
        region_len / 1024,
    );
    let _ = (used, free); // suppress unused warning in release
}

/// Initialize the physical frame allocator from the BootInfo memory map.
///
/// Marks all Usable regions as available, then reserves the kernel heap
/// and process heap regions so they can't be double-allocated.
fn init_frame_allocator() {
    use cambios_core::boot::MemoryRegionKind;
    use cambios_core::FRAME_ALLOCATOR;
    use cambios_core::memory::frame_allocator::PAGE_SIZE;

    let info = cambios_core::boot::info();

    let mut fa = FRAME_ALLOCATOR.lock();

    // Pass 1: Add all Usable regions
    for region in info.memory_regions() {
        if region.kind == MemoryRegionKind::Usable {
            fa.add_region(region.base, region.length);
        }
    }

    // Pass 2: Reserve regions we're already using
    // - First 1 MB: x86 real-mode/BIOS area (not applicable on AArch64)
    #[cfg(target_arch = "x86_64")]
    fa.reserve_region(0, 0x100000);
    // - Kernel heap (base was chosen dynamically by init_kernel_heap)
    let heap_phys = KERNEL_HEAP_PHYS_BASE.load(core::sync::atomic::Ordering::Acquire);
    fa.reserve_region(heap_phys, KERNEL_HEAP_SIZE);

    // RISC-V (and any future boot adapter using the "full RAM as one
    // Usable region + overlay reservations" model): iterate non-Usable
    // regions and reserve them explicitly. Limine-populated BootInfo
    // already has non-overlapping Usable/non-Usable regions, so this
    // pass is a no-op on x86/AArch64 in practice — but making it
    // portable keeps init_frame_allocator protocol-agnostic.
    //
    // ExecutableAndModules = kernel image / boot modules. Reserved =
    // DTB / hardware MMIO. BootloaderReclaimable = OpenSBI / Limine
    // itself. All must stay off-limits to the frame allocator.
    for region in info.memory_regions() {
        match region.kind {
            MemoryRegionKind::ExecutableAndModules
            | MemoryRegionKind::Reserved
            | MemoryRegionKind::BootloaderReclaimable
            | MemoryRegionKind::AcpiReclaimable
            | MemoryRegionKind::AcpiNvs
            | MemoryRegionKind::BadMemory
            | MemoryRegionKind::Framebuffer => {
                fa.reserve_region(region.base, region.length);
            }
            MemoryRegionKind::Usable | MemoryRegionKind::Unknown(_) => {}
        }
    }
    //
    // Phase 3.2a (ADR-008): per-process heaps are no longer pre-reserved
    // as a fixed slab at PROCESS_HEAP_BASE. Instead, each process
    // allocates its heap on demand via `FrameAllocator::allocate_contiguous`
    // in `ProcessDescriptor::new`, and reclaims it via `free_contiguous`
    // in `ProcessTable::destroy_process` during `handle_exit`. No
    // pre-reservation call is needed here.

    fa.finalize();

    println!(
        "✓ Frame allocator: {} free frames ({} MB of {} MB tracked)",
        fa.free_count(),
        fa.free_count() * PAGE_SIZE as usize / (1024 * 1024),
        fa.total_count() * PAGE_SIZE as usize / (1024 * 1024),
    );
}

/// Phase 3.2a (ADR-008): compute `num_slots` from the active tier policy
/// and the available memory figure, allocate the kernel object table
/// region from the frame allocator, and install the slice-backed
/// `ProcessTable` and `CapabilityManager` into their globals.
///
/// After this runs, `PROCESS_TABLE` and `CAPABILITY_MANAGER` are set
/// but empty — the first three kernel tasks are populated later in
/// `process_table_init` and `capability_manager_init`, respectively.
fn init_kernel_object_tables() {
    use cambios_core::config;
    use cambios_core::ipc::capability::CapabilityManager;
    use cambios_core::memory::frame_allocator::PAGE_SIZE;
    use cambios_core::memory::object_table;
    use cambios_core::process::ProcessTable;
    use cambios_core::{CAPABILITY_MANAGER, CHANNEL_MANAGER, FRAME_ALLOCATOR, PROCESS_TABLE};

    // Available memory figure: the *free* frame count at this point
    // in boot, times the page size. This is what's actually allocatable
    // (after USABLE regions added, reserved regions subtracted, kernel
    // heap carved out).
    //
    // We use free_count, NOT total_count, because the object table
    // region must be allocated from the pool that remains — and
    // allocate_contiguous needs a physically contiguous run that
    // fits within the free pool.
    let (available_memory_bytes, free_frames) = {
        let fa = FRAME_ALLOCATOR.lock();
        (fa.free_count() as u64 * PAGE_SIZE, fa.free_count())
    };

    // Compute num_slots and the binding constraint from the active
    // tier policy. Purely functional — no side effects.
    let mut num_slots = config::init_num_slots(available_memory_bytes);
    let binding = config::binding_constraint_for(
        &config::ACTIVE_POLICY,
        available_memory_bytes,
    );

    // Safety cap: the region must be allocatable as a contiguous
    // physical run from the frame allocator. If the policy-derived
    // num_slots would produce a region larger than half the free
    // frames (heuristic: we need room for process heaps + other
    // allocations too), reduce num_slots until it fits. This is
    // the "contiguous run" constraint that the tier policy's budget
    // ceiling doesn't know about.
    let max_region_frames = free_frames / 2; // leave at least half for process heaps
    loop {
        let needed_frames = (object_table::region_bytes_for(num_slots) / PAGE_SIZE) as usize;
        if needed_frames <= max_region_frames || num_slots <= config::ACTIVE_POLICY.min_slots as usize {
            break;
        }
        num_slots /= 2;
    }
    // Re-store the capped num_slots so downstream reads see the final value.
    config::init_num_slots_override(num_slots);

    // Allocate the contiguous region from the frame allocator and
    // carve out the two page-aligned subregions.
    let hhdm = cambios_core::hhdm_offset();
    let table = {
        let mut fa = FRAME_ALLOCATOR.lock();
        match object_table::init(&mut fa, num_slots, hhdm, binding) {
            Ok(t) => t,
            Err(e) => {
                println!("✗ Kernel object table allocation failed: {:?}", e);
                println!("  tier = {}, num_slots = {}, binding = {}",
                    config::ACTIVE_TIER_NAME,
                    num_slots,
                    binding.as_str(),
                );
                cambios_core::halt();
            }
        }
    };

    // Operator-visible boot log line — per ADR-008 § Migration Path
    // step 2a, this line documents the tier, slot count, region size,
    // and which constraint bound the computation. When `SLOT_OVERHEAD`
    // grows or workload pressure shifts, this line is the first place
    // to look.
    println!(
        "✓ Kernel object tables: {} slots × ({} + {}) bytes = {} KiB, \
         tier={}, binding={}, phys={:#x}",
        table.num_slots,
        core::mem::size_of::<Option<cambios_core::process::ProcessDescriptor>>(),
        core::mem::size_of::<Option<cambios_core::ipc::capability::ProcessCapabilities>>(),
        table.region_bytes / 1024,
        config::ACTIVE_TIER_NAME,
        table.binding.as_str(),
        table.region_base_phys,
    );

    // Move the two slices into their respective globals. Both are
    // `Box<T>` wrappers around `&'static mut [...]` slices — the slot
    // storage lives in the object table region, only the small
    // header lands on the kernel heap.
    let process_table = match ProcessTable::from_object_slice(table.process_slots, hhdm) {
        Some(pt) => pt,
        None => {
            println!("✗ Failed to wrap ProcessTable around object table slice — halting");
            cambios_core::halt();
        }
    };
    let capability_manager = match CapabilityManager::from_object_slice(table.capability_slots) {
        Some(cm) => cm,
        None => {
            println!("✗ Failed to wrap CapabilityManager around object table slice — halting");
            cambios_core::halt();
        }
    };

    *PROCESS_TABLE.lock() = Some(process_table);
    *CAPABILITY_MANAGER.lock() = Some(capability_manager);

    // Phase 3.2d.iii: initialize the channel manager (lock position 5).
    *CHANNEL_MANAGER.lock() = Some(Box::new(
        cambios_core::ipc::channel::ChannelManager::new(),
    ));
}

/// Phase 3.3 (ADR-007): allocate global audit ring buffer from the frame
/// allocator and initialize the per-CPU staging buffers.
///
/// Must be called after `init_frame_allocator()` and before any process
/// is created so early boot events are captured.
fn audit_init() {
    use cambios_core::audit::drain::AuditRing;
    use cambios_core::FRAME_ALLOCATOR;

    let hhdm = cambios_core::hhdm_offset();
    let ring = {
        let mut fa = FRAME_ALLOCATOR.lock();
        match AuditRing::init(&mut fa, hhdm) {
            Ok(r) => r,
            Err(e) => {
                println!("✗ Audit ring allocation failed: {:?}", e);
                println!("  Audit infrastructure disabled — events will be dropped");
                return;
            }
        }
    };

    let capacity = ring.capacity();
    let pages = ring.page_count();
    *cambios_core::AUDIT_RING.lock() = Some(ring);

    println!("✓ Audit: initialized ({} pages, {} event slots)",
        pages, capacity);
}

/// Map ACPI-related physical memory into the HHDM (x86_64 only).
///
/// With Limine base revision 3, only Usable, Bootloader-reclaimable,
/// Executable/modules, and Framebuffer regions are in the HHDM.
/// ACPI_RECLAIMABLE, ACPI_NVS, and RESERVED regions (where RSDP and
/// ACPI tables reside) are NOT mapped. We must explicitly map them
/// so `parse_acpi()` can read them via the standard `phys + hhdm` path.
#[cfg(target_arch = "x86_64")]
fn map_acpi_regions(rsdp_phys: u64) {
    use cambios_core::boot::MemoryRegionKind;
    use cambios_core::FRAME_ALLOCATOR;
    use cambios_core::memory::paging;
    use x86_64::structures::paging::PageTableFlags;

    let hhdm = cambios_core::hhdm_offset();
    let flags = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;

    let mut fa_guard = FRAME_ALLOCATOR.lock();

    // SAFETY: Single-threaded boot, interrupts disabled, page table valid.
    let mut pt = unsafe { paging::active_page_table() };

    // Map the page containing the RSDP (often in BIOS RESERVED area, not in HHDM)
    if rsdp_phys != 0 {
        let page_phys = rsdp_phys & !0xFFF;
        let _ = paging::map_page(&mut pt, page_phys + hhdm, page_phys, flags, &mut fa_guard);
    }

    // Map all ACPI-related and small Reserved regions.
    // With Limine base revision 3, only Usable/Bootloader/Executable/Framebuffer
    // regions are in the HHDM. ACPI tables may be in AcpiReclaimable, AcpiNvs,
    // or Reserved regions (SeaBIOS puts ACPI tables in Reserved memory).
    // Map small Reserved regions (< 1 MB) to safely cover BIOS data and ACPI tables
    // without accidentally mapping huge MMIO ranges.
    /// TUNING: ceiling on Reserved-region size that still qualifies
    /// for HHDM remapping. 1 MiB covers typical BIOS/ACPI regions
    /// while excluding accidental huge MMIO ranges in the same
    /// memory-map classification. Replace when a platform appears
    /// with legitimate Reserved-kind ACPI data above 1 MiB.
    const MAX_RESERVED_MAP_SIZE: u64 = 1024 * 1024; // 1 MB
    let mut mapped_pages = 0usize;
    for region in cambios_core::boot::info().memory_regions() {
        let should_map = match region.kind {
            MemoryRegionKind::AcpiReclaimable | MemoryRegionKind::AcpiNvs => true,
            MemoryRegionKind::Reserved if region.length <= MAX_RESERVED_MAP_SIZE => true,
            _ => false,
        };
        if should_map {
            let base = region.base & !0xFFF;
            let end = (region.base + region.length + 0xFFF) & !0xFFF;
            let page_count = ((end - base) / 4096) as usize;
            for i in 0..page_count {
                let phys = base + (i as u64) * 4096;
                // Ignore AlreadyMapped — page may overlap with an existing mapping
                let _ = paging::map_page(&mut pt, phys + hhdm, phys, flags, &mut fa_guard);
            }
            mapped_pages += page_count;
        }
    }

    println!("✓ ACPI regions mapped into HHDM ({} pages)", mapped_pages);
}

/// Initialize the task scheduler with tick-based preemption
///
/// Allocates real kernel stacks for each task and sets up initial SavedContext
/// frames so the timer ISR can dispatch them via iretq.
fn scheduler_init() {
    // Create and initialize scheduler — allocate directly on heap to avoid
    // large stack temporaries (Scheduler contains [Option<Task>; 32])
    let mut scheduler = Scheduler::new_boxed();
    if let Err(e) = scheduler.init() {
        println!("✗ Scheduler init failed: {:?}", e);
        cambios_core::halt();
    }

    // Idle task (Task 0) uses the Limine boot stack (256KB). Its saved_rsp
    // starts at 0 and will be filled on the first timer interrupt.

    // Load ELF binaries from Limine boot modules (filesystem-free loading)
    load_boot_modules(&mut scheduler);

    // Register all initial tasks in the global task→CPU map (all on CPU 0)
    for slot in 0..cambios_core::MAX_TASKS as u32 {
        if scheduler.get_task_pub(TaskId(slot)).is_some() {
            cambios_core::set_task_cpu(slot, 0);
        }
    }

    // Store in per-CPU scheduler array (BSP = CPU 0, already heap-allocated)
    *PER_CPU_SCHEDULER[0].lock() = Some(scheduler);

    // Initialize timer (100 Hz = 10ms ticks)
    let mut timer = match Timer::new(TimerConfig::HZ_100) {
        Ok(t) => t,
        Err(e) => {
            println!("✗ Timer creation failed: {}", e);
            cambios_core::halt();
        }
    };

    if let Err(e) = timer.init() {
        println!("✗ Timer init failed: {}", e);
        cambios_core::halt();
    }

    *PER_CPU_TIMER[0].lock() = Some(timer);
}

// ============================================================================
// Task entry points and stack setup
// ============================================================================

/// Register send+receive capabilities for a user process on all endpoints.
///
/// Called when creating user-mode processes (boot modules) so their
/// capabilities are registered after the process table entry exists.
///
/// Grants send/receive on endpoints 0-31 (full range) and binds the
/// bootstrap Principal to the process (boot modules are trusted).
fn register_process_capabilities(process_id: ProcessId) {
    use cambios_core::ipc::capability::CapabilityKind;

    let mut guard = CAPABILITY_MANAGER.lock();
    let cap_mgr = match guard.as_mut() {
        Some(m) => m,
        None => return,
    };
    if let Err(e) = cap_mgr.register_process(process_id) {
        println!("  ✗ Failed to register caps for process {}: {}", process_id.slot(), e);
        return;
    }
    // Grant send/receive on all endpoints (boot modules are trusted)
    for endpoint_id in 0..cambios_core::ipc::MAX_ENDPOINTS as u32 {
        let _ = cap_mgr.grant_capability(
            process_id,
            EndpointId(endpoint_id),
            CapabilityRights { send: true, receive: true, delegate: false, revoke: false },
        );
    }
    // Phase 3.2b (ADR-008): boot modules are trusted and may spawn
    // child processes (e.g., the shell uses SYS_SPAWN).
    let _ = cap_mgr.grant_system_capability(process_id, CapabilityKind::CreateProcess);
    // Phase 3.2d.iv (ADR-005): boot modules may create shared-memory channels.
    let _ = cap_mgr.grant_system_capability(process_id, CapabilityKind::CreateChannel);
    // Bind bootstrap Principal to boot module processes (they're trusted)
    let bootstrap = BOOTSTRAP_PRINCIPAL.load();
    if !bootstrap.is_zero() {
        let _ = cap_mgr.bind_principal(process_id, bootstrap);
    }
}

/// Load ELF binaries from Limine boot modules.
///
/// Iterates all modules provided by the bootloader (specified in limine.conf
/// via `module_path` directives). Each module is treated as a complete ELF
/// binary and loaded through the full verify-before-execute pipeline.
///
/// Process IDs are assigned starting at 5 (0-4 are used by kernel tasks
/// and the existing hand-built user tasks).
fn load_boot_modules(scheduler: &mut Scheduler) {
    use cambios_core::loader::{self, SignedBinaryVerifier};
    use cambios_core::FRAME_ALLOCATOR;

    let info = cambios_core::boot::info();
    if info.module_count() == 0 {
        println!("  No boot modules found");
        return;
    }

    println!("Loading {} boot module(s)...", info.module_count());

    // Use SignedBinaryVerifier with the bootstrap public key as the trust anchor.
    // All boot modules must be signed by the bootstrap key (via sign-elf tool).
    let bootstrap = BOOTSTRAP_PRINCIPAL.load();
    let verifier = SignedBinaryVerifier::with_key(bootstrap.public_key);
    let mut loaded_count = 0u32;

    for (i, module) in info.modules().enumerate() {
        let size = module.size;
        let addr = module.phys_addr as *const u8;
        let short_name = module.name_bytes();

        let name_str = core::str::from_utf8(short_name).unwrap_or("<invalid utf8>");
        println!("  Module {}: {} ({} bytes at {:#x})", i, name_str, size, addr as u64);

        if size == 0 {
            println!("    ✗ Skipped (empty module)");
            continue;
        }

        // SAFETY: Limine loaded this module into memory and provides a valid
        // address and size. The memory is part of the bootloader-reclaimable
        // region and is accessible via the HHDM. We create a read-only slice
        // for the duration of ELF loading.
        let binary = unsafe { core::slice::from_raw_parts(addr, size as usize) };

        // Check for ELF magic before attempting to load
        if binary.len() < 4 || &binary[0..4] != b"\x7fELF" {
            println!("    ✗ Skipped (not an ELF binary)");
            continue;
        }

        // Deferred: hardcoded name list couples the kernel boot loop to
        // the user-space app registry. Cleaner shapes would be a limine
        // per-module cmdline flag, a `game-` filename prefix convention,
        // or a manifest file read at boot.
        // Why: the shell `play` launcher UX needs "load-but-don't-start"
        // semantics so boot lands at `cambios>` rather than in a game;
        // the cleaner mechanisms are larger scope than the HN launcher
        // arc.
        // Revisit when: the super-sprouty-o launcher arc closes within
        // this session — followup scheduled to replace this list with a
        // config-driven mechanism.
        const SPAWN_ONLY_MODULES: &[&[u8]] =
            &[b"tree", b"worm", b"pong", b"super-sprouty-o"];

        if SPAWN_ONLY_MODULES.iter().any(|name| *name == short_name) {
            BOOT_MODULE_REGISTRY
                .lock()
                .register(short_name, addr, size as usize);
            println!("    ✓ Registered as spawn-only (not auto-started)");
            continue;
        }

        let mut pt_guard = PROCESS_TABLE.lock();
        let mut fa_guard = FRAME_ALLOCATOR.lock();
        let pt = match pt_guard.as_mut() {
            Some(pt) => pt,
            None => {
                println!("    ✗ ProcessTable not initialized");
                continue;
            }
        };

        // Phase 3.2c: process table allocates slot + generation internally.
        match loader::load_elf_process(
            binary,
            Priority::NORMAL,
            &verifier,
            pt,
            &mut fa_guard,
            scheduler,
        ) {
            Ok(result) => {
                let process_id = result.process_id;
                // Drop locks before acquiring CAPABILITY_MANAGER
                drop(fa_guard);
                drop(pt_guard);
                register_process_capabilities(process_id);

                // Register in boot module registry for runtime Spawn syscall
                BOOT_MODULE_REGISTRY.lock().register(short_name, addr, size as usize);

                // Phase 3.4: identify the policy service by module name
                if short_name == b"policy-service" {
                    cambios_core::POLICY_SERVICE_PID.store(
                        process_id.as_raw(),
                        core::sync::atomic::Ordering::Release,
                    );
                    println!("    ✓ Policy service identified as process {}", process_id.slot());
                }

                // Phase GUI-0+ (ADR-011, ADR-014): grant the
                // `MapFramebuffer` system capability to modules that
                // need to call `SYS_MAP_FRAMEBUFFER`. Today fb-demo
                // (one-shot smoke test) and scanout-limine (Phase
                // Scanout-2 fallback driver). Per ADR-014 the
                // compositor never holds this capability — only
                // scanout-driver services do. Grant is name-based
                // rather than all-boot-modules because MapFramebuffer
                // is a hardware-access capability, narrower than the
                // default send/receive + CreateProcess grant.
                if short_name == b"fb-demo" || short_name == b"scanout-limine" {
                    use cambios_core::ipc::capability::CapabilityKind;
                    let mut cap_guard = cambios_core::CAPABILITY_MANAGER.lock();
                    if let Some(cap_mgr) = cap_guard.as_mut() {
                        let _ = cap_mgr.grant_system_capability(
                            process_id,
                            CapabilityKind::MapFramebuffer,
                        );
                        println!(
                            "    ✓ Granted MapFramebuffer to {} (process {})",
                            core::str::from_utf8(short_name).unwrap_or("?"),
                            process_id.slot(),
                        );
                    }
                }

                // ADR-023: grant `AuditConsumer` to the audit-tail boot
                // module. AuditConsumer gates SYS_AUDIT_ATTACH (replacing
                // the bootstrap-Principal-only check from ADR-007 §"Audit
                // channel boot sequence") and SYS_GET_PROCESS_PRINCIPAL.
                // Name-based grant matches the MapFramebuffer pattern —
                // narrow capability, single trusted holder, no need for a
                // dynamic policy until a second consumer (kernelvisor)
                // appears.
                if short_name == b"audit-tail" {
                    use cambios_core::ipc::capability::CapabilityKind;
                    let mut cap_guard = cambios_core::CAPABILITY_MANAGER.lock();
                    if let Some(cap_mgr) = cap_guard.as_mut() {
                        let _ = cap_mgr.grant_system_capability(
                            process_id,
                            CapabilityKind::AuditConsumer,
                        );
                        println!(
                            "    ✓ Granted AuditConsumer to audit-tail (process {})",
                            process_id.slot(),
                        );
                    }
                }

                println!(
                    "    ✓ Loaded as task {} → process {} (entry={:#x}, signed)",
                    result.task_id.0, result.process_id.slot(), result.entry_point
                );

                // Sequential boot-release chain: append this task to the
                // ordered roster. Every loaded module after the first
                // starts Blocked on `BootGate` — it stays parked until
                // its predecessor calls `sys::module_ready()`, at which
                // point `handle_module_ready` wakes it.
                //
                // Module 0 (`loaded_count == 0` at this point) runs
                // Ready as before. This preserves the invariant the
                // scheduler already relies on: at least one task
                // (besides idle) is runnable at boot.
                cambios_core::BOOT_MODULE_ORDER.lock().push(result.task_id);
                if loaded_count > 0 {
                    let _ = scheduler.block_task(
                        result.task_id,
                        cambios_core::scheduler::BlockReason::BootGate,
                    );
                }

                loaded_count += 1;
            }
            Err(e) => {
                println!("    ✗ ELF load failed: {}", e);
            }
        }
    }

    if loaded_count > 0 {
        println!("✓ Loaded {} signed module(s) as user processes", loaded_count);
        // Phase 3.4: Enable policy enforcement if the policy service was loaded.
        // The fail-open timeout handles the startup window before the policy
        // service processes its first query.
        if cambios_core::POLICY_SERVICE_PID.load(core::sync::atomic::Ordering::Acquire) != u64::MAX {
            cambios_core::POLICY_SERVICE_READY.store(true, core::sync::atomic::Ordering::Release);
            println!("✓ Policy enforcement enabled (fail-open until service starts)");
        }
    }

    // Phase 3.2c: NEXT_PROCESS_ID removed — process table allocates
    // slots internally via linear scan with generation stamping.
}

/// Initialize IPC subsystem
fn ipc_init() {
    let mut ipc = match IpcManager::new_boxed() {
        Some(ipc) => ipc,
        None => {
            println!("✗ Failed to allocate IpcManager — halting");
            cambios_core::halt();
        }
    };

    // Install zero-trust IPC interceptor on legacy IPC_MANAGER
    use cambios_core::ipc::interceptor::{DefaultInterceptor, IpcInterceptorBackend};
    // Enum-dispatch shim per ADR-002 § Divergence — no `dyn` trait object.
    ipc.set_interceptor(IpcInterceptorBackend::Default(DefaultInterceptor::new()));

    *IPC_MANAGER.lock() = Some(ipc);

    // Also install interceptor on the sharded IPC manager.
    cambios_core::SHARDED_IPC
        .set_interceptor(IpcInterceptorBackend::Default(DefaultInterceptor::new()));

    println!("✓ IPC manager ready [interceptor active, per-endpoint sharding enabled]");
}

/// Initialize capability manager — register the first 3 kernel processes.
///
/// Phase 3.2a: the `CapabilityManager` itself was constructed in
/// `init_kernel_object_tables` with slice-backed storage. This step
/// only registers processes 0-2 (kernel tasks created in
/// process_table_init) and grants their initial capabilities.
/// Boot module processes are registered later when load_boot_modules
/// calls register_process_capabilities after their process table
/// entries exist.
fn capability_manager_init() {
    use cambios_core::ipc::capability::CapabilityKind;

    let mut guard = CAPABILITY_MANAGER.lock();
    let cap_mgr = match guard.as_mut() {
        Some(m) => m,
        None => {
            println!("✗ CAPABILITY_MANAGER not initialized before capability_manager_init — halting");
            cambios_core::halt();
        }
    };

    // Only register processes that already exist in the process table (0-2).
    // Processes 3+ are registered on-demand when user tasks are created.
    for task_id in 0..3u32 {
        let process_id = ProcessId::new(task_id, 0);
        if let Err(e) = cap_mgr.register_process(process_id) {
            println!("  ✗ Failed to register process {}: {}", task_id, e);
            continue;
        }

        // Grant each process access to endpoints for communication
        // For this demo: allow all processes to communicate with each other
        // Real system: would restrict based on process privileges
        for endpoint_id in 0..16 {
            let endpoint = EndpointId(endpoint_id);

            // Task 0 (idle) gets full capabilities everywhere
            if task_id == 0 {
                let _ = cap_mgr.grant_capability(
                    process_id,
                    endpoint,
                    CapabilityRights::FULL,
                );
            }
            // Other tasks get send+receive but not delegate
            else {
                let _ = cap_mgr.grant_capability(
                    process_id,
                    endpoint,
                    CapabilityRights {
                        send: true,
                        receive: true,
                        delegate: false,
                        revoke: false,
                    },
                );
            }
        }

        // Phase 3.2b (ADR-008): grant CreateProcess to all kernel
        // processes. These run with the bootstrap Principal and
        // orchestrate boot module loading + runtime Spawn.
        let _ = cap_mgr.grant_system_capability(process_id, CapabilityKind::CreateProcess);
        // Phase 3.2d.iv (ADR-005): grant CreateChannel to kernel processes.
        let _ = cap_mgr.grant_system_capability(process_id, CapabilityKind::CreateChannel);
    }

    println!("  ✓ Capability manager initialized with {} processes", cap_mgr.process_count());
}

/// Initialize bootstrap identity.
///
/// Loads the bootstrap Principal from a compiled-in public key (extracted
/// from the signing YubiKey at build time). Binds it to kernel processes 0-2.
///
/// The bootstrap secret key lives exclusively on the hardware YubiKey — it
/// never enters kernel memory. Runtime object signing is delegated to
/// user-space services with their own operational keys.
fn bootstrap_identity_init() {
    use cambios_core::ipc::Principal;

    // Bootstrap public key compiled in from bootstrap_pubkey.bin.
    // Generated by: sign-elf --yubikey --export-pubkey bootstrap_pubkey.bin
    // (or --seed <hex> for dev/CI builds without a YubiKey present)
    const BOOTSTRAP_PUBKEY: &[u8; 32] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/bootstrap_pubkey.bin"));

    let bootstrap = Principal::from_public_key(*BOOTSTRAP_PUBKEY);

    // Store globally for BindPrincipal restriction check and ELF signature verification.
    // No secret key stored — the signing key lives on the hardware YubiKey.
    BOOTSTRAP_PRINCIPAL.store(bootstrap);

    // Bind the bootstrap Principal to all kernel processes (0-2)
    let mut cap_guard = CAPABILITY_MANAGER.lock();
    if let Some(cap_mgr) = cap_guard.as_mut() {
        for pid in 0..3u32 {
            if let Err(e) = cap_mgr.bind_principal(ProcessId::new(pid, 0), bootstrap) {
                println!("  ✗ Failed to bind bootstrap Principal to process {}: {}", pid, e);
            }
        }
    }
    drop(cap_guard);

    println!("✓ Bootstrap identity bound (hardware-backed public key)");
    println!("  Principal: {}", bootstrap);
}

/// Initialize the object store — Phase 4a.iii wires the disk-backed
/// `LazyDiskStore` so objects persist across reboots. The handshake with
/// the virtio-blk user-space driver happens on the first `SYS_OBJ_*` call
/// (driver isn't running yet at this boot stage). Until that handshake,
/// the store has no capacity and every `get` returns a deferred error;
/// first write will trigger the init.
///
/// Lock ordering position: 9 (OBJECT_STORE). No hierarchy violation when
/// calling into `VirtioBlkDevice::call` under this lock — the device uses
/// `SHARDED_IPC` (per-endpoint shard locks, outside the main hierarchy)
/// and `PER_CPU_SCHEDULER` (per-CPU, no cycle with OBJECT_STORE since
/// scheduler / ISR code never acquires OBJECT_STORE).
fn object_store_init() {
    use cambios_core::fs::ram::RamObjectStore;
    use cambios_core::fs::ObjectStoreBackend;

    // Boot with RamObjectStore — fast, no IPC, no driver dependency.
    // The first SYS_OBJ_* syscall calls ensure_disk_store() (outside any
    // lock) to handshake with virtio-blk and swap in a DiskObjectStore.
    // If the handshake fails (no driver, no device), RAM store persists
    // — arcobj works but objects don't survive reboot.
    //
    // Backend dispatch is monomorphized via `ObjectStoreBackend` enum (no
    // `dyn` trait object) per ADR-003 § Divergence.
    let store = match RamObjectStore::new_boxed() {
        Some(s) => s,
        None => {
            println!("✗ RamObjectStore allocation failed — halting");
            cambios_core::halt();
        }
    };
    *OBJECT_STORE.lock() = Some(ObjectStoreBackend::Ram(store));

    println!("✓ Object store initialized (RAM, disk upgrade deferred to first use)");
}

/// Initialize process table — populate the first 3 kernel processes.
///
/// Phase 3.2a: the `ProcessTable` itself was constructed in
/// `init_kernel_object_tables` with slice-backed storage. This step
/// only creates the first three `ProcessDescriptor`s, allocating each
/// one's heap via the frame allocator.
fn process_table_init() {
    use cambios_core::FRAME_ALLOCATOR;

    // Lock order: PROCESS_TABLE (5) -> FRAME_ALLOCATOR (6). Valid.
    let mut pt_guard = PROCESS_TABLE.lock();
    let pt = match pt_guard.as_mut() {
        Some(pt) => pt,
        None => {
            println!("✗ PROCESS_TABLE not initialized before process_table_init — halting");
            cambios_core::halt();
        }
    };

    let mut fa_guard = FRAME_ALLOCATOR.lock();

    // Create process descriptors for the first 3 processes (matching
    // task count). Each one gets a freshly allocated heap region via
    // FrameAllocator::allocate_contiguous (1024 frames / 4 MiB each).
    // Phase 3.2c: slot + generation assigned by process table.
    for i in 0..3 {
        match pt.create_process(&mut fa_guard, /* create_page_table = */ false) {
            Ok(process_id) => {
                let heap_base = pt.get_heap_base(process_id);
                println!("  ✓ Process {} (gen {}) heap at {:#x}", process_id.slot(), process_id.generation(), heap_base);
            }
            Err(e) => {
                println!("  ✗ Failed to create process {}: {}", i, e);
            }
        }
    }

    println!("✓ Process table initialized");
}

// ============================================================================
// SMP — Application Processor startup
// ============================================================================

/// Atomic counter of APs that have completed initialization.
/// BSP polls this to know when all APs are ready.
static AP_READY_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// AP entry point — x86_64 (called by Limine when an AP is woken via `goto_address`).
///
/// Each AP arrives in 64-bit long mode with its own 64KB stack (provided by Limine),
/// the kernel page tables active, and interrupts disabled.
///
/// The `cpu` parameter identifies this AP (APIC ID, and `extra` holds the
/// logical CPU index assigned by the BSP).
///
/// # Safety
/// Called by the Limine MP protocol machinery. Must never return.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn ap_entry(cpu: &limine::mp::Cpu) -> ! {
    let cpu_index = cpu.extra.load(core::sync::atomic::Ordering::Acquire) as usize;
    let apic_id = cpu.lapic_id;

    // Step 1: Load this AP's GDT + TSS (replaces Limine's)
    // SAFETY: Interrupts disabled, called once per AP.
    unsafe { cambios_core::arch::gdt::init_for_cpu(cpu_index) };

    // Step 2: Initialize per-CPU data (writes GS base MSR)
    // SAFETY: GDT loaded (GS base will be overwritten by percpu init). One-time per AP.
    unsafe { cambios_core::arch::x86_64::percpu::init_ap(cpu_index, apic_id) };

    // Step 3: Load the shared IDT (configured by BSP)
    // SAFETY: BSP has fully configured and loaded the IDT.
    unsafe { cambios_core::interrupts::load_idt_ap() };

    // Step 4: Initialize SYSCALL/SYSRET MSRs (per-CPU)
    // SAFETY: GDT loaded, per-CPU init done.
    unsafe { cambios_core::arch::syscall::init() };

    // Step 5: Enable this AP's Local APIC
    // SAFETY: BSP already mapped the APIC MMIO page (shared page tables).
    unsafe { cambios_core::arch::x86_64::apic::init_ap() };

    // Step 6: Configure APIC timer using BSP's calibration values
    // SAFETY: BSP has completed configure_timer() and stored the initial count.
    unsafe { cambios_core::arch::x86_64::apic::configure_timer_ap() };

    // Step 7: Initialize per-CPU scheduler and timer
    // Each AP needs its own Scheduler (with idle task) so migrated tasks
    // can be dispatched, and its own Timer for tick accounting.
    {
        use cambios_core::scheduler::{Scheduler, Timer, TimerConfig};

        let mut scheduler = Scheduler::new_boxed();
        if scheduler.init().is_err() {
            // Non-fatal: AP will just idle without a scheduler
        } else {
            *PER_CPU_SCHEDULER[cpu_index].lock() = Some(scheduler);
        }

        if let Ok(mut timer) = Timer::new(TimerConfig::HZ_100) {
            let _ = timer.init();
            *PER_CPU_TIMER[cpu_index].lock() = Some(timer);
        }
    }

    // Step 8: Signal BSP that this AP is ready
    AP_READY_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    cambios_core::ONLINE_CPU_COUNT.fetch_add(1, core::sync::atomic::Ordering::Release);

    // Step 9: Enable interrupts and enter idle loop
    // SAFETY: All AP-local hardware is initialized.
    x86_64::instructions::interrupts::enable();

    loop {
        hlt();
    }
}

/// AP entry point — AArch64 (called by Limine when an AP is woken via `goto_address`).
///
/// Each AP arrives at EL1 with its own stack (provided by Limine),
/// kernel page tables active, and interrupts masked (DAIF.I set).
///
/// `cpu.lapic_id` on AArch64 is the MPIDR_EL1 value for the AP.
/// `cpu.extra` holds the logical CPU index assigned by the BSP.
///
/// # Safety
/// Called by the Limine MP protocol machinery. Must never return.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn ap_entry(cpu: &limine::mp::Cpu) -> ! {
    let cpu_index = cpu.extra.load(core::sync::atomic::Ordering::Acquire) as usize;
    let mpidr_aff = cpu.mpidr;

    // SAFETY: All steps below are called exactly once per AP during the AP
    // startup sequence. BSP has already initialized shared hardware (GIC
    // distributor, timer frequency). Each unsafe call initialises per-CPU
    // state (TPIDR_EL1, VBAR_EL1, GIC CPU interface, GICR, timer).
    unsafe {
        // Step 1: Per-CPU EL1 config (no-op on AArch64)
        cambios_core::arch::gdt::init_for_cpu(cpu_index);

        // Step 2: Initialize per-CPU data (writes TPIDR_EL1)
        cambios_core::arch::aarch64::percpu::init_ap(cpu_index, mpidr_aff);

        // Step 3: Install exception vector table (per-CPU VBAR_EL1)
        cambios_core::arch::syscall::init();

        // Step 4: Initialize GIC CPU interface for this AP
        cambios_core::arch::aarch64::gic::init();

        // Step 5: Initialize GIC Redistributor for this AP
        /// HARDWARE: ARM GICv3 Redistributor base on QEMU `virt`;
        /// matches the BSP constant of the same name above. Every
        /// AP walks its own redistributor at `base + cpu_index*stride`
        /// inside `init_redistributor`.
        const GICR_PHYS: u64 = 0x080A_0000;
        let hhdm = cambios_core::hhdm_offset();
        cambios_core::arch::aarch64::gic::init_redistributor(GICR_PHYS + hhdm, cpu_index as u32);

        // Step 6: Start ARM Generic Timer (reuses BSP's frequency/reload values)
        // ADR-021 Phase B.3: AP discovers if BSP forgot to init the timer.
        cambios_core::arch::aarch64::timer::init_ap()
            .unwrap_or_else(|err| cambios_core::boot::boot_failed(err));
    }

    // Step 7: Initialize per-CPU scheduler and timer
    {
        use cambios_core::scheduler::{Scheduler, Timer, TimerConfig};

        let mut scheduler = Scheduler::new_boxed();
        if scheduler.init().is_err() {
            // Non-fatal: AP will just idle without a scheduler
        } else {
            *PER_CPU_SCHEDULER[cpu_index].lock() = Some(scheduler);
        }

        if let Ok(mut timer) = Timer::new(TimerConfig::HZ_100) {
            let _ = timer.init();
            *PER_CPU_TIMER[cpu_index].lock() = Some(timer);
        }
    }

    // Step 8: Signal BSP that this AP is ready
    AP_READY_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    cambios_core::ONLINE_CPU_COUNT.fetch_add(1, core::sync::atomic::Ordering::Release);

    // Step 9: Set SP_EL1 and enable IRQs
    // SAFETY: All AP-local hardware is initialized.
    unsafe {
        // Set SP_EL1 = current AP stack for exception entry
        core::arch::asm!(
            "mov {tmp}, sp",
            "msr spsel, #1",
            "mov sp, {tmp}",
            "msr spsel, #0",
            tmp = out(reg) _,
            options(nostack),
        );
        // Unmask IRQ — timer was started by init_ap(), GIC is configured
        core::arch::asm!("msr daifclr, #2", options(nostack, nomem));
    }

    loop {
        cambios_core::wfi();
    }
}

/// Distribute tasks from CPU 0 to APs for balanced scheduling.
///
/// Called after all APs are online with their own schedulers.
/// Migrates a subset of tasks from the BSP's run queue to available APs
/// in round-robin fashion. Only Ready/Blocked tasks are migrated.
fn distribute_tasks_to_aps() {
    use cambios_core::scheduler::{TaskId, migrate_task};

    // Count online APs by checking which per-CPU schedulers are initialized
    let ap_count = AP_READY_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize;
    if ap_count == 0 {
        return; // Single-CPU — nothing to distribute
    }

    // Collect migratable task IDs from CPU 0's scheduler
    // Skip idle task (0) — each CPU has its own idle task
    let mut migratable: [Option<TaskId>; 256] = [None; 256];
    let mut count = 0;

    {
        let guard = PER_CPU_SCHEDULER[0].lock();
        if let Some(sched) = guard.as_ref() {
            // Tasks 1..N that are Ready (not Running or Blocked on hardware)
            for slot in 1..cambios_core::MAX_TASKS as u32 {
                let tid = TaskId(slot);
                if let Some(task) = sched.get_task_pub(tid) {
                    if task.state == cambios_core::scheduler::TaskState::Ready {
                        migratable[count] = Some(tid);
                        count += 1;
                    }
                }
            }
        }
    }

    if count == 0 {
        return;
    }

    // Distribute ~half the tasks to APs (round-robin across available APs)
    let to_migrate = count / 2;
    if to_migrate == 0 {
        return;
    }

    let mut migrated = 0;
    let mut ap_target = 1usize; // Start with CPU 1

    for &slot in migratable.iter().take(count) {
        if migrated >= to_migrate {
            break;
        }
        if let Some(tid) = slot {
            match migrate_task(tid, 0, ap_target) {
                Ok(()) => {
                    println!("  ✓ Migrated {} → CPU {}", tid, ap_target);
                    migrated += 1;
                    ap_target = 1 + (ap_target % ap_count); // Round-robin
                }
                Err(e) => {
                    println!("  ✗ Failed to migrate {}: {:?}", tid, e);
                }
            }
        }
    }

    if migrated > 0 {
        println!("✓ Distributed {} task(s) across {} CPU(s)", migrated, ap_count + 1);
    }
}

/// Wake all Application Processors and wait for them to initialize.
///
/// Uses the Limine MP protocol: for each non-BSP CPU entry, writes the
/// logical CPU index to `extra` and the AP entry function to `goto_address`.
///
/// # Safety
/// Must be called after all BSP subsystems are initialized (GDT, IDT, APIC,
/// scheduler, etc.) and after `init_hardware_interrupts()`.
unsafe fn start_application_processors() {
    // RISC-V SMP — Phase R-5.a. Iterate harts reported by the DTB
    // (`/cpus/cpu@N/reg`), skip the BSP (our own hart_id), and wake
    // each AP via SBI HSM's `sbi_hart_start`. The target PA is the
    // `_ap_start` assembly entry in `src/arch/riscv64/entry.rs`,
    // which loads the AP's boot stack, flips satp to the BSP's root
    // (published via `BOOT_SATP`), and jumps to `kmain_riscv64_ap`.
    // The `opaque` argument carries `cpu_index` — the index the AP
    // uses to reach its PER_CPU_SCHEDULER / PER_CPU_TIMER / percpu
    // slot.
    //
    // Long-term this is where a `BootProtocol` trait would factor:
    // x86_64 + AArch64 use Limine's MP response, RISC-V uses SBI
    // HSM, and the BSP is the same portable code. For now the
    // arch-gated branches live here.
    #[cfg(target_arch = "riscv64")]
    {
        use cambios_core::arch::riscv64::entry::MAX_AP_BOOT_STACKS;
        use cambios_core::arch::riscv64::sbi;

        let info = cambios_core::boot::info();
        let hart_count = info.hart_count();
        if hart_count <= 1 {
            println!("  Single-hart (DTB reported {} hart(s))", hart_count);
            return;
        }

        // Own hart id (the BSP) — skip it when dispatching APs.
        // SAFETY: BSP per-CPU storage is initialized earlier in boot
        // (before AP dispatch), so `tp` holds a valid `&'static PerCpu`
        // and `current_percpu()` returns a live reference.
        let bsp_hart_id = unsafe {
            cambios_core::arch::riscv64::percpu::current_percpu().apic_id()
        } as u64;

        // `_ap_start` is linked at a higher-half VMA; SBI needs the
        // LMA (physical address). The linker script sets
        // VMA - LMA = 0xffffffff_00000000.
        extern "C" {
            fn _ap_start();
        }
        let ap_start_phys = (_ap_start as *const () as u64)
            .wrapping_sub(0xffff_ffff_0000_0000);

        println!(
            "  Waking {} AP(s) via SBI HSM (total harts: {}; _ap_start phys = {:#x})",
            hart_count - 1, hart_count, ap_start_phys,
        );

        // cpu_index 0 is the BSP. APs claim 1, 2, ... in the order
        // the DTB enumerates them. Bounded by MAX_AP_BOOT_STACKS.
        let mut next_cpu_idx: u64 = 1;
        let mut dispatched: u32 = 0;
        for hart_id in info.harts() {
            if hart_id == bsp_hart_id {
                continue;
            }
            if (next_cpu_idx as usize) >= MAX_AP_BOOT_STACKS {
                println!(
                    "  ⚠ Out of AP boot stacks (MAX_AP_BOOT_STACKS={}) — \
                     skipping hart {}",
                    MAX_AP_BOOT_STACKS, hart_id,
                );
                break;
            }
            // SAFETY: `hart_id` came from the DTB hart enumeration and
            // is a valid hart. `ap_start_phys` is the LMA of `_ap_start`
            // (computed above by subtracting the VMA→LMA offset the
            // linker script fixes at build time). `next_cpu_idx` is
            // bounded by `MAX_AP_BOOT_STACKS` (checked immediately
            // above). SBI HSM accepts these as ecall args.
            let err = unsafe { sbi::sbi_hart_start(hart_id, ap_start_phys, next_cpu_idx) };
            if err == 0 {
                println!(
                    "  → sbi_hart_start(hart={}, cpu_idx={}) dispatched",
                    hart_id, next_cpu_idx,
                );
                next_cpu_idx += 1;
                dispatched += 1;
            } else {
                println!(
                    "  ✗ sbi_hart_start(hart={}) failed: SBI err={}",
                    hart_id, err,
                );
            }
        }

        // Spin-wait for APs to signal readiness. Matches the AArch64
        // pattern — AP counter lands here via AP_READY_COUNT.
        if dispatched > 0 {
            while AP_READY_COUNT.load(core::sync::atomic::Ordering::Acquire) < dispatched {
                core::hint::spin_loop();
            }
            println!("  ✓ {} AP(s) online (total harts: {})", dispatched, hart_count);
        }
        return;
    }

    #[cfg(not(target_arch = "riscv64"))]
    {
    let mp_response = match MP_REQUEST.get_response() {
        Some(r) => r,
        None => {
            println!("  No MP response — single-CPU system");
            return;
        }
    };

    #[cfg(target_arch = "x86_64")]
    let bsp_id: u64 = mp_response.bsp_lapic_id() as u64;
    #[cfg(target_arch = "aarch64")]
    let bsp_id: u64 = mp_response.bsp_mpidr();

    let cpus = mp_response.cpus();
    let total_cpus = cpus.len();

    // Count APs (non-BSP CPUs)
    #[cfg(target_arch = "x86_64")]
    let ap_count = cpus.iter().filter(|c| c.lapic_id as u64 != bsp_id).count();
    #[cfg(target_arch = "aarch64")]
    let ap_count = cpus.iter().filter(|c| c.mpidr != bsp_id).count();

    if ap_count == 0 {
        println!("  Single-CPU system (BSP only)");
        return;
    }

    println!("  Waking {} AP(s) (total CPUs: {})...", ap_count, total_cpus);

    // Assign logical CPU indices and wake each AP
    let mut cpu_index: usize = 1; // BSP = 0, APs start at 1
    for cpu in cpus.iter() {
        #[cfg(target_arch = "x86_64")]
        let is_bsp = cpu.lapic_id as u64 == bsp_id;
        #[cfg(target_arch = "aarch64")]
        let is_bsp = cpu.mpidr == bsp_id;
        if is_bsp {
            continue; // Skip BSP
        }

        // Store the logical CPU index in the `extra` field for the AP to read
        cpu.extra.store(cpu_index as u64, core::sync::atomic::Ordering::Release);

        // Write the entry function — this wakes the AP
        cpu.goto_address.write(ap_entry);

        cpu_index += 1;
    }

    // Wait for all APs to signal ready (with timeout)
    let expected = ap_count as u32;
    let mut spin_count: u64 = 0;
    /// TUNING: spin-loop ceiling while waiting for all APs to reach
    /// their ready signal. 100M ≈ a few seconds on modern hardware,
    /// which is well above any realistic AP wake latency and short
    /// enough that a failed AP doesn't hang boot indefinitely.
    /// Replace when a platform with slow AP bring-up (rare) or many
    /// cores (> ~32) needs a larger budget.
    const MAX_SPINS: u64 = 100_000_000; // ~a few seconds on modern hardware

    while AP_READY_COUNT.load(core::sync::atomic::Ordering::Acquire) < expected {
        core::hint::spin_loop();
        spin_count += 1;
        if spin_count >= MAX_SPINS {
            let ready = AP_READY_COUNT.load(core::sync::atomic::Ordering::Acquire);
            println!(
                "  WARNING: AP startup timeout — {}/{} APs ready",
                ready, expected
            );
            break;
        }
    }

    let ready = AP_READY_COUNT.load(core::sync::atomic::Ordering::Acquire);
    println!(
        "  ✓ {}/{} AP(s) online (total CPUs: {})",
        ready, expected, ready as usize + 1
    );
    } // end #[cfg(not(target_arch = "riscv64"))]
}

/// Main microkernel event loop
///
/// Scheduling is interrupt-driven (timer ISR → scheduler tick + context switch).
/// This loop serves as the idle task. It halts/waits until the next interrupt,
/// reducing power consumption.
///
/// The timer ISR handles all tick counting, time slice accounting, and scheduling.
/// Periodic diagnostics run between halts, gated by tick count (not idle wakeups)
/// for deterministic frequency regardless of interrupt rate.
fn microkernel_loop() -> ! {
    // Enable interrupts before entering the idle loop
    #[cfg(target_arch = "x86_64")]
    x86_64::instructions::interrupts::enable();
    #[cfg(target_arch = "aarch64")]
    {
        // Drain any pending GIC interrupts from boot that were never acknowledged.
        // Without this, the GIC won't deliver new interrupts.
        // SAFETY: GIC is initialized. acknowledge_irq/write_eoi are ICC sysreg
        // operations valid at EL1. Loop terminates when INTID >= 1020 (spurious).
        unsafe {
            loop {
                let intid = cambios_core::arch::aarch64::gic::acknowledge_irq();
                if intid >= 1020 { break; }
                cambios_core::arch::aarch64::gic::write_eoi();
            }
        }
        // Rearm the timer so the first tick fires cleanly.
        // SAFETY: Timer is initialized; writing CNTP_TVAL_EL0 is valid at EL1.
        unsafe { cambios_core::arch::aarch64::timer::rearm(); }
        // Set SP_EL1 = current kernel stack so the first timer ISR has a
        // valid stack. Exception entry forces SPSel=1 → SP = SP_EL1.
        // Uses SPSel toggle because QEMU traps `msr sp_el1`.
        // SAFETY: SPSel toggle is valid at EL1. The current SP (boot stack)
        // is valid kernel memory. No interrupts are active yet.
        unsafe {
            core::arch::asm!(
                "mov {tmp}, sp",         // tmp = current SP (SP_EL0 = boot stack)
                "msr spsel, #1",         // SP = SP_EL1
                "mov sp, {tmp}",         // SP_EL1 = boot stack
                "msr spsel, #0",         // SP = SP_EL0 (back)
                tmp = out(reg) _,
                options(nostack),
            );
        }
        // SAFETY: All hardware initialized (GIC, timer, VBAR_EL1).
        unsafe { core::arch::asm!("msr daifclr, #2", options(nostack, nomem)); }
    }

    // Tick-based gating: deterministic frequency regardless of interrupt rate.
    // Invariant check every 60s (6000 ticks @ 100Hz). The periodic status
    // tick ("[Tick N] Tasks: ...") was removed in Phase 4b — it cluttered
    // serial output without providing runtime value. Invariant verification
    // stays: it halts on corruption, which is silent and load-bearing.
    let mut last_verify_tick: u64 = 0;
    // SMP timer-diagnostic snapshot: a single one-shot print 1 s after
    // APs come online, so any AP whose PPI 30 isn't being delivered
    // shows up as a zero tick count in the serial log. Keyed off the
    // global tick count rather than wall-clock for determinism.
    let mut smp_diag_printed: bool = false;

    loop {
        let ticks = Timer::get_ticks();

        // Periodic invariant verification (every ~60 seconds)
        if ticks >= last_verify_tick + 6000 {
            last_verify_tick = ticks;
            if let Some(scheduler) = cambios_core::local_scheduler().try_lock() {
                if let Some(sched) = scheduler.as_ref() {
                    if let Err(e) = sched.verify_invariants() {
                        println!("✗ Scheduler invariant violated: {}", e);
                        cambios_core::halt();
                    }
                }
            }
        }

        // SMP timer diagnostic: dump per-CPU tick counters once, ~1 s
        // after boot, so a silent AP timer (GIC PPI 30 on aarch64,
        // LVT timer on x86_64) surfaces as a zero in the log.
        if !smp_diag_printed && ticks >= 100 {
            smp_diag_printed = true;
            let online = cambios_core::online_cpu_count();
            let mut buf_tail: [u64; 8] = [0; 8];
            let report_n = core::cmp::min(online, 8);
            for i in 0..report_n {
                buf_tail[i] = cambios_core::PER_CPU_TIMER_TICKS[i]
                    .load(core::sync::atomic::Ordering::Relaxed);
            }
            println!(
                "[SMP] per-CPU timer ticks after ~1s ({} online): {:?}",
                online, &buf_tail[..report_n],
            );
        }

        // Load balancing: migrate tasks from overloaded to underloaded CPUs
        // (internally throttled to once per BALANCE_INTERVAL_TICKS)
        cambios_core::try_load_balance();

        // Halt/wait CPU until next interrupt (timer, keyboard, etc.)
        #[cfg(target_arch = "x86_64")]
        hlt();
        #[cfg(target_arch = "aarch64")]
        cambios_core::wfi();
    }
}


/// Panic handler for microkernel
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("\nMICROKERNEL PANIC: {:?}", info);
    cambios_core::halt();
}
