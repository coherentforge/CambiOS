#![no_std]
#![no_main]

//! ArcOS Microkernel Main
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

extern crate arcos_core;
extern crate alloc;

// ============================================================================
// Lock ordering — see arcos_core::lib.rs for the authoritative hierarchy
// ============================================================================
//
// PER_CPU_SCHEDULER[*](1) → PER_CPU_TIMER[*](2) → IPC_MANAGER(3) →
// CAPABILITY_MANAGER(4) → PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) →
// INTERRUPT_ROUTER(7) → OBJECT_STORE(8)
//
// Lower-numbered locks must be acquired before higher-numbered ones.
// Sequential (non-nested) acquisitions are always safe — release the first
// before acquiring the second.  Nested acquisitions must follow the order.
//
// Per-CPU lock rule: NEVER hold two different CPUs' scheduler (or timer)
// locks simultaneously.  If cross-CPU access is required (e.g., task
// migration), acquire in ascending CPU index order.
//
// Key patterns in this file:
//   create_user_task:     PROCESS_TABLE(5) + FRAME_ALLOCATOR(6) nested  ✓
//   create_elf_user_task: PROCESS_TABLE(5) + FRAME_ALLOCATOR(6) nested  ✓
//   ipc_send_and_notify:  IPC_MANAGER(3) released, then SCHEDULER(1)   ✓ (sequential)
//   sync_ipc_*:           IPC_MANAGER(3) released, then SCHEDULER(1)   ✓ (sequential)
//
// ============================================================================
// Scalability constraints (known architectural limits)
// ============================================================================
//
// These are documented here for future work, not immediate fixes.
//
// SCHEDULER:
//   - MAX_TASKS=32 is the hard ceiling across all CPUs. With 256 CPUs, most
//     cores idle. Needs per-CPU task arrays or dynamic allocation.
//   - find_next_ready_task() does a two-pass O(32) scan on every timer tick
//     (100Hz × cpu_count). Replace with per-priority run queues or bitmap.
//   - on_timer_isr() uses try_lock(): if the scheduler lock is contended,
//     the timer tick is silently skipped (no preemption, no time accounting).
//
// IPC:
//   - Single global IPC_MANAGER lock serializes all endpoints across all CPUs.
//     Needs per-endpoint sharding or lock-free queues.
//   - MAX_ENDPOINTS=32, queue depth=16. Under load, QueueFull rejections.
//   - Capability verify_access() is O(32) per message send/recv.
//
// MEMORY:
//   - Single global FRAME_ALLOCATOR lock; allocate() scans up to 8192 bitmap
//     words under fragmentation. Needs per-CPU free-lists or zone allocators.
//   - map_range() holds FRAME_ALLOCATOR for N page allocations (e.g., 262
//     frames for a 1MB allocation). Should batch or use per-CPU caches.
//   - Kernel heap is first-fit linked-list with no size-class segregation.

use alloc::boxed::Box;
use limine::BaseRevision;
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RsdpRequest,
    RequestsEndMarker, RequestsStartMarker, StackSizeRequest,
};
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::hlt;
use arcos_core::println;
use arcos_core::scheduler::{Scheduler, Timer, TimerConfig, Priority, BlockReason, TaskId};
use arcos_core::ipc::{EndpointId, IpcManager, Message, ProcessId, CapabilityRights};
use arcos_core::ipc::capability::CapabilityManager;
use arcos_core::interrupts::{IrqNumber, InterruptContext};
use arcos_core::process::ProcessTable;

// Use the global statics from the library crate
use arcos_core::{PER_CPU_SCHEDULER, PER_CPU_TIMER, IPC_MANAGER, CAPABILITY_MANAGER, PROCESS_TABLE, INTERRUPT_ROUTER, BOOTSTRAP_PRINCIPAL, OBJECT_STORE};



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
    if let Some(hhdm_response) = HHDM_REQUEST.get_response() {
        arcos_core::set_hhdm_offset(hhdm_response.offset());
    }

    // AArch64: Diagnose and map MMIO devices before any I/O.
    // Limine's HHDM only covers RAM, not device MMIO.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // Read TCR_EL1 to determine actual VA width
        let tcr: u64;
        core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr, options(nostack, nomem));
        let t1sz = (tcr >> 16) & 0x3F;
        // VA bits for TTBR1 = 64 - T1SZ
        // If T1SZ=25 → 39-bit VA → TTBR1 covers 0xFFFFFF8000000000+
        // If T1SZ=16 → 48-bit VA → TTBR1 covers 0xFFFF000000000000+

        // Widen TCR_EL1.T1SZ to 16 (48-bit VA space) if it's smaller,
        // so that the full HHDM range is addressable.
        if t1sz > 16 {
            let new_tcr = (tcr & !(0x3F << 16)) | (16 << 16);
            core::arch::asm!(
                "msr tcr_el1, {}",
                "isb",
                in(reg) new_tcr,
                options(nostack),
            );
        }

        // Now map MMIO devices into TTBR1
        use arcos_core::memory::paging::early_map_mmio;
        // PL011 UART0 at 0x0900_0000 (QEMU virt)
        if let Err(_) = early_map_mmio(0x0900_0000) {
            // Can't print — UART isn't mapped yet. Just halt.
            loop { core::arch::asm!("wfe", options(nostack, nomem)); }
        }
        // GIC Distributor at 0x0800_0000 (QEMU virt) — map 64KB region.
        // Failure is fatal: scheduling requires GIC for timer interrupts.
        for page in 0..16u64 {
            if let Err(_) = early_map_mmio(0x0800_0000 + page * 0x1000) {
                loop { core::arch::asm!("wfe", options(nostack, nomem)); }
            }
        }
        // GIC Redistributor at 0x080A_0000 (QEMU virt)
        // Each CPU's GICR frame is 128KB (0x20000 stride, two 64KB frames).
        // Map enough for 4 CPUs: 4 × 32 pages = 128 pages = 512KB.
        for page in 0..128u64 {
            if let Err(_) = early_map_mmio(0x080A_0000 + page * 0x1000) {
                loop { core::arch::asm!("wfe", options(nostack, nomem)); }
            }
        }
    }

    // Early diagnostic on AArch64: write to PL011 via HHDM to confirm entry
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let hhdm = arcos_core::hhdm_offset();
        let uart = (0x0900_0000u64 + hhdm) as *mut u8;
        // SAFETY: PL011 UART0 at HHDM address. Just mapped via early_map_mmio.
        core::ptr::write_volatile(uart, b'K');
    }

    // Initialize serial output FIRST so panic messages are visible
    // SAFETY: Called once as the first init step. No other code accesses SERIAL1 yet.
    unsafe { arcos_core::io::init(); }

    // Verify Limine protocol is supported (panics with a message if not)
    assert!(BASE_REVISION.is_supported(), "Limine base revision not supported!");

    println!("=== ArcOS Microkernel [v0.1.0] ===");
    println!("Booted via Limine\n");

    let hhdm_offset = arcos_core::hhdm_offset();
    println!("HHDM offset: {:#x}", hhdm_offset);

    // Report memory map
    if let Some(memmap_response) = MEMORY_MAP_REQUEST.get_response() {
        let entries = memmap_response.entries();
        println!("Memory map: {} entries", entries.len());
        for (i, entry) in entries.iter().enumerate() {
            let type_str = match entry.entry_type {
                limine::memory_map::EntryType::USABLE => "Usable",
                limine::memory_map::EntryType::RESERVED => "Reserved",
                limine::memory_map::EntryType::ACPI_RECLAIMABLE => "ACPI Reclaim",
                limine::memory_map::EntryType::ACPI_NVS => "ACPI NVS",
                limine::memory_map::EntryType::BAD_MEMORY => "Bad",
                limine::memory_map::EntryType::BOOTLOADER_RECLAIMABLE => "Bootloader",
                limine::memory_map::EntryType::EXECUTABLE_AND_MODULES => "Executable",
                limine::memory_map::EntryType::FRAMEBUFFER => "Framebuffer",
                _ => "Unknown",
            };
            println!(
                "  [{:2}] {:#016x} - {:#016x} len={:#x} ({})",
                i,
                entry.base,
                entry.base + entry.length,
                entry.length,
                type_str,
            );
        }
    } else {
        println!("WARNING: No memory map from bootloader");
    }

    // Report framebuffer
    if let Some(fb_response) = FRAMEBUFFER_REQUEST.get_response() {
        if let Some(fb) = fb_response.framebuffers().next() {
            println!(
                "Framebuffer: {}x{} @ {:#x}",
                fb.width(),
                fb.height(),
                fb.addr() as usize,
            );
        }
    }

    println!();

    // Initialize kernel heap allocator from Limine memory map
    init_kernel_heap();

    // Initialize physical frame allocator from Limine memory map
    init_frame_allocator();

    // Load our GDT (replaces Limine's) — must be before IDT and syscall init
    // On AArch64: no-op (EL1/EL0 managed via exception levels).
    // SAFETY: Single-threaded boot, interrupts disabled.
    unsafe { arcos_core::arch::gdt::init(); }
    println!("✓ GDT loaded (kernel CS={:#x}, SS={:#x})",
        arcos_core::arch::gdt::KERNEL_CS,
        arcos_core::arch::gdt::KERNEL_SS,
    );

    // Save the kernel page table root for restoring address space after user tasks
    {
        #[cfg(target_arch = "x86_64")]
        {
            let cr3: u64;
            // SAFETY: Reading CR3 is safe at ring 0. Returns the PML4 physical address.
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem)); }
            arcos_core::set_kernel_cr3(cr3);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let ttbr1: u64;
            // SAFETY: Reading TTBR1_EL1 is safe at EL1. This is the kernel page table.
            unsafe { core::arch::asm!("mrs {}, ttbr1_el1", out(reg) ttbr1, options(nostack, nomem)); }
            arcos_core::set_kernel_cr3(ttbr1);
        }
    }

    // Initialize exception/interrupt vector table
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Single-threaded boot, GDT already loaded. Sets up exception handlers.
        unsafe { arcos_core::interrupts::init(); }
        println!("✓ IDT loaded");
    }

    // Initialize SYSCALL/SYSRET MSRs (x86_64) or VBAR_EL1 exception vectors (AArch64)
    // SAFETY: GDT loaded, single-threaded boot.
    unsafe { arcos_core::arch::syscall::init(); }
    #[cfg(target_arch = "x86_64")]
    println!("✓ SYSCALL/SYSRET configured");
    #[cfg(target_arch = "aarch64")]
    println!("✓ Exception vector table loaded (VBAR_EL1)");

    // Initialize microkernel subsystems
    process_table_init();  // Must be before scheduler (user tasks need process table)
    scheduler_init();
    ipc_init();
    capability_manager_init();
    bootstrap_identity_init();  // Must be after capability_manager_init (binds to processes)
    object_store_init();        // Must be after heap init (heap-allocated)

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
        let rsdp_phys = RSDP_REQUEST.get_response()
            .map(|r| r.address() as u64)
            .unwrap_or(0);

        // Map ACPI physical memory into the HHDM before parsing.
        map_acpi_regions(rsdp_phys);

        // SAFETY: All subsystems initialized. HHDM offset is set.
        unsafe {
            arcos_core::interrupts::init_hardware_interrupts(100, rsdp_phys);
        }
        println!("✓ APIC-driven scheduling active\n");
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
            arcos_core::arch::aarch64::percpu::init_bsp(bsp_mpidr & 0xFF_FFFF);
            println!("  ✓ Per-CPU data initialized (BSP, MPIDR={:#x})", bsp_mpidr & 0xFF_FFFF);

            // Initialize GIC CPU interface (ICC system registers)
            arcos_core::arch::aarch64::gic::init();
            println!("  ✓ GIC CPU interface enabled");

            // Initialize GIC Distributor (SPI routing, priorities)
            // QEMU virt physical addresses, translated through HHDM
            const GICD_PHYS: u64 = 0x0800_0000;
            const GICR_PHYS: u64 = 0x080A_0000;
            let hhdm = arcos_core::hhdm_offset();
            arcos_core::arch::aarch64::gic::init_distributor(GICD_PHYS + hhdm);
            println!("  ✓ GIC Distributor initialized");

            // Initialize GIC Redistributor for BSP (PPI 30 = timer)
            arcos_core::arch::aarch64::gic::init_redistributor(GICR_PHYS + hhdm, 0);
            println!("  ✓ GIC Redistributor initialized (CPU 0)");

            // Start ARM Generic Timer at 100 Hz
            arcos_core::arch::aarch64::timer::init(100);
            println!("  ✓ ARM Generic Timer started (100 Hz)");
        }
        println!("✓ GIC + timer scheduling active\n");
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

    // Enter idle loop — all scheduling is now interrupt-driven
    // APIC timer fires vector 32 → timer_isr_stub → scheduler tick + context switch.
    microkernel_loop();
}

// ============================================================================
// Kernel heap initialization from Limine memory map
// ============================================================================

/// Kernel heap size: 4 MB (plenty for kernel-level Box/Vec allocations)
const KERNEL_HEAP_SIZE: u64 = 4 * 1024 * 1024;

/// Actual physical base chosen by init_kernel_heap(). Used by init_frame_allocator()
/// to reserve the correct region regardless of where RAM starts (x86: 0x200000,
/// AArch64 QEMU virt: somewhere above 0x4000_0000).
static KERNEL_HEAP_PHYS_BASE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Initialize the kernel heap allocator from the Limine physical memory map.
///
/// Finds a large USABLE physical region, converts it to a virtual address via
/// the HHDM offset, and hands it to the global allocator.
fn init_kernel_heap() {
    use limine::memory_map::EntryType;

    let hhdm_offset = HHDM_REQUEST
        .get_response()
        .expect("HHDM response required for kernel heap")
        .offset();

    let memmap = MEMORY_MAP_REQUEST
        .get_response()
        .expect("Memory map required for kernel heap");

    // Find the largest USABLE region that can hold our heap
    let mut best: Option<(u64, u64)> = None; // (base, length)
    for entry in memmap.entries() {
        if entry.entry_type == EntryType::USABLE && entry.length >= KERNEL_HEAP_SIZE {
            match best {
                Some((_, best_len)) if entry.length <= best_len => {}
                _ => best = Some((entry.base, entry.length)),
            }
        }
    }

    let (phys_base, region_len) = best.expect("No usable memory region large enough for kernel heap");

    // Skip first 1MB of region to avoid any low-memory conflicts
    let safe_offset: u64 = if phys_base < 0x200000 { 0x200000 - phys_base } else { 0 };
    let phys_base = phys_base + safe_offset;
    let region_len = region_len - safe_offset;

    assert!(
        region_len >= KERNEL_HEAP_SIZE,
        "Largest usable region too small after skipping low memory ({:#x} < {:#x})",
        region_len, KERNEL_HEAP_SIZE,
    );

    // Use only what we need from this region
    let heap_size = KERNEL_HEAP_SIZE as usize;
    let virt_base = phys_base as usize + hhdm_offset as usize;

    // Record the actual physical base so init_frame_allocator() can reserve it
    KERNEL_HEAP_PHYS_BASE.store(phys_base, core::sync::atomic::Ordering::Release);

    // SAFETY: virt_base is a valid writable address in the HHDM region, covering
    // heap_size bytes of usable physical memory reported by Limine. Called once.
    unsafe {
        arcos_core::KERNEL_HEAP.init(virt_base, heap_size);
    }

    let (used, free) = arcos_core::KERNEL_HEAP.stats();
    println!(
        "✓ Kernel heap: {} KB at virt {:#x} (phys {:#x}, region {} KB)",
        heap_size / 1024,
        virt_base,
        phys_base,
        region_len / 1024,
    );
    let _ = (used, free); // suppress unused warning in release
}

/// Initialize the physical frame allocator from the Limine memory map.
///
/// Marks all USABLE regions as available, then reserves the kernel heap
/// and process heap regions so they can't be double-allocated.
fn init_frame_allocator() {
    use limine::memory_map::EntryType;
    use arcos_core::FRAME_ALLOCATOR;
    use arcos_core::memory::frame_allocator::PAGE_SIZE;

    let memmap = MEMORY_MAP_REQUEST
        .get_response()
        .expect("Memory map required for frame allocator");

    let mut fa = FRAME_ALLOCATOR.lock();

    // Pass 1: Add all USABLE regions
    for entry in memmap.entries() {
        if entry.entry_type == EntryType::USABLE {
            fa.add_region(entry.base, entry.length);
        }
    }

    // Pass 2: Reserve regions we're already using
    // - First 1 MB: x86 real-mode/BIOS area (not applicable on AArch64)
    #[cfg(target_arch = "x86_64")]
    fa.reserve_region(0, 0x100000);
    // - Kernel heap (base was chosen dynamically by init_kernel_heap)
    let heap_phys = KERNEL_HEAP_PHYS_BASE.load(core::sync::atomic::Ordering::Acquire);
    fa.reserve_region(heap_phys, KERNEL_HEAP_SIZE);
    // - Process heaps: 32 × 1 MB starting at 0x800000
    fa.reserve_region(
        arcos_core::process::PROCESS_HEAP_BASE,
        arcos_core::process::MAX_PROCESSES as u64 * arcos_core::process::HEAP_SIZE,
    );

    fa.finalize();

    println!(
        "✓ Frame allocator: {} free frames ({} MB of {} MB tracked)",
        fa.free_count(),
        fa.free_count() * PAGE_SIZE as usize / (1024 * 1024),
        fa.total_count() * PAGE_SIZE as usize / (1024 * 1024),
    );
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
    use limine::memory_map::EntryType;
    use arcos_core::FRAME_ALLOCATOR;
    use arcos_core::memory::paging;
    use x86_64::structures::paging::PageTableFlags;

    let hhdm = arcos_core::hhdm_offset();
    let flags = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;

    let mut fa_guard = FRAME_ALLOCATOR.lock();

    // SAFETY: Single-threaded boot, interrupts disabled, page table valid.
    let mut pt = unsafe { paging::active_page_table() };

    // Map the page containing the RSDP (often in BIOS RESERVED area, not in HHDM)
    if rsdp_phys != 0 {
        let page_phys = rsdp_phys & !0xFFF;
        let _ = paging::map_page(&mut pt, page_phys + hhdm, page_phys, flags, &mut *fa_guard);
    }

    // Map all ACPI-related and small RESERVED regions.
    // With Limine base revision 3, only Usable/Bootloader/Executable/Framebuffer
    // regions are in the HHDM. ACPI tables may be in ACPI_RECLAIMABLE, ACPI_NVS,
    // or RESERVED regions (SeaBIOS puts ACPI tables in RESERVED memory).
    // Map small RESERVED regions (< 1 MB) to safely cover BIOS data and ACPI tables
    // without accidentally mapping huge MMIO ranges.
    const MAX_RESERVED_MAP_SIZE: u64 = 1024 * 1024; // 1 MB
    let mut mapped_pages = 0usize;
    if let Some(memmap) = MEMORY_MAP_REQUEST.get_response() {
        for entry in memmap.entries() {
            let should_map = match entry.entry_type {
                EntryType::ACPI_RECLAIMABLE | EntryType::ACPI_NVS => true,
                EntryType::RESERVED if entry.length <= MAX_RESERVED_MAP_SIZE => true,
                _ => false,
            };
            if should_map {
                let base = entry.base & !0xFFF;
                let end = (entry.base + entry.length + 0xFFF) & !0xFFF;
                let page_count = ((end - base) / 4096) as usize;
                for i in 0..page_count {
                    let phys = base + (i as u64) * 4096;
                    // Ignore AlreadyMapped — page may overlap with an existing mapping
                    let _ = paging::map_page(&mut pt, phys + hhdm, phys, flags, &mut *fa_guard);
                }
                mapped_pages += page_count;
            }
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
        arcos_core::halt();
    }

    // Idle task (Task 0) uses the Limine boot stack (256KB). Its saved_rsp
    // starts at 0 and will be filled on the first timer interrupt.

    // Create test tasks with real allocated kernel stacks
    let entry_a = task_a_entry as *const () as u64;
    let entry_b = task_b_entry as *const () as u64;

    let saved_rsp_1 = alloc_task_stack(entry_a);
    let saved_rsp_2 = alloc_task_stack(entry_b);

    let _t1 = scheduler.create_isr_task(
        entry_a,
        saved_rsp_1,
        0, // stack_top tracked via saved_rsp
        Priority::NORMAL,
    );
    let _t2 = scheduler.create_isr_task(
        entry_b,
        saved_rsp_2,
        0,
        Priority::NORMAL,
    );

    // Create user-mode tasks with their own address spaces
    {
        // Create a user-mode task with its own address space (hand-rolled)
        create_user_task(&mut scheduler);

        // Create a second user task via the ELF loader pipeline (verify-before-execute)
        create_elf_user_task(&mut scheduler);
    }

    // Load ELF binaries from Limine boot modules (filesystem-free loading)
    load_boot_modules(&mut scheduler);

    // Register all initial tasks in the global task→CPU map (all on CPU 0)
    for slot in 0..arcos_core::MAX_TASKS as u32 {
        if scheduler.get_task_pub(TaskId(slot)).is_some() {
            arcos_core::set_task_cpu(slot, 0);
        }
    }

    // Store in per-CPU scheduler array (BSP = CPU 0, already heap-allocated)
    *PER_CPU_SCHEDULER[0].lock() = Some(scheduler);

    // Initialize timer (100 Hz = 10ms ticks)
    let mut timer = match Timer::new(TimerConfig::HZ_100) {
        Ok(t) => t,
        Err(e) => {
            println!("✗ Timer creation failed: {}", e);
            arcos_core::halt();
        }
    };

    if let Err(e) = timer.init() {
        println!("✗ Timer init failed: {}", e);
        arcos_core::halt();
    }

    *PER_CPU_TIMER[0].lock() = Some(timer);
}

// ============================================================================
// Task entry points and stack setup
// ============================================================================

/// Per-task kernel stack size (8 KB)
const TASK_STACK_SIZE: usize = 8192;

/// Allocate a kernel stack and initialize a SavedContext for first dispatch (x86_64).
///
/// Returns the initial saved_rsp (pointer to SavedContext on the new stack).
/// The iretq in the ISR stub will pop this context and jump to entry_point.
#[cfg(target_arch = "x86_64")]
fn alloc_task_stack(entry_point: u64) -> u64 {
    use alloc::alloc::{alloc, Layout};
    use arcos_core::arch::SavedContext;
    use core::mem::size_of;

    let layout = Layout::from_size_align(TASK_STACK_SIZE, 16)
        .expect("Invalid stack layout");
    // SAFETY: Layout is valid (TASK_STACK_SIZE=8192, align=16). Returns a 16-byte
    // aligned allocation of TASK_STACK_SIZE bytes from the kernel heap.
    let stack_base = unsafe { alloc(layout) };
    if stack_base.is_null() {
        panic!("Failed to allocate kernel stack");
    }

    let stack_top = stack_base as u64 + TASK_STACK_SIZE as u64;

    // Place a SavedContext at the top of the stack (as if the task was just interrupted)
    let saved_ctx_addr = stack_top - size_of::<SavedContext>() as u64;
    let saved_ctx = saved_ctx_addr as *mut SavedContext;

    // SAFETY: saved_ctx points to a valid, aligned, writable location within the
    // newly allocated stack (stack_top - sizeof(SavedContext)). The SavedContext is
    // fully initialized with the entry point, kernel CS/SS, and IF-enabled RFLAGS.
    // The ISR stub's iretq will pop this context to start the task.
    unsafe {
        core::ptr::write(saved_ctx, SavedContext {
            r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0,
            r9: 0, r8: 0, rbp: 0, rdi: 0, rsi: 0, rdx: 0,
            rcx: 0, rbx: 0, rax: 0,
            rip: entry_point,
            cs: arcos_core::arch::gdt::KERNEL_CS as u64,
            rflags: 0x202,  // IF set (interrupts enabled on entry)
            rsp: stack_top,  // Task gets a clean stack after iretq
            ss: arcos_core::arch::gdt::KERNEL_SS as u64,
        });
    }

    saved_ctx_addr
}

/// Allocate a kernel stack and initialize a SavedContext for first dispatch (AArch64).
///
/// Returns the initial saved_sp (pointer to SavedContext on the new stack).
/// The timer ISR stub's eret will pop this context and jump to entry_point.
#[cfg(target_arch = "aarch64")]
fn alloc_task_stack(entry_point: u64) -> u64 {
    use alloc::alloc::{alloc, Layout};
    use arcos_core::arch::SavedContext;
    use core::mem::size_of;

    let layout = Layout::from_size_align(TASK_STACK_SIZE, 16)
        .expect("Invalid stack layout");
    // SAFETY: Layout is valid (TASK_STACK_SIZE=8192, align=16).
    let stack_base = unsafe { alloc(layout) };
    if stack_base.is_null() {
        panic!("Failed to allocate kernel stack");
    }

    let stack_top = stack_base as u64 + TASK_STACK_SIZE as u64;

    // Place a SavedContext at the top of the stack
    let saved_ctx_addr = stack_top - size_of::<SavedContext>() as u64;
    let saved_ctx = saved_ctx_addr as *mut SavedContext;

    // SAFETY: saved_ctx points to a valid, aligned, writable location within the
    // newly allocated stack. The SavedContext is initialized with the entry point
    // in elr_el1 and SPSR_EL1 set for EL1h with interrupts enabled (DAIF clear).
    unsafe {
        // Zero-initialize all GPRs
        let mut ctx = core::mem::zeroed::<SavedContext>();
        ctx.elr_el1 = entry_point;
        // SPSR_EL1: EL1h (M[3:0]=0b0101=5), DAIF clear (interrupts enabled)
        ctx.spsr_el1 = 0x5;
        // SP_EL0: not used for kernel tasks, set to stack top as scratch
        ctx.sp_el0 = stack_top;
        core::ptr::write(saved_ctx, ctx);
    }

    saved_ctx_addr
}

/// Task A entry point — kernel-mode loop
///
/// Runs in Ring 0 (x86_64) or EL1 (AArch64).
/// Prints periodic status to prove context switching works.
/// Must never return.
#[cfg(target_arch = "x86_64")]
fn task_a_entry() -> ! {
    // Test SYSCALL from ring 0: invoke SYS_GET_PID (number 8)
    let pid: i64;
    // SAFETY: We are in ring 0 with SYSCALL/SYSRET initialized. RAX=8 invokes
    // SYS_GET_PID. The clobber list covers all caller-saved registers that the
    // syscall convention may modify.
    unsafe {
        core::arch::asm!(
            "mov rax, 8",
            "syscall",
            lateout("rax") pid,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("rdi") _,
            lateout("rsi") _,
            lateout("rdx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
        );
    }
    arcos_core::println!("[Task A] SYSCALL test: GetPid returned {} — idle", pid);

    // Idle: halt until next interrupt, repeat (low power, no output)
    loop { hlt(); }
}

/// Task B entry point — kernel-mode loop (x86_64)
#[cfg(target_arch = "x86_64")]
fn task_b_entry() -> ! {
    // Test SYSCALL from ring 0: invoke SYS_GET_TIME (number 9)
    let ticks: i64;
    // SAFETY: Same as task_a_entry — ring 0 SYSCALL with full clobber list.
    unsafe {
        core::arch::asm!(
            "mov rax, 9",
            "syscall",
            lateout("rax") ticks,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("rdi") _,
            lateout("rsi") _,
            lateout("rdx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
        );
    }
    arcos_core::println!("[Task B] SYSCALL test: GetTime returned {} — idle", ticks);

    // Idle: halt until next interrupt, repeat (low power, no output)
    loop { hlt(); }
}

/// Task A entry point — kernel-mode loop (AArch64)
///
/// Runs at EL1. Uses SVC #0 to invoke syscalls (x8=number, x0-x5=args).
#[cfg(target_arch = "aarch64")]
fn task_a_entry() -> ! {
    // Test SVC syscall: SYS_GET_PID (number 8)
    let pid: u64;
    // SAFETY: We are at EL1 with the exception vector table installed.
    // x8=8 invokes SYS_GET_PID. Result is returned in x0.
    unsafe {
        core::arch::asm!(
            "mov x8, #8",
            "svc #0",
            lateout("x0") pid,
            out("x8") _,
            out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _, out("x18") _,
        );
    }
    arcos_core::println!("[Task A] SVC test: GetPid returned {} — idle", pid);

    // Idle: wait for interrupt, repeat (low power, no output)
    loop { arcos_core::wfi(); }
}

/// Task B entry point — kernel-mode loop (AArch64)
#[cfg(target_arch = "aarch64")]
fn task_b_entry() -> ! {
    // Test SVC syscall: SYS_GET_TIME (number 9)
    let ticks: u64;
    // SAFETY: Same as task_a_entry — EL1 SVC with full clobber list.
    unsafe {
        core::arch::asm!(
            "mov x8, #9",
            "svc #0",
            lateout("x0") ticks,
            out("x8") _,
            out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _, out("x18") _,
        );
    }
    arcos_core::println!("[Task B] SVC test: GetTime returned {} — idle", ticks);

    // Idle: wait for interrupt, repeat (low power, no output)
    loop { arcos_core::wfi(); }
}

// ============================================================================
// User-mode task constants and entry stubs
// ============================================================================

/// User virtual address where user code is mapped
const USER_CODE_VADDR: u64 = 0x40_0000;
/// User virtual address for the top of the user stack (grows down)
const USER_STACK_TOP: u64 = 0x80_0000;
/// User stack size in pages
const USER_STACK_PAGES: usize = 4; // 16 KB

// User-mode entry function — x86_64 (pure assembly, position-independent).
//
// Runs in Ring 3:
//   1. Calls SYS_GET_PID (syscall 8) — result in RAX
//   2. Converts PID to ASCII, patches message template on the user stack
//   3. Calls SYS_PRINT (syscall 10) — prints "[User N] Ring 3 OK!\n"
//   4. Calls SYS_EXIT (syscall 0) — clean exit
//
// This code is copied to a user-accessible page. Must be fully self-contained
#[cfg(target_arch = "x86_64")]
// (no references to kernel symbols, no relocations).
core::arch::global_asm!(
    ".section .text.user,\"ax\"",
    ".global user_task_entry",
    ".global user_task_entry_end",
    "user_task_entry:",

    // SYS_GET_PID = 8, result in RAX
    "mov rax, 8",
    "syscall",
    // RAX = PID

    // Convert PID to ASCII digit and save
    "add al, 0x30",             // PID → '0'..'9'
    "mov r12b, al",             // save in callee-saved register

    // Copy message template to stack (stack is RW, code page is RO)
    "sub rsp, 24",              // 24 bytes (8-aligned, fits 20-byte message)
    "lea rsi, [rip + .Lmsg]",
    "mov rcx, [rsi]",           // bytes 0..7
    "mov [rsp], rcx",
    "mov rcx, [rsi+8]",         // bytes 8..15
    "mov [rsp+8], rcx",
    "mov ecx, [rsi+16]",        // bytes 16..19
    "mov [rsp+16], ecx",

    // Patch PID digit at offset 6: "[User X]" → "[User N]"
    // Template: [User X] Ring 3 OK!\n
    //           0123456
    //                 ^ byte 6 = 'X' placeholder
    // WARNING: If .Lmsg template changes, this offset MUST be updated to match.
    "mov [rsp+6], r12b",

    // SYS_PRINT = 10: buffer on stack, length = 20
    "mov rdi, rsp",
    "mov rsi, 20",
    "mov rax, 10",
    "syscall",

    "add rsp, 24",

    // SYS_EXIT = 0: clean exit after printing
    "xor edi, edi",
    "mov rax, 0",
    "syscall",

    // Should not reach here — safety spin
    ".Luser_spin:",
    "pause",
    "jmp .Luser_spin",

    // Message template (X is patched at runtime with actual PID digit)
    ".Lmsg:",
    ".ascii \"[User X] Ring 3 OK!\\n\"",   // 20 bytes

    "user_task_entry_end:",
    ".section .text",             // Switch back to normal text section
);

// User-mode entry function — AArch64 (pure assembly, position-independent).
//
// Runs at EL0:
//   1. Calls SYS_GET_PID (x8=8) — result in x0
//   2. Converts PID to ASCII, patches message template on the user stack
//   3. Calls SYS_PRINT (x8=10, x0=buffer, x1=length) — prints "[User N] EL0 OK!\n"
//   4. Calls SYS_EXIT (x8=0) — clean exit
//
// This code is copied to a user-accessible page. Must be fully self-contained
// (no references to kernel symbols, no relocations).
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".section .text.user,\"ax\"",
    ".global user_task_entry",
    ".global user_task_entry_end",
    "user_task_entry:",

    // SYS_GET_PID = 8, result in x0
    "mov x8, #8",
    "svc #0",
    // x0 = PID

    // Convert PID to ASCII digit and save in callee-saved register
    "add w19, w0, #0x30",          // PID → '0'..'9' (w19 = callee-saved)

    // Load message template address (PC-relative)
    "adr x20, .Lmsg_a64",

    // Copy 24 bytes of template to stack (stack is RW, code page is RO)
    // Message is 19 bytes but we copy 24 (3 × 8) for alignment.
    "sub sp, sp, #32",             // 32 bytes (16-aligned)
    "ldp x2, x3, [x20]",          // bytes 0..15
    "stp x2, x3, [sp]",
    "ldr x2, [x20, #16]",         // bytes 16..23 (3 extra bytes past message end)
    "str x2, [sp, #16]",

    // Patch PID digit at offset 6: "[User X]" → "[User N]"
    "strb w19, [sp, #6]",

    // SYS_PRINT = 10: x0=buffer, x1=length
    "mov x0, sp",
    "mov x1, #19",
    "mov x8, #10",
    "svc #0",

    "add sp, sp, #32",

    // SYS_EXIT = 0: clean exit after printing
    "mov x0, #0",
    "mov x8, #0",
    "svc #0",

    // Should not reach here — safety spin
    ".Luser_spin_a64:",
    "mov x8, #7",                  // SYS_YIELD
    "svc #0",
    "b .Luser_spin_a64",

    // Message template (X is patched at runtime with actual PID digit)
    // 19 bytes: "[User X] EL0 OK!\n" + padding to 24 for safe 8-byte loads
    ".Lmsg_a64:",
    ".ascii \"[User X] EL0 OK!\\n\"",  // 19 bytes
    ".balign 8, 0",                     // Pad to 8-byte boundary for safe ldp

    "user_task_entry_end:",
    ".section .text",
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn user_task_entry();
    fn user_task_entry_end();
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    fn user_task_entry();
    fn user_task_entry_end();
}

/// Create a user-mode task with its own address space.
///
/// Portable across x86_64 and AArch64. Steps:
/// 1. Create a process with its own page table (PML4 on x86, L0 on AArch64)
/// 2. Allocate + map user code page at USER_CODE_VADDR
/// 3. Allocate + map user stack pages at USER_STACK_TOP
/// 4. Copy user entry code to the user code page
/// 5. Allocate a kernel stack (for ISR/syscall from user mode)
/// 6. Set up SavedContext for return to user mode (iretq on x86, eret on AArch64)
/// 7. Register the task in the scheduler
fn create_user_task(scheduler: &mut Scheduler) {
    use arcos_core::arch::SavedContext;
    use arcos_core::memory::paging;
    use arcos_core::memory::frame_allocator::PAGE_SIZE;
    use arcos_core::FRAME_ALLOCATOR;
    use alloc::alloc::{alloc, Layout};
    use core::mem::size_of;

    let process_id = ProcessId(3); // Process 3 = first user process

    // --- Step 1: Create process with per-process page table ---
    {
        let mut pt_guard = PROCESS_TABLE.lock();
        let pt = pt_guard.as_mut().expect("ProcessTable not initialized");
        let mut fa_guard = FRAME_ALLOCATOR.lock();
        if let Err(e) = pt.create_process(process_id, Some(&mut fa_guard)) {
            println!("  ✗ Failed to create user process: {}", e);
            return;
        }
        println!("  ✓ User process {} created with page table", process_id.0);
    }

    // Get the process CR3
    let cr3 = {
        let pt_guard = PROCESS_TABLE.lock();
        let pt = pt_guard.as_ref().unwrap();
        pt.get_cr3(process_id)
    };

    if cr3 == 0 {
        println!("  ✗ User process has no page table!");
        return;
    }

    // --- Step 2: Allocate + map user code page ---
    {
        let mut fa_guard = FRAME_ALLOCATOR.lock();
        let code_frame = fa_guard.allocate().expect("Failed to allocate user code frame");
        // SAFETY: cr3 is a valid PML4 from create_process_page_table(). page_table_from_cr3
        // converts it to a usable OffsetPageTable via HHDM. map_page maps USER_CODE_VADDR
        // to the freshly allocated frame with user-read-only flags.
        unsafe {
            let mut pt = paging::page_table_from_cr3(cr3);
            paging::map_page(
                &mut pt,
                USER_CODE_VADDR,
                code_frame.addr,
                paging::flags::user_ro(),
                &mut fa_guard,
            ).expect("Failed to map user code page");
        }

        // Copy user entry code to the code page via HHDM
        let hhdm = arcos_core::hhdm_offset();
        let code_src = user_task_entry as *const u8;
        let code_len = user_task_entry_end as *const () as usize - user_task_entry as *const () as usize;
        let code_dst = (code_frame.addr + hhdm) as *mut u8;
        // SAFETY: code_src points to the global_asm user_task_entry symbol (valid kernel memory).
        // code_dst is the HHDM-mapped address of the newly allocated frame (writable).
        // code_len is computed from the user_task_entry/user_task_entry_end symbol difference.
        // Source and destination don't overlap (kernel .text vs allocated frame).
        unsafe {
            core::ptr::copy_nonoverlapping(code_src, code_dst, code_len);
        }
        println!("  ✓ User code mapped at {:#x} ({} bytes)", USER_CODE_VADDR, code_len);
    }

    // --- Step 3: Allocate + map user stack pages ---
    {
        let mut fa_guard = FRAME_ALLOCATOR.lock();
        let stack_base = USER_STACK_TOP - (USER_STACK_PAGES as u64 * PAGE_SIZE);
        for i in 0..USER_STACK_PAGES {
            let frame = fa_guard.allocate().expect("Failed to allocate user stack frame");
            // SAFETY: Same pattern as code page mapping — cr3 is valid, frame is freshly
            // allocated, user_rw flags grant read/write/user-accessible permission.
            unsafe {
                let mut pt = paging::page_table_from_cr3(cr3);
                paging::map_page(
                    &mut pt,
                    stack_base + (i as u64 * PAGE_SIZE),
                    frame.addr,
                    paging::flags::user_rw(),
                    &mut fa_guard,
                ).expect("Failed to map user stack page");
            }
        }
        println!("  ✓ User stack mapped at {:#x}..{:#x}", stack_base, USER_STACK_TOP);
    }

    // --- Step 4: Allocate kernel stack for this task ---
    let layout = Layout::from_size_align(TASK_STACK_SIZE, 16).expect("Invalid stack layout");
    // SAFETY: Layout is valid (TASK_STACK_SIZE=8192, align=16).
    let kstack_base = unsafe { alloc(layout) };
    if kstack_base.is_null() {
        panic!("Failed to allocate kernel stack for user task");
    }
    let kstack_top = kstack_base as u64 + TASK_STACK_SIZE as u64;

    // --- Step 5: Set up SavedContext for return to user mode ---
    let saved_ctx_addr = kstack_top - size_of::<SavedContext>() as u64;
    let saved_ctx = saved_ctx_addr as *mut SavedContext;

    #[cfg(target_arch = "x86_64")]
    {
        use arcos_core::arch::gdt;
        // SAFETY: saved_ctx points within the freshly allocated kernel stack.
        // iretq will pop this to transition to ring 3.
        unsafe {
            core::ptr::write(saved_ctx, SavedContext {
                r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0,
                r9: 0, r8: 0, rbp: 0, rdi: 0, rsi: 0, rdx: 0,
                rcx: 0, rbx: 0, rax: 0,
                rip: USER_CODE_VADDR,
                cs: gdt::USER_CS as u64,
                rflags: 0x202,                   // IF set (interrupts enabled)
                rsp: USER_STACK_TOP,
                ss: gdt::USER_SS as u64,
            });
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: saved_ctx points within the freshly allocated kernel stack.
        // eret with SPSR_EL1=EL0t will return to user mode.
        unsafe {
            let mut ctx = core::mem::zeroed::<SavedContext>();
            // ELR_EL1: return address = user entry point
            ctx.elr_el1 = USER_CODE_VADDR;
            // SPSR_EL1: EL0t (M[3:0]=0b0000=0), DAIF clear (interrupts enabled)
            // EL0t = exception level 0, SP_EL0 stack pointer
            ctx.spsr_el1 = 0x0;
            // SP_EL0: user stack pointer
            ctx.sp_el0 = USER_STACK_TOP;
            core::ptr::write(saved_ctx, ctx);
        }
    }

    // --- Step 6: Register task in scheduler ---
    match scheduler.create_isr_task(
        USER_CODE_VADDR,
        saved_ctx_addr,
        kstack_top,
        Priority::NORMAL,
    ) {
        Ok(task_id) => {
            // Set process_id and CR3 on the task
            if let Some(task) = scheduler.get_task_mut_pub(task_id) {
                task.process_id = Some(process_id);
                task.cr3 = cr3;
            }
            println!("  ✓ User task {} (ring 3) created → process {}",
                task_id.0, process_id.0);
        }
        Err(e) => {
            println!("  ✗ Failed to create user task: {:?}", e);
        }
    }

    // --- Step 7: Register capabilities for this user process ---
    register_process_capabilities(process_id);
}

/// Create a user-mode task via the ELF loader pipeline.
///
/// Wraps the same `user_task_entry` assembly into a minimal ELF binary, then
/// loads it through `load_elf_process()` with the DefaultVerifier. This
/// validates the full loader pipeline: parse → verify → map → schedule.
fn create_elf_user_task(scheduler: &mut Scheduler) {
    use arcos_core::loader::{self, DefaultVerifier};
    use arcos_core::FRAME_ALLOCATOR;

    let process_id = ProcessId(4); // Process 4 = second user process (ELF-loaded)

    // Extract raw bytes from the user_task_entry assembly
    let code_start = user_task_entry as *const u8;
    let code_len = user_task_entry_end as *const () as usize - user_task_entry as *const () as usize;
    // SAFETY: user_task_entry..user_task_entry_end are linker symbols bounding
    // the global_asm block in .text.user. The slice covers valid kernel memory.
    let code_bytes = unsafe { core::slice::from_raw_parts(code_start, code_len) };
    // Construct a minimal ELF binary wrapping the code at USER_CODE_VADDR
    let elf_binary = loader::build_boot_elf(code_bytes, USER_CODE_VADDR);

    // Load through the full verify-before-execute pipeline
    let verifier = DefaultVerifier::new();
    let mut pt_guard = PROCESS_TABLE.lock();
    let mut fa_guard = FRAME_ALLOCATOR.lock();
    let pt = pt_guard.as_mut().expect("ProcessTable not initialized");

    match loader::load_elf_process(
        &elf_binary,
        process_id,
        Priority::NORMAL,
        &verifier,
        pt,
        &mut fa_guard,
        scheduler,
    ) {
        Ok(result) => {
            // Must drop locks before acquiring CAPABILITY_MANAGER (lower in hierarchy)
            drop(fa_guard);
            drop(pt_guard);
            register_process_capabilities(process_id);
            println!("  ✓ ELF-loaded task {} (ring 3) created → process {} [verified]",
                result.task_id.0, result.process_id.0);
        }
        Err(e) => {
            println!("  ✗ ELF loader failed: {}", e);
        }
    }
}

/// Register send+receive capabilities for a user process on all endpoints.
///
/// Called when creating user-mode processes (3, 4, boot modules) so their
/// capabilities are registered after the process table entry exists.
///
/// Grants send/receive on endpoints 0-31 (full range) and binds the
/// bootstrap Principal to the process (boot modules are trusted).
fn register_process_capabilities(process_id: ProcessId) {
    let mut guard = CAPABILITY_MANAGER.lock();
    let cap_mgr = match guard.as_mut() {
        Some(m) => m,
        None => return,
    };
    if let Err(e) = cap_mgr.register_process(process_id) {
        println!("  ✗ Failed to register caps for process {}: {}", process_id.0, e);
        return;
    }
    // Grant send/receive on all endpoints (boot modules are trusted)
    for endpoint_id in 0..arcos_core::ipc::MAX_ENDPOINTS as u32 {
        let _ = cap_mgr.grant_capability(
            process_id,
            EndpointId(endpoint_id),
            CapabilityRights { send: true, receive: true, delegate: false },
        );
    }
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
    use arcos_core::loader::{self, SignedBinaryVerifier};
    use arcos_core::FRAME_ALLOCATOR;

    let module_response = match MODULE_REQUEST.get_response() {
        Some(r) => r,
        None => {
            println!("  No boot modules (ModuleRequest not answered)");
            return;
        }
    };

    let modules = module_response.modules();
    if modules.is_empty() {
        println!("  No boot modules found");
        return;
    }

    println!("Loading {} boot module(s)...", modules.len());

    // Use SignedBinaryVerifier with the bootstrap public key as the trust anchor.
    // All boot modules must be signed by the bootstrap key (via sign-elf tool).
    let bootstrap = BOOTSTRAP_PRINCIPAL.load();
    let verifier = SignedBinaryVerifier::with_key(bootstrap.public_key);
    let mut loaded_count = 0u32;

    for (i, module) in modules.iter().enumerate() {
        let path = module.path().to_bytes();
        let size = module.size();
        let addr = module.addr();

        // Display module info (path is a CStr, convert to str for printing)
        let path_str = core::str::from_utf8(path).unwrap_or("<invalid utf8>");
        println!("  Module {}: {} ({} bytes at {:#x})", i, path_str, size, addr as u64);

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

        // Assign process IDs starting at 5
        let process_id = ProcessId(5 + loaded_count);

        let mut pt_guard = PROCESS_TABLE.lock();
        let mut fa_guard = FRAME_ALLOCATOR.lock();
        let pt = match pt_guard.as_mut() {
            Some(pt) => pt,
            None => {
                println!("    ✗ ProcessTable not initialized");
                continue;
            }
        };

        match loader::load_elf_process(
            binary,
            process_id,
            Priority::NORMAL,
            &verifier,
            pt,
            &mut fa_guard,
            scheduler,
        ) {
            Ok(result) => {
                // Drop locks before acquiring CAPABILITY_MANAGER
                drop(fa_guard);
                drop(pt_guard);
                register_process_capabilities(process_id);
                println!(
                    "    ✓ Loaded as task {} → process {} (entry={:#x}, signed)",
                    result.task_id.0, result.process_id.0, result.entry_point
                );
                loaded_count += 1;
            }
            Err(e) => {
                println!("    ✗ ELF load failed: {}", e);
            }
        }
    }

    if loaded_count > 0 {
        println!("✓ Loaded {} signed module(s) as user processes", loaded_count);
    }
}

/// Initialize IPC subsystem
fn ipc_init() {
    let mut ipc = IpcManager::new_boxed();

    // Install zero-trust IPC interceptor on legacy IPC_MANAGER
    use arcos_core::ipc::interceptor::DefaultInterceptor;
    ipc.set_interceptor(Box::new(DefaultInterceptor::new()));

    *IPC_MANAGER.lock() = Some(ipc);

    // Also install interceptor on the sharded IPC manager
    arcos_core::SHARDED_IPC.set_interceptor(Box::new(DefaultInterceptor::new()));

    println!("✓ IPC manager ready [interceptor active, per-endpoint sharding enabled]");
}

/// Initialize capability manager.
///
/// Only registers processes 0-2 (kernel tasks created in process_table_init).
/// User processes 3-4 are registered later when create_user_task / create_elf_user_task
/// call into the capability manager after their process table entries exist.
fn capability_manager_init() {
    let mut guard = CAPABILITY_MANAGER.lock();
    let cap_mgr = guard.insert(CapabilityManager::new_boxed());

    // Only register processes that already exist in the process table (0-2).
    // Processes 3+ are registered on-demand when user tasks are created.
    for task_id in 0..3u32 {
        let process_id = ProcessId(task_id);
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
                    },
                );
            }
        }
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
    use arcos_core::ipc::Principal;

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
            if let Err(e) = cap_mgr.bind_principal(ProcessId(pid), bootstrap) {
                println!("  ✗ Failed to bind bootstrap Principal to process {}: {}", pid, e);
            }
        }
    }
    drop(cap_guard);

    println!("✓ Bootstrap identity bound (hardware-backed public key)");
    println!("  Principal: {}", bootstrap);
}

/// Initialize the object store (RAM-backed, Phase 0).
///
/// Lock ordering position: 8 (after INTERRUPT_ROUTER at 7).
fn object_store_init() {
    use arcos_core::fs::ram::RamObjectStore;

    let store = RamObjectStore::new_boxed();
    *OBJECT_STORE.lock() = Some(store);

    println!("✓ Object store initialized (RAM, capacity: {} objects)", arcos_core::fs::ram::MAX_OBJECTS);
}

/// Initialize process table
fn process_table_init() {
    let mut pt = ProcessTable::new_boxed(arcos_core::hhdm_offset());
    
    // Create process descriptors for the first 3 processes (matching task count)
    for i in 0..3 {
        let process_id = ProcessId(i as u32);
        if let Err(e) = pt.create_process(process_id, None) {
            println!("  ✗ Failed to create process {}: {}", i, e);
        } else {
            let heap_base = pt.get_heap_base(process_id);
            println!("  ✓ Process {} heap at {:#x}", i, heap_base);
        }
    }
    
    *PROCESS_TABLE.lock() = Some(pt);
    println!("✓ Process table initialized");
}

/// Helper: Send IPC message and wake receiver
///
/// This is the pattern drivers use to send to services.
/// Uses per-endpoint sharded IPC — only locks the target endpoint shard,
/// not the global IPC_MANAGER. Different endpoints on different CPUs
/// never contend on the same lock.
#[allow(dead_code)]
fn ipc_send_and_notify(endpoint: EndpointId, msg: Message) -> bool {
    // Queue the message via sharded IPC (per-endpoint lock only)
    if arcos_core::SHARDED_IPC.send_message(endpoint, msg).is_err() {
        return false;
    }

    // Try to wake the highest-priority receiver across online CPUs.
    // Only scans ONLINE_CPU_COUNT schedulers (not all MAX_CPUS=256).
    {
        let mut best: Option<TaskId> = None;
        let mut best_priority = arcos_core::scheduler::Priority::IDLE;
        let cpu_count = arcos_core::ONLINE_CPU_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize;

        for cpu in 0..cpu_count {
            let guard = PER_CPU_SCHEDULER[cpu].lock();
            if let Some(sched) = guard.as_ref() {
                if let Some(tid) = sched.find_highest_priority_receiver(endpoint.0) {
                    if let Some(task) = sched.get_task_pub(tid) {
                        if best.is_none() || task.priority > best_priority {
                            best = Some(tid);
                            best_priority = task.priority;
                        }
                    }
                }
            }
        }

        if let Some(receiver_id) = best {
            arcos_core::wake_task_on_cpu(receiver_id);
        }
    }
    
    true
}

/// Helper: Try to receive IPC message or block caller
///
/// This is the pattern services use to wait for messages.
/// Returns message if available, blocks caller if queue is empty.
#[allow(dead_code)]
fn ipc_recv_or_block(current_task: TaskId, endpoint: EndpointId) -> Option<Message> {
    // Try to get message via sharded IPC (per-endpoint lock only)
    if let Some(msg) = arcos_core::SHARDED_IPC.recv_message(endpoint) {
        return Some(msg);
    }

    // Queue is empty - block caller on its local CPU's scheduler
    arcos_core::block_local_task(current_task, BlockReason::MessageWait(endpoint.0));

    None
}


/// Receive IPC message with capability enforcement
///
/// Safe version using spinlock guards (no unsafe raw pointers).
/// Lock ordering: CAPABILITY_MANAGER → IPC_MANAGER   (nested)
///
/// Flow:
/// 1. Receive (process) requests message from endpoint
/// 2. Capability manager verifies receiver has RECEIVE right
/// 3. If denied, returns PermissionDenied error
/// 4. If allowed, returns message or None if queue empty
#[allow(dead_code)]
fn ipc_recv_with_capability(
    receiver_process: ProcessId,
    endpoint: EndpointId,
) -> Result<Option<Message>, &'static str> {
    // Lock order: IPC_MANAGER (must come after CAPABILITY_MANAGER in global order)
    // Global order is CAPABILITY_MANAGER → IPC_MANAGER , so check capability FIRST
    let cap_guard = CAPABILITY_MANAGER.lock();
    let cap_mgr = cap_guard.as_ref().unwrap();
    if cap_mgr.verify_access(receiver_process, endpoint, CapabilityRights::RECV_ONLY).is_err() {
        return Err("Access denied - insufficient capabilities");
    }
    drop(cap_guard); // Explicitly release capability lock
    
    // Now acquire IPC manager to receive message
    let mut ipc_guard = IPC_MANAGER.lock();
    let ipc_mgr = ipc_guard.as_mut().unwrap();
    Ok(ipc_mgr.recv_message(endpoint))
}

// ============================================================================
// Synchronous IPC helpers
// ============================================================================

/// Synchronous send: deposit message on endpoint, block sender until receiver picks up
///
/// Lock ordering: IPC_MANAGER released before SCHEDULER acquired.
///
/// Returns true if send completed (receiver was already waiting),
/// false if sender was blocked (will be woken when receiver calls sync_recv).
#[allow(dead_code)]
fn sync_ipc_send(sender_task: TaskId, endpoint: EndpointId, msg: Message) -> bool {
    use arcos_core::ipc::SyncSendResult;

    // Deposit via sharded IPC (per-endpoint lock only)
    let result = arcos_core::SHARDED_IPC.sync_send(endpoint, msg, sender_task.0);

    match result {
        Ok(SyncSendResult::ReceiverWoken(receiver_task_id)) => {
            arcos_core::wake_task_on_cpu(TaskId(receiver_task_id));
            true
        }
        Ok(SyncSendResult::SenderMustBlock) => {
            arcos_core::block_local_task(sender_task, BlockReason::SyncSendWait(endpoint.0));
            false
        }
        Err(_) => false,
    }
}

/// Synchronous receive: pick up message or block until one arrives
///
/// Uses per-endpoint sharded IPC — endpoint lock released before scheduler.
#[allow(dead_code)]
fn sync_ipc_recv(receiver_task: TaskId, endpoint: EndpointId) -> Option<Message> {
    use arcos_core::ipc::SyncRecvResult;

    let result = arcos_core::SHARDED_IPC.sync_recv(endpoint, receiver_task.0);

    match result {
        Ok(SyncRecvResult::Message(msg, wake_sender)) => {
            if let Some(sender_task_id) = wake_sender {
                arcos_core::wake_task_on_cpu(TaskId(sender_task_id));
            }
            Some(msg)
        }
        Ok(SyncRecvResult::ReceiverMustBlock) => {
            arcos_core::block_local_task(receiver_task, BlockReason::SyncRecvWait(endpoint.0));
            None
        }
        Err(_) => None,
    }
}

/// Synchronous call: send message + block until reply (RPC pattern)
///
/// Uses per-endpoint sharded IPC — endpoint lock released before scheduler.
#[allow(dead_code)]
fn sync_ipc_call(caller_task: TaskId, endpoint: EndpointId, msg: Message) {
    use arcos_core::ipc::SyncCallResult;

    let result = arcos_core::SHARDED_IPC.sync_call(endpoint, msg, caller_task.0);

    match result {
        Ok(SyncCallResult::ReceiverWoken(receiver_task_id)) => {
            arcos_core::wake_task_on_cpu(TaskId(receiver_task_id));
            arcos_core::block_local_task(caller_task, BlockReason::SyncReplyWait(endpoint.0));
        }
        Ok(SyncCallResult::CallerMustBlock) => {
            arcos_core::block_local_task(caller_task, BlockReason::SyncReplyWait(endpoint.0));
        }
        Err(_) => {}
    }
}

/// Synchronous reply: complete an RPC cycle by sending reply to blocked caller
///
/// Uses per-endpoint sharded IPC — endpoint lock released before scheduler.
#[allow(dead_code)]
fn sync_ipc_reply(endpoint: EndpointId, reply: Message) -> bool {
    let caller_task = arcos_core::SHARDED_IPC.sync_reply(endpoint, reply);

    match caller_task {
        Ok(caller_task_id) => {
            arcos_core::wake_task_on_cpu(TaskId(caller_task_id));
            true
        }
        Err(_) => false,
    }
}

/// Dispatch an interrupt to its registered driver
///
/// This is the critical path that bridges hardware events to driver tasks:
/// 
/// 1. Hardware generates interrupt (e.g., timer tick, keyboard press)
/// 2. CPU delivers to IDT handler 
/// 3. Handler calls this function with IRQ number
/// 4. Look up which driver (task) is registered to handle this IRQ
/// 5. Create InterruptContext with event details
/// 6. Queue IPC message to driver's endpoint
/// 7. Wake driver task (remove from Blocked state)
/// 8. Scheduler will run driver on next schedule() call
///
/// Lock ordering: sequential (non-nested), so global order does not apply.
/// INTERRUPT_ROUTER released before IPC_MANAGER acquired.
/// IPC_MANAGER released before SCHEDULER acquired.
///
/// Result: Drivers don't poll or spin; they sleep until their interrupt fires.
#[allow(dead_code)]
pub fn dispatch_interrupt(irq: IrqNumber, timestamp_ticks: u64) {
    // Step 1: Look up handler task (acquire and release INTERRUPT_ROUTER early)
    let route_info = {
        let router = INTERRUPT_ROUTER.lock();
        router.lookup(irq)
    }; // router lock released here
    
    let route = match route_info {
        Some(r) => r,
        None => return, // No handler registered for this IRQ
    };
    
    // Step 2: Create interrupt context message
    let context = InterruptContext::new(irq, timestamp_ticks, 0);
    let message_data = [
        (context.irq.0 as u32) as u8,
        (timestamp_ticks & 0xFF) as u8,
        ((timestamp_ticks >> 8) & 0xFF) as u8,
        ((timestamp_ticks >> 16) & 0xFF) as u8,
    ];

    // Step 3: Create IPC message to driver
    let mut msg = Message::new(
        EndpointId(0),                      // From kernel (endpoint 0)
        EndpointId(route.irq.0 as u32),    // To driver's IRQ endpoint
    );
    let _ = msg.set_payload(&message_data);

    // Step 4: Queue message via sharded IPC (per-endpoint lock only)
    if arcos_core::SHARDED_IPC.send_message(EndpointId(route.irq.0 as u32), msg).is_err() {
        return; // Failed to queue
    }
    
    // Step 5: Wake the driver task on its owning CPU
    arcos_core::wake_task_on_cpu(route.handler_task);
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
    arcos_core::arch::gdt::init_for_cpu(cpu_index);

    // Step 2: Initialize per-CPU data (writes GS base MSR)
    // SAFETY: GDT loaded (GS base will be overwritten by percpu init). One-time per AP.
    arcos_core::arch::x86_64::percpu::init_ap(cpu_index, apic_id);

    // Step 3: Load the shared IDT (configured by BSP)
    // SAFETY: BSP has fully configured and loaded the IDT.
    arcos_core::interrupts::load_idt_ap();

    // Step 4: Initialize SYSCALL/SYSRET MSRs (per-CPU)
    // SAFETY: GDT loaded, per-CPU init done.
    arcos_core::arch::syscall::init();

    // Step 5: Enable this AP's Local APIC
    // SAFETY: BSP already mapped the APIC MMIO page (shared page tables).
    arcos_core::arch::x86_64::apic::init_ap();

    // Step 6: Configure APIC timer using BSP's calibration values
    // SAFETY: BSP has completed configure_timer() and stored the initial count.
    arcos_core::arch::x86_64::apic::configure_timer_ap();

    // Step 7: Initialize per-CPU scheduler and timer
    // Each AP needs its own Scheduler (with idle task) so migrated tasks
    // can be dispatched, and its own Timer for tick accounting.
    {
        use arcos_core::scheduler::{Scheduler, Timer, TimerConfig};

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
    arcos_core::ONLINE_CPU_COUNT.fetch_add(1, core::sync::atomic::Ordering::Release);

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

    // Step 1: Per-CPU EL1 config (no-op on AArch64)
    arcos_core::arch::gdt::init_for_cpu(cpu_index);

    // Step 2: Initialize per-CPU data (writes TPIDR_EL1)
    // SAFETY: Called once per AP during init.
    arcos_core::arch::aarch64::percpu::init_ap(cpu_index, mpidr_aff);

    // Step 3: Install exception vector table (per-CPU VBAR_EL1)
    // SAFETY: Exception vector table is shared and already initialized by BSP.
    arcos_core::arch::syscall::init();

    // Step 4: Initialize GIC CPU interface for this AP
    // SAFETY: GIC distributor already initialized by BSP.
    arcos_core::arch::aarch64::gic::init();

    // Step 5: Initialize GIC Redistributor for this AP
    // SAFETY: GICR physical base at QEMU virt address, translated through HHDM.
    const GICR_PHYS: u64 = 0x080A_0000;
    let hhdm = arcos_core::hhdm_offset();
    arcos_core::arch::aarch64::gic::init_redistributor(GICR_PHYS + hhdm, cpu_index as u32);

    // Step 6: Start ARM Generic Timer (reuses BSP's frequency/reload values)
    // SAFETY: BSP has completed timer::init(), COUNTER_FREQ and TIMER_RELOAD are set.
    arcos_core::arch::aarch64::timer::init_ap();

    // Step 7: Initialize per-CPU scheduler and timer
    {
        use arcos_core::scheduler::{Scheduler, Timer, TimerConfig};

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
    arcos_core::ONLINE_CPU_COUNT.fetch_add(1, core::sync::atomic::Ordering::Release);

    // Step 9: Enable interrupts and enter idle loop
    // SAFETY: All AP-local hardware is initialized.
    core::arch::asm!("msr daifclr, #2", options(nostack, nomem)); // Unmask IRQ

    loop {
        arcos_core::wfi();
    }
}

/// Distribute tasks from CPU 0 to APs for balanced scheduling.
///
/// Called after all APs are online with their own schedulers.
/// Migrates a subset of tasks from the BSP's run queue to available APs
/// in round-robin fashion. Only Ready/Blocked tasks are migrated.
fn distribute_tasks_to_aps() {
    use arcos_core::scheduler::{TaskId, migrate_task};

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
            for slot in 1..arcos_core::MAX_TASKS as u32 {
                let tid = TaskId(slot);
                if let Some(task) = sched.get_task_pub(tid) {
                    if task.state == arcos_core::scheduler::TaskState::Ready {
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

    for i in 0..count {
        if migrated >= to_migrate {
            break;
        }
        if let Some(tid) = migratable[i] {
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
    // SAFETY: All hardware initialized (GIC, timer, VBAR_EL1).
    unsafe { core::arch::asm!("msr daifclr, #2", options(nostack, nomem)); }

    // Tick-based gating: deterministic frequency regardless of interrupt rate.
    // Status every 10s (1000 ticks @ 100Hz), invariants every 60s (6000 ticks).
    let mut last_status_tick: u64 = 0;
    let mut last_verify_tick: u64 = 0;

    loop {
        let ticks = Timer::get_ticks();

        // Periodic status reporting (every ~10 seconds)
        if ticks >= last_status_tick + 1000 {
            last_status_tick = ticks;
            // Use try_lock to avoid blocking the idle loop under contention
            if let Some(scheduler) = arcos_core::local_scheduler().try_lock() {
                if let Some(sched) = scheduler.as_ref() {
                    let stats = sched.stats();
                    println!(
                        "  [Tick {}] Tasks: {}, Current: {:?}, State: {:?}",
                        ticks,
                        stats.active_tasks,
                        stats.current_task,
                        stats.state
                    );
                }
            }
        }

        // Periodic invariant verification (every ~60 seconds)
        if ticks >= last_verify_tick + 6000 {
            last_verify_tick = ticks;
            if let Some(scheduler) = arcos_core::local_scheduler().try_lock() {
                if let Some(sched) = scheduler.as_ref() {
                    if let Err(e) = sched.verify_invariants() {
                        println!("✗ Scheduler invariant violated: {}", e);
                        arcos_core::halt();
                    }
                }
            }
        }

        // Load balancing: migrate tasks from overloaded to underloaded CPUs
        // (internally throttled to once per BALANCE_INTERVAL_TICKS)
        arcos_core::try_load_balance();

        // Halt/wait CPU until next interrupt (timer, keyboard, etc.)
        #[cfg(target_arch = "x86_64")]
        hlt();
        #[cfg(target_arch = "aarch64")]
        arcos_core::wfi();
    }
}


/// Panic handler for microkernel
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("\nMICROKERNEL PANIC: {:?}", info);
    arcos_core::halt();
}
