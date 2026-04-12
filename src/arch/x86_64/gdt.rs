// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! Global Descriptor Table (GDT) and Task State Segment (TSS)
//!
//! Replaces the Limine-provided GDT with our own that includes:
//! - Kernel code/data segments (Ring 0)
//! - User code/data segments (Ring 3)
//! - 64-bit TSS (for ring 3 → ring 0 stack switching)
//!
//! ## Segment layout
//!
//! | Index | Selector | Description              |
//! |-------|----------|--------------------------|
//! |   0   |   0x00   | Null descriptor          |
//! |   1   |   0x08   | Kernel code 64-bit DPL=0 |
//! |   2   |   0x10   | Kernel data 64-bit DPL=0 |
//! |   3   |   0x18   | User data 64-bit DPL=3   |
//! |   4   |   0x20   | User code 64-bit DPL=3   |
//! |  5-6  |   0x28   | TSS (16-byte descriptor)  |
//!
//! User data comes before user code because SYSRET computes:
//!   SS = STAR[63:48] + 8 | 3      (0x10 + 8 = 0x18 | 3 = 0x1B)
//!   CS = STAR[63:48] + 16 | 3     (0x10 + 16 = 0x20 | 3 = 0x23)

/// Kernel code segment selector
pub const KERNEL_CS: u16 = 0x08;
/// Kernel data segment selector
pub const KERNEL_SS: u16 = 0x10;
/// User data segment selector (RPL=3)
pub const USER_SS: u16 = 0x1B; // 0x18 | 3
/// User code segment selector (RPL=3)
pub const USER_CS: u16 = 0x23; // 0x20 | 3

/// TSS selector (GDT index 5, occupies slots 5-6)
pub const TSS_SELECTOR: u16 = 0x28;

/// HARDWARE: 7 GDT entries (null + kernel CS + kernel SS + user SS + user CS +
/// TSS low + TSS high). SYSRET requires user data before user code; this exact
/// layout is fixed by the SYSCALL/SYSRET MSR ABI.
const GDT_ENTRIES: usize = 7;

use super::percpu::MAX_CPUS;

/// Base GDT template — entries 0-4 are identical across all CPUs.
/// Entries 5-6 (TSS descriptor) are filled per-CPU at runtime.
const BASE_GDT: [u64; GDT_ENTRIES] = [
    0x0000_0000_0000_0000, // 0x00: Null
    0x00AF_9A00_0000_FFFF, // 0x08: Kernel code — P=1, DPL=0, S=1, type=Execute/Read, L=1, D=0
    0x00CF_9200_0000_FFFF, // 0x10: Kernel data — P=1, DPL=0, S=1, type=Read/Write
    0x00CF_F200_0000_FFFF, // 0x18: User data   — P=1, DPL=3, S=1, type=Read/Write
    0x00AF_FA00_0000_FFFF, // 0x20: User code   — P=1, DPL=3, S=1, type=Execute/Read, L=1, D=0
    0x0000_0000_0000_0000, // 0x28: TSS low  (filled at runtime)
    0x0000_0000_0000_0000, // 0x30: TSS high (filled at runtime)
];

/// Per-CPU GDT arrays.
///
/// Each CPU needs its own GDT because the TSS descriptor (entries 5-6)
/// points to that CPU's TSS. Must be `static mut` (writable) because:
/// - The CPU sets the Accessed bit in segment descriptors on load
/// - The TSS descriptor's type field changes from Available to Busy on `ltr`
/// - The TSS descriptor is written at runtime (base address not known at compile time)
static mut CPU_GDT: [[u64; GDT_ENTRIES]; MAX_CPUS] = [BASE_GDT; MAX_CPUS];

// ============================================================================
// Task State Segment (TSS)
// ============================================================================

/// 64-bit Task State Segment.
///
/// In long mode the TSS is used for:
/// - RSP0: kernel stack pointer loaded on ring 3 → ring 0 transitions
/// - RSP1/RSP2: stack pointers for other privilege levels (unused)
/// - IST1-IST7: per-interrupt stack pointers for critical handlers
/// - I/O permission bitmap base (unused, set past TSS limit)
#[repr(C, packed)]
pub struct Tss {
    _reserved0: u32,
    /// Stack pointer for ring 0 (loaded on privilege escalation)
    pub rsp0: u64,
    /// Stack pointer for ring 1 (unused)
    pub rsp1: u64,
    /// Stack pointer for ring 2 (unused)
    pub rsp2: u64,
    _reserved1: u64,
    /// Interrupt Stack Table entries (IST1-IST7)
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// I/O map base address (offset from TSS base; set past limit to disable)
    pub iomap_base: u16,
}

impl Default for Tss {
    fn default() -> Self { Self::new() }
}

impl Tss {
    /// Create a zeroed TSS.
    pub const fn new() -> Self {
        Tss {
            _reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            iomap_base: 104, // = size of TSS struct → no I/O bitmap
        }
    }
}

/// Per-CPU TSS instances.
///
/// Each CPU needs its own TSS because:
/// - RSP0 is per-CPU (each core runs a different task)
/// - `ltr` marks the TSS as Busy — sharing would cause #GP on the second core
/// - IST entries may differ per CPU
static mut CPU_TSS: [Tss; MAX_CPUS] = [const { Tss::new() }; MAX_CPUS];

/// GDT pseudo-descriptor for `lgdt`
#[repr(C, packed)]
struct GdtDescriptor {
    limit: u16,
    base: u64,
}

/// Load the BSP's GDT (CPU index 0), reload segment registers, and load TR.
///
/// # Safety
/// Must be called during single-threaded init with interrupts disabled.
/// After this, all code using the old Limine selectors (0x28/0x30) will
/// use the new selectors (0x08/0x10).
pub unsafe fn init() {
    // SAFETY: Caller ensures single-threaded init with interrupts disabled.
    unsafe { init_for_cpu(0) };
}

/// Load a per-CPU GDT, reload segment registers, install the TSS, and load TR.
///
/// For the BSP, call with `cpu_index = 0` during boot.
/// For APs, call with their logical CPU index during AP startup.
///
/// **Note:** Segment reload sets GS to KERNEL_SS (base=0), which clears any
/// previously set GS base. `percpu::init_bsp()` / `percpu::init_ap()` must
/// be called AFTER this function to set the correct GS base via IA32_GS_BASE MSR.
///
/// # Safety
/// Must be called with interrupts disabled, once per CPU.
/// For BSP: single-threaded init. For APs: called on the AP itself.
pub unsafe fn init_for_cpu(cpu_index: usize) {
    assert!(cpu_index < MAX_CPUS, "cpu_index out of range");

    // ---- Write TSS descriptor into this CPU's GDT slots 5-6 ----
    //
    // A 64-bit TSS descriptor is 16 bytes (2 GDT entries):
    //
    //   Low qword (GDT[5]):
    //     bits 15:0   = limit 15:0
    //     bits 31:16  = base 15:0
    //     bits 39:32  = base 23:16
    //     bits 43:40  = type (0x9 = 64-bit TSS Available)
    //     bit  44     = 0 (system segment)
    //     bits 46:45  = DPL (0)
    //     bit  47     = P (present)
    //     bits 51:48  = limit 19:16
    //     bit  55:52  = flags (G=0)
    //     bits 63:56  = base 31:24
    //
    //   High qword (GDT[6]):
    //     bits 31:0   = base 63:32
    //     bits 63:32  = reserved (must be 0)

    // SAFETY: CPU_TSS is a static array with stable addresses. We index within
    // bounds (asserted above). Taking a raw pointer to read the address is safe.
    let tss_ptr = unsafe { &raw const CPU_TSS[cpu_index] };
    let tss_addr = tss_ptr as u64;
    let tss_limit = (core::mem::size_of::<Tss>() - 1) as u64;

    let low: u64 = (tss_limit & 0xFFFF)                  // limit 15:0
        | ((tss_addr & 0xFFFF) << 16)                     // base 15:0
        | (((tss_addr >> 16) & 0xFF) << 32)               // base 23:16
        | (0x89u64 << 40)                                  // P=1, DPL=0, type=0x9 (Available 64-bit TSS)
        | (((tss_limit >> 16) & 0xF) << 48)               // limit 19:16
        | (((tss_addr >> 24) & 0xFF) << 56);               // base 31:24

    let high: u64 = (tss_addr >> 32) & 0xFFFF_FFFF;       // base 63:32

    // SAFETY: Interrupts disabled, called once per CPU. Accessing this CPU's GDT.
    let gdt_ptr = unsafe { &raw mut CPU_GDT[cpu_index] };
    // SAFETY: Writing TSS descriptor low DWORD into GDT slot 5 (within bounds).
    unsafe { (*gdt_ptr)[5] = low };
    // SAFETY: Writing TSS descriptor high DWORD into GDT slot 6 (within bounds).
    unsafe { (*gdt_ptr)[6] = high };

    // ---- Load this CPU's GDT ----
    // SAFETY: descriptor.base points to this CPU's static GDT array, limit is
    // computed from its actual size. GDT entries are correctly formed above.
    let gdt_ref = unsafe { &CPU_GDT[cpu_index] };
    let descriptor = GdtDescriptor {
        limit: (core::mem::size_of_val(gdt_ref) - 1) as u16,
        base: gdt_ref.as_ptr() as u64,
    };

    // SAFETY: descriptor is a valid GDT pseudo-descriptor pointing to our static GDT.
    // Interrupts are disabled so no handler can reference stale selectors.
    unsafe {
        core::arch::asm!(
            "lgdt [{0}]",
            in(reg) &descriptor,
            options(nostack, preserves_flags),
        );
    }

    // SAFETY: CS and data segment registers must be reloaded to activate the new GDT.
    // gdt_reload_segments uses a far-return to switch CS=0x08 and sets DS/ES/FS/GS/SS=0x10.
    unsafe { gdt_reload_segments() };

    // ---- Load Task Register with TSS selector ----
    // SAFETY: TSS descriptor is in GDT slots 5-6 at selector 0x28. The descriptor
    // is type=0x9 (Available 64-bit TSS). ltr marks it Busy. Called once per CPU.
    unsafe {
        core::arch::asm!(
            "ltr {0:x}",
            in(reg) TSS_SELECTOR,
            options(nostack, nomem),
        );
    }
}

/// Update the kernel stack pointer (RSP0) in the current CPU's TSS and PerCpu.
///
/// Called during context switches to ensure that interrupts from ring 3 land
/// on the current task's kernel stack (via TSS.RSP0) and that SYSCALL entry
/// can switch to the kernel stack (via PerCpu.kernel_rsp0).
///
/// # Safety
/// Must be called with interrupts disabled (e.g., from within an ISR or
/// with IF cleared). Per-CPU data must be initialized (`percpu::init_bsp`
/// or `percpu::init_ap` must have been called on this CPU).
pub unsafe fn set_kernel_stack(rsp0: u64) {
    // SAFETY: Called with interrupts disabled. Per-CPU data is initialized.
    // current_percpu() returns this CPU's PerCpu (via GS base).
    let cpu_idx = unsafe { super::percpu::current_percpu() }.cpu_id() as usize;
    // SAFETY: cpu_idx is in 0..MAX_CPUS (set during percpu init). Accessing our CPU's TSS.
    let tss_ptr = unsafe { &raw mut CPU_TSS[cpu_idx] };
    // SAFETY: Writing rsp0 field of our CPU's TSS entry.
    unsafe { (*tss_ptr).rsp0 = rsp0 };
    // Also update PerCpu.kernel_rsp0 — read by syscall_entry (gs:[24]) to
    // switch RSP from user stack to kernel stack on SYSCALL.
    // SAFETY: Called with interrupts disabled; only this CPU's PerCpu is written.
    unsafe {
        super::percpu::current_percpu_mut().set_kernel_rsp0(rsp0);
    }
}

/// Set an Interrupt Stack Table entry in the current CPU's TSS.
///
/// IST entries provide dedicated stacks for critical interrupt handlers
/// (e.g., double-fault) that must not depend on the current task's kernel stack.
///
/// `index` is 0-based (IST1 = index 0, IST7 = index 6).
/// `stack_top` is the top (highest address) of the allocated stack.
///
/// # Safety
/// Must be called with interrupts disabled. Per-CPU data must be initialized.
/// The stack must remain valid for the lifetime of the kernel.
pub unsafe fn set_ist(index: usize, stack_top: u64) {
    assert!(index < 7, "IST index must be 0..6");
    // SAFETY: Called with interrupts disabled. Per-CPU data is initialized.
    let cpu_idx = unsafe { super::percpu::current_percpu() }.cpu_id() as usize;
    // SAFETY: cpu_idx is in 0..MAX_CPUS. Accessing our CPU's TSS.
    let tss_ptr = unsafe { &raw mut CPU_TSS[cpu_idx] };
    // SAFETY: Writing the IST entry (index is checked above to be < 7).
    unsafe { (*tss_ptr).ist[index] = stack_top };
}

extern "C" {
    fn gdt_reload_segments();
}

// Pure assembly: reload CS via far return, then reload DS/ES/FS/GS/SS.
//
// Called via `call` from Rust, returns via `ret`. The far return in the
// middle switches CS to KERNEL_CS without disturbing the outer call/ret.
#[cfg(not(fuzzing))]
core::arch::global_asm!(
    ".global gdt_reload_segments",
    "gdt_reload_segments:",
    // Far return to reload CS: push selector, push label address, retfq
    "push 0x08",                        // KERNEL_CS
    "lea rax, [rip + .Lgdt_cs_done]",   // address of next instruction
    "push rax",
    "retfq",                            // pops RIP + CS → CS=0x08, RIP=.Lgdt_cs_done
    ".Lgdt_cs_done:",
    // Reload data segment registers with KERNEL_SS
    "mov ax, 0x10",
    "mov ds, ax",
    "mov es, ax",
    "mov fs, ax",
    "mov gs, ax",
    "mov ss, ax",
    "ret",                              // return to Rust caller
);
