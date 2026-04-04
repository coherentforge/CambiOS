# ArcOS Microkernel — Claude Code Context

## Project Vision

ArcOS is a next-gen AI-integrated operating system built on these principles:

- **Security First:** Zero-trust architecture with real-time AI monitoring. No backdoors, no telemetry/telematics. Every process is verified at runtime.
- **Microkernel Isolation:** Device drivers, networking, and file systems run in isolated user-space environments — minimal kernel attack surface.
- **AI-Powered Security:** Just-in-time code analysis pre-execution, behavioral anomaly detection, automatic quarantining of threats.
- **Cryptographic Identity:** Identity-based access replaces passwords. Decentralized identity and networking — no reliance on legacy IP/DNS.
- **AI Compatibility Layer:** AI-driven adaptation for running legacy Windows apps and cross-platform hardware support.
- **Live-Patchable:** AI-assisted kernel updates without reboots.
- **Platform Agnostic** Design with x86_64 and ARM compatibility.

Never suggest adding telemetry, analytics, or any form of phone-home behavior.

## Development Environment

- **Host:** macOS (Apple Silicon)
- **Kernel target:** `x86_64-unknown-none` (ELF, bare metal)
- **Unit tests:** `cargo test --lib` (runs natively on macOS)
- **Integration testing:** QEMU (installed via Homebrew)

## Critical Rules

- **NEVER** suggest `cargo run` or `cargo build` without `--target x86_64-unknown-none` for kernel crates.
- **NEVER** suggest running kernel binaries directly on the host. Always use QEMU.

## Quick Reference

```bash
# Build kernel (release)
cargo build --target x86_64-unknown-none --release

# Build kernel (debug)
cargo build --target x86_64-unknown-none

# Run tests (114 tests, all passing)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Build ISO + run in QEMU
make iso && make run

# Just run (rebuilds automatically)
make run
```

**Important:** The microkernel binary (`src/microkernel/main.rs`) cannot compile for test on macOS because it uses ELF-specific linker sections. Always use `--lib` when running tests. The `RUST_MIN_STACK` env var is required because some tests (buddy allocator) need >2MB stack.

## Project Overview

ArcOS is a verification-ready microkernel OS for x86-64 written in Rust (`no_std`). It boots via the Limine v8.x protocol, runs a custom 7-entry GDT with per-CPU TSS, supports SYSCALL/SYSRET fast path, and has preemptive multitasking with ring 3 user tasks.

**Current state:** 134/134 tests pass (133 new + 1 pre-existing flaky TLB ordering), clean release build, QEMU boots to stable preemptive multitasking with 2 CPUs (`-smp 2`). APIC timer drives scheduling at 100Hz, two user tasks round-robin with syscalls (GetPid, GetTime). Per-process VMA tracking enables proper SYS_ALLOCATE/SYS_FREE with frame reclamation. WaitIrq wake path wired for all routed IRQs. All 5 processes (0-4) create successfully at boot, including two ring-3 user tasks with per-process page tables and ELF loading. SMP Phase 0 complete: IrqSpinlock, per-CPU data (GS base), per-CPU GDT/TSS. SMP Phase 1 complete: ACPI MADT parser, I/O APIC driver, device IRQ routing (keyboard, serial, IDE) with interrupt source overrides. SMP Phase 2 complete: AP startup via Limine MP protocol (each AP loads GDT/TSS, percpu, IDT, SYSCALL MSRs, APIC timer; BSP waits with timeout). SMP Phase 3 complete: IPI send primitives (ICR access, fixed/broadcast/self), TLB shootdown via vector 0xFE (per-page invlpg or full CR3 reload, serialized lock, ISR + EOI). SMP Phase 4a complete: per-CPU scheduler/timer arrays (`PER_CPU_SCHEDULER[256]`, `PER_CPU_TIMER[256]`), `local_scheduler()`/`local_timer()` helpers via GS base, all access sites migrated. SMP Phase 4b complete: task migration primitives (`remove_task`, `accept_task`, `migrate_task_between`, `migrate_task`), AP per-CPU scheduler/timer init, boot-time distribution of kernel tasks to APs, tasks running across multiple CPUs in QEMU. Cross-CPU wake correctness: `TASK_CPU_MAP` (lock-free `AtomicU16` array) tracks task→CPU assignment, `wake_task_on_cpu()` and `block_local_task()` replace all hardcoded `PER_CPU_SCHEDULER[0]` in IPC, ISR dispatch, and diagnostics — tasks wake/block on correct CPU regardless of migration. SMP Phase 4c complete: load balancer (`try_load_balance()` in `lib.rs`) samples per-CPU runnable counts every 100 ticks (1s), migrates one task when imbalance ≥ 2; `ONLINE_CPU_COUNT` atomic tracks live CPUs; `active_runnable_count()`/`pick_migratable_task()` on Scheduler. ACPI region mapping: explicit page table mapping for RESERVED/ACPI regions required by Limine base revision 3 (HHDM only covers Usable/Bootloader/Executable/Framebuffer memory).

## Toolchain

- Rust nightly (see `rust-toolchain.toml`)
- Target: `x86_64-unknown-none` (set in `.cargo/config.toml`)
- Linker script: `linker.ld`
- Bootloader: Limine v8.x (binary branch cloned to `/tmp/limine`)
- Dependencies: `x86_64` 0.14, `uart_16550` 0.3, `bitflags` 2.3, `limine` 0.5

## Architecture

```
src/
├── lib.rs                    # Crate root, global statics, init, halt
├── process.rs                # ProcessTable, ProcessDescriptor, VmaTracker
├── acpi/
│   └── mod.rs                # ACPI table parser (RSDP, XSDT, MADT)
├── arch/
│   ├── mod.rs                # cfg-gated architecture shim (re-exports x86_64)
│   ├── spinlock.rs           # Spinlock + IrqSpinlock (interrupt-disabling)
│   └── x86_64/
│       ├── mod.rs            # Context switching, SavedContext, timer_isr_inner
│       ├── apic.rs           # Local APIC driver (timer, EOI, PIC disable)
│       ├── gdt.rs            # Per-CPU GDT + TSS + IST (SMP-ready)
│       ├── ioapic.rs         # I/O APIC driver (device IRQ routing)
│       ├── percpu.rs         # Per-CPU data (GS base), PerCpu struct
│       ├── syscall.rs        # SYSCALL/SYSRET MSR init + entry point
│       └── tlb.rs            # TLB shootdown via IPI (vector 0xFE)
├── interrupts/
│   ├── mod.rs                # IDT setup, exception/device ISR handlers
│   ├── pic.rs                # 8259 PIC driver (disabled at boot)
│   ├── pit.rs                # 8254 PIT (calibration only)
│   └── routing.rs            # IRQ → driver task routing table
├── io/
│   └── mod.rs                # Serial output (uart_16550), print!/println! macros
├── ipc/
│   ├── mod.rs                # IPC: EndpointQueue, SyncChannel, IpcManager
│   ├── capability.rs         # Capability-based security
│   └── interceptor.rs        # Zero-trust IPC interceptor (policy enforcement)
├── loader/
│   ├── mod.rs                # ELF process loader + verify-before-execute gate
│   └── elf.rs                # ELF64 header/program header parser
├── memory/
│   ├── mod.rs                # Memory subsystem init, get_page_table()
│   ├── heap.rs               # Kernel heap allocator (linked-list, GlobalAlloc)
│   ├── frame_allocator.rs    # Bitmap-based physical frame allocator
│   ├── buddy_allocator.rs    # Pure bookkeeping buddy allocator
│   └── paging.rs             # Page table management (OffsetPageTable)
├── microkernel/
│   └── main.rs               # Kernel entry point, all subsystem init
├── platform/
│   └── mod.rs                # Platform abstraction, CR4 features
├── scheduler/
│   ├── mod.rs                # Round-robin scheduler, on_timer_isr()
│   ├── task.rs               # Task/TaskState/CpuContext definitions
│   └── timer.rs              # Timer tick management
└── syscalls/
    ├── mod.rs                # SyscallNumber enum, SyscallArgs
    ├── dispatcher.rs         # Syscall dispatch + handlers (all 11 implemented)
    └── userspace.rs          # Stub userspace syscall wrappers
```

## Key Technical Details

### GDT Layout (7 entries per CPU, replaces Limine's at boot)
| Index | Offset | Description | Selector |
|-------|--------|-------------|----------|
| 0 | 0x00 | Null | — |
| 1 | 0x08 | Kernel Code 64-bit DPL=0 | KERNEL_CS=0x08 |
| 2 | 0x10 | Kernel Data 64-bit DPL=0 | KERNEL_SS=0x10 |
| 3 | 0x18 | User Data 64-bit DPL=3 | USER_SS=0x1B |
| 4 | 0x20 | User Code 64-bit DPL=3 | USER_CS=0x23 |
| 5 | 0x28 | TSS low | TSS_SELECTOR=0x28 |
| 6 | 0x30 | TSS high | — |

User data before user code is **required** by SYSRET selector computation.

### SYSCALL/SYSRET
- STAR MSR: bits[47:32]=0x08 (kernel CS), bits[63:48]=0x10 (user base)
- SFMASK=0x200 (clears IF on syscall entry)
- Entry point in `src/arch/x86_64/syscall.rs`

### Memory Layout
- **Kernel heap:** 4MB at HHDM+physical, initialized from Limine memory map
- **Boot stack:** 256KB via Limine StackSizeRequest
- **User code:** mapped at 0x400000
- **User stack:** top at 0x800000, 16KB (4 pages), grows down
- **Per-process PML4:** kernel half cloned (entries 256..511)
- **HHDM:** Higher Half Direct Map provided by Limine for physical memory access

### Lock Ordering (MUST be followed to prevent deadlock)
```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7)
```
`*` = IrqSpinlock (saves/disables interrupts before acquiring, prevents same-CPU deadlock when timer ISR fires while lock is held). Others use plain Spinlock.

Lower-numbered locks must be acquired before higher-numbered ones. See `src/lib.rs` comment.

### Timer / Preemptive Scheduling
- **APIC timer** at 100Hz (periodic mode, PIT-calibrated), fires on vector 32
- **I/O APIC** routes device IRQs (keyboard, serial, IDE) on vectors 33-56
- Device ISRs: `x86-interrupt` ABI handlers, wake blocked tasks via `try_lock()` + EOI
- 8259 PIC disabled (remapped to 0xF0-0xFF, all lines masked)
- PIT used only for one-shot APIC timer calibration at boot
- Timer ISR: naked asm stub (`global_asm!` in `arch/mod.rs`) �� Rust `timer_isr_inner`
- APIC EOI (`apic::write_eoi()`) replaces PIC EOI
- IST1 allocated for double-fault handler (4KB dedicated stack)
- Uses `try_lock()` to avoid deadlock when interrupted code holds a lock
- Portable `on_timer_isr()` + `ContextSwitchHint` pattern in `scheduler/mod.rs`
- **IPI primitives** in `apic.rs`: `send_ipi()`, `send_ipi_all_excluding_self()`, `send_ipi_self()` via ICR
- **TLB shootdown** via vector 0xFE (`tlb.rs`): `shootdown_page()`, `shootdown_range()`, `shootdown_all()` — broadcast IPI, target CPUs execute `invlpg` or CR3 reload, initiating CPU spins on atomic pending counter
- **Cross-CPU task wake**: `TASK_CPU_MAP` (`[AtomicU16; 32]` in `lib.rs`) tracks task→CPU assignment (lock-free). `wake_task_on_cpu(TaskId)` reads the map and acquires the correct CPU's scheduler to wake. `block_local_task(TaskId, BlockReason)` uses `local_scheduler()`. All IPC helpers, ISR dispatch, and diagnostics use these instead of hardcoded `PER_CPU_SCHEDULER[0]`. `migrate_task_between()` updates the map atomically.

### Syscall Numbers
```
Exit=0, Write=1, Read=2, Allocate=3, Free=4, WaitIrq=5,
RegisterEndpoint=6, Yield=7, GetPid=8, GetTime=9, Print=10
```
All 11 syscalls are implemented in `src/syscalls/dispatcher.rs`:
- **Exit**: Marks task as Terminated in scheduler
- **Write**: Page-table-walk user buffer → IPC send (capability + interceptor checks)
- **Read**: IPC recv (capability + interceptor checks) → page-table-walk write to user buffer
- **Allocate**: VMA tracker assigns virtual address, frame allocation + map into process page tables (with rollback on OOM)
- **Free**: VMA lookup → unmap pages → free frames back to allocator
- **WaitIrq**: Registers task as IRQ handler + blocks until IRQ fires
- **RegisterEndpoint**: Grants full capability on endpoint to calling process
- **Yield**: Sets task Ready + zeroes time slice for reschedule
- **GetPid / GetTime / Print**: Fully functional

## Development Conventions

1. **Every `unsafe` block MUST have a `// SAFETY:` comment** explaining why the operation is safe. This was comprehensively audited — maintain it.

2. **Lock ordering** (see above) must always be followed. Never acquire a lower-numbered lock while holding a higher-numbered one.

3. **Architecture portability:** All x86-specific code must be behind `#[cfg(target_arch = "x86_64")]`. The `src/arch/mod.rs` shim re-exports the active backend. Portable scheduler logic lives in `scheduler/mod.rs`.

4. **Large structs** (IpcManager, CapabilityManager, BuddyAllocator) must be heap-allocated via `new_boxed()` pattern to avoid stack overflow. Boot stack is only 256KB.

5. **`no_std` only.** No standard library. No heap allocation before `memory::init()` completes in `main.rs`.

6. **GDT must be `static mut`** (writable .data section) because the CPU writes the Accessed bit.

7. **Never assume zeroed memory equals `None` for `Option<T>`.** Rust does not guarantee the Option discriminant layout — the compiler may assign discriminant 0 to `Some` (not `None`), especially for large structs on bare-metal targets. Always use explicit `core::ptr::write(None)` when initializing heap-allocated arrays of `Option<T>`.

## Dual-Platform Strategy (x86_64 + AArch64)

ArcOS targets **x86_64 first, AArch64 second**. The architecture abstraction is already in place:

### Current Portability Boundary
- `src/arch/mod.rs` — cfg-gated shim that re-exports the active backend
- `src/arch/x86_64/` — all x86-specific code lives here (GDT, SYSCALL/SYSRET, ISR stubs)
- `src/arch/spinlock.rs` — portable spinlock (already arch-independent)
- `src/scheduler/mod.rs` — portable `on_timer_isr()` + `ContextSwitchHint` (no arch dependency)
- `src/scheduler/task.rs`, `timer.rs` — portable (no arch dependency)
- `src/ipc/`, `src/syscalls/mod.rs`, `src/process.rs` — fully portable
- `src/memory/buddy_allocator.rs`, `frame_allocator.rs` — portable (address-space agnostic)

### Arch-Specific Code That Needs AArch64 Equivalents
| x86_64 Module | Responsibility | AArch64 Equivalent |
|---|---|---|
| `arch/x86_64/gdt.rs` | GDT + TSS + segment selectors | Exception level config (EL1/EL0), VBAR_EL1 |
| `arch/x86_64/syscall.rs` | SYSCALL/SYSRET via MSRs | SVC instruction + ESR_EL1 routing |
| `arch/x86_64/mod.rs` | SavedContext, context_switch, timer ISR stub | AArch64 register save/restore, IRQ vector table |
| `interrupts/mod.rs` | x86 IDT setup | AArch64 exception vector table |
| `arch/x86_64/apic.rs` | Local APIC timer + PIC disable + IPI | GICv2/GICv3 timer + SGI (software-generated interrupts) |
| `arch/x86_64/tlb.rs` | TLB shootdown via IPI | TLBI broadcast instructions (hardware-assisted on ARMv8.4+) |
| `interrupts/pic.rs` | 8259 PIC (disabled, legacy) | N/A (no legacy PIC on ARM) |
| `interrupts/pit.rs` | 8254 PIT (calibration only) | ARM Generic Timer (CNTV) |
| `memory/paging.rs` | x86_64 4-level page tables | AArch64 4-level page tables (different format) |
| `io/mod.rs` | uart_16550 (x86 port I/O) | PL011 UART (MMIO) |
| `platform/mod.rs` | CR4 feature detection | ID_AA64* system registers |

### Rules for New Code
- **Never put arch-specific code in portable modules.** If it touches registers, instructions, or hardware directly, it goes under `src/arch/<target>/`.
- **New arch backends must match the public API** defined by `src/arch/x86_64/mod.rs`: `SavedContext`, `context_switch()`, `timer_isr_inner()`, etc.
- **The AArch64 target triple will be `aarch64-unknown-none`** with a separate linker script.
- **Keep the interrupt subsystem portable where possible.** `interrupts/routing.rs` is already arch-independent. The PIC/PIT modules should move under `arch/x86_64/` when AArch64 work begins.
- **Bootloader:** Limine supports AArch64, so the same boot protocol should work.

## Known Issues

- `SYS_WAIT_IRQ` wake path works for all routed IRQs (timer + device). Device ISRs use `try_lock()` — if SCHEDULER lock is contended, wake is deferred to the next timer tick.
- `pic.rs` / `pit.rs` still exist as modules but are no longer called from the boot path (PIC disabled, PIT used only for calibration in `apic.rs`)
- `demo_syscalls`, legacy `handle_syscall`, `copy_from_user`/`copy_to_user`, and `register_example_interrupts` removed (superseded by SyscallDispatcher + page-table-walk helpers)
- **Limine base revision 3 HHDM gap:** ACPI_RECLAIMABLE, ACPI_NVS, and RESERVED regions are NOT in the HHDM. `map_acpi_regions()` in `main.rs` explicitly maps small RESERVED regions (≤1MB) and all ACPI regions into the HHDM before ACPI parsing. SeaBIOS puts ACPI tables in RESERVED memory (not ACPI_RECLAIMABLE), so the RESERVED mapping is essential.

## Planned Next Steps (Roadmap)

1. ~~**ELF Loader**~~ — DONE. Production loader with per-process page tables, frame allocation, segment mapping via HHDM, kernel stack + SavedContext setup. Wired into `main.rs` via `create_elf_user_task()`.
2. ~~**ELF "verify before execute" gate**~~ — DONE. `BinaryVerifier` trait + `DefaultVerifier` enforcing W^X, entry point validation, kernel space rejection, overlap detection, memory limits. Every ELF passes through the gate before any allocation.
3. ~~**Zero-Trust IPC Interceptor**~~ — DONE. `IpcInterceptor` trait + `DefaultInterceptor` with hooks at 3 enforcement points: IpcManager send/recv (after capability check), SyscallDispatcher pre-dispatch, CapabilityManager delegation. Installed at boot in `ipc_init()`.
4. ~~**Syscall implementations**~~ — DONE. All 11 syscalls implemented in `dispatcher.rs`: Exit (terminates task), Write/Read (page-table-walk + IPC with capability + interceptor), Allocate (frame alloc + map), Free (validates, needs VMA tracking), WaitIrq (register + block), RegisterEndpoint (grant capability), Yield (reschedule), GetPid/GetTime/Print (fully functional).
5. ~~**Multicore safety (SERIAL1)**~~ — DONE. `static mut SERIAL1` replaced with `Spinlock<Option<SerialPort>>`. All access goes through `lock()`.
6. ~~**APIC migration (BSP)**~~ — DONE. Local APIC timer replaces PIC+PIT for BSP. PIC disabled (remapped 0xF0, masked). APIC timer calibrated against PIT at boot. IST1 allocated for double-fault. EOI switched from PIC to APIC. `set_ist()` added to GDT module.
7. **SMP Phase 0 (foundations)** — DONE. IrqSpinlock (saves/disables interrupts before acquiring, prevents same-CPU deadlock in ISR context). Per-CPU data via GS base MSR (`percpu.rs`): BSP initialized at boot, AP slots reserved. Per-CPU GDT/TSS arrays: each CPU gets its own GDT (TSS descriptor differs) and TSS (RSP0 per-CPU, `ltr` marks Busy). SCHEDULER and TIMER globals migrated from `Spinlock` to `IrqSpinlock`.
8. **SMP Phase 1 (I/O APIC)** — DONE. ACPI table parser (`acpi/mod.rs`): RSDP validation, XSDT/RSDT walk, MADT parsing for I/O APIC addresses and interrupt source overrides. I/O APIC driver (`ioapic.rs`): MMIO register access via indirect IOREGSEL/IOWIN, redirection table programming, per-GSI device ISR handlers (vectors 33-56). Device IRQs routed at boot: keyboard (GSI 1), COM1/COM2 (GSI 3/4), PS/2 mouse (GSI 12), IDE (GSI 14/15). WaitIrq wake path now works for all device IRQs (not just timer). Limine RSDP request wired into boot sequence.
9. ~~**SMP Phase 2 (AP startup)**~~ — DONE. Limine MP protocol: BSP iterates non-BSP CPUs, assigns logical indices via `extra` field, writes `goto_address` to wake each AP. AP entry (`ap_entry`): loads per-CPU GDT/TSS, initializes percpu (GS base), loads shared IDT, configures SYSCALL MSRs, enables Local APIC, starts APIC timer (reuses BSP calibration), signals ready, enters idle loop. BSP busy-waits with timeout for all APs to report ready.
10. ~~**SMP Phase 3 (IPI + TLB shootdown)**~~ — DONE. IPI primitives in `apic.rs`: ICR register access (`send_ipi`, `send_ipi_all_excluding_self`, `send_ipi_self`) with delivery-status polling. TLB shootdown module (`tlb.rs`): dedicated vector 0xFE, global `ShootdownRequest` state, serialization lock, ISR handler (`invlpg` for small ranges, CR3 reload for large), public API (`shootdown_page`, `shootdown_range`, `shootdown_all`). Single-CPU fast path (local flush only). IDT registration in `init_hardware_interrupts`. Paging module documented for SMP callsite integration (per-process unmaps don't need shootdown until SMP scheduler).
11. ~~**SMP Phase 4 (SMP scheduler)**~~ — DONE. Phase 4a: per-CPU scheduler/timer arrays (`PER_CPU_SCHEDULER[256]`, `PER_CPU_TIMER[256]`), `local_scheduler()`/`local_timer()` helpers via GS base, all access sites migrated. Phase 4b: task migration primitives (`remove_task`, `accept_task`, `migrate_task_between`, `migrate_task`), AP scheduler/timer initialization in `ap_entry`, boot-time task distribution across CPUs, `home_cpu` field on Task, first-free-slot allocation in `create_task`/`create_isr_task`. Cross-CPU wake correctness: `TASK_CPU_MAP` (lock-free `AtomicU16` array) tracks task→CPU assignment, `wake_task_on_cpu()`/`block_local_task()` replace all hardcoded `PER_CPU_SCHEDULER[0]` in IPC helpers, ISR dispatch, and diagnostics. Phase 4c: load balancer (`try_load_balance()` in `lib.rs`) samples per-CPU runnable counts every 100 ticks (1s) from BSP idle loop, migrates one task when imbalance ≥ 2; `ONLINE_CPU_COUNT` atomic tracks live CPUs; `active_runnable_count()`/`pick_migratable_task()` methods on Scheduler; all `try_lock()` for non-blocking sampling.
12. **AArch64 port** — Create `src/arch/aarch64/` backend, move `interrupts/pic.rs` and `pit.rs` under `arch/x86_64/`, implement GICv3 + ARM Generic Timer + PL011 UART + exception vector table

## Verification Strategy

- Trait-based abstractions for property-based verification
- Explicit state tracking via enums (TaskState, etc.)
- Error handling via Result types throughout
- BuddyAllocator is pure bookkeeping (address-space agnostic) for testability
- 114 unit tests run on host macOS target (`x86_64-apple-darwin`)

## Post-Change Review Protocol

After any code change, run through this checklist systematically before considering the change complete.

### 1. Build Verification
```bash
# Unit tests (host)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Kernel build (debug + release)
cargo build --target x86_64-unknown-none
cargo build --target x86_64-unknown-none --release

# QEMU integration (when touching boot/runtime paths)
make run
```
All three must pass with zero warnings. Do not skip any step.

### 2. Safety Audit
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariants
- New unsafe code cites what guarantees make it sound (alignment, bounds, aliasing, lifetime)
- No raw pointer dereference without a bounds or null check nearby

### 3. Lock Ordering
Verify no change introduces a lock ordering violation:
```
SCHEDULER(1) → TIMER(2) → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7)
```
- Lower-numbered locks must be acquired before higher-numbered ones
- `try_lock()` in ISR context is acceptable (already established pattern)
- Holding multiple locks simultaneously requires explicit justification

### 4. Architecture Portability
- New x86-specific code is behind `#[cfg(target_arch = "x86_64")]`
- New x86-specific code lives under `src/arch/x86_64/`, not in portable modules
- Portable modules (`scheduler/`, `ipc/`, `process.rs`, `loader/elf.rs`) contain no arch-specific code

### 5. Memory Safety
- Large structs (>1KB) are heap-allocated via `new_boxed()` or `Box::new()` — boot stack is 256KB
- No heap allocation before `memory::init()` completes
- Frame allocator regions don't overlap with kernel heap or reserved memory

### 6. Security Review (for loader/IPC/syscall changes)
- ELF binaries pass through `BinaryVerifier` before any memory allocation
- W^X enforcement: no page is both writable and executable
- User-space segments don't map into kernel address space
- Syscall handlers validate all user-provided pointers and lengths
- Capabilities are checked before granting IPC access

### 7. Test Coverage
- New logic has corresponding unit tests in `#[cfg(test)]` modules
- Edge cases are tested (boundary values, error paths, overflow)
- Tests run on host macOS target — no x86 hardware dependencies in test code
