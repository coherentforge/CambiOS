# ArcOS Microkernel

A security-first microkernel OS written in Rust (`no_std`) targeting **x86_64** and **AArch64**. Boots via the Limine protocol with preemptive SMP multitasking, capability-based IPC, zero-trust enforcement, and an ELF process loader with ring-3 user tasks.

## Current Status

- **143/143 unit tests passing**
- **x86_64**: QEMU boots to stable preemptive multitasking with 2 CPUs (`-smp 2`), APIC timer at 100Hz, 5 tasks (3 kernel + 2 ring-3 user with per-process page tables and ELF loading), full SMP with IRQ affinity and load balancing
- **AArch64**: QEMU `virt` boots to stable preemptive scheduling with GICv3 + ARM Generic Timer at 100Hz, 3 kernel tasks, full memory subsystem

## Design Principles

- **Microkernel isolation** — device drivers, networking, and filesystems run in user-space; minimal kernel attack surface
- **Zero-trust security** — capability-based IPC, verify-before-execute ELF gate, IPC interceptor at 3 enforcement points
- **Cryptographic identity** — identity-based access replaces passwords (planned)
- **Platform agnostic** — x86_64 and AArch64 today, RISC-V planned
- **Live-patchable** — AI-assisted kernel updates without reboots (planned)
- **No telemetry** — no analytics, no phone-home behavior, ever

## Features

### Completed

- **Preemptive SMP scheduler** — per-CPU priority-band scheduling (4 bands, O(1) via VecDeque), task migration, load balancing (every 1s, threshold of 2)
- **SYSCALL/SYSRET fast path** (x86_64) / **SVC handler** (AArch64) — 11 syscalls implemented (Exit, Write, Read, Allocate, Free, WaitIrq, RegisterEndpoint, Yield, GetPid, GetTime, Print)
- **ELF process loader** — per-process page tables, frame allocation, segment mapping, kernel stack setup, verify-before-execute gate (W^X, entry validation, overlap detection)
- **Capability-based IPC** — endpoint message passing with fine-grained access control (send/receive/delegate), priority levels, zero-trust interceptor
- **SMP** — Limine MP protocol AP startup, per-CPU GDT/TSS, IPI primitives, TLB shootdown (vector 0xFE), cross-CPU task wake via lock-free `TASK_CPU_MAP`
- **Local APIC timer** (x86_64) / **ARM Generic Timer** (AArch64) — 100Hz preemptive ticks
- **I/O APIC** (x86_64) / **GICv3** (AArch64) — device IRQ routing
- **ACPI parsing** — RSDP, XSDT, MADT for I/O APIC and interrupt source overrides
- **Memory subsystem** — kernel heap (4MB), bitmap frame allocator (covers 0–2 GiB), buddy allocator, per-process page tables (4-level on both architectures)
- **Ring-3 user tasks** — user code at 0x400000, user stack at 0x800000, per-process heap with Allocate/Free syscalls

### Planned

- AArch64 SMP (AP startup via Limine MP protocol)
- Device IRQ routing via GIC SPIs on AArch64
- Userspace driver framework
- AI-powered binary analysis and anomaly detection
- Cryptographic identity system
- Live kernel patching
- RISC-V port

## Building

### Prerequisites

- Rust nightly toolchain (see `rust-toolchain.toml`)
- Targets: `x86_64-unknown-none`, `aarch64-unknown-none`
- QEMU (via Homebrew)
- Limine v8.7.0 (cloned automatically to `/tmp/limine`)
- `mtools` (for AArch64 FAT disk images)

### Commands

```bash
# Build kernel — x86_64
cargo build --target x86_64-unknown-none --release

# Build kernel — AArch64
cargo build --target aarch64-unknown-none --release

# Run unit tests (host macOS)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Build ISO + run in QEMU (x86_64, 2 CPUs)
make iso && make run

# Build FAT image + run in QEMU (AArch64)
make img-aarch64 && make run-aarch64
```

## Project Structure

```
src/
├── lib.rs                    # Crate root, global statics, init, halt
├── process.rs                # ProcessTable, ProcessDescriptor, VmaTracker
├── acpi/
│   └── mod.rs                # ACPI table parser (RSDP, XSDT, MADT)
├── arch/
│   ├── mod.rs                # cfg-gated architecture shim
│   ├── spinlock.rs           # Spinlock + IrqSpinlock (interrupt-disabling)
│   ├── x86_64/
│   │   ├── mod.rs            # Context switching, SavedContext, timer ISR
│   │   ├── apic.rs           # Local APIC driver (timer, EOI, IPI)
│   │   ├── gdt.rs            # Per-CPU GDT + TSS + IST
│   │   ├── ioapic.rs         # I/O APIC driver (device IRQ routing)
│   │   ├── percpu.rs         # Per-CPU data (GS base)
│   │   ├── syscall.rs        # SYSCALL/SYSRET MSR init + entry point
│   │   └── tlb.rs            # TLB shootdown via IPI
│   └── aarch64/
│       ├── mod.rs            # SavedContext, context_switch, timer ISR
│       ├── gic.rs            # GICv3 driver (Distributor, Redistributor, ICC)
│       ├── percpu.rs         # Per-CPU data (TPIDR_EL1)
│       ├── syscall.rs        # SVC entry + VBAR_EL1 exception vector table
│       ├── timer.rs          # ARM Generic Timer (CNTP)
│       └── tlb.rs            # TLB shootdown via TLBI broadcast
├── interrupts/
│   ├── mod.rs                # IDT setup, exception/device ISR handlers
│   ├── pic.rs                # 8259 PIC driver (disabled at boot)
│   ├── pit.rs                # 8254 PIT (APIC calibration only)
│   └── routing.rs            # IRQ → driver task routing table
├── io/
│   └── mod.rs                # Serial output (uart_16550 / PL011 UART)
├── ipc/
│   ├── mod.rs                # EndpointQueue, SyncChannel, IpcManager
│   ├── capability.rs         # Capability-based security
│   └── interceptor.rs        # Zero-trust IPC interceptor
├── loader/
│   ├── mod.rs                # ELF process loader + verify-before-execute
│   └── elf.rs                # ELF64 header/program header parser
├── memory/
│   ├── mod.rs                # Memory init + AArch64 paging (L0-L3)
│   ├── heap.rs               # Kernel heap allocator (GlobalAlloc)
│   ├── frame_allocator.rs    # Bitmap frame allocator (0–2 GiB)
│   ├── buddy_allocator.rs    # Pure bookkeeping buddy allocator
│   └── paging.rs             # x86_64 page table management
├── microkernel/
│   └── main.rs               # Kernel entry point, subsystem init
├── platform/
│   └── mod.rs                # Platform abstraction, feature detection
├── scheduler/
│   ├── mod.rs                # Per-CPU priority-band scheduler, on_timer_isr()
│   ├── task.rs               # Task/TaskState/CpuContext definitions
│   └── timer.rs              # Timer tick management
└── syscalls/
    ├── mod.rs                # SyscallNumber enum, SyscallArgs
    ├── dispatcher.rs         # Syscall dispatch + all 11 handlers
    └── userspace.rs          # Stub userspace syscall wrappers
```

## Boot Sequence

ArcOS boots via the **Limine v8.7.0** boot protocol on both architectures.

### x86_64

1. Limine loads kernel ELF, provides memory map, HHDM, RSDP
2. Kernel heap initialized (4MB), frame allocator initialized
3. ACPI regions mapped into HHDM, MADT parsed for I/O APIC
4. Per-CPU GDT/TSS installed, IDT loaded, SYSCALL MSRs configured
5. PIC disabled, I/O APIC programmed, APIC timer started at 100Hz
6. IPC manager, capability manager, and interceptor initialized
7. Kernel tasks created, ELF user processes loaded with per-process page tables
8. AP cores started via Limine MP protocol (per-CPU GDT, APIC, scheduler)
9. Preemptive SMP scheduling begins

### AArch64

1. Limine loads kernel ELF, provides memory map, HHDM
2. TCR_EL1.T1SZ widened to 16 (48-bit VA for HHDM)
3. Early MMIO mapping: PL011 UART, GIC Distributor/Redistributor into TTBR1
4. Kernel heap and frame allocator initialized
5. GIC distributor, redistributor, and CPU interface initialized
6. ARM Generic Timer started at 100Hz
7. Exception vector table installed (VBAR_EL1), SVC handler configured
8. Kernel tasks created, preemptive scheduling begins

## IPC Model

Capability-based message passing with zero-trust enforcement:

- **Fixed-size messages** (256 bytes) for predictable verification
- **Capability rights**: Send, Receive, Delegate — fine-grained per-endpoint
- **Priority levels**: Critical, High, Normal, Low
- **Three-layer enforcement**: IPC interceptor hooks at IpcManager send/recv, syscall pre-dispatch, and capability delegation
- **Page-table-walk** for user buffer validation in Write/Read syscalls

## Memory Layout

| Region | x86_64 | AArch64 |
|--------|--------|---------|
| HHDM base | `0xFFFF800000000000` | `0xFFFF000000000000` |
| User code | `0x400000` | `0x400000` |
| User stack top | `0x800000` (16KB) | `0x800000` (16KB) |
| Process heap base | `0x800000` | `0x40800000` |
| Kernel heap | 4MB at HHDM+physical | 4MB at HHDM+physical |
| Frame allocator | Bitmap, 0–2 GiB | Bitmap, 0–2 GiB |

## Lock Ordering

All locks follow strict ordering to prevent deadlock:

```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7)
```

`*` = IrqSpinlock (saves/disables interrupts before acquiring)

## Development

### Code Principles

- `no_std` only — no heap before `memory::init()` completes
- Every `unsafe` block requires a `// SAFETY:` comment
- Architecture-specific code lives under `src/arch/<target>/`
- Large structs heap-allocated via `new_boxed()` (boot stack is 256KB)
- Lock ordering must be followed; `try_lock()` in ISR context is the established pattern

### Running Tests

```bash
# All 143 tests (requires extra stack for buddy allocator tests)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin
```

Note: The microkernel binary (`src/microkernel/main.rs`) uses ELF-specific linker sections and cannot compile for test on macOS. Always use `--lib`.

## References

- [Limine Boot Protocol](https://github.com/limine-bootloader/limine)
- [OSDev Wiki](https://wiki.osdev.org/)
- [seL4 Microkernel](https://sel4.systems/) — verification reference
- [Rust on Baremetal](https://github.com/rust-osdev)
