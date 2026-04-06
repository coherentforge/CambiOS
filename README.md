# ArcOS Microkernel

A security-first microkernel OS written in Rust (`no_std`) targeting **x86_64** and **AArch64**. Boots via the Limine protocol with preemptive SMP multitasking, capability-based IPC, zero-trust enforcement, and an ELF process loader with ring-3 user tasks.

## Current Status

- **190/190 unit tests passing**
- **x86_64**: QEMU boots to stable preemptive multitasking with 2 CPUs (`-smp 2`), APIC timer at 100Hz, 7 tasks (3 kernel + 2 ring-3 user + hello module + FS service), full SMP (phases 0–4c) with IRQ affinity and load balancing
- **AArch64**: QEMU `virt` boots to stable preemptive SMP scheduling with GICv3 + ARM Generic Timer at 100Hz, 3 kernel tasks, full memory subsystem (kernel heap, frame allocator, process heaps), EL0 user tasks with per-process TTBR0
- **Identity (Phase 0)**: Bootstrap Principal bound to kernel processes and boot modules, IPC messages carry unforgeable `sender_principal` stamped by kernel, BindPrincipal/GetPrincipal syscalls
- **ObjectStore (Phase 0)**: Content-addressed ArcObjects with author/owner/signature/ACL, RamObjectStore (256 objects, FNV-1a hashing), ObjPut/ObjGet/ObjDelete/ObjList syscalls
- **FS Service**: First user-space Rust service (`user/fs-service/`), receives IPC on endpoint 16, enforces ownership via `sender_principal`, delegates to ObjectStore syscalls

## Design Principles

- **Microkernel isolation** — device drivers, networking, and filesystems run in user-space; minimal kernel attack surface
- **Zero-trust security** — capability-based IPC, verify-before-execute ELF gate, IPC interceptor at 3 enforcement points
- **Cryptographic identity** — identity-based access with unforgeable Principals (Phase 0 complete, Ed25519 + Blake3 in Phase 1)
- **Platform agnostic** — x86_64 and AArch64 today, RISC-V planned
- **Live-patchable** — AI-assisted kernel updates without reboots (planned)
- **No telemetry** — no analytics, no phone-home behavior, ever

## Features

### Completed

- **Preemptive SMP scheduler** — per-CPU priority-band scheduling (4 bands, O(1) via VecDeque, MAX_TASKS=256), task migration, load balancing (every 1s, threshold of 2)
- **SYSCALL/SYSRET fast path** (x86_64) / **SVC handler** (AArch64) — 18 syscalls implemented (Exit, Write, Read, Allocate, Free, WaitIrq, RegisterEndpoint, Yield, GetPid, GetTime, Print, BindPrincipal, GetPrincipal, RecvMsg, ObjPut, ObjGet, ObjDelete, ObjList)
- **ELF process loader** — per-process page tables, frame allocation, segment mapping, kernel stack setup, verify-before-execute gate (W^X, entry validation, overlap detection)
- **Capability-based IPC** — per-endpoint sharded locking (`ShardedIpcManager`, 32 shards), fine-grained access control (send/receive/delegate), priority levels, zero-trust interceptor, identity-aware `sender_principal` stamping
- **SMP** — Limine MP protocol AP startup on both x86_64 and AArch64, per-CPU GDT/TSS, IPI primitives, TLB shootdown (vector 0xFE on x86_64, TLBI broadcast on AArch64), cross-CPU task wake via lock-free `TASK_CPU_MAP`
- **Local APIC timer** (x86_64) / **ARM Generic Timer** (AArch64) — 100Hz preemptive ticks
- **I/O APIC** (x86_64) / **GICv3** (AArch64) — device IRQ routing
- **ACPI parsing** — RSDP, XSDT, MADT for I/O APIC and interrupt source overrides
- **Memory subsystem** — kernel heap (4MB), bitmap frame allocator (covers 0–2 GiB, 524288 frames), buddy allocator, per-CPU frame cache (32-frame LIFO, batch refill/drain), per-process page tables (4-level on both architectures)
- **Ring-3 user tasks** — user code at 0x400000, user stack at 0x800000, per-process heap with Allocate/Free syscalls, EL0 support on AArch64 with per-process TTBR0
- **Identity (Phase 0)** — `Principal` type (32-byte public key), Bootstrap Principal bound at boot, `BindPrincipal`/`GetPrincipal` syscalls, IPC messages carry unforgeable `sender_principal` stamped by kernel
- **ObjectStore (Phase 0)** — `ArcObject` (content-addressed, author/owner, signature field, ACL, lineage), `RamObjectStore` (256 objects, FNV-1a hashing), ObjPut/ObjGet/ObjDelete/ObjList syscalls with ownership enforcement
- **FS Service** — first user-space Rust service (`user/fs-service/`), registers IPC endpoint 16, service loop (RecvMsg → parse → ObjectStore syscalls → respond), ownership enforcement via `sender_principal`

### Planned

- AArch64 device IRQ routing via GIC SPIs
- Crypto integration (Ed25519 + Blake3, replacing FNV-1a, signed ELF binaries)
- Key store service (user-space capability-gated, private key isolation)
- Virtio-net driver (user-space MMIO, DMA buffer management)
- UDP stack + NTP demo
- AI-powered binary analysis and anomaly detection
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

# Build ISO + run in QEMU (x86_64, 2 CPUs) — includes kernel, hello.elf, fs-service
make iso && make run

# Just run (rebuilds kernel + user modules automatically)
make run

# Build FAT image + run in QEMU (AArch64)
make img-aarch64 && make run-aarch64

# Build fs-service only
make fs-service
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
├── fs/
│   ├── mod.rs                # ArcObject, ObjectStore trait (content-addressed signed objects)
│   └── ram.rs                # RamObjectStore (256 objects, FNV-1a hashing)
├── interrupts/
│   ├── mod.rs                # IDT setup, exception/device ISR handlers
│   ├── pic.rs                # 8259 PIC driver (disabled at boot)
│   ├── pit.rs                # 8254 PIT (APIC calibration only)
│   └── routing.rs            # IRQ → driver task routing table
├── io/
│   └── mod.rs                # Serial output (uart_16550 / PL011 UART)
├── ipc/
│   ├── mod.rs                # IPC: Principal, EndpointQueue, SyncChannel, IpcManager, ShardedIpcManager
│   ├── capability.rs         # Capability-based security + Principal binding
│   └── interceptor.rs        # Zero-trust IPC interceptor
├── loader/
│   ├── mod.rs                # ELF process loader + verify-before-execute
│   └── elf.rs                # ELF64 header/program header parser
├── memory/
│   ├── mod.rs                # Memory init + AArch64 paging (L0-L3)
│   ├── heap.rs               # Kernel heap allocator (GlobalAlloc)
│   ├── frame_allocator.rs    # Bitmap frame allocator (0–2 GiB) + per-CPU FrameCache
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
    ├── dispatcher.rs         # Syscall dispatch + all 18 handlers
    └── userspace.rs          # Stub userspace syscall wrappers
user/
├── hello.S                   # Test module (prints 3x, exits)
├── user.ld                   # User-space linker script (base 0x400000)
└── fs-service/               # Filesystem service (Rust no_std crate)
    ├── Cargo.toml
    ├── link.ld               # Linker script (.data on separate page for GOT)
    └── src/main.rs           # IPC service loop on endpoint 16, ObjectStore gateway
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
7. Bootstrap Principal created, bound to kernel processes
8. Kernel tasks created, ELF user processes loaded (hello.elf + fs-service) with per-process page tables
9. AP cores started via Limine MP protocol (per-CPU GDT, APIC, scheduler)
10. Preemptive SMP scheduling begins

### AArch64

1. Limine loads kernel ELF, provides memory map, HHDM
2. TCR_EL1.T1SZ widened to 16 (48-bit VA for HHDM)
3. Early MMIO mapping: PL011 UART, GIC Distributor/Redistributor into TTBR1
4. Kernel heap and frame allocator initialized
5. GIC distributor, redistributor, and CPU interface initialized
6. ARM Generic Timer started at 100Hz
7. Exception vector table installed (VBAR_EL1), SVC handler configured
8. Per-CPU data initialized via MPIDR_EL1
9. Kernel tasks created, AP cores started via Limine MP protocol
10. Preemptive SMP scheduling begins

## IPC Model

Capability-based message passing with zero-trust enforcement:

- **Fixed-size messages** (256 bytes) for predictable verification
- **Capability rights**: Send, Receive, Delegate — fine-grained per-endpoint
- **Priority levels**: Critical, High, Normal, Low
- **Three-layer enforcement**: IPC interceptor hooks at IpcManager send/recv, syscall pre-dispatch, and capability delegation
- **Page-table-walk** for user buffer validation in Write/Read syscalls
- **Identity-aware receive** (`RecvMsg`): returns `[sender_principal:32][from_endpoint:4][payload:N]`

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
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7) → OBJECT_STORE(8)
```

`*` = IrqSpinlock (saves/disables interrupts before acquiring)

Additional lock domains (independent of hierarchy above):
- `PER_CPU_FRAME_CACHE[cpu]` — per-CPU, never held with FRAME_ALLOCATOR
- `SHARDED_IPC.shards[endpoint]` — per-endpoint, never held cross-endpoint
- `BOOTSTRAP_PRINCIPAL` — written once at boot, read-only thereafter

## Development

### Code Principles

- `no_std` only — no heap before `memory::init()` completes
- Every `unsafe` block requires a `// SAFETY:` comment
- Architecture-specific code lives under `src/arch/<target>/`
- Large structs heap-allocated via `new_boxed()` (boot stack is 256KB)
- Lock ordering must be followed; `try_lock()` in ISR context is the established pattern

### Running Tests

```bash
# All 190 tests (requires extra stack for buddy allocator tests)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin
```

Note: The microkernel binary (`src/microkernel/main.rs`) uses ELF-specific linker sections and cannot compile for test on macOS. Always use `--lib`.

## Design Documents

- [ArcOS.md](ArcOS.md) — Source-of-truth architecture document
- [PHILOSOPHY.md](PHILOSOPHY.md) — Philosophical foundations: consciousness, creation, and the motivations behind ArcOS
- [identity.md](identity.md) — Identity architecture: Ed25519 Principals, author/owner model, biometric commitment, did:key DID method, revocation
- [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md) — Implementation sequencing for identity + storage: content-addressed ObjectStore, ArcObject model, bootstrap identity, IPC sender_principal stamping
- [SECURITY.md](SECURITY.md) — Zero-trust enforcement map: what's enforced, where, and how
- [SYSCALLS.md](SYSCALLS.md) — All 18 syscalls: numbers, arguments, behavior, calling conventions
- [INTERRUPT_ROUTING.md](INTERRUPT_ROUTING.md) — IRQ-to-task wakeup routing system
- [src/scheduler/SCHEDULER.md](src/scheduler/SCHEDULER.md) — Scheduler internals: tick-based preemptive round-robin

## Architecture Decision Records

- [ADR-000](docs/adr/000-zta-and-cap.md) — Zero-trust architecture and capability-based access control
- [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) — Per-CPU scheduling and SMP task management
- [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) — Three-layer enforcement pipeline for IPC and syscalls
- [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) — Content-addressed storage and cryptographic identity
- [ADR-004](docs/adr/004-cryptographic-integrity.md) — Cryptographic integrity: Blake3 hashing and Ed25519 signatures

## References

- [Limine Boot Protocol](https://github.com/limine-bootloader/limine)
- [OSDev Wiki](https://wiki.osdev.org/)
- [seL4 Microkernel](https://sel4.systems/) — verification reference
- [Rust on Baremetal](https://github.com/rust-osdev)
