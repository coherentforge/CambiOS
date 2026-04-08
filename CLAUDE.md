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
- **Kernel targets:** `x86_64-unknown-none` and `aarch64-unknown-none` (ELF, bare metal)
- **Unit tests:** `cargo test --lib` (runs natively on macOS)
- **Integration testing:** QEMU (installed via Homebrew)
- **AArch64 boot media:** FAT disk image via `mtools` (ISO/cdrom doesn't work for AArch64 UEFI on QEMU)

## Critical Rules

- **NEVER** suggest `cargo run` or `cargo build` without `--target x86_64-unknown-none` or `--target aarch64-unknown-none` for kernel crates.
- **NEVER** suggest running kernel binaries directly on the host. Always use QEMU.
- **AArch64 QEMU MUST use** `-machine virt,gic-version=3` (GICv3 required for ICC system registers).
- **ALWAYS*** all new files are tagged for copyright: // Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

## Quick Reference

```bash
# Build kernel (release)
cargo build --target x86_64-unknown-none --release

# Build kernel (debug)
cargo build --target x86_64-unknown-none

# Build AArch64 kernel (release)
cargo build --target aarch64-unknown-none --release

# Run tests (213 tests, all passing)
# Note: must use --manifest-path if cwd could be user/fs-service/
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Build ISO + run in QEMU (x86_64) — includes kernel, hello.elf, fs-service
make iso && make run

# Just run (rebuilds kernel + user modules automatically)
make run

# Build FAT image + run in QEMU (AArch64)
make img-aarch64 && make run-aarch64

# Build fs-service only (standalone Rust crate)
make fs-service

# Build ELF signing tool (host-side, for signing boot modules)
make sign-tool

# Sign an ELF binary via YubiKey (default — requires YubiKey + OpenPGP Ed25519 key)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf <elf-file>

# Sign via seed (for CI/testing without hardware key)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --seed <hex> <elf-file>

# Export bootstrap public key from YubiKey (one-time setup)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --export-pubkey bootstrap_pubkey.bin

# Print the bootstrap public key (hex)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --print-pubkey
```

**Important:** The microkernel binary (`src/microkernel/main.rs`) cannot compile for test on macOS because it uses ELF-specific linker sections. Always use `--lib` when running tests. The `RUST_MIN_STACK` env var is required because some tests (buddy allocator) need >2MB stack. The `user/fs-service/` crate is built separately with `CARGO_ENCODED_RUSTFLAGS` to override the parent `.cargo/config.toml` (which targets kernel code model). The `tools/sign-elf/` crate is a host-side tool with its own `.cargo/config.toml` targeting `aarch64-apple-darwin`.

## Project Overview

ArcOS is a verification-ready microkernel OS written in Rust (`no_std`) targeting x86_64 and AArch64. It boots via the Limine v8.x protocol and has preemptive multitasking with ring 3 user tasks.

**Current state:** 213/213 tests pass, clean release builds for both x86_64 and aarch64-unknown-none. **x86_64**: QEMU boots to stable preemptive multitasking with 2 CPUs (`-smp 2`), APIC timer at 100Hz, 10 tasks (3 kernel + 2 ring-3 user + 5 boot modules: hello, key-store, fs-service, virtio-net, udp-stack), full SMP (phases 0-4c), IRQ affinity, load balancing, PCI device discovery (7 devices), 24 syscalls. **AArch64**: QEMU `virt` boots to stable preemptive scheduling with GICv3 + ARM Generic Timer at 100Hz, 3 kernel tasks, full memory subsystem (kernel heap, frame allocator, process heaps). AArch64 SMP (AP startup via Limine MP protocol) is implemented. **Identity (Phase 1C, hardware-backed)**: Bootstrap Principal from compiled-in YubiKey public key (`bootstrap_pubkey.bin`), no secret key in kernel memory. Boot modules signed at build time via YubiKey OpenPGP interface. Bootstrap Principal bound to kernel processes and boot modules, IPC messages carry unforgeable sender_principal stamped by kernel, BindPrincipal/GetPrincipal/ClaimBootstrapKey syscalls (11/12/18). **Key Store Service**: User-space key-store (`user/key-store-service/`) on endpoint 17. In hardware-backed mode (no kernel secret key), enters degraded mode — signing unavailable until USB HID enables runtime YubiKey communication. fs-service falls back to unsigned ObjPut. **ObjectStore (Phase 1C)**: ArcObject (content-addressed via Blake3, author/owner, Ed25519 signature verified on retrieval, ACL), RamObjectStore (256 objects). ObjPut (14) creates unsigned objects; ObjPutSigned (19) stores pre-signed objects (kernel verifies signature). fs-service requests signing from key-store before storing. RecvMsg/ObjPut/ObjGet/ObjDelete/ObjList/ClaimBootstrapKey/ObjPutSigned syscalls (13-19). **FS Service**: User-space Rust ELF (`user/fs-service/`) on endpoint 16, requests signing from key-store, enforces ownership via sender_principal. **Signed ELF Loading**: Boot modules require Ed25519 signature (ARCSIG trailer), verified by SignedBinaryVerifier before execution. **Virtio-Net Driver (Phase 2A)**: User-space MMIO driver (`user/virtio-net/`) on endpoint 20 — PCI device discovery, legacy virtio transport, TX/RX virtqueues with DMA bounce buffers, hostile-device validation via `DeviceValue<T>`. **UDP Stack (Phase 2B)**: User-space stateless UDP/IP service (`user/udp-stack/`) on endpoint 21 — ARP, IPv4 (RFC 1071 checksum), UDP, built-in NTP demo (queries time.google.com), hardcoded for QEMU SLIRP (10.0.2.15/24, gateway 10.0.2.2). **PCI Subsystem**: Bus 0 scan at boot, device table exposed via DeviceInfo syscall (22), port I/O validation via PortIo syscall (23). **Device Syscalls**: MapMmio (20), AllocDma (21), DeviceInfo (22), PortIo (23) — enable user-space drivers to access MMIO, allocate DMA buffers, discover PCI devices, and perform validated port I/O.

**x86_64 features**: Custom 7-entry GDT with per-CPU TSS, SYSCALL/SYSRET fast path, APIC timer + I/O APIC device IRQ routing, SMP with per-CPU priority-band schedulers (4 bands, O(1) scheduling via VecDeque ready queues, MAX_TASKS=256), task migration, IRQ affinity, TLB shootdown via IPI, ACPI MADT parsing. **AArch64 features**: GICv3 (Distributor + Redistributor + CPU interface via ICC system registers), ARM Generic Timer (CNTP), AArch64 4-level page tables (L0-L3, TTBR0/TTBR1 split), exception vector table (VBAR_EL1), SVC syscall handler, PL011 UART, early MMIO page mapping (bootstrap frames for TTBR1), TCR_EL1 VA width fix for 48-bit HHDM, EL0 user tasks with per-process TTBR0 + user code/stack mapping.

## Toolchain

- Rust nightly (see `rust-toolchain.toml`)
- Default target: `x86_64-unknown-none` (set in `.cargo/config.toml`)
- AArch64 target: `aarch64-unknown-none` (pass `--target aarch64-unknown-none` explicitly)
- Linker scripts: `linker.ld` (x86_64, `elf64-x86-64`), `linker-aarch64.ld` (AArch64, `elf64-littleaarch64`)
- Bootloader: Limine v8.7.0 (binary branch cloned to `/tmp/limine`)
- Dependencies: `x86_64` 0.14, `uart_16550` 0.3, `bitflags` 2.3, `limine` 0.5, `blake3` 1.8 (no_std, pure), `ed25519-compact` 2.2 (no_std)
- Sign-elf tool deps: `ed25519-compact` 2.2, `openpgp-card` 0.6, `card-backend-pcsc` 0.5, `secrecy` 0.10 (YubiKey OpenPGP interface)

## Architecture

```
src/
├── lib.rs                    # Crate root, global statics, init, halt
├── process.rs                # ProcessTable, ProcessDescriptor, VmaTracker
├── acpi/
│   └── mod.rs                # ACPI table parser (RSDP, XSDT, MADT)
├── arch/
│   ├── mod.rs                # cfg-gated architecture shim (re-exports active backend)
│   ├── spinlock.rs           # Spinlock + IrqSpinlock (interrupt-disabling)
│   ├── x86_64/
│   │   ├── mod.rs            # Context switching, SavedContext, timer_isr_inner
│   │   ├── apic.rs           # Local APIC driver (timer, EOI, PIC disable)
│   │   ├── gdt.rs            # Per-CPU GDT + TSS + IST (SMP-ready)
│   │   ├── ioapic.rs         # I/O APIC driver (device IRQ routing)
│   │   ├── percpu.rs         # Per-CPU data (GS base), PerCpu struct
│   │   ├── syscall.rs        # SYSCALL/SYSRET MSR init + entry point
│   │   └── tlb.rs            # TLB shootdown via IPI (vector 0xFE)
│   └── aarch64/
│       ├── mod.rs            # SavedContext, context_switch, timer_isr_inner (asm)
│       ├── gic.rs            # GICv3 driver (Distributor, Redistributor, ICC sysregs)
│       ├── percpu.rs         # Per-CPU data (TPIDR_EL1), PerCpu struct
│       ├── syscall.rs        # SVC entry stub + VBAR_EL1 init
│       ├── timer.rs          # ARM Generic Timer (CNTP_TVAL_EL0, 100Hz)
│       └── tlb.rs            # TLB shootdown via TLBI broadcast instructions
├── interrupts/
│   ├── mod.rs                # IDT setup, exception/device ISR handlers
│   ├── pic.rs                # 8259 PIC driver (disabled at boot)
│   ├── pit.rs                # 8254 PIT (calibration only)
│   └── routing.rs            # IRQ → driver task routing table
├── fs/
│   ├── mod.rs                # ArcObject, ObjectStore trait, Blake3 hashing, Ed25519 sign/verify
│   └── ram.rs                # RamObjectStore (fixed-capacity 256 objects, Blake3 hashing)
user/
├── hello.S                   # Test module (prints 3x, exits)
├── user.ld                   # User-space linker script (base 0x400000)
├── libsys/                   # Shared syscall wrapper library for all user-space crates
│   ├── Cargo.toml
│   └── src/lib.rs            # Safe wrappers around x86_64 SYSCALL; only unsafe crate in user-space
├── fs-service/               # Filesystem service (Rust no_std crate)
│   ├── Cargo.toml
│   ├── link.ld               # Linker script (.data on separate page for GOT)
│   └── src/main.rs           # IPC service loop on endpoint 16, ObjectStore gateway
├── key-store-service/        # Key store service (Ed25519 signing, Rust no_std crate)
│   ├── Cargo.toml            # Uses ed25519-compact (no_std)
│   ├── link.ld               # Linker script (same pattern as fs-service)
│   └── src/main.rs           # Claims bootstrap key at boot, signs on IPC request (endpoint 17)
├── virtio-net/               # Virtio-net driver (user-space, Rust no_std crate)
│   ├── Cargo.toml
│   ├── link.ld
│   └── src/                  # main.rs + transport.rs, virtqueue.rs, device.rs, pci.rs
│       └── main.rs           # PCI discovery, legacy virtio transport, IPC on endpoint 20
└── udp-stack/                # UDP/IP network service (user-space, Rust no_std crate)
    ├── Cargo.toml
    ├── link.ld
    └── src/main.rs           # ARP, IPv4, UDP, NTP demo, IPC on endpoint 21
tools/
└── sign-elf/                 # Host-side ELF signing tool (Ed25519)
    ├── Cargo.toml            # Uses ed25519-compact, openpgp-card, card-backend-pcsc
    └── src/main.rs           # Signs ELF binaries via YubiKey or seed, ARCSIG trailer
├── io/
│   └── mod.rs                # Serial output (uart_16550), print!/println! macros
├── ipc/
│   ├── mod.rs                # IPC: Principal, EndpointQueue, SyncChannel, IpcManager, ShardedIpcManager
│   ├── capability.rs         # Capability-based security + Principal binding
│   └── interceptor.rs        # Zero-trust IPC interceptor (policy enforcement)
├── loader/
│   ├── mod.rs                # ELF process loader + verify-before-execute gate + SignedBinaryVerifier
│   └── elf.rs                # ELF64 header/program header parser
├── memory/
│   ├── mod.rs                # Memory subsystem init + AArch64 paging (L0-L3, early_map_mmio)
│   ├── heap.rs               # Kernel heap allocator (linked-list, GlobalAlloc)
│   ├── frame_allocator.rs    # Bitmap-based physical frame allocator (covers 0-2GiB) + per-CPU FrameCache
│   ├── buddy_allocator.rs    # Pure bookkeeping buddy allocator
│   └── paging.rs             # x86_64 page table management (OffsetPageTable)
├── microkernel/
│   └── main.rs               # Kernel entry point, all subsystem init
├── pci/
│   └── mod.rs                # PCI bus scan (bus 0), device table, BAR decoding, port validation
├── platform/
│   └── mod.rs                # Platform abstraction, CR4 features
├── scheduler/
│   ├── mod.rs                # Priority-band scheduler with per-band VecDeque, on_timer_isr()
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
- **User stack:** top at 0x800000, 64KB (16 pages), grows down
- **Per-process PML4:** kernel half cloned (entries 256..511)
- **HHDM:** Higher Half Direct Map provided by Limine for physical memory access
- **x86_64 HHDM:** `0xFFFF800000000000`, process heap base `0x800000`
- **AArch64 HHDM:** `0xFFFF000000000000`, process heap base `0x40800000` (QEMU virt RAM starts at 1 GiB)
- **Frame allocator:** bitmap covers 0-2 GiB physical (524288 frames, 64 KB bitmap in .bss)

### Lock Ordering (MUST be followed to prevent deadlock)
```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7) → OBJECT_STORE(8)
```
`*` = IrqSpinlock (saves/disables interrupts before acquiring, prevents same-CPU deadlock when timer ISR fires while lock is held). Others use plain Spinlock.

Lower-numbered locks must be acquired before higher-numbered ones. See `src/lib.rs` comment.

**Additional lock domains (independent of hierarchy above):**
- `PER_CPU_FRAME_CACHE[cpu]` — per-CPU, never held with FRAME_ALLOCATOR. Cache lock released before acquiring global allocator on refill/drain.
- `SHARDED_IPC.shards[endpoint]` — per-endpoint, never held cross-endpoint. Released before acquiring scheduler for task wake.
- `BOOTSTRAP_PRINCIPAL` — written once at boot, read-only thereafter. Not part of the lock hierarchy.

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
- **Cross-CPU task wake**: `TASK_CPU_MAP` (`[AtomicU16; 256]` in `lib.rs`) tracks task→CPU assignment (lock-free). `wake_task_on_cpu(TaskId)` reads the map and acquires the correct CPU's scheduler to wake. `block_local_task(TaskId, BlockReason)` uses `local_scheduler()`. All IPC helpers, ISR dispatch, and diagnostics use these instead of hardcoded `PER_CPU_SCHEDULER[0]`. `migrate_task_between()` updates the map atomically.

### Syscall Numbers
```
Exit=0, Write=1, Read=2, Allocate=3, Free=4, WaitIrq=5,
RegisterEndpoint=6, Yield=7, GetPid=8, GetTime=9, Print=10,
BindPrincipal=11, GetPrincipal=12, RecvMsg=13,
ObjPut=14, ObjGet=15, ObjDelete=16, ObjList=17,
ClaimBootstrapKey=18, ObjPutSigned=19,
MapMmio=20, AllocDma=21, DeviceInfo=22, PortIo=23
```
All 24 syscalls are implemented in `src/syscalls/dispatcher.rs`:
- **Exit**: Marks task as Terminated in scheduler
- **Write**: Page-table-walk user buffer → IPC send (capability + interceptor checks, sender_principal stamped)
- **Read**: IPC recv (capability + interceptor checks) → page-table-walk write to user buffer
- **Allocate**: VMA tracker assigns virtual address, frame allocation + map into process page tables (with rollback on OOM)
- **Free**: VMA lookup → unmap pages → free frames back to allocator
- **WaitIrq**: Registers task as IRQ handler + blocks until IRQ fires
- **RegisterEndpoint**: Grants full capability on endpoint to calling process
- **Yield**: Sets task Ready + zeroes time slice for reschedule
- **GetPid / GetTime / Print**: Fully functional
- **BindPrincipal**: Binds a 32-byte Principal (public key) to a process. Restricted: only the bootstrap Principal can call this
- **GetPrincipal**: Returns the calling process's bound Principal (32 bytes)
- **RecvMsg**: Like Read but returns `[sender_principal:32][from_endpoint:4][payload:N]` — identity-aware receive
- **ObjPut**: Store ArcObject with caller as author/owner, returns 32-byte content hash
- **ObjGet**: Retrieve object content by hash
- **ObjDelete**: Delete object (ownership enforced — only owner can delete)
- **ObjList**: List all object hashes (packed 32-byte hashes)
- **ClaimBootstrapKey**: One-shot: writes 64-byte bootstrap secret key to caller buffer, zeroes kernel copy. Restricted to bootstrap Principal
- **ObjPutSigned**: Like ObjPut but accepts pre-computed Ed25519 signature. Kernel verifies signature against caller's Principal before storing
- **MapMmio**: Maps device MMIO pages into process address space (uncacheable). Rejects addresses within RAM range. Returns user virtual address
- **AllocDma**: Allocates physically contiguous DMA pages with guard pages (unmapped before/after). Returns user vaddr; writes physical address to caller buffer
- **DeviceInfo**: Returns 108-byte PCI device descriptor by index (vendor/device ID, class, BARs with decoded addresses/sizes/types)
- **PortIo**: Kernel-validated port I/O on PCI device I/O BARs. Rejects ports not within a discovered PCI BAR. Supports byte/word/dword read/write

## Development Conventions

1. **Every `unsafe` block MUST have a `// SAFETY:` comment** explaining why the operation is safe. This was comprehensively audited — maintain it.

2. **Lock ordering** (see above) must always be followed. Never acquire a lower-numbered lock while holding a higher-numbered one.

3. **Architecture portability:** All x86-specific code must be behind `#[cfg(target_arch = "x86_64")]`. The `src/arch/mod.rs` shim re-exports the active backend. Portable scheduler logic lives in `scheduler/mod.rs`.

4. **Large structs** (Scheduler, IpcManager, CapabilityManager, BuddyAllocator) must be heap-allocated via `new_boxed()` pattern to avoid stack overflow. Boot stack is only 256KB. Scheduler uses Vec/VecDeque internally so only ~128 bytes of metadata lands on the stack.

5. **`no_std` only.** No standard library. No heap allocation before `memory::init()` completes in `main.rs`.

6. **GDT must be `static mut`** (writable .data section) because the CPU writes the Accessed bit.

7. **Never assume zeroed memory equals `None` for `Option<T>`.** Rust does not guarantee the Option discriminant layout — the compiler may assign discriminant 0 to `Some` (not `None`), especially for large structs on bare-metal targets. Always use explicit `core::ptr::write(None)` when initializing heap-allocated arrays of `Option<T>`.

## Multi-Platform Strategy (x86_64, AArch64, RISC-V planned)

ArcOS runs on **x86_64** and **AArch64** today, with **RISC-V** planned. The architecture abstraction is in place:

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
- **The AArch64 target triple is `aarch64-unknown-none`** with `linker-aarch64.ld` (`elf64-littleaarch64`).
- **Keep the interrupt subsystem portable where possible.** `interrupts/routing.rs` is already arch-independent. The PIC/PIT modules should move under `arch/x86_64/` eventually.
- **Bootloader:** Limine 8.7.0 supports AArch64 UEFI. Same boot protocol, same request statics. AArch64 uses FAT disk image (not ISO) for QEMU boot.
- **AArch64 MMIO must be explicitly mapped.** Limine's HHDM on AArch64 only covers RAM. Device MMIO (PL011, GIC) must be mapped into TTBR1 via `early_map_mmio()` at early boot.

## Known Issues

- `SYS_WAIT_IRQ` wake path works for all routed IRQs (timer + device) with IRQ affinity. Registered device IRQs use targeted single-CPU wake via TASK_CPU_MAP. Unregistered IRQs fall back to all-CPU scan with `try_lock()` — if SCHEDULER lock is contended, wake is deferred to the next timer tick.
- `pic.rs` / `pit.rs` still exist as modules but are no longer called from the boot path (PIC disabled, PIT used only for calibration in `apic.rs`)
- `demo_syscalls`, legacy `handle_syscall`, `copy_from_user`/`copy_to_user`, and `register_example_interrupts` removed (superseded by SyscallDispatcher + page-table-walk helpers)
- **Limine base revision 3 HHDM gap (x86_64):** ACPI_RECLAIMABLE, ACPI_NVS, and RESERVED regions are NOT in the HHDM. `map_acpi_regions()` in `main.rs` explicitly maps small RESERVED regions (≤1MB) and all ACPI regions into the HHDM before ACPI parsing. SeaBIOS puts ACPI tables in RESERVED memory (not ACPI_RECLAIMABLE), so the RESERVED mapping is essential.
- **Limine AArch64 HHDM does NOT map device MMIO.** PL011 UART (0x0900_0000), GIC Distributor (0x0800_0000), and GIC Redistributor (0x080A_0000) must be explicitly mapped into TTBR1 via `early_map_mmio()` before any I/O. Uses bootstrap frames from kernel .bss (physical address found by walking TTBR1 page tables, since kernel statics are NOT in HHDM).
- **Limine AArch64 TCR_EL1.T1SZ too narrow.** Limine sets T1SZ for ~39-bit VA, but HHDM at `0xFFFF000000000000` needs 48-bit. `kmain` widens T1SZ to 16 (48-bit) at early boot.
- **AArch64 QEMU requires GICv3.** Must use `-machine virt,gic-version=3` because the GIC driver uses ICC system registers (GICv3). Default GICv2 causes Undefined Instruction on `mrs ICC_SRE_EL1`.
- **AArch64 ELF loader fully ported.** `load_elf_process`, `build_boot_elf`, `create_elf_user_task`, and `load_boot_modules` are all portable — no `#[cfg(target_arch)]` gates. ELF machine type check uses `ELF_MACHINE_EXPECTED` (0x3E on x86_64, 0xB7 on AArch64).
- ~~**Terminated tasks re-fault after SYS_EXIT.**~~ FIXED. After dispatching SYS_EXIT, the syscall handler calls `halt_until_preempted(kernel_stack_top)` which switches RSP to the task's kernel stack (HHDM, stable across all page tables) before entering an `sti; hlt` loop (x86_64) or `daifclr + wfi` loop (AArch64). The kernel stack switch is critical: the SYSCALL handler runs on the user stack, and the timer ISR's CR3 switch would remap that stack to the new task's zeroed pages, corrupting the ISR's local variables. Using the kernel stack (HHDM) avoids this because the kernel half is shared across all page tables.
- **ELF loader doesn't upgrade page permissions for overlapping segments.** If two PT_LOAD segments share a page but have different permissions (e.g., .text RX and .got RW), the first segment's permissions are used. The fs-service linker script works around this by `ALIGN(4096)` before `.data` to force separate pages. The loader should be fixed to use the most permissive flags when segments share a page.
- **fs-service is x86_64 only.** The user-space crate uses x86_64 `syscall` inline assembly. AArch64 user-space modules need SVC-based syscall wrappers (future work).
- **AArch64 device IRQ routing not wired.** GIC `enable_spi()`/`set_spi_trigger()` exist but aren't called from the boot path or `handle_wait_irq()`. Device IRQ handlers (keyboard, virtio) not yet functional on AArch64.
- **No voluntary context switch.** ArcOS's only context switch mechanism is the timer ISR. Syscall handlers run with IF=0 (SFMASK) and cannot be preempted. `yield_now()` sets time_remaining=0 but does not actually switch — the task continues until the timer catches a brief IF=1 window in user mode. `recv_msg` has a partial blocking implementation (`suspend_to_kernel_stack` builds a synthetic SavedContext and halts on the kernel stack), but this only works for the specific recv_msg→halt path. Device drivers cannot wait for I/O completion (e.g., virtio TX used ring) without spinning. **This is the next architectural priority: implement `sched_yield()` as a first-class voluntary context switch callable from any kernel code path.** This unlocks: blocking IPC (clean), device I/O wait, proper yield, and eliminates all spin-wait workarounds.
- **Virtio-net TX completion blocks on QEMU TCG.** QEMU TCG defers virtio TX processing to its event loop (runs during guest `hlt`). The driver's TX completion poll spins in user mode, but the timer rarely catches the brief IF=1 window between syscalls. Requires voluntary context switch to yield to idle (which does `hlt`, triggering QEMU's event loop). Workaround: yield_now loop, but this depends on timer starvation luck.

## Planned Next Steps (Roadmap)

1. ~~**ELF Loader**~~ — DONE. Production loader with per-process page tables, frame allocation, segment mapping via HHDM, kernel stack + SavedContext setup. Wired into `main.rs` via `create_elf_user_task()`.
2. ~~**ELF "verify before execute" gate**~~ — DONE. `BinaryVerifier` trait + `DefaultVerifier` enforcing W^X, entry point validation, kernel space rejection, overlap detection, memory limits. Every ELF passes through the gate before any allocation.
3. ~~**Zero-Trust IPC Interceptor**~~ — DONE. `IpcInterceptor` trait + `DefaultInterceptor` with hooks at 3 enforcement points: IpcManager send/recv (after capability check), SyscallDispatcher pre-dispatch, CapabilityManager delegation. Installed at boot in `ipc_init()`.
4. ~~**Syscall implementations**~~ — DONE. All 13 syscalls implemented in `dispatcher.rs`: Exit (terminates task), Write/Read (page-table-walk + IPC with capability + interceptor + sender_principal stamping), Allocate (frame alloc + map), Free (validates, needs VMA tracking), WaitIrq (register + block), RegisterEndpoint (grant capability), Yield (reschedule), GetPid/GetTime/Print (fully functional), BindPrincipal (identity service binds key to process, restricted to bootstrap), GetPrincipal (process reads own identity).
5. ~~**Multicore safety (SERIAL1)**~~ — DONE. `static mut SERIAL1` replaced with `Spinlock<Option<SerialPort>>`. All access goes through `lock()`.
6. ~~**APIC migration (BSP)**~~ — DONE. Local APIC timer replaces PIC+PIT for BSP. PIC disabled (remapped 0xF0, masked). APIC timer calibrated against PIT at boot. IST1 allocated for double-fault. EOI switched from PIC to APIC. `set_ist()` added to GDT module.
7. **SMP Phase 0 (foundations)** — DONE. IrqSpinlock (saves/disables interrupts before acquiring, prevents same-CPU deadlock in ISR context). Per-CPU data via GS base MSR (`percpu.rs`): BSP initialized at boot, AP slots reserved. Per-CPU GDT/TSS arrays: each CPU gets its own GDT (TSS descriptor differs) and TSS (RSP0 per-CPU, `ltr` marks Busy). SCHEDULER and TIMER globals migrated from `Spinlock` to `IrqSpinlock`.
8. **SMP Phase 1 (I/O APIC)** — DONE. ACPI table parser (`acpi/mod.rs`): RSDP validation, XSDT/RSDT walk, MADT parsing for I/O APIC addresses and interrupt source overrides. I/O APIC driver (`ioapic.rs`): MMIO register access via indirect IOREGSEL/IOWIN, redirection table programming, per-GSI device ISR handlers (vectors 33-56). Device IRQs routed at boot: keyboard (GSI 1), COM1/COM2 (GSI 3/4), PS/2 mouse (GSI 12), IDE (GSI 14/15). WaitIrq wake path now works for all device IRQs (not just timer). Limine RSDP request wired into boot sequence.
9. ~~**SMP Phase 2 (AP startup)**~~ — DONE. Limine MP protocol: BSP iterates non-BSP CPUs, assigns logical indices via `extra` field, writes `goto_address` to wake each AP. AP entry (`ap_entry`): loads per-CPU GDT/TSS, initializes percpu (GS base), loads shared IDT, configures SYSCALL MSRs, enables Local APIC, starts APIC timer (reuses BSP calibration), signals ready, enters idle loop. BSP busy-waits with timeout for all APs to report ready.
10. ~~**SMP Phase 3 (IPI + TLB shootdown)**~~ — DONE. IPI primitives in `apic.rs`: ICR register access (`send_ipi`, `send_ipi_all_excluding_self`, `send_ipi_self`) with delivery-status polling. TLB shootdown module (`tlb.rs`): dedicated vector 0xFE, global `ShootdownRequest` state, serialization lock, ISR handler (`invlpg` for small ranges, CR3 reload for large), public API (`shootdown_page`, `shootdown_range`, `shootdown_all`). Single-CPU fast path (local flush only). IDT registration in `init_hardware_interrupts`. Paging module documented for SMP callsite integration (per-process unmaps don't need shootdown until SMP scheduler).
11. ~~**SMP Phase 4 (SMP scheduler)**~~ — DONE. Phase 4a: per-CPU scheduler/timer arrays (`PER_CPU_SCHEDULER[256]`, `PER_CPU_TIMER[256]`), `local_scheduler()`/`local_timer()` helpers via GS base, all access sites migrated. Phase 4b: task migration primitives (`remove_task`, `accept_task`, `migrate_task_between`, `migrate_task`), AP scheduler/timer initialization in `ap_entry`, boot-time task distribution across CPUs, `home_cpu` field on Task, first-free-slot allocation in `create_task`/`create_isr_task`. Cross-CPU wake correctness: `TASK_CPU_MAP` (lock-free `AtomicU16` array) tracks task→CPU assignment, `wake_task_on_cpu()`/`block_local_task()` replace all hardcoded `PER_CPU_SCHEDULER[0]` in IPC helpers, ISR dispatch, and diagnostics. Phase 4c: load balancer (`try_load_balance()` in `lib.rs`) samples per-CPU runnable counts every 100 ticks (1s) from BSP idle loop, migrates one task when imbalance ≥ 2; `ONLINE_CPU_COUNT` atomic tracks live CPUs; `active_runnable_count()`/`pick_migratable_task()` methods on Scheduler; all `try_lock()` for non-blocking sampling.
12. ~~**AArch64 port (scaffolding)**~~ — DONE. `src/arch/aarch64/` backend created with full API surface matching x86_64: `mod.rs` (SavedContext, context_switch stubs), `gic.rs` (GICv3 interrupt controller stubs — write_eoi, read_cpu_id), `tlb.rs` (TLBI shootdown stubs — shootdown_page/range/all), `percpu.rs` (TPIDR_EL1-based per-CPU data stubs), `syscall.rs` (SVC/VBAR_EL1 init stub). All cfg-gated in `src/arch/mod.rs`. Function bodies are `todo!()` — compiles for cross-reference but not yet runnable on AArch64 hardware. Validates that the architecture abstraction boundary is clean.
13. ~~**AArch64 port (Phase 1 — real assembly)**~~ — DONE. All `todo!()` stubs replaced with real implementations (0 remaining). CpuContext in `task.rs` cfg-gated: x86_64 (18 fields), aarch64 (x19-x30, sp, pc, pstate = 15 fields). SavedContext: gpr[31] + elr_el1 + spsr_el1 + sp_el0. Context save/restore/switch assembly (stp/ldp based). Exception vector table (16 entries at VBAR_EL1). Timer ISR stub saves all regs → calls timer_isr_inner → eret. GIC CPU interface via ICC system registers (acknowledge_irq, write_eoi, init, send_sgi, read_cpu_id). TLB: TLBI VALE1IS / VMALLE1IS instructions. PerCpu: TPIDR_EL1-based init_bsp/init_ap/current_percpu. PL011 UART (MMIO at 0x0900_0000) in `io/mod.rs`. Loader SavedContext construction cfg-gated.
14. ~~**AArch64 port (Phase 2 — hardware drivers + page tables)**~~ — DONE. ARM Generic Timer driver (`arch/aarch64/timer.rs`): reads CNTFRQ_EL0, computes reload, writes CNTP_TVAL_EL0/CNTP_CTL_EL0, rearm on each tick, init/init_ap/stop/read_counter/elapsed_ms. AArch64 4-level page tables (`memory/mod.rs` paging module): L0→L3 walk with 4KB granule, 48-bit VA, TTBR0/TTBR1 split (user tables clean — no kernel entries copied), descriptor bits (Valid, Table, AF, ISH, AP, AttrIndx, PXN, UXN), flags module (KERNEL_RO, kernel_rw, user_ro, user_rw), all 8 public functions (active_page_table, page_table_from_cr3, map_page, unmap_page, map_range, translate, create_process_page_table, free_process_page_table). GICv3 Distributor/Redistributor MMIO (`gic.rs`): GICD at 0x0800_0000, GICR at 0x080A_0000; init_distributor (TYPER, SPI priorities, ARE+GRP1NS), init_redistributor (wake, PPI 30 timer), enable_spi/disable_spi/set_spi_trigger. SVC exception handler: `svc_entry_stub` assembly (save/restore all regs, ESR_EL1-aware), `svc_handler_inner` Rust handler (EC=0x15 verification, x8=syscall number, x0-x5=args, dispatches to SyscallDispatcher, return value in x0).
15. ~~**AArch64 port (Phase 3 — boot sequence)**~~ — DONE. Full `main.rs` boot sequence ported for AArch64: all Limine requests work, kernel heap init (4MB at first USABLE region), frame allocator (MAX_FRAMES increased to 524288 covering 2GiB for AArch64 RAM at 1GiB+), process heap at `PROCESS_HEAP_BASE=0x40800000`, GIC distributor/redistributor/CPU-interface init, ARM Generic Timer at 100Hz, BSP per-CPU data via MPIDR_EL1, exception vector table, 3 kernel tasks running with preemptive scheduling. Early boot fixes: TCR_EL1.T1SZ widened to 16 (48-bit VA) for HHDM access, `early_map_mmio()` maps PL011 + GIC MMIO into TTBR1 using bootstrap frames (kernel virt→phys via TTBR1 page table walk). Build via `make img-aarch64` (FAT disk image with mtools — ISO/cdrom approach doesn't work for AArch64 UEFI on QEMU). Run via `make run-aarch64` (QEMU `virt`, cortex-a72, `gic-version=3`, edk2 firmware). Remaining: SMP AP startup on AArch64, device IRQ routing via GIC SPIs.
16. ~~**AArch64 SMP**~~ — DONE. AArch64 `ap_entry` implemented in `main.rs`: Limine MP protocol, per-CPU TPIDR_EL1 init, GIC redistributor per-CPU init, ARM Generic Timer per-AP, per-CPU scheduler/timer creation, AP ready signaling. QEMU `virt` multi-core boot verified.
17. ~~**Scheduler scalability**~~ — DONE. MAX_TASKS raised from 32 to 256. Task storage changed from inline array to heap-allocated `Vec<Option<Task>>`. Added 4-band priority ready queues (`VecDeque<TaskId>` per band) for O(1) amortized scheduling. `active_runnable_count()` maintained as O(1) counter. `verify_invariants()` is O(1) via `current_task`. `Scheduler::new_boxed()` pattern.
18. ~~**Per-CPU frame cache**~~ — DONE. `FrameCache` (32-frame LIFO stack per CPU) in `frame_allocator.rs`. `PER_CPU_FRAME_CACHE[MAX_CPUS]` in `lib.rs`. `cached_allocate_frame()`/`cached_free_frame()` serve most allocations without global lock. Batch refill (16) and drain (16) amortize slow path. Syscall `handle_allocate`/`handle_free` migrated to cached path.
19. ~~**Per-endpoint IPC sharding**~~ — DONE. `ShardedIpcManager` with 32 independently-locked `EndpointShard` structs. `SHARDED_IPC` static in `lib.rs`. All IPC callsites in `main.rs` migrated from global `IPC_MANAGER` to per-endpoint locks. CPUs communicating on different endpoints never contend.
20. ~~**AArch64 EL0 user tasks**~~ — DONE. `create_user_task` ported to AArch64: SavedContext with SPSR_EL1=EL0t mode, per-process TTBR0 page table, user code/stack mapping, EL0 assembly entry stub (`svc #0` for syscalls). `read_user_buffer()`/`write_user_buffer()` made portable (removed x86_64 cfg gate). `handle_wait_irq()` wired to GIC `enable_spi()` on AArch64. `USER_SPACE_END` made arch-dependent (0x0001_0000_0000_0000 for 48-bit AArch64 VA).
21. ~~**Identity + ObjectStore Phase 0**~~ — DONE. `Principal` type (32-byte public key) in `ipc/mod.rs`. IPC `Message.sender_principal` stamped by kernel in `send_message_with_capability()` — unforgeable. `ProcessCapabilities.principal` field + `bind_principal()`/`get_principal()` on `CapabilityManager`. `BindPrincipal` (11) and `GetPrincipal` (12) syscalls — BindPrincipal restricted to bootstrap Principal. `BOOTSTRAP_PRINCIPAL` global (now hardware-backed via compiled-in YubiKey public key). `ArcObject` struct (content_hash, immutable author, transferable owner, signature, ACL, lineage, content). `ObjectStore` trait (get/put/delete/list/count). `RamObjectStore` (256 objects, FNV-1a content hashing, heap-allocated). `OBJECT_STORE` global at lock position 8. Bootstrap Principal bound to kernel processes 0-2 at boot. 35 new tests.
22. ~~**FS Service (user-space)**~~ — DONE. First real user-space service. Rust `no_std` crate (`user/fs-service/`) compiled to static ELF, loaded as boot module. Registers IPC endpoint 16, enters service loop: `RecvMsg` → parse command (PUT/GET/DELETE/LIST) → check sender_principal → call ObjPut/ObjGet/ObjDelete/ObjList syscalls → `Write` response back to sender. 5 new kernel syscalls (RecvMsg=13, ObjPut=14, ObjGet=15, ObjDelete=16, ObjList=17). RecvMsg returns `[sender_principal:32][from_endpoint:4][payload:N]`. ObjDelete enforces ownership (only owner can delete). Build integrated into Makefile (`make fs-service`), loaded via limine.conf. Also fixed: hello.S changed from infinite loop to 3 prints + exit; scheduler `time_slice_expired()` now forces reschedule for terminated tasks.
23. **AArch64 device IRQ routing** — Wire GIC `enable_spi()`/`set_spi_trigger()` into AArch64 boot path for QEMU virt devices (virtio, PL011 RX). Port `handle_wait_irq()` to use GIC SPI routing.
24. ~~**Crypto Integration (Phase 1B)**~~ — DONE. Added `ed25519-compact` 2.2 + `blake3` 1.8 crates (both `no_std`, pure Rust). Replaced FNV-1a with Blake3 for content hashing. **Bootstrap identity is now hardware-backed**: Ed25519 public key compiled in from `bootstrap_pubkey.bin` (extracted from YubiKey via `sign-elf --export-pubkey`). No secret key in kernel memory — `BOOTSTRAP_SECRET_KEY` stays zeroed. `handle_obj_put` creates unsigned objects; `handle_obj_get` verifies signature before returning content (unsigned objects allowed). `SignedBinaryVerifier` with ARCSIG signature trailer format (64-byte Ed25519 sig + 8-byte magic). `load_boot_modules` requires signed ELFs. Host-side `tools/sign-elf/` signs via YubiKey OpenPGP (default) or seed (CI fallback). Makefile signs hello.elf, key-store-service.elf, and fs-service.elf during ISO/image build. 205 tests total.
25. ~~**Key Store Service (Phase 1C)**~~ — DONE. User-space key-store service (`user/key-store-service/`) on IPC endpoint 17. At boot, attempts `ClaimBootstrapKey` (syscall 18). In hardware-backed mode (YubiKey), no secret key exists in kernel memory — key-store enters **degraded mode** (no signing, responds with STATUS_ERROR). `fs-service` falls back to unsigned ObjPut automatically. `ObjPutSigned` (syscall 19) still available for future use when USB HID enables runtime YubiKey communication. Loaded as signed boot module (limine.conf, before fs-service for scheduling priority).
26. ~~**Virtio-Net Driver (Phase 2A)**~~ — DONE. User-space MMIO driver (`user/virtio-net/`) on IPC endpoint 20. PCI device discovery via DeviceInfo syscall, legacy virtio transport (I/O port BAR), TX/RX virtqueues with DMA bounce buffers (AllocDma syscall), hostile-device validation via `DeviceValue<T>` (out-of-bounds indices, length overflows kill the device — no recovery). IPC protocol: CMD_SEND_PACKET(1), CMD_RECV_PACKET(2), CMD_GET_MAC(3), CMD_GET_STATUS(4). 4 new syscalls: MapMmio(20), AllocDma(21), DeviceInfo(22), PortIo(23). PCI bus scan wired into boot path. libsys shared syscall library (`user/libsys/`) with safe wrappers for all 24 syscalls.
27. ~~**UDP Stack + NTP Demo (Phase 2B)**~~ — DONE. User-space stateless UDP/IP service (`user/udp-stack/`) on IPC endpoint 21. Implements: Ethernet framing, ARP (4-entry cache, broadcast request/reply), IPv4 (RFC 1071 checksum, DF flag, TTL=64), UDP (checksum optional for IPv4). Built-in NTP demo at startup: ARP-resolves QEMU SLIRP gateway (10.0.2.2), sends NTPv4 client request to time.google.com (216.239.35.0:123), parses transmit timestamp, prints human-readable UTC. Service loop on endpoint 21: CMD_UDP_SEND(1), CMD_UDP_RECV(2), CMD_GET_CONFIG(3). Hardcoded for QEMU SLIRP: IP 10.0.2.15/24, gateway 10.0.2.2. Startup race with virtio-net handled via retry-with-backoff on MAC request.
28. **RISC-V port** — `src/arch/riscv64/` backend matching x86_64/AArch64 public API. PLIC interrupt controller, SBI timer, Sv48 page tables.

## Design Documents

These documents capture architectural decisions that upcoming implementation must align with:

- **[identity.md](identity.md)** — Identity architecture: what identity means in ArcOS, Ed25519 Principals, author/owner model, biometric commitment, did:key DID method, revocation model. This is the authoritative design document for identity.
- **[FS-and-ID-design-plan.md](FS-and-ID-design-plan.md)** — Implementation sequencing for identity + storage: content-addressed ObjectStore, ArcObject model (Blake3 hashes, signed artifacts), bootstrap identity, IPC sender_principal stamping, SSB-inspired social layer. Flows from identity.md.

Any work on identity, storage, filesystem, or object model must be consistent with these documents. If implementation reveals a design problem, update the design doc — don't silently diverge.

## Verification Strategy

- Trait-based abstractions for property-based verification
- Explicit state tracking via enums (TaskState, etc.)
- Error handling via Result types throughout
- BuddyAllocator is pure bookkeeping (address-space agnostic) for testability
- 213 unit tests run on host macOS target (`x86_64-apple-darwin`), including 12 portable AArch64 logic tests, 50 identity/ObjectStore/crypto tests, 7 signed ELF verifier tests

## Post-Change Review Protocol

After any code change, run through this checklist systematically before considering the change complete.

### 1. Build Verification
```bash
# Unit tests (host)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Kernel build — x86_64 (debug + release)
cargo build --target x86_64-unknown-none
cargo build --target x86_64-unknown-none --release

# Kernel build — AArch64 (release)
cargo build --target aarch64-unknown-none --release

# QEMU integration (when touching boot/runtime paths)
make run            # x86_64
make run-aarch64    # AArch64
```
All builds must pass with zero errors. Do not skip any step.

### 2. Safety Audit
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariants
- New unsafe code cites what guarantees make it sound (alignment, bounds, aliasing, lifetime)
- No raw pointer dereference without a bounds or null check nearby

### 3. Lock Ordering
Verify no change introduces a lock ordering violation:
```
SCHEDULER(1) → TIMER(2) → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7) → OBJECT_STORE(8)
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
