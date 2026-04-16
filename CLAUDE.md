# CambiOS Microkernel — Claude Code Context

## Formal Verification (Non-Negotiable Constraint)
The microkernel must be written for future formal verification. Every design decision in kernel code should keep this achievable. Concretely:

- **Pure logic separated from effects.** Algorithms that can be expressed as pure functions (e.g. BuddyAllocator) must be. Pure code is verifiable independently of hardware state.
- **Explicit state machines.** All state is represented as enums with exhaustive match. No boolean flags standing in for state, no implicit state encoded in combinations of fields.
- **Result/Option everywhere in kernel paths.** No panics, no unwrap(), no expect() in non-test kernel code. Every failure is a typed error that propagates explicitly.
- **Bounded iteration.** No unbounded loops in kernel paths. Loop bounds must be statically knowable or asserted. Verifiers cannot reason about unbounded loops.
unsafe minimized and isolated. Each unsafe block must be the smallest possible scope. Unsafe must be wrapped behind a safe abstraction boundary that can be audited and eventually replaced with a verified implementation.
- **No trait objects in kernel hot paths.** Monomorphized generics are statically analyzable; dynamic dispatch is not.
- **Invariants encoded in types, not comments.** If a value must be page-aligned, represent it as a newtype. If a region must be non-empty, make the empty case unrepresentable.
- **Separation of specification from implementation.** When implementing a component, identify the properties it must satisfy (preconditions, postconditions, invariants) and make them explicit — as type constraints where possible, as documented contracts otherwise. These become the verification targets.

The BuddyAllocator (pure bookkeeping, no hardware access, fully testable on host) is the template for how kernel logic should be structured. New kernel components will follow this pattern.


## Project Vision

CambiOS is a next-gen AI-integrated operating system built on these principles:

- **Security First:** Zero-trust architecture with real-time AI monitoring. No backdoors, no telemetry/telematics. Every process is verified at runtime.
- **Microkernel Isolation:** Device drivers, networking, and file systems run in isolated user-space environments — aligned for future formal verification.
- **AI-Powered Security:** Just-in-time code analysis pre-execution, behavioral anomaly detection, automatic quarantining of threats.
- **Cryptographic Identity:** Identity-based access replaces passwords. Decentralized identity and networking — no reliance on legacy IP/DNS.
- **AI Compatibility Layer:** AI-driven adaptation for running legacy Windows apps and cross-platform hardware support.
- **Live-Patchable:** AI-assisted kernel updates without reboots.
- **Platform Agnostic** Design with x86_64 and ARM compatibility.

Never suggest adding telemetry, analytics, or any form of phone-home behavior.

## Development Environment

- **Host:** macOS (Apple Silicon)
- **Kernel targets:** `x86_64-unknown-none`, `aarch64-unknown-none`, and `riscv64gc-unknown-none-elf` (ELF, bare metal). RISC-V backend is in progress (Phase R-0 done) — see [ADR-013](docs/adr/013-riscv64-architecture-support.md) and [STATUS.md](STATUS.md) RISC-V port phases.
- **Unit tests:** `cargo test --lib` (runs natively on macOS)
- **Integration testing:** QEMU (installed via Homebrew)
- **AArch64 boot media:** FAT disk image via `mtools` (ISO/cdrom doesn't work for AArch64 UEFI on QEMU)
- **RISC-V boot:** OpenSBI (M-mode firmware, ships with QEMU as `-bios default`) hands a DTB pointer to a custom S-mode boot stub at `src/boot/riscv.rs`. No Limine on RISC-V.

## Critical Rules

- **NEVER** suggest `cargo run` or `cargo build` without `--target x86_64-unknown-none`, `--target aarch64-unknown-none`, or `--target riscv64gc-unknown-none-elf` for kernel crates.
- **NEVER** suggest running kernel binaries directly on the host. Always use QEMU.
- **AArch64 QEMU MUST use** `-machine virt,gic-version=3` (GICv3 required for ICC system registers).
- **RISC-V QEMU MUST use** `-machine virt -bios default` (loads OpenSBI as M-mode firmware; the kernel is the S-mode payload). No vendor-specific machine types — generic-first per [ADR-013](docs/adr/013-riscv64-architecture-support.md).
- **Tri-arch regression gate is mandatory before commits** ([ADR-013](docs/adr/013-riscv64-architecture-support.md) § Tri-Architecture Regression Discipline). During RISC-V Phases R-1 through R-6 (the riscv64 backend is mid-construction and not expected to build between phase boundaries), use `make check-stable` (x86_64 + aarch64). After Phase R-6 lands, use `make check-all` (all three) as the permanent gate. The discipline is identical: no commits regress any *currently buildable* arch.
- **ALWAYS*** all new files are tagged for copyright: // Copyright (C) 2024-2026 Jason Ricca. All rights reserved.
- **FUTURE VERIFICATION** every part of the microkernel will be formally verified at a later date.

## Stop-and-Ask Gate

Before the first edit, stop and confirm with the user when any of these apply. The cost of pausing is a sentence; the cost of proceeding wrong is a debug session or a silent design drift. User standing preference: questions over wrong assumptions — "I don't know" is acceptable.

- **Unread subsystem.** About to modify a subsystem listed in the [Required Reading](#required-reading-by-subsystem) map without having read its docs *this session*. Re-read first, or flag the reading gap.
- **New `unsafe` invariant.** About to add `unsafe` that introduces a *new kind* of safety obligation (not mechanically matching a pre-existing pattern in the same module). Mechanical copies are fine; new invariants need user sign-off so the audit trail is intentional.
- **ADR rewrite.** About to edit an ADR's original decision text. Use a `## Divergence` appendix or a new superseding ADR instead — original reasoning is immutable history.
- **Lock hierarchy change.** About to add a new lock to the hierarchy, reorder entries, or change `IrqSpinlock` vs plain `Spinlock`. Formally relevant, cross-subsystem, and exactly the class of change that breaks invariants silently.
- **SCAFFOLDING bound without v1 math.** About to pick a `const MAX_*` value without working through Dev Convention 8's extrapolation: v1-endgame workload, ≤25% utilization, memory cost. See [ASSUMPTIONS.md](ASSUMPTIONS.md).
- **Dynamic dispatch in kernel.** About to introduce a trait object (`Box<dyn …>`, `&dyn …`) in kernel hot paths. Violates the Formal Verification rule ("no dynamic dispatch"). Propose the monomorphized design first.
- **Panic / unwrap / expect in non-test kernel code.** Every kernel failure must be a typed `Result`. If the only forward motion seems to be a panic, stop — the error type is probably wrong.
- **Telemetry / analytics / phone-home.** Project principle is zero telemetry. Any feature that emits data off-device (even "anonymous") is a stop.
- **Portable module drift.** About to add `#[cfg(target_arch = …)]` to `src/scheduler/`, `src/ipc/`, `src/process.rs`, `src/loader/elf.rs`, or another portable module. Factor an `arch::` helper instead, or escalate.
- **Identity-gate bypass.** About to add a syscall without updating `requires_identity()` + the identity tests in [src/syscalls/mod.rs](src/syscalls/mod.rs), or add an IPC receiver that uses plain `recv_msg` where `recv_verified` is the load-bearing variant.
- **Destructive or shared-state action.** `git reset --hard`, branch deletion, force-push, `rm -rf` under the repo, or any action visible outside this machine. The top-level "Executing actions with care" rule applies; this bullet is the local reminder.

This list is not exhaustive. The rule: **when you are about to modify something the user would want to be consulted on before the first edit, stop before the first edit.**

## Prompt-Shaping Changelog

Why each non-obvious rule was added, so a future session can generalize instead of pattern-matching on surface syntax. Keep entries terse (`YYYY-MM-DD — change — reason/failure it addresses`). Newest first.

- **2026-04-16** — Added `arch::interrupts_enabled()` helper (x86_64 / AArch64 / RISC-V + host stub) and `debug_assert!` at heap entry, `map_page` (both arches), `Scheduler::block_task`. Reason: prose invariants ("disable interrupts before `block_task`", "heap alloc requires `memory::init()` first", "page-align before `map_page`") lose force across sessions; code-level asserts fire at the bad callsite every build.
- **2026-04-16** — Reverted a proposed `bind_principal` `debug_assert!`. Lesson: asserts and negative-path tests on the same invariant collide — the test intentionally triggers the error, and the assert fires on it. Test wins because it runs in release. Rule: before adding an assert, check for an existing `test_X_rejects_Y` — if it exists, the invariant is already enforced louder than an assert can.
- **2026-04-16** — Added Failure Mode Signatures section (Common Failure Signatures). Reason: Claude Code sees compiler errors and QEMU hangs first, not architectural concepts. Maps the observed symptom text back to the root cause + where to look.
- **2026-04-16** — Tiered the Post-Change Review Protocol (scope triage: small change → §1 + §8; subsystem change → full §1–§8). Reason: one-size-fits-all checklist on a typo produces fatigue, which gets paid in skipped steps later.
- **2026-04-16** — Added Stop-and-Ask Gate. Reason: user standing preference ("questions over wrong assumptions") wasn't encoded in CLAUDE.md, only in memory; without an explicit gate, ambiguous cross-subsystem changes proceeded on guesswork.
- **2026-04-16** — `make stats` target + stripped hard-coded syscall/test counts from prose. Reason: counts duplicated across CLAUDE.md / STATUS.md drifted silently (doc said "37 syscalls" when actual was 38; lock hierarchy duplicated with one copy missing `CHANNEL_MANAGER`). Canonical source is code; run `make stats` when a number actually matters.

## Quick Reference

```bash
# Build kernel (release)
cargo build --target x86_64-unknown-none --release

# Build kernel (debug)
cargo build --target x86_64-unknown-none

# Build AArch64 kernel (release)
cargo build --target aarch64-unknown-none --release

# Build RISC-V kernel (release) — Phase R-0 done; full kernel currently
# fails to compile pending Phase R-1 arch backend. ADR-013.
cargo build --target riscv64gc-unknown-none-elf --release

# Tri-arch regression gate (MANDATORY before commits). During Phases
# R-1..R-6 of the RISC-V port (riscv64 backend mid-construction), use
# check-stable. After R-6 lands, use check-all as the permanent gate.
# ADR-013 § Tri-Architecture Regression Discipline.
make check-stable     # x86_64 + aarch64 (use during RISC-V buildup)
make check-all        # x86_64 + aarch64 + riscv64 (post-R-6)

# Run tests. Test count is not cited here — run `make stats` when you
# need it (syscall count, test count, .rs file counts are all derived
# from source). Canonical counts live in code, not prose.
# Note: must use --manifest-path if cwd could be user/fs-service/
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Derived counts (syscalls, tests, LOC) — run when a number actually matters.
make stats

# Build for a specific deployment tier (Phase 3.2a / ADR-008 / ADR-009).
# CAMBIOS_TIER selects which TableSizingPolicy is compiled in. Default
# is tier3 when unset — always target tier3 unless specifically
# working on tier1 or tier2. build.rs reads CAMBIOS_TIER and emits a
# single --cfg tierN flag; any other value is a build error.
CAMBIOS_TIER=tier1 cargo build --target x86_64-unknown-none --release
CAMBIOS_TIER=tier2 cargo build --target x86_64-unknown-none --release
CAMBIOS_TIER=tier3 cargo build --target x86_64-unknown-none --release   # same as leaving it unset

# Generate symbol index for AI-assisted navigation (read .symbols at session start)
make symbols

# Build ISO + run in QEMU (x86_64) — includes kernel + boot modules (policy, ks, fs, virtio-blk, shell)
make iso && make run

# Just run (rebuilds kernel + user modules automatically)
make run

# Build FAT image + run in QEMU (AArch64)
make img-aarch64 && make run-aarch64

# Build + run RISC-V kernel in QEMU virt with OpenSBI (Phase R-0 builds
# the target; Phase R-1+ produces useful boot output)
make run-riscv64

# Build fs-service only (standalone Rust crate)
make fs-service

# Create the backing file for the virtio-blk device (64 MiB raw image).
# `make run` depends on this target; idempotent — leaves an existing image alone.
make disk-img

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

## Code Navigation — rust-analyzer MCP Tools

An MCP server exposing rust-analyzer is configured in `.mcp.json`. **Prefer these tools over Grep/Glob for code navigation whenever practical:**

- **`mcp__rust-analyzer__symbol_references`** — find a symbol by name and get all references in one call. Use this instead of grepping for a symbol name.
- **`mcp__rust-analyzer__hover`** — get the resolved type, struct fields, and doc comments at a position. Use this instead of reading surrounding code to understand a type.
- **`mcp__rust-analyzer__definition`** — jump to where a symbol is defined. Use this instead of grepping for `fn name` or `struct name`.
- **`mcp__rust-analyzer__references`** — find all references at a position (when you already have file:line:col).
- **`mcp__rust-analyzer__implementations`** — find all trait implementations. Use this instead of grepping for `impl TraitName`.
- **`mcp__rust-analyzer__symbols`** — fuzzy search for symbols across the workspace.
- **`mcp__rust-analyzer__document_symbols`** — structural overview of a file (all functions, types, constants).

These tools return semantically precise results (no false positives from comments or strings) and save significant tokens compared to grep-then-read cycles. Grep is still appropriate for searching within string literals, comments, or non-Rust files.

## Project Overview

CambiOS is a verification-ready microkernel OS written in Rust (`no_std`) targeting **x86_64**, **AArch64**, and **riscv64gc** (Phase R-0 done; full backend in progress per [ADR-013](docs/adr/013-riscv64-architecture-support.md)). It boots via the Limine v8.x protocol on x86_64 and AArch64; via OpenSBI + custom S-mode stub on RISC-V. Preemptive multitasking with ring 3 (x86), EL0 (AArch64), or U-mode (RISC-V) user tasks.

**Current state:** see [STATUS.md](STATUS.md). That file is the canonical source for what is built, what is in progress, and what is planned, including test counts, subsystem status, phase markers, v1 roadmap progress, and known issues. **This file (CLAUDE.md) is the technical reference for the kernel** — conventions, rules, lock ordering, build commands, required-reading map. Status info is intentionally not duplicated here so the two files cannot drift.

## Toolchain

- Rust nightly (see `rust-toolchain.toml`)
- Default target: `x86_64-unknown-none` (set in `.cargo/config.toml`)
- AArch64 target: `aarch64-unknown-none` (pass `--target aarch64-unknown-none` explicitly)
- Linker scripts: `linker.ld` (x86_64, `elf64-x86-64`), `linker-aarch64.ld` (AArch64, `elf64-littleaarch64`)
- Bootloader: Limine v8.7.0 (binary branch cloned to `/tmp/limine`)
- Dependencies: `x86_64` 0.14, `uart_16550` 0.3, `bitflags` 2.3, `limine` 0.5, `blake3` 1.8 (no_std, pure), `ed25519-compact` 2.2 (no_std)
- Sign-elf tool deps: `ed25519-compact` 2.2, `openpgp-card` 0.6, `card-backend-pcsc` 0.5, `secrecy` 0.10 (YubiKey OpenPGP interface)

## Architecture

### Build-time configuration (`build.rs`)

```
build.rs                      # Reads CAMBIOS_TIER env var (default: tier3),
                              # emits --cfg tierN for src/config/tier.rs to
                              # select the compiled-in TableSizingPolicy.
                              # See ADR-008 and ADR-009.
```

### Kernel (`src/`)

```
src/
├── lib.rs                    # Crate root, global statics, init, halt
├── process.rs                # ProcessTable, ProcessDescriptor, VmaTracker (Phase 3.2a: slice-backed; Phase 3.2c: generation counters, slot allocator)
├── boot_modules.rs           # Boot module registry (name → physical range)
├── acpi/
│   └── mod.rs                # ACPI table parser (RSDP, XSDT, MADT)
├── config/
│   ├── mod.rs                # Build-time configuration re-exports
│   └── tier.rs               # TableSizingPolicy, TIER{1,2,3}_POLICY, num_slots_from, binding_constraint_for (Phase 3.2a)
├── arch/
│   ├── mod.rs                # cfg-gated architecture shim (re-exports active backend)
│   ├── spinlock.rs           # Spinlock + IrqSpinlock (interrupt-disabling)
│   ├── x86_64/
│   │   ├── mod.rs            # SavedContext, context_switch, timer_isr_inner, yield_save_and_switch
│   │   ├── apic.rs           # Local APIC driver (timer, EOI, PIC disable, IPI primitives)
│   │   ├── gdt.rs            # Per-CPU GDT + TSS + IST (SMP-ready)
│   │   ├── ioapic.rs         # I/O APIC driver (device IRQ routing)
│   │   ├── msr.rs            # Shared rdmsr/wrmsr wrappers used by apic/percpu/syscall
│   │   ├── percpu.rs         # Per-CPU data (GS base), PerCpu struct
│   │   ├── portio.rs         # Safe wrappers around in/out port I/O (Port8/16/32)
│   │   ├── syscall.rs        # SYSCALL/SYSRET MSR init + kernel-stack entry stub
│   │   └── tlb.rs            # TLB shootdown via IPI (vector 0xFE)
│   └── aarch64/
│       ├── mod.rs            # SavedContext, context_switch, timer_isr_inner (asm), yield_save_and_switch
│       ├── gic.rs            # GICv3 driver (Distributor, Redistributor, ICC sysregs)
│       ├── percpu.rs         # Per-CPU data (TPIDR_EL1), PerCpu struct
│       ├── syscall.rs        # SVC entry stub + VBAR_EL1 init
│       ├── timer.rs          # ARM Generic Timer (CNTP_TVAL_EL0, 100 Hz)
│       └── tlb.rs            # TLB shootdown via TLBI broadcast instructions
├── audit/
│   ├── mod.rs                # AuditEventKind (16 variants), RawAuditEvent (64-byte wire format), emit(), builder constructors, sampling config (Phase 3.3)
│   ├── buffer.rs             # StagingBuffer: lock-free SPSC ring buffer (per-CPU, formally verifiable)
│   └── drain.rs              # AuditRing (global ring buffer, HHDM-backed), drain_tick() (BSP timer ISR piggyback)
├── fs/
│   ├── mod.rs                # CambiObject, ObjectStore trait (by-value get, &mut self), Blake3 hashing, Ed25519 sign/verify
│   ├── block.rs              # BlockDevice trait (4 KiB sectors), MemBlockDevice (testing)
│   ├── disk.rs               # DiskObjectStore<B: BlockDevice> (Phase 4a.i, ADR-010 on-disk format)
│   ├── lazy_disk.rs          # LazyDiskStore — deferred-init wrapper, OBJECT_STORE backing (Phase 4a.iii)
│   ├── virtio_blk_device.rs  # VirtioBlkDevice: BlockDevice — kernel IPC client to user/virtio-blk driver (Phase 4a.iii)
│   └── ram.rs                # RamObjectStore (fixed-capacity 256 objects, Phase 0 fallback)
├── interrupts/
│   ├── mod.rs                # IDT setup, exception/device ISR handlers
│   ├── pic.rs                # 8259 PIC driver (disabled at boot, x86_64 only)
│   ├── pit.rs                # 8254 PIT (APIC calibration only, x86_64 only)
│   └── routing.rs            # IRQ → driver task routing table (portable)
├── io/
│   └── mod.rs                # Serial output (uart_16550 / PL011), print!/println! macros
├── ipc/
│   ├── mod.rs                # IPC: Principal, EndpointQueue, SyncChannel, IpcManager, ShardedIpcManager
│   ├── capability.rs         # Capability-based security + Principal binding
│   ├── channel.rs            # Shared-memory data channels (Phase 3.2d, ADR-005)
│   └── interceptor.rs        # Zero-trust IPC interceptor (policy enforcement)
├── loader/
│   ├── mod.rs                # ELF process loader + verify-before-execute gate + SignedBinaryVerifier
│   └── elf.rs                # ELF64 header/program header parser
├── memory/
│   ├── mod.rs                # Memory subsystem init + AArch64 paging (L0-L3, early_map_mmio)
│   ├── buddy_allocator.rs    # Pure bookkeeping buddy allocator
│   ├── frame_allocator.rs    # Bitmap-based physical frame allocator (covers 0–2 GiB) + per-CPU FrameCache + allocate_contiguous / free_contiguous
│   ├── heap.rs               # Kernel heap allocator (linked-list, GlobalAlloc)
│   ├── object_table.rs       # Kernel object table region allocator (Phase 3.2a, ADR-008)
│   └── paging.rs             # x86_64 page table management (OffsetPageTable)
├── microkernel/
│   └── main.rs               # Kernel entry point, all subsystem init
├── pci/
│   └── mod.rs                # PCI bus scan (bus 0), device table, BAR decoding, port validation
├── platform/
│   └── mod.rs                # Platform abstraction, CR4/CPU feature detection
├── scheduler/
│   ├── mod.rs                # Priority-band scheduler with per-band VecDeque, on_timer_isr()
│   ├── task.rs               # Task/TaskState/CpuContext definitions
│   └── timer.rs              # Timer tick management
└── syscalls/
    ├── mod.rs                # SyscallNumber enum, SyscallArgs
    ├── dispatcher.rs         # Syscall dispatch + handlers (all 28 implemented)
    └── userspace.rs          # Stub userspace syscall wrappers
```

### User-space services (`user/`)

```
user/
├── user.ld                   # x86_64 user-space linker script (base 0x400000)
├── user-aarch64.ld           # AArch64 user-space linker script
├── hello.S                   # Test module (prints 3x, exits) — boot module
├── libsys/                   # Shared syscall wrapper library — only unsafe user-space crate
│   └── src/lib.rs            # Safe wrappers over x86_64 SYSCALL and AArch64 SVC; Principal, VerifiedMessage, recv_verified (load-bearing identity types)
├── fs-service/               # Filesystem service — boot module, IPC endpoint 16
│   └── src/main.rs           # ObjectStore gateway (sender_principal enforcement)
├── key-store-service/        # Key store service (Ed25519 signing) — boot module, IPC endpoint 17
│   └── src/main.rs           # Claims bootstrap key at boot, signs ObjectStore puts
├── virtio-net/               # Virtio-net driver — boot module, IPC endpoint 20
│   └── src/                  # main.rs + transport.rs, virtqueue.rs, device.rs, pci.rs
├── virtio-blk/               # Virtio-blk driver — boot module (Phase 4a.ii/4a.iii)
│   └── src/                  # main.rs + transport.rs, virtqueue.rs, device.rs, pci.rs
│                             # endpoint 24 = user clients (recv_verified)
│                             # endpoint 26 = kernel-only commands (recv_msg, no cap check)
│                             # endpoint 25 = kernel's reply endpoint (handle_write intercept)
├── i219-net/                 # Intel I219-LM driver — boot module (Dell 3630 bare metal)
│   └── src/                  # main.rs + mmio.rs, pci.rs, phy.rs, regs.rs, ring.rs
├── udp-stack/                # UDP/IP network service — boot module, IPC endpoint 21
│   └── src/main.rs           # ARP, IPv4, UDP, NTP demo
└── shell/                    # Interactive serial shell — boot module
    └── src/main.rs           # Command parsing over ConsoleRead
```

### Host-side tools (`tools/`)

```
tools/
└── sign-elf/                 # Ed25519 ELF signing tool (YubiKey or seed) — produces ARCSIG trailer
    └── src/main.rs
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
- **Kernel stack switch on entry:** `syscall_entry` saves user RSP to `gs:[32]` (PerCpu.user_rsp_scratch), loads kernel RSP from `gs:[24]` (PerCpu.kernel_rsp0), pushes user RSP onto kernel stack. Return path: `cli`, restore regs, `pop rsp`, `sysretq`.
- **Interrupts enabled in handlers:** `sti` after kernel stack switch, `cli` before return. Syscall handlers are preemptible by the timer ISR.
- `PerCpu.kernel_rsp0` updated by `set_kernel_stack()` on every context switch (timer ISR + yield_save_and_switch).

### Memory Layout
- **Kernel heap:** 4MB at HHDM+physical, initialized from Limine memory map
- **Boot stack:** 256KB via Limine StackSizeRequest
- **Kernel object table region (Phase 3.2a):** contiguous physical region allocated at boot via `FrameAllocator::allocate_contiguous`, HHDM-mapped, holds two page-aligned subregions — `[Option<ProcessDescriptor>; num_slots]` and `[Option<ProcessCapabilities>; num_slots]`. Size is determined by `config::num_slots()` × (`size_of::<Option<ProcessDescriptor>>() + size_of::<Option<ProcessCapabilities>>()`), rounded up per subregion to a page boundary. Allocated in `init_kernel_object_tables()` in `main.rs` between frame allocator init and GDT setup. See [ADR-008](docs/adr/008-boot-time-sized-object-tables.md) and `src/memory/object_table.rs`.
- **Per-process heaps (Phase 3.2a):** each process gets a `HEAP_SIZE` (1 MiB) contiguous physical region, allocated on demand in `ProcessDescriptor::new` via `FrameAllocator::allocate_contiguous(HEAP_PAGES)` and freed in `handle_exit` via `free_contiguous`. No more `PROCESS_HEAP_BASE + pid * HEAP_SIZE` arithmetic — the physical base is whatever the frame allocator hands out. Kernel still accesses the heap via HHDM (`virt_base = phys_base + hhdm_offset`).
- **User code:** mapped at 0x400000
- **User stack:** top at 0x800000, 64KB (16 pages), grows down
- **Per-process PML4:** kernel half cloned (entries 256..511)
- **HHDM:** Higher Half Direct Map provided by Limine for physical memory access
- **x86_64 HHDM:** `0xFFFF800000000000`
- **AArch64 HHDM:** `0xFFFF000000000000` (QEMU virt RAM starts at 1 GiB)
- **Frame allocator:** bitmap covers 0-2 GiB physical (524288 frames, 64 KB bitmap in .bss)

### Lock Ordering (MUST be followed to prevent deadlock)
```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
CHANNEL_MANAGER(5) → PROCESS_TABLE(6) → FRAME_ALLOCATOR(7) →
INTERRUPT_ROUTER(8) → OBJECT_STORE(9)
```
`*` = IrqSpinlock (saves/disables interrupts before acquiring, prevents same-CPU deadlock when timer ISR fires while lock is held). Others use plain Spinlock.

Lower-numbered locks must be acquired before higher-numbered ones. See `src/lib.rs` comment.

**Additional lock domains (independent of hierarchy above):**
- `PER_CPU_FRAME_CACHE[cpu]` — per-CPU, never held with FRAME_ALLOCATOR. Cache lock released before acquiring global allocator on refill/drain.
- `SHARDED_IPC.shards[endpoint]` — per-endpoint, never held cross-endpoint. Released before acquiring scheduler for task wake.
- `BOOTSTRAP_PRINCIPAL` — written once at boot, read-only thereafter. Not part of the lock hierarchy.
- `AUDIT_RING` — acquired by `drain_tick()` (try_lock from BSP ISR, holds no other lock) and by `SYS_AUDIT_ATTACH`/`SYS_AUDIT_INFO` handlers (two-phase protocol: never held while PROCESS_TABLE or FRAME_ALLOCATOR is held). `audit::emit()` never touches it.
- `PER_CPU_AUDIT_BUFFER[cpu]` — lock-free SPSC; no lock at all. Written by local CPU, drained by BSP.

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
- **Voluntary context switch** via `yield_save_and_switch`: builds synthetic SavedContext (identical layout to timer ISR) on the kernel stack, calls `yield_inner` → `on_voluntary_yield` → `scheduler.voluntary_yield()`. No EOI (not a hardware interrupt). x86_64 (`arch/x86_64/mod.rs`): synthetic iretq frame, TSS/CR3 updates. AArch64 (`arch/aarch64/mod.rs`): synthetic eret frame, SP_EL0 via SPSel toggle, TTBR0_EL1/TLB updates. Used by handle_exit, handle_yield, handle_recv_msg (restart loop), handle_wait_irq.
- **Blocking pattern**: disable interrupts (`cli`/`msr daifset, #2`) → `block_task(Blocked)` → `yield_save_and_switch()` → re-check on wake. The interrupt disable before `block_task` prevents the timer ISR from seeing Blocked state before yield saves correct context.
- **IPI primitives** in `apic.rs`: `send_ipi()`, `send_ipi_all_excluding_self()`, `send_ipi_self()` via ICR
- **TLB shootdown** via vector 0xFE (`tlb.rs`): `shootdown_page()`, `shootdown_range()`, `shootdown_all()` — broadcast IPI, target CPUs execute `invlpg` or CR3 reload, initiating CPU spins on atomic pending counter
- **Cross-CPU task wake**: `TASK_CPU_MAP` (`[AtomicU16; 256]` in `lib.rs`) tracks task→CPU assignment (lock-free). `wake_task_on_cpu(TaskId)` reads the map and acquires the correct CPU's scheduler to wake. `block_local_task(TaskId, BlockReason)` uses `local_scheduler()`. All IPC helpers, ISR dispatch, and diagnostics use these instead of hardcoded `PER_CPU_SCHEDULER[0]`. `migrate_task_between()` updates the map atomically.
- **IPC reply-endpoint registry**: `REPLY_ENDPOINT` (`[AtomicU32; 256]` in `lib.rs`) stores the first endpoint each process registered via `SYS_REGISTER_ENDPOINT`. `handle_write` uses this as the `from` field of outgoing messages, so receivers doing `sys::write(msg.from_endpoint(), reply)` route replies back to a queue the sender is actually listening on. Falls back to pid-slot when a process has never registered. Landed in Phase 4b — before this fix, `from` was the sender's pid slot, which was always a different number from the registered endpoint, and any reply sent via `msg.from_endpoint()` went into a queue nobody read.

### Syscall Numbers

The canonical list is the `SyscallNumber` enum in [src/syscalls/mod.rs](src/syscalls/mod.rs) — that is the ABI. Run `make stats` for the current count. The per-syscall summaries below describe *behavior*, not *existence*; if you need the authoritative list of numbers, read the enum.

Handlers live in [src/syscalls/dispatcher.rs](src/syscalls/dispatcher.rs). Behavior summaries:
- **Exit**: Marks task as Terminated in scheduler and calls `CapabilityManager::revoke_all_for_process()` to reclaim endpoint capabilities (see [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md)); VMA / page-table / frame reclaim is still partial
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
- **RecvMsg**: Like Read but returns `[sender_principal:32][from_endpoint:4][payload:N]` — identity-aware receive. Blocks on `MessageWait(endpoint)` when no message is queued
- **TryRecvMsg** (Phase 4b): Non-blocking variant of RecvMsg — returns 0 immediately if empty, never blocks. Required for services that poll multiple endpoints (virtio-blk listens on ep24 + ep26; blocking on one would miss wakes on the other). `from_endpoint` is the sender's **reply endpoint** (first endpoint they registered), tracked in `REPLY_ENDPOINT` since Phase 4b — fixes a pre-existing bug where `from = pid_slot` caused replies to land on the wrong queue
- **ObjPut**: Store CambiObject with caller as author/owner, returns 32-byte content hash
- **ObjGet**: Retrieve object content by hash
- **ObjDelete**: Delete object (ownership enforced — only owner can delete)
- **ObjList**: List all object hashes (packed 32-byte hashes)
- **ClaimBootstrapKey**: One-shot: writes 64-byte bootstrap secret key to caller buffer, zeroes kernel copy. Restricted to bootstrap Principal
- **ObjPutSigned**: Like ObjPut but accepts pre-computed Ed25519 signature. Kernel verifies signature against caller's Principal before storing
- **MapMmio**: Maps device MMIO pages into process address space (uncacheable). Rejects addresses within RAM range. Returns user virtual address
- **AllocDma**: Allocates physically contiguous DMA pages with guard pages (unmapped before/after). Returns user vaddr; writes physical address to caller buffer
- **DeviceInfo**: Returns 108-byte PCI device descriptor by index (vendor/device ID, class, BARs with decoded addresses/sizes/types)
- **PortIo**: Kernel-validated port I/O on PCI device I/O BARs. Rejects ports not within a discovered PCI BAR. Supports byte/word/dword read/write
- **ConsoleRead**: Non-blocking read of bytes from the serial console into a user buffer
- **Spawn**: Create a new process from a named boot module; parent is the caller. Requires `CapabilityKind::CreateProcess` (Phase 3.2b, ADR-008); returns `PermissionDenied` without it
- **WaitTask**: Block until a named child task exits; returns the child's exit code
- **RevokeCapability**: Revoke a capability held by another process on an endpoint. Phase 3.1 authority = bootstrap Principal only; grantor / holder-of-`revoke`-right / policy service paths land in Phase 3.4. `CapabilityHandle` refactor deferred to post-v1 handle table. See [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md)
- **ChannelCreate**: Allocate a shared-memory channel. Creator specifies size (pages), peer Principal, and role (Producer/Consumer/Bidirectional). Requires `CreateChannel` system capability. Returns ChannelId; writes creator's vaddr to output pointer. See [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md)
- **ChannelAttach**: Attach to an existing channel as the named peer. Kernel verifies caller's Principal matches peer_principal from create. Maps shared pages into peer's address space with role-determined permissions (RO/RW). Returns vaddr
- **ChannelClose**: Gracefully close a channel. Unmaps from both processes, TLB shootdown, frees physical frames. Only creator or peer may call
- **ChannelRevoke**: Force-close a channel (bootstrap authority, Phase 3.1 pattern). Same teardown as close but no caller-identity check
- **ChannelInfo**: Read channel metadata (state, role, sizes, addresses, tick) into user buffer
- **AuditAttach**: Attach as the audit ring consumer. Maps kernel audit ring pages RO into caller's address space. Restricted to bootstrap Principal (Phase 3.3). Returns user vaddr
- **AuditInfo**: Read audit ring statistics (total produced, total dropped, capacity, consumer attached, per-CPU staging occupancy) into a 48-byte user buffer. Any process may call
- **MapFramebuffer**: Maps a Limine-reported framebuffer (selected by zero-based index) into the calling process and writes a 32-byte `FramebufferDescriptor` (vaddr + geometry + pixel format) to a caller buffer. Kernel holds the physical address; userspace never specifies it. Capability-gated (`MapFramebuffer`). Multi-monitor: call once per display. Phase GUI-0 (ADR-011)
- **ModuleReady**: Signals that a boot module has finished initialization (endpoint registration, etc.). Used by sequential boot-time module loading: kernel blocks the next module in `BOOT_MODULE_ORDER` behind a `BlockReason::BootGate` until the current module calls `ModuleReady`. Every boot module's `_start` calls `sys::module_ready()` after setup

## Development Conventions

1. **Every `unsafe` block MUST have a `// SAFETY:` comment** explaining why the operation is safe. This was comprehensively audited — maintain it.

2. **Lock ordering** (see above) must always be followed. Never acquire a lower-numbered lock while holding a higher-numbered one.

3. **Architecture portability:** All x86-specific code must be behind `#[cfg(target_arch = "x86_64")]`. The `src/arch/mod.rs` shim re-exports the active backend. Portable scheduler logic lives in `scheduler/mod.rs`.

4. **Large structs** (Scheduler, IpcManager, CapabilityManager, BuddyAllocator) must be heap-allocated via `new_boxed()` pattern to avoid stack overflow. Boot stack is only 256KB. Scheduler uses Vec/VecDeque internally so only ~128 bytes of metadata lands on the stack.

5. **`no_std` only.** No standard library. No heap allocation before `memory::init()` completes in `main.rs`.

6. **GDT must be `static mut`** (writable .data section) because the CPU writes the Accessed bit.

7. **Never assume zeroed memory equals `None` for `Option<T>`.** Rust does not guarantee the Option discriminant layout — the compiler may assign discriminant 0 to `Some` (not `None`), especially for large structs on bare-metal targets. Always use explicit `core::ptr::write(None)` when initializing heap-allocated arrays of `Option<T>`.

8. **Every numeric bound is a conscious bound.** Fixed `const` numerics, fixed-size arrays, and `MAX_*` values in kernel code must carry a doc comment naming their category: `SCAFFOLDING` (verification ergonomics, expected to grow), `ARCHITECTURAL` (real invariant, won't change), `HARDWARE` (ABI/spec fact), or `TUNING` (workload-dependent). Unconscious bounds — values picked because something fit — are how production-ready software accrues weakness while it's still cheap to fix. The full catalog with rationale and replacement criteria lives in [ASSUMPTIONS.md](ASSUMPTIONS.md). Templates:

```rust
/// SCAFFOLDING: <one-line statement of the constraint>
/// Why: <verification or early-development rationale>
/// Replace when: <observable trigger that should make a future maintainer revisit>
const MAX_FOO: usize = 32;

/// ARCHITECTURAL: <statement of the invariant the constant encodes>
const NUM_PRIORITY_BANDS: usize = 4;

/// HARDWARE: <ABI/spec reference that fixes this number>
const MAX_GSI_PINS: usize = 24;

/// TUNING: <what workload property this number trades off>
const CACHE_CAPACITY: usize = 32;
```

**SCAFFOLDING bounds must be sized for the v1 endgame, not today's workload.** When picking a SCAFFOLDING value, do not pick "the smallest number that works today" with the plan to resize later. Extrapolate forward across the full v1 sequence: Phase 3 (channels, policy service, audit telemetry), Phase 4 (persistent ObjectStore + virtio-blk), Phase 5 (Yggdrasil mesh networking), the init process spawning services from a boot manifest, and per-service state growth as the kernel matures. A bound that is comfortably above today's usage but gets crossed during v1 development is the worst case — it looks fine at review time and silently becomes a bottleneck during the subphases where changing it is most disruptive. The rule:

1. Estimate **(a)** current workload, **(b)** v1 workload after all phases land, **(c)** memory cost at candidate multiples of the v1 estimate.
2. Pick the smallest value where the v1 estimate is approximately **≤ 25% of the bound** AND the memory cost is still comfortable. "≤ 25%" means the bound has ~4× headroom above the v1 estimate — enough that a surprising workload or an unplanned consumer (a new audit channel, a second policy cache) does not push against the wall.
3. Record the math in the row for that constant in [ASSUMPTIONS.md](ASSUMPTIONS.md) — the "Why this number" column should show the v1 workload estimate and the memory cost, not just "big enough."

When you add a new bound or change one, update the matching table in [ASSUMPTIONS.md](ASSUMPTIONS.md) in the same change. Step 8 of the Post-Change Review Protocol lists this as an explicit checklist item.

## Multi-Platform Strategy (x86_64, AArch64, RISC-V)

CambiOS runs on **x86_64** and **AArch64** today, with **riscv64gc** in progress (Phase R-0 build infrastructure done; Phase R-1+ implements the arch backend per [ADR-013](docs/adr/013-riscv64-architecture-support.md)). The architecture abstraction is in place:

### Current Portability Boundary
- `src/arch/mod.rs` — cfg-gated shim that re-exports the active backend
- `src/arch/x86_64/` — all x86-specific code lives here (GDT, SYSCALL/SYSRET, ISR stubs)
- `src/arch/spinlock.rs` — portable spinlock (already arch-independent)
- `src/scheduler/mod.rs` — portable `on_timer_isr()` + `ContextSwitchHint` (no arch dependency)
- `src/scheduler/task.rs`, `timer.rs` — portable (no arch dependency)
- `src/ipc/`, `src/syscalls/mod.rs`, `src/process.rs` — fully portable
- `src/memory/buddy_allocator.rs`, `frame_allocator.rs` — portable (address-space agnostic)

### Arch-Specific Parity Status
| x86_64 Module | Responsibility | AArch64 Status | RISC-V Status |
|---|---|---|---|
| `arch/x86_64/gdt.rs` | GDT + TSS + segment selectors | Done — `arch/aarch64/mod.rs::gdt` shim (EL1/EL0 config, `set_kernel_stack` via TPIDR_EL1) | Phase R-3 — `gdt` shim (no segments; `set_kernel_stack` via PerCpu through `tp` register) |
| `arch/x86_64/syscall.rs` | SYSCALL/SYSRET via MSRs | Done — SVC instruction + ESR_EL1 routing in `sync_el0_stub` | Phase R-3/R-4 — `ecall` instruction + `scause==8` dispatch in unified trap handler; `stvec` install |
| `arch/x86_64/mod.rs` | SavedContext, context_switch, timer ISR, yield_save_and_switch | Done — full assembly: context_save/restore/switch, timer_isr_stub, yield_save_and_switch + yield_inner | Phase R-3 — single trap vector at `stvec`, `scause`-dispatched, sscratch/tp swap on U→S, callee-saved context_switch |
| `interrupts/mod.rs` | x86 IDT setup | Done — AArch64 exception vector table at VBAR_EL1 | Phase R-3 — single S-mode trap vector at `stvec`, scause-dispatched |
| `arch/x86_64/apic.rs` | Local APIC timer + PIC disable + IPI | Done — GICv3 (gic.rs) + ARM Generic Timer (timer.rs) | Phase R-3 — SBI `sbi_set_timer` (no chip driver); SBI `sbi_send_ipi` for IPI |
| `arch/x86_64/tlb.rs` | TLB shootdown via IPI | Done — TLBI broadcast instructions (tlb.rs) | Phase R-3 (local) / Phase R-5 (remote) — `sfence.vma` local; SBI IPI + remote `sfence.vma` (or Svinval `sinval.vma` if available) |
| `interrupts/pic.rs` | 8259 PIC (disabled, legacy) | N/A (no legacy PIC on ARM) | N/A |
| `interrupts/pit.rs` | 8254 PIT (calibration only) | N/A (ARM Generic Timer is direct, no calibration needed) | N/A (timer base frequency comes from DTB `/cpus/timebase-frequency`) |
| `memory/paging.rs` | x86_64 4-level page tables | Done — AArch64 4-level page tables in `memory/mod.rs` | Phase R-2 — Sv48 4-level page tables in shared `memory/mod.rs` paging module (already `#[cfg(not(target_arch = "x86_64"))]` — auto-includes RISC-V; only PTE bit constants differ from AArch64 descriptors) |
| `io/mod.rs` | uart_16550 (x86 port I/O) | Done — PL011 UART (MMIO) | Phase R-1 — NS16550 UART (MMIO at `0x10000000` on QEMU virt; address discovered from DTB on real hardware) |
| `platform/mod.rs` | CR4 feature detection | Done — MIDR_EL1 CPU identification, arch-specific features | Phase R-4 — `misa` CSR for ISA extensions; CPU info from DTB (most M-mode IDs are not S-mode-readable) |
| `arch/x86_64/ioapic.rs` | I/O APIC device IRQ routing | **Gap** — GIC SPI enable exists but not wired into boot path | Phase R-3 — PLIC driver (`arch/riscv64/plic.rs`); `claim()`/`complete()` in trap handler when `scause` indicates external interrupt |
| `arch/x86_64/percpu.rs` | Per-CPU data via GS base | Done — `arch/aarch64/percpu.rs` via TPIDR_EL1 | Phase R-1 — `arch/riscv64/percpu.rs` via `tp` register; `csrrw tp, sscratch, tp` swap on trap entry (analogous to x86 swapgs) |
| **boot adapter** | `boot::limine::populate()` (x86_64 + AArch64) | Same Limine adapter | Phase R-1 — `boot::riscv::populate(dtb_phys)` reads DTB, populates BootInfo, no Limine |

### Rules for New Code
- **Never put arch-specific code in portable modules.** If it touches registers, instructions, or hardware directly, it goes under `src/arch/<target>/`.
- **New arch backends must match the public API** defined by `src/arch/x86_64/mod.rs`: `SavedContext`, `context_switch()`, `timer_isr_inner()`, etc.
- **The AArch64 target triple is `aarch64-unknown-none`** with `linker-aarch64.ld` (`elf64-littleaarch64`).
- **The RISC-V target triple is `riscv64gc-unknown-none-elf`** with `linker-riscv64.ld` (`elf64-littleriscv`). Code model must be `medium` — `medlow` cannot reach the higher-half kernel.
- **Keep the interrupt subsystem portable where possible.** `interrupts/routing.rs` is already arch-independent. The PIC/PIT modules should move under `arch/x86_64/` eventually.
- **Bootloader:**
  - x86_64 / AArch64 — Limine 8.7.0 (UEFI on both, plus BIOS on x86_64).
  - RISC-V — OpenSBI in M-mode (ships with QEMU as `-bios default`) hands a DTB pointer to a custom S-mode boot stub. No Limine on RISC-V (Limine does not support it). See [ADR-013](docs/adr/013-riscv64-architecture-support.md).
- **AArch64 MMIO must be explicitly mapped.** Limine's HHDM on AArch64 only covers RAM. Device MMIO (PL011, GIC) must be mapped into TTBR1 via `early_map_mmio()` at early boot.
- **RISC-V follows generic-first, never board-specific.** Use RISC-V standards (SBI, DTB, PLIC, CLINT, virtio-mmio); discover MMIO addresses from the DTB. No vendor-specific code paths in the core arch backend ([ADR-013](docs/adr/013-riscv64-architecture-support.md) § Strategic Posture).
- **Three-architecture cfg discipline.** Prefer `#[cfg(not(target_arch = "x86_64"))]` when AArch64 + RISC-V share behavior (e.g., the shared paging module). Use positive cfgs for all three only when behavior diverges. When a 3-way cfg block emerges in inline code, factor a portable `arch::` helper instead of carrying three inline arms.

## Platform Gotchas

These are persistent platform/bootloader quirks that any new code in the boot or hardware paths must respect. Status of *features* (what's built vs planned) lives in [STATUS.md](STATUS.md); this section is for things that won't go away.

- **Limine base revision 3 HHDM gap (x86_64):** ACPI_RECLAIMABLE, ACPI_NVS, and RESERVED regions are NOT in the HHDM. `map_acpi_regions()` in `main.rs` explicitly maps small RESERVED regions (≤1MB) and all ACPI regions into the HHDM before ACPI parsing. SeaBIOS puts ACPI tables in RESERVED memory (not ACPI_RECLAIMABLE), so the RESERVED mapping is essential.
- **Limine AArch64 HHDM does NOT map device MMIO.** PL011 UART (0x0900_0000), GIC Distributor (0x0800_0000), and GIC Redistributor (0x080A_0000) must be explicitly mapped into TTBR1 via `early_map_mmio()` before any I/O. Uses bootstrap frames from kernel .bss (physical address found by walking TTBR1 page tables, since kernel statics are NOT in HHDM).
- **Limine AArch64 TCR_EL1.T1SZ too narrow.** Limine sets T1SZ for ~39-bit VA, but HHDM at `0xFFFF000000000000` needs 48-bit. `kmain` widens T1SZ to 16 (48-bit) at early boot.
- **AArch64 QEMU requires GICv3.** Must use `-machine virt,gic-version=3` because the GIC driver uses ICC system registers (GICv3). Default GICv2 causes Undefined Instruction on `mrs ICC_SRE_EL1`.
- **ELF loader doesn't merge overlapping segment permissions.** If two PT_LOAD segments share a page with different permissions (e.g., .text RX and .got RW), the first segment's permissions are used. User-space linker scripts work around this with `ALIGN(4096)` before `.data`. Loader fix is tracked in [STATUS.md](STATUS.md).
- **`SYS_WAIT_IRQ` unregistered-IRQ wake fallback.** Registered device IRQs use targeted single-CPU wake via `TASK_CPU_MAP`. Unregistered IRQs fall back to all-CPU scan with `try_lock()` — if SCHEDULER lock is contended, wake is deferred to the next timer tick. Acceptable; not a bug.

## Common Failure Signatures

Map the error string or symptom you actually observe back to the likely root cause. These pairings exist because the symptom rarely names the invariant it violated — a compiler error or a silent QEMU hang says nothing about "lock ordering" or "HHDM gap."

- **`error[E0152]: found duplicate lang item 'panic_impl'`** → a crate in the dependency tree pulled in `std`. Kernel and userspace modules are both `no_std`; most commonly triggered when a new dependency's default features include `std`. Disable default features on the offender and pick only `no_std`-compatible flags.

- **`link error: undefined reference to 'memcpy'` / `memset` / `memmove`** → new crate missing the `compiler_builtins` `mem` feature, or kernel linker flags lost `-C link-arg=--no-undefined`. Cross-check the failing module's `Cargo.toml` against a working sibling (`user/fs-service`, `user/shell`).

- **QEMU reboots / triple-faults immediately after "booting kernel…"** → IDT not installed yet (any exception before `interrupts::init()` is a triple fault), or the double-fault handler faulted because IST1 isn't pointing at valid memory. Check the boot sequence in [src/microkernel/main.rs](src/microkernel/main.rs) for ordering regressions.

- **AArch64 "Undefined Instruction" exception at `mrs ICC_SRE_EL1`** → QEMU running default GICv2. Must use `-machine virt,gic-version=3`. (Duplicates a Platform Gotcha intentionally — this error text should resolve to its cause from either direction.)

- **Kernel panic "allocation failed" / `GlobalAlloc::alloc` returns null in early boot** → attempted `Box::new` / `Vec::new` before `memory::init()` ran. Move the allocation after init, or pre-allocate a static. The `debug_assert!` at the top of [src/memory/heap.rs](src/memory/heap.rs) will name this directly in debug builds.

- **`#PF` in kernel with CR2 = user vaddr during a syscall** → the user pointer belongs to a process whose page tables aren't currently loaded in CR3 (e.g., kernel reading a peer's channel buffer while in a third process's context). Use the page-walk helpers in [src/syscalls/dispatcher.rs](src/syscalls/dispatcher.rs) rather than dereferencing user pointers directly. *Note: this codebase does not enable SMAP, so `stac`/`clac` is not the cause — don't go looking for it.*

- **QEMU output stops mid-run with no panic, no reboot, no further timer ticks** → a silent hang. Locate the last thing that printed and check the code path immediately after it:
  - *Touched a lock used from an ISR?* → it must use `try_lock()`, not `lock()`. A blocking ISR lock deadlocks the CPU.
  - *Touched lock ordering?* → re-check the [Lock Ordering](#lock-ordering-must-be-followed-to-prevent-deadlock) hierarchy. Acquiring a lower-numbered lock while holding a higher-numbered one freezes the CPU that hits the violation. No runtime "deadlock detected" message is printed — silence *is* the diagnostic.
  - *Touched the timer ISR?* → missing APIC EOI (`apic::write_eoi()`) or GIC EOI means no further timer interrupts fire.
  - *Touched yield / context switch?* → a lock held across `yield_save_and_switch` freezes the next task to try to acquire it.

## Roadmap

What's built, what's in progress, what's planned (including v1 ordering, phase markers, and known issues) all live in **[STATUS.md](STATUS.md)**. Architectural decisions live in the ADRs under [docs/adr/](docs/adr/). This file contains neither — it's the technical reference.

## Required Reading by Subsystem

When working on a subsystem, read its design and implementation docs *before* writing code. This map exists so context doesn't get forgotten between sessions. If a doc is missing from the list it means the subsystem is small enough that the code is the documentation.

| Working on... | Read first | Then |
|---|---|---|
| **Scheduler / context switch / preemption** | [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) | This file's "Lock Ordering" and "Timer / Preemptive Scheduling" sections |
| **IPC control path (256-byte messages)** | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) | `src/ipc/mod.rs`, `src/ipc/interceptor.rs` |
| **IPC bulk path (channels — Phase 3)** | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) (channels are the audit transport) |
| **Capabilities, grant/revoke, delegation** | [ADR-000](docs/adr/000-zta-and-cap.md), [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) | `src/ipc/capability.rs` |
| **Process tables / tier configuration / boot-time object sizing** | [ADR-008](docs/adr/008-boot-time-sized-object-tables.md), [ADR-009](docs/adr/009-purpose-tiers-scope.md) | `src/process.rs`, `src/ipc/capability.rs`, [ASSUMPTIONS.md § Tier policies](ASSUMPTIONS.md) |
| **Policy / `on_syscall` / interceptor decisions** | [ADR-006](docs/adr/006-policy-service.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) | `src/ipc/interceptor.rs` |
| **Audit infrastructure / observability** | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md), [PHILOSOPHY.md](PHILOSOPHY.md) | `src/audit/mod.rs`, `src/audit/buffer.rs`, `src/audit/drain.rs` |
| **Identity / Principal / sender_principal** | [identity.md](identity.md), [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) | [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md) (intent only) |
| **ObjectStore / CambiObject / fs-service** | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md), [ADR-004](docs/adr/004-cryptographic-integrity.md) | `src/fs/mod.rs`, `src/fs/ram.rs`, `user/fs-service/src/main.rs` |
| **Persistent ObjectStore / on-disk format / BlockDevice** | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) | `src/fs/block.rs`, `src/fs/disk.rs`; [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) for the `CambiObject` model the format serializes |
| **Signed ELF loading / cryptographic integrity** | [ADR-004](docs/adr/004-cryptographic-integrity.md) | `src/loader/mod.rs` (`SignedBinaryVerifier`) |
| **User-space services (any new boot module)** | [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) | `user/libsys/src/lib.rs`, an existing service like `user/udp-stack/src/main.rs` as template |
| **Architecture port (RISC-V — in progress, future archs)** | [ADR-013](docs/adr/013-riscv64-architecture-support.md), this file's "Multi-Platform Strategy" section, plan file at `/Users/jasonricca/.claude/plans/melodic-tumbling-muffin.md` | `src/arch/aarch64/mod.rs` as the closest structural reference (single trap vector, `scause`-style dispatch, callee-saved context_switch); `src/boot/mod.rs` for the BootInfo contract a new boot adapter must satisfy |
| **Graphics / compositor / GUI / GPU driver** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) (channels are the surface-buffer transport); graphics stack itself is not built yet (see ADR-011 phased plan) |
| **Input drivers / Input Hub / event wire format / trust tiers** | [ADR-012](docs/adr/012-input-architecture-and-device-classes.md) | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) (Principals and load-bearing identity — signed input devices participate in this model). No code yet; the wire format is the first thing to land when the first input driver ships. |
| **Security review / threat model** | [SECURITY.md](SECURITY.md), [ADR-000](docs/adr/000-zta-and-cap.md), [PHILOSOPHY.md](PHILOSOPHY.md) | All ADRs |
| **"Is X done yet?" / current state** | [STATUS.md](STATUS.md) | — |

## Design Documents

These documents capture architectural decisions that implementation must align with. Pure intent goes in the design docs and ADRs; current implementation status goes in [STATUS.md](STATUS.md).

- **[CambiOS.md](CambiOS.md)** — Source-of-truth architecture document (vision, principles, what CambiOS *is*).
- **[identity.md](identity.md)** — Identity architecture: what identity means in CambiOS, Ed25519 Principals, author/owner model, biometric commitment, did:key DID method, revocation model.
- **[FS-and-ID-design-plan.md](FS-and-ID-design-plan.md)** — Phase intent for identity + storage. Content-addressed ObjectStore, CambiObject model, bootstrap identity, IPC sender_principal stamping. Flows from identity.md.
- **[win-compat.md](win-compat.md)** — Windows compatibility layer design: sandboxed PE loader, AI-translated Win32 shim tiers, virtual registry/filesystem, sandboxed Principal model, target application phases (business → CAD → instrumentation).
- **[PHILOSOPHY.md](PHILOSOPHY.md)** — Why CambiOS exists, the AI-watches-not-decides stance, the verification-first commitment.
- **[SECURITY.md](SECURITY.md)** — Security posture, enforcement table, threat model.
- **[ASSUMPTIONS.md](ASSUMPTIONS.md)** — Catalog of every numeric bound in kernel code with category (SCAFFOLDING / ARCHITECTURAL / HARDWARE / TUNING) and replacement criteria. Anti-drift mechanism for bounds chosen for verification ergonomics.
- **[GOVERNANCE.md](GOVERNANCE.md)** — Project governance, deployment tiers, and scope boundaries. Companion to [ADR-009](docs/adr/009-purpose-tiers-scope.md).
- **[docs/adr/](docs/adr/)** — Architecture decision records. Read the ones in the Required Reading map for the subsystem you're touching. (Run `ls docs/adr/` for the current set; do not cite a range here — it drifts.)

Any work on identity, storage, filesystem, IPC architecture, capabilities, policy, or telemetry must be consistent with these documents. If implementation reveals a design problem, update the design doc *first* — don't silently diverge.

## Verification Strategy

- Trait-based abstractions for property-based verification
- Explicit state tracking via enums (TaskState, etc.)
- Error handling via Result types throughout
- BuddyAllocator is pure bookkeeping (address-space agnostic) for testability
- Unit tests run on host macOS target (`x86_64-apple-darwin`). Current count is derived — run `make stats` or `make test`. Test categories span: portable AArch64 logic, identity/ObjectStore/crypto, signed ELF verifier, capability revocation, tier configuration + kernel object tables, BuddyAllocator reserved-prefix, system capabilities, ProcessId generation counters, audit infrastructure (staging + event types + ring/drain), identity gate (exempt set validation + coverage + minimality), ceiling bounds, BootInfo abstraction, DiskObjectStore + block device. [STATUS.md](STATUS.md) tracks per-subsystem coverage notes.

## Post-Change Review Protocol

After any code change, run through this checklist systematically before considering the change complete.

### Scope triage (do this first)

Running the full 8-step protocol on a typo fix produces fatigue that gets paid in skipped steps later. Decide which tier applies before you start:

- **Small change** — typo, comment prose, whitespace, unused-import removal, local variable rename, STATUS.md note, or documentation-only edit that doesn't touch invariants. Run only **§1 (Build Verification)** and **§8 (Documentation Sync)**. Skip §2–§7.
- **Subsystem change** — anything that touches a module's public API, an `unsafe` block, the lock hierarchy, the syscall ABI, the boot path, a kernel invariant, a cross-cutting concern, or an ADR-worthy decision. Run the **full protocol §1–§8, in order**. This tier is where drift becomes load-bearing.

**When unsure, run the full protocol.** Over-auditing a small change costs minutes; under-auditing a subsystem change costs a deadlock the next maintainer has to debug. If the Stop-and-Ask Gate fired during planning, this is automatically a subsystem change.

### 1. Build Verification
```bash
# Unit tests (host)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Clippy lint pass (catches correctness + style issues beyond warnings)
# Note: not yet -D warnings — 164 pre-existing style lints need a
# dedicated cleanup pass first. Run without -D to check for NEW lints
# introduced by the current change. Once the baseline is clean,
# promote to -D warnings.
cargo clippy --target x86_64-unknown-none 2>&1 | grep "^error\|^warning" | head -20

# Kernel build — x86_64 (debug + release)
cargo build --target x86_64-unknown-none
cargo build --target x86_64-unknown-none --release

# Kernel build — AArch64 (release)
cargo build --target aarch64-unknown-none --release

# QEMU integration (when touching boot/runtime paths)
make run            # x86_64
make run-aarch64    # AArch64
```
All builds and clippy must pass with zero errors. Do not skip any step.

**Flag pre-existing warnings.** Any warning surfaced by `cargo build` / `cargo test` / `cargo clippy` — even pre-existing and unrelated to the current change — must be acknowledged, not silently passed through. Warnings accumulate, and "pre-existing and unrelated" is how technical debt becomes invisible. Two acceptable responses:

- **Tiny and safe → fix it in the same change.** Unused imports, unused variables, dead `let` bindings, trivially redundant casts. These take seconds and clearing them keeps build output clean for the next change.
- **Otherwise → report and track.** Surface the warning explicitly to the user (file:line, warning text, one-line note) and add it to [STATUS.md](STATUS.md)'s "Known issues" section (or another tracked list) so it is not forgotten. Silent pass-through is not acceptable, because build noise is how formal-verification prep and human review lose signal.

### 2. Safety Audit
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariants
- New unsafe code cites what guarantees make it sound (alignment, bounds, aliasing, lifetime)
- No raw pointer dereference without a bounds or null check nearby

### 3. Lock Ordering
Verify no change introduces a lock ordering violation against the canonical hierarchy in the [Lock Ordering](#lock-ordering-must-be-followed-to-prevent-deadlock) section above. **Do not duplicate the hierarchy here** — it drifted once and will drift again. Checklist:
- Lower-numbered locks must be acquired before higher-numbered ones
- `try_lock()` in ISR context is acceptable (already established pattern)
- Holding multiple locks simultaneously requires explicit justification
- If you are *adding or reordering a lock*, trip the Stop-and-Ask gate before editing — lock hierarchy changes are cross-subsystem and formally relevant

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

### 8. Documentation Sync
Docs in this repo are categorized by how they relate to the code, and that determines whether they auto-refresh on a code change. **This step is required, not optional** — stale implementation docs are how priorities get forgotten between sessions.

| Category | Files | Auto-refresh? | Rule |
|---|---|---|---|
| **implementation_reference** | [STATUS.md](STATUS.md), [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ASSUMPTIONS.md](ASSUMPTIONS.md), and any `*.md` colocated with code that documents *current* implementation | **Yes** | If your change moves a subsystem's status (built/in-progress/planned), test count, known issue, implementation detail, or numeric bound, update the matching doc *in the same change*. Set `last_synced_to_code:` in the frontmatter to today's date. |
| **decision_record** | [docs/adr/](docs/adr/) | **Append-only divergence** | The original decision text is immutable history — never rewrite it. If a decision is wrong or superseded, write a new ADR that supersedes it. However, when implementation diverges from the plan described in an ADR (deferred work, changed approach, new information), append a **`## Divergence`** section at the end of the ADR documenting *what* changed and *why*. This keeps the original reasoning intact while ensuring the ADR doesn't silently become fiction. ADRs must NOT contain status info ("X tests passing", "currently implemented in Y") — that drifts. They can name files and structs as a starting point, but never as a current-state claim. |
| **design / source_of_truth** | [CambiOS.md](CambiOS.md), [identity.md](identity.md), [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md), [win-compat.md](win-compat.md), [PHILOSOPHY.md](PHILOSOPHY.md), [SECURITY.md](SECURITY.md), [GOVERNANCE.md](GOVERNANCE.md) | **No** — human only | These describe intent and design, not current state. If implementation reveals a design problem, propose the change to the user; don't silently rewrite. They link to STATUS.md for the implementation status of any phase or feature. |
| **index** | [README.md](README.md), [CLAUDE.md](CLAUDE.md) (this file) | **Light touch** | Update only when the structure changes (new doc, new ADR, new build command, new lock in the hierarchy). Status info goes in STATUS.md, not here. |

**Concrete checklist for the change you just made:**
1. Did this change modify a subsystem listed in [STATUS.md](STATUS.md)'s subsystem table? → Update its row and bump `last_synced_to_code:`.
2. Did this change move a phase forward (e.g., "Phase 3 in progress" → "Phase 3 done")? → Update the Phase markers table.
3. Did this change touch the scheduler? → Re-read [SCHEDULER.md](src/scheduler/SCHEDULER.md) and update if anything in it is now wrong.
4. Did this change introduce a new architectural decision? → Draft a new ADR. Don't bury the decision in code comments. Did this change diverge from an existing ADR's plan? → Append a `## Divergence` entry to that ADR documenting what changed and why.
5. Did this change add or rename a build command, lock, or syscall? → Update CLAUDE.md's Quick Reference / Lock Ordering / Syscall Numbers tables.
6. Did this change resolve a Platform Gotcha in CLAUDE.md or a Known Issue in STATUS.md? → Remove it from the gotcha list (don't leave a `~~strikethrough~~ FIXED` ghost).
7. Did this change cite a doc that doesn't exist yet? → Either create the doc or remove the citation.
8. Did this change add or modify a numeric `const`, fixed-size array, or `MAX_*` bound in kernel code? → Tag it with `SCAFFOLDING` / `ARCHITECTURAL` / `HARDWARE` / `TUNING` per Development Convention 8, and add or update the row in [ASSUMPTIONS.md](ASSUMPTIONS.md). Unconscious bounds are not allowed.
