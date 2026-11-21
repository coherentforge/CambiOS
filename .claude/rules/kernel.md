---
paths:
  - "src/**/*"
  - "linker*.ld"
---

# Kernel reference

Sections below hold Development Convention 3, the kernel detail of Conventions 4 and 8, which carry the same force as the rest of the numbered list in the root, and describe kernel state (directory pointers, memory layout). Per-syscall behavior is in [syscalls.md](syscalls.md), the lock hierarchy in [locks.md](locks.md), Convention 6 in [x86_64.md](x86_64.md). Operational rules in the root [CLAUDE.md](../../CLAUDE.md) outrank them when they conflict. Toolchain versions live in [Cargo.toml](../../Cargo.toml) and [rust-toolchain.toml](../../rust-toolchain.toml); linker scripts are `linker.ld` (x86_64) / `linker-aarch64.ld` / `linker-riscv64.ld`. Bootloader is Limine 8.x on x86_64 and AArch64, pinned by `LIMINE_COMMIT` in the [Makefile](../../Makefile); OpenSBI on RISC-V.

## Development Conventions 3, 4 and 8

Convention 3 applies to the kernel tree only. Conventions 4 and 8 are stated in the root CLAUDE.md; the kernel pattern for 4, its reference failure, and the templates for 8 are here. The rest of the numbered list is in the root.

3. **Architecture portability:** All x86-specific code must be behind `#[cfg(target_arch = "x86_64")]`. The `src/arch/mod.rs` shim re-exports the active backend. Portable scheduler logic lives in `scheduler/mod.rs`.

4. **Large structs** (Scheduler, IpcManager, ChannelManager, ClusterManager, BuddyAllocator, BootInfo) must be constructed **in place**, never as a stack local that is then moved. `Box::new(T::new())` is NOT the pattern — it builds all of `T` on the caller's stack first and then copies it into the box. The pattern is `alloc` + field-wise `addr_of_mut!(...).write(...)` + `Box::from_raw` (`IpcManager::new_boxed`, `ClusterManager::new_boxed`, `ChannelManager::new_boxed`) or an in-place initializer into a static (`BootInfo::init_empty_at` via `boot::begin_install`). Boot stacks: 256 KiB on every arch (Limine `StackSizeRequest` on x86_64/aarch64; `BOOT_STACK_SIZE` parity on riscv64). Adjacent memory below a boot or kernel stack is *other data* — an overflow corrupts silently. The 2026-09-14 riscv64 boot rot was exactly this: a 16 KiB riscv64 boot stack, 17–75 KiB stack transients from `Box::new(X::new())` and `BootInfo::empty()`, and `.data` statics (`POLICY_ROUTER`, `AUDIT_RING`) linked just below it reading back as garbage. Scheduler uses Vec/VecDeque internally so only ~200 bytes of metadata lands on the stack.

8. **Numeric bound templates.** The doc comment names the category; the full catalog is [ASSUMPTIONS.md](../../docs/ASSUMPTIONS.md).

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

## Multi-Platform Strategy (x86_64, AArch64, RISC-V)

x86_64, AArch64 and riscv64gc build at every commit ([ADR-013](../../docs/adr/013-riscv64-architecture-support.md) § Tri-Architecture Regression Discipline). Per-module parity status lives in [STATUS.md](../../STATUS.md).

### Portability Boundary (portable modules — no arch code)
`src/scheduler/`, `src/ipc/`, `src/syscalls/mod.rs`, `src/process.rs`, `src/loader/elf.rs` (its machine-type selection, `ELF_MACHINE_EXPECTED`, is the one cfg it carries), `src/memory/buddy_allocator.rs` + `frame_allocator.rs`, `src/arch/spinlock.rs`. This is the list the root Stop-and-Ask bullet "Portable module drift" and [review-protocol.md](../../docs/review-protocol.md) § 4 are checked against. All arch code lives under `src/arch/<target>/`; `src/arch/mod.rs` is the cfg-gated shim.

### Rules for New Code
- **Arch-specific code goes under `src/arch/<target>/`**, never in portable modules.
- **New arch backends match the public API** in `src/arch/x86_64/mod.rs` (`SavedContext`, `context_switch()`, `timer_isr_inner()`, etc.). The closest structural reference for a new backend is `src/arch/aarch64/mod.rs` (single trap vector, `scause`-style dispatch, callee-saved `context_switch`); a new boot adapter satisfies the `BootInfo` contract in `src/boot/mod.rs`.
- **Targets:** aarch64 = `aarch64-unknown-none` + `linker-aarch64.ld`. riscv64 = `riscv64gc-unknown-none-elf` + `linker-riscv64.ld`; code model must be `medium` (`medlow` can't reach higher-half).
- **Interrupt subsystem portable where possible.** `interrupts/routing.rs` is arch-independent; PIC/PIT should eventually move under `arch/x86_64/`.
- **Bootloader:** RISC-V = OpenSBI + custom S-mode stub; no Limine (unsupported). AArch64 device MMIO is not in Limine's direct map; see [platform-gotchas.md](platform-gotchas.md).
- **RISC-V is generic-first.** Discover MMIO via DTB; no vendor-specific paths in the core backend.
- **Three-arch cfg discipline.** Prefer `#[cfg(not(target_arch = "x86_64"))]` when AArch64 + RISC-V share behavior; use positive 3-way cfgs only when behavior diverges; factor an `arch::` helper instead of inline 3-way cfg blocks.

## Architecture (directory layout)

Run `tree -L 2 src/ user/ tools/` for the current layout; file names and purposes drift, so this file doesn't restate them. The non-obvious pieces that *don't* read off the tree:

- **`build.rs`** reads `CAMBIOS_TIER` (default `tier3`) and emits `--cfg tierN` for `src/config/tier.rs`. See [ADR-008](../../docs/adr/008-boot-time-sized-object-tables.md) / [ADR-009](../../docs/adr/009-purpose-tiers-scope.md).
- **Arch split:** the portable modules are the Portability Boundary list above. All arch backends live under `src/arch/<target>/`. `src/arch/mod.rs` is the cfg-gated shim.

Service endpoints are in [userspace.md](userspace.md); `tools/sign-elf/` is in [tools.md](tools.md).

## Memory Layout
- **Kernel heap:** 4MB at HHDM+physical, initialized from Limine memory map
- **Kernel object table region (Phase 3.2a):** contiguous physical region allocated at boot via `FrameAllocator::allocate_contiguous`, HHDM-mapped, holds two page-aligned subregions — `[ProcessDescriptor; num_slots]` and `[Option<ProcessCapabilities>; num_slots]`. Size is determined by `config::num_slots()` × (`size_of::<ProcessDescriptor>() + size_of::<Option<ProcessCapabilities>>()`), rounded up per subregion to a page boundary. Allocated in `init_kernel_object_tables()` in `main.rs` between frame allocator init and GDT setup. **Process descriptors are slot-resident:** every slot holds a `ProcessDescriptor` for the kernel's lifetime, written in place once at boot (`ProcessDescriptor::init_empty_at`, the `BootInfo::init_empty_at` pattern) and carrying an explicit `state: SlotState { Empty, Live }` instead of an `Option` wrapper; `create_process` fills the slot through `&mut` (`init_live`) and `destroy_process` resets it in place (`clear`). A ~12 KiB descriptor never exists by value on a kernel stack (Convention 4; the by-value `create_process` measured 32,856 B on a 32 KiB task stack, 2026-11-09). See [ADR-008](../../docs/adr/008-boot-time-sized-object-tables.md) and `src/memory/object_table.rs`.
- **Per-process heaps (Phase 3.2a):** each process gets a `HEAP_SIZE` (4 MiB) contiguous physical region, allocated on demand in `ProcessDescriptor::init_live` via `FrameAllocator::allocate_contiguous(HEAP_PAGES)` and freed in `handle_exit` via `free_contiguous`. No more `PROCESS_HEAP_BASE + pid * HEAP_SIZE` arithmetic — the physical base is whatever the frame allocator hands out. Kernel still accesses the heap via HHDM (`virt_base = phys_base + hhdm_offset`).
- **User code:** mapped at 0x400000
- **User stack:** top at 0x800000, 64KB (16 pages), grows down
- **Per-process PML4:** kernel half cloned (entries 256..511)
- **HHDM:** Higher Half Direct Map provided by Limine for physical memory access
- **x86_64 HHDM:** `0xFFFF800000000000`
- **AArch64 HHDM:** `0xFFFF000000000000` (QEMU virt RAM starts at 1 GiB)
- **Frame allocator:** bitmap covers 0-2 GiB physical (524288 frames, 64 KB bitmap in .bss)
