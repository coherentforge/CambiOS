# ADR-013: RISC-V (riscv64gc) Architecture Support

- **Status:** Proposed
- **Date:** 2026-04-15
- **Depends on:** [ADR-001](001-smp-scheduling-and-lock-hierarchy.md) (SMP scheduling and lock hierarchy), [ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives — control and bulk), [ADR-009](009-purpose-tiers-scope.md) (Purpose, deployment tiers, and scope)
- **Related:** [src/boot/mod.rs](../../src/boot/mod.rs) (BootInfo abstraction this ADR plugs into), [CLAUDE.md](../../CLAUDE.md) § "Multi-Platform Strategy", plan file at `/Users/jasonricca/.claude/plans/melodic-tumbling-muffin.md`
- **Supersedes:** N/A

## Context

CambiOS has matured two architecture backends — x86_64 and AArch64 — with a clean abstraction boundary. Roughly 85% of the kernel is portable, the arch-specific 15% lives under `src/arch/<target>/` behind a documented public API contract, and the boot path is fully protocol-agnostic via `BootInfo` ([src/boot/mod.rs](../../src/boot/mod.rs)) — the only piece still tied to Limine is application-processor wakeup.

This ADR commits CambiOS to a third backend, **riscv64gc**, in parallel with Phase 4b. The work is sequenced through Phases R-0 through R-6 in the plan file; this ADR records the architecturally load-bearing decisions made before code lands, so future maintainers (and future Claude sessions) can recover the *why* without rereading every commit.

Three things make now the right time to add a third architecture:

1. **The abstraction boundary works.** Two backends are not enough to validate that a contract is a contract; three are. The exercise of fitting RISC-V into the existing `arch/` and `boot/` shapes will reveal whichever assumptions in those shapes are accidentally x86-or-AArch64-specific. Fixing them now — while the kernel is small — is cheaper than fixing them after a graphics stack, a network stack, and a Windows compatibility layer have all consumed those shapes.
2. **The hardware target is undecided.** Bare-metal CambiOS hardware will be project-designed (per the memory note "Build it to work on hardware we design"). Encoding RISC-V support against a generic standards-compliant target now means future CambiOS hardware inherits a working backend rather than waiting on a port.
3. **Phase 4b is concurrent, not blocking.** The two streams touch disjoint code: 4b is persistent storage and a Phase 4a follow-up; RISC-V is `arch/` plus a new `boot/` adapter plus surgical cfg gates. There is no merge-conflict surface area worth managing serially.

The remainder of this ADR records six decisions (bootloader, DTB parsing, paging mode, timer source, interrupt controllers, per-CPU register), one strategic posture (generic-first, never board-specific), and one process commitment (tri-architecture regression discipline). It does not enumerate the implementation sequence — that is the plan file's job.

## Decisions

### Decision 1 — Bootloader: OpenSBI + custom S-mode stub now; CambiOS-native firmware long-term

RISC-V has no equivalent of Limine. The de-facto standard is a two-layer stack: an M-mode firmware (almost universally OpenSBI in production, shipped with QEMU as `-bios default`) loads an S-mode payload (Linux, BSD, or in our case CambiOS) and remains resident to provide the Supervisor Binary Interface (SBI) — a stable ecall-based ABI for things only M-mode can do (timer arming, IPI dispatch, hart start/stop).

**Decision:** CambiOS targets OpenSBI as the M-mode firmware on RISC-V for the foreseeable future. We do *not* write our own M-mode firmware. We do write a minimal S-mode boot stub at [src/boot/riscv.rs](../../src/boot/riscv.rs) that:

- Receives control from OpenSBI in S-mode with `a0 = hart_id` and `a1 = dtb_phys_addr`
- Parses the DTB enough to discover memory regions and core peripheral addresses (UART, PLIC, CLINT)
- Sets up a minimal Sv48 page table establishing identity map plus higher-half direct map (HHDM)
- Writes `satp` to enable paging
- Jumps through a virtual-address trampoline to higher-half `kmain`
- Populates a `BootInfo` via `boot::install()` so the rest of the kernel reads boot data through the existing protocol-agnostic seam

**Why OpenSBI rather than rolling our own M-mode firmware:**

- M-mode firmware is a hardware-quirk absorber, not an interesting design surface for a microkernel project. OpenSBI handles timer extension probing, hart enumeration, console putchar, system reset, RFENCE coordination — and does so portably across QEMU, SiFive silicon, StarFive silicon, T-Head silicon, and unannounced future RISC-V boards. Reimplementing that work would consume calendar time we owe to the kernel.
- The SBI ABI is stable, versioned (currently v2.0), and explicitly designed to be the OS↔firmware interface. Unlike UEFI on x86/ARM (which CambiOS plans to replace, per the camBIOS firmware roadmap), SBI is *not* a complex protocol for OS load — it is a thin syscall-like interface that we use *during normal kernel operation* for a small handful of services. Replacing SBI would mean writing M-mode timer drivers, M-mode IPI machinery, M-mode RFENCE coordination, and PMP/PMA configuration — all infrastructure with no CambiOS-distinguishing properties.
- OpenSBI is reproducible-buildable, audit-friendly (BSD-2-clause C, ~50K lines), and shipped pre-signed by upstream. We can pin a known-good OpenSBI binary the same way we pin a known-good Limine binary.

**Why a custom S-mode stub rather than a generic bootloader (U-Boot, GRUB):**

- The plan-file principle "build it generic, never board-specific" makes any production bootloader a poor fit — they all carry per-board configuration baggage. Our needs are tiny: parse DTB, set up paging, populate `BootInfo`, jump.
- Routing through the existing `boot::` abstraction means *no other kernel code changes* to accommodate RISC-V boot. The S-mode stub is a peer of `boot::limine::populate()`. This is exactly the seam the boot abstraction was designed for ([src/boot/mod.rs](../../src/boot/mod.rs:6-23)).
- A custom stub keeps verification surface area small. U-Boot is ~1M lines of C; our stub is ~500 lines of Rust + assembly with bounded iteration and explicit invariants per the verification convention.

**Long-term posture:**

The camBIOS firmware roadmap (memory note `project_cambios_firmware`) commits CambiOS to its own UEFI replacement long-term. The RISC-V analogue would be a CambiOS-native M-mode firmware replacing OpenSBI. This is **deferred until target CambiOS hardware exists** — there is no reason to build an M-mode firmware for QEMU virt or for someone else's RISC-V board. When the project's own RISC-V hardware lands, the M-mode firmware question reopens. Until then, OpenSBI is the right choice.

### Decision 2 — DTB parsing: hand-rolled, bounded, minimal

OpenSBI hands us the physical address of a DeviceTree Blob (DTB, also called a Flattened Device Tree or FDT). The DTB is a structured binary describing the platform — memory regions, CPU cores, peripheral addresses, interrupt routing, and so on. There is no ACPI on RISC-V; the DTB is the canonical hardware enumeration mechanism.

**Decision:** the RISC-V boot stub includes a hand-rolled DTB parser (~250 lines, in [src/boot/riscv.rs](../../src/boot/riscv.rs)) that reads only the nodes the kernel needs:

- `/memory@*` — usable physical memory regions, mapped to `BootInfo::push_memory_region()` as `MemoryRegionKind::Usable`
- `/chosen` — initrd start/end if present (boot modules), `stdout-path` for console identification
- `/cpus` — hart identifiers and `timebase-frequency` for timer calibration
- Reserved-memory regions — the DTB itself, OpenSBI's address range (`0x80000000`–`0x80200000` on QEMU virt), our own kernel image range; all marked `MemoryRegionKind::Reserved`

Parsing follows the verification convention: bounded iteration (`MAX_DTB_NODES`, `MAX_DTB_DEPTH`), every variable-length read returns `Result`, no recursion, no panics. The parser is pure — it consumes a `&[u8]` and produces a `BootInfo`, with no side effects.

**Why hand-roll rather than use the `fdt` crate:**

- The `fdt` crate is well-tested but gives us a full DTB parser as a dependency — far more capability than we use. CambiOS's verification posture treats every external dependency as audit work owed; the `fdt` crate would land us tens of thousands of lines of parsing code under our trust boundary for the savings of a few hundred lines of writing.
- The minimum viable parser is small. The DTB binary format is straightforward: a header, a string table, and a token stream of `BEGIN_NODE` / `END_NODE` / `PROP` / `NOP` / `END`. A bounded recursive-descent parser fits in 250 lines including error handling.
- Hand-rolling forces familiarity with the format. RISC-V is the project's third architecture; the DTB is going to come up again — for runtime device discovery on future CambiOS RISC-V hardware, for ARM SBC support, for anything else that reuses the FDT format. Owning the parser is cheaper over the project's lifetime than depending on a crate that may eventually need a fork anyway.

The parser may be promoted to `src/dtb/` (out of `src/boot/riscv.rs`) when a second consumer appears.

### Decision 3 — Paging mode: Sv48

RISC-V S-mode supports four paging modes selectable via the `MODE` field in `satp`: `Bare` (no translation), `Sv39` (3 levels, 39-bit VA, 512 GiB address space), `Sv48` (4 levels, 48-bit VA, 256 TiB), and `Sv57` (5 levels, 57-bit VA, 128 PiB). All use 4 KiB base pages with optional megapage (2 MiB) and gigapage (1 GiB) leaves.

**Decision:** CambiOS targets Sv48 on RISC-V.

**Why Sv48:**

- Structural parity with x86_64 4-level paging and AArch64's existing 4-level Sv48-equivalent. CambiOS's shared paging module ([src/memory/mod.rs:60+](../../src/memory/mod.rs#L60)) already operates on a 4-level model under `#[cfg(not(target_arch = "x86_64"))]` — RISC-V slots in directly with only the PTE bit encoding differing from AArch64's descriptor format.
- 256 TiB of virtual address space is comfortably above any v1 workload and matches the address-space model the rest of the kernel assumes (HHDM at `0xffff_8000_0000_0000`-class offsets, kernel at `0xffff_ffff_8000_0000`).
- Sv48 is the universally-supported "real workload" paging mode on RISC-V hardware with MMUs. Sv39 exists for very small embedded systems; Sv57 exists for hyperscalers. CambiOS is targeting general-purpose computing across deployment tiers (per [ADR-009](009-purpose-tiers-scope.md)), which is squarely Sv48 territory.

**Fallback:** if the Sv48 boot trampoline proves disproportionately fiddly during Phase R-1, we may temporarily land Sv39 as a stepping stone (smaller address space, identical structure minus one level). This is recorded as a risk in the plan file. The fallback is purely transitional — production CambiOS RISC-V is Sv48.

### Decision 4 — Timer: SBI ecall (`sbi_set_timer`), not direct CLINT MMIO

RISC-V supervisor-mode software has two ways to arm a per-hart timer: program the M-mode CLINT (Core Local Interruptor) MMIO directly, or call SBI's `sbi_set_timer` ecall and let M-mode do it.

**Decision:** CambiOS uses `sbi_set_timer`. The standard `time` CSR (readable from S-mode) gives us the current tick count; `sbi_set_timer(time + reload)` arms the next interrupt. Per-hart timer interrupt enable is via the `STIE` bit in `sie`.

**Why SBI rather than direct MMIO:**

- CLINT addresses and layouts vary across implementations. SBI normalizes this — the same code runs on QEMU virt, on SiFive silicon, on hypothetical future CambiOS RISC-V hardware, without per-platform CLINT bring-up code.
- The SBI Timer Extension is a stable, versioned interface. Direct CLINT access requires us to know whether we're running on a system with SSTC (Supervisor-mode Timer extension), which would let us arm the timer from S-mode without an ecall — but at the cost of an SSTC capability probe and a per-platform code path. Until SSTC is universal on CambiOS-relevant hardware, the SBI path is simpler.
- SBI also gives us `sbi_send_ipi` for cross-hart interrupts, used by Phase R-5 TLB shootdown. Reusing the same ABI for both is consistency we should not give up casually.

When CambiOS-native RISC-V hardware exists and we have eliminated OpenSBI in favor of a CambiOS M-mode firmware, this decision reopens — at that point we own both layers and direct CLINT/SSTC access becomes attractive.

### Decision 5 — Interrupt controllers: PLIC for devices, CLINT for timer + IPI

RISC-V splits interrupt handling between two MMIO units:

- **CLINT** (Core Local Interruptor) — per-hart timer interrupt and software interrupt (used for IPIs)
- **PLIC** (Platform-Level Interrupt Controller) — external (device) interrupts, routed to harts via priority-based claim/complete

**Decision:** CambiOS uses PLIC for device IRQs (network, block, console input) and CLINT-via-SBI for timer and IPIs. PLIC driver lives at [src/arch/riscv64/plic.rs](../../src/arch/riscv64/plic.rs); CLINT operations are mediated through SBI per Decision 4 and so do not need a dedicated CLINT driver.

The PLIC operations CambiOS needs are minimal: `init()` (mask all sources, set hart context threshold to 0), `enable_irq(source_id, hart_context)` (set the per-hart enable bit), `claim() -> u32` (read claim register inside the trap handler when `scause` indicates external interrupt), `complete(source_id)` (write completion). All other PLIC features — preemption, priority levels, per-source priority tuning — are unused; CambiOS's interrupt model treats all device IRQs as equal-priority and dispatches via [src/interrupts/routing.rs](../../src/interrupts/routing.rs).

This matches CambiOS's existing pattern: AArch64 uses GICv3 with a similarly minimal driver surface; x86_64 uses APIC + IOAPIC ditto. The interrupt-routing layer is portable; the controller drivers are arch-specific and small.

### Decision 6 — Per-CPU pointer: `tp` register, swapped via `sscratch` on U→S trap

Every CambiOS arch needs a fast way to get from "current execution context" to the per-CPU `PerCpu` struct, including from inside a trap handler before the kernel stack is established. x86_64 uses GS base; AArch64 uses TPIDR_EL1.

**Decision:** RISC-V uses the `tp` (thread pointer, x4) register as the per-CPU pointer in S-mode. The RISC-V ABI reserves `tp` for thread-local storage and the compiler will not clobber it. On U→S trap entry, the trap handler executes `csrrw tp, sscratch, tp` — atomically swapping the user's `tp` with the kernel's per-CPU pointer that was pre-stashed in `sscratch`. On S→U return, the swap is reversed.

This is structurally identical to x86_64's `swapgs` mechanism: a CSR holds the kernel pointer while the user holds its own value in the GPR; a single instruction swaps them on the privilege boundary. AArch64 uses a different model (TPIDR_EL1 always holds the kernel pointer because user space cannot read it from EL0 without going through a system register), but the RISC-V `tp` is user-readable, so the swap is necessary.

`PerCpu` shape matches the existing AArch64 layout — `self_ptr`, `cpu_id`, `hardware_id` (here `hart_id`), `kernel_stack_top`, `current_task_id`, `interrupt_depth`. Every arch's `PerCpu` should keep this shape so portable code reads it uniformly.

## Strategic Posture: Generic-First, Never Board-Specific

The plan file commits to "generic first, board-specific never" for RISC-V. This ADR makes the same commitment formal: CambiOS RISC-V code targets *RISC-V standards*, not any specific board's quirks.

Concretely:

- **No SiFive-isms, no T-Head-isms, no StarFive-isms.** No code path keyed on a vendor's MIDR-equivalent CSR.
- **DTB-driven device discovery, no hardcoded MMIO addresses in code.** Even the QEMU virt UART address (`0x10000000`) is a default the boot stub uses only if the DTB does not name it; the DTB-named address always wins.
- **Standards-compliant transport: virtio-mmio (not vendor-specific), PLIC (not vendor extensions), SBI (not direct CLINT).** Where a RISC-V standard exists, we use it.

The reasoning is the bare-metal target: CambiOS's eventual RISC-V hardware will be project-designed and will conform to RISC-V standards by construction. Generic code is the code that runs on it. Code carrying a vendor's quirk burden is code we'd have to delete before bringing up our own silicon.

Where a board *requires* nonstandard handling, that handling lives in a future device-specific overlay (analogous to how Linux uses DTS overlays per board), not in the core arch backend. No such overlays exist today; if one becomes necessary, a follow-up ADR records the boundary.

## Process Commitment: Tri-Architecture Regression Discipline

Two backends could be sustained by occasionally running the other one. Three cannot.

**Decision:** `make check-all` builds all three kernels (x86_64, AArch64, riscv64) and is **mandatory** before every commit and as a CI gate when CI exists. Any commit that breaks any architecture is rejected. There is no "fix it on the next pass" — there is no next pass, because by the time the second arch breaks the first one has already drifted.

The Makefile target was added in Phase R-0:

```
make check-all      # builds all three
make check-x86      # x86_64 only
make check-aarch64  # AArch64 only
make check-riscv64  # riscv64 only
```

This ADR also commits to two structural conventions that reduce the cost of three backends:

- **Negated cfg when AArch64 + RISC-V share behavior.** The paging module at [src/memory/mod.rs:60](../../src/memory/mod.rs#L60) already uses `#[cfg(not(target_arch = "x86_64"))]` for the 4-level Sv48-class implementation that both ARM and RISC-V want. This pattern auto-includes RISC-V without modification. Where all three diverge, use positive cfgs for all three.
- **When a 3-way cfg block emerges, factor.** Two-arch inline-asm cfg blocks become noisy at three. The right time to factor `arch::interrupts_enable()`, `arch::read_page_table_root()`, `arch::wait_for_interrupt()` helpers is when the third arm appears, not after the noise has accumulated.

## Implementation

The execution sequence is recorded in the plan file at `/Users/jasonricca/.claude/plans/melodic-tumbling-muffin.md`, not duplicated here. Phase markers (R-0 through R-6) appear in [STATUS.md](../../STATUS.md) as they land.

Critical files to be created (full list in the plan):

- [src/arch/riscv64/](../../src/arch/riscv64/) — backend implementing the contract documented in [src/arch/mod.rs](../../src/arch/mod.rs) (mirror of [src/arch/aarch64/](../../src/arch/aarch64/))
- [src/boot/riscv.rs](../../src/boot/riscv.rs) — S-mode boot stub, DTB parser, Sv48 boot page table setup, populator for `boot::install()`
- [linker-riscv64.ld](../../linker-riscv64.ld) — already created in Phase R-0
- [user/hello-riscv64.S](../../user/hello-riscv64.S), [user/user-riscv64.ld](../../user/user-riscv64.ld) — user-space entry templates

## Consequences

**Positive:**

- Three-architecture support with the kernel's existing portability ratio preserved (target ≥85%).
- Validates the `arch/` and `boot/` abstractions against a third independent backend — anywhere they accidentally encoded x86 or ARM assumptions becomes visible and fixable.
- Establishes RISC-V as a first-class CambiOS target, ready to absorb future project-designed RISC-V hardware without a port phase.

**Negative:**

- Build matrix triples. CI cost, local-test cost, and reviewer cognitive load all grow. The `make check-all` discipline plus the negated-cfg pattern keep this manageable but do not eliminate it.
- No bare-metal RISC-V validation possible until target hardware exists. All RISC-V testing is QEMU virt for the foreseeable future. This is acknowledged and acceptable given the "CambiOS-designed hardware" target — but it does mean RISC-V cannot claim "boot-tested on real silicon" for v1.
- Adds a long-running concurrent workstream against the v1 roadmap. Phase R-N progress tracking lands in [STATUS.md](../../STATUS.md) as each milestone passes.

**Reversibility:**

- The decision is reversible at any phase boundary by deleting `src/arch/riscv64/`, `src/boot/riscv.rs`, the linker script, and the four cfg gates added to lib.rs / main.rs / io / loader. No data structures change; no portable code is rewritten in a RISC-V-specific way. The build infrastructure additions (rust-toolchain target, .cargo/config.toml block, Makefile targets) are inert when removed.

## Open Questions

- **`riscv` crate vs hand-rolled CSR access.** Deferred to Phase R-1 when the first CSR write is written. Hand-rolled is leaning, for verification transparency matching how AArch64 accesses TPIDR_EL1 / VBAR_EL1 / SPSR_EL1 directly via inline asm. Decision recorded inline in `src/arch/riscv64/mod.rs` when made.
- **`BootProtocol` trait.** AP wakeup is currently Limine-specific in [src/microkernel/main.rs](../../src/microkernel/main.rs)'s `start_application_processors()`. Phase R-5 forces the third arm in; at that point we choose between adding a third inline arch arm or factoring a `BootProtocol` trait. The trait would benefit camBIOS long-term anyway. Decision deferred to Phase R-5 review.
- **Eventual M-mode firmware.** OpenSBI is the right choice for now. Whether CambiOS eventually replaces it with a CambiOS-native M-mode firmware (the RISC-V analogue of replacing UEFI) reopens when CambiOS-designed RISC-V hardware exists. No work required before that.

## Divergence

### 2026-04-16 — Phase R-1 ships in low-memory layout; Sv48 trampoline deferred to R-2

**What changed.** Phase R-1 was originally scoped to deliver the serial-banner milestone *with* the Sv48 boot page table trampoline that establishes the HHDM and switches the kernel from its physical load address to a higher-half mapping at `0xffffffff80000000`. The plan file flagged this trampoline as "the single hardest piece of Phase R-1" and listed an explicit fallback in Risk #1: "If Sv48 proves hard, fall back temporarily to Sv39 ... or run without paging." During implementation we took the simpler half of that fallback: **R-1 runs with paging disabled, kernel linked at `0x80200000` (= the OpenSBI handoff address) physical = virtual.** [linker-riscv64.ld](../../linker-riscv64.ld) carries the Phase R-1 layout; [src/arch/riscv64/entry.rs](../../src/arch/riscv64/entry.rs) does *not* set up Sv48 page tables, only a boot stack and the call into Rust. The `_start` → `kmain_riscv64` → `halt` path runs entirely in physical address space.

**Why.** The Sv48 trampoline is a self-contained piece of work that naturally co-locates with frame-allocator init and the shared paging module's RISC-V PTE bit constants — all of which are Phase R-2 deliverables. Front-loading it into R-1 would have made R-1 substantially larger without unblocking anything (the banner-milestone goal doesn't need paging). Splitting it into R-2 keeps R-1's testable surface narrow (boot stack + UART driver + Rust entry) and lands paging in the phase where the rest of the memory subsystem is being built.

**How to apply.** Phase R-2 now owns: (a) the Sv48 boot page table trampoline (identity map for the boot path + HHDM + higher-half kernel map), (b) the `satp` write that enables paging, (c) the linker script revision putting VMA at `0xffffffff80000000` with LMA via `AT(0x80200000)`. The shared paging module work in [src/memory/mod.rs](../../src/memory/mod.rs) (RISC-V PTE bit constants, `satp`-based `active_page_table()`) was already R-2 scope; the trampoline joins it.

This deviation is reversible — restoring the original "Sv48 in R-1" plan would only require swapping the linker script and adding the boot trampoline. No Phase R-1 code becomes wrong; the entry stub and `kmain_riscv64` continue to work unchanged once paging is added underneath them.

### 2026-04-16 — Pre-existing TryRecvMsg dispatch bug surfaced and fixed during R-1

**What changed.** Adding the third architecture forced a fresh-cache build of the kernel crate, which surfaced an existing non-exhaustive-match error: `SyscallNumber::TryRecvMsg = 37` had been added to [src/syscalls/mod.rs](../../src/syscalls/mod.rs) but never wired to a dispatcher arm. The bug was hidden on x86 and AArch64 by stale incremental compilation — both arches *also* failed on a clean build. Fixed in [src/syscalls/dispatcher.rs](../../src/syscalls/dispatcher.rs) by adding a `handle_try_recv_msg` non-blocking handler (mirrors `handle_recv_msg` minus the block-and-yield loop; returns `Ok(0)` on empty queue).

**Why this matters for the ADR.** The fix is unrelated to the RISC-V port itself but the port surfaced it, which is exactly the kind of cross-arch-discipline outcome ADR-013 § Process Commitment ("Tri-Architecture Regression Discipline") predicts. Recording it here so future sessions reading this ADR understand why a pre-existing dispatcher arm appeared in the same change set as the RISC-V scaffolding.

### 2026-04-16 — Phase R-2 landing notes (Sv48 trampoline, DTB overlay model, portable reservation pass, R-2.d deferral)

**Phase R-2 delivered** the full memory subsystem — Sv48 boot page table trampoline, higher-half kernel at `0xffffffff80200000`, hand-rolled DTB parser, frame allocator + kernel heap init, `Box::new` end-to-end round-trip. Four points worth recording for future maintainers:

**(1) Boot trampoline — long jump to higher-half.** The `_start` assembly in [src/arch/riscv64/entry.rs](../../src/arch/riscv64/entry.rs) calls a Rust helper (`riscv64_fill_boot_page_tables`) to populate the three static page tables (1 L3 root, 1 L2_IDENTITY shared between L3[0] and L3[256] for HHDM, 1 L2_KERNEL with a single gigapage at L2[510] for the kernel map). It then writes `satp` and does the transition via a `.quad kmain_riscv64` in `.rodata` — loading the absolute VMA `0xffffffff802XXXXX` through a PC-relative-addressable physical load *before* paging flips on, then `jr`ing to that loaded address *after* `satp` + `sfence.vma`. `la kmain_riscv64` would not reach — the 32-bit pcrel displacement from physical `0x80200000` can't span to `0xffffffff802XXXXX`. This idiom should be reused for any future boot-time jump to higher-half on RISC-V.

**(2) DTB "full RAM + overlay reservations" model conflicts with existing heap init.** Limine delivers separate non-overlapping Usable/non-Usable regions; the x86/AArch64 `init_kernel_heap` happily picks the largest Usable and starts allocating at its base. The RISC-V DTB path populates BootInfo as "4 GiB Usable region + overlay reservations for OpenSBI / DTB / kernel image" — if `init_kernel_heap` picks `0x80000000` as base it collides with OpenSBI's PMP-protected range and the heap init's first write traps to a zero `stvec`, hanging the boot. Fixed by making `init_kernel_heap` overlay-aware: sort non-Usable overlays by base, skip past each, or clamp to the first gap large enough to hold the heap. Added a parallel pass in `init_frame_allocator` that reserves every non-Usable region as a belt-and-suspenders. Both are *portable improvements* — no-ops on x86/AArch64 today, and naturally correct when a future boot adapter chooses to emit BootInfo in either shape.

**(3) FDT field-order bug in our parser surfaced during R-2.b.** First implementation read `size_dt_struct` at header offset 32 and `size_dt_strings` at offset 36. Per Devicetree Spec v0.4 §5.2 the assignment is reversed: offset 32 is `size_dt_strings`, offset 36 is `size_dt_struct`. Our sanity check (`strings_end <= totalsize`) then failed because we were adding the struct-block size to the strings offset. Fixed and documented inline; the comment above the header read now calls out the easy-to-swap ordering explicitly. No observable behaviour change for valid DTBs — if the spec-defined offsets are read correctly, the parser advances through the whole blob without issue.

**(4) R-2.d (shared paging module RISC-V PTE arm) deferred.** The plan scoped R-2 to include "RISC-V PTE bit constants in shared paging module, `satp`-based `active_page_table()`." Neither is consumed in R-2 itself — the boot trampoline has its own hardcoded PTE bits (legitimately so; it runs pre-paging), the frame allocator doesn't touch PTEs, and the kernel heap uses HHDM (already mapped). The consumers of the shared paging module are `early_map_mmio()` (Phase R-3 for PLIC) and process page-table creation (Phase R-4). Per the project's "skip test hooks when next step consumes" feedback memory, we do not add compile-only arms ahead of their first real consumer. R-3 and R-4 will add the RISC-V PTE encoding to `src/memory/mod.rs` when they land. This deviation is recorded in the STATUS.md R-phase track with pointer to this note.

### 2026-04-16 — Phase R-3.a: shared paging module split into per-arch PTE helpers

**What changed.** Phase R-3 ("Interrupts + preemptive scheduling") is large (~1400 new lines across trap vector, SBI timer, PLIC, context switch, scheduler integration). It is being executed as sub-phases R-3.a through R-3.f. **R-3.a** is the load-bearing first sub-phase: the shared paging module at [src/memory/mod.rs](../../src/memory/mod.rs) was written for AArch64 but gated `#[cfg(not(target_arch = "x86_64"))]`, which silently auto-included RISC-V. Any RISC-V code calling into the shared paging module today would have written AArch64 descriptor bits into Sv48 page tables. Safe only because no RISC-V consumer existed in R-1 or R-2. The first consumer was about to land in R-3.d (PLIC MMIO via `early_map_mmio`). Rather than fix it inline, R-3.a did the Option 2 refactor from the plan-file ("cleanest refactor: hoist PTE-bit-related constants and barrier sequences into a tiny arch helper, keep the main paging module truly shared").

**Factoring shape.** Arch-specific pieces — PTE bit constants, leaf/table construction, validity/table predicates, address extraction, post-mapping barrier, page-table-root reads, and `early_map_mmio` — moved to per-arch modules:

- [src/arch/aarch64/paging.rs](../../src/arch/aarch64/paging.rs) — AArch64 descriptor bits (`DESC_VALID`, `DESC_TABLE`, `DESC_AF`, `DESC_ISH`, `DESC_AP_*`, `DESC_ATTR_*`, `DESC_PXN`, `DESC_UXN`, `ADDR_MASK`) and the `DEVICE_MEMORY_FLAG` sentinel that `make_leaf_pte` translates into MAIR AttrIndx.
- [src/arch/riscv64/paging.rs](../../src/arch/riscv64/paging.rs) — Sv48 PTE bits (`PTE_V/R/W/X/U/G/A/D`, PPN mask `((1<<44)-1)<<10`), `active_root`/`kernel_root_phys` reading `satp`, `barrier_map` using `sfence.vma zero, zero`, per-VA flush via `sfence.vma va, zero`.

The shared module at [src/memory/mod.rs](../../src/memory/mod.rs) kept: walk logic (`walk_to_l3`, `walk_to_l3_readonly`), `read_entry`/`write_entry` via HHDM, all L0–L3 index extractors (identical 9/9/9/9/12 split across AArch64 and Sv48), `map_page`/`unmap_page`/`map_range`/`translate`/`create_process_page_table`/`free_process_page_table`/`reclaim_process_page_tables`, the 3-frame bootstrap pool, `kernel_virt_to_phys` (walking a root phys the caller supplies), and a new `early_map_mmio_arch(pa, root_phys, make_leaf, flush)` driver that each arch's `early_map_mmio` calls with closures for the arch-specific leaf PTE and TLB flush.

**Public API unchanged.** All 40+ call-sites across `process.rs`, `loader/mod.rs`, `syscalls/dispatcher.rs`, and `microkernel/main.rs` still speak `paging::flags::user_rw()`, `paging::active_page_table()`, `paging::early_map_mmio()`, etc. The flags submodule is re-exported from `crate::arch::paging::flags`.

**MMIO attribution on RISC-V: PMA, not Svpbmt.** AArch64 uses the `DEVICE_MEMORY_FLAG` internal bit-62 sentinel to pick MAIR AttrIndx=0 (Device-nGnRnE). RISC-V's analog would be Svpbmt's PBMT=IO (bits 62:61). We intentionally leave Svpbmt bits zero and trust the hart's Physical Memory Attribute table to mark MMIO regions strongly-ordered. QEMU virt has PMA correctly configured by construction; CambiOS-designed RISC-V hardware will own PMA configuration as a hardware-design concern. If a future target platform has a permissive default PMA, this is where Svpbmt enters — as a probe against `misa` plus conditional bits in `make_leaf_pte`.

**Verification.** `make check-all` green across x86_64 + aarch64 + riscv64. `cargo test --lib --target x86_64-apple-darwin` runs all 447 tests clean. AArch64 `make run-aarch64` boots through PL011 + GIC + timer + all 6 user-space service modules to the shell prompt — `early_map_mmio`'s behavior is preserved end-to-end. RISC-V `make run-riscv64` still hits its Phase R-2 milestone (Sv48 + DTB + heap + `Box::new`) unchanged — no RISC-V consumer of the new helpers yet, first lands in R-3.d (PLIC).

**How to apply.** Future work that adds page-table functionality — the RISC-V process model in R-4, userspace MMIO mapping on RISC-V, any framebuffer / virtio-mmio mapping — now has a clean seam: extend the `pte_*` / `make_*` / `flags::*` surface in the per-arch `paging.rs`, not the shared walk code. If a third type of mapping (beyond normal and device) ever becomes necessary, add it uniformly across both arches' `flags` submodules. The `early_map_mmio_arch` shape also generalizes — if an arch later needs a different *kind* of early mapping (e.g. cache-coherent DMA regions distinct from MMIO), add a second shared driver alongside, keep closures per-arch.

### 2026-04-16 — Phase R-3.b+c: trap vector + SBI timer (kernel-mode entry only)

**What changed.** Landed the RISC-V trap handler and SBI-mediated 100 Hz timer in one commit. Milestone: `make run-riscv64` runs past the R-2 boot banner, installs `stvec`, arms the SBI timer, enables `sstatus.SIE`, and the idle `wfi` loop emits `[R-3 tick N]` diagnostic lines every 500 ms — observable proof that trap entry/exit, `scause` dispatch, and SBI ecalls all work end-to-end.

**Scope sized for the first consumer, not the R-4 endgame.** The plan file and R-3 header called for a trap handler with `sscratch`/`tp` swap on U→S entry. That logic is **deferred to R-4** when its first consumer (user processes) lands. The current trap vector is *kernel-mode-entry only*: on entry, `sp` is already the kernel stack, `tp` is already the kernel per-CPU pointer, and we simply allocate `ISR_FRAME_SIZE` (288 bytes) on `sp`, save x1 + x3..x31 + sepc + sstatus, call `rust_trap_handler`, restore, and `sret`. This keeps the first trap-handler commit ~150 lines of asm instead of ~400. Per the project's "skip test hooks when next step consumes" feedback memory, we do not build the U-mode swap before R-4.

**Guard rail:** the trap handler panics on `ECALL from U-mode` (scause=8) and any page fault, preventing a silent stack corruption if anything tries to enter U-mode before R-4 extends this vector. The `rust_trap_handler` body explicitly enumerates the 16 RISC-V scause codes and pairs each with a diagnostic panic message — the only non-panicking paths today are `IRQ_TIMER` (rearms + logs) and, in the future, `IRQ_EXTERNAL` (PLIC in R-3.d) / `IRQ_SOFTWARE` (IPI in R-5).

**Landing pieces.**

- [src/arch/riscv64/trap.rs](../../src/arch/riscv64/trap.rs) — `_riscv_trap_vector` assembly (via `global_asm!`, 16-byte aligned, section `.text.trap`), `rust_trap_handler`, `install()` (writes `stvec` MODE=0), `enable_interrupts()` (sets `sstatus.SIE`).
- [src/arch/riscv64/sbi.rs](../../src/arch/riscv64/sbi.rs) — hand-rolled SBI ecall wrappers. Uses the legacy SET_TIMER extension (EID=0, FID=0) which is universally supported and simpler than the v2.0 TIME extension split-register form. `read_time()` shim around `csrr time`.
- [src/arch/riscv64/timer.rs](../../src/arch/riscv64/timer.rs) — replaced the R-1 stub with real implementation. `init(hz)` reads `BootInfo::timer_base_frequency_hz`, computes `RELOAD = base / hz`, enables `sie.STIE`, arms first interrupt. `rearm()` issues `sbi_set_timer(time + reload)`. `on_timer_interrupt()` bumps a tick counter and emits the R-3.b+c milestone diagnostic every 50 ticks (500 ms). Removed when R-3.f wires the scheduler.
- [src/boot/mod.rs](../../src/boot/mod.rs) — added `timer_base_frequency_hz: Option<u32>` to BootInfo. Unconditional; populated by boot adapters that have authoritative knowledge (RISC-V DTB parser), left `None` elsewhere (x86 calibrates APIC via PIT at runtime; AArch64 reads CNTFRQ_EL0 directly).
- [src/boot/riscv.rs](../../src/boot/riscv.rs) — DTB walker extended to track `/cpus` ancestor alongside `/memory@*`, and capture `timebase-frequency` (emitted as a `u32` at `/cpus` on QEMU virt and every standards-compliant RISC-V platform). The existing per-depth `in_memory_stack` pattern gained a parallel `in_cpus_stack`.
- [src/microkernel/main.rs](../../src/microkernel/main.rs) — `kmain_riscv64` grew a trap-install → timer-init → SIE-enable → `wfi` idle loop sequence between the R-2 `Box::new` smoke and the former halt.

**Observed behaviour.** QEMU virt reports timebase-frequency = 10 MHz (standard), so `reload = 100_000` ticks per 100 Hz interval. The diagnostic line every 50 ticks shows the `time` CSR advancing monotonically, with between-line deltas ~6.1 M ticks instead of the "ideal" 5 M — the difference is printf/serial-write latency inside the ISR, which is acceptable for a boot-diagnostic path and will go away in R-3.f once the scheduler replaces the per-tick logging.

**How to apply.** When R-4 wires user processes, extend [src/arch/riscv64/trap.rs](../../src/arch/riscv64/trap.rs)'s `_riscv_trap_vector` with a front-end that tests `sstatus.SPP`, swaps `tp` with `sscratch` on U→S, and loads the kernel stack from `tp + PerCpu::kernel_stack_top` — same shape as the AArch64 vector's `SPSel` toggle. The existing kernel-mode body below remains the trailer. When R-3.d wires the PLIC, replace the `IRQ_EXTERNAL` panic with a claim/complete + portable IRQ-router dispatch. When R-3.f lands the scheduler, replace `on_timer_interrupt`'s diagnostic print with a call into `crate::scheduler::on_timer_isr` and remove the tick-counter module-level state (or keep it behind a debug feature).

### 2026-04-18 — Phase R-3.d: PLIC driver + DTB-driven discovery + console RX proof

**What changed.** Landed the RISC-V PLIC driver, rewired the trap handler's `IRQ_EXTERNAL` arm from its R-3.b+c panic guard rail to real claim/complete dispatch through the portable `crate::INTERRUPT_ROUTER`, and closed the loop with the first observable device IRQ: NS16550 console RX. Feeding bytes into QEMU's stdio UART now produces `[R-3 RX] 0xNN ('c')` lines on serial, proving every link in the chain — UART → PLIC → S-mode trap → claim → router lookup → inline fallback → complete — works end-to-end.

**DTB-driven MMIO discovery.** The walker (`src/boot/riscv.rs`) was refactored off the earlier parallel-boolean-stack pattern (`in_memory_stack`, `in_cpus_stack`) onto a single `DeviceKind` enum per depth. That made it cheap to add `/soc` / `/soc/plic@*` / `/soc/serial@*` recognition alongside the existing `/memory@*` and `/cpus` paths. The walker now collects four facts in one pass into a `DtbFacts` struct that `populate()` drains into BootInfo: memory regions, `timebase-frequency`, `plic@*/reg` (PLIC MMIO base + size), and `serial@*/interrupts` (console IRQ source ID). No hardcoded MMIO addresses in the kernel — QEMU virt's `0x0c00_0000` PLIC base and IRQ 10 for the UART come out of the DTB at boot. Matches ADR-013 § Strategic Posture (generic-first, DTB-driven).

**BootInfo additions.** Unconditional fields in the shared `BootInfo` struct:
- `plic_mmio: Option<(u64, u64)>` — `(phys_base, size_bytes)`, populated only by the RISC-V adapter.
- `console_irq: Option<u32>` — primary UART's IRQ source ID.

x86_64 (Limine) and AArch64 (Limine) populators leave both `None`. No cfg nesting; the optionality is the contract.

**PLIC driver shape** (`src/arch/riscv64/plic.rs`, ~280 lines). Register layout follows the SiFive/QEMU virt standard: priority stride 4 B per source, enable-bitmap stride 0x80 per context, context control stride 0x1000 starting at 0x20_0000. Public surface: `init(phys_base, size)` maps the region via `early_map_mmio` (see gigapage fix below), zeros all priorities 1..`MAX_SOURCES`=128, clears the hart-0 S-mode context's enable bitmap, sets threshold=0, and sets `sie.SEIE`. `enable_irq` / `disable_irq` arm a source at priority 1 + flip its enable bit. `claim` and `complete` are single-word MMIO accesses. `dispatch_pending` is the loop that drains every pending source in one trap: claim → `crate::INTERRUPT_ROUTER.try_lock()` → `lookup(IrqNumber(source_id as u8))` → if routed, log (R-4 wires IPC wake); if source matches the registered console IRQ, inline-read via `crate::io::read_byte()` and log; else "no handler" + complete.

**`early_map_mmio` gigapage fix.** The first boot attempt panicked with `load access fault @ stval=0xffff_8000_8000_0008` mid-PLIC-init. Root cause: the RISC-V boot trampoline (`src/arch/riscv64/entry.rs`) populates the HHDM with four 1 GiB gigapages at L1[0..4] under L0[256], covering `[0, 4 GiB)` of phys space. R-3.a's shared `early_map_mmio_arch` walks every level top-down expecting tables; when it hit the L1 gigapage it misclassified as "unmapped" and tried to allocate a bootstrap frame to replace it, destroying the entire low-4-GiB HHDM and taking the kernel's next read with it.

The fix: **RISC-V `early_map_mmio` is now a bounded-check no-op**. The boot trampoline already covers every MMIO region QEMU virt exposes (PLIC `0x0c00_0000`, NS16550 `0x1000_0000`, CLINT `0x0200_0000`, virtio-mmio `0x1000_1000`, ECAM `0x3000_0000`) via those gigapages, and device-memory attribution is the PMA table's job, not a PTE attribute (ADR-013 § Decision 5). The AArch64 `early_map_mmio` still uses the shared driver — Limine's HHDM on AArch64 excludes MMIO so it has to. Divergence is intentional: arch-specific because the boot-HHDM shape diverges.

A consequence: if a future CambiOS RISC-V hardware target has MMIO above 4 GiB, the fix lives in the boot trampoline (add gigapages) rather than in `early_map_mmio`. The bounded check in the no-op returns an explicit error pointing at `entry.rs` so future-me knows where to look.

**NS16550 RX-IRQ wiring** (`src/io/mod.rs`). Added `Ns16550::IER` register constant (offset 1) and `IER_ERBFI` bit (Enable Received Data Available Interrupt, bit 0). New function `io::enable_console_rx_irq()` — RISC-V-only, takes the SERIAL1 lock, writes `IER_ERBFI` to IER. After kmain calls this, every byte arriving in the RHR asserts IRQ 10 on the PLIC.

**Trap-handler rewire** (`src/arch/riscv64/trap.rs`). The `IRQ_EXTERNAL` match arm now calls `plic::dispatch_pending()` under the enclosing `unsafe` instead of panicking. `stval` is intentionally unused (it's zero for external IRQs on RISC-V).

**Verification.** `make check-stable` (x86_64 + aarch64) green. 487 host tests pass. `make run-riscv64` boots past the R-2 + R-3.b+c milestones, prints `[R-3 tick N]` at 500 ms cadence, and — on stdin feed — emits `[R-3 RX] 0x58 ('X')` / `[R-3 RX] 0x79 ('y')` exactly at the bytes fed. Timer ticks continue uninterrupted across the external IRQs, demonstrating the two interrupt paths coexist (STIE and SEIE both active, trap vector dispatches cleanly on `scause` bit 63 + cause code).

**How to apply.** When R-4 wires the first RISC-V user-space driver (likely fs-service via virtio-mmio), register the driver's TaskId in `crate::INTERRUPT_ROUTER.register(IrqNumber(X), task, priority)`. The PLIC's `dispatch_pending` will then route via the existing IPC wake path instead of falling through to the inline console-RX diagnostic. The inline path in [src/arch/riscv64/plic.rs](../../src/arch/riscv64/plic.rs)'s `dispatch_pending` (the branch matching `CONSOLE_IRQ`) is a R-3.d milestone scaffold marked for removal when a real console driver registers.

When Phase R-5 brings up APs, generalize `HART0_S_CONTEXT` (currently a hardcoded `1`) to compute `hart * 2 + 1` per target hart, or read context-to-hart mapping from the DTB's `/soc/plic/interrupts-extended` property (which lists `<phandle> <irq>` pairs per context).
