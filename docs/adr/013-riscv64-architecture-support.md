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

### 2026-04-18 — Phase R-3.e: context-switch primitives (scaffolding for R-3.f)

**What changed.** Replaced the R-1 panic stubs for `context_save` / `context_restore` / `context_switch` / `yield_save_and_switch` in [src/arch/riscv64/mod.rs](../../src/arch/riscv64/mod.rs) with real implementations, added a RISC-V `CpuContext` arm to [src/scheduler/task.rs](../../src/scheduler/task.rs), and wrote real `saved_to_cpu_context` / `cpu_to_saved_context` converters. No consumer is wired yet — these are scaffolding for R-3.f's scheduler integration, which will be the first production caller.

**CpuContext layout.** 16 u64 fields matching the AArch64 shape:
- `s0..s11` (x8/x9/x18..x27) — 12 RISC-V callee-saved registers
- `ra` (x1) — preserved as the caller's post-call PC
- `sp` (x2) — stack pointer
- `pc` — resume PC (set to `ra` at save time so `context_restore` branches back to the instruction after the `call context_save` that reached us)
- `sstatus` — snapshot for forward compatibility with FP dirty-state bits

Total 128 bytes, 8-byte aligned. Offsets documented inline for the asm.

**Explicit context-switch assembly.** Three `global_asm!` entry points following the AArch64 pattern (stp/ldp → sd/ld, `ret` → `ret`, `br x2` → `jr t0`):

- `context_save(ctx: *mut CpuContext)` — stores s0..s11 + ra + sp + `ra` (as pc) + sstatus, then returns normally.
- `context_restore(ctx: *const CpuContext) -> !` — loads the 16 fields back and `jr t0` (saved pc).
- `context_switch(current: *mut, next: *const) -> !` — the save + restore fused.

**Voluntary yield assembly.** `yield_save_and_switch` builds a synthetic SavedContext on the kernel stack (identical layout to what the trap vector would push on preemption) and rides the same restore path. Key differences from the trap-vector save:

1. Masks SIE via `csrci sstatus, 2` before the save, not hardware-implicit.
2. Sets synthetic `sepc = .Lyield_resume` — the post-`sret` landing inside the same function.
3. Sets synthetic `sstatus` with SPP=1 (bit 8) + SPIE=1 (bit 5) via `ori t0, t0, 0x120`. `sret` then pops: mode ← S (from SPP), SIE ← 1 (from SPIE). Lands at `.Lyield_resume` in S-mode with interrupts re-enabled.
4. Saves x1 at offset 8 before the scheduler call → the caller's pre-yield `ra`. After `sret` restores x1 from the (possibly different) SavedContext, the trailing `ret` at `.Lyield_resume` branches back to the kernel path that called `yield_save_and_switch`.

**`yield_inner` Rust handler.** Takes the current SavedContext SP, calls `crate::scheduler::on_voluntary_yield(current_sp)` — which returns `(new_sp, Option<ContextSwitchHint>)` — and applies arch-side per-hart state updates from the hint before returning `new_sp` to the asm. Kernel stack top goes through `gdt::set_kernel_stack` (writes `PerCpu.kernel_stack_top` via `tp+24`). Page-table root update reads current `satp`, compares PPN × 4 KiB against `hint.page_table_root`, and on mismatch writes a new `satp = (MODE=9 Sv48 << 60) | PPN` + `sfence.vma zero, zero`.

**Mapping to SavedContext.** `saved_to_cpu_context` pulls `s0` from `gpr[8]`, `s1` from `gpr[9]`, `s2..s11` from `gpr[18..27]`, `ra` from `gpr[1]`, `sp` from `gpr[2]`, `pc` from `sepc`. The reverse direction zeros the full `gpr[..32]` first then writes only the callee-saved slots — caller-saved registers must not leak values across task resumes.

**Nothing is consumed yet.** No production path calls `context_switch` or `yield_save_and_switch` on RISC-V until R-3.f wires a real `on_voluntary_yield` pathway through the scheduler's portable arm branches (halt/wfi/local_scheduler/local_timer). This is deliberate per the project's "skip test hooks when next step consumes" feedback — the R-3.f scheduler integration is the real consumer, and writing a synthetic two-task test here would be scaffolding we'd throw away when R-3.f lands.

**Verification.** `make check-all` green all three arches. `cargo test --lib --target x86_64-apple-darwin` — 487/487 host tests pass. `make run-riscv64` still reaches the R-3.d milestone unchanged (timer ticks + stdin-fed console RX still observable) — the context-switch primitives are unreachable at this phase.

**How to apply.** R-3.f's scheduler integration will be the first real test of this code. If subtle bugs surface then (register ordering, sstatus bits, sp restore timing), they are intentionally deferred: debugging the layered R-3.e + R-3.f intersection is cheaper than building a synthetic two-task harness here that we'd throw away. The AArch64 scheduler path is the reference for the portable wiring — the RISC-V arch primitives here match its shape pin-for-pin.

### 2026-04-18 — Phase R-3.f: scheduler live, 100 Hz preemption milestone

**What changed.** R-3's capstone — the RISC-V scheduler path is wired end-to-end, kernel-task preemption is observable, and every R-3.a–R-3.e primitive has a production caller. `make run-riscv64` now emits `[R-3.f ping N]` once per quantum from a ping kernel task, with idle `wfi` in between, proving timer-driven round-robin works. The R-3.d console RX path coexists cleanly — stdin-fed bytes land `[R-3 RX] 0xNN` interleaved with ping output.

**Wiring.**

- **Trap handler returns `*mut SavedContext`.** `_riscv_rust_trap_handler` in `src/arch/riscv64/trap.rs` changed from `-> ()` to `-> u64`. The trap vector's asm gained `mv sp, a0` after `call`, so the restore path addresses whatever SavedContext the handler returns. For timer ticks that context may be a *different task's* frame (preemptive switch); for exceptions / external IRQs / non-switching ticks it's the input frame unchanged.
- **`timer_isr_inner` (`src/arch/riscv64/mod.rs`).** New Rust entry point mirroring AArch64's shape: rearms the SBI timer, calls `crate::scheduler::on_timer_isr(current_sp)`, applies `ContextSwitchHint` (kernel stack via `gdt::set_kernel_stack`, satp via `csrw satp + sfence.vma zero, zero` when the root differs), returns `new_sp`. The trap handler's `IRQ_TIMER` arm calls straight through.
- **`scheduler::on_timer_isr` grew a riscv64 arm.** Audit-ring drain + policy-query expiration now fires on hart 0 for RISC-V too — matches x86_64 and AArch64 modulo the percpu accessor (`crate::arch::riscv64::percpu::current_percpu().cpu_id()`).
- **`on_timer_interrupt` deleted from `src/arch/riscv64/timer.rs`.** The R-3.b+c per-tick diagnostic (tick counter + 50-tick println) is gone; `init` and `rearm` remain as the public timer surface.
- **`scheduler_init_riscv64` in `kmain_riscv64`.** Allocates `Scheduler::new_boxed`, calls `init` (implicit idle task = kmain's wfi loop), installs in `PER_CPU_SCHEDULER[0]`; creates `Timer::new(TimerConfig::HZ_100)`, installs in `PER_CPU_TIMER[0]`. No boot-module loading — that's R-4/R-6 scope.

**Observable preemption: the kernel ping task.**

`riscv64_ping_task` is a kernel-mode function — `loop { println!("[R-3.f ping {n}]"); spin_loop × 5M; n += 1; }` — spawned via `spawn_riscv64_ping_task`. That helper:

1. Allocates 4 pages (16 KiB) of kernel stack via `FrameAllocator::allocate_contiguous`, translates to HHDM VA.
2. Builds an initial SavedContext at `stack_top - ISR_FRAME_SIZE`: zeros all GPRs, then fills `gpr[2]=sp=stack_top`, `gpr[3]=current_gp`, `gpr[4]=current_tp`, `sepc=ping_fn_addr`, `sstatus=SPP=1 | SPIE=1`.
3. Registers via `Scheduler::create_isr_task`. On first dispatch the trap vector's restore path pops the synthetic frame; `sret` lands in the ping function at S-mode with SIE re-enabled.

**Surprise fix 1: `percpu::init_bsp(hart_id)` was never called on RISC-V.** The scheduler's `on_timer_isr` reads `PerCpu.cpu_id` through `tp`, and `tp` is the thread-pointer register. Without `init_bsp` setting `tp` to point at `PER_CPU_DATA[0]`, `tp` held a stale OpenSBI-left value (phys `0x8004a000` — inside OpenSBI's M-mode data region). The first timer ISR deref `lw a3, 8(tp)` took a load-access fault from PMP. Fix: call `arcos_core::arch::riscv64::percpu::init_bsp(hart_id)` early in `kmain_riscv64`, right after paging is up and before the trap vector installs.

**Surprise fix 2: kernel tasks must inherit `gp` and `tp` in their initial SavedContext.** Once `init_bsp` fixed the idle path, the next timer tick inside the ping task faulted at `stval=0x8` — because my ping SavedContext zero-initialized every GPR, including `tp`. After `sret` into ping, `tp=0`; on the next preemption the trap vector saved `tp=0` into ping's new frame and handed it to the scheduler, which dereffed `0+8` → load-access fault at phys 0. Fix: snapshot `gp` and `tp` via inline asm when spawning, copy into `gpr[3]` and `gpr[4]` of the initial frame. Every RISC-V kernel task must now inherit the spawner's `gp`/`tp`. Once R-4 adds the U→S `sscratch`/`tp` swap to the trap vector, user tasks will have their own `tp` (whatever the user wants) while the kernel always recovers the PerCpu pointer via `sscratch`.

**Verification.**

- `make check-stable` green (x86_64 + aarch64 release builds unchanged).
- `cargo test --lib --target x86_64-apple-darwin` — **487 pass / 0 fail**.
- `make run-riscv64` observes:
  - `✓ Scheduler + Timer installed on hart 0 (idle task = kmain idle loop)`
  - `✓ Spawned kernel ping task as TaskId(1)`
  - `[R-3.f ping 0]` through `[R-3.f ping 49]` in a 6-second QEMU run — ~8 Hz visible cadence, driven by the 5M-iteration spin plus println latency straddling timer quanta.
  - Stdin `Xy` feed still produces `[R-3 RX] 0x58 ('X')` + `[R-3 RX] 0x79 ('y')` interleaved with ping output — R-3.d path untouched, PLIC and timer IRQs coexist through the shared trap vector.

**Leftover diagnostics (removed when R-4 replaces them).**

- The ping task itself is R-3.f milestone scaffolding — deleted when a real RISC-V user-space driver spawns (R-4+).
- R-3.d's inline UART-RX fallback in `plic::dispatch_pending` still stands; removed once a user-space console driver registers in `INTERRUPT_ROUTER`.

**How to apply.** R-4 picks up from here — add the `sscratch`/`tp` swap front-end to `_riscv_trap_vector` so traps from U-mode correctly flip per-CPU state, extend the ELF loader for `EM_RISCV` (0xF3), and the first user process with `ecall`-based syscalls via libsys replaces the kernel ping task as the scheduler's real workload. R-3 is complete.

### 2026-04-18 — Phase R-4.a: trap vector `sscratch`/`tp` swap front-end

**What changed.** `_riscv_trap_vector` now handles U-mode entry correctly: on `csrrw tp, sscratch, tp`, a non-zero new `tp` indicates a U→S trap, and the vector switches to the kernel stack from `PerCpu.kernel_stack_top`, records the user's `sp`/`tp` into the SavedContext's `gpr[2]` and `gpr[4]` slots, and dispatches. On return, `sstatus.SPP` decides the restore path — SPP=1 restores as before; SPP=0 writes `sscratch = kernel_tp` and restores including the user-valued `tp` and `sp` before `sret`. Existing S→S traps (the R-3.f preemption path) behave identically through a `swap`/`swap-back` pair — verified end-to-end via the kernel ping task and console RX still working.

**Convention.** The existing R-3.f invariant — `tp = kernel_tp`, `sscratch = 0` while kernel executes — is preserved. Before entering U-mode for the first time, the sret-to-U path sets `sscratch = kernel_tp` so the next U→S trap's swap delivers the kernel PerCpu pointer into `tp`. Cleared back to 0 on every S→S return.

**Pieces.**

- [src/arch/riscv64/percpu.rs](../../src/arch/riscv64/percpu.rs) — `PerCpu` grew a `user_sp_scratch: u64` field at offset 40. The trap vector's `sd sp, 40(tp)` on U-entry stashes user sp here because we need it before the full SavedContext is allocated (we haven't switched to the kernel stack yet). `init_bsp` clears both `user_sp_scratch` and `sscratch` (via `csrw sscratch, zero`) so the invariant is established from hart-0 boot.
- [src/arch/riscv64/trap.rs](../../src/arch/riscv64/trap.rs) — trap vector asm rewritten. Entry: swap + branch on origin. From-S: second swap restores `tp`, allocate frame on current sp, save all regs. From-U: stash user sp, load kernel sp, allocate frame, save user_sp/user_tp from scratch sources into gpr[2]/gpr[4]. Shared tail: sepc/sstatus + dispatch. Exit: branch on new `sstatus.SPP` (bit 8 via `andi t1, t0, 0x100`) — to-S restores directly, to-U sets `sscratch = tp` (= kernel_tp) first so the next U→S trap picks up the swap.
- No Rust-side changes to `_riscv_rust_trap_handler` — the handler continues returning the SavedContext pointer, and `mv sp, a0` before the restore tail honors any frame swap.

**Scaffolding note.** The U-mode entry path compiles and the vector is ready, but no U-mode code runs yet — that lands in R-4.b (ELF `EM_RISCV` + libsys `ecall` stubs + `hello-riscv64`). Until then only the S→S path is exercised. R-3.f's regression gate (kernel ping + stdin RX through the shared trap vector) stayed identical on the new code, so the swap infrastructure is inert for the kernel-only workload.

**Verification.**
- `make check-all` green all three arches.
- `cargo test --lib --target x86_64-apple-darwin` — 487/487.
- `make run-riscv64` with stdin feed still produces `[R-3.f ping N]` continuously + `[R-3 RX] 0xNN ('c')` on keypress.

**How to apply.** R-4.b wires the first U-mode code. Checkpoint before trying to sret to user: the `sscratch` invariant must be primed (`sscratch = kernel_tp`) — the process-spawn path that builds a user task's initial SavedContext should set it, just as R-3.f's kernel-ping-spawn set `gp`/`tp`/`sstatus`. The cleanest place is inside `create_isr_task`'s RISC-V user-task variant, or right before the first sret to U.

### 2026-04-18 — Phase R-4.b: hello-riscv64 runs in U-mode

**What changed.** The RISC-V port now executes U-mode code. `make run-riscv64` loads the bundled `hello-riscv64.elf` as a user process, the scheduler dispatches it, `sret` drops it to U-mode, and `ecall` lands back in the kernel's syscall dispatcher. Hello prints `[Module] Hello from boot module (riscv64)!` three times and exits cleanly via `SYS_EXIT`. The full trap-vector U↔S swap from R-4.a is exercised end-to-end.

**Pieces landed.**

- [user/hello-riscv64.S](../../user/hello-riscv64.S) + [user/user-riscv64.ld](../../user/user-riscv64.ld) — minimal U-mode program mirroring `hello-aarch64.S`: `SYS_GETPID` → loop×3 { `SYS_PRINT`; `SYS_YIELD` } → `SYS_EXIT`. Entry at `0x400000`. Built by `clang -target riscv64-unknown-none-elf -march=rv64gc -mno-relax` + `ld.lld`.
- [Makefile](../../Makefile) — `user-elf-riscv64` target; `kernel-riscv64` depends on it so `include_bytes!` always finds the ELF.
- [src/loader/elf.rs](../../src/loader/elf.rs) — `EM_RISCV = 0xF3` added to the `ELF_MACHINE_EXPECTED` cfg match.
- [src/arch/riscv64/syscall.rs](../../src/arch/riscv64/syscall.rs) — `ecall_handler_inner(saved_sp)` extracts `a7` = syscall number and `a0..a5` = args from the SavedContext, resolves current task/process/cr3 from the scheduler, dispatches through the portable `SyscallDispatcher::dispatch`, writes the result back to `a0` (= `gpr[10]`), and bumps `sepc` by 4 so `sret` resumes at the instruction after the `ecall`.
- [src/arch/riscv64/trap.rs](../../src/arch/riscv64/trap.rs) — cause-8 (ECALL from U-mode) arm routes through `ecall_handler_inner` instead of panicking.
- [src/microkernel/main.rs](../../src/microkernel/main.rs) — `HELLO_RISCV64_ELF = include_bytes!(...)`; `spawn_hello_riscv64` calls `loader::load_elf_process` with `DefaultVerifier` (unsigned — signing lands in R-6 with initrd+DTB). `kmain_riscv64` now also calls `init_kernel_object_tables` + `process_table_init` so `ProcessTable` is live before the load.

**Two integration bugs found + fixed.**

1. **`create_process_page_table` left RISC-V user L0s without kernel-half mappings.** On AArch64 with TTBR0/TTBR1 split, user L0 tables are clean by design (kernel lives in TTBR1). On RISC-V there is no TTBR split — the kernel and the active user task share one `satp`. When the scheduler swapped `satp` to hello's fresh L0, L0[256..512] was all zero. Kernel text (mapped via L0[511] in the boot root) became unmapped. The first kernel-side access after the swap (the upcoming trap vector's instruction fetch) faulted silently into an unmapped range. **Fix:** [src/memory/mod.rs](../../src/memory/mod.rs) — `create_process_page_table`'s riscv64 arm now copies the upper half (indices 256..512) from the currently-active `satp` root into the freshly allocated L0 before returning, so every user page table carries kernel-side mappings transitively.

2. **Boot stack sp stayed in its pre-paging physical identity form.** [src/arch/riscv64/entry.rs](../../src/arch/riscv64/entry.rs) computed `sp = &BOOT_STACK + BOOT_STACK_SIZE` before enabling paging, giving the physical address (e.g., `0x80340008`). After `csrw satp`, that sp *still* works — as long as the active satp has L0[0] pointing at the identity gigapage (true of the boot root). But when the scheduler swapped to hello's satp (kernel-half copied, low half zero), the low-identity mapping vanished and the boot-stack sp became invalid. The timer ISR save-path faulted on its first store. **Fix:** entry.rs now adds the VMA–LMA offset (`0xffffffff_00000000` per the linker script) to `sp` right before jumping to `kmain_riscv64`, so the kernel executes on the higher-half VA mapping of BOOT_STACK from day one.

**Scope for R-4.b.**

- No libsys riscv64 ecall stubs yet (`hello.S` uses raw assembly). Landing libsys bindings is a follow-up once a Rust user-space service needs them.
- No per-user-crate `.cargo/config.toml` riscv64 blocks — the ~10 existing user services stay x86_64/aarch64-only until R-6 brings them up with virtio-mmio.
- hello-riscv64 is UNSIGNED; `spawn_hello_riscv64` uses `DefaultVerifier`. Ed25519 signing of RISC-V boot modules is R-6 scope, gated on the DTB/`/chosen/linux,initrd-{start,end}` boot-module delivery path.
- The R-3.f kernel ping task is removed — replaced by hello as the scheduler's observable workload.

**Verification.**

- `make check-all` green across all three arches.
- `cargo test --lib --target x86_64-apple-darwin` — 487/487.
- `make run-riscv64`:
  - `✓ Spawned hello-riscv64 user task as TaskId(1)`
  - `[Module] Hello from boot module (riscv64)!`
  - `[Module] Hello from boot module (riscv64)!`
  - `[Module] Hello from boot module (riscv64)!`
  - (hello exits; scheduler reaps; hart returns to idle wfi)

**How to apply.** R-5 (SMP) is next. The `percpu::init_ap` path is already in place; hart enumeration from DTB + `sbi_hart_start` + per-hart `sscratch=0` + trap vector re-installation per hart are the remaining pieces. R-6 ships virtio-mmio + libsys + real signed boot modules + shell.

### 2026-04-18 — Phase R-5.a: AP bring-up via SBI HSM

**What changed.** Secondary harts wake on RISC-V. `make run-riscv64` now reports `✓ AP hart=1 cpu_idx=1 online` alongside the BSP's init banner — hart 1 runs its own trap vector + timer + scheduler idle loop, and `AP_READY_COUNT` synchronizes hands-off before the milestone print.

**Wiring.**

- [src/arch/riscv64/sbi.rs](../../src/arch/riscv64/sbi.rs) — `sbi_hart_start(hart_id, start_addr_phys, opaque) -> SbiRet` (HSM extension, EID=0x48534D, FID=0). Also `sbi_probe_extension(eid)` for R-5.b.
- [src/boot/mod.rs](../../src/boot/mod.rs) — `BootInfo.harts: [Option<u64>; MAX_HARTS]` (new field) with `push_hart` + `harts()` iterator + `hart_count()`. `MAX_HARTS = 8` SCAFFOLDING.
- [src/boot/riscv.rs](../../src/boot/riscv.rs) — DTB walker's `DeviceKind` enum gains `Cpu`; `/cpus/cpu@N/reg` harvests hart ids; `DtbFacts.harts[8]` fills BootInfo.
- [src/arch/riscv64/entry.rs](../../src/arch/riscv64/entry.rs) — three new pieces:
  - `AP_BOOT_STACKS: [[u8; 16 KiB]; 8]` — per-AP boot stacks in `.bss.ap_boot_stacks`. 128 KiB total; indexed by `cpu_index`.
  - `BOOT_SATP: AtomicU64` — BSP publishes its satp value after `riscv64_fill_boot_page_tables`; APs load it in their pre-paging stub and enter the same address space (identity + HHDM + kernel gigapage shared).
  - `_ap_start` global_asm — AP entry from OpenSBI. Saves `a0 = hart_id` + `a1 = cpu_idx` into `s2/s3` (not `s0/s1` — see bug below), computes `sp` from `AP_BOOT_STACKS[cpu_idx]`, loads `BOOT_SATP`, `csrw satp`, `sfence.vma`, promotes `sp` to higher-half (add `0xffffffff_00000000`), and `jr` to `kmain_riscv64_ap`.
- [src/microkernel/main.rs](../../src/microkernel/main.rs) — `kmain_riscv64_ap(cpu_index, hart_id)` runs `percpu::init_ap` → `trap::install` → `timer::init(100)` → per-hart `Scheduler::new_boxed` + `Timer::new(HZ_100)` into `PER_CPU_*[cpu_idx]` → signals `AP_READY_COUNT` → enables SIE → drops into wfi idle. `start_application_processors` gained a riscv64 branch: iterates `BootInfo.harts`, skips BSP by comparing with `current_percpu().apic_id()`, dispatches `sbi_hart_start` per AP, spins on `AP_READY_COUNT` until every dispatched hart is online.

**Bug found and fixed: `s0 == fp == x8`.** My first AP commit crashed with `hart=0` logged from hart 1. The asm stashed `a0 = hart_id` in `s0`, then later ran `mv fp, zero` (ABI frame-pointer reset). On RISC-V `s0` IS `fp` (same register — `x8`). The `mv fp, zero` overwrote hart_id with 0. BSP had the same latent bug in `_start` but never manifested: BSP always runs as hart 0, so the pre- and post-zero values coincidentally matched. R-5.a surfaced it by having an AP with hart_id = 1. Fix: use `s2`/`s3` for arg preservation in both `_start` and `_ap_start`. Still zeroes `fp` per ABI; the stashed values are in a different register class.

**Milestone output.**

```
  Waking 1 AP(s) via SBI HSM (total harts: 2; _ap_start phys = 0x8020004a)
  → sbi_hart_start(hart=1, cpu_idx=1) dispatched
  ✓ AP hart=1 cpu_idx=1 online
  ✓ 1 AP(s) online (total harts: 2)

Phase R-5.a milestone: SMP live. APs bootstrapped via SBI HSM, each
hart runs its own scheduler + timer. hello-riscv64 ran on BSP (hart 0).

[Module] Hello from boot module (riscv64)!
[Module] Hello from boot module (riscv64)!
[Module] Hello from boot module (riscv64)!
  [Exit] pid=3 task=1 code=0 (reclaimed 0 cap(s), 0 chan(s), heap+vma+pt)
```

The AP idles after init — no cross-hart work scheduled yet (R-6 distributes real drivers). The point R-5.a proves: the hart wakes, its scheduler is live, and it coexists with the BSP cleanly.

**Out of scope for R-5.a.**

- Remote TLB shootdown — lands in R-5.b. Any user-space work that unmaps a page while that page could be cached in another hart's TLB needs cross-hart invalidation. Today the only cross-hart state write is `csrw satp` at first dispatch, and each hart only loads its own process table (no shared user mappings between harts yet).
- `BootProtocol` trait factoring. Plan file called this out for R-5; deferred per ADR-013 open question. Two implementations (Limine MP on x86/aarch64, SBI HSM on RISC-V) converge on the same `PER_CPU_*[idx] + tp + trap vector + timer + scheduler` shape, but the trait is cosmetic — not load-bearing for correctness, and three concrete arches is still a manageable amount of arch-gated code.
- Task migration to APs. `distribute_tasks_to_aps` exists on x86/aarch64 and could run on RISC-V too, but there are no registered user tasks beyond hello and hello lives on BSP.

**Verification.**

- `make check-all` green all three arches.
- `cargo test --lib --target x86_64-apple-darwin` — 487/487.
- `make run-riscv64` — both harts online, hello still completes its 3 prints + exit on BSP.

**How to apply.** R-5.b (next) adds SBI IPI for remote TLB shootdown. `sbi_send_ipi` via the IPI extension, probe for Svinval with `sbi_probe_extension`. The trap vector's `IRQ_SOFTWARE` arm (currently panics) wires through to a hart-local `sfence.vma` on the requested VA range. R-6 ships virtio-mmio + libsys + shell.
