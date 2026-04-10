<!--
doc_type: implementation_reference
owns: project-wide numeric bound catalog
auto_refresh: required
last_synced_to_code: 2026-04-10
authoritative_for: every fixed numeric bound, fixed-size array, hard limit in kernel code — what kind of bound it is, why this number, and what triggers re-evaluation
-->

# ArcOS Numeric Assumptions

> **The rule:** every arbitrary numeric bound in kernel code must be a *conscious* bound. Not "this is what fit when I wrote it." Not "this looked big enough." Conscious means: I picked this number, I know why I picked it, I know what category it belongs to, and I know what would make me change it.
>
> Unconscious bounds are how production-ready software accrues weakness. ArcOS catches them while it's still early enough to fix them painlessly.

## Why this document exists

The microkernel was deliberately written to be small and verifiable. Verification rewards fixed-size arrays, bounded loops, and statically-knowable limits. Many numeric bounds in the codebase were chosen to make verification ergonomic, not because the number itself is meaningful — `MAX_TASKS = 256`, `MAX_PROCESSES = 32`, `MAX_VMAS = 64`, `[Option<Capability>; 32]`. These are *scaffolding*, and scaffolding that nobody marks as scaffolding becomes load-bearing assumption.

This document catalogs every such bound and forces a category on each: which ones are scaffolding (will change), which are architectural invariants (won't change), which are hardware/ABI facts, and which are tuning knobs that need workload data rather than opinion. The point is *not* to grow the numbers — most of the small ones are correct for now. The point is that future-you can tell at a glance which bounds are deliberate forever versus deliberate for now, and what would trigger revisiting them.

## Categories

| Category | Meaning | Will it change? |
|---|---|---|
| **SCAFFOLDING** | Picked for verification ergonomics or early-development simplicity. The constraint exists because of how the code was built, not because of what the system *is*. | Yes — when the trigger condition fires. |
| **ARCHITECTURAL** | A real invariant of the system. Encodes a structural decision. Changing it means changing what ArcOS is. | No. |
| **HARDWARE** | Imposed by an external ABI, spec, or chip. Bounded by reality outside the codebase. | Only if the underlying spec changes. |
| **TUNING** | Performance knob that depends on workload. Picking a number is meaningless without measurements. | When benchmarks say so, not before. |
| **LEGACY** | Picked early, never revisited, no recorded rationale. **No bound should stay in this category** — every legacy bound is a bug waiting for somebody to discover that the constraint doesn't make sense. Audit them on sight; promote to one of the four real categories or remove the limit. |

## How to mark a bound in code

Every fixed numeric `const`, fixed-size array, and `MAX_*` value in kernel code carries a doc comment that names its category. The format mirrors the existing `// SAFETY:` convention.

**SCAFFOLDING** — full template, three required fields:

```rust
/// SCAFFOLDING: <one-line statement of the constraint>
/// Why: <verification ergonomics or early-development reason>
/// Replace when: <observable trigger that should make a future maintainer revisit>
const MAX_FOO: usize = 32;
```

**ARCHITECTURAL** — single line, no replacement criteria (because the answer is "never"):

```rust
/// ARCHITECTURAL: <statement of the invariant the constant encodes>
const NUM_PRIORITY_BANDS: usize = 4;
```

**HARDWARE** — single line, cite the spec or chip:

```rust
/// HARDWARE: <ABI/spec reference that fixes this number>
const MAX_GSI_PINS: usize = 24;
```

**TUNING** — single line, name the workload variable:

```rust
/// TUNING: <what workload property this number trades off>
const CACHE_CAPACITY: usize = 32;
```

When you add a new bound or change one of these, also update the table below. CLAUDE.md's Post-Change Review Step 8 lists this as an explicit checklist item.

## Catalog

This is the full table. Bounds are grouped by category, and the most-likely-to-bite ones come first within each section.

### SCAFFOLDING — verification or early-development bounds

These are the ones that will need to grow as the system matures. They are correct for the current shape of the kernel but encode no real invariant.

| Constant | Value | Where | Why this number | Replace when |
|---|---|---|---|---|
| `MAX_PROCESSES` | 32 | [src/process.rs:132](src/process.rs#L132) | ProcessDescriptor contains a ~20 KB allocator (bitmap + order map); 32 keeps the table small. Verification arrays sized to this. | A user shell session + a couple of pipes brushes 32. The first time a real `ps` listing is non-trivial, this needs to grow — likely to 256+. Driven by the shell/init work in the v1 roadmap. |
| `MAX_TASKS` (per CPU) | 256 | [src/scheduler/mod.rs:124](src/scheduler/mod.rs#L124), [src/lib.rs:150](src/lib.rs#L150) | Heap-allocated, per-CPU. Originally raised from 32 to support multi-core workloads. | Current workloads sit far below 256. Revisit when a single CPU is regularly seeing >100 active tasks, or when AI inference services start spawning per-request worker tasks. |
| `MAX_CPUS` | 256 | [src/lib.rs:88](src/lib.rs#L88), [src/arch/x86_64/percpu.rs:23](src/arch/x86_64/percpu.rs#L23), [src/arch/aarch64/percpu.rs:23](src/arch/aarch64/percpu.rs#L23), [src/arch/aarch64/gic.rs:30](src/arch/aarch64/gic.rs#L30) | Matches xAPIC 8-bit APIC ID space; statically-sized per-CPU arrays. | x2APIC support (32-bit IDs) or > 256-core targets. Not a v1 concern. |
| `MAX_ENDPOINTS` | 32 | [src/ipc/mod.rs:17](src/ipc/mod.rs#L17) | Matches `MAX_PROCESSES`. Sharded IPC has one shard per endpoint; static array. | When `MAX_PROCESSES` grows, this grows with it. They're a pair. |
| Per-process capability table | 32 | [src/ipc/capability.rs:54](src/ipc/capability.rs#L54) | Bounded set for verification; cache-line-friendly linear scan. | Phase 3 work: the policy service holds one capability per service it mediates, the audit consumer holds one per producer. 32 will get tight fast. |
| Per-endpoint message queue | 16 | [src/ipc/mod.rs:216](src/ipc/mod.rs#L216) | Pre-allocated 32 × 16 × 280 B ≈ 140 KB; conscious memory cap. | Phase 3 audit telemetry channel (ADR-007) will see bursts; first dropped event is the trigger. |
| `MAX_VMAS` (per process) | 64 | [src/process.rs:21](src/process.rs#L21) | One slot per allocated user-space region; bump allocator for vaddrs. | Channels (ADR-005) add shared-memory mappings — every attached channel consumes a VMA slot. The first service that holds 5+ channels is on the edge. |
| `MAX_OBJECTS` (RamObjectStore) | 256 | [src/fs/ram.rs:17](src/fs/ram.rs#L17) | Phase 0 RAM-backed store, fixed-capacity array. | Disappears when persistent ObjectStore (Phase 4) lands — that backend will be dynamically sized. Until then, the first time we want to store >256 objects this is the wall. |
| `MAX_OBJECT_CAPS` | 8 | [src/fs/mod.rs:111](src/fs/mod.rs#L111) | Per-object ACL set; bounded for verification. | If per-object ACL ever gets exercised at scale (group-shared documents), 8 is small. |
| `MAX_MODULES` | 16 | [src/boot_modules.rs:11](src/boot_modules.rs#L11) | Fixed boot module list from Limine. | Currently 7 boot modules; headroom for ~9 more. The init process from the post-v1 roadmap (boot manifest → spawn services) makes this less relevant once it lands. |
| `MAX_NAME_LEN` | 64 | [src/boot_modules.rs:14](src/boot_modules.rs#L14) | Fixed-size buffer for boot module names. | A boot module path > 64 chars. Cheap to grow. |
| `MAX_LOAD_SEGMENTS` | 16 | [src/loader/elf.rs:270](src/loader/elf.rs#L270) | Most ELFs have 3-5 segments; 16 is generous for current binaries. | ELF binaries with > 16 PT_LOAD segments — would only happen for unusual layouts (lots of separate sections forced into separate segments). |
| `MAX_TRUSTED_KEYS` | 4 | [src/loader/mod.rs:241](src/loader/mod.rs#L241) | Bootstrap + a few rotation keys. | First time we have CI builder + your YubiKey + backup key + rotation key, we've used the budget with zero room for new signers. Coming up faster than the other PKI items because CI signing is in the early v1 path. |
| `MAX_USER_BUFFER` | 4096 | [src/syscalls/dispatcher.rs:34](src/syscalls/dispatcher.rs#L34) | Single-syscall arg buffer cap; bounds copy_from_user / copy_to_user. | A user-space service that needs to read or write > 4 KB in one syscall and gets a confusing failure at exactly the boundary. Channels (ADR-005) are the long-term answer for bulk; until then this needs to grow on demand. |
| `MAX_PCI_DEVICES` | 32 | [src/pci/mod.rs:24](src/pci/mod.rs#L24) | PCI bus 0 device table. | Bare-metal target with > 32 devices on bus 0 (typical desktops have ~8-15). Revisit during bare-metal bring-up. |
| `KERNEL_HEAP_SIZE` | 4 MiB | [src/microkernel/main.rs:497](src/microkernel/main.rs#L497) | Sufficient for current Box/Vec allocations; conscious upper bound to make memory accounting easy. | Phase 3 channels + audit ring buffers + larger capability tables will pressure this. First OOM in `Box::new()` is the signal. |
| `HEAP_SIZE` (per process) | 1 MiB | [src/process.rs:146](src/process.rs#L146) | Fixed budget hardcoded into the address layout (`PROCESS_HEAP_BASE + pid * HEAP_SIZE`). udp-stack is already feeling this. | Already pressing on this in udp-stack. The growth path is non-trivial because the value is baked into the per-PID address arithmetic — needs a layout change, not a constant bump. |
| `KERNEL_STACK_SIZE` (per task) | 8 KiB | [src/loader/mod.rs:28](src/loader/mod.rs#L28) | Linux uses 16 KiB; ArcOS uses 8 because syscall handlers are currently shallow. | First deep call chain — recursive ELF verifier, signed-object validator with stack-allocated context, channel teardown that walks process tables. Watch for stack-overflow double-faults landing on IST1. |
| `MAX_FRAMES` (frame allocator) | 524288 | [src/memory/frame_allocator.rs:26](src/memory/frame_allocator.rs#L26) | Bitmap covers 0-2 GiB physical. Bitmap is 64 KiB in `.bss`. | The Dell 3630 target has 16 GiB. The bare-metal bring-up will hit this immediately. The bitmap just needs to grow — a real production blocker, not verification scaffolding. |
| `MAX_PROCESS_MEMORY` (per binary) | 256 MiB | [src/loader/mod.rs:37](src/loader/mod.rs#L37) | ELF verifier hard cap; prevents OOM via crafted binaries. | A legitimate user-space service that needs > 256 MiB. Fine for now. |
| `DEFAULT_STACK_PAGES` (per process) | 16 (64 KiB) | [src/loader/mod.rs:31](src/loader/mod.rs#L31) | Conservative default; existing services fit. | Per-service decision; should become a process descriptor field rather than a constant once different services have different needs. |
| Boot stack | 256 KiB | [src/microkernel/main.rs:129](src/microkernel/main.rs#L129) | Limine StackSizeRequest. Forces large structs onto the heap (already a kernel-wide convention). | Stack overflow at boot. Currently fine because of the heap-allocate-everything-large pattern. |

### ARCHITECTURAL — real invariants

These are *not* arbitrary. Each one encodes a design decision. They should not change unless the design changes.

| Constant | Value | Where | Invariant |
|---|---|---|---|
| Control IPC payload | 256 bytes | [src/ipc/mod.rs:90](src/ipc/mod.rs#L90) | Fixed for verification: kernel reads every byte of every control-IPC message. Bulk data takes a separate path (channels — see [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md)). |
| `NUM_PRIORITY_BANDS` | 4 | [src/scheduler/mod.rs:133](src/scheduler/mod.rs#L133) | Idle / Low / Normal / High+Critical — the priority taxonomy. 4 bands is the design, not a tuning choice. |
| `MIN_BLOCK_SIZE` (heap) | 16 bytes | [src/memory/heap.rs:16](src/memory/heap.rs#L16) | Minimum heap allocation. Below this, free-list metadata costs more than the allocation. |
| `HEAP_ALIGN` | 16 bytes | [src/memory/heap.rs:19](src/memory/heap.rs#L19) | Maximum alignment any allocation needs (matches `max_align_t`). |
| `MIN_ORDER` / `MAX_ORDER` (buddy) | 4 / 19 | [src/memory/buddy_allocator.rs](src/memory/buddy_allocator.rs) | 16 B minimum, 512 KiB maximum allocation. Encodes the buddy allocator's range. |
| `ENTRIES_PER_TABLE` (page table) | 512 | [src/memory/mod.rs:111](src/memory/mod.rs#L111) | x86_64 / AArch64 4-level page tables have exactly 512 entries per level. Hardware-defined but expressed as a structural constant. |
| `Principal::public_key` length | 32 bytes | [src/ipc/mod.rs:40](src/ipc/mod.rs#L40) | Ed25519 public key length. The crypto algorithm is the design decision; 32 is its consequence. Changes only if [identity.md](identity.md) chooses a different crypto primitive (e.g., ML-DSA-65 post-quantum). |
| Lock hierarchy depth | 8 | n/a | The seven-lock hierarchy in [CLAUDE.md § Lock Ordering](CLAUDE.md#lock-ordering). Adding a lock is a deliberate architectural decision, not a number bump. |

### HARDWARE — fixed by external ABI/spec

These are facts about the world. ArcOS has no leverage to change them.

| Constant | Value | Where | Source |
|---|---|---|---|
| `MAX_GSI_PINS` (I/O APIC) | 24 | [src/arch/x86_64/ioapic.rs:55](src/arch/x86_64/ioapic.rs#L55) | Intel I/O APIC has 24 redirection entries. |
| `MAX_DEVICE_IRQ` | 224 | [src/syscalls/dispatcher.rs:31](src/syscalls/dispatcher.rs#L31) | x86 IDT has 256 entries; vectors 0-31 are CPU exceptions, 32-255 are device IRQs and IPIs, top 32 reserved for APIC/IPI. |
| Interrupt routing table size | 224 | [src/interrupts/routing.rs:84](src/interrupts/routing.rs#L84) | Same 224 from the IDT layout above. |
| `GDT_ENTRIES` | 7 | [src/arch/x86_64/gdt.rs:38](src/arch/x86_64/gdt.rs#L38) | Null + kernel CS + kernel SS + user SS + user CS + TSS low + TSS high. SYSRET requires this exact layout. |
| `IST_STACK_SIZE` | 4 KiB | [src/interrupts/mod.rs:437](src/interrupts/mod.rs#L437) | Double-fault handler dedicated stack. The double-fault handler is small; doesn't need more. |
| `MAX_IO_APICS` | 4 | [src/acpi/mod.rs:184](src/acpi/mod.rs#L184) | Realistic upper bound for x86 server hardware. Defensible until somebody hands us a chassis with 5. |
| `SIGNATURE_TRAILER_SIZE` | 72 (64 + 8) | [src/loader/mod.rs:220](src/loader/mod.rs#L220) | Ed25519 signature (64 B) + ARCSIG magic (8 B). Fixed by the on-disk format. |

### TUNING — needs benchmarks, not opinion

These are performance knobs. Picking a number without measurements is guessing. They should change in response to observed workload, not architectural changes.

| Constant | Value | Where | What it trades off |
|---|---|---|---|
| `CACHE_CAPACITY` (per-CPU frame cache) | 32 | [src/memory/frame_allocator.rs:322](src/memory/frame_allocator.rs#L322) | Allocator lock contention vs. per-CPU memory parked unused. Larger = less lock contention, more wasted frames. |
| `REFILL_COUNT` / `DRAIN_COUNT` | 16 / 16 | [src/memory/frame_allocator.rs:326](src/memory/frame_allocator.rs#L326) | Batch size for cache refill/drain — amortizes the global lock cost. |
| `MAX_INDIVIDUAL_PAGES` (TLB shootdown) | 32 | [src/arch/x86_64/tlb.rs:31](src/arch/x86_64/tlb.rs#L31) | Threshold for `invlpg` per-page vs. full CR3 reload. Above 32, full reload is cheaper. Verified empirically by other kernels; not measured for ArcOS. |
| `MAX_OVERRIDES` (ACPI MADT) | 16 | [src/acpi/mod.rs:187](src/acpi/mod.rs#L187) | Realistic firmware override count. |

## Adding or changing a bound

When you add a `const` numeric or fixed-size array to kernel code:

1. **Pick the category.** SCAFFOLDING, ARCHITECTURAL, HARDWARE, or TUNING. If you cannot pick one, that is the signal that you have not thought about the bound enough — that is what this whole document is for.
2. **Add the doc comment.** Use the templates above. SCAFFOLDING requires the three fields (constraint, why, replace-when); the others require one line.
3. **Add a row to the matching table here.** Same level of detail as the other rows.
4. **Bump the `last_synced_to_code:` date in the frontmatter.**
5. **CLAUDE.md Post-Change Review Step 8** lists this as an explicit checklist item — it shows up in the same place that asks you to update STATUS.md.

When you remove a bound or remove a constant entirely, delete its row from this document in the same change.

## What is not in this document

- Memory addresses (HHDM bases, page table layouts, MMIO bases) — those are documented in CLAUDE.md's Memory Layout section because they're tied to the bootloader and architecture, not arbitrary numeric choices.
- Syscall numbers — those are an interface, not a bound.
- Lock ordering numbers (the 1-8 hierarchy) — that's an ordering, not a bound.

## Cross-references

- [CLAUDE.md § Numeric bounds: tagging convention](CLAUDE.md) — the rule, the templates, the post-change checklist
- [STATUS.md](STATUS.md) — current implementation status (where this catalog's bounds actually live in the build)
- [SCHEDULER.md](src/scheduler/SCHEDULER.md) — scheduler implementation reference
- [docs/adr/](docs/adr/) — architectural decisions that are *referenced* by this catalog (especially ADR-005 for the 256-byte payload, ADR-007 for the audit channel pressure on the message queues)
