<!--
doc_type: implementation_reference
owns: project-wide numeric bound catalog
auto_refresh: required
last_synced_to_code: 2026-04-15 (KERNEL_STACK_SIZE bump 8 KiB \u2192 32 KiB)
authoritative_for: every fixed numeric bound, fixed-size array, hard limit in kernel code — what kind of bound it is, why this number, and what triggers re-evaluation
-->

# CambiOS Numeric Assumptions

> **The rule:** every arbitrary numeric bound in kernel code must be a *conscious* bound. Not "this is what fit when I wrote it." Not "this looked big enough." Conscious means: I picked this number, I know why I picked it, I know what category it belongs to, and I know what would make me change it.
>
> Unconscious bounds are how production-ready software accrues weakness. CambiOS catches them while it's still early enough to fix them painlessly.

## Why this document exists

The microkernel was deliberately written to be small and verifiable. Verification rewards fixed-size arrays, bounded loops, and statically-knowable limits. Many numeric bounds in the codebase were chosen to make verification ergonomic, not because the number itself is meaningful — `MAX_TASKS = 256`, `MAX_VMAS = 64`, `[Option<Capability>; 32]`. These are *scaffolding*, and scaffolding that nobody marks as scaffolding becomes load-bearing assumption.

Phase 3.2a (ADR-008) removed one of the most prominent scaffolding bounds — `MAX_PROCESSES = 32` — by replacing it with a runtime-computed `num_slots` derived from the tier policy and available RAM. That's the template for how the other SCAFFOLDING bounds here should eventually move: pure-function sizing from a policy + hardware measurement, clamped so the verifier can still reason about the result symbolically.

This document catalogs every such bound and forces a category on each: which ones are scaffolding (will change), which are architectural invariants (won't change), which are hardware/ABI facts, and which are tuning knobs that need workload data rather than opinion. The point is *not* to grow the numbers — most of the small ones are correct for now. The point is that future-you can tell at a glance which bounds are deliberate forever versus deliberate for now, and what would trigger revisiting them.

## Categories

| Category | Meaning | Will it change? |
|---|---|---|
| **SCAFFOLDING** | Picked for verification ergonomics or early-development simplicity. The constraint exists because of how the code was built, not because of what the system *is*. | Yes — when the trigger condition fires. |
| **ARCHITECTURAL** | A real invariant of the system. Encodes a structural decision. Changing it means changing what CambiOS is. | No. |
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
| `MAX_TASKS` (per CPU) | 256 | [src/scheduler/mod.rs:126](src/scheduler/mod.rs#L126), [src/lib.rs:157](src/lib.rs#L157) | Heap-allocated, per-CPU. Originally raised from 32 to support multi-core workloads. | Current workloads sit far below 256. Revisit when a single CPU is regularly seeing >100 active tasks, or when AI inference services start spawning per-request worker tasks. |
| `MAX_CPUS` | 256 | [src/lib.rs:91](src/lib.rs#L91), [src/arch/x86_64/percpu.rs:23](src/arch/x86_64/percpu.rs#L23), [src/arch/aarch64/percpu.rs:23](src/arch/aarch64/percpu.rs#L23), [src/arch/aarch64/gic.rs:30](src/arch/aarch64/gic.rs#L30) | Matches xAPIC 8-bit APIC ID space; statically-sized per-CPU arrays. | x2APIC support (32-bit IDs) or > 256-core targets. Not a v1 concern. |
| `MAX_ENDPOINTS` | 32 | [src/ipc/mod.rs:22](src/ipc/mod.rs#L22) | Historically matched `MAX_PROCESSES` (one endpoint per service). Sharded IPC has one shard per endpoint; static array. | `MAX_PROCESSES` is gone as of Phase 3.2a — the process table now scales with tier policy. This endpoint cap should eventually move too (tie it to `config::num_slots()` or a new `MAX_ENDPOINTS_PER_SLOT * num_slots()` computation). First Phase 3 service that needs >32 endpoints is the trigger. |
| Per-process capability table | 32 | [src/ipc/capability.rs:59](src/ipc/capability.rs#L59) | Bounded set for verification; cache-line-friendly linear scan. | Phase 3 work: the policy service holds one capability per service it mediates, the audit consumer holds one per producer. 32 will get tight fast. |
| Per-endpoint message queue | 16 | [src/ipc/mod.rs:242](src/ipc/mod.rs#L242) | Pre-allocated 32 × 16 × 280 B ≈ 140 KB; conscious memory cap. | Phase 3 audit telemetry channel (ADR-007) will see bursts; first dropped event is the trigger. |
| `MAX_VMAS` (per process) | 256 | [src/process.rs:33](src/process.rs#L33) | One slot per allocated user-space region; bump allocator for vaddrs. Sized for v1 endgame graphics compositor ([ADR-011](docs/adr/011-graphics-architecture-and-scaling.md)): ~50 VMA entries (3 framebuffer mappings + 6 scanout channels + 30 window surfaces + GPU MMIO + command/memory channels + heap + stack), 4× headroom per CLAUDE.md Convention 8. Memory cost: ~6 KiB per VmaTracker (was 1.5 KiB at 64). | Bumped 2026-04-13 from 64 in the Phase GUI-0 prep pass. Next revisit: the first service holding 50+ simultaneous channel mappings (texture-heavy GPU workloads, multi-compositor split-brain). |
| `MAX_OBJECTS` (RamObjectStore) | 256 | [src/fs/ram.rs:22](src/fs/ram.rs#L22) | Phase 0 RAM-backed store, fixed-capacity array. Still in place as a fallback / test fixture after Phase 4a.i; `DiskObjectStore` is the persistent backend. | Retire `RamObjectStore` entirely once `DiskObjectStore` is the runtime default (Phase 4a.iii hot-swap). |
| `MAX_OBJECTS_ON_DISK` | 4096 | [src/fs/disk.rs:48](src/fs/disk.rs#L48) | Ceiling for `DiskObjectStore` slot count ([ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md)). Sized for v1 endgame: human-scale workload (identity attestations, documents, social log entries) expected ~1000 objects → 4× headroom. Memory cost at full capacity: ~200 KiB (BTreeMap + FreeMap). On-disk cost: 4096 × 8 KiB per slot + 4 KiB superblock = ~32 MiB. Format itself is u64-addressable; this is the runtime clamp. | Phase 5 (social attestations) or Phase 7 (SSB federation) push object count toward ~1000. At that point bump to 16384 or 65536; verify heap budget (~800 KiB / ~3 MiB) and on-disk footprint (~128 MiB / ~512 MiB). |
| `MAX_CONTENT_BYTES_ON_DISK` | 4096 | [src/fs/disk.rs:55](src/fs/disk.rs#L55) | Max content bytes per stored object in the Phase 4a format. Equals `BLOCK_SIZE` — one block per content. Matches the existing syscall-side `MAX_USER_BUFFER` ceiling. | Phase 4b channel-based bulk IPC raises the syscall ceiling; bumping the on-disk limit requires a new format version (multi-block content). Track as a coordinated change. |
| `MAX_WAIT_ITERATIONS` (VirtioBlkDevice poll) | 10000 | [src/fs/virtio_blk_device.rs:59](src/fs/virtio_blk_device.rs#L59) | Upper bound on yield iterations the kernel's `VirtioBlkDevice::call` spends polling `SHARDED_IPC.shard[25]` for a reply from the user-space virtio-blk driver. On real NVMe/AHCI a single I/O is microseconds; 10000 × 100 Hz ≈ 100 s of scheduler-quantum budget is far more headroom than any real request needs, but short enough to fail loudly rather than hang forever on a dead driver. | Switching to interrupt-driven virtio-blk completion removes the polling path entirely — at that point this constant disappears with it. |
| `MAX_OBJECT_CAPS` | 8 | [src/fs/mod.rs:111](src/fs/mod.rs#L111) | Per-object ACL set; bounded for verification. | If per-object ACL ever gets exercised at scale (group-shared documents), 8 is small. |
| `MAX_MODULES` | 16 | [src/boot_modules.rs:11](src/boot_modules.rs#L11) | Fixed boot module list from Limine. | Currently 7 boot modules; headroom for ~9 more. The init process from the post-v1 roadmap (boot manifest → spawn services) makes this less relevant once it lands. |
| `MAX_NAME_LEN` | 64 | [src/boot_modules.rs:14](src/boot_modules.rs#L14) | Fixed-size buffer for boot module names. | A boot module path > 64 chars. Cheap to grow. |
| `MAX_LOAD_SEGMENTS` | 16 | [src/loader/elf.rs:270](src/loader/elf.rs#L270) | Most ELFs have 3-5 segments; 16 is generous for current binaries. | ELF binaries with > 16 PT_LOAD segments — would only happen for unusual layouts (lots of separate sections forced into separate segments). |
| `MAX_TRUSTED_KEYS` | 4 | [src/loader/mod.rs:258](src/loader/mod.rs#L258) | Bootstrap + a few rotation keys. | First time we have CI builder + your YubiKey + backup key + rotation key, we've used the budget with zero room for new signers. Coming up faster than the other PKI items because CI signing is in the early v1 path. |
| `MAX_USER_BUFFER` | 4096 | [src/syscalls/dispatcher.rs:40](src/syscalls/dispatcher.rs#L40) | Single-syscall arg buffer cap; bounds copy_from_user / copy_to_user. | A user-space service that needs to read or write > 4 KB in one syscall and gets a confusing failure at exactly the boundary. Channels (ADR-005) are the long-term answer for bulk; until then this needs to grow on demand. |
| `MAX_PCI_DEVICES` | 32 | [src/pci/mod.rs:24](src/pci/mod.rs#L24) | PCI bus 0 device table. | Bare-metal target with > 32 devices on bus 0 (typical desktops have ~8-15). Revisit during bare-metal bring-up. |
| `MAX_MEMORY_REGIONS` (BootInfo) | 128 | [src/boot/mod.rs:51](src/boot/mod.rs#L51) | Boot-protocol-agnostic kernel-owned memory map size (populated by `boot::limine::populate`). QEMU reports ~10-15; bare-metal firmwares ≤ several dozen. 128 covers all realistic firmwares with margin. Memory cost: 128 × ~24 B ≈ 3 KiB in .bss. | Real firmware reports >128 entries (would indicate badly-fragmented memory worth investigating regardless). Landed 2026-04-14 as part of the [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) Limine→camBIOS abstraction. |
| `MAX_FRAMEBUFFERS` (BootInfo) | 8 | [src/boot/mod.rs:60](src/boot/mod.rs#L60) | Kernel-owned framebuffer list; boot adapter populates. Matches [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) multi-monitor target of 3+ displays with ~2× headroom. Memory cost: 8 × ~40 B ≈ 320 B. | Workstation deployments with >8 active displays (uncommon even for pro rigs). |
| `MAX_BOOT_MODULES` (BootInfo) | 16 | [src/boot/mod.rs:69](src/boot/mod.rs#L69) | Mirrors the runtime `BootModuleRegistry::MAX_MODULES` used by the spawn syscall. BootInfo holds the boot-protocol view; registry holds the spawnable view. | Tied to boot-module count growth — see `MAX_MODULES` row. |
| `MAX_MODULE_NAME_LEN` (BootInfo) | 64 | [src/boot/mod.rs:72](src/boot/mod.rs#L72) | Fixed-size module-name buffer in BootInfo. Must equal [`crate::boot_modules::MAX_NAME_LEN`] so strip-then-register round-trips cleanly. | A boot module path > 64 chars after stripping (see `MAX_NAME_LEN` row). |
| `FB_DESC_SIZE` (SYS_MAP_FRAMEBUFFER wire format) | 32 | [src/syscalls/dispatcher.rs handle_map_framebuffer](src/syscalls/dispatcher.rs) | ARCHITECTURAL: v1 framebuffer descriptor ABI — `{vaddr:u64, width:u32, height:u32, pitch:u32, bpp:u16, red/green/blue mask sizes+shifts, reserved}`. Mirrored by `libsys::FramebufferDescriptor`. Changing this is a new syscall + capability, not a size bump. See [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md). | Intentionally never — this is the boundary every future compositor / GPU driver speaks. |
| `MAX_CHANNELS` | 256 | [src/ipc/channel.rs:40](src/ipc/channel.rs#L40) | Bounded channel table for verification. Sized for v1 endgame multi-monitor compositor ([ADR-011](docs/adr/011-graphics-architecture-and-scaling.md)): ~6 scanout channels (3 displays × front/back) + ~30 window surfaces + ~10 GPU command/memory channels + non-GUI services (~14 from current boot modules) = ~60 active. 4× headroom per CLAUDE.md Convention 8. Memory cost: 256 × ~160 B ≈ 40 KiB (was 10 KiB at 64). | Bumped 2026-04-13 from 64 in the Phase GUI-0 prep pass. Next revisit: multi-monitor + many-client graphics workloads exceeding 60 active channels, or a service that legitimately needs dozens of simultaneous data paths. |
| `MAX_CHANNEL_PAGES` | 65536 (256 MiB) | [src/ipc/channel.rs:56](src/ipc/channel.rs#L56) | Soft cap on channel size in pages. Sized for v1 endgame graphics ([ADR-011](docs/adr/011-graphics-architecture-and-scaling.md)): a 4K display at 2× Retina backing scale = 8K backing store = 128 MiB @ 32bpp, 256 MiB @ 64bpp HDR. Single-channel ceiling accommodates one such full-screen window surface; multi-monitor workloads use multiple channels (one per display scanout, one per window surface). Ceiling is soft (not always-allocated). | Bumped 2026-04-13 from 4096 in the Phase GUI-0 prep pass. Next revisit: HDR + backing scale beyond 2× on 5K/8K displays pushes single-surface size past 256 MiB, at which point the tier-aware policy service (Phase 3.4) and a `LargeChannel` capability should gate these allocations before the ceiling rises further. |
| `MIN_CHANNEL_PAGES` | 1 (4 KiB) | [src/ipc/channel.rs:62](src/ipc/channel.rs#L62) | Minimum channel size. Channels smaller than a page would defeat the purpose — the 256-byte control IPC already covers small messages. |
| `STAGING_BUFFER_CAPACITY` | 128 | [src/audit/buffer.rs:31](src/audit/buffer.rs#L31) | Per-CPU audit staging ring. At ~64 bytes/event, 128 entries = 8 KiB per CPU. At 1000 events/sec across 4 CPUs, each CPU sees ~250 events/sec. With drain at 100 Hz, ~2.5 events/drain cycle typical. 128 entries gives 50× headroom for typical, handles 10× burst without drops. Memory: 256 CPUs × 8 KiB = 2 MiB worst case, ~16 KiB typical (2 CPUs). | Observed drop rates exceed 0.1% under sustained load. |
| `AUDIT_RING_PAGES` | 16 (64 KiB) | [src/audit/drain.rs:51](src/audit/drain.rs#L51) | Global audit ring buffer. Minus 64-byte header, holds 1023 events. At 1000 events/sec typical rate, ~1 second of buffering. ADR-007 specifies 64 KiB. Memory cost: 64 KiB, negligible. | Consumer consistently drops events due to ring overflow (visible via SYS_AUDIT_INFO stats). |
| `KERNEL_HEAP_SIZE` | 4 MiB | [src/microkernel/main.rs:501](src/microkernel/main.rs#L501) | Sufficient for current Box/Vec allocations; conscious upper bound to make memory accounting easy. | Phase 3 channels + audit ring buffers + larger capability tables will pressure this. First OOM in `Box::new()` is the signal. |
| `HEAP_SIZE` (per process) | 4 MiB | [src/process.rs:175](src/process.rs#L175) | Default per-process heap size. Each process's heap is dynamically allocated from the frame allocator via `allocate_contiguous(HEAP_PAGES)` at creation and reclaimed via `free_contiguous` at exit. Bumped 2026-04-13 from 1 MiB: udp-stack was already documented as feeling the 1 MiB ceiling, and the v1 endgame graphics workload ([ADR-011](docs/adr/011-graphics-architecture-and-scaling.md)) pushes harder (GUI clients need widget trees, font atlases, software-rendered backing stores). Memory cost at 7 boot modules: 28 MiB baseline (up from 7 MiB), comfortable on 128 MiB+ QEMU and 16 GiB Dell 3630 targets. | Next revisit: a single process needs more than 4 MiB. The right fix at that point is **per-process heap sizing** (spawn-time argument), not another global bump — different processes have different needs. |
| `HEAP_PAGES` (per process) | 1024 (4 MiB / 4 KiB) | [src/process.rs:178](src/process.rs#L178) | Derived from `HEAP_SIZE / PAGE_SIZE`. Drives the `allocate_contiguous` request in `ProcessDescriptor::new`. Paired with `HEAP_SIZE` and grows with it. | N/A — derived, tracks `HEAP_SIZE`. |
| `KERNEL_STACK_SIZE` (per task) | 32 KiB | [src/loader/mod.rs:33](src/loader/mod.rs#L33) | Bumped 2026-04-15 from 8 KiB. The original 8 KiB was an unconscious bound — real exit-path frame depths exceeded it. `ChannelManager::revoke_all_for_process` formerly stack-allocated `[Option<ChannelRecord>; 256]` ≈ 36 KiB (fixed to `Vec`), and debug-build frames for the remaining `handle_exit` call chain still pushed past 8 KiB. Adjacent kstacks are heap-allocated contiguously with no guard pages, so overflow silently corrupted the next task's `SavedContext` (root cause of the persistent shell-death-after-task-exit bug). 32 KiB gives ~4× headroom over observed usage. Memory cost: MAX_TASKS × 32 KiB ≈ 8 MiB. | Per-kstack guard-page mapping lands — at that point overflow page-faults cleanly and this value can be tuned down based on actual frame-depth measurements rather than guesswork. |
| `MAX_FRAMES` (frame allocator) | 4194304 | [src/memory/frame_allocator.rs:40](src/memory/frame_allocator.rs#L40) | Bitmap covers 0-16 GiB physical. Bitmap is 512 KiB in `.bss` (up from 64 KiB at 2 GiB). Bumped 2026-04-13 from 524288 in the Phase GUI-0 prep pass — resolves the pre-existing bare-metal blocker (Dell 3630 has 16 GiB) and gives headroom for the v1 endgame graphics workload ([ADR-011](docs/adr/011-graphics-architecture-and-scaling.md)) which can hold multi-GiB GPU textures, backing stores, and framebuffers. | Next revisit: bare-metal targets with >16 GiB RAM. At that point switch to a tiered/sparse structure rather than growing the flat bitmap further — at 32 GiB the bitmap is 1 MiB, at 64 GiB it's 2 MiB, and linear-scan allocate_contiguous becomes prohibitively slow for large regions. |
| `MAX_PROCESS_MEMORY` (per binary) | 256 MiB | [src/loader/mod.rs:49](src/loader/mod.rs#L49) | ELF verifier hard cap; prevents OOM via crafted binaries. | A legitimate user-space service that needs > 256 MiB. Fine for now. |
| `DEFAULT_STACK_PAGES` (per process) | 16 (64 KiB) | [src/loader/mod.rs:40](src/loader/mod.rs#L40) | Conservative default; existing services fit. | Per-service decision; should become a process descriptor field rather than a constant once different services have different needs. |
| Boot stack | 256 KiB | [src/microkernel/main.rs:129](src/microkernel/main.rs#L129) | Limine StackSizeRequest. Forces large structs onto the heap (already a kernel-wide convention). | Stack overflow at boot. Currently fine because of the heap-allocate-everything-large pattern. |

### ARCHITECTURAL — real invariants

These are *not* arbitrary. Each one encodes a design decision. They should not change unless the design changes.

| Constant | Value | Where | Invariant |
|---|---|---|---|
| Control IPC payload | 256 bytes | [src/ipc/mod.rs:98](src/ipc/mod.rs#L98) | Fixed for verification: kernel reads every byte of every control-IPC message. Bulk data takes a separate path (channels — see [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md)). |
| `NUM_PRIORITY_BANDS` | 4 | [src/scheduler/mod.rs:135](src/scheduler/mod.rs#L135) | Idle / Low / Normal / High+Critical — the priority taxonomy. 4 bands is the design, not a tuning choice. |
| `MIN_BLOCK_SIZE` (heap) | 16 bytes | [src/memory/heap.rs:16](src/memory/heap.rs#L16) | Minimum heap allocation. Below this, free-list metadata costs more than the allocation. |
| `HEAP_ALIGN` | 16 bytes | [src/memory/heap.rs:19](src/memory/heap.rs#L19) | Maximum alignment any allocation needs (matches `max_align_t`). |
| `MIN_ORDER` / `MAX_ORDER` (buddy) | 4 / 19 | [src/memory/buddy_allocator.rs](src/memory/buddy_allocator.rs) | 16 B minimum, 512 KiB maximum allocation. Encodes the buddy allocator's range. |
| `ENTRIES_PER_TABLE` (page table) | 512 | [src/memory/mod.rs:111](src/memory/mod.rs#L111) | x86_64 / AArch64 4-level page tables have exactly 512 entries per level. Hardware-defined but expressed as a structural constant. |
| `Principal::public_key` length | 32 bytes | [src/ipc/mod.rs:45](src/ipc/mod.rs#L45) | Ed25519 public key length. The crypto algorithm is the design decision; 32 is its consequence. Changes only if [identity.md](identity.md) chooses a different crypto primitive (e.g., ML-DSA-65 post-quantum). |
| Lock hierarchy depth | 9 | n/a | The nine-lock hierarchy in [CLAUDE.md § Lock Ordering](CLAUDE.md#lock-ordering). Adding a lock is a deliberate architectural decision, not a number bump. |
| `RAW_AUDIT_EVENT_SIZE` | 64 bytes | [src/audit/mod.rs:91](src/audit/mod.rs#L91) | One x86_64 cache line. Matches ADR-007's "~64 bytes average" target. The flat wire format avoids serialization overhead and is memcpy-safe. |
| `ARCOBJ_MAGIC` | `"ARCOBJ00"` | [src/fs/disk.rs:28](src/fs/disk.rs#L28) | Persistent ObjectStore superblock magic ([ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md)). Changing it is a new format family, not a version bump. Readers that see a different magic treat the disk as corrupt. |
| `ARCOREC_MAGIC_OCCUPIED` | `"ARCOREC1"` | [src/fs/disk.rs:31](src/fs/disk.rs#L31) | Record-header magic for an occupied slot. Commit point of the write protocol (ADR-010). Absence = free. The `1` at the end distinguishes from a future `ARCOREC2` if record layout changes. |
| `FORMAT_VERSION` | 1 | [src/fs/disk.rs:35](src/fs/disk.rs#L35) | Persistent ObjectStore on-disk format version. Mount rejects unknown versions. Version 2 lands when ML-DSA signatures or multi-block content records require a layout change. |

### HARDWARE — fixed by external ABI/spec

These are facts about the world. CambiOS has no leverage to change them.

| Constant | Value | Where | Source |
|---|---|---|---|
| `MAX_GSI_PINS` (I/O APIC) | 24 | [src/arch/x86_64/ioapic.rs:55](src/arch/x86_64/ioapic.rs#L55) | Intel I/O APIC has 24 redirection entries. |
| `MAX_DEVICE_IRQ` | 224 | [src/syscalls/dispatcher.rs:31](src/syscalls/dispatcher.rs#L31) | x86 IDT has 256 entries; vectors 0-31 are CPU exceptions, 32-255 are device IRQs and IPIs, top 32 reserved for APIC/IPI. |
| Interrupt routing table size | 224 | [src/interrupts/routing.rs:84](src/interrupts/routing.rs#L84) | Same 224 from the IDT layout above. |
| `GDT_ENTRIES` | 7 | [src/arch/x86_64/gdt.rs:40](src/arch/x86_64/gdt.rs#L40) | Null + kernel CS + kernel SS + user SS + user CS + TSS low + TSS high. SYSRET requires this exact layout. |
| `IST_STACK_SIZE` | 4 KiB | [src/interrupts/mod.rs:438](src/interrupts/mod.rs#L438) | Double-fault handler dedicated stack. The double-fault handler is small; doesn't need more. |
| `MAX_IO_APICS` | 4 | [src/acpi/mod.rs:184](src/acpi/mod.rs#L184) | Realistic upper bound for x86 server hardware. Defensible until somebody hands us a chassis with 5. |
| `SIGNATURE_TRAILER_SIZE` | 72 (64 + 8) | [src/loader/mod.rs:232](src/loader/mod.rs#L232) | Ed25519 signature (64 B) + ARCSIG magic (8 B). Fixed by the on-disk format. |
| `BLOCK_SIZE` | 4096 | [src/fs/block.rs:30](src/fs/block.rs#L30) | On-disk sector size for the persistent ObjectStore ([ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md)). Matches x86_64 page size and is a multiple of every common physical sector size (512 B and 4K-native). All `BlockDevice` I/O is sized at this boundary regardless of whether the underlying hardware reports 512-byte or 4K-native sectors. |

### TUNING — needs benchmarks, not opinion

These are performance knobs. Picking a number without measurements is guessing. They should change in response to observed workload, not architectural changes.

| Constant | Value | Where | What it trades off |
|---|---|---|---|
| `CACHE_CAPACITY` (per-CPU frame cache) | 32 | [src/memory/frame_allocator.rs:329](src/memory/frame_allocator.rs#L329) | Allocator lock contention vs. per-CPU memory parked unused. Larger = less lock contention, more wasted frames. |
| `REFILL_COUNT` / `DRAIN_COUNT` | 16 / 16 | [src/memory/frame_allocator.rs:332](src/memory/frame_allocator.rs#L332) | Batch size for cache refill/drain — amortizes the global lock cost. |
| `MAX_INDIVIDUAL_PAGES` (TLB shootdown) | 32 | [src/arch/x86_64/tlb.rs:31](src/arch/x86_64/tlb.rs#L31) | Threshold for `invlpg` per-page vs. full CR3 reload. Above 32, full reload is cheaper. Verified empirically by other kernels; not measured for CambiOS. |
| `MAX_OVERRIDES` (ACPI MADT) | 16 | [src/acpi/mod.rs:187](src/acpi/mod.rs#L187) | Realistic firmware override count. |
| `DRAIN_BATCH_SIZE` (audit) | 64 | [src/audit/drain.rs:59](src/audit/drain.rs#L59) | Max events drained from all per-CPU staging buffers per timer tick. Bounds ISR time: 64 events × 64 bytes = 4 KiB of copies. |
| `AUDIT_IPC_SAMPLE_RATE` | 100 | [src/audit/mod.rs:393](src/audit/mod.rs) | IPC send/recv sampling: emit 1 audit event per 100 operations. At ~1000 IPC/sec, produces ~10 events/sec — informative for pattern detection without flooding. |

#### Tier policies

These three rows capture the default `TableSizingPolicy` per deployment tier introduced by [ADR-008](docs/adr/008-boot-time-sized-object-tables.md) and [ADR-009](docs/adr/009-purpose-tiers-scope.md). Each policy is a 5-field struct — `min_slots`, `max_slots`, `ram_budget_ppm`, `ram_budget_floor`, `ram_budget_ceiling` — that drives the boot-time `num_slots` computation in [`config::num_slots_from`](src/config/tier.rs). They are TUNING because the defaults are starting points chosen from estimated workload density; the right values depend on what each tier's deployments actually run, and will shift as real workload data arrives. The kernel binary is identical across tiers per ADR-009; what differs is which policy is selected by the `CAMBIOS_TIER` build environment variable (default: `tier3`), wired in via [`build.rs`](build.rs).

| Policy | Value | Where | What it trades off |
|---|---|---|---|
| `TIER1_POLICY` (CambiOS-Embedded) | `{ min_slots: 32, max_slots: 256, ram_budget_ppm: 15_000, ram_budget_floor: 2 MiB, ram_budget_ceiling: 8 MiB }` | [src/config/tier.rs:129](src/config/tier.rs#L129) | 1.5% of RAM, clamped 2-8 MiB, for 32-256 slots. Embedded deployments run small, stable sets of fixed-function processes; 256-slot ceiling reflects "more than this is probably the wrong tier." Tunable per deployment via custom tier config. |
| `TIER2_POLICY` (CambiOS-Standard, no AI) | `{ min_slots: 128, max_slots: 4096, ram_budget_ppm: 20_000, ram_budget_floor: 16 MiB, ram_budget_ceiling: 64 MiB }` | [src/config/tier.rs:139](src/config/tier.rs#L139) | 2% of RAM, clamped 16-64 MiB, for 128-4096 slots. Sized for a typical single-user desktop or workstation. Shared multi-user machines or heavy build farms raise the ceiling in a custom tier config. |
| `TIER3_POLICY` (CambiOS-Full) | `{ min_slots: 256, max_slots: 65536, ram_budget_ppm: 30_000, ram_budget_floor: 64 MiB, ram_budget_ceiling: 512 MiB }` | [src/config/tier.rs:149](src/config/tier.rs#L149) | 3% of RAM, clamped 64-512 MiB, for 256-65536 slots. Sized for heavy general-purpose workloads (large builds, many user applications, AI services with per-request workers). 65536 is a default, not a physical limit. |

**Current binding observation (tier3, QEMU 128 MiB):** after the BuddyAllocator-to-per-heap move, `SLOT_OVERHEAD` dropped from ~22 KB to ~2 KB. On QEMU 128 MiB, `num_slots` is capped by the contiguous-region fitting heuristic (half of free frames). At 1 TiB, Tier 3 hits `max_slots = 65536` (slot-bound) — the binding flip the ADR originally predicted. Tier 1 is also slot-bound; Tier 2 transitions from budget-bound to slot-bound at ~8 GiB of RAM.

**Revisit when:** ADR-008 § "Post-Change Review Protocol" note — changes to per-process kernel state (new fields in `ProcessDescriptor`, `ProcessCapabilities`, etc.) shift `SLOT_OVERHEAD`, which changes how many slots fit in a given budget. When that happens, the tier defaults may need to move so the binding constraint (slot count vs. budget) stays where the policy intended. A `SLOT_OVERHEAD` reduction (e.g. moving `BuddyAllocator` state out of `ProcessDescriptor` onto the heap it manages) would flip Tier 2/3 back to slot-bound and is a natural follow-up to Phase 3.2a. The first real workload data from bare-metal Tier 3 deployment is also a revisit trigger.

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
