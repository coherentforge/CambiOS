<!--
doc_type: implementation_reference
owns: project-wide implementation status
auto_refresh: required
last_synced_to_code: 2026-04-15 (sequential boot-time module loading + scheduler purge_task + kstack overflow fix)
authoritative_for: what is built vs designed vs planned, current test counts, current phase status
-->

# CambiOS Implementation Status

> **Living status doc.** This file is the single source of truth for "what is currently built." It is auto-refreshed when feature work lands (see [CLAUDE.md § Post-Change Review Protocol Step 8](CLAUDE.md#post-change-review-protocol)). Pure intent and plans live in [CambiOS.md](CambiOS.md) and the design docs; this file is for *current state*.
>
> If you're trying to figure out "is X done yet?" — this is the doc to read. If you're trying to figure out "should X be done a certain way?" — read the linked design doc instead.

## At a glance

- **447 unit tests passing** on host (`x86_64-apple-darwin`)
- **x86_64**: clean release build, boots in QEMU with 2 CPUs, 7 boot modules running (hello, fs-service, key-store, virtio-net, i219-net, udp-stack, shell)
- **AArch64**: clean release build, boots in QEMU `virt`, all 7 modules running, full SMP (single-CPU mode tested; SMP timer-on-AP issue tracked). virtio-blk x86_64 only at Phase 4a.ii — AArch64 device IRQ routing is a known gap.
- **Bare metal**: USB boot tooling complete (`make img-usb` builds GPT image; `make usb DEVICE=/dev/diskN` writes safely); not yet tested on target hardware (Dell Precision 3630)

## Subsystem status

| Subsystem | Status | Notes | Code | Design |
|---|---|---|---|---|
| **Microkernel core** | Done | Heap, frame allocator, page tables, GDT/IDT (x86), VBAR_EL1 (AArch64) | `src/microkernel/`, `src/memory/` | [CambiOS.md § The Microkernel](CambiOS.md) |
| **Per-CPU SMP scheduler** | Done | Per-CPU schedulers, 4 priority bands, O(1) scheduling, task migration, push-based load balancing | `src/scheduler/` | [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) |
| **Voluntary context switch** | Done | `yield_save_and_switch` (x86_64 + AArch64), synthetic exception frame | `src/arch/x86_64/mod.rs`, `src/arch/aarch64/mod.rs` | — |
| **Preemptive context switch** | Done | Timer ISR with full register save, context switch hint, TLB shootdown | `src/arch/*/mod.rs` | [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) |
| **Capability-based IPC (control path)** | Done | 256-byte fixed messages, three-layer enforcement, sender_principal stamping, sharded per-endpoint | `src/ipc/` | [ADR-000](docs/adr/000-zta-and-cap.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) |
| **Capability bulk path (channels)** | Done (Phase 3.2d) | Shared-memory channels: `ChannelManager`, 5 syscalls (28-32), `CreateChannel` system capability, channel-aware process exit cleanup, TLB shootdown on close/revoke, `libsys` wrappers. Producer/Consumer/Bidirectional roles with MMU-enforced access (RW/RO). | `src/ipc/channel.rs`, `src/syscalls/dispatcher.rs`, `src/ipc/capability.rs`, `user/libsys/` | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) |
| **Capability revocation** | Done (Phase 3.1, bootstrap-only) | `SYS_REVOKE_CAPABILITY` (#27), `CapabilityManager::revoke()`, `revoke_all_for_process()` wired into `handle_exit`. Authority = bootstrap Principal only; grantor/revoke-right paths defer to Phase 3.4. Audit emit, channel mapping cleanup, policy cache invalidation, and active holder notification are in-code stubs citing Phase 3.2/3.3/3.4. | `src/ipc/capability.rs`, `src/syscalls/dispatcher.rs` | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) |
| **CreateProcess capability** | Done (Phase 3.2b) | `CapabilityKind::CreateProcess` system capability. `handle_spawn` checks authority before allocation. Granted to kernel processes (0-2) and all boot modules at boot. `revoke_all_for_process` clears system caps on exit. | `src/ipc/capability.rs`, `src/syscalls/dispatcher.rs`, `src/microkernel/main.rs` | [ADR-008](docs/adr/008-boot-time-sized-object-tables.md) § Migration Path |
| **Boot-time-sized kernel object tables** | Done (Phase 3.2a+3.2b+3.2c+3.2d) | `MAX_PROCESSES` removed as compile-time constant. `num_slots` computed at boot from `config::ACTIVE_POLICY` and frame allocator's tracked memory. Kernel object table region allocated via `FrameAllocator::allocate_contiguous`, HHDM-mapped, carries `ProcessTable` and `CapabilityManager` slot storage as `&'static mut` slices. Per-process heap region allocated on demand and reclaimed on exit. Phase 3.2b: `CapabilityKind::CreateProcess` system capability. Phase 3.2c: `ProcessId` generation counters. Phase 3.2d: shared-memory channels (`ChannelManager`, 5 syscalls, `CreateChannel` cap), full process lifecycle cleanup (VMA reclaim, page table frame reclaim on exit), lock hierarchy renumbered (CHANNEL_MANAGER at position 5). `CapabilityHandle` refactor deferred to post-v1 handle table. | `src/config/tier.rs`, `src/memory/object_table.rs`, `src/process.rs`, `src/ipc/capability.rs`, `src/ipc/mod.rs`, `src/syscalls/dispatcher.rs`, `src/loader/mod.rs`, `src/microkernel/main.rs`, `build.rs` | [ADR-008](docs/adr/008-boot-time-sized-object-tables.md) |
| **Deployment tiers / scope** | Designed, policy-only | Three tiers (Tier 1 CambiOS-Embedded, Tier 2 CambiOS-Standard, Tier 3 CambiOS-Full). Single kernel binary across tiers; tier selection is an install-time choice that decides which `TableSizingPolicy` and which user-space services are loaded. No code gate yet. | — | [ADR-009](docs/adr/009-purpose-tiers-scope.md), [GOVERNANCE.md](GOVERNANCE.md) |
| **Audit infrastructure** | Done (Phase 3.3) | Kernel→userspace event streaming for security observability. Per-CPU lock-free staging buffers → global audit ring (64 KiB, 1023 event slots). 16 event types, `audit::emit()` at 14 instrumentation points. IPC send/recv sampled 1-in-100. Drain via BSP timer ISR piggyback (100 Hz). `SYS_AUDIT_ATTACH` (33) maps ring RO into consumer. `SYS_AUDIT_INFO` (34) returns stats. | `src/audit/`, `src/syscalls/dispatcher.rs`, `user/libsys/` | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) |
| **Policy service** | Designed, not implemented | User-space externalization of `on_syscall` decisions | — | [ADR-006](docs/adr/006-policy-service.md) |
| **Cryptographic identity** | Done (Phase 1C, hardware-backed + load-bearing) | Bootstrap Principal from compiled-in YubiKey pubkey, IPC sender stamping, BindPrincipal/GetPrincipal syscalls, **identity gate in syscall dispatcher** (unidentified processes can only Exit/Yield/GetPid/GetTime/Print/GetPrincipal), **`recv_verified` in libsys** (userspace services structurally reject anonymous IPC senders) | `src/ipc/`, `src/syscalls/`, `user/libsys/`, `bootstrap_pubkey.bin` | [identity.md](identity.md), [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) |
| **Signed ELF loading** | Done | ARCSIG trailer, Ed25519 signature verification, `SignedBinaryVerifier` | `src/loader/` | [ADR-004](docs/adr/004-cryptographic-integrity.md) |
| **Content-addressed ObjectStore** | Done (Phase 1C, RAM-backed) | CambiObject with Blake3, Ed25519, ACL; RamObjectStore (256 objects) | `src/fs/` | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md), [ADR-004](docs/adr/004-cryptographic-integrity.md) |
| **Persistent ObjectStore** | In progress (Phase 4a.iii done) | `DiskObjectStore<B: BlockDevice>` — generic disk-backed impl of `ObjectStore` (Phase 4a.i). On-disk format specified in [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md): 4 KiB blocks, superblock + 2-block record slots, commit-by-header-magic-write crash consistency, bounded-iteration mount scan. Phase 4a.iii wired `OBJECT_STORE` to a `LazyDiskStore` wrapper around `DiskObjectStore<VirtioBlkDevice>`; handshake with the user-space driver is deferred to the first `SYS_OBJ_*` call (driver needs to be running by then). Kernel uses poll-with-yield for driver replies (not block+wake — the wake path through `handle_write`'s endpoint-25 intercept provoked a virtqueue-level stall in the driver's own self-test flush; root cause not fully characterized, poll-with-yield avoids the interaction). End-to-end put/get/reboot demo waits on Phase 4a.iv (`arcobj` CLI). | `src/fs/disk.rs`, `src/fs/block.rs`, `src/fs/lazy_disk.rs`, `src/fs/virtio_blk_device.rs`, `src/fs/mod.rs`, `src/syscalls/dispatcher.rs`, `src/lib.rs` | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md), [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md) |
| **BlockDevice abstraction** | Done (Phase 4a.i) | `BlockDevice` trait (`read_block`/`write_block`/`flush`/`capacity_blocks` at 4 KiB granularity) + in-kernel `MemBlockDevice`. The trait is the seam between `DiskObjectStore` and any storage backend — memory (testing), virtio-blk (4a.iii), NVMe/AHCI (post-v1). | `src/fs/block.rs` | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) |
| **Key-store service** | Done | User-space, IPC endpoint 17, runs in degraded mode (no runtime YubiKey access yet) | `user/key-store-service/` | — |
| **FS service** | Done | User-space, IPC endpoint 16, ObjectStore gateway with sender_principal enforcement | `user/fs-service/` | — |
| **Virtio-net driver** | Done | User-space, IPC endpoint 20, PCI discovery, TX/RX virtqueues, DMA bounce buffers. Shares the legacy-virtio queue-size bug fixed in virtio-blk (Phase 4a.ii) — driver clamps queue size to 32 but the device thinks it's 256, so completions land at an offset the driver never reads. Re-enable in limine.conf after applying the virtio-blk fix (use device-reported queue size, bump `MAX_QUEUE_SIZE` to 256). Tracked as a known issue. | `user/virtio-net/` | — |
| **Virtio-blk driver** | Done (Phase 4a.iii) | User-space. Endpoint 24 (user clients, `recv_verified`) + endpoint 26 (kernel-only, `recv_msg`, no identity check — trust by endpoint choice, mirror of policy service at 22). PCI discovery (vendor 0x1AF4, device 0x1001 legacy / 0x1042 modern), single request virtqueue with 3-descriptor chains, DMA bounce buffers, `DeviceValue<T>` hostile-device validation. Kernel commands on 26: `HANDSHAKE` (allocate shared region, return paddr), `READ_BLOCK`, `WRITE_BLOCK`, `FLUSH`, `CAPACITY` — all operate against the kernel-visible shared DMA region. Responses flow back to endpoint 25 via the `handle_write` intercept. x86_64 only — AArch64 GIC device-IRQ routing is a known gap. | `user/virtio-blk/` | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) |
| **Intel I219-LM driver** | Scaffolded, untested on hardware | User-space, same IPC interface as virtio-net for bare-metal target | `user/i219-net/` | — |
| **UDP/IP stack** | Done | User-space, IPC endpoint 21, ARP, IPv4, UDP, NTP demo | `user/udp-stack/` | — |
| **DHCP client** | Pre-work landed in udp-stack; client paused | UDP stack has CMD_SET_CONFIG and CMD_DHCP_SEND helpers; the client itself is paused pending channel architecture | partial in `user/udp-stack/` | — |
| **DNS resolver** | Planned | Stub resolver over UDP, caches results | — | — |
| **TCP stack** | Planned | Connection state machine, retransmission, sliding window | — | — |
| **Virtio-blk driver** | Planned | Block I/O via virtqueue + DMA bounce buffers | — | — |
| **Shell** | Done | Interactive shell over serial, command parsing. Phase 4a.iv adds `arcobj put/get/list/delete` (fs-service client, shell endpoint 18) — exercises the full SYS_OBJ_* → LazyDiskStore → VirtioBlkDevice → driver path end-to-end. | `user/shell/` | — |
| **Spawn / WaitTask syscalls** | Done | New process creation from boot module by name; parent waits for child exit | `src/syscalls/dispatcher.rs`, `src/boot_modules.rs` | — |
| **PCI bus discovery** | Done | Bus 0 scan at boot, device table via `DeviceInfo` syscall | `src/pci/` | — |
| **Device syscalls** | Done | `MapMmio`, `AllocDma`, `DeviceInfo`, `PortIo` | `src/syscalls/dispatcher.rs` | — |
| **Bootloader abstraction** | Done (Phase GUI-0) | `BootInfo` + `src/boot/` module isolates the kernel from Limine types (`MemoryRegion`, `FramebufferInfo`, `ModuleInfo`). `boot::limine::populate` is the only site that reads `limine::*` responses outside the one early HHDM read; every subsequent consumer uses `boot::info()`. Prepares for camBIOS firmware replacement without kernel-wide refactor. SMP/AP wakeup not yet abstracted (deeper coupling; deferred). | `src/boot/mod.rs`, `src/boot/limine.rs`, `src/microkernel/main.rs` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) |
| **SYS_MAP_FRAMEBUFFER + graphics caps** | Done (Phase GUI-0, unwired) | `SyscallNumber::MapFramebuffer = 35` returns a 32-byte `FramebufferDescriptor` to user-space (vaddr + geometry + pixel format). Capability-gated via `CapabilityKind::MapFramebuffer`. `LegacyPortIo` and `LargeChannel` capability kinds landed alongside; all three are unwired (granted to nobody today) awaiting Phase GUI-1+ consumers. libsys wrappers `wait_irq` + `map_framebuffer` added. | `src/syscalls/dispatcher.rs`, `src/ipc/capability.rs`, `user/libsys/src/lib.rs` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) |
| **GIC + ARM Generic Timer (AArch64)** | Done | GICv3 (Distributor + Redistributor + ICC sysregs), CNTP at 100Hz | `src/arch/aarch64/gic.rs`, `src/arch/aarch64/timer.rs` | — |
| **APIC + I/O APIC (x86_64)** | Done | Local APIC timer at 100Hz, I/O APIC for device IRQs, SMP IPI | `src/arch/x86_64/apic.rs`, `src/arch/x86_64/ioapic.rs` | — |
| **TLB shootdown** | Done | x86_64 via vector 0xFE IPI; AArch64 via TLBI broadcast | `src/arch/*/tlb.rs` | — |
| **AArch64 SMP timer on AP** | Known issue | AP timer PPI not firing in QEMU virt; single-CPU works fully | — | — |
| **AArch64 device IRQ routing** | Gap | GIC `enable_spi`/`set_spi_trigger` exist but not wired into boot path | — | — |
| **USB boot tooling** | Done | `make img-usb` builds GPT-partitioned UEFI image; `make usb DEVICE=...` writes safely with confirmation | `Makefile` | — |
| **Yggdrasil mesh networking** | Planned | Identity-routed overlay network (post-DNS/TCP) | — | [identity.md](identity.md) |
| **TLS transport** | Planned (post-v1) | TLS 1.3 over TCP | — | — |
| **VFS / mount infrastructure** | Planned (post-v1) | Mount table, path resolution, namespace isolation | — | — |
| **USB HID driver** | Planned (post-v1) | XHCI host controller, HID device support; prerequisite for runtime YubiKey | — | — |
| **DID resolution** | Planned (post-v1) | `did:key` method per [identity.md](identity.md) | — | [identity.md](identity.md) |
| **Identity revocation (per identity.md)** | Planned (post-v1) | Eventually-consistent revocation via signed objects in social log | — | [identity.md](identity.md) |
| **Process lifecycle cleanup** | Done (Phase 3.2d.ii) | `handle_exit` performs full cleanup: capability revocation, channel revocation (unmap + TLB shootdown + frame free), VMA region reclaim, page table frame reclaim (PML4 + intermediates), heap reclaim. `purge_task` evicts exiting task from scheduler ready queues. Kernel stack dealloc deferred (bounded 32 KiB/process leak, requires scheduler-level deferred-free). | `src/syscalls/dispatcher.rs`, `src/process.rs`, `src/memory/paging.rs`, `src/memory/mod.rs` | — |
| **AArch64 user-space services** | Done | All boot modules build for both targets via `libsys` shared syscall wrappers (x86_64 syscall + AArch64 svc) | `user/libsys/` | — |
| **RISC-V port** | Planned (post-v1) | Third arch backend matching x86_64/AArch64 public API | — | — |
| **AI pre-execution code analysis** | Planned (post-v1) | JIT analysis of ELF binaries before execution | — | [CambiOS.md § AI Integration](CambiOS.md) |
| **Behavioral anomaly detection (AI)** | Planned (post-v1) | Runtime monitoring service consuming audit telemetry | — | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md), [PHILOSOPHY.md](PHILOSOPHY.md) |
| **AI compatibility layer (Win32)** | Planned (post-v1) | Long-term vision item from CambiOS.md | — | [CambiOS.md § Application Compatibility](CambiOS.md) |

## Phase markers

CambiOS uses informal phases to mark identity/storage milestones. These phases are referenced from [identity.md](identity.md) and [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md).

| Phase | Goal | Status |
|---|---|---|
| **Phase 0** | Identity primitives in kernel + RAM-backed ObjectStore. Stamps unforgeable identity on every IPC message; gives every stored object an author and owner. | **Done** |
| **Phase 1** | Real cryptography. Blake3 hashing, Ed25519 signature verification on objects, signed ELF modules, key store as user-space service. | **Done** |
| **Phase 1B** | Hardware-backed bootstrap identity. YubiKey-derived public key compiled into kernel; private key never enters kernel memory. | **Done** |
| **Phase 1C** | Key-store service degraded mode + signed ObjectStore puts. fs-service requests signing from key-store before ObjPutSigned; **no unsigned fallback** — objects cannot be stored without a valid signature. Identity is load-bearing: kernel identity gate + userspace `recv_verified` create structural dependency on the security model. | **Done** |
| **Phase 2A** | First user-space hardware driver. Virtio-net with PCI discovery, virtqueues, DMA bounce buffers, hostile-device validation. | **Done** |
| **Phase 2B** | First user-space network service. Stateless UDP/IP over virtio-net, with NTP demo. | **Done** |
| **Phase 3** | Architecture: bulk data path (channels) + externalized policy + capability revocation + audit infrastructure. The substrate that real workloads (video, file I/O, AI inference) need. | **In progress: 3.1 (revocation primitive) landed; 3.2a (boot-time-sized object tables) landed; 3.2b (`CreateProcess` capability) landed; 3.2c (`ProcessId` generation counter) landed; 3.2d (shared-memory channels + process lifecycle cleanup) landed; 3.3 (audit infrastructure) landed — see [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md). 3.4 (policy service) pending** |
| **Phase 4** | Persistent storage. Virtio-blk driver, disk-backed ObjectStore, CambiObject CLI in shell. | **Phase 4a done** (4a.i — persistent ObjectStore + on-disk format + BlockDevice trait; 4a.ii — virtio-blk user-space driver; 4a.iii — kernel `VirtioBlkDevice` adapter + `LazyDiskStore` hot-swap onto `OBJECT_STORE`; 4a.iv — `arcobj put/get/list/delete` in the shell) — see [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) incl. its Divergence section. The planned plan/execute/commit decomposition turned out unnecessary: `SHARDED_IPC` (per-endpoint shard locks) and `PER_CPU_SCHEDULER` (per-CPU, no cycle with OBJECT_STORE) don't produce the IPC_MANAGER-hierarchy deadlock originally feared. Kernel↔driver uses poll-with-yield (not block+wake) after a virtqueue-interaction bug was observed. End-to-end `put`/`get`/reboot demo is a human-interactive test through the shell; the first real call path is exercised on every `arcobj put`. Phase 4b (move ObjectStore ownership into fs-service + bulk channel IPC) deferred. |
| **Phase 5** | Identity-routed networking. Yggdrasil peer service, Ed25519→IPv6 mapping, mesh routing without DNS. | **Planned** |
| **Phase 6** | Biometric commitment + key recovery. Retinal/facial ZKP enrollment, social attestation, key rotation protocol. | **Planned (post-v1)** |
| **Phase 7** | SSB bridge. Cross-instance capability grants and identity attestations over append-only logs. | **Planned (post-v1)** |

## v1 Roadmap progress

The v1 milestone is "interactive, network-capable, identity-rooted OS running on real hardware with persistent storage." Items in dependency order:

| # | Item | Status |
|---|---|---|
| 1 | Shell | **Done** |
| 2 | USB boot tooling (Dell 3630) | **Done** (untested on target hardware) |
| 3 | Intel I219-LM NIC driver | **Scaffolded** (untested on target hardware) |
| 4 | DHCP client | **Paused** (pre-work landed in udp-stack; pending Phase 3 architecture) |
| 5 | DNS resolver | **Planned** |
| 6 | TCP stack | **Planned** |
| 7 | Virtio-blk driver | **Planned** |
| 8 | Persistent ObjectStore | **In progress** (Phase 4a.i landed: format + `DiskObjectStore` tested on `MemBlockDevice`; awaiting Phase 4a.iii hot-swap onto virtio-blk) |
| 9 | CambiObject CLI | **Done** (Phase 4a.iv — `arcobj put/get/list/delete` in the shell) |
| 10 | Yggdrasil peer service | **Planned** |

**Currently blocking the v1 sequence:** Phase 3.4 (policy service). Revocation (Phase 3.1), channels (Phase 3.2d), and audit infrastructure (Phase 3.3) are done. Once the policy service exists, items 4-10 sit on top of it and proceed in order.

## Test coverage

| Subsystem | Tests | Notes |
|---|---|---|
| Scheduler | 35 | Creation, init, lifecycle, schedule, time slice, block/wake, IRQ/message wake, idle immutability, migration primitives, invariants |
| Capability manager | 40 | Grant, verify, delegation, escalation prevention, capacity limits, Principal bind/get, revocation authority checks, revoke_all_for_process cleanup, system capability (CreateProcess + CreateChannel) grant/check/revoke/idempotency/independence/cleanup, ProcessId generation counter stale-reference rejection, ProcessId encoding round-trip, error-path coverage |
| IPC interceptor | 13 | Payload validation, bounds, self-send, delegation policy, syscall filtering, custom interceptors |
| ELF verifier | 14 | W^X, kernel space rejection, overlapping segments, memory limits, entry point boundary cases, signed binary verifier |
| IPC sender_principal | 4 | Default None, kernel stamping, no-principal path, direct send bypass |
| ObjectStore types + crypto | 21 | Principal equality, Blake3 hashing, Ed25519 sign/verify, CambiObject creation/author immutability/owner/lineage, ObjectCapSet |
| RamObjectStore | 12 | Put/get, idempotency, invalid hash rejection, delete, list, capacity, slot reuse, author/owner preservation |
| BlockDevice abstraction (Phase 4a.i) | 11 | `MemBlockDevice` zero-init, read/write round-trip, block isolation, out-of-bounds, flush no-op, full-pattern sweep, error `Display` |
| DiskObjectStore (Phase 4a.i) | 30 | Superblock encode/decode + blank/wrong-magic/corrupt-checksum classification, record-header encode/decode + torn-write treated as free + oversized-content rejection, `FreeMap` ops, format+put+get, idempotent put, delete + slot reuse, capacity exhaustion, list, **reboot preserves objects**, reboot preserves signed-and-verified object, reboot after delete, reboot with store at capacity, generation counter bump on mount, corrupt-superblock rejection, torn-header invisible after remount, orphan-content-block is reusable (crash between content and header write), undersized device fails, LBA math |
| Memory subsystem | ~37 | Buddy allocator, frame allocator (including Phase 3.2a `free_contiguous` round-trip + atomicity tests), heap, paging primitives; `allocate_contiguous` at `HEAP_PAGES` (Phase GUI-0 bounds bump, ADR-011) |
| Tier configuration (Phase 3.2a) | 16 | `TableSizingPolicy` field bounds, `num_slots_from` clamp behavior, realistic memory sizes (256 MB / 4 GB / 8 GB / 32 GB / 1 TB) per tier, monotonicity, `binding_constraint_for` per clamp, slot-clamp-shadows-budget-clamp invariant |
| Kernel object table region (Phase 3.2a) | 5 | `region_bytes_for` page-aligned and monotonic, `init` produces disjoint valid slices with `None` initialization, rejects zero slots, propagates frame-alloc failure |
| Channel manager (Phase 3.2d) | 29 | ChannelId encoding, ChannelRole permissions, create/attach/close/revoke state machine, table full, principal mismatch, stale generation, slot reuse, revoke_all_for_process, preserve-bystander; create-at-MAX_CHANNEL_PAGES ceiling test (Phase GUI-0 bounds bump, ADR-011) |
| Process lifecycle cleanup (Phase 3.2d.ii) | 3 | VMA reclaim (empty, drains tracker, kernel task noop) |
| Audit staging buffer (Phase 3.3) | 14 | SPSC ring: push, drain, wrap-around, overflow, interleaved, capacity cycles, take_dropped |
| Audit event types (Phase 3.3) | 18 | Event kind discriminants, wire format size, builder round-trips for all 16 event types, timestamp/sequence encoding |
| Audit ring + drain (Phase 3.3) | 12 | Ring header magic/capacity, write/wrap, drain from staging, staging drop reporting, batch bound, consumer attach/detach, capacity math |
| AArch64 portable logic | 12 | PerCpu offsets, GIC register math, page table descriptor flags |
| Other | ~70 | Timer, IPC sync channel, ProcessTable, VMA tracker, syscall args, etc. |
| **Total** | **447** | All passing on `x86_64-apple-darwin` |

Run with: `RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin`

## Known issues

- **AArch64 SMP timer on AP**: PPI 30 (ARM Generic Timer) does not fire on the second CPU in QEMU `virt`. Single-CPU mode works fully. Investigation pending; may be a QEMU configuration issue or a missing GIC redistributor configuration step on the AP path.
- **AArch64 device IRQ routing**: GIC `enable_spi()` / `set_spi_trigger()` exist as functions but are not called from the boot path or `handle_wait_irq()`. Device IRQs (virtio, PL011 RX) are not yet functional on AArch64. Affects virtio-blk polling-mode viability too — deferred.
- **Legacy-virtio queue-size clamping (virtio-net)**: `user/virtio-net/src/main.rs` caps the virtqueue at 32 entries, but the device advertises more (QEMU: 256) and legacy virtio's Queue Size register is read-only — the driver MUST use the device-reported size. The mismatch puts avail/used rings at different offsets on the two sides, so completions never arrive. Diagnosed during Phase 4a.ii. Fix: bump `MAX_QUEUE_SIZE` to 256 and drop the clamp (the virtio-blk driver does this). Re-enable the network drivers in `limine.conf` only after fixing this.
- **fb-demo (Phase GUI-1) blocks Phase 4a services when both are enabled**: When `fb-demo` is in `limine.conf` alongside the Phase 4a modules (fs-service, virtio-blk, shell), fb-demo's `SYS_MAP_FRAMEBUFFER` call completes kernel-side (kernel prints `[fb-syscall] write_user_buffer rc=Ok(32)`) but fb-demo's userspace never prints `[FB-DEMO] after syscall`, and the subsequent boot modules (fs-service, virtio-blk, shell) never reach their service loops. Root cause undiagnosed; likely an issue in the framebuffer syscall's return path or fb-demo's expectations about the mapping. Temporarily disabling `fb-demo.elf` in `limine.conf` lets the Phase 4a chain come up cleanly. Not a Phase 4a bug — it's a Phase GUI-1 concern — but listed here because it affects the `arcobj` interactive demo.
- ~~**Boot module ordering is non-deterministic**~~ **Resolved.** Sequential boot-time module loading landed: `SYS_MODULE_READY = 36` + `BlockReason::BootGate` + `BOOT_MODULE_ORDER` static. Each boot module's `_start` calls `sys::module_ready()` after endpoint registration; modules boot in dependency order (policy → ks → fs → virtio-blk → shell → hello.elf). `limine.conf` reordered accordingly.
- ~~**Intermittent kernel page fault in `Scheduler::schedule` during task-exit cleanup**~~ **Resolved.** Root cause was two interacting bugs: (1) `handle_exit` did not purge the exiting task from the scheduler's ready queues, leaving a stale `TaskId` that later dereferenced a freed slot; (2) `ChannelManager::revoke_all_for_process` returned a `[Option<ChannelRecord>; MAX_CHANNELS]` (~36 KiB) on the 8 KiB kernel stack, overflowing into adjacent task stacks and corrupting the BSP scheduler's data. Fixes: `Scheduler::purge_task(tid)` helper added (called from `handle_exit` before `yield_save_and_switch`), `revoke_all_for_process` changed to return `Vec<ChannelRecord>`, and `KERNEL_STACK_SIZE` bumped from 8 KiB to 32 KiB.
- **ELF loader doesn't merge overlapping segment permissions**: If two PT_LOAD segments share a page with different permissions, the first segment's permissions win. Worked around in user-space linker scripts via `ALIGN(4096)` before `.data`. Loader fix is roadmap item 20.
- **Kernel stack not freed on process exit**: `handle_exit` now performs full cleanup (capabilities, channels, VMAs, page table frames, heap) as of Phase 3.2d.ii. The 32 KiB kernel stack per task is the remaining leak — freeing it requires a deferred-dealloc mechanism (can't free the stack you're running on). The leak is bounded by `num_slots` × 32 KiB (~6.4 MiB worst case). Scheduled for a dedicated cleanup pass.
- **Pre-existing user-space driver warnings**: `cargo build` on the `user/virtio-net/` and `user/i219-net/` crates emits `dead_code` / `unused_imports` warnings for scaffolded driver state (PCI field metadata, unused transport constants, `phy_read`/`phy_write` stubs, `DmaBuf::zero`, etc.). These are excluded from the main kernel workspace (`Cargo.toml` exclude list) so they do not affect kernel builds, but surface when `make run` invokes them. Not a correctness issue — the fields/methods are staged for future use. Tracking here so they get cleaned up when the respective drivers get their next real-hardware bring-up pass.
- **Virtio-net TX completion may require yield to idle on QEMU TCG**: QEMU TCG defers virtio TX processing to its event loop, which runs during guest `hlt`. The driver yields and the idle task hlts, which works for small bursts but the UDP stack's ARP retry/timeout logic doesn't yet exploit this fully.
- **Clippy warnings (~125 remaining, down from 164)**: Auto-fixable suggestions applied; doc formatting and module-level comment style fixed. Remaining breakdown: ~67 `multiple_unsafe_ops_per_block` (unsafe block splitting in arch code — debatable in hardware-adjacent code), ~25 missing `// SAFETY:` comments, ~12 `static_mut_refs` (Rust 2024 edition migration — IDT/GDT/TSS patterns need `UnsafeCell` or `addr_of!`), ~20 `new_without_default` suggestions. Scheduled for a dedicated cleanup pass between Phase 3.2d (channels) and Phase 3.3 (telemetry), before the static mut deprecation becomes a hard error.

## Cross-references

- [CambiOS.md](CambiOS.md) — source-of-truth architecture document
- [identity.md](identity.md) — identity architecture (Phases 0-7 are defined here)
- [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md) — settled decisions for the identity + storage layer
- [SECURITY.md](SECURITY.md) — enforcement status table (security-specific subset of this document)
- [GOVERNANCE.md](GOVERNANCE.md) — project governance, deployment tiers, scope boundaries (companion to [ADR-009](docs/adr/009-purpose-tiers-scope.md))
- [ASSUMPTIONS.md](ASSUMPTIONS.md) — catalog of every numeric bound in kernel code with SCAFFOLDING / ARCHITECTURAL / HARDWARE / TUNING category
- [README.md](README.md) — public-facing summary
- [SCHEDULER.md](src/scheduler/SCHEDULER.md) — scheduler implementation reference
- [docs/adr/](docs/adr/) — architecture decision records (ADRs 000-009)
- [CLAUDE.md](CLAUDE.md) — kernel technical reference and required-reading map
