<!--
doc_type: implementation_reference
owns: project-wide implementation status
auto_refresh: required
last_synced_to_code: 2026-04-12 (Phase 3.3 landed)
authoritative_for: what is built vs designed vs planned, current test counts, current phase status
-->

# CambiOS Implementation Status

> **Living status doc.** This file is the single source of truth for "what is currently built." It is auto-refreshed when feature work lands (see [CLAUDE.md § Post-Change Review Protocol Step 8](CLAUDE.md#post-change-review-protocol)). Pure intent and plans live in [CambiOS.md](CambiOS.md) and the design docs; this file is for *current state*.
>
> If you're trying to figure out "is X done yet?" — this is the doc to read. If you're trying to figure out "should X be done a certain way?" — read the linked design doc instead.

## At a glance

- **316 unit tests passing** on host (`x86_64-apple-darwin`)
- **x86_64**: clean release build, boots in QEMU with 2 CPUs, 7 boot modules running (hello, fs-service, key-store, virtio-net, i219-net, udp-stack, shell)
- **AArch64**: clean release build, boots in QEMU `virt`, all 7 modules running, full SMP (single-CPU mode tested; SMP timer-on-AP issue tracked)
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
| **Cryptographic identity** | Done (Phase 1C, hardware-backed) | Bootstrap Principal from compiled-in YubiKey pubkey, IPC sender stamping, BindPrincipal/GetPrincipal syscalls | `src/ipc/`, `bootstrap_pubkey.bin` | [identity.md](identity.md), [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) |
| **Signed ELF loading** | Done | ARCSIG trailer, Ed25519 signature verification, `SignedBinaryVerifier` | `src/loader/` | [ADR-004](docs/adr/004-cryptographic-integrity.md) |
| **Content-addressed ObjectStore** | Done (Phase 1C, RAM-backed) | CambiObject with Blake3, Ed25519, ACL; RamObjectStore (256 objects) | `src/fs/` | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md), [ADR-004](docs/adr/004-cryptographic-integrity.md) |
| **Persistent ObjectStore** | Planned | Disk-backed implementation of the ObjectStore trait | — | [identity.md](identity.md), [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md) |
| **Key-store service** | Done | User-space, IPC endpoint 17, runs in degraded mode (no runtime YubiKey access yet) | `user/key-store-service/` | — |
| **FS service** | Done | User-space, IPC endpoint 16, ObjectStore gateway with sender_principal enforcement | `user/fs-service/` | — |
| **Virtio-net driver** | Done | User-space, IPC endpoint 20, PCI discovery, TX/RX virtqueues, DMA bounce buffers | `user/virtio-net/` | — |
| **Intel I219-LM driver** | Scaffolded, untested on hardware | User-space, same IPC interface as virtio-net for bare-metal target | `user/i219-net/` | — |
| **UDP/IP stack** | Done | User-space, IPC endpoint 21, ARP, IPv4, UDP, NTP demo | `user/udp-stack/` | — |
| **DHCP client** | Pre-work landed in udp-stack; client paused | UDP stack has CMD_SET_CONFIG and CMD_DHCP_SEND helpers; the client itself is paused pending channel architecture | partial in `user/udp-stack/` | — |
| **DNS resolver** | Planned | Stub resolver over UDP, caches results | — | — |
| **TCP stack** | Planned | Connection state machine, retransmission, sliding window | — | — |
| **Virtio-blk driver** | Planned | Block I/O via virtqueue + DMA bounce buffers | — | — |
| **Shell** | Done | Interactive shell over serial, command parsing | `user/shell/` | — |
| **Spawn / WaitTask syscalls** | Done | New process creation from boot module by name; parent waits for child exit | `src/syscalls/dispatcher.rs`, `src/boot_modules.rs` | — |
| **PCI bus discovery** | Done | Bus 0 scan at boot, device table via `DeviceInfo` syscall | `src/pci/` | — |
| **Device syscalls** | Done | `MapMmio`, `AllocDma`, `DeviceInfo`, `PortIo` | `src/syscalls/dispatcher.rs` | — |
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
| **Process lifecycle cleanup** | Done (Phase 3.2d.ii) | `handle_exit` performs full cleanup: capability revocation, channel revocation (unmap + TLB shootdown + frame free), VMA region reclaim, page table frame reclaim (PML4 + intermediates), heap reclaim. Kernel stack dealloc deferred (bounded 8 KiB/process leak, requires scheduler-level deferred-free). | `src/syscalls/dispatcher.rs`, `src/process.rs`, `src/memory/paging.rs`, `src/memory/mod.rs` | — |
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
| **Phase 1C** | Key-store service degraded mode + signed ObjectStore puts. fs-service requests signing from key-store before ObjPut; falls back to unsigned when key-store is in degraded mode (no runtime YubiKey). | **Done** |
| **Phase 2A** | First user-space hardware driver. Virtio-net with PCI discovery, virtqueues, DMA bounce buffers, hostile-device validation. | **Done** |
| **Phase 2B** | First user-space network service. Stateless UDP/IP over virtio-net, with NTP demo. | **Done** |
| **Phase 3** | Architecture: bulk data path (channels) + externalized policy + capability revocation + audit infrastructure. The substrate that real workloads (video, file I/O, AI inference) need. | **In progress: 3.1 (revocation primitive) landed; 3.2a (boot-time-sized object tables) landed; 3.2b (`CreateProcess` capability) landed; 3.2c (`ProcessId` generation counter) landed; 3.2d (shared-memory channels + process lifecycle cleanup) landed; 3.3 (audit infrastructure) landed — see [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md). 3.4 (policy service) pending** |
| **Phase 4** | Persistent storage. Virtio-blk driver, disk-backed ObjectStore, CambiObject CLI in shell. | **Planned** |
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
| 8 | Persistent ObjectStore | **Planned** |
| 9 | CambiObject CLI | **Planned** |
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
| Memory subsystem | ~36 | Buddy allocator, frame allocator (including Phase 3.2a `free_contiguous` round-trip + atomicity tests), heap, paging primitives |
| Tier configuration (Phase 3.2a) | 16 | `TableSizingPolicy` field bounds, `num_slots_from` clamp behavior, realistic memory sizes (256 MB / 4 GB / 8 GB / 32 GB / 1 TB) per tier, monotonicity, `binding_constraint_for` per clamp, slot-clamp-shadows-budget-clamp invariant |
| Kernel object table region (Phase 3.2a) | 5 | `region_bytes_for` page-aligned and monotonic, `init` produces disjoint valid slices with `None` initialization, rejects zero slots, propagates frame-alloc failure |
| Channel manager (Phase 3.2d) | 28 | ChannelId encoding, ChannelRole permissions, create/attach/close/revoke state machine, table full, principal mismatch, stale generation, slot reuse, revoke_all_for_process, preserve-bystander |
| Process lifecycle cleanup (Phase 3.2d.ii) | 3 | VMA reclaim (empty, drains tracker, kernel task noop) |
| Audit staging buffer (Phase 3.3) | 14 | SPSC ring: push, drain, wrap-around, overflow, interleaved, capacity cycles, take_dropped |
| Audit event types (Phase 3.3) | 18 | Event kind discriminants, wire format size, builder round-trips for all 16 event types, timestamp/sequence encoding |
| Audit ring + drain (Phase 3.3) | 12 | Ring header magic/capacity, write/wrap, drain from staging, staging drop reporting, batch bound, consumer attach/detach, capacity math |
| AArch64 portable logic | 12 | PerCpu offsets, GIC register math, page table descriptor flags |
| Other | ~70 | Timer, IPC sync channel, ProcessTable, VMA tracker, syscall args, etc. |
| **Total** | **362** | All passing on `x86_64-apple-darwin` |

Run with: `RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin`

## Known issues

- **AArch64 SMP timer on AP**: PPI 30 (ARM Generic Timer) does not fire on the second CPU in QEMU `virt`. Single-CPU mode works fully. Investigation pending; may be a QEMU configuration issue or a missing GIC redistributor configuration step on the AP path.
- **AArch64 device IRQ routing**: GIC `enable_spi()` / `set_spi_trigger()` exist as functions but are not called from the boot path or `handle_wait_irq()`. Device IRQs (virtio, PL011 RX) are not yet functional on AArch64.
- **ELF loader doesn't merge overlapping segment permissions**: If two PT_LOAD segments share a page with different permissions, the first segment's permissions win. Worked around in user-space linker scripts via `ALIGN(4096)` before `.data`. Loader fix is roadmap item 20.
- **Kernel stack not freed on process exit**: `handle_exit` now performs full cleanup (capabilities, channels, VMAs, page table frames, heap) as of Phase 3.2d.ii. The 8 KiB kernel stack per task is the remaining leak — freeing it requires a deferred-dealloc mechanism (can't free the stack you're running on). The leak is bounded by `num_slots` × 8 KiB (~1.6 MiB worst case). Scheduled for a dedicated cleanup pass.
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
