<!--
doc_type: implementation_reference
owns: project-wide implementation status
auto_refresh: required
last_synced_to_code: 2026-04-10
authoritative_for: what is built vs designed vs planned, current test counts, current phase status
-->

# ArcOS Implementation Status

> **Living status doc.** This file is the single source of truth for "what is currently built." It is auto-refreshed when feature work lands (see [CLAUDE.md § Post-Change Review Protocol Step 8](CLAUDE.md#post-change-review-protocol)). Pure intent and plans live in [ArcOS.md](ArcOS.md) and the design docs; this file is for *current state*.
>
> If you're trying to figure out "is X done yet?" — this is the doc to read. If you're trying to figure out "should X be done a certain way?" — read the linked design doc instead.

## At a glance

- **218 unit tests passing** on host (`x86_64-apple-darwin`)
- **x86_64**: clean release build, boots in QEMU with 2 CPUs, 7 boot modules running (hello, fs-service, key-store, virtio-net, i219-net, udp-stack, shell)
- **AArch64**: clean release build, boots in QEMU `virt`, all 7 modules running, full SMP (single-CPU mode tested; SMP timer-on-AP issue tracked)
- **Bare metal**: USB boot tooling complete (`make img-usb` builds GPT image; `make usb DEVICE=/dev/diskN` writes safely); not yet tested on target hardware (Dell Precision 3630)

## Subsystem status

| Subsystem | Status | Notes | Code | Design |
|---|---|---|---|---|
| **Microkernel core** | Done | Heap, frame allocator, page tables, GDT/IDT (x86), VBAR_EL1 (AArch64) | `src/microkernel/`, `src/memory/` | [ArcOS.md § The Microkernel](ArcOS.md) |
| **Per-CPU SMP scheduler** | Done | Per-CPU schedulers, 4 priority bands, O(1) scheduling, task migration, push-based load balancing | `src/scheduler/` | [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) |
| **Voluntary context switch** | Done | `yield_save_and_switch` (x86_64 + AArch64), synthetic exception frame | `src/arch/x86_64/mod.rs`, `src/arch/aarch64/mod.rs` | — |
| **Preemptive context switch** | Done | Timer ISR with full register save, context switch hint, TLB shootdown | `src/arch/*/mod.rs` | [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) |
| **Capability-based IPC (control path)** | Done | 256-byte fixed messages, three-layer enforcement, sender_principal stamping, sharded per-endpoint | `src/ipc/` | [ADR-000](docs/adr/000-zta-and-cap.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) |
| **Capability bulk path (channels)** | Designed, not implemented | Shared memory channels for data plane | — | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) |
| **Capability revocation** | Designed, not implemented | `SYS_REVOKE_CAPABILITY` + atomic teardown | — | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) |
| **Audit telemetry** | Designed, not implemented | Kernel→userspace event channel for AI observability | — | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) |
| **Policy service** | Designed, not implemented | User-space externalization of `on_syscall` decisions | — | [ADR-006](docs/adr/006-policy-service.md) |
| **Cryptographic identity** | Done (Phase 1C, hardware-backed) | Bootstrap Principal from compiled-in YubiKey pubkey, IPC sender stamping, BindPrincipal/GetPrincipal syscalls | `src/ipc/`, `bootstrap_pubkey.bin` | [identity.md](identity.md), [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) |
| **Signed ELF loading** | Done | ARCSIG trailer, Ed25519 signature verification, `SignedBinaryVerifier` | `src/loader/` | [ADR-004](docs/adr/004-cryptographic-integrity.md) |
| **Content-addressed ObjectStore** | Done (Phase 1C, RAM-backed) | ArcObject with Blake3, Ed25519, ACL; RamObjectStore (256 objects) | `src/fs/` | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md), [ADR-004](docs/adr/004-cryptographic-integrity.md) |
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
| **Process lifecycle cleanup** | Partial | `handle_exit` works; reclaim of page tables / VMA / endpoints on exit not yet complete | `src/syscalls/dispatcher.rs` | — |
| **AArch64 user-space services** | Done | All boot modules build for both targets via `libsys` shared syscall wrappers (x86_64 syscall + AArch64 svc) | `user/libsys/` | — |
| **RISC-V port** | Planned (post-v1) | Third arch backend matching x86_64/AArch64 public API | — | — |
| **AI pre-execution code analysis** | Planned (post-v1) | JIT analysis of ELF binaries before execution | — | [ArcOS.md § AI Integration](ArcOS.md) |
| **Behavioral anomaly detection (AI)** | Planned (post-v1) | Runtime monitoring service consuming audit telemetry | — | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md), [PHILOSOPHY.md](PHILOSOPHY.md) |
| **AI compatibility layer (Win32)** | Planned (post-v1) | Long-term vision item from ArcOS.md | — | [ArcOS.md § Application Compatibility](ArcOS.md) |

## Phase markers

ArcOS uses informal phases to mark identity/storage milestones. These phases are referenced from [identity.md](identity.md) and [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md).

| Phase | Goal | Status |
|---|---|---|
| **Phase 0** | Identity primitives in kernel + RAM-backed ObjectStore. Stamps unforgeable identity on every IPC message; gives every stored object an author and owner. | **Done** |
| **Phase 1** | Real cryptography. Blake3 hashing, Ed25519 signature verification on objects, signed ELF modules, key store as user-space service. | **Done** |
| **Phase 1B** | Hardware-backed bootstrap identity. YubiKey-derived public key compiled into kernel; private key never enters kernel memory. | **Done** |
| **Phase 1C** | Key-store service degraded mode + signed ObjectStore puts. fs-service requests signing from key-store before ObjPut; falls back to unsigned when key-store is in degraded mode (no runtime YubiKey). | **Done** |
| **Phase 2A** | First user-space hardware driver. Virtio-net with PCI discovery, virtqueues, DMA bounce buffers, hostile-device validation. | **Done** |
| **Phase 2B** | First user-space network service. Stateless UDP/IP over virtio-net, with NTP demo. | **Done** |
| **Phase 3** | Architecture: bulk data path (channels) + externalized policy + capability revocation + audit telemetry. The substrate that real workloads (video, file I/O, AI inference) need. | **In progress: ADRs 005-007 drafted, implementation pending** |
| **Phase 4** | Persistent storage. Virtio-blk driver, disk-backed ObjectStore, ArcObject CLI in shell. | **Planned** |
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
| 9 | ArcObject CLI | **Planned** |
| 10 | Yggdrasil peer service | **Planned** |

**Currently blocking the v1 sequence:** Phase 3 (architecture work — channels, policy service, revocation, telemetry). Once the architectural substrate exists, items 4-10 sit on top of it and proceed in order.

## Test coverage

| Subsystem | Tests | Notes |
|---|---|---|
| Scheduler | 35 | Creation, init, lifecycle, schedule, time slice, block/wake, IRQ/message wake, idle immutability, migration primitives, invariants |
| Capability manager | 11 | Grant, verify, delegation, escalation prevention, capacity limits, Principal bind/get |
| IPC interceptor | 13 | Payload validation, bounds, self-send, delegation policy, syscall filtering, custom interceptors |
| ELF verifier | 14 | W^X, kernel space rejection, overlapping segments, memory limits, entry point boundary cases, signed binary verifier |
| IPC sender_principal | 4 | Default None, kernel stamping, no-principal path, direct send bypass |
| ObjectStore types + crypto | 21 | Principal equality, Blake3 hashing, Ed25519 sign/verify, ArcObject creation/author immutability/owner/lineage, ObjectCapSet |
| RamObjectStore | 12 | Put/get, idempotency, invalid hash rejection, delete, list, capacity, slot reuse, author/owner preservation |
| Memory subsystem | ~30 | Buddy allocator, frame allocator, heap, paging primitives |
| AArch64 portable logic | 12 | PerCpu offsets, GIC register math, page table descriptor flags |
| Other | ~70 | Timer, IPC sync channel, ProcessTable, VMA tracker, syscall args, etc. |
| **Total** | **218** | All passing on `x86_64-apple-darwin` |

Run with: `RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin`

## Known issues

- **AArch64 SMP timer on AP**: PPI 30 (ARM Generic Timer) does not fire on the second CPU in QEMU `virt`. Single-CPU mode works fully. Investigation pending; may be a QEMU configuration issue or a missing GIC redistributor configuration step on the AP path.
- **AArch64 device IRQ routing**: GIC `enable_spi()` / `set_spi_trigger()` exist as functions but are not called from the boot path or `handle_wait_irq()`. Device IRQs (virtio, PL011 RX) are not yet functional on AArch64.
- **ELF loader doesn't merge overlapping segment permissions**: If two PT_LOAD segments share a page with different permissions, the first segment's permissions win. Worked around in user-space linker scripts via `ALIGN(4096)` before `.data`. Loader fix is roadmap item 20.
- **Process lifecycle cleanup is partial**: `handle_exit` marks the task Terminated but doesn't reclaim page tables, frames, IPC endpoints, or VMA regions. Roadmap item 17.
- **Virtio-net TX completion may require yield to idle on QEMU TCG**: QEMU TCG defers virtio TX processing to its event loop, which runs during guest `hlt`. The driver yields and the idle task hlts, which works for small bursts but the UDP stack's ARP retry/timeout logic doesn't yet exploit this fully.

## Cross-references

- [ArcOS.md](ArcOS.md) — source-of-truth architecture document
- [identity.md](identity.md) — identity architecture (Phases 0-7 are defined here)
- [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md) — settled decisions for the identity + storage layer
- [SECURITY.md](SECURITY.md) — enforcement status table (security-specific subset of this document)
- [README.md](README.md) — public-facing summary
- [SCHEDULER.md](src/scheduler/SCHEDULER.md) — scheduler implementation reference
- [docs/adr/](docs/adr/) — architecture decision records
- [CLAUDE.md](CLAUDE.md) — kernel technical reference and required-reading map
