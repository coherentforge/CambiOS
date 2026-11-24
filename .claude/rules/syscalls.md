---
paths:
  - "src/syscalls/**"
  - "cambios-abi/**"
  - "user/libsys/**"
  - "user/libsys-rt/**"
---

# Syscall Numbers

The canonical list is the `SyscallNumber` enum in [cambios-abi/src/lib.rs](../../cambios-abi/src/lib.rs) ([ADR-024](../../docs/adr/024-syscall-abi-crate.md)); [src/syscalls/mod.rs](../../src/syscalls/mod.rs) re-exports it. That enum is the ABI. Run `make stats` for the current count. The per-syscall summaries below describe *behavior*, not *existence*; if you need the authoritative list of numbers, read the enum.

Handlers live in [src/syscalls/dispatcher.rs](../../src/syscalls/dispatcher.rs). All IPC syscalls go through capability + interceptor checks and stamp `sender_principal`. Only the non-obvious gotchas / ABIs / restrictions are listed below:

- **Exit**: calls `CapabilityManager::revoke_all_for_process()` ([ADR-007](../../docs/adr/007-capability-revocation-and-telemetry.md)); VMA / page-table / frame reclaim is still partial.
- **Allocate**: rolls back on OOM.
- **No syscall is bootstrap-Principal-gated any more** (slots 11 `BindPrincipal` and 31 `ChannelRevoke` retired 2026-09-15; never reused). Principals are bound kernel-internally at spawn from the manifest row. **AuditAttach** is gated by `AuditConsumer`, the FDE pair by `UnlockVolume`, cluster create/revoke by `CreateCluster` / `ClusterRevoke` (or being the cluster's creator), and **RevokeCapability** by holding the `revoke` right on the target endpoint (ADR-007 § "Who can revoke", path 2).
- **RecvMsg**: wire format is `[sender:32][from_endpoint:4][payload:N]`. The sender field is the kernel's stamp: the sending process's bound Principal, or `cambios_abi::KERNEL_ORIGIN_SENDER` for a message the kernel itself sent; `cambios_abi::WireSender` decodes it, and all zero means a kernel that does not stamp. libsys `recv_verified` accepts only a Principal, `recv_kernel` only the kernel origin (identity.md § Kernel transcribes). Blocks on `MessageWait(endpoint)`.
- **TryRecvMsg** (Phase 4b): non-blocking RecvMsg. Required for services polling multiple endpoints (virtio-blk ep24+ep26). `from_endpoint` is the sender's **reply endpoint** (first registered endpoint, tracked in `REPLY_ENDPOINT`) — before Phase 4b, `from = pid_slot` sent replies into a queue nobody read.
- **ObjPutSigned**: caller supplies an Ed25519 signature; kernel verifies against caller's Principal before storing.
- **MapMmio**: an allow-list: the range must lie wholly inside a memory BAR of a discovered device (`pci::is_range_in_pci_mem_bar`; on riscv64 the DTB's virtio-mmio regions are recorded as BAR 0), and must not overlap usable RAM. Refusal is `PermissionDenied` + `syscall_denied` audit. The earlier rule refused only usable RAM, so the kernel image and boot modules mapped user-writable (sandbox review R1, 2026-11-21). Any map-mmio row may still map any device's BAR (no device assignment yet). **PortIo**: rejects ports outside discovered PCI BARs. **AllocDma**: guard pages before + after.
- **DeviceInfo**: 108-byte descriptor. **AuditInfo**: 48-byte buffer. **MapFramebuffer**: 32-byte `FramebufferDescriptor`, capability-gated, kernel holds the phys addr; call once per display.
- **RevokeCapability**: `CapabilityHandle` refactor waits on the post-v1 handle table.
- **ChannelCreate**: needs `CreateChannel` system cap; roles are Producer / Consumer / Bidirectional ([ADR-005](../../docs/adr/005-ipc-primitives-control-and-bulk.md)). **ChannelAttach**: kernel verifies caller's Principal matches `peer_principal` from create; maps pages RO/RW per role. The state check, the mapping and the commit run under one `CHANNEL_MANAGER` hold (nesting `PROCESS_TABLE` → `FRAME_ALLOCATOR`), and any failure after the region is allocated unmaps and releases it: a failed attach leaves the caller no mapping. Taken as three sections, the creator could close the channel mid-map and the caller kept a writable mapping of the freed frames (sandbox review R2, 2026-11-23).
- **Slot 36 (was ModuleReady)**: retired at ADR-018 step 9 with the boot-release chain; never reused (slot-18 discipline). Readiness is `cambios_libsys_rt::ready()` — an ordinary IPC write of `READY_PING_TAG` to init's endpoint 1; init matches the kernel-stamped sender AID against the manifest entry.
- **Spawn**: requires `CapabilityKind::CreateProcess` ([ADR-008](../../docs/adr/008-boot-time-sized-object-tables.md)). Manifest-only. Row lookup by name (unknown ⇒ `InvalidArg`), then the row's `SpawnAuthority` (`InitOnly` for boot-wave rows, `AnyCreateProcessHolder` for on-demand apps), then signed-ELF load, then `install_manifest_row` binds the row's derived AID + exactly its grants.
