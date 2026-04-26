<!--
doc_type: implementation_reference
owns: project-wide implementation status
auto_refresh: required
last_synced_to_code: 2026-04-22 (ECAM PCI enumerator + aarch64 GUI parity)
authoritative_for: what is built vs designed vs planned, current test counts, current phase status
convention: Keep `last_synced_to_code` a single date. Chronological narrative
goes in the "Recent landings" section below — rotate out after ~3 weeks so
this file stays scannable. Subsystem table cells stay short; deep rationale
belongs in the linked ADR, not here.
-->

# CambiOS Implementation Status

> **Living doc.** Single source of truth for "what is currently built." Auto-refreshed as feature work lands (see [CLAUDE.md § Post-Change Review Protocol Step 8](CLAUDE.md#post-change-review-protocol)). Intent lives in [CambiOS.md](docs/CambiOS.md) and the design docs; this file is for *current state*.
>
> "Is X done yet?" — read here. "Should X be done a certain way?" — read the linked design doc.

## At a glance

- **Tri-arch first-class**: clean release build on `x86_64`, `aarch64`, `riscv64gc`; all three boot in QEMU to an `arcos>` shell prompt. `make check-all` is the permanent regression gate.
- **540 host unit tests passing** on `x86_64-apple-darwin`. Run `make stats` for current counts — numbers live in code, not prose.
- **Security model live end-to-end**: cryptographic identity, signed-ELF verification, capability-gated IPC, content-addressed ObjectStore, audit ring, kernel identity gate, userspace `recv_verified`.
- **GUI stack live on x86_64 + aarch64**: scanout-virtio-gpu drives QEMU virtio-gpu-pci; compositor composites; virtio-input forwards HID keyboard/pointer events into the focused window; first-party app `pong` (continuous-motion 1-player vs AI) runs as the default GUI boot module on x86_64, and `worm` renders on aarch64 via `make run-aarch64-gui` now that the kernel has an ECAM-based PCI enumerator. `tree` (Minesweeper) stays buildable for regression.
- **Persistent storage live**: virtio-blk + disk-backed ObjectStore + `arcobj` shell CLI; objects survive reboot.
- **Bare metal**: USB boot tooling complete, untested on target hardware (Dell Precision 3630).
- **Formal verification**: Kani proofs live on BuddyAllocator + ELF parser + FrameAllocator + CapabilityManager (1 + 7 + 9 + 12 = 29 harnesses across 4 proof crates; proof authoring fixed 6 overflow sites in `src/loader/elf.rs` and 2 in `src/memory/frame_allocator.rs`).

## Recent landings

Chronological, newest first. ~3 week window — older items rotate out; git log has the full history.

- **2026-04-26** — Audit consumer capability ([ADR-023](docs/adr/023-audit-consumer-capability.md)). `CapabilityKind::AuditConsumer` replaces the bootstrap-Principal-only check on `SYS_AUDIT_ATTACH` (ADR-007 § "Audit channel boot sequence"); `SYS_GET_PROCESS_PRINCIPAL = 42` resolves a `subject_pid` to its bound 32-byte Principal so audit consumers can render `did:key:z6Mk…` without widening the 64-byte event format. Recent-exits ring on `ProcessTable` (SCAFFOLDING, 64 entries) handles principal-after-exit lookups. New signed `user/audit-tail/` boot module holds the cap, attaches to the ring, resolves principals via the new syscall, and prints one-line summaries to serial. Tri-arch built; 554 host tests pass.
- **2026-04-21** — Kani proofs for FrameAllocator (`verification/frame-proofs/`): 9 harnesses on `src/memory/frame_allocator.rs` covering `allocate`, `free`, `allocate_contiguous`, `free_contiguous`, and `add_region` overflow. Proof authoring found 2 integer-overflow sites that panic in debug / wrap in release on malformed bootloader memory-map entries (`add_region` line 138, `reserve_region` line 158); both fixed with `saturating_add`. `reserve_region`'s fully-symbolic overflow proof blows CBMC's memory budget; covered instead by a mechanical-copy of the `add_region` fix + a unit-test regression gate (`test_reserve_region_wrap_boundary_no_panic`).
- **2026-04-21** — Kani proofs for CapabilityManager (`verification/capability-proofs/`): 12 harnesses on `src/ipc/capability.rs`. Tier A (7) covers `ProcessCapabilities` — empty-table denial, grant/verify composition, revoke effectiveness, absent-endpoint rejection, rights upgrade, count bound ≤ 32, capacity-full rejection. Tier B (5) covers `CapabilityManager` on a 3-slot `Box::leak`'d manager — stale-generation rejection (ADR-008 slot-reuse defence), delegate-without-delegate-right denied, no-rights-escalation, `revoke_all_for_process` clears every endpoint cap + all 5 system-cap flags, non-bootstrap revoke returns `AccessDenied` with no state change. Kernel source unchanged; proof crate includes `src/ipc/capability.rs` verbatim via `#[path]` and stubs `crate::ipc::{ProcessId, EndpointId, CapabilityRights, Principal}` locally, drops the audit emit via the existing `#[cfg(not(any(test, fuzzing)))]` gate flipped by `build.rs` `--cfg fuzzing`. [ADR-000 § Divergence](docs/adr/000-zta-and-cap.md) now cites these proofs as the formal backing for the capability-soundness claim.
- **2026-04-21** — `did:key` encoder for Principals ([identity.md](docs/identity.md) Phase 4 pull-forward): 32-byte Ed25519 pubkey ↔ `did:key:z6Mk…` via multicodec `0xed` + base58btc, implemented in `user/libsys/` (no new deps, no_std). Shell gains a `did-key` command (self / encode-hex / decode-did:key). Cross-verified against the RFC 8032 Test 1 vector. x/a/r.
- **2026-04-22** — Kernel ECAM PCI enumerator → aarch64 GUI parity. `src/pci/mod.rs` grew a `mod ecam` + `mod config` shim: x86_64 continues to use mechanism-1 port I/O (CF8/CFC), aarch64 + riscv64 route through ECAM MMIO at `ECAM_VIRT + (bus << 20) + (dev << 15) + (func << 12) + off`. `scan`, `decode_bars`, and `walk_virtio_modern_caps` are now arch-agnostic. `pci::init_ecam(phys_base, size)` maps the window into TTBR1 via `memory::paging::map_range` on aarch64 (kernel frame allocator; bus 0 only, 1 MiB = 2 intermediate tables) and is a sanity check + VA publish on riscv64 (boot-HHDM gigapages already cover `[0, 4 GiB)`). `handle_device_info` is no longer x86-gated. Under `make run-aarch64-gui` (new target) the kernel discovers virtio-gpu-pci + virtio-keyboard-pci over ECAM, scanout-virtio-gpu + virtio-input bind, the compositor handshake completes, and `worm` renders frames — the verified failure mode before this landed was scanout-virtio-gpu hitting `SYS_DEVICE_INFO` = `Enosys` and falling into passive idle, which stalled the compositor's blocking `recv_verified(WelcomeCompositor)`.
- **2026-04-22** — Pong v0 (first-party app): `user/pong/` — third game in the HN-launch playable arc. Continuous-motion physics (8-bit subpixel integer fixed-point, AABB collision, classic-Pong spin, speed-capped AI), Tree-world palette (logs + acorn + grass). Replaces worm as default GUI boot module; worm + tree stay buildable for regression via `make worm` / `make tree` (and each `-aarch64` / `-riscv64` variant). Second consumer of `libgui::FrameClock` (extracted in the prior commit).
- **2026-04-22** — `libgui::FrameClock`: fixed-interval tick gate for self-driven apps. Pure-logic, host-testable; 7 unit tests covering boundary, refire, large-gap-no-catchup, backward-time, seed reset, zero-interval, step_ticks getter. Extraction trigger per Development Convention 9 (second consumer = pong).
- **2026-04-22** — Worm v0 (first-party app): `user/worm/` — classic snake on a 20×15 dirt grid with Tree-palette continuity (shared biosphere narrative). 200 ms tick, ring-buffer body + collision bitmap, bounded iteration. Replaces `tree` as default GUI boot module; `tree` retained for regression.
- **2026-04-21** — Tree v0 (first-party app): `user/tree/` — 9×9 Minesweeper homage on libgui + virtio-input, replaces `hello-window` as default GUI boot module; `hello-window` retained as protocol regression test.
- **2026-04-21** — Input-1 (ADR-012): `user/libinput-proto` 96-byte wire format; `user/virtio-input` driver (modern virtio-pci, device class probed via `VIRTIO_INPUT_CFG_EV_BITS`, evdev→HID translation); compositor forwards events to focused window on `COMPOSITOR_INPUT_ENDPOINT = 30`; libgui `Client::poll_event` drains on a tagged libgui-proto message. `make run-gui` captures Cocoa keyboard/mouse → serial log end-to-end. x86_64 only.
- **2026-04-21** — `user/libgui` v0: `Client::open`, `Surface` primitives (`fill_rect`, `draw_line` Bresenham, `draw_text_builtin` 8×8 ASCII font, `blit_bitmap` with optional chroma-key), `TileGrid`. hello-window ported to the library; Tree v0 consumes it.
- **2026-04-21** — Licensing: AGPLv3-or-later on kernel + services + apps, MPL-2.0 on `user/libsys/`. SPDX headers across every source + config file. LICENSE files at both scope levels. Repo now public at [github.com/coherentforge/CambiOS](https://github.com/coherentforge/CambiOS).
- **2026-04-21** — Docs pivot: [ADR-016](docs/adr/016-win-compat-api-ai-boundary.md) rewritten as "Windows Compatibility via Bounded Static Shims" (AI translator pipeline withdrawn); [ADR-017](docs/adr/017-user-directed-cloud-inference.md) slot reused for "User-Directed Cloud Inference" (generative-not-extractive principle operationalized).
- **2026-04-20** — Phase Scanout-4.b: scanout-virtio-gpu is the default scanout driver. Modern virtio-pci transport via kernel-parsed `VirtioModernCaps` + `SYS_VIRTIO_MODERN_CAPS = 38`. Five 2D ops (CREATE_2D / ATTACH_BACKING / SET_SCANOUT / TRANSFER_TO_HOST_2D / RESOURCE_FLUSH). `make run-gui` shows a visible green window.
- **2026-04-19 → 04-21** — [ADR-020](docs/adr/020-typed-user-buffer-slices-at-syscall-boundary.md) Phase A → B.1-B.5 → C landed: typed `UserReadSlice` / `UserWriteSlice` at the syscall boundary; every handler migrated; raw `u64` user pointers are type-system unreachable in production code. Phase D marked deferred with revisit triggers.
- **2026-04-19 → 04-20** — [ADR-021](docs/adr/021-typed-boot-error-propagation.md) Phase A → B.3 landed: `BootError` propagation from Limine adapter → APIC → timer / PLIC init. Phase C lint (`make check-boot-panics`) enforces no new panic sites in the curated boot-path file set.
- **2026-04-19** — RISC-V Phase R-6: riscv64 boots to `arcos>` shell prompt with 5 signed boot modules via `-initrd` (CAMBINIT archive). Third architecture at service-level parity.

## Subsystem status

**Archs column:** `x` = x86_64, `a` = AArch64, `r` = riscv64. `x/a/r` means first-class parity. Subsystems still gapped on one or two arches show what runs today; see known issues for what's missing.

| Subsystem | Status | Archs | Code | Design |
|---|---|---|---|---|
| Microkernel core | Done | x/a/r | `src/microkernel/`, `src/memory/` | [CambiOS.md](docs/CambiOS.md) |
| Per-CPU SMP scheduler | Done | x/a/r | `src/scheduler/` | [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) |
| Voluntary + preemptive context switch | Done | x/a/r | `src/arch/*/mod.rs` | [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) |
| IPC control path (256-byte messages) | Done | x/a/r | `src/ipc/` | [ADR-000](docs/adr/000-zta-and-cap.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) |
| IPC bulk path (shared-memory channels) | Done (Phase 3.2d) | x/a/r | `src/ipc/channel.rs` | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) |
| Capability revocation | Done (Phase 3.1, bootstrap-authority only; grantor + revoke-right paths deferred to post-v1) | x/a/r | `src/ipc/capability.rs` | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) |
| Boot-time-sized kernel object tables | Done (Phase 3.2a-d) | x/a/r | `src/config/tier.rs`, `src/memory/object_table.rs`, `src/process.rs`, `build.rs` | [ADR-008](docs/adr/008-boot-time-sized-object-tables.md) |
| Deployment tiers | Designed, policy-only (single binary; tier selects `TableSizingPolicy` at install) | — | — | [ADR-009](docs/adr/009-purpose-tiers-scope.md), [GOVERNANCE.md](docs/GOVERNANCE.md) |
| Audit infrastructure | Done (Phase 3.3) | x/a/r | `src/audit/` | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) |
| Audit consumer capability + `audit-tail` | Done (bootstrap-only check replaced) | x/a/r | `user/audit-tail/`, `src/ipc/capability.rs` (`AuditConsumer`), `src/syscalls/dispatcher.rs` (`handle_get_process_principal`), `src/process.rs` (`RecentExitsRing`) | [ADR-023](docs/adr/023-audit-consumer-capability.md) |
| Policy service (syscall allowlisting) | Done (Phase 3.4b, per-process allowlists) | x/a/r | `user/policy-service/` | [ADR-006](docs/adr/006-policy-service.md) |
| Cryptographic identity | Done (Phase 1C, hardware-backed + load-bearing) | x/a/r | `src/ipc/`, `src/syscalls/`, `user/libsys/`, `bootstrap_pubkey.bin` | [identity.md](docs/identity.md), [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) |
| `did:key` encoding (Principal ↔ `did:key:z6Mk…`) | Done (encoder + decoder; not full DID resolution) | x/a/r | `user/libsys/src/lib.rs` (`did_key_encode`/`did_key_decode`), `user/shell/src/main.rs` (`did-key` cmd) | [identity.md](docs/identity.md) Phase 4 |
| Signed ELF loading | Done (ARCSIG trailer, Ed25519) | x/a/r | `src/loader/` | [ADR-004](docs/adr/004-cryptographic-integrity.md) |
| Content-addressed ObjectStore (RAM) | Done (Phase 1C, fallback) | x/a/r | `src/fs/ram.rs` | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) |
| Persistent ObjectStore (disk) | Done (Phase 4b) | x (via virtio-blk) | `src/fs/disk.rs`, `src/fs/block.rs`, `src/fs/lazy_disk.rs`, `src/fs/virtio_blk_device.rs` | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) |
| BlockDevice abstraction | Done (Phase 4a.i) | x/a/r | `src/fs/block.rs` | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) |
| FS service | Done (endpoint 16, ObjectStore gateway) | x/a/r | `user/fs-service/` | — |
| Key-store service | Done (endpoint 17, degraded mode — no runtime YubiKey yet) | x/a/r | `user/key-store-service/` | — |
| Virtio-blk driver | Done (Phase 4b, dual-endpoint user/kernel) | x/a/r | `user/virtio-blk/` | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) |
| Virtio-net driver | Done (Phase 4c, modern virtio-pci on x86_64; legacy MMIO on aarch64+riscv64; live in boot, drives udp-stack NTP demo) | x/a/r | `user/virtio-net/` | — |
| Intel I219-LM driver | Scaffolded, untested on hardware | x | `user/i219-net/` | — |
| UDP/IP stack (ARP/IPv4/UDP + NTP demo) | Done | x/a | `user/udp-stack/` | — |
| Shell (`arcobj` CLI incl.) | Done | x/a/r | `user/shell/` | — |
| Spawn / WaitTask syscalls | Done | x/a/r | `src/syscalls/dispatcher.rs` | — |
| PCI bus discovery | Done (x86_64 = port I/O mechanism 1; aarch64 + riscv64 = ECAM via `init_ecam`; riscv64 also synthesizes virtio-mmio via `register_virtio_mmio`) | x/a/r | `src/pci/` | — |
| Device syscalls (MapMmio/AllocDma/DeviceInfo/PortIo/VirtioModernCaps) | Done | x/a/r | `src/syscalls/dispatcher.rs` | — |
| Bootloader abstraction (BootInfo + `src/boot/`) | Done (Phase GUI-0) | x/a/r | `src/boot/` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) |
| `SYS_MAP_FRAMEBUFFER` + graphics capabilities | Done (Phase GUI-0) | x/a | `src/syscalls/dispatcher.rs`, `src/ipc/capability.rs` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) |
| Compositor (incl. Input-1 event routing) | Done (Scanout-2/3 + Input-1) | x/a | `user/compositor/` | [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) |
| scanout-virtio-gpu driver (default) | Done (Scanout-4.b; aarch64 enabled by kernel ECAM 2026-04-22) | x/a | `user/scanout-virtio-gpu/` | [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) |
| scanout-limine driver (fallback, not in default boot) | Done | x/a | `user/scanout-limine/` | [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) |
| pong v0 (first-party app, default GUI boot module) | Done | x | `user/pong/` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md), [ADR-012](docs/adr/012-input-architecture-and-device-classes.md), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) |
| worm v0 (first-party app, buildable; default GUI on aarch64 `run-aarch64-gui` + regression on x86_64) | Done | x/a | `user/worm/` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md), [ADR-012](docs/adr/012-input-architecture-and-device-classes.md) |
| tree v0 (first-party app, buildable; retained for regression) | Done | x | `user/tree/` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md), [ADR-012](docs/adr/012-input-architecture-and-device-classes.md), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) |
| hello-window | Done, buildable; retained as protocol regression (replaced by `tree` → `worm` → `pong` as default GUI boot module) | x | `user/hello-window/` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) |
| libgui::FrameClock | Done | x/a/r (host-testable) | `user/libgui/src/frame_clock.rs` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) |
| libgui v0 (GUI client library) | Done | x/a/r (buildable; GUI only runs where scanout driver exists) | `user/libgui/` | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) |
| libinput-proto (wire format) | Done (Input-0) | x/a/r | `user/libinput-proto/` | [ADR-012](docs/adr/012-input-architecture-and-device-classes.md) |
| virtio-input driver | Done (Input-1) | x/a | `user/virtio-input/` | [ADR-012](docs/adr/012-input-architecture-and-device-classes.md) |
| APIC + I/O APIC + SMP IPI | Done | x | `src/arch/x86_64/` | — |
| GIC v3 + ARM Generic Timer | Done | a | `src/arch/aarch64/` | — |
| PLIC + SBI timer + SBI IPI | Done | r | `src/arch/riscv64/` | [ADR-013](docs/adr/013-riscv64-architecture-support.md) |
| TLB shootdown | Done (x86 vector-IPI / ARM TLBI broadcast / RISC-V SBI IPI) | x/a/r | `src/arch/*/tlb.rs` | — |
| Process lifecycle cleanup | Done (Phase 3.2d.ii; kernel stack free deferred) | x/a/r | `src/syscalls/dispatcher.rs`, `src/process.rs` | — |
| USB boot tooling | Done (`make img-usb` + `make usb DEVICE=...`) | x | `Makefile` | — |
| Formal verification (Kani) | Started 2026-04-16. Live across 4 proof crates: `BuddyAllocator::free` reserved-prefix (150 checks, ~18s); ELF header parser in `src/loader/elf.rs` (7 harnesses covering `parse_header`, `get_program_header`, `analyze_binary`, `collect_load_segments`; proof authoring found + fixed 6 integer-overflow sites); FrameAllocator in `src/memory/frame_allocator.rs` (9 harnesses covering `allocate`, `free`, `allocate_contiguous`, `free_contiguous`, `add_region` overflow; fixed 2 overflow sites with `saturating_add`; `reserve_region` overflow blew CBMC's budget and is covered by unit tests instead); capability manager in `src/ipc/capability.rs` (12 harnesses — Tier A `ProcessCapabilities` state-machine invariants + Tier B cross-process properties on a 3-slot `Box::leak`'d manager: stale-generation rejection, no-delegate-without-right, no-escalation, `revoke_all` clears endpoint + system caps, non-bootstrap revoke denied). 29 passing harnesses total. Compositor protocol parser deferred until scanout settles past Scanout-4.c. | — | `verification/{buddy,elf,frame,capability}-proofs/` | [ADR-000 § Divergence](docs/adr/000-zta-and-cap.md) |
| AArch64 SMP timer on AP | **Gap**: PPI 30 not firing on second CPU under QEMU `virt`. Single-CPU works. | a | — | — |
| DHCP client | Paused (pre-work in `udp-stack`; waiting on channel architecture consumer) | — | partial in `user/udp-stack/` | — |
| DNS / TCP / Yggdrasil mesh / TLS / VFS / USB HID / DID resolution / identity revocation | Planned | — | — | [identity.md](docs/identity.md), various ADRs |
| AI pre-exec analysis / behavioral anomaly detection / Win32 compat | Planned (post-v1) | — | — | [CambiOS.md](docs/CambiOS.md), [ADR-016](docs/adr/016-win-compat-api-ai-boundary.md), [ADR-017](docs/adr/017-user-directed-cloud-inference.md) |

## Roadmap

### Identity / storage phases

Source: [identity.md](docs/identity.md), [FS-and-ID-design-plan.md](docs/FS-and-ID-design-plan.md).

| Phase | Goal | Status |
|---|---|---|
| **0** | Identity primitives in kernel + RAM ObjectStore (stamps identity on every IPC; every object has author + owner) | Done |
| **1** | Real cryptography: Blake3, Ed25519, signed ELF, key-store service | Done |
| **1B** | YubiKey-derived bootstrap pubkey compiled into kernel | Done |
| **1C** | Key-store degraded mode + signed ObjectStore puts + identity gate (no unsigned fallback) | Done |
| **2A** | First user-space hardware driver (virtio-net) | Done |
| **2B** | First user-space network service (UDP/IP + NTP demo) | Done |
| **3** | Architecture substrate: revocation (3.1), CreateProcess cap (3.2b), ProcessId generation counters (3.2c), channels (3.2d), audit (3.3), policy service (3.4b) | Done |
| **4** | Persistent storage: virtio-blk + disk ObjectStore + `arcobj` CLI | Done |
| **5** | Identity-routed Yggdrasil networking | Planned |
| **6** | Biometric commitment + key recovery | Planned (post-v1) |
| **7** | SSB bridge | Planned (post-v1) |

### v1 target

*Interactive, network-capable, identity-rooted OS running on real hardware with persistent storage.* Items are dependency-ordered. Blocker = Intel I219-LM real-hardware bring-up on Dell 3630.

| # | Item | Status |
|---|---|---|
| 1 | Shell | Done |
| 2 | USB boot tooling | Done (untested on target hardware) |
| 3 | Intel I219-LM NIC driver | Scaffolded (untested on target hardware) |
| 4 | DHCP client | Paused |
| 5 | DNS resolver | Planned |
| 6 | TCP stack | Planned |
| 7 | Virtio-blk driver | Done |
| 8 | Persistent ObjectStore | Done |
| 9 | `arcobj` CLI | Done |
| 10 | Yggdrasil peer service | Planned |

### RISC-V arch port

Parity-target with x86_64 / AArch64. All phases landed as of 2026-04-19. Source: [ADR-013](docs/adr/013-riscv64-architecture-support.md).

| Phase | Goal | Status |
|---|---|---|
| **R-0** | Build infra + tri-arch gate | Done (2026-04-15) |
| **R-1** | First serial output, `kmain_riscv64` banner | Done (2026-04-16) |
| **R-2** | Sv48 higher-half, DTB parser, frame allocator + heap | Done (2026-04-16) |
| **R-3** | Trap vector, SBI timer, PLIC, context switch, 100 Hz preemption | Done (2026-04-18) |
| **R-4** | U-mode transition via `sscratch`/`tp` swap, ELF `EM_RISCV` | Done (2026-04-18) |
| **R-5** | SMP (SBI HSM), cross-hart TLB shootdown (SBI IPI) | Done (2026-04-18/19) |
| **R-6** | Service parity: virtio-mmio transport, `-initrd` signed modules, 5 boot services | Done (2026-04-19) |

## Test coverage

Total: **538** on `x86_64-apple-darwin`. Run `RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin`, or `make stats` for the current number.

Major categories (approximate; breakdown drifts faster than the total):

| Area | Tests |
|---|---|
| Scheduler | 35 |
| Capability manager | 40 |
| IPC (interceptor, sender_principal, sync channel) | 17 |
| Channel manager | 29 |
| Process lifecycle cleanup | 3 |
| ELF verifier (incl. signed binary) | 14 |
| ObjectStore types + crypto | 21 |
| RamObjectStore | 12 |
| BlockDevice abstraction | 11 |
| DiskObjectStore (incl. reboot preservation) | 30 |
| Memory subsystem (buddy, frame, heap, paging, contiguous) | ~37 |
| Tier configuration | 16 |
| Kernel object table region | 5 |
| Audit (staging + events + ring/drain) | 44 |
| Syscall dispatcher (Cuts 1/2/3a) | 40 |
| Syscalls user_slice (ADR-020 Phase A) | 26 |
| Boot adapter (BootInfo + initrd parser) | 8 |
| PCI virtio-modern caps | 11 |
| AArch64 portable logic | 12 |
| Timer, ProcessTable, VMA tracker, syscall args, other | ~127 |

**User-space crates** have their own host tests: libgui v0 ships 26 (drawing primitives + TileGrid + font coverage); libinput-proto ships 8 (wire format, round-trips, signature preservation); libgui-proto ships 13 (including `input_event_roundtrip`). Run `cargo test --lib --target x86_64-apple-darwin` from each crate directory.

## Known issues (active)

- **AArch64 SMP timer on AP**: PPI 30 not firing on second CPU under QEMU `virt`. Single-CPU works fully. Likely QEMU config or missing GIC redistributor step on the AP path. Investigation pending.
- **AArch64 device IRQ routing**: GIC `enable_spi` / `set_spi_trigger` exist but are not called from the boot path or `handle_wait_irq`. No device IRQs on aarch64 today. **Revisit when:** first aarch64 path needs device IRQs (likely a polling→IRQ-driven transition in virtio-blk, or resolution of the AP-timer gap enabling PL011 RX to drive a consumer).
- **ELF loader overlapping-segment permissions**: If two PT_LOAD segments share a page with different permissions, the first segment's permissions win. Worked around in user-space linker scripts via `ALIGN(4096)` before `.data`.
- **Kernel stack not freed on process exit**: `handle_exit` now performs full lifecycle cleanup (Phase 3.2d.ii), but the 32 KiB kernel stack per task remains a bounded leak — can't free the stack you're running on. Requires scheduler-level deferred-dealloc. Bounded by `num_slots × 32 KiB` (~6.4 MiB worst case).
- **Clippy warnings** (~125): ~67 `multiple_unsafe_ops_per_block` in arch code, ~25 missing `// SAFETY:`, ~12 `static_mut_refs` (Rust 2024 migration — IDT/GDT/TSS patterns need `UnsafeCell` or `addr_of!`), ~20 `new_without_default`. Dedicated pass scheduled before `static_mut` deprecation becomes a hard error.
- **Pre-existing driver warnings** in `user/i219-net/`: `dead_code` / `unused_imports` from scaffolded state. Not correctness issues; clean up on next real-hardware bring-up.
- **Virtio-net TX on QEMU TCG**: QEMU defers virtio TX to its event loop, which runs during guest `hlt`. The UDP stack's ARP retry/timeout logic doesn't yet exploit this fully.

## Cross-references

- [CambiOS.md](docs/CambiOS.md) — source-of-truth architecture document
- [identity.md](docs/identity.md) — identity architecture (Phases 0-7 defined here)
- [FS-and-ID-design-plan.md](docs/FS-and-ID-design-plan.md) — storage + identity decisions
- [SECURITY.md](docs/SECURITY.md) — enforcement status (security subset)
- [GOVERNANCE.md](docs/GOVERNANCE.md) — governance, deployment tiers, scope
- [ASSUMPTIONS.md](docs/ASSUMPTIONS.md) — catalog of numeric bounds (SCAFFOLDING / ARCHITECTURAL / HARDWARE / TUNING)
- [README.md](README.md) — public-facing summary
- [SCHEDULER.md](src/scheduler/SCHEDULER.md) — scheduler implementation reference
- [docs/adr/INDEX.md](docs/adr/INDEX.md) — architecture decision records (000-021, auto-generated)
- [CLAUDE.md](CLAUDE.md) — kernel technical reference + required-reading map
