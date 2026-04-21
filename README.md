# CambiOS

*A secure bridge from human consciousness to the electron.*

CambiOS is a general-purpose operating system built on a verification-ready microkernel written in Rust. Every process is isolated, every binary is verified before it runs, every IPC message carries an unforgeable cryptographic identity, and nothing in the stack phones home. It targets **x86_64**, **AArch64**, and **RISC-V (riscv64gc)**, boots in QEMU on all three, and is designed to eventually run on sovereign silicon.

- Why CambiOS exists → [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md)
- What's built right now → [STATUS.md](STATUS.md)
- Kernel technical reference and per-subsystem required reading → [CLAUDE.md](CLAUDE.md)

---

There are two essential problems with modern operating systems. The first we're fixing here. The second is on a longer arc.

## The Software Problem

It's an open secret. Modern operating systems — Windows, macOS, Linux — are inherently leaky, buggy, and insecure. They were designed for a world that no longer exists: one where vendors are trustworthy, your identity comes from "someone else," a password is adequate to protect it, and code was trusted to swim in one vast pool with no lanes or lifeguards. Every telemetry scandal, every ransomware story, every "a kernel extension crashed my laptop" moment traces back to one of those assumptions. Zero-day exploits come alive here, where memory safety really isn't, privilege equals access, and every attack is an escalation.

CambiOS rejects this, fundamentally, at the design level. Rust itself closes entire classes of memory bugs. The kernel (the "pool") is *very* small. Drivers and services run isolated in user-space — a crash here is more a hiccup than a blue screen of death. Every process has a cryptographic identity. Every binary is verified before it runs. Every IPC message carries an unforgeable sender. There are no privileges to escalate — no capabilities are given without established credentials. Nothing phones home. This is 99% of what's wrong with modern operating systems — and it's fixable today, in software, without waiting for anyone.

## The Hardware Problem

Below all of that sits silicon with coprocessors you don't own. On Intel, the Management Engine: its own processor, its own network stack, its own private keys, DMA access to main memory, running whether the machine is "on" or just plugged in. AMD ships the Platform Security Processor. ARM ships TrustZone. This is documented hardware design, not conspiracy.

CambiOS cannot neutralize those coprocessors. No software can. The long-term answer is open hardware all the way down, and we are building toward it. Until then, most people are running on x86 or ARM, and they deserve a software stack that does not add to the problem. In the not too distant future, our goal is an open architecture from silicon through software. A future where CambiOS runs on top of CamBIOS open source firmware — including the boot path and TPM. Until that day, we close the holes we can.

---

## Status

CambiOS boots to preemptive SMP multitasking on all three target architectures under QEMU. The security model — cryptographic identity, signed-binary verification, capability-checked IPC, content-addressed object store — is implemented and exercised end-to-end. Static analysis and fuzzing are active; formal verification is the destination.

[STATUS.md](STATUS.md) is the canonical account of what is built, in progress, and planned, including phase markers, per-subsystem status, and known issues. Run `make stats` for current syscall, test, and LOC counts (those numbers live in the source, not in prose).

---

## Building

Host: macOS (Apple Silicon). Kernel binaries run only under QEMU or on bare-metal target hardware — never on the host.

Prerequisites:
- Rust nightly (pinned in `rust-toolchain.toml`)
- Targets: `x86_64-unknown-none`, `aarch64-unknown-none`, `riscv64gc-unknown-none-elf`
- QEMU (Homebrew)
- `mtools` (AArch64 FAT disk images)
- Limine is auto-cloned; OpenSBI ships with QEMU as `-bios default` for RISC-V

```bash
# Unit tests (host macOS)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Tri-architecture regression gate — REQUIRED before any commit
make check-all              # x86_64 + aarch64 + riscv64

# Run in QEMU
make run                    # x86_64
make img-aarch64 && make run-aarch64
make run-riscv64

# Derived counts (syscalls, tests, LOC)
make stats

# Sign a boot module (YubiKey-backed; --seed <hex> for CI without hardware)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf <elf-file>
```

The full build / test / lint commands and their rationale live in [CLAUDE.md](CLAUDE.md#quick-reference). If a command above drifts, CLAUDE.md is authoritative.

---

## Architecture

CambiOS is a microkernel. The kernel handles five things: scheduling, memory management, IPC, syscall dispatch, and cryptographic identity. Filesystems, networking, device drivers, window management, and every other service run as isolated user-space processes communicating over capability-checked IPC.

This is structural isolation, not policy. A buggy filesystem service cannot corrupt the kernel. A compromised network driver cannot read another process's memory. A malicious module cannot forge the identity of a peer.

### Enforcement pipeline

Every piece of code that runs on CambiOS passes through the same sequence of checks, with no bypass:

```
ELF binary arrives
    → BinaryVerifier: W^X, entry validation, overlap detection, Ed25519 signature
    → IPC send:  capability check, interceptor hook, sender_principal stamp
    → IPC recv:  capability check, interceptor hook
    → Syscall pre-dispatch: interceptor hook before handler
    → ObjectStore: ownership enforced on get / put / delete
```

The three interceptor hooks collapse into one trait that an out-of-kernel policy service can drive — see [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md).

### Identity

Every process is bound to a **Principal**: a 32-byte Ed25519 public key. The kernel stamps the sender's Principal onto every IPC message. It cannot be forged — user-space code never has the opportunity to write that field. Receivers enforce ownership, access control, and audit on the stamped identity rather than on sender claims.

The bootstrap Principal derives from a compiled-in YubiKey public key. No private key ever lives in kernel memory. Quantum-resistant signatures are planned.

Full model: [docs/identity.md](docs/identity.md), [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md).

### IPC

Two paths, chosen by workload shape:

- **Control path** — fixed-size (256-byte) messages, capability-gated, sharded per endpoint. Predictable for verification; used for commands, replies, and small events.
- **Bulk data path** — shared-memory channels with MMU-enforced producer / consumer / bidirectional roles. Creator names the peer Principal; the kernel verifies identity on attach. Used for video frames, file payloads, and any workload where 256 bytes does not fit.

See [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md).

### Lock ordering and memory layout

Strict lock hierarchy, no exceptions, documented and enforced in source. Every `unsafe` block carries a `// SAFETY:` comment. The canonical hierarchy and memory-layout tables live in [CLAUDE.md § Lock Ordering](CLAUDE.md#lock-ordering) and are intentionally not duplicated here — they drift.

---

## Boot Sequence

All three architectures share the same high-level sequence:

1. Firmware / bootloader loads the kernel ELF and hands over a memory description.
2. Early MMU and exception-vector setup, heap and frame allocator initialization.
3. Interrupt controller + timer + per-CPU data structures.
4. IPC manager, capability manager, zero-trust interceptor.
5. Bootstrap Principal built from the compiled-in YubiKey public key.
6. Kernel object tables sized from detected memory and the active tier policy ([ADR-008](docs/adr/008-boot-time-sized-object-tables.md)).
7. Signed ELF boot modules verified and loaded, one per entry in `BOOT_MODULE_ORDER`.
8. AP cores come online with per-CPU scheduler state.
9. Preemptive SMP scheduling begins.

Where the architectures differ:

- **x86_64 / AArch64** boot via Limine (version pinned in the Makefile). x86_64 also parses ACPI + programs the I/O APIC + calibrates the APIC timer via the PIT. AArch64 widens `TCR_EL1.T1SZ` and maps device MMIO (PL011, GIC) into TTBR1, then initializes GICv3 and the ARM Generic Timer.
- **RISC-V** boots via OpenSBI in M-mode, which hands a DTB pointer to a custom S-mode stub in `src/boot/riscv.rs`. Timer and IPI go through SBI calls; external interrupts arrive via PLIC. No Limine — see [ADR-013](docs/adr/013-riscv64-architecture-support.md).

The narrative walkthrough of what actually happens during boot, including the bootstrap paradoxes, is [Manual 01: Waking Up](docs/manuals/01-waking-up.md).

---

## Project Structure

```
src/
├── microkernel/main.rs      # Kernel entry, subsystem init sequence
├── arch/                    # Per-architecture backends
│   ├── x86_64/              #   GDT, APIC, SYSCALL/SYSRET, I/O APIC, TLB IPI, SMP
│   ├── aarch64/             #   GICv3, ARM Generic Timer, SVC, TLBI, EL0/EL1
│   └── riscv64/             #   PLIC, SBI timer/IPI, ecall dispatch, Sv48 paging
├── boot/                    # Bootloader-abstracted BootInfo (Limine / OpenSBI adapters)
├── scheduler/               # Priority-band preemptive SMP scheduler (portable)
├── ipc/                     # Capability-based IPC, Principal, channels, interceptor
├── syscalls/                # Syscall dispatch and handlers (list: `make stats`)
├── memory/                  # Frame allocator, buddy allocator, page tables, object tables
├── fs/                      # CambiObject, ObjectStore, Blake3, Ed25519, persistent disk store
├── loader/                  # ELF loader, BinaryVerifier, SignedBinaryVerifier
├── pci/                     # PCI bus scan, device table, BAR decoding
├── audit/                   # Lock-free per-CPU audit buffers + global drain ring
└── config/                  # Tier policy (compile-time deployment-tier selection)

user/                        # User-space services — each one is an isolated boot module
├── libsys/                  # Syscall wrapper library (the only unsafe user-space crate)
├── libfs-proto/ libgui-proto/ libscanout/ libterm/ libflag/   # Service-protocol libraries
├── fs-service/              # Content-addressed object store front-end
├── key-store-service/       # Ed25519 signing service (bootstrap-key holder)
├── policy-service/          # Out-of-kernel policy decisions via interceptor hook
├── virtio-{net,blk}/ i219-net/ udp-stack/ dhcp-client/   # Network + storage drivers / stack
├── compositor/ scanout-{limine,virtio-gpu}/              # Graphics stack (ADR-011/014)
└── shell/                   # Interactive serial shell

tools/sign-elf/              # Host-side ELF signing tool (YubiKey or seed-based)
fuzz/                        # cargo-fuzz targets with shadow-model oracles
docs/                        # Design docs, ADRs, manuals
```

The authoritative list of *what actually builds into the boot image* is the `BOOT_MODULE_ORDER` constant in `src/boot_modules.rs` and the Makefile's per-target module rules. If the tree above and the Makefile disagree, the Makefile wins.

---

## Contributing

CambiOS is looking for people who understand what's at stake — OS internals, compiler infrastructure, hardware security, ML systems, formal methods. The foundation is real. The work ahead is larger than any one person should do alone.

**Before you write code:**

1. Read [CLAUDE.md](CLAUDE.md). It is the kernel's technical reference and the contract for how changes get made — conventions, lock ordering, per-subsystem required reading, post-change review protocol. Every non-trivial PR is judged against it.
2. Read the ADRs for the subsystem you are about to touch. The required-reading map in CLAUDE.md names them.
3. Check [STATUS.md](STATUS.md) to confirm the work is not already in progress in another phase.

**Working rules:**

- **Tri-architecture regression gate is mandatory.** `make check-all` must pass before any commit — no commit may regress x86_64, aarch64, or riscv64. See [ADR-013](docs/adr/013-riscv64-architecture-support.md) § Tri-Architecture Regression Discipline.
- **Commits are PGP-signed.** The repo enforces signing at the Git level; unsigned commits will not land.
- **Every `unsafe` block needs a `// SAFETY:` comment** explaining the invariants that make the operation sound.
- **No panics, unwraps, or expects in kernel code.** Every failure is a typed `Result`.
- **No dynamic dispatch in kernel hot paths.** Monomorphized generics only — verifiers cannot reason about trait objects.
- **Design changes warrant an ADR.** A new decision or a divergence from an existing ADR is captured in `docs/adr/` before or alongside the code change, not after. `make check-adrs` verifies cross-references.

The full catalog of conventions (numeric-bound discipline, deferral discipline, unsafe minimization, documentation-sync expectations) lives in [CLAUDE.md § Development Conventions](CLAUDE.md#development-conventions).

---

## Manuals

Narrative walkthroughs that follow a concrete thing through the system, useful if you are new to the codebase and want the *why* before the *what*:

- [01 — Waking Up](docs/manuals/01-waking-up.md): the boot sequence as a story
- [02 — The Life of a Message](docs/manuals/02-life-of-a-message.md): an IPC message from syscall to delivery
- [03 — The Signature Chain](docs/manuals/03-signature-chain.md): YubiKey to boot verification
- [04 — Why a Buggy Driver Can't Kill You](docs/manuals/04-driver-isolation.md): microkernel isolation told through consequences
- [05 — From NTP Query to UTC Clock](docs/manuals/05-ntp-query.md): a UDP packet end-to-end through the network stack

---

## Design Documents

- [CambiOS.md](docs/CambiOS.md) — source-of-truth architecture
- [PHILOSOPHY.md](docs/PHILOSOPHY.md) — why this project exists, the AI-watches-not-decides stance
- [SECURITY.md](docs/SECURITY.md) — zero-trust enforcement map
- [identity.md](docs/identity.md) — Ed25519 Principals, author/owner model, revocation
- [FS-and-ID-design-plan.md](docs/FS-and-ID-design-plan.md) — identity + storage phase intent
- [win-compat.md](docs/win-compat.md) — Windows compatibility layer design
- [ASSUMPTIONS.md](docs/ASSUMPTIONS.md) — catalog of every numeric bound in kernel code
- [GOVERNANCE.md](docs/GOVERNANCE.md) — project governance, deployment tiers

**Architecture Decision Records** live under [docs/adr/](docs/adr/). The current set, with titles and status, is auto-generated in [docs/adr/INDEX.md](docs/adr/INDEX.md) by `make check-adrs` — treat that as authoritative rather than any enumeration in prose (which drifts).

---

## Licensing

CambiOS is dual-licensed.

- **Kernel, services, host tools, and first-party applications: [AGPLv3-or-later](LICENSE).** Modifications, derivatives, and network-service uses must stay open under AGPL. The "generative, not extractive" posture enforced by a license that keeps the stack visible and the contributions open.
- **User-space syscall library ([user/libsys/](user/libsys/LICENSE)): [MPL-2.0](user/libsys/LICENSE).** File-level copyleft — modifications to libsys must stay open, but applications that *link* libsys are free to ship under any license the application author chooses. Permits proprietary third-party apps on CambiOS without forcing the kernel or services into permissive territory.

Every source file carries an `SPDX-License-Identifier:` header. Per-crate `license` fields are set in each `Cargo.toml`. The bucketing is mechanical: files under `user/libsys/` are MPL-2.0; everything else is AGPL-3.0-or-later.

The kernel only loads signed modules. Users control their own trust chain: add signing keys, remove the default, replace it entirely. It's their machine.

Anyone can fork the code — the license permits it. The name **CambiOS** belongs to the distribution whose security model is intact. Code enforcement is technical; naming enforcement is legal.

---

## References

- [Limine Boot Protocol](https://github.com/limine-bootloader/limine)
- [OpenSBI](https://github.com/riscv-software-src/opensbi) — RISC-V M-mode firmware
- [seL4 Microkernel](https://sel4.systems/) — verification reference
- [OSDev Wiki](https://wiki.osdev.org/)
- [Rust on Baremetal](https://github.com/rust-osdev)

---

*No telemetry. No analytics. No management engine. No compromises on the things that matter.*
