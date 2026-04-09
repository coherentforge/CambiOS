# ArcOS

> *Your computer... is not your own.*

Right now, before your OS boots, before your kernel loads, before any software you chose runs — a separate processor with its own OS, its own network stack, and its own keys is already running. You didn't install it. You can't audit it. You can't turn it off. On Intel machines it's called the Management Engine. On AMD it's the Platform Security Processor. It has DMA access to your memory. It runs whether your machine is on or off, as long as it has power. 

This is not a conspiracy theory. It is documented hardware design. Even Apple's Secure Enclave cannot be verified all the way down.

Almost everything running on top of this foundation — whether Windows, macOS, Linux — layers additional extraction: telemetry baked into the kernel, analytics in the bootloader, identifiers that follow you across reinstalls. The software stack most people trust with their most sensitive data was designed, at a fundamental level, around interests that are not theirs.

Ready to take it back? ArcOS is your response.

---

## What ArcOS Is

ArcOS is a complete modern operating system — one ordinary users can run, with a GUI, real applications, and a user experience that is inherently private and secure. Not as a locked-down appliance. As a general-purpose computer that is verifiably yours.

At its foundation is a microkernel written from first principles in Rust:

- **Every process is isolated.** Device drivers, networking, and filesystems run in user-space. The kernel attack surface is minimal by design.
- **Every binary is verified before it runs.** Cryptographic identity is threaded through the entire stack — from boot modules to IPC messages to stored objects.
- **Every IPC message carries an unforgeable sender identity.** The kernel stamps it. Nothing in user-space can lie about who sent what.
- **No telemetry. No analytics. No phone-home behavior.** Ever. Not now, not in future versions. This is a design constraint, not a policy.
- **Designed to host LLM security services.** Behavioral anomaly detection, just-in-time binary analysis, and automatic threat quarantine — running locally, on hardware you control.

---

## Honesty About the "Hardware Problem"

ArcOS runs on x86_64 and AArch64. On those platforms it dramatically reduces the software attack surface — capability-based IPC, zero-trust enforcement, cryptographic identity, verified execution protect against a vast category of threats that affect everyone running conventional systems.

But it cannot remove Intel ME or AMD PSP. Those coprocessors sit below the kernel — ME and PSP on x86, TrustZone on ARM. No software can fully neutralize them. ArcOS is explicit about this rather than pretending otherwise.

**True security and true sovereignty are undercut until the hardware beneath the kernel is open and auditable.** Everything ArcOS builds — verified boot, signed binaries, unforgeable identity — sits on a foundation it cannot yet inspect. That is not an acceptable permanent state.

The long-term answer is open hardware all the way down. We're building toward that. In the meantime most people are on x86, and they deserve better security now, and clear eyes about what the silicon underneath still does.

---

## Current State

Built by one person. In two weeks of coding:

- **213/213 unit tests passing.** Clean release builds on both x86_64 and AArch64.
- **x86_64 boots to stable preemptive SMP multitasking** in QEMU: 2 CPUs, 10 concurrent tasks, APIC timer at 100Hz, IRQ affinity, load balancing, PCI device discovery, 24 syscalls.
- **AArch64 boots to stable preemptive SMP scheduling** in QEMU: GICv3, ARM Generic Timer at 100Hz, EL0 user tasks with per-process page tables.

**The security model is real and running:**
- Cryptographic identity backed by hardware YubiKey — no secret key in kernel memory. Open secure element long-term.
- Boot modules signed at build time, verified before execution
- User-space services (filesystem, key store, virtio-net, UDP stack) isolated behind capability-checked IPC, each message carrying an unforgeable sender identity
- Content-addressed object store with Blake3 hashing, Ed25519 signatures, and ownership enforcement

Every unsafe block has a // SAFETY: comment. Lock ordering is documented and enforced. The code is written to be read.

The kernel is real. The security model is real. This code is not a prototype.

---

## Architecture

ArcOS is a full operating system. Its kernel is a microkernel and does five things: scheduling, memory management, IPC, syscall dispatch, and cryptographic identity. Everything else - filesystems, networking, device drivers - all run as isolated user-space services communicating over capability-checked IPC.

The attack surface is small by design. A buggy filesystem service can't take down the kernel. A compromised network driver can't read another process's memory. Isolation is structural, not policy.

**Enforcement is layered and has no bypass:**
```
ELF binary arrives
    → BinaryVerifier: W^X, entry point validation, overlap detection, signature check
    → IPC send: capability check, interceptor hook, sender_principal stamp
    → IPC recv: capability check, interceptor hook
    → Syscall pre-dispatch: interceptor hook before handler
    → ObjectStore: ownership enforced on every get/put/delete
```

Identity is a 32-byte Ed25519 public key bound to every process (quantum resistant keying planned.) The kernel stamps Identity onto every IPC message — unforgeable, no trust required from user-space. The bootstrap Principal derives from a compiled-in YubiKey public key. No private key lives in kernel memory.

IPC is capability-based, sharded per-endpoint, with fixed 256-byte messages for predictable verification. Three enforcement points: IpcManager send/recv, syscall pre-dispatch, capability delegation.
For detailed internals — lock ordering, memory layout, syscall reference, scheduler design — see the Design Documents section below.

## Boot Sequence

ArcOS boots via the **Limine v8.7.0** boot protocol on both architectures.

The boot sequence is where trust is established — before any user-space code runs.

### x86_64

1. Limine loads kernel ELF, provides memory map, HHDM, RSDP
2. Kernel heap initialized (4MB), frame allocator initialized
3. ACPI regions mapped into HHDM, MADT parsed for I/O APIC
4. Per-CPU GDT/TSS installed, IDT loaded, SYSCALL MSRs configured
5. PIC disabled, I/O APIC programmed, APIC timer started at 100Hz
6. IPC manager, capability manager, and zero-trust interceptor initialized
7. Bootstrap Principal created from compiled-in YubiKey public key, bound to kernel processes
8. PCI bus scan, device table populated
9. Signed ELF boot modules loaded and verified (hello, key-store, fs-service, virtio-net, udp-stack) with per-process page tables
10. AP cores started via Limine MP protocol — per-CPU GDT, APIC, scheduler
11. Preemptive SMP scheduling begins

### AArch64

1. Limine loads kernel ELF, provides memory map, HHDM
2. TCR_EL1.T1SZ widened to 16 (48-bit VA for HHDM)
3. Early MMIO mapping: PL011 UART, GIC Distributor/Redistributor into TTBR1
4. Kernel heap and frame allocator initialized
5. GIC distributor, redistributor, and CPU interface initialized
6. ARM Generic Timer started at 100Hz
7. Exception vector table installed, SVC handler configured
8. IPC manager, capability manager, and zero-trust interceptor initialized
9. Bootstrap Principal created from compiled-in YubiKey public key, bound to kernel processes
10. Signed ELF boot modules loaded and verified with per-process page tables
11. AP cores started via Limine MP protocol — per-CPU GIC, timer, scheduler
12. Preemptive SMP scheduling begins

---

## Building

ArcOS builds on macOS (Apple Silicon) with Rust nightly. Kernel binaries run only in QEMU — never directly on the host.
Prerequisites

Rust nightly (see rust-toolchain.toml)
Targets: x86_64-unknown-none, aarch64-unknown-none
QEMU via Homebrew
Limine v8.7.0 (auto-cloned to /tmp/limine)
mtools for AArch64 FAT disk images
```
Unit tests (host macOS)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Run in QEMU — x86_64
make run

# Run in QEMU — AArch64
make img-aarch64 && make run-aarch64

# Sign a boot module via YubiKey
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf <elf-file>

# Sign via seed (CI / no hardware key)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --seed <hex> <elf-file>
```
---

## Project Structure

```
src/
├── arch/x86_64/          # GDT, APIC, SYSCALL/SYSRET, TLB shootdown, SMP
├── arch/aarch64/         # GICv3, ARM Generic Timer, SVC, TLBI, EL0/EL1
├── scheduler/            # Priority-band preemptive SMP scheduler (portable)
├── ipc/                  # Capability-based IPC, Principal, zero-trust interceptor
├── syscalls/             # 24 syscalls, all implemented
├── memory/               # Frame allocator, buddy allocator, per-process page tables
├── fs/                   # ArcObject, ObjectStore, Blake3, Ed25519
├── loader/               # ELF loader, BinaryVerifier, SignedBinaryVerifier
├── pci/                  # PCI bus scan, device table, BAR decoding
└── microkernel/main.rs   # Kernel entry point

user/
├── libsys/               # Shared syscall wrapper library
├── fs-service/           # Filesystem service (endpoint 16)
├── key-store-service/    # Ed25519 signing service (endpoint 17)
├── virtio-net/           # Virtio-net driver (endpoint 20)
└── udp-stack/            # UDP/IP network service (endpoint 21)

tools/
└── sign-elf/             # Host-side ELF signing tool (YubiKey or seed)
```

---

## Manuals

Narrative walkthroughs that explain how ArcOS works by following real things through the system:

- [Waking Up](docs/manuals/01-waking-up.md) — The boot sequence as a story: bootstrap paradoxes, dependency chains, and bringing a microkernel to life
- [The Life of a Message](docs/manuals/02-life-of-a-message.md) — An IPC message from syscall to delivery, through capability checks and identity stamping
- [The Signature Chain](docs/manuals/03-signature-chain.md) — From YubiKey to boot verification: how the kernel knows code is authentic
- [Why a Buggy Driver Can't Kill You](docs/manuals/04-driver-isolation.md) — Microkernel isolation told through consequences
- [From NTP Query to UTC Clock](docs/manuals/05-ntp-query.md) — A UDP packet end-to-end through the full networking stack

---

## Design Documents

- [ArcOS.md](ArcOS.md) — Source-of-truth architecture document
- [PHILOSOPHY.md](PHILOSOPHY.md) — Philosophical foundations: consciousness, creation, and the motivations behind ArcOS
- [identity.md](identity.md) — Identity architecture: Ed25519 Principals, author/owner model, biometric commitment, did:key DID method, revocation
- [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md) — Implementation sequencing for identity + storage
- [SECURITY.md](SECURITY.md) — Zero-trust enforcement map: what's enforced, where, and how
- [SYSCALLS.md](SYSCALLS.md) — All 24 syscalls: numbers, arguments, behavior, calling conventions
- [INTERRUPT_ROUTING.md](INTERRUPT_ROUTING.md) — IRQ-to-task wakeup routing system
- [src/scheduler/SCHEDULER.md](src/scheduler/SCHEDULER.md) — Scheduler internals

### Architecture Decision Records

- [ADR-000](docs/adr/000-zta-and-cap.md) — Zero-trust architecture and capability-based access control
- [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) — Per-CPU scheduling and SMP task management
- [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) — Three-layer enforcement pipeline for IPC and syscalls
- [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) — Content-addressed storage and cryptographic identity
- [ADR-004](docs/adr/004-cryptographic-integrity.md) — Cryptographic integrity: Blake3 hashing and Ed25519 signatures

---

## Contributing

ArcOS is looking for people who understand what's at stake.

If you work on OS internals, compiler infrastructure, hardware security, or ML systems — and you've read this far and feel something — reach out. The foundation is real. The roadmap is clear. The work ahead is large enough that no single person should do it alone.

---

## References

- [Limine Boot Protocol](https://github.com/limine-bootloader/limine)
- [OSDev Wiki](https://wiki.osdev.org/)
- [seL4 Microkernel](https://sel4.systems/) — verification reference
- [Rust on Baremetal](https://github.com/rust-osdev)

---

*No telemetry. No analytics. No management engine. No compromises on the things that matter.*


### Security Enforcement Layers

```
ELF binary arrives
    → BinaryVerifier: W^X, entry point validation, overlap detection, signature check
    → IPC Interceptor (send path): capability check, interceptor hook, sender_principal stamp
    → IPC Interceptor (recv path): capability check, interceptor hook
    → Syscall pre-dispatch: interceptor hook before handler
    → ObjectStore: ownership enforced on every get/put/delete
```

### Identity Model

Every process has a Principal — a 32-byte Ed25519 public key. The kernel stamps every IPC message with the sender's Principal. It cannot be forged. User-space services use this to enforce ownership, access control, and audit trails without trusting the sender's claims.

The bootstrap Principal derives from a compiled-in YubiKey public key. No private key lives in kernel memory.

### IPC Model

Capability-based message passing with zero-trust enforcement:

- **Fixed-size messages** (256 bytes) for predictable verification
- **Capability rights**: Send, Receive, Delegate — fine-grained per-endpoint
- **Priority levels**: Critical, High, Normal, Low
- **Three-layer enforcement**: IPC interceptor hooks at IpcManager send/recv, syscall pre-dispatch, and capability delegation
- **Page-table-walk** for user buffer validation in Write/Read syscalls
- **Identity-aware receive** (`RecvMsg`): returns `[sender_principal:32][from_endpoint:4][payload:N]`

### Memory Layout

| Region | x86_64 | AArch64 |
|--------|--------|---------|
| HHDM base | `0xFFFF800000000000` | `0xFFFF000000000000` |
| User code | `0x400000` | `0x400000` |
| User stack top | `0x800000` (64KB) | `0x800000` (64KB) |
| Process heap base | `0x800000` | `0x40800000` |
| Kernel heap | 4MB at HHDM+physical | 4MB at HHDM+physical |
| Frame allocator | Bitmap, 0-2 GiB | Bitmap, 0-2 GiB |

### Lock Ordering

Strict lock hierarchy prevents deadlock across all kernel subsystems:

```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
PROCESS_TABLE(5) → FRAME_ALLOCATOR(6) → INTERRUPT_ROUTER(7) → OBJECT_STORE(8)
```

`*` = IrqSpinlock (interrupt-disabling). Lower numbers acquired before higher. No exceptions.

Additional lock domains (independent of hierarchy):
- `PER_CPU_FRAME_CACHE[cpu]` — per-CPU, never held with FRAME_ALLOCATOR
- `SHARDED_IPC.shards[endpoint]` — per-endpoint, never held cross-endpoint
- `BOOTSTRAP_PRINCIPAL` — written once at boot, read-only thereafter

---