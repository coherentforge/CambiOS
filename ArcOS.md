# ArcOS

## What This Document Is

This is the source document for ArcOS. Everything else — contributor guides, marketing copy, technical references — derives from what's written here. If a decision contradicts this document, this document wins or this document gets updated. There is no third option.

The architectural commitments that this document carries narratively are made formal and cite-able in **[ADR-009](docs/adr/009-purpose-tiers-scope.md)** — purpose statements, deployment tiers, hardware floors, and scope boundaries. Governance and funding commitments are in **[GOVERNANCE.md](GOVERNANCE.md)**. When a future decision needs a stable reference for what ArcOS *is*, cite ADR-009. When it needs a reference for how ArcOS is *run*, cite GOVERNANCE.md.

---

## The Problem

Operating systems were designed in an era when the threat model was "keep users from crashing each other's programs" and the networking model was "trust the network, authenticate at the edge." That era is over.

Modern operating systems are layers of compromise stacked on top of assumptions that stopped being true decades ago. Monolithic kernels run hundreds of millions of lines of code at the highest privilege level. Security is bolted on after the fact — antivirus software that runs with the same privileges as the threats it's trying to stop. Identity is still passwords. Networking still assumes a trusted infrastructure layer. Updates still require reboots.

Every patch is damage control. The architecture itself is the vulnerability.

ArcOS starts from the position that **the only way to build a secure system is to design one**, not to retrofit security onto a system that was never designed for it.

---

## Principles

These are non-negotiable. They constrain every design decision. When two goals conflict, these principles break the tie.

### 1. Security as Architecture (Not Policy)

Security isn't a feature that gets added. We're making security a structural property of the system. Every component — the kernel, the scheduler, the IPC mechanism, the driver model, the networking stack — is designed so that compromise of any single component cannot propagate to others. This is achieved through signing (keys), isolation (IPC), verification (pre-execution analysis), and least privilege (capabilities).

### 2. Minimal Kernel, Maximal Isolation

arcOS kernel does exactly five things: manage CPU time, manage physical memory, route messages between isolated processes, enforce capabilities, and handle hardware interrupts. Everything else — device drivers, file systems, networking, graphics, audio, AI inference — runs in user-space processes with no special privileges beyond what capabilities explicitly grant.

A smaller kernel means a smaller attack surface. A smaller attack surface means fewer places where a vulnerability grants total control.

### 3. No Telemetry. No Backdoors. No Exceptions.

arcOS will never phone home - there is no home to phone. It will never collect usage data. It will never contain a mechanism — hidden or documented — that allows remote access without the explicit, informed, per-session consent of the machine's owner. This is not a privacy "feature." It is a guarantee that is architecturally enforced: there is no telemetry subsystem to compromise because there is no telemetry subsystem.

### 4. AI as Infrastructure, Not Application

We aren't strapping a little chat-boy on the desktop here. AI/LLM compose a structural component of the operating system — the same way virtual memory or preemptive scheduling is a structural component. Checking code before execution, detecting anomalous behavior at runtime, adapting legacy applications to run on unfamiliar hardware, live-patching if and when updates are needed - all supervised by fast and light specialized models. These are capabilities that the system depends on to function, to safeguard user data and ensure malicious code is caught and sandboxed, and to truly improve overall UX.

This applies at the tiers of ArcOS that include AI components (see [ADR-009 § Deployment Tiers](docs/adr/009-purpose-tiers-scope.md)). ArcOS is delivered in three tiers: an embedded tier with no AI, a standard tier with no AI but with the full non-AI feature set, and a full tier with all AI components. On tiers without AI, the features described above degrade gracefully to non-AI alternatives where they exist or are absent where they do not. The architecture is the same across all tiers; the set of user-space services compiled into the boot image is what differs.

### 5. Identity Is Cryptographic, Not Secret-Based

If a passwords is a shared secrets, we all know what happens when two people try to keep one. Shared secrets are almost always compromised in the end. ArcOS replaces password-based authentication with cryptographic identity — key pairs, attestation, zero-knowledge proofs. You don't prove who you are by knowing a secret. You prove who you are by demonstrating possession of a key that only you control. Identity is decentralized: no central authority can revoke your existence.

### 6. The Network Is Hostile

ArcOS does not assume a trusted network. It does not assume DNS is honest. It does not assume IP addresses are stable or meaningful. Networking is built on cryptographic overlays where every connection is authenticated, every packet is encrypted, and routing does not depend on infrastructure that can be compromised, censored, or surveilled.

### 7. The System Evolves Without Stopping

Reboots are an admission that the system cannot maintain its own integrity across a state change. ArcOS is designed to be live-patched — kernel updates, driver replacements, security policy changes — without interrupting running workloads. The microkernel architecture makes this possible: replacing a user-space driver is just stopping one process and starting another.

### 8. Platform Is an Implementation Detail

ArcOS runs on x86_64 and AArch64. The architecture abstraction boundary is sharp and explicit. Portable code never touches hardware directly. Architecture-specific code lives behind a defined interface. Adding a new platform means implementing that interface, not rewriting the OS.

---

## Architecture

ArcOS is a layered system with hard isolation boundaries between layers. Communication between layers happens exclusively through message-passing IPC, mediated by capabilities.

```
+============================================================+
|                      Applications                          |
|  Native ArcOS apps  |  Legacy apps (Win32/POSIX compat)    |
+============================================================+
|                    User Experience                          |
|  Spatial UI | Workflow AI | Social feeds | Sovereign sync   |
+============================================================+
|                    System Services                          |
|  Window manager | Package manager | Shell | Update service  |
+============================================================+
|                    Compatibility                            |
|  Win32 API module | POSIX layer | PE loader                 |
+============================================================+
|                    OS Services                              |
|  VFS | Network stack | Audio | Graphics | Device managers   |
+============================================================+
|                    Core Services                            |
|  AI Engine | Identity | Social protocol | Policy | Logging  |
+============================================================+
|                    Microkernel                              |
|  Scheduling | Memory | IPC | Capabilities | Interrupts      |
+============================================================+
|                    Hardware                                 |
|  x86_64  |  AArch64  |  (future targets)                   |
+============================================================+
```

Every box above the microkernel is a user-space process. Every arrow between boxes is a capability-checked IPC message. There are no exceptions.

---

## The Microkernel

### What Lives in the Kernel

The microkernel is the only code that runs at the highest hardware privilege level (ring 0 on x86, EL1 on ARM). It contains:

- **Scheduler** — Preemptive, priority-based, per-CPU run queues with cross-CPU migration and load balancing. Time-sliced round-robin within priority bands. The scheduler decides who runs. It does not decide what they do.

- **Memory manager** — Physical frame allocation (bitmap-based), virtual memory (per-process page tables), kernel heap. The memory manager provides isolation between address spaces. It does not understand file systems, caches, or swap — those are user-space concerns.

- **IPC** — Synchronous and asynchronous message passing between processes. Endpoint-based addressing. The IPC subsystem routes messages. It does not interpret them.

- **Capability manager** — Every IPC endpoint, every memory region, every hardware resource is accessed through capabilities. Capabilities are unforgeable tokens that grant specific rights to specific resources. The kernel enforces capability checks on every IPC operation.

- **Interrupt dispatch** — Hardware interrupts are caught by the kernel, translated into IPC messages, and delivered to the user-space driver that registered for them. The kernel handles the interrupt mechanism. The driver handles the interrupt meaning.

### What Does Not Live in the Kernel

Everything else:

- Device drivers (disk, network, USB, GPU, input devices)
- File systems (VFS layer, concrete FS implementations)
- Networking (TCP/IP, the overlay network, DNS if we ever need it)
- Graphics and windowing
- Audio
- AI inference engines
- The compatibility layer
- User authentication and identity management
- Package management
- Logging and diagnostics

Each of these runs as an isolated process. A bug in a network driver cannot corrupt the file system. A vulnerability in the graphics stack cannot read kernel memory. A compromised application cannot escalate to root because "root" doesn't exist in the traditional sense — there are only capabilities.

### IPC as the Universal Interface

In a monolithic kernel, subsystems communicate through function calls and shared memory within the same address space. This is fast and completely insecure — any subsystem can read or corrupt any other's state.

In ArcOS, subsystems communicate through IPC messages. This is the only mechanism. There is no shared memory between services unless explicitly granted through a capability. There are no system calls that bypass IPC for "performance reasons."

The IPC system supports:

- **Synchronous call-reply** — Caller blocks until server responds. Used for operations that need an answer (read a file, query a device).
- **Asynchronous send** — Fire and forget. Used for notifications, logging, events.
- **Endpoint-based addressing** — Processes communicate through named endpoints, not PIDs. A process can hold a capability to an endpoint without knowing (or caring) which process implements it.

### Zero-Trust IPC Interceptor

Every IPC message passes through an interceptor layer before delivery. The interceptor enforces security policy:

- **Pre-send validation** — Is this process allowed to send to this endpoint? Does it hold the required capability?
- **Content inspection** — For sensitive endpoints, the interceptor can examine message contents (with AI assistance) for policy violations.
- **Rate limiting** — Prevents denial-of-service through IPC flooding.
- **Audit logging** — Every capability exercise is logged. Every policy violation is recorded.

The interceptor is not a firewall bolted onto the side. It is the IPC path. There is no way to send a message that doesn't go through it.

---

## Security Architecture

### Defense in Depth

ArcOS security operates at multiple layers, each independent of the others:

**Layer 0: Hardware isolation** — Each process runs in its own address space. The microkernel enforces W^X (write XOR execute) — no memory page is both writable and executable. User-space processes cannot access kernel memory. This is enforced by the CPU's memory management hardware (page tables, privilege rings).

**Layer 1: Capability-based access control** — No process can access any resource without an explicit capability. Capabilities are granted at process creation, delegated by other processes (with permission), or earned through an authentication protocol. They cannot be forged, guessed, or stolen through memory corruption (they are kernel-managed, not user-space tokens).

**Layer 2: Pre-execution verification** — Before any ELF binary is loaded and executed, it passes through a verification gate. The verifier checks structural integrity (valid headers, no overlapping segments), security properties (W^X compliance, entry point not in kernel space), and resource limits (memory budget). In the future, AI-powered static analysis extends this to behavioral properties.

**Layer 3: Runtime behavioral monitoring** — The AI security engine observes process behavior at runtime. Anomalous patterns — unexpected system call sequences, unusual IPC targets, resource consumption spikes — trigger graduated responses from logging to quarantine to termination. The AI doesn't need signatures of known threats. It detects deviation from expected behavior.

**Layer 4: Network-level encryption** — Every network connection is end-to-end encrypted with authenticated endpoints. There is no unencrypted communication, even on a local network. Man-in-the-middle attacks are structurally impossible because connection establishment requires cryptographic proof of endpoint identity.

### Threat Model

ArcOS assumes:

- **The network is hostile.** Every packet may be forged, replayed, or intercepted.
- **Applications are untrusted.** Every application runs in its own sandbox. Even "system" applications have only the capabilities they need.
- **Drivers are untrusted.** A device driver is just another user-space process. A buggy driver can crash itself but cannot corrupt kernel state or other drivers.
- **Physical access is possible.** Disk encryption and secure boot protect against offline attacks. (This is a future capability.)
- **The user is the owner.** ArcOS does not protect against the machine's owner. There is no DRM. There is no "you can't do that to your own machine." Root access (through cryptographic identity, not a password) grants full control.

### What ArcOS Does Not Protect Against

Honesty matters. These are outside the current threat model:

- **Hardware backdoors** (CPU microcode, firmware) — ArcOS runs on commodity hardware. If the CPU itself is compromised, no software can save you.
- **Side-channel attacks** (Spectre, Meltdown variants) — Mitigations will be applied as they mature, but speculative execution attacks are a hardware problem that software can only partially address.
- **Rubber-hose cryptanalysis** — If someone physically coerces you into unlocking your machine, cryptography doesn't help. ArcOS provides plausible deniability features where possible, but this is fundamentally a human problem.

---

## AI Integration

AI in ArcOS is not a product feature. It is infrastructure — load-bearing components that the system depends on to function.

### The Three Pillars

**Pillar 1: Security AI** — Watches the system. Verifies code before execution. Detects anomalous behavior at runtime. Makes quarantine decisions. This is the immune system of the operating system.

- Pre-execution static analysis: Before a binary runs, AI examines its code paths for known vulnerability patterns, suspicious system call sequences, and policy violations.
- Runtime behavioral analysis: AI monitors process behavior — system call patterns, IPC targets, memory allocation patterns, timing — and flags deviations from expected profiles.
- Threat response: Graduated responses from logging (low confidence) to capability revocation (medium) to process termination and quarantine (high).
- Adaptive learning: The security AI builds behavioral profiles over time. A web browser that suddenly starts making raw disk I/O calls triggers an alert, even if each individual call is technically permitted.

**Pillar 2: Compatibility AI** — Adapts legacy software to run on ArcOS. Windows applications expect a specific set of system calls, DLLs, registry keys, and hardware interfaces. Rather than reimplementing Win32 call-by-call (the Wine approach), ArcOS uses AI to understand what the application is trying to do and translate the intent to native ArcOS operations.

- API translation: Intercepts foreign system calls and maps them to ArcOS IPC + capability operations.
- Behavioral adaptation: When an application expects a hardware interface that doesn't exist (e.g., a specific GPU feature), AI synthesizes a compatible abstraction.
- Driver synthesis: For hardware that lacks ArcOS drivers, AI analyzes existing drivers (Linux, Windows) and generates ArcOS user-space driver code. This is not emulation — it is translation.

**Pillar 3: Operations AI** — Keeps the system running. Assists with live patching, performance optimization, resource management, and self-healing.

- Live patch generation: When a security update is needed, AI generates a hot-patch that can be applied to a running kernel module or user-space service without restart.
- Resource optimization: AI monitors system-wide resource usage and adjusts scheduling priorities, memory pressure responses, and I/O scheduling to match actual workload patterns.
- Self-healing: When a service crashes, AI analyzes the crash context, determines if the failure is transient or structural, and either restarts the service, migrates its workload, or escalates to the user.

### Where AI Runs

AI inference is computationally expensive. ArcOS provides multiple execution paths:

- **On-CPU inference** — Small, latency-sensitive models (syscall classifiers, anomaly detectors) run directly on the CPU. These must be fast enough to not measurably impact system call latency.
- **Accelerator offload** — Larger models (binary analysis, compatibility translation) offload to GPU, NPU, or dedicated AI accelerator hardware when available.
- **Deferred analysis** — Some analysis doesn't need to be real-time. Batch processing of logs, deep binary analysis, and model training happen during idle periods.

The AI subsystem is itself a set of user-space services. It has no special kernel privileges. It communicates with the kernel and other services through the same IPC + capability mechanism as everything else. The kernel trusts the AI's *recommendations* (quarantine this process, approve this binary) only because the AI service holds the capabilities to make those requests — not because it has a backdoor into the kernel.

---

## Identity and Authentication

### Cryptographic Identity

Every entity in ArcOS — users, machines, services — has a cryptographic identity: a key pair. The private key never leaves the device. The public key is the identity.

- **No passwords.** Authentication is proof of key possession: challenge-response, digital signatures, zero-knowledge proofs. There is nothing to steal from a server because the server never sees a secret.
- **No central authority.** Identity is not issued by a corporation or government. It is generated locally. Trust relationships between identities are established through direct exchange, web-of-trust models, or decentralized identity protocols (DIDs).
- **Hardware-backed keys.** When available, private keys are stored in hardware security modules (TPM, Secure Enclave, smart cards). The key material is never exposed to software.

### Access Control

Traditional access control (users, groups, permissions) is a coarse model designed for shared mainframes. ArcOS replaces it with capability-based access:

- A process can access a file not because it runs as a user who owns the file, but because it holds a capability that grants read access to that specific file.
- Capabilities can be delegated: Process A can grant Process B a subset of its own capabilities.
- Capabilities can be time-limited, usage-limited, or conditionally revocable.
- There is no "superuser." No single capability grants access to everything. Administrative operations require specific administrative capabilities, and those capabilities can be held by different entities for different subsystems.

### Multi-User Model

ArcOS supports multiple identities on a single machine. Each identity has its own set of capabilities, its own key pair, and its own view of the system. Switching between identities does not require "logging out" — it is a capability context switch, the same way the scheduler switches between processes.

---

## Networking

### The Overlay Network

ArcOS does not depend on IP addresses, DNS, or any infrastructure-layer naming system for its core networking. Instead, it builds a cryptographic overlay network:

- **Identity-addressed routing** — Machines are addressed by their public key (or a hash of it), not by IP address. The overlay network routes packets to the destination key regardless of where that machine physically sits on the network.
- **End-to-end encryption** — Every connection is encrypted between endpoint keys. There is no "trusted LAN." Even the machine sitting next to you on the same switch gets encrypted traffic.
- **Infrastructure independence** — The overlay can run on top of TCP/IP, UDP, or any transport that provides basic packet delivery. If the underlying network changes (VPN, cellular, coffee shop WiFi), the overlay session persists because it is identified by key, not by address.
- **Censorship resistance** — Because routing is cryptographic and not dependent on DNS or centralized nameservers, the overlay is resistant to domain seizure, DNS poisoning, and IP-level blocking. This is a structural property, not a feature that can be disabled.

### Social Protocol

The overlay network is not just a transport layer. It is a social layer.

ArcOS adopts a model inspired by Secure Scuttlebutt (SSB): peer-to-peer, append-only logs signed by each identity's cryptographic key. Every identity maintains a personal log — a tamper-proof record of things they choose to publish (posts, status, shared files, presence). Peers replicate logs they subscribe to. There is no central server. There is no algorithm deciding what you see. There is no advertising.

- **Peer-to-peer push sharing** — Sharing a file, a link, a message with another ArcOS user is a direct peer-to-peer operation. No cloud service in the middle. No upload-to-server-then-share-link. You push content directly to the recipient's machine (or their sovereign storage, if they're offline). Encrypted in transit. Signed by the sender's key.
- **Social feed without a platform** — The append-only log model gives every user a "feed" without requiring a social media platform. You follow identities, not accounts on a service. Your client aggregates the logs of identities you've subscribed to. The rendering, filtering, and presentation is local — controlled by you, not by an engagement-optimization algorithm.
- **Offline-first replication** — Because logs are append-only and signed, they can be replicated through any channel: direct network connection, USB drive, even printed QR codes. If two peers haven't synced in a week, they catch up the next time they connect. No data is lost. No "you missed this because you were offline."
- **No platform lock-in** — The social protocol is an open specification, not a proprietary service. Third-party clients can render the same feeds differently. The data belongs to the identity that signed it, not to any service that hosted it.

### Compatibility with Existing Networks

ArcOS can participate in traditional TCP/IP networks. The networking stack (running in user space) implements standard protocols as needed for interoperability. But the overlay network is the native communication model. TCP/IP is a compatibility layer, not the foundation.

---

## Application Compatibility

### Windows as a First-Class Compatibility Target

Most of the world's desktop software targets Win32. ArcOS treats Windows compatibility not as an afterthought but as a built-in subsystem — a dedicated Win32 translation layer that ships with the OS.

- **Win32 API module** — A user-space service that implements the Win32 API surface: window management (USER32), graphics (GDI32/Direct2D), file I/O (KERNEL32), registry (emulated as a capability-scoped key-value store), COM/OLE, and the subset of NTDLL that user-mode applications actually call. This is not a full Windows reimplementation — it is a focused translation of the APIs that real applications use.
- **PE loader** — ArcOS loads Windows PE executables natively. The ELF loader already verifies and maps binaries; the PE loader extends this to the PE/COFF format with the same security gate (W^X enforcement, entry point validation, segment verification).
- **DLL mapping** — Windows DLLs are mapped to ArcOS-native service endpoints. An application that calls `CreateFile()` sends an IPC message to the VFS service through the Win32 translation layer. The application doesn't know the difference. The VFS doesn't know it's talking to a Windows app.
- **Disposable by design** — The Win32 layer is a compatibility bridge, not a dependency. Native ArcOS applications never touch it. As the native ecosystem grows, the Win32 layer becomes less relevant — but it doesn't rot, because it's a self-contained service with a clean IPC boundary. It can be updated, replaced, or removed without affecting anything else.

### POSIX Compatibility

A thinner layer than Win32, because POSIX semantics map more naturally to ArcOS's model. Fork/exec becomes process creation via IPC. File descriptors become capability handles. Signals become IPC messages. The POSIX layer exists for the same reason the Win32 layer exists: to let existing software run while the native ecosystem bootstraps.

### AI-Assisted Translation

Beyond the hand-coded API layers, the compatibility AI extends coverage:

- **System call inference** — When an application calls an API that isn't explicitly mapped, AI analyzes the call context (parameters, surrounding call pattern, return value usage) and synthesizes a translation. These synthesized mappings are logged, reviewed, and promoted to the hand-coded layer when validated.
- **Behavioral adaptation** — When an application expects hardware behavior that doesn't exist (specific GPU features, timing-dependent I/O), AI synthesizes a compatible abstraction.
- **Driver synthesis** — For hardware that lacks ArcOS drivers, AI analyzes existing drivers (Linux, Windows) and generates ArcOS user-space driver code.

### The Migration Path

No user switches operating systems overnight. ArcOS provides a migration path:

1. **Run legacy apps alongside native apps** — The compatibility layer runs foreign applications in isolated sandboxes. They look and feel like native apps but run through the translation layer.
2. **Gradual native port** — As ArcOS-native libraries and frameworks mature, applications can be ported incrementally. The compatibility layer and native APIs can coexist in the same application.
3. **AI-assisted porting** — For open-source applications, AI can assist in translating source code from POSIX/Win32 APIs to native ArcOS APIs. This is a developer tool, not an automatic process — humans review and approve the changes.

---

## Live Patching

### Why Reboots Are Unacceptable

A reboot is an uncontrolled state transition. Every running process is killed. Every network connection is dropped. Every in-progress operation is abandoned. Users have learned to accept this because every OS they've ever used requires it. That doesn't make it acceptable.

### The Microkernel Advantage

Live patching a monolithic kernel is extraordinarily difficult because the kernel is a single, densely interconnected binary. Patching one function might change the behavior of hundreds of callers.

In ArcOS, most "kernel updates" are actually user-space service updates. Updating the network driver means stopping one process and starting a new one. Updating the file system means the same. The IPC endpoint doesn't change — clients don't even notice.

For actual microkernel patches (scheduler, memory manager, IPC), the strategy is:

- **Hot-patch small changes** — Single-function patches can be applied by rewriting the function's entry point to jump to new code. The AI operations engine assists in verifying that the patch is safe (same calling convention, compatible state assumptions).
- **Rolling restart for large changes** — Major kernel changes that can't be hot-patched trigger a rapid kexec-style restart: save critical state, load new kernel, restore state. This is not a reboot — it is a controlled transition that takes milliseconds, not minutes.

---

## User Experience

The operating system is not the kernel. It is not the driver model. It is the thing a person sits in front of and uses. ArcOS's UX philosophy is as deliberate as its security architecture.

### Spatial Interface

The desktop metaphor — files in folders on a desktop — is a 1984 idea. It maps poorly to how humans actually organize and retrieve information. People don't think in hierarchical trees. They think in spatial relationships, associations, and contexts.

ArcOS explores a spatial interface model:

- **3D space, not folder trees** — Information, people, and activities are arranged in a navigable three-dimensional space. Things that are related are near each other. Things you use frequently are close. Things you haven't touched in months drift to the periphery. The space is personal — it reflects how *you* organize your world, not how a file system forces you to.
- **Entities, not files** — The primary objects in the spatial UI are not files. They are entities: people, projects, conversations, documents, data streams. A "person" entity clusters their messages, shared files, collaborative projects, and social feed in one spatial location. You navigate to a person, not to a folder named after them.
- **Contextual workspaces** — The space reconfigures based on what you're doing. Working on a code project? The relevant source files, documentation, terminal, and collaborators cluster around you. Switching to communication? The space shifts to foreground your contacts, messages, and feeds. This isn't multiple desktops — it's a continuous space with focus regions.
- **Navigable like the physical world** — Humans are extraordinarily good at spatial memory. We remember where things are in physical space far better than we remember which folder we put them in. The spatial interface leverages this: finding something means going to where you remember it being, not typing a search query.

### Sovereign Data

Your data lives where you put it. Not where a corporation decides to store it.

- **Self-directed storage** — ArcOS integrates with cloud storage, but the user chooses where. Personal encrypted buckets — potentially hosted by a foundation or cooperative entity aligned with ArcOS's values, or by any S3-compatible provider, or on your own hardware. The OS doesn't care. Once configured, it sees a storage endpoint with a proper capability and that's where your data goes.
- **No third-party scanning** — Data at rest in your sovereign storage is encrypted with your keys. The hosting provider cannot read it. They cannot scan it. They cannot hand it to a government or train an AI on it. They store ciphertext. That's it.
- **Local-first, sync-second** — Data originates locally. It syncs to remote storage for backup and multi-device access. If the remote storage disappears, you still have your data. If the network goes down, you still have your data. Cloud is a convenience, not a dependency.

### Workflow AI

The AI subsystem serves the user's focus, not an engagement metric.

- **Relevance surfacing** — AI observes your current workflow context (what files are open, what project you're in, who you're communicating with) and proactively surfaces relevant information: related documents, recent messages from collaborators, bookmarks you saved weeks ago that are suddenly pertinent. This is a quiet assistant, not a notification bombardment.
- **Distraction narrowing** — Rather than optimizing for attention capture (the social media model), the workflow AI optimizes for attention *protection*. It filters, prioritizes, and defers interruptions based on what you're doing right now. A message from a collaborator on your active project surfaces immediately. A marketing email gets deferred. You set the policy. The AI enforces it.
- **Cross-context memory** — The AI maintains a model of your working patterns across sessions. It remembers that you were researching a topic last Tuesday, that you have a meeting about it Thursday, and that a document arrived overnight that's relevant to both. It connects dots that you'd miss because they span time and context.

### Social Without Surveillance

ArcOS provides the utility of social media — sharing, communication, presence, feeds — without the business model of social media. There are no ads. There is no engagement optimization. There is no data harvesting.

The social protocol (described in the Networking section) provides the infrastructure. The UX layer makes it usable:

- **Integrated presence and sharing** — Sharing content with another person is a first-class OS action, not an app-specific feature. Select something, push it to a person. Their machine receives it, encrypted and signed. No intermediary service.
- **Feeds as a native UI element** — The social feed (from the SSB-inspired append-only logs) is rendered by the OS, not by a web browser pointed at a platform. This means the OS controls the rendering: no injected ads, no manipulated ordering, no dark patterns.
- **Group spaces** — Groups of people (teams, families, communities) can share a region of the spatial interface. Shared documents, group conversations, and collaborative projects live in a shared space that all members can navigate. Access is controlled by capabilities, not by a platform's permission model.

### UX Tier Dependencies

The spatial interface, workflow AI, and contextual adaptation described above require local LLM inference and are features of the full (Tier 3) deployment of ArcOS. On Tier 2 (no AI), ArcOS provides a traditional windowing shell with the same security, privacy, and sovereignty properties as Tier 3 but without the contextual adaptation. On Tier 1 (embedded), most UX features are absent by design — embedded deployments are typically headless or use a minimal console. This is graceful degradation, not missing functionality: a Tier 2 deployment is a complete, usable operating system with a traditional but modern shell; a Tier 1 deployment is a complete, usable embedded kernel. See [ADR-009](docs/adr/009-purpose-tiers-scope.md) for the full tier model.

---

## Platform Support

### Current: x86_64

The primary development target. ArcOS boots via the Limine protocol, runs a custom GDT with per-CPU TSS, uses SYSCALL/SYSRET for fast system call entry, and schedules preemptively via the Local APIC timer. SMP is fully operational: per-CPU schedulers, task migration, load balancing, TLB shootdown. User-space services run in ring 3 — a filesystem service, key store, virtio-net network driver, and UDP/IP stack all communicate through capability-checked IPC. PCI device discovery, DMA allocation, and MMIO mapping are exposed to user-space drivers through validated syscalls.

### Current: AArch64

AArch64 boots on QEMU `virt` (GICv3 required) and runs preemptive scheduling with EL0 user tasks. The full memory subsystem is operational — kernel heap, bitmap frame allocator, per-process page tables with TTBR0/TTBR1 split. GICv3 (Distributor + Redistributor + ICC system registers), ARM Generic Timer at 100Hz, PL011 UART, SVC-based syscall entry, and SMP (AP startup via Limine MP protocol) are all implemented. All boot modules build for AArch64 via shared `libsys` syscall wrappers. Voluntary context switch is implemented for both architectures.

For the up-to-date list of remaining gaps (device IRQ routing on AArch64, SMP timer on AP, bare-metal testing) see [STATUS.md](STATUS.md).

### Future Considerations

ArcOS's architecture does not assume x86 or ARM. The platform abstraction is a defined interface. If RISC-V, or something that doesn't exist yet, becomes relevant — the interface accommodates it. But we don't design for hypothetical targets. We design for a clean abstraction, and clean abstractions naturally extend.

### Deployment Tiers

ArcOS is delivered in three compile-time tiers. The kernel is the same across tiers; what differs is which user-space services are included in the boot image. Full details in [ADR-009](docs/adr/009-purpose-tiers-scope.md).

- **Tier 1 — ArcOS-Embedded** — 256 MB to 1 GB RAM. Full microkernel, minimal core services. No AI. No shell beyond minimal console. No compositor. For fixed-function devices where ArcOS's security architecture is valuable but AI inference is not available.
- **Tier 2 — ArcOS-Standard** — 1 GB to 16 GB RAM. Full microkernel, full core services, hand-coded Windows compatibility, traditional windowing shell. No AI components. For users who want ArcOS's security, privacy, and sovereignty commitments on hardware that cannot run local LLMs, or who prefer not to run AI components.
- **Tier 3 — ArcOS-Full** — 8 GB+ RAM, ideally with GPU or NPU for AI workloads. Everything. The spatial UX, the security AI watcher, AI-assisted Windows compatibility, the full native ecosystem. The primary development target and the tier that embodies the full ArcOS vision.

The tiers are user choices informed by hardware guidance, not kernel classifications. Hardware provenance (commodity vs vendor-audited vs fully open) is a separate axis and is discussed in [ADR-009's Hardware Supply Chain section](docs/adr/009-purpose-tiers-scope.md).

---

## What ArcOS Will Never Be

Some boundaries are as important as goals. ArcOS will never:

- **Collect telemetry or analytics.** No usage data. No crash reports sent without explicit consent. No "anonymous" statistics. The machine belongs to its owner, not its manufacturer.
- **Require an internet connection.** ArcOS is fully functional offline. Network features degrade gracefully when disconnected. There is no "activation" step.
- **Implement DRM or restrict the owner.** The machine's owner has full control. ArcOS will not prevent you from running software, modifying the OS, or accessing your own hardware. Secure boot protects the owner from unauthorized modifications, not the vendor from the owner.
- **Include advertising, promoted content, or sponsored integrations.** The user interface serves the user. Nothing else.
- **Depend on a single vendor's cloud services.** No Apple ID equivalent. No mandatory Microsoft account. No Google sign-in. If ArcOS ever supports cloud services, they will be pluggable, optional, and user-controlled.
- **Sacrifice security for compatibility.** If running a legacy application requires disabling a security boundary, the application doesn't run. The user can make an informed choice to override this, but the default is always secure.

---

## The Road Ahead

### What Exists Today (Summary)

The microkernel is real and running on both x86_64 and AArch64. It is not a design document. It is working code — comprehensive unit tests pass on host, and integration testing runs in QEMU. The headline:

- **Kernel fundamentals** are complete: preemptive SMP scheduling with per-CPU priority-band schedulers, load balancing and task migration, per-process page tables with W^X enforcement, capability-checked IPC with zero-trust interception.
- **Identity** is hardware-backed. A YubiKey-derived Ed25519 bootstrap principal is compiled into the kernel; no secret key lives in kernel memory. Boot modules are signed at build time and verified before execution. IPC messages carry unforgeable sender principals stamped by the kernel.
- **Storage** uses content-addressed objects — Blake3 hashes, Ed25519 signatures verified on retrieval, ownership enforced per-principal.
- **Networking** has a working vertical slice: user-space virtio-net driver, stateless UDP/IP stack, and a working NTP demo that queries an external time server through QEMU's SLIRP network.

For the canonical, kept-current breakdown — every subsystem, every phase, every test count, every known issue — see **[STATUS.md](STATUS.md)**. This file (ArcOS.md) is for *intent*, not *current state*.

### What Comes Next

The v1 target is an interactive, network-capable, identity-rooted OS running on real hardware with persistent storage. The dependency-ordered roadmap (shell → bare-metal boot → real NIC driver → DHCP/DNS → TCP → persistent storage → mesh networking → AI integration) lives in [STATUS.md § v1 Roadmap progress](STATUS.md#v1-roadmap-progress) so the order doesn't drift across documents. The architectural substrate that the post-shell items sit on — the bulk-data IPC channel primitive, externalized policy decisions, capability revocation, and audit telemetry — is described in [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md), [ADR-006](docs/adr/006-policy-service.md), and [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md).

### What We Don't Know Yet

Some parts of this vision are clear in intent but unclear in implementation. That's honest, not a weakness:

- **How large can the on-CPU AI models be before they impact latency?** We need benchmarks. The answer determines how much of the security AI runs inline versus deferred.
- **What is the right granularity for the overlay network?** Per-connection? Per-session? Per-application? This depends on performance characteristics we haven't measured yet.
- **How do we handle the cold-start problem for behavioral AI?** A freshly installed system has no behavioral profiles. What does the security AI do on day one? Conservative defaults, probably, with a learning period. But the details matter.
- **What does the native application framework look like?** ArcOS needs a way for developers to build native apps. The kernel provides IPC and capabilities. What goes on top of that — the equivalent of a GUI toolkit, a standard library, a package format — is not yet designed.

These are open questions, not blockers. The microkernel doesn't need to answer them to keep making progress. The architecture is designed to accommodate answers we haven't found yet.

---

## Closing

ArcOS is not a hobby project with aspirations of grandeur. It is not a Linux reskin with a new logo. It is a ground-up operating system built on the belief that the fundamental architecture of how we manage computation, security, identity, and communication is due for replacement — not incremental improvement.

The microkernel exists. It runs. It schedules. It isolates. Everything described in this document is either built, being built, or designed to be buildable on the foundation that already exists.

The road is long. The map is incomplete. But the compass works.
