# ADR-009: Purpose, Deployment Tiers, and Scope Boundaries

- **Status:** Proposed
- **Date:** 2026-04-11
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities)
- **Related:** [ArcOS.md](../../ArcOS.md), [PHILOSOPHY.md](../../PHILOSOPHY.md), [SECURITY.md](../../SECURITY.md), [win-compat.md](../../win-compat.md), [identity.md](../../identity.md), [GOVERNANCE.md](../../GOVERNANCE.md)
- **Supersedes:** N/A

## Context

Load-bearing framing assumptions about what ArcOS is, what hardware it targets, and what scope it commits to have been carried implicitly across the project's documentation. ADR-008 (process table allocation, pending) cannot be written without these assumptions being explicit — it needs a hardware floor, and the hardware floor requires a commitment to what architectural tier ArcOS targets. Rather than embed those commitments inside ADR-008 (where they would be tangled with a mechanism decision), this ADR makes them explicit as a separate, cite-able reference that future ADRs can depend on.

## Problem

ArcOS's documentation describes a system with ambitious goals: a verified microkernel, AI-integrated security, spatial UX, Windows compatibility, user sovereignty, platform-agnostic hardware support. Each of these is individually articulated in [ArcOS.md](../../ArcOS.md) and [PHILOSOPHY.md](../../PHILOSOPHY.md). None of them is individually contradicted. But several of them, taken together, surface ambiguities that the documentation has not resolved:

**Is AI integral to ArcOS, or is it an optional feature?** [ArcOS.md § Principles](../../ArcOS.md) states "AI as Infrastructure, Not Application" and describes AI as "load-bearing components that the system depends on to function." This reads as integral. But no document has committed to a hardware profile that makes this true — a machine that cannot run a useful LLM cannot run the full ArcOS architecture, yet nothing in the documentation says ArcOS requires such a machine. The tension has not been forced.

**What does "platform-agnostic" mean concretely?** ArcOS targets x86_64 and AArch64 today, with RISC-V planned. Its kernel code is `no_std`, position-independent, and could in principle run on any hardware with the right drivers. But "the kernel could run on anything" is not the same as "the full OS is supported on anything." A 256 MB embedded board cannot run the AI watcher. A 16 TB datacenter server can run all of ArcOS with room to spare. What is the project's actual commitment?

**Is the spatial / contextually aware UX a serious goal, or is it an aspiration?** [ArcOS.md § User Experience](../../ArcOS.md) describes a 3D spatial interface with workflow AI and cross-context memory. This is described as a feature of ArcOS, not as a future possibility. But no document commits to the hardware required to make it work. Classical ML and hardcoded rules are insufficient for the adaptation a contextually aware system requires — real contextual awareness across the diversity of user tasks (programming, writing, tax preparation, music production, research, collaboration) requires language-model-scale pattern recognition. If the UX is a serious goal, local LLMs are a hard requirement, and the hardware profile must accommodate them.

**Is Windows compatibility a destination or a bridge?** [win-compat.md](../../win-compat.md) frames the compat layer as a transition aid — a way for Windows users to switch to ArcOS without abandoning their software. This framing is right but has not been made explicit enough for architectural decisions to rely on it. If Windows compat is a destination, ArcOS has to match Windows's effective floor and performance. If it is a bridge, the compat layer can run in a sandbox with a constrained resource budget and be allowed to be slower than native. The difference matters for every ADR that touches compatibility.

**Is embedded / small-device support maintained as a first-class target or a secondary one?** The platform-agnostic framing suggests first-class. The AI-integral framing suggests not. These cannot both be true for the same configuration of ArcOS. But they can both be true if ArcOS commits to a tiered deployment model where the AI-integral configuration and the embedded configuration are distinct build targets.

These ambiguities have not yet caused harm because no decision has been forced to resolve them. During the drafting of ADR-008 (the process table allocation decision), all of them became blocking at once: the allocation formula needs a hardware floor, the hardware floor needs to know whether AI is required, the AI requirement needs to know whether the architecture tolerates AI-less deployments, and the tolerance question needs a tier model. Solving any one of these without the others produces an inconsistent architecture.

This ADR resolves them together.

## The Reframe

The principle that resolves the ambiguities is:

> **ArcOS is one architecture with multiple deployment tiers. The architecture defines what ArcOS *is*. The tiers define what ArcOS *runs on*.**

The architecture is not negotiable. Every tier of ArcOS runs the same verified microkernel, enforces the same capability model, uses the same identity primitives, and honors the same privacy and sovereignty commitments. No tier compromises the security architecture.

What differs between tiers is *which user-space services are compiled into the deployed image*, and therefore which features are available to the user on that hardware. A tier that excludes AI services does not have a behavioral anomaly detector, a context-aware UX, or AI-assisted Windows compatibility translation. It still has everything the microkernel provides: capability isolation, verified code paths, zero-trust IPC, cryptographic identity, no telemetry, audit recording. The missing pieces are the ones that genuinely require AI inference capacity to function well, and on hardware that cannot run AI well, their absence is an honest reflection of hardware constraints rather than an architectural compromise.

This reframe lets the project commit to all of its goals without pretending they all apply uniformly to all hardware. AI is integral *on hardware that can run it*. Embedded support is first-class *at the embedded tier*. Platform-agnostic support means "same architecture, tier-appropriate service set" rather than "same features everywhere." Windows compatibility is a bridge at the tiers that include it, and absent at the tiers that do not.

## Purpose Statements

ArcOS exists to address four deficiencies in current operating system design. These are the project's load-bearing goals. They answer the question *why does ArcOS exist?* — they name problems we believe need solving. The *how* — the design rules that follow from these purposes — is in the Architectural Principles section that follows.

### 1. The memory vulnerability surface of current OSes is unacceptable

Current operating systems ship with decades of accumulated memory safety bugs in their kernels and system libraries. The industry response — more testing, more patches, more mitigations — has not changed the overall trajectory. Users have learned to accept that their operating systems have an ongoing stream of remotely-exploitable vulnerabilities, and that accepting this stream is the cost of using a computer. ArcOS exists, in part, because this is not acceptable.

### 2. Current OSes trust too much by default

Applications receive broad authority at install time. Drivers run at the highest privilege level. Users authenticate with passwords, which are spoofable and phishable. Security software runs at the same level as the threats it protects against, with predictable results. Users have learned to accept that a single compromised component — a browser tab, a printer driver, a downloaded file — can escalate to total system compromise. ArcOS exists, in part, because this is not acceptable.

### 3. User sovereignty is being eroded by commercial OS vendors

Users do not own their data on current commercial operating systems. Telemetry flows to vendors by default, identity is controlled by platform companies, applications phone home without explicit consent, and the legal frameworks around data collection are weak enough that even well-intentioned vendors can be compelled to hand over user information. The machine that a user purchased and paid for is not fully under the user's control. ArcOS exists, in part, because this is not acceptable.

### 4. Operating system user experience has stagnated

The desktop metaphor is 40 years old. Users manage files in folders, launch applications from menus, and manually arrange their work into application-specific silos. The human cognitive model for organizing tasks — spatial, contextual, associative, task-oriented — does not map to this metaphor, so users spend significant mental effort translating between how they think about their work and how the OS wants them to structure it. This is a solvable problem. Modern AI gives us primitives for building UX that adapts to context, anticipates relevance, and reduces the friction between intent and action. ArcOS exists, in part, to build that.

## Architectural Principles

These principles follow from the purpose statements. They answer the question *how does the architecture work?* — they are design-level commitments that apply across ADRs. Future architectural decisions should cite these principles when tradeoffs need to be resolved.

### 1. Security and sovereignty as architecture, not policy

Security and user sovereignty are structural properties of the system, not features that get added on top. Every component is designed so that compromise of any single component cannot propagate to others. The microkernel is small and verifiable. User-space services are capability-isolated. Drivers run in user space with no privileged access. Applications run in sandboxes with explicit capabilities. The kernel enforces these boundaries mechanically; it does not rely on developer discipline or runtime checks that can be bypassed.

The same principle applies to sovereignty. No telemetry. No vendor phone-home. No forced updates. No advertising. No hidden data collection. Identity belongs to the user and is rooted in hardware keys the user controls. Data belongs to the user and lives in storage the user chooses. These commitments are architecturally enforced rather than policy-enforced: there is no telemetry subsystem to compromise because there is no telemetry subsystem. The policy service, when it exists, is the user's agent in mediating what software can do — not the platform's agent in mediating what the user can do.

This principle addresses Purposes 1, 2, and 3. It applies at every tier, including ArcOS-Embedded.

### 2. Interoperability through protocols, not platforms

ArcOS commits to protocols over proprietary APIs. Wherever possible, services interoperate via open specifications — cryptographic identity via DIDs, social feeds via Secure-Scuttlebutt-style append-only logs, content via content-addressed storage, networking via an overlay-routed cryptographic protocol. ArcOS prefers to build on and contribute to open protocols rather than invent proprietary alternatives, because proprietary APIs create platform lock-in and protocol-based interop lets users leave if they want to. This is the difference between "ArcOS works with other systems because we built adapters" and "ArcOS works with other systems because we all speak the same protocol." The second is robust; the first decays.

This principle addresses Purposes 3 and 4, and shapes how ArcOS integrates with the world outside itself. It applies at every tier.

### 3. Graceful degradation across tiers

ArcOS is delivered in three tiers (see the Hardware Profile and Deployment Tiers section below). Features that require AI inference must degrade gracefully on tiers that do not include AI. The degradation is not "error the feature out" — it is "provide a non-AI alternative that is less capable but still useful."

For example, the Windows compatibility story has two components: a hand-coded Win32 shim that handles common APIs structurally, and an AI-assisted translator that handles edge cases and adapts to unfamiliar API patterns. On Tier 3 (full AI), both run; the AI expands coverage and improves the shim's robustness over time. On Tier 2 (no AI), only the hand-coded shim runs; Windows apps that rely on the common APIs work, and apps that need AI interpretation fail gracefully with a clear error rather than crashing. On Tier 1 (embedded), the compat layer is absent entirely.

This pattern — structural fallback with clear degradation semantics — applies to every AI-dependent feature: UX context awareness, security AI, driver synthesis, live patching assistance. A Tier 1 or Tier 2 deployment should never appear broken; it should appear *smaller*, in ways the user can understand. This principle shapes every feature that has AI-dependent behavior.

### 4. Efficient in implementation, generous in features

ArcOS does the work its purposes require without apologizing for the cost. Idle components stay idle. Pushes replace polls. Batches replace ones-at-a-time. Caches replace recomputation. Efficiency is a discipline about *how* work is done, not a cudgel used to prevent work from being done. The current commercial-OS pattern of disabling features for battery savings is not a pattern ArcOS inherits: the features that make ArcOS worth running are the features that make ArcOS worth running, and users who choose ArcOS are implicitly choosing to pay the electricity cost of those features. That said, every feature should be implemented such that it uses the minimum resources sufficient to its job.

This principle addresses Purpose 4 (good UX is worth its cost) and constrains implementation across every subsystem.

### 5. Pragmatic backward compatibility

ArcOS does not compromise its architecture to accommodate legacy patterns from other operating systems. Windows compatibility (see [win-compat.md](../../win-compat.md)) is a bridge for users switching from Windows, not a destination for ArcOS as a project. The compatibility layer runs in sandboxes, receives constrained resource budgets, is explicitly allowed to run slower than native, and is expected to become less important over time as native ArcOS software matures. The same philosophy applies to POSIX compatibility: a thin translation layer for existing software during the bootstrap period, not a long-term dependency. ArcOS's architecture is designed to obsolete the compatibility layers, not depend on them.

This principle keeps compatibility work from slowly becoming the center of gravity of the project. It applies to Tiers 2 and 3.

## Hardware Profile and Deployment Tiers

ArcOS is delivered in three compile-time deployment tiers. Each tier produces a distinct boot image with a different set of user-space services included. The kernel binary is identical across tiers (modulo feature flags that gate optional kernel-side optimizations); what differs is the user-space boot manifest — which services are loaded at boot, which capabilities are granted to them, and which user-facing features are therefore available.

### Tier 1 — ArcOS-Embedded

**Target hardware:** Small embedded systems, typically headless or single-purpose, with 256 MB to 1 GB of RAM. Examples: industrial control systems, automotive subsystems, IoT gateways, sensor hubs, dedicated network appliances.

**Included:** The full microkernel (scheduler, memory manager, capability manager, IPC, interrupt dispatch). A minimal core service set: capability enforcement, basic IPC routing, a minimal storage service, identity primitives (if the deployment uses cryptographic identity), and device drivers for the deployed hardware. No shell beyond a minimal console if any is needed. No compositor. No Windows compatibility layer.

**Excluded:** All AI components (security watcher, UX context model, AI-assisted compatibility). The spatial UX. The full application ecosystem. Network overlay services beyond what the deployment specifically requires.

**Value proposition:** A verified, memory-safe, capability-isolated, zero-trust microkernel for deployments where AI overhead is not available and full UX is not required. ArcOS-Embedded is "ArcOS security architecture without the AI layer and UX layer." It is not a stripped-down version of ArcOS — it is the ArcOS kernel in a deployment tier appropriate to its hardware. Value to users who need a secure microkernel-based OS for fixed-function devices; value to the project as a proving ground for the verification story on small targets.

### Tier 2 — ArcOS-Standard (no AI)

**Target hardware:** General-purpose desktop, laptop, and workstation hardware with 1 GB to 16 GB of RAM that either cannot run local AI inference well or whose users choose not to run it. Examples: older laptops (2015-2022 class hardware), entry-level desktops, developer boxes repurposed as secondary machines, computers in resource-constrained environments.

**Included:** The full microkernel. The full core service set (file system, key store, network stack, identity service, audit service, shell). Non-AI Windows compatibility (hand-coded Win32 shim for common APIs, PE loader with static translation). A traditional windowing shell (not the spatial UX). Full capability enforcement and audit recording. The overlay network (when applicable). User-space applications and the native application framework.

**Excluded:** The security AI watcher (audit recording still happens; there is just no AI consumer of the recordings). The UX context model (the shell is traditional, not contextually adaptive). AI-assisted compatibility translation (Windows apps that require it don't run). AI-assisted driver synthesis. AI-assisted live patching.

**Value proposition:** All the ArcOS security, privacy, and sovereignty commitments on hardware that cannot run local LLMs. Users get a verified microkernel, capability-based isolation, cryptographic identity, zero telemetry, and a traditional but modern shell. The user experience is closer to "a secure BSD with excellent fundamentals" than to "ArcOS as the vision describes it" — and that is a legitimate, valuable product. Many users will run Tier 2 by choice, not because they lack the hardware for Tier 3.

### Tier 3 — ArcOS-Full

**Target hardware:** Modern general-purpose hardware with 8 GB or more of RAM, a 64-bit CPU (x86_64 or AArch64), and ideally GPU or NPU acceleration for AI workloads. This is the primary development target and the tier that embodies the full ArcOS vision.

**Included:** Everything. The full microkernel. The full core service set. All AI components (security watcher, UX context model, AI-assisted compatibility). The spatial, contextually aware UX. AI-assisted Windows compatibility with intelligent translation. The full native application ecosystem. Every feature described in [ArcOS.md](../../ArcOS.md).

**Excluded:** Nothing.

**Value proposition:** ArcOS as envisioned. This is the tier where the project's purpose statements all apply in their strongest form — the tier where a user experiences the spatial UX, runs the behavioral security AI, uses AI-assisted Windows apps, and benefits from the full integration between the kernel and the AI layer.

**Memory budget at the floor.** At 8 GB of RAM, the Tier 3 budget is approximately: 1.5 GB kernel and core services, 2-3 GB user workloads (shell, editor, 1-2 active applications), 1.5 GB security AI watcher (small specialized or heavily-quantized model), 1.5 GB UX context AI (can share infrastructure with security AI where architecturally possible), with roughly 0.5-1.5 GB margin. This is workable but not generous. Users with 16 GB or more see progressively better experiences because the AI components can use larger models, audit ring buffers scale up, cache grows, and more applications can be kept resident.

**Floor revision clause.** The 8 GB floor is chosen so that a wide range of modern hardware qualifies. If experimental work on the AI components reveals that 8 GB is insufficient for the AI workloads ArcOS actually needs — for example, if small specialized models fail to deliver useful behavioral detection — the floor may be revised upward in a superseding document. Such a revision is a documentation change, not a code change: ArcOS's kernel adapts to whatever hardware it finds, and the floor is a commitment about what the project supports well, not a constraint at the code level. Raising the floor later is cheap and is explicitly anticipated. The project prefers to try to fit AI services into a smaller memory window before front-loading bloat into the minimum specification.

### Tiers are user choices informed by hardware, not kernel classifications

The kernel does not detect hardware class and select a tier automatically. The tier is determined at build time: *which user-space services are compiled into the boot image*. A Tier 1 build omits AI components and most non-essential user-space services. A Tier 2 build omits only the AI components. A Tier 3 build includes everything. The user — or the system builder, or the distribution packager — chooses which build to install based on hardware capability, personal preference, and use case.

This is important because hardware capability is not well-captured by any single dimension. A machine with 8 GB of system RAM and a high-end GPU can run Tier 3 comfortably because the AI workloads offload to the GPU and leave system RAM for processes. A machine with 32 GB of system RAM and a weak integrated GPU may not run Tier 3 well because AI inference falls back to CPU and competes with user workloads. A user may have enough hardware for Tier 3 but prefer to run Tier 2 because they do not want AI components active on their machine. All of these are legitimate configurations.

The RAM-based floors in the tier descriptions are *guidance*, not classifications. They describe the hardware profile that the project commits to supporting well at each tier. A user is free to install any tier on any hardware; the project's commitment is that the tier works well when the guidance floor is met, and the user is on their own when it is not.

ArcOS's kernel does not know or care which tier it is running. It runs what the boot manifest gives it. This preserves user freedom to configure custom builds (for specialized workloads, for experimentation, for minimal installations) while giving the project a clean support matrix to maintain.

## Hardware Supply Chain and the Platform Threat Model

The tier model describes what ArcOS does on the software side. It does not fully describe a user's threat model, because hardware supply chain and firmware integrity are upstream of the operating system. This section acknowledges that gap honestly so users can make informed choices.

ArcOS's principles include "Platform Is an Implementation Detail" — the architecture abstraction boundary is clean and the software runs on whatever CPU speaks the right instruction set. This is true about the software. It does not mean the software is the only thing that matters to a user's security posture. A user running ArcOS on commodity consumer hardware has a meaningfully different threat model than a user running it on hardware where the firmware, CPU microcode, boot chain, and supply chain have all been audited. ArcOS's software guarantees are the same in both cases. The user's real-world security story is not.

**What ArcOS cannot defend against at the hardware layer.** Modern x86_64 ships with closed firmware (Intel ME, AMD PSP) that runs in a privilege level below the operating system. A compromised CPU, compromised microcode, or tampered boot firmware is outside ArcOS's defensive surface. AArch64 is similar on many commodity platforms (TrustZone secure monitor blobs, vendor firmware). ArcOS's verification efforts apply to the kernel and user-space code that ArcOS itself writes; they do not apply to the hardware and firmware the kernel runs on top of. This is acknowledged in [ArcOS.md § What ArcOS Does Not Protect Against](../../ArcOS.md) as a side note, but it is a first-class part of the threat model and should be surfaced as such.

**The hardware spectrum.** Users evaluating ArcOS can be placed along a rough spectrum of hardware provenance:

- **Commodity consumer hardware** (retail laptops, desktops, generic ARM boards): the weakest hardware provenance story. Closed firmware, closed CPU microcode, no supply chain transparency. ArcOS's software guarantees apply, but the overall threat model is bounded by what the hardware vendor already knows and what the user cannot audit.
- **Vendor-audited consumer hardware** (System76 Coreboot, Purism Librem, hardware from vendors that publish their firmware and open their supply chains): stronger. The firmware is auditable. The vendor has a public commitment to customer interests rather than platform-vendor interests. ArcOS's software guarantees compose with the vendor's firmware guarantees into a stronger overall story.
- **Auditable open hardware** (Talos II, Raptor Blackbird, open RISC-V workstations, other POWER9 or RISC-V systems with open boot chains): the strongest currently available hardware provenance. Firmware is open source and auditable end-to-end. No proprietary microcode blobs. Supply chain is either transparent or verifiable through community audits. ArcOS's software guarantees compose with hardware guarantees that are also auditable, producing the strongest end-to-end story.

**The project's position.** ArcOS runs on all points along this spectrum. The project does not lock users into any specific hardware vendor, does not recommend any specific vendor commercially, and does not refuse to support commodity hardware. A user running ArcOS on a commodity laptop gets ArcOS's full software security model, which is already much stronger than what current commercial operating systems provide on the same hardware. But users who want the strongest end-to-end security story should look at auditable open hardware, and the project wants those users to understand that software can only do so much if the hardware underneath it is untrustworthy.

**Not a tier boundary.** Hardware provenance is not a deployment tier. Tiers are about which user-space services are included in the build. Hardware provenance is about the user's real-world threat model. They are orthogonal. A Tier 3 ArcOS installation on a Talos II is the strongest configuration available; a Tier 3 installation on a retail laptop is the weakest end-to-end story but the strongest software story. Both are valid. The project supports both.

**Not project effort.** ArcOS does not commit development effort to specific hardware vendors, audited firmware, or custom boot chains for particular platforms. Porting to auditable hardware, certifying specific firmware configurations, and building supply-chain-verified distributions are valuable activities, but they are downstream of the ArcOS project — they are what distributions, vendors, and community ports would do. The project welcomes such work and supports it where the architecture allows, but does not commit resources to it. This is honest guidance rather than an effort commitment.

## Scope Boundaries

### In scope for the full ArcOS project

- **All three deployment tiers** as first-class support targets, with Tier 3 as the primary development target and Tiers 1 and 2 supported secondarily.
- **The microkernel** (verified, capability-based, `no_std` Rust) is the same across tiers.
- **Core user-space services** that apply to all tiers: IPC services, capability enforcement, identity, file system, network stack core, shell.
- **AI components** (security watcher, UX context model, AI-assisted compat) for Tier 3.
- **Non-AI compatibility layers** (hand-coded Win32 shim, POSIX layer, PE loader) for Tiers 2 and 3.
- **AI-assisted compatibility** for Tier 3.
- **Spatial / contextual UX** for Tier 3.
- **Traditional windowing shell** for Tier 2.
- **Minimal console** for Tier 1 where applicable.
- **Windows compatibility bridge** at Tiers 2 and 3 as a transition aid, per Principle 5.
- **Native ArcOS application ecosystem** at all tiers (scope of applications varies by tier).
- **Cryptographic identity, overlay networking, content-addressed storage, signed binaries** at all tiers.
- **Documentation, verification proofs, and test infrastructure.**
- **Target users**: civilian users for whom privacy, sovereignty, and verifiable security are load-bearing. Explicitly including journalists, human rights researchers, healthcare workers, security professionals, educators, and private individuals who want their computer to work for them rather than for a platform company.

### Out of scope

- **Real-time operating system deployments (hard or firm RTOS).** ArcOS targets general-purpose use across all three tiers. RTOS workloads have different scheduling, latency, and verification requirements than ArcOS commits to. A future fork or variant could target RTOS use cases, but that is not this project.
- **High-assurance military / defense workloads.** ArcOS's project effort, design decisions, and development priorities are oriented toward civilian use cases. The project does not commit effort to the specific requirements of military procurement, high-assurance certification (EAL6+, Common Criteria), or classified-information-handling workloads. ArcOS is openly developed and the project cannot and does not attempt to prevent anyone from using the software; but the project's effort goes toward the users it is trying to serve, and military or defense deployments are not among them. The project's position on funding from defense research agencies is documented in [GOVERNANCE.md](../../GOVERNANCE.md).
- **Backward compatibility with pre-UEFI firmware, BIOS-only boot, or 32-bit CPU architectures.** ArcOS targets modern boot firmware and 64-bit CPUs.
- **Maintenance of ports to closed-source proprietary hardware without community interest.** The project will accept ports but does not commit to maintaining them.
- **Matching any existing operating system feature-for-feature.** ArcOS builds what ArcOS needs, not what Linux, Windows, or macOS happen to have.
- **Legacy hardware bare-metal support below the ArcOS-Embedded tier floor.** Below 256 MB of RAM or on unusual CPU architectures, ArcOS is not supported.

### Out of this ADR's scope (but in the project's scope)

- **The design of the spatial UX itself.** User-space work; a future ADR or design document will address it when the time comes.
- **The specific model architecture for the security AI.** A future ADR will address it based on experimental data.
- **The specific model architecture for the UX AI.** Same.
- **The ArcOS-Embedded build mechanism.** Implementation detail — likely Cargo feature flags plus boot manifest variants. Will be addressed at implementation time.
- **The criteria for adding or removing tiers.** If the three-tier model turns out to need a fourth tier (e.g., a "server" tier with different service emphasis) or fewer tiers, that is a future ADR's job.
- **Project governance and funding.** Documented separately in [GOVERNANCE.md](../../GOVERNANCE.md).

## Relationship to Other ADRs

ADRs 000-007 describe mechanism — capability enforcement, scheduler lock hierarchy, IPC design, identity, signed binaries, policy service, audit telemetry, IPC bulk path. This ADR describes purpose. The two layers interact:

- **[ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities)** is the foundational mechanism that delivers the zero-trust portion of Purpose 2. This ADR depends on ADR-000 and applies across all tiers.
- **[ADR-005](005-ipc-primitives-control-and-bulk.md) (IPC primitives)** describes the channel mechanism. Purpose 4 (modern UX) implies channels will carry compositor-to-GPU traffic; Principle 4 (efficient implementation) implies the control path should not add latency to the UX hot path. Applies to Tiers 2 and 3.
- **[ADR-006](006-policy-service.md) (Policy service)** is where Purpose 3 (user sovereignty) gets its user-facing mechanism. The user's ability to see and control what their software does is mediated by the policy service. Applies to Tiers 2 and 3; degraded on Tier 1 where no user interaction mechanism may exist.
- **[ADR-007](007-capability-revocation-and-telemetry.md) (Revocation + telemetry)** provides the audit substrate that the security AI component consumes. Audit recording itself applies to all tiers; the AI consumer applies only to Tier 3.
- **ADR-008 (process table allocation, pending)** depends on this ADR for its hardware floor assumption. The Tier 3 floor of 8 GB is the hardware precondition for ADR-008's boot-time-sized allocator producing useful process table sizes on the primary target.

Future ADRs should cite this one when their scope, hardware assumptions, or tier-dependent behavior requires commitments from this document. If this ADR's commitments change (via a superseding ADR), citing ADRs are flagged for review.

## Cross-References

- [ArcOS.md](../../ArcOS.md) — Source-of-truth architecture document. This ADR makes explicit the commitments that ArcOS.md carries implicitly. ArcOS.md is updated to cross-reference this ADR for tier-specific scope and hardware commitments.
- [PHILOSOPHY.md](../../PHILOSOPHY.md) — Project philosophy. The Purpose Statements section aligns with and makes concrete the philosophical stance described there, particularly the "AI watches without controlling" framing.
- [GOVERNANCE.md](../../GOVERNANCE.md) — Project governance, funding, and contributor commitments. Addresses the funding and institutional independence questions that are adjacent to but distinct from this ADR's architectural commitments.
- [CLAUDE.md](../../CLAUDE.md) — Kernel technical reference. Several sections of CLAUDE.md should reference this ADR once it lands (see "See Also in CLAUDE.md" below).
- [SECURITY.md](../../SECURITY.md) — Security posture document. Purpose 2 is where SECURITY.md's threat model connects to this ADR.
- [win-compat.md](../../win-compat.md) — Windows compatibility design. This ADR makes explicit that Windows compat is a bridge (Principle 5) and scopes it to Tiers 2 and 3.
- [identity.md](../../identity.md) — Identity architecture. Purpose 3 (user sovereignty) is operationalized in identity.md's Principal and key management model.
- [ASSUMPTIONS.md](../../ASSUMPTIONS.md) — Numeric bounds catalog. This ADR does not itself add numeric bounds to the catalog (the tier floors are documentation commitments, not kernel constants), but future ADRs that land tier-dependent bounds will cite this ADR.

## See Also in CLAUDE.md

When this ADR lands, the following CLAUDE.md sections should be updated to reference it:

- **"Project Vision"** paragraph — the four purpose statements in this ADR are the project vision, stated explicitly. Update to cite ADR-009 for the load-bearing commitments.
- **"Development Environment"** section — the hardware profile in this ADR is the target environment. Update to mention the tier model and cite ADR-009 for the floors.
- **"Multi-Platform Strategy"** — the broad hardware range is now bounded by the tier floors. Update to cite ADR-009.
- **"Required Reading by Subsystem"** — add a new row for "Project purpose / hardware tiers / scope boundaries" pointing to ADR-009. This makes ADR-009 discoverable to future contributors working on any subsystem that depends on its commitments.
- **"Post-Change Review Protocol"** — Step 8 (documentation sync) should note that changes which affect tier-dependent features require checking ADR-009's tier descriptions and updating them if necessary.
