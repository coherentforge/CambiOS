<!--
doc_type: design_plan
owns: Windows compatibility layer architecture and sequencing
auto_refresh: forbidden
authoritative_for: PE loader sandbox, sandboxed Principal model, Win32 application support phases, virtual filesystem/registry mapping
-->

# CambiOS Windows Compatibility Layer — Design Document

This document captures the design for CambiOS's Windows application compatibility layer — a sandboxed execution environment that runs unmodified Windows PE binaries on CambiOS using hand-coded static shims over a bounded, published Win32 surface. It is a living design document, not a specification. Implementation status of any phase or feature lives in [STATUS.md](../STATUS.md).

For the identity model that governs how sandboxed processes interact with the system, see [identity.md](identity.md). For the object store that mediates file access, see [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md). For the authoritative rules defining which Win32 functions are supported, how they are dispatched, how unsupported calls behave, and the Phase 1 catalog, see [ADR-016](adr/016-win-compat-api-ai-boundary.md). Sections below that describe those topics are kept brief; ADR-016 is the source of truth.

---

## The Core Claim

CambiOS can run Windows applications without Windows, without a Windows kernel, without a hypervisor, and without an AI translator on the critical path. The mechanism is a bounded, published set of hand-coded Win32 shims in Rust, a PE/COFF loader that resolves imports against that set, and an explicit "not supported" outcome for everything outside it. What we support is documented; what we don't, we don't pretend to.

This is the same shape as Wine — a user-space reimplementation of the Win32 API — narrowed by two CambiOS constraints. First, the kernel below it is a microkernel with zero-trust IPC and capability-based access, so every shim runs under a sandboxed Principal with explicit grants. Second, the scope is deliberately bounded: a defined list of applications we aim to run, and a defined Win32 surface that covers them. We trade breadth for provability and clarity of contract.

---

## What This Is Not

**It is not a virtual machine.** The application runs natively on CambiOS hardware. No Windows kernel, no hypervisor, no license.

**It is not a full Win32 reimplementation.** Wine aims for API-level fidelity across most of Win32. CambiOS aims for behavioral equivalence across a bounded subset — the functions listed in ADR-016's Phase 1 catalog, grown by an explicit process when target apps require it. Applications outside that scope are out of scope, not half-working.

**It is not AI-translated.** An earlier version of this design proposed an AI translation layer that produced validated interpretation plans for Win32 functions lacking a static handler. That direction was withdrawn; see [ADR-016](adr/016-win-compat-api-ai-boundary.md) for the reasoning. All shims are hand-coded Rust.

**It is not unrestricted.** A Windows binary is untrusted foreign code. It runs in a sandbox with a constrained Principal, mediated IPC access, and no direct hardware interaction. The zero-trust model applies fully.

---

## Trust Model

### Sandboxed Principal

A Windows PE binary cannot carry a CambiOS Ed25519 identity. It receives a **sandboxed Principal** — a synthetic identity generated per-application-instance, scoped to the compatibility sandbox.

```
SandboxedPrincipal {
    inner:       Principal,          // Ed25519 keypair, ephemeral or user-bound
    parent:      Principal,          // the CambiOS user who launched the app
    permissions: SandboxPolicy,      // what this process may access
    label:       String,             // human-readable: "QuickBooks 2024"
}
```

The sandboxed Principal:

- **Cannot impersonate** the parent user's Principal
- **Cannot access** IPC endpoints unless the sandbox policy explicitly grants it
- **Cannot touch hardware** — all device access is mediated through CambiOS services
- **Can store objects** in the ObjectStore, tagged with the sandbox Principal as author (the parent user is owner)
- **Can be revoked** by the parent user at any time — killing the process and invalidating stored capabilities

### File Access

Windows apps expect a filesystem with drive letters, paths, and ACLs. The compatibility layer provides a **virtual filesystem view**:

```
C:\Users\<user>\Documents\  →  ObjectStore query (owner = parent Principal, tag = "documents")
C:\Program Files\<app>\     →  read-only view of the app's installation objects
C:\Windows\System32\        →  compatibility layer's DLL shim library
HKEY_LOCAL_MACHINE\...      →  virtual registry (CambiObject-backed key-value store)
HKEY_CURRENT_USER\...       →  per-sandbox registry (CambiObject-backed)
```

File writes from the sandboxed app create CambiObjects with:

- **author** = sandboxed Principal (the app created it)
- **owner** = parent Principal (the user controls it)

The user owns everything the app produces, and authorship is attributable to the specific sandboxed instance.

### Network Access

Sandboxed processes have no network access by default. The sandbox policy can grant:

- Specific endpoint access (e.g., "QuickBooks may reach intuit.com on port 443")
- Full outbound access (opt-in, with user consent)
- No inbound access (the sandbox cannot listen)

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    CambiOS Kernel                        │
│  (IPC, scheduler, memory, identity — unchanged)          │
└──────────┬──────────────────────────────┬────────────────┘
           │ IPC                          │ IPC
┌──────────▼──────────┐      ┌────────────▼───────────────┐
│  win-compat          │      │  CambiOS Native Services   │
│  (endpoint 24)       │──────│  fs-service (16)           │
│                      │ IPC  │  key-store (17)            │
│  Single user-space   │      │  net, print, UI (future)   │
│  service crate       │──────│                            │
└──────────┬───────────┘      └────────────────────────────┘
           │ IPC (private
           │  endpoint per
           │  sandboxed PE)
┌──────────▼──────────┐
│  Sandboxed PE        │   Each PE process gets a private
│  Process             │   endpoint from the tier-policy pool.
│  (ring 3, restricted │   Enables per-sandbox capability
│   Principal)         │   isolation at the IPC layer.
└─────────────────────┘
```

No translator service. The compat layer's trust boundary is `(kernel ↔ win-compat ↔ sandbox)`; there is no third party between win-compat and the sandbox. AI-assisted features that involve Windows-app data (e.g., a user asking "summarize this document" where the document is open inside a sandboxed PE app) are handled by the cloud-inference facility described in [ADR-017](adr/017-user-directed-cloud-inference.md), invoked by the user, not by the compat layer.

### Crate Structure

The entire compatibility layer is a single user-space service crate, following the same pattern as `fs-service` and `key-store-service`: one crate, one IPC control endpoint, loaded as a signed boot module.

```
user/
├── fs-service/             # existing — endpoint 16
├── key-store-service/      # existing — endpoint 17
└── win-compat/             # control endpoint 24; per-sandbox endpoints from tier pool
    ├── Cargo.toml
    ├── link.ld             # linker script (same pattern as fs-service)
    └── src/
        ├── main.rs         # service loop: IPC recv → dispatch → respond
        ├── pe.rs           # PE/COFF loader (PE32 + PE32+)
        ├── msi.rs          # MSI engine (component tables, file extraction, custom actions)
        ├── shims/          # curated Win32 API implementations
        │   ├── mod.rs      # shim dispatch table (import name → handler fn)
        │   ├── ntdll.rs    # heap, TLS, low-level runtime
        │   ├── kernel32.rs # file I/O, memory, threading, version queries
        │   ├── user32.rs   # windowing, message loop, dialogs
        │   ├── gdi32.rs    # 2D rendering, device contexts, fonts
        │   ├── advapi32.rs # registry, security tokens, crypto stubs
        │   ├── ole32.rs    # COM runtime (bounded CLSID set)
        │   ├── shell32.rs  # file dialogs, shell integration
        │   └── comctl32.rs # common controls (list view, tree view, etc.)
        ├── vfs.rs          # virtual filesystem (drive letters → ObjectStore)
        ├── registry.rs     # virtual registry (HKLM/HKCU/HKCR → CambiObject KV)
        ├── sandbox.rs      # sandbox policy + SandboxedPrincipal management
        └── thunk32.rs      # 32-bit compat-mode support (heaven's gate stub)
```

### Components

**PE Loader** (`pe.rs`) — Parses PE/COFF headers (PE32 and PE32+), maps sections into the sandboxed process's address space (analogous to the existing ELF loader but for PE format). Resolves import tables against the shim dispatch table. Missing imports become stubs or refuse-to-load depending on sandbox manifest. PE binaries use a separate verification path (see below) — they do not pass through the signed ELF gate.

**Shim Layer** (`shims/`) — Hand-coded Rust implementations of supported Win32 functions, one file per DLL. Dispatch table maps `(dll_name, function_name)` to a handler or a router (for argument-sensitive APIs). ADR-016 lists the full Phase 1 catalog; adding new functions follows the [Adding Functions](adr/016-win-compat-api-ai-boundary.md#adding-functions) process in that ADR.

**Virtual Filesystem** — Maps Windows path conventions to ObjectStore queries. Maintains a path-to-hash index per sandbox. Handles drive letters, UNC paths, and Windows path separators. Translates Windows file attributes and timestamps to CambiObject metadata.

**Virtual Registry** — Windows applications depend heavily on the registry for configuration, COM class registration, file associations, and license state. The virtual registry is a CambiObject-backed key-value store, scoped per-sandbox. Registry writes from one sandboxed app are invisible to others (isolation).

**Sandbox Policy** — Declarative policy attached to each sandboxed Principal:

```
SandboxPolicy {
    fs_access:       Vec<FsGrant>,        // which ObjectStore paths/tags are visible
    net_access:      Vec<NetGrant>,       // which endpoints are reachable
    ipc_endpoints:   Vec<EndpointGrant>,  // which CambiOS IPC endpoints are callable
    resource_limits: ResourceLimits,      // memory, CPU time, object count
    clipboard:       bool,                // can read/write host clipboard
    ui:              bool,                // can create windows/dialogs
    strict_imports:  bool,                // refuse to load when imports are missing
}
```

---

## PE Binary Verification

Windows binaries don't carry ARCSIG signatures and cannot pass through the `SignedBinaryVerifier`. The compatibility layer uses a separate trust chain:

1. **Authenticode verification** — if the PE binary has a valid Microsoft Authenticode signature, verify it. This provides provenance (the binary came from a known publisher) but not CambiOS-level trust.
2. **User consent** — the parent Principal must explicitly authorize execution. The first launch of a new PE binary presents a consent dialog showing the publisher (if Authenticode-signed) or "unknown publisher."
3. **Content hash tracking** — the PE binary's Blake3 hash is recorded. If the binary changes (update, tampering), the user is prompted again.
4. **No implicit trust** — an Authenticode signature does not grant the sandboxed process any additional capabilities. Trust comes from the sandbox policy, not the binary's signature.

---

## Design Principles

### Defined Surface, Not Inferred Surface

The compat layer supports a documented list of Win32 functions. Applications whose needs fall outside that list are either out of scope or become the trigger for extending the list by the process documented in ADR-016. There is no inference, no pattern recognition, no attempt to handle functions we haven't written code for. This is how the compat layer earns the property of being testable and, eventually, formally verifiable.

### Graceful Degradation, Not Silent Degradation

When a call cannot be served — because the import is stubbed, because the router has no matching sub-handler, because a supported function hits an unsupported argument combination — the outcome is a specific Win32 error code. Applications see a clear signal and can take their own fallback paths. The compat layer never fakes success.

### Audit Drives Catalog Growth

Every unsupported call is audit-logged (see ADR-016 § Audit). The audit trail is the feedback loop: when a target application fails because of a missing function, the audit log names the function, and that function becomes a candidate for catalog entry if it meets the scoping criteria.

---

## Target Application Phases

### Phase 1 — Business/Accounting (smallest Win32 surface)

**Target apps:** QuickBooks Desktop, Sage 50, tax preparation software (Lacerte, Drake)

**Why first:** These apps use standard Win32 controls (dialogs, list views, tree views), file I/O, registry for config, and printing. They don't use DirectX, COM automation is light, and rendering is GDI-based. The API surface is well-documented and relatively small — ~95 functions covers most of it (see the ADR-016 Phase 1 catalog).

**Validation target:** QuickBooks Desktop installs from its .exe installer, opens a company file, generates a report, prints it.

### Phase 2 — CAD/Engineering (the north star, open feasibility)

**Target apps:** SolidWorks, AutoCAD, Revit, Inventor

**Why second:** These apps are deeply COM-dependent, use DirectX or OpenGL for 3D rendering, and have complex plugin architectures. They represent the hardest and most valuable target.

**Open feasibility question.** Phase 2 previously relied on the AI translator to bridge the COM/DirectX/OLE surface without hand-coding every interaction. Without the translator, each COM interface, each DirectX subset, each OLE container primitive must be hand-coded as a shim. That is a substantial body of work — feasible in principle (Wine demonstrates this, over decades), but the question of *whether Phase 2 is achievable at CambiOS's pace and with CambiOS's headcount* is open until Phase 1 is shipped and maintenance cost is known.

**Validation target:** SolidWorks installs, opens a part file, renders it, allows basic editing. Whether this target is reached in a few years or is deferred to a partner effort will be decided after Phase 1 lands.

### Phase 3 — Scientific/Instrumentation (hardware-coupled)

**Target apps:** LabVIEW, instrument control software

**Additional requirements:** USB device passthrough, VISA/GPIB protocol translation. This tier depends on CambiOS having a mature USB stack and device driver model, and is downstream of Phase 1 and Phase 2 decisions.

---

## Interaction with Existing CambiOS Architecture

### Kernel Changes Required

**Minimal.** The compatibility layer is a user-space service. The kernel needs:

- **PE section mapping** — the loader maps PE sections with appropriate permissions (RX for `.text`, RW for `.data`). The existing `map_page` / `map_range` primitives suffice.
- **No new syscalls for Phase 1** — the existing syscall set covers process lifecycle, memory, IPC, and object store access. The compat service translates Win32 calls into sequences of existing syscalls.
- **Possible future syscall for SEH** — Windows uses structured exception handling pervasively. A lightweight trap-and-dispatch mechanism in the kernel may be more efficient than a full user-space emulator. This is a Phase 2 decision; Phase 1 stubs the SEH entry points.

### IPC Integration

The compatibility service registers on a dedicated IPC endpoint (24). Sandboxed PE processes communicate with it on per-sandbox private endpoints (drawn from the tier-policy pool). The existing IPC infrastructure — capability checks, `sender_principal` stamping, zero-trust interceptor — applies unchanged.

### ObjectStore Integration

All file I/O from sandboxed apps flows through the compatibility service → FS service → ObjectStore. The sandboxed Principal is the author; the parent user is the owner. Existing ownership, signature, and ACL enforcement applies.

### Identity Integration

The sandboxed Principal is created by the compatibility service (which holds the parent user's delegation). `BindPrincipal` assigns the sandboxed identity. `GetPrincipal` / `RecvMsg` identity-aware IPC works unchanged — CambiOS services receiving requests from a sandboxed app see the sandboxed Principal and enforce policy accordingly.

---

## Settled Decisions

**32-bit PE support on x86_64 — yes, via CPU compatibility mode.** The microkernel's IPC architecture makes this dramatically simpler than Windows WoW64. In a monolithic kernel, WoW64 must thunk ~2000 syscalls between 32-bit and 64-bit struct layouts. In CambiOS, the 32-bit PE process communicates with the 64-bit compatibility service via IPC messages (raw bytes — no pointer-width dependency). The IPC boundary does the thunking for free. Kernel changes: two new GDT entries (32-bit compat-mode code/data segments, L=0 D=1), ~4 lines in `gdt.rs`. User-space: a "heaven's gate" thunk (~20 instructions) in the shim DLLs does a far-jump to 64-bit mode for CambiOS syscalls. Process address space already fits in the lower 4 GB. **AArch64 32-bit x86 PE requires full binary translation — part of the larger "x86-on-ARM" problem, not addressed here.**

**Installer UX — "download .exe, it works."** Download a Windows installer (.exe or .msi), double-click it, it installs and runs. The installer executes inside the sandbox like any other PE binary. All side effects are captured:

- File creation → ObjectStore objects (virtual filesystem)
- Registry writes → virtual registry (CambiObject-backed KV store)
- COM registration → virtual registry entries under HKCR
- Service registration → sandboxed background tasks
- Shortcut creation → sandbox manifest metadata

The sandbox fakes the environment the installer expects: UAC elevation prompts auto-approve within the sandbox (sandbox "admin" has no real privilege); Windows version queries report Windows 10 22H2 (or configurable); reboot requests restart the sandbox process; .NET / VC++ redistributable checks are satisfied by the shim library.

MSI support requires a minimal Windows Installer engine (MSI is a transactional relational database, not a simple archive). Prior art: Wine's `msi.dll`, GNOME's `msitools`. Mapped territory but non-trivial — Phase 0 work because most enterprise apps ship as MSI.

**DLL loading strategy — curated set only.** Ship a curated set of shim DLLs for core Win32 surface (`ntdll`, `kernel32`, `user32`, `gdi32`, `advapi32`, `ole32`, `shell32`, `comctl32`, `comdlg32`). Less common DLLs are not automatically generated; an app importing from a DLL outside the curated set fails to load (strict_imports) or loads with all imports from that DLL stubbed. Adding a new DLL to the curated set is a scope decision that lands with hand-coded shim content.

---

## Open Questions

1. **Graphics rendering.** DirectX and OpenGL translation are substantial efforts. The choices (DirectX → Vulkan à la DXVK; native DirectX-subset renderer; Phase 2 deferral) all carry significant implementation cost. Decision deferred to Phase 2 design. **Revisit when:** Phase 1 ships and Phase 2 feasibility becomes the next scope decision.

2. **Threading model.** Windows threading (fibers, APCs, TLS, apartment threading for COM) has subtle differences from a straightforward model. How much do we faithfully replicate vs. simplify at the shim boundary? **Revisit when:** a Phase 1 app fails because of a threading-subtlety gap named in audit.

3. **Shared shim distribution.** If multiple CambiOS users benefit from the same shim additions, is there a mechanism for publishing the curated set (plus its growth) to other instances — e.g., via SSB — or is it bundled per-release? Distribution is a later concern; coherence of what's shipped matters first. **Revisit when:** a first external contributor proposes a catalog addition.

4. **x86-on-AArch64.** Running x86 PE binaries on AArch64 hardware requires binary translation (Apple Rosetta-style). Separate, large effort. Initial compatibility layer targets x86_64 native only.

---

## Non-Goals

- **Running Windows drivers.** Drivers require kernel-level access the sandbox cannot provide.
- **Running Windows services.** Background services that expect SCM (Service Control Manager) integration are out of scope for Phase 1.
- **DRM / anti-cheat compatibility.** Kernel-level DRM and anti-cheat systems (Denuvo kernel mode, Vanguard, EAC) require ring 0 access. They will not work and we will not try to make them work.
- **Pixel-perfect UI rendering.** The goal is functional equivalence, not visual identity with Windows. A "Save As" dialog should work correctly; it doesn't need to look exactly like the Windows 11 version.
- **Full Win32 coverage.** The compat layer supports a documented subset. This is a feature, not a limitation.

---

## Implementation Sequencing

Preliminary. The actual implementation plan will be developed as the prerequisites (virtio-net, UDP stack, UI service) are completed and the compatibility layer moves from design to implementation.

### Phase 0 — PE Loader + Installer + Minimal Shims

- PE/COFF parser for PE32 and PE32+ (analogous to `loader/elf.rs`)
- Section mapper (reuse existing page-table infrastructure)
- 32-bit compat-mode GDT entries + heaven's gate thunk in shim library
- Import table resolution against curated shim set; stubbed-import default; `strict_imports` sandbox-manifest override
- Shim DLLs: `ntdll` (heap, TLS basics), `kernel32` (file I/O, memory, threading basics, version queries)
- Sandboxed Principal creation and binding
- Virtual registry (HKCU/HKLM/HKCR, CambiObject-backed KV store)
- Virtual filesystem (drive letter mapping, path translation, `C:\Windows\System32\` → shim library)
- MSI engine (minimal: component/feature tables, file extraction, registry actions, custom action execution)
- NSIS/Inno Setup support (these are PE executables — they run naturally once the shim layer works)
- Environment faking: Windows version reporting, UAC auto-approve, reboot simulation
- **Validation target 0a:** a simple 32-bit Win32 console application runs and exits cleanly
- **Validation target 0b:** an NSIS-packaged application installs and launches in the sandbox

### Phase 1 — Business Application Support

- Expand shim coverage to the full ADR-016 Phase 1 catalog: `user32`, `gdi32`, `advapi32`, `ole32` (bounded CLSID set), `shell32`, `comctl32`
- Printing pipeline (translate Win32 GDI printing to CambiOS print service)
- .NET Framework hosting (CoreCLR or Mono, in-sandbox) — many business apps are .NET WinForms
- **Validation target:** QuickBooks Desktop installs from its .exe installer, opens a company file, generates a report, prints it

### Phase 2 — CAD Application Support (feasibility to be re-evaluated after Phase 1)

- Expanded COM runtime (class factory, apartment threading, marshaling, structured storage)
- DirectX/OpenGL rendering translation (approach TBD — see Open Questions)
- OLE/ActiveX container (in-place activation, drag-and-drop)
- COM interop for .NET mixed-mode assemblies
- **Validation target:** SolidWorks installs, opens a part file, renders it, allows basic editing. Reaching this target is contingent on Phase 1 maintenance cost being acceptable.

### Phase 3 — Ecosystem + Instrumentation

- USB device passthrough for instrumentation software
- x86-on-AArch64 binary translation (if AArch64 is a target platform for the compat layer)
- **Validation target:** LabVIEW communicates with a connected NI DAQ device
