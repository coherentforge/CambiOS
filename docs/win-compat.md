<!--
doc_type: design_plan
owns: Windows compatibility layer architecture and sequencing
auto_refresh: forbidden
authoritative_for: PE loader sandbox, sandboxed Principal model, AI shim translation tiers, Win32 application support phases
-->

# CambiOS Windows Compatibility Layer — Design Document

This document captures the design for CambiOS's Windows application compatibility layer — a sandboxed execution environment that runs unmodified Windows PE binaries on CambiOS, using AI-assisted API translation at JIT and runtime. It is a living design document, not a specification. Implementation status of any phase or feature lives in [STATUS.md](../STATUS.md).

For the identity model that governs how sandboxed processes interact with the system, see [identity.md](identity.md).
For the object store that mediates file access, see [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md).
For the authoritative rules defining which Win32 functions are served by static shims vs. the AI translator (the API/AI boundary, plan grammar, validation pipeline, caching, audit schema), see [ADR-010](adr/010-win-compat-api-ai-boundary.md) and the companion [Phase 1 catalog](adr/010-win-compat-phase1-catalog.md). Sections below that describe these topics are kept brief; ADR-010 is the source of truth.

---

## The Core Claim

CambiOS can run Windows applications without Windows. Not by reimplementing Win32 line-by-line (the Wine approach, 30 years and counting), but by understanding what the application is trying to do and translating that intent to CambiOS primitives — at load time where possible, at runtime where necessary, with AI bridging the gaps that static translation cannot.

The compatibility layer is not an emulator. It is a translator with a learning curve.

---

## What This Is Not

**It is not a virtual machine.** The application runs natively on CambiOS hardware. No Windows kernel, no hypervisor, no license.

**It is not Wine.** Wine reimplements the Win32 API surface function-by-function. CambiOS's compatibility layer starts with static shims for known APIs but falls back to AI-assisted intent translation for unknown or complex call patterns. The goal is behavioral equivalence, not API-level fidelity.

**It is not unrestricted.** A Windows binary is untrusted foreign code. It runs in a sandbox with a constrained Principal, mediated IPC access, and no direct hardware interaction. The zero-trust model applies fully.

---

## Trust Model

### Sandboxed Principal

A Windows PE binary cannot carry an CambiOS Ed25519 identity. It receives a **sandboxed Principal** — a synthetic identity generated per-application-instance, scoped to the compatibility sandbox.

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
- **Can store objects** in the ObjectStore, but they are tagged with the sandbox Principal as author (the parent user is owner)
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

This means the user owns everything the app produces, and authorship is attributable to the specific sandboxed instance.

### Network Access

Sandboxed processes have no network access by default. The sandbox policy can grant:
- Specific endpoint access (e.g., "QuickBooks may reach intuit.com on port 443")
- Full outbound access (opt-in, with user consent)
- No inbound access (the sandbox cannot listen)

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    CambiOS Kernel                           │
│  (IPC, scheduler, memory, identity — unchanged)          │
└──────────┬──────────────────────────────┬────────────────┘
           │ IPC                          │ IPC
┌──────────▼──────────┐      ┌────────────▼───────────────┐
│  win-compat          │      │  CambiOS Native Services     │
│  (endpoint 24)       │──────│  fs-service (16)           │
│                      │ IPC  │  key-store (17)            │
│  Single user-space   │──────│  AI translator (25)        │
│  service crate       │      │  net, print, UI (future)   │
└──────────┬───────────┘      └───────────────────────────┘
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

**Endpoint allocation note.** Earlier drafts of this document named endpoint 20 for win-compat and endpoint 21 for the AI translator, but those endpoints are now in use by the virtio-net driver (20) and UDP stack (21). The revised allocation is: win-compat control endpoint = 24, AI translator = 25, with per-sandbox private endpoints drawn from the tier-policy pool (see the endpoint-sizing ADR landing alongside ADR-010).

### Crate Structure

The entire compatibility layer is a single user-space service crate, following the same pattern as `fs-service` and `key-store-service`: one crate, one IPC endpoint, loaded as a signed boot module.

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
        │   ├── ntdll.rs    # heap, TLS, SEH, process/thread internals
        │   ├── kernel32.rs # file I/O, memory, threading, version queries
        │   ├── user32.rs   # windowing, message loop, dialogs
        │   ├── gdi32.rs    # 2D rendering, device contexts, fonts
        │   ├── advapi32.rs # registry, security tokens, crypto stubs
        │   ├── ole32.rs    # COM runtime (CoCreateInstance, apartments)
        │   ├── shell32.rs  # file dialogs, shell integration
        │   └── comctl32.rs # common controls (list view, tree view, etc.)
        ├── vfs.rs          # virtual filesystem (drive letters → ObjectStore)
        ├── registry.rs     # virtual registry (HKLM/HKCU/HKCR → CambiObject KV)
        ├── sandbox.rs      # sandbox policy + SandboxedPrincipal management
        └── thunk32.rs      # 32-bit compat-mode support (heaven's gate stub)
```

The AI translator is the one component that lives outside `win-compat` — it runs as a separate service (endpoint 25) with its own Principal, because it has a fundamentally different resource profile (model weights, inference compute) and its own trust boundary. But from the PE process's perspective, the AI translator doesn't exist. The PE process only ever talks to `win-compat` on its sandbox's private endpoint.

### Components

**PE Loader** (`pe.rs`) — Parses PE/COFF headers (both PE32 and PE32+), maps sections into the sandboxed process's address space (analogous to the existing ELF loader but for PE format). Resolves import tables against the shim dispatch table. Does NOT execute the binary through the signed ELF gate — PE binaries use a separate verification path (see below).

**API Shim Layer** (`shims/`) — Static implementations of known Win32 API calls. These are pre-built translations:
- `CreateFileW` → ObjectStore put/get via FS service IPC
- `ReadFile` / `WriteFile` → IPC read/write to FS service
- `VirtualAlloc` / `VirtualFree` → CambiOS Allocate/Free syscalls
- `GetSystemTime` → CambiOS GetTime syscall
- `MessageBoxW` → CambiOS UI service notification (future)
- `RegOpenKeyEx` / `RegQueryValueEx` → virtual registry lookup

This is the fast path. Known APIs, known translations, no AI involved.

**AI Translator** (endpoint 25, separate service) — The novel component. When the shim layer encounters an API call it doesn't have a static translation for, or when a sequence of calls forms a pattern that needs higher-level understanding, `win-compat` forwards the request to the AI translator over IPC. The translator's output is a validated *interpretation plan* (not emitted code) that the dispatcher executes under the sandbox's capabilities. The full plan grammar, validation pipeline, caching model, and signature requirements are in [ADR-010](adr/010-win-compat-api-ai-boundary.md).

**Virtual Filesystem** — Maps Windows path conventions to ObjectStore queries. Maintains a path-to-hash index per sandbox. Handles drive letters, UNC paths, and Windows path separators. Translates Windows file attributes and timestamps to CambiObject metadata.

**Virtual Registry** — Windows applications depend heavily on the registry for configuration, COM class registration, file associations, and license state. The virtual registry is an CambiObject-backed key-value store, scoped per-sandbox. Registry writes from one sandboxed app are invisible to others (isolation).

**Sandbox Policy** — Declarative policy attached to each sandboxed Principal:
```
SandboxPolicy {
    fs_access:     Vec<FsGrant>,        // which ObjectStore paths/tags are visible
    net_access:    Vec<NetGrant>,        // which endpoints are reachable
    ipc_endpoints: Vec<EndpointGrant>,   // which CambiOS IPC endpoints are callable
    resource_limits: ResourceLimits,     // memory, CPU time, object count
    clipboard:     bool,                 // can read/write host clipboard
    ui:            bool,                 // can create windows/dialogs
}
```

---

## PE Binary Verification

Windows binaries don't carry ARCSIG signatures and cannot pass through the SignedBinaryVerifier. Instead, the compatibility layer uses a separate trust chain:

1. **Authenticode verification** — if the PE binary has a valid Microsoft Authenticode signature, verify it. This provides provenance (the binary came from a known publisher) but not CambiOS-level trust.

2. **User consent** — the parent Principal must explicitly authorize execution. The first launch of a new PE binary presents a consent dialog showing the publisher (if Authenticode-signed) or "unknown publisher."

3. **Content hash tracking** — the PE binary's Blake3 hash is recorded. If the binary changes (update, tampering), the user is prompted again.

4. **No implicit trust** — an Authenticode signature does not grant the sandboxed process any additional capabilities. Trust comes from the sandbox policy, not the binary's signature.

---

## AI Translation — Design Principles

### Intent Over Fidelity

The AI translator does not aim to produce a pixel-perfect reimplementation of every Win32 API. It aims to preserve the **intent** of the application's behavior:

- A file save dialog doesn't need `CreateWindowExW` + `WM_INITDIALOG` + owner-drawn controls. It needs "the user picks a file path to save to."
- A registry query for a configuration value doesn't need the full HKEY hierarchy. It needs "read a named setting."
- A COM `QueryInterface` chain doesn't need a full COM runtime. It needs "get an interface pointer that supports these methods."

This is where the AI has a structural advantage over static reimplementation: it can recognize patterns at a higher level of abstraction.

### Translation Tiers and Boundary Rules

The four-tier model (Tier 0 static / Tier 1 JIT / Tier 2 behavioral / Tier 3 interactive) is specified in [ADR-010](adr/010-win-compat-api-ai-boundary.md). The ADR defines the decision procedure (determinism, statefulness, frequency, risk surface, argument complexity), the plan grammar the AI translator emits, the validation pipeline every plan passes before execution, the cache and promotion rules, and the audit schema.

The companion [Phase 1 catalog](adr/010-win-compat-phase1-catalog.md) applies those rules to the ~100 Win32 functions the Phase 1 target apps (QuickBooks, Sage 50, Lacerte, Drake) call. Summary: ~71 Tier 0 static shims, ~19 Tier 1 JIT plans, 6 Tier 2 behavioral patterns, 4 argument-sensitive routers. New Win32 functions are classified using the ADR's procedure and added to the catalog; the ADR itself changes only if the rules change.

### Model Placement

The AI model powering the translator does NOT run inside the sandboxed process. It runs as a separate CambiOS service with its own Principal, communicating with the compatibility service over IPC. This means:
- The model's weights and state are protected from the sandboxed app
- The sandboxed app cannot influence the model's behavior (no prompt injection via API call parameters)
- Model updates don't require restarting sandboxed apps
- The model service can be shared across multiple compatibility instances

---

## Target Application Tiers

### Phase 1 — Business/Accounting (smallest Win32 surface)

**Target apps:** QuickBooks Desktop, Sage 50, tax preparation software (Lacerte, Drake)

**Why first:** These apps use standard Win32 controls (dialogs, list views, tree views), file I/O, registry for config, and printing. They don't use DirectX, COM automation is light, and rendering is GDI-based. The API surface is well-documented and relatively small.

**Win32 APIs required:**
- File I/O: `CreateFile`, `ReadFile`, `WriteFile`, `FindFirstFile`, `GetFileAttributes`
- Registry: `RegOpenKeyEx`, `RegQueryValueEx`, `RegSetValueEx`, `RegCreateKeyEx`
- Memory: `VirtualAlloc`, `VirtualFree`, `HeapCreate`, `HeapAlloc`
- UI: `CreateWindowEx`, `ShowWindow`, `MessageBox`, `GetMessage`, `DispatchMessage`
- GDI: `CreateDC`, `TextOut`, `BitBlt`, `SelectObject` (basic 2D rendering)
- Threading: `CreateThread`, `WaitForSingleObject`, `EnterCriticalSection`
- DLL: `LoadLibrary`, `GetProcAddress`
- Printing: `StartDoc`, `StartPage`, `EndPage`, `EndDoc`

### Phase 2 — CAD/Engineering (the north star)

**Target apps:** SolidWorks, AutoCAD, Revit, Inventor

**Why second:** These apps are deeply COM-dependent, use DirectX or OpenGL for 3D rendering, and have complex plugin architectures. They represent the hardest and most valuable target.

**Additional API surface required:**
- COM: `CoCreateInstance`, `QueryInterface`, `IUnknown`, `IDispatch`, apartment threading
- DirectX 11/12: device creation, swap chains, shader compilation, draw calls
- OpenGL: `wglCreateContext`, full GL 4.x+ call surface
- OLE/ActiveX: drag-and-drop, in-place activation, structured storage
- .NET interop: P/Invoke, COM interop, mixed-mode assemblies
- MAPI: email integration (for "send drawing to..." workflows)

### Phase 3 — Scientific/Instrumentation (hardware-coupled)

**Target apps:** LabVIEW, instrument control software

**Additional requirements:** USB device passthrough, VISA/GPIB protocol translation. This tier depends on CambiOS having a mature USB stack and device driver model.

---

## Interaction with Existing CambiOS Architecture

### Kernel Changes Required

**Minimal.** The compatibility layer is a user-space service. The kernel needs:
- **PE section mapping** — the loader needs to map PE sections with appropriate permissions (RX for .text, RW for .data). The existing `map_page`/`map_range` primitives suffice; the PE loader just needs to call them correctly.
- **No new syscalls** for Phase 1 — the existing 20 syscalls cover process lifecycle, memory, IPC, and object store access. The compatibility service translates Win32 calls into sequences of existing syscalls.
- **Possible future syscall** for structured exception handling (SEH) — Windows uses SEH pervasively. A lightweight trap-and-dispatch mechanism in the kernel may be more efficient than emulating it entirely in user space. This is a Phase 2 consideration.

### IPC Integration

The compatibility service registers on a dedicated IPC endpoint (e.g., endpoint 20). Sandboxed PE processes communicate with it for all translated API calls. The existing IPC infrastructure (capability checks, sender_principal stamping, zero-trust interceptor) applies unchanged.

### ObjectStore Integration

All file I/O from sandboxed apps flows through the compatibility service → FS service → ObjectStore. The sandboxed Principal is the author; the parent user is the owner. Existing ownership, signature, and ACL enforcement applies.

### Identity Integration

The sandboxed Principal is created by the compatibility service (which holds the parent user's delegation). The `BindPrincipal` syscall is used to assign the sandboxed identity. The existing `GetPrincipal` / `RecvMsg` identity-aware IPC works unchanged — CambiOS services receiving requests from a sandboxed app see the sandboxed Principal and can enforce policy accordingly.

---

## Settled Decisions (Compatibility Layer)

**32-bit PE support on x86_64 — yes, via CPU compatibility mode.** The microkernel's IPC architecture makes this dramatically simpler than Windows WoW64. In a monolithic kernel, WoW64 must thunk ~2000 syscalls between 32-bit and 64-bit struct layouts. In CambiOS, the 32-bit PE process communicates with the 64-bit compatibility service via IPC messages (raw bytes — no pointer-width dependency). The IPC boundary does the thunking for free. Kernel changes: two new GDT entries (32-bit compat-mode code/data segments, L=0 D=1), ~4 lines in `gdt.rs`. User-space: a "heaven's gate" thunk (~20 instructions) in the shim DLLs does far-jump to 64-bit mode for CambiOS syscalls. Process address space already fits in the lower 4GB (user code at 0x400000, stack at 0x800000). **AArch64 32-bit x86 PE requires full binary translation — that is part of the larger "x86-on-ARM" problem, not addressed here.**

**Installer UX — "download .exe, it works."** The user experience is: download a Windows installer (.exe or .msi), double-click it, it installs and runs. The installer executes inside the sandbox like any other PE binary. All side effects are captured:
- File creation → ObjectStore objects (virtual filesystem)
- Registry writes → virtual registry (CambiObject-backed KV store)
- COM registration → virtual registry entries under HKCR
- Service registration → sandboxed background tasks
- Shortcut creation → sandbox manifest metadata

The sandbox fakes the environment the installer expects:
- UAC elevation prompts → auto-approve within sandbox (sandbox "admin" has no real privilege)
- Windows version queries → report Windows 10 22H2 (or configurable)
- Reboot requests → restart the sandbox process
- .NET Framework / VC++ redistributable checks → satisfied by the shim library

MSI support requires a minimal Windows Installer engine (MSI is a transactional relational database, not a simple archive). Prior art: Wine's `msi.dll`, GNOME's `msitools`. This is mapped territory but non-trivial — it is Phase 0 work because most enterprise apps ship as MSI.

**DLL loading strategy — curated base + AI extensions.** Ship a curated set of shim DLLs for core Win32 surface (`ntdll`, `kernel32`, `user32`, `gdi32`, `advapi32`, `ole32`, `shell32`, `comctl32`, `comdlg32`). Less common DLLs are generated on-demand by the AI translator, validated, cached, and shared.

---

## Open Questions

1. **Graphics rendering** — DirectX translation is a massive effort. Do we translate DirectX → Vulkan (like DXVK does for Wine), build a native DirectX-subset renderer, or translate at a higher level (scene graph intent rather than draw call fidelity)? For CAD apps, the AI could potentially understand "render this 3D model with these materials" without translating every draw call. Decision deferred to Phase 2 design.

2. **Threading model** — Windows threading (fibers, APCs, thread-local storage, apartment threading for COM) has subtle differences from a straightforward POSIX-like model. How much do we need to faithfully replicate vs. translate at a higher level?

3. **AI model requirements** — what size/capability of model is needed for effective JIT translation? Can a small, specialized model handle Tier 1 (single API calls) while a larger model handles Tier 2 (behavioral patterns)? What are the latency requirements — a 100ms JIT shim generation is fine for a first call, but runtime behavioral translation needs to be faster.

4. **Shared shim distribution** — how do CambiOS instances share validated translation shims? The SSB bridge is the natural transport, but we need a discovery mechanism (how does an instance find shims for QuickBooks?) and a trust model (whose shims do you trust?).

5. **x86-on-AArch64** — running x86 PE binaries on AArch64 hardware requires binary translation (Apple Rosetta-style). This is a separate, large effort. Initial compatibility layer targets x86_64 native only.

---

## Non-Goals

- **Running Windows drivers.** Drivers require kernel-level access that the sandbox cannot provide. Hardware support comes from native CambiOS drivers.
- **Running Windows services.** Background services that expect SCM (Service Control Manager) integration are out of scope for Phase 1.
- **DRM/anti-cheat compatibility.** Kernel-level DRM and anti-cheat systems (Denuvo kernel mode, Vanguard, EAC) require ring 0 access. These will not work and we will not try to make them work.
- **Pixel-perfect UI rendering.** The goal is functional equivalence, not visual identity with Windows. A "Save As" dialog should work correctly; it doesn't need to look exactly like the Windows 11 version.

---

## Implementation Sequencing

This is preliminary. The actual implementation plan will be developed as the prerequisites (virtio-net, UDP stack) are completed and the compatibility layer moves from design to implementation.

### Phase 0 — PE Loader + Installer + Minimal Shims
- PE/COFF parser for both PE32 and PE32+ (analogous to existing `loader/elf.rs`)
- Section mapper (reuse existing page table infrastructure)
- 32-bit compat-mode GDT entries + heaven's gate thunk in shim library
- Import table resolution against curated shim set
- Shim DLLs: `ntdll` (heap, TLS, structured exception handling), `kernel32` (file I/O, memory, threading basics, version queries)
- Sandboxed Principal creation and binding
- Virtual registry (HKCU/HKLM/HKCR, CambiObject-backed KV store)
- Virtual filesystem (drive letter mapping, path translation, `C:\Windows\System32\` → shim library)
- MSI engine (minimal: component/feature tables, file extraction, registry actions, custom action execution)
- NSIS/Inno Setup support (these are PE executables — they run naturally once the shim layer works)
- Environment faking: Windows version reporting, UAC auto-approve, reboot simulation
- **Validation target 0a:** a simple 32-bit Win32 console application runs and exits cleanly
- **Validation target 0b:** an NSIS-packaged application installs and launches in the sandbox

### Phase 1 — Business Application Support
- Expand shim coverage: `user32` (windowing, messages), `gdi32` (2D rendering), `advapi32` (registry, security tokens), `ole32` (basic COM), `shell32` (file dialogs, shell integration), `comctl32`/`comdlg32` (common controls/dialogs)
- Printing pipeline (translate Win32 GDI printing to CambiOS print service)
- .NET Framework hosting (CoreCLR or Mono, in-sandbox) — many business apps are .NET WinForms
- AI translator service (Tier 0 + Tier 1 — static + JIT shims)
- **Validation target:** QuickBooks Desktop installs from its .exe installer, opens a company file, generates a report, prints it

### Phase 2 — CAD Application Support
- Full COM runtime (class factory, apartment threading, marshaling, structured storage)
- DirectX/OpenGL rendering translation (approach TBD — see open questions)
- OLE/ActiveX container (in-place activation, drag-and-drop)
- COM interop for .NET mixed-mode assemblies
- AI translator Tier 2 (behavioral pattern recognition for COM call chains)
- **Validation target:** SolidWorks installs, opens a part file, renders it, allows basic editing

### Phase 3 — Ecosystem + Instrumentation
- Shared shim distribution via SSB bridge
- USB device passthrough for instrumentation software
- AI translator Tier 3 (interactive mediation)
- x86-on-AArch64 binary translation (if AArch64 is a target platform for compat layer)
- **Validation target:** LabVIEW communicates with a connected NI DAQ device
