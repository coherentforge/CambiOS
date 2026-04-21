# ADR-016: Windows Compatibility via Bounded Static Shims

- **Status:** Proposed
- **Date:** 2026-04-21
- **Rewritten:** This ADR replaces an earlier decision (2026-04-13) that centered the Win32 compatibility layer on an AI translator producing validated interpretation plans. The AI translation layer has been removed from the compat layer. The ADR-016 slot is reused rather than superseded because the prior direction was withdrawn whole before any code landed — appending a `## Divergence` would have left this ADR as a tangle of stale rationale plus current decision. The prior content is in git history if ever needed.
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-003](003-content-addressed-storage-and-identity.md) (Content-Addressed Storage), [ADR-007](007-capability-revocation-and-telemetry.md) (Audit Telemetry), [ADR-009](009-purpose-tiers-scope.md) (Deployment Tiers)
- **Related:** [win-compat.md](../win-compat.md)
- **Supersedes:** N/A

## Context

Windows compatibility in CambiOS runs as a user-space service (endpoint 24) that loads PE/COFF binaries, maps their imports to handler functions, and mediates access to the rest of the system through IPC. This ADR answers *what* the handlers are, *how* they are implemented, and *what scope* the compatibility layer commits to support.

An earlier version of this ADR answered those questions with an AI translation layer: an out-of-process translator service produced validated interpretation plans for Win32 functions that lacked a static handler, plans were cached as CambiObjects, and the dispatcher executed them under the sandbox's capabilities. That direction has been withdrawn. Three reasons, in descending weight:

1. **Verification story.** AI-generated plans — even validated at the grammar + capability-bound level — cannot be formally verified in the sense the project has committed to. The validation pipeline catches structural violations, but the *semantics* of a plan produced by a learned model remain probabilistic. A microkernel whose stated non-negotiable is future formal verification cannot put AI-generated semantics on the critical path of a user-facing subsystem.
2. **Generative, not extractive.** A defined, bounded compat surface tells users what works; an AI-translated surface asks users to trust that what worked yesterday will work tomorrow. The first is a product commitment; the second is a promise that decays with every model update.
3. **Scope honesty.** The AI pipeline carried work the project is not ready to own — model weights, inference infrastructure, signature-of-translator trust, per-model revalidation, plan-grammar evolution. Each of those was a project in itself, defended from scope pressure by the premise that "the AI makes hard things easy." It doesn't; it makes hard things unverifiable.

What remains is the Wine-style approach, narrowed by CambiOS's constraints: a defined set of Win32 functions with hand-written handlers in Rust, a router mechanism for argument-sensitive functions, and an explicit "not supported" outcome for everything outside the set.

## Decision

**The Windows compatibility layer supports a bounded, enumerated set of Win32 functions. Everything outside the set returns a well-defined error at call time, and applications whose import tables reference unsupported functions either fail to launch cleanly (with a machine-readable list of what's missing) or load with stubbed imports that return `ERROR_CALL_NOT_IMPLEMENTED` when called.**

Four pieces give this its shape.

### 1. Scope is a published list, not an inferred surface

The [Phase 1 Catalog](#phase-1-catalog) below enumerates every Win32 function the compat layer supports. An application importing a function not in the catalog either:

- **Stubs the import with a well-defined error handler** (default). The app loads; the missing function returns `ERROR_CALL_NOT_IMPLEMENTED` when invoked. Many Windows apps probe for optional features this way, so refusing to load would be overly strict.
- **Refuses to load** when the sandbox manifest sets `strict_imports = true`. The refusal carries the list of missing functions so the user knows up front that the app cannot run.

New Win32 functions enter the catalog by the [Adding Functions](#adding-functions) process, not by inference at runtime.

### 2. Handlers are hand-coded Rust, one file per DLL

Every supported function has a handler in `user/win-compat/src/shims/<dll>.rs`. The handler signature is fixed: it takes the sandbox context plus the Win32 call arguments (unmarshaled from the IPC wire format), returns a `Result<Win32Return, Win32Error>`, and executes under the sandbox's capabilities.

Handlers do not share state with each other except through explicitly-managed sandbox structures (the sandbox handle table, the virtual registry, the virtual filesystem). There is no shared "shim runtime" executing plans or interpretations.

### 3. Argument-sensitive functions dispatch through routers

A small set of Win32 functions have enough semantic variation by argument that one handler would be unwieldy. For these, the dispatch table resolves to a *router* — a hand-coded function that inspects arguments and calls one of several sub-handlers, each fully specified. The router mechanism preserves the "everything is hand-coded Rust" property. Each router publishes the enumerated set of argument combinations it supports and the error code for everything else.

### 4. Unsupported behavior is specified, not silent

When a call routes to a stubbed import, an unsupported router branch, or a handler that hits an unsupported feature (e.g., `CreateFileW` with `FILE_FLAG_OVERLAPPED` — async I/O, which CambiOS does not yet support), the call returns a specific Win32 error code documented in the catalog. The compat layer never fakes success, never silently mutates behavior, and never leaves the user to guess whether a call worked.

The audit trail (§ [Audit](#audit)) records every unsupported-call event with enough detail for an operator to answer: *which function did the app try to call, what was it passed, and why did we refuse*. This is the feedback loop that drives catalog growth.

## Scoping Criteria for New Functions

A Win32 function enters the catalog when a target application needs it and it meets all of these:

- **Determinism.** The Win32 specification (MSDN) and observed real-world behavior give an unambiguous mapping to CambiOS primitives. Functions whose behavior depends on interpretation of intent (`CoCreateInstance` for a novel CLSID, `DeviceIoControl` for a vendor-specific IOCTL) are not candidates — they are left as routers with explicit "not supported" branches for unknown cases.
- **Statefulness is bounded.** The function touches state scoped to a handle, the sandbox, or process-global structures (heap, TLS) whose shape is known. Functions that reach into cross-sandbox shared state or kernel-equivalent structures are not candidates.
- **Risk surface is characterized.** A bug in the handler has a documented worst case: wrong return value, functional failure, or sandbox-isolation failure. Functions whose worst case cannot be bounded at design time do not enter the catalog; they stay stubbed.
- **Argument shape is enumerable.** Either arguments have a single meaningful shape (fixed), or they vary across a small enumerable set that a router can dispatch (bounded). Functions with effectively arbitrary argument shapes (`IDispatch::Invoke` with arbitrary dispatch IDs, `DeviceIoControl` across all IOCTLs) are not candidates — they remain stubbed, and apps that need them are Phase 2+ considerations.

These four criteria gate *inclusion*, not tiering — every supported function is a static handler.

## Dispatch Flow

A Win32 call from a sandboxed PE process reaches its handler via this path:

1. PE process invokes the shim DLL stub linked into its address space. The stub packages the call's arguments into a wire format.
2. Stub sends an IPC message to the win-compat service on the sandbox's private endpoint (see [ADR-009](009-purpose-tiers-scope.md) tier-policy endpoint pool).
3. win-compat decodes `(dll_ix, function_ix, args)` and looks up the dispatch table.
   - **Function present, single handler:** handler invoked directly. Returns a Win32 result; dispatcher packages it and IPC-replies to the PE.
   - **Function present, router:** router inspects arguments, calls the matching sub-handler, handles "no match" by returning the unsupported-branch error.
   - **Function absent:** stubbed import handler returns `ERROR_CALL_NOT_IMPLEMENTED`.
4. Audit event emitted per the schema in § [Audit](#audit).
5. PE stub receives the reply, returns to the caller.

The PE process cannot distinguish between "real handler" and "stubbed unsupported import" except by the return value. This is deliberate — a supported function and an unsupported function have the same call interface; only the outcome differs.

## Audit

Every Win32 call emits an audit event using the infrastructure from [ADR-007](007-capability-revocation-and-telemetry.md). The event schema:

```
AuditEventKind::WinShimCall {
    sandbox_id:   u32,   // per-sandbox Principal identifier
    dll_ix:       u8,    // index into a fixed DLL table
    function_ix:  u16,   // index into per-DLL function table
    outcome:      u8,    // 0=OK, 1=Win32 error return, 2=unsupported import, 3=router-no-match
    duration_us:  u16,   // wall-clock time in the shim
}
```

Fits the 64-byte `RawAuditEvent` wire format. DLL and function names live in a static table the audit consumer resolves — names don't travel in the event.

Per-call audit for hot-path handlers (`ReadFile`, `WriteFile`, `GetMessage`, `GetLastError`) would saturate the audit ring. Default sampling:

- **Normal handlers:** summary-only. Per-sandbox, per-function counters emitted every 5 seconds. Per-call events available via a debug flag in the sandbox manifest.
- **Unsupported calls, router-no-match, error returns:** every event audited. These drive catalog growth; we want every one.

## Adding Functions

A new function enters the catalog by a short, explicit process:

1. Observe the gap. An audit event with `outcome = unsupported` or `router-no-match` identifies a function the target app calls.
2. Apply the [Scoping Criteria](#scoping-criteria-for-new-functions). If all four are met, the function is a candidate. If not, the function stays stubbed and the app is a scope boundary — either the app is out of scope or the criteria need revision (a scope decision, not a classification one).
3. Write the handler in `user/win-compat/src/shims/<dll>.rs`. Test against observed real-world Win32 behavior.
4. Add the entry to the Phase 1 catalog (this ADR) with a one-line note on mapping and risk.

The ADR itself does not change unless the scoping criteria change. The catalog grows.

## Phase 1 Catalog

Phase 1 target applications: business accounting software with bounded Win32 surfaces — QuickBooks Desktop, Sage 50, tax preparation (Lacerte, Drake). The catalog below is the authoritative list of supported functions for Phase 1.

**Support states:**

- **✓** — supported, single handler
- **R** — router with enumerable sub-cases (sub-table follows)
- **·** — stubbed (not in catalog; returns `ERROR_CALL_NOT_IMPLEMENTED`). Not listed below — by definition this is everything else.

### kernel32.dll

| Function | State | Mapping |
|----------|-------|---------|
| `CreateFileW` | R | See sub-routing below |
| `ReadFile` | ✓ | IPC to FS service |
| `WriteFile` | ✓ | IPC to FS service |
| `CloseHandle` | ✓ | Handle-table free |
| `GetLastError` | ✓ | TLS read |
| `SetLastError` | ✓ | TLS write |
| `VirtualAlloc` | ✓ | `SYS_ALLOCATE` + protection-flag mapping |
| `VirtualFree` | ✓ | `SYS_FREE` |
| `HeapCreate` / `HeapAlloc` / `HeapFree` / `HeapDestroy` | ✓ | Sandbox heap allocator |
| `CreateThread` / `ExitThread` / `WaitForSingleObject` | ✓ | Maps to CambiOS threads once that subsystem lands; stubbed until then |
| `GetModuleHandleW` | ✓ | Lookup in sandbox's loaded-module table |
| `GetProcAddress` | ✓ | Lookup in shim dispatch table |
| `LoadLibraryW` | ✓ | Returns handle for DLLs in the curated shim set; `NULL` + `ERROR_MOD_NOT_FOUND` otherwise |
| `FreeLibrary` | ✓ | Refcount decrement |
| `GetSystemTimeAsFileTime` | ✓ | `SYS_GET_TIME` + Win32 epoch conversion |
| `QueryPerformanceCounter` / `QueryPerformanceFrequency` | ✓ | `SYS_GET_TIME` + scaling |
| `GetTickCount` | ✓ | `SYS_GET_TIME` ms |
| `GetVersionExW` | ✓ | Returns sandbox-configured fake Windows version (default: 10.0.19045) |
| `GetSystemInfo` | ✓ | Fixed Win32 `SYSTEM_INFO` |
| `FindFirstFileW` / `FindNextFileW` / `FindClose` | ✓ | VFS query + find-handle management |
| `GetFileAttributesW` / `GetFileSize` | ✓ | VFS metadata read |
| `SetFilePointer` | ✓ | Handle-scoped seek |
| `GetCommandLineW` | ✓ | Sandbox-configured command line |
| `GetCurrentProcessId` / `GetCurrentThreadId` | ✓ | `SYS_GET_PID` / TLS read |
| `ExitProcess` | ✓ | `SYS_EXIT`. Always audited per-call |
| `Sleep` | ✓ | `SYS_YIELD` + deadline |
| `EnterCriticalSection` / `LeaveCriticalSection` / `InitializeCriticalSection` / `DeleteCriticalSection` | ✓ | User-space spinlock in sandbox heap |
| `GetEnvironmentVariableW` / `SetEnvironmentVariableW` | ✓ | Sandbox-scoped env |
| `DeviceIoControl` | R | See sub-routing below |

#### `CreateFileW` sub-routing

| Flag combination | State | Handler |
|------------------|-------|---------|
| `OPEN_EXISTING` + `FILE_ATTRIBUTE_NORMAL` + GENERIC_READ/WRITE | ✓ | Direct FS-service IPC |
| `CREATE_NEW` / `CREATE_ALWAYS` + `FILE_ATTRIBUTE_NORMAL` | ✓ | FS-service create + IPC |
| `FILE_FLAG_OVERLAPPED` (async I/O) | × | `ERROR_NOT_SUPPORTED`. CambiOS does not have async I/O yet |
| `FILE_FLAG_NO_BUFFERING` / `FILE_FLAG_WRITE_THROUGH` | ✓ | Mapped to FS-service sync hints |
| `FILE_ATTRIBUTE_DEVICE` / device paths (`\\.\`) | × | `ERROR_ACCESS_DENIED`. No direct device access from sandbox |
| `FILE_FLAG_OPEN_REPARSE_POINT` | ✓ | VFS symlink/junction read, bounded by VFS grant |

#### `DeviceIoControl` sub-routing

| IOCTL class | State | Handler |
|-------------|-------|---------|
| `FSCTL_GET_VOLUME_INFORMATION`, common volume queries | ✓ | Hard-coded responses matching the fake volume state |
| `IOCTL_DISK_*` | × | `ERROR_ACCESS_DENIED`. Direct disk access not permitted |
| `IOCTL_SERIAL_*` | × | `ERROR_NOT_SUPPORTED`. Deferred to Phase 3 instrumentation |
| Vendor-specific / unknown IOCTLs | × | `ERROR_NOT_SUPPORTED`. Audit-logged for catalog growth |

### ntdll.dll

| Function | State | Mapping |
|----------|-------|---------|
| `RtlAllocateHeap` / `RtlFreeHeap` / `RtlReAllocateHeap` | ✓ | Mirrors `HeapAlloc`/`HeapFree`/`HeapReAlloc` |
| `RtlCreateHeap` / `RtlDestroyHeap` / `RtlSizeHeap` | ✓ | Heap-table ops |
| `RtlInitUnicodeString` / `RtlInitAnsiString` | ✓ | Pure memory setup |
| `RtlUnicodeStringToAnsiString` / `RtlAnsiStringToUnicodeString` | ✓ | UTF-16 ↔ ANSI conversion |
| `NtQueryInformationProcess` | R | Information class varies; common classes supported (see sub-table) |
| `NtQuerySystemInformation` | R | Per-class routing; common classes supported, unknown → `STATUS_NOT_IMPLEMENTED` |
| `RtlAddVectoredExceptionHandler` / `RtlRemoveVectoredExceptionHandler` | × | `STATUS_NOT_IMPLEMENTED`. SEH support is a Phase 2 decision (kernel SEH mechanism required) |
| `NtSetInformationThread` | R | Priority and affinity classes supported; TLS alternate-base and scheduler-class stubbed |
| `RtlAcquirePebLock` / `RtlReleasePebLock` | ✓ | Per-sandbox PEB lock |
| `NtClose` | ✓ | Generic handle close; routes by kind |
| `NtCreateFile` | R | Lower-level CreateFile; used by .NET and some C runtimes |
| `NtReadFile` / `NtWriteFile` | ✓ | Lower-level Read/Write; same FS-service mapping |
| `NtQueryAttributesFile` | ✓ | VFS metadata read |
| `RtlGetVersion` | ✓ | Same as `GetVersionExW` |

### user32.dll

| Function | State | Mapping |
|----------|-------|---------|
| `CreateWindowExW` | ✓ | Window-table entry; UI service IPC for surface allocation |
| `DestroyWindow` | ✓ | Window teardown; handle-free |
| `ShowWindow` / `UpdateWindow` | ✓ | Visibility / invalidation via UI service IPC |
| `GetMessageW` | ✓ | Hot. Message queue read. Summary-only audit |
| `TranslateMessage` | ✓ | Pure transformation |
| `DispatchMessageW` | ✓ | Invoke registered window proc |
| `DefWindowProcW` | ✓ | Default window proc; handles standard messages |
| `PostQuitMessage` | ✓ | Sets quit flag in sandbox's message loop |
| `RegisterClassExW` / `UnregisterClassW` | ✓ | Window class registration / teardown |
| `SendMessageW` / `PostMessageW` | ✓ | Message delivery within sandbox |
| `MessageBoxW` | ✓ | Modal dialog via UI service; bounded set of button/icon combinations |
| `LoadStringW` / `LoadIconW` / `LoadCursorW` | ✓ | PE resource read |
| `SetWindowTextW` / `GetWindowTextW` | ✓ | Window title |

### gdi32.dll

| Function | State | Mapping |
|----------|-------|---------|
| `CreateDCW` | R | Printer / display / memory DCs have different backends |
| `CreateCompatibleDC` | ✓ | Memory DC |
| `DeleteDC` | ✓ | DC free |
| `CreateCompatibleBitmap` | ✓ | Bitmap allocation |
| `SelectObject` | ✓ | DC state update |
| `DeleteObject` | ✓ | GDI object free |
| `TextOutW` / `ExtTextOutW` | ✓ | Font rendering via UI service. Common font configurations supported; exotic configs fall back to bitmap-font substitution |
| `BitBlt` | ✓ | Pixel transfer |
| `StretchBlt` | ✓ | Scaling variant via UI service |
| `CreateSolidBrush` | ✓ | Constant-color brush |
| `CreateFontIndirectW` | ✓ | Font lookup; substitution table for missing fonts |
| `GetDeviceCaps` | ✓ | Fixed DC capability table |

### advapi32.dll

| Function | State | Mapping |
|----------|-------|---------|
| `RegOpenKeyExW` / `RegCloseKey` | ✓ | Virtual registry |
| `RegQueryValueExW` | ✓ | Virtual registry read |
| `RegSetValueExW` | ✓ | Virtual registry write |
| `RegCreateKeyExW` | R | Most flag combinations supported; security-descriptor variants route to a sub-handler that ignores the SD (sandbox has its own model) |
| `RegEnumKeyExW` / `RegEnumValueW` | ✓ | Registry iteration |
| `RegDeleteKeyW` / `RegDeleteValueW` | ✓ | Registry delete |
| `OpenProcessToken` | ✓ | Returns a synthetic token referencing the sandbox Principal |
| `GetTokenInformation` | R | `TokenUser`, `TokenGroups`, `TokenElevation` supported; obscure classes error |
| `LookupAccountSidW` | ✓ | Sandbox-SID-to-Principal mapping |
| `CryptAcquireContextW` / `CryptCreateHash` / `CryptHashData` / `CryptDestroyHash` | ✓ | Delegates to CambiOS crypto (Blake3 / SHA-2) |

### ole32.dll

Phase 1 target applications use COM lightly. The support here covers the minimum — CLSIDs beyond the enumerated set return `REGDB_E_CLASSNOTREG`, which Phase 1 apps handle gracefully (they have non-COM fallbacks).

| Function | State | Mapping |
|----------|-------|---------|
| `CoInitializeEx` / `CoUninitialize` | ✓ | Apartment-model init / teardown |
| `CoCreateInstance` | R | Enumerated CLSIDs (Phase 1 app-specific: `CLSID_ShellLink`, `CLSID_FileOpenDialog`, a short list) supported; others return `REGDB_E_CLASSNOTREG` |
| `CoTaskMemAlloc` / `CoTaskMemFree` | ✓ | Task memory allocation |
| `CoRegisterClassObject` / `CoGetClassObject` | ✓ | Class factory registration/lookup; same CLSID set as `CoCreateInstance` |

### shell32.dll

| Function | State | Mapping |
|----------|-------|---------|
| `SHGetFolderPathW` / `SHGetKnownFolderPath` | ✓ | Known-folder CSIDL/KNOWNFOLDERID → VFS path mapping |
| `SHBrowseForFolderW` | ✓ | UI service folder dialog; BIF flags mapped or ignored |
| `SHGetPathFromIDListW` | ✓ | PIDL resolution |
| `ShellExecuteW` | R | `open` / `edit` / `print` verbs on files supported; URLs supported via net-service IPC (when granted); `runas` and other privileged verbs error |

### comctl32.dll

| Function | State | Mapping |
|----------|-------|---------|
| `InitCommonControlsEx` | ✓ | Sandbox state update |
| `ImageList_Create` / `ImageList_Add` / `ImageList_Destroy` | ✓ | Image list allocation / append / free |

### Catalog summary

- Supported: ~85 functions with direct handlers
- Routers: 8 (`CreateFileW`, `DeviceIoControl`, `CreateDCW`, `NtQueryInformationProcess`, `NtQuerySystemInformation`, `NtCreateFile`, `NtSetInformationThread`, `RegCreateKeyExW`, `GetTokenInformation`, `CoCreateInstance`, `ShellExecuteW`)
- Stubbed at Phase 1: SEH (`RtlAddVectoredExceptionHandler` etc.), async I/O (`FILE_FLAG_OVERLAPPED`), direct device I/O (`IOCTL_DISK_*`, `IOCTL_SERIAL_*`), most ole32 beyond the enumerated CLSIDs

This surface covers the observed Win32 call patterns of the Phase 1 target apps. Phase 2 (CAD) and Phase 3 (instrumentation) will require substantial additions; those catalogs are future ADRs.

## Relationship to Other ADRs

- **[ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities).** Handler execution runs under the sandbox's capabilities. Every IPC call a handler makes on the sandbox's behalf passes through the standard capability check.
- **[ADR-003](003-content-addressed-storage-and-identity.md) (Content-Addressed Storage).** File access from a sandboxed PE flows through the VFS layer to the ObjectStore; the sandboxed Principal is the author, the parent user is the owner.
- **[ADR-007](007-capability-revocation-and-telemetry.md) (Audit Telemetry).** The `WinShimCall` audit event kind lands in the existing 64-byte `RawAuditEvent` format.
- **[ADR-009](009-purpose-tiers-scope.md) (Deployment Tiers).** Windows compatibility is available on Tiers 2 and 3; the hardware floor for running Phase 1 apps is the Tier 2 target. The removal of the AI translator means compat is no longer gated by on-device model capacity.

## Non-Goals

- **Full Win32 coverage.** By design, this layer does not aim to implement all of Win32. It aims to implement a defined, tested subset well.
- **Behavioral pattern recognition across call sequences.** Without the AI translator, there is no machinery for recognizing a `CoCreateInstance → QueryInterface → method` sequence as a translatable pattern. Each call is a handler; sequences emerge from app behavior, not from translation.
- **Running Windows drivers, services, DRM, or anti-cheat.** Kernel-mode code cannot run. See [win-compat.md](../win-compat.md) for the broader non-goals list.
- **x86-on-AArch64 binary translation.** Separate problem, separate eventual ADR.

## Deferred Decisions

- **SEH support.** Structured exception handling is pervasive in Windows apps but requires either a kernel SEH mechanism or a full user-space SEH emulator. Phase 1 stubs; decide when a target app's failure trace names `RtlAddVectoredExceptionHandler`.
  **Revisit when:** a Phase 1 target app fails with `STATUS_NOT_IMPLEMENTED` from `RtlAddVectoredExceptionHandler` in the audit trail.
- **Threading model details.** `CreateThread`/`WaitForSingleObject` map cleanly once CambiOS has a user-visible thread primitive. Until then, they stub.
  **Revisit when:** CambiOS threading lands and the `user/thread-primitives` crate is buildable.
- **UI service contract.** Several handlers IPC into the "UI service" for window surfaces, dialogs, and font rendering. The UI service contract is not yet written.
  **Revisit when:** the UI service ADR lands (it will need to predate the first target app that hits a windowing handler).
- **Phase 2 CAD scope.** The Phase 1 catalog covers business apps. CAD apps (SolidWorks, AutoCAD) require substantial additions (full COM, DirectX or OpenGL, OLE/ActiveX container, .NET interop). Without AI translation, each of these is a significant body of hand-written shim code. Whether Phase 2 is feasible at all in the bounded-static model — vs. deferred indefinitely or re-evaluated against a different translation strategy — is an open question.
  **Revisit when:** Phase 1 ships and the compat layer's maintenance cost is a known quantity.

## Cross-References

- [win-compat.md](../win-compat.md) — Design document for the broader compat layer (PE loader, sandbox policy, virtual filesystem/registry, target application phases). This ADR is the shim-layer decision within that design.
- [STATUS.md](../../STATUS.md) — Windows compatibility remains "Planned (post-v1)." This ADR is a design landing, not an implementation landing.
- [CLAUDE.md](../../CLAUDE.md) — Required Reading map gets a row when the scaffolding lands: "Windows compatibility / PE loader / shim layer" → this ADR.
