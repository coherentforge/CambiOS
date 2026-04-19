# ADR-017 Catalog: Phase 1 Win32 Surface — Tier Assignments

- **Status:** Proposed
- **Date:** 2026-04-13
- **Renumbered:** 2026-04-19 — was ADR-010; see [ADR-016](016-win-compat-api-ai-boundary.md) renumber note.
- **Companion to:** [ADR-016](016-win-compat-api-ai-boundary.md) — classification rules and decision procedure
- **Applies to:** Phase 1 target applications (QuickBooks Desktop, Sage 50, Lacerte, Drake) per [win-compat.md](../win-compat.md) § Phase 1

## Purpose

ADR-016 defines the rules. This document applies them. Each Win32 function in the Phase 1 surface is classified using the five-axis decision procedure (determinism, statefulness, frequency, risk surface, argument complexity) and assigned a tier. Scaffolding of `user/win-compat/` uses this catalog as the source of truth for per-function tier tags in the shim dispatch table.

When a new Win32 function enters the Phase 1 surface (because a target application calls it and we didn't anticipate it), add it here using the decision procedure. The ADR itself needs revision only if the rules change.

## Classification Shorthand

Tier values from ADR-016 § Decision Procedure:

- **T0** — Static shim. Hand-coded in `user/win-compat/src/shims/<dll>.rs`. Deterministic, fixed or bounded arguments, risk ≠ High.
- **T1** — JIT plan. Translator produces plan on first call, cached per ADR-016 § Caching and Promotion.
- **T2** — Behavioral pattern. Part of a named multi-call sequence; translation happens once per pattern, not per call.
- **T3** — Interactive fallback. Not a default assignment; reached only when T1/T2 translation fails validation.
- **R** — Router. Argument-sensitive; see the per-function sub-routing for which sub-handler fires.

Where a function is a router, its sub-handlers are listed inline with their sub-tier assignments.

## kernel32.dll

Core process, memory, file I/O, threading. Most of the hot path lives here.

| Function | Tier | Notes |
|----------|------|-------|
| `CreateFileW` | **R** | Router. See sub-table below. |
| `ReadFile` | T0 | IPC to FS service. Hot. Determinism=High, Args=Fixed, Risk=Medium. |
| `WriteFile` | T0 | IPC to FS service. Hot. Same shape as ReadFile. |
| `CloseHandle` | T0 | Handle-table free. Determinism=High, Args=Fixed, Risk=Low. |
| `GetLastError` | T0 | TLS read. Hot. Trivial. |
| `SetLastError` | T0 | TLS write. Hot. Trivial. |
| `VirtualAlloc` | T0 | `SYS_ALLOCATE`. Args=Bounded (protection flags enumerable). Risk=Medium. |
| `VirtualFree` | T0 | `SYS_FREE`. Determinism=High. |
| `HeapCreate` | T0 | Allocator construction in sandbox heap. Cold. |
| `HeapAlloc` | T0 | Heap allocation. Hot. Statefulness=Handle-scoped. |
| `HeapFree` | T0 | Heap free. Hot. |
| `HeapDestroy` | T0 | Heap teardown. Cold. |
| `CreateThread` | T1 | Thread model not yet finalized in CambiOS sandboxes. See Open Question in ADR-016. |
| `ExitThread` | T1 | Depends on CreateThread semantics. |
| `WaitForSingleObject` | T1 | Multiple object kinds (thread, mutex, event); argument-shape inspection needed. |
| `GetModuleHandleW` | T0 | Lookup in sandbox's loaded-module table. |
| `GetProcAddress` | T0 | Lookup in shim dispatch table. |
| `LoadLibraryW` | T1 | First call may trigger AI-generated shims for uncommon DLLs. |
| `FreeLibrary` | T0 | Refcount decrement. |
| `GetSystemTimeAsFileTime` | T0 | `SYS_GET_TIME` + Win32 epoch conversion. |
| `QueryPerformanceCounter` | T0 | `SYS_GET_TIME` + scaling. Hot. |
| `QueryPerformanceFrequency` | T0 | Constant from timer calibration. |
| `GetTickCount` | T0 | `SYS_GET_TIME` ms. Hot. |
| `GetVersionExW` | T0 | Returns configured fake Windows version. |
| `GetSystemInfo` | T0 | Returns fixed Win32 SYSTEM_INFO struct. |
| `FindFirstFileW` | T0 | VFS query, allocates find-handle. |
| `FindNextFileW` | T0 | Find-handle iteration. |
| `FindClose` | T0 | Find-handle free. |
| `GetFileAttributesW` | T0 | VFS resolve + attribute translation. |
| `GetFileSize` | T0 | VFS metadata read. |
| `SetFilePointer` | T0 | Handle-scoped seek. |
| `GetCommandLineW` | T0 | Returns sandbox-configured command line. |
| `GetCurrentProcessId` | T0 | `SYS_GET_PID`. |
| `GetCurrentThreadId` | T0 | TLS read. |
| `ExitProcess` | T0 | `SYS_EXIT`. Tier 0 but always audited. |
| `Sleep` | T0 | Scheduler delay via `SYS_YIELD` + deadline. |
| `EnterCriticalSection` | T0 | User-space spinlock in sandbox heap. |
| `LeaveCriticalSection` | T0 | Same. |
| `InitializeCriticalSection` | T0 | Constructor. |
| `DeleteCriticalSection` | T0 | Destructor. |
| `GetEnvironmentVariableW` | T0 | Sandbox-scoped env var read. |
| `SetEnvironmentVariableW` | T0 | Sandbox-scoped env var write. |
| `DeviceIoControl` | **R** | Router. See sub-table below. |

### `CreateFileW` sub-routing

| Flag combination | Tier | Handler |
|------------------|------|---------|
| `OPEN_EXISTING` + `FILE_ATTRIBUTE_NORMAL` + GENERIC_READ/WRITE | T0 | Direct FS-service IPC. |
| `CREATE_NEW` / `CREATE_ALWAYS` + `FILE_ATTRIBUTE_NORMAL` | T0 | FS-service create + IPC. |
| `FILE_FLAG_OVERLAPPED` (async I/O) | T3 | Async I/O not yet supported in CambiOS. Prompts user. |
| `FILE_FLAG_NO_BUFFERING` / `FILE_FLAG_WRITE_THROUGH` | T1 | Plan-based; semantics depend on FS service's caching model. |
| `FILE_ATTRIBUTE_DEVICE` / device paths (`\\.\`) | T3 | Device access via compat layer not supported; user consent. |
| `FILE_FLAG_OPEN_REPARSE_POINT` | T1 | Junctions/symlinks; VFS handles but needs plan. |

### `DeviceIoControl` sub-routing

| IOCTL class | Tier | Handler |
|-------------|------|---------|
| `FSCTL_GET_VOLUME_INFORMATION`, common volume queries | T0 | Hard-coded responses matching fake volume state. |
| `IOCTL_DISK_*`, storage control codes | T3 | Direct device access not permitted. |
| `IOCTL_SERIAL_*`, serial port codes | T3 | Defer to Phase 3 instrumentation support. |
| Vendor-specific / unknown IOCTLs | T3 | User consent required. |

## ntdll.dll

Low-level runtime, heap, TLS, structured exception handling.

| Function | Tier | Notes |
|----------|------|-------|
| `RtlAllocateHeap` | T0 | Heap allocation. Mirrors HeapAlloc. Hot. |
| `RtlFreeHeap` | T0 | Heap free. Hot. |
| `RtlReAllocateHeap` | T0 | Heap realloc. |
| `RtlCreateHeap` | T0 | Heap construction. |
| `RtlDestroyHeap` | T0 | Heap destruction. |
| `RtlSizeHeap` | T0 | Heap size query. |
| `RtlInitUnicodeString` | T0 | Pure memory setup. |
| `RtlInitAnsiString` | T0 | Pure memory setup. |
| `RtlUnicodeStringToAnsiString` | T0 | UTF-16 → ANSI conversion. |
| `RtlAnsiStringToUnicodeString` | T0 | ANSI → UTF-16 conversion. |
| `NtQueryInformationProcess` | **R** | Information class varies widely; most classes T0, some T1. |
| `NtQuerySystemInformation` | T1 | Many info classes; per-class plans cached. |
| `RtlAddVectoredExceptionHandler` | T2 | SEH is a sandbox-scoped pattern; part of exception-handling dispatch. |
| `RtlRemoveVectoredExceptionHandler` | T2 | SEH teardown. |
| `NtSetInformationThread` | T1 | TLS, affinity, priority classes. |
| `RtlAcquirePebLock` | T0 | Per-sandbox PEB lock. |
| `RtlReleasePebLock` | T0 | Same. |
| `NtClose` | T0 | Generic handle close, routes by handle kind. |
| `NtCreateFile` | **R** | Router. Lower-level than CreateFileW; used by .NET and some C runtimes. |
| `NtReadFile` | T0 | Lower-level ReadFile; same FS-service mapping. |
| `NtWriteFile` | T0 | Lower-level WriteFile. |
| `NtQueryAttributesFile` | T0 | VFS metadata read. |
| `RtlGetVersion` | T0 | Same as GetVersionExW. |

## user32.dll

Windowing, message pump, dialogs. Phase 1 coverage is minimal — business apps use standard controls.

| Function | Tier | Notes |
|----------|------|-------|
| `CreateWindowExW` | T2 | Windowing pattern; coordinated with subsequent message-pump calls. |
| `DestroyWindow` | T0 | Window teardown; handle-free. |
| `ShowWindow` | T0 | Visibility state change via UI service IPC. |
| `UpdateWindow` | T0 | Invalidation signal. |
| `GetMessageW` | T0 | Hot. Message queue read. Summary-only audit. |
| `TranslateMessage` | T0 | Pure transformation. |
| `DispatchMessageW` | T0 | Message dispatch via registered window proc. |
| `DefWindowProcW` | T0 | Default window proc; handles standard messages. |
| `PostQuitMessage` | T0 | Sets quit flag in sandbox's message loop. |
| `RegisterClassExW` | T0 | Window class registration in sandbox table. |
| `UnregisterClassW` | T0 | Window class teardown. |
| `SendMessageW` | T0 | Synchronous message delivery within sandbox. |
| `PostMessageW` | T0 | Asynchronous message post. |
| `MessageBoxW` | T0 | Modal dialog via UI service; bounded set of button/icon combinations. |
| `LoadStringW` | T0 | PE resource read. |
| `LoadIconW` | T0 | PE resource read. |
| `LoadCursorW` | T0 | PE resource read. |
| `SetWindowTextW` | T0 | Window title update. |
| `GetWindowTextW` | T0 | Window title read. |

## gdi32.dll

2D rendering, device contexts, fonts. Phase 1 needs basic text/drawing.

| Function | Tier | Notes |
|----------|------|-------|
| `CreateDCW` | T1 | DC for printer, display, memory — mode-dependent. |
| `CreateCompatibleDC` | T0 | Memory DC; bounded. |
| `DeleteDC` | T0 | DC free. |
| `CreateCompatibleBitmap` | T0 | Bitmap allocation. |
| `SelectObject` | T0 | DC state update. |
| `DeleteObject` | T0 | GDI object free. |
| `TextOutW` | T1 | Font rendering via UI service; plan caches common font configurations. |
| `ExtTextOutW` | T1 | Extended text out; similar. |
| `BitBlt` | T0 | Pixel transfer; mode-limited set. |
| `StretchBlt` | T1 | Scaling variant; uses UI service. |
| `CreateSolidBrush` | T0 | Constant-color brush. |
| `CreateFontIndirectW` | T1 | Font lookup; plan per font-family. |
| `GetDeviceCaps` | T0 | Fixed DC capability table. |

## advapi32.dll

Registry, security tokens, cryptography stubs.

| Function | Tier | Notes |
|----------|------|-------|
| `RegOpenKeyExW` | T0 | Virtual registry open. |
| `RegQueryValueExW` | T0 | Virtual registry read. Warm. |
| `RegSetValueExW` | T0 | Virtual registry write. |
| `RegCreateKeyExW` | **R** | Router — some flag combinations (security descriptors) go T1. |
| `RegCloseKey` | T0 | Registry handle free. |
| `RegEnumKeyExW` | T0 | Registry iteration. |
| `RegEnumValueW` | T0 | Registry iteration. |
| `RegDeleteKeyW` | T0 | Registry delete. |
| `RegDeleteValueW` | T0 | Registry value delete. |
| `OpenProcessToken` | T1 | Security token API; sandbox-scoped. |
| `GetTokenInformation` | T1 | Token info classes; per-class plans. |
| `LookupAccountSidW` | T1 | SID lookup; sandbox returns parent Principal for user SIDs. |
| `CryptAcquireContextW` | T1 | Crypto API; delegates to CambiOS crypto services. |
| `CryptCreateHash` | T1 | Hash context creation. |
| `CryptHashData` | T0 | Hash update (Blake3/SHA-256). |
| `CryptDestroyHash` | T0 | Hash context free. |

## ole32.dll

COM runtime. Phase 1 needs light COM for some apps (QuickBooks uses it sparingly).

| Function | Tier | Notes |
|----------|------|-------|
| `CoInitializeEx` | T0 | Apartment model init. |
| `CoUninitialize` | T0 | Apartment teardown. |
| `CoCreateInstance` | T2 | Part of `CoCreateInstance → QueryInterface → method` behavioral pattern. |
| `CoTaskMemAlloc` | T0 | Task memory allocation. |
| `CoTaskMemFree` | T0 | Task memory free. |
| `CoRegisterClassObject` | T2 | Class factory registration pattern. |
| `CoGetClassObject` | T2 | Class factory lookup. |

## shell32.dll

File dialogs, shell integration.

| Function | Tier | Notes |
|----------|------|-------|
| `SHGetFolderPathW` | T0 | Fixed mapping of known folder CSIDLs to VFS paths. |
| `SHGetKnownFolderPath` | T0 | Same with KNOWNFOLDERID enum. |
| `SHBrowseForFolderW` | T1 | UI service dialog; plan varies by BIF flags. |
| `SHGetPathFromIDListW` | T1 | PIDL resolution. |
| `ShellExecuteW` | T1 | Verb dispatch; sandbox-scoped. |

## comctl32.dll

Common controls (list view, tree view, status bar).

| Function | Tier | Notes |
|----------|------|-------|
| `InitCommonControlsEx` | T0 | Initialization call; sandbox state update. |
| `ImageList_Create` | T0 | Image list allocation. |
| `ImageList_Add` | T0 | Image list append. |
| `ImageList_Destroy` | T0 | Image list free. |

## Behavioral Patterns (Tier 2)

Multi-call patterns translated as sequences, not as individual functions.

| Pattern name | Participating functions | Pattern description |
|--------------|-------------------------|---------------------|
| COM instantiation | `CoCreateInstance`, `QueryInterface`, first method call | Create object, get interface, dispatch. Translator recognizes common CLSID + IID combinations and collapses the sequence to a direct CambiOS service call. |
| Windowing bootstrap | `RegisterClassExW`, `CreateWindowExW`, `ShowWindow`, `UpdateWindow` | Standard window creation sequence. Mapped to UI service window creation. |
| File open dialog | `GetOpenFileNameW` (plus callbacks, subclassing) | Common-dialog file selection. Mapped to UI service file picker. |
| Printing pipeline | `StartDoc`, `StartPage`, GDI calls, `EndPage`, `EndDoc` | Print job construction. Mapped to print service job submission. |
| SEH dispatch | `RtlAddVectoredExceptionHandler`, exception trigger, `RtlRemoveVectoredExceptionHandler` | Sandbox-scoped exception handling. Requires kernel SEH support (Open Question in ADR-016). |
| Drag-and-drop | `DoDragDrop`, `IDropSource` / `IDropTarget` vtable calls | OLE drag-and-drop protocol. Deferred to Phase 2 (CAD apps use this heavily). |

## Summary

- Total Phase 1 functions classified: 99
- Tier 0 (static): 71
- Tier 1 (JIT plan): 19
- Tier 2 (behavioral patterns): 6 patterns covering ~12 function roles
- Tier 3 (interactive fallback): 0 by default; reached via router sub-handlers (`FILE_FLAG_OVERLAPPED`, device IOCTLs, etc.)
- Routers: 4 (`CreateFileW`, `DeviceIoControl`, `NtCreateFile`, `RegCreateKeyExW`)

This catalog is the authoritative per-function classification. When the Phase 0 scaffolding lands in `user/win-compat/src/shims/`, each shim entry in the dispatch table is tagged with its tier from this catalog. Tier 1 entries carry no implementation (the translator produces them at first call); Tier 0 entries carry a hand-written handler.
