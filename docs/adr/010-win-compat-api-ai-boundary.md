# ADR-010: Windows Compatibility — The API/AI Boundary

- **Status:** Proposed
- **Date:** 2026-04-13
- **Depends on:** [ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities), [ADR-003](003-content-addressed-storage-and-identity.md) (Content-Addressed Storage), [ADR-007](007-capability-revocation-and-telemetry.md) (Audit Telemetry), [ADR-009](009-purpose-tiers-scope.md) (Deployment Tiers)
- **Related:** [win-compat.md](../../win-compat.md), [docs/adr/010-win-compat-phase1-catalog.md](010-win-compat-phase1-catalog.md) (sibling catalog)
- **Supersedes:** N/A

## Context

[win-compat.md](../../win-compat.md) describes a four-tier translation model for the Windows compatibility layer — Tier 0 static shims, Tier 1 JIT shims, Tier 2 behavioral pattern translation, Tier 3 interactive fallback. It names the tiers but does not define the decision rules that assign a given Win32 API call to a given tier, and it does not specify the mechanics of the boundary between them.

Without those rules, any attempt to scaffold the `user/win-compat/` crate produces code that bakes in tier assignments by implication — the very act of putting `CreateFileW` under `shims/kernel32.rs` implicitly classifies it as Tier 0, whether or not that classification is correct. If the classification is later revisited, every shim file gets rewritten. Worse, the contract between the static shim layer and the AI translator service — who validates what, who signs what, what the audit trail looks like — gets invented ad hoc at implementation time rather than designed deliberately.

This ADR draws the boundary. Its job is to make the Tier 0 / Tier 1 cut line explicit, to define the validation pipeline that AI-generated shims must pass before installation, to specify the caching and promotion model, and to fix the audit schema. After this lands, the Phase 0 scaffolding of `user/win-compat/` has concrete targets and the AI translator service (endpoint 25, future) has a contract to implement against.

## Problem

The Tier 0/1/2/3 model in win-compat.md answers *what* the tiers do but not *how* assignment works. Five ambiguities have to be resolved before any code is written.

**What granularity carries the tier assignment?** A tier could be assigned per-DLL (all of `ntdll.dll` is Tier 0), per-function (`CreateFileW` is Tier 0, `NtCreateFile` is Tier 1), or per-call-pattern (`CreateFileW` with ordinary flags is Tier 0, `CreateFileW` with `FILE_FLAG_OVERLAPPED` goes to Tier 1 until the translator generates a shim for that pattern). Each choice has different dispatch-table implications. Per-DLL is too coarse to be useful. Per-function is the natural default. Per-call-pattern is needed for a small number of Win32 APIs whose behavior diverges sharply by flag. The ADR has to specify which combination is used.

**What criteria drive the assignment?** "Feels static" is not a criterion. The ADR has to name the observable properties that push a function into one tier or another — otherwise the classification is arbitrary and cannot be extended to Win32 functions we haven't yet surveyed.

**What does the AI translator actually produce, and how is it trusted?** A Tier 1 call produces a shim. Is that shim code (x86 instructions the translator emits and caches), data (a serialized interpretation plan the dispatcher executes), or an IPC request the translator handles itself every time? Each has very different trust and verification implications. If the translator emits code, every shim is new code entering the system and must be verified. If the translator produces an interpretation plan, the dispatcher is the thing executing user-space code and the translator is a data source. This choice shapes the validation pipeline and the sandbox escape surface.

**When and how does a Tier 1 shim become "warm"?** win-compat.md says shims are cached after first call. It does not say whether the cache is per-sandbox, per-user, or system-wide; it does not say how cache invalidation works when the translator model is updated; it does not say whether cached shims survive reboot; it does not say what happens when two sandboxes want the same shim. Each of these is a real decision with security and performance implications.

**What does the audit trail look like?** ADR-007 gives us the audit infrastructure. win-compat.md says Windows calls should be audited. Neither specifies the event schema, the sampling strategy (every call vs. summary statistics), or what an operator should be able to answer from the audit record. Without this, the observability story for Windows compat is undefined — and Windows compat has more operational risk than any other subsystem, so the audit story has to be tight.

These ambiguities compose. A decision on granularity (per-function) narrows the shape of the dispatch table, which shapes what "a shim" is, which shapes what the translator produces, which shapes the validation pipeline, which shapes the audit schema. Resolving them in sequence produces an inconsistent architecture. Resolving them together is this ADR's job.

## Decision Summary

- **Tier assignment granularity is per-function by default, with per-call-pattern dispatchers for a small enumerated set of argument-sensitive APIs.** The dispatch table is keyed by `(dll_name, function_name)`. Most entries resolve to a single handler. Argument-sensitive entries resolve to a router that inspects arguments and dispatches to sub-handlers, each of which may be at a different tier.

- **Assignment criteria are five observable properties: determinism, statefulness, frequency, risk surface, and argument complexity.** A function's tier is the outcome of applying a decision procedure to these five properties. The procedure is deterministic and extensible — a new Win32 function can be classified by a contributor without requiring a judgment call from the maintainers.

- **AI-generated shims are interpretation plans (data), not emitted code.** The translator produces a bounded-shape plan — a sequence of primitive operations over IPC endpoints, VFS handles, and registry keys — that the dispatcher executes. This makes the validation pipeline tractable: we check plans, not arbitrary code. It eliminates the "new code entering the system" problem. It is slower than emitted code in the worst case, but the dominant cost of a Win32 call is the IPC round-trip, not the plan interpretation overhead.

- **Cached shims are content-addressed CambiObjects, system-wide, signed by the AI translator's Principal, revalidated on model updates.** The cache lives in the ObjectStore (ADR-003 gives us the machinery). Caching is system-wide because identical (function, argument-shape) inputs should produce identical plans regardless of which sandbox first triggered the translation. Cross-sandbox sharing is safe because the plan is not arbitrary code and because the interpretation happens per-sandbox under per-sandbox capabilities.

- **Audit events carry tier, DLL/function identity, sandbox ID, and outcome, with per-sandbox summary statistics emitted on a rate-limited schedule.** Per-call audit is available but disabled by default — the overhead is unacceptable for hot-path functions called tens of thousands of times per second. Summary statistics satisfy the common operator questions.

The remainder of the ADR develops these five decisions in detail.

## Classification Criteria

Five observable properties determine a Win32 function's tier. Each is scored on a three-level scale. The scores combine deterministically into a tier assignment.

### Determinism

Does the Win32 function's semantics map onto CambiOS primitives in a way that can be specified once and re-used?

- **High:** 1:1 semantic mapping to a CambiOS syscall or a fixed IPC request. `GetTickCount` → `SYS_GET_TIME`. `VirtualAlloc` → `SYS_ALLOCATE`. `CloseHandle` → handle-table lookup + resource release. No interpretation needed.
- **Medium:** Mapping is well-defined but has multiple variants by argument. `CreateFileW` with ordinary flags maps to an FS-service IPC; with `FILE_FLAG_OVERLAPPED` or `FILE_ATTRIBUTE_DEVICE`, the mapping diverges. Requires argument inspection, but each variant has a known mapping.
- **Low:** Mapping depends on application context, COM class hierarchy, or interpretation of intent. `CoCreateInstance` for a novel CLSID cannot be mapped without understanding what the class is expected to do.

### Statefulness

Does the function operate on state that persists beyond the call?

- **Stateless:** Pure function, no sandbox state touched. `GetTickCount`, `GetCurrentProcessId`.
- **Handle-scoped:** Operates on state referenced by an argument handle (file, mutex, registry key). State lives in the sandbox's handle table, bounded per-handle.
- **Sandbox-scoped:** Affects state spanning multiple handles — heap, TLS, process environment, registry hive. Changes here can invalidate assumptions in unrelated calls.

### Frequency

Is the function on the hot path?

- **Hot:** Called many times per second in running applications. `ReadFile`, `WriteFile`, `GetMessage`, `DispatchMessage`, `GetLastError`.
- **Warm:** Called occasionally during steady-state operation. `RegQueryValueEx`, `CreateFile`, `CoCreateInstance`.
- **Cold:** Called once or a few times per process lifetime. `LoadLibrary` at startup, `GetVersionEx`, shutdown sequences.

### Risk Surface

What happens if the shim has a bug?

- **Low:** Wrong return value in a non-critical path. App displays a wrong timestamp, wrong window title, wrong file count in a listing.
- **Medium:** Functional failure. App crashes cleanly, data is not written, dialog fails to open. User notices. Sandbox is not compromised.
- **High:** Sandbox isolation failure. Memory corruption in shared buffers, unintended capability use, registry writes that leak across sandboxes, cross-sandbox object store writes.

### Argument Complexity

How much variety do we see in how the function is called?

- **Fixed:** Arguments have a single meaningful shape. `CloseHandle(HANDLE)` — one argument, one interpretation.
- **Bounded:** Arguments vary across a small, enumerable set. `CreateFileW` with ~8 practically-occurring flag combinations.
- **Unbounded:** Arguments are effectively arbitrary. `DeviceIoControl` with arbitrary IOCTL codes. `CoCreateInstance` with arbitrary CLSIDs. `IDispatch::Invoke` with arbitrary dispatch IDs.

### Decision Procedure

Given a function's five scores, assign tier:

- **Tier 0 (static shim):** Determinism = High AND Argument complexity = Fixed or Bounded AND Risk surface ≠ High. Frequency is not a gating criterion — a cold Tier 0 shim is fine, but a Tier 0 function must be specifiable once. Most of kernel32 and ntdll's core surface lands here.
- **Tier 1 (JIT shim):** Determinism = High or Medium AND Argument complexity = Bounded or Unbounded AND (function is Warm or Cold in frequency). The translator generates a plan on first call, caches it. First-call latency is amortized over the life of the sandbox.
- **Tier 2 (behavioral):** Determinism = Low AND Statefulness = Sandbox-scoped, OR the function participates in a named multi-call pattern (COM QueryInterface chains, OLE in-place activation, dialog handshakes). Recognized as a sequence, translated once, executed with cached context.
- **Tier 3 (interactive fallback):** Any function where classification criteria do not produce a usable assignment, or where a Tier 1/2 translation fails validation. The sandboxed process is paused, the user is consulted, the outcome is recorded.

**Per-call-pattern escape hatch.** A small enumerated set of functions — tracked in a `ROUTER_FUNCTIONS` constant list alongside the shim dispatch table — resolve to a router that inspects arguments and dispatches to a tier-appropriate sub-handler. `CreateFileW` with `FILE_ATTRIBUTE_NORMAL` is Tier 0; `CreateFileW` with `FILE_FLAG_OVERLAPPED` (async I/O, not currently supported in CambiOS) dispatches to a Tier 3 handler that asks the user. This mechanism exists so that a function with mostly-easy semantics isn't forced to the highest tier its worst argument combination requires.

**High-risk functions are never Tier 0.** If a function's risk surface is High (sandbox isolation implications), it cannot be a static shim — the validation pipeline must apply to every call. This means every call goes through at least Tier 1's plan validator, even if the plan is cached and identical each time. The overhead is acceptable because high-risk functions are not on the hot path.

## Phase 1 Catalog

The full per-function tier assignment for the ~80 Win32 functions covering Phase 1 (business applications: QuickBooks, Sage 50, tax prep) is in the sibling document [docs/adr/010-win-compat-phase1-catalog.md](010-win-compat-phase1-catalog.md). Summary:

- **Tier 0 (static):** ~52 functions. The bulk of kernel32 (file I/O, memory, time, process ID), ntdll (heap, TLS basics), advapi32 (core registry operations), user32 (message pump primitives).
- **Tier 1 (JIT):** ~18 functions. Rare ntdll internals, uncommon advapi32 (security tokens, crypto API stubs), GDI DC/font variants, shell32 folder path resolution.
- **Tier 2 (behavioral):** ~8 named multi-call patterns. COM `CoCreateInstance` → `QueryInterface` → method dispatch. OLE drag-and-drop protocol. Common dialog handshakes (`GetOpenFileName` + subclassing). Printing pipeline (`StartDoc` → `StartPage` → GDI calls → `EndPage` → `EndDoc`).
- **Tier 3 (interactive):** Fallback only, no functions assigned by default. Reached when a Tier 1 plan fails validation or a novel argument combination appears.
- **Routers:** 4 functions flagged as argument-sensitive: `CreateFileW`, `DeviceIoControl`, `NtCreateFile`, `RegCreateKeyExW`.

The catalog is the authoritative per-function classification. This ADR is the rules; the catalog is the rules applied to today's target surface. Adding a Win32 function to the scaffolding requires classifying it using the Decision Procedure and updating the catalog. The ADR itself does not need revision unless the rules change.

## AI-Generated Shims Are Plans, Not Code

When the translator produces a Tier 1 shim, the output is a **plan** — a bounded-shape data structure describing a sequence of primitive operations over a restricted instruction set. The dispatcher executes the plan; the translator never contributes executable code to the sandboxed process or the compatibility service.

The primitive instruction set is intentionally small:

- `IPC_SEND(endpoint, capability, bytes)` — send an IPC message. Endpoint must be in the sandbox's grant list. Capability must be one the sandbox holds.
- `IPC_RECV(endpoint) -> bytes` — receive a response. Blocks with a bounded timeout.
- `HANDLE_ALLOC(kind) -> handle` / `HANDLE_FREE(handle)` — allocate/free a slot in the sandbox's Win32 handle table.
- `HANDLE_GET(handle) -> resource_ref` — dereference a Win32 handle to a CambiOS resource (file object, mutex, registry key).
- `REG_READ(key, value_name) -> bytes` / `REG_WRITE(key, value_name, bytes)` — virtual registry operations.
- `VFS_RESOLVE(winpath) -> object_hash` / `VFS_QUERY(tag, filter) -> hash_list` — virtual filesystem operations.
- `MEM_COPY(src, dst, len)` — bounded memcpy in the sandbox's address space. Bounds checked against the sandbox's VMA tracker.
- `RETURN(value)` — plan exit with a return value mapped to the Win32 calling convention.
- `ERROR(code)` — plan exit with a Win32 error code; `GetLastError` sees this.

A plan is a directed acyclic graph of these primitives with bounded depth and bounded fan-out. The translator can conditional on argument values but cannot loop unboundedly. Plans are serialized as a compact binary format and stored in the ObjectStore.

**Why plans, not code.** Three reasons.

First, validation is tractable. We can statically check a plan — does every `IPC_SEND` target an endpoint in the sandbox's grant list? Does every `HANDLE_GET` reference a handle previously allocated in this plan? Is plan depth below the bound? Does the plan terminate? These are decidable questions over a small grammar. The equivalent checks on emitted x86 machine code are undecidable or require verified abstract interpretation.

Second, no new code enters the system. The dispatcher that executes plans is a fixed piece of code, written by humans, reviewed, eventually formally verified. The translator is a data source. This makes the trust story much simpler: if the translator is compromised, it can produce wrong plans (which will fail validation or produce wrong application behavior) but it cannot inject executable code.

Third, plans are portable. A plan produced on an x86_64 CambiOS instance is executable on an AArch64 CambiOS instance without re-translation. This matters for the SSB-shared-shim model in win-compat.md: one translation serves the whole network.

**Cost.** Plan interpretation has higher per-call overhead than emitted machine code — estimated 5-10× for the interpreter dispatch loop. This is swamped by the dominant cost of a Win32 call under the compatibility layer: the IPC round-trip to the FS service, the AI translator, or any other user-space service. For functions that would benefit from code emission (hot Tier 0 functions), hand-coded static shims in `user/win-compat/src/shims/` already bypass the interpreter. The plan machinery is for Tier 1+ only.

## Validation Pipeline

Every plan, whether newly produced by the translator or pulled from the ObjectStore cache, passes through the validation pipeline before the dispatcher executes it. Validation is the same in both cases — cached plans are revalidated — so that a model update or a policy change automatically re-checks existing plans.

The pipeline runs five checks in sequence. A failure at any step rejects the plan; the call falls through to Tier 3 (interactive consent).

1. **Grammar check.** The plan parses as a well-formed plan structure. Primitive opcodes are in the allowed set. Depth is below the per-plan bound. No unbounded iteration. Rejection cause: malformed translator output.

2. **Capability bound check.** Every `IPC_SEND` targets an endpoint in the sandbox's grant list. Every capability referenced is one the sandbox currently holds. This is checked statically against the `SandboxPolicy`. A plan that tries to reach the key-store service (endpoint 17) from a sandbox that hasn't been granted key-store access is rejected here, not at runtime.

3. **Memory bound check.** Every `MEM_COPY` source and destination is within the sandbox's VMA tracker. Plans cannot reach outside the sandbox's address space, into the compatibility service's memory, or into another sandbox.

4. **Resource bound check.** Plan execution is bounded — a plan cannot allocate more than N handles, more than M bytes of heap, or consume more than T units of CPU time during execution. Bounds are per-plan, set by the translator at generation time based on the expected Win32 function's behavior, and enforced by the dispatcher at runtime.

5. **Signature check.** For plans pulled from the cache, the stored signature verifies against the translator's Principal. An unsigned or incorrectly signed plan is treated as absent; the translator is invoked to re-generate.

Plans that pass validation are installed in the dispatch table. Plans that fail are logged to the audit stream with the rejection reason (grammar/capability/memory/resource/signature) so operators can distinguish translator bugs from policy changes from tampering.

## Caching and Promotion

**Storage.** Validated plans are stored in the ObjectStore as CambiObjects. The object's content is the serialized plan. The author is the AI translator's Principal. The owner is the CambiOS system (not any individual user), making plans discoverable across sandboxes. The cache key is a Blake3 hash over `(dll_name, function_name, argument_signature)`, where `argument_signature` is a canonical fingerprint of the argument shape (types and flag values that route execution, excluding data values like file contents or string contents). This is content addressing applied to shims.

**Hit path.** A PE call arrives. The dispatcher computes the cache key, queries the ObjectStore, retrieves the plan, runs it through validation, and executes it if valid. If the ObjectStore does not have the plan or validation fails, the translator is invoked.

**Promotion to warm.** A plan that has been executed N times without revalidation failure can be promoted to a warm cache held in the compatibility service's memory — no ObjectStore round-trip per call. Promotion is a TUNING decision (cache size vs. memory pressure); the initial rule is "promote after 10 successful executions, cap warm cache at 256 plans per sandbox." Adjust with measurements.

**Invalidation on model update.** When the AI translator's model is updated (new weights, new safety rules), the translator emits an invalidation event that drops the warm cache and marks the ObjectStore plans as "revalidate on next use." Old plans are not deleted — they remain available and will revalidate successfully if the new model still considers them valid. Plans that fail revalidation are evicted.

**Cross-sandbox sharing is safe.** A plan generated while translating a call from Sandbox A is usable verbatim by Sandbox B, because (a) the plan does not embed Sandbox A's identity, handles, or memory addresses — those are filled in at dispatch time from Sandbox B's context; (b) the validation pipeline runs per-sandbox using Sandbox B's policy, so a plan that's valid for A but not for B is correctly rejected when B tries to use it.

**Cross-instance sharing via SSB.** Plans signed by a trusted translator Principal can be fetched from the Yggdrasil mesh over the SSB bridge (future work). Trust is per-Principal: a CambiOS operator chooses whose translations to trust by accepting that Principal's key. Validation still runs locally before any plan executes — the remote translator's signature authenticates provenance, not correctness.

## Audit and Observability

Windows compatibility is the subsystem with the largest operational risk surface in CambiOS — arbitrary third-party code, large API surface, AI in the translation loop. The audit story has to be correspondingly tight.

**Schema.** A new audit event kind lands in `src/audit/mod.rs`:

```
AuditEventKind::WinShimCall {
    sandbox_id: u32,          // per-sandbox Principal identifier
    dll_ix: u8,               // index into a fixed DLL enum (8 DLLs initially)
    function_ix: u16,         // index into per-DLL function table
    tier: u8,                 // 0=Static, 1=JIT-cached, 2=JIT-first-call, 3=Behavioral, 4=Interactive
    outcome: u8,              // 0=OK, 1=Win32 error return, 2=plan rejected, 3=user denied
    duration_us: u16,         // wall-clock time in the shim
}
```

Fits in the 64-byte RawAuditEvent wire format from ADR-007 (Phase 3.3). DLL and function indices rather than names because audit events have a fixed size; name strings live in a static table the audit consumer resolves.

**Sampling.** Per-call audit of hot-path Tier 0 shims (`ReadFile`, `WriteFile`, `GetMessage`) would saturate the audit ring. Default behavior:

- **Tier 0:** Summary-only. Per-sandbox, per-function counters emitted every 5 seconds. Per-call events available via a debug flag in the sandbox policy.
- **Tier 1, cached:** Per-call audit with sampling at 1-in-100 (adjustable).
- **Tier 1, first-call / Tier 2:** Every call audited. These are inherently rare.
- **Tier 3 (interactive):** Every call audited. These surface to the user, so there are very few per session.
- **Rejections:** Every rejected plan audited regardless of tier. A plan rejection is always interesting.

**Questions the audit trail answers.** After a Windows app session, an operator can answer: What fraction of calls ran as static shims vs. through the translator? Which functions are Tier 1 hot-spots (good candidates for promotion to Tier 0 static shims)? Did any call fall through to Tier 3 (user consent)? Were there validation rejections, and if so, which ones and with what reason codes? What did the sandbox try to do that the policy denied?

These questions shape the audit consumer UI (future work — a win-compat dashboard backed by the audit ring). The ADR commits only to the schema.

## Call Flow: PE Dispatch to Shim Execution

Putting the pieces together, a Win32 call from a sandboxed PE process reaches its executing shim via this path:

1. PE process in ring 3 invokes a shim DLL's stub function. The stub packages the arguments into a wire format.
2. Stub sends an IPC message to the win-compat service endpoint (the sandbox's private endpoint — see the endpoint-sizing ADR for why sandboxes get private endpoints).
3. win-compat service receives, decodes the `(dll_ix, function_ix, args)` tuple.
4. Dispatch table lookup by `(dll_ix, function_ix)`.
   - **Static entry:** Hand-coded shim function invoked directly. Returns to the dispatcher, which packages the result and IPC-replies to the PE process. Audit summary counter incremented.
   - **Router entry:** Router inspects args, picks a sub-handler, which may be static (as above) or one of the plan-based tiers below.
   - **Tier 1+ entry:** Dispatcher computes the plan cache key from `(dll_name, function_name, argument_signature)`. Warm cache checked first; then ObjectStore. On miss, translator is invoked over IPC (endpoint 25, future), which produces a plan.
5. Plan passes through the validation pipeline. On rejection, path branches to Tier 3 (user consent via the UI service — future).
6. Plan is promoted to warm cache if it's been used enough times.
7. Dispatcher interprets the plan. Each primitive operation executes against the sandbox's capability context — IPC sends go out on the sandbox's behalf, handles allocate in the sandbox's table, memory operations bounds-check against the sandbox's VMA tracker.
8. Plan returns or errors. Dispatcher packages the Win32-style return value and IPC-replies to the PE process.
9. Audit event emitted (per sampling rules).
10. PE process's shim DLL stub receives the response, unpacks it, returns to the caller.

The PE process cannot tell which tier served its call — from its perspective, every Win32 function is "the kernel32.dll stub I linked against." This is a correctness feature: migration of a function from Tier 1 back to Tier 0 (or forward to Tier 2) is invisible to the application.

## Decision Drivers

**Why not pure static (no AI)?** Tier 0-only is Wine's architecture. Wine has been under active development for 30 years and still has incomplete coverage of the Win32 surface. CambiOS does not have 30 years. The AI translator shortens the tail — uncommon APIs get usable-if-not-perfect translations at the cost of some latency on first call — without requiring a human implementer for every function.

**Why not pure AI (no static shims)?** Routing hot-path functions through an AI-generated plan imposes unnecessary latency and cache pressure. `GetTickCount` called 10,000 times per second does not need a plan interpreter. Static shims for the well-understood, well-bounded core of Win32 are faster, simpler, and easier to audit.

**Why not emitted code instead of plans?** Emitted code is faster per-call (~5-10×) but much harder to validate. The validation pipeline is the load-bearing security boundary for the AI component — "the translator is untrusted, but its output is constrained to a verifiable shape" is the whole premise. Giving up plan-level validation in exchange for faster interpretation would require verified code generation in the translator, which is far more than the project wants to own.

**Why is the plan grammar so small?** The grammar is the attack surface. A larger instruction set (arithmetic, loops, conditionals on computed values) gives the translator more expressive power at the cost of a harder validation job. The initial grammar covers what Phase 1 business apps need and can grow by ADR supersession when Phase 2 CAD apps require something we cannot express.

## Rejected Alternatives

**Per-DLL tier assignment.** Rejected — too coarse. ntdll contains both `RtlAllocateHeap` (clearly Tier 0) and `RtlAddVectoredExceptionHandler` (clearly Tier 2 because SEH is a sandbox-scoped pattern). Forcing them to the same tier makes one of them wrong.

**Tier assignment by risk only.** Rejected — would push every function with any risk surface to Tier 1+, including easy wins like `VirtualAlloc`. The risk gating is "High risk cannot be Tier 0," not "any risk pushes to Tier 1." Most low-risk functions are Tier 0 because other criteria (determinism, argument shape) allow it.

**Emitted machine code for Tier 1 shims.** Rejected — validation is intractable. See Decision Drivers.

**Per-sandbox plan cache with no sharing.** Rejected — means every sandbox re-translates every function on first use, wasting translator capacity. Sandbox isolation is preserved by running plans in the calling sandbox's capability context, not by re-translating the same plan N times.

**Tier 3 interactive fallback as default for unclassified functions.** Rejected as default behavior — too much user friction. Unclassified functions go to the translator first; the user is consulted only when translation fails validation or when a plan requests a capability the sandbox hasn't been granted.

**AI translator runs inside win-compat service.** Rejected — different resource profile (model weights, inference compute) and different trust boundary. The translator is its own service at endpoint 25, with its own Principal. win-compat is a thin dispatcher.

## Open Questions

- **Phase 2 grammar expansion.** COM `QueryInterface` chains with type-dependent method dispatch may require adding bounded polymorphism to the plan grammar. Deferred to a Phase 2 ADR that can be written with concrete examples in hand.
- **DirectX/OpenGL translation.** Is the compat layer the right home for graphics translation, or does it belong in a separate "graphics translator" service that win-compat calls out to? Deferred.
- **.NET hosting.** .NET runtime runs inside the sandbox, not as a service — that much is clear. How the runtime's JIT is sandboxed (its own plan grammar? emitted code with W^X enforcement?) is a Phase 1 question; may need a separate ADR.
- **Translator model architecture.** ADR-009 defers "specific model architecture for the AI translator" to a future ADR. This ADR specifies the contract the translator implements (input: function + args, output: plan) without committing to a model.
- **Plan size and complexity bounds.** Initial bounds picked conservatively (N=16 primitives, bounded depth=4). Will be revised after Phase 1 catalog implementation reveals realistic distributions.

## Relationship to Other ADRs

- **[ADR-000](000-zta-and-cap.md) (Zero-Trust + Capabilities).** Plan execution is the sandbox's capability use. Validation pipeline enforces that plans only reference capabilities the sandbox holds. The API/AI boundary is an instance of zero-trust applied to AI-generated content.
- **[ADR-003](003-content-addressed-storage-and-identity.md) (Content-Addressed Storage).** Plans are CambiObjects. The ObjectStore is the plan cache. Content addressing makes cross-sandbox sharing correct.
- **[ADR-004](004-cryptographic-integrity.md) (Cryptographic Integrity).** Plans are signed by the translator's Principal. Signature verification is part of the validation pipeline.
- **[ADR-007](007-capability-revocation-and-telemetry.md) (Audit Telemetry).** Audit events for Win32 calls use the ADR-007 infrastructure. The new `WinShimCall` event kind fits the 64-byte RawAuditEvent format.
- **[ADR-009](009-purpose-tiers-scope.md) (Deployment Tiers).** Windows compat runs at Tiers 2 and 3. On Tier 2 (no AI), only Tier 0 static shims are available; Tier 1/2/3 routing returns an error. On Tier 3, all four tiers are active. This ADR's tier-0-only fallback is the mechanism by which ADR-009's "graceful degradation" commitment applies to Windows compat.
- **Future endpoint-sizing ADR.** Private endpoints per sandboxed PE process are a prerequisite for the per-sandbox capability context that validation depends on. That ADR lands alongside this one.

## Cross-References

- [win-compat.md](../../win-compat.md) — Updated to reference this ADR as the authoritative source for tier classification rules, plan grammar, validation pipeline, and audit schema. Sections that described these in prose are shortened to a one-line reference.
- [docs/adr/010-win-compat-phase1-catalog.md](010-win-compat-phase1-catalog.md) — Sibling document containing the per-function tier assignments for the Phase 1 Win32 surface. Applies this ADR's rules to today's target.
- [STATUS.md](../../STATUS.md) — Windows compatibility remains "Planned (post-v1)." This ADR is a design landing, not an implementation landing.
- [CLAUDE.md](../../CLAUDE.md) — Required Reading table gets a new row when the scaffolding lands: "Windows compatibility / PE loader / shim layer" pointing to this ADR and its catalog.

## See Also

- Phase 0 scaffolding of `user/win-compat/` is the first consumer of this ADR. The scaffolding cites this ADR in every shim file's module doc comment, tags every shim entry with its assigned tier, and implements the plan interpreter / validation pipeline as specified here.
- The AI translator service (endpoint 25) is the other consumer. Its specification is "produces plans conforming to this ADR's grammar, signed by its Principal, content-addressed by `(dll, function, argument_signature)` fingerprint." Translator implementation is a separate work stream.
