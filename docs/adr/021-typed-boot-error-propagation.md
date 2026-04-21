# ADR-021: Typed BootError Propagation Through the Init Path

- **Status:** Proposed
- **Date:** 2026-04-19
- **Depends on:** CLAUDE.md Development Convention 1 (no `panic!` / `expect` / `unwrap` in non-test kernel code; every failure must be a typed Result)
- **Related:** [ADR-019](019-process-fault-reaping-and-peer-generation.md) (which scoped runtime *kernel-mode* fault recovery out; this ADR handles the *boot-time* failure path, a different surface), [ADR-013](013-riscv64-architecture-support.md) (RISC-V boot stub and DTB-derived timer; several of the sites live in the RISC-V init chain)
- **Supersedes:** N/A

## Scope Boundary (read this first)

This ADR replaces eleven boot-path `.expect()` / `panic!()` / `Layout::expect()` / null-check-`panic` sites with a typed `BootError` enum propagated through `Result<(), BootError>` returns from init functions. It does *not* touch:

| Concern | Owner |
|---|---|
| Boot-path init failures (the eleven sites below) | **This ADR** |
| Runtime kernel-mode fault recovery (`src/arch/riscv64/trap.rs` panics, kernel page-faults in syscall handlers) | [ADR-019](019-process-fault-reaping-and-peer-generation.md) § Kernel-mode fault recovery (deferred) |
| Infallible-by-construction `unwrap()` calls (e.g., `[a..a+8].try_into::<[u8; 8]>().unwrap()` on known-length slice ranges in `src/audit/mod.rs`) | Out of scope — these are type-level infallible; removing them would require unstable `Try` machinery or extra match arms that obscure intent |
| `assert!(…)` sites in init functions (e.g., `assert!(hz > 0)` in RISC-V timer init) | Out of scope — distinct discipline; an assertion is a documented precondition, not an error-handling choice. A future ADR may unify assertion policy if drift emerges |
| User-mode fault reaping | [ADR-019](019-process-fault-reaping-and-peer-generation.md) |
| Test-module `unwrap()` / `panic!()` | Out of scope — test code is explicitly exempt per CLAUDE.md Convention 1 |
| `MemBlockDevice::new` (a host-test / synthetic helper, not in the production boot path) | Out of scope |

The rule is tight: **panics that happen during BSP or AP init before user tasks exist.** Those, and only those.

## Context

CambiOS's boot path today relies on `.expect()` and `panic!()` at eleven load-bearing init sites. If a Limine response is missing, a hardware register reports zero, the frame allocator hands out a null pointer, or the DTB omits a required property, the kernel panics with a format-string message and the panic handler halts the CPU.

This works — the CPU stops, the operator sees a message, the system is not in an undefined state. But it is not the shape Development Convention 1 asks for. The convention reads:

> **Result/Option everywhere in kernel paths.** No panics, no unwrap(), no expect() in non-test kernel code. Every failure is a typed error that propagates explicitly.

The eleven boot-path sites violate the letter of the rule. They violate the spirit less flagrantly because they are all genuinely fatal — you cannot run without an APIC, without a timer, without HHDM — but "fatal" is not the same as "un-typed." A verifier reasoning about total correctness of the boot sequence cannot see every way boot can fail by looking at the types. It has to inspect every expect string, every panic message, every Layout call.

The cost today is small because the sites are few. The cost compounds as more subsystems land their own init: the R-6 PLIC addition (2026-04-19) added one more `.expect()`; future graphics/storage/network init will each bring their own. The discipline either lives in the types or it does not.

## Problem

**Problem 1 — eleven ways to panic, zero exhaustive match.** The sites are:

| File | Line (approx) | Site | Arch |
|---|---|---|---|
| `src/boot/limine.rs` | 61 | `.expect("Limine HHDM response missing")` | x86_64 / aarch64 |
| `src/boot/limine.rs` | 67 | `.expect("Limine memory map response missing")` | x86_64 / aarch64 |
| `src/interrupts/mod.rs` | 408 | `apic::detect_and_init().expect("APIC initialization failed")` | x86_64 |
| `src/interrupts/mod.rs` | 488 | `Layout::from_size_align(...).expect("IST stack layout")` | x86_64 |
| `src/interrupts/mod.rs` | 492 | `panic!("Failed to allocate double-fault IST stack")` | x86_64 |
| `src/microkernel/main.rs` | 666 | `.expect("plic::init failed — DTB reported implausible range")` | riscv64 |
| `src/arch/x86_64/apic.rs` | 294 | `panic!("APIC timer calibration failed: bus frequency is 0")` | x86_64 |
| `src/arch/aarch64/timer.rs` | 101 | `panic!("ARM Generic Timer: CNTFRQ_EL0 is 0 (firmware bug)")` | aarch64 |
| `src/arch/aarch64/timer.rs` | 167 | `panic!("ARM timer: BSP timer not initialized before AP")` | aarch64 (AP bring-up) |
| `src/arch/riscv64/timer.rs` | 66 | `.expect("timer::init: DTB did not report /cpus/timebase-frequency...")` | riscv64 |

(Line numbers will drift after landing; the path column is stable.)

Each of these is a category: "bootloader contract violated," "hardware reports impossible value," "allocation during early boot failed," "firmware omitted mandatory DTB property." An exhaustive enum makes those categories first-class; a verifier can reason about all of them by looking at the type.

**Problem 2 — panic-formatting machinery in the init path.** Every `expect` and `panic!` pulls in `core::fmt::Display` / `Arguments` / the panic handler's format-string traversal. This is small in binary size but non-trivial in proof surface: panic handlers run with the kernel in an undefined init state, they re-enter format code, and they call into the serial driver — which may not have been initialized yet at some of the failure sites. A typed handler that names the error and halts with a compile-time-known string is smaller in every direction that matters.

**Problem 3 — the "AP-discovered BSP-init gap" is silent.** The ARM timer site at `src/arch/aarch64/timer.rs:167` fires when an AP comes up and discovers the BSP never initialized the timer — a boot-sequence invariant violation. Today it panics with a string. An exhaustive `BootError::InvariantViolation { which: BootInvariant }` makes the class of failure type-level and lets verification tools notice if a new AP-side init call forgets its invariant check.

## The Reframe

> **The boot path is a pipeline of `Result<(), BootError>`-returning init functions. `kmain` threads them with `?`. A single `boot_failed(err: BootError) -> !` handler is the only code path that halts the system on init failure. Every way boot can fail is a named enum variant.**

This is the same pattern the rest of the kernel already follows (`SyscallResult`, `FrameAllocError`, `IpcError`). ADR-021 extends it to the one surface that still pre-dates the Convention.

## Decision

### 1. A flat `BootError` enum

```rust
// src/boot/error.rs (new) — accessible via crate::boot::BootError.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    // Bootloader contract (Limine on x86_64 / aarch64, boot stub on riscv64).
    LimineHhdmMissing,
    LimineMemoryMapMissing,

    // Interrupt controller init.
    ApicInitFailed,
    ApicCalibrationFailed,   // x86_64: bus frequency = 0
    PlicInitFailed,          // riscv64: DTB PLIC range implausible

    // Early-heap allocations during interrupt setup.
    IstStackLayoutInvalid,
    IstStackAllocFailed,

    // Platform timer.
    TimerFrequencyMissing,   // aarch64 CNTFRQ_EL0 = 0, riscv64 DTB omits timebase-frequency
    TimerFrequencyTooLow,    // reload divisor would be 0
    TimerInvariantViolation, // AP came up before BSP finished timer init (sequencing bug)
}
```

Flat rather than per-subsystem-subtype because (a) eleven variants is not enough to justify the `BootError::Timer(TimerError::Missing)` indirection, (b) a verifier sees a single exhaustive match either way, (c) callers above the init layer (i.e., `kmain`) already don't care about sub-categorization — they halt on any failure.

### 2. Init functions return `Result<(), BootError>`

Every function currently `.expect`-ing during init changes signature:

```rust
// Before
pub fn init() { /* … */ apic::detect_and_init().expect("APIC init failed"); }

// After
pub fn init() -> Result<(), BootError> {
    // … 
    apic::detect_and_init().map_err(|_| BootError::ApicInitFailed)?;
    Ok(())
}
```

The top-level `kmain` (per arch) threads them:

```rust
fn kmain() -> ! {
    if let Err(err) = kmain_init() {
        boot_failed(err);
    }
    // … enter scheduler loop …
}

fn kmain_init() -> Result<(), BootError> {
    boot::populate_info()?;
    memory::init()?;
    interrupts::init()?;
    timer::init(TIMER_HZ)?;
    // … every current init call, each returning Result<(), BootError> …
    Ok(())
}
```

### 3. A single `boot_failed` handler

```rust
// src/boot/error.rs
pub fn boot_failed(err: BootError) -> ! {
    // Compile-time-known string per variant; no format machinery.
    let msg = match err {
        BootError::LimineHhdmMissing => "boot: Limine did not provide HHDM response",
        BootError::LimineMemoryMapMissing => "boot: Limine did not provide memory map",
        BootError::ApicInitFailed => "boot: APIC initialization failed",
        BootError::ApicCalibrationFailed => "boot: APIC timer calibration (bus frequency zero)",
        BootError::PlicInitFailed => "boot: PLIC init failed (DTB range implausible)",
        BootError::IstStackLayoutInvalid => "boot: IST stack layout computation failed",
        BootError::IstStackAllocFailed => "boot: IST stack allocation returned null",
        BootError::TimerFrequencyMissing => "boot: platform timer frequency unavailable",
        BootError::TimerFrequencyTooLow => "boot: platform timer base frequency too low for target HZ",
        BootError::TimerInvariantViolation => "boot: AP came up before BSP finished timer init",
    };
    crate::println!("[BOOT FAIL] {}", msg);
    crate::halt()
}
```

The match is exhaustive by construction (no default arm). Every new variant forces a message at compile time.

The `println!` call is the same one `halt()` already uses; if serial is not yet initialized at a failing site, the output is silently dropped — exactly today's behavior on pre-serial-init panics. A future refinement (early-serial fallback via MMIO poke) is out of scope here; it is a separate observability concern.

### 4. What stays `assert!` / `debug_assert!`

Preconditions that express invariants the caller owes — `assert!(hz > 0)` in timer init — stay as asserts. They are not error-handling; they are contract documentation that happens to panic on violation. Whether to convert them to `debug_assert!` or typed preconditions is a different discipline question and is explicitly out of this ADR's scope. Named here so the ADR is clear about what it is *not* changing.

## Architecture

### Where `BootError` lives

`src/boot/error.rs` (new file), re-exported from `src/boot/mod.rs` as `crate::boot::BootError`. Co-locates with the existing `boot::info()` bootloader adapter, which is the first site that produces a `BootError` (HHDM/memory-map missing).

### Error-propagation shape per subsystem

Each subsystem that has an init function owns the mapping from its internal error types to `BootError`. For example:

```rust
// interrupts/mod.rs
pub fn init() -> Result<(), BootError> {
    // …
    apic::detect_and_init().map_err(|_| BootError::ApicInitFailed)?;
    // IST stack setup:
    let layout = Layout::from_size_align(IST_STACK_SIZE, 16)
        .map_err(|_| BootError::IstStackLayoutInvalid)?;
    let ist_base = unsafe { alloc(layout) };
    if ist_base.is_null() {
        return Err(BootError::IstStackAllocFailed);
    }
    // … carry on …
    Ok(())
}
```

The subsystem's *internal* error type (e.g., `LayoutError`, `ApicInitError`) is discarded at the `map_err`; the boundary is `BootError`. Richer diagnostics (capturing the underlying Layout error, e.g.) are flagged as an Open Problem for later refinement.

### Panic handler and `boot_failed` coexistence

The existing panic handler (`#[panic_handler]`) stays — it handles runtime panics outside the init path (which should be zero but the handler is defense-in-depth). `boot_failed` is the *expected* init-failure landing; the panic handler is for the "something we didn't anticipate" case. If ADR-021 is landed correctly, the panic handler should never fire on a clean boot failure.

A diagnostic marker distinguishing "typed boot failure" from "unexpected panic" in the output is a small observability win:

```
[BOOT FAIL] boot: APIC timer calibration (bus frequency zero)
// vs.
PANIC: 'foo' at src/bar.rs:42
```

Already encoded in the `boot_failed` prefix; no separate flag needed.

## Threat Model Impact

| Threat | Today | With BootError |
|---|---|---|
| A future commit adds a twelfth init failure site without deciding how to surface it | Possible — a new `.expect` is locally plausible and passes code review | Possible but louder — a new failure either needs a new `BootError` variant (forcing the decision), or it is silently swallowed with `map_err(|_| …)`. The variant-add is the easier path; discipline wins |
| Verifier reasons about "all ways boot can fail" | Has to inspect every expect-string and panic! call | Reads the exhaustive match in `boot_failed` |
| Binary-size / proof-surface growth from format machinery in panic paths | Eleven sites pull in `core::fmt::Arguments` | One site; compile-time-known strings only |
| `boot_failed` is called from somewhere other than `kmain`'s `?`-ladder | N/A (no such function today) | Possible — nothing prevents calling `boot_failed(ApicInitFailed)` from middle of an init. Prevented by convention, caught by review. Worth a lint in the future (see Open Problems) |

Kernel TCB does not grow. One enum, one function, one mapping per init site. No new `unsafe`, no new locks, no new syscall.

## Verification Stance

- `BootError` is `#[repr(u8)]`-shaped (small enum, no payload) — layout-trivial.
- `boot_failed` is a single function with exhaustive match. No default arm. Every variant is reachable via a named variant constructor in the init code.
- Init functions gain a `Result<(), BootError>` return; `?` propagation is a bounded, statically-checkable operation.
- The refactor removes eleven `.expect` / `panic!` sites and replaces them with typed propagation. Convention 1 compliance on the boot path becomes structural, not discipline-dependent.

The verification target unlocked: a Hoare-style proof of the boot sequence of the shape "every init step either returns Ok and establishes its postcondition, or returns a specific `BootError` and `kmain` halts — no other behavior is reachable." Today's panic-on-expect breaks this shape because the panic handler is outside the typed return chain.

## Why Not Other Options

### Option A: Leave the panics alone; they're "fine for boot"

**Why considered.** Eleven sites, all genuinely fatal, all halting cleanly via the existing panic handler. The practical difference to an operator is zero.

**Why not.** Convention 1 is not a "mostly" rule. The cost of staying is compounding: every new subsystem's init adds another site. The cost of fixing is one-time and bounded.

### Option B: Structured sub-error types per subsystem

**Why considered.** Richer diagnostics (`BootError::Interrupts(InterruptError::ApicCalibration { bus_freq: 0 })`).

**Why not.** Eleven sites do not justify the indirection. `boot_failed` flattens everything to a string anyway; the `Debug` derive on the flat enum gives the same information with less type hierarchy. If a future subsystem has >5 init failure modes and meaningful differentiation, promote it to a subtype then.

### Option C: Convert asserts to typed preconditions too

**Why considered.** Full Convention 1 conformance on the boot path.

**Why not.** Different discipline. An `assert!(hz > 0)` expresses a *precondition the caller owes* — violating it is a programming bug, not a runtime error. Conflating the two surfaces makes both harder to reason about. Split ADRs for split concerns.

### Option D: Make `boot_failed` return `Infallible` / `!` but stay in-line at each site (no central handler)

**Why considered.** Avoids the "indirection" of a dedicated handler.

**Why not.** Central handler means one match, one exhaustive-variant audit point. Distributing the halt logic loses that property for no gain.

## Migration Path / Phased Plan

**Phase 021.A — Introduce `BootError` + `boot_failed`, no behavior change.** Add `src/boot/error.rs`. Export `crate::boot::BootError` and `crate::boot::boot_failed`. Nothing consumes them yet. Tri-arch green; one commit.

**Phase 021.B — Migrate sites in subsystem groups.** Each commit migrates one subsystem and threads the return through `kmain`:
- B1: Boot adapter (`src/boot/limine.rs` — 2 sites). `kmain` grows its first `?`.
- B2: Interrupts (`src/interrupts/mod.rs` + `src/arch/x86_64/apic.rs` — 4 sites on x86).
- B3: Timer (`src/arch/aarch64/timer.rs`, `src/arch/riscv64/timer.rs`, PLIC init in `src/microkernel/main.rs` — 4 sites).

Each commit is independently revertable. Each lands under the tri-arch gate.

**Phase 021.C — Remove the compatibility surface.** Verify no boot-path `.expect` / `panic!` remains (outside of explicitly out-of-scope sites documented above). Add a targeted grep-based self-test to the Makefile or CI that fails if a new `.expect` or `panic!` appears in `src/boot/`, `src/interrupts/mod.rs`, or arch init modules without an exemption comment.

Each phase is independently useful. 021.A unblocks 020-style adoption patterns for future work; 021.B lands the eleven migrations; 021.C prevents regression.

## Open Problems (deferred)

### Early-serial fallback for pre-`io::init` failures

If a boot failure happens before serial is initialized (e.g., a Limine response missing before `io::init` runs), `boot_failed`'s `println!` is silently dropped. An early-serial fallback (direct MMIO poke to a known UART address per arch) would surface these failures. **Revisit when:** a real boot failure fires before serial init and nobody sees the message. Today the pre-`io::init` window is narrow and all known failing sites within it (Limine responses) already execute before ADR-021's `boot_failed` runs — the panic handler today is in the same boat. This is not a regression, but it is a quality-of-diagnostics gap worth closing eventually.

### Richer internal diagnostics on mapped errors

`map_err(|_| BootError::ApicInitFailed)` discards the underlying error's context. An optional `source` field on `BootError` variants would preserve it (`BootError::ApicInitFailed(ApicError)`). Not needed for v1 because the operator's question on boot failure is almost always "what subsystem, what category" — which the flat enum already answers. **Revisit when:** a boot-failure investigation asks a question the top-level variant cannot answer.

### Lint against `.expect` / `panic!` in init paths

A grep-based `make check-boot-panics` lint that enforces "no `.expect` / `panic!` in `src/boot/`, `src/interrupts/mod.rs:init`, or arch timer/apic/plic init functions" would make regressions mechanical to catch. Parallels `make check-assumptions` and `make check-deferrals`. **Revisit when:** Phase 021.C lands and a regression appears — that is the signal that the discipline needs tooling, not just convention.

### Assertion policy across the kernel

`assert!` sites in kernel code are currently un-inventoried. Some express preconditions (fine), some are stand-ins for typed errors (should convert). A separate ADR could set a policy: "assertions express preconditions; typed errors express operational failures; `debug_assert!` expresses invariants we want to check in dev but trust in release." **Revisit when:** an `assert!` fires in production (real signal that the distinction was unclear) or a new subsystem adds several assertions of ambiguous intent during review.
