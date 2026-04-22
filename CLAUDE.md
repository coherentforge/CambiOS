# CambiOS Microkernel — Claude Code Context

## Formal Verification (Non-Negotiable Constraint)
The microkernel must be written for future formal verification. Every design decision in kernel code should keep this achievable. Concretely:

- **Pure logic separated from effects.** Algorithms that can be expressed as pure functions (e.g. BuddyAllocator) must be. Pure code is verifiable independently of hardware state.
- **Explicit state machines.** All state is represented as enums with exhaustive match. No boolean flags standing in for state, no implicit state encoded in combinations of fields.
- **Result/Option everywhere in kernel paths.** No panics, no unwrap(), no expect() in non-test kernel code. Every failure is a typed error that propagates explicitly.
- **Bounded iteration.** No unbounded loops in kernel paths. Loop bounds must be statically knowable or asserted. Verifiers cannot reason about unbounded loops.
unsafe minimized and isolated. Each unsafe block must be the smallest possible scope. Unsafe must be wrapped behind a safe abstraction boundary that can be audited and eventually replaced with a verified implementation.
- **No trait objects in kernel hot paths.** Monomorphized generics are statically analyzable; dynamic dispatch is not.
- **Invariants encoded in types, not comments.** If a value must be page-aligned, represent it as a newtype. If a region must be non-empty, make the empty case unrepresentable.
- **Separation of specification from implementation.** When implementing a component, identify the properties it must satisfy (preconditions, postconditions, invariants) and make them explicit — as type constraints where possible, as documented contracts otherwise. These become the verification targets.

The BuddyAllocator (pure bookkeeping, no hardware access, fully testable on host) is the template for how kernel logic should be structured. New kernel components will follow this pattern.


## Project Vision

CambiOS is a next-gen AI-integrated operating system built on these principles:

- **Security First:** Zero-trust architecture with real-time AI monitoring. No backdoors, no telemetry/telematics. Every process is verified at runtime.
- **Microkernel Isolation:** Device drivers, networking, and file systems run in isolated user-space environments — aligned for future formal verification.
- **AI-Powered Security:** Just-in-time code analysis pre-execution, behavioral anomaly detection, automatic quarantining of threats.
- **Cryptographic Identity:** Identity-based access replaces passwords. Decentralized identity and networking — no reliance on legacy IP/DNS.
- **AI Compatibility Layer:** AI-driven adaptation for running legacy Windows apps and cross-platform hardware support.
- **Live-Patchable:** AI-assisted kernel updates without reboots.
- **Platform Agnostic** Design with x86_64 and ARM compatibility.

Never suggest adding telemetry, analytics, or any form of phone-home behavior.

## Development Environment

- **Host:** macOS (Apple Silicon)
- **Kernel targets:** `x86_64-unknown-none`, `aarch64-unknown-none`, and `riscv64gc-unknown-none-elf` (ELF, bare metal). RISC-V backend is in progress (Phase R-0 done) — see [ADR-013](docs/adr/013-riscv64-architecture-support.md) and [STATUS.md](STATUS.md) RISC-V port phases.
- **Unit tests:** `cargo test --lib` (runs natively on macOS)
- **Integration testing:** QEMU (installed via Homebrew)
- **AArch64 boot media:** FAT disk image via `mtools` (ISO/cdrom doesn't work for AArch64 UEFI on QEMU)
- **RISC-V boot:** OpenSBI (M-mode firmware, ships with QEMU as `-bios default`) hands a DTB pointer to a custom S-mode boot stub at `src/boot/riscv.rs`. No Limine on RISC-V.

## Critical Rules

- **NEVER** suggest `cargo run` or `cargo build` without `--target x86_64-unknown-none`, `--target aarch64-unknown-none`, or `--target riscv64gc-unknown-none-elf` for kernel crates.
- **NEVER** suggest running kernel binaries directly on the host. Always use QEMU.
- **AArch64 QEMU MUST use** `-machine virt,gic-version=3` (GICv3 required for ICC system registers).
- **RISC-V QEMU MUST use** `-machine virt -bios default` (loads OpenSBI as M-mode firmware; the kernel is the S-mode payload). No vendor-specific machine types — generic-first per [ADR-013](docs/adr/013-riscv64-architecture-support.md).
- **Tri-arch regression gate is mandatory before commits** ([ADR-013](docs/adr/013-riscv64-architecture-support.md) § Tri-Architecture Regression Discipline). Use `make check-all` (x86_64 + aarch64 + riscv64) as the permanent gate — R-6 landed 2026-04-19 so all three arches are now buildable at every commit boundary. `make check-stable` (x86_64 + aarch64 only) remains available as an escape hatch for future temporary backend breakage; the discipline is identical either way — no commits regress any *currently buildable* arch.
- **ALWAYS** all new files get an SPDX license header + copyright at the top. Default: `// SPDX-License-Identifier: AGPL-3.0-or-later` then `// Copyright (C) 2024-2026 Jason Ricca` on the next line. Files under `user/libsys/` use `// SPDX-License-Identifier: MPL-2.0` instead. Adapt the comment syntax to file type (`#` for .toml/.py/.sh/Makefile; `/* ... */` for .ld/.S linker scripts and assembly). Do NOT use "All rights reserved" — a license grant supersedes reserved rights, and the SPDX header is the load-bearing declaration.
- **FUTURE VERIFICATION** every part of the microkernel will be formally verified at a later date.

## Stop-and-Ask Gate

Before the first edit, stop and confirm with the user when any of these apply. The cost of pausing is a sentence; the cost of proceeding wrong is a debug session or a silent design drift. User standing preference: questions over wrong assumptions — "I don't know" is acceptable.

- **Unread subsystem.** About to modify a subsystem listed in the [Required Reading](#required-reading-by-subsystem) map without having read its docs *this session*. Re-read first, or flag the reading gap.
- **New `unsafe` invariant.** About to add `unsafe` that introduces a *new kind* of safety obligation (not mechanically matching a pre-existing pattern in the same module). Mechanical copies are fine; new invariants need user sign-off so the audit trail is intentional.
- **ADR rewrite.** About to edit an ADR's original decision text. Use a `## Divergence` appendix or a new superseding ADR instead — original reasoning is immutable history.
- **Lock hierarchy change.** About to add a new lock to the hierarchy, reorder entries, or change `IrqSpinlock` vs plain `Spinlock`. Formally relevant, cross-subsystem, and exactly the class of change that breaks invariants silently.
- **SCAFFOLDING bound without v1 math.** About to pick a `const MAX_*` value without working through Dev Convention 8's extrapolation: v1-endgame workload, ≤25% utilization, memory cost. See [ASSUMPTIONS.md](docs/ASSUMPTIONS.md).
- **Dynamic dispatch in kernel.** About to introduce a trait object (`Box<dyn …>`, `&dyn …`) in kernel hot paths. Violates the Formal Verification rule ("no dynamic dispatch"). Propose the monomorphized design first.
- **Panic / unwrap / expect in non-test kernel code.** Every kernel failure must be a typed `Result`. If the only forward motion seems to be a panic, stop — the error type is probably wrong.
- **Telemetry / analytics / phone-home.** Project principle is zero telemetry. Any feature that emits data off-device (even "anonymous") is a stop.
- **Portable module drift.** About to add `#[cfg(target_arch = …)]` to `src/scheduler/`, `src/ipc/`, `src/process.rs`, `src/loader/elf.rs`, or another portable module. Factor an `arch::` helper instead, or escalate.
- **Identity-gate bypass.** About to add a syscall without updating `requires_identity()` + the identity tests in [src/syscalls/mod.rs](src/syscalls/mod.rs), or add an IPC receiver that uses plain `recv_msg` where `recv_verified` is the load-bearing variant.
- **Destructive or shared-state action.** `git reset --hard`, branch deletion, force-push, `rm -rf` under the repo, or any action visible outside this machine. The top-level "Executing actions with care" rule applies; this bullet is the local reminder.

This list is not exhaustive. The rule: **when you are about to modify something the user would want to be consulted on before the first edit, stop before the first edit.**

## Commit Cadence

Commit at natural topic boundaries within a session, not at session end. The cost of a commit is one PGP passphrase entry; the benefit is a bisectable history of self-contained improvements and a fallback point before riskier work.

- **Commit when a discrete improvement is complete and green** (builds + tests pass). Don't bundle unrelated improvements into one commit — they lose attribution, bisectability, and rollback granularity.
- **Commit before starting risky work** (major restructures, cross-file refactors, ADR changes). The pre-work state is your fallback.
- **Don't let 50+ edits accumulate uncommitted.** Reviewing a single giant diff is harder than reviewing five focused ones; passphrase cost scales linearly but review cost scales superlinearly.
- **Split by logical boundary, not by file.** A small multi-file change is one commit; a large single-file change spanning multiple topics should be multiple commits if the edits are cleanly separable.
- **Never `git add .` or `git commit -a` without naming files.** Working-tree sweeps conflate unrelated work — if a parallel session has uncommitted edits, those will get swept into the commit message of whatever is landing. Stage by explicit filename.
- **Draft the commit body from `git diff --cached`, not from memory.** After staging, read the cached diff end-to-end while writing the body. Every claim — "removes X", "fixes Y", "renames Z" — must correspond to a line in the diff. Verification bullets ("grep returns nothing", "make check-all clean") must be run against the staged tree at the moment of drafting, not recalled from earlier in the session. Commit bodies written from recall drift ahead of what actually got staged; the commit lands with an aspirational description of what *was meant* to be committed instead of an audit of what was. This is the failure mode behind the afc4b11 Makefile mis-fire (body described Makefile var / target / comment removals; only the `.S` + `.ld` file deletions actually staged; the cleanup had to be folded into a later commit).
- **Claude drafts; user executes.** Claude prepares `git add <files>` + commit message; user runs the commit to enter their PGP passphrase. Never bypass signing (`--no-gpg-sign`, `--no-verify`).

## Prompt-Shaping Changelog

Why each non-obvious rule was added, so a future session can generalize instead of pattern-matching on surface syntax. Keep entries terse (`YYYY-MM-DD — change — reason/failure it addresses`). Newest first.

- **2026-04-21** — Added `make check-banned-paths` lint + `tools/banned-paths.txt`; moved the pre-commit hook from per-clone `.git/hooks/pre-commit` to tracked `.githooks/pre-commit` with `make install-hooks` (one-time per clone, sets `core.hooksPath`). Reason: third recurrence of a prose-rule-fails-under-multi-clone-state pattern. Precedents: the `git commit -a` rule (two recurrences, logged in the git-commit-a feedback memory), and the commit-body-from-memory failure (afc4b11 Makefile mis-fire, 2026-04-20 changelog entry). Current recurrence: afc4b11 (2026-04-19) deleted `user/hello-riscv64.S` + `user/user-riscv64.ld` from git and the commit body verified `grep -rn "hello-riscv64"` was clean — but the working-tree copies survived (most likely mechanism: `git rm --cached` keeping disk, or a later merge resurrecting them). Both files sat untracked for two days before the 2026-04-21 rebase surfaced them. Prose rule would be "always `git rm` instead of `git rm --cached`, and always check `git status` after deletion commits" — same shape as the two prior prose rules that recurred. Per the precedent rule ("on third recurrence propose a mechanism, not a stronger rule"), this ships as tooling: the lint catches any listed path existing on disk, baseline is hand-maintained (new deletion commits append the path, new restore commits remove it), pre-commit hook fires. Tracked-hook move is the secondary lesson: the 2026-04-21 index-isolation entry documented the per-clone hook install via `cp`, which is itself the fragility shape that makes hook propagation unreliable across parallel Claude sessions on different clones. `.githooks/` + `core.hooksPath` + `make install-hooks` removes the `cp` step for every future lint. Onboarding a new clone is now `git clone … && make install-hooks`; hook file changes propagate via `git pull`. The 2026-04-21 index-isolation changelog entry is historically accurate for what shipped that day; this entry supersedes its per-clone-install guidance.
- **2026-04-21** — Fourth Kani proof crate landed (`verification/capability-proofs/`, 12 harnesses on `src/ipc/capability.rs` — Tier A single-process `ProcessCapabilities` invariants + Tier B cross-process `CapabilityManager` properties on a 3-slot `Box::leak`'d manager). `make verify` now gates 29 harnesses across four crates. No kernel source changed — all stop-and-ask items from the Landing 3 plan ("expose private API", "add cfg(kani) ctor") were avoided by construction. Two generalizable lessons for future kernel-code Kani targets: (1) *`#[path]` on a nested module is resolved from the nested module's **implicit directory**, not the declaring file's directory.* So `pub mod ipc { #[path = "../../../src/ipc/capability.rs"] pub mod capability; }` looks in `<crate>/src/ipc/../../../src/ipc/capability.rs` — wrong, and the intermediate `<crate>/src/ipc/` doesn't even exist. Fix: include the kernel file at the crate root under a private name (`mod _capability_src`), then `pub use crate::_capability_src as capability;` inside the stub `ipc` module. Buddy/elf/frame proofs didn't hit this because their targets had no `crate::*` imports — they could be included flat at the crate root with no stubs needed. Capability is the first target that pulls `crate::ipc::{ProcessId, EndpointId, CapabilityRights, Principal}` and `crate::ipc::interceptor::{IpcInterceptor, InterceptDecision}`; stubs for those live in a sibling `ipc` module in the proof crate's lib.rs, structurally matching the kernel's own layout. (2) *Drop kernel-crate-graph tentacles via existing cfg gates rather than rewriting code.* `CapabilityManager::revoke` calls `crate::audit::emit(...)` under `#[cfg(not(any(test, fuzzing)))]`; setting `--cfg fuzzing` via `build.rs` (`println!("cargo:rustc-cfg=fuzzing")`) drops that branch without touching the kernel source. Cheaper and less intrusive than carving out a `#[cfg(kani)]` ctor or fighting the full `crate::audit` + `crate::scheduler` graph. Pattern for future kernel targets that reach into other subsystems: look for an existing `#[cfg(not(test))]` or `#[cfg(not(any(test, fuzzing)))]` gate on the kernel side of the tentacle first — if one exists, reusing it is strictly better than a new cfg.
- **2026-04-21** — Third Kani proof crate landed (`verification/frame-proofs/`, 10 harnesses on `src/memory/frame_allocator.rs`). Authoring the proofs found two integer-overflow sites in `add_region` (line 138: `base + length`) and `reserve_region` (line 158: `(base + length).div_ceil(PAGE_SIZE)`) that panic in debug / wrap in release on malformed bootloader memory-map entries. Both fixed with `saturating_add` — overflow now means "region extends to end of address space," which the existing `MAX_FRAMES` cap handles cleanly. Second lesson for future proof work: *CBMC's budget scales poorly with allocator state × loop-iteration × symbolic-index combinations.* The `reserve_region` proof blew memory on the fully-symbolic version; the multi-frame `allocate_contiguous → free_contiguous` round-trip blew the unwind-assertion budget on the compounded bit-manipulation loops. Fallback shape: prove one representative function (`add_region`) with a full symbolic Kani proof, prove a single-frame `free_contiguous` round-trip, and cover the remaining mechanical-pattern-match cases (`reserve_region` wrap boundary, multi-frame round-trips) with `#[test]` unit tests in the kernel crate. "Split the proof budget" is now the pragmatic norm when state × loop product explodes — document the intractable harness in the proof crate with a pointer to the unit-test regression gate.
- **2026-04-21** — Second Kani proof crate landed (`verification/elf-proofs/`, 7 harnesses on `src/loader/elf.rs`). Authoring the proofs found six integer-overflow sites in the ELF parser (`e_phoff + index * e_phentsize`, `p_vaddr + p_memsz`, `p_offset + p_filesz` in three paths) that could wrap on attacker-chosen input and let a malicious unsigned binary bypass the parser's own bounds checks. All six fixed in the same landing (`checked_add` / `checked_mul` → typed `Err(ElfError::SegmentOutOfBounds)` / `Err(InvalidProgramHeaderOffset)`). Lesson for future proof work: *running Kani on code written without verification intent typically finds real bugs, not just proves existing safety.* The buddy allocator proof didn't find anything because that code was already written verification-first; parsers-on-untrusted-input are the high-yield target precisely because they weren't. Worked-example shape for future proof landings: write the proof, let Kani flag, pause before editing kernel source, propose the fix, land fix + proof together. Scoped P1.7/P1.8 out of this landing (they target `src/loader/mod.rs`, which would pull the full kernel dependency graph into the proof crate) — kept the elf-proofs crate dependency-free, same shape as buddy-proofs.
- **2026-04-21** — Added `make check-index-isolation` lint + `.git/hooks/pre-commit` wiring. Rejects commits where `STATUS.md` has more than 20 lines of diff AND any `*.rs` file is also staged. Reason: earlier the same day, two parallel Claude sessions ("main" and "tree") both touched STATUS.md — one restructuring it, the other adding feature-landing rows. The tree session's commit (4ce7ea0, since soft-reset) bundled 323 lines of STATUS.md restructuring with 12 Rust files of feature work; splitting it was manual and awkward. The lint codifies the split: small Post-Change Review Step 8 row updates (≤ 20 lines) remain free to bundle with code as the auto-refresh convention intends; structural rewrites must commit alone. Threshold reasoning in the lint's docstring. Pre-commit hook is per-clone (not tracked in repo — install via `cp /dev/stdin .git/hooks/pre-commit` or equivalent when onboarding a new clone); lint is also runnable as `make check-index-isolation`. Classic scheduler-mutex shape applied at the commit granularity: the file is the critical section, the commit-boundary is the lock acquire/release. If a third recurrence of a similar "parallel sessions collide on a shared index file" pattern shows up on another file (CLAUDE.md, README.md, docs/adr/INDEX.md), extend the lint to cover that file rather than trusting prose.
- **2026-04-21** — Broke the ADR append-only rule for [ADR-016](docs/adr/016-win-compat-api-ai-boundary.md) + [ADR-017](docs/adr/017-user-directed-cloud-inference.md): full rewrite on 016, slot reuse on 017 (prior content — Phase 1 Win32 catalog — folded into ADR-016's body so the 017 slot could be reclaimed for the User-Directed Cloud Inference decision). Both ADRs were the subject of a single mid-session pivot (AI translator for Win32 compat → bounded static shims; zero-telemetry principle refined to permit user-directed cloud inference) before any code had shipped against them. A `## Divergence` appendix on each would have left the ADRs as ~50% stale rationale + 50% current decision, with future readers paying the stale half every time. Rule refined, not abandoned: *append-only divergence for decisions that shipped code (ADR-002 interceptor enum-dispatch, ADR-003 ObjectStore shim); full rewrite or slot reuse for decisions withdrawn whole before implementation consumed them.* The append-only discipline exists to preserve load-bearing history; when the history is only load-bearing because it was never acted on, preserving it inverts the purpose. Executive call — logged here so a future session can tell which path applies without re-relitigating the governance question.
- **2026-04-19** — Added `make check-boot-panics` lint + baseline (`tools/check-boot-panics-baseline.txt`) enforcing ADR-021 Phase C. Scans a curated boot-path file set (src/boot/**/*.rs, src/interrupts/mod.rs, arch init modules — apic, timer, gic, plic, sbi, entry) for `.expect()` / `panic!()` / `unimplemented!()` / `todo!()` and fails on any new site. Baseline starts empty because 021.B.1–B.3 cleared the eleven sites ADR-021 identified; the lint is "don't regress from zero." Runtime fault handlers (`src/arch/riscv64/trap.rs` etc.) stay out of scope — kernel-mode fault recovery is deferred in ADR-019. Per-site exemption is `// BOOT_PANIC_OK: <reason>` within 3 lines. Reason: without tooling, the boot-path discipline is reviewer memory against a big kernel surface; the analogous gap Convention 9's lint closed for deferrals.
- **2026-04-20** — Added Commit Cadence rule: draft the commit body from `git diff --cached`, not from memory. Reason: the afc4b11 hello-riscv64-removal commit body described Makefile var / target / `.PHONY` / stale-comment removals as part of the change, but only `user/hello-riscv64.S` + `user/user-riscv64.ld` were actually staged. The body even listed a verification bullet (`grep -rn "hello-riscv64" src/ Makefile` returns nothing) that would have tripped if run against the staged tree — but it was evidently run against the planned tree, or not run at all. Three days later the unfolded Makefile cleanup had to be bundled into Scanout-2 (the change that happened to touch the same Makefile). Failure mode: commit body written from "what I meant to stage" instead of "what's in `git diff --cached`" produces an aspirational description of a partial change. Fix is discipline-only (no tooling): stage, then read the cached diff end-to-end while writing the body, verify every claim against a diff line. If this recurrence-pattern fails a third time (precedent: the `git commit -a` rule), escalate to a pre-commit hook that greps the message for file paths / symbol names and warns if any aren't in the staged diff.
- **2026-04-19** — Added `make check-assumptions` lint + baseline file (`tools/check-assumptions-baseline.txt`). Enforces existing Development Convention 8 ("Every numeric bound is a conscious bound") by flagging `const NAME: <numeric> = …` in `src/**/*.rs` without a `SCAFFOLDING` / `ARCHITECTURAL` / `HARDWARE` / `TUNING` tag in a doc comment above it. Reason: the post-Hubris-talk verification-readiness audit found ~290 untagged numeric consts in kernel code — Convention 8 was being observed for new bounds but old drift was invisible. Baseline absorbs the pre-existing set (don't-grow-the-baseline gate, same pattern as Convention 9's lint); new untagged consts fail the lint. Test modules are skipped via a brace-depth walker tracking `mod tests` / `#[cfg(test)]` context. Companion to the SAFETY-comment completion pass in the same session — two isolated hygiene gains, not rule changes.
- **2026-04-19** — Added Development Convention 9 ("Every deferral is a conscious deferral") + `make check-deferrals` lint + baseline file. Reason: ADR-006 carried a forward reference to "ADR-021 Init Process" for months, pointing at an anchor in CLAUDE.md that also didn't exist. When `make check-adrs` landed (2026-04-16) it caught the forward reference, but only because that specific shape (ADR-NNN cite) was lint-able. Within one session three more instances of the same pattern surfaced across different surfaces: a discarded return value meant to become load-bearing (`_vma_count` in `reclaim_user_vmas`), Frame-A identity vestiges flagged in memory but not cleaned up, and the R-5.b shootdown self-test that was only rescued from drift because its ADR entry happened to flag it in prose. Common shape: a deferral whose revisit trigger is "whenever someone notices" instead of an observable condition. Convention 9 mirrors Convention 8's template — SCAFFOLDING bounds already require `Replace when:` with an observable trigger; the discipline now extends to decisions, ADR prose, and code comments via `Revisit when:`. The lint grep-catches the high-signal token shapes (TODO/FIXME/eventually/later/placeholder/for-now/TBD) and flags any without a trigger within 3 lines. Baseline file (`tools/check-deferrals-baseline.txt`) exempts pre-existing instances so the lint is a don't-grow-the-baseline gate, not a boil-the-ocean blocker.
- **2026-04-16** — Added Commit Cadence rule. Reason: session-end-only commits accumulate unrelated work (a RISC-V commit silently swept in this session's prompt-shaping code edits because `git commit -a` was used in a parallel session). Rule: topic-boundary commits, explicit file staging, Claude drafts / user executes.
- **2026-04-16** — Layered the doc: operational sections (Dev Conventions, Post-Change Review, Failure Signatures, Worked Examples) promoted above reference material; directory tree + per-syscall behavior descriptions demoted to the bottom. Reason: instructions near the top of context are absorbed more reliably; what-to-do outranks what-to-look-up.
- **2026-04-16** — Added `arch::interrupts_enabled()` helper (x86_64 / AArch64 / RISC-V + host stub) and `debug_assert!` at heap entry, `map_page` (both arches), `Scheduler::block_task`. Reason: prose invariants ("disable interrupts before `block_task`", "heap alloc requires `memory::init()` first", "page-align before `map_page`") lose force across sessions; code-level asserts fire at the bad callsite every build.
- **2026-04-16** — Reverted a proposed `bind_principal` `debug_assert!`. Lesson: asserts and negative-path tests on the same invariant collide — the test intentionally triggers the error, and the assert fires on it. Test wins because it runs in release. Rule: before adding an assert, check for an existing `test_X_rejects_Y` — if it exists, the invariant is already enforced louder than an assert can.
- **2026-04-16** — Added Failure Mode Signatures section (Common Failure Signatures). Reason: Claude Code sees compiler errors and QEMU hangs first, not architectural concepts. Maps the observed symptom text back to the root cause + where to look.
- **2026-04-16** — Tiered the Post-Change Review Protocol (scope triage: small change → §1 + §8; subsystem change → full §1–§8). Reason: one-size-fits-all checklist on a typo produces fatigue, which gets paid in skipped steps later.
- **2026-04-16** — Added Stop-and-Ask Gate. Reason: user standing preference ("questions over wrong assumptions") wasn't encoded in CLAUDE.md, only in memory; without an explicit gate, ambiguous cross-subsystem changes proceeded on guesswork.
- **2026-04-16** — `make check-adrs` lint + [docs/adr/INDEX.md](docs/adr/INDEX.md) auto-generated + rule against forward numeric ADR references. Reason: ADR-012 referenced "future ADR-013…" as a placeholder before ADR-013 landed with different content (superseded by the riscv64 architecture-support decision). The forward reference aged into a lie between commits. Rule: reference future work by concept, never by number. Lint: walks every ADR, verifies all `ADR-NNN` references resolve to existing non-superseded ADRs, regenerates the index; flags duplicates. First run already caught two more drift cases (006→021 stale forward ref; three files sharing number 010) — not fixed in the same commit because they're design-choice renames you should make, not mechanical fixes.
- **2026-04-16** — `make stats` target + stripped hard-coded syscall/test counts from prose. Reason: counts duplicated across CLAUDE.md / STATUS.md drifted silently (doc said "37 syscalls" when actual was 38; lock hierarchy duplicated with one copy missing `CHANNEL_MANAGER`). Canonical source is code; run `make stats` when a number actually matters.

## Development Conventions

1. **Every `unsafe` block MUST have a `// SAFETY:` comment** explaining why the operation is safe. Citing alignment, bounds, aliasing, or lifetime invariants is the point — "trust me" is not a SAFETY comment.

2. **Lock ordering** (see [Lock Ordering](#lock-ordering)) must always be followed. Never acquire a lower-numbered lock while holding a higher-numbered one.

3. **Architecture portability:** All x86-specific code must be behind `#[cfg(target_arch = "x86_64")]`. The `src/arch/mod.rs` shim re-exports the active backend. Portable scheduler logic lives in `scheduler/mod.rs`.

4. **Large structs** (Scheduler, IpcManager, CapabilityManager, BuddyAllocator) must be heap-allocated via `new_boxed()` pattern to avoid stack overflow. Boot stack is only 256KB. Scheduler uses Vec/VecDeque internally so only ~128 bytes of metadata lands on the stack.

5. **`no_std` only.** No standard library. No heap allocation before `memory::init()` completes in `main.rs`.

6. **GDT must be `static mut`** (writable .data section) because the CPU writes the Accessed bit.

7. **Never assume zeroed memory equals `None` for `Option<T>`.** Rust does not guarantee the Option discriminant layout — the compiler may assign discriminant 0 to `Some` (not `None`), especially for large structs on bare-metal targets. Always use explicit `core::ptr::write(None)` when initializing heap-allocated arrays of `Option<T>`.

8. **Every numeric bound is a conscious bound.** Fixed `const` numerics, fixed-size arrays, and `MAX_*` values in kernel code must carry a doc comment naming their category: `SCAFFOLDING` (verification ergonomics, expected to grow), `ARCHITECTURAL` (real invariant, won't change), `HARDWARE` (ABI/spec fact), or `TUNING` (workload-dependent). Unconscious bounds — values picked because something fit — are how production-ready software accrues weakness while it's still cheap to fix. The full catalog with rationale and replacement criteria lives in [ASSUMPTIONS.md](docs/ASSUMPTIONS.md). Templates:

```rust
/// SCAFFOLDING: <one-line statement of the constraint>
/// Why: <verification or early-development rationale>
/// Replace when: <observable trigger that should make a future maintainer revisit>
const MAX_FOO: usize = 32;

/// ARCHITECTURAL: <statement of the invariant the constant encodes>
const NUM_PRIORITY_BANDS: usize = 4;

/// HARDWARE: <ABI/spec reference that fixes this number>
const MAX_GSI_PINS: usize = 24;

/// TUNING: <what workload property this number trades off>
const CACHE_CAPACITY: usize = 32;
```

**SCAFFOLDING bounds must be sized for the v1 endgame, not today's workload.** Do not pick "the smallest number that works today" and plan to resize later. Extrapolate forward across the full v1 sequence ([STATUS.md](STATUS.md) has the phase list and per-service growth). A bound that's comfortable today but gets crossed during v1 is the worst case — it looks fine at review and silently becomes a bottleneck in the subphase where changing it is most disruptive. The rule:

1. Estimate **(a)** current workload, **(b)** v1 workload after all phases land, **(c)** memory cost at candidate multiples of the v1 estimate.
2. Pick the smallest value where the v1 estimate is approximately **≤ 25% of the bound** AND the memory cost is still comfortable. "≤ 25%" means the bound has ~4× headroom above the v1 estimate — enough that a surprising workload or an unplanned consumer (a new audit channel, a second policy cache) does not push against the wall.
3. Record the math in the row for that constant in [ASSUMPTIONS.md](docs/ASSUMPTIONS.md) — the "Why this number" column should show the v1 workload estimate and the memory cost, not just "big enough."

When you add a new bound or change one, update the matching table in [ASSUMPTIONS.md](docs/ASSUMPTIONS.md) in the same change. Step 8 of the Post-Change Review Protocol lists this as an explicit checklist item.

The [`make check-assumptions`](Makefile) lint scans `src/**/*.rs` for numeric `const` declarations without one of the four category tags in a doc comment above them; run it alongside `make check-deferrals` when editing kernel code. Baseline exemptions live in `tools/check-assumptions-baseline.txt`. As with Convention 9's lint, the goal is to not *grow* the baseline, not to clear it overnight.

9. **Every deferral is a conscious deferral.** Any "figure it out later" — TODO, placeholder, temporary workaround, "eventually," "when X lands," forward reference without an anchor — must carry a **Revisit when:** line naming an observable trigger. "When it matters" doesn't count. Applies to ADR prose, code comments, doc citations, and commit messages. Unconscious deferrals are how load-bearing placeholders age into lies between the session that wrote them and the session that would have caught them. Concrete triggers look like:

   - *A named commit or subphase:* "Revisit when R-6 lands" (observable: git log names R-6 commit).
   - *A workload crossing a threshold:* "Revisit when a second boot module needs user-declared endpoints" (observable: second call-site appears).
   - *A subsystem landing:* "Revisit when the init-process ADR lands" (observable: ADR file exists + check-adrs resolves the reference).
   - *A measured metric:* "Revisit when audit ring drop counter > 0 under nominal load" (observable: `SYS_AUDIT_INFO` output).

   Vague triggers that **fail** the rule: "later," "eventually," "in the future," "when that matters," "TBD." These are indistinguishable from no trigger at all. If you can't name an observable trigger, the decision isn't ready to defer — either make it now or escalate. The existing SCAFFOLDING bound convention (Convention 8) already follows this template for numeric bounds via `Replace when:`; Convention 9 extends the discipline from bounds to decisions.

   Template for code comments:

   ```rust
   // Deferred: <one-line statement of the deferral>
   // Why: <what information we don't yet have, or why deferring is cheaper than deciding now>
   // Revisit when: <observable trigger>
   ```

   Template for ADR prose:

   ```markdown
   > **Deferred decision.** <statement>. **Revisit when:** <observable trigger>.
   ```

   The [`make check-deferrals`](Makefile) lint scans ADRs + kernel source for deferral tokens without adjacent triggers; run it alongside `make check-adrs` when editing design docs. It's noisy on first introduction (baseline exemptions live in `tools/check-deferrals-baseline.txt`); the goal is to not *grow* the baseline, not to clear it overnight.

## Post-Change Review Protocol

Run this checklist after any code change, before considering it complete.

### Scope triage (do this first)

Running the full 8-step protocol on a typo fix produces fatigue paid for later in skipped steps. Decide which tier applies first:

- **Small change** — typo, comment prose, whitespace, unused-import removal, local variable rename, STATUS.md note, or documentation-only edit that doesn't touch invariants. Run only **§1 (Build Verification)** and **§8 (Documentation Sync)**. Skip §2–§7.
- **Subsystem change** — anything that touches a module's public API, an `unsafe` block, the lock hierarchy, the syscall ABI, the boot path, a kernel invariant, a cross-cutting concern, or an ADR-worthy decision. Run the **full protocol §1–§8, in order**. This tier is where drift becomes load-bearing.

**When unsure, run the full protocol.** Over-auditing a small change costs minutes; under-auditing a subsystem change costs a deadlock the next maintainer has to debug. If the Stop-and-Ask Gate fired during planning, this is automatically a subsystem change.

### 1. Build Verification
```bash
# Unit tests (host)
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Clippy lint pass (catches correctness + style issues beyond warnings)
# Note: not yet -D warnings — 164 pre-existing style lints need a
# dedicated cleanup pass first. Run without -D to check for NEW lints
# introduced by the current change. Once the baseline is clean,
# promote to -D warnings.
cargo clippy --target x86_64-unknown-none 2>&1 | grep "^error\|^warning" | head -20

# Kernel build — x86_64 (debug + release)
cargo build --target x86_64-unknown-none
cargo build --target x86_64-unknown-none --release

# Kernel build — AArch64 (release)
cargo build --target aarch64-unknown-none --release

# QEMU integration (when touching boot/runtime paths)
make run            # x86_64
make run-aarch64    # AArch64
```
All builds and clippy must pass with zero errors. Do not skip any step.

**Flag pre-existing warnings.** Any build/test/clippy warning — even pre-existing — must be acknowledged, not silently passed through. "Pre-existing and unrelated" is how technical debt becomes invisible. Two responses:

- **Tiny and safe → fix it in the same change.** Unused imports/variables, dead bindings, trivially redundant casts. Seconds to clear, keeps build output clean.
- **Otherwise → report and track.** Surface it to the user (file:line + warning text) and add to [STATUS.md](STATUS.md)'s Known Issues. Silent pass-through loses signal for formal-verification prep and human review.

### 2. Safety Audit
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariants
- New unsafe code cites what guarantees make it sound (alignment, bounds, aliasing, lifetime)
- No raw pointer dereference without a bounds or null check nearby

### 3. Lock Ordering
Verify no change introduces a lock ordering violation against the canonical hierarchy in the [Lock Ordering](#lock-ordering) section. **Do not duplicate the hierarchy here** — it drifted once and will drift again. Checklist:
- Lower-numbered locks must be acquired before higher-numbered ones
- `try_lock()` in ISR context is acceptable (already established pattern)
- Holding multiple locks simultaneously requires explicit justification
- If you are *adding or reordering a lock*, trip the Stop-and-Ask gate before editing — lock hierarchy changes are cross-subsystem and formally relevant

### 4. Architecture Portability
- New x86-specific code is behind `#[cfg(target_arch = "x86_64")]`
- New x86-specific code lives under `src/arch/x86_64/`, not in portable modules
- Portable modules (`scheduler/`, `ipc/`, `process.rs`, `loader/elf.rs`) contain no arch-specific code

### 5. Memory Safety
- Large structs (>1KB) are heap-allocated via `new_boxed()` or `Box::new()` — boot stack is 256KB
- No heap allocation before `memory::init()` completes
- Frame allocator regions don't overlap with kernel heap or reserved memory

### 6. Security Review (for loader/IPC/syscall changes)
- ELF binaries pass through `BinaryVerifier` before any memory allocation
- W^X enforcement: no page is both writable and executable
- User-space segments don't map into kernel address space
- Syscall handlers validate all user-provided pointers and lengths
- Capabilities are checked before granting IPC access

### 7. Test Coverage
- New logic has corresponding unit tests in `#[cfg(test)]` modules
- Edge cases are tested (boundary values, error paths, overflow)
- Tests run on host macOS target — no x86 hardware dependencies in test code

### 8. Documentation Sync
Docs in this repo are categorized by how they relate to the code, and that determines whether they auto-refresh on a code change. **This step is required, not optional** — stale implementation docs are how priorities get forgotten between sessions.

| Category | Files | Auto-refresh? | Rule |
|---|---|---|---|
| **implementation_reference** | [STATUS.md](STATUS.md), [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ASSUMPTIONS.md](docs/ASSUMPTIONS.md), and any `*.md` colocated with code that documents *current* implementation | **Yes** | If your change moves a subsystem's status (built/in-progress/planned), test count, known issue, implementation detail, or numeric bound, update the matching doc *in the same change*. Set `last_synced_to_code:` in the frontmatter to today's date. |
| **decision_record** | [docs/adr/](docs/adr/) ([INDEX.md](docs/adr/INDEX.md)) | **Append-only divergence** | The original decision text is immutable history — never rewrite it. If a decision is wrong or superseded, write a new ADR that supersedes it. However, when implementation diverges from the plan described in an ADR (deferred work, changed approach, new information), append a **`## Divergence`** section at the end of the ADR documenting *what* changed and *why*. This keeps the original reasoning intact while ensuring the ADR doesn't silently become fiction. ADRs must NOT contain status info ("X tests passing", "currently implemented in Y") — that drifts. They can name files and structs as a starting point, but never as a current-state claim. **No forward numeric ADR references.** Do not write "future ADR-NNN" or link to an ADR number that doesn't exist yet — such references age into lies when ADR-NNN lands with different content (or lands at a different number entirely). Reference future work by concept ("future init-process ADR", "when the bulk-channel decision lands") instead. After editing any ADR, run `make check-adrs` to verify every `ADR-NNN` reference resolves to an existing, non-superseded ADR and to regenerate [docs/adr/INDEX.md](docs/adr/INDEX.md). |
| **design / source_of_truth** | [CambiOS.md](docs/CambiOS.md), [identity.md](docs/identity.md), [FS-and-ID-design-plan.md](docs/FS-and-ID-design-plan.md), [win-compat.md](docs/win-compat.md), [PHILOSOPHY.md](docs/PHILOSOPHY.md), [SECURITY.md](docs/SECURITY.md), [GOVERNANCE.md](docs/GOVERNANCE.md) | **No** — human only | These describe intent and design, not current state. If implementation reveals a design problem, propose the change to the user; don't silently rewrite. They link to STATUS.md for the implementation status of any phase or feature. |
| **index** | [README.md](README.md), [CLAUDE.md](CLAUDE.md) (this file) | **Light touch** | Update only when the structure changes (new doc, new ADR, new build command, new lock in the hierarchy). Status info goes in STATUS.md, not here. |

**Concrete checklist for the change you just made:**
1. Did this change modify a subsystem listed in [STATUS.md](STATUS.md)'s subsystem table? → Update its row and bump `last_synced_to_code:`.
2. Did this change move a phase forward (e.g., "Phase 3 in progress" → "Phase 3 done")? → Update the Phase markers table.
3. Did this change touch the scheduler? → Re-read [SCHEDULER.md](src/scheduler/SCHEDULER.md) and update if anything in it is now wrong.
4. Did this change introduce a new architectural decision? → Draft a new ADR. Don't bury the decision in code comments. Did this change diverge from an existing ADR's plan? → Append a `## Divergence` entry to that ADR documenting what changed and why.
5. Did this change add or rename a build command, lock, or syscall? → Update CLAUDE.md's Quick Reference / Lock Ordering / Syscall Numbers tables.
6. Did this change resolve a Platform Gotcha in CLAUDE.md or a Known Issue in STATUS.md? → Remove it from the gotcha list (don't leave a `~~strikethrough~~ FIXED` ghost).
7. Did this change cite a doc that doesn't exist yet? → Either create the doc or remove the citation.
8. Did this change add or modify a numeric `const`, fixed-size array, or `MAX_*` bound in kernel code? → Tag it with `SCAFFOLDING` / `ARCHITECTURAL` / `HARDWARE` / `TUNING` per Development Convention 8, and add or update the row in [ASSUMPTIONS.md](docs/ASSUMPTIONS.md). Unconscious bounds are not allowed.

## Common Failure Signatures

Map the error string or symptom you actually observe back to the likely root cause. These pairings exist because the symptom rarely names the invariant it violated — a compiler error or a silent QEMU hang says nothing about "lock ordering" or "HHDM gap."

- **`error[E0152]: found duplicate lang item 'panic_impl'`** → a crate in the dependency tree pulled in `std`. Kernel and userspace modules are both `no_std`; most commonly triggered when a new dependency's default features include `std`. Disable default features on the offender and pick only `no_std`-compatible flags.

- **`link error: undefined reference to 'memcpy'` / `memset` / `memmove`** → new crate missing the `compiler_builtins` `mem` feature, or kernel linker flags lost `-C link-arg=--no-undefined`. Cross-check the failing module's `Cargo.toml` against a working sibling (`user/fs-service`, `user/shell`).

- **QEMU reboots / triple-faults immediately after "booting kernel…"** → IDT not installed yet (any exception before `interrupts::init()` is a triple fault), or the double-fault handler faulted because IST1 isn't pointing at valid memory. Check the boot sequence in [src/microkernel/main.rs](src/microkernel/main.rs) for ordering regressions.

- **AArch64 "Undefined Instruction" exception at `mrs ICC_SRE_EL1`** → QEMU running default GICv2. Must use `-machine virt,gic-version=3`. (Duplicates a Platform Gotcha intentionally — this error text should resolve to its cause from either direction.)

- **Kernel panic "allocation failed" / `GlobalAlloc::alloc` returns null in early boot** → attempted `Box::new` / `Vec::new` before `memory::init()` ran. Move the allocation after init, or pre-allocate a static. The `debug_assert!` at the top of [src/memory/heap.rs](src/memory/heap.rs) will name this directly in debug builds.

- **`#PF` in kernel with CR2 = user vaddr during a syscall** → the user pointer belongs to a process whose page tables aren't currently loaded in CR3 (e.g., kernel reading a peer's channel buffer while in a third process's context). Use the page-walk helpers in [src/syscalls/dispatcher.rs](src/syscalls/dispatcher.rs) rather than dereferencing user pointers directly. *Note: this codebase does not enable SMAP, so `stac`/`clac` is not the cause — don't go looking for it.*

- **QEMU output stops mid-run with no panic, no reboot, no further timer ticks** → a silent hang. Locate the last thing that printed and check the code path immediately after it:
  - *Touched a lock used from an ISR?* → it must use `try_lock()`, not `lock()`. A blocking ISR lock deadlocks the CPU.
  - *Touched lock ordering?* → re-check the [Lock Ordering](#lock-ordering) hierarchy. Acquiring a lower-numbered lock while holding a higher-numbered one freezes the CPU that hits the violation. No runtime "deadlock detected" message is printed — silence *is* the diagnostic.
  - *Touched the timer ISR?* → missing APIC EOI (`apic::write_eoi()`) or GIC EOI means no further timer interrupts fire.
  - *Touched yield / context switch?* → a lock held across `yield_save_and_switch` freezes the next task to try to acquire it.

## Worked Examples

Concrete before/after examples for recurring multi-place changes. A diff beats a paragraph of rules: it names every file touched and proves the steps are complete by construction.

### Adding a new syscall

Seven places must change atomically. Skipping any one produces a specific failure mode named below. The canonical reference is the `TryRecvMsg = 37` landing — every step below is taken verbatim from that change.

**(1) Declare the variant** — [src/syscalls/mod.rs](src/syscalls/mod.rs), in the `SyscallNumber` enum.
```rust
/// SYS_TRY_RECV_MSG (37): non-blocking variant of RecvMsg. Returns 0
/// immediately if no message is queued, instead of parking the task
/// on `MessageWait(endpoint)`. …
TryRecvMsg = 37,
```
*Skipping:* userspace hits `SyscallError::Enosys` because `from_u64` doesn't know the number.

**(2) Classify identity requirement** — same file, `requires_identity()` match.
```rust
Self::Write | Self::Read | Self::RecvMsg | Self::TryRecvMsg |
```
*Skipping:* if the new syscall touches identity-bearing state and you forget this arm, unidentified processes can call it. The `identity_required_syscalls_are_gated` test below fails — that is the safety net. **Do not silence the test by adding the syscall to the `EXEMPT` set unless the syscall genuinely needs no identity** (check the small exempt list for precedent).

**(3) Wire `from_u64`** — same file.
```rust
37 => Some(Self::TryRecvMsg),
```
*Skipping:* runtime dispatch returns `None`, the kernel returns `Enosys`, the syscall appears un-implemented.

**(4) Update test coverage** — same file, `#[cfg(test)] mod tests`.
```rust
// Add to the `all` array in identity_required_syscalls_are_gated:
SyscallNumber::TryRecvMsg,

// Extend the range in all_syscall_numbers_covered:
for i in 0..=37u64 { … }
```
*Skipping:* the new variant isn't exercised by `all_syscall_numbers_covered` (test passes vacuously) and isn't checked against the exempt set (test passes because the check iterates `all`, not the enum). Both tests are *cooperative* — they only catch omissions when you also maintain the arrays. This is by design; treat it as a prompt to think about coverage.

**(5) Dispatch the call** — [src/syscalls/dispatcher.rs](src/syscalls/dispatcher.rs), in `handle_syscall`'s dispatch match.
```rust
SyscallNumber::TryRecvMsg => Self::handle_try_recv_msg(args, &ctx),
```
*Skipping:* compile error (match non-exhaustive). This is the one step the compiler catches for free.

**(6) Implement the handler** — same file.
```rust
fn handle_try_recv_msg(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
    let endpoint_id = args.arg1_u32();
    let user_buf = args.arg2;
    let buf_len = args.arg_usize(3);
    // … capability check → IPC recv → page-walk to user buffer …
}
```
*Skipping:* compile error at step (5). Paired with it.

**(7) Expose the userspace wrapper** — [user/libsys/src/lib.rs](user/libsys/src/lib.rs). Add the `SYS_*` constant alongside the others, then the safe wrapper.
```rust
const SYS_TRY_RECV_MSG: u64 = 37;

pub fn try_recv_msg(endpoint: u32, buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_TRY_RECV_MSG, endpoint as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
}
```
*Skipping:* userspace services can't call the syscall without raw `asm!`. The kernel side works; every consumer is broken until libsys catches up.

**Verification:** after all seven, `RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin` must pass (identity-gate tests exercise the new variant), and `make check-all` must build clean on x86_64 + aarch64 + riscv64.

**Stop-and-Ask triggers in this flow:** does the new syscall belong in the exempt set? (Almost always no — default to identity-required.) Does it introduce a new kind of capability check? (If yes, trip the unread-subsystem gate on `src/ipc/capability.rs` first.) Does it need a new arch backend helper? (If yes, add to all three arch modules.)

## Quick Reference

```bash
# Build kernel (release)
cargo build --target x86_64-unknown-none --release

# Build kernel (debug)
cargo build --target x86_64-unknown-none

# Build AArch64 kernel (release)
cargo build --target aarch64-unknown-none --release

# Build RISC-V kernel (release). See ADR-013 / STATUS.md for backend phase state;
# some phases intentionally don't build while the backend is under construction.
cargo build --target riscv64gc-unknown-none-elf --release

# Tri-arch regression gate (MANDATORY before commits). R-6 landed
# 2026-04-19 so check-all is now the permanent gate; check-stable is
# retained as an escape hatch for future temporary backend breakage.
# ADR-013 § Tri-Architecture Regression Discipline.
make check-all        # x86_64 + aarch64 + riscv64 (permanent gate)
make check-stable     # x86_64 + aarch64 only (escape hatch)

# Run tests. Test count is not cited here — run `make stats` when you
# need it (syscall count, test count, .rs file counts are all derived
# from source). Canonical counts live in code, not prose.
# Note: must use --manifest-path if cwd could be user/fs-service/
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Derived counts (syscalls, tests, LOC) — run when a number actually matters.
make stats

# Verify ADR cross-references and regenerate docs/adr/INDEX.md. Run after
# any ADR edit or addition. Exits nonzero if any ADR references a missing
# or superseded ADR, or if two ADRs share a number.
make check-adrs

# Verify every numeric `const` in kernel code carries a Convention 8
# category tag (SCAFFOLDING / ARCHITECTURAL / HARDWARE / TUNING).
# Baseline exemptions in tools/check-assumptions-baseline.txt.
make check-assumptions

# Enforce ADR-021 Phase C — no `.expect() / panic!() / unimplemented!() / todo!()`
# in boot-path init code. Scans src/boot/**/*.rs, src/interrupts/mod.rs, and
# arch init modules (apic, timer, gic, plic, sbi, entry). Runtime fault
# handlers stay out of scope (kernel-mode recovery deferred per ADR-019).
# Baseline is expected-empty; `// BOOT_PANIC_OK: <reason>` is the per-site
# exemption for genuinely unrecoverable cases.
make check-boot-panics

# Enforce that paths deleted from git stay deleted on disk. Reads
# tools/banned-paths.txt; fails if any listed path exists in the working
# tree. Wired into .githooks/pre-commit. Append a path here in the same
# commit that deletes the file from git; remove the entry in the same
# commit that re-adds it.
make check-banned-paths

# One-time per clone: point core.hooksPath at .githooks/ so the tracked
# pre-commit hook fires on every commit. Updates to .githooks/pre-commit
# propagate via `git pull` — no re-install needed. Required after every
# fresh `git clone`.
make install-hooks

# Build for a specific deployment tier (Phase 3.2a / ADR-008 / ADR-009).
# CAMBIOS_TIER selects which TableSizingPolicy is compiled in. Default
# is tier3 when unset — always target tier3 unless specifically
# working on tier1 or tier2. build.rs reads CAMBIOS_TIER and emits a
# single --cfg tierN flag; any other value is a build error.
CAMBIOS_TIER=tier1 cargo build --target x86_64-unknown-none --release
CAMBIOS_TIER=tier2 cargo build --target x86_64-unknown-none --release
CAMBIOS_TIER=tier3 cargo build --target x86_64-unknown-none --release   # same as leaving it unset

# Generate symbol index for AI-assisted navigation (read .symbols at session start)
make symbols

# Build ISO + run in QEMU (x86_64) — includes kernel + boot modules (policy, ks, fs, virtio-blk, shell)
make iso && make run

# Just run (rebuilds kernel + user modules automatically)
make run

# Build FAT image + run in QEMU (AArch64)
make img-aarch64 && make run-aarch64

# Build + run RISC-V kernel in QEMU virt with OpenSBI (Phase R-0 builds
# the target; Phase R-1+ produces useful boot output)
make run-riscv64

# Build fs-service only (standalone Rust crate)
make fs-service

# Create the backing file for the virtio-blk device (64 MiB raw image).
# `make run` depends on this target; idempotent — leaves an existing image alone.
make disk-img

# Build ELF signing tool (host-side, for signing boot modules)
make sign-tool

# Sign an ELF binary via YubiKey (default — requires YubiKey + OpenPGP Ed25519 key)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf <elf-file>

# Sign via seed (for CI/testing without hardware key)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --seed <hex> <elf-file>

# Export bootstrap public key from YubiKey (one-time setup)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --export-pubkey bootstrap_pubkey.bin

# Print the bootstrap public key (hex)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --print-pubkey
```

**Important:** The microkernel binary (`src/microkernel/main.rs`) cannot compile for test on macOS because it uses ELF-specific linker sections. Always use `--lib` when running tests. The `RUST_MIN_STACK` env var is required because some tests (buddy allocator) need >2MB stack. The `user/fs-service/` crate is built separately with `CARGO_ENCODED_RUSTFLAGS` to override the parent `.cargo/config.toml` (which targets kernel code model). The `tools/sign-elf/` crate is a host-side tool with its own `.cargo/config.toml` targeting `aarch64-apple-darwin`.

## Code Navigation — rust-analyzer MCP Tools

An MCP server exposing rust-analyzer is configured in `.mcp.json`. **Prefer these tools over Grep/Glob for code navigation whenever practical:**

- **`mcp__rust-analyzer__symbol_references`** — find a symbol by name and get all references in one call. Use this instead of grepping for a symbol name.
- **`mcp__rust-analyzer__hover`** — get the resolved type, struct fields, and doc comments at a position. Use this instead of reading surrounding code to understand a type.
- **`mcp__rust-analyzer__definition`** — jump to where a symbol is defined. Use this instead of grepping for `fn name` or `struct name`.
- **`mcp__rust-analyzer__references`** — find all references at a position (when you already have file:line:col).
- **`mcp__rust-analyzer__implementations`** — find all trait implementations. Use this instead of grepping for `impl TraitName`.
- **`mcp__rust-analyzer__symbols`** — fuzzy search for symbols across the workspace.
- **`mcp__rust-analyzer__document_symbols`** — structural overview of a file (all functions, types, constants).

These tools return semantically precise results (no false positives from comments or strings) and save significant tokens compared to grep-then-read cycles. Grep is still appropriate for searching within string literals, comments, or non-Rust files.

## Lock Ordering

Lock ordering MUST be followed to prevent deadlock.

```
SCHEDULER(1)* → TIMER(2)* → IPC_MANAGER(3) → CAPABILITY_MANAGER(4) →
CHANNEL_MANAGER(5) → PROCESS_TABLE(6) → FRAME_ALLOCATOR(7) →
INTERRUPT_ROUTER(8) → OBJECT_STORE(9)
```
`*` = IrqSpinlock (saves/disables interrupts before acquiring, prevents same-CPU deadlock when timer ISR fires while lock is held). Others use plain Spinlock.

Lower-numbered locks must be acquired before higher-numbered ones. See `src/lib.rs` comment.

**Additional lock domains (independent of hierarchy above):**
- `PER_CPU_FRAME_CACHE[cpu]` — per-CPU, never held with FRAME_ALLOCATOR. Cache lock released before acquiring global allocator on refill/drain.
- `SHARDED_IPC.shards[endpoint]` — per-endpoint, never held cross-endpoint. Released before acquiring scheduler for task wake.
- `BOOTSTRAP_PRINCIPAL` — written once at boot, read-only thereafter. Not part of the lock hierarchy.
- `AUDIT_RING` — acquired by `drain_tick()` (try_lock from BSP ISR, holds no other lock) and by `SYS_AUDIT_ATTACH`/`SYS_AUDIT_INFO` handlers (two-phase protocol: never held while PROCESS_TABLE or FRAME_ALLOCATOR is held). `audit::emit()` never touches it.
- `PER_CPU_AUDIT_BUFFER[cpu]` — lock-free SPSC; no lock at all. Written by local CPU, drained by BSP.

## Multi-Platform Strategy (x86_64, AArch64, RISC-V)

CambiOS runs on **x86_64** and **AArch64** today, with **riscv64gc** in progress (Phase R-0 build infrastructure done; Phase R-1+ implements the arch backend per [ADR-013](docs/adr/013-riscv64-architecture-support.md)). The architecture abstraction is in place:

### Current Portability Boundary
- `src/arch/mod.rs` — cfg-gated shim that re-exports the active backend
- `src/arch/x86_64/` — all x86-specific code lives here (GDT, SYSCALL/SYSRET, ISR stubs)
- `src/arch/spinlock.rs` — portable spinlock (already arch-independent)
- `src/scheduler/mod.rs` — portable `on_timer_isr()` + `ContextSwitchHint` (no arch dependency)
- `src/scheduler/task.rs`, `timer.rs` — portable (no arch dependency)
- `src/ipc/`, `src/syscalls/mod.rs`, `src/process.rs` — fully portable
- `src/memory/buddy_allocator.rs`, `frame_allocator.rs` — portable (address-space agnostic)

### Arch-Specific Parity Status
| x86_64 Module | Responsibility | AArch64 Status | RISC-V Status |
|---|---|---|---|
| `arch/x86_64/gdt.rs` | GDT + TSS + segment selectors | Done — `arch/aarch64/mod.rs::gdt` shim (EL1/EL0 config, `set_kernel_stack` via TPIDR_EL1) | Phase R-3 — `gdt` shim (no segments; `set_kernel_stack` via PerCpu through `tp` register) |
| `arch/x86_64/syscall.rs` | SYSCALL/SYSRET via MSRs | Done — SVC instruction + ESR_EL1 routing in `sync_el0_stub` | Phase R-3/R-4 — `ecall` instruction + `scause==8` dispatch in unified trap handler; `stvec` install |
| `arch/x86_64/mod.rs` | SavedContext, context_switch, timer ISR, yield_save_and_switch | Done — full assembly: context_save/restore/switch, timer_isr_stub, yield_save_and_switch + yield_inner | Phase R-3 — single trap vector at `stvec`, `scause`-dispatched, sscratch/tp swap on U→S, callee-saved context_switch |
| `interrupts/mod.rs` | x86 IDT setup | Done — AArch64 exception vector table at VBAR_EL1 | Phase R-3 — single S-mode trap vector at `stvec`, scause-dispatched |
| `arch/x86_64/apic.rs` | Local APIC timer + PIC disable + IPI | Done — GICv3 (gic.rs) + ARM Generic Timer (timer.rs) | Phase R-3 — SBI `sbi_set_timer` (no chip driver); SBI `sbi_send_ipi` for IPI |
| `arch/x86_64/tlb.rs` | TLB shootdown via IPI | Done — TLBI broadcast instructions (tlb.rs) | Phase R-3 (local) / Phase R-5 (remote) — `sfence.vma` local; SBI IPI + remote `sfence.vma` (or Svinval `sinval.vma` if available) |
| `interrupts/pic.rs` | 8259 PIC (disabled, legacy) | N/A (no legacy PIC on ARM) | N/A |
| `interrupts/pit.rs` | 8254 PIT (calibration only) | N/A (ARM Generic Timer is direct, no calibration needed) | N/A (timer base frequency comes from DTB `/cpus/timebase-frequency`) |
| `memory/paging.rs` | x86_64 4-level page tables | Done — AArch64 4-level page tables in `memory/mod.rs` | Phase R-2 — Sv48 4-level page tables in shared `memory/mod.rs` paging module (already `#[cfg(not(target_arch = "x86_64"))]` — auto-includes RISC-V; only PTE bit constants differ from AArch64 descriptors) |
| `io/mod.rs` | uart_16550 (x86 port I/O) | Done — PL011 UART (MMIO) | Phase R-1 — NS16550 UART (MMIO at `0x10000000` on QEMU virt; address discovered from DTB on real hardware) |
| `platform/mod.rs` | CR4 feature detection | Done — MIDR_EL1 CPU identification, arch-specific features | Phase R-4 — `misa` CSR for ISA extensions; CPU info from DTB (most M-mode IDs are not S-mode-readable) |
| `arch/x86_64/ioapic.rs` | I/O APIC device IRQ routing | **Gap** — GIC SPI enable exists but not wired into boot path | Phase R-3 — PLIC driver (`arch/riscv64/plic.rs`); `claim()`/`complete()` in trap handler when `scause` indicates external interrupt |
| `arch/x86_64/percpu.rs` | Per-CPU data via GS base | Done — `arch/aarch64/percpu.rs` via TPIDR_EL1 | Phase R-1 — `arch/riscv64/percpu.rs` via `tp` register; `csrrw tp, sscratch, tp` swap on trap entry (analogous to x86 swapgs) |
| **boot adapter** | `boot::limine::populate()` (x86_64 + AArch64) | Same Limine adapter | Phase R-1 — `boot::riscv::populate(dtb_phys)` reads DTB, populates BootInfo, no Limine |

### Rules for New Code
- **Never put arch-specific code in portable modules.** If it touches registers, instructions, or hardware directly, it goes under `src/arch/<target>/`.
- **New arch backends must match the public API** defined by `src/arch/x86_64/mod.rs`: `SavedContext`, `context_switch()`, `timer_isr_inner()`, etc.
- **The AArch64 target triple is `aarch64-unknown-none`** with `linker-aarch64.ld` (`elf64-littleaarch64`).
- **The RISC-V target triple is `riscv64gc-unknown-none-elf`** with `linker-riscv64.ld` (`elf64-littleriscv`). Code model must be `medium` — `medlow` cannot reach the higher-half kernel.
- **Keep the interrupt subsystem portable where possible.** `interrupts/routing.rs` is already arch-independent. The PIC/PIT modules should move under `arch/x86_64/` eventually.
- **Bootloader:**
  - x86_64 / AArch64 — Limine 8.7.0 (UEFI on both, plus BIOS on x86_64).
  - RISC-V — OpenSBI in M-mode (ships with QEMU as `-bios default`) hands a DTB pointer to a custom S-mode boot stub. No Limine on RISC-V (Limine does not support it). See [ADR-013](docs/adr/013-riscv64-architecture-support.md).
- **AArch64 MMIO must be explicitly mapped.** Limine's HHDM on AArch64 only covers RAM. Device MMIO (PL011, GIC) must be mapped into TTBR1 via `early_map_mmio()` at early boot.
- **RISC-V follows generic-first, never board-specific.** Use RISC-V standards (SBI, DTB, PLIC, CLINT, virtio-mmio); discover MMIO addresses from the DTB. No vendor-specific code paths in the core arch backend ([ADR-013](docs/adr/013-riscv64-architecture-support.md) § Strategic Posture).
- **Three-architecture cfg discipline.** Prefer `#[cfg(not(target_arch = "x86_64"))]` when AArch64 + RISC-V share behavior (e.g., the shared paging module). Use positive cfgs for all three only when behavior diverges. When a 3-way cfg block emerges in inline code, factor a portable `arch::` helper instead of carrying three inline arms.

## Platform Gotchas

These are persistent platform/bootloader quirks that any new code in the boot or hardware paths must respect. Status of *features* (what's built vs planned) lives in [STATUS.md](STATUS.md); this section is for things that won't go away.

- **Limine base revision 3 HHDM gap (x86_64):** ACPI_RECLAIMABLE, ACPI_NVS, and RESERVED regions are NOT in the HHDM. `map_acpi_regions()` in `main.rs` explicitly maps small RESERVED regions (≤1MB) and all ACPI regions into the HHDM before ACPI parsing. SeaBIOS puts ACPI tables in RESERVED memory (not ACPI_RECLAIMABLE), so the RESERVED mapping is essential.
- **Limine AArch64 HHDM does NOT map device MMIO.** PL011 UART (0x0900_0000), GIC Distributor (0x0800_0000), and GIC Redistributor (0x080A_0000) must be explicitly mapped into TTBR1 via `early_map_mmio()` before any I/O. Uses bootstrap frames from kernel .bss (physical address found by walking TTBR1 page tables, since kernel statics are NOT in HHDM).
- **Limine AArch64 TCR_EL1.T1SZ too narrow.** Limine sets T1SZ for ~39-bit VA, but HHDM at `0xFFFF000000000000` needs 48-bit. `kmain` widens T1SZ to 16 (48-bit) at early boot.
- **AArch64 QEMU requires GICv3.** Must use `-machine virt,gic-version=3` because the GIC driver uses ICC system registers (GICv3). Default GICv2 causes Undefined Instruction on `mrs ICC_SRE_EL1`.
- **ELF loader doesn't merge overlapping segment permissions.** If two PT_LOAD segments share a page with different permissions (e.g., .text RX and .got RW), the first segment's permissions are used. User-space linker scripts work around this with `ALIGN(4096)` before `.data`. Loader fix is tracked in [STATUS.md](STATUS.md).
- **`SYS_WAIT_IRQ` unregistered-IRQ wake fallback.** Registered device IRQs use targeted single-CPU wake via `TASK_CPU_MAP`. Unregistered IRQs fall back to all-CPU scan with `try_lock()` — if SCHEDULER lock is contended, wake is deferred to the next timer tick. Acceptable; not a bug.

## Required Reading by Subsystem

When working on a subsystem, read its design and implementation docs *before* writing code. This map exists so context doesn't get forgotten between sessions. If a doc is missing from the list it means the subsystem is small enough that the code is the documentation.

| Working on... | Read first | Then |
|---|---|---|
| **Scheduler / context switch / preemption** | [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) | This file's [Lock Ordering](#lock-ordering) and "Timer / Preemptive Scheduling" sections |
| **IPC control path (256-byte messages)** | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) | `src/ipc/mod.rs`, `src/ipc/interceptor.rs` |
| **IPC bulk path (channels — Phase 3)** | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) (channels are the audit transport) |
| **Capabilities, grant/revoke, delegation** | [ADR-000](docs/adr/000-zta-and-cap.md), [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) | `src/ipc/capability.rs` |
| **Process tables / tier configuration / boot-time object sizing** | [ADR-008](docs/adr/008-boot-time-sized-object-tables.md), [ADR-009](docs/adr/009-purpose-tiers-scope.md) | `src/process.rs`, `src/ipc/capability.rs`, [ASSUMPTIONS.md § Tier policies](docs/ASSUMPTIONS.md) |
| **Policy / `on_syscall` / interceptor decisions** | [ADR-006](docs/adr/006-policy-service.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) ([§ Divergence](docs/adr/002-three-layer-enforcement-pipeline.md#divergence): interceptor moved from `Box<dyn IpcInterceptor>` to `IpcInterceptorBackend` enum-dispatch shim — same precedent as ADR-003 for `OBJECT_STORE`) | `src/ipc/interceptor.rs` (trait + `IpcInterceptorBackend` enum), `src/ipc/mod.rs` (`IpcManager.interceptor` and `ShardedIpcManager.interceptor` field sites) |
| **Audit infrastructure / observability** | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md), [PHILOSOPHY.md](docs/PHILOSOPHY.md) | `src/audit/mod.rs`, `src/audit/buffer.rs`, `src/audit/drain.rs` |
| **Identity / Principal / sender_principal** | [identity.md](docs/identity.md), [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) | [FS-and-ID-design-plan.md](docs/FS-and-ID-design-plan.md) (intent only) |
| **ObjectStore / CambiObject / fs-service** | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md), [ADR-004](docs/adr/004-cryptographic-integrity.md) | `src/fs/mod.rs`, `src/fs/ram.rs`, `user/fs-service/src/main.rs` |
| **Persistent ObjectStore / on-disk format / BlockDevice** | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) | `src/fs/block.rs`, `src/fs/disk.rs`; [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) for the `CambiObject` model the format serializes |
| **Signed ELF loading / cryptographic integrity** | [ADR-004](docs/adr/004-cryptographic-integrity.md) | `src/loader/mod.rs` (`SignedBinaryVerifier`) |
| **User-space services (any new boot module)** | [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) | `user/libsys/src/lib.rs`, an existing service like `user/udp-stack/src/main.rs` as template |
| **Architecture port (RISC-V — in progress, future archs)** | [ADR-013](docs/adr/013-riscv64-architecture-support.md), this file's "Multi-Platform Strategy" section, plan file at `/Users/jasonricca/.claude/plans/melodic-tumbling-muffin.md` | `src/arch/aarch64/mod.rs` as the closest structural reference (single trap vector, `scause`-style dispatch, callee-saved context_switch); `src/boot/mod.rs` for the BootInfo contract a new boot adapter must satisfy |
| **Graphics / compositor / GUI / GPU driver** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) (stack design), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) (compositor ↔ scanout-driver protocol, incl. § Divergence for 4.a/4.b landing notes: kernel-side virtio-modern cap parsing via `SYS_VIRTIO_MODERN_CAPS = 38`, deliberate double-copy frame path, `-vga virtio` QEMU shape) | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) (channels are the surface-buffer transport); through Scanout-4.b: `user/compositor` (endpoint 28), `user/scanout-virtio-gpu` as default x86_64 driver (endpoint 27, modern virtio-pci, 5 2D ops — CREATE_2D / ATTACH_BACKING / SET_SCANOUT / TRANSFER_TO_HOST_2D / RESOURCE_FLUSH), `user/scanout-limine` kept buildable as non-virtio-gpu fallback. Intel scanout + aarch64 / riscv64 virtio-gpu deferred to 4.c+. |
| **GUI client library (user/libgui v0)** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) (stack design — libgui is the in-process widget layer; v0 is drawing primitives only, widgets deferred) | `user/libgui-proto/src/lib.rs` (wire format that libgui wraps); `user/hello-window/src/main.rs` (canonical client — every libgui primitive is exercised on-screen); `user/libgui/src/{surface,font,tile_grid,client,bitmap}.rs`. No new kernel syscalls — drawing is CPU writes into the attached surface channel. `Client::open` performs the CreateWindow/WelcomeClient/channel_attach handshake. `Surface::draw_line`, `fill_rect`, `draw_text_builtin`, `blit_bitmap`. `TileGrid` for grid geometry (`hit_test` deferred to the virtio-input session — don't add it here without a consumer). |
| **Input drivers / Input Hub / event wire format / trust tiers** | [ADR-012](docs/adr/012-input-architecture-and-device-classes.md) (incl. § Divergence for the Input-0 / Input-1 landing: virtio-input-first, `COMPOSITOR_INPUT_ENDPOINT = 30`, "first live window" focus) | `user/libinput-proto/src/lib.rs` (96-byte wire format + class payloads + modifier/button bitfields), `user/virtio-input/` (first driver — `main.rs` event loop + `transport.rs` reused-from-scanout-virtio-gpu + `virtqueue.rs` device-writable event pool + `evdev.rs` evdev→HID table), `user/compositor/src/main.rs` (`pump_input_once` — driver events → focused window via libgui-proto `MsgTag::InputEvent = 0x4030`), `user/libgui/src/client.rs` (`Client::poll_event`). Hub deferred (Input-2 trigger: second input-consuming client, or signed-carrier hardware). `signature_block` reserved in every event from day one — signed-carrier (ADR-012 Input-5) lands without format revision. |
| **Security review / threat model** | [SECURITY.md](docs/SECURITY.md), [ADR-000](docs/adr/000-zta-and-cap.md), [PHILOSOPHY.md](docs/PHILOSOPHY.md) | All ADRs |
| **"Is X done yet?" / current state** | [STATUS.md](STATUS.md) | — |

## Design Documents

These documents capture architectural decisions that implementation must align with. Pure intent goes in the design docs and ADRs; current implementation status goes in [STATUS.md](STATUS.md).

- **[CambiOS.md](docs/CambiOS.md)** — Source-of-truth architecture document (vision, principles, what CambiOS *is*).
- **[identity.md](docs/identity.md)** — Identity architecture: what identity means in CambiOS, Ed25519 Principals, author/owner model, biometric commitment, did:key DID method, revocation model.
- **[FS-and-ID-design-plan.md](docs/FS-and-ID-design-plan.md)** — Phase intent for identity + storage. Content-addressed ObjectStore, CambiObject model, bootstrap identity, IPC sender_principal stamping. Flows from identity.md.
- **[win-compat.md](docs/win-compat.md)** — Windows compatibility layer design: sandboxed PE loader, AI-translated Win32 shim tiers, virtual registry/filesystem, sandboxed Principal model, target application phases (business → CAD → instrumentation).
- **[PHILOSOPHY.md](docs/PHILOSOPHY.md)** — Why CambiOS exists, the AI-watches-not-decides stance, the verification-first commitment.
- **[SECURITY.md](docs/SECURITY.md)** — Security posture, enforcement table, threat model.
- **[ASSUMPTIONS.md](docs/ASSUMPTIONS.md)** — Catalog of every numeric bound in kernel code with category (SCAFFOLDING / ARCHITECTURAL / HARDWARE / TUNING) and replacement criteria. Anti-drift mechanism for bounds chosen for verification ergonomics.
- **[GOVERNANCE.md](docs/GOVERNANCE.md)** — Project governance, deployment tiers, and scope boundaries. Companion to [ADR-009](docs/adr/009-purpose-tiers-scope.md).
- **[docs/adr/](docs/adr/)** — Architecture decision records. Read the ones in the Required Reading map for the subsystem you're touching. (Run `ls docs/adr/` for the current set; do not cite a range here — it drifts.)

Any work on identity, storage, filesystem, IPC architecture, capabilities, policy, or telemetry must be consistent with these documents. If implementation reveals a design problem, update the design doc *first* — don't silently diverge.

## Roadmap

What's built, what's in progress, what's planned (including v1 ordering, phase markers, and known issues) all live in **[STATUS.md](STATUS.md)**. Architectural decisions live in the ADRs under [docs/adr/](docs/adr/). This file contains neither — it's the technical reference.

## Verification Strategy

- Trait-based abstractions for property-based verification
- Explicit state tracking via enums (TaskState, etc.)
- Error handling via Result types throughout
- BuddyAllocator is pure bookkeeping (address-space agnostic) for testability
- Unit tests run on host macOS target (`x86_64-apple-darwin`); run `make stats` or `make test` for the current count. [STATUS.md](STATUS.md) tracks per-subsystem coverage — do not enumerate categories here (they drift).

---

# Deep Reference

The sections below are consulted less often than the operational protocols above. They describe the *state of the kernel* (directory layout, tables, bitfield offsets, per-syscall behavior). Read them when you need the specific fact; the operational rules above outrank them when they conflict.

## Project Overview

CambiOS is a verification-ready microkernel OS written in Rust (`no_std`) targeting **x86_64**, **AArch64**, and **riscv64gc** (Phase R-0 done; full backend in progress per [ADR-013](docs/adr/013-riscv64-architecture-support.md)). It boots via the Limine v8.x protocol on x86_64 and AArch64; via OpenSBI + custom S-mode stub on RISC-V. Preemptive multitasking with ring 3 (x86), EL0 (AArch64), or U-mode (RISC-V) user tasks.

**Current state:** see [STATUS.md](STATUS.md) — the canonical source for what is built, in progress, and planned, including test counts, subsystem status, phase markers, v1 roadmap progress, and known issues. **This file (CLAUDE.md) is the technical reference for the kernel** — conventions, rules, lock ordering, build commands, required-reading map. Do not duplicate status info here, to avoid drift.

## Toolchain

- Rust nightly (see `rust-toolchain.toml`)
- Default target: `x86_64-unknown-none` (set in `.cargo/config.toml`)
- AArch64 target: `aarch64-unknown-none` (pass `--target aarch64-unknown-none` explicitly)
- Linker scripts: `linker.ld` (x86_64, `elf64-x86-64`), `linker-aarch64.ld` (AArch64, `elf64-littleaarch64`)
- Bootloader: Limine v8.7.0 (binary branch cloned to `/tmp/limine`)
- Dependencies: `x86_64` 0.14, `uart_16550` 0.3, `bitflags` 2.3, `limine` 0.5, `blake3` 1.8 (no_std, pure), `ed25519-compact` 2.2 (no_std)
- Sign-elf tool deps: `ed25519-compact` 2.2, `openpgp-card` 0.6, `card-backend-pcsc` 0.5, `secrecy` 0.10 (YubiKey OpenPGP interface)

## Architecture (directory layout)

### Build-time configuration (`build.rs`)

```
build.rs                      # Reads CAMBIOS_TIER env var (default: tier3),
                              # emits --cfg tierN for src/config/tier.rs to
                              # select the compiled-in TableSizingPolicy.
                              # See ADR-008 and ADR-009.
```

### Kernel (`src/`)

```
src/
├── lib.rs                    # Crate root, global statics, init, halt
├── process.rs                # ProcessTable, ProcessDescriptor, VmaTracker (Phase 3.2a: slice-backed; Phase 3.2c: generation counters, slot allocator)
├── boot_modules.rs           # Boot module registry (name → physical range)
├── acpi/
│   └── mod.rs                # ACPI table parser (RSDP, XSDT, MADT)
├── config/
│   ├── mod.rs                # Build-time configuration re-exports
│   └── tier.rs               # TableSizingPolicy, TIER{1,2,3}_POLICY, num_slots_from, binding_constraint_for (Phase 3.2a)
├── arch/
│   ├── mod.rs                # cfg-gated architecture shim (re-exports active backend)
│   ├── spinlock.rs           # Spinlock + IrqSpinlock (interrupt-disabling)
│   ├── x86_64/
│   │   ├── mod.rs            # SavedContext, context_switch, timer_isr_inner, yield_save_and_switch
│   │   ├── apic.rs           # Local APIC driver (timer, EOI, PIC disable, IPI primitives)
│   │   ├── gdt.rs            # Per-CPU GDT + TSS + IST (SMP-ready)
│   │   ├── ioapic.rs         # I/O APIC driver (device IRQ routing)
│   │   ├── msr.rs            # Shared rdmsr/wrmsr wrappers used by apic/percpu/syscall
│   │   ├── percpu.rs         # Per-CPU data (GS base), PerCpu struct
│   │   ├── portio.rs         # Safe wrappers around in/out port I/O (Port8/16/32)
│   │   ├── syscall.rs        # SYSCALL/SYSRET MSR init + kernel-stack entry stub
│   │   └── tlb.rs            # TLB shootdown via IPI (vector 0xFE)
│   └── aarch64/
│       ├── mod.rs            # SavedContext, context_switch, timer_isr_inner (asm), yield_save_and_switch
│       ├── gic.rs            # GICv3 driver (Distributor, Redistributor, ICC sysregs)
│       ├── percpu.rs         # Per-CPU data (TPIDR_EL1), PerCpu struct
│       ├── syscall.rs        # SVC entry stub + VBAR_EL1 init
│       ├── timer.rs          # ARM Generic Timer (CNTP_TVAL_EL0, 100 Hz)
│       └── tlb.rs            # TLB shootdown via TLBI broadcast instructions
├── audit/
│   ├── mod.rs                # AuditEventKind (16 variants), RawAuditEvent (64-byte wire format), emit(), builder constructors, sampling config (Phase 3.3)
│   ├── buffer.rs             # StagingBuffer: lock-free SPSC ring buffer (per-CPU, formally verifiable)
│   └── drain.rs              # AuditRing (global ring buffer, HHDM-backed), drain_tick() (BSP timer ISR piggyback)
├── fs/
│   ├── mod.rs                # CambiObject, ObjectStore trait (by-value get, &mut self), Blake3 hashing, Ed25519 sign/verify
│   ├── block.rs              # BlockDevice trait (4 KiB sectors), MemBlockDevice (testing)
│   ├── disk.rs               # DiskObjectStore<B: BlockDevice> (Phase 4a.i, ADR-010 on-disk format)
│   ├── lazy_disk.rs          # LazyDiskStore — deferred-init wrapper, OBJECT_STORE backing (Phase 4a.iii)
│   ├── virtio_blk_device.rs  # VirtioBlkDevice: BlockDevice — kernel IPC client to user/virtio-blk driver (Phase 4a.iii)
│   └── ram.rs                # RamObjectStore (fixed-capacity 256 objects, Phase 0 fallback)
├── interrupts/
│   ├── mod.rs                # IDT setup, exception/device ISR handlers
│   ├── pic.rs                # 8259 PIC driver (disabled at boot, x86_64 only)
│   ├── pit.rs                # 8254 PIT (APIC calibration only, x86_64 only)
│   └── routing.rs            # IRQ → driver task routing table (portable)
├── io/
│   └── mod.rs                # Serial output (uart_16550 / PL011), print!/println! macros
├── ipc/
│   ├── mod.rs                # IPC: Principal, EndpointQueue, SyncChannel, IpcManager, ShardedIpcManager
│   ├── capability.rs         # Capability-based security + Principal binding
│   ├── channel.rs            # Shared-memory data channels (Phase 3.2d, ADR-005)
│   └── interceptor.rs        # Zero-trust IPC interceptor (policy enforcement)
├── loader/
│   ├── mod.rs                # ELF process loader + verify-before-execute gate + SignedBinaryVerifier
│   └── elf.rs                # ELF64 header/program header parser
├── memory/
│   ├── mod.rs                # Memory subsystem init + AArch64 paging (L0-L3, early_map_mmio)
│   ├── buddy_allocator.rs    # Pure bookkeeping buddy allocator
│   ├── frame_allocator.rs    # Bitmap-based physical frame allocator (covers 0–2 GiB) + per-CPU FrameCache + allocate_contiguous / free_contiguous
│   ├── heap.rs               # Kernel heap allocator (linked-list, GlobalAlloc)
│   ├── object_table.rs       # Kernel object table region allocator (Phase 3.2a, ADR-008)
│   └── paging.rs             # x86_64 page table management (OffsetPageTable)
├── microkernel/
│   └── main.rs               # Kernel entry point, all subsystem init
├── pci/
│   └── mod.rs                # PCI bus scan (bus 0), device table, BAR decoding, port validation
├── platform/
│   └── mod.rs                # Platform abstraction, CR4/CPU feature detection
├── scheduler/
│   ├── mod.rs                # Priority-band scheduler with per-band VecDeque, on_timer_isr()
│   ├── task.rs               # Task/TaskState/CpuContext definitions
│   └── timer.rs              # Timer tick management
└── syscalls/
    ├── mod.rs                # SyscallNumber enum, SyscallArgs
    ├── dispatcher.rs         # Syscall dispatch + handlers
    └── userspace.rs          # Stub userspace syscall wrappers
```

### User-space services (`user/`)

```
user/
├── user.ld                   # x86_64 user-space linker script (base 0x400000)
├── user-aarch64.ld           # AArch64 user-space linker script
├── hello.S                   # Test module (prints 3x, exits) — boot module
├── libsys/                   # Shared syscall wrapper library — only unsafe user-space crate
│   └── src/lib.rs            # Safe wrappers over x86_64 SYSCALL and AArch64 SVC; Principal, VerifiedMessage, recv_verified (load-bearing identity types)
├── fs-service/               # Filesystem service — boot module, IPC endpoint 16
│   └── src/main.rs           # ObjectStore gateway (sender_principal enforcement)
├── key-store-service/        # Key store service (Ed25519 signing) — boot module, IPC endpoint 17
│   └── src/main.rs           # Claims bootstrap key at boot, signs ObjectStore puts
├── virtio-net/               # Virtio-net driver — boot module, IPC endpoint 20
│   └── src/                  # main.rs + transport.rs, virtqueue.rs, device.rs, pci.rs
├── virtio-blk/               # Virtio-blk driver — boot module (Phase 4a.ii/4a.iii)
│   └── src/                  # main.rs + transport.rs, virtqueue.rs, device.rs, pci.rs
│                             # endpoint 24 = user clients (recv_verified)
│                             # endpoint 26 = kernel-only commands (recv_msg, no cap check)
│                             # endpoint 25 = kernel's reply endpoint (handle_write intercept)
├── i219-net/                 # Intel I219-LM driver — boot module (Dell 3630 bare metal)
│   └── src/                  # main.rs + mmio.rs, pci.rs, phy.rs, regs.rs, ring.rs
├── udp-stack/                # UDP/IP network service — boot module, IPC endpoint 21
│   └── src/main.rs           # ARP, IPv4, UDP, NTP demo
└── shell/                    # Interactive serial shell — boot module
    └── src/main.rs           # Command parsing over ConsoleRead
```

### Host-side tools (`tools/`)

```
tools/
└── sign-elf/                 # Ed25519 ELF signing tool (YubiKey or seed) — produces ARCSIG trailer
    └── src/main.rs
```

## Key Technical Details

### GDT Layout (7 entries per CPU, replaces Limine's at boot)
| Index | Offset | Description | Selector |
|-------|--------|-------------|----------|
| 0 | 0x00 | Null | — |
| 1 | 0x08 | Kernel Code 64-bit DPL=0 | KERNEL_CS=0x08 |
| 2 | 0x10 | Kernel Data 64-bit DPL=0 | KERNEL_SS=0x10 |
| 3 | 0x18 | User Data 64-bit DPL=3 | USER_SS=0x1B |
| 4 | 0x20 | User Code 64-bit DPL=3 | USER_CS=0x23 |
| 5 | 0x28 | TSS low | TSS_SELECTOR=0x28 |
| 6 | 0x30 | TSS high | — |

User data before user code is **required** by SYSRET selector computation.

### SYSCALL/SYSRET
- STAR MSR: bits[47:32]=0x08 (kernel CS), bits[63:48]=0x10 (user base)
- SFMASK=0x200 (clears IF on syscall entry)
- Entry point in `src/arch/x86_64/syscall.rs`
- **Kernel stack switch on entry:** `syscall_entry` saves user RSP to `gs:[32]` (PerCpu.user_rsp_scratch), loads kernel RSP from `gs:[24]` (PerCpu.kernel_rsp0), pushes user RSP onto kernel stack. Return path: `cli`, restore regs, `pop rsp`, `sysretq`.
- **Interrupts enabled in handlers:** `sti` after kernel stack switch, `cli` before return. Syscall handlers are preemptible by the timer ISR.
- `PerCpu.kernel_rsp0` updated by `set_kernel_stack()` on every context switch (timer ISR + yield_save_and_switch).

### Memory Layout
- **Kernel heap:** 4MB at HHDM+physical, initialized from Limine memory map
- **Boot stack:** 256KB via Limine StackSizeRequest
- **Kernel object table region (Phase 3.2a):** contiguous physical region allocated at boot via `FrameAllocator::allocate_contiguous`, HHDM-mapped, holds two page-aligned subregions — `[Option<ProcessDescriptor>; num_slots]` and `[Option<ProcessCapabilities>; num_slots]`. Size is determined by `config::num_slots()` × (`size_of::<Option<ProcessDescriptor>>() + size_of::<Option<ProcessCapabilities>>()`), rounded up per subregion to a page boundary. Allocated in `init_kernel_object_tables()` in `main.rs` between frame allocator init and GDT setup. See [ADR-008](docs/adr/008-boot-time-sized-object-tables.md) and `src/memory/object_table.rs`.
- **Per-process heaps (Phase 3.2a):** each process gets a `HEAP_SIZE` (1 MiB) contiguous physical region, allocated on demand in `ProcessDescriptor::new` via `FrameAllocator::allocate_contiguous(HEAP_PAGES)` and freed in `handle_exit` via `free_contiguous`. No more `PROCESS_HEAP_BASE + pid * HEAP_SIZE` arithmetic — the physical base is whatever the frame allocator hands out. Kernel still accesses the heap via HHDM (`virt_base = phys_base + hhdm_offset`).
- **User code:** mapped at 0x400000
- **User stack:** top at 0x800000, 64KB (16 pages), grows down
- **Per-process PML4:** kernel half cloned (entries 256..511)
- **HHDM:** Higher Half Direct Map provided by Limine for physical memory access
- **x86_64 HHDM:** `0xFFFF800000000000`
- **AArch64 HHDM:** `0xFFFF000000000000` (QEMU virt RAM starts at 1 GiB)
- **Frame allocator:** bitmap covers 0-2 GiB physical (524288 frames, 64 KB bitmap in .bss)

### Timer / Preemptive Scheduling
- **APIC timer** at 100Hz (periodic mode, PIT-calibrated), fires on vector 32
- **I/O APIC** routes device IRQs (keyboard, serial, IDE) on vectors 33-56
- Device ISRs: `x86-interrupt` ABI handlers, wake blocked tasks via `try_lock()` + EOI
- 8259 PIC disabled (remapped to 0xF0-0xFF, all lines masked)
- PIT used only for one-shot APIC timer calibration at boot
- Timer ISR: naked asm stub (`global_asm!` in `arch/mod.rs`) → Rust `timer_isr_inner`
- APIC EOI (`apic::write_eoi()`) replaces PIC EOI
- IST1 allocated for double-fault handler (4KB dedicated stack)
- Uses `try_lock()` to avoid deadlock when interrupted code holds a lock
- Portable `on_timer_isr()` + `ContextSwitchHint` pattern in `scheduler/mod.rs`
- **Voluntary context switch** via `yield_save_and_switch`: builds synthetic SavedContext (identical layout to timer ISR) on the kernel stack, calls `yield_inner` → `on_voluntary_yield` → `scheduler.voluntary_yield()`. No EOI (not a hardware interrupt). x86_64 (`arch/x86_64/mod.rs`): synthetic iretq frame, TSS/CR3 updates. AArch64 (`arch/aarch64/mod.rs`): synthetic eret frame, SP_EL0 via SPSel toggle, TTBR0_EL1/TLB updates. Used by handle_exit, handle_yield, handle_recv_msg (restart loop), handle_wait_irq.
- **Blocking pattern**: disable interrupts (`cli`/`msr daifset, #2`) → `block_task(Blocked)` → `yield_save_and_switch()` → re-check on wake. The interrupt disable before `block_task` prevents the timer ISR from seeing Blocked state before yield saves correct context.
- **IPI primitives** in `apic.rs`: `send_ipi()`, `send_ipi_all_excluding_self()`, `send_ipi_self()` via ICR
- **TLB shootdown** via vector 0xFE (`tlb.rs`): `shootdown_page()`, `shootdown_range()`, `shootdown_all()` — broadcast IPI, target CPUs execute `invlpg` or CR3 reload, initiating CPU spins on atomic pending counter
- **Cross-CPU task wake**: `TASK_CPU_MAP` (`[AtomicU16; 256]` in `lib.rs`) tracks task→CPU assignment (lock-free). `wake_task_on_cpu(TaskId)` reads the map and acquires the correct CPU's scheduler to wake. `block_local_task(TaskId, BlockReason)` uses `local_scheduler()`. All IPC helpers, ISR dispatch, and diagnostics use these instead of hardcoded `PER_CPU_SCHEDULER[0]`. `migrate_task_between()` updates the map atomically.
- **IPC reply-endpoint registry**: `REPLY_ENDPOINT` (`[AtomicU32; 256]` in `lib.rs`) stores the first endpoint each process registered via `SYS_REGISTER_ENDPOINT`. `handle_write` uses this as the `from` field of outgoing messages, so receivers doing `sys::write(msg.from_endpoint(), reply)` route replies back to a queue the sender is actually listening on. Falls back to pid-slot when a process has never registered. Landed in Phase 4b — before this fix, `from` was the sender's pid slot, which was always a different number from the registered endpoint, and any reply sent via `msg.from_endpoint()` went into a queue nobody read.

### Syscall Numbers

The canonical list is the `SyscallNumber` enum in [src/syscalls/mod.rs](src/syscalls/mod.rs) — that is the ABI. Run `make stats` for the current count. The per-syscall summaries below describe *behavior*, not *existence*; if you need the authoritative list of numbers, read the enum.

Handlers live in [src/syscalls/dispatcher.rs](src/syscalls/dispatcher.rs). Behavior summaries:
- **Exit**: Marks task as Terminated in scheduler and calls `CapabilityManager::revoke_all_for_process()` to reclaim endpoint capabilities (see [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md)); VMA / page-table / frame reclaim is still partial
- **Write**: Page-table-walk user buffer → IPC send (capability + interceptor checks, sender_principal stamped)
- **Read**: IPC recv (capability + interceptor checks) → page-table-walk write to user buffer
- **Allocate**: VMA tracker assigns virtual address, frame allocation + map into process page tables (with rollback on OOM)
- **Free**: VMA lookup → unmap pages → free frames back to allocator
- **WaitIrq**: Registers task as IRQ handler + blocks until IRQ fires
- **RegisterEndpoint**: Grants full capability on endpoint to calling process
- **Yield**: Sets task Ready + zeroes time slice for reschedule
- **GetPid / GetTime / Print**: Fully functional
- **BindPrincipal**: Binds a 32-byte Principal (public key) to a process. Restricted: only the bootstrap Principal can call this
- **GetPrincipal**: Returns the calling process's bound Principal (32 bytes)
- **RecvMsg**: Like Read but returns `[sender_principal:32][from_endpoint:4][payload:N]` — identity-aware receive. Blocks on `MessageWait(endpoint)` when no message is queued
- **TryRecvMsg** (Phase 4b): Non-blocking variant of RecvMsg — returns 0 immediately if empty, never blocks. Required for services that poll multiple endpoints (virtio-blk listens on ep24 + ep26; blocking on one would miss wakes on the other). `from_endpoint` is the sender's **reply endpoint** (first endpoint they registered), tracked in `REPLY_ENDPOINT` since Phase 4b — fixes a pre-existing bug where `from = pid_slot` caused replies to land on the wrong queue
- **ObjPut**: Store CambiObject with caller as author/owner, returns 32-byte content hash
- **ObjGet**: Retrieve object content by hash
- **ObjDelete**: Delete object (ownership enforced — only owner can delete)
- **ObjList**: List all object hashes (packed 32-byte hashes)
- **ClaimBootstrapKey**: One-shot: writes 64-byte bootstrap secret key to caller buffer, zeroes kernel copy. Restricted to bootstrap Principal
- **ObjPutSigned**: Like ObjPut but accepts pre-computed Ed25519 signature. Kernel verifies signature against caller's Principal before storing
- **MapMmio**: Maps device MMIO pages into process address space (uncacheable). Rejects addresses within RAM range. Returns user virtual address
- **AllocDma**: Allocates physically contiguous DMA pages with guard pages (unmapped before/after). Returns user vaddr; writes physical address to caller buffer
- **DeviceInfo**: Returns 108-byte PCI device descriptor by index (vendor/device ID, class, BARs with decoded addresses/sizes/types)
- **PortIo**: Kernel-validated port I/O on PCI device I/O BARs. Rejects ports not within a discovered PCI BAR. Supports byte/word/dword read/write
- **ConsoleRead**: Non-blocking read of bytes from the serial console into a user buffer
- **Spawn**: Create a new process from a named boot module; parent is the caller. Requires `CapabilityKind::CreateProcess` (Phase 3.2b, ADR-008); returns `PermissionDenied` without it
- **WaitTask**: Block until a named child task exits; returns the child's exit code
- **RevokeCapability**: Revoke a capability held by another process on an endpoint. Phase 3.1 authority = bootstrap Principal only; grantor / holder-of-`revoke`-right / policy service paths land in Phase 3.4. `CapabilityHandle` refactor deferred to post-v1 handle table. See [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md)
- **ChannelCreate**: Allocate a shared-memory channel. Creator specifies size (pages), peer Principal, and role (Producer/Consumer/Bidirectional). Requires `CreateChannel` system capability. Returns ChannelId; writes creator's vaddr to output pointer. See [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md)
- **ChannelAttach**: Attach to an existing channel as the named peer. Kernel verifies caller's Principal matches peer_principal from create. Maps shared pages into peer's address space with role-determined permissions (RO/RW). Returns vaddr
- **ChannelClose**: Gracefully close a channel. Unmaps from both processes, TLB shootdown, frees physical frames. Only creator or peer may call
- **ChannelRevoke**: Force-close a channel (bootstrap authority, Phase 3.1 pattern). Same teardown as close but no caller-identity check
- **ChannelInfo**: Read channel metadata (state, role, sizes, addresses, tick) into user buffer
- **AuditAttach**: Attach as the audit ring consumer. Maps kernel audit ring pages RO into caller's address space. Restricted to bootstrap Principal (Phase 3.3). Returns user vaddr
- **AuditInfo**: Read audit ring statistics (total produced, total dropped, capacity, consumer attached, per-CPU staging occupancy) into a 48-byte user buffer. Any process may call
- **MapFramebuffer**: Maps a Limine-reported framebuffer (selected by zero-based index) into the calling process and writes a 32-byte `FramebufferDescriptor` (vaddr + geometry + pixel format) to a caller buffer. Kernel holds the physical address; userspace never specifies it. Capability-gated (`MapFramebuffer`). Multi-monitor: call once per display. Phase GUI-0 (ADR-011)
- **ModuleReady**: Signals that a boot module has finished initialization (endpoint registration, etc.). Used by sequential boot-time module loading: kernel blocks the next module in `BOOT_MODULE_ORDER` behind a `BlockReason::BootGate` until the current module calls `ModuleReady`. Every boot module's `_start` calls `sys::module_ready()` after setup
