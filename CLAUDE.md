# CambiOS Microkernel — Claude Code Context

## Formal Verification (Non-Negotiable Constraint)

Every design decision in kernel code must keep future formal verification achievable:

- **Pure logic separated from effects.** Algorithms expressible as pure functions (e.g. BuddyAllocator) must be. Pure code is verifiable independently of hardware state.
- **Explicit state machines.** All state as enums with exhaustive match. No boolean flags standing in for state, no implicit state encoded across fields.
- **Result/Option everywhere in kernel paths.** No panics, no `unwrap()`, no `expect()` in non-test kernel code. Every failure is a typed error.
- **Bounded iteration.** Loop bounds must be statically knowable or asserted. Verifiers cannot reason about unbounded loops.
- **unsafe minimized and isolated.** Smallest possible scope, wrapped behind a safe abstraction boundary that can be audited and eventually replaced with a verified implementation.
- **No trait objects in kernel hot paths.** Monomorphized generics are statically analyzable; dynamic dispatch is not.
- **Invariants encoded in types, not comments.** Page-aligned → newtype. Non-empty region → empty case unrepresentable.
- **Separation of specification from implementation.** Identify preconditions, postconditions, invariants as type constraints where possible, documented contracts otherwise. These are the verification targets.

BuddyAllocator (pure bookkeeping, host-testable) is the template; new kernel components follow the pattern.

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

Before the first edit, stop and confirm when any of these apply. Questions beat wrong assumptions; "I don't know" is acceptable.

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
- **Pre-edit audit.** Before the first Edit/Write on any file per session (especially under parallel-thread development), run `make claude-preflight FILE=<path>` or `git diff <path>`. If the diff is non-empty and the changes aren't this session's, STOP — ask the user to commit them before proceeding, or pick a different file. File-scoped `git add <file>` does not protect against *within-file* multi-authorship, so the gate has to fire before the edit, not before the commit.

This list is not exhaustive. The rule: **when you are about to modify something the user would want to be consulted on before the first edit, stop before the first edit.**

## Commit Cadence

Commit at topic boundaries within a session, not at session end. Bisectable history + fallback point before risky work.

- **Commit when a discrete improvement is complete and green** (builds + tests pass). Don't bundle unrelated improvements into one commit — they lose attribution, bisectability, and rollback granularity.
- **Commit before starting risky work** (major restructures, cross-file refactors, ADR changes). The pre-work state is your fallback.
- **Don't let 50+ edits accumulate uncommitted.** Reviewing a single giant diff is harder than reviewing five focused ones; passphrase cost scales linearly but review cost scales superlinearly.
- **Split by logical boundary, not by file.** A small multi-file change is one commit; a large single-file change spanning multiple topics should be multiple commits if the edits are cleanly separable.
- **Never `git add .` or `git commit -a` without naming files.** Working-tree sweeps conflate unrelated work — if a parallel session has uncommitted edits, those will get swept into the commit message of whatever is landing. Stage by explicit filename.
- **Draft the commit body from `git diff --cached`, not from memory.** Every claim ("removes X", "renames Y") must match a line in the staged diff. Verification bullets ("grep returns nothing", "make check-all clean") must be run against the staged tree at drafting time, not recalled. Bodies written from memory drift ahead of what got staged.
- **Claude drafts; user executes.** Claude prepares `git add <files>` + commit message; user runs the commit to enter their PGP passphrase. Never bypass signing (`--no-gpg-sign`, `--no-verify`).

## Prompt-Shaping Changelog

Why each non-obvious rule exists. Format: `YYYY-MM-DD — change — reason/failure addressed`. Newest first.

- **2026-04-25** — Shipped option (b) too — pre-push edit-window gate. New `tools/log-claude-edit.py` records every `Edit` / `Write` / `NotebookEdit` Claude performs (via a PostToolUse hook in `.claude/settings.local.json`) into `.git/claude-edit-log/<session_id>.jsonl`. New `tools/check-edit-window.py` runs as a pre-push hook (new tracked `.githooks/pre-push`) and rejects pushes whose Claude-authored commits modify files that no recorded session ever edited — the catch-anything backstop for sweeps that bypass the commit-msg gate via `--no-verify`. Same gradual-rollout posture as (a): warn-but-pass when no edit log exists or `CLAUDE_PREFLIGHT_SESSION` is unset, so manual pushes and pre-adoption sessions stay unblocked. With (a) and (b) both in place, the working-tree-sweep ladder has reached its planned terminus: (a) catches at commit time, (b) catches at push time, both have explicit `--no-verify` bypasses for the rare case where the human knows better than the gate. If a 7th recurrence happens despite both, the next escalation is per-hunk provenance (every staged hunk recorded with the originating Edit/Write call's file+offset, verified at commit time), but that's a notably bigger build than (a)+(b) and shouldn't be pre-emptively designed.
- **2026-04-25** — Resolved the 2026-04-24 deferred decision in favor of option (a): sticky `claude-preflight`. `tools/claude-preflight.py` now records each invocation in `.git/claude-preflight/<session_id>.json` when `CLAUDE_PREFLIGHT_SESSION` is set. New `tools/check-preflight-discipline.py` runs as the second commit-msg hook (after H1) and rejects Claude-authored commits whose staged set contains any file from `initial_dirty_files` (snapshot taken on first preflight call this session) that was never preflighted by the session — the exact shape that produced the 6th recurrence. Gradual rollout: warn-but-pass when `CLAUDE_PREFLIGHT_SESSION` is unset, so manual commits and pre-adoption sessions are unblocked. Option (b) — pre-push gate diffing each Claude commit against the session's observed worktree edit window — remains queued as defense-in-depth; tracked in [`~/.claude/plans/threat-model-implementation.md`](../../.claude/plans/threat-model-implementation.md). If a 7th recurrence happens despite (a), implement (b) immediately; if not, ship (b) opportunistically when the Claude-Code PostToolUse hook config is being touched anyway.
- **2026-04-24** — 6th recurrence of the working-tree-sweep family. Claude session A's `Edit` on `src/syscalls/dispatcher.rs` (F2+F3 threat-model follow-ups per [docs/threat-model.md](docs/threat-model.md)) had no preflight `git diff` — violated the Stop-and-Ask "Pre-edit audit" bullet. Parallel session B had in-flight `[STOMP-PRE-LOAD]` diagnostic hunks in the same file tracking the lazy-spawn `saved_rsp` stomp. When B landed the real fix as `4d4a4ab` (`kernel/memory: fix lazy-spawn saved_rsp stomp via BuddyAllocator::init_at`), `git add src/syscalls/dispatcher.rs` swept A's F2+F3 hunks into that commit alongside B's own instrumentation; A's body attributed the work to B. H1 (2026-04-23) passed because the `Staged files:` block correctly listed `dispatcher.rs` — H1 verifies file-list correspondence, not per-hunk authorship. No mechanism change in this entry. **Deferred decision:** per-hunk provenance tooling. Two options — (a) strengthen `tools/claude-preflight.py` from informational (`exit 0` always) to sticky: record each FILE preflighted in per-session state, have the commit-msg hook reject commits whose staged files had foreign hunks at session start and were never preflighted by the committer; (b) a pre-push gate that diffs each Claude-authored commit against that session's observed worktree edit window. **Revisit when:** the 7th recurrence lands, or an option is chosen proactively — whichever comes first.
- **2026-04-23** — Added `.githooks/commit-msg` + `tools/check-claude-staged-files.py` (H1). Fifth recurrence of the working-tree-sweep family — c9e8e86 ("super-sprouty-o: new first-party crate scaffold") swept a parallel session's staged `user/shell/src/main.rs` (the `play` verb) into its own commit via `git add -A` / `git commit -a`. The commit body explicitly claimed "user/shell/src/main.rs (other thread) not staged" while the stat line showed it as `| 36 ++++++++`. The prior four mechanisms (prose rule, `check-banned-paths`, `check-index-isolation`, `claude-preflight`) were pre-commit advisories or cross-file lints that didn't inspect the body-against-diff correspondence. H1 closes that gap: every Claude-authored commit (detected via `Co-Authored-By: Claude` trailer) MUST include a `Staged files:` block listing every staged path; the commit-msg hook parses the block, runs `git diff --cached --name-only`, and rejects on any mismatch. Non-Claude commits pass through untouched. If this recurs despite H1, the next escalation is a post-commit or pre-push hook that verifies the signed-off-by chain against per-session provenance.
- **2026-04-22** — Added `make claude-preflight FILE=<path>` + `tools/claude-preflight.py` + Stop-and-Ask Gate bullet. Fourth recurrence of the working-tree-sweep family (precedents: `git commit -a` rule, commit-body-from-memory rule, `check-banned-paths` lint, `check-index-isolation` lint). This one was within-file multi-authorship: session A edited `Makefile` without running `git diff Makefile` first; session B had in-flight uncommitted hunks in the same file; file-scoped `git add Makefile` would have swept both into A's commit. The prior tooling catches cross-file working-tree noise (banned paths, STATUS.md + `*.rs`), but *within-file* multi-authorship slipped through because `git add <explicit-file>` looked like adequate hygiene. Mechanism per changelog convention — prose rule would have been a fifth attempt at the same behavior change. The script is informational only (exit 0 always); the gate is "editor reads NOTICE, distinguishes mine from not-mine." If this recurs despite the gate, escalate to a pre-commit hook that verifies every staged hunk's author-session matches the commit author.
- **2026-04-21** — Added `make check-banned-paths` lint + `tools/banned-paths.txt`; moved pre-commit hook to tracked `.githooks/pre-commit` + `make install-hooks`. Third recurrence of a prose-rule-fails-under-multi-clone-state pattern (precedents: `git commit -a` rule, commit-body-from-memory) — on third recurrence ship tooling, not a stronger rule. Secondary lesson: tracked hooks via `core.hooksPath` beat per-clone `cp` install for propagation across parallel sessions.
- **2026-04-21** — Fourth Kani proof crate landed (`verification/capability-proofs/`, 12 harnesses on `src/ipc/capability.rs`). Two generalizable lessons for kernel-code Kani targets: (1) `#[path]` on a nested module resolves from the nested module's **implicit directory**, not the declaring file's — include the kernel file flat at crate root under a private name, then `pub use` through a stub module mirroring the kernel layout. (2) Drop kernel-crate-graph tentacles via *existing* cfg gates (e.g. `--cfg fuzzing` flips a pre-existing `#[cfg(not(any(test, fuzzing)))]` branch) before carving a new `#[cfg(kani)]` ctor — strictly cheaper.
- **2026-04-21** — Third Kani proof crate (`verification/frame-proofs/`). Found two integer-overflow sites in `frame_allocator.rs` `add_region`/`reserve_region`, fixed with `saturating_add`. Lesson: *CBMC's budget scales poorly with allocator state × loop-iteration × symbolic-index combinations* — when a harness explodes, split the proof budget (one representative function fully symbolic, mechanical wrap-boundary cases covered by `#[test]` unit tests). Document intractable harnesses with a pointer to the unit-test regression gate.
- **2026-04-21** — Second Kani proof crate (`verification/elf-proofs/`). Found six integer-overflow sites in the ELF parser; fixed with `checked_add`/`checked_mul` → typed errors. Lesson: *running Kani on code written without verification intent typically finds real bugs* — parsers-on-untrusted-input are the high-yield target precisely because they weren't written verification-first. Worked-example shape for future proof landings: write proof → let Kani flag → pause → propose fix → land fix + proof together.
- **2026-04-21** — Added `make check-index-isolation` lint. Rejects commits where STATUS.md diff > 20 lines AND any `*.rs` staged. Reason: parallel Claude sessions collided on STATUS.md; lint codifies the split so small row updates can still bundle with code but structural rewrites commit alone. If a similar collision recurs on another shared index file (CLAUDE.md, docs/adr/INDEX.md), extend the lint rather than trusting prose.
- **2026-04-21** — Broke ADR append-only for [ADR-016](docs/adr/016-win-compat-api-ai-boundary.md) + [ADR-017](docs/adr/017-user-directed-cloud-inference.md) (full rewrite + slot reuse). Rule refined: *append-only Divergence for decisions that shipped code; full rewrite or slot reuse for decisions withdrawn whole before implementation consumed them.* Preserving history that was never acted on inverts the purpose of the discipline.
- **2026-04-20** — Commit Cadence rule: draft the commit body from `git diff --cached`, not from memory. Triggered by afc4b11 mis-fire where the body described Makefile cleanups that never staged. Fix is discipline-only: stage, read cached diff end-to-end while writing, verify every claim. If this fails a third time, escalate to a pre-commit hook that greps the message for paths not in the staged diff.
- **2026-04-19** — `make check-boot-panics` lint + empty baseline, enforcing ADR-021 Phase C. Scans boot-path init code for `.expect()/panic!()/unimplemented!()/todo!()`; runtime fault handlers out of scope. Per-site exemption `// BOOT_PANIC_OK: <reason>`.
- **2026-04-19** — `make check-assumptions` lint + baseline. Enforces Convention 8 by flagging numeric `const` without SCAFFOLDING/ARCHITECTURAL/HARDWARE/TUNING tag. Baseline absorbs ~290 pre-existing untagged consts; don't-grow-the-baseline gate.
- **2026-04-19** — Development Convention 9 (conscious deferrals) + `make check-deferrals` lint. Mirrors Convention 8's `Replace when:` template, extended from bounds to decisions/ADR prose/code comments via `Revisit when:`. Triggered by a stale ADR-021 forward reference that aged into a lie between commits.
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

**SCAFFOLDING bounds must be sized for the v1 endgame.** Extrapolation procedure + 25%-utilization rule: see [ASSUMPTIONS.md § Sizing SCAFFOLDING bounds](docs/ASSUMPTIONS.md#sizing-scaffolding-bounds-for-the-v1-endgame). Update the matching row in the same change; Step 8 of the Post-Change Review lists this.

`make check-assumptions` flags untagged numeric consts; baseline in `tools/check-assumptions-baseline.txt`; don't-grow-the-baseline gate.

9. **Every deferral is a conscious deferral.** TODO / placeholder / "eventually" / "when X lands" / forward ref without anchor must carry a **Revisit when:** line naming an **observable trigger**. Applies to code comments, ADR prose, doc citations, commit messages.

   **Valid triggers** (observable): named commit/subphase ("Revisit when R-6 lands"), workload threshold crossed ("when a second call-site appears"), subsystem landing ("when ADR file exists + check-adrs resolves"), measured metric ("when audit drop counter > 0").
   **Invalid triggers** (fail the rule): "later", "eventually", "in the future", "when that matters", "TBD". If you can't name an observable trigger, don't defer — decide now or escalate.

   Template:
   ```rust
   // Deferred: <one-line statement>
   // Why: <what info is missing, or why deferring is cheaper than deciding now>
   // Revisit when: <observable trigger>
   ```
   ADR prose variant: `> **Deferred decision.** <statement>. **Revisit when:** <trigger>.`

   `make check-deferrals` flags deferral tokens without adjacent triggers; baseline `tools/check-deferrals-baseline.txt`; don't-grow-the-baseline gate.

## Post-Change Review Protocol

**After any code change, before reporting the change complete, Read [docs/review-protocol.md](docs/review-protocol.md).** For subsystem-tier changes (see triage below) this is non-negotiable. The protocol file carries §1 (Build Verification bash block), §2–§7 (Safety / Lock Ordering / Portability / Memory / Security / Test checklists), and the §8 Documentation Sync category table. The scope-triage decision and the §8 concrete 8-item checklist stay here because they fire every change and are the parts most likely to be skipped.

### Scope triage (do this first)

- **Small change** — typo, comment prose, whitespace, unused-import removal, local variable rename, STATUS.md note, or documentation-only edit that doesn't touch invariants. Run only **§1 (Build Verification)** and the §8 checklist below. Skip §2–§7.
- **Subsystem change** — anything that touches a module's public API, an `unsafe` block, the lock hierarchy, the syscall ABI, the boot path, a kernel invariant, a cross-cutting concern, or an ADR-worthy decision. Run the **full protocol §1–§8**. This tier is where drift becomes load-bearing.

**When unsure, run the full protocol.** Over-auditing a small change costs minutes; under-auditing a subsystem change costs a deadlock the next maintainer has to debug. If the Stop-and-Ask Gate fired during planning, this is automatically a subsystem change.

### §8 Documentation Sync — concrete checklist for the change you just made

This 8-item checklist fires every change (both tiers). The category table it draws from (implementation_reference / decision_record / design / index rules) lives in [docs/review-protocol.md § 8](docs/review-protocol.md#8-documentation-sync--category-table).

1. Did this change modify a subsystem listed in [STATUS.md](STATUS.md)'s subsystem table? → Update its row and bump `last_synced_to_code:`.
2. Did this change move a phase forward (e.g., "Phase 3 in progress" → "Phase 3 done")? → Update the Phase markers table.
3. Did this change touch the scheduler? → Re-read [SCHEDULER.md](src/scheduler/SCHEDULER.md) and update if anything in it is now wrong.
4. Did this change introduce a new architectural decision? → Draft a new ADR. Don't bury the decision in code comments. Did this change diverge from an existing ADR's plan? → Append a `## Divergence` entry to that ADR documenting what changed and why.
5. Did this change add or rename a build command, lock, or syscall? → Update CLAUDE.md's Quick Reference / Lock Ordering / Syscall Numbers tables.
6. Did this change resolve a Platform Gotcha in CLAUDE.md or a Known Issue in STATUS.md? → Remove it from the gotcha list (don't leave a `~~strikethrough~~ FIXED` ghost).
7. Did this change cite a doc that doesn't exist yet? → Either create the doc or remove the citation.
8. Did this change add or modify a numeric `const`, fixed-size array, or `MAX_*` bound in kernel code? → Tag it with `SCAFFOLDING` / `ARCHITECTURAL` / `HARDWARE` / `TUNING` per Development Convention 8, and add or update the row in [ASSUMPTIONS.md](docs/ASSUMPTIONS.md). Unconscious bounds are not allowed.

## Common Failure Signatures

Observed symptom → likely root cause. The symptom rarely names the invariant it violated.

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

### Adding a new syscall

Seven places must change atomically. Canonical reference: `TryRecvMsg = 37` landing. Skipping any step produces a specific failure mode named below.

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

**Verification:** `cargo test --lib` + `make check-all`. **Flow-specific stop-and-ask:** syscall in exempt set? (default: no). New capability-check kind? (unread-subsystem gate on `src/ipc/capability.rs`). New arch backend helper? (all three arches).

## Quick Reference

```bash
# Kernel builds
cargo build --target x86_64-unknown-none [--release]
cargo build --target aarch64-unknown-none --release
cargo build --target riscv64gc-unknown-none-elf --release

# Tri-arch gate (MANDATORY before commits) — ADR-013 § Tri-Architecture Regression Discipline
make check-all        # x86_64 + aarch64 + riscv64 (permanent gate)
make check-stable     # x86_64 + aarch64 only (escape hatch for temporary backend breakage)

# Unit tests (host). `--lib` mandatory (microkernel binary can't link on macOS). RUST_MIN_STACK needed for buddy-allocator tests.
RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# Derived counts (syscalls, tests, LOC)
make stats

# Lints (all don't-grow-the-baseline gates; baselines in tools/check-*-baseline.txt)
make check-adrs              # ADR cross-refs + regenerate docs/adr/INDEX.md
make check-assumptions       # Convention 8 numeric-const tags
make check-deferrals         # Convention 9 Revisit-when triggers
make check-boot-panics       # ADR-021 Phase C — no panic!/expect/etc in boot init; exempt via `// BOOT_PANIC_OK: <reason>`
make check-banned-paths      # paths in tools/banned-paths.txt must not exist on disk
make check-index-isolation   # STATUS.md diff >20 lines + any .rs staged → reject
# Commit-msg hooks (Claude-authored commits only):
# 1. H1 (2026-04-23): `Staged files:` block must match `git diff --cached
#    --name-only`. Script: tools/check-claude-staged-files.py.
# 2. Sticky preflight (2026-04-25): rejects commits that stage a file
#    which was already dirty at the start of the current Claude session
#    AND was never preflighted. Catches the 6th-recurrence shape that H1
#    misses (within-file sweeps). Set `CLAUDE_PREFLIGHT_SESSION=<id>`
#    once per session to enable enforcement; warn-but-pass when unset.
#    Script: tools/check-preflight-discipline.py.
# Pre-push hook (Claude-authored commits only):
# 3. Edit-window gate (2026-04-25): rejects pushes whose Claude-authored
#    commits modify files no Claude session ever touched via Edit/Write/
#    NotebookEdit. Defense-in-depth on top of (2); catches anything that
#    bypassed commit-msg via `--no-verify`. Requires the PostToolUse hook
#    in .claude/settings.local.json (calls tools/log-claude-edit.py) plus
#    `CLAUDE_PREFLIGHT_SESSION`. Warn-but-pass without an edit log.
#    Scripts: tools/log-claude-edit.py + tools/check-edit-window.py.
# All run automatically when installed via `make install-hooks`.

# One-time per clone — installs .githooks/ via core.hooksPath
make install-hooks

# Tier-policy builds (ADR-008/009). CAMBIOS_TIER ∈ {tier1, tier2, tier3}; default tier3.
CAMBIOS_TIER=tier1 cargo build --target x86_64-unknown-none --release

# QEMU
make run                         # x86_64 (ISO, rebuilds kernel + modules)
make run-quiet                   # x86_64, filtered via tools/qemu-run-quiet.py; exit 0 = success sentinel (default `arcos> `), 1 = panic/exception, 2 = hang. Override with `make run-quiet SUCCESS="virtio-net ready" TIMEOUT=90` for pre-shell testing.
make run-aarch64                 # AArch64 (FAT image)
make run-riscv64                 # RISC-V (OpenSBI)
make iso                         # x86_64 ISO only
make img-aarch64                 # AArch64 FAT image only
make disk-img                    # 64 MiB raw backing for virtio-blk (idempotent; `make run` depends on it)

# Symbol index for AI-assisted navigation (read .symbols at session start)
make symbols

# Standalone builds
make fs-service                  # user/fs-service — separate crate, uses CARGO_ENCODED_RUSTFLAGS to override parent .cargo/config.toml
make sign-tool                   # tools/sign-elf — host-side, own .cargo/config.toml targeting aarch64-apple-darwin

# ELF signing (produces ARCSIG trailer)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf <elf-file>                                    # YubiKey (default)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --seed <hex> <elf-file>                       # seed (CI/test)
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --export-pubkey bootstrap_pubkey.bin          # one-time setup
./tools/sign-elf/target/aarch64-apple-darwin/release/sign-elf --print-pubkey
```

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

x86_64 + AArch64 shipping; riscv64gc in progress per [ADR-013](docs/adr/013-riscv64-architecture-support.md). Per-module parity status lives in [STATUS.md](STATUS.md).

### Portability Boundary (portable modules — no arch code)
`src/scheduler/`, `src/ipc/`, `src/syscalls/mod.rs`, `src/process.rs`, `src/memory/buddy_allocator.rs` + `frame_allocator.rs`, `src/arch/spinlock.rs`. All arch code lives under `src/arch/<target>/`; `src/arch/mod.rs` is the cfg-gated shim.

### Rules for New Code
- **Arch-specific code goes under `src/arch/<target>/`**, never in portable modules.
- **New arch backends match the public API** in `src/arch/x86_64/mod.rs` (`SavedContext`, `context_switch()`, `timer_isr_inner()`, etc.).
- **Targets:** aarch64 = `aarch64-unknown-none` + `linker-aarch64.ld`. riscv64 = `riscv64gc-unknown-none-elf` + `linker-riscv64.ld`; code model must be `medium` (`medlow` can't reach higher-half).
- **Interrupt subsystem portable where possible.** `interrupts/routing.rs` is arch-independent; PIC/PIT should eventually move under `arch/x86_64/`.
- **Bootloader:** x86_64/AArch64 = Limine 8.7.0. RISC-V = OpenSBI + custom S-mode stub; no Limine (unsupported).
- **AArch64 MMIO must be explicitly mapped** into TTBR1 via `early_map_mmio()` — Limine's AArch64 HHDM covers RAM only.
- **RISC-V is generic-first.** Discover MMIO via DTB; no vendor-specific paths in the core backend.
- **Three-arch cfg discipline.** Prefer `#[cfg(not(target_arch = "x86_64"))]` when AArch64 + RISC-V share behavior; use positive 3-way cfgs only when behavior diverges; factor an `arch::` helper instead of inline 3-way cfg blocks.

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
| **Graphics / compositor / GUI / GPU driver** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) (+ § Divergence for 4.a/4.b: `SYS_VIRTIO_MODERN_CAPS = 38`, double-copy frame path, `-vga virtio` QEMU) | `user/compositor` (ep 28), `user/scanout-virtio-gpu` (ep 27 — default x86_64 driver, 5 2D ops: CREATE_2D / ATTACH_BACKING / SET_SCANOUT / TRANSFER_TO_HOST_2D / RESOURCE_FLUSH), `user/scanout-limine` (fallback). Intel + aarch64/riscv64 virtio-gpu deferred to 4.c+. [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) for channel transport. |
| **GUI client library (user/libgui v0)** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) (libgui = in-process widget layer; v0 drawing primitives only, widgets deferred) | `user/libgui-proto/src/lib.rs` (wire format), `user/hello-window/` (canonical client), `user/libgui/src/{surface,font,tile_grid,client,bitmap}.rs`. No new kernel syscalls — drawing is CPU writes into attached surface channel. `Client::open` does CreateWindow/WelcomeClient/channel_attach handshake. `TileGrid::hit_test` deferred — don't add without consumer. |
| **Input drivers / Input Hub / event wire format / trust tiers** | [ADR-012](docs/adr/012-input-architecture-and-device-classes.md) (+ § Divergence: virtio-input-first, `COMPOSITOR_INPUT_ENDPOINT = 30`, first-live-window focus) | `user/libinput-proto/src/lib.rs` (96-byte wire + class payloads + modifier/button bitfields), `user/virtio-input/` (main.rs + transport.rs + virtqueue.rs + evdev.rs), `user/compositor/src/main.rs::pump_input_once` (→ focused window via `MsgTag::InputEvent = 0x4030`), `user/libgui/src/client.rs::poll_event`. Hub deferred until second consumer or signed-carrier hardware. `signature_block` reserved from day one so ADR-012 Input-5 lands without format revision. |
| **Security review / threat model** | [SECURITY.md](docs/SECURITY.md), [threat-model.md](docs/threat-model.md), [ADR-000](docs/adr/000-zta-and-cap.md), [PHILOSOPHY.md](docs/PHILOSOPHY.md) | All ADRs |
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

---

# Deep Reference

Sections below describe kernel state (directory pointers, tables, per-syscall behavior). Operational rules above outrank them when they conflict. Toolchain versions live in [Cargo.toml](Cargo.toml) and [rust-toolchain.toml](rust-toolchain.toml); linker scripts are `linker.ld` (x86_64) / `linker-aarch64.ld` / `linker-riscv64.ld`. Bootloader is Limine 8.7.0 on x86_64+AArch64, OpenSBI on RISC-V.

## Architecture (directory layout)

Run `tree -L 2 src/ user/ tools/` for the current layout; file names and purposes drift, so this file doesn't restate them. The non-obvious pieces that *don't* read off the tree:

- **`build.rs`** reads `CAMBIOS_TIER` (default `tier3`) and emits `--cfg tierN` for `src/config/tier.rs`. See [ADR-008](docs/adr/008-boot-time-sized-object-tables.md) / [ADR-009](docs/adr/009-purpose-tiers-scope.md).
- **Arch split:** portable modules (`scheduler/`, `ipc/`, `process.rs`, `loader/elf.rs`, `memory/buddy_allocator.rs` + `frame_allocator.rs`, `syscalls/mod.rs`) contain no arch-specific code. All arch backends live under `src/arch/<target>/`. `src/arch/mod.rs` is the cfg-gated shim.
- **Service endpoints (load-bearing numbers):** fs-service=16, key-store-service=17, virtio-net=20, udp-stack=21, virtio-blk=24 (user clients, `recv_verified`) + 26 (kernel-only commands, `recv_msg`, no cap check) + 25 (kernel's reply endpoint, `handle_write` intercept), scanout-virtio-gpu=27, compositor=28, compositor-input=30.
- **`tools/sign-elf/`** — host-side Ed25519 ELF signer (YubiKey or seed), produces the ARCSIG trailer. Own `.cargo/config.toml` targeting `aarch64-apple-darwin`.

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

Handlers live in [src/syscalls/dispatcher.rs](src/syscalls/dispatcher.rs). All IPC syscalls go through capability + interceptor checks and stamp `sender_principal`. Only the non-obvious gotchas / ABIs / restrictions are listed below:

- **Exit**: calls `CapabilityManager::revoke_all_for_process()` ([ADR-007](docs/adr/007-capability-revocation-and-telemetry.md)); VMA / page-table / frame reclaim is still partial.
- **Allocate**: rolls back on OOM.
- **BindPrincipal**, **ClaimBootstrapKey**, **AuditAttach**, **ChannelRevoke**, early **RevokeCapability**: **bootstrap-Principal-only**. `ClaimBootstrapKey` is one-shot and zeroes the kernel copy.
- **RecvMsg**: wire format is `[sender_principal:32][from_endpoint:4][payload:N]`. Blocks on `MessageWait(endpoint)`.
- **TryRecvMsg** (Phase 4b): non-blocking RecvMsg. Required for services polling multiple endpoints (virtio-blk ep24+ep26). `from_endpoint` is the sender's **reply endpoint** (first registered endpoint, tracked in `REPLY_ENDPOINT`) — before Phase 4b, `from = pid_slot` sent replies into a queue nobody read.
- **ObjPutSigned**: caller supplies an Ed25519 signature; kernel verifies against caller's Principal before storing.
- **MapMmio**: rejects addresses within RAM range. **PortIo**: rejects ports outside discovered PCI BARs. **AllocDma**: guard pages before + after.
- **DeviceInfo**: 108-byte descriptor. **AuditInfo**: 48-byte buffer. **MapFramebuffer**: 32-byte `FramebufferDescriptor`, capability-gated, kernel holds the phys addr; call once per display.
- **Spawn**: requires `CapabilityKind::CreateProcess` ([ADR-008](docs/adr/008-boot-time-sized-object-tables.md)).
- **RevokeCapability**: Phase 3.1 authority = bootstrap only; grantor / `revoke`-right-holder / policy paths land in Phase 3.4. `CapabilityHandle` refactor deferred to post-v1 handle table.
- **ChannelCreate**: needs `CreateChannel` system cap; roles are Producer / Consumer / Bidirectional ([ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md)). **ChannelAttach**: kernel verifies caller's Principal matches `peer_principal` from create; maps pages RO/RW per role.
- **ModuleReady**: gates the next module in `BOOT_MODULE_ORDER` behind `BlockReason::BootGate`. Every boot module's `_start` must call `sys::module_ready()` after endpoint registration.
