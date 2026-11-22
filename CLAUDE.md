# CambiOS Microkernel — Claude Code Context

## Scope

CambiOS is Jason Ricca's own kernel, licensed AGPL-3.0-or-later (GNU Affero General Public License). Work here is defensive review of this kernel and its services, and that review is the priority. Deliverables are fixes, tests, and proofs. A probe that reproduces a finding against this kernel under QEMU is a test, and it exists so the fix can be shown to close it.

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
- **Enforcement fails closed.** Any path that cannot obtain an authorization decision denies, audits, and does not cache the non-answer. Feature availability may degrade (a service retries, or exits and is restarted by init); permission may not. The one structural exception is a window in which there is provably no one to ask (init before the policy service exists). Why this is non-negotiable: the policy upcall ran fail-open for months with every query undelivered, and every boot "worked" because the outcome was always Allow (2026-10-27). A fail-open path hides exactly the failure it claims to survive. `make check-fail-open` flags the phrase in code and comments; ADR-006 § Divergence 2026-10-28 carries the decision.

BuddyAllocator (pure bookkeeping, host-testable) is the template; new kernel components follow the pattern.

## Build with the End in Mind

Architectural choices — bounds, test infrastructure, abstractions, decomposition, error types — aim at the v1-endgame workload, not throwaway scaffolding. The Formal Verification list above is one application; Convention 8's SCAFFOLDING rule is another. The general form: when facing a design choice, the question is *"what does v1 need from this?"*, not *"what's cheapest now?"*. When stuck between two compromised options, widen the horizon (time, hardware, workload) until the compromise dissolves.

**Sawtooth check.** Before executing a planned step, ask: *in v1, will this exact code, format, or decision still exist, or will a later step have replaced it?* If replaced, the step is about to ship scaffolding that has to be torn down. Either change the plan so the step delivers v1-shape work directly, or accept the tear-down explicitly with the trigger and cost named. The 5C/5D POSIX backend per-instance bitmap and journal — replaced by the unified storage substrate in storage step 7 — is the canonical example of what this check is meant to catch. Sawtooth is the principle being applied per-step instead of across the chain; the check operationalizes "widen the horizon" into a concrete pre-execution test.

**The pre-user period is when compromise-avoidance is cheapest.** Before real users have data on disk, the "we can iterate later" reflex feels safe; once data lands, iteration costs migration tools, version skew, and backwards-compat shims. Apply the sawtooth check more aggressively pre-user, not less. The pre-user period is not a license to compromise — it is the window where the v1-shape decision is cheapest to honor.

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

- **Host:** macOS on Apple Silicon or x86_64 Linux (the host CI runs on). The Makefile detects the host triple; no command in this file needs one typed by hand. `make check-env` reports what a machine has and lacks.
- **Kernel targets:** `x86_64-unknown-none`, `aarch64-unknown-none`, and `riscv64gc-unknown-none-elf` (ELF, bare metal). All three build at every commit (`make check-all`). What each one boots, and how far, is in [STATUS.md](STATUS.md); the RISC-V design is [ADR-013](docs/adr/013-riscv64-architecture-support.md).
- **Unit tests:** `make test` (the kernel library, on the host) and `make test-user` (the user, protocol and tool crates that have host tests). A bare `cargo test` fails: the default cargo target is bare metal.
- **AArch64 boot media:** FAT disk image via `mtools` (ISO/cdrom doesn't work for AArch64 UEFI on QEMU)
- **RISC-V boot:** OpenSBI (M-mode firmware, ships with QEMU as `-bios default`) hands a DTB pointer to a custom S-mode boot stub at `src/boot/riscv.rs`. No Limine on RISC-V.

## Critical Rules

- **NEVER** suggest `cargo run` or `cargo build` without `--target x86_64-unknown-none`, `--target aarch64-unknown-none`, or `--target riscv64gc-unknown-none-elf` for kernel crates.
- **NEVER** suggest running kernel binaries directly on the host. Always use QEMU.
- **AArch64 QEMU MUST use** `-machine virt,gic-version=3` (GICv3 required for ICC system registers).
- **RISC-V QEMU MUST use** `-machine virt -bios default` (loads OpenSBI as M-mode firmware; the kernel is the S-mode payload). No vendor-specific machine types — generic-first per [ADR-013](docs/adr/013-riscv64-architecture-support.md).
- **Tri-arch regression gate is mandatory before commits** ([ADR-013](docs/adr/013-riscv64-architecture-support.md) § Tri-Architecture Regression Discipline). Use `make check-all` (x86_64 + aarch64 + riscv64) as the permanent gate — R-6 landed 2026-04-19 so all three arches are now buildable at every commit boundary. `make check-stable` (x86_64 + aarch64 only) remains available as an escape hatch for future temporary backend breakage; the discipline is identical either way — no commits regress any *currently buildable* arch.
- **ALWAYS** all new files get an SPDX license header + copyright at the top. Default: `// SPDX-License-Identifier: AGPL-3.0-or-later` then `// Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors` on the next line. A file that already carries the earlier `Copyright (C) 2024-2026 Jason Ricca` line keeps it; headers are not rewritten in passing. Files under `user/libsys/` use `// SPDX-License-Identifier: MPL-2.0` instead. Adapt the comment syntax to file type (`#` for .toml/.py/.sh/Makefile; `/* ... */` for .ld/.S linker scripts and assembly). Do NOT use "All rights reserved" — a license grant supersedes reserved rights, and the SPDX header is the load-bearing declaration.
- **FUTURE VERIFICATION** every part of the microkernel will be formally verified at a later date.
- **Design documents come first.** Any work on identity, storage, filesystem, IPC architecture, capabilities, policy, or telemetry must be consistent with the design documents and ADRs in [Required Reading by Subsystem](#required-reading-by-subsystem). If implementation reveals a design problem, update the design doc *first* — don't silently diverge.
- **Path-scoped reference lives in `.claude/rules/`.** Claude Code loads each file there when a file matching its `paths:` list is read or edited. Other agents read the file that [Where things live](#where-things-live) names before working on those paths. The rules in this file outrank them when they conflict. Claude Code loads a rules file only when a matching file is read or edited. When the work concerns those paths with no such file open (a plan, an ADR draft, a review read from `git diff`, a new file written before any neighbour is read) or the block is no longer in context after a compaction, read the rules file named in Where things live first.

## Stop-and-Ask Gate

Before the first edit, stop and confirm when any of these apply. Questions beat wrong assumptions; "I don't know" is acceptable.

- **Unread subsystem.** About to modify a subsystem listed in the [Required Reading](#required-reading-by-subsystem) map without having read its docs *this session*. Re-read first, or flag the reading gap.
- **New `unsafe` invariant.** About to add `unsafe` that introduces a *new kind* of safety obligation (not mechanically matching a pre-existing pattern in the same module). Mechanical copies are fine; new invariants need user sign-off so the audit trail is intentional.
- **ADR edit.** About to edit an ADR's body. Show the planned diff first; the user approves before the edit lands. The body is then rewritten to reflect the current truth; a `## Divergence` appendix at the bottom preserves the prior wording with date and commit reference for history. A reader walking the body top-to-bottom should see the current design without contradiction; the appendix is where superseded designs go to be remembered, not where new design lives. New ADRs are appropriate when content is genuinely new and doesn't fit any existing ADR's scope.
- **Lock hierarchy change.** About to add a new lock to the hierarchy, reorder entries, or change `IrqSpinlock` vs plain `Spinlock`. Formally relevant, cross-subsystem, and exactly the class of change that breaks invariants silently.
- **SCAFFOLDING bound without v1 math.** About to pick a `const MAX_*` value without working through Dev Convention 8's extrapolation: v1-endgame workload, ≤25% utilization, memory cost. See [ASSUMPTIONS.md](docs/ASSUMPTIONS.md).
- **Dynamic dispatch in kernel.** About to introduce a trait object (`Box<dyn …>`, `&dyn …`) in kernel hot paths. Violates the Formal Verification rule ("no dynamic dispatch"). Propose the monomorphized design first.
- **Panic / unwrap / expect in non-test kernel code.** Every kernel failure must be a typed `Result`. If the only forward motion seems to be a panic, stop — the error type is probably wrong.
- **Telemetry / analytics / phone-home.** Project principle is zero telemetry. Any feature that emits data off-device (even "anonymous") is a stop.
- **Fail-open path.** About to make an enforcement decision default to Allow when the decider is unavailable, slow, full, or returns garbage — or to describe one in a comment. Enforcement fails closed (Formal Verification list); propose the deny + audit + restart shape instead, or name the structural reason there is no one to ask.
- **Portable module drift.** About to add `#[cfg(target_arch = …)]` to `src/scheduler/`, `src/ipc/`, `src/process.rs`, `src/loader/elf.rs`, or another module in the Portability Boundary list in [.claude/rules/kernel.md](.claude/rules/kernel.md). Factor an `arch::` helper instead, or escalate.
- **Identity-gate bypass.** About to add a syscall without updating `requires_identity()` and the identity tests beside it in [cambios-abi/src/lib.rs](cambios-abi/src/lib.rs), or add an IPC receiver that uses plain `recv_msg` where `recv_verified` is the load-bearing variant.
- **Destructive or shared-state action.** `git reset --hard`, branch deletion, force-push, `rm -rf` under the repo, or any action visible outside this machine. Confirm with the user before any of these; this holds whatever the agent's own instructions say about destructive actions.
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
- **The hooks bind every Claude-authored commit.** Its message carries a `Staged files:` block equal to `git diff --cached --name-only`. Set `CLAUDE_PREFLIGHT_SESSION=<id>` once per session so the preflight and edit-window gates enforce instead of warn. The pre-push gate refuses a commit that changes a file no Claude session edited with Edit, Write or NotebookEdit. Mechanics and scripts: [.claude/rules/tools.md](.claude/rules/tools.md); `make install-hooks` installs them once per clone.
- **Sign off every commit** (`git commit -s`). The `Signed-off-by:` line certifies the Developer Certificate of Origin; the commit-msg hook rejects a commit without it. An agent-authored commit carries the sign-off of the person the agent works for. Process details for contributors are in [CONTRIBUTING.md](CONTRIBUTING.md).
- **Who runs the commit.** On the maintainer's clone the agent drafts and the maintainer executes: the agent prepares `git add <files>` and the commit message, and the maintainer runs the commit to enter their PGP (Pretty Good Privacy) passphrase. On a contributor's clone or fork, the contributor, or their agent under the contributor's own identity, commits to a branch and opens a pull request; a contributor's change reaches `main` only through a pull request that passes the required checks. The project's own agent identity (the `cambios-agent` GitHub App) takes the same pull-request path. In every case: never bypass signing or hooks (`--no-gpg-sign`, `--no-verify`).

## Acronyms in Chat and Docs

**Every acronym or initialism gets a parenthetical on first use per message (chat) or per document (docs): the expansion, plus a reference to where the term is defined when one exists.** Project terms point at their ADR or doc section; hardware and spec terms point at the spec; general terms get the expansion alone.

- `FPEN (Floating-Point Enable, the CPACR_EL1 field; Arm Architecture Reference Manual, CPACR_EL1)`
- `HHDM (Higher Half Direct Map, Limine's identity map of physical memory; .claude/rules/platform-gotchas.md)`
- `AID (Autonomic Identifier, the 32-byte Principal; ADR-025, identity.md § AID)`
- `EC (Exception Class, ESR_EL1 bits 31:26)`

Why: the fault lines, ADRs, and spec names in this project are dense with abbreviations, and a reader entering a message cold should not have to hunt for what one stands for before they can follow the decision it supports. The parenthetical is also where the definition's home gets named, so the reference becomes clickable context rather than a word to remember.

Exempt: the handful that read as plain English (CPU, RAM, OS, API, ID, URL, PC in the program-counter sense once the register name is near). Repo-wide abbreviations with a canonical table (`ADR`, `SPDX`, `QEMU`, `ELF`) need the expansion only, no reference.

## Prompt-Shaping Changelog

Open mechanism decisions awaiting Revisit-when triggers — see [docs/dev-notes/prompt-shaping-changelog.md](docs/dev-notes/prompt-shaping-changelog.md). Codified rules and shipped tooling are out of scope; their history lives in `git log -- CLAUDE.md` and `git log -- tools/`.

## Development Conventions

1. **Every `unsafe` block MUST have a `// SAFETY:` comment, and every `pub unsafe fn` MUST have a `# Safety` rustdoc section** explaining why the operation is safe / what contract the caller must uphold. Citing alignment, bounds, aliasing, or lifetime invariants is the point — "trust me" is not a SAFETY comment. The `unsafe { ... }` rule is enforced by `make check-unsafe-coverage`; the `pub unsafe fn` rule is enforced by `clippy::missing_safety_doc = "deny"` in `[lints.clippy]`. One unsafe op per block, each with its own `// SAFETY:`, is hard-enforced by `multiple_unsafe_ops_per_block = "deny"` + `undocumented_unsafe_blocks = "deny"` in the same `[lints.clippy]` table (Cargo.toml, so they bind the library and the kernel binary alike), gated tri-arch by `make check-clippy` (a genuinely-irreducible block takes a local `#[allow(...)]` with rationale).

2. **Lock ordering** (see [.claude/rules/locks.md](.claude/rules/locks.md)) must always be followed. Never acquire a lower-numbered lock while holding a higher-numbered one.

Convention 3 (architecture portability) applies to the kernel tree and is in [.claude/rules/kernel.md](.claude/rules/kernel.md).

4. **Large structs are constructed in place**, never as a stack local that is then moved: kernel and boot stacks are small and so are user stacks (64 KiB). The kernel pattern and the reference failure are in [.claude/rules/kernel.md](.claude/rules/kernel.md).

5. **`no_std` only.** No standard library. No heap allocation before `memory::init()` completes in `main.rs`.

Convention 6 (the GDT is `static mut`) is x86_64-only, in [.claude/rules/x86_64.md](.claude/rules/x86_64.md).

7. **Never assume zeroed memory equals `None` for `Option<T>`.** Rust does not guarantee the Option discriminant layout — the compiler may assign discriminant 0 to `Some` (not `None`), especially for large structs on bare-metal targets. Always use explicit `core::ptr::write(None)` when initializing heap-allocated arrays of `Option<T>`.

8. **Every numeric bound is a conscious bound.** Fixed `const` numerics, fixed-size arrays, and `MAX_*` values in kernel code must carry a doc comment naming their category: `SCAFFOLDING` (verification ergonomics, expected to grow), `ARCHITECTURAL` (real invariant, won't change), `HARDWARE` (ABI/spec fact), or `TUNING` (workload-dependent). Unconscious bounds — values picked because something fit — are how production-ready software accrues weakness while it's still cheap to fix. The full catalog with rationale and replacement criteria lives in [ASSUMPTIONS.md](docs/ASSUMPTIONS.md). The doc-comment template for each category is in [.claude/rules/kernel.md](.claude/rules/kernel.md).

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

10. **Code comments anchor to durable things, never to roadmap phase numbers.** A phase identifier (`Phase 3.2a`, `Phase R-6`, `Phase B.3`, `GUI-0+`) is an index into STATUS.md that moves as work lands. The comment outlives the index. The next reader, with no surviving STATUS.md context for "Phase 3.2a", sees git-blame noise in the source.

   **Valid anchors:**
   - ADR ID, when there is a ratified decision: `// ADR-008: num_slots derived from tier policy`
   - Substantive reason (the WHY a future reader can't recover from the code itself): `// Reading CR3 returns the PML4 physical address`
   - Both: `// ADR-007: per-CPU audit ring, written by local CPU, drained by BSP`

   **Invalid anchors:**
   - Phase prefix alone: `// Phase 3.2a: compute num_slots from tier policy`
   - Phase prefix with redundant ADR: `// Phase 3.2a (ADR-008): compute num_slots` (drop the prefix; the ADR carries the load)
   - Roadmap-log narration in doc comments: `/// Phase R-2 expands this with DTB parse, frame allocator, heap`

   STATUS.md is the canonical index of phase progress; code is the canonical index of behavior. Don't crosswire them.

   Same anti-rot shape as the "no forward numeric ADR references" rule (changelog 2026-04-16) and Convention 9 (deferrals need observable triggers): durable artifacts must not anchor to mutable indices. Lint deferred per usual cadence (prose first; `make check-phase-refs` flagging `Phase \d` patterns lands on first recurrence).

   **Convention 9 triggers keep their phase numbers.** `// Revisit when: R-6 lands` is an observable trigger, not an anchor; don't strip it. The other exceptions a comment sweep leaves alone (log strings, ADR prose, in-function step labels, subsystem parentheticals) are in [docs/dev-notes/convention-10-exceptions.md](docs/dev-notes/convention-10-exceptions.md).

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
4. Did this change introduce a new architectural decision? → Draft a new ADR. Don't bury the decision in code comments. Did this change diverge from an existing ADR's plan? → Show the user the planned diff to the ADR body first; once approved, edit the body to reflect the new design and add a `## Divergence` appendix at the bottom preserving the prior wording with date + commit reference. The body is current truth; the appendix is history.
5. Did this change add or rename a build command, lock, or syscall? → Update whichever file holds it: CLAUDE.md's Quick Reference, [.claude/rules/tools.md](.claude/rules/tools.md) or [.claude/rules/sandbox.md](.claude/rules/sandbox.md) for a build command, [.claude/rules/locks.md](.claude/rules/locks.md) for a lock, [.claude/rules/syscalls.md](.claude/rules/syscalls.md) for a syscall.
6. Did this change resolve a Platform Gotcha in [.claude/rules/platform-gotchas.md](.claude/rules/platform-gotchas.md) or a Known Issue in STATUS.md? → Remove it from the gotcha list (don't leave a `~~strikethrough~~ FIXED` ghost).
7. Did this change cite a doc that doesn't exist yet? → Either create the doc or remove the citation.
8. Did this change add or modify a numeric `const`, fixed-size array, or `MAX_*` bound in kernel code? → Tag it with `SCAFFOLDING` / `ARCHITECTURAL` / `HARDWARE` / `TUNING` per Development Convention 8, and add or update the row in [ASSUMPTIONS.md](docs/ASSUMPTIONS.md). Unconscious bounds are not allowed.

## Common Failure Signatures

Observed symptom, likely root cause: [docs/dev-notes/failure-signatures.md](docs/dev-notes/failure-signatures.md). Read it when a build error or a QEMU log does not name its cause. It covers duplicate `panic_impl` and missing `memcpy` link errors, triple faults at boot, the GICv2 undefined instruction, early allocation failures, write-once statics reading back as garbage, `#PF` on a user address in a syscall, a user task reaped at a kernel-text PC, and silent hangs.

## Worked Examples

### Adding a new syscall

Seven coordinated places must change atomically (variant declaration, identity gate, `from_u64` wire-up, test coverage, dispatcher arm, handler, libsys wrapper) — full walkthrough with each step's failure mode in [docs/dev-notes/syscall-workflow.md](docs/dev-notes/syscall-workflow.md). Canonical reference: `TryRecvMsg = 37`. **Flow-specific stop-and-ask:** syscall in exempt set? new capability-check kind? new arch backend helper?

### Adding a user crate

Six things have to agree: the crate itself, the Makefile's build lists, `workspace.exclude`, the Limine configs, the `manifest.toml` entry, and the host-test lists. `make check-lists` names the one that is missing. Walkthrough: [docs/dev-notes/adding-a-user-crate.md](docs/dev-notes/adding-a-user-crate.md).

## Quick Reference

```bash
# Kernel builds
cargo build --target x86_64-unknown-none [--release]
cargo build --target aarch64-unknown-none --release
cargo build --target riscv64gc-unknown-none-elf --release

# Tri-arch gate (MANDATORY before commits) — ADR-013 § Tri-Architecture Regression Discipline
make check-all        # x86_64 + aarch64 + riscv64 (permanent gate)
make check-stable     # x86_64 + aarch64 only (escape hatch for temporary backend breakage)

# Unit tests (host). `make test` builds for TEST_TARGET, the host triple, so each host runs its own backend's
# tests; `make test-user` for USER_TEST_TARGET, the x86_64 triple of this OS (libsys names x18, which Apple
# reserves). On a macOS host `make test` also links the test binary as ELF, the format CI links, without running it.
make test             # kernel library
make test-user        # every package in the Makefile's HOST_TEST_CRATES (`make host-test-user-libsys` for one)
make check-user       # every user crate builds for every architecture that lists it

# What this machine has and lacks: toolchain, targets, emulator, firmware, hooks
make check-env

# Proofs (Kani 0.67.0, its own bundled toolchain). CI compiles every proof crate on every push and
# solves the crates whose inputs changed; verification/CLAIMS.md maps claims to harnesses.
make verify-all       # every crate under verification/ (`make verify-<crate>` for one)

# Fuzz targets (cargo-fuzz, the pinned nightly). Building them is the check; runs are manual.
make fuzz-build

# Derived counts (syscalls, tests, LOC)
make stats

# Lints. A failing lint prints its own remedy. Most are don't-grow-the-baseline gates (tools/check-*-baseline.txt).
# CI = run on every push; hook = run by pre-commit.
make check-lists             # every copy of a build list matches the Makefile's (CI, hook)
make check-adrs              # ADR cross-refs; regenerates docs/adr/INDEX.md (CI)
make audit-taxonomy          # regenerates docs/generated/audit-taxonomy.md from cambios-abi
make check-audit-taxonomy    # that generated doc is in sync (CI)
make check-assumptions       # Convention 8 tags on numeric consts (CI)
make check-deferrals         # Convention 9 Revisit-when triggers (CI)
make check-boot-panics       # ADR-021: no panic paths in boot init (CI)
make check-fail-open         # enforcement fails closed: no fail-open phrase (CI, hook)
make check-doc-refs          # ASSUMPTIONS.md file.rs#Lnnn refs still name their symbol (CI, hook)
make check-banned-paths      # tools/banned-paths.txt entries absent (CI, hook)
make check-index-isolation   # no STATUS.md diff >20 lines with .rs staged (hook)
make check-lockfile          # lists Cargo.lock crate changes (hook, advisory)
make check-unsafe-coverage   # Convention 1: every unsafe block has SAFETY (CI, hook)
make check-status-freshness  # STATUS.md sync date within 7 days (hook, advisory); CI runs --strict for Kani-total drift
make check-clippy            # Convention 1 clippy denies and -D warnings, library + kernel binary, all three arches (CI)
# check-doc-refs is line-keyed: any edit that moves a const in a cited file trips it. Run it with the other
# line-keyed gates after the last edit; `python3 tools/check-doc-refs.py --fix` re-anchors drifted refs.

# One-time per clone — installs .githooks/ via core.hooksPath (what the hooks require: Commit Cadence)
make install-hooks

# Tier-policy builds (ADR-008/009). CAMBIOS_TIER ∈ {tier1, tier2, tier3}; default tier3.
CAMBIOS_TIER=tier1 cargo build --target x86_64-unknown-none --release

# QEMU
make run                         # x86_64 (ISO, rebuilds kernel + modules)
make run-quiet                   # x86_64 via tools/qemu-run-quiet.py. Exit 0 = shell banner reached and every required line seen, 1 = panic or exception, 2 = hang or a required line missing. Required lines: RUN_QUIET_REQUIRES in the Makefile, plus EXTRA_REQUIRES="--require '…'"; `SUCCESS="virtio-net ready" TIMEOUT=90` for pre-shell testing.
make run-aarch64                 # AArch64 (FAT image); serial-only, no GPU: the compositor runs headless (run-aarch64-gui attaches one)
make run-riscv64                 # RISC-V (OpenSBI)
make iso                         # x86_64 ISO only
make img-aarch64                 # AArch64 FAT image only
make disk-img                    # 64 MiB raw backing for the block driver (idempotent; `make run` depends on it)
make run-quiet DISK_BUS=nvme     # same disk image behind a QEMU NVMe controller instead of virtio-blk-pci

# Symbol index for AI-assisted navigation (read .symbols at session start)
make symbols

# Bare-metal USB images and the fbcon-hold diagnostic stick: .claude/rules/platform-gotchas.md.
# Standalone builds, dev-PIV builds and ELF signing: .claude/rules/tools.md.
# Sandbox VM: .claude/rules/sandbox.md.
```

## Code Navigation — rust-analyzer MCP Tools

`.mcp.json` configures an MCP (Model Context Protocol) server that exposes rust-analyzer. When it is connected, prefer its symbol, definition, reference, implementation and hover tools over Grep for navigating Rust; Grep stays right for string literals, comments and non-Rust files.

## Required Reading by Subsystem

When working on a subsystem, read its design documents and ADRs *before* writing code; the "Unread subsystem" Stop-and-Ask bullet is checked against this map. Source files are not listed: open the subsystem's directory. A subsystem with no row is small enough that the code is the documentation. Pure intent lives in the design documents and ADRs, current status in [STATUS.md](STATUS.md). The full ADR set is [docs/adr/](docs/adr/) (run `ls docs/adr/`; do not cite a range here, it drifts).

| Working on... | Read first |
|---|---|
| **Scheduler / context switch / preemption** | [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) |
| **IPC control path (256-byte messages)** | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) |
| **IPC bulk path (channels)** | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md), [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) (channels are the audit transport) |
| **Service clusters / cluster-shaped revoke / boot-time mesh setup** | [ADR-027](docs/adr/027-service-clusters.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) (channel substrate), [ADR-018](docs/adr/018-init-process-and-boot-manifest.md) (manifest-driven boot) |
| **Capabilities, grant/revoke, delegation** | [ADR-000](docs/adr/000-zta-and-cap.md), [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) |
| **Process tables / tier configuration / boot-time object sizing** | [ADR-008](docs/adr/008-boot-time-sized-object-tables.md), [ADR-009](docs/adr/009-purpose-tiers-scope.md), [ASSUMPTIONS.md § Tier policies](docs/ASSUMPTIONS.md) |
| **Policy / `on_syscall` / interceptor decisions** | [ADR-006](docs/adr/006-policy-service.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) and its [§ Divergence](docs/adr/002-three-layer-enforcement-pipeline.md#divergence) (the interceptor is an enum, `IpcInterceptorBackend`, not a trait object) |
| **Audit infrastructure / observability** | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md), [PHILOSOPHY.md](docs/PHILOSOPHY.md) |
| **Audit consumer capability / `audit-tail`** | [ADR-023](docs/adr/023-audit-consumer-capability.md), [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) (the bootstrap-only check ADR-023 supersedes) |
| **Identity / Principal / sender_principal / vault** | [identity.md](docs/identity.md), [ADR-025](docs/adr/025-principal-as-aid.md) (supersedes [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md)'s implementation contract), [ADR-026](docs/adr/026-identity-transcription-at-the-kernel-ring.md), [ADR-033](docs/adr/033-multi-principal-vault.md); [FS-and-ID-design-plan.md](docs/FS-and-ID-design-plan.md) (intent only) |
| **ObjectStore / CambiObject / fs-service** | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md), [ADR-004](docs/adr/004-cryptographic-integrity.md) |
| **Persistent ObjectStore / on-disk format / BlockDevice** | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) and its § Divergence 3, [ADR-029 § Decision 5](docs/adr/029-posix-file-storage-model.md) (shared bitmap and journal), [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) (the `CambiObject` model the format serializes) |
| **Signed ELF loading / cryptographic integrity** | [ADR-004](docs/adr/004-cryptographic-integrity.md) |
| **User-space services (any new boot module)** | [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) |
| **Init / boot manifest / service lifecycle** | [ADR-018](docs/adr/018-init-process-and-boot-manifest.md), [ADR-019](docs/adr/019-process-fault-reaping-and-peer-generation.md) (restart substrate) |
| **Architecture port (a new backend)** | [ADR-013](docs/adr/013-riscv64-architecture-support.md), the Multi-Platform Strategy section of [.claude/rules/kernel.md](.claude/rules/kernel.md); `make check-lists` names each file a new architecture has to be added to |
| **Graphics / compositor / GPU driver** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) and its § Divergence 2026-04-20 (scanout transport) and 2026-05-08 (client-compositor protocol), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) (channel transport); [.claude/rules/gui.md](.claude/rules/gui.md) |
| **GUI client library (`user/libgui`)** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) § Divergence 2026-05-08; [.claude/rules/gui.md](.claude/rules/gui.md) |
| **Input drivers / Input Hub / event wire format / trust tiers** | [ADR-012](docs/adr/012-input-architecture-and-device-classes.md) and its § Divergence; [.claude/rules/gui.md](.claude/rules/gui.md) |
| **Security review / threat model** | [SECURITY.md](docs/SECURITY.md), [threat-model.md](docs/threat-model.md), [ADR-000](docs/adr/000-zta-and-cap.md), [PHILOSOPHY.md](docs/PHILOSOPHY.md), then all ADRs |
| **"Is X done yet?" / current state** | [STATUS.md](STATUS.md) |

**Read when the topic enters scope** (no subsystem row):
- [CambiOS.md](docs/CambiOS.md): what CambiOS is; the source-of-truth architecture document.
- [GOVERNANCE.md](docs/GOVERNANCE.md): deployment tiers and scope boundaries; companion to [ADR-009](docs/adr/009-purpose-tiers-scope.md).
- [ADR-015](docs/adr/015-storage-tiers-and-commitment-ladder.md): storage durability tiers, replication.
- [ADR-016](docs/adr/016-win-compat-api-ai-boundary.md) and [win-compat.md](docs/win-compat.md): the Windows compatibility layer.
- [ADR-017](docs/adr/017-user-directed-cloud-inference.md): cloud-AI routing and consent.
- [ADR-019](docs/adr/019-process-fault-reaping-and-peer-generation.md): process lifecycle, fault recovery, service restart.
- [ADR-020](docs/adr/020-typed-user-buffer-slices-at-syscall-boundary.md): a syscall that takes user pointers.
- [ADR-021](docs/adr/021-typed-boot-error-propagation.md): `src/microkernel/main.rs` or any boot-init path.
- [ADR-022](docs/adr/022-wall-clock-time.md): wall-clock time (syscalls and cap reserved, not built).
- [ADR-024](docs/adr/024-syscall-abi-crate.md): the syscall ABI or its bindings.
- [ADR-034](docs/adr/034-deferred-task-resource-reclamation.md): process exit and teardown, the reaper, the task-slot lifecycle; pairs with ADR-019.

## Roadmap

What's built, what's in progress, what's planned (including v1 ordering, phase markers, and known issues) all live in **[STATUS.md](STATUS.md)**. Architectural decisions live in the ADRs under [docs/adr/](docs/adr/). This file contains neither — it's the technical reference.

---

## Where things live

Reference that matters only inside one part of the tree is in `.claude/rules/`. Claude Code loads each file there when a file matching its `paths:` list is read or edited. Other agents read the file named below before working on the paths it lists. The `paths:` list at the top of each file is the list of record; the paths named here follow it. "The kernel's `src/`" is the one at the repository root, not a crate's. A section name cited by an older comment ("CLAUDE.md § Timer / Preemptive Scheduling") is in the Holds column of the file that now has it.

| File | Loads for | Holds |
|---|---|---|
| [kernel.md](.claude/rules/kernel.md) | the kernel's `src/`, the three kernel linker scripts | Convention 3, Convention 4's kernel pattern, Convention 8's templates, Multi-Platform Strategy and the portable-module list, directory layout, [Memory Layout](#memory-layout) |
| [platform-gotchas.md](.claude/rules/platform-gotchas.md) | the kernel's `src/`, the device-driver crates, linker scripts, Limine configs, `manifest.toml`, the `Makefile` | Platform Gotchas: bootloader, firmware and real-hardware quirks; bare-metal USB images and the `fbcon-hold` stick |
| [scheduling.md](.claude/rules/scheduling.md) | the scheduler, arch backends, interrupts, IPC, syscalls, policy, audit, `src/io/`, loader, memory, `src/microkernel/`, `src/lib.rs`, three other kernel files that block or wake | Timer / Preemptive Scheduling: the Blocking pattern, voluntary context switch, the reschedule kick, cross-CPU wake |
| [syscalls.md](.claude/rules/syscalls.md) | `src/syscalls/`, `cambios-abi/`, `user/libsys/`, `user/libsys-rt/` | Syscall Numbers: where the canonical list is, and per-syscall behavior that does not read off it |
| [x86_64.md](.claude/rules/x86_64.md) | `src/arch/x86_64/` | Convention 6, the GDT layout, SYSCALL/SYSRET register values, the kernel stack switch |
| [userspace.md](.claude/rules/userspace.md) | `user/`, `manifest.toml`, `cambios-manifest/`, `cambios-blk-proto/`, the two kernel files that handle the block driver's endpoints | Service endpoints whose handling does not read off the `manifest.toml` header |
| [gui.md](.claude/rules/gui.md) | the compositor, scanout, libgui, libgui-proto, hello-window, terminal-window, libinput-proto and virtio-input crates | graphics, GUI client library and input: protocol sources, the rules that bind changes there |
| [tools.md](.claude/rules/tools.md) | `tools/sign-elf/`, `tools/build-manifest/`, `tools/gen-dev-piv-keys/`, `tools/format-volume/`, `.githooks/`, `user/key-store-service/`, `user/fde-mount/`, `user/libsys/src/vault.rs`, `manifest.toml` | hook mechanics (what they require of a commit: Commit Cadence), standalone and dev-PIV builds, ELF signing |
| [sandbox.md](.claude/rules/sandbox.md) | `tools/sandbox/` | the `make sandbox-*` targets |

### Lock Ordering

[.claude/rules/locks.md](.claude/rules/locks.md), for the kernel's `src/`. The hierarchy, why a plain `Spinlock` holder is never descheduled, the boot context, and the lock domains outside the hierarchy.

### Memory Layout

In [.claude/rules/kernel.md](.claude/rules/kernel.md). Kernel heap, boot stack, the object-table region, per-process heaps, user code and stack addresses, and the direct-map bases.
