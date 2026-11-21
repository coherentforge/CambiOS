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
- **Design documents come first.** Any work on identity, storage, filesystem, IPC architecture, capabilities, policy, or telemetry must be consistent with the [Design Documents](#design-documents) and the ADRs. If implementation reveals a design problem, update the design doc *first* — don't silently diverge.
- **Path-scoped reference lives in `.claude/rules/`.** Claude Code loads each file there when a file matching its `paths:` list is read or edited. Other agents read the file that [Where things live](#where-things-live) names before working on those paths. The rules in this file outrank them when they conflict.

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
- **Portable module drift.** About to add `#[cfg(target_arch = …)]` to `src/scheduler/`, `src/ipc/`, `src/process.rs`, `src/loader/elf.rs`, or another portable module. Factor an `arch::` helper instead, or escalate.
- **Identity-gate bypass.** About to add a syscall without updating `requires_identity()` and the identity tests beside it in [cambios-abi/src/lib.rs](cambios-abi/src/lib.rs), or add an IPC receiver that uses plain `recv_msg` where `recv_verified` is the load-bearing variant.
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

1. **Every `unsafe` block MUST have a `// SAFETY:` comment, and every `pub unsafe fn` MUST have a `# Safety` rustdoc section** explaining why the operation is safe / what contract the caller must uphold. Citing alignment, bounds, aliasing, or lifetime invariants is the point — "trust me" is not a SAFETY comment. The `unsafe { ... }` rule is enforced by `make check-unsafe-coverage`; the `pub unsafe fn` rule is enforced by `clippy::missing_safety_doc = "deny"` in `[lints.clippy]`. One unsafe op per block, each with its own `// SAFETY:`, is hard-enforced by `#![deny(clippy::multiple_unsafe_ops_per_block)]` + `#![deny(clippy::undocumented_unsafe_blocks)]` in `src/lib.rs`, gated tri-arch by `make check-clippy` (a genuinely-irreducible block takes a local `#[allow(...)]` with rationale).

2. **Lock ordering** (see [.claude/rules/locks.md](.claude/rules/locks.md)) must always be followed. Never acquire a lower-numbered lock while holding a higher-numbered one.

Conventions 3 (architecture portability) and 4 (large structs are constructed in place) apply to kernel code only and are in [.claude/rules/kernel.md](.claude/rules/kernel.md).

5. **`no_std` only.** No standard library. No heap allocation before `memory::init()` completes in `main.rs`.

Conventions 6 (the GDT is `static mut`) and 7 (zeroed memory is not `None`) are kernel-only too, in the same file.

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

   **Exceptions in practice** (from the kernel sweep precedent — see commits f24233e through a15a743):

   - **Convention 9 triggers preserve their phase numbers.** `// Replace when: R-6 lands` and `// Revisit when: identity.md Phase 1.5 lands (post-v1)` are valid per Convention 9's own examples ("Revisit when R-6 lands"). Don't strip phase numbers from `Replace when:` / `Revisit when:` blocks; they're observable triggers, not anchors.
   - **Runtime log strings are out of scope.** Convention 10 is about code *comments*. Output strings like `[R-3 RX]` (the RISC-V trap-handler diagnostic prefix in `src/arch/riscv64/plic.rs`) are operator-visible artifacts; renaming them is a coordinated multi-file decision, not a comment cleanup.
   - **ADR prose is out of scope.** ADR files in `docs/adr/` are historical decision records. Phase references in the reasoning are part of the record. Don't touch unless explicitly addressing an ADR's content.
   - **Within-function step labels rename to "Step N".** Inline comments like `// Phase 1: handshake` / `// Phase 2: install` used as in-function ordering (precedents: `src/fs/lazy_disk.rs::ensure_disk_store`, `src/policy/mod.rs::expire_stale_decisions`, `src/syscalls/dispatcher.rs::handle_audit_attach`) describe code structure that needs *some* label. Rename to `// Step N:` rather than dropping — the word "Phase" trips readers into looking for a STATUS.md index that isn't there.
   - **`Phase X (substantive-subsystem)` parentheticals where the subsystem name is adjacent get the phase dropped, name kept.** `Phase 5 (social log)` → `social log`. The substantive name is the durable anchor; the phase tag was a forecast of when growth would come from there.

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

# Lints. Most are don't-grow-the-baseline gates (baselines in tools/check-*-baseline.txt); check-lists has no baseline.
make check-lists             # every copy of a build list (architectures, user crates, host-tested packages, proof crates) agrees with the Makefile's "Build lists" section
make check-adrs              # ADR cross-refs + regenerate docs/adr/INDEX.md
make audit-taxonomy          # regenerate docs/generated/audit-taxonomy.md from cambios-abi (audit_taxonomy! macro)
make check-audit-taxonomy    # verify the generated taxonomy doc is in sync (local only: neither CI nor the hooks run it)
make check-assumptions       # Convention 8 numeric-const tags
make check-deferrals         # Convention 9 Revisit-when triggers
make check-boot-panics       # ADR-021 Phase C — no panic!/expect/etc in boot init; exempt via `// BOOT_PANIC_OK: <reason>`
make check-fail-open         # Enforcement fails closed (ADR-006 § Divergence 2026-10-28) — no fail-open phrase in kernel/user code or comments; exempt via `// FAIL_OPEN_OK: <reason>`; baseline expected empty
make check-doc-refs          # ASSUMPTIONS.md `file.rs#Lnnn` source refs name the symbol within ±1 line (CI-gated since b194a8b; any edit that moves a const in a cited file trips it — run it with the other line-keyed gates, `python3 tools/check-doc-refs.py --fix` re-anchors drifted refs)
make check-banned-paths      # paths in tools/banned-paths.txt must not exist on disk
make check-index-isolation   # STATUS.md diff >20 lines + any .rs staged → reject
make check-lockfile          # T-1: lists added/removed Cargo.lock crates (advisory)
make check-unsafe-coverage   # Convention 1 (blocks): every `unsafe { }` has `// SAFETY:` (cluster + cfg-attr + assignment-continuation aware)
make check-status-freshness  # STATUS.md `last_synced_to_code:` within 7 days of today (advisory; warn-but-pass). CI runs it with `--strict`, which fails when STATUS.md's Kani harness total disagrees with the source
make check-clippy            # Convention 1 (tri-arch deny gate, CI per-push): missing_safety_doc (every `pub unsafe fn` has `# Safety`) + multiple_unsafe_ops_per_block + undocumented_unsafe_blocks; runs clippy on x86_64+aarch64+riscv64 because arch-cfg'd unsafe only lints on its own target

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
make run-quiet                   # x86_64, filtered via tools/qemu-run-quiet.py; exit 0 = success sentinel (default: the `CambiOS Shell v0.1` banner) AND every `--require REGEX` matched, 1 = panic/exception, 2 = hang or a required line missing. Default requires (RUN_QUIET_REQUIRES): `boot wave settled: N ready, 0 spawn-failed, 0 dep-failed` and `[COMPOSITOR] display connected: WxH` (this recipe attaches a GPU; a boot with no display reaches the shell headless, so the display is required where it is known to exist); CI adds the policy counters via EXTRA_REQUIRES="--require '…'". Override with `make run-quiet SUCCESS="virtio-net ready" TIMEOUT=90` for pre-shell testing.
make run-aarch64                 # AArch64 (FAT image); serial-only, no GPU: the compositor runs headless (run-aarch64-gui attaches one)
make run-riscv64                 # RISC-V (OpenSBI)
make iso                         # x86_64 ISO only
make img-aarch64                 # AArch64 FAT image only
make disk-img                    # 64 MiB raw backing for the block driver (idempotent; `make run` depends on it)
make run-quiet DISK_BUS=nvme     # same disk image behind a QEMU NVMe controller instead of virtio-blk-pci (also `run-img-usb DISK_BUS=nvme PROFILE=headless`, the bare-metal rehearsal: the headless/framebuffer-fallback profiles spawn `user/nvme`, `default` spawns virtio-blk; both serve the block seam in `cambios-blk-proto`)
make img-usb [PROFILE=headless]  # bare-metal USB image: iso_root + the signed manifest for PROFILE (headless = text shell on the framebuffer console, with the shell rebuilt `--features headless-input` and swapped in so it owns input endpoint 30 and reads the USB keyboard from usb-host; framebuffer-fallback = scanout-limine + compositor + terminal-window, keyboard via usb-host HID → compositor). `make usb DEVICE=/dev/diskN PROFILE=…` writes it.
make usb DEVICE=/dev/diskN PROFILE=framebuffer-fallback KERNEL_FEATURES=fbcon-hold   # diagnostic stick for a machine with no serial: the kernel text console keeps mirroring over the scanout driver after the handoff, so the boot log (policy denials, `[sched]` counters, service lines) stays readable on the panel when the GUI chain fails silently. Garbled by design; never ship it.

# Symbol index for AI-assisted navigation (read .symbols at session start)
make symbols

# Standalone builds, dev-PIV builds and ELF signing: .claude/rules/tools.md.
# Sandbox VM: .claude/rules/sandbox.md.
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

## Required Reading by Subsystem

When working on a subsystem, read its design and implementation docs *before* writing code. This map exists so context doesn't get forgotten between sessions. If a doc is missing from the list it means the subsystem is small enough that the code is the documentation.

| Working on... | Read first | Then |
|---|---|---|
| **Scheduler / context switch / preemption** | [SCHEDULER.md](src/scheduler/SCHEDULER.md), [ADR-001](docs/adr/001-smp-scheduling-and-lock-hierarchy.md) | [.claude/rules/locks.md](.claude/rules/locks.md) and [.claude/rules/scheduling.md](.claude/rules/scheduling.md) |
| **IPC control path (256-byte messages)** | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) | `src/ipc/mod.rs`, `src/ipc/interceptor.rs` |
| **IPC bulk path (channels — Phase 3)** | [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) (channels are the audit transport) |
| **Service clusters / cluster-shaped revoke / boot-time mesh setup** | [ADR-027](docs/adr/027-service-clusters.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) (channel substrate), [ADR-018](docs/adr/018-init-process-and-boot-manifest.md) (manifest-driven boot) | `src/ipc/cluster.rs` (skeleton, post-HN), `user/compositor/src/main.rs` (rendering limb is the first cluster). Per-channel quiesce protocol is the prerequisite — independent pre-HN work that closes the compositor #PF on clean client exit; clusters wrap N quiesce-revokes in a single locked transition. |
| **Capabilities, grant/revoke, delegation** | [ADR-000](docs/adr/000-zta-and-cap.md), [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) | `src/ipc/capability.rs` |
| **Process tables / tier configuration / boot-time object sizing** | [ADR-008](docs/adr/008-boot-time-sized-object-tables.md), [ADR-009](docs/adr/009-purpose-tiers-scope.md) | `src/process.rs`, `src/ipc/capability.rs`, [ASSUMPTIONS.md § Tier policies](docs/ASSUMPTIONS.md) |
| **Policy / `on_syscall` / interceptor decisions** | [ADR-006](docs/adr/006-policy-service.md), [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md) ([§ Divergence](docs/adr/002-three-layer-enforcement-pipeline.md#divergence): interceptor moved from `Box<dyn IpcInterceptor>` to `IpcInterceptorBackend` enum-dispatch shim — same precedent as ADR-003 for `OBJECT_STORE`) | `src/ipc/interceptor.rs` (trait + `IpcInterceptorBackend` enum), `src/ipc/mod.rs` (`IpcManager.interceptor` and `ShardedIpcManager.interceptor` field sites) |
| **Audit infrastructure / observability** | [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md), [PHILOSOPHY.md](docs/PHILOSOPHY.md) | `src/audit/mod.rs`, `src/audit/buffer.rs`, `src/audit/drain.rs` |
| **Audit consumer capability / kernelvisor prep / `audit-tail` boot module** | [ADR-023](docs/adr/023-audit-consumer-capability.md), [ADR-007](docs/adr/007-capability-revocation-and-telemetry.md) (the bootstrap-only check ADR-023 supersedes) | `user/audit-tail/src/main.rs`, `src/syscalls/dispatcher.rs` (`handle_audit_attach`, `handle_get_process_principal`), `src/process.rs` (`RecentExitsRing`) |
| **Identity / Principal / sender_principal / vault** | [identity.md](docs/identity.md), [ADR-025](docs/adr/025-principal-as-aid.md) (Principal as 32-byte AID — supersedes the implementation contract from [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md)), [ADR-026](docs/adr/026-identity-transcription-at-the-kernel-ring.md) (kernel transcribes identity events without interpreting them), [ADR-033](docs/adr/033-multi-principal-vault.md) (`user/key-store-service` as the AID → hardware-key-slot directory; `bind_for_spawn` / `sign_with` / `decrypt_with` IPC) | [FS-and-ID-design-plan.md](docs/FS-and-ID-design-plan.md) (intent only) |
| **ObjectStore / CambiObject / fs-service** | [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md), [ADR-004](docs/adr/004-cryptographic-integrity.md) | `src/fs/mod.rs`, `src/fs/ram.rs`, `user/fs-service/src/main.rs` |
| **Persistent ObjectStore / on-disk format / BlockDevice** | [ADR-010](docs/adr/010-persistent-object-store-on-disk-format.md) (+ § Divergence 3 landed 2026-05-16: v2 record format, shared bitmap + journal via [ADR-029 § Decision 5](docs/adr/029-posix-file-storage-model.md)) | `src/fs/block.rs`, `src/fs/disk.rs`, `src/fs/bitmap.rs`, `src/fs/journal.rs`; [ADR-003](docs/adr/003-content-addressed-storage-and-identity.md) for the `CambiObject` model the format serializes |
| **Signed ELF loading / cryptographic integrity** | [ADR-004](docs/adr/004-cryptographic-integrity.md) | `src/loader/mod.rs` (`SignedBinaryVerifier`) |
| **User-space services (any new boot module)** | [ADR-002](docs/adr/002-three-layer-enforcement-pipeline.md), [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) | `user/libsys/src/lib.rs`, an existing service like `user/udp-stack/src/main.rs` as template |
| **Init / boot manifest / service lifecycle** | [ADR-018](docs/adr/018-init-process-and-boot-manifest.md) (kernel transcribes security sections, init interprets policy sections; migration-step ordering), [ADR-019](docs/adr/019-process-fault-reaping-and-peer-generation.md) (restart substrate — gates step 10) | `cambios-manifest/src/lib.rs` (wire format, shared parser, boot-protocol consts), `user/init/src/engine.rs` (supervisor state machine), `src/manifest.rs` (kernel transcription), `manifest.toml` + `tools/build-manifest` (registry artifact) |
| **Architecture port (a new backend)** | [ADR-013](docs/adr/013-riscv64-architecture-support.md), the Multi-Platform Strategy section of [.claude/rules/kernel.md](.claude/rules/kernel.md); `make check-lists` names each file a new architecture has to be added to | `src/arch/aarch64/mod.rs` as the closest structural reference (single trap vector, `scause`-style dispatch, callee-saved context_switch); `src/boot/mod.rs` for the BootInfo contract a new boot adapter must satisfy |
| **Graphics / compositor / GUI / GPU driver** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) (+ § Divergence 2026-04-20 for 4.a/4.b scanout transport: `SYS_VIRTIO_MODERN_CAPS = 38`, double-copy frame path, `-vga virtio` QEMU; + § Divergence 2026-05-08 for the client↔compositor protocol — 10 wire messages 0x3xxx/0x4xxx, libgui-proto authoritative) | `user/compositor` (ep 28), `user/scanout-virtio-gpu` (ep 27 — default x86_64 driver, 5 2D ops: CREATE_2D / ATTACH_BACKING / SET_SCANOUT / TRANSFER_TO_HOST_2D / RESOURCE_FLUSH), `user/scanout-limine` (fallback). Intel + aarch64/riscv64 virtio-gpu deferred to 4.c+. [ADR-005](docs/adr/005-ipc-primitives-control-and-bulk.md) for channel transport. |
| **GUI client library (user/libgui v0)** | [ADR-011](docs/adr/011-graphics-architecture-and-scaling.md) (libgui = in-process widget layer; v0 drawing primitives only, widgets deferred), [ADR-014](docs/adr/014-compositor-scanout-driver-protocol.md) § Divergence 2026-05-08 (client↔compositor wire protocol — full message table + authority model) | `user/libgui-proto/src/lib.rs` (wire format), `user/hello-window/` (canonical client), `user/libgui/src/{surface,font,tile_grid,client,bitmap}.rs`. No new kernel syscalls — drawing is CPU writes into attached surface channel. `Client::open` does CreateWindow/WelcomeClient/channel_attach handshake. `TileGrid::hit_test` deferred — don't add without consumer. |
| **Input drivers / Input Hub / event wire format / trust tiers** | [ADR-012](docs/adr/012-input-architecture-and-device-classes.md) (+ § Divergence: virtio-input-first, `COMPOSITOR_INPUT_ENDPOINT = 30`, first-live-window focus) | `user/libinput-proto/src/lib.rs` (96-byte wire + class payloads + modifier/button bitfields), `user/virtio-input/` (main.rs + transport.rs + virtqueue.rs + evdev.rs), `user/compositor/src/main.rs::pump_input_once` (→ focused window via `MsgTag::InputEvent = 0x4030`), `user/libgui/src/client.rs::poll_event`. Hub deferred until second consumer or signed-carrier hardware. `signature_block` reserved from day one so ADR-012 Input-5 lands without format revision. |
| **Security review / threat model** | [SECURITY.md](docs/SECURITY.md), [threat-model.md](docs/threat-model.md), [ADR-000](docs/adr/000-zta-and-cap.md), [PHILOSOPHY.md](docs/PHILOSOPHY.md) | All ADRs |
| **"Is X done yet?" / current state** | [STATUS.md](STATUS.md) | — |

**Orphan ADRs** — not bound to any subsystem row above; consult when their topic enters scope:
- [ADR-015](docs/adr/015-storage-tiers-and-commitment-ladder.md) — storage durability tiers / commitment ladder. Read when working on persistence, replication, or durability guarantees.
- [ADR-016](docs/adr/016-win-compat-api-ai-boundary.md) — Win32 API surface and the AI-translation boundary. Read when working on the Windows compatibility shim.
- [ADR-017](docs/adr/017-user-directed-cloud-inference.md) — user-directed cloud inference policy. Read when adding cloud-AI routing or consent flows.
- [ADR-019](docs/adr/019-process-fault-reaping-and-peer-generation.md) — process fault reaping and peer generation. Read when working on process lifecycle, fault recovery, or service restart.
- [ADR-020](docs/adr/020-typed-user-buffer-slices-at-syscall-boundary.md) — typed user buffer slices at the syscall boundary. Read alongside the syscall walkthrough when a new syscall takes user pointers.
- [ADR-021](docs/adr/021-typed-boot-error-propagation.md) — typed boot error propagation; enforced by `make check-boot-panics`. Read when working on `src/microkernel/main.rs` or any boot-init path.
- [ADR-022](docs/adr/022-wall-clock-time.md) — wall-clock time syscalls (44/45) and the SetWallclock cap (reservation only; impl deferred behind audit refactor). Read when impl resumes.
- [ADR-024](docs/adr/024-syscall-abi-crate.md) — `cambios-abi` crate as the syscall ABI definition surface. Read when modifying the syscall ABI or generating bindings.
- [ADR-034](docs/adr/034-deferred-task-resource-reclamation.md) — deferred reclamation of a terminating task's self-referential resources (page-table root, kernel stack, task slot) via per-CPU reapers; the N-CPU address-space occupancy invariant. Read when working on process exit/teardown, the reaper, or the scheduler slot lifecycle; pairs with [ADR-019](docs/adr/019-process-fault-reaping-and-peer-generation.md).

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

Work on identity, storage, filesystem, IPC architecture, capabilities, policy, or telemetry follows the "Design documents come first" rule under [Critical Rules](#critical-rules).

## Roadmap

What's built, what's in progress, what's planned (including v1 ordering, phase markers, and known issues) all live in **[STATUS.md](STATUS.md)**. Architectural decisions live in the ADRs under [docs/adr/](docs/adr/). This file contains neither — it's the technical reference.

---

## Where things live

Reference that matters only inside one part of the tree is in `.claude/rules/`. Claude Code loads each file there when a file matching its `paths:` list is read or edited. Other agents read the file named below before working on the paths it lists. The `paths:` list at the top of each file is the list of record; the paths named here follow it. Each heading keeps the name the section had in this file, so older links and citations still resolve.

### Lock Ordering

[.claude/rules/locks.md](.claude/rules/locks.md), for any file under the kernel's `src/` (the one at the repository root, not a crate's). The hierarchy, why a plain `Spinlock` holder is never descheduled, the boot context, and the lock domains outside the hierarchy.

### Multi-Platform Strategy (x86_64, AArch64, RISC-V)

[.claude/rules/kernel.md](.claude/rules/kernel.md), for any file under the kernel's `src/`. The same file holds Development Conventions 3, 4, 6 and 7, the toolchain and linker-script pointers, Architecture (directory layout) and Memory Layout.

### Memory Layout

In [.claude/rules/kernel.md](.claude/rules/kernel.md), for any file under the kernel's `src/`. Kernel heap, boot stack, the object-table region, per-process heaps, user code and stack addresses, and the direct-map bases.

### Platform Gotchas

[.claude/rules/platform-gotchas.md](.claude/rules/platform-gotchas.md), for the kernel's `src/`, the user-space device-driver crates, the linker scripts, the Limine configs, `manifest.toml` and the `Makefile`. Bootloader, firmware and real-hardware quirks that boot and hardware-path code must respect: manifest and init staging, direct-map gaps, x86_64 memory types, GICv3, per-CPU floating-point enable, stray interrupts, the USB controller hand-off.

### Timer / Preemptive Scheduling

[.claude/rules/scheduling.md](.claude/rules/scheduling.md), for the scheduler, the architecture backends, interrupts, IPC, syscalls, policy, audit, `src/io/`, the loader, memory, `src/microkernel/`, `src/lib.rs` and the three other kernel files that block or wake. It holds the Blocking pattern, voluntary context switch, the reschedule kick and cross-CPU wake.

### Syscall Numbers

[.claude/rules/syscalls.md](.claude/rules/syscalls.md), for `src/syscalls/`, `cambios-abi/`, `user/libsys/` and `user/libsys-rt/`. Where the canonical list is (the `SyscallNumber` enum in `cambios-abi`) and the per-syscall behavior that does not read off it: wire formats, gating capabilities, retired slots.

### GDT Layout and SYSCALL/SYSRET

[.claude/rules/x86_64.md](.claude/rules/x86_64.md), for `src/arch/x86_64/`. The seven GDT entries and their selectors, the STAR and SFMASK register values, and the kernel stack switch on syscall entry.

### Service endpoints

[.claude/rules/userspace.md](.claude/rules/userspace.md), for `user/`, `manifest.toml`, `cambios-manifest/`, `cambios-blk-proto/` and the two kernel files that handle the block driver's endpoints. The load-bearing endpoint numbers and how each is handled; the assignment of record is the header of `manifest.toml`.

### Git hooks, host tools and signing

[.claude/rules/tools.md](.claude/rules/tools.md), for `tools/`, `.githooks/`, `user/key-store-service/`, `user/fde-mount/` and `manifest.toml`. Standalone builds, dev-PIV builds, ELF signing and `tools/sign-elf/`. What the hooks require of a commit is in the [Quick Reference](#quick-reference), above `make install-hooks`.

### Sandbox VM

[.claude/rules/sandbox.md](.claude/rules/sandbox.md), for `tools/sandbox/`. The `make sandbox-*` targets: session up and down, the egress proxy, handing a task to the agent, and the golden image.
