# Post-Change Review Protocol

Full protocol for verifying a code change before reporting it complete. [CLAUDE.md](../CLAUDE.md)'s Post-Change Review Protocol section carries the directive, the scope-triage rules, and the §8 concrete checklist (the most drift-prone part); this file holds §1–§7 and the §8 category table that are referenced on demand.

## 1. Build Verification

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
- **Otherwise → report and track.** Surface it to the user (file:line + warning text) and add to [STATUS.md](../STATUS.md)'s Known Issues. Silent pass-through loses signal for formal-verification prep and human review.

## 2. Safety Audit
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariants
- New unsafe code cites what guarantees make it sound (alignment, bounds, aliasing, lifetime)
- No raw pointer dereference without a bounds or null check nearby

## 3. Lock Ordering
Verify no change introduces a lock ordering violation against the canonical hierarchy in CLAUDE.md's [Lock Ordering](../CLAUDE.md#lock-ordering) section. **Do not duplicate the hierarchy here** — it drifted once and will drift again. Checklist:
- Lower-numbered locks must be acquired before higher-numbered ones
- `try_lock()` in ISR context is acceptable (already established pattern)
- Holding multiple locks simultaneously requires explicit justification
- If you are *adding or reordering a lock*, trip the Stop-and-Ask gate before editing — lock hierarchy changes are cross-subsystem and formally relevant

## 4. Architecture Portability
- New x86-specific code is behind `#[cfg(target_arch = "x86_64")]`
- New x86-specific code lives under `src/arch/x86_64/`, not in portable modules
- Portable modules (`scheduler/`, `ipc/`, `process.rs`, `loader/elf.rs`) contain no arch-specific code

## 5. Memory Safety
- Large structs (>1KB) are heap-allocated via `new_boxed()` or `Box::new()` — boot stack is 256KB
- No heap allocation before `memory::init()` completes
- Frame allocator regions don't overlap with kernel heap or reserved memory

## 6. Security Review (for loader/IPC/syscall changes)
- ELF binaries pass through `BinaryVerifier` before any memory allocation
- W^X enforcement: no page is both writable and executable
- User-space segments don't map into kernel address space
- Syscall handlers validate all user-provided pointers and lengths
- Capabilities are checked before granting IPC access

## 7. Test Coverage
- New logic has corresponding unit tests in `#[cfg(test)]` modules
- Edge cases are tested (boundary values, error paths, overflow)
- Tests run on host macOS target — no x86 hardware dependencies in test code

## 8. Documentation Sync — category table

Docs in this repo are categorized by how they relate to the code, and that determines whether they auto-refresh on a code change. The **concrete 8-item checklist** for §8 lives in CLAUDE.md (it fires every change and is the most drift-prone part of the protocol); the category rules below are the ruleset it draws from.

| Category | Files | Auto-refresh? | Rule |
|---|---|---|---|
| **implementation_reference** | [STATUS.md](../STATUS.md), [SCHEDULER.md](../src/scheduler/SCHEDULER.md), [ASSUMPTIONS.md](ASSUMPTIONS.md), and any `*.md` colocated with code that documents *current* implementation | **Yes** | If your change moves a subsystem's status (built/in-progress/planned), test count, known issue, implementation detail, or numeric bound, update the matching doc *in the same change*. Set `last_synced_to_code:` in the frontmatter to today's date. |
| **decision_record** | [docs/adr/](adr/) ([INDEX.md](adr/INDEX.md)) | **Append-only divergence** | The original decision text is immutable history — never rewrite it. If a decision is wrong or superseded, write a new ADR that supersedes it. However, when implementation diverges from the plan described in an ADR (deferred work, changed approach, new information), append a **`## Divergence`** section at the end of the ADR documenting *what* changed and *why*. This keeps the original reasoning intact while ensuring the ADR doesn't silently become fiction. ADRs must NOT contain status info ("X tests passing", "currently implemented in Y") — that drifts. They can name files and structs as a starting point, but never as a current-state claim. **No forward numeric ADR references.** Do not write "future ADR-NNN" or link to an ADR number that doesn't exist yet — such references age into lies when ADR-NNN lands with different content (or lands at a different number entirely). Reference future work by concept ("future init-process ADR", "when the bulk-channel decision lands") instead. After editing any ADR, run `make check-adrs` to verify every `ADR-NNN` reference resolves to an existing, non-superseded ADR and to regenerate [docs/adr/INDEX.md](adr/INDEX.md). |
| **design / source_of_truth** | [CambiOS.md](CambiOS.md), [identity.md](identity.md), [FS-and-ID-design-plan.md](FS-and-ID-design-plan.md), [win-compat.md](win-compat.md), [PHILOSOPHY.md](PHILOSOPHY.md), [SECURITY.md](SECURITY.md), [GOVERNANCE.md](GOVERNANCE.md) | **No** — human only | These describe intent and design, not current state. If implementation reveals a design problem, propose the change to the user; don't silently rewrite. They link to STATUS.md for the implementation status of any phase or feature. |
| **index** | [README.md](../README.md), [CLAUDE.md](../CLAUDE.md) | **Light touch** | Update only when the structure changes (new doc, new ADR, new build command, new lock in the hierarchy). Status info goes in STATUS.md, not here. |
