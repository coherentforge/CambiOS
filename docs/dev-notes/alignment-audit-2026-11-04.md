# Alignment audit, 2026-11-04: what the documents say is enforced, and what runs

Written for collaborators, human and agent, joining the project. It records a one-time stress test of the project's stated guardrails (CLAUDE.md, README, GOVERNANCE, SECURITY, the threat model, CLAIMS.md, the ADRs) against what the repository enforced on the audit date: Makefile targets, `tools/check-*`, `.githooks/`, the GitHub workflows, branch protection and CODEOWNERS.

Read it as a dated snapshot. The gate map below describes the tree at commit `eb8a5f4`, before any remediation. Each finding is closed by the commit that fixes it, not by an edit to this file.

## Method

1. Three read-only exploration passes: the internals of every gate and every hand-copied configuration list; every claim the intent documents make about gates, proofs, fuzzing, signing and process; the path a new collaborator takes on a fresh clone, and the code lanes no gate covers.
2. Headline findings were re-run by hand (lint exit codes, `gh api` branch protection, `cargo kani --only-codegen`, a key derivation, a `cargo fuzz` build).
3. A verification pass judged every finding through three independent lenses and kept it only if at least two held: the cited line says what the finding claims; no other mechanism already covers the gap; no commit or open pull request already fixes it. Verifiers were read-only and told to refute when unsure.
4. A completeness sweep then read the ADRs, the manuals, `SYSCALLS.md`, `INTERRUPT_ROUTING.md`, the design documents, the STATUS tables, `manifest.toml` against the image recipes, and the crate headers. It ran four rounds. Every round still found new items, so the sweep is a sample of the document drift, not a census.

| | Count |
|---|---|
| Findings from the exploration passes | 85 |
| of those verified / refuted | 84 / 1 |
| Fresh findings from the sweep, verified | 364 |
| Verified findings in total | 448 |
| Verification agents | 203 |

Limits. Verifiers did not build or run the kernel, so findings that depend on a build were confirmed by hand in step 2. Sixteen findings were kept on two lenses of three and are marked †: in each the substance held and one detail (a count, a quoted phrase, a line number) did not. Linux behaviour of the QEMU run targets was not exercised.

| Tier | Meaning | Verified findings |
|---|---|---|
| P0 | A gate reports green without running, or a statement of enforcement is false | 22 |
| P1 | A document misleads a reader about what exists or is enforced | 347 |
| P2 | A binding mechanism is missing: a list or rule is hand-copied with nothing checking the copies | 48 |
| P3 | The development contract assumes one host | 20 |
| P4 | A governance decision only the maintainer can make | 8 |

## What green meant on the audit date (P0)

These are the findings where a check, a required status or a sentence said "enforced" and the repository did not enforce it.

- **A1** `.github/workflows/ci.yml:141` The lints job runs check-adrs, check-assumptions, check-deferrals, check-boot-panics, check-banned-paths, check-unsafe-coverage, check-status-freshness --strict and does NOT run check-fail-open, check-doc-refs or check-audit-taxonomy.
- **A3** `tools/check-doc-refs.py:42` Running `python3 tools/check-doc-refs.py` from the repo root exits 1 today with ~44 findings / 46 baseline / ~37 new; SCAN_DOCS is a single hardcoded doc (docs/ASSUMPTIONS.md); nothing in CI or hooks runs it.
- **A6** `.github/workflows/proofs.yml:75` The dorny/paths-filter list (6 kernel files + verification/** + the workflow) and the 6-crate matrix are hand-copied; when no listed path changes, the kani jobs skip the Kani steps and report success.
- **A9** `gh:runs` `gh run list --workflow=boot-smoke.yml --branch main --limit 8` shows failures on every scheduled run from 2026-10-30 through 2026-11-04 and the last success on 2026-10-29.
- **A10** `Makefile:1915` fuzz-build and fuzz-syscall-dispatcher hardcode `cargo +nightly fuzz … --target x86_64-apple-darwin`; no CI workflow runs any fuzz target.
- **A11** `src/syscalls/fuzz_fixture.rs:88` `task_id: TaskId(FIXTURE_TASK)` constructs TaskId with a private field (src/scheduler/task.rs `pub struct TaskId(u64)`), so the fuzz build of the kernel fails with E0423; TaskId field became private in 3cea74e (2026-06-04).
- **A12** `fuzz/fuzz_targets/fuzz_capability.rs:14` The target assumes the per-process capability table fills at 32 entries (also near line 89) while src/ipc/capability.rs MAX_CAPS_PER_PROCESS is 64.
- **A14** `.git/hooks/pre-commit:19` `git config --get core.hooksPath` is not `.githooks` on the maintainer's clone; the active .git/hooks/pre-commit (dated 2026-04-21) runs only tools/check-index-isolation.py and .git/hooks has no commit-msg or pre-push hook.
- **A25** `tools/check-deferrals-baseline.txt:1` About 340 of ~487 lines are paths under tools/mcp-rust-analyzer/.venv/… (a gitignored venv per .gitignore); CI never sees those paths, so the committed baseline encodes machine-local entries.
- **A30** `tools/check-adrs.py:121` check-adrs rewrites docs/adr/INDEX.md as a side effect and exits 0 when cross-refs resolve, so a stale committed INDEX.md passes CI (ci.yml comment at ~132-134 says so).
- **B6** `gh:run-35011228949` `gh run view 35011228949 --json conclusion,event,headSha` shows conclusion=failure, event=push, headSha=e40096e… (2026-09-15), i.e. a red required Kani check on a commit that was pushed directly to main; every later proofs.yml run on main reports …
- **E1** `verification/capability-proofs/src/lib.rs:534` `mgr.revoke(holder, endpoint, attacker, bootstrap)` passes 4 arguments while src/ipc/capability.rs `pub fn revoke(&mut self, holder, endpoint, revoker)` (near line 784) takes 3; the harness (P3.12 near line 521) also still encodes the retired …
- **E2** `Makefile:190` `SIGN_MODE ?= seed` is the default while the comment at ~189 says "yubikey (default)"; BOOTSTRAP_SEED_HEX at ~193 is the ASCII of "ArcOS-Bootstrap-Identity-Phase0!"; the Ed25519 public key derived from that seed equals bytes 8..40 of the committed …
- **E10c** † `STATUS.md:27` STATUS.md ~27 and ~150 say 48 harnesses / 48 passing harnesses; 12 capability-proofs harnesses do not compile, so at most 36 pass; ~239 per-lib test counts (libgui 26, libinput-proto 8, libgui-proto 13) differ from the source (42, 11, 23).
- **E14e** `README.md:198` README ~198 says "Commits are PGP-signed. The repo enforces signing at the Git level; unsigned commits will not land." GitHub required_signatures is disabled and `git log -120 --format=%G?` shows 4 bot squash-merge commits as E (web-flow key), not G.
- **adr-a-crit-02** `docs/adr/000-zta-and-cap.md:226` Least privilege: a serial driver gets send/recv on the serial endpoint and `WaitIrq` for the serial IRQ. Nothing else. *Found:* CapabilityKind (src/ipc/capability.rs) has no WaitIrq/IRQ variant. handle_wait_irq (dispatcher.rs:920-934) does no capability check: any caller that passes policy_check can register for any IRQ below …
- **adr-a-crit-03** † `docs/adr/000-zta-and-cap.md:151` A future fork that weakens any of these properties is observable as a Kani failure in CI. *Found:* verification/capability-proofs does not compile against the current revoke signature (E1). proofs.yml skips Kani unless a listed path changes (A6). The weakened bootstrap-revoke rule merged with no Kani …
- **adr-a-crit3-01** `docs/adr/000-zta-and-cap.md:146` Verified property: Full process revocation — revoke_all_for_process clears every endpoint capability and every system-cap flag *Found:* capability.rs:879-888 resets 10 flags but never unlock_volume (:218). Harness P3.11 (capability-proofs lib.rs:472-512) grants and asserts only 5 of 11 system caps, so the gap is not proved.
- **adr-c-10** `docs/adr/023-audit-consumer-capability.md:99` test_revoke_all_clears_every_system_capability walks all variants; adding a variant without updating the test array trips the next CI run (also :58 every system cap must reset in revoke_all_for_process) *Found:* The test (capability.rs:1368) hand-lists 8 kinds and omits CreateCluster, ClusterRevoke, UnlockVolume. revoke_all_for_process (~873-886) never resets unlock_volume. CI stays green.
- **man-cr-2** `docs/manuals/04-driver-isolation.md:54` PortIo: the kernel ensures the driver can only talk to the specific device it's been granted access to. *Found:* handle_port_io (dispatcher.rs:2119) only checks pci::is_port_in_pci_bar(port) (pci/mod.rs:1110-1127), which accepts any I/O BAR of any discovered PCI device. Nothing binds a caller to a device, so any port-io …
- **dd-crit-02** `docs/CambiOS.md:111` Capability manager: every IPC endpoint, every memory region, every hardware resource is accessed through capabilities. *Found:* handle_map_mmio (dispatcher.rs:1673-1712) and handle_allocate/handle_alloc_dma check no capability, only RAM overlap; any non-RAM phys addr is mappable. CapabilityKind::LegacyPortIo says 'not yet checked …

Not listed here: one P0 finding that has a concrete route to misuse, and the code defects that surfaced when the dormant fuzz targets were run again. They are tracked with the maintainer and will be recorded in the commits that fix them.

## Gate map at `eb8a5f4`

Where each gate ran on the audit date. "Required check" means the job name is in branch protection for `main`. "Prose only" means a document states the rule and nothing checks it. Rows marked (unconfirmed) could not be fully confirmed by the reviewing pass.

| Gate | Ran where | Main gaps |
|---|---|---|
| make check-all (check-x86 / check-aarch64 / check-riscv64) + ci.yml `build (<target>)` matrix | make target, CI, required check | Workspace-excluded crates (user/*, cambios-*, tools/*, verification/*) and the separate fuzz/ workspace are never built per PR (A1d); No hook runs it, so ADR-013's 'mandatory before every commit' has no local enforcement. enforce_admins=false lets direct pushes to main land before … |
| make check-stable | make target | Skips riscv64. Its echo still says 'RISC-V intentionally excluded — see Makefile comment' although riscv64 is in check-all, and CLAUDE.md still says …; Pre-approved in .claude/settings.json next to check-all, while verify-all, check-clippy, test and check-doc-refs are not (ec-crit-2) |
| make test + ci.yml `unit tests (--lib)` job | make target, CI, required check | 543 #[test]s in tracked .rs files outside src/ run under no target or job. Examples: cambios-abi ABI coverage tests, cambios-manifest (34), …; policy-service has 0 tests despite ADR-006's testing claim. libterm and init headers claim a bare `cargo test` works (adr-a-crit-06, crate- … |
| make check-clippy (check-clippy-x86 / -aarch64 / -riscv64) + ci.yml `clippy (unsafe … | make target, CI, required check | --lib only: the [[bin]] src/microkernel/main.rs and its 59 `unsafe {` blocks are never clippy-linted (A4, A5); Workspace-excluded crates (user/, cambios-*, tools/) are never clippy-linted at all |
| crate-attr: Cargo.toml [lints.clippy] missing_safety_doc = "deny" | compiler lint, make target, CI, required check | The comment says 'we run at `warn` only while a known-incomplete back-fill is in flight', but the value is deny (A29); Not evaluated for the bin target (clippy --lib) or by plain cargo build (A4) |
| crate-attr: src/lib.rs #![deny(clippy::undocumented_unsafe_blocks)] + … | compiler lint, make target, CI, required check | src/microkernel/main.rs has only no_std/no_main/deny(unsafe_op_in_unsafe_fn), so its 59 unsafe blocks get no clippy unsafe-discipline lint (A5, A4); user/ crates carry no equivalent deny. ~19 user unsafe blocks have no SAFETY comment (A19) |
| crate-attr: #![deny(unsafe_op_in_unsafe_fn)] (src/lib.rs:7, src/microkernel/main.rs:6, … | compiler lint, make target, CI, required check | user/libgui (and every other user crate) is never built per PR (A1d); No other user/ or cambios-* crate carries this deny |
| crate-attr: Cargo.toml [lints.rust] unexpected_cfgs (warn; check-cfg fuzzing, kani) | compiler lint | Warn level with no -D warnings anywhere, so it never blocks; Not applied to user/, cambios-*, tools/ or fuzz/ crates |
| crate-attr: user/* #![deny(unsafe_code)] (25 crate-root files incl. cambios-fde-proto) / … | compiler lint, make target, CI | No per-PR build of any user crate, so a violation surfaces only locally or in the non-required nightly boot-smoke (A1d); No SAFETY-comment gate or clippy unsafe lint over user/ (A19) |
| Kernel no-panic / no-unwrap / no-expect rule (README) — clippy::expect_used / unwrap_used / … | prose only | Non-test .expect() exists in src/fs/crypto/encrypted_device.rs:166/193 and src/fs/posix/mod.rs:564/575 (E3); README ~200 claims no panics/unwraps/expects (E14j) |
| ci.yml `baseline lints` job (aggregate) | CI, required check | Does not run check-fail-open, check-doc-refs or check-audit-taxonomy, and the exclusion comment does not mention them (A1, A1b); The ci.yml header still says Tier C boot smoke is deferred, but boot-smoke.yml exists (A1c) |
| make check-adrs (tools/check-adrs.py) | make target, CI, required check | Rewrites INDEX.md and exits 0 when refs resolve, so a stale committed INDEX passes CI (A30); Superseded detection is status.lower().startswith('superseded'), so 'Stale — superseded by ADR-028' is never flagged. The status vocabulary is not … |
| make check-assumptions (tools/check-assumptions.py) | make target, CI, required check | Fixed-size arrays and inline literal bounds (64 MiB SYS_ALLOCATE, 16384, 32768) are invisible to it (dd-c-12, adrb-c-2); 302 untagged consts are grandfathered in the baseline (dd-c-12) |
| make check-deferrals (tools/check-deferrals.py) | make target, CI, required check | A bare 'Phase N' / 'R-N' counts as a valid trigger, in tension with Convention 10 (A23); Skips cambios-*/src, tools/*/src (Rust), verification/** (incl. CLAIMS.md), fuzz/, README.md, Makefile, manifest.toml and .github/. Walks the … |
| make check-boot-panics (tools/check-boot-panics.py) | make target, CI, required check | Excludes src/microkernel/main.rs, src/arch/*/mod.rs and src/manifest.rs, where boot manifest transcription runs (A17, adrb-c-1); The is_dir()/is_file() guards (lines 80/82) silently skip a renamed or missing listed file (A17) |
| make check-banned-paths (tools/check-banned-paths.py) | make target, CI, required check | In CI's fresh checkout it can only catch a re-add to git. The untracked-leftover class it was written for is visible only locally, and the tracked …; The list is manual (3 entries): nothing appends deleted paths automatically |
| make check-unsafe-coverage (tools/check-unsafe-coverage.py) | make target, CI, required check | user/, cambios-*, tools/, fuzz/ and verification/ are not scanned. ~19 user/ unsafe blocks lack SAFETY (virtio-net virtqueue x12, compositor, …; The script's baseline header (~248) cites an untracked private plan ('prancy-manatee plan'), not a machine-local filesystem path (E12) |
| make check-status-freshness / tools/check-status-freshness.py --strict | make target, CI, required check | Passes silently when STATUS.md states no total. Never checks crate membership, or whether harnesses compile or pass (A22); STATUS.md claims 48 passing harnesses (lines 27, 152) while the 12 capability-proofs harnesses do not compile (4-arg revoke vs the 3-arg signature … |
| make check-fail-open (tools/check-fail-open.py) | make target | Run by no CI job or hook (A1). CLAUDE.md lists it with no wiring (E11d); cambios-blk/fde/ccid-proto, tools/build-manifest/src, manifest.toml, verification/, fuzz/ and docs/ are not scanned (A20) |
| make check-doc-refs (tools/check-doc-refs.py) | make target | Red today: exit 1, '44 total findings, 46 baseline, 37 new' (A3, re-observed); Not in CI or any hook (A3, A1). Not in the .claude allowlist |
| make check-audit-taxonomy | make target | Not run by CI or .githooks/pre-commit, although its comment says '(and in the commit gate)'. ADR-007 claims the doc 'cannot drift' (E14d, adr-a-23, …; stderr is sent to /dev/null, so a generator build failure is reported as 'stale'. The generator is pinned to aarch64-apple-darwin via tools/gen- … |
| make check-index-isolation (tools/check-index-isolation.py) | make target, pre-commit hook | It is the only lint the active .git/hooks/pre-commit (2026-04-21) runs, so it is the one local commit gate that actually fires (A14); Excluded from CI by design, so web/bot/PR merges and --no-verify bypass it (A1b) |
| make check-lockfile (tools/check-lockfile-additions.py) | make target | Always exits 0. The other 55 tracked Cargo.lock files are ignored (A21); Tracked pre-commit wiring is inactive (A14). Excluded from CI (A1b). Missing from .PHONY (A27) |
| .githooks/pre-commit (tracked hook script) | nowhere | On the maintainer clone core.hooksPath is explicitly /Users/jasonricca/coding/cambios/.git/hooks, so this file never runs (A14); Even when installed it does not run check-all, clippy, test, check-fail-open, check-audit-taxonomy, check-adrs, check-deferrals, check-assumptions … |
| .git/hooks/pre-commit (active, untracked, 2026-04-21) | pre-commit hook | Untracked and diverged from .githooks/pre-commit. The four other tracked lints never run locally (A14); No commit-msg or pre-push hook exists in .git/hooks (only *.sample files) (A14) |
| commit-msg: tools/check-claude-staged-files.py (.githooks/commit-msg) | nowhere | No commit-msg hook is installed on the maintainer clone (A14); Case-sensitive literal trigger: Codex/Copilot/other trailers or no trailer are ungated (A15) |
| commit-msg: tools/check-preflight-discipline.py (.githooks/commit-msg) | nowhere | Hook not installed (A14); Skipped when CLAUDE_PREFLIGHT_SESSION is unset (gradual-rollout bypass, per the hook header) |
| pre-push: tools/check-edit-window.py (.githooks/pre-push) | nowhere | No pre-push hook is installed (A14). The install-hooks echo omits pre-push (E14l); Warns but passes when no edit logs exist. The logs come only from the untracked PostToolUse hook (A16) |
| make claude-preflight + Claude Code PreToolUse hook (tools/claude-preflight.py) | make target | The hook exists only in .claude/settings.local.json, which is gitignored (.gitignore:46). Tracked .claude/settings.json has no hooks (A16); The hook can never block (stdout to /dev/null, `// true`). It is advisory at best |
| Claude Code PostToolUse hook: tools/log-claude-edit.py | nowhere | Lives only in gitignored settings.local.json (A16); Its docstring cites the machine-local ~/.claude/plans path (E12). Its only consumer (pre-push) is not installed |
| make install-hooks | make target | Never run on the maintainer clone: core.hooksPath is the absolute .git/hooks path (A14); The echo mentions only pre-commit + commit-msg, not pre-push (E14l). Missing from .PHONY (A27) |
| tools/check-demo-readiness.sh | nowhere | Referenced by no tracked file other than itself: Makefile, CI, hooks or docs (A26); Yet another hand-copied arch list (D1) |
| proofs.yml `changes` job (detect proof-relevant changes) | CI | Hand-copied list and matrix. When no listed path changes, all 6 required kani checks report success without running Kani (e.g. PR #9: each kani …; Proof-relevant inputs outside the list (types the capability-proofs stubs mirror from src/ipc/mod.rs, cambios-abi) do not retrigger (adr-a-crit3-02) |
| proofs.yml `setup` job (Kani install/cache) | CI | KANI_VERSION is hand-pinned with only a 'keep in lockstep' comment. Nothing checks it against the Makefile or the local `cargo kani --version` (A7); Skipped when the paths filter is false. Not a required check |
| Kani capability-proofs: make verify-capability + proofs.yml `kani (capability-proofs)` | make target, CI, required check | Does not compile: the harness calls mgr.revoke(holder, endpoint, attacker, bootstrap) (4 args) against the 3-arg signature at capability.rs:784, and …; CI stays green because the path filter skips it. The last real run (e40096e, a direct push to main) concluded failure, and every later main run is a … |
| Kani buddy/elf/frame/userslice/dtb: make verify-buddy/-elf/-frame/-userslice/-dtb + … | make target, CI, required check | They report success as no-ops whenever the hand-copied path filter does not match (A6, B4). Recent main runs do not show whether they pass at HEAD; proofs.yml concurrency is cancel-in-progress per ref; several main pushes (049a2ec, 13a07a3, d1bacff) ended cancelled with no completed Kani result |
| make verify / make verify-all | make target | Fails at verify-capability today because capability-proofs does not compile, so userslice and dtb never run in the aggregate (without make -k) (E1); Not 'the single canonical list' its comment claims: proofs.yml's matrix/filter and Cargo.toml's exclude hold independent copies (E14l, A6) |
| make fuzz-build / make fuzz-syscall-dispatcher (fuzz/ — 5 targets) | make target | No CI workflow runs any fuzz target. The target triple is hardcoded to darwin (A10); `cargo +nightly` overrides the rust-toolchain.toml pin (nightly-2026-02-07), so the fuzz build uses an unpinned floating nightly |
| boot-smoke.yml `boot-smoke (x86_64)` job (make run-quiet) | CI | Not per-PR and not a required status check (A8); Red on every scheduled run since 2026-10-30 (6 consecutive failures through 2026-11-04). The 2026-11-04 run timed out with no shell sentinel after … |
| make run-quiet / make run-quiet-dev-piv | make target, CI | Only plain run-quiet runs in CI (nightly, non-required). run-quiet-dev-piv (FDE path) runs nowhere automated (A8); DISK_BUS is not coupled to PROFILE, so the disk can end up with no driver (man-c-04) |
| tools/build-manifest validation (make manifest / manifest-profile / manifest-headless / … | make target, CI | No per-PR job runs build-manifest. headless, framebuffer-fallback, aarch64 and riscv64 cells are never built in CI (man-crit-1); Reserved-endpoint uniqueness is unchecked (24/25/30) (man-crit-2) |
| GitHub branch protection on main | required check | required_signatures=false. strict=false (no up-to-date requirement). enforce_admins=false, so direct pushes to main bypass checks (e40096e landed …; required_approving_review_count=0, dismiss_stale_reviews=false, require_last_push_approval=false, and required_conversation_resolution and … |
| .github/CODEOWNERS | required check | No owner for user/, verification/ (proofs could be made vacuous), docs/ non-adr, README.md, STATUS.md, Cargo.toml, every Cargo.lock, rust- …; Open PR #9 (README + new spec/ dir) matches no rule and is mergeable with 0 approvals. It has not merged (state OPEN), contrary to the original … |
| Actions / external-input pinning (repo settings + Limine fetch) | nowhere | No SHA pinning or allowlist of actions (B3); Limine comes from `--branch=v8.x-binary --depth=1` and is re-fetched only when its files are missing (F7) |
| make check-claims (documented, nonexistent) | prose only | No Makefile target or tools/ script exists (grep confirms). Drift has already happened: C-10 cites a non-existent test name, and C-4 says the suite …; The ADR-034 invariant was never added as a CLAIMS row (adr-d-8) |
| make check-phase-refs (documented, nonexistent) | prose only | No target or script. The recurrence has already happened: `// Phase 1: begin.` / `// Phase 2: complete.` in src/ipc/channel.rs:1711/1719, plus …; check-deferrals itself accepts bare 'Phase N' as a trigger (A23) |
| Commit-signature enforcement (README: 'unsigned commits will not land') | prose only | GitHub required_signatures.enabled=false (B1); `git log --format=%G?` shows 5 E commits in the last 300, all GitHub web/PR merge commits (E14e) |
| Lock-hierarchy / lock-rank enforcement (README: 'enforced in source') (unconfirmed) | prose only | Position numbers in comments and docs have drifted (INTERRUPT_ROUTER 7/8 vs 9, PROCESS_TABLE 6 vs 7, OBJECT_STORE 8/9 vs 10, '1-8 hierarchy') with …; BLOCK_BITMAP_LOCK and JOURNAL_LOCK are declared in the order but never acquired (adr-c-12) |
| Constant / endpoint lockstep invariants (manifest.toml endpoints vs client consts; … (unconfirmed) | prose only | ~35 hardcoded endpoint consts copy manifest.toml (man-crit2-3); The MAX_MANIFEST_ENTRIES trio is tied only by comments (adrb-crit-4). The GUEST_GRANTS_MAX=32 lockstep is already broken vs 64 (adr-d-1). … |
| Bootstrap trust-root provenance (docs: YubiKey-held key, 'yubikey (default)' signing) | prose only | The committed key equals the pubkey derived from the public ASCII BOOTSTRAP_SEED_HEX (not re-derived in this pass), and the Makefile comment says …; README, SECURITY.md, main.rs comments, ADR-004/032, manuals, FS-and-ID plan, identity.md, STATUS and CambiOS.md all assert hardware-backed identity … |
| Per-tier kernel builds (CAMBIOS_TIER tier1/tier2/tier3 as a 'supported build axis') | prose only | tier1/tier2 code is never compiled or tested (adr-a-25); Docs say the kernel binary is identical across tiers and selected at install, while it is compile-time. ADR-008's Cargo-feature design is unrecorded … |
| Arch-isolation invariants (no #[cfg(target_arch)] in src/fs; no asm! outside src/arch; factor … (unconfirmed) | prose only | The src/fs rule holds today (0 cfg(target_arch) hits) but no lint enforces it (dd-x-11); 3-way inline asm sits in portable code (lib.rs halt, policy cli/sti, dispatcher) and the promised helpers do not exist (adrb-crit-2) |
| Disassembly verification of typed-MMIO zero cost (ADR-036) | prose only | Step commits record manual QEMU boots only. #[inline(always)] is the only safeguard (adr-d-crit-6) |
| Published-doc freshness (make sync-site-check / sync-site; doc_type + last_synced_to_code … (unconfirmed) | make target | Stale SYSCALLS.md (18 of 72 syscalls) and INTERRUPT_ROUTING.md publish with no header or gate (SD1, SD9); manuals/, SECURITY.md, threat-model.md and developer-experience.md have no header or freshness check (man-cr-3, E6c, E7a, E8) |
| make verify-usb | make target | Manual and macOS-only (diskutil). The usb recipe silently skips unmount on Linux (sr-crit-5, F6); Not a code gate. Run nowhere automated |
| rust-toolchain.toml nightly pin (nightly-2026-02-07 + 4 targets) | CI, make target | fuzz targets use `cargo +nightly`, which bypasses the pin with a floating nightly; Kani uses its own bundled toolchain (proofs.yml header), so proofs and the kernel build are compiled by different compilers |
| CI concurrency: cancel-in-progress per ref (ci.yml / proofs.yml / boot-smoke.yml) | CI | Back-to-back pushes to main cancel the previous commit's run, so intermediate main commits get no completed required checks. Proofs runs for …; Combined with enforce_admins=false and direct pushes, a commit can land on main and never be verified (B6) |
| Don't-grow baselines (tools/check-*-baseline.txt + make update-*-baseline) | make target, CI, required check | Nothing checks that a baseline only shrinks. A commit that runs update-*-baseline alongside new violations passes every lint, and only CODEOWNERS …; Machine-local entries (340 .venv lines in the check-deferrals baseline) inflate the baseline beyond what CI sees (A25) |

## Missing binding mechanisms (P2)

Lists and rules that exist in several hand-maintained copies, or rules stated in prose that a small lint could hold.

- **A1d** `.github/workflows/ci.yml:71` The build job runs `cargo build --target X --release` at the repo root, which builds only the kernel crate; user/, cambios-*/, tools/, fuzz/ are workspace-excluded (Cargo.toml:7) and never built per PR.
- **A4** `Makefile:1891` check-clippy-* run `cargo clippy --target <t> --release --lib`, so the [[bin]] src/microkernel/main.rs is never clippy-linted.
- **A5** `src/microkernel/main.rs:4` main.rs crate attributes are only no_std/no_main/deny(unsafe_op_in_unsafe_fn): no clippy::undocumented_unsafe_blocks or multiple_unsafe_ops_per_block deny; the file has ~59 `unsafe {` blocks.
- **A7** `.github/workflows/proofs.yml:55` KANI_VERSION "0.67.0" is hand-pinned with a comment to keep it in lockstep locally; nothing checks it against the Makefile or the local version.
- **A8** `.github/workflows/boot-smoke.yml:34` Boot smoke runs only on schedule (nightly) + workflow_dispatch, x86_64 only, and is not a required status check (branch protection contexts list 12 checks, none named boot-smoke).
- **A15** `tools/check-claude-staged-files.py:102` The gate triggers only on the case-sensitive literal "Co-Authored-By: Claude"; commits with other agent trailers (Codex, Copilot) or none are not gated; the same literal is used in check-preflight-discipline.py and check-edit-window.py.
- **A16** `.gitignore:46` .claude/* is gitignored except settings.json, so the PreToolUse (claude-preflight) and PostToolUse (log-claude-edit) hooks that CLAUDE.md describes live only in the untracked settings.local.json.
- **A17** `tools/check-boot-panics.py:62` SCAN_PATHS is a hardcoded list (src/boot dir + ~8 named arch files, ~13 of ~95 src files); it does not include src/microkernel/main.rs or src/arch/*/mod.rs, and the is_dir()/is_file() guards skip a renamed or missing listed file silently.
- **A19** † `tools/check-unsafe-coverage.py:46` SCAN_DIRS = ["src"]; running the same scanner over user/ finds ~19 `unsafe {` blocks with no preceding // SAFETY: comment (virtio-net virtqueue.rs ×12, virtio-net main.rs ×2, compositor, libgui ×2, usb-host xhci.rs, virtio-blk virtqueue.rs).
- **A20** `tools/check-fail-open.py:60` SCAN_DIRS = ["src","user","cambios-abi/src","cambios-manifest/src"]; cambios-blk-proto, cambios-fde-proto, cambios-ccid-proto, tools/build-manifest/src, manifest.toml, verification/, fuzz/ and docs/ are not scanned.
- **A21** † `tools/check-lockfile-additions.py:85` Only the root Cargo.lock is inspected; `git ls-files "*Cargo.lock"` lists ~56 tracked lockfiles; the script always exits 0 (advisory).
- **A22** `tools/check-status-freshness.py:99` --strict compares only the harness TOTAL in STATUS.md ("N harnesses across M proof crates" / "N passing harnesses") against a count of #[kani::proof] lines; it passes silently if STATUS.md states no total, and never checks crate membership in …
- **A23** `tools/check-deferrals.py:62` A bare "Phase N" or "R-N" token counts as a valid Revisit-when trigger (lines ~62/66), in tension with CLAUDE.md Convention 10.
- **A24** `tools/check-deferrals.py:70` The scanner skips cambios-*/src, tools/*/src, verification/** (incl. CLAIMS.md), README.md, Makefile, manifest.toml and .github/, and walks the filesystem (not git ls-files), so gitignored files under scanned dirs are included.
- **A27** `Makefile:214` The .PHONY line omits at least: check-assumptions, check-banned-paths, check-boot-panics, check-lockfile, check-status-freshness, check-unsafe-coverage, install-hooks, run-quiet, update-assumptions-baseline, update-boot-panics-baseline, update- …
- **D1** `rust-toolchain.toml:9` The arch list is spelled out independently in rust-toolchain.toml targets, .cargo/config.toml target sections, ci.yml build matrix (~57-60) and clippy rustup line (~112), Makefile check-all/check-stable/check-clippy/kernel-*/manifest-* and ~71 per- …
- **D2** `Cargo.toml:7` workspace.exclude lists 37 user crates and omits user/dhcp-client (a vestigial dir with Cargo.toml + link scripts and no src/) and fuzz/ (fuzz/Cargo.toml has its own [workspace] table so cargo tolerates it); the Makefile has no …
- **E3** `src/fs/crypto/encrypted_device.rs:166` Non-test kernel code calls .expect() at encrypted_device.rs:166 and :193 and at src/fs/posix/mod.rs:564 and :575; no clippy::expect_used / unwrap_used lint is enabled anywhere (Cargo.toml [lints], src/lib.rs attrs).
- **E4a** `src/ipc/channel.rs:1711` Comments `// Phase N:` step labels exist at src/ipc/channel.rs ~1711 and ~1719 and src/syscalls/dispatcher.rs ~3540 and ~3555, added after the Convention-10 sweep (a15a743); CLAUDE.md Convention 10 says `make check-phase-refs` "lands on first …
- **E4b** `verification/CLAIMS.md:54` CLAIMS.md says `make check-claims` is the planned drift gate (mechanism on first drift); no such Makefile target or tools/ script exists; C-10 (~145) cites test_revoke_all_for_process, which is not an exact function name in src/ipc/capability.rs; …
- **F2** `cambios-abi/.cargo/config.toml:15` cambios-abi/.cargo/config.toml ~15-17 claims the kernel's `cargo test --lib` exercises its tests through the re-export; it does not (cargo test --lib runs only the root package). Excluded crates carry ~543 #[test] functions in total (user/ ~459: …
- **F4** † `user/libgui/Cargo.lock:1` No `--locked`/`--frozen` appears in the Makefile or workflows; the committed Cargo.lock in user/libfs, user/libgui and user/libterm lists cambios-libsys without cambios-abi (stale relative to libsys's current deps); fuzz/Cargo.lock predates the …
- **S1** `src/arch/mod.rs:10` The "Adding a new architecture" checklist (~10-15) lists only code steps (mod.rs, cfg block, SavedContext etc.) and omits rust-toolchain.toml, .cargo/config.toml, Makefile targets, CI matrix, linker script, and the check-boot-panics file list.
- **SD1** `docs/SYSCALLS.md:3` All 18 syscalls are fully implemented in src/syscalls/dispatcher.rs *Found:* cambios-abi/src/lib.rs SyscallNumber has 72 variants (0..=75 with 11/18/31/36 retired); the doc only documents 0-17 and is last touched 36d1cbb (2026-05-12). Nothing checks this doc against the enum.
- **SD9** `tools/sync-to-site.toml:73` SYSCALLS.md / INTERRUPT_ROUTING.md mapped to public site /docs/syscalls/ and /docs/interrupt-routing/ *Found:* Both stale docs are published to the public site via sync-site; no freshness/sync header (no doc_type/last_synced) and no gate before publishing.
- **EC2** `.claude/settings.json:3` allowlist covers the lint make targets *Found:* Makefile has check-boot-panics, check-fail-open, check-doc-refs, check-audit-taxonomy, check-clippy, verify-all; the allowlist has none of them. All 9 targets that are listed do exist.
- **adr-a-25** `docs/adr/008-boot-time-sized-object-tables.md:335` Each tier adjustment is a few fields in src/config/tier.rs followed by a rebuild (three tiers are a supported build axis). *Found:* No Makefile target or workflow sets CAMBIOS_TIER (grep Makefile .github .githooks: 0 hits), so cfg(tier1)/cfg(tier2) code (src/config/tier.rs:166-176) is never compiled or tested.
- **adr-c-23** `docs/adr/024-syscall-abi-crate.md:59` After the chain lands the canonical ABI lives in exactly one file; drift is structurally impossible *Found:* Tracked user/hello.S and user/hello-aarch64.S (built by Makefile user-elf / user-elf-aarch64, :246/:435) hardcode syscall numbers 0/7/8/10 in asm. They match today, but nothing ties them to cambios-abi.
- **adr-d-c8** `docs/adr/037-native-app-framework.md:103` L3 scaffolding: consolidate the 24 `link.ld` into one canonical script *Found:* The tree now has 26 user/*/link.ld and 73 user/*/link*.ld in total (per-arch variants included). No consolidation has happened and nothing tracks the count.
- **man-c-04** `Makefile:1002` DISK_BUS: virtio served by virtio-blk in `default`, nvme served by nvme in the bare-metal profiles (comment :995-1000) *Found:* DISK_BUS ?= virtio is independent of PROFILE ?= headless. Default `make run-img-usb` attaches virtio-blk-pci to a headless manifest that filters virtio-blk out (profile=[default]), and `run`/`run-quiet …
- **sr-c-8** † `STATUS.md:256` ELF loader overlapping-segment permissions: worked around in user-space linker scripts via ALIGN(4096) before .data *Found:* The shared templates user/user.ld (USER_LD, Makefile:37) and user/user-aarch64.ld have no ALIGN before .data. Of the 75 tracked user/*.ld files, the per-crate ones carry the workaround by hand-copy, and no …
- **dd-c-12** `docs/ASSUMPTIONS.md:35` Every fixed numeric const, fixed-size array, and MAX_* value in kernel code carries a doc comment that names its category. *Found:* tools/check-assumptions.py checks only `const NAME: <int type>` in src/**. It does not check fixed-size arrays. tools/check-assumptions-baseline.txt grandfathers 302 untagged consts (e.g. src/acpi/mod.rs:95 …
- **adrb-crit-2** `docs/adr/013-riscv64-architecture-support.md:160` Process commitment: when a 3-way cfg block emerges, factor arch::interrupts_enable(), arch::read_page_table_root(), arch::wait_for_interrupt() helpers when the third arm appears. *Found:* None of these helpers exist (git grep finds no such fn). 3-way cfg inline asm is still in portable code: src/lib.rs:1467-1491 halt(), src/policy/mod.rs ~636-680 cli/sti, dispatcher.rs:988. No lint flags asm! …
- **adrb-crit-4** `docs/adr/018-init-process-and-boot-manifest.md:177` `MAX_MANIFEST_ENTRIES` moves in lockstep with `MAX_BOOT_MODULES` (sized together for the v1-endgame service count). *Found:* All three are 128 today (cambios-manifest/src/lib.rs:101, src/boot/mod.rs:84, src/boot_modules.rs MAX_MODULES). Only 'keep the trio equal' comments tie them together; no const assert or test does, so a one- …
- **adr-d-crit-8** `docs/adr/INDEX.md:27` ADR-015 status 'Stale — superseded by ADR-028'; check-adrs is said to flag references to superseded ADRs *Found:* tools/check-adrs.py:88 flags only statuses where status.lower().startswith('superseded'). 'Stale — superseded…' does not match, so references to ADR-015 (e.g. from ADR-026) are never flagged, and the Status …
- **adr-d-crit-9** `docs/adr/032-full-disk-encryption-below-substrate.md:132` `MAX_SLOTS = 16` is SCAFFOLDING per Convention 8 (also :79, :185) *Found:* The const is named MAX_VOLUME_SLOTS (cambios-fde-proto/src/lib.rs:73). It has no docs/ASSUMPTIONS.md row, and check-assumptions scans only src/** (check-assumptions.py:79), so cambios-*-proto SCAFFOLDING …
- **man-crit-1** `manifest.toml:52` A dependant names a ROLE by endpoint and build-manifest resolves it to whichever kept entry owns it, so the emitted manifest is always a plain name dependency on the one driver this image carries. *Found:* Closure and owner checks run only when a make target builds that cell. No CI workflow or hook runs build-manifest. Only nightly boot-smoke builds x86 default; headless, fb-fallback, aarch64 and riscv64 never …
- **man-crit-2** † `manifest.toml:149` Endpoint 27 is the scanout-driver ROLE: exactly one driver owns it per profile (also :98 'One block driver serves the seam (endpoints 24/25/26) per image'). *Found:* build-manifest (main.rs ~355-395) checks single ownership only for endpoints in some depends_on_endpoints (26, 27). It never checks reserved endpoints for uniqueness, so 24, 25 and 30 (compositor vs headless …
- **man-crit-3** `manifest.toml:288` Headless posture of the same binary (built with the `headless-input` feature; `make img-x86 PROFILE=headless` stages it). *Found:* The second shell entry has no arch tag, so it is declared for aarch64/riscv64 headless too. Yet shell-aarch64/-riscv64 (Makefile:497,661) ignore SHELL_FEATURES. The swap at Makefile:1173 is keyed on the …
- **man-cr-3** `docs/manuals/README.md:1` The manuals narrate how CambiOS works today (present tense, real constants, syscalls, endpoints, IPs). *Found:* docs/manuals/* has no doc_type/last_synced_to_code header and was last touched 027d088 (2026-05-12). No lint, freshness check or sync-to-site entry covers docs/manuals, and check-doc-refs scans only …
- **ec-crit-2** `.claude/settings.json:9` Allowlist entry Bash(make check-stable *) pre-approves the stable gate *Found:* check-stable (Makefile:1867) runs only check-x86 and check-aarch64. The allowlist approves a 2-arch subset alongside check-all. No allowlist entry exists for verify-all, check-clippy, or test.
- **dd-x-11** `docs/FS-and-ID-design-plan.md:222` Architectural invariant (applies to every phase): no #[cfg(target_arch)] in src/fs/ or identity-related IPC changes. *Found:* This holds today (0 hits in src/fs), but no lint, hook or CI step enforces it. check-banned-paths and the other check-*.py scripts do not scan for target_arch in src/fs.
- **adr-d-crit2-3** `docs/adr/034-postponed-task-resource-reclamation.md:128` Open Problem: Revisit the reaper starvation bound when a per-CPU queue high-watermark > 25% of its bound under any test workload *Found:* No high-watermark is recorded. ReclaimQueue::len() (src/reaper.rs:124, doc'd 'for the high-watermark trigger') is never called; the queue is only used via push (reap.rs:456) and pop (reaper.rs:165). The …
- **man-crit2-1** `Makefile:807` manifest.toml:47-49 says `profile` tags select entries per deployment through `--profile`. manifest.toml:201 tags scanout-limine (framebuffer-fallback) for aarch64, and the headless shell entry (:293) has no arch tag, so it ships on every arch. *Found:* manifest-aarch64 (:807) and manifest-riscv64 (:815) never pass --profile, so PROFILE is ignored and they always emit `default`. `make img-aarch64 PROFILE=framebuffer-fallback` silently ships default; the …
- **man-crit2-2** `manifest.toml:127` fde-mount has no arch or profile tag and declares depends_on_endpoints=[26] ('nvme serves the same seam on bare metal'), so the entry is declared for every (arch, profile) cell. *Found:* Outside `default`, the only owner of endpoint 26 is nvme (arch=[x86_64]; virtio-blk is profile=[default]). For aarch64/riscv64 with headless or framebuffer-fallback, build-manifest :373-381 exits 1 ('no kept …
- **man-crit2-3** `manifest.toml:9` Never a parallel authority: change endpoints HERE; client const tables (libsys / libfs-proto / libgui-proto / libscanout) must agree until they are generated from this file. *Found:* About 35 hardcoded endpoint consts (user/*/src, cambios-blk-proto, src/policy/mod.rs:40/45, dispatcher.rs:433/1135) copy manifest.toml's numbers. No lint, test or build step compares any of them to …
- **man-crit2-4** `tools/build-manifest/src/main.rs:613` build-manifest is where filtering, closure, endpoint-owner resolution, duplicate-name and on-demand rules are enforced (manifest.toml:30,52; usage :216-223). *Found:* The crate has exactly 1 #[test] (same_name_disjoint_profiles…). Nothing tests endpoint-owner resolution (:355-395), the on-demand rules (:452-479) or reject_duplicate_names. No Makefile target or CI job runs …
- **man-crit2-5** `manifest.toml:37` Since step 9 this file is the ONLY grant authority — the kernel has no name-based grants left. *Found:* src/syscalls/dispatcher.rs:2372 and :2429 test `name == b"policy-service"`. The first maps the manifest blob into the new process; the second sets POLICY_SERVICE_PID/TASK (response-endpoint write gate + …

## Host portability (P3)

Places where the build, test and tooling contract assumes the maintainer's machine.

- **A26** `tools/check-demo-readiness.sh:1` No tracked file (Makefile, CI, hooks, docs) references check-demo-readiness.sh; it hardcodes arch/target lists and macOS-only remediation (brew, xcode-select).
- **F6** `Makefile:1346` `test:` hardcodes --target x86_64-apple-darwin (not overridable); HOST_TARGET ?= aarch64-apple-darwin (~109) affects only sign-elf/build-manifest/mkinitrd; gen-dev-piv-keys (~179/830), format-volume (~187/841), bake-font (~853-855) and gen-audit- …
- **F6b** `rust-toolchain.toml:13` rust-toolchain.toml lists x86_64-apple-darwin and no linux triple, and has no components = ["clippy"] (ci.yml adds clippy manually); tools/{sign-elf,build-manifest,mkinitrd,gen-dev-piv-keys,format-volume,gen-audit-taxonomy,bake- …
- **F7** `Makefile:877` Limine is cloned with `git clone --branch=v8.x-binary --depth=1` (a moving branch, not a tag/commit) into ~/.cache/cambios/limine and only re-fetched if BOOTX64.EFI/BOOTAA64.EFI is missing; there is no help/doctor/setup/bootstrap target; sign-elf …
- **F8** `.vscode/settings.json:87` .vscode/settings.json (tracked) carries x86_64-apple-darwin in task regexes near lines 87/91/95; user/ping/src/lib.rs ~5, user/worm/src/lib.rs ~5, user/sprouty/src/lib.rs ~6 give darwin-only test commands; STATUS.md ~212/239 and docs/review- …
- **E11b** `CLAUDE.md:45` CLAUDE.md ~45 says unit tests are `cargo test --lib` (runs natively on macOS); with .cargo/config.toml defaulting to x86_64-unknown-none a bare `cargo test --lib` fails; the Makefile uses --target x86_64-apple-darwin (Rosetta on Apple Silicon).
- **E11g** `.mcp.json:4` .mcp.json command is an absolute path under /Users/jasonricca/Library/CloudStorage/OneDrive-Personal/… and WORKSPACE_ROOT is /Users/jasonricca/coding/cambios; .gitignore ~21-25 says the server is the tools/mcp-rust-analyzer clone; CLAUDE.md ~324 …
- **EC1** `.cargo/config.toml:37` alias ktest = "test --lib" *Found:* [build] target = x86_64-unknown-none (line 5) applies to the alias, so `cargo ktest` builds tests for bare metal and fails. Working host tests need --target x86_64-apple-darwin (Makefile test:).
- **EC3** `CambiOS.code-workspace:8` workspace autoApprove settings *Found:* Untracked: git ls-files does not list it; excluded via .git/info/exclude:9. A 188-line machine-local copy of the tracked .vscode/settings.json autoApprove regex list.
- **EC4** `.vscode/settings.json:2` chat.tools.terminal.autoApprove list of exact one-off commands *Found:* Tracked file of ~45 exact regexes taken from past sessions (e.g. grep for send_message_with_capability, 'unexpected closing'), plus `make iso` chains. None cover make check-*/verify targets. Stale ad-hoc …
- **ec-c-1** `.vscode/settings.json:3` The tracked autoApprove list is the editor's terminal allowlist for the repo's build/test loop *Found:* All 44 regexes target x86_64-unknown-none or x86_64-apple-darwin. None covers aarch64-unknown-none, riscv64gc-unknown-none-elf, make check-all/check-clippy/verify-all, so the 3-arch gate always prompts.
- **ec-c-2** `.cargo/config.toml:36` alias kbuild = "build --target x86_64-unknown-none" *Found:* This alias repeats [build] target (line 5), so it is a no-op. There are no kbuild/kcheck aliases for aarch64 or riscv64, and nothing in the Makefile, CI or docs uses kbuild.
- **ec-crit-1** `.vscode/settings.json:180` rust-analyzer.cargo.target = x86_64-unknown-none with check.allTargets=false (tracked editor config) *Found:* The editor analyzes only the x86_64 cfg. Code in src/arch/aarch64 and src/arch/riscv64 behind cfg(target_arch) gets no diagnostics. No per-arch override or linkedProjects exists for user/ or cambios-* crates, …
- **ec-crit2-1** `.vscode/settings.json:151` autoApprove entries pre-approve raw `qemu-system-x86_64 -cdrom cambios.iso ... -m 128M` boot commands (also :155, :163, :167) as the routine boot loop *Found:* Every Makefile run target uses -m 4G (Makefile:1032,1067,1107,1127,1147). These raw 128M boots also have no virtio-gpu, so the default manifest stalls at compositor (man-c-02). The approved commands are stale.
- **ec-crit2-2** `.vscode/settings.json:167` autoApprove entry for `gtimeout 10 qemu-system-x86_64 ...` *Found:* gtimeout is the Homebrew coreutils name and only exists on macOS. It sits beside a `timeout` duplicate (:163), and the tracked config hardcodes this macOS-only form.
- **chc-2** `cambios-abi/.cargo/config.toml:8` Using the native macOS-on-Apple-Silicon triple avoids cross-compile overhead (cambios-manifest/.cargo/config.toml:7 'native host triple') *Found:* The config hardcodes [build] target=aarch64-apple-darwin, so a standalone cargo test fails on Linux/CI hosts and on Intel Macs. It is only 'native' on the author's machine.
- **cha-3** `user/init/src/main.rs:23` Host stub so `cargo test` in this package can build the bin target; `cargo test --lib` works too *Found:* user/init has no .cargo/, so the root .cargo/config.toml default target x86_64-unknown-none applies and a bare cargo test builds for bare metal. No Makefile or CI target runs init tests.
- **crate-headers-b-1** `user/libterm/src/lib.rs:21` The parser ... has #[cfg(test)] coverage runnable on host (`cargo test`). *Found:* user/libterm has no .cargo/; cargo walks up to the root .cargo/config.toml, whose default target is x86_64-unknown-none, so a bare `cargo test` builds for bare metal. No Makefile/CI target runs libterm tests.
- **sr-crit-5** `STATUS.md:185` USB boot tooling / Done (`make img-usb` + `make usb DEVICE=...`) / x / Makefile *Found:* The Makefile:1267-1290 usb recipe calls macOS-only `diskutil list external`, `diskutil info` and `diskutil unmountDisk` before `sudo dd`. On Linux the device listing is empty and the unmount is silently …
- **man-crit-4** `Makefile:1618` img-aarch64 / img-x86 stage signed modules through scratch copies before mcopy. *Found:* Staging uses fixed shared paths: /tmp/<name>-signed.elf (21 files in img-aarch64 at ~1618-1638), /tmp/init-signed.elf and /tmp/shell-headless-signed.elf (img-x86 ~1175). Concurrent builds or other users …

## Governance (P4)

Statements about ownership, review, licensing and signing that only the maintainer can settle.

- **B1** `gh:branch-protection` `gh api repos/coherentforge/CambiOS/branches/main/protection` shows required_signatures.enabled=false, required_status_checks.strict=false, enforce_admins.enabled=false, required_approving_review_count=0, require_code_owner_reviews=true, 12 …
- **B2** † `.github/CODEOWNERS:30` CODEOWNERS owns only /src/ /cambios-abi/ /docs/adr/ /CLAUDE.md /Makefile /tools/ /.github/; user/, verification/, docs/ (non-adr), README.md, STATUS.md, every Cargo.lock, Cargo.toml, rust-toolchain.toml, .cargo/, build.rs, linker*.ld, …
- **B3** `gh:repo-settings` `gh api repos/coherentforge/CambiOS` shows allow_auto_merge=true, allow_update_branch=false, delete_branch_on_merge=false; `gh api repos/coherentforge/CambiOS/actions/permissions` shows allowed_actions=all, sha_pinning_required=false; the workflows …
- **B4** `gh:pr-9` `gh pr view 9 --json files` shows README.md plus a new top-level spec/ directory (~23 files); no CODEOWNERS rule matches spec/ or README.md; no lint scans spec/; the PR has 0 approving reviews and all 12 required checks pass with the 6 kani checks …
- **E5a** `docs/GOVERNANCE.md:47` GOVERNANCE says contributors retain copyright with no assignment, while CLAUDE.md:56 requires `Copyright (C) 2024-2026 Jason Ricca` on every new file; no CONTRIBUTING.md, CLA, DCO or CODE_OF_CONDUCT exists.
- **E5b** `docs/GOVERNANCE.md:92` GOVERNANCE says the project uses a permissive license (Apache 2.0, MIT, or a combination); LICENSE is AGPL-3.0-or-later and user/libsys/LICENSE is MPL-2.0; the root COPYRIGHT file says "All rights reserved" and that no license is currently granted.
- **E5d** `docs/PHILOSOPHY.md:165` PHILOSOPHY says the build does not delegate correctness decisions to AI, while .github/CODEOWNERS:6 allows "a review agent acting as [an owner]" to approve and the bot auto-merges unowned paths; CLAUDE.md:89 "Claude drafts; user executes" does not …
- **E5e** `docs/GOVERNANCE.md:69` GOVERNANCE "Current state" says authority rests with the founder and the future-state transition (~80) has no observable trigger; ~86 claims the repo is mirrored across multiple locations and ~61 claims canonical builds are reproducible, with no …

## Document drift (P1), by file

347 verified statements that no longer match the tree. Listed by file with the affected lines; each remediation commit re-derives its own list from the file it edits, so the per-item text is not repeated here.

| File | Statements | Lines |
|---|---|---|
| `docs/SYSCALLS.md` | 23 | 7, 9, 11, 23, 48, 64, 114, 117, 144, 152, 156, 162, 181, 230, 234, 292, 300, 314, 334, 401, 405, 442, 461 |
| `STATUS.md` | 22 | 26, 33, 104, 106, 110, 115, 124, 128, 130, 138, 139, 145, 150, 154, 168, 213, 219, 246, 253, 255, 257, 259 |
| `docs/FS-and-ID-design-plan.md` | 12 | 11, 74, 102, 121, 125, 126, 136, 176, 177, 216, 221, 224 |
| `docs/INTERRUPT_ROUTING.md` | 12 | 9, 13, 23, 105, 126, 140, 198, 199, 201, 210, 232, 299 |
| `docs/manuals/01-waking-up.md` | 12 | 23, 25, 33, 39, 47, 49, 51, 55, 65, 67, 79, 93 |
| `docs/CambiOS.md` | 11 | 113, 120, 150, 151, 180, 392, 396, 400, 430, 438, 447 |
| `docs/adr/000-zta-and-cap.md` | 9 | 71, 109, 111, 136, 144, 147, 160, 250, 258 |
| `docs/adr/032-full-disk-encryption-below-substrate.md` | 9 | 3, 53, 185, 206, 218, 231, 235, 293, 296 |
| `Makefile` | 8 | 1119, 1358, 1438, 1696, 1716, 1758, 1808, 1867 |
| `docs/adr/006-policy-service.md` | 8 | 187, 206, 230, 233, 239, 273, 278, 421 |
| `docs/adr/027-service-clusters.md` | 8 | 3, 23, 60, 101, 252, 253, 276, 297 |
| `docs/identity.md` | 8 | 111, 220, 487, 499, 538, 586, 610, 648 |
| `docs/adr/033-multi-principal-vault.md` | 7 | 99, 102, 104, 132, 133, 142, 147 |
| `docs/adr/034-postponed-task-resource-reclamation.md` | 7 | 64, 85, 91, 114, 127, 133, 143 |
| `README.md` | 6 | 31, 33, 96, 125, 159, 193 |
| `docs/adr/001-smp-scheduling-and-lock-hierarchy.md` | 6 | 108, 112, 116, 374, 391, 401 |
| `docs/adr/004-cryptographic-integrity.md` | 6 | 196, 244, 289, 290, 291, 295 |
| `docs/adr/013-riscv64-architecture-support.md` | 6 | 133, 144, 157, 169, 290, 293 |
| `docs/adr/019-process-fault-reaping-and-peer-generation.md` | 6 | 40, 120, 227, 255, 312, 314 |
| `docs/adr/022-wall-clock-time.md` | 6 | 110, 114, 129, 180, 182, 183 |
| `docs/adr/023-audit-consumer-capability.md` | 6 | 19, 34, 66, 70, 75, 112 |
| `docs/manuals/02-life-of-a-message.md` | 6 | 29, 55, 61, 63, 81, 85 |
| `docs/manuals/04-driver-isolation.md` | 6 | 21, 36, 44, 62, 77, 87 |
| `docs/adr/003-content-addressed-storage-and-identity.md` | 5 | 122, 171, 247, 285, 314 |
| `docs/adr/005-ipc-primitives-control-and-bulk.md` | 5 | 43, 178, 182, 225, 387 |
| `docs/adr/008-boot-time-sized-object-tables.md` | 5 | 143, 156, 408, 532, 540 |
| `docs/adr/038-sandboxed-guest-processes.md` | 5 | 39, 141, 214, 270, 298 |
| `docs/manuals/03-signature-chain.md` | 5 | 15, 20, 61, 69, 77 |
| `CLAUDE.md` | 4 | 44, 73, 236, 246 |
| `docs/SECURITY.md` | 4 | 31, 227, 354, 389 |
| `docs/adr/002-three-layer-enforcement-pipeline.md` | 4 | 92, 113, 130, 270 |
| `docs/adr/007-capability-revocation-and-telemetry.md` | 4 | 51, 309, 314, 443 |
| `docs/adr/010-persistent-object-store-on-disk-format.md` | 4 | 79, 129, 150, 174 |
| `docs/adr/011-graphics-architecture-and-scaling.md` | 4 | 102, 123, 127, 226 |
| `docs/adr/014-compositor-scanout-driver-protocol.md` | 4 | 200, 202, 271, 279 |
| `docs/adr/018-init-process-and-boot-manifest.md` | 4 | 69, 81, 214, 343 |
| `docs/adr/020-typed-user-buffer-slices-at-syscall-boundary.md` | 4 | 68, 166, 199, 215 |
| `docs/adr/024-syscall-abi-crate.md` | 4 | 25, 63, 64, 71 |
| `docs/adr/029-posix-file-storage-model.md` | 4 | 161, 163, 483, 531 |
| `docs/adr/036-typed-mmio-register-blocks.md` | 4 | 77, 85, 97, 133 |
| `docs/adr/037-native-app-framework.md` | 4 | 36, 46, 108, 151 |
| `docs/manuals/05-ntp-query.md` | 4 | 9, 31, 35, 71 |
| `docs/adr/012-input-architecture-and-device-classes.md` | 3 | 6, 253, 255 |
| `docs/adr/026-identity-transcription-at-the-kernel-ring.md` | 3 | 18, 67, 131 |
| `docs/adr/028-three-storage-models.md` | 3 | 82, 242, 247 |
| `docs/adr/030-stream-cap-variant.md` | 3 | 125, 145, 281 |
| `docs/win-compat.md` | 3 | 235, 240, 248 |
| `.github/workflows/ci.yml` | 2 | 20, 124 |
| `docs/ASSUMPTIONS.md` | 2 | 17, 266 |
| `docs/adr/009-purpose-tiers-scope.md` | 2 | 19, 103 |
| `docs/adr/021-typed-boot-error-propagation.md` | 2 | 259, 281 |
| `docs/storage-planning.md` | 2 | 99, 145 |
| `docs/threat-model.md` | 2 | 4, 42 |
| `src/syscalls/dispatcher.rs` | 2 | 760, 928 |
| `user/compositor/src/main.rs` | 2 | 16, 33 |
| `user/scanout-virtio-gpu/src/main.rs` | 2 | 44, 153 |
| `.github/copilot-instructions.md` | 1 | 4 |
| `Cargo.toml` | 1 | 23 |
| `docs/adr/016-win-compat-api-ai-boundary.md` | 1 | 12 |
| `docs/adr/025-principal-as-aid.md` | 1 | 37 |
| `docs/adr/INDEX.md` | 1 | 22 |
| `docs/dev-notes/prompt-shaping-changelog.md` | 1 | 9 |
| `docs/developer-experience.md` | 1 | 19 |
| `git:grep-local-paths` | 1 |  |
| `limine-aarch64.conf` | 1 | 12 |
| `src/arch/riscv64/plic.rs` | 1 | 43 |
| `src/microkernel/main.rs` | 1 | 2059 |
| `user/fde-mount/src/main.rs` | 1 | 7 |
| `user/fs-service/src/main.rs` | 1 | 20 |
| `user/hello-window/src/main.rs` | 1 | 14 |
| `user/i219-net/src/main.rs` | 1 | 31 |
| `user/key-store-service/src/lib.rs` | 1 | 6 |
| `user/key-store-service/src/main.rs` | 1 | 6 |
| `user/libfs/src/lib.rs` | 1 | 23 |
| `user/libsys-rt/src/lib.rs` | 1 | 37 |
| `user/sprouty/src/main.rs` | 1 | 54 |
| `user/tree/src/main.rs` | 1 | 55 |
| `user/usb-host/src/main.rs` | 1 | 14 |
| `user/virtio-blk/src/main.rs` | 1 | 11 |

## Remediation order

1. **Gates that report green without running.** The capability proofs compile and verify again; every proof crate is compiled on every CI run and solved weekly; `check-fail-open` and `check-doc-refs` run in CI and in the pre-commit hook; the lint scanners index repository files only; the fuzz targets build.
2. **Document truth and the collaborator contract.** CONTRIBUTING.md, README, SECURITY, the threat model, GOVERNANCE, CLAIMS, STATUS, the manuals and the ADR bodies say what the tree does. ADR bodies are rewritten to current truth with the prior wording kept in a dated Divergence appendix, after the maintainer approves each diff.
3. **Binding.** The Makefile builds from one list of architectures and one list of crates per architecture; `check-lists`, `check-gates` and `check-claims` fail CI when a copy disagrees with its source; user crates are built, tested and linted on every push.
4. **Host portability.** The host triple is detected, a `check-env` target reports what a clone is missing, and Limine is pinned.
5. **Governance.** CODEOWNERS owns everything by default with explicit hands-off lanes; branch rulesets, required signatures and pinned actions are repository settings the maintainer applies.
