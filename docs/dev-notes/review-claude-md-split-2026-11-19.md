# Review of the CLAUDE.md split (bf515aa), sandbox run 002

Commit `bf515aa` cut the root `CLAUDE.md` from 91 KB to 52 KB by moving ten path-scoped sections into nine files under `.claude/rules/`, each with a `paths:` list that tells Claude Code when to load it, and left a "Where things live" index in the root for agents that have no such loader. The move itself was script-verified, so this review does not look for lost text. It asks whether each rule now reaches the agent at the moment the agent needs it: I read the root and all nine rules files against the pre-split text, compared every `paths:` pattern with `git ls-files` (600 tracked files), followed every "above", "below", "this file" and section name that crossed a file boundary, and watched what the harness actually loaded in this session and in nine fresh subagents that each read a fixed list of files and reported which rules blocks arrived.

Two kinds of change are kept apart throughout. A finding marked **applied on the branch** is a placement change (a glob, a link, a pointer, text moved verbatim) and is in the second commit. A finding marked **proposed** would change what an agent must do, may do, or must ask about, or needs a file outside the set this run may edit; its text is given here and nothing was changed.

One number to carry into the decisions below: the applied edits take the root from 51,950 to 54,721 bytes. The hook block that moved back (finding 1.1) is 1,212 of those; the index descriptions (finding 3.2) are the rest. Section 6 says how to get both back.

## 1. Rules that fire too late

**1.1 What the commit hooks require of a commit message is loaded only when a file under `tools/` is open. Applied on the branch.**

- **Where:** `.claude/rules/tools.md` § Git hooks (18 comment lines; pre-split root lines 296–313, directly above `make install-hooks`).
- **The rule and the decision:** the commit-msg hook rejects a Claude-authored commit whose `Staged files:` block does not equal `git diff --cached --name-only`, and the preflight and edit-window gates only enforce once `CLAUDE_PREFLIGHT_SESSION=<id>` is set "once per session". The agent decides both things with no file open: one at session start, one while drafting any commit message. `tools.md` loads for `tools/**`, `.githooks/**`, two user crates and `manifest.toml`. An agent that fixed a bug in `src/ipc/` drafts its commit with the block absent from context.
- **Why it matters:** after bf515aa the root did not contain the string `Staged files` at all (`git show bf515aa:CLAUDE.md | grep -c 'Staged files'` prints 0). Commit Cadence says the agent drafts and the maintainer executes, so the miss surfaces as a hook rejection at the maintainer's passphrase prompt. `AGENTS.md:12` and `CONTRIBUTING.md:64` carry the rule, but Claude Code loads neither.
- **What was done:** the block is back in the root Quick Reference above `make install-hooks`, byte-identical to the pre-split text (the edit script asserted it against `bf515aa^:CLAUDE.md`). `tools.md` § Git hooks is now a pointer that names the four scripts and says why the text lives in the root. The root index entry and the pointer comment at the end of the Quick Reference were adjusted to match. Finding 6.6 proposes the shorter form.

**1.2 Work that concerns a subsystem without opening a file in it gets none of the subsystem's rules. Proposed.**

- **Where:** root Critical Rules, last bullet ("Path-scoped reference lives in `.claude/rules/`…"), which tells only *other* agents to read the rules file before working on the paths.
- **The decisions:** (a) a design conversation or plan ("where does the new lock go?") answered before any file is read; (b) drafting an ADR (Architecture Decision Record) under `docs/adr/`, which matches no glob (observed: reading `docs/adr/001-smp-scheduling-and-lock-hierarchy.md` loaded nothing); (c) reviewing a change from `git show` or `git diff` (observed: `git show bf515aa` loaded nothing, although a Bash `head` of a matching file does); (d) composing a new file under `src/` with Write before reading a neighbour (not observed; the block can only arrive after the content is written); (e) the stretch between a context compaction and the next file read (observed in this session: the rules blocks were gone from context after compaction and came back on the next Read).
- **Why it matters:** the Stop-and-Ask bullets "Lock hierarchy change" and "Portable module drift" stayed in the root, but the hierarchy and the portable-module list they are checked against did not. In cases (a) to (c) the gate fires with nothing to compare against, and the agent answers from memory of a 13-entry ordering.
- **Proposed text** (append to the Critical Rules bullet): "Claude Code loads a rules file only when a matching file is read or edited. When the work concerns those paths with no such file open (a plan, an ADR draft, a review read from `git diff`, a new file written before any neighbour is read) or the block is no longer in context after a compaction, read the rules file named in Where things live first." This adds an obligation, so it is the maintainer's call.

**1.3 Conventions 4 and 7 no longer reach user-space code, by scope statement and now by glob. Proposed.**

- **Where:** root lines 117 and 121 ("apply to kernel code only", "are kernel-only too") and `.claude/rules/kernel.md` line 12 ("These apply to kernel code only").
- **What changed:** the pre-split root listed Conventions 3, 4, 6 and 7 with no scope statement; the phrase "kernel code only" is new in bf515aa. Before this branch the narrowing was hidden by accident: `kernel.md` loaded for every crate's `src/` (finding 2.1), so user-crate sessions still saw the text. With the glob anchored they see neither the text nor a rule that binds them.
- **The decision:** building a large value on a 64 KiB user stack, or treating zeroed memory as `None`, in a user crate or host tool. `user/init/src/engine.rs:121` documents a ~10 KiB struct that "lives on the shell's stack (user stacks are 64 KiB…)", so the hazard Convention 4 names exists outside the kernel. Convention 7 is a statement about Rust's layout guarantees and is true in any crate. Conventions 3 and 6 are kernel-shaped (the `src/arch/` shim, the kernel's GDT (Global Descriptor Table)) and lose nothing.
- **Proposed text**, if the narrowing was not intended. Root line 117: "Convention 3 (architecture portability) applies to the kernel tree and is in kernel.md. **4. Large structs are constructed in place**, never as a stack local that is then moved: kernel and boot stacks are small and so are user stacks (64 KiB). The kernel pattern and the reference failure are in kernel.md." Root line 121: restore Convention 7 whole (about 340 bytes) and keep "Convention 6 (the GDT is `static mut`) is kernel-only, in kernel.md". `kernel.md` line 12: "Conventions 3 and 6 apply to the kernel tree only; 4 and 7 are stated in the root and detailed here." If the narrowing was intended, nothing needs to change.

## 2. Glob coverage

**2.1 `src/**` is not anchored to the kernel tree: three kernel files loaded for every crate's `src/`. Applied on the branch.**

- **Where:** the first `paths:` entry of `kernel.md`, `locks.md` and `platform-gotchas.md`.
- **What was observed:** reading `user/shell/src/main.rs`, `cambios-manifest/src/lib.rs` or `verification/buddy-proofs/src/lib.rs` in a fresh context loaded `locks.md`, `kernel.md` and `platform-gotchas.md`. Patterns with a slash before the wildcard (`src/scheduler/**`, `user/libsys/**`, `tools/sandbox/**`) behaved as anchored. So a pattern whose only slash is the one in the trailing `/**` floats: it matches a directory of that name at any depth.
- **Why it matters:** 135 tracked files sit under a nested `src/` (116 in `user/`, 7 in `tools/`, 6 in `verification/`, 6 in the `cambios-*` crates) against 96 in the kernel's. A session in `user/shell` loaded 22.7 KB of rules, of which 1.5 KB (`userspace.md`) was written for it. The lock hierarchy in a user-space context is not harmless filler: it invites an agent to reason about kernel locks in code that has none.
- **What was done:** the three entries are now `src/**/*`. Verified in fresh subagents after the edit: `user/shell/src/main.rs` loads `userspace.md` only, `verification/buddy-proofs/src/lib.rs` and `tools/build-manifest/src/main.rs` load no kernel file, and `src/reap.rs`, `src/fs/posix/mod.rs`, `src/memory/paging.rs` and `src/scheduler/SCHEDULER.md` still load `kernel.md` and `locks.md`. A trial with `/src/**` anchored equally well; `src/**/*` was kept because it means the same thing under ordinary glob rules. Interaction to be aware of: finding 1.3.

**2.2 `platform-gotchas.md` covered one driver crate of eight and not the file that assembles the boot image. Applied on the branch.**

- **Where:** `platform-gotchas.md` `paths:`.
- **Why:** the file's driver-facing entries (the unregistered-IRQ (interrupt request) wake fallback, stray level-triggered interrupts being masked until a driver claims the pin, the write-combining framebuffer mapping, device registers staying uncacheable) apply to every crate that calls `wait_irq`, `map_mmio`, `map_framebuffer` or `alloc_dma`. `git grep` finds those calls in eight crates; only `user/usb-host/**` was listed, and the other seven received the file solely through the floating `src/**` that 2.1 removes. The first entry (boot needs both `manifest.bin` and `init.elf` staged) and the GICv3 (Generic Interrupt Controller version 3; `.claude/rules/platform-gotchas.md`) entry describe what the `Makefile`'s image and QEMU (Quick Emulator) recipes must do, and the `Makefile` matched no glob at all.
- **What was done:** added `user/i219-net/**`, `user/nvme/**`, `user/scanout-limine/**`, `user/scanout-virtio-gpu/**`, `user/virtio-blk/**`, `user/virtio-input/**`, `user/virtio-net/**` and `Makefile`. Verified: `user/virtio-net/src/main.rs` and `Makefile` each load it in a fresh context.
- **Not covered, proposed only:** `.github/workflows/boot-smoke.yml` carries the same QEMU flags and matches nothing. A `.github/workflows/**` entry would fix it; it was left out because that directory is a hands-off lane for this run.

**2.3 The Blocking pattern does not load for kernel files that block or wake. Applied on the branch.**

- **Where:** `scheduling.md` `paths:` (scheduler, arch, interrupts, ipc, syscalls, policy, microkernel, `src/lib.rs`: 52 files).
- **Why:** the primitives the file governs are used outside those directories: `src/fs/block_driver_client.rs` (`yield_save_and_switch` three times, `wake_message_waiters_all_cpus` twice), `src/reaper.rs` (`yield_save_and_switch`), `src/reap.rs` (`REPLY_ENDPOINT`), `src/audit/drain.rs` (`on_timer_isr` context, `try_lock`), `src/io/mod.rs` and `src/io/fbcon.rs` (`try_lock` from interrupt handlers), `src/loader/mod.rs` (`TASK_CPU_MAP`), `src/memory/mod.rs` and `src/memory/paging.rs` (`shootdown_page`). The block driver client is the clearest case: it blocks on a condition another CPU signals, which is exactly the lost-wake shape the Blocking pattern exists for, and it sat outside the glob.
- **What was done:** added `src/audit/**`, `src/io/**`, `src/loader/**`, `src/memory/**`, `src/fs/block_driver_client.rs`, `src/reap.rs`, `src/reaper.rs` (16 more files). Verified on `src/fs/block_driver_client.rs` and `src/memory/paging.rs`; `src/fs/posix/mod.rs` and `src/boot/mod.rs` still do not load it.

**2.4 The kernel side of endpoints 24, 25 and 26 did not load the text that describes it. Applied on the branch.**

- **Where:** `userspace.md` `paths:` (`user/**`, `manifest.toml`, two `cambios-*` crates).
- **Why:** the longest clause in that file is kernel behavior: "`handle_write` intercepts [25] before the IPC (inter-process communication) pipeline and accepts a write only from a process whose Principal is the manifest's reservation owner", and what `BlockDriverClient` accepts as a reply. `BLK_*_ENDPOINT` is used 11 times in `src/fs/block_driver_client.rs` and 4 times in `src/syscalls/dispatcher.rs`. An agent editing `handle_write` is the reader that clause was written for.
- **What was done:** added those two files. Verified on `src/fs/block_driver_client.rs`.

**2.5 `syscalls.md` names `cambios_libsys_rt::ready()` and does not load for `user/libsys-rt/`. Applied on the branch.**

- **Where:** `syscalls.md` `paths:`; the "Slot 36 (was ModuleReady)" bullet.
- **Why:** `user/libsys/**` does not match the sibling crate `user/libsys-rt/` (observed: no load). That crate is where the readiness write that replaced slot 36 lives.
- **What was done:** added `user/libsys-rt/**`; verified. Not added: `fuzz/fuzz_targets/fuzz_syscall_dispatcher.rs` (observed: loads nothing) and `docs/dev-notes/syscall-workflow.md`. Both are read together with `cambios-abi/src/lib.rs`, which does load the file.

**2.6 `kernel.md` describes `build.rs`, the linker scripts and the toolchain files, and loads for none of them. Proposed.**

- **Where:** `kernel.md` intro and § Architecture ("`build.rs` reads `CAMBIOS_TIER`…"); observed: `build.rs` and `Cargo.toml` load nothing, `linker.ld` loads only `platform-gotchas.md`.
- **Why it is small:** each of those files explains itself once open (`.cargo/config.toml:22` states the RISC-V code-model requirement in a comment), and the reverse direction works: an agent in `src/config/tier.rs` does get the `build.rs` note. The one real gap is Memory Layout for someone editing `linker-riscv64.ld`, where Convention 4's reference failure (statics linked directly below the boot stack) was made.
- **Proposed:** add `linker*.ld` to `kernel.md`. Write `build.rs` as `/build.rs` if it is added: an unslashed `build.rs` would, by the rule seen in 2.1, also match the three `verification/*/build.rs` files. Neither form was tested, which is why this is not applied.

**2.7 `tools.md` loads where it is not needed and not where its dev-PIV text is. Proposed.**

- **Where:** `tools.md` `paths:` (`tools/**` first).
- **Over-match:** `tools/**` loads 4.2 KB of standalone-build, dev-PIV (Personal Identity Verification, the smart-card standard the development signing keys stand in for; ADR-032) and signing text for every lint script and for `tools/sandbox/**`, where none of it applies.
- **Under-match:** the `dev-piv` feature that the file's longest entry governs ("kernel + key-store-service must both be built with this feature") is consumed in `Cargo.toml`, `Makefile`, `src/fs/disk.rs`, `src/microkernel/main.rs`, `src/syscalls/dispatcher.rs`, `user/libsys/src/vault.rs` and `user/shell/src/main.rs`; none loads it.
- **Proposed:** replace `tools/**` with `tools/sign-elf/**`, `tools/build-manifest/**`, `tools/gen-dev-piv-keys/**`, `tools/format-volume/**`, and add `user/libsys/src/vault.rs`. Not applied because narrowing removes text from sessions that have it today, and which lint scripts should keep it is a judgment about the maintainer's workflow.

**2.8 The `make sandbox-*` and standalone-build targets are defined in a file that loads neither `sandbox.md` nor `tools.md`. Proposed.**

- **Where:** `Makefile` (15 `sandbox-*` targets); `sandbox.md` `paths:` is `tools/sandbox/**`.
- **Why:** an agent that renames or adds one of those targets edits the `Makefile` and never sees the file that documents it. Adding `Makefile` to both would load 6.3 KB more on every `Makefile` read (on top of `platform-gotchas.md` from 2.2), which is a poor trade for a doc-sync reminder.
- **What covers it instead:** finding 3.1 makes §8 item 5 name both files, so the obligation is stated where it is always loaded. No glob change proposed.

## 3. References that broke in meaning

**3.1 §8 item 5 sends a renamed build command to a file that may no longer hold it. Applied on the branch.**

- **Where:** root, Post-Change Review Protocol, §8 item 5: "Update CLAUDE.md's Quick Reference, locks.md or syscalls.md".
- **Why:** 27 build commands (standalone builds, dev-PIV builds, the sandbox targets) moved to `tools.md` and `sandbox.md`. An agent that renames `make sandbox-up` checks the Quick Reference, finds nothing to update, and is done.
- **What was done:** the item now reads "Update whichever file holds it: CLAUDE.md's Quick Reference, tools.md or sandbox.md for a build command, locks.md for a lock, syscalls.md for a syscall." The obligation is the one the item had before the split; only the places are named.

**3.2 Five root index entries gave a path and nothing else. Applied on the branch.**

- **Where:** root § Where things live: Syscall Numbers, Platform Gotchas, GDT Layout and SYSCALL/SYSRET, Service endpoints, Sandbox VM; and Memory Layout, which read "In kernel.md." with no paths.
- **Why:** this index is the whole loading mechanism for an agent without Claude Code, and for Claude Code in the cases of finding 1.2. "for `src/arch/x86_64/`" tells the reader when to open the file but not whether it holds what they are looking for.
- **What was done:** every entry now has a one-sentence statement of contents; the path prose was brought in line with the globs as changed in section 2; "`src/`" is written "the kernel's `src/` (the one at the repository root, not a crate's)" where it first appears. The headings are unchanged, so the eight inbound `#lock-ordering` links and the `#memory-layout` link still resolve.

**3.3 `kernel.md`'s opening sentence describes the pre-split file. Applied in part; the rest proposed.**

- **Where:** `kernel.md` line 8: "Sections below describe kernel state (directory pointers, tables, per-syscall behavior)."
- **Why:** per-syscall behavior is now `syscalls.md`, and the first section below is not state at all but four numbered conventions. Read literally, the next sentence ("Operational rules in the root CLAUDE.md outrank them") files Conventions 3, 4, 6 and 7 under descriptions that root rules outrank; before the split they *were* root rules.
- **What was done:** the sentence now says the file holds four of the numbered conventions and describes kernel state (directory pointers, memory layout), with links to `syscalls.md` and `locks.md`.
- **Proposed** (changes force, so not applied): add "The four conventions carry the same force as the rest of the numbered list in the root."

**3.4 `locks.md` cites "the Blocking pattern" twice with no pointer to the file that now holds it. Applied on the branch.**

- **Where:** `locks.md`, the "never descheduled" paragraph and the `SHARDED_IPC.shards` bullet.
- **Why:** `locks.md` loads for all of the kernel's `src/`; `scheduling.md` for a subset. In `src/fs/posix/` the reader is told a pattern "already requires" something and has no text for it. Both mentions now link to `scheduling.md`.

**3.5 Three section names in `failure-signatures.md` pointed at the root by name only. Applied on the branch.**

- **Where:** `docs/dev-notes/failure-signatures.md`: "Duplicates a Platform Gotcha", "see Convention 4", "see the Blocking pattern".
- **Why:** this file is read on demand from the root, usually mid-diagnosis with no matching file open, and all three targets left the root. Each now carries a relative link (`../../.claude/rules/…`), checked to resolve from `docs/dev-notes/`.

**3.6 `platform-gotchas.md` calls itself "this section". Applied on the branch.** The opening paragraph (line 21) now says "this file".

**3.7 Citations in files this run may not edit now land one hop short. Proposed.**

- **Where:** `src/syscalls/dispatcher.rs:3928` ("CLAUDE.md kernel stack guidance", which is Convention 4 and has no heading by that name anywhere); `src/policy/mod.rs:623` and `src/scheduler/mod.rs:255,833` ("CLAUDE.md Blocking pattern"); `src/arch/{x86_64,aarch64,riscv64}/mod.rs` and `src/scheduler/mod.rs:826` ("CLAUDE.md § Timer / Preemptive Scheduling"); `docs/adr/008-…md:567` (`CLAUDE.md#memory-layout`); `docs/adr/013-…md:6` ("CLAUDE.md § Multi-Platform Strategy").
- **Why it is tolerable:** every one of the `src/` files is matched by the rules file that holds the cited text, so Claude Code has it in context when the comment is read, and the root index heading of the same name catches everyone else. Nothing is dead.
- **Proposed:** leave the ADRs (historical record). Re-anchor the code comments the next time each file is edited for another reason, to the form "Convention 4 (`.claude/rules/kernel.md`)" and "Blocking pattern (`.claude/rules/scheduling.md`)".

**3.8 The Stop-and-Ask Gate cites a rule that exists in no file in the repository. Proposed.**

- **Where:** root, Stop-and-Ask Gate, "Destructive or shared-state action": "The top-level "Executing actions with care" rule applies; this bullet is the local reminder."
- **Why:** older than the split, but the split made the root the contract for every agent (`AGENTS.md:5`), and the phrase names a section of one vendor's system prompt. A reader without that prompt has a pointer to nothing.
- **Proposed text:** "Confirm with the user before any of these; this holds whatever the agent's own instructions say about destructive actions."

**3.9 Two moved or adjacent texts cite files under the gitignored `notes/` directory. Proposed.**

- **Where:** `.claude/rules/sandbox.md` line 9 (`notes/stage-g-mythos-sandbox-vm.md`); `docs/dev-notes/failure-signatures.md:26` (`notes/boot-smoke-regression-2026-11-02.md`). `.gitignore:31` excludes `notes/`.
- **Why:** §8 item 7 says a cited doc must exist. These exist on one machine. Inside the sandbox VM (virtual machine), where `sandbox.md` is most likely to be read by an agent, the file is absent.
- **Proposed:** drop the parenthetical in `sandbox.md`, or move the cited note's durable part to `docs/dev-notes/`.

## 4. Duplication and drift risk

**4.1 Every rules file's paths are stated twice: in its frontmatter and in root index prose. Applied on the branch (source named).**

- **Where:** root § Where things live against the nine `paths:` lists.
- **Why:** the loader reads only the frontmatter. The prose was already wrong about what loads (finding 2.1), and this branch changed five lists, so the two copies would have parted on the first edit.
- **Single source:** the frontmatter. The index intro now says so ("The `paths:` list at the top of each file is the list of record; the paths named here follow it"), and the prose was shortened to a summary where a list grew (driver crates, kernel files).
- **Proposed, outside this run's files:** teach `make check-lists` to compare the directory names in each index entry with that file's `paths:`. It already exists to catch hand-copied lists.

**4.2 The hook requirement exists in four places. Applied on the branch (one pointer).**

- **Where:** root Quick Reference (after 1.1), `tools.md` § Git hooks, `AGENTS.md:12`, `CONTRIBUTING.md:64–72`.
- **Single source:** the root block for mechanics; `CONTRIBUTING.md` for the contract in prose, written for contributors who never read the root. `tools.md` is now a pointer. `AGENTS.md` is a one-line carry and should stay one line.

**4.3 Endpoint numbers are listed in five places and the lists already disagree. Applied on the branch (pointer); shrink proposed.**

- **Where:** `manifest.toml` header (says "change endpoints HERE"), `userspace.md`, `locks.md` (22, 26), the root Required Reading map (27, 28, 30), the root Quick Reference (30).
- **Drift found:** `userspace.md` omits 15 (terminal-window), 18 (shell), 22/23 (policy), 31 (usb-host), 32 (fde-mount) and 33 (ccid), all present in the manifest header.
- **Single source:** the `manifest.toml` header. `userspace.md` now ends with a sentence naming it as the assignment of record.
- **Proposed:** cut the plain `name=number` pairs from `userspace.md` and keep only what the header cannot say: the 24/25/26 handling, who owns 30 in which profile, and endpoint 0 as the unset sentinel.

**4.4 The list of portable modules exists four times and no two copies agree. Proposed.**

- **Where:** root Stop-and-Ask "Portable module drift" (scheduler, ipc, `process.rs`, `loader/elf.rs`, "or another portable module"); `kernel.md` § Portability Boundary (adds `syscalls/mod.rs`, the two allocators, `arch/spinlock.rs`; omits `loader/elf.rs`); `kernel.md` § Architecture, "Arch split" (has `loader/elf.rs`, omits `arch/spinlock.rs`); `docs/review-protocol.md:51` (four entries).
- **Why it matters:** the gate's reach is "another portable module", and which modules those are depends on which copy the agent read. Separately, `src/loader/elf.rs` carries six `target_arch` attributes (lines 20–29), so "contain no arch-specific code" is not true of it as written.
- **Single source:** `kernel.md` § Portability Boundary. **Proposed text** there: "`src/scheduler/`, `src/ipc/`, `src/syscalls/mod.rs`, `src/process.rs`, `src/loader/elf.rs` (its machine-type selection is the one cfg it carries), `src/memory/buddy_allocator.rs` + `frame_allocator.rs`, `src/arch/spinlock.rs`." The "Arch split" bullet becomes "see Portability Boundary above"; the root gate ends "…or another module in kernel.md's Portability Boundary list"; `review-protocol.md:51` points at the same list. Not applied: taking the union changes which files the gate covers.

**4.5 `review-protocol.md` §5 contradicts Convention 4. Proposed.**

- **Where:** `docs/review-protocol.md:54`: "Large structs (>1KB) are heap-allocated via `new_boxed()` or `Box::new()`". Convention 4 (`kernel.md`): "`Box::new(T::new())` is NOT the pattern".
- **Why it matters more after the split:** the protocol is read from the root after every change; Convention 4's text is now loaded only under the kernel's `src/`. A reviewer agent holding only the protocol approves the exact construction that caused the 2026-09-14 boot rot.
- **Single source:** Convention 4. **Proposed text** for line 54: "Large structs are constructed in place (Convention 4, `.claude/rules/kernel.md`): `new_boxed()` or an in-place initializer into a static, never `Box::new(T::new())`."

**4.6 `syscalls.md` states two authorities for RevokeCapability. Proposed.**

- **Where:** the "No syscall is bootstrap-Principal-gated any more" bullet ("**RevokeCapability** by holding the `revoke` right on the target endpoint") against the later "**RevokeCapability**: Phase 3.1 authority = bootstrap only; grantor / `revoke`-right-holder / policy paths land in Phase 3.4."
- **Which is true:** the first. `handle_revoke_capability` (`src/syscalls/dispatcher.rs:2653`) delegates to `revoke()`, whose check is "caller holds the `revoke` right on the endpoint". The contradiction predates the split (old root lines 596 and 603) and moved intact.
- **Proposed text** for the second bullet: "**RevokeCapability**: `CapabilityHandle` refactor waits on the post-v1 handle table." Not applied because it removes a statement of fact, which is more than placement.

**4.7 `syscalls.md` had two bullets labelled Spawn, four lines apart. Applied on the branch.** They are one bullet now, both sentences kept word for word ("requires `CapabilityKind::CreateProcess` (ADR-008). Manifest-only. Row lookup by name…").

**4.8 "The manifest is the only spawn authority" is explained four times. Proposed.**

- **Where:** `platform-gotchas.md` first entry (with the failure modes), `syscalls.md` Spawn, `tools.md` `make manifest`, `userspace.md` (init clause). `manifest.toml` loads three of the four at once.
- **Single source:** `platform-gotchas.md`, which has the typed errors an agent will actually see. **Proposed:** `tools.md` keeps the command and drops "The manifest is the ONLY spawn authority since step 9: …" down to "(what the manifest governs: platform-gotchas.md, first entry)"; `userspace.md` drops "and init spawns the service set; the kernel auto-starts nothing".

**4.9 `kernel.md` repeats itself and `platform-gotchas.md`, with which it always loads. Proposed.**

- **Where and source:** "AArch64 MMIO (memory-mapped I/O) must be explicitly mapped" in Rules for New Code restates the fourth gotcha (source: the gotcha, which has the addresses). "Limine 8.7.0" appears at lines 8 and 36 while the pin is `LIMINE_COMMIT` in `Makefile:36` (source: the Makefile; say "Limine 8.x, pinned in the Makefile" once). "Boot stack: 256KB via Limine StackSizeRequest" in Memory Layout restates Convention 4's "256 KiB on every arch" and leaves out riscv64 (source: Convention 4).
- **Proposed:** delete the three restatements. About 350 bytes; grouped here because none is worth a finding alone.

## 5. Observed loading

Each row is one tool call in a context where the listed files had not yet been loaded. "Before" is bf515aa as committed; "after" is this branch. Subagent rows are from agents told to read a fixed list one file per turn and report only what arrived.

| Context | File opened (tool) | Rules files that appeared |
|---|---|---|
| main, before | `git show bf515aa` (Bash) | none |
| main, before | `src/ipc/mod.rs` (Read) | locks, scheduling, platform-gotchas, kernel |
| main, before | `Makefile` (Read) | none |
| main, before | `manifest.toml` (Read) | userspace, tools (platform-gotchas already present) |
| main, before | `src/syscalls/dispatcher.rs` (Read) | syscalls |
| main, before | `src/arch/x86_64/gdt.rs` (Read) | x86_64 |
| main, before | `tools/sandbox/session.sh` (Read) | sandbox (tools already present) |
| main, before | `CLAUDE.md`, then each `.claude/rules/*.md` (Read) | none |
| subagent 1, before | `src/ipc/mod.rs` (Bash `head -5`) | locks, scheduling, platform-gotchas, kernel |
| subagent 1, before | `user/libsys/src/lib.rs` (Read) | userspace, syscalls |
| subagent 1, before | `src/ipc/capability.rs` (Read) | none (nothing is delivered twice) |
| subagent 2, before | `limine-aarch64.conf` | platform-gotchas |
| subagent 2, before | `user/user.ld` | userspace |
| subagent 2, before | `docs/adr/001-smp-scheduling-and-lock-hierarchy.md` | none |
| subagent 2, before | `fuzz/fuzz_targets/fuzz_syscall_dispatcher.rs` | none |
| subagent 2, before | `src/scheduler/SCHEDULER.md` | locks, scheduling, kernel |
| subagent 3, before | `build.rs`, `Cargo.toml`, `verification/CLAIMS.md` | none |
| subagent 3, before | `linker.ld` | platform-gotchas |
| subagent 3, before | `cambios-manifest/src/lib.rs` | **locks**, userspace, **kernel** |
| subagent 3, before | `cambios-abi/src/lib.rs` | syscalls |
| subagent 3, before | `.githooks/commit-msg` | tools |
| subagent 4, before | `user/shell/src/main.rs` | **locks**, userspace, **platform-gotchas**, **kernel** |
| subagent 4, before | `user/libsys-rt/src/lib.rs` | none (**syscalls expected**) |
| subagent 5, before | `verification/buddy-proofs/src/lib.rs` | **locks, platform-gotchas, kernel** |
| subagent 5, before | `tools/check-deferrals.py` | tools |
| subagent 5, before | `src/lib.rs` | scheduling |
| subagent 6, trial | `user/shell/src/main.rs` (locks = `src/**/*`, kernel = `/src/**`, gotchas unchanged) | userspace, platform-gotchas |
| subagent 6, trial | `src/process.rs` | locks, kernel |
| subagent 7, after | `user/shell/src/main.rs` | userspace |
| subagent 7, after | `user/libsys-rt/src/lib.rs` | syscalls |
| subagent 7, after | `user/virtio-net/src/main.rs` | platform-gotchas |
| subagent 7, after | `cambios-manifest/src/lib.rs` | none new (userspace present; no kernel file) |
| subagent 7, after | `src/reap.rs` | locks, scheduling, kernel |
| subagent 8, after | `verification/buddy-proofs/src/lib.rs` | none |
| subagent 8, after | `src/fs/posix/mod.rs` | locks, platform-gotchas, kernel |
| subagent 8, after | `src/fs/block_driver_client.rs` | scheduling, userspace |
| subagent 8, after | `src/audit/drain.rs` | none new |
| subagent 8, after | `src/syscalls/dispatcher.rs` | syscalls |
| subagent 9, after | `Makefile` | platform-gotchas |
| subagent 9, after | `tools/build-manifest/src/main.rs` | tools (no kernel file) |
| subagent 9, after | `src/memory/paging.rs` | locks, scheduling, kernel |
| subagent 9, after | `src/boot/mod.rs` | none new |
| subagent 9, after | `src/arch/x86_64/gdt.rs` | x86_64 |
| main, after compaction | (no tool call yet) | none in context |
| main, after compaction | `src/reap.rs` (Read) | all nine, including sandbox, tools, syscalls, x86_64 and userspace, which do not match it |
| main, after a second compaction | `grep` over `src/` files, `Makefile`, `.gitignore` (Bash) | sandbox, tools, scheduling, userspace, platform-gotchas, syscalls; not x86_64 (kernel and locks were already back in context as plain file reads) |

Bold marks a file that loaded where the root index said it would not, or failed to load where its own text expects it. What the table shows beyond the rows:

- **5.1 `src/**` floats.** The three bold kernel files on `user/`, `cambios-manifest/` and `verification/` paths are finding 2.1. Nothing in the rules files or the root predicted it.
- **5.2 Each file arrives once per context and is not repeated.** A second matching read delivers nothing. A long session therefore relies on a block that may be tens of thousands of tokens back.
- **5.3 After a compaction the blocks are absent until the next file read, and that read restores files the session had loaded, matching or not.** In this session the summary carried only the root; the first Read afterwards (`src/reap.rs`) brought back all nine, and after a second compaction a Bash command that read files under `src/` and the `Makefile` brought back six, among them sandbox, which matches nothing that command touched. Steps taken between the two (a Bash edit, a commit) run without them. This is case (e) of finding 1.2.
- **5.4 A Bash `head` of a matching file loads its rules; `git show` and `git diff` output does not.** Reading a rules file directly returns its text, frontmatter included, and loads nothing else. The loaded block has the frontmatter stripped, so an agent cannot see from the block which paths triggered it.
- **5.5 Rules files are read from disk at match time; the root is not.** Subagents started after the `paths:` edits obeyed the new lists at once. Subagent 9, started after the root index was rewritten, still quoted the old index wording, so the root an agent and its subagents hold is the session-start copy. An edit to a rules file takes effect mid-session; an edit to the root does not.

Subagents receive the root `CLAUDE.md` and no rules block until their own first matching read, so a delegated task loads what the delegate opens, independent of what the parent holds.

## 6. Step 2 candidates

The test used for each: *is this text obeyed before any file is opened?* If yes it stays in the root in some form; if no it can go, provided the place it goes loads where the work happens. Byte figures are measured on this branch's root (54,721); savings are estimates. Section 6 as a whole reaches roughly 39 KB, not 36; 6.11 says where the rest could come from.

**6.1 Shrink the Required Reading map to one line per subsystem; move "Then" into rules files. Do, with a different destination for most of it.** The table is 8,235 bytes; the "Then" column is 3,183 of them. The "Read first" column is what the Stop-and-Ask bullet "Unread subsystem" is checked against before the first edit, so it must stay, as ADR numbers without titles. Most "Then" cells are source paths inside the subsystem's own directory, which an agent finds by opening the directory: delete those; do not move them. Only about a third of the 21 rows have a rules file whose glob fits the subsystem; the graphics, GUI-library and input rows would land in `userspace.md`, which loads for all 273 files under `user/`. Those three rows also hide rules in table cells ("`TileGrid::hit_test` … don't add without consumer", "`signature_block` reserved from day one") that must survive: give them a `.claude/rules/gui.md` scoped to the compositor, scanout, libgui and input crates. Estimated saving 5 KB.

**6.2 Delete Design Documents after adding its missing entries to the map. Do, with two repairs.** 2,071 bytes. The Critical Rules bullet "Design documents come first" links to `#design-documents`, and the section's last line links back; both need a new target (the map). `CambiOS.md`, `win-compat.md` and `GOVERNANCE.md` have no subsystem row and would need a short "read when" list like the Orphan ADRs one. Estimated saving 1.6 KB.

**6.3 Move Convention 10's "Exceptions in practice" to `docs/dev-notes/`. Do, keeping one line.** 1,721 bytes. Four of the five exceptions are consulted during a comment sweep, which is rare and deliberate. The first ("Convention 9 triggers preserve their phase numbers") is different: it stops an agent applying Convention 10 from stripping the trigger out of a valid `Revisit when:` line, and that mistake is made while writing any comment. Keep that one in the root as a sentence. Estimated saving 1.5 KB.

**6.4 Keep lint names in the root, move descriptions to `tools.md`. Do it by shortening; do not rely on `tools.md`.** The lint block is 2,273 bytes. Which lint to run is decided at the shell after editing `src/` or `docs/`, with no file under `tools/` open, so a description moved to `tools.md` is a description the deciding agent does not have. What makes the cut safe is that a failing lint prints its own remedy (the Convention 9 lint prints the three ways to resolve a report, including the baseline line to add). Keep per lint: the name, what it gates in under ten words, and whether CI (continuous integration) enforces it. Keep whole the one instruction that is obeyed before a commit: the `check-doc-refs` note that any edit moving a cited const trips it. Estimated saving 1.2 KB.

**6.5 Keep the four QEMU run targets in the root, move bare-metal detail out. Do, but not to `tools.md`.** The QEMU block is 2,335 bytes. `img-usb`, `usb DEVICE=…` and the `fbcon-hold` line are run by the maintainer at a physical machine, and the `fbcon-hold` explanation already exists in `locks.md` (the `SERIAL1`/`FBCON` bullet). Their natural home is `platform-gotchas.md`, which after 2.2 loads for the `Makefile` and the driver crates, where bare-metal work happens; `tools.md` loads for none of that. Keep in the root a one-line form of the `run-quiet` exit contract (0 = shell reached and every required line seen, 1 = panic, 2 = hang or a missing line): an agent reads an exit code with no file open. Estimated saving 1.6 KB.

Candidates this review adds:

**6.6 Replace the hook block with one Commit Cadence bullet.** Finding 1.1 put 1,212 bytes back. What must be in the root is two sentences: "A Claude-authored commit message carries a `Staged files:` block equal to `git diff --cached --name-only`. Set `CLAUDE_PREFLIGHT_SESSION=<id>` once per session so the preflight and edit-window gates enforce instead of warn (mechanics: tools.md)." The dates, script names and the description of each gate go back to `tools.md`. This rewords a root rule, so it is listed here and not applied. Estimated saving 0.9 KB.

**6.7 Turn the Orphan ADRs list into one short line each.** 1,981 bytes for nine entries; "ADR-020: syscalls that take user pointers" is enough to trigger the read. Estimated saving 1.1 KB.

**6.8 Shrink Code Navigation to two sentences.** 1,364 bytes describing seven tools of a server that, in this sandbox, is not installed (`mcp-rust-analyzer` is not on the path; the harness reports the failure at session start). The tool names and descriptions arrive with the server when it connects. Estimated saving 0.9 KB.

**6.9 Move Convention 8's four code templates to `kernel.md`.** The convention already says "in kernel code"; the rule and the four category names stay in the root with the Stop-and-Ask bullet, and the templates load where a const is typed. Estimated saving 0.8 KB.

**6.10 Collapse the Where things live entries into a table.** This branch grew the section to 3,657 bytes. Only `#lock-ordering` (eight inbound links) and `#memory-layout` (one) are cited from outside, so those two headings stay and the other eight become rows: file, paths in brief, contents. Estimated saving 1 KB. Also move Convention 6 into `x86_64.md`, the only place a GDT is written (rules-file hygiene, not root size).

**6.11 Where the remaining 3 KB could come from.** Project Vision (1,022 bytes) restates `docs/CambiOS.md` and carries one rule, "Never suggest adding telemetry", which the Stop-and-Ask Gate also states. The target triples are given three times in the root (Development Environment, Critical Rules, Quick Reference). Convention 1 spends about 400 bytes on which lint enforces which half of the rule.

**What should not move in any pass:** the Formal Verification list, the Stop-and-Ask Gate, Commit Cadence, the scope triage and the §8 checklist. All are obeyed with no file open, and the history sentences in them (the fail-open months, the 6th-recurrence sweep) are the reasons attached to the rules.

## Lint results on the second commit

- `make check-doc-refs`: passes, 0 findings.
- The Convention 9 lint (`make check-deferrals`) reports one new entry, `.claude/rules/platform-gotchas.md:31:deferred`. It is the existing baseline entry `.claude/rules/platform-gotchas.md:23` ("Unregistered IRQs fall back to all-CPU scan … wake is deferred to the next timer tick"), moved down eight lines by the eight `paths:` entries added in finding 2.2. The text of the line is unchanged. The baseline was left alone for regeneration on the host. The other two baseline entries in files this run edited (`.claude/rules/kernel.md:35`, `CLAUDE.md:11`) did not move.
- Hooks are not installed in this clone (`core.hooksPath` is unset), so the commit-msg checks did not run here. Both commits carry a `Staged files:` block; neither carries a `Signed-off-by:` line, which is the maintainer's to add.

## Checked and found sound

- **Anchors.** Every `CLAUDE.md#…` link in the tree (`#development-conventions`, `#formal-verification-non-negotiable-constraint`, `#lock-ordering`, `#memory-layout`, `#post-change-review-protocol`, `#quick-reference`) resolves in the new root, before and after this branch.
- **Relative links in moved text.** Every `../../` link in the nine rules files resolves from `.claude/rules/`; the links added on this branch were checked the same way.
- **Convention citations in code.** The 17 `(Convention 4)` / `(Convention 7)` comments are all in the kernel's `src/`, where `kernel.md` loads.
- **Rules that stayed.** The GICv3 requirement is in Critical Rules (the rule), `platform-gotchas.md` (the reason) and `failure-signatures.md` (the symptom); the last says the duplication is deliberate, and each copy serves a different entry point. The Stop-and-Ask Gate, Commit Cadence, the §8 checklist and the "Adding a new syscall" pointer are intact.
- **Decisions that precede a file but are covered.** Choosing a syscall number (retired-slot discipline) happens with `cambios-abi/src/lib.rs` open, which loads `syscalls.md`. Choosing an endpoint happens in `manifest.toml`, which loads `userspace.md`. Choosing a dev-PIV or standalone build command is covered by the pointer comment at the end of the Quick Reference. The `make sandbox-*` commands are run on the host, not by the agent inside the VM.
- **Exact globs.** `user/libsys/**` matches the MPL-licensed crate and nothing else; `*.ld` and `limine*.conf` match the root linker scripts and Limine configs; `src/arch/x86_64/**` loads `x86_64.md` and only there.
- **Delegation.** A subagent gets the root and loads rules from its own reads, so a brief does not need to carry rules text.
- **SPDX (Software Package Data Exchange) header on this file.** Critical Rules asks for one on every new file. None of the 84 tracked Markdown files has one, including the two newest in this directory. This file carries it as an HTML comment; whether Markdown is meant to be in scope is a rule-versus-practice gap for the maintainer to settle.
