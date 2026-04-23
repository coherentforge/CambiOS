<!--
doc_type: implementation_reference
owns: adversarial threat ledger — known penetration paths, severity, mitigations, revisit triggers
last_synced_to_code: 2026-04-23 (initial)
authoritative_for: ranked adversarial attack surfaces against CambiOS, what each one needs to become exploitable, and what observable trigger should cause it to be re-audited
-->

# CambiOS Adversarial Threat Model

Companion to [SECURITY.md](SECURITY.md), which describes *posture* and *enforcement points*. This document describes *attacks* — ranked by yield against CambiOS as it exists today, with current mitigations and the observable trigger that should cause each to be re-audited.

A threat listed here is not a bug report. Some are live (exploitable today), some are latent (need future code to become live), some are out-of-scope-today (depend on environmental assumptions that haven't been resolved, e.g. physical access on the Dell). The ledger's purpose is twofold:

1. **No threat gets forgotten.** When something is mitigated or deleted, the entry moves to `Status: Mitigated` / `Removed`, it does not disappear.
2. **External review has a starting point.** Post-HN, this is the document a security researcher reads first to understand what has and has not been audited.

## Severity legend

- **Critical** — achieves kernel-mode code execution, or exfiltrates the bootstrap Principal, or bypasses the capability check.
- **High** — elevates one user-space process to privileges it was not granted; leaks another process's data.
- **Medium** — denial-of-service, denial-of-audit, information leak that does not directly elevate.
- **Low** — latent hazard; no current exploit, but the invariant is weaker than the code reads.

## Status legend

- **Live** — exploitable today given the stated attacker capability.
- **Latent** — no current exploit path; becomes live if future code crosses a named boundary.
- **Mitigated** — defense-in-depth reduces severity; primary defense still applies.
- **Out-of-scope-today** — depends on an environmental assumption that hasn't been resolved (physical access, external CI, etc.).
- **Dead-code** — associated code path is unreachable; deletion tracked separately.

Each entry carries a `Revisit when:` line naming an **observable trigger** (per Dev Convention 9). "Eventually" / "when that matters" is not a valid trigger.

---

## T-1 — Build-time supply chain

**Threat.** A poisoned Cargo dependency (direct or transitive) runs arbitrary code in `build.rs` or a proc macro on the developer host during `cargo build --target x86_64-unknown-none`. The compromised kernel image is then handed to `sign-elf`, which signs whatever bytes it receives. ARCSIG verification in the kernel passes because the signature is over the compromised bytes.

**Why it matters for CambiOS.** The verification story ends at the Rust source. Build scripts are not sandboxed by the kernel target triple — they run as the developer's user on the developer's macOS host, with full FS access. The YubiKey signs hashes, not intent; the signed-ELF chain of trust is only as strong as the host that produced the hash.

**Current mitigation.** Solo author with an auditable tree. No known poisoned deps. Formal verification (future) would not catch this — it verifies the written source, not the built artifact.

**Gap.** No lockfile audit gate. No reproducible-build check. No `cargo-vet` / `cargo-crev`. No host hardening discipline documented.

**Severity.** Critical. **Status.** Live.

**Revisit when:** first external contributor lands a PR that touches `Cargo.toml` or `Cargo.lock`; or when CI infrastructure (GitHub Actions, etc.) gains the ability to run `cargo build` on fork PRs.

---

## T-2 — Pre-kernel attacker on boot media

**Threat.** An adversary with brief physical access to the Dell 3630 (evil maid), or with pre-boot malware persistence, modifies the Limine config or the kernel ELF on the boot partition. The modified kernel boots, ARCSIG verification is irrelevant because *the verifier is the kernel itself* and no measurement exists below the kernel.

**Why it matters for CambiOS.** The project's identity model anchors at the bootstrap Principal, which is generated inside the already-booted kernel. Nothing in firmware measures the kernel before it runs. On QEMU this is abstract. On the Dell it's physical reality.

**Current mitigation.** None on the Dell. UEFI image validates in QEMU; bare-metal boot pending.

**Gap.** Secure Boot / BitLocker decision unresolved (see project memory: `dell_bare_metal_gate`). TPM measured boot not integrated. Firmware-level anchor does not exist.

**Severity.** Critical (attacker with physical access). **Status.** Out-of-scope-today pending the Dell boot-gate decision; Live the moment physical deployment begins without a firmware anchor.

**Revisit when:** Jason picks one of the three Secure Boot / BitLocker options in `dell_bare_metal_gate`; or when `docs/camBIOS.md` (project memory: `cambios_firmware`) firmware roadmap produces a measurable boot anchor.

---

## T-3 — Bootstrap Principal as kernel-held secret

**Threat.** The bootstrap Principal is the most privileged identity in the running system — it can `bind_principal`, `claim_bootstrap_key`, `audit_attach`, `channel_revoke`, and perform early `revoke_capability`. If the bootstrap *secret key* ever lands in kernel memory, any info-leak primitive elsewhere in the kernel exfiltrates the crown jewel.

**Why it matters for CambiOS.** The identity story's entire weight sits on this key. "Frame-A" identity (project memory: `frame_b_identity`) treated the kernel as a Principal; "Frame-B" reframes the kernel as an arbiter. Until the Frame-B rewrite lands, the Frame-A code paths are vestigial but still shaped like real attack surface.

**Current mitigation.** `BootstrapSecretKey::store()` is never called anywhere in the tree (see [F2](#f2--dead-bootstrap-claim-syscall) below). `SYS_CLAIM_BOOTSTRAP_KEY` therefore always returns `PermissionDenied`. The "key in kernel memory" threat is *not live* because the key is never there. But the mechanism remains shaped for a key that no longer exists in the design.

**Gap.** Dead code occupying a syscall number and an API-visible concept. Frame-B identity rewrite pending — until it lands, the Frame-A-shaped surface is bait for a future contributor who "fixes" the dead path by reviving it.

**Severity.** High (if revived without Frame-B). **Status.** Dead-code.

**Revisit when:** Frame-B identity rewrite lands (project memory: `frame_b_identity`); or someone proposes restoring `BootstrapSecretKey::store()`.

---

## T-4 — `unsafe` in syscall entry/exit and context switch

**Threat.** A mismatch between the syscall-entry stack swap and the timer-ISR / `yield_save_and_switch` save-context paths corrupts `SavedContext` or leaves the kernel `RSP` pointing at attacker-influenced memory. Result: kernel-mode RIP control at the next return — full compromise, no capability check ever runs.

**Why it matters for CambiOS.** These `unsafe` blocks are irreducible (the hardware semantics require raw asm). They are also the blocks where a bug is invisible in SAFETY comments — the invariant lives in the *agreement* between two separate asm paths (syscall vs. ISR vs. voluntary yield) that must produce bit-identical frames. x86_64 `syscall_entry` / AArch64 SPSel toggle / RISC-V S-mode trap are the three hot sites.

**Current mitigation.** SAFETY comments + host-side layout tests on `SavedContext`. Tri-arch build gate (`make check-all`) catches compile-time frame mismatches. `PerCpu.kernel_rsp0` updated on every context switch.

**Gap.** No formal proof that the three save paths produce identical frames. No Kani harness on context switch. The "three sites must agree" invariant is enforced by human discipline, not the type system.

**Severity.** Critical. **Status.** Mitigated (no known exploit), Live for a future regression.

**Revisit when:** a context-switch Kani proof crate lands (mirror the `capability-proofs` crate shape from prompt-shaping changelog 2026-04-21); or any of the three arch backends grows a fourth save path.

---

## T-5 — ELF loader permission-merge

**Threat.** Two `PT_LOAD` segments in a signed ELF share a page with different permissions (e.g. `.text` RX + `.got`/`.data` RW). The loader uses the first segment's permissions for the shared page. A carefully laid-out ELF gets a page mapped more permissively than the author intended — specifically, an RW page where an RX page was expected, or vice versa, producing a W^X violation that survives signature verification.

**Why it matters for CambiOS.** The signature covers the bytes, not the layout semantics. A self-signed binary that crafts a tail-sharing layout defeats the W^X invariant the rest of the system assumes. Attacker then has a legitimate code-signing primitive via ordinary `ObjPutSigned` flows.

**Current mitigation.** User-space linker scripts use `ALIGN(4096)` before `.data` to avoid tail-sharing in first-party code. The issue is documented in `CLAUDE.md` "Platform Gotchas." Signed-binary verification still catches arbitrary unsigned code.

**Gap.** Loader-side enforcement missing. A malicious-but-signed binary (e.g., after F2 in T-3 is closed) bypasses the W^X invariant regardless of the linker script.

**Severity.** High. **Status.** Live against any signed binary whose author controls the layout.

**Revisit when:** loader grows either strictest-perm merging for shared pages, or rejection of overlapping PT_LOAD segments. See `STATUS.md` loader row.

---

## T-6 — Syscall user-pointer double-fetch

**Threat family.** A syscall handler reads user memory once to validate/parse, then reads the same (or derived) user memory again to act. A concurrent thread in the same process swaps the page between reads. Kernel validates one value and acts on a different one.

**Why it matters for CambiOS.** No SMAP. User pointers are page-walked via HHDM, not copied to kernel memory via a hardware-atomic path. The kernel's guarantees about what it "read" are only as strong as its discipline about re-reading.

**Current mitigation.** ADR-020 typed slices (`UserReadSlice` / `UserWriteSlice`) force a validate-once / read-into-kernel-buffer-once shape. Audited 2026-04-23: every handler in `src/syscalls/dispatcher.rs` that touches user memory reads into a kernel `kbuf` and makes all downstream decisions from `kbuf`. `dispatch()` resolves `caller_principal` once from `CAPABILITY_MANAGER`, not user memory. `SyscallArgs` is a by-value register snapshot — no back-channel through arg accessors.

**Gap.** The family-level invariant is discipline, not the type system. A future handler that acts on a derived user pointer (reads a header, extracts a pointer field, re-validates) reintroduces the hazard. Two sub-findings below.

**Severity.** Medium (family). **Status.** Mitigated for current handlers; Latent for future handlers.

**Revisit when:** any new handler reads a user buffer and then validates a *second* user address whose value was derived from the first read; or when `UserReadSlice::read_into` is called more than once on the same slice.

### F1 — Intra-`read_into` cross-page TOCTOU

**Threat.** `copy_from_user_pages` at [user_slice.rs:91-131](user_slice.rs) walks pages in a loop: `translate(vaddr_n)` then `read_phys(...)` per page. The loop is not atomic across pages. A multithreaded caller unmaps+remaps page N+1 between the N-th and (N+1)-th iterations. Kernel's `kbuf` ends up mixed from two timelines of the caller's memory.

**Why it matters.** The invariant "`kbuf` is a faithful point-in-time snapshot of caller memory" is false today. No current handler is exploitable because nobody acts on *derived pointers* inside `kbuf`; `handle_obj_put_signed` verifies the signature over the same `kbuf` it stores, so intra-read inconsistency costs the attacker a valid signature rather than earning them anything.

**Current mitigation.** None beyond the `kbuf`-is-consistent-with-itself-not-with-reality shape.

**Gap.** A future handler that reads a header containing a pointer, then validates and reads from that pointer, would be vulnerable. There is no lint for this.

**Fix menu, cheap → expensive.** (a) Document `kbuf` as non-atomic with respect to caller memory; callers must not trust cross-page consistency for security decisions. (b) Hold the process's VMA lock for the duration of the read (new lock-order position). (c) Page-pin the entire range via refcount. Near-term answer is (a).

**Severity.** Low. **Status.** Latent.

**Revisit when:** a new handler reads `> 4096 / PAGE_SIZE` pages of user memory in one call and acts on a pointer field inside the read.

### F3 — Pre-validate u64 arithmetic

**Threat.** Several handlers compute `user_addr + offset` in raw `u64` before passing to `UserWriteSlice::validate`. Specifically: `handle_recv_msg` [dispatcher.rs:1034](../src/syscalls/dispatcher.rs#L1034), `handle_try_recv_msg` [dispatcher.rs:1139](../src/syscalls/dispatcher.rs#L1139), `handle_obj_list` [dispatcher.rs:1350](../src/syscalls/dispatcher.rs#L1350). A wrapping add silently produces a low address that passes `validate`'s canonical-range checks.

**Why it matters.** The practical safety of these sites depends on a *different* function's invariant — `validate` rejects `addr >= USER_SPACE_END`, and `USER_SPACE_END < 2^47`, so a `user_buf` that passes validate-for-the-header cannot wrap when 36 or 4096 is added. The argument is correct but cross-function; it survives one refactor and dies at the second.

**Current mitigation.** `USER_SPACE_END` bound in [user_slice.rs:64-68](../src/syscalls/user_slice.rs#L64-L68) sits two orders of magnitude below `u64::MAX`.

**Gap.** Defense-in-depth missing. `checked_add` at each of the three sites is a two-line change.

**Severity.** Low. **Status.** Mitigated (practically); defense-in-depth gap.

**Revisit when:** `USER_SPACE_END` is raised (e.g., port to a 57-bit VA architecture), or a fourth site is added.

---

## T-7 — Virtio-input focus hijack

**Threat.** First-live-window focus per ADR-012 Divergence: whichever process creates a window first becomes the focused recipient of `MsgTag::InputEvent = 0x4030`. A malicious application that wins the focus race receives keystrokes intended for a later-created sensitive window (e.g., key-store password entry).

**Why it matters for CambiOS.** The compositor trusts the first-window-wins policy. There is no trust tier on input routing — every focused window is equally trusted with every input event. ADR-012 Input-5 (trust tiers / signed carrier) is explicitly deferred.

**Current mitigation.** None beyond "first wins." Input Hub is not deployed. Signed-carrier hardware does not yet exist.

**Gap.** Anti-spoofing on focus transitions. User-visible indicator of which process holds focus. Trust-tier-per-event routing.

**Severity.** Medium (elevation of one app to snoop another's input). **Status.** Live.

**Revisit when:** a second input consumer appears (triggers Input Hub per ADR-012 Divergence); or any window class gains a higher-trust tier in the compositor.

---

## T-8 — Audit silencing via ring-lock contention

**Threat.** `AUDIT_RING` is drained by `drain_tick()` from the BSP via `try_lock`. A capability-holding attacker who contends the ring lock across drain intervals (e.g., via timed `SYS_AUDIT_ATTACH` / `SYS_AUDIT_INFO` calls) causes per-CPU SPSC buffers to overflow. Overflowed events are dropped. Dropped events are the attacker's footprint — if the drop counter does not fail loud, the attack leaves no trace.

**Why it matters for CambiOS.** Audit is the only observable below-the-policy-service telemetry path. Denial-of-audit is a prerequisite for any multi-step attack that would otherwise trip a behavioral anomaly detector. Silent audit failure is strictly worse than loud audit failure.

**Current mitigation.** Per-CPU SPSC buffers reduce contention; `try_lock` on BSP prevents deadlock; drop counter exists. Two-phase protocol in `SYS_AUDIT_ATTACH` avoids lock-ordering violations.

**Gap.** No loud-failure path when drop counter increments. No alarm is raised to a privileged observer. The counter is readable but no subsystem checks it on a schedule.

**Severity.** Medium. **Status.** Live.

**Revisit when:** a privileged observer (init process, policy service, or dedicated audit-health task) starts checking `drop_counter > 0` on a schedule; or a loud-path alarm is added to the kernel when the counter first becomes non-zero.

---

## F2 — Dead bootstrap-claim syscall

**Finding.** `BOOTSTRAP_SECRET_KEY` at [lib.rs:421](../src/lib.rs#L421) is declared as 64 zero bytes. `BootstrapSecretKey::store()` is defined but **never called anywhere in the source tree** (grep 2026-04-23). `SYS_CLAIM_BOOTSTRAP_KEY` at [dispatcher.rs:1386-1388](../src/syscalls/dispatcher.rs#L1386-L1388) therefore always takes the `None` branch of `claim()` and returns `PermissionDenied`. The syscall number, the enum variant, the handler, the userspace wrapper, and the kernel-side secret slot are all vestigial Frame-A surface.

**Why it matters for CambiOS.** Dead code that looks like live code is a future-contributor trap. Someone will "fix" the unreachable `None` branch by wiring up `store()` without understanding the Frame-B implications.

**Recommended action.** Either delete the whole Frame-A path (`BOOTSTRAP_SECRET_KEY`, `SYS_CLAIM_BOOTSTRAP_KEY`, `BootstrapSecretKey` struct, userspace wrapper), or annotate each site with a `Revisit when: Frame-B lands` deferral comment per Dev Convention 9. Deletion is cleaner; annotation preserves optionality if Frame-B reuses the slot.

**Severity.** High if revived without Frame-B. **Status.** Dead-code.

**Revisit when:** Frame-B identity rewrite lands; or any commit adds a call to `BootstrapSecretKey::store()`.

---

## How to use this document

- **Before starting work on security-adjacent code:** scan the `Revisit when:` lines for triggers that match your change. If a trigger matches, re-audit the entry before editing.
- **When a threat is mitigated:** move it to `Status: Mitigated`, add a line explaining what mitigated it, keep the entry. Do not delete.
- **When a threat is obsoleted** (the code it referred to no longer exists): move to `Status: Removed`, add the commit that removed it, keep the entry. Historical attack surface that came and went is useful to future reviewers.
- **When a new threat is identified:** add a new entry. If it's a sub-finding of an existing family (like F1 under T-6), nest it. If it's orthogonal, give it a new top-level slot.

This file is not a dashboard. It does not get auto-generated. It gets updated by hand when the world changes.
