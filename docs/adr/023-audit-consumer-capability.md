# ADR-023: Audit Consumer Capability and Principal Resolution

- **Status:** Proposed
- **Date:** 2026-04-26
- **Depends on:** [ADR-007](007-capability-revocation-and-telemetry.md) (audit ring + bootstrap-only attach), [ADR-008](008-boot-time-sized-object-tables.md) (capability-table sizing), [ADR-002](002-three-layer-enforcement-pipeline.md) (three-layer enforcement)
- **Related:** [identity.md](../identity.md) (Principal model + did:key encoding), [PHILOSOPHY.md](../PHILOSOPHY.md) (AI watches, not decides)
- **Context:** Replacing the bootstrap-Principal-only check on `SYS_AUDIT_ATTACH` with a delegated capability so signed boot modules — `audit-tail` today, the kernelvisor / AI watcher tomorrow — can read the audit ring without sharing the bootstrap Principal

## Problem

[ADR-007 § "Audit channel boot sequence"](007-capability-revocation-and-telemetry.md) ships an audit ring that today is consumable by exactly one Principal: the bootstrap. Two architectural gates make it unusable for any other consumer:

1. **`SYS_AUDIT_ATTACH` is bootstrap-Principal-only.** `handle_audit_attach` does an exact equality check against `BOOTSTRAP_PRINCIPAL.load()`. A signed boot module that holds its own Principal cannot attach.

2. **Audit events don't carry the Principal pubkey.** `RawAuditEvent` (`src/audit/mod.rs`, 64 bytes) carries `subject_pid: u64` — a process slot number — not the 32-byte Ed25519 pubkey. Even after attaching, a consumer can't render principals as `did:key:z6Mk…` without an out-of-band lookup.

The IIW-prep work (April 2026) surfaced both gates while scoping a shell-side `audit-tail` command. Two designs were rejected before this one was chosen:

- **Widen `RawAuditEvent` to include the 32-byte pubkey.** Doubles event size, breaks bounded-iteration Kani proofs on `src/audit/buffer.rs`, and reopens ADR-007's wire format. Audit-event emission is on every IPC hot path; the size cost is real.
- **Build around the bootstrap-only check with a delegation shim** (e.g., audit-tail attaches as bootstrap, then re-streams events to other consumers). Locks in the wrong delegation model and double-buffers events that the kernel already buffers once. Pushes complexity that belongs to `revoke()` / capability machinery into a userspace daemon.

The right move is structural: the cap that gates audit consumption is a regular `CapabilityKind` variant; principal resolution is a separate cap-gated syscall; the 64-byte event format stays untouched.

## Decision

Two changes, designed to compose:

### Change A — `CapabilityKind::AuditConsumer`

Replace the bootstrap-equality check in `handle_audit_attach` with a capability check against a new `CapabilityKind::AuditConsumer` variant. Bootstrap grants this capability via the existing capability machinery in `src/ipc/capability.rs` to specific Principals at boot — initially the `audit-tail` boot module, eventually the kernelvisor.

**Why a capability and not a role-flag or trust tier:**
- Reuses the existing `grant` / `verify` / `revoke` paths — no new enforcement substrate.
- Aligns with [ADR-008](008-boot-time-sized-object-tables.md) table-sized capability storage; one more variant fits in the existing `[CapabilityKind; 32]` per-process bound.
- Inherits ADR-007 revocation semantics — a compromised consumer can be cut off via `revoke_all_for_process` on exit, no special audit-side cleanup.

**Granted by name in `load_boot_modules`** (mirroring the `MapFramebuffer` pattern for `fb-demo` / `scanout-limine`). One trusted holder today; widens to the kernelvisor when that ships. Identity-aware grants (per [ADR-018](018-init-process-and-boot-manifest.md) init manifest) replace name-matching when that ADR lands.

### Change B — `SYS_GET_PROCESS_PRINCIPAL`

New syscall. Takes a raw `ProcessId` (slot + generation per ADR-008), writes the bound 32-byte Principal to a user buffer, returns 32 on success. Capability-gated on `AuditConsumer` — same gating posture as audit_attach: if you can read events, you can resolve the principals they reference.

**Why a separate syscall and not a wider event format:**
- Events stay 64 bytes (one cache line). The wire format is a verification target; widening it ripples into ADR-007 + Kani proofs.
- Lookup is rare relative to event emission. Most consumers see the same pids repeatedly and cache the resolved did:keys in userspace.
- Keeps the audit ring as pure transport; identity resolution is its own concern.

**Lookup chain.** Live process table first via `CapabilityManager::get_principal(target_pid)`. On miss, fall back to a recent-exits ring on `ProcessTable` — a bounded SCAFFOLDING circular buffer that records `(slot, generation, principal)` at process exit, so an audit consumer reading buffered events can resolve a `subject_pid` whose process has already exited. Both lookups exit-cleanly with `InvalidArg` if neither produces a match (no `Enoent` variant on `SyscallError` today; documented in the syscall doc).

**Process-exit corner case.** ADR-008 covers slot reuse via generation counters; `subject_pid` in events encodes (slot, generation) and the recent-exits ring is keyed on the same pair. If the same slot is reused before the consumer queries, the new occupant has a different generation — the ring entry from the original occupant survives until evicted by ring wrap.

**Recent-exits ring sizing.** SCAFFOLDING per CLAUDE.md Convention 8. v1 default: 64 entries. At ~10 process exits/min steady state and consumers reading at ≥1/sec, 64 covers ~6 minutes of exit history (25%-utilization rule: typical workload uses ~16 entries). Replace when: kernelvisor stress test shows >64 distinct exits within any 10-second consumer-lag window, or a per-Principal resolution table replaces the ring entirely.

## Architecture

### Capability table

`CapabilityKind::AuditConsumer` joins the existing system-cap variants (`CreateProcess`, `CreateChannel`, `LegacyPortIo`, `MapFramebuffer`, `LargeChannel`, `EmitInputAudit`). `ProcessCapabilities` gains an `audit_consumer: bool` field; `grant_system` / `has_system` / `revoke_system` get matching arms; `revoke_all_for_process` resets the field alongside the others. Convention: every system-cap variant must reset in `revoke_all_for_process` (security-review 2026-04-25 F2 lesson — `emit_input_audit` was originally missed).

### New syscall

| Number | Name | Purpose |
|---|---|---|
| 42 | `SYS_GET_PROCESS_PRINCIPAL` | Resolve a `ProcessId` to its bound 32-byte Principal; AuditConsumer-gated |

Slots 39 and 40 reserved by ADR-022 (wallclock); slot 41 is `SYS_AUDIT_EMIT_INPUT_FOCUS` (T-7 Phase A). Canonical source: the `SyscallNumber` enum in [src/syscalls/mod.rs](../../src/syscalls/mod.rs).

### Lock ordering

No new lock. The handler acquires `CAPABILITY_MANAGER(4)` for the cap check on the caller, releases, acquires it again for the live principal lookup, releases. On miss it acquires `PROCESS_TABLE(6)` for the recent-exits ring lookup. Both acquisitions are read-only; both follow the existing 4 → 6 hierarchy.

### audit-tail boot module

New signed user crate at `user/audit-tail/`. Entry `_start`:
1. Calls `sys::module_ready()` immediately (audit-tail is a leaf consumer; releasing the boot gate up-front means a failure to attach never blocks the rest of the chain).
2. Calls `sys::audit_attach()` — exercises the AuditConsumer cap check.
3. Validates the ring header magic (`ARCAUDIT` little-endian).
4. Loops reading events; for each, resolves `subject_pid` via `sys::get_process_principal()`, formats the principal as `did:key:z6Mk…` via `Principal::to_did_key()` (Phase 4 of identity.md, already shipped in libsys), and prints a one-line summary to the serial console.

Tri-arch: x86_64, AArch64, RISC-V. Position in `limine.conf` / `limine-aarch64.conf` / RISC-V initrd: just before `shell.elf` so most boot events are already in the ring when audit-tail attaches.

## Threat Model Impact

| Threat | Without AuditConsumer | With AuditConsumer |
|---|---|---|
| Compromised audit consumer (signed module exploit) | Same as bootstrap compromise (audit consumer holds bootstrap Principal) | Bounded blast radius — revoke `AuditConsumer` cap via `revoke_all_for_process`, no impact on bootstrap key |
| Audit consumer wants `did:key` rendering | Out-of-band lookup table, sync drift risk, kernel doesn't know who knows what | `SYS_GET_PROCESS_PRINCIPAL` with same cap gate; no parallel auth axis |
| Privacy: who can observe IPC patterns | Only bootstrap | Any process holding `AuditConsumer` — same observability scope as ADR-007 envisions for the future kernelvisor |
| Slot-reuse races (process exits while consumer is mid-batch) | N/A (consumer can't query post-exit principals) | Recent-exits ring; bounded window; consumer detects stale `(slot, generation)` via `InvalidArg` return |

### What this does NOT protect against

- **A malicious AuditConsumer holder fabricating audit observations.** The cap grants *read* access; the holder can't forge events into the ring (kernel-only writer). It can lie *about* what it read in its own output, but that's a userspace-output-trust problem, not an audit-ring-trust problem.
- **Kernel compromise.** The kernel writes events and enforces the cap check. Same TCB as ADR-007.
- **A future ProcessIntrospect cap.** Today `GET_PROCESS_PRINCIPAL` and `AUDIT_ATTACH` share the same gate. If a non-audit consumer (GUI window-owner labeling, win-compat layer) needs principal lookup without ring access, a separate `ProcessIntrospect` cap is added — then `GET_PROCESS_PRINCIPAL` accepts either cap. Deferred until a second consumer needs it.

## Verification Stance

- **Cap variant mechanics.** Every system-cap variant must round-trip through `grant_system` / `has_system` / `revoke_system` and reset in `revoke_all_for_process`. The exhaustive regression test `test_revoke_all_clears_every_system_capability` walks all variants — adding a variant without updating the test array trips the next CI run.
- **Identity-gate completeness.** `requires_identity()` and the `identity_required_syscalls_are_gated` test array must include every new syscall. The `all_syscall_numbers_covered` test rounds-trip-checks every defined `from_u64` slot.
- **Bounded recent-exits ring.** `RECENT_EXITS_RING_SIZE = 64` is `const`; lookup is a single-pass linear scan over a fixed-size array — verifiable bounded iteration per CLAUDE.md.
- **No new unsafe blocks.** The cap check, principal lookup, and ring push are pure-Rust; the audit-tail user code uses one `read_volatile` per event read, with bounds enforced by ring-slot arithmetic against the kernel-validated `capacity` header field.

## Migration Path

Three commits on the `audit-consumer-cap` branch:

1. **Capability variant.** Adds `CapabilityKind::AuditConsumer` + `audit_consumer: bool` field + match arms + reset block + 3 focused tests + extended regression test array. Behavior unchanged (no caller checks the cap yet).

2. **Syscall + handler change.** Replaces the bootstrap-eq check on `handle_audit_attach` with the AuditConsumer cap check. Adds `SYS_GET_PROCESS_PRINCIPAL = 42` (handler + dispatch arm + libsys wrapper). Adds the recent-exits ring on `ProcessTable` with `record_exit` / `lookup_recent_exit` methods. Wires `record_exit` into `handle_exit` before `destroy_process` bumps the generation. 5 new ring tests.

3. **`audit-tail` boot module.** New user crate (Cargo.toml + 3 link scripts + main.rs). Makefile recipes for x86_64 / AArch64 / RISC-V; iso/img/initrd packaging. `limine.conf` + `limine-aarch64.conf` entries. RISC-V initrd `--module audit-tail=`. Kernel-side name-based grant of `AuditConsumer` in `load_boot_modules`. ADR-023 + STATUS.md row + CLAUDE.md Required Reading row + this ADR.

Each commit independently passes `make check-all` + `cargo test --lib`. Bisect-friendly.

## Open Questions

1. **Single fat `AuditConsumer` cap or partitioned by event-kind subset?** Today: single fat cap. Partition (e.g., `AuditConsumer(IPC|Capability|Object|Input|Compositor)`) when a second consumer with asymmetric needs appears (e.g., a per-window event log only the compositor reads). YAGNI until then.

2. **`GET_PROCESS_PRINCIPAL` gated by `AuditConsumer` or separate `ProcessIntrospect` cap?** Today: gated by `AuditConsumer`. Decoupled when a non-audit consumer (GUI window-owner labeling, win-compat layer) needs principal lookup without ring access. Forward-compatible — adding `ProcessIntrospect` later means `GET_PROCESS_PRINCIPAL` accepts either cap, no syscall renumber.

3. **Recent-exits ring sizing.** SCAFFOLDING bound `RECENT_EXITS_RING_SIZE = 64`. **Revisit when:** kernelvisor stress test shows >64 distinct exits within any 10-second consumer-lag window, or a per-Principal resolution table makes the ring obsolete.

4. **Audit-tail's role post-kernelvisor.** Once the kernelvisor exists, audit-tail becomes either (a) redundant — kernelvisor reads the ring directly; or (b) the user-facing `tail -f /var/log/audit` analog while kernelvisor does anomaly detection. Decide when kernelvisor design lands.

## Cross-References

- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Original audit ring design; this ADR replaces its bootstrap-only attach check.
- **[ADR-002](002-three-layer-enforcement-pipeline.md)** — The pipeline AuditConsumer cap-gating fits into (Layer 2 capability check).
- **[ADR-008](008-boot-time-sized-object-tables.md)** — Capability-table sizing (`[CapabilityKind; 32]` per process); generation counters (basis for recent-exits ring keys).
- **[identity.md](../identity.md)** — Principal model; Phase 4 did:key encoding (already shipped in libsys; consumed by audit-tail).
- **[PHILOSOPHY.md](../PHILOSOPHY.md)** — "AI watches, not decides" — the architectural commitment audit-tail is the first concrete step toward.
