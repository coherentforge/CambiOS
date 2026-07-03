# CambiOS Verification Claims

The honest gap-map between *what runs* and *what's proven*.

[STATUS.md](../STATUS.md) is the index of "what runs" (subsystems built, phases reached, test counts). This document is the index of "what's proven" — every load-bearing safety/identity/correctness claim the project makes anywhere (CLAUDE.md, ADRs, [PHILOSOPHY.md](../docs/PHILOSOPHY.md), [SECURITY.md](../docs/SECURITY.md)) gets a row, with an honest column saying how strongly we actually back it. The gap between the two documents is the gap between marketing and reality.

If you came here looking for a list of features, that's STATUS.md. This file is what to point at when someone asks "you keep saying X — what does that mean and how do you know?"

## Schema

One row per *property*, not per harness. A single proof crate may back many properties; conversely, a single property may be backed by multiple harnesses or a mix of proof + tests.

```
## C-N: <one-sentence property statement, in safety-property form>

| Layer        | 1 (behavior) / 2 (guarantee) / 3 (meaning) |
| Status       | Proven / Tested / Asserted / Aspirational |
| Backing      | <crate>::<harness> or <test path> or "prose only" |
| Bound        | <symbolic input range> or "N/A for tests" |
| Gap          | <what's NOT covered — the honest column> |
| Cited where  | <ADR / file:line / CLAUDE.md section> |
| Revisit when | <observable trigger>  (Aspirational rows only) |
```

`Gap:` is the honesty mechanism. A row whose gap reads "behavior on inputs > 256 bytes" is much more useful than a row that just says "memory-safe." Vacuous rows fail review.

## Status — drawn strictly

| Value | Meaning |
| --- | --- |
| **Proven** | Kani / Verus / proof harness in CI. The verifier is the witness. |
| **Tested** | `cargo test --lib` (or equivalent) covers it. Real but weaker — passes are existential ("there exists an input where it works"), not universal. |
| **Asserted** | `debug_assert!` at the relevant callsite. Catches regressions in debug builds; silent in release. Weakest non-trivial backing. |
| **Aspirational** | Claim is made in prose somewhere, with no executable backing. The honest gap. |

If a row would conflate two values (e.g. "Tested at the unit level but Proven at the boundary"), split it into two rows.

## Layer — what kind of claim it is

| Value | Meaning |
| --- | --- |
| **1 (behavior)** | Observable: "RecvMsg blocks on an empty queue and wakes on send." Tests are a natural fit; proofs sometimes apply. |
| **2 (guarantee)** | Invariant: "Every IPC message's `sender_principal` equals the sender's bound Principal at send time." Proofs are the right tool; tests can corroborate. |
| **3 (meaning)** | Intent: "Zero-trust: no operation is implicitly trusted." Always `Aspirational` — meaning-claims are not proof-shaped. Adjudicated by ADR review and red-team, never by a verifier. Layer-3 rows exist so the doc explicitly maps the territory verifiers cannot reach. |

## How to add rows

1. Pick the next free `C-N` (rows are append-only; renumbering breaks every external reference).
2. State the property in safety-property form — what *can't* happen, or what *must* hold. "Foo is fast" is not a property; "Foo terminates within K iterations" is.
3. Fill every field. If `Bound:` would be empty, the property is probably stated wrong. If `Gap:` would be empty, you've over-claimed; widen the property until the gap shows up.
4. If Status is `Aspirational`, the `Revisit when:` field is mandatory and must name an *observable* trigger (Convention 9). "Eventually" / "later" fail the rule.
5. When a Kani harness (or Verus proof, or unit test) lands that strengthens a row, edit the row in the same commit. Don't let proof landings drift out of sync with their CLAIMS.md row.

`make check-claims` is the planned drift gate — orphan harnesses (no corresponding row) and orphan rows (cite a harness/test that doesn't exist) both fail. Lint deferred per the usual cadence: prose first, mechanism on first drift.

---

# Rows

## C-1: ELF parse_header is memory-safe on bounded adversarial input

| Layer        | 2 |
| Status       | Proven |
| Backing      | `verification/elf-proofs::{proof_parse_header_safe_below_size, proof_parse_header_safe_at_size}` |
| Bound        | symbolic `[u8; HDR_SIZE+1]`, len ∈ [0, HDR_SIZE+1] |
| Gap          | Behavior on inputs > 65 bytes is not exhaustively explored. Functional correctness on well-formed binaries is not the proof target — only "no panic, no OOB, no overflow on adversarial input." |
| Cited where  | [ADR-004](../docs/adr/004-cryptographic-integrity.md), CLAUDE.md "Signed ELF loading" |

## C-2: ELF get_program_header arithmetic does not overflow

| Layer        | 2 |
| Status       | Proven |
| Backing      | `verification/elf-proofs::{proof_get_program_header_arithmetic_safe, proof_get_program_header_rejects_out_of_range_index}` |
| Bound        | symbolic `[u8; 256]` + symbolic header + symbolic index |
| Gap          | Loops in `analyze_binary` / `collect_load_segments` are bounded with `e_phnum ≤ 2` so unwind stays tractable; the proof holds per-iteration but iteration count is restricted under symbolic execution. |
| Cited where  | [ADR-004](../docs/adr/004-cryptographic-integrity.md), `src/loader/elf.rs` |

## C-3: BuddyAllocator free() rejects every offset inside the reserved prefix

| Layer        | 2 |
| Status       | Proven |
| Backing      | `verification/buddy-proofs::proof_free_rejects_reserved_prefix` |
| Bound        | reserved prefix size ∈ [16, 256] bytes; symbolic offsets across the full reserved range |
| Gap          | Generalizes a unit test from three hand-picked offsets to *all* offsets at the proven prefix bounds. Larger prefix sizes and the rest of the BuddyAllocator API surface (allocate, order_for_size, etc.) are not yet covered by harnesses; rely on host unit tests. |
| Cited where  | CLAUDE.md "BuddyAllocator template", `src/memory/buddy_allocator.rs` |

## C-4: Frame allocator add_region / reserve_region do not overflow on physical-address arithmetic

| Layer        | 2 |
| Status       | Proven |
| Backing      | `verification/frame-proofs::{proof_add_region_overflow_safe, proof_add_region_idempotent_accounting, proof_allocate_returns_in_bounds, proof_allocate_free_roundtrip}` (11 harnesses total) |
| Bound        | symbolic region (base, length) pairs at u64::MAX boundary; bitmap state up to a small N (`MAX_FRAMES` is shrunk to 256 under `cfg(kani)` so symbolic-base proofs stay tractable) |
| Gap          | Allocator-state-explosion limits prove-able loop depth; mechanical wrap-boundary cases verified, but multi-region interactions beyond the symbolic budget rely on host unit tests as a regression gate. Two real overflow sites in `add_region`/`reserve_region` were found by these proofs and fixed (`saturating_add`) — see CLAUDE.md changelog 2026-04-21. **Honesty note (2026-05-30):** this crate silently stopped compiling once `zero_frame_range` added a `crate::hhdm_offset()` call the proof crate didn't stub, so for an unknown window this "Proven" status was *vacuous* — the suite is in no commit gate, so `make verify` erroring at `verify-frame` went unnoticed. Repaired with a crate-root stub; same pass added `proof_add_region_idempotent_accounting` (the free-frame double-count, P2.10b) and the `cfg(kani)` `MAX_FRAMES` shrink. The deeper fix is gating the suite, not the per-bug repairs. |
| Cited where  | CLAUDE.md changelog 2026-04-21, `src/memory/frame_allocator.rs` |

## C-5: Capability delegation cannot escalate rights

| Layer        | 2 |
| Status       | Proven |
| Backing      | `verification/capability-proofs::{proof_delegate_cannot_escalate_rights, proof_delegate_without_delegate_right_denied}` |
| Bound        | symbolic grantor rights ⊆ `CapabilityRights::all()`, symbolic delegated rights, exhaustive over the rights bitmask space |
| Gap          | The full `CapabilityManager` lifecycle (grant + revoke + delegate + lookup against a generation-counter `ProcessId`) is covered by 12 harnesses, but cross-process composition (sender's caps × receiver's caps × interceptor decision) is per-function — not yet a single end-to-end claim. Identity-binding is C-9 / C-10 below. |
| Cited where  | [ADR-000](../docs/adr/000-zta-and-cap.md), [ADR-007](../docs/adr/007-capability-revocation-and-telemetry.md), `src/ipc/capability.rs` |

## C-6: User-pointer slice validators reject every kernel pointer with non-zero length

| Layer        | 2 |
| Status       | Proven |
| Backing      | `verification/userslice-proofs::{proof_read_kernel_cr3_with_nonzero_len_rejects, proof_write_kernel_cr3_with_nonzero_len_rejects, proof_read_addr_plus_len_overflow_rejects, proof_write_addr_plus_len_overflow_rejects}` (12 harnesses total across read + write) |
| Bound        | symbolic `(addr, len)` over the full u64 × usize space; symbolic CR3 / page-walk state |
| Gap          | The validators (typed `UserReadSlice` / `UserWriteSlice` from ADR-020) are proven safe at the syscall boundary; correctness of the page-walk *result* against actual page-table contents is enforced by the page-walker itself, not these harnesses. |
| Cited where  | [ADR-020](../docs/adr/020-typed-user-buffer-slices-at-syscall-boundary.md), `src/syscalls/user_slice.rs` |

## C-7: DTB byte-extraction primitives never panic on any (slice, offset)

| Layer        | 2 |
| Status       | Proven |
| Backing      | `verification/dtb-proofs::{proof_be_reads_safe_for_any_offset, proof_header_rejects_undersized, proof_header_accepted_offsets_in_range, proof_parse_chosen_addr_length_contract, proof_parse_reg_pairs_bounded}` |
| Bound        | symbolic `[u8; 32]` + symbolic offset for byte-extraction; symbolic `[u8; 96]` for `parse_reg_pairs` with unwind 6; header proofs over `[u8; 40]` |
| Gap          | The end-to-end walker (`walk_dtb_slice`) is *not* yet proven memory-safe at the natural bound — its CBMC budget on macOS Apple Silicon exceeds one CPU-hour per run, and the fix needs walker restructuring, not unwind-tuning. See the deferred P-DTB-6 comment in `verification/dtb-proofs/src/lib.rs` for the trigger. Real bug surfaced and fixed by these proofs: `be_u32_at`/`be_u64_at` claimed "return 0 on overrun" but actually panicked with `attempt to add with overflow` at `usize::MAX - 8` — fixed with `checked_add` (commit `e99cbb8`). |
| Cited where  | [ADR-013](../docs/adr/013-riscv64-architecture-support.md) Decision 2, `src/boot/riscv.rs` |

## C-8: RecvMsg blocks on an empty queue and wakes on subsequent send

| Layer        | 1 |
| Status       | Tested |
| Backing      | `src/syscalls/dispatcher.rs` unit tests + integration tests via `make run` smoke runs across x86_64/aarch64/riscv64 |
| Bound        | N/A — tests pick representative inputs, not symbolic ones |
| Gap          | No proof that for *all* queue states the wake-up is delivered exactly once with no torn read. Concurrency claims (cross-CPU send + recv with intervening preemption) are not proof-shaped under Kani; eventually a TLA+ or seL4-style refinement target. |
| Cited where  | [ADR-005](../docs/adr/005-ipc-primitives-control-and-bulk.md), `src/ipc/mod.rs` |

## C-9: Heap allocation requires `memory::init()` to have completed first

| Layer        | 1 |
| Status       | Asserted |
| Backing      | `debug_assert!` at `src/memory/heap.rs::alloc` entry (CLAUDE.md changelog 2026-04-16) |
| Bound        | N/A — fires at the bad call-site in debug builds; silent in release |
| Gap          | Release builds lose the guard. The invariant is also documented in CLAUDE.md ("No heap allocation before `memory::init()` completes in `main.rs`"), but the only mechanical enforcement is the assert. A static analysis pass that traces reachable code from boot symbols and rejects allocator calls before the init point would be the upgrade. |
| Cited where  | CLAUDE.md "Critical Rules" / Development Convention 5, `src/memory/heap.rs` |

## C-10: Exit revokes every capability held by the exiting process

| Layer        | 2 |
| Status       | Tested |
| Backing      | `src/ipc/capability.rs::tests::test_revoke_all_for_process` + handle_exit integration covered by capability-proofs grant/revoke harnesses |
| Bound        | N/A — tests pick representative cap states, not symbolic ones |
| Gap          | Cross-module property (ProcessTable + CapabilityManager) — Kani's per-function model can't state the claim because the postcondition mentions invariants from two different modules. Targeted for the planned Kani→Verus pivot once contracts compose. The deliberate-fail-in-Kani artifact is row C-11's planned scaffold. |
| Cited where  | [ADR-007](../docs/adr/007-capability-revocation-and-telemetry.md), `src/syscalls/dispatcher.rs::handle_exit` |

## C-11: Identity transcription invariant — every IPC message's `sender_principal` equals the sender process's bound Principal at send time

| Layer        | 2 |
| Status       | Aspirational |
| Backing      | prose only — [ADR-026](../docs/adr/026-identity-transcription-at-the-kernel-ring.md) |
| Bound        | N/A |
| Gap          | The entire claim. The property spans `IpcManager::send_message_with_capability` (stamps sender_principal) + `CapabilityManager::verify_access` (cap check) + `ProcessTable::lookup` (resolves caller's Principal) + `IpcInterceptor` (potential tampering). Four modules, three lock domains, no Kani vocabulary for stating it. The deliberate-Kani-failure step in the planned pivot turns this row's `Backing:` into "Kani harness X (deliberately fails to discharge); Verus harness Y (proven)" once the artifact lands. |
| Cited where  | [ADR-026](../docs/adr/026-identity-transcription-at-the-kernel-ring.md), [identity.md](../docs/identity.md), [ADR-007](../docs/adr/007-capability-revocation-and-telemetry.md) |
| Revisit when | Verus proof crate `verification/identity-proofs-verus/` lands with this claim as row 1; per the Kani→Verus pivot plan in `~/.claude/projects/.../memory/project_verification_claims_and_verus_pivot.md`. The ipc-proofs-failed/ Kani harness is the load-bearing artifact justifying the pivot. |

## C-12: ObjectStore put/get is gated by Principal-based authorization across the fs-service ↔ kernel boundary

| Layer        | 2 |
| Status       | Aspirational |
| Backing      | prose only — [ADR-003](../docs/adr/003-content-addressed-storage-and-identity.md), [ADR-010](../docs/adr/010-persistent-object-store-on-disk-format.md) |
| Bound        | N/A |
| Gap          | Whole claim. Closer to Kani's reach than C-11 (cap-table state is bounded), but cross-process composition (caller's Principal × object owner × ARCSIG signature verification per ADR-010) puts it in Verus territory once the toolchain is paid for. Targeted as the second proof on the Verus crate after C-11 lands. |
| Cited where  | [ADR-003](../docs/adr/003-content-addressed-storage-and-identity.md), [ADR-010](../docs/adr/010-persistent-object-store-on-disk-format.md), [identity.md](../docs/identity.md) |
| Revisit when | C-11 has a Verus proof in CI; the toolchain is then paid-for and C-12 is the next consumer. |

## C-13: Zero-trust — no operation in CambiOS is implicitly trusted

| Layer        | 3 |
| Status       | Aspirational  *(and always will be)* |
| Backing      | prose — [PHILOSOPHY.md](../docs/PHILOSOPHY.md), [ADR-000](../docs/adr/000-zta-and-cap.md), [SECURITY.md](../docs/SECURITY.md) |
| Bound        | N/A |
| Gap          | This is a meaning-claim, not a proof-shape. Adjudicated by ADR review, threat-model coverage, and red-team — never by a verifier. The doc records it explicitly so future readers know the project's verification strategy is *part of* its zero-trust posture, not a substitute for it. The constituent guarantees that *do* compose into "zero-trust" are split out as Layer-2 rows above (C-5 capability non-escalation, C-6 user-pointer validators, C-10 capability revocation, C-11 identity transcription, C-12 storage authorization). |
| Cited where  | [PHILOSOPHY.md](../docs/PHILOSOPHY.md), [CambiOS.md](../docs/CambiOS.md), [ADR-000](../docs/adr/000-zta-and-cap.md), [SECURITY.md](../docs/SECURITY.md) |
| Revisit when | Never (Layer-3). The constituent Layer-2 rows have their own triggers; this row stays Aspirational and acts as the integrator. |

## C-14: AI watches, flags, and sandboxes — but does not write policy

| Layer        | 3 |
| Status       | Aspirational |
| Backing      | prose — [PHILOSOPHY.md](../docs/PHILOSOPHY.md), [ADR-026](../docs/adr/026-identity-transcription-at-the-kernel-ring.md) §3, [SECURITY.md](../docs/SECURITY.md) |
| Bound        | N/A |
| Gap          | A meaning-claim about where AI sits in the trust hierarchy. The mechanical commitment is "AI takes containment action (flag + narrow caps) but does not author the policy that's being enforced" — adjudicated by reviewing every AI-adjacent feature against the rule, never by a verifier. Identity transcription (C-11) is the Layer-2 manifestation of *part* of this stance: the kernel does not branch on AID values, so an AI-mediated decision can never be hidden inside an apparently-mechanical transcription. |
| Cited where  | [PHILOSOPHY.md](../docs/PHILOSOPHY.md), [ADR-026](../docs/adr/026-identity-transcription-at-the-kernel-ring.md), `~/.claude/projects/.../memory/feedback_ai_watches_flags_sandboxes.md` |
| Revisit when | Never (Layer-3). Tracked here so the project's verification strategy stays honest: this is the AI-trust commitment the *rest* of the architecture is being built to make believable, and it cannot be discharged by proof alone. |

## C-15: ProcessTable lookups reject a stale ProcessId whose slot has been reused

| Layer        | 2 |
| Status       | Tested |
| Backing      | `src/process.rs::tests::{process_table_rejects_stale_generation_on_reads, process_table_stale_id_cannot_destroy_current_occupant}` |
| Bound        | N/A — tests pick representative (slot, generation) pairs, not symbolic ones |
| Gap          | Found and fixed a *live* confused-deputy. Every `ProcessTable` read/mutate path (`get_cr3`, `get_heap_base`, `get_heap_size`, `vma`, `vma_mut`, `slot_occupied`, `allocate_for`, `free_for`, `destroy_process`) indexed by `slot()` without checking the generation counter that `destroy_process` bumps on reuse. A stale `creator_pid`/`peer_pid` held in a long-lived channel record therefore resolved to the slot's *new* occupant — `teardown_channel_mappings` freed the wrong process's VMA region and unmapped/tombstoned pages out of an unrelated process's page table. All paths now route through `ProcessTable::resolve` (range + generation + occupancy). Not yet a Kani harness: the `&'static mut` slot array plus a frame-allocating, HHDM-writing `ProcessDescriptor::new` need a `verification/process-proofs` stub crate (mirroring `capability-proofs`) before the property is symbolic. The generation predicate itself is a trivial `!=`; the value of a proof here is cross-path coverage, which the host tests already give. |
| Cited where  | [ADR-019](../docs/adr/019-process-fault-reaping-and-peer-generation.md), `src/process.rs::resolve`, `src/syscalls/dispatcher.rs::teardown_channel_mappings` |
| Revisit when | A `verification/process-proofs/` crate lands (stubs for memory/paging/config, mirroring capability-proofs) — then this row's Backing gains a Kani harness driving create→destroy→reuse→stale-lookup over a symbolic generation, and Status moves Tested → Proven. |

## C-16: An aarch64 TLB shootdown orders the unmapped PTE write before the broadcast invalidation, so no remote core retains a live mapping after the shootdown returns

| Layer        | 2 |
| Status       | Aspirational |
| Backing      | Barrier emitted, disassembly-confirmed (WI-1, `4f29675`): `dsb ishst` precedes every broadcast `tlbi ...is` in `shootdown_page` / `shootdown_range` / `shootdown_all`, with the trailing `dsb ish; isb` retained. Arm ARM DDI 0487 requires the store-ordering `DSB ISHST` before a broadcast TLBI so the PTE write is observable to the invalidate. Not a test, not a proof - the witness is the emitted instruction plus the spec rule. |
| Bound        | The three shootdown primitives in `src/arch/aarch64/tlb.rs`; every unmap path that reaches them. |
| Gap          | QEMU TCG is too strongly ordered to witness the race, so a green boot proves only no-regression and no test can exercise it; no herd7/litmus or Kani weak-memory model exists. The claim rests on (a) the `dsb ishst` being present in the emitted code and (b) the Arm ARM ordering rule being applied correctly - neither is machine-checked. The TLBI *completion* ordering (trailing `dsb ish`) was already correct before WI-1; only the *pre-TLBI store* ordering was missing. |
| Cited where  | `src/arch/aarch64/tlb.rs`, WI-1 (`4f29675`), `notes/audit-concurrency-cfg-parity.md` finding A |
| Revisit when | Real weakly-ordered aarch64 SMP hardware is in the test loop, OR a herd7/litmus or Kani weak-memory model of the shootdown handshake is added to CI - then Status can move toward Tested/Proven. |

## C-17: A riscv64 TLB-shootdown responder always observes the current request payload, never a stale VA/page-count from a prior shootdown

| Layer        | 2 |
| Status       | Aspirational |
| Backing      | Fences emitted, disassembly-confirmed (WI-2, `3cb182b`): `fence rw, w` (Release) before the SBI IPI send in `broadcast_shootdown`, and `fence r, rw` (Acquire) in the inlined `handle_ipi` after clearing `sip.SSIP` and before the payload loads. RISC-V RVWMO: release/acquire synchronize only on the *same* location, so the `SHOOTDOWN_ACK` counter does not order the *payload* (a different location), and neither the SBI IPI nor trap entry is a cross-hart fence - the explicit fence pair is the message-passing happens-before edge. Not a test, not a proof. |
| Bound        | `broadcast_shootdown` + `handle_ipi` in `src/arch/riscv64/tlb.rs`; the `SHOOTDOWN_VA` / `SHOOTDOWN_PAGES` payload. |
| Gap          | QEMU TCG cannot reproduce the stale-read race (it serializes the IPI under a strong model), so no test witnesses it; no litmus/Kani RVWMO model exists. The claim rests on (a) both fences being present in the emitted code and (b) the RVWMO message-passing argument being correct - neither is machine-checked. The `SHOOTDOWN_ACK` release/acquire counter (a separate location) was already correct and is unchanged; only the payload publication lacked an edge. |
| Cited where  | `src/arch/riscv64/tlb.rs`, WI-2 (`3cb182b`), `notes/audit-concurrency-cfg-parity.md` finding B |
| Revisit when | Real riscv64 SMP hardware is in the test loop, OR a herd7/litmus or Kani RVWMO model of the shootdown handshake is added to CI - then Status can move toward Tested/Proven. |

---

# Status summary

As of this draft (2026-06-11):

| Status | Layer 1 | Layer 2 | Layer 3 | Total |
| --- | --- | --- | --- | --- |
| Proven | 0 | 7 | 0 | 7 |
| Tested | 1 | 2 | 0 | 3 |
| Asserted | 1 | 0 | 0 | 1 |
| Aspirational | 0 | 4 | 2 | 6 |
| **Total** | **2** | **13** | **2** | **17** |

The shape is what it should be at this stage: most of the load-bearing safety properties (parsers, allocator, capability manager, user-slice validators) have proof backing; the cross-module identity / authorization properties are honestly Aspirational with a concrete pivot plan; the meaning-claims are Aspirational by their nature and the doc explicitly says so. The two weak-memory TLB-shootdown ordering invariants (C-16, C-17) are a third honest-Aspirational kind: the barrier/fence is provably emitted (disassembly) but the only witness QEMU can give is no-regression, so real weakly-ordered SMP hardware or a litmus/Kani model is the path to a stronger status.

Counts are not the goal; the goal is that the gap is named everywhere it exists.
