# ADR-024: Syscall ABI in a Standalone Contract Crate (`cambios-abi`)

- **Status:** Proposed
- **Date:** 2026-04-26
- **Depends on:** [ADR-002](002-three-layer-enforcement-pipeline.md) (the pipeline that enforces the ABI), [ADR-022](022-wall-clock-time.md) (slot reservation discipline that depends on a stable ABI definition)
- **Related:** [ADR-023](023-audit-consumer-capability.md) (concurrent landing whose dead-code warnings on policy-service made the duplication concrete)
- **Context:** Where the canonical syscall-number table lives, and why the kernel and userspace both depend on a third crate rather than embedding their own copies

## Problem

Through 2026-04, the syscall-number table was encoded in three places:

1. The kernel's `SyscallNumber` enum in `src/syscalls/mod.rs` (canonical, `repr(u64)`).
2. `user/libsys/src/lib.rs` — 37 private `const SYS_*: u64` declarations referenced by every wrapper function (`sys::audit_attach()` etc.).
3. `user/policy-service/src/main.rs` — 38 private `const SYS_*: u32` declarations used to build per-process syscall allowlists.

The userspace mirrors were maintained by hand. The comment "must match `src/syscalls/mod.rs`" was the only enforcement mechanism. Drift was inevitable and observable: when `SYS_GET_PROCESS_PRINCIPAL = 42` landed in the [ADR-023](023-audit-consumer-capability.md) chain, libsys was updated but policy-service was missed; the next `make iso` emitted **9 dead-code warnings** for constants policy-service had declared but didn't reference for any tracked process. Those warnings were the symptom; the missing entries that would have been needed for a future profile change were the latent bug.

A "compile fails if mismatched" enforcement was structurally impossible while three separate copies existed.

## Decision

Factor the syscall ABI out into a standalone `cambios-abi` crate that both the kernel and userspace depend on. The kernel re-exports the types via `pub use cambios_abi::*` so existing call sites (`use crate::syscalls::SyscallNumber`) compile unchanged; userspace crates depend on `cambios-abi` directly (libsys consumes it; libsys re-exports `SyscallNumber` so downstream user crates don't need to take a direct dep on cambios-abi).

`cambios-abi` owns:
- `pub enum SyscallNumber` — `repr(u64)`, full mirror of the kernel-side enum, with `from_u64` and `requires_identity` impls.
- `pub enum SyscallError` — return-code variants.
- `pub struct SyscallArgs` — abstract 6-arg shape with helper methods.
- `pub type SyscallResult` — the kernel handler return type.
- The four ABI tests (exempt-set membership, identity-gate completeness, exempt-set size, full `from_u64` round-trip).

## Architecture

### Why a separate crate, not a shared module

Cargo workspace mechanics: the kernel is the workspace root crate; userspace crates are workspace-excluded (different targets, different linker scripts, different toolchain configs). A shared module across that boundary requires *some* crate to own it. Embedding the ABI in `cambios` (kernel) means userspace can't consume it without depending on the kernel binary; embedding in `cambios-libsys` means the kernel depends on a userspace crate. A third crate is the only shape that lets both sides consume cleanly.

### Why permissive license (MPL-2.0)

The kernel is AGPL-3.0-or-later; libsys is MPL-2.0. AGPL → MPL consumption is one-way (an MPL contract can be consumed by AGPL code; the reverse would virally restrict). Putting the ABI under MPL-2.0 (matching libsys) preserves the option for future non-AGPL consumers — a Windows compatibility layer ([ADR-016](016-win-compat-api-ai-boundary.md)), a non-Rust ABI client (cbindgen target eventually), or a third-party user crate — to depend on the contract without inheriting AGPL terms.

### Why `no_std` + zero dependencies beyond `core`

`cambios-abi` is consumable by every CambiOS target — `x86_64-unknown-none`, `aarch64-unknown-none`, `riscv64gc-unknown-none-elf`, plus the `x86_64-apple-darwin` host for tests. Any non-`core` dependency would have to satisfy all four. More importantly, the crate is a future verification target: a Kani harness proving `from_u64 ∘ as_u64 = id` is straightforward when there's nothing to mock. Adding deps now would foreclose that.

### Why workspace-excluded

`cambios-abi` is not a kernel workspace member. Mirrors the existing posture for libsys and every user crate: kernel and userspace both reference it via `path = "..."`, build it once per consumer's target, and don't pull it into `cargo build` against the kernel workspace.

## Migration

Four-commit chain on the `syscall-abi-crate` branch (each independently passes `make check-all`):

1. **Crate creation.** `cambios-abi/{Cargo.toml,src/lib.rs}` with the full type mirror. Workspace `exclude` updated. Standalone build + tests pass; nothing else uses it yet (intentional dead code for one commit, bisect-friendly).
2. **Kernel migration.** `Cargo.toml` adds the path dep; `src/syscalls/mod.rs` cuts ~590 lines and replaces them with `pub use cambios_abi::{...}`. Kernel call sites unchanged. `make stats` repointed at the new file.
3. **libsys migration.** `user/libsys/Cargo.toml` adds its first dependency (`cambios-abi`); 37 private `const SYS_*` declarations cut; every wrapper-internal `SYS_FOO` becomes `SyscallNumber::Foo as u64`; `pub use cambios_abi::SyscallNumber` re-exports the type for downstream consumers.
4. **policy-service migration.** Drops 38 private `const SYS_*: u32` plus the `_SYS_MAP_FRAMEBUFFER_KEPT` dead-code-silencing hack. `fn profile(syscalls: &[u32]) -> Profile` becomes `fn profile(syscalls: &[SyscallNumber]) -> Profile` — type-safe profile arrays. The 9 dead-code warnings vanish.

After the chain lands, the canonical ABI lives in exactly one file. Adding a new syscall touches cambios-abi (the enum + `from_u64` arm) and downstream consumers as needed; the kernel re-export propagates the new variant automatically; drift is structurally impossible.

## Verification Stance

- **Coverage tests stay where the types live.** The four `#[cfg(test)] mod tests` (exempt-set membership, identity-gate completeness, exempt-set minimal, `from_u64` round-trip) move to cambios-abi alongside `SyscallNumber`. `cargo test --target x86_64-apple-darwin` from `cambios-abi/` runs them; the kernel test suite (`cargo test --lib --target x86_64-apple-darwin`) drops 4 tests but loses no coverage (548 → 550 → continues).
- **Type-system enforcement.** `policy-service`'s profile arrays now type-check at compile time: `&[SyscallNumber::Write, …]` cannot accidentally include a non-syscall integer.
- **Zero `unsafe`.** `cambios-abi` has no unsafe blocks. Future Kani proofs land cleanly.

## What This Does NOT Decide

- **The ABI shape itself.** Numbers, identity gating, capability requirements, error-code semantics — all unchanged from before the refactor. This ADR is about *where* the contract lives, not *what* it says.
- **Stability commitment.** Slots are reserved per ADR-022 discipline; that discipline now applies to cambios-abi rather than `src/syscalls/mod.rs`. Nothing about the long-term ABI commitment changes.
- **Multi-language clients.** `cambios-abi` is the cbindgen target when one is needed. No header is generated today; the crate's permissive license + lean dep tree keep that option open.

## Open Questions

1. **Kani proof crate for ABI invariants?** Strong candidate post-HN: `from_u64 ∘ as_u64 = id` for every variant, exempt-set inclusion in the identity-gate complement, etc. Trivial proofs against pure pattern-matching; verification-friendly.
2. **Should `cambios-abi` grow more types over time?** Probable additions: a stable `Principal` representation (currently in `src/ipc/mod.rs`), the `RawAuditEvent` wire format ([ADR-007](007-capability-revocation-and-telemetry.md)), maybe `ChannelRole` ([ADR-005](005-ipc-primitives-control-and-bulk.md)). Decide on a per-type basis: anything the kernel + userspace both need to agree on is a candidate; anything kernel-internal stays in the kernel.
3. **Versioning and compatibility.** `cambios-abi` is at `0.1.0` today; pre-1.0 means breaking changes are allowed. When the project hits a public-stability point (post-HN, post-IIW external feedback absorbed), bump to 1.0 and commit to no-renumber, no-removal — the same discipline ADR-022 already applies to slot reservations.
