# ADR-020: Typed User-Buffer Slices at the Syscall Boundary

- **Status:** Proposed
- **Date:** 2026-04-19
- **Depends on:** CLAUDE.md Development Convention 1 (no panics in kernel) and Convention 6 (invariants encoded in types), [ADR-002](002-three-layer-enforcement-pipeline.md) (kernel is the enforcement boundary between user and kernel trust domains)
- **Related:** [ADR-019](019-process-fault-reaping-and-peer-generation.md) (the proposed `ExitInfo` struct is one of many user-provided output buffers; this ADR's types are how that handshake should be implemented), [ADR-018](018-init-process-and-boot-manifest.md) (manifest-driven spawn; init-facing syscalls take user pointers like every other syscall), [ADR-007](007-capability-revocation-and-telemetry.md) (audit events for user-pointer validation failures fit the existing machinery)
- **Supersedes:** N/A

## Scope Boundary (read this first)

This ADR retrofits **every user-provided pointer argument in every syscall** to a validated newtype. It does not introduce kernel-wide typed addresses (no `VirtAddr` / `PhysAddr` pass). The split:

| Concern | In scope |
|---|---|
| User buffers read by the kernel (e.g., `SYS_WRITE` payload) | ✅ `UserReadSlice<'ctx>` |
| User buffers written by the kernel (e.g., `SYS_RECV_MSG` output) | ✅ `UserWriteSlice<'ctx>` |
| Output pointers in channel / MMIO / DMA syscalls (user buffers the kernel writes kernel-allocated values into) | ✅ `UserWriteSlice<'ctx>` |
| Kernel-returned virtual-address *values* (the `u64` the kernel computes and returns) | ❌ out of scope |
| Physical addresses inside kernel bookkeeping | ❌ out of scope |
| Kernel-internal pointers (IPC message buffers, frame-allocator scratch, etc.) | ❌ out of scope |
| A broader `VirtAddr` / `PhysAddr` / `UserVirtAddr` / `KernelVirtAddr` newtype pass across the kernel | ❌ future ADR (see Open Problems) |

The rule: this ADR fixes the **trust-boundary** validation problem — untrusted user input crossing into the kernel. The separate class of bug (mixing phys and virt addresses inside the kernel) is a different scope and a different ADR.

## Context

CambiOS today handles user-pointer syscall arguments as raw `u64` values that flow through multiple handler layers before reaching the validating helpers `read_user_buffer` and `write_user_buffer` in [src/syscalls/dispatcher.rs](../../src/syscalls/dispatcher.rs). A typical path:

```rust
fn handle_write(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
    let endpoint_id = args.arg1_u32();
    let user_buf = args.arg2;             // raw u64 — unvalidated
    let len = args.arg_usize(3);          // raw usize — unvalidated
    if len == 0 { return Ok(0); }
    if len > 256 { return Err(SyscallError::InvalidArg); }
    let mut kbuf = [0u8; 256];
    read_user_buffer(ctx.cr3, user_buf, len, &mut kbuf)?;   // validation happens here
    // ... kbuf is used ...
}
```

The pair `(user_buf, len)` is semantically a single concept — "a user-provided slice" — but is carried as two independent `u64` arguments, indistinguishable from any other pair of `u64` values, all the way to the moment `read_user_buffer` runs its bounds checks.

Seventeen syscall handlers follow this pattern — some with user-read pointers, some with user-write pointers, a few with both — and the validating helpers (`read_user_buffer`, `write_user_buffer`, `copy_from_user_pages`, `copy_to_user_pages`) are well-tested at the edges but structurally separate from the handlers that call them. A refactor that shuffles a call site can silently skip the validation and the type system will not object.

This is exactly the pattern Cliff Biffle named in the Hubris/Humility talk: *the address and the size are not welded into a unitary value; operations are inconsistent on whether they take both or just part; the validated pair is indistinguishable from the unvalidated pair.* Rust's type system is the fix he named too.

## Problem

Four specific gaps, compounding.

**Problem 1 — the validated pair is indistinguishable from the unvalidated pair.** After `read_user_buffer` returns `Ok(())`, the `(user_buf, len)` values that went in are still a pair of `u64`s; no type-level record exists that they were validated. A future function that takes `(u64, u64)` as user-pointer arguments will accept them whether they've been validated or not. The validation is local to the helper call; it does not propagate.

**Problem 2 — `(addr, len)` is not a unitary value.** Callers threading this pair across multiple functions can (today, accidentally tomorrow) pass a `len` from one context and an `addr` from another. The compiler cannot complain. This is the exact structural weakness Biffle flagged.

**Problem 3 — the handler and the helper don't share a lifetime.** The validation in `read_user_buffer` is a function of `(cr3, addr, len)`. If the handler held onto `addr` past the end of its invocation — stored it in a static, passed it to a worker thread — and read from it later, the page-walk that validated it at time T says nothing about readability at time T+N. Today no handler does this, but nothing structurally prevents it.

**Problem 4 — read and write direction is a runtime argument.** `read_user_buffer` and `write_user_buffer` are separate functions and today's handlers call the right one by convention. A generalized helper or a refactor that tries to unify them risks introducing an API shape where the direction is a runtime argument, one `if` away from reading where a write was intended.

**Why these compose.** Fix validation opacity (Problem 1) without unifying the pair (Problem 2) and a refactor can still split (addr, len) and confuse them. Fix both without lifetime binding (Problem 3) and a pointer can silently outlive its validity. Fix all three without direction typing (Problem 4) and a future helper breaks the guarantees the first three established. The four are one mechanism: **parse the user pointer once, at the syscall boundary; carry the parsed artifact through the handler; make misuse a compile error.**

## The Reframe

> **A user-pointer argument is not a pair of `u64`s. It is a `UserReadSlice<'ctx>` or `UserWriteSlice<'ctx>` — a type that carries the validated address, validated length, syscall-context borrow, and direction of use. It comes into existence via a `::validate()` constructor that can fail, and it is consumed by `.read_into()` or `.write_from()` operations that cannot fail for structural reasons.**

The validated facts the slice carries by construction:
- Address is in the canonical user-space range.
- Length is non-zero and within the per-syscall maximum.
- Address + length does not overflow or cross the user-space end.
- Caller's `cr3` is non-zero (kernel tasks can't meaningfully pass user pointers).

The facts it does *not* yet carry (and may never, per the validation-timing discussion below):
- Every page in the range is currently mapped in the caller's page table. That check happens at read/write time, per-page, in `copy_from_user_pages` / `copy_to_user_pages`.

## Decision

### 1. Two types, one lifetime

```rust
pub struct UserReadSlice<'ctx> {
    ctx: &'ctx SyscallContext,
    addr: u64,
    len: usize,
}

pub struct UserWriteSlice<'ctx> {
    ctx: &'ctx SyscallContext,
    addr: u64,
    len: usize,
}
```

The lifetime `'ctx` ties each slice to a specific `SyscallContext` borrow. Because `SyscallContext` is itself borrowed for the duration of one handler invocation, slices **cannot escape the syscall handler**. Attempting to store one in a static or return it to a caller that outlives the context is a compile error. This is the whole point.

Two types instead of one direction-enum because every current handler uses each pointer in exactly one direction. Splitting them costs ~30 lines of parallel impl and gives the verifier a cleaner proof surface: "UserWriteSlice cannot be read from" is a type-level fact, not a property to check.

### 2. Fallible construction, infallible use

```rust
impl<'ctx> UserReadSlice<'ctx> {
    /// Validate a user-pointer pair from syscall arguments.
    ///
    /// Checks: cr3 non-zero, len in (0, MAX_USER_BUFFER], address canonical,
    /// address + length does not overflow or cross USER_SPACE_END.
    ///
    /// Does not page-walk. Read operations page-walk per page at read time.
    pub fn validate(
        ctx: &'ctx SyscallContext,
        addr: u64,
        len: usize,
    ) -> Result<Self, SyscallError>;

    pub fn len(&self) -> usize;

    /// Copy the user buffer into `dst`. `dst.len()` must equal `self.len()`.
    /// Can still fail at read time if a page in the range is unmapped.
    pub fn read_into(&self, dst: &mut [u8]) -> Result<(), SyscallError>;
}

impl<'ctx> UserWriteSlice<'ctx> {
    pub fn validate(
        ctx: &'ctx SyscallContext,
        addr: u64,
        len: usize,
    ) -> Result<Self, SyscallError>;

    pub fn len(&self) -> usize;

    /// Copy `src` into the user buffer. `src.len()` must equal `self.len()`.
    /// Can still fail at write time if a page in the range is unmapped.
    pub fn write_from(&self, src: &[u8]) -> Result<(), SyscallError>;
}
```

`validate` is the only constructor. `read_into` / `write_from` are the only use operations. There is no escape hatch that produces a `UserReadSlice` without the validation.

### 3. `read_user_buffer` / `write_user_buffer` become thin adapters

The existing helpers stay as the internals, taking a `&SyscallContext` plus `(addr, len)` the old way, because they implement the per-page copy logic that `read_into` / `write_from` delegate to. The public API callers see is the slice type. In migration phase 020.C these helpers are made pub(crate) or fully hidden; the handler surface becomes slice-only.

### 4. Scope inventory — every user-pointer argument

Read sites become `UserReadSlice::validate(...)?`:

- `handle_write` (arg2/arg3 payload)
- `handle_print` (arg1/arg2 text)
- `handle_bind_principal` (arg2/arg3 pubkey)
- `handle_obj_put` (arg1/arg2 content)
- `handle_obj_get` (arg1/arg2 hash)
- `handle_obj_put_signed` (arg1/arg2 content, arg3/arg4 signature)
- `handle_spawn` (arg1/arg2 module name)
- `handle_channel_create` (arg2/arg3 peer principal)

Write sites become `UserWriteSlice::validate(...)?`:

- `handle_read` (arg2/arg3 output buffer)
- `handle_get_principal` (arg1/arg2 output buffer)
- `handle_recv_msg`, `handle_try_recv_msg` (arg2/arg3 output buffer with header+payload)
- `handle_obj_list` (arg1/arg2 output buffer)
- `handle_claim_bootstrap_key` (arg3/arg4 secret-key output)
- `handle_channel_create` (arg4/sizeof\<u64\> output vaddr)
- `handle_channel_info` (arg2/arg3 metadata output)
- `handle_alloc_dma` (arg3/sizeof\<u64\> output paddr)
- `handle_console_read` (arg1/arg2 output buffer)
- `handle_map_mmio` (output vaddr pointer — retrofit when the handler's output-pointer shape is used)
- `handle_wait_task` (output `ExitInfo` buffer — ADR-019 lands with this shape directly)

Bidirectional (both a read-slice and a write-slice):

- `handle_obj_get` (read hash in, write content out)
- Any future handler with a request+reply pair.

### 5. Error surface

Validation failures return the existing `SyscallError::InvalidArg`. A new variant is tempting for audit precision ("user pointer invalid" distinct from "length out of range") but not required for this ADR — the audit event could add a flag byte later if needed. Keeping the existing error avoids cascading ABI changes through libsys and every user service.

## Architecture

### Lifetime and borrow shape

`SyscallContext` is passed to every handler as `ctx: &SyscallContext` (by reference; see [src/syscalls/dispatcher.rs](../../src/syscalls/dispatcher.rs) for the type definition). `UserReadSlice<'ctx>` holds `&'ctx SyscallContext`, so the borrow checker enforces:

1. A slice cannot outlive its context (compile error if stashed in a static, returned from the handler, etc.).
2. The slice carries the context internally; callers of `read_into` / `write_from` don't re-pass `ctx`, making the call sites shorter than today's `read_user_buffer(ctx.cr3, addr, len, &mut kbuf)`.
3. The slice is `Copy` or `Clone` only where semantically safe. Default: neither. A slice is consumed once by `read_into` / `write_from`; wanting two reads is a rare need that can be added explicitly if it ever arises.

### Validation timing (decided: lazy page-walk)

Construction-time validation does the cheap checks (bounds, canonical range, overflow). Page-walk happens at use time, inside `copy_from_user_pages` / `copy_to_user_pages`, per page. This matches today's behavior in `read_user_buffer` / `write_user_buffer`.

**The expensive option — full page-walk at construction — is deliberately deferred.** See Open Problems for the observable triggers that would justify switching.

### Bidirectional pointers

A handler that needs both a read-slice and a write-slice constructs both independently. There is no `UserReadWriteSlice`. Rationale: every current bidirectional case uses two separate user pointers (`SYS_OBJ_GET` reads hash from one pointer, writes content to another), so they are structurally two slices. The case where a single user buffer is both read and then written by the kernel does not exist in today's syscalls and is not in the v1 roadmap.

### Test coverage migration

The existing tests on `read_user_buffer` / `write_user_buffer` edge cases (zero length, length > max, cr3 == 0, address at user-space end, overflow, page-boundary crossing) transplant directly onto `UserReadSlice::validate` / `UserWriteSlice::validate`. New tests added: lifetime tests (compile-fail tests that a slice cannot outlive its context), direction tests (compile-fail that `UserWriteSlice::read_into` does not exist).

## Threat Model Impact

| Threat | Today | With UserSlice |
|---|---|---|
| Refactor shuffles a call site, accidentally bypassing validation | Possible — `(user_buf, len)` is just `(u64, u64)` | Impossible — handler cannot produce a `UserReadSlice` without calling `::validate` |
| Function accidentally receives `(len, addr)` instead of `(addr, len)` | Possible — argument order is a runtime fact | Impossible — the pair is a single typed value |
| Kernel reads from a user pointer it meant to write to | Possible — separate functions by convention | Impossible — `UserWriteSlice` has no read method |
| Validated pointer is stashed in a static and used after the syscall returns | Possible — the `u64` has no lifetime | Impossible — `'ctx` lifetime binds to the handler |
| Validation succeeds but page is unmapped by the time of read | Possible (TOCTOU) but no exploitation path under current single-CPU-per-process model | Same — this ADR does not change TOCTOU exposure; deferred with explicit trigger |

Kernel TCB does not grow. Two struct types plus two impls. No dynamic dispatch, no new `unsafe` (the existing unsafe in the copy helpers remains unchanged), no lock hierarchy change, no new syscall. The validation logic already exists; the ADR re-homes it into a type.

## Verification Stance

- `UserReadSlice` / `UserWriteSlice` are `#[repr(C)]` structs with plain fields; layout is deterministic.
- `validate` is a single function with a bounded sequence of branch checks. Exhaustive matching on error paths; no default fallthrough.
- `read_into` / `write_from` delegate to `copy_from_user_pages` / `copy_to_user_pages`, which already have bounded page-walk loops (bound = `len / PAGE_SIZE + 1`, statically computable from the validated length).
- Lifetime parameter is a type-system proof of the "slice does not outlive context" invariant. No runtime check, no assertion, no documentation convention — the compiler enforces it.
- Two types for two directions is a type-system proof that direction cannot be confused at use.

The verification target this shape unlocks: a Hoare-triple proof of the form `{valid_syscall_ctx(ctx) ∧ valid_slice(s)} s.read_into(dst) {dst contains user bytes OR err}`. The current pair-of-u64 shape cannot support this proof because there is no `valid_slice` predicate to attach to.

## Why Not Other Options

### Option A: Single `UserSlice<DIR>` with a const-generic direction flag

**Why considered.** One struct, two type aliases (`type UserReadSlice<'c> = UserSlice<'c, { Read }>;`), DRY impl.

**Why not.** Const-generic enum discriminants have awkward ergonomics in stable Rust and force the impl to be split by direction anyway (you can't write `read_into` on `UserSlice<{ Write }>`). The syntactic DRY is paid for with proof-surface complexity. Two plain structs are easier for human readers, rust-analyzer, and future verifiers.

### Option B: One `UserSlice` with a runtime direction tag

**Why considered.** Maximum flexibility.

**Why not.** Exactly the problem Biffle named: direction becomes a runtime fact, one `if` away from misuse. This is the option the ADR explicitly moves away from.

### Option C: Newtype the `(addr, len)` pair without a lifetime

**Why considered.** Smaller change. Catches the "unitary value" weakness (Problem 2) without the ergonomic cost of a `'ctx` parameter everywhere.

**Why not.** Leaves Problem 3 (lifetime binding) un-addressed. A validated slice could still be stashed and used after the syscall returns. The lifetime parameter is load-bearing, not cosmetic.

### Option D: Full kernel-wide `VirtAddr` / `PhysAddr` newtype pass rolled in

**Why considered.** Solve both classes of pointer weakness at once.

**Why not.** Different bug class (phys/virt mix-ups inside the kernel) with a different blast radius (hundreds of sites). Bundling invites bikeshedding on the type hierarchy and makes the ADR reviewable only as a massive single commit. Deferred with a trigger in Open Problems.

### Option E: Validate at construction including full page-walk (D2 in session shorthand)

**Why considered.** Turns the slice into a provably-readable handle; eliminates TOCTOU between validate and read.

**Why not.** Costs a page-walk on every syscall even when a handler might not reach its read (e.g., fails a prior check), and TOCTOU isn't exploitable under the current single-CPU-per-process execution model. Revisit when the trigger conditions fire (Open Problems).

## Migration Path / Phased Plan

**Phase 020.A — Land the types as adapters over the existing helpers.** Add `UserReadSlice` and `UserWriteSlice` in [src/syscalls/dispatcher.rs](../../src/syscalls/dispatcher.rs) (or a new `user_slice.rs` module). Their `validate` / `read_into` / `write_from` call through to the existing `read_user_buffer` / `write_user_buffer`. No handlers change. Tri-arch green. One commit.

**Phase 020.B — Migrate handlers in subsystem-sized groups.** Each commit migrates one logical group: IPC (`write`, `read`, `recv_msg`, `try_recv_msg`), ObjectStore (`obj_put`, `obj_get`, `obj_list`, `obj_put_signed`), identity (`bind_principal`, `get_principal`, `claim_bootstrap_key`), boot/lifecycle (`spawn`, `print`, `console_read`), channel/MMIO/DMA (`channel_create`, `channel_info`, `alloc_dma`, `map_mmio`). Each commit deletes its raw `(u64, usize)` argument passes through the handler body. Tri-arch green at each commit boundary.

**Phase 020.C — Make the compatibility shims internal.** `read_user_buffer` and `write_user_buffer` become `pub(crate)` (or private). Raw `u64` user pointers cannot cross into the handler-facing API. The type system is the enforcement.

**Phase 020.D — Compile-fail tests.** *Deferred — see Open Problems.* The belt-and-suspenders pass (`#[compile_fail]` tests asserting lifetime + direction invariants via trybuild or doc-test) would prove that the type system *continues* to enforce the ADR-020 guarantees across future refactors. The type system enforces them *today* as a consequence of Phase C landing — Phase D is meta-protection, not primary protection, so it can wait.

Each phase is independently revertable and lands on its own; 020.B can span many commits over weeks if needed without blocking other work.

## Open Problems (deferred)

### Full-page-walk validation at construction

Discussed above as Option E. **Revisit when:** either (a) SMP-per-process concurrency lands (threads within a process, or intra-process migration during a syscall) making TOCTOU exploitable, OR (b) formal-verification tooling lands that demands construction-time readability preconditions for a Hoare-style proof. Both are observable: (a) is a scheduler ADR; (b) is the first verification commit that hits a "needs a provably-readable precondition" wall.

### Kernel-wide typed addresses (`VirtAddr` / `PhysAddr` / `UserVirtAddr` / `KernelVirtAddr`)

Discussed above as Option D. Different bug class (phys/virt arithmetic confusion inside the kernel) with hundreds of sites to retrofit. **Revisit when:** either (a) the first phys/virt mix-up bug that would have been caught by types, OR (b) formal-verification tooling reaches a point where arithmetic on typed addresses becomes a precondition for proofs about memory safety. Both are observable; (a) via incident, (b) via the verification roadmap. No ADR number pre-registered — draft when the trigger fires.

### Unifying with `ExitInfo` output buffer (ADR-019)

[ADR-019](019-process-fault-reaping-and-peer-generation.md) introduces an `ExitInfo` struct that `SYS_WAIT_TASK` writes into a caller-provided buffer. The clean landing sequence is: ADR-020 Phase A lands the types, then ADR-019's implementation uses `UserWriteSlice` for the `ExitInfo` output pointer from day one, so we never have a fresh handler site using raw `u64`. **Revisit when:** ADR-019 implementation starts — whichever ADR implements second inherits the types from whichever lands first.

### Phase D compile-fail tests (deferred, not dropped)

Phases A–C leave the type system as the sole enforcement mechanism: `UserReadSlice<'ctx>` cannot outlive its borrow; `UserWriteSlice` has no `read_into` method; raw `u64` doesn't match `::validate`'s signature. A refactor that silently weakens any of these would compile clean without a compile-fail test catching it. That's a real but modest risk today, judged lower than the infrastructure cost of the test harness (trybuild dev-dependency + per-test `.stderr` fixtures, or fragile no_std doc-test coverage).

**Revisit when:** any of (a) a refactor lands that removes or weakens the `'ctx` lifetime parameter on either slice type, (b) a future `UserSlice` variant with runtime-determined direction is proposed, (c) CLAUDE.md's broader discipline grows a trybuild-based compile-fail test harness for other invariants (at which point marginal cost to add UserSlice coverage drops to near zero). All three are observable in code review or ADR traffic.

### `from_user_struct<T>(slice)` / `to_user_struct<T>(slice)` generic helpers

Many handlers read or write a fixed-size struct (e.g., `ExitInfo`, `ChannelInfo`, `FramebufferDescriptor`). Today these are all byte buffers of known length. A generic helper `UserWriteSlice::write_struct::<T>(&T)` that asserts `slice.len() == size_of::<T>()` and `transmute_copy`s the bytes would be type-safer than manual `write_from(as_bytes(&t))`. **Revisit when:** the third identical copy of "byte-encode this struct then write_from" appears — the rule-of-three says the abstraction is earning its keep. Two copies today: `ExitInfo` (once ADR-019 lands), `ChannelInfo`, `FramebufferDescriptor`. Close to the trigger.
