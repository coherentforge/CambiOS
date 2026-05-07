# Adding a New Syscall — Worked Example

Seven places must change atomically. Canonical reference: `TryRecvMsg = 37` landing. Skipping any step produces a specific failure mode named below.

This walkthrough used to live in CLAUDE.md but was moved to `docs/dev-notes/` because it's only relevant when adding a syscall — a rare event that didn't justify loading 66 lines into context on every turn. The Required Reading table in CLAUDE.md points here from the syscall-related rows.

---

**(1) Declare the variant** — [src/syscalls/mod.rs](../../src/syscalls/mod.rs), in the `SyscallNumber` enum.
```rust
/// SYS_TRY_RECV_MSG (37): non-blocking variant of RecvMsg. Returns 0
/// immediately if no message is queued, instead of parking the task
/// on `MessageWait(endpoint)`. …
TryRecvMsg = 37,
```
*Skipping:* userspace hits `SyscallError::Enosys` because `from_u64` doesn't know the number.

**(2) Classify identity requirement** — same file, `requires_identity()` match.
```rust
Self::Write | Self::Read | Self::RecvMsg | Self::TryRecvMsg |
```
*Skipping:* if the new syscall touches identity-bearing state and you forget this arm, unidentified processes can call it. The `identity_required_syscalls_are_gated` test below fails — that is the safety net. **Do not silence the test by adding the syscall to the `EXEMPT` set unless the syscall genuinely needs no identity** (check the small exempt list for precedent).

**(3) Wire `from_u64`** — same file.
```rust
37 => Some(Self::TryRecvMsg),
```
*Skipping:* runtime dispatch returns `None`, the kernel returns `Enosys`, the syscall appears un-implemented.

**(4) Update test coverage** — same file, `#[cfg(test)] mod tests`.
```rust
// Add to the `all` array in identity_required_syscalls_are_gated:
SyscallNumber::TryRecvMsg,

// Extend the range in all_syscall_numbers_covered:
for i in 0..=37u64 { … }
```
*Skipping:* the new variant isn't exercised by `all_syscall_numbers_covered` (test passes vacuously) and isn't checked against the exempt set (test passes because the check iterates `all`, not the enum). Both tests are *cooperative* — they only catch omissions when you also maintain the arrays. This is by design; treat it as a prompt to think about coverage.

**(5) Dispatch the call** — [src/syscalls/dispatcher.rs](../../src/syscalls/dispatcher.rs), in `handle_syscall`'s dispatch match.
```rust
SyscallNumber::TryRecvMsg => Self::handle_try_recv_msg(args, &ctx),
```
*Skipping:* compile error (match non-exhaustive). This is the one step the compiler catches for free.

**(6) Implement the handler** — same file.
```rust
fn handle_try_recv_msg(args: SyscallArgs, ctx: &SyscallContext) -> SyscallResult {
    let endpoint_id = args.arg1_u32();
    let user_buf = args.arg2;
    let buf_len = args.arg_usize(3);
    // … capability check → IPC recv → page-walk to user buffer …
}
```
*Skipping:* compile error at step (5). Paired with it.

**(7) Expose the userspace wrapper** — [user/libsys/src/lib.rs](../../user/libsys/src/lib.rs). Add the `SYS_*` constant alongside the others, then the safe wrapper.
```rust
const SYS_TRY_RECV_MSG: u64 = 37;

pub fn try_recv_msg(endpoint: u32, buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_TRY_RECV_MSG, endpoint as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
}
```
*Skipping:* userspace services can't call the syscall without raw `asm!`. The kernel side works; every consumer is broken until libsys catches up.

**Verification:** `cargo test --lib` + `make check-all`. **Flow-specific stop-and-ask:** syscall in exempt set? (default: no). New capability-check kind? (unread-subsystem gate on `src/ipc/capability.rs`). New arch backend helper? (all three arches).
