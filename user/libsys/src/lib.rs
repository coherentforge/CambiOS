// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS user-space syscall library
//!
//! Safe wrappers around architecture-specific syscall instructions. This is
//! the ONLY crate in user-space that contains `unsafe` code. All other
//! user-space crates should use `#![forbid(unsafe_code)]` and call these
//! safe functions.
//!
//! ## Architecture conventions
//!
//! | Arch    | Instruction | Syscall # | Args       | Return |
//! |---------|-------------|-----------|------------|--------|
//! | x86_64  | `syscall`   | RAX       | RDI..R9    | RAX    |
//! | AArch64 | `svc #0`    | x8        | x0..x5     | x0     |
//! | RISC-V  | `ecall`     | a7 (x17)  | a0..a5     | a0     |

#![no_std]

// Syscall numbers (must match kernel src/syscalls/mod.rs)
const SYS_EXIT: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_REGISTER_ENDPOINT: u64 = 6;
const SYS_YIELD: u64 = 7;
const SYS_GET_PID: u64 = 8;
const SYS_PRINT: u64 = 10;
const SYS_RECV_MSG: u64 = 13;
const SYS_OBJ_PUT: u64 = 14;
const SYS_OBJ_GET: u64 = 15;
const SYS_OBJ_DELETE: u64 = 16;
const SYS_OBJ_LIST: u64 = 17;
const SYS_CLAIM_BOOTSTRAP_KEY: u64 = 18;
const SYS_OBJ_PUT_SIGNED: u64 = 19;

// ============================================================================
// Raw syscall primitives — the ONLY unsafe code in user-space
// ============================================================================

// ----------------------------------------------------------------------------
// x86_64: SYSCALL instruction
// ----------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn syscall_raw3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: Invokes the kernel syscall handler via the SYSCALL instruction.
    // The kernel validates all arguments.
    //
    // Clobbers: The CPU clobbers RCX (saved RIP) and R11 (saved RFLAGS).
    // The kernel syscall stub does NOT restore RDI, RSI, RDX, R8, R9, R10
    // (they are caller-saved in the SysV ABI and discarded when the
    // SyscallFrame is cleaned up with `add rsp, 56`).
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            inlateout("rdi") arg1 => _,
            inlateout("rsi") arg2 => _,
            inlateout("rdx") arg3 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn syscall_raw4(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    // SAFETY: Same as syscall_raw3. Arg4 goes in R10, not RCX — the SYSCALL
    // instruction unconditionally writes saved RIP into RCX, destroying
    // whatever we put there. The kernel's SyscallFrame reads R10 for arg4
    // (see src/arch/x86_64/syscall.rs).
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            inlateout("rdi") arg1 => _,
            inlateout("rsi") arg2 => _,
            inlateout("rdx") arg3 => _,
            inlateout("r10") arg4 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ----------------------------------------------------------------------------
// AArch64: SVC #0 instruction
// ----------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn syscall_raw3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: Invokes the kernel SVC handler via `svc #0`.
    // The kernel validates all arguments.
    //
    // AArch64 convention: x8 = syscall number, x0-x5 = args, x0 = return.
    // The SVC exception saves/restores all registers via the exception
    // vector stub (sync_el0_stub), so only x0 is modified on return
    // (the stub writes the return value into the saved x0 slot).
    //
    // Clobbers: x0 (return value). x1-x7 and x8 are restored by the kernel's
    // exception return path, but we mark them clobbered defensively since
    // the kernel could change its ABI without breaking us.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x0") arg1 as i64 => ret,
            inlateout("x1") arg2 => _,
            inlateout("x2") arg3 => _,
            inlateout("x8") num => _,
            // x3-x7 not used but may be clobbered by future kernel changes
            lateout("x3") _,
            lateout("x4") _,
            lateout("x5") _,
            lateout("x6") _,
            lateout("x7") _,
            // x9-x15 are caller-saved (corruptible) in AAPCS64
            lateout("x9") _,
            lateout("x10") _,
            lateout("x11") _,
            lateout("x12") _,
            lateout("x13") _,
            lateout("x14") _,
            lateout("x15") _,
            // x16-x17 are intra-procedure-call scratch
            lateout("x16") _,
            lateout("x17") _,
            // x18 is platform register (caller-saved)
            lateout("x18") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn syscall_raw4(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    // SAFETY: Same as syscall_raw3. x3 carries the 4th argument.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x0") arg1 as i64 => ret,
            inlateout("x1") arg2 => _,
            inlateout("x2") arg3 => _,
            inlateout("x3") arg4 => _,
            inlateout("x8") num => _,
            lateout("x4") _,
            lateout("x5") _,
            lateout("x6") _,
            lateout("x7") _,
            lateout("x9") _,
            lateout("x10") _,
            lateout("x11") _,
            lateout("x12") _,
            lateout("x13") _,
            lateout("x14") _,
            lateout("x15") _,
            lateout("x16") _,
            lateout("x17") _,
            lateout("x18") _,
            options(nostack),
        );
    }
    ret
}

// ----------------------------------------------------------------------------
// RISC-V (riscv64gc): ECALL instruction
// ----------------------------------------------------------------------------

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn syscall_raw3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: Invokes the kernel ecall handler. The kernel's trap vector
    // saves the full SavedContext; `ecall_handler_inner` extracts a7 + a0..a5,
    // dispatches, writes the return value into the saved a0 slot, and bumps
    // sepc by 4. On sret, every register *other than* a0 is restored from
    // the saved frame — but we mark a0-a7 + t0-t6 clobbered defensively so
    // a future kernel ABI change (scratch use, signal delivery) can't
    // silently corrupt caller state.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg1 as i64 => ret,
            inlateout("a1") arg2 => _,
            inlateout("a2") arg3 => _,
            inlateout("a7") num => _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
            lateout("a6") _,
            lateout("t0") _,
            lateout("t1") _,
            lateout("t2") _,
            lateout("t3") _,
            lateout("t4") _,
            lateout("t5") _,
            lateout("t6") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn syscall_raw4(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    // SAFETY: Same as syscall_raw3. a3 carries the 4th argument.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg1 as i64 => ret,
            inlateout("a1") arg2 => _,
            inlateout("a2") arg3 => _,
            inlateout("a3") arg4 => _,
            inlateout("a7") num => _,
            lateout("a4") _,
            lateout("a5") _,
            lateout("a6") _,
            lateout("t0") _,
            lateout("t1") _,
            lateout("t2") _,
            lateout("t3") _,
            lateout("t4") _,
            lateout("t5") _,
            lateout("t6") _,
            options(nostack),
        );
    }
    ret
}

// ============================================================================
// Safe public API
// ============================================================================

pub fn exit(code: u32) -> ! {
    syscall_raw3(SYS_EXIT, code as u64, 0, 0);
    loop {}
}

pub fn print(msg: &[u8]) {
    syscall_raw3(SYS_PRINT, msg.as_ptr() as u64, msg.len() as u64, 0);
}

/// Log an error message. Currently prints to the kernel console.
///
/// Future: will also emit an audit event (kernel audit ring) so a log
/// viewer can surface errors without them stepping on the user's display.
/// Services should prefer this over `print` for error conditions — it
/// gives us a single hook to evolve into "silent success, visible failure".
pub fn log_error(tag: &[u8], msg: &[u8]) {
    // Assemble a single [TAG] ERROR: msg line to keep output contiguous.
    let mut buf = [0u8; 256];
    let mut n = 0;
    let push = |buf: &mut [u8], n: &mut usize, bytes: &[u8]| {
        let space = buf.len().saturating_sub(*n);
        let take = core::cmp::min(space, bytes.len());
        buf[*n..*n + take].copy_from_slice(&bytes[..take]);
        *n += take;
    };
    push(&mut buf, &mut n, b"[");
    push(&mut buf, &mut n, tag);
    push(&mut buf, &mut n, b"] ERROR: ");
    push(&mut buf, &mut n, msg);
    if n < buf.len() {
        buf[n] = b'\n';
        n += 1;
    }
    print(&buf[..n]);
}

pub fn register_endpoint(endpoint_id: u32) -> i64 {
    syscall_raw3(SYS_REGISTER_ENDPOINT, endpoint_id as u64, 0, 0)
}

const SYS_MODULE_READY: u64 = 36;

/// Signal to the kernel that this boot module has finished initialization
/// and is about to enter its service loop.
///
/// The kernel's sequential boot-release chain: modules 1..N of the
/// `limine.conf` roster start `Blocked` on `BootGate`. Each module's
/// `module_ready()` call advances the cursor and wakes the next module,
/// guaranteeing deterministic boot ordering — each service's
/// "[X] ready on endpoint N\n" print appears in strict limine.conf
/// order, and the shell's `arcos>` prompt arrives only after everything
/// it depends on is up.
///
/// Identity-exempt (does not require a bound Principal). Safe to call
/// before the key-store / signing infrastructure is reachable.
///
/// Always returns 0. Idempotent at the kernel side: a second call from
/// the same module, or a call from a late-loaded module, is a no-op.
pub fn module_ready() {
    syscall_raw3(SYS_MODULE_READY, 0, 0, 0);
}

pub fn yield_now() {
    syscall_raw3(SYS_YIELD, 0, 0, 0);
}

pub fn get_pid() -> u32 {
    syscall_raw3(SYS_GET_PID, 0, 0, 0) as u32
}

const SYS_GET_PRINCIPAL: u64 = 12;

/// Read this process's bound Principal (32-byte Ed25519 public key).
/// Returns 32 on success (caller buffer must be ≥32 bytes), or negative
/// error. Unbound processes (no `BindPrincipal` at boot) see
/// `Principal::ANONYMOUS` — 32 zero bytes.
pub fn get_principal(out: &mut [u8; 32]) -> i64 {
    syscall_raw3(SYS_GET_PRINCIPAL, out.as_mut_ptr() as u64, 32, 0)
}

/// Send IPC message (Write syscall).
pub fn write(endpoint: u32, buf: &[u8]) -> i64 {
    syscall_raw3(SYS_WRITE, endpoint as u64, buf.as_ptr() as u64, buf.len() as u64)
}

/// Receive IPC message with sender identity (blocking).
/// Returns total bytes in buf (≥36) on success, or negative error.
/// Blocks on `MessageWait(endpoint)` when no message is queued.
/// buf layout: [sender_principal:32][from_endpoint:4][payload:N]
pub fn recv_msg(endpoint: u32, buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_RECV_MSG, endpoint as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
}

const SYS_TRY_RECV_MSG: u64 = 37;

/// Non-blocking variant of `recv_msg`. Returns bytes received (≥36) or 0
/// if no message is queued — never blocks. Required for services that
/// poll multiple endpoints (e.g., a driver listening on both a user-facing
/// endpoint and a kernel-command endpoint): blocking `recv_msg` on one
/// endpoint would miss wakes on the other.
pub fn try_recv_msg(endpoint: u32, buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_TRY_RECV_MSG, endpoint as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// Store object. Writes 32-byte hash to out_hash. Returns 0 or negative error.
pub fn obj_put(content: &[u8], out_hash: &mut [u8; 32]) -> i64 {
    syscall_raw3(SYS_OBJ_PUT, content.as_ptr() as u64, content.len() as u64, out_hash.as_mut_ptr() as u64)
}

/// Get object content by hash. Returns bytes read or negative error.
pub fn obj_get(hash: &[u8; 32], out_buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_OBJ_GET, hash.as_ptr() as u64, out_buf.as_mut_ptr() as u64, out_buf.len() as u64)
}

/// Delete object by hash. Returns 0 or negative error.
pub fn obj_delete(hash: &[u8; 32]) -> i64 {
    syscall_raw3(SYS_OBJ_DELETE, hash.as_ptr() as u64, 0, 0)
}

/// List object hashes. Returns count of objects.
pub fn obj_list(out_buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_OBJ_LIST, out_buf.as_mut_ptr() as u64, out_buf.len() as u64, 0)
}

/// Store a pre-signed object. Kernel verifies the signature.
pub fn obj_put_signed(content: &[u8], sig: &[u8; 64], out_hash: &mut [u8; 32]) -> i64 {
    syscall_raw4(
        SYS_OBJ_PUT_SIGNED,
        content.as_ptr() as u64,
        content.len() as u64,
        sig.as_ptr() as u64,
        out_hash.as_mut_ptr() as u64,
    )
}

/// Claim the bootstrap secret key from the kernel (one-shot).
/// Returns 64 on success, negative error on failure.
pub fn claim_bootstrap_key(out_sk: &mut [u8; 64]) -> i64 {
    syscall_raw3(SYS_CLAIM_BOOTSTRAP_KEY, out_sk.as_mut_ptr() as u64, 0, 0)
}

// ============================================================================
// Identity types — the userspace half of "no ID, no participation"
// ============================================================================

/// A 32-byte Ed25519 public key representing a process identity.
/// The zero value is invalid (anonymous / unidentified).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Principal([u8; 32]);

impl Principal {
    /// The zero Principal — sentinel for "no identity."
    pub const ANONYMOUS: Self = Self([0u8; 32]);

    /// Returns `true` if this is the zero (anonymous) Principal.
    pub fn is_anonymous(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// The raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct a Principal from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Format this Principal as a `did:key:z6Mk…` string.
    ///
    /// The returned `DidKey` owns a fixed-size buffer; call `.as_str()` or
    /// `.as_bytes()` to read it.
    pub fn to_did_key(&self) -> DidKey {
        did_key_encode(&self.0)
    }

    /// Parse a `did:key:z6Mk…` string into a Principal. Returns `None` if the
    /// input is not a valid Ed25519 did:key.
    pub fn from_did_key(input: &[u8]) -> Option<Self> {
        did_key_decode(input).map(Self)
    }
}

// ============================================================================
// did:key encoding (W3C did:key v0.7 — Ed25519 multikey)
// ============================================================================
//
// Wire format:
//   "did:key:" + "z" + base58btc([0xed, 0x01] || pubkey_bytes)
//
// - "z" is the multibase identifier for base58btc.
// - [0xed, 0x01] is the unsigned varint encoding of multicodec 0xed (Ed25519
//   public key).
// - For a 32-byte Ed25519 pubkey the full string is 56 characters; the
//   `DidKey` struct reserves 64 bytes to cover any valid encoding without
//   dynamic allocation.
//
// This is the userspace half of Phase 4 from identity.md, pulled forward so
// CambiOS Principals are expressible in the DID/SSI community's vocabulary.

const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];
const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DID_KEY_PREFIX: &[u8] = b"did:key:z";

/// A rendered did:key string (owns its buffer; no allocation).
#[derive(Clone, Copy)]
pub struct DidKey {
    buf: [u8; 64],
    len: u8,
}

impl DidKey {
    /// The rendered string as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// The rendered string as `&str`. base58btc output is pure ASCII so this
    /// never fails, but we return an `Option` to stay panic-free.
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
}

/// Encode a 32-byte Ed25519 public key as a `did:key:z6Mk…` string.
pub fn did_key_encode(pubkey: &[u8; 32]) -> DidKey {
    let mut prefixed = [0u8; 34];
    prefixed[0] = MULTICODEC_ED25519_PUB[0];
    prefixed[1] = MULTICODEC_ED25519_PUB[1];
    prefixed[2..].copy_from_slice(pubkey);

    let mut out = DidKey { buf: [0u8; 64], len: 0 };
    out.buf[..DID_KEY_PREFIX.len()].copy_from_slice(DID_KEY_PREFIX);
    let mut cursor = DID_KEY_PREFIX.len();

    let written = base58btc_encode(&prefixed, &mut out.buf[cursor..]);
    cursor += written;
    out.len = cursor as u8;
    out
}

/// Decode a `did:key:z6Mk…` string into a 32-byte Ed25519 public key.
/// Returns `None` if the string has the wrong prefix, invalid base58btc
/// characters, or a multicodec prefix other than Ed25519.
pub fn did_key_decode(input: &[u8]) -> Option<[u8; 32]> {
    if input.len() < DID_KEY_PREFIX.len() {
        return None;
    }
    if &input[..DID_KEY_PREFIX.len()] != DID_KEY_PREFIX {
        return None;
    }
    let body = &input[DID_KEY_PREFIX.len()..];

    let mut decoded = [0u8; 64];
    let n = base58btc_decode(body, &mut decoded)?;
    // Expect exactly 34 bytes: 2 multicodec + 32 pubkey
    if n != 34 {
        return None;
    }
    if decoded[0] != MULTICODEC_ED25519_PUB[0] || decoded[1] != MULTICODEC_ED25519_PUB[1] {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[2..34]);
    Some(out)
}

/// base58btc encode. Big-endian input is divided by 58 repeatedly; remainders
/// become output characters (least-significant first, then reversed). Leading
/// zero bytes in input map to leading `'1'` characters in output.
///
/// Returns the number of bytes written. `output` must have capacity for at
/// least `input.len() * 138 / 100 + 1` bytes (ceil of log_58(256) * len).
fn base58btc_encode(input: &[u8], output: &mut [u8]) -> usize {
    let leading_zeros = input.iter().take_while(|&&b| b == 0).count();

    let mut work = [0u8; 64];
    let work_len = input.len();
    debug_assert!(work_len <= work.len(), "base58btc_encode: input too large");
    work[..work_len].copy_from_slice(input);

    let mut out_rev = [0u8; 96];
    let mut out_rev_len = 0;

    loop {
        // Is work all zero?
        let mut all_zero = true;
        for i in 0..work_len {
            if work[i] != 0 {
                all_zero = false;
                break;
            }
        }
        if all_zero {
            break;
        }

        // Long-divide work (big-endian) by 58.
        let mut carry: u32 = 0;
        for i in 0..work_len {
            let cur = carry * 256 + work[i] as u32;
            work[i] = (cur / 58) as u8;
            carry = cur % 58;
        }
        out_rev[out_rev_len] = BASE58_ALPHABET[carry as usize];
        out_rev_len += 1;
    }

    // Emit leading '1's for input leading zeros.
    for _ in 0..leading_zeros {
        out_rev[out_rev_len] = b'1';
        out_rev_len += 1;
    }

    // Reverse into caller's buffer.
    let out_len = core::cmp::min(out_rev_len, output.len());
    for i in 0..out_len {
        output[i] = out_rev[out_rev_len - 1 - i];
    }
    out_len
}

/// base58btc decode. Returns the number of bytes written to `output`, or
/// `None` on any character outside the base58btc alphabet.
fn base58btc_decode(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let leading_ones = input.iter().take_while(|&&b| b == b'1').count();

    let mut work = [0u8; 64];
    let mut work_len = 0;

    for &ch in input.iter().skip(leading_ones) {
        let digit = base58_char_value(ch)?;
        // Multiply `work` by 58 and add `digit`.
        let mut carry: u32 = digit as u32;
        for i in (0..work_len).rev() {
            let cur = work[i] as u32 * 58 + carry;
            work[i] = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        // Prepend carry bytes if they overflow.
        while carry > 0 {
            if work_len >= work.len() {
                return None; // overflow guard
            }
            // Shift right by one to make room at the front.
            for i in (1..=work_len).rev() {
                work[i] = work[i - 1];
            }
            work[0] = (carry & 0xff) as u8;
            work_len += 1;
            carry >>= 8;
        }
    }

    let total = leading_ones + work_len;
    if total > output.len() {
        return None;
    }
    for i in 0..leading_ones {
        output[i] = 0;
    }
    for i in 0..work_len {
        output[leading_ones + i] = work[i];
    }
    Some(total)
}

fn base58_char_value(c: u8) -> Option<u8> {
    // Linear scan — alphabet is 58 chars, and this runs once per input char
    // (~47 for a typical did:key); no benefit from a lookup table in no_std.
    for (idx, &alpha) in BASE58_ALPHABET.iter().enumerate() {
        if alpha == c {
            return Some(idx as u8);
        }
    }
    None
}

#[cfg(test)]
mod did_key_tests {
    use super::*;

    #[test]
    fn ed25519_prefix_is_varint_0xed() {
        // Multicodec 0xed (Ed25519 pub key) as unsigned varint:
        //   0xed = 0b1110_1101 = 237
        //   low 7 bits: 0x6d ; with continuation bit: 0xed
        //   remainder: 237 >> 7 = 1, emitted as 0x01
        assert_eq!(MULTICODEC_ED25519_PUB, [0xed, 0x01]);
    }

    #[test]
    fn round_trip_zeros() {
        let pubkey = [0u8; 32];
        let rendered = did_key_encode(&pubkey);
        let decoded = did_key_decode(rendered.as_bytes()).expect("decode");
        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn round_trip_ones() {
        let pubkey = [0xffu8; 32];
        let rendered = did_key_encode(&pubkey);
        let decoded = did_key_decode(rendered.as_bytes()).expect("decode");
        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn round_trip_sequential() {
        let mut pubkey = [0u8; 32];
        for (i, b) in pubkey.iter_mut().enumerate() {
            *b = i as u8;
        }
        let rendered = did_key_encode(&pubkey);
        let decoded = did_key_decode(rendered.as_bytes()).expect("decode");
        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn output_starts_with_did_key_z6mk() {
        // Every Ed25519 did:key starts with "did:key:z6Mk" because the
        // multicodec prefix [0xed, 0x01] base58btc-encodes to a fixed
        // high-order prefix across all 32-byte payloads.
        let pubkey = [0x42u8; 32];
        let rendered = did_key_encode(&pubkey);
        let bytes = rendered.as_bytes();
        assert!(
            bytes.starts_with(b"did:key:z6Mk"),
            "expected did:key:z6Mk prefix, got {:?}",
            core::str::from_utf8(bytes).unwrap_or("<non-utf8>")
        );
    }

    #[test]
    fn output_length_is_56() {
        // 32-byte pubkey + 2-byte multicodec = 34 bytes.
        // base58btc(34 bytes) is 46 chars for most inputs, occasionally 47.
        // "did:key:" (8) + "z" (1) + body = 55 or 56 chars.
        let pubkey = [0x42u8; 32];
        let rendered = did_key_encode(&pubkey);
        let len = rendered.as_bytes().len();
        assert!(
            len == 55 || len == 56,
            "expected 55 or 56 bytes, got {}",
            len
        );
    }

    #[test]
    fn decode_rejects_wrong_prefix() {
        assert!(did_key_decode(b"did:web:example.com").is_none());
        assert!(did_key_decode(b"did:key:mBase64Stuff").is_none()); // not z
        assert!(did_key_decode(b"short").is_none());
        assert!(did_key_decode(b"").is_none());
    }

    #[test]
    fn decode_rejects_bad_base58_chars() {
        // '0', 'O', 'I', 'l' are outside the base58btc alphabet.
        assert!(did_key_decode(b"did:key:z0MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_none());
        assert!(did_key_decode(b"did:key:zOMkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_none());
    }

    #[test]
    fn decode_rejects_wrong_multicodec() {
        // Hand-craft a base58btc string whose decoded prefix is NOT
        // [0xed, 0x01] — start from a non-Ed25519 32-byte payload.
        // Use multicodec 0xe7 (secp256k1 pub key): varint = [0xe7, 0x01].
        let secp_prefix = [0xe7u8, 0x01];
        let payload = [0x42u8; 32];
        let mut prefixed = [0u8; 34];
        prefixed[0] = secp_prefix[0];
        prefixed[1] = secp_prefix[1];
        prefixed[2..].copy_from_slice(&payload);
        let mut b58 = [0u8; 64];
        let n = base58btc_encode(&prefixed, &mut b58);
        let mut input = [0u8; 128];
        input[..DID_KEY_PREFIX.len()].copy_from_slice(DID_KEY_PREFIX);
        input[DID_KEY_PREFIX.len()..DID_KEY_PREFIX.len() + n].copy_from_slice(&b58[..n]);
        let total = DID_KEY_PREFIX.len() + n;
        // Correct base58btc, correct multibase, WRONG multicodec.
        assert!(did_key_decode(&input[..total]).is_none());
    }

    #[test]
    fn principal_methods_round_trip() {
        let p = Principal::from_bytes([0xabu8; 32]);
        let rendered = p.to_did_key();
        let parsed = Principal::from_did_key(rendered.as_bytes()).expect("parse");
        // Principal doesn't derive Debug, so compare via as_bytes() rather
        // than assert_eq!.
        assert!(p == parsed);
        assert_eq!(p.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn rfc_8032_test1_pubkey_encodes_correctly() {
        // RFC 8032 §7.1 Test 1 Ed25519 public key. The expected did:key
        // output was cross-checked against an independent Python
        // bignum-division reference. If this test drifts, either the
        // encoder is buggy or someone changed the multicodec bytes.
        let pubkey: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
            0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        let expected = b"did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
        let rendered = did_key_encode(&pubkey);
        assert_eq!(rendered.as_bytes(), &expected[..]);
    }

    #[test]
    fn base58btc_classical_vectors() {
        // Canonical Bitcoin base58btc test vectors — if any of these fail,
        // the raw codec is wrong independent of did:key wrapping.
        let cases: &[(&[u8], &[u8])] = &[
            (&[0x00], b"1"),
            (&[0x61], b"2g"),
            (&[0x62, 0x62, 0x62], b"a3gV"),
            (&[0x63, 0x63, 0x63], b"aPEr"),
            (&[0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd], b"11233QC4"),
            (
                b"simply a long string" as &[u8],
                b"2cFupjhnEsSn59qHXstmK2ffpLv2",
            ),
        ];
        for (input, expected) in cases {
            let mut out = [0u8; 128];
            let n = base58btc_encode(input, &mut out);
            assert_eq!(
                &out[..n],
                *expected,
                "encode mismatch for {:?}: got {:?}, expected {:?}",
                input,
                core::str::from_utf8(&out[..n]).unwrap_or("<non-utf8>"),
                core::str::from_utf8(expected).unwrap_or("<non-utf8>"),
            );
            // Decode round-trip
            let mut back = [0u8; 128];
            let m = base58btc_decode(expected, &mut back).expect("decode");
            assert_eq!(
                &back[..m],
                *input,
                "decode mismatch for {:?}",
                core::str::from_utf8(expected).unwrap_or("<non-utf8>"),
            );
        }
    }

    #[test]
    fn base58btc_round_trip_random_like() {
        // Round-trip a handful of patterns through the raw codec.
        for seed in 0u8..16 {
            let mut input = [0u8; 34];
            for (i, b) in input.iter_mut().enumerate() {
                *b = seed.wrapping_mul(7).wrapping_add(i as u8);
            }
            let mut enc = [0u8; 64];
            let n = base58btc_encode(&input, &mut enc);
            let mut dec = [0u8; 64];
            let m = base58btc_decode(&enc[..n], &mut dec).expect("decode");
            assert_eq!(m, input.len(), "length mismatch for seed {}", seed);
            assert_eq!(&dec[..m], &input[..], "bytes mismatch for seed {}", seed);
        }
    }
}

/// An IPC message whose sender identity has been verified as non-anonymous.
///
/// This type **cannot** be constructed without a valid (non-zero) Principal.
/// If the kernel does not stamp principals on IPC messages (e.g., a stripped
/// fork), `recv_verified()` always returns `None` and the service is inert.
///
/// This is the userspace half of the "identity is load-bearing" invariant.
/// The kernel half is the identity gate in the syscall dispatcher.
pub struct VerifiedMessage<'a> {
    sender: Principal,
    from_endpoint: u32,
    payload: &'a [u8],
}

impl<'a> VerifiedMessage<'a> {
    /// The sender's verified Principal (guaranteed non-anonymous).
    pub fn sender(&self) -> &Principal {
        &self.sender
    }

    /// The endpoint the message was sent from.
    pub fn from_endpoint(&self) -> u32 {
        self.from_endpoint
    }

    /// The payload bytes (after the 36-byte header).
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    /// Split the payload into (command_byte, data) if non-empty.
    pub fn command(&self) -> Option<(u8, &[u8])> {
        self.payload.split_first().map(|(&cmd, rest)| (cmd, rest))
    }
}

/// Receive and verify an IPC message on `endpoint`.
///
/// `buf` should be at least 292 bytes for full 256-byte payloads
/// (36-byte header + 256 payload). Smaller buffers work but truncate.
///
/// Returns `Some(VerifiedMessage)` only if a message is available AND the
/// sender has a non-anonymous (non-zero) Principal. Returns `None` if:
/// - No message available (queue empty)
/// - Message too short (< 37 bytes: 32 principal + 4 endpoint + 1 payload)
/// - Sender principal is anonymous (all zeros)
///
/// This is the **only** way to obtain a `VerifiedMessage`. Services that
/// use this function structurally cannot operate on a kernel that does not
/// stamp sender identity on IPC messages.
pub fn recv_verified<'a>(endpoint: u32, buf: &'a mut [u8]) -> Option<VerifiedMessage<'a>> {
    let n = recv_msg(endpoint, buf);
    if n <= 0 {
        return None;
    }
    let total = n as usize;
    // 32 principal + 4 endpoint + 1 minimum payload byte
    if total < 37 || total > buf.len() {
        return None;
    }

    let mut principal_bytes = [0u8; 32];
    principal_bytes.copy_from_slice(&buf[0..32]);
    let principal = Principal(principal_bytes);

    // THE STRUCTURAL CHECK: no principal, no message, no service.
    if principal.is_anonymous() {
        return None;
    }

    let from_endpoint = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);

    Some(VerifiedMessage {
        sender: principal,
        from_endpoint,
        payload: &buf[36..total],
    })
}

// ============================================================================
// Device / DMA syscalls
// ============================================================================

const SYS_ALLOCATE: u64 = 3;
const SYS_MAP_MMIO: u64 = 20;
const SYS_ALLOC_DMA: u64 = 21;
const SYS_DEVICE_INFO: u64 = 22;
const SYS_PORT_IO: u64 = 23;

/// Allocate `num_pages` of plain RW user-space virtual memory. Returns
/// the base virtual address as a positive value on success, or a
/// negative errno (OOM, invalid size, etc.).
///
/// The kernel ABI takes bytes; this wrapper converts pages so callers
/// keep sizing in the 4 KiB unit they'll actually use. Per-call cap is
/// 64 MiB (SCAFFOLDING bound per handle_allocate).
///
/// Unlike `alloc_dma`, the returned region is not guaranteed physically
/// contiguous and has no guard pages — suitable for general scratch /
/// sprite buffers / software render targets, not DMA.
pub fn allocate(num_pages: u32) -> i64 {
    let bytes = (num_pages as u64) * 4096;
    syscall_raw3(SYS_ALLOCATE, bytes, 0, 0)
}

/// Map device MMIO into this process's address space.
/// Returns user-space virtual address, or negative error.
pub fn map_mmio(phys_addr: u64, num_pages: u32) -> i64 {
    syscall_raw3(SYS_MAP_MMIO, phys_addr, num_pages as u64, 0)
}

/// Allocate physically contiguous DMA-capable pages with guard pages.
/// Returns user-space virtual address. Physical address written to `out_paddr`.
pub fn alloc_dma(num_pages: u32, out_paddr: &mut u64) -> i64 {
    syscall_raw3(SYS_ALLOC_DMA, num_pages as u64, 0, out_paddr as *mut u64 as u64)
}

/// Query PCI device info by index.
/// Writes a 108-byte device descriptor to `out_buf`.
/// Returns 0 on success, negative error if index is out of range.
pub fn device_info(index: u32, out_buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_DEVICE_INFO, index as u64, out_buf.as_mut_ptr() as u64, out_buf.len() as u64)
}

/// Perform kernel-validated port I/O on a PCI device I/O BAR.
/// The kernel rejects ports not within a discovered PCI I/O BAR.
///
/// `flags` bit 0: direction (0=read, 1=write)
/// `flags` bits 2:1: width (0=byte, 1=word, 2=dword)
pub fn port_io(port: u16, value: u32, flags: u32) -> i64 {
    syscall_raw3(SYS_PORT_IO, port as u64, value as u64, flags as u64)
}

/// Read a byte from a PCI device I/O port.
pub fn port_read8(port: u16) -> Result<u8, i64> {
    let r = port_io(port, 0, 0b000); // read, byte
    if r < 0 { Err(r) } else { Ok(r as u8) }
}

/// Write a byte to a PCI device I/O port.
pub fn port_write8(port: u16, value: u8) -> Result<(), i64> {
    let r = port_io(port, value as u32, 0b001); // write, byte
    if r < 0 { Err(r) } else { Ok(()) }
}

/// Read a 16-bit word from a PCI device I/O port.
pub fn port_read16(port: u16) -> Result<u16, i64> {
    let r = port_io(port, 0, 0b010); // read, word
    if r < 0 { Err(r) } else { Ok(r as u16) }
}

/// Write a 16-bit word to a PCI device I/O port.
pub fn port_write16(port: u16, value: u16) -> Result<(), i64> {
    let r = port_io(port, value as u32, 0b011); // write, word
    if r < 0 { Err(r) } else { Ok(()) }
}

/// Read a 32-bit dword from a PCI device I/O port.
pub fn port_read32(port: u16) -> Result<u32, i64> {
    let r = port_io(port, 0, 0b100); // read, dword
    if r < 0 { Err(r) } else { Ok(r as u32) }
}

/// Write a 32-bit dword to a PCI device I/O port.
pub fn port_write32(port: u16, value: u32) -> Result<(), i64> {
    let r = port_io(port, value, 0b101); // write, dword
    if r < 0 { Err(r) } else { Ok(()) }
}

// ============================================================================
// Virtio-modern PCI capability discovery (ADR-014 Scanout-4.a)
// ============================================================================
//
// Modern virtio-pci drivers (virtio-gpu and future virtio devices) need
// the (BAR, offset) locations of the common-config, notify, ISR, and
// device-specific-config register structures. The kernel parses the PCI
// capability list at boot; this syscall retrieves the parsed result.
//
// Byte layout must match `arcos::pci::VirtioModernCaps` exactly.

const SYS_VIRTIO_MODERN_CAPS: u64 = 38;

/// One virtio-pci capability entry (virtio spec §4.1.4.1).
///
/// `bar` is the BAR index (0..=5); `offset` and `length` locate the
/// register structure within that BAR. All zero when the cap type
/// was not present on the device.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioPciCapEntry {
    pub bar: u8,
    pub _pad: [u8; 3],
    pub offset: u32,
    pub length: u32,
}

/// Parsed virtio-modern capability set for a PCI device.
///
/// `present == 0` means the device is not a virtio-modern device, or its
/// capability list contained no recognized virtio entries. Drivers MUST
/// check `present` before using the cap fields.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct VirtioModernCaps {
    pub common_cfg: VirtioPciCapEntry,
    pub notify_cfg: VirtioPciCapEntry,
    pub notify_off_multiplier: u32,
    pub _pad: u32,
    pub isr_cfg: VirtioPciCapEntry,
    pub device_cfg: VirtioPciCapEntry,
    pub present: u8,
    pub _pad2: [u8; 7],
}

/// Retrieve the kernel-parsed virtio-modern capabilities for the PCI
/// device at `index`. Returns `None` on a bad index or if the syscall
/// otherwise fails. `caps.present == 0` distinguishes "not a virtio
/// device" from "index out of range" (the latter returns `None`).
pub fn virtio_modern_caps(index: u32) -> Option<VirtioModernCaps> {
    let mut caps = VirtioModernCaps::default();
    let r = syscall_raw3(
        SYS_VIRTIO_MODERN_CAPS,
        index as u64,
        &mut caps as *mut VirtioModernCaps as u64,
        core::mem::size_of::<VirtioModernCaps>() as u64,
    );
    if r < 0 {
        return None;
    }
    Some(caps)
}

// ============================================================================
// Shell / interactive syscalls
// ============================================================================

const SYS_CONSOLE_READ: u64 = 24;
const SYS_SPAWN: u64 = 25;
const SYS_WAIT_TASK: u64 = 26;
const SYS_GET_TIME: u64 = 9;

/// Read bytes from the serial console (non-blocking).
/// Returns the number of bytes read (0 if no data available).
pub fn console_read(buf: &mut [u8]) -> i64 {
    syscall_raw3(SYS_CONSOLE_READ, buf.as_mut_ptr() as u64, buf.len() as u64, 0)
}

/// Spawn a boot module by name. Returns the new task ID, or negative error.
pub fn spawn(name: &[u8]) -> i64 {
    syscall_raw3(SYS_SPAWN, name.as_ptr() as u64, name.len() as u64, 0)
}

/// Block until the specified child task exits. Returns the child's exit code.
pub fn wait_task(task_id: u32) -> i64 {
    syscall_raw3(SYS_WAIT_TASK, task_id as u64, 0, 0)
}

/// Get system time in ticks.
pub fn get_time() -> u64 {
    syscall_raw3(SYS_GET_TIME, 0, 0, 0) as u64
}

// ============================================================================
// Phase 3.2d.iv: Shared-memory channel syscalls (ADR-005)
// ============================================================================

const SYS_CHANNEL_CREATE: u64 = 28;
const SYS_CHANNEL_ATTACH: u64 = 29;
const SYS_CHANNEL_CLOSE: u64 = 30;
const SYS_CHANNEL_REVOKE: u64 = 31;
const SYS_CHANNEL_INFO: u64 = 32;

/// Create a shared-memory channel.
///
/// `size_pages`: number of 4 KiB pages (1..=4096).
/// `peer_principal`: 32-byte Ed25519 public key of the intended peer.
/// `role`: 0 = Producer (creator writes), 1 = Consumer (creator reads),
///         2 = Bidirectional (both sides write).
/// `out_vaddr`: receives the creator's virtual address of the shared region.
///
/// Returns the ChannelId (>= 0) on success, or a negative error code.
/// Requires the `CreateChannel` system capability.
pub fn channel_create(
    size_pages: u32,
    peer_principal: &[u8; 32],
    role: u32,
    out_vaddr: &mut u64,
) -> i64 {
    syscall_raw4(
        SYS_CHANNEL_CREATE,
        size_pages as u64,
        peer_principal.as_ptr() as u64,
        role as u64,
        out_vaddr as *mut u64 as u64,
    )
}

/// Attach to an existing channel as the named peer.
///
/// The kernel verifies the caller's Principal matches the peer_principal
/// specified at create time. Returns the user-space virtual address of
/// the shared region on success, or a negative error code.
pub fn channel_attach(channel_id: u64) -> i64 {
    syscall_raw3(SYS_CHANNEL_ATTACH, channel_id, 0, 0)
}

/// Close a channel. Both sides' mappings are removed.
///
/// Only the creator or peer may call this. Returns 0 on success.
pub fn channel_close(channel_id: u64) -> i64 {
    syscall_raw3(SYS_CHANNEL_CLOSE, channel_id, 0, 0)
}

/// Force-revoke a channel (bootstrap/policy authority required).
///
/// Returns 0 on success.
pub fn channel_revoke(channel_id: u64) -> i64 {
    syscall_raw3(SYS_CHANNEL_REVOKE, channel_id, 0, 0)
}

/// Query channel metadata.
///
/// Writes a 46-byte descriptor to `out_buf`. Returns 0 on success.
pub fn channel_info(channel_id: u64, out_buf: &mut [u8]) -> i64 {
    syscall_raw3(
        SYS_CHANNEL_INFO,
        channel_id,
        out_buf.as_mut_ptr() as u64,
        out_buf.len() as u64,
    )
}

// ============================================================================
// Audit infrastructure (Phase 3.3, ADR-007)
// ============================================================================

const SYS_AUDIT_ATTACH: u64 = 33;
const SYS_AUDIT_INFO: u64 = 34;

/// Attach as the audit ring consumer.
///
/// Maps the kernel's audit ring pages read-only into this process's
/// address space. Returns the user-space virtual address on success,
/// or a negative error code.
///
/// Capability-gated on `AuditConsumer` system capability. Granted to
/// the `audit-tail` boot module; future kernelvisor / AI-watcher
/// consumers hold this cap.
pub fn audit_attach() -> i64 {
    syscall_raw3(SYS_AUDIT_ATTACH, 0, 0, 0)
}

/// Read audit ring statistics into `out_buf`.
///
/// `out_buf` must be at least 48 bytes. Returns 0 on success.
///
/// # Wire format
/// ```text
///   0..8   total_produced     (u64)
///   8..16  total_dropped      (u64) — staging-buffer overflow count
///  16..20  capacity           (u32) — ring slot count
///     20   consumer_attached  (u8)  — 0 = no consumer, 1 = attached
///  21..24  reserved
///  24..28  online_cpus        (u32)
///  28..44  staging[0..4]      (u32 × 4) — per-CPU staging-buffer length
///  44..48  drain_skips        (u32 saturating) — T-8: count of
///          drain_tick invocations that found AUDIT_RING contended
///          and skipped. Leading indicator of denial-of-audit
///          attempts (sustained contention precedes staging-buffer
///          overflow). u32::MAX means "≥ 4B skips, very bad."
/// ```
pub fn audit_info(out_buf: &mut [u8]) -> i64 {
    syscall_raw3(
        SYS_AUDIT_INFO,
        out_buf.as_mut_ptr() as u64,
        out_buf.len() as u64,
        0,
    )
}

const SYS_AUDIT_EMIT_INPUT_FOCUS: u64 = 41;

/// Emit a window-focus-change event into the kernel audit ring
/// (T-7 Phase A, docs/threat-model.md).
///
/// `new_window_id` is 0 when focus is lost (the last live window
/// just exited); `old_window_id` is 0 on the initial focus
/// transition (no prior focused window). `owner_principal` carries
/// the new window's owner Principal — pass an all-zero array when
/// focus is being lost.
///
/// Capability-gated on `EmitInputAudit`. Returns 0 on success or
/// `PermissionDenied` without the capability.
pub fn audit_emit_input_focus(
    new_window_id: u32,
    old_window_id: u32,
    owner_principal: &[u8; 32],
) -> i64 {
    syscall_raw3(
        SYS_AUDIT_EMIT_INPUT_FOCUS,
        new_window_id as u64,
        old_window_id as u64,
        owner_principal.as_ptr() as u64,
    )
}

const SYS_GET_PROCESS_PRINCIPAL: u64 = 42;

/// Resolve a `ProcessId` (raw u64; encodes slot + generation per
/// ADR-008) to its bound 32-byte Principal. Lets an audit consumer
/// render `subject_pid` fields from buffered audit events as
/// `did:key:z6Mk…` without widening the 64-byte event format.
///
/// Capability-gated on `AuditConsumer`. The kernel first looks up the
/// principal in the live process table; on miss, falls back to a
/// recent-exits ring on the process table for principals of processes
/// that have already exited.
///
/// Returns 32 on success (bytes written to `out`), `PermissionDenied`
/// without the capability, or `InvalidArg` on bad pointer or unknown
/// target (no live binding and no recent-exits entry).
pub fn get_process_principal(target_pid_raw: u64, out: &mut [u8; 32]) -> i64 {
    syscall_raw3(
        SYS_GET_PROCESS_PRINCIPAL,
        target_pid_raw,
        out.as_mut_ptr() as u64,
        32,
    )
}

// ============================================================================
// Hardware-IRQ wait + framebuffer mapping (Phase GUI-0, ADR-011)
// ============================================================================

const SYS_WAIT_IRQ: u64 = 5;
const SYS_MAP_FRAMEBUFFER: u64 = 35;

/// Block this task until the named IRQ fires.
///
/// IRQ numbers follow the I/O APIC GSI convention: 1 = keyboard, 12 = PS/2
/// mouse, etc. `irq` must be < 224 (the kernel's MAX_DEVICE_IRQ ceiling).
/// Returns 0 on wake. Negative codes on registration failure (already
/// claimed, invalid IRQ, etc.).
///
/// Today only one task may register per IRQ (first-come-first-served).
pub fn wait_irq(irq: u32) -> i64 {
    syscall_raw3(SYS_WAIT_IRQ, irq as u64, 0, 0)
}

/// Layout of the descriptor returned by [`map_framebuffer`].
///
/// Wire-format size: 32 bytes, little-endian, `#[repr(C)]`. Mirrors the
/// kernel-side layout in `handle_map_framebuffer` (see ADR-011).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FramebufferDescriptor {
    /// User-space virtual address where the framebuffer pages are mapped.
    pub vaddr: u64,
    pub width: u32,
    pub height: u32,
    /// Bytes per scanline (≥ width × bpp/8).
    pub pitch: u32,
    pub bpp: u16,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
    /// Reserved (zero today).
    pub reserved: u32,
}

/// Wire-format size of `FramebufferDescriptor`.
pub const FRAMEBUFFER_DESCRIPTOR_SIZE: usize = 32;

/// Map the framebuffer at `index` (zero-based, per-display) into this
/// process and fill `out` with its descriptor.
///
/// Multi-monitor: call once per display. `index = 0` is the primary;
/// out-of-range indices return `Err(-1)` with no mapping made.
///
/// Capability-gated: caller must hold
/// `CapabilityKind::MapFramebuffer`. Without it, returns
/// `Err(-3)` (PermissionDenied).
///
/// Returns `Ok(())` on success; the user vaddr is in `out.vaddr`.
pub fn map_framebuffer(index: u32, out: &mut FramebufferDescriptor) -> Result<(), i64> {
    let mut buf = [0u8; FRAMEBUFFER_DESCRIPTOR_SIZE];
    let rc = syscall_raw3(
        SYS_MAP_FRAMEBUFFER,
        index as u64,
        buf.as_mut_ptr() as u64,
        FRAMEBUFFER_DESCRIPTOR_SIZE as u64,
    );
    if rc < 0 {
        return Err(rc);
    }
    out.vaddr = u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    out.width = u32::from_le_bytes(buf[8..12].try_into().unwrap_or([0; 4]));
    out.height = u32::from_le_bytes(buf[12..16].try_into().unwrap_or([0; 4]));
    out.pitch = u32::from_le_bytes(buf[16..20].try_into().unwrap_or([0; 4]));
    out.bpp = u16::from_le_bytes(buf[20..22].try_into().unwrap_or([0; 2]));
    out.red_mask_size = buf[22];
    out.red_mask_shift = buf[23];
    out.green_mask_size = buf[24];
    out.green_mask_shift = buf[25];
    out.blue_mask_size = buf[26];
    out.blue_mask_shift = buf[27];
    out.reserved = u32::from_le_bytes(buf[28..32].try_into().unwrap_or([0; 4]));
    Ok(())
}

// ============================================================================
// Virtio-blk driver IPC client (Phase 4a.ii)
// ============================================================================
//
// Thin wrappers over the `write` + `recv_verified` pair for talking to the
// virtio-blk driver at endpoint 22. Each wrapper sends a single control-frame
// request and polls the caller's own endpoint for the response. `block_read`
// and `block_write` are deliberately absent — the 4 KiB data path is Phase
// 4a.iii work and the protocol (multi-frame, channel, shared map) has not
// landed. Callers that need bulk I/O today must roll their own path.

/// IPC endpoint registered by the virtio-blk driver. Endpoint 22 is the
/// policy-service query channel; virtio-blk lives on 24.
pub const BLK_DRIVER_ENDPOINT: u32 = 24;

const BLK_CMD_FLUSH: u8 = 3;
const BLK_CMD_GET_CAPACITY: u8 = 4;
const BLK_CMD_GET_STATUS: u8 = 5;

const BLK_STATUS_OK: u8 = 0;

/// Poll the caller's endpoint for up to 20 yields waiting for a reply.
/// Returns the verified message's payload bytes copied into `out`, or `None`
/// on timeout / anonymous sender / transport error.
fn blk_await_reply(caller_endpoint: u32, out: &mut [u8; 256]) -> Option<usize> {
    let mut buf = [0u8; 292];
    for _ in 0..20 {
        if let Some(msg) = recv_verified(caller_endpoint, &mut buf) {
            let payload = msg.payload();
            let n = core::cmp::min(payload.len(), out.len());
            out[..n].copy_from_slice(&payload[..n]);
            return Some(n);
        }
        yield_now();
    }
    None
}

/// Ask the virtio-blk driver for the device capacity, in 512-byte sectors.
///
/// `caller_endpoint` is the caller's own IPC endpoint — the driver's reply
/// lands there. Returns `None` if the driver is absent, the reply times out,
/// or the device reports no capacity.
pub fn block_capacity(caller_endpoint: u32) -> Option<u64> {
    if write(BLK_DRIVER_ENDPOINT, &[BLK_CMD_GET_CAPACITY]) < 0 {
        return None;
    }
    let mut reply = [0u8; 256];
    let n = blk_await_reply(caller_endpoint, &mut reply)?;
    if n < 9 || reply[0] != BLK_STATUS_OK {
        return None;
    }
    Some(u64::from_le_bytes(reply[1..9].try_into().ok()?))
}

/// Ask the driver to issue a `VIRTIO_BLK_T_FLUSH`. Returns `true` on success.
pub fn block_flush(caller_endpoint: u32) -> bool {
    if write(BLK_DRIVER_ENDPOINT, &[BLK_CMD_FLUSH]) < 0 {
        return false;
    }
    let mut reply = [0u8; 256];
    match blk_await_reply(caller_endpoint, &mut reply) {
        Some(n) if n >= 1 => reply[0] == BLK_STATUS_OK,
        _ => false,
    }
}

/// Probe the driver — returns `Some(alive)` where `alive` reflects whether
/// the device and its virtqueue are healthy. `None` means the driver itself
/// is not reachable.
pub fn block_status(caller_endpoint: u32) -> Option<bool> {
    if write(BLK_DRIVER_ENDPOINT, &[BLK_CMD_GET_STATUS]) < 0 {
        return None;
    }
    let mut reply = [0u8; 256];
    let n = blk_await_reply(caller_endpoint, &mut reply)?;
    if n < 2 || reply[0] != BLK_STATUS_OK {
        return None;
    }
    Some(reply[1] != 0)
}
