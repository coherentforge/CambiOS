//! ArcOS Key Store Service — user-space Ed25519 signing service
//!
//! When a bootstrap secret key is available in the kernel (legacy seed mode),
//! claims it at boot and signs on behalf of callers. When no secret key is
//! available (hardware-backed YubiKey mode), enters degraded mode: responds
//! to sign requests with STATUS_ERROR so callers fall back to unsigned storage.
//!
//! Degraded mode is the expected state when the bootstrap signing key lives
//! on external hardware (YubiKey). Full signing resumes when the USB HID
//! stack enables runtime communication with the hardware key store.
//!
//! Runs as a ring-3 process. Registers IPC endpoint 17, receives
//! sign and get-public-key requests over IPC.
//!
//! IPC protocol (256-byte payload):
//!   Request:  [cmd:1][data...]
//!   Response: [status:1][data...]
//!
//!   cmd: 1=SIGN, 2=GET_PUBKEY
//!   status: 0=OK, 1=ERROR

#![no_std]
#![no_main]

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let msg = b"[KS] PANIC!\n";
    sys_print(msg);
    sys_exit(1);
}

// ============================================================================
// Syscall wrappers (x86_64 SYSCALL instruction)
// ============================================================================

#[inline(always)]
fn syscall3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: Invokes the kernel syscall handler via the SYSCALL instruction.
    // The kernel validates all arguments.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn syscall1(num: u64, arg1: u64) -> i64 {
    syscall3(num, arg1, 0, 0)
}

#[inline(always)]
fn syscall0(num: u64) -> i64 {
    syscall3(num, 0, 0, 0)
}

// Syscall numbers (must match kernel src/syscalls/mod.rs)
const SYS_EXIT: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_REGISTER_ENDPOINT: u64 = 6;
const SYS_YIELD: u64 = 7;
const SYS_PRINT: u64 = 10;
const SYS_RECV_MSG: u64 = 13;
const SYS_CLAIM_BOOTSTRAP_KEY: u64 = 18;

fn sys_exit(code: u32) -> ! {
    syscall1(SYS_EXIT, code as u64);
    loop {}
}

fn sys_print(msg: &[u8]) {
    syscall3(SYS_PRINT, msg.as_ptr() as u64, msg.len() as u64, 0);
}

fn sys_register_endpoint(endpoint_id: u32) -> i64 {
    syscall3(SYS_REGISTER_ENDPOINT, endpoint_id as u64, 0, 0)
}

fn sys_yield() {
    syscall0(SYS_YIELD);
}

fn sys_write(endpoint: u32, buf: &[u8]) -> i64 {
    syscall3(SYS_WRITE, endpoint as u64, buf.as_ptr() as u64, buf.len() as u64)
}

fn sys_recv_msg(endpoint: u32, buf: &mut [u8]) -> i64 {
    syscall3(SYS_RECV_MSG, endpoint as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// Claim the bootstrap secret key from the kernel (one-shot).
/// Returns 64 on success, negative error on failure.
fn sys_claim_bootstrap_key(out_sk: &mut [u8; 64]) -> i64 {
    syscall1(SYS_CLAIM_BOOTSTRAP_KEY, out_sk.as_mut_ptr() as u64)
}

// ============================================================================
// Ed25519 signing (minimal inline implementation using kernel-compatible API)
// ============================================================================

// We need to sign data with the secret key. Since this is a no_std user-space
// binary without access to the ed25519-compact crate (that's a kernel dep),
// we use a raw SYSCALL-based approach: we don't actually need the ed25519
// crate here because the signing is done via the secret key bytes directly.
//
// Actually, we DO need Ed25519 signing in user-space. The simplest approach:
// duplicate the minimal signing logic. But ed25519-compact is pure Rust and
// no_std-compatible — we can add it as a dependency.
//
// For Phase 1C, we'll use a syscall-based approach instead: we store the
// secret key and use it to sign. But we need the ed25519 crate for that.
// Let's keep the service simple and just store/use the raw key bytes.

// The key-store service needs the ed25519-compact crate to actually sign.
// We add it as a dependency in Cargo.toml. But wait — the user-space crate
// can't easily use ed25519-compact because the parent .cargo/config.toml
// sets kernel code model. The fs-service solves this with CARGO_ENCODED_RUSTFLAGS.
// We'll do the same.

// For now, we store the secret key and use ed25519-compact for signing.

// ============================================================================
// IPC Protocol
// ============================================================================

const KS_ENDPOINT: u32 = 17;

const CMD_SIGN: u8 = 1;
const CMD_GET_PUBKEY: u8 = 2;

const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;

// ============================================================================
// Global state (secret key stored in process memory)
// ============================================================================

static mut SECRET_KEY: [u8; 64] = [0u8; 64];
static mut PUBLIC_KEY: [u8; 32] = [0u8; 32];
static mut KEY_INITIALIZED: bool = false;

// ============================================================================
// Signing
// ============================================================================

/// Sign content using the stored secret key.
/// Returns a 64-byte Ed25519 signature.
fn sign(content: &[u8]) -> [u8; 64] {
    // SAFETY: SECRET_KEY is written once at startup, read-only after.
    // Single-threaded user-space process — no race conditions.
    let mut sk = [0u8; 64];
    unsafe { core::ptr::copy_nonoverlapping((&raw const SECRET_KEY).cast::<u8>(), sk.as_mut_ptr(), 64) };
    let ed_sk = ed25519_compact::SecretKey::new(sk);
    let sig = ed_sk.sign(content, None);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ============================================================================
// Service handlers
// ============================================================================

fn handle_sign(payload: &[u8], response: &mut [u8]) -> usize {
    if payload.is_empty() {
        response[0] = STATUS_ERROR;
        return 1;
    }

    // SAFETY: KEY_INITIALIZED is set once at startup, read-only after.
    if unsafe { !*(&raw const KEY_INITIALIZED) } {
        response[0] = STATUS_ERROR;
        return 1;
    }

    let sig = sign(payload);
    response[0] = STATUS_OK;
    response[1..65].copy_from_slice(&sig);
    65
}

fn handle_get_pubkey(response: &mut [u8]) -> usize {
    // SAFETY: KEY_INITIALIZED and PUBLIC_KEY written once at startup, read-only after.
    if unsafe { !*(&raw const KEY_INITIALIZED) } {
        response[0] = STATUS_ERROR;
        return 1;
    }

    response[0] = STATUS_OK;
    unsafe { core::ptr::copy_nonoverlapping((&raw const PUBLIC_KEY).cast::<u8>(), response[1..33].as_mut_ptr(), 32) };
    33
}

// ============================================================================
// Entry point
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys_print(b"[KS] Key store service starting\n");

    // Step 1: Try to claim the bootstrap secret key from the kernel.
    // In hardware-backed mode (YubiKey), no secret key exists in the kernel
    // and this call returns an error. The service enters degraded mode:
    // it still registers its endpoint and responds to requests, but all
    // sign operations return STATUS_ERROR until runtime hardware key
    // access is available (USB HID stack).
    let mut sk = [0u8; 64];
    let ret = sys_claim_bootstrap_key(&mut sk);
    if ret < 0 {
        sys_print(b"[KS] No kernel secret key available (hardware-backed mode)\n");
        sys_print(b"[KS] Entering degraded mode - signing unavailable\n");
        // KEY_INITIALIZED stays false — sign requests will return ERROR
    } else {
        // Legacy seed mode: store the key in process memory
        // SAFETY: Single-threaded init, before service loop starts.
        unsafe {
            core::ptr::copy_nonoverlapping(sk.as_ptr(), (&raw mut SECRET_KEY).cast::<u8>(), 64);
            core::ptr::copy_nonoverlapping(sk[32..64].as_ptr(), (&raw mut PUBLIC_KEY).cast::<u8>(), 32);
            *(&raw mut KEY_INITIALIZED) = true;
        }

        // Zero the stack copy
        for b in sk.iter_mut() {
            *b = 0;
        }

        sys_print(b"[KS] Bootstrap key claimed, kernel copy zeroed\n");
    }

    // Step 2: Register our IPC endpoint
    sys_register_endpoint(KS_ENDPOINT);
    sys_print(b"[KS] Endpoint 17 registered, entering service loop\n");

    // Step 3: Service loop
    let mut recv_buf = [0u8; 256];
    let mut resp_buf = [0u8; 256];

    loop {
        let n = sys_recv_msg(KS_ENDPOINT, &mut recv_buf);

        if n <= 0 {
            sys_yield();
            continue;
        }
        let total = n as usize;

        if total < 37 {
            // Too short: need at least 36-byte header + 1 byte command
            continue;
        }

        // Parse header: [sender_principal:32][from_endpoint:4][payload:N]
        let from_endpoint = u32::from_le_bytes([
            recv_buf[32], recv_buf[33], recv_buf[34], recv_buf[35],
        ]);
        let payload = &recv_buf[36..total];

        let cmd = payload[0];
        let cmd_data = &payload[1..];

        let resp_len = match cmd {
            CMD_SIGN => handle_sign(cmd_data, &mut resp_buf),
            CMD_GET_PUBKEY => handle_get_pubkey(&mut resp_buf),
            _ => {
                resp_buf[0] = STATUS_ERROR;
                1
            }
        };

        sys_write(from_endpoint, &resp_buf[..resp_len]);
    }
}
