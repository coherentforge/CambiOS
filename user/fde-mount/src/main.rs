// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS FDE-mount orchestrator (stream A substage A-v.a).
//!
//! Boot module that walks the FDE volume unlock flow per ADR-032 §
//! Architecture lines 154-167:
//!
//! 1. Probe key-store-service PIV health (bail to "no PIV" in
//!    default builds — only `--features dev-piv` on key-store-service
//!    gives a usable backend right now).
//! 2. Verify the dev PIN (`123456` per the standard PIV factory
//!    default; production prompts the user via a UX path not yet
//!    built).
//! 3. Call `SYS_READ_VOLUME_HEADER` to copy LBA 0..=3 of the on-disk
//!    header into a local 16 KiB buffer.
//! 4. Call `SYS_VERIFY_VOLUME_HEADER` (A-iv) — kernel verifies the
//!    signature against the baked bootstrap pubkey + the
//!    AID-equals-pubkey invariant.
//! 5. Walk the slot table via `cambios_fde_proto::parse_slot_table`
//!    and `find_first_live_yubikey` (A-v.b).
//! 6. Extract the envelope: `ephemeral_pk` at bytes 0..32,
//!    ChaCha20-Poly1305 ciphertext at bytes 32..112 per ADR-032 § 4.
//! 7. Call `piv_decrypt(slot=KeyManagement, ephemeral_pk)` to get
//!    the 32-byte X25519 ECDH shared secret.
//! 8. Derive the symmetric ChaCha20-Poly1305 key via
//!    `blake3::derive_key(WRAP_KDF_CONTEXT, shared_secret)`.
//! 9. Decrypt the envelope ciphertext in-place under the symmetric
//!    key with the fixed twelve-zero nonce. Plaintext is the 64-byte
//!    XTS-AES-256 FDE master key (K1 || K2 per NIST SP 800-38E).
//! 10. **Stub install** — A-v.d will add `SYS_INSTALL_MASTER_KEY`;
//!     until then this module logs success and exits. The master
//!     key + shared secret + symmetric key are zeroized via
//!     `zeroize` before the function returns.
//!
//! Recovery slots (Argon2id, slot_type=0x02) and the recovery boot
//! path are out of scope — recovery is a future ADR per the in-
//! session discussion.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use cambios_fde_proto::{
    FDE_MASTER_KEY_LEN, MAX_VOLUME_SLOTS, WRAP_ENV_CIPHERTEXT_LEN, WRAP_ENV_CIPHERTEXT_OFF,
    WRAP_ENV_EPHEMERAL_PK_LEN, WRAP_ENV_EPHEMERAL_PK_OFF, WRAP_ENV_LEN, WRAP_KDF_CONTEXT,
    WRAP_NONCE, find_first_live_yubikey, parse, parse_slot_table,
};
use cambios_libsys as sys;
use cambios_libsys::keystore::{PivError, PivHealthState, PivSlot};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use zeroize::Zeroize;

// ============================================================================
// Constants
// ============================================================================

/// Reply endpoint registered by `fde-mount`. Picked from the next
/// available slot after usb-host (31). Used as the caller's reply
/// queue for all libsys IPC wrappers + `SYS_REGISTER_ENDPOINT`'s
/// reply-endpoint registry.
const FDE_MOUNT_ENDPOINT: u32 = 32;

/// HARDWARE: the `SYS_READ_VOLUME_HEADER` syscall reads LBA 0..=3
/// per ADR-032 § 4 ("Lives at fixed LBAs on the underlying device —
/// before the substrate's region map") — 16 KiB regardless of
/// `header_length`. Padding bytes past `header_length` are part of
/// the reserved header region.
const HEADER_BUF_BYTES: usize = 16384;

/// Dev PIN — matches the PIV factory default, the same value
/// `SwPivBackend` (A-ii) accepts. Production builds prompt the user
/// via a UX path that doesn't exist yet.
const DEV_PIN: &[u8] = b"123456";

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[FDE-MOUNT] PANIC!\n");
    sys::exit(1);
}

// ============================================================================
// Outcome
// ============================================================================

enum UnlockOutcome {
    /// Master key derived; stub install printed; A-v.d will replace
    /// the stub with `SYS_INSTALL_MASTER_KEY`.
    Success,
    /// PIV backend reported `NotPresent`. Default-build kernel +
    /// key-store-service produce this; rebuild both with
    /// `--features dev-piv` for end-to-end coverage.
    NoPiv,
    /// Numeric failure — `stage` is a short label printed alongside
    /// the negative return code.
    Failure(&'static [u8], i64),
}

// ============================================================================
// Entry point
// ============================================================================

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys::register_endpoint(FDE_MOUNT_ENDPOINT);
    sys::print(b"[FDE-MOUNT] starting on endpoint 32\n");
    sys::module_ready();

    match unlock_flow() {
        UnlockOutcome::Success => {
            sys::print(
                b"[FDE-MOUNT] OK: master key derived (64 bytes); install stub awaits A-v.d\n",
            );
        }
        UnlockOutcome::NoPiv => {
            sys::print(
                b"[FDE-MOUNT] no PIV backend (degraded mode); skipping FDE unlock\n",
            );
        }
        UnlockOutcome::Failure(stage, code) => {
            sys::print(b"[FDE-MOUNT] FAIL at ");
            sys::print(stage);
            sys::print(b": ");
            print_i64(code);
            sys::print(b"\n");
        }
    }

    sys::exit(0);
}

// ============================================================================
// Unlock flow
// ============================================================================

fn unlock_flow() -> UnlockOutcome {
    // Step 1: PIV health probe.
    let health = match sys::keystore::piv_health(FDE_MOUNT_ENDPOINT) {
        Ok(h) => h,
        Err(_) => return UnlockOutcome::Failure(b"piv_health (IPC)", -1),
    };
    if matches!(health, PivHealthState::NotPresent) {
        return UnlockOutcome::NoPiv;
    }

    // Step 2: PIN verification.
    if let Err(e) = sys::keystore::piv_verify_pin(FDE_MOUNT_ENDPOINT, DEV_PIN) {
        return UnlockOutcome::Failure(b"piv_verify_pin", piv_error_code(e));
    }

    // Step 3: Read the on-disk volume header.
    let mut header_buf = [0u8; HEADER_BUF_BYTES];
    let n = sys::read_volume_header(&mut header_buf);
    if n < 0 {
        return UnlockOutcome::Failure(b"read_volume_header", n);
    }
    if n as usize != HEADER_BUF_BYTES {
        return UnlockOutcome::Failure(b"read_volume_header (size)", n);
    }

    // Step 4: Verify the header (parse + signature against the
    // kernel-baked bootstrap pubkey + AID-equals-pubkey).
    let parsed = match parse(&header_buf) {
        Ok(h) => h,
        Err(_) => return UnlockOutcome::Failure(b"parse", -1),
    };
    let header_len = parsed.header_length as usize;
    let verify_result = sys::verify_volume_header(&header_buf[..header_len]);
    if verify_result != 0 {
        return UnlockOutcome::Failure(b"verify_volume_header", verify_result);
    }

    // Step 5: Walk the slot table, find live YubiKey slot.
    let slots = match parse_slot_table(&header_buf[..header_len], parsed.slot_count as usize) {
        Ok(s) => s,
        Err(_) => return UnlockOutcome::Failure(b"parse_slot_table", -1),
    };
    let live_slot = match find_first_live_yubikey(&slots) {
        Some(s) => s,
        None => return UnlockOutcome::Failure(b"find_first_live_yubikey (no live YK)", -1),
    };

    // Step 6: Extract envelope bytes.
    let envelope = live_slot.wrapped_key_bytes();
    if envelope.len() < WRAP_ENV_LEN {
        return UnlockOutcome::Failure(b"envelope length", envelope.len() as i64);
    }
    let eph_pk = &envelope[WRAP_ENV_EPHEMERAL_PK_OFF
        ..WRAP_ENV_EPHEMERAL_PK_OFF + WRAP_ENV_EPHEMERAL_PK_LEN];
    let ciphertext_with_tag = &envelope
        [WRAP_ENV_CIPHERTEXT_OFF..WRAP_ENV_CIPHERTEXT_OFF + WRAP_ENV_CIPHERTEXT_LEN];

    // Step 7: ECDH via piv_decrypt.
    let mut shared = [0u8; 32];
    let n = match sys::keystore::piv_decrypt(
        FDE_MOUNT_ENDPOINT,
        PivSlot::KeyManagement,
        eph_pk,
        &mut shared,
    ) {
        Ok(n) => n,
        Err(e) => return UnlockOutcome::Failure(b"piv_decrypt", piv_error_code(e)),
    };
    if n != 32 {
        return UnlockOutcome::Failure(b"piv_decrypt (size)", n as i64);
    }

    // Step 8: Derive symmetric key via Blake3.
    let mut symm_key: [u8; 32] = blake3::derive_key(WRAP_KDF_CONTEXT, &shared);

    // Step 9: ChaCha20-Poly1305 decrypt in-place.
    //
    // The envelope's ciphertext field is 80 bytes = 64 ciphertext +
    // 16 Poly1305 tag. `decrypt_in_place_detached` takes
    // ciphertext and tag separately and writes plaintext over the
    // ciphertext buffer.
    let mut plaintext = [0u8; FDE_MASTER_KEY_LEN];
    plaintext.copy_from_slice(&ciphertext_with_tag[..FDE_MASTER_KEY_LEN]);
    let tag = Tag::from_slice(&ciphertext_with_tag[FDE_MASTER_KEY_LEN..]);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&symm_key));
    let nonce = Nonce::from_slice(&WRAP_NONCE);
    if cipher
        .decrypt_in_place_detached(nonce, &[], &mut plaintext, tag)
        .is_err()
    {
        // Zero before bailing — failed authentication doesn't
        // exempt us from key hygiene.
        shared.zeroize();
        symm_key.zeroize();
        plaintext.zeroize();
        return UnlockOutcome::Failure(b"chacha20-poly1305 decrypt", -1);
    }

    // Step 10: Stub install.
    //
    // A-v.d will replace this with `SYS_INSTALL_MASTER_KEY(plaintext,
    // header_bytes)` — the kernel will accept the master key only
    // after re-verifying the header signature and confirming
    // verify-by-decryption against a known LBA. Until A-v.d lands,
    // we print success and exit.
    let _master_key_len = plaintext.len(); // touched so zeroize isn't DCE'd

    // Step 11: Key hygiene.
    shared.zeroize();
    symm_key.zeroize();
    plaintext.zeroize();

    UnlockOutcome::Success
}

// ============================================================================
// Helpers
// ============================================================================

fn piv_error_code(e: PivError) -> i64 {
    match e {
        PivError::Generic => -1,
        PivError::NotPresent => -2,
        PivError::AuthRequired => -3,
        PivError::SlotEmpty => -4,
        PivError::WrongAlgorithm => -5,
        PivError::PinLocked => -6,
        PivError::CardTransport => -7,
        PivError::WireFormat => -8,
        PivError::Ipc => -9,
    }
}

fn print_i64(n: i64) {
    let mut buf = [0u8; 24];
    let mut i = 0;
    let mut value = n;
    let neg = value < 0;
    if neg {
        value = -value;
    }
    if value == 0 {
        buf[0] = b'0';
        i = 1;
    } else {
        let mut digits = [0u8; 24];
        let mut d = 0;
        while value > 0 {
            digits[d] = b'0' + (value % 10) as u8;
            d += 1;
            value /= 10;
        }
        if neg {
            buf[i] = b'-';
            i += 1;
        }
        while d > 0 {
            d -= 1;
            buf[i] = digits[d];
            i += 1;
        }
    }
    sys::print(&buf[..i]);
}

// Touched so MAX_VOLUME_SLOTS isn't an "unused import" lint —
// the constant is part of the proto-crate API surface fde-mount
// reasons against, even when it's not directly named in code.
const _: usize = MAX_VOLUME_SLOTS;
