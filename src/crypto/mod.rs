// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Kernel-wide signature verification dispatch.
//!
//! This module owns the **verify boundary**: every kernel signature check
//! routes through [`verify`], which dispatches on a [`SignatureAlgo`] tag.
//! The shape exists pre-v1 so post-quantum (ML-DSA-65) and hybrid signing
//! land at v1.5 as a single match-arm extension instead of a refactor across
//! every call site that today bakes "sig is exactly 64 bytes Ed25519" into
//! its shape.
//!
//! See [ADR-025](../../docs/adr/025-principal-as-aid.md) (Principal-as-AID)
//! and [identity.md](../../docs/identity.md) Phase 1.5 for the post-quantum
//! roadmap this boundary protects.
//!
//! ## Convention compliance
//! - **No dynamic dispatch.** [`SignatureAlgo`] is `#[repr(u8)]` and
//!   [`verify`] is a `match` — monomorphizes to a static branch table per
//!   call site, statically analyzable.
//! - **No `unsafe`.** All operations go through `ed25519-compact`'s safe API.
//! - **Typed return.** Zeroed signatures and algorithm/type mismatches all
//!   fail closed (return `false`); no panics on malformed input.

/// Signature algorithm identifier.
///
/// `#[repr(u8)]` so the wire-format byte (e.g. ARCSIG trailer byte 7,
/// CambiObject record-header byte 108, CKEY pubkey-file byte 5) maps 1:1.
/// Variants are append-only — the u8 values are part of the kernel ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureAlgo {
    /// Ed25519 (RFC 8032). 32-byte public key, 64-byte signature.
    Ed25519 = 0,
    /// ML-DSA-65 (NIST FIPS 204, formerly Dilithium3).
    /// 1952-byte public key, 3293-byte signature.
    ///
    /// Reserved tag — verification returns `false` until v1.5.
    MlDsa65 = 1,
}

/// Borrowed reference to a public key, tagged by algorithm.
///
/// Today only `Ed25519` constructs successfully; future variants slot in
/// alongside as new arms when their algorithms land. Keeping the enum
/// monomorphized + reference-borrowed avoids any heap allocation in the
/// kernel verify path.
#[derive(Debug, Clone, Copy)]
pub enum PublicKeyRef<'a> {
    Ed25519(&'a [u8; 32]),
}

/// Borrowed reference to a signature, tagged by algorithm.
///
/// Mirrors [`PublicKeyRef`]; same rationale.
#[derive(Debug, Clone, Copy)]
pub enum SignatureRef<'a> {
    Ed25519(&'a [u8; 64]),
}

/// Verify a signature over `msg` using `key` under the named `algo`.
///
/// Returns `true` iff the signature verifies. All failure modes (algorithm
/// mismatch between `algo` / `key` / `sig`, zeroed signature, cryptographic
/// failure) return `false` — fail closed, no panics.
///
/// At v1 only the `Ed25519` arm produces `true`. The `MlDsa65` arm is
/// reserved and always returns `false` until the post-quantum implementation
/// lands at v1.5.
pub fn verify(
    algo: SignatureAlgo,
    key: PublicKeyRef<'_>,
    msg: &[u8],
    sig: SignatureRef<'_>,
) -> bool {
    match algo {
        SignatureAlgo::Ed25519 => match (key, sig) {
            (PublicKeyRef::Ed25519(k), SignatureRef::Ed25519(s)) => verify_ed25519(k, msg, s),
            // Algorithm/key/signature type mismatch — programmer error, fail closed.
            #[allow(unreachable_patterns)]
            _ => false,
        },
        SignatureAlgo::MlDsa65 => {
            // Deferred: ML-DSA-65 verification ([identity.md](../../docs/identity.md) Phase 1.5).
            // Why: PQ crate selection unresolved; 256 KB boot stack budget for lattice ops needs measurement.
            // Revisit when: identity.md Phase 1.5 lands (post-v1).
            false
        }
    }
}

/// Inner Ed25519 verification. Zeroed signatures are rejected explicitly so
/// uninitialized [`crate::fs::SignatureBytes::EMPTY`] cannot accidentally
/// pass in a code path that forgot to populate the signature field.
fn verify_ed25519(public_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    if *sig == [0u8; 64] {
        return false;
    }
    let pk = ed25519_compact::PublicKey::new(*public_key);
    let signature = ed25519_compact::Signature::new(*sig);
    pk.verify(msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `verify` accepts a known-good Ed25519 signature.
    #[test]
    fn verify_accepts_valid_ed25519() {
        let seed = [7u8; 32];
        let (pk, sk) = crate::fs::keypair_from_seed(&seed);
        let msg = b"hello, AID";
        let sig = crate::fs::sign_content(&sk, msg);
        assert!(verify(
            SignatureAlgo::Ed25519,
            PublicKeyRef::Ed25519(&pk),
            msg,
            SignatureRef::Ed25519(&sig.data),
        ));
    }

    /// `verify` rejects a zeroed signature even when algo + types align.
    #[test]
    fn verify_rejects_zeroed_signature() {
        let key = [0u8; 32];
        let zero = [0u8; 64];
        assert!(!verify(
            SignatureAlgo::Ed25519,
            PublicKeyRef::Ed25519(&key),
            b"any",
            SignatureRef::Ed25519(&zero),
        ));
    }

    /// The `MlDsa65` arm returns `false` until v1.5 lands. This test will
    /// flip to `assert!(...)` and gain a real-key fixture when ML-DSA-65 is
    /// implemented per identity.md Phase 1.5.
    #[test]
    fn verify_mldsa65_arm_returns_false_pre_v1_5() {
        let key = [0u8; 32];
        let zero = [0u8; 64];
        // Construct a "fake" Ed25519-tagged input under the MlDsa65 algo —
        // the dispatch should refuse on algorithm mismatch / unimplemented.
        assert!(!verify(
            SignatureAlgo::MlDsa65,
            PublicKeyRef::Ed25519(&key),
            b"any",
            SignatureRef::Ed25519(&zero),
        ));
    }
}
