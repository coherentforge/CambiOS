// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS ELF Signing Tool
//!
//! Signs ELF binaries with an Ed25519 signature for the CambiOS kernel's
//! SignedBinaryVerifier. Appends a signature trailer to the binary.
//!
//! Two signing modes:
//!   - **YubiKey** (default): Signs via the OpenPGP smart card interface.
//!     The private key lives on the YubiKey and never touches host memory.
//!   - **Seed**: Signs via a deterministic Ed25519 keypair. For CI/testing only.
//!
//! Trailer format: [Ed25519 signature: 64 bytes][magic: "ARCSIG\x01\x00"]
//! The signature covers all original bytes (everything before the trailer).
//!
//! Bootstrap pubkey file format (CKEY v1, Ed25519 = 40 bytes total):
//!   [0..4]  = magic "CKEY"
//!   [4]     = version byte (currently 1)
//!   [5]     = algorithm byte (0 = Ed25519)
//!   [6..8]  = AID prefix = blake3(key)[..2] (informational, future KERI key-id)
//!   [8..40] = Ed25519 public key bytes
//! See ADR-025 (Principal-as-AID).
//!
//! Usage:
//!   sign-elf <elf-file> [--output <path>]                  # sign via YubiKey
//!   sign-elf --seed <hex> <elf-file> [--output <path>]     # sign via seed
//!   sign-elf --print-pubkey                                # print public key (hex)
//!   sign-elf --export-pubkey <path>                        # write CKEY-headered pubkey file
//!   sign-elf --rewrap-pubkey <input> [--output <path>]     # convert raw 32-byte pubkey -> CKEY format
//!   sign-elf --pin <pin>                                   # YubiKey PIN (or env CAMBIO_SIGN_PIN)

use ed25519_compact::{KeyPair, Seed};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process;

/// ARCSIG trailer format (mirrors `src/loader/mod.rs` constants).
/// Layout: [sig: 64][prefix: "ARCSIG" 6][version: u8][algo: u8] = 72 bytes.
/// Byte 6 = trailer-format-version, byte 7 = signature-algorithm tag.
const SIGNATURE_TRAILER_PREFIX: &[u8; 6] = b"ARCSIG";
const TRAILER_VERSION_V1: u8 = 1;
const TRAILER_ALGO_ED25519: u8 = 0;
/// Backward-compat constant: equivalent to building the v1 + Ed25519 header
/// byte-for-byte (`b"ARCSIG\x01\x00"`). Kept so existing call sites that
/// emit the magic suffix in one go continue to compile; new code should
/// emit the prefix + version + algo bytes via the named constants above.
const SIGNATURE_MAGIC: &[u8; 8] = b"ARCSIG\x01\x00";

/// Bootstrap pubkey file magic ("CKEY"). See ADR-025.
const PUBKEY_FILE_MAGIC: &[u8; 4] = b"CKEY";
/// Bootstrap pubkey file format version 1.
const PUBKEY_FILE_VERSION_V1: u8 = 1;
/// Algorithm tag matching `SignatureAlgorithm::Ed25519` in the kernel.
const PUBKEY_ALGO_ED25519: u8 = 0;
/// Total file size for a v1 Ed25519 bootstrap pubkey: 8-byte header + 32-byte key.
const PUBKEY_FILE_V1_ED25519_SIZE: usize = 40;

/// Wrap a raw 32-byte Ed25519 public key in the v1 CKEY file format.
///
/// Format: [magic:4]["CKEY"] [version:1=01] [algo:1=00 Ed25519] [aid_prefix:2]
/// [key:32]. The AID prefix is `blake3(key)[..2]` — informational fingerprint
/// for boot logs and future KERI key-id lookup.
fn wrap_pubkey_v1_ed25519(pk: &[u8; 32]) -> [u8; PUBKEY_FILE_V1_ED25519_SIZE] {
    let aid_full = blake3::hash(pk);
    let aid_bytes = aid_full.as_bytes();
    let mut out = [0u8; PUBKEY_FILE_V1_ED25519_SIZE];
    out[0..4].copy_from_slice(PUBKEY_FILE_MAGIC);
    out[4] = PUBKEY_FILE_VERSION_V1;
    out[5] = PUBKEY_ALGO_ED25519;
    out[6] = aid_bytes[0];
    out[7] = aid_bytes[1];
    out[8..40].copy_from_slice(pk);
    out
}

// ============================================================================
// Argument parsing
// ============================================================================

struct Args {
    mode: SigningMode,
    action: Action,
}

enum SigningMode {
    Seed([u8; 32]),
    YubiKey { pin: Option<String> },
}

enum Action {
    SignFile {
        path: String,
        output: Option<String>,
    },
    PrintPubkey,
    ExportPubkey(String),
    /// Read a raw 32-byte Ed25519 pubkey and write the CKEY-headered v1 format.
    /// Does not require YubiKey or seed; pure file-format migration.
    RewrapPubkey { input: String, output: String },
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().collect();

    if argv.len() < 2 {
        print_usage(&argv[0]);
        process::exit(1);
    }

    let mut elf_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut seed_hex: Option<String> = None;
    let mut seed_file: Option<String> = None;
    let mut pin: Option<String> = None;
    let mut print_pubkey = false;
    let mut export_pubkey: Option<String> = None;
    let mut rewrap_pubkey: Option<String> = None;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--seed" => {
                i += 1;
                seed_hex = Some(argv.get(i).expect("--seed requires a hex argument").clone());
            }
            "--seed-file" => {
                i += 1;
                seed_file = Some(argv.get(i).expect("--seed-file requires a path").clone());
            }
            "--output" | "-o" => {
                i += 1;
                output_path = Some(argv.get(i).expect("--output requires a path").clone());
            }
            "--pin" => {
                i += 1;
                pin = Some(argv.get(i).expect("--pin requires a value").clone());
            }
            "--print-pubkey" => {
                print_pubkey = true;
            }
            "--export-pubkey" => {
                i += 1;
                export_pubkey =
                    Some(argv.get(i).expect("--export-pubkey requires a path").clone());
            }
            "--rewrap-pubkey" => {
                i += 1;
                rewrap_pubkey =
                    Some(argv.get(i).expect("--rewrap-pubkey requires a path").clone());
            }
            arg if !arg.starts_with('-') && elf_path.is_none() => {
                elf_path = Some(arg.to_string());
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                process::exit(1);
            }
        }
        i += 1;
    }

    let mode = if let Some(hex) = seed_hex {
        SigningMode::Seed(parse_hex_seed(&hex))
    } else if let Some(path) = seed_file {
        let content = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Failed to read seed file '{}': {}", path, e);
            process::exit(1);
        });
        SigningMode::Seed(parse_hex_seed(content.trim()))
    } else {
        let pin = pin.or_else(|| env::var("CAMBIO_SIGN_PIN").ok());
        SigningMode::YubiKey { pin }
    };

    let action = if let Some(input) = rewrap_pubkey {
        let output = output_path.unwrap_or_else(|| input.clone());
        Action::RewrapPubkey { input, output }
    } else if let Some(path) = export_pubkey {
        Action::ExportPubkey(path)
    } else if print_pubkey {
        Action::PrintPubkey
    } else if let Some(path) = elf_path {
        Action::SignFile {
            path,
            output: output_path,
        }
    } else {
        eprintln!("No action specified.");
        process::exit(1);
    };

    Args { mode, action }
}

fn print_usage(prog: &str) {
    eprintln!("CambiOS ELF Signing Tool v0.3.0");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  {} <elf-file> [options]               Sign via YubiKey (default)", prog);
    eprintln!("  {} --seed <hex> <elf-file> [options]   Sign via seed (CI/testing)", prog);
    eprintln!("  {} --print-pubkey [--seed <hex>]      Print public key (hex)", prog);
    eprintln!("  {} --export-pubkey <path>             Export pubkey in CKEY v1 format", prog);
    eprintln!("  {} --rewrap-pubkey <input> [-o <path>] Convert raw 32-byte pubkey to CKEY v1", prog);
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --output, -o <path>   Write signed binary to <path> (default: in-place)");
    eprintln!("  --pin <pin>           YubiKey OpenPGP PIN (or set CAMBIO_SIGN_PIN env var)");
    eprintln!("  --seed <hex>          Use seed-derived key (64 hex chars = 32 bytes)");
}

// ============================================================================
// Seed-based signing (for CI/testing)
// ============================================================================

fn seed_get_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    let kp = KeyPair::from_seed(Seed::new(*seed));
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.pk.as_ref());
    pk
}

fn seed_sign(data: &[u8], seed: &[u8; 32]) -> [u8; 64] {
    let kp = KeyPair::from_seed(Seed::new(*seed));
    let hash = blake3::hash(data);
    let sig = kp.sk.sign(hash.as_bytes(), None);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ============================================================================
// YubiKey-based signing (via OpenPGP smart card / PCSC)
// ============================================================================

fn yubikey_resolve_pin(pin: &Option<String>) -> String {
    if let Some(p) = pin {
        return p.clone();
    }
    eprint!("YubiKey OpenPGP PIN: ");
    io::stderr().flush().ok();
    rpassword::read_password().unwrap_or_else(|e| {
        eprintln!("\nFailed to read PIN: {}", e);
        process::exit(1);
    })
}

/// Read the Ed25519 public key from the YubiKey (no PIN needed).
fn yubikey_get_pubkey() -> [u8; 32] {
    let mut card = open_openpgp_card();
    let mut tx = card.transaction().unwrap_or_else(|e| {
        eprintln!("Failed to start card transaction: {}", e);
        process::exit(1);
    });

    let pk_material = tx
        .public_key_material(openpgp_card::ocard::KeyType::Signing)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read public key: {}", e);
            process::exit(1);
        });

    extract_ed25519_pubkey(&pk_material)
}

/// Sign data using the YubiKey. Retries on transient card errors.
fn yubikey_sign(data: &[u8], pin: &Option<String>) -> ([u8; 64], [u8; 32]) {
    let pin_str = yubikey_resolve_pin(pin);

    for attempt in 0..5 {
        if attempt > 0 {
            eprintln!("  Retrying ({}/5)...", attempt + 1);
            std::thread::sleep(std::time::Duration::from_millis(500 * attempt as u64));
        }

        match yubikey_sign_attempt(data, &pin_str) {
            Ok(pair) => return pair,
            Err(e) => {
                let msg = format!("{}", e);
                if msg.contains("blocked") || msg.contains("Security status") {
                    eprintln!("PIN/auth error: {}", e);
                    eprintln!("Unblock: gpg --card-edit > admin > passwd > 2");
                    process::exit(1);
                }
                if attempt < 4 {
                    eprintln!("  Card error: {}", e);
                    continue;
                }
                eprintln!("YubiKey signing failed after 5 attempts: {}", e);
                process::exit(1);
            }
        }
    }
    unreachable!()
}

fn yubikey_sign_attempt(
    data: &[u8],
    pin: &str,
) -> Result<([u8; 64], [u8; 32]), openpgp_card::Error> {
    let mut card = open_openpgp_card();
    let mut tx = card.transaction()?;

    let pk_material =
        tx.public_key_material(openpgp_card::ocard::KeyType::Signing)?;
    let pubkey = extract_ed25519_pubkey(&pk_material);

    tx.verify_user_signing_pin(secrecy::SecretString::from(pin.to_string()))?;

    // Hash the data first — send only 32 bytes to the card instead of the
    // full binary. This avoids multi-APDU chains that macOS CryptoTokenKit
    // interrupts, and is architecturally cleaner (hardware signs a hash).
    let hash = blake3::hash(data);

    let sig_bytes = tx
        .card()
        .signature_for_hash(openpgp_card::ocard::crypto::Hash::EdDSA(hash.as_bytes()))?;

    if sig_bytes.len() != 64 {
        return Err(openpgp_card::Error::InternalError(
            format!("Unexpected signature length: {}", sig_bytes.len()),
        ));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    Ok((sig, pubkey))
}

fn open_openpgp_card() -> openpgp_card::Card<openpgp_card::state::Open> {
    use card_backend_pcsc::PcscBackend;

    // Kill scdaemon to release card
    let _ = std::process::Command::new("gpgconf")
        .args(["--kill", "scdaemon"])
        .output();

    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut cards_iter = PcscBackend::cards(None).unwrap_or_else(|e| {
        eprintln!("Failed to access smart card reader: {}", e);
        process::exit(1);
    });

    let backend = loop {
        match cards_iter.next() {
            Some(Ok(b)) => break b,
            Some(Err(_)) => continue,
            None => {
                eprintln!("No smart card found. Insert your YubiKey.");
                process::exit(1);
            }
        }
    };

    openpgp_card::Card::new(backend).unwrap_or_else(|e| {
        eprintln!("Failed to open OpenPGP card: {}", e);
        process::exit(1);
    })
}

fn extract_ed25519_pubkey(
    pk: &openpgp_card::ocard::crypto::PublicKeyMaterial,
) -> [u8; 32] {
    match pk {
        openpgp_card::ocard::crypto::PublicKeyMaterial::E(ecc_pub) => {
            let raw = ecc_pub.data();
            if raw.len() != 32 {
                eprintln!("Public key is {} bytes, expected 32.", raw.len());
                process::exit(1);
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(raw);
            pk
        }
        _ => {
            eprintln!("Card signing key is not Ed25519/ECC.");
            process::exit(1);
        }
    }
}

// ============================================================================
// ELF signing
// ============================================================================

fn read_binary_for_signing(path: &str) -> Vec<u8> {
    let mut binary = fs::read(path).unwrap_or_else(|e| {
        eprintln!("Failed to read '{}': {}", path, e);
        process::exit(1);
    });

    if binary.len() >= 72 && &binary[binary.len() - 8..] == SIGNATURE_MAGIC {
        eprintln!("Binary already signed, stripping old signature...");
        binary.truncate(binary.len() - 72);
    }

    if binary.len() < 4 || &binary[..4] != b"\x7fELF" {
        eprintln!("'{}' does not appear to be an ELF binary", path);
        process::exit(1);
    }

    binary
}

fn write_signed_elf(path: &str, output: Option<&str>, original: &[u8], sig: &[u8; 64], pk: &[u8; 32]) {
    let mut binary = original.to_vec();
    binary.extend_from_slice(sig);
    // Trailer header: prefix(6) + version(1) + algo(1) = 8 bytes.
    // Mirrors src/loader/mod.rs::parse_signature_trailer dispatch.
    binary.extend_from_slice(SIGNATURE_TRAILER_PREFIX);
    binary.push(TRAILER_VERSION_V1);
    binary.push(TRAILER_ALGO_ED25519);

    let out_path = output.unwrap_or(path);
    fs::write(out_path, &binary).unwrap_or_else(|e| {
        eprintln!("Failed to write '{}': {}", out_path, e);
        process::exit(1);
    });

    eprintln!("Signed '{}' ({} bytes)", out_path, binary.len());
    eprintln!("  Public key: {}", hex_encode(pk));
    eprintln!("  Signature:  {}...", &hex_encode(&sig[..8]));
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args = parse_args();

    match (&args.mode, &args.action) {
        (SigningMode::Seed(seed), Action::PrintPubkey) => {
            println!("{}", hex_encode(&seed_get_pubkey(seed)));
        }
        (SigningMode::YubiKey { .. }, Action::PrintPubkey) => {
            let pk = yubikey_get_pubkey();
            println!("{}", hex_encode(&pk));
        }
        (SigningMode::Seed(seed), Action::ExportPubkey(path)) => {
            let pk = seed_get_pubkey(seed);
            let wrapped = wrap_pubkey_v1_ed25519(&pk);
            fs::write(path, wrapped).unwrap_or_else(|e| {
                eprintln!("Failed to write '{}': {}", path, e);
                process::exit(1);
            });
            eprintln!("Exported pubkey (CKEY v1, Ed25519, {} bytes) to '{}'",
                PUBKEY_FILE_V1_ED25519_SIZE, path);
            eprintln!("  Key:        {}", hex_encode(&pk));
            eprintln!("  AID prefix: {:02x}{:02x}", wrapped[6], wrapped[7]);
        }
        (SigningMode::YubiKey { .. }, Action::ExportPubkey(path)) => {
            let pk = yubikey_get_pubkey();
            let wrapped = wrap_pubkey_v1_ed25519(&pk);
            fs::write(path, wrapped).unwrap_or_else(|e| {
                eprintln!("Failed to write '{}': {}", path, e);
                process::exit(1);
            });
            eprintln!("Exported pubkey (CKEY v1, Ed25519, {} bytes) to '{}'",
                PUBKEY_FILE_V1_ED25519_SIZE, path);
            eprintln!("  Key:        {}", hex_encode(&pk));
            eprintln!("  AID prefix: {:02x}{:02x}", wrapped[6], wrapped[7]);
        }
        (_, Action::RewrapPubkey { input, output }) => {
            let raw = fs::read(input).unwrap_or_else(|e| {
                eprintln!("Failed to read '{}': {}", input, e);
                process::exit(1);
            });
            if raw.len() != 32 {
                eprintln!(
                    "Rewrap expects a raw 32-byte Ed25519 pubkey; '{}' is {} bytes.",
                    input,
                    raw.len()
                );
                process::exit(1);
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&raw);
            let wrapped = wrap_pubkey_v1_ed25519(&pk);
            fs::write(output, wrapped).unwrap_or_else(|e| {
                eprintln!("Failed to write '{}': {}", output, e);
                process::exit(1);
            });
            eprintln!("Rewrapped '{}' -> '{}' (CKEY v1, Ed25519, {} bytes)",
                input, output, PUBKEY_FILE_V1_ED25519_SIZE);
            eprintln!("  Key:        {}", hex_encode(&pk));
            eprintln!("  AID prefix: {:02x}{:02x}", wrapped[6], wrapped[7]);
        }
        (SigningMode::Seed(seed), Action::SignFile { path, output }) => {
            let binary = read_binary_for_signing(path);
            let sig = seed_sign(&binary, seed);
            let pk = seed_get_pubkey(seed);
            write_signed_elf(path, output.as_deref(), &binary, &sig, &pk);
        }
        (SigningMode::YubiKey { pin }, Action::SignFile { path, output }) => {
            let binary = read_binary_for_signing(path);
            let (sig, pk) = yubikey_sign(&binary, pin);
            write_signed_elf(path, output.as_deref(), &binary, &sig, &pk);
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_hex_seed(hex: &str) -> [u8; 32] {
    let hex = hex.trim();
    if hex.len() != 64 {
        eprintln!("Seed must be 64 hex characters (32 bytes), got {}", hex.len());
        process::exit(1);
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("Invalid hex at position {}", i * 2);
            process::exit(1);
        });
    }
    bytes
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
