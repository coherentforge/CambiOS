//! ArcOS ELF Signing Tool
//!
//! Signs ELF binaries with an Ed25519 signature for the ArcOS kernel's
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
//! Usage:
//!   sign-elf <elf-file> [--output <path>]                  # sign via YubiKey
//!   sign-elf --seed <hex> <elf-file> [--output <path>]     # sign via seed
//!   sign-elf --print-pubkey                                # print public key (hex)
//!   sign-elf --export-pubkey <path>                        # write raw 32-byte pubkey
//!   sign-elf --pin <pin>                                   # YubiKey PIN (or env ARCOS_SIGN_PIN)

use ed25519_compact::{KeyPair, Seed};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process;

const SIGNATURE_MAGIC: &[u8; 8] = b"ARCSIG\x01\x00";

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

    // Resolve signing mode: --seed/--seed-file → Seed, otherwise → YubiKey
    let mode = if let Some(hex) = seed_hex {
        SigningMode::Seed(parse_hex_seed(&hex))
    } else if let Some(path) = seed_file {
        let content = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Failed to read seed file '{}': {}", path, e);
            process::exit(1);
        });
        SigningMode::Seed(parse_hex_seed(content.trim()))
    } else {
        // YubiKey mode — check env var for PIN
        let pin = pin.or_else(|| env::var("ARCOS_SIGN_PIN").ok());
        SigningMode::YubiKey { pin }
    };

    // Resolve action
    let action = if let Some(path) = export_pubkey {
        Action::ExportPubkey(path)
    } else if print_pubkey {
        Action::PrintPubkey
    } else if let Some(path) = elf_path {
        Action::SignFile {
            path,
            output: output_path,
        }
    } else {
        eprintln!("No action specified. Provide an ELF file, --print-pubkey, or --export-pubkey.");
        process::exit(1);
    };

    Args { mode, action }
}

fn print_usage(prog: &str) {
    eprintln!("ArcOS ELF Signing Tool v0.2.0");
    eprintln!();
    eprintln!("Usage:");
    eprintln!(
        "  {} <elf-file> [options]              Sign via YubiKey (default)",
        prog
    );
    eprintln!(
        "  {} --seed <hex> <elf-file> [options]  Sign via seed (CI/testing)",
        prog
    );
    eprintln!(
        "  {} --print-pubkey [--seed <hex>]     Print public key (hex)",
        prog
    );
    eprintln!(
        "  {} --export-pubkey <path> [--seed <hex>]  Export raw 32-byte pubkey",
        prog
    );
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --output, -o <path>   Write signed binary to <path> (default: in-place)");
    eprintln!("  --pin <pin>           YubiKey OpenPGP PIN (or set ARCOS_SIGN_PIN env var)");
    eprintln!("  --seed <hex>          Use seed-derived key (64 hex chars = 32 bytes)");
    eprintln!("  --seed-file <path>    Read seed hex from file");
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
    let sig = kp.sk.sign(data, None);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ============================================================================
// YubiKey-based signing (via OpenPGP smart card)
// ============================================================================

fn yubikey_resolve_pin(pin: &Option<String>) -> String {
    if let Some(p) = pin {
        return p.clone();
    }

    // Prompt interactively
    eprint!("YubiKey OpenPGP PIN: ");
    io::stderr().flush().ok();
    rpassword::read_password().unwrap_or_else(|e| {
        eprintln!("\nFailed to read PIN: {}", e);
        process::exit(1);
    })
}

/// Open the first available YubiKey, verify the signing PIN, and read the public key.
/// Returns (public_key, low-level access for signing).
fn yubikey_get_pubkey(pin: &Option<String>) -> [u8; 32] {
    let pin_str = yubikey_resolve_pin(pin);

    let mut card = open_openpgp_card();
    let mut tx = card.transaction().unwrap_or_else(|e| {
        eprintln!("Failed to start card transaction: {}", e);
        process::exit(1);
    });

    // Verify User Signing PIN (PW1 for signing)
    tx.verify_user_signing_pin(secrecy::SecretString::from(pin_str))
        .unwrap_or_else(|e| {
            eprintln!("PIN verification failed: {}", e);
            eprintln!("Check your YubiKey OpenPGP User PIN.");
            process::exit(1);
        });

    // Read the signing public key
    let pk_material = tx
        .public_key_material(openpgp_card::ocard::KeyType::Signing)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read public key from YubiKey: {}", e);
            eprintln!("Is an Ed25519 signing key configured on the OpenPGP applet?");
            process::exit(1);
        });

    extract_ed25519_pubkey(&pk_material)
}

/// Sign data using the YubiKey. Returns (signature, public_key).
fn yubikey_sign(data: &[u8], pin: &Option<String>) -> ([u8; 64], [u8; 32]) {
    let pin_str = yubikey_resolve_pin(pin);

    let mut card = open_openpgp_card();
    let mut tx = card.transaction().unwrap_or_else(|e| {
        eprintln!("Failed to start card transaction: {}", e);
        process::exit(1);
    });

    // Verify User Signing PIN
    tx.verify_user_signing_pin(secrecy::SecretString::from(pin_str))
        .unwrap_or_else(|e| {
            eprintln!("PIN verification failed: {}", e);
            process::exit(1);
        });

    // Read public key
    let pk_material = tx
        .public_key_material(openpgp_card::ocard::KeyType::Signing)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read public key: {}", e);
            process::exit(1);
        });
    let pubkey = extract_ed25519_pubkey(&pk_material);

    // Sign via the low-level card API
    let sig_bytes = tx
        .card()
        .signature_for_hash(openpgp_card::ocard::crypto::Hash::EdDSA(data))
        .unwrap_or_else(|e| {
            eprintln!("YubiKey signing failed: {}", e);
            if data.len() > 60_000 {
                eprintln!(
                    "Binary is {} bytes — may exceed YubiKey's buffer limit.",
                    data.len()
                );
            }
            process::exit(1);
        });

    if sig_bytes.len() != 64 {
        eprintln!(
            "Unexpected signature length: {} (expected 64)",
            sig_bytes.len()
        );
        process::exit(1);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    (sig, pubkey)
}

/// Open the first available OpenPGP smart card via PCSC.
fn open_openpgp_card() -> openpgp_card::Card<openpgp_card::state::Open> {
    use card_backend_pcsc::PcscBackend;

    let mut cards_iter = PcscBackend::cards(None).unwrap_or_else(|e| {
        eprintln!("Failed to access smart card reader: {}", e);
        eprintln!("Is pcscd running? Is the YubiKey plugged in?");
        process::exit(1);
    });

    let backend = loop {
        match cards_iter.next() {
            Some(Ok(b)) => break b,
            Some(Err(e)) => {
                eprintln!("Warning: skipping card with error: {}", e);
                continue;
            }
            None => {
                eprintln!("No smart card found. Insert your YubiKey and try again.");
                process::exit(1);
            }
        }
    };

    openpgp_card::Card::new(backend).unwrap_or_else(|e| {
        eprintln!("Failed to open OpenPGP card: {}", e);
        process::exit(1);
    })
}

/// Extract raw 32-byte Ed25519 public key from OpenPGP card public key material.
fn extract_ed25519_pubkey(
    pk: &openpgp_card::ocard::crypto::PublicKeyMaterial,
) -> [u8; 32] {
    use openpgp_card::ocard::crypto::PublicKeyMaterial;

    match pk {
        PublicKeyMaterial::E(ecc_pub) => {
            let raw = ecc_pub.data();
            if raw.len() != 32 {
                eprintln!(
                    "Public key is {} bytes, expected 32 (Ed25519). Wrong key type?",
                    raw.len()
                );
                process::exit(1);
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(raw);
            pk
        }
        _ => {
            eprintln!("Card signing key is not Ed25519/ECC. Configure an Ed25519 key.");
            eprintln!("Use: gpg --edit-key <keyid>  or  ykman openpgp keys generate sig");
            process::exit(1);
        }
    }
}

// ============================================================================
// ELF signing
// ============================================================================

/// Read an ELF binary, stripping any existing signature trailer.
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

/// Write a signed ELF file with the ARCSIG trailer appended.
fn write_signed_elf(path: &str, output: Option<&str>, original: &[u8], sig: &[u8; 64], pk: &[u8; 32]) {
    let mut binary = original.to_vec();
    binary.extend_from_slice(sig);
    binary.extend_from_slice(SIGNATURE_MAGIC);

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
        // ---- Print public key (hex) ----
        (SigningMode::Seed(seed), Action::PrintPubkey) => {
            println!("{}", hex_encode(&seed_get_pubkey(seed)));
        }
        (SigningMode::YubiKey { pin }, Action::PrintPubkey) => {
            let pk = yubikey_get_pubkey(pin);
            println!("{}", hex_encode(&pk));
        }

        // ---- Export raw public key to file ----
        (SigningMode::Seed(seed), Action::ExportPubkey(path)) => {
            let pk = seed_get_pubkey(seed);
            fs::write(path, pk).unwrap_or_else(|e| {
                eprintln!("Failed to write '{}': {}", path, e);
                process::exit(1);
            });
            eprintln!("Exported 32-byte public key to '{}'", path);
            eprintln!("  Key: {}", hex_encode(&pk));
        }
        (SigningMode::YubiKey { pin }, Action::ExportPubkey(path)) => {
            let pk = yubikey_get_pubkey(pin);
            fs::write(path, pk).unwrap_or_else(|e| {
                eprintln!("Failed to write '{}': {}", path, e);
                process::exit(1);
            });
            eprintln!("Exported 32-byte public key to '{}'", path);
            eprintln!("  Key: {}", hex_encode(&pk));
        }

        // ---- Sign ELF file ----
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
        eprintln!(
            "Seed must be 64 hex characters (32 bytes), got {}",
            hex.len()
        );
        process::exit(1);
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!(
                "Invalid hex at position {}: '{}'",
                i * 2,
                &hex[i * 2..i * 2 + 2]
            );
            process::exit(1);
        });
    }
    bytes
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
