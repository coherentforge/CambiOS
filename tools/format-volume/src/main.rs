// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS FDE volume header formatter (host-side).
//!
//! Sibling to `tools/sign-elf/` and `tools/gen-dev-piv-keys/`.
//! Writes a fresh, signed volume header to a raw disk image file
//! per ADR-032 § 4. Stream A substage A-v.e — produces the on-disk
//! artifact `fde-mount` (A-v.a) reads at boot.
//!
//! ## Inputs
//!
//! - `<disk-image>` (positional, required): path to the raw image
//!   file to overwrite at offset 0..16384.
//! - `--dpiv-secret <path>`: path to the 168-byte DPIV v1 bundle
//!   produced by `gen-dev-piv-keys`. Default:
//!   `<workspace>/user/key-store-service/dev_piv_secret.bin`.
//! - `--master-key-hex <64hex>`: optional override for the
//!   AES-256 master key. Default: 32 random bytes from
//!   `/dev/urandom`. Hex argument lets dev-loop scripts use a
//!   deterministic master key for reproducible runs.
//! - `--print-only`: do everything except write the disk image
//!   (sanity check the inputs + dump the would-be header layout).
//!
//! ## Outputs
//!
//! Writes a 16 KiB region (LBA 0..3) to `<disk-image>` at offset 0:
//!
//!   - bytes [0..432]: the signed volume header
//!       (HEADER_FIXED_PREFIX + 1 × SLOT_BYTES + SIGNATURE_BYTES
//!        = 112 + 256 + 64 = 432)
//!   - bytes [432..16384]: zero-padded to fill the reserved
//!     header extent. `SYS_READ_VOLUME_HEADER` always reads
//!     exactly 16 KiB; deterministic padding keeps the read
//!     result stable.
//!
//! Prints a summary to stderr: volume_uuid (= bootstrap AID),
//! header_length, master-key blake3 fingerprint (first 8 bytes hex
//! — never the master key itself), and the path written.
//!
//! ## Slot table layout (v1: one live-YubiKey slot)
//!
//! ```text
//!   slot[0]:
//!     slot_type   = 0x01 (YubiKey)
//!     slot_class  = 0x00 (Live)
//!     wrapped_key_len = 80
//!     slot_principal  = bootstrap AID (slot-9C pubkey from DPIV)
//!     wrapped_key:
//!       [0..32]  ephemeral_pk (fresh per format operation)
//!       [32..80] ChaCha20-Poly1305 ciphertext + tag
//! ```

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use cambios_fde_proto as proto;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

// ============================================================================
// DPIV v1 bundle layout (mirrors tools/gen-dev-piv-keys/src/main.rs)
// ============================================================================

const DPIV_MAGIC: &[u8; 4] = b"DPIV";
const DPIV_VERSION_V1: u8 = 1;
const DPIV_V1_SIZE: usize = 168;

const DPIV_OFF_ED25519_SK: usize = 8;
// DPIV_OFF_X25519_SK (= 72) intentionally omitted — format-volume
// only needs the slot-9D PUBLIC key (offset 136), because ECDH in
// this direction is `eph_sk × slot_9d_pk`. The slot-9D private key
// stays on the YubiKey (or in the SwPivBackend's memory under
// dev-piv); the host tool never sees it.
const DPIV_OFF_ED25519_PK: usize = 104;
const DPIV_OFF_X25519_PK: usize = 136;

// ============================================================================
// Disk image constants
// ============================================================================

/// HARDWARE: ADR-032 § 4 reserves LBA 0..3 (4 × 4 KiB = 16 KiB) for
/// the volume header. SYS_READ_VOLUME_HEADER reads this full extent.
const RESERVED_HEADER_BYTES: usize = 16384;

/// Default location of the DPIV bundle.
const DEFAULT_DPIV_RELATIVE: &str = "user/key-store-service/dev_piv_secret.bin";

// ============================================================================
// CLI
// ============================================================================

struct Args {
    disk_image: PathBuf,
    dpiv_secret: Option<PathBuf>,
    master_key_hex: Option<String>,
    print_only: bool,
}

fn print_usage(prog: &str) {
    eprintln!("Usage: {} <disk-image> [options]", prog);
    eprintln!();
    eprintln!("Writes a fresh signed CambiOS FDE volume header per ADR-032 § 4");
    eprintln!("to bytes 0..16384 of <disk-image>.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --dpiv-secret <path>     Path to DPIV bundle. Default:");
    eprintln!("                           <workspace>/{DEFAULT_DPIV_RELATIVE}");
    eprintln!("  --master-key-hex <hex>   Override master key (64 hex chars = 32 bytes).");
    eprintln!("                           Default: read 32 bytes from /dev/urandom.");
    eprintln!("  --print-only             Do everything except write the disk image.");
    eprintln!("  -h, --help               Show this help.");
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().collect();
    let prog = argv.first().cloned().unwrap_or_else(|| "format-volume".to_string());

    let mut disk_image: Option<PathBuf> = None;
    let mut dpiv_secret: Option<PathBuf> = None;
    let mut master_key_hex: Option<String> = None;
    let mut print_only = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-h" | "--help" => {
                print_usage(&prog);
                process::exit(0);
            }
            "--dpiv-secret" => {
                i += 1;
                dpiv_secret = Some(PathBuf::from(
                    argv.get(i).expect("--dpiv-secret requires a path"),
                ));
            }
            "--master-key-hex" => {
                i += 1;
                master_key_hex = Some(argv.get(i).expect("--master-key-hex requires hex").clone());
            }
            "--print-only" => print_only = true,
            other if !other.starts_with("--") && disk_image.is_none() => {
                disk_image = Some(PathBuf::from(other));
            }
            other => {
                eprintln!("unknown argument: {}", other);
                print_usage(&prog);
                process::exit(1);
            }
        }
        i += 1;
    }

    let disk_image = match disk_image {
        Some(p) => p,
        None => {
            eprintln!("error: <disk-image> is required");
            print_usage(&prog);
            process::exit(1);
        }
    };

    Args {
        disk_image,
        dpiv_secret,
        master_key_hex,
        print_only,
    }
}

// ============================================================================
// Workspace + entropy
// ============================================================================

fn workspace_root() -> PathBuf {
    let mut cwd = env::current_dir().expect("failed to get cwd");
    loop {
        if cwd.join("Cargo.lock").is_file() && cwd.join("tools").is_dir() {
            return cwd;
        }
        if !cwd.pop() {
            eprintln!("error: could not locate workspace root from cwd; pass --dpiv-secret with an absolute path");
            process::exit(1);
        }
    }
}

/// Read exactly 32 bytes of entropy from /dev/urandom.
fn random_32() -> [u8; 32] {
    let mut f = fs::File::open("/dev/urandom").expect("open /dev/urandom");
    let mut out = [0u8; 32];
    f.read_exact(&mut out).expect("read 32 bytes from /dev/urandom");
    out
}

fn parse_hex_32(hex: &str) -> [u8; 32] {
    if hex.len() != 64 {
        eprintln!("error: --master-key-hex must be exactly 64 hex chars (32 bytes); got {}", hex.len());
        process::exit(1);
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("error: --master-key-hex contains non-hex char at index {}", i * 2);
            process::exit(1);
        });
        out[i] = byte;
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ============================================================================
// DPIV bundle parse
// ============================================================================

struct DpivKeys {
    ed25519_sk: [u8; 64],
    ed25519_pk: [u8; 32],
    x25519_pk: [u8; 32],
}

fn load_dpiv_bundle(path: &Path) -> DpivKeys {
    let bytes = fs::read(path).unwrap_or_else(|e| {
        eprintln!("error: failed to read DPIV bundle at {}: {}", path.display(), e);
        eprintln!("hint: run `make gen-dev-piv-keys` first.");
        process::exit(1);
    });
    if bytes.len() != DPIV_V1_SIZE {
        eprintln!("error: DPIV bundle wrong size: expected {} got {}", DPIV_V1_SIZE, bytes.len());
        process::exit(1);
    }
    if &bytes[0..4] != DPIV_MAGIC {
        eprintln!("error: DPIV bundle has wrong magic (not 'DPIV')");
        process::exit(1);
    }
    if bytes[4] != DPIV_VERSION_V1 {
        eprintln!("error: DPIV bundle version {} != 1", bytes[4]);
        process::exit(1);
    }
    let mut ed25519_sk = [0u8; 64];
    ed25519_sk.copy_from_slice(&bytes[DPIV_OFF_ED25519_SK..DPIV_OFF_ED25519_SK + 64]);
    let mut ed25519_pk = [0u8; 32];
    ed25519_pk.copy_from_slice(&bytes[DPIV_OFF_ED25519_PK..DPIV_OFF_ED25519_PK + 32]);
    let mut x25519_pk = [0u8; 32];
    x25519_pk.copy_from_slice(&bytes[DPIV_OFF_X25519_PK..DPIV_OFF_X25519_PK + 32]);
    DpivKeys { ed25519_sk, ed25519_pk, x25519_pk }
}

// ============================================================================
// Header construction
// ============================================================================

/// Build the 432-byte signed volume header for a 1-slot YubiKey-live
/// configuration. Returns the header bytes + the master-key fingerprint
/// for the summary print.
fn build_signed_header(keys: &DpivKeys, master_key: &[u8; 32]) -> Vec<u8> {
    use proto::{
        FDE_MASTER_KEY_LEN, HEADER_FIXED_PREFIX, OFF_CIPHER_ID, OFF_FORMAT_GEN, OFF_HEADER_LEN,
        OFF_KDF_ID, OFF_MAGIC, OFF_RESERVED_FLAGS, OFF_SLOT_COUNT, OFF_SLOT_TABLE,
        OFF_VOLUME_UUID, SIGNATURE_BYTES, SLOT_BYTES, SLOT_OFF_CLASS, SLOT_OFF_PRINCIPAL,
        SLOT_OFF_TYPE, SLOT_OFF_WRAPPED_KEY, SLOT_OFF_WRAPPED_LEN, SlotClass, SlotType,
        VOLUME_MAGIC, WRAP_ENV_CIPHERTEXT_LEN, WRAP_ENV_CIPHERTEXT_OFF, WRAP_ENV_EPHEMERAL_PK_LEN,
        WRAP_ENV_EPHEMERAL_PK_OFF, WRAP_ENV_LEN, WRAP_KDF_CONTEXT, WRAP_NONCE,
    };

    const HEADER_TOTAL: usize = HEADER_FIXED_PREFIX + SLOT_BYTES + SIGNATURE_BYTES; // 432
    let mut header = vec![0u8; HEADER_TOTAL];

    // Fixed prefix.
    header[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(VOLUME_MAGIC);
    header[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
        .copy_from_slice(&(HEADER_TOTAL as u32).to_le_bytes());
    header[OFF_CIPHER_ID..OFF_CIPHER_ID + 4].copy_from_slice(&1u32.to_le_bytes()); // AES-256-XTS
    header[OFF_VOLUME_UUID..OFF_VOLUME_UUID + 32].copy_from_slice(&keys.ed25519_pk);
    header[OFF_FORMAT_GEN..OFF_FORMAT_GEN + 4].copy_from_slice(&1u32.to_le_bytes());
    header[OFF_KDF_ID..OFF_KDF_ID + 4].copy_from_slice(&1u32.to_le_bytes()); // Argon2id
    header[OFF_SLOT_COUNT..OFF_SLOT_COUNT + 4].copy_from_slice(&1u32.to_le_bytes());
    header[OFF_RESERVED_FLAGS..OFF_RESERVED_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());

    // ----------------------------------------------------------------
    // Slot 0: live-YubiKey envelope.
    // ----------------------------------------------------------------

    // 1. Generate ephemeral X25519 keypair via Ed25519→X25519
    //    conversion (matches the gen-dev-piv-keys pattern).
    let eph_ed_seed_bytes = random_32();
    let eph_ed_keypair = ed25519_compact::KeyPair::from_seed(
        ed25519_compact::Seed::new(eph_ed_seed_bytes),
    );
    let eph_x_keypair =
        ed25519_compact::x25519::KeyPair::from_ed25519(&eph_ed_keypair).expect("eph X25519");
    let mut eph_pk = [0u8; 32];
    eph_pk.copy_from_slice(eph_x_keypair.pk.as_ref());

    // 2. Compute ECDH shared secret against the slot-9D pubkey.
    //    `pk.dh(&sk)` in ed25519-compact computes X25519 scalar
    //    multiplication: same shared secret either party derives.
    let slot_9d_pk = ed25519_compact::x25519::PublicKey::from_slice(&keys.x25519_pk)
        .expect("slot 9D pk");
    let shared = slot_9d_pk.dh(&eph_x_keypair.sk).expect("ECDH");

    // 3. Derive symmetric key via Blake3.
    let symm_key: [u8; 32] = blake3::derive_key(WRAP_KDF_CONTEXT, shared.as_ref());

    // 4. ChaCha20-Poly1305 encrypt the master key.
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&symm_key));
    let nonce = Nonce::from_slice(&WRAP_NONCE);
    let mut ciphertext = master_key.to_vec();
    let tag: Tag = cipher
        .encrypt_in_place_detached(nonce, &[], &mut ciphertext)
        .expect("ChaCha20-Poly1305 encrypt");
    assert_eq!(ciphertext.len(), FDE_MASTER_KEY_LEN);
    assert_eq!(tag.len(), 16);

    // 5. Build the slot bytes.
    let slot_base = OFF_SLOT_TABLE;
    header[slot_base + SLOT_OFF_TYPE] = SlotType::YubiKey as u8;
    header[slot_base + SLOT_OFF_CLASS] = SlotClass::Live as u8;
    header[slot_base + SLOT_OFF_WRAPPED_LEN..slot_base + SLOT_OFF_WRAPPED_LEN + 2]
        .copy_from_slice(&(WRAP_ENV_LEN as u16).to_le_bytes());
    header[slot_base + SLOT_OFF_PRINCIPAL..slot_base + SLOT_OFF_PRINCIPAL + 32]
        .copy_from_slice(&keys.ed25519_pk);

    // Envelope: ephemeral pubkey + ciphertext + tag.
    let env_base = slot_base + SLOT_OFF_WRAPPED_KEY;
    header[env_base + WRAP_ENV_EPHEMERAL_PK_OFF
        ..env_base + WRAP_ENV_EPHEMERAL_PK_OFF + WRAP_ENV_EPHEMERAL_PK_LEN]
        .copy_from_slice(&eph_pk);
    header[env_base + WRAP_ENV_CIPHERTEXT_OFF
        ..env_base + WRAP_ENV_CIPHERTEXT_OFF + FDE_MASTER_KEY_LEN]
        .copy_from_slice(&ciphertext);
    header[env_base + WRAP_ENV_CIPHERTEXT_OFF + FDE_MASTER_KEY_LEN
        ..env_base + WRAP_ENV_CIPHERTEXT_OFF + WRAP_ENV_CIPHERTEXT_LEN]
        .copy_from_slice(tag.as_ref());

    // ----------------------------------------------------------------
    // Signature over [0..HEADER_TOTAL-64] under slot-9C Ed25519.
    // ----------------------------------------------------------------

    let sig_offset = HEADER_TOTAL - SIGNATURE_BYTES;
    let signing_key = ed25519_compact::SecretKey::from_slice(&keys.ed25519_sk)
        .expect("slot 9C sk parse");
    let sig = signing_key.sign(&header[..sig_offset], None);
    header[sig_offset..HEADER_TOTAL].copy_from_slice(sig.as_ref());

    header
}

// ============================================================================
// Disk image write
// ============================================================================

fn write_disk_image(path: &Path, header_bytes: &[u8]) {
    let mut buf = vec![0u8; RESERVED_HEADER_BYTES];
    buf[..header_bytes.len()].copy_from_slice(header_bytes);

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to open {} for writing: {}", path.display(), e);
            process::exit(1);
        });
    file.write_all(&buf).unwrap_or_else(|e| {
        eprintln!("error: failed to write header to {}: {}", path.display(), e);
        process::exit(1);
    });
    file.sync_all().ok();
}

// ============================================================================
// main
// ============================================================================

fn main() {
    let args = parse_args();

    let dpiv_path = args.dpiv_secret.clone().unwrap_or_else(|| {
        workspace_root().join(DEFAULT_DPIV_RELATIVE)
    });
    let dpiv = load_dpiv_bundle(&dpiv_path);

    let master_key = match &args.master_key_hex {
        Some(hex) => parse_hex_32(hex),
        None => random_32(),
    };

    let header = build_signed_header(&dpiv, &master_key);

    // Master-key fingerprint for the summary — Blake3 hash of the
    // master key, first 8 bytes hex. Never the master key itself.
    let mk_fingerprint = blake3::hash(&master_key);
    let mk_fp_short = &mk_fingerprint.as_bytes()[..8];

    eprintln!("Volume header summary:");
    eprintln!("  volume_uuid (= bootstrap AID, slot-9C pubkey):");
    eprintln!("    {}", hex_encode(&dpiv.ed25519_pk));
    eprintln!("  header_length: {} bytes", header.len());
    eprintln!("  slot_count:    1 (live YubiKey)");
    eprintln!("  cipher_id:     0x01 (AES-256-XTS)");
    eprintln!("  kdf_id:        0x01 (Argon2id, unused at slot 0)");
    eprintln!("  master_key blake3 fingerprint (first 8 bytes): {}", hex_encode(mk_fp_short));

    if args.print_only {
        eprintln!();
        eprintln!("--print-only: skipping disk image write.");
        return;
    }

    write_disk_image(&args.disk_image, &header);

    // Self-verification: round-trip the just-written header through
    // the same proto-crate parser fde-mount uses. Catches "did the
    // writer's byte layout match the spec" bugs at format time
    // rather than at first-boot.
    verify_written_header(&args.disk_image, &dpiv.ed25519_pk);

    eprintln!();
    eprintln!("Wrote {} bytes ({} byte header + zero padding) to:", RESERVED_HEADER_BYTES, header.len());
    eprintln!("  {}", args.disk_image.display());
    eprintln!("Self-verification: PASS (parse + slot table + envelope shape).");
}

fn verify_written_header(disk_image: &Path, expected_volume_uuid: &[u8; 32]) {
    let bytes = fs::read(disk_image).expect("read back disk image");
    if bytes.len() < RESERVED_HEADER_BYTES {
        eprintln!("error (self-verify): disk image too small after write");
        process::exit(1);
    }

    let header = proto::parse(&bytes[..RESERVED_HEADER_BYTES]).unwrap_or_else(|e| {
        eprintln!("error (self-verify): proto::parse failed: {:?}", e);
        process::exit(1);
    });

    if &header.volume_uuid != expected_volume_uuid {
        eprintln!("error (self-verify): volume_uuid mismatch");
        process::exit(1);
    }
    if header.slot_count != 1 {
        eprintln!("error (self-verify): slot_count = {} (expected 1)", header.slot_count);
        process::exit(1);
    }

    let slots = proto::parse_slot_table(&bytes[..RESERVED_HEADER_BYTES], header.slot_count as usize)
        .unwrap_or_else(|e| {
            eprintln!("error (self-verify): parse_slot_table failed: {:?}", e);
            process::exit(1);
        });
    let live = proto::find_first_live_yubikey(&slots).unwrap_or_else(|| {
        eprintln!("error (self-verify): no live YubiKey slot in written table");
        process::exit(1);
    });
    let envelope = live.wrapped_key_bytes();
    if envelope.len() != proto::WRAP_ENV_LEN {
        eprintln!(
            "error (self-verify): envelope length {} != WRAP_ENV_LEN {}",
            envelope.len(),
            proto::WRAP_ENV_LEN,
        );
        process::exit(1);
    }
    // Note: signature verification requires the Ed25519 public key
    // and verification logic — we don't repeat that here. fde-mount
    // calls SYS_VERIFY_VOLUME_HEADER at runtime; the parse +
    // slot-shape check above is the local invariant.
}
