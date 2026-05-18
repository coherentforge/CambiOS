// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS dev-PIV keypair generator (host-side).
//!
//! Derives slot-9C (Ed25519, signing) and slot-9D (X25519, key management)
//! keypairs from a persistent per-developer seed. Writes:
//!
//! 1. `<workspace>/dev_bootstrap_pubkey.bin` — 40-byte CKEY v1 file (same
//!    format `tools/sign-elf --export-pubkey` produces). The kernel picks
//!    this up when built with `--features dev-piv` (substitutes for the
//!    YubiKey-derived `bootstrap_pubkey.bin`).
//!
//! 2. `<workspace>/user/key-store-service/dev_piv_secret.bin` — 168-byte
//!    secret bundle (DPIV v1 format below). `SwPivBackend` picks this up
//!    when key-store-service is built with `--features dev-piv`.
//!
//! Both outputs are gitignored. The seed at
//! `tools/gen-dev-piv-keys/.dev-seed.bin` is also gitignored. The tool is
//! idempotent: same seed → byte-identical derived files. Fresh-clone
//! developers run `make gen-dev-piv-keys` once before `make iso`-ish flows
//! that need `--features dev-piv`.
//!
//! ## DPIV v1 secret file format (168 bytes)
//!
//! ```text
//!   [0..4]    magic = "DPIV"
//!   [4]       version = 0x01
//!   [5..8]    reserved (zero)
//!   [8..72]   slot-9C Ed25519 secret key (64 bytes, seed||pubkey per ed25519-compact)
//!   [72..104] slot-9D X25519 secret scalar (32 bytes)
//!   [104..136] slot-9C Ed25519 public key (32 bytes; informational, redundant with SK tail)
//!   [136..168] slot-9D X25519 public key (32 bytes)
//! ```
//!
//! The pubkeys are stored alongside the secrets so `SwPivBackend` can
//! answer `CMD_PIV_GET_PUBKEY` without re-deriving from the secret at every
//! query.
//!
//! ## Seed derivation
//!
//! Domain separation via blake3 with a labeled context string:
//!
//! ```text
//!   slot_9c_seed = blake3(seed || "cambios-dev-piv:slot-9c-ed25519")
//!   slot_9d_seed = blake3(seed || "cambios-dev-piv:slot-9d-x25519")
//! ```
//!
//! Different label = different secret = different pubkey. No accidental
//! key reuse across slots.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

const SEED_FILE: &str = ".dev-seed.bin";
const DEV_BOOTSTRAP_PUBKEY_FILE: &str = "dev_bootstrap_pubkey.bin";
const DEV_PIV_SECRET_FILE: &str = "dev_piv_secret.bin";
const KEY_STORE_SERVICE_DIR: &str = "user/key-store-service";

// CKEY v1 constants (must match tools/sign-elf and src/microkernel/main.rs).
const CKEY_MAGIC: &[u8; 4] = b"CKEY";
const CKEY_VERSION_V1: u8 = 1;
const CKEY_ALGO_ED25519: u8 = 0;
const CKEY_V1_ED25519_SIZE: usize = 40;

// DPIV v1 constants.
const DPIV_MAGIC: &[u8; 4] = b"DPIV";
const DPIV_VERSION_V1: u8 = 1;
const DPIV_V1_SIZE: usize = 168;

const SLOT_9C_LABEL: &[u8] = b"cambios-dev-piv:slot-9c-ed25519";
const SLOT_9D_LABEL: &[u8] = b"cambios-dev-piv:slot-9d-x25519";

fn print_usage(prog: &str) {
    eprintln!("Usage: {} [options]", prog);
    eprintln!();
    eprintln!("Generates / refreshes dev-PIV keypair files for the");
    eprintln!("`dev-piv` kernel + key-store-service feature.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --regenerate       Force a fresh seed (deletes existing .dev-seed.bin)");
    eprintln!("  --print-pubkey     Print the slot-9C bootstrap pubkey hex; no file writes");
    eprintln!("  --workspace <p>    Workspace root (default: auto-detect)");
    eprintln!("  -h, --help         Show this help");
}

fn workspace_root() -> PathBuf {
    // The tool lives at <workspace>/tools/gen-dev-piv-keys/. CARGO_MANIFEST_DIR
    // at build time would point there. At runtime (especially when invoked via
    // `cargo run`), env vars are not guaranteed — use CWD-walk as the
    // authoritative method. Walks up looking for `Cargo.lock` + `tools/`.
    let mut cwd = env::current_dir().expect("failed to get cwd");
    loop {
        if cwd.join("Cargo.lock").is_file() && cwd.join("tools").is_dir() {
            return cwd;
        }
        if !cwd.pop() {
            eprintln!("error: could not locate workspace root from cwd; pass --workspace");
            process::exit(1);
        }
    }
}

fn read_or_generate_seed(seed_path: &Path, force: bool) -> [u8; 32] {
    if force {
        let _ = fs::remove_file(seed_path);
    }
    if let Ok(bytes) = fs::read(seed_path) {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return seed;
        }
        eprintln!(
            "warning: seed file {} has wrong length ({}); regenerating",
            seed_path.display(),
            bytes.len()
        );
    }
    // Generate fresh entropy. /dev/urandom is universally available on macOS +
    // Linux; we read exactly 32 bytes (the file is unbounded so `fs::read`
    // would never return).
    use std::io::Read;
    let mut urandom = fs::File::open("/dev/urandom")
        .expect("failed to open /dev/urandom for seed entropy");
    let mut seed = [0u8; 32];
    urandom
        .read_exact(&mut seed)
        .expect("failed to read 32 bytes from /dev/urandom");
    if let Some(parent) = seed_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(seed_path, seed).unwrap_or_else(|e| {
        eprintln!("failed to write seed file {}: {}", seed_path.display(), e);
        process::exit(1);
    });
    eprintln!("Generated fresh dev seed: {}", seed_path.display());
    seed
}

fn derive_slot_seed(master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(master);
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

struct DevKeys {
    ed25519_sk: [u8; 64],
    ed25519_pk: [u8; 32],
    x25519_sk: [u8; 32],
    x25519_pk: [u8; 32],
}

fn derive_dev_keys(seed: &[u8; 32]) -> DevKeys {
    use ed25519_compact::{KeyPair, Seed};

    // Ed25519 slot 9C.
    let slot_9c_seed_bytes = derive_slot_seed(seed, SLOT_9C_LABEL);
    let ed_seed = Seed::new(slot_9c_seed_bytes);
    let ed_keypair = KeyPair::from_seed(ed_seed);
    let mut ed25519_sk = [0u8; 64];
    ed25519_sk.copy_from_slice(ed_keypair.sk.as_ref());
    let mut ed25519_pk = [0u8; 32];
    ed25519_pk.copy_from_slice(ed_keypair.pk.as_ref());

    // X25519 slot 9D. ed25519-compact's x25519 module exposes conversion
    // from Ed25519, not direct seeded construction. We derive an
    // Ed25519 keypair under SLOT_9D_LABEL and convert it; the resulting
    // X25519 secret is the clamped form of the Ed25519 secret seed.
    use ed25519_compact::x25519;
    let slot_9d_seed_bytes = derive_slot_seed(seed, SLOT_9D_LABEL);
    let ed_for_x_seed = Seed::new(slot_9d_seed_bytes);
    let ed_for_x_keypair = KeyPair::from_seed(ed_for_x_seed);
    let x_keypair = x25519::KeyPair::from_ed25519(&ed_for_x_keypair)
        .expect("Ed25519→X25519 conversion failed");
    let mut x25519_sk = [0u8; 32];
    x25519_sk.copy_from_slice(x_keypair.sk.as_ref());
    let mut x25519_pk = [0u8; 32];
    x25519_pk.copy_from_slice(x_keypair.pk.as_ref());

    DevKeys {
        ed25519_sk,
        ed25519_pk,
        x25519_sk,
        x25519_pk,
    }
}

fn build_ckey_v1(ed25519_pk: &[u8; 32]) -> [u8; CKEY_V1_ED25519_SIZE] {
    let aid_full = blake3::hash(ed25519_pk);
    let aid_bytes = aid_full.as_bytes();
    let mut out = [0u8; CKEY_V1_ED25519_SIZE];
    out[0..4].copy_from_slice(CKEY_MAGIC);
    out[4] = CKEY_VERSION_V1;
    out[5] = CKEY_ALGO_ED25519;
    out[6] = aid_bytes[0];
    out[7] = aid_bytes[1];
    out[8..40].copy_from_slice(ed25519_pk);
    out
}

fn build_dpiv_v1(keys: &DevKeys) -> [u8; DPIV_V1_SIZE] {
    let mut out = [0u8; DPIV_V1_SIZE];
    out[0..4].copy_from_slice(DPIV_MAGIC);
    out[4] = DPIV_VERSION_V1;
    // 5..8 reserved (zero)
    out[8..72].copy_from_slice(&keys.ed25519_sk);
    out[72..104].copy_from_slice(&keys.x25519_sk);
    out[104..136].copy_from_slice(&keys.ed25519_pk);
    out[136..168].copy_from_slice(&keys.x25519_pk);
    out
}

fn write_file_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let prog = argv.first().cloned().unwrap_or_else(|| "gen-dev-piv-keys".to_string());

    let mut force = false;
    let mut print_only = false;
    let mut workspace_override: Option<PathBuf> = None;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--regenerate" => force = true,
            "--print-pubkey" => print_only = true,
            "--workspace" => {
                i += 1;
                workspace_override = Some(PathBuf::from(
                    argv.get(i).expect("--workspace requires a path").as_str(),
                ));
            }
            "-h" | "--help" => {
                print_usage(&prog);
                return;
            }
            other => {
                eprintln!("unknown argument: {}", other);
                print_usage(&prog);
                process::exit(1);
            }
        }
        i += 1;
    }

    let workspace = workspace_override.unwrap_or_else(workspace_root);
    let seed_path = workspace
        .join("tools")
        .join("gen-dev-piv-keys")
        .join(SEED_FILE);
    let pubkey_path = workspace.join(DEV_BOOTSTRAP_PUBKEY_FILE);
    let secret_path = workspace.join(KEY_STORE_SERVICE_DIR).join(DEV_PIV_SECRET_FILE);

    let seed = read_or_generate_seed(&seed_path, force);
    let keys = derive_dev_keys(&seed);
    let pubkey_blob = build_ckey_v1(&keys.ed25519_pk);
    let secret_blob = build_dpiv_v1(&keys);

    if print_only {
        println!("slot 9C Ed25519 pubkey: {}", hex_encode(&keys.ed25519_pk));
        println!("slot 9D X25519  pubkey: {}", hex_encode(&keys.x25519_pk));
        println!("CKEY v1 (40 bytes):     {}", hex_encode(&pubkey_blob));
        return;
    }

    write_file_atomic(&pubkey_path, &pubkey_blob).unwrap_or_else(|e| {
        eprintln!("failed to write {}: {}", pubkey_path.display(), e);
        process::exit(1);
    });
    write_file_atomic(&secret_path, &secret_blob).unwrap_or_else(|e| {
        eprintln!("failed to write {}: {}", secret_path.display(), e);
        process::exit(1);
    });

    println!("dev-PIV keypair files written.");
    println!("  pubkey:  {} (40 bytes, CKEY v1)", pubkey_path.display());
    println!("  secret:  {} (168 bytes, DPIV v1)", secret_path.display());
    println!("  seed:    {} (32 bytes, persistent)", seed_path.display());
    println!();
    println!("Kernel must be built with `--features dev-piv` to pick up the new bootstrap pubkey.");
    println!("key-store-service must be built with `--features dev-piv` to load SwPivBackend.");
}
