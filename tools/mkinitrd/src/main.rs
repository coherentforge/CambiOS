// Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

//! mkinitrd — build a CambiOS initrd archive for the RISC-V boot path.
//!
//! Format is documented in `src/boot/initrd.rs` of the kernel; this
//! tool writes bytes that the kernel-side parser accepts.
//!
//! Usage:
//!   mkinitrd --out initrd.img --module name1=path1 [--module name2=path2 ...]
//!
//! `name` is what the kernel's `SYS_SPAWN` handler will match against.
//! It mirrors the stripped Limine module name on x86_64/aarch64 so a
//! single boot-module roster works across arches. Names may be up to
//! 64 bytes; files up to 4 GiB.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const ARCHIVE_MAGIC: &[u8; 8] = b"CAMBINIT";
const ARCHIVE_VERSION: u32 = 1;
const MAX_NAME_LEN: usize = 64;

struct Module {
    name: String,
    path: PathBuf,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mut out_path: Option<PathBuf> = None;
    let mut modules: Vec<Module> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                if i >= args.len() {
                    return usage("--out requires a path");
                }
                out_path = Some(PathBuf::from(&args[i]));
            }
            "--module" => {
                i += 1;
                if i >= args.len() {
                    return usage("--module requires name=path");
                }
                let spec = &args[i];
                let Some(eq_pos) = spec.find('=') else {
                    return usage("--module value must be name=path");
                };
                let (name, path) = spec.split_at(eq_pos);
                let path = &path[1..];
                if name.is_empty() || path.is_empty() {
                    return usage("--module: empty name or path");
                }
                if name.len() > MAX_NAME_LEN {
                    eprintln!("module name '{}' exceeds {} bytes", name, MAX_NAME_LEN);
                    return ExitCode::from(2);
                }
                modules.push(Module {
                    name: name.to_string(),
                    path: PathBuf::from(path),
                });
            }
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => {
                return usage(&format!("unknown flag: {}", other));
            }
        }
        i += 1;
    }

    let Some(out_path) = out_path else {
        return usage("--out is required");
    };

    match build_archive(&out_path, &modules) {
        Ok(()) => {
            eprintln!(
                "mkinitrd: wrote {} module(s) to {}",
                modules.len(),
                out_path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mkinitrd: {}", e);
            ExitCode::from(1)
        }
    }
}

fn build_archive(out_path: &PathBuf, modules: &[Module]) -> io::Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(ARCHIVE_MAGIC);
    buf.extend_from_slice(&ARCHIVE_VERSION.to_le_bytes());
    buf.extend_from_slice(&(modules.len() as u32).to_le_bytes());

    for m in modules {
        let data = fs::read(&m.path)?;
        let data_size = u32::try_from(data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("module '{}' > 4 GiB", m.name),
            )
        })?;
        buf.extend_from_slice(&data_size.to_le_bytes());
        buf.extend_from_slice(&(m.name.len() as u32).to_le_bytes());

        let mut name_field = [0u8; MAX_NAME_LEN];
        name_field[..m.name.len()].copy_from_slice(m.name.as_bytes());
        buf.extend_from_slice(&name_field);

        buf.extend_from_slice(&data);

        while buf.len() % 8 != 0 {
            buf.push(0);
        }
    }

    let mut f = fs::File::create(out_path)?;
    f.write_all(&buf)?;
    Ok(())
}

fn print_usage() {
    eprintln!(
        "mkinitrd --out <path> --module name1=path1 [--module name2=path2 ...]\n\n\
         Writes a CambiOS initrd archive (magic CAMBINIT, version 1) that\n\
         the RISC-V boot path parses to populate BootInfo.modules."
    );
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("mkinitrd: {}\n", msg);
    print_usage();
    ExitCode::from(2)
}
