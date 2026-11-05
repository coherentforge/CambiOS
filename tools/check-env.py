#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""
check-env: what this machine has, and lacks, for working on CambiOS.

Three tiers, each named by the make targets it gates:

  needed  `make check-all`, `make test`, `make check-clippy` and the
          commit hooks. A missing item here is the exit code.
  image   building boot images and booting them under QEMU
          (`make iso`, `make run-quiet`, `make run-aarch64`, ...).
  extra   proofs (`make verify-all`) and fuzzing (`make fuzz-build`).

Nothing here installs anything, and nothing here starts a toolchain
download: the pinned toolchain is looked up with `rustup toolchain list`,
and cargo / rustc are only run once it is known to be installed.

The architecture list, the triples, the Limine pin and the firmware
lookup are read from the Makefile (tools/_lists.py), so this report
cannot disagree with the build about what the build needs.

Exit status:
  0  every `needed` item is present
  1  a `needed` item is missing
  2  the lists could not be read (not a checkout, or the Makefile does
     not parse)
"""

import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    print(f"check-env: Python {platform.python_version()} is too old; the lints "
          "need 3.11 or newer (tomllib).", file=sys.stderr)
    sys.exit(1)

import tomllib  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lists  # noqa: E402

ROOT = _lists.ROOT
IS_MAC = sys.platform == "darwin"

missing_needed = 0


def run(*cmd, cwd=ROOT):
    """(exit status, stdout + stderr) of a command; (127, "") if absent."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return p.returncode, (p.stdout + p.stderr).strip()


def ok(what, detail=""):
    print(f"  ok       {what}" + (f"  ({detail})" if detail else ""))


def missing(tier, what, gates, fix):
    """Report an absent item. Only the `needed` tier affects the exit code."""
    global missing_needed
    if tier == "needed":
        missing_needed += 1
    label = "MISSING" if tier == "needed" else "absent "
    print(f"  {label}  {what}: {gates}")
    print(f"           -> {fix}")


def pkg(mac, linux):
    return f"brew install {mac}" if IS_MAC else f"install the `{linux}` package (Debian/Ubuntu name)"


def tool(tier, name, gates, fix, version_arg="--version"):
    path = shutil.which(name)
    if not path:
        missing(tier, name, gates, fix)
        return False
    _, out = run(name, version_arg) if version_arg else (0, "")
    first = out.splitlines()[0] if out else ""
    ok(name, first[:70])
    return True


def main():
    try:
        arch_list = _lists.arches()
        triples = _lists.per_arch("TRIPLE", arch_list)
        pins = _lists.make_vars("LIMINE_DIR", "LIMINE_COMMIT", "ELF_LINK_TARGET")
    except _lists.ListError as e:
        print(f"check-env: {e}", file=sys.stderr)
        return 2
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]

    print("needed: make check-all, make test, make check-clippy, the commit hooks")
    ok("python", platform.python_version())
    tool("needed", "make", "every target", pkg("make", "make"))
    tool("needed", "git", "the lints index repository files through git", pkg("git", "git"))
    tool("needed", "cc", "linking the host unit tests and host tools",
         "xcode-select --install" if IS_MAC else "install the `gcc` and `libc6-dev` packages (Debian/Ubuntu names)")

    have_rustup = tool("needed", "rustup", "the pinned toolchain in rust-toolchain.toml",
                       "install from https://rustup.rs")
    toolchain = None
    if have_rustup:
        _, listed = run("rustup", "toolchain", "list")
        for line in listed.splitlines():
            if line.startswith(channel + "-"):
                toolchain = line.split()[0]
        if toolchain:
            ok("pinned toolchain", toolchain)
        else:
            missing("needed", f"toolchain {channel}", "every cargo command in this tree",
                    f"rustup toolchain install {channel}  (or run any cargo command here: rustup installs it)")

    host = test_target = None
    if toolchain:
        _, installed = run("rustup", "target", "list", "--installed", "--toolchain", toolchain)
        installed = set(installed.split())
        host = _lists.make_vars("HOST_TARGET")["HOST_TARGET"][0]
        test_target = _lists.make_vars("TEST_TARGET")["TEST_TARGET"][0]
        wanted = [(triples[a][0], f"`make check-all` ({a} kernel)") for a in arch_list]
        wanted.append((test_target, "`make test` (unit tests build for an x86_64 triple of this OS)"))
        if IS_MAC:
            wanted.append((pins["ELF_LINK_TARGET"][0], "`make test` links the unit tests as ELF on a macOS host"))
        for triple, gates in wanted:
            if triple in installed:
                ok(f"target {triple}")
            else:
                missing("needed", f"target {triple}", gates, f"rustup target add {triple}")
        _, comps = run("rustup", "component", "list", "--installed", "--toolchain", toolchain)
        if re.search(r"^clippy", comps, re.M):
            ok("clippy")
        else:
            missing("needed", "clippy", "`make check-clippy`", "rustup component add clippy")

        # Can this machine run an x86_64 test binary?
        host_arch = host.split("-")[0]
        if host_arch == "x86_64":
            ok("runs x86_64 test binaries", "native")
        elif IS_MAC:
            status, _ = run("arch", "-x86_64", "/usr/bin/true")
            if status == 0:
                ok("runs x86_64 test binaries", "Rosetta 2")
            else:
                missing("needed", "Rosetta 2", f"`make test` runs {test_target} binaries",
                        "softwareupdate --install-rosetta")
        else:
            cross = shutil.which("x86_64-linux-gnu-gcc")
            emu = any(Path(p).exists() for p in ("/proc/sys/fs/binfmt_misc/qemu-x86_64",
                                                 "/proc/sys/fs/binfmt_misc/rosetta"))
            if cross and emu:
                ok("runs x86_64 test binaries", "cross linker + binfmt emulation")
            else:
                missing("needed", "x86_64 cross linker and emulator",
                        f"`make test` builds and runs {test_target} binaries on a {host_arch} host",
                        "install `gcc-x86-64-linux-gnu` and `qemu-user-static` (Debian/Ubuntu names) "
                        "and set CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc")

    _, hooks = run("git", "config", "--get", "core.hooksPath")
    if hooks == ".githooks":
        ok("commit hooks", "core.hooksPath = .githooks")
    else:
        missing("needed", "commit hooks",
                f"core.hooksPath is {hooks or 'unset'}, so commits here skip the tracked hooks",
                "make install-hooks")

    print("\nimage: make iso, make run-quiet, make run-aarch64, make run-riscv64")
    tool("image", "xorriso", "`make iso` (x86_64)", pkg("xorriso", "xorriso"))
    for t in ("mformat", "mcopy", "mmd"):
        tool("image", t, "`make img-aarch64`, `make img-x86`", pkg("mtools", "mtools"), version_arg=None)
    tool("image", "qemu-img", "`make disk-img`", pkg("qemu", "qemu-utils"))
    qemu_pkg = {"x86_64": "qemu-system-x86", "aarch64": "qemu-system-arm", "riscv64": "qemu-system-misc"}
    for a in arch_list:
        tool("image", f"qemu-system-{a}", f"booting {a}", pkg("qemu", qemu_pkg.get(a, "qemu-system")))
    if not IS_MAC:
        status, _ = run("pkg-config", "--exists", "libpcsclite")
        if status == 0:
            ok("libpcsclite")
        else:
            missing("image", "libpcsclite", "building tools/sign-elf (its smart-card backend links it)",
                    "install the `libpcsclite-dev` and `pkg-config` packages (Debian/Ubuntu names)")
    fw = _lists.make_vars("EFI_FW_AARCH64", "EFI_FW_X86", "EFI_VARS_X86")
    for var, gates in (("EFI_FW_AARCH64", "`make run-aarch64`"),
                       ("EFI_FW_X86", "`make run-uefi`, `make run-img-x86`"),
                       ("EFI_VARS_X86", "`make run-uefi`, `make run-img-x86`")):
        if fw[var] and Path(fw[var][0]).is_file():
            ok(var, fw[var][0])
        else:
            missing("image", var, gates,
                    f"set {var} to the edk2 image (QEMU ships it; some distributions package it separately)")
    limine = Path(pins["LIMINE_DIR"][0])
    if (limine / "BOOTX64.EFI").is_file():
        _, at = run("git", "rev-parse", "HEAD", cwd=limine)
        if at == pins["LIMINE_COMMIT"][0]:
            ok("Limine cache", f"{limine} at the pinned commit")
        else:
            missing("image", "Limine cache at the pinned commit",
                    f"{limine} is at {at[:12] or 'an unknown commit'}, the build pins {pins['LIMINE_COMMIT'][0][:12]}",
                    f"rm -rf {limine}  (the next image build fetches the pinned commit)")
    else:
        ok("Limine cache", "not fetched yet; the first image build fetches the pinned commit")
    tool("image", "sgdisk", "`make img-usb` (bare-metal USB image)", pkg("gptfdisk", "gdisk"))
    tool("image", "xxd", "`SIGN_MODE=dev-piv` builds", pkg("xxd", "xxd"), version_arg=None)
    if not IS_MAC:
        print("  note     `make usb` and `make verify-usb` call diskutil and run on macOS only")

    print("\nextra: make verify-all, make fuzz-build")
    m = re.search(r'KANI_VERSION:\s*"([^"]+)"', (ROOT / ".github/workflows/proofs.yml").read_text())
    kani_pin = m.group(1) if m else None
    if shutil.which("cargo-kani"):
        _, v = run("cargo-kani", "--version")
        if kani_pin and kani_pin in v:
            ok("cargo-kani", v)
        else:
            missing("extra", f"cargo-kani {kani_pin}", f"found `{v}`; CI solves with {kani_pin}",
                    f"cargo install --locked kani-verifier@{kani_pin} && cargo kani setup")
    else:
        missing("extra", "cargo-kani", "`make verify-all` (CI runs the proofs either way)",
                f"cargo install --locked kani-verifier@{kani_pin} && cargo kani setup")
    if shutil.which("cargo-fuzz"):
        ok("cargo-fuzz")
    else:
        missing("extra", "cargo-fuzz", "`make fuzz-build`", "cargo install cargo-fuzz")

    print()
    if missing_needed:
        print(f"check-env FAILED: {missing_needed} needed item(s) missing")
        return 1
    print("check-env OK: everything `make check-all` and `make test` need is present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
