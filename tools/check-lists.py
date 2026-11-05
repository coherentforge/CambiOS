#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""
check-lists: every copy of a build list agrees with the Makefile.

The Makefile's "Build lists" section names the architectures (from
src/arch/), the user crates per architecture, and the proof crates (from
verification/). Other files have to repeat parts of those lists because
their formats cannot import them: the toolchain file, the cargo config,
the CI workflows, the Limine configs, the workspace exclude list, the
manifest's tags. This lint fails when one of those repeats disagrees.

What it checks:
  architectures   src/arch/mod.rs declares each backend; rust-toolchain.toml
                  installs each triple; .cargo/config.toml has a section
                  (and an existing linker script) per triple; the CI build
                  matrix and clippy job name each triple.
  user crates     every binary crate under user/ has a build rule on some
                  architecture; every listed crate exists, is named
                  cambios-<dir>, and has the linker script each of its
                  architectures uses; a directory under user/ with a
                  Cargo.toml and no source is an error.
  workspace       Cargo.toml's workspace.exclude is exactly the nested
                  packages that do not declare their own [workspace].
  boot images     limine.conf and limine-aarch64.conf load exactly the
                  staged crates, init and the manifest.
  manifest        every [[service]] names a user crate; `arch` and
                  `profile` tags use known values (an unknown tag would
                  silently drop the entry from every image).
  proof crates    the Proofs workflow's matrix is the proof-crate list; its
                  path filter is exactly the kernel files the crates
                  include with #[path]; each crate is in workspace.exclude
                  and has at least one harness.

There is no baseline. A disagreement is fixed, or the list that is wrong
is corrected; a deliberate exception lives in the Makefile lists
(UNSTAGED_<arch>) with its reason.

Deferred: checking that the manifest entries a profile resolves to are
the crates that image stages. The resolution rules live in
tools/build-manifest; repeating them here would be a second copy.
Revisit when: build-manifest can print the entries it kept for an
(arch, profile) pair; the image recipes then assert it at build time.

Exit status:
  0  every copy agrees
  1  at least one disagreement
  2  the lists could not be read (make failed, or Python < 3.11)
"""

import re
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    print("check-lists: needs Python 3.11 or newer (tomllib)", file=sys.stderr)
    sys.exit(2)

import _lists
from _lists import ROOT

PROBLEMS = []


def problem(where, text):
    PROBLEMS.append(f"  {where}: {text}")


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def toml(rel):
    return tomllib.loads(read(rel))


def same(where, what, expected, actual):
    """Report the two-way difference between an expected and an actual set."""
    expected, actual = set(expected), set(actual)
    missing, extra = sorted(expected - actual), sorted(actual - expected)
    if missing:
        problem(where, f"{what}: missing {' '.join(missing)}")
    if extra:
        problem(where, f"{what}: unexpected {' '.join(extra)}")


def check_arches(arch_list, triple):
    triples = [triple[a] for a in arch_list]

    mod = read("src/arch/mod.rs")
    for a in arch_list:
        if not re.search(r'#\[cfg\(target_arch = "%s"\)\]\s*\npub mod %s;' % (a, a), mod):
            problem("src/arch/mod.rs", f'no `#[cfg(target_arch = "{a}")] pub mod {a};` for src/arch/{a}/')

    installed = toml("rust-toolchain.toml").get("toolchain", {}).get("targets", [])
    for t in triples:
        if t not in installed:
            problem("rust-toolchain.toml", f"targets does not list {t}")

    cargo = toml(".cargo/config.toml")
    for t in triples:
        section = cargo.get("target", {}).get(t)
        if section is None:
            problem(".cargo/config.toml", f"no [target.{t}] section")
            continue
        for flag in section.get("rustflags", []):
            m = re.match(r"link-arg=--script=(.+)", flag)
            if m and not (ROOT / m.group(1)).is_file():
                problem(".cargo/config.toml", f"[target.{t}] names linker script {m.group(1)}, which does not exist")

    ci = read(".github/workflows/ci.yml")
    m = re.search(r"matrix:\s*\n\s*target:\s*\n((?:\s*- \S+\s*\n)+)", ci)
    matrix = re.findall(r"- (\S+)", m.group(1)) if m else []
    same(".github/workflows/ci.yml", "build matrix targets", triples, matrix)
    m = re.search(r"rustup target add ([^\n]+)\n\s*- uses: Swatinem/rust-cache@v2\s*\n\s*with:\s*\n\s*key: clippy", ci)
    clippy = m.group(1).split() if m else []
    same(".github/workflows/ci.yml", "clippy job `rustup target add`", triples, clippy)


def check_user_crates(arch_list, crates, link):
    listed = {c for a in arch_list for c in crates[a]}
    binaries = set()
    for d in sorted((ROOT / "user").iterdir()):
        if not (d / "Cargo.toml").is_file():
            continue
        has_main, has_lib = (d / "src" / "main.rs").is_file(), (d / "src" / "lib.rs").is_file()
        if has_main:
            binaries.add(d.name)
        elif not has_lib:
            problem(f"user/{d.name}", "has a Cargo.toml and neither src/main.rs nor src/lib.rs")
    for name in sorted(binaries - listed):
        problem(f"user/{name}", "is a binary crate with no build rule: add it to STAGE_<arch> or UNSTAGED_<arch> in the Makefile")
    for name in sorted(listed - binaries):
        problem("Makefile", f"lists {name}, but user/{name}/src/main.rs does not exist")
    for name in sorted(listed & binaries):
        pkg = toml(f"user/{name}/Cargo.toml").get("package", {}).get("name")
        if pkg != f"cambios-{name}":
            problem(f"user/{name}/Cargo.toml", f"package name is {pkg!r}; the build rule expects 'cambios-{name}'")
        for a in arch_list:
            if name in crates[a] and not (ROOT / "user" / name / link[a]).is_file():
                problem(f"user/{name}", f"is built for {a} but has no {link[a]}")


def check_workspace_exclude():
    declared = toml("Cargo.toml").get("workspace", {}).get("exclude", [])
    nested = []
    for cargo_toml in sorted(ROOT.glob("*/Cargo.toml")) + sorted(ROOT.glob("*/*/Cargo.toml")):
        rel = cargo_toml.parent.relative_to(ROOT).as_posix()
        if rel.startswith(("target", "iso_root")) or "/target" in rel:
            continue
        if "workspace" in tomllib.loads(cargo_toml.read_text(encoding="utf-8")):
            continue  # its own workspace root; cargo does not need it excluded
        nested.append(rel)
    same("Cargo.toml", "workspace.exclude", nested, declared)
    return declared


def check_boot_configs(stage):
    for conf, arch in (("limine.conf", "x86_64"), ("limine-aarch64.conf", "aarch64")):
        if arch not in stage:
            continue
        modules = re.findall(r"^\s*module_path:\s*\S*?/boot/(\S+)", read(conf), flags=re.M)
        expected = [f"{c}.elf" for c in stage[arch]] + ["init.elf", "manifest.bin"]
        same(conf, "module_path entries", expected, modules)


def check_manifest(arch_list, profiles):
    manifest = toml("manifest.toml")
    user_dirs = {d.name for d in (ROOT / "user").iterdir() if (d / "Cargo.toml").is_file()}
    for entry in manifest.get("service", []):
        name = entry.get("name", "<unnamed>")
        if name not in user_dirs:
            problem("manifest.toml", f"[[service]] {name}: no user/{name}/ crate")
        for a in entry.get("arch", []):
            if a not in arch_list:
                problem("manifest.toml", f"[[service]] {name}: arch tag {a!r} is not an architecture ({' '.join(arch_list)})")
        for p in entry.get("profile", []):
            if p not in profiles:
                problem("manifest.toml", f"[[service]] {name}: profile tag {p!r} is not a profile ({' '.join(profiles)})")


def check_proof_crates(proofs, excluded):
    wf = read(".github/workflows/proofs.yml")
    m = re.search(r"matrix:\s*\n\s*crate:\s*\n((?:\s*- \S+\s*\n)+)", wf)
    matrix = re.findall(r"- (\S+)", m.group(1)) if m else []
    same(".github/workflows/proofs.yml", "kani matrix crates", proofs, matrix)

    included = set()
    for crate in proofs:
        src = ROOT / "verification" / crate / "src"
        text = "".join(p.read_text(encoding="utf-8") for p in sorted(src.rglob("*.rs")))
        for target in re.findall(r'^\s*#\[path = "((?:\.\./)+src/[^"]+)"\]', text, flags=re.M):
            included.add(re.sub(r"^(\.\./)+", "", target))
        if not re.search(r"^\s*#\[kani::proof\]", text, flags=re.M):
            problem(f"verification/{crate}", "has no #[kani::proof] harness")
        if f"verification/{crate}" not in excluded:
            problem("Cargo.toml", f"workspace.exclude does not list verification/{crate}")
    filtered = set(re.findall(r"^\s*- '(src/[^']+)'", wf, flags=re.M))
    same(".github/workflows/proofs.yml", "path filter vs the kernel files the proof crates #[path]-include", included, filtered)

    m = re.search(r"across (\d+) proof crates", read("STATUS.md"))
    if m and int(m.group(1)) != len(proofs):
        problem("STATUS.md", f'says "across {m.group(1)} proof crates"; there are {len(proofs)}')


def main():
    try:
        arch_list = _lists.arches()
        triple = {a: v[0] if v else "" for a, v in _lists.per_arch("TRIPLE", arch_list).items()}
        link = {a: v[0] if v else "" for a, v in _lists.per_arch("USER_LINK", arch_list).items()}
        crates = _lists.per_arch("CRATES", arch_list)
        stage = _lists.per_arch("STAGE", arch_list)
        proofs = _lists.proof_crates()
        profiles = _lists.make_vars("PROFILES")["PROFILES"]
    except _lists.ListError as e:
        print(f"check-lists: {e}", file=sys.stderr)
        return 2
    if not arch_list or not proofs or not profiles:
        print("check-lists: the Makefile reported an empty ARCHES, PROOF_CRATES or PROFILES; "
              "nothing was checked", file=sys.stderr)
        return 2

    check_arches(arch_list, triple)
    check_user_crates(arch_list, crates, link)
    excluded = check_workspace_exclude()
    check_boot_configs(stage)
    check_manifest(arch_list, profiles)
    check_proof_crates(proofs, excluded)

    n_crates = len({c for a in arch_list for c in crates[a]})
    print(f"check-lists: {len(arch_list)} architectures, {n_crates} user crates, "
          f"{len(proofs)} proof crates; {len(PROBLEMS)} disagreement(s)")
    if PROBLEMS:
        print("check-lists found copies that disagree with the Makefile lists:", file=sys.stderr)
        for p in PROBLEMS:
            print(p, file=sys.stderr)
        return 1
    print("check-lists OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
