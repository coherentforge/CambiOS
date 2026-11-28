#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""
Pre-commit: compile every Kani proof crate whose inputs this commit
touches (`cargo kani --only-codegen`: harnesses included, no solver).

Why: a proof crate includes one kernel file with `#[path]` and supplies
stand-ins for every name outside it. When the kernel file starts using a
new name, the proof crate stops compiling, and nothing on the developer's
machine notices: CI's kani-codegen job failed on every push from
2026-11-24 (userslice-proofs, after the user-copy permission fix) and
from 2026-09-15 (capability-proofs, after `revoke` lost a parameter).
This is the local twin of that job, run only where it can fail.

A proof crate verification/<name>/ has as inputs:
  - every file under its own directory;
  - every file it includes with `#[path = "..."]`, resolved against the
    directory of the file that holds the attribute;
  - every file under a path dependency named in its Cargo.toml.
(An included kernel file that declared `mod child;` would make `child`
an input too; none does, and the codegen in CI still covers it.)

Behavior:
  - Hook mode (no argument): the staged paths (`git diff --cached
    --name-only`). Each crate with a staged input is compiled; any
    failure prints cargo's error and exits 1.
  - `--all` (`make check-proof-codegen`): every crate.
  - Kani not installed (`cargo-kani` not on PATH): a warning, exit 0.
    CI's kani-codegen job still gates the push.

Bypass: none intended; fix the stand-ins. `git commit --no-verify` skips
every hook and is not used on this repository.
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    print("check-proof-codegen: needs Python 3.11 or newer (tomllib)", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parent.parent
VERIFICATION = ROOT / "verification"

PATH_ATTR = re.compile(r'^\s*#\[path\s*=\s*"([^"]+)"\]', re.MULTILINE)
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")

# Lines of cargo's output shown for a failing crate.
TAIL_LINES = 40


def path_attrs(source: str) -> list:
    """The targets of every `#[path = "..."]` attribute in `source`."""
    return PATH_ATTR.findall(source)


def path_deps(cargo_toml: str) -> list:
    """The `path` of every path dependency in a Cargo.toml, including
    target-specific tables. Not `[lib] path`, which names a source file."""
    data = tomllib.loads(cargo_toml)
    tables = [data.get(t, {}) for t in DEP_TABLES]
    for target in data.get("target", {}).values():
        tables += [target.get(t, {}) for t in DEP_TABLES]
    return [spec["path"] for table in tables for spec in table.values()
            if isinstance(spec, dict) and "path" in spec]


def rel(p: Path, root: Path) -> str:
    return p.resolve().relative_to(root.resolve()).as_posix()


def crate_inputs(crate: Path, root: Path):
    """(files, directory prefixes) that are this proof crate's inputs,
    as repository-relative POSIX paths. Directory prefixes end in '/'."""
    files = set()
    prefixes = {rel(crate, root) + "/"}
    for src in sorted((crate / "src").rglob("*.rs")):
        for target in path_attrs(src.read_text(encoding="utf-8")):
            files.add(rel(src.parent / target, root))
    toml = crate / "Cargo.toml"
    if toml.exists():
        for dep in path_deps(toml.read_text(encoding="utf-8")):
            prefixes.add(rel(crate / dep, root) + "/")
    return files, prefixes


def touches(inputs, staged) -> bool:
    files, prefixes = inputs
    return any(s in files or any(s.startswith(p) for p in prefixes) for s in staged)


def proof_crates(verification: Path) -> list:
    return sorted(p.parent for p in verification.glob("*-proofs/Cargo.toml"))


def staged_paths() -> list:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def codegen(crate: Path) -> bool:
    result = subprocess.run(
        ["cargo", "kani", "--only-codegen"],
        cwd=crate, capture_output=True, text=True,
    )
    if result.returncode == 0:
        return True
    lines = (result.stdout + result.stderr).splitlines()
    print(f"check-proof-codegen: {rel(crate, ROOT)} does not compile under Kani:", file=sys.stderr)
    for line in lines[-TAIL_LINES:]:
        print(f"  {line}", file=sys.stderr)
    return False


def main(argv) -> int:
    crates = proof_crates(VERIFICATION)
    if "--all" in argv:
        selected = crates
    else:
        staged = staged_paths()
        selected = [c for c in crates if touches(crate_inputs(c, ROOT), staged)]
    if not selected:
        return 0
    names = ", ".join(c.name for c in selected)
    if shutil.which("cargo-kani") is None:
        print(f"check-proof-codegen: WARNING: Kani is not installed, so {names} "
              "went unchecked here; CI's kani-codegen job will compile them.", file=sys.stderr)
        return 0
    failed = [c for c in selected if not codegen(c)]
    if failed:
        print("check-proof-codegen: fix the proof crate's stand-ins for the names the "
              "included kernel file now uses (verification/CLAIMS.md maps the claims).",
              file=sys.stderr)
        return 1
    print(f"check-proof-codegen OK: {names} compile under Kani")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
