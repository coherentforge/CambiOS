#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Pre-commit advisory: surface every new crate that this commit pulls
into Cargo.lock.

T-1 in docs/threat-model.md — supply-chain risk. CambiOS's verification
story ends at the Rust source; build scripts and proc macros run with
full host privileges before any signature is checked. The cheapest
defense is *visibility* at the moment a new crate enters the lockfile,
so the human reviewing the commit can decide whether it belongs.

Pre-CI / pre-HN posture: this is informational, not blocking. Lockfile
additions are often legitimate (`cargo update`, intentional new dep,
pulled-in transitive). Exit 0 is the right behavior; the value is in
the stderr message that prompts review. Tightening to a hard block
becomes worth it when external PRs are coming in via a forge that
runs `cargo build` automatically — for now we trust the solo author
to read the output.

# Behavior

- If `Cargo.lock` is not in the staged diff, exit 0 silently.
- If staged: parse the HEAD version and the index version, diff the
  set of `(crate-name, version)` pairs, print added entries (and
  removed entries for symmetry) to stderr.
- Exit 0 unconditionally.

Manual invocation (between commits) compares the working-tree lockfile
against HEAD instead of against the index. Useful after `cargo update`
to preview what would land if you staged.

Usage:
  python3 tools/check-lockfile-additions.py     # auto-detect mode
  make check-lockfile                            # same, via Makefile

Bypass:
  None needed — the gate doesn't block. If you want to silence the
  output entirely (e.g. CI noise), pipe stderr to /dev/null.
"""
import re
import subprocess
import sys


CRATE_RE = re.compile(
    r'^\[\[package\]\]\nname = "(?P<name>[^"]+)"\nversion = "(?P<version>[^"]+)"',
    re.MULTILINE,
)


def crates_in(text: str) -> set[tuple[str, str]]:
    """Return the set of (name, version) pairs declared in a Cargo.lock
    body. Robust against trailing whitespace and missing fields — pairs
    that don't match the expected 3-line preamble are skipped silently."""
    return {(m.group("name"), m.group("version")) for m in CRATE_RE.finditer(text)}


def git_show(ref: str) -> str | None:
    """Read the contents of a git object (e.g. `HEAD:Cargo.lock` or
    `:Cargo.lock` for the index). Returns None if the object does not
    exist (initial commit, file added in this commit, etc.)."""
    proc = subprocess.run(
        ["git", "show", ref],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def main() -> int:
    # Decide which two trees to compare.
    #   - If Cargo.lock is staged, compare HEAD vs. index.
    #   - Otherwise, compare HEAD vs. working tree (manual `make check-lockfile`).
    cached = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()

    head_text = git_show("HEAD:Cargo.lock")
    if "Cargo.lock" in cached:
        new_text = git_show(":Cargo.lock")
        mode = "staged"
    else:
        try:
            with open("Cargo.lock", "r", encoding="utf-8") as f:
                new_text = f.read()
        except FileNotFoundError:
            new_text = None
        mode = "working-tree"

    if head_text is None and new_text is None:
        return 0  # nothing to compare; no Cargo.lock anywhere

    head_set = crates_in(head_text) if head_text is not None else set()
    new_set = crates_in(new_text) if new_text is not None else set()

    added = sorted(new_set - head_set)
    removed = sorted(head_set - new_set)

    if not added and not removed:
        return 0

    print(f"NOTICE: Cargo.lock {mode} diff — review supply-chain delta.", file=sys.stderr)
    if added:
        print(f"  Added crates ({len(added)}):", file=sys.stderr)
        for name, version in added:
            print(f"    + {name} {version}", file=sys.stderr)
    if removed:
        print(f"  Removed crates ({len(removed)}):", file=sys.stderr)
        for name, version in removed:
            print(f"    - {name} {version}", file=sys.stderr)
    if added:
        print(
            "",
            file=sys.stderr,
        )
        print(
            "  Anything you didn't intentionally pull in is a supply-chain risk.",
            file=sys.stderr,
        )
        print(
            "  build.rs and proc-macro crates run with full host privileges before",
            file=sys.stderr,
        )
        print(
            "  any signature is checked. T-1 in docs/threat-model.md.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
