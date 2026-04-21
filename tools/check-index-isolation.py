#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Reject commits that bundle a structural STATUS.md change with source code.

Context: STATUS.md is a load-bearing index file edited by two distinct
concerns:
  (a) small Post-Change Review Step 8 updates that keep a subsystem row
      in sync with a code change — bundling with code is correct;
  (b) structural rewrites of the file itself — bundling with code
      produces un-bisectable commits and guarantees merge conflicts when
      parallel sessions both touch STATUS.md concurrently.

The 2026-04-21 Tree v0 incident bundled ~320 lines of STATUS.md
restructuring into a 13-file feature commit, which had to be soft-reset
and split by hand. This lint codifies the split rule so the same
incident can't recur silently.

Rule: if STATUS.md has more than THRESHOLD_LINES of diff (additions +
removals) AND any `*.rs` file is also staged, reject.

Passes:
  - Small STATUS.md row update (< THRESHOLD_LINES) + code  → Step 8 bundle
  - Large STATUS.md restructure + no code                  → solo doc commit
  - STATUS.md + docs/config only (no .rs)                  → docs commit

Blocks:
  - Large STATUS.md restructure + any .rs                  → today's bug

Threshold = 20 lines (add + remove). Typical Step 8 row update is 1-5
lines; new Recent-landings entry is 2-4 lines; multiple simultaneous
small updates might hit 10-15. Structural rewrites are 50+. 20 gives
comfortable headroom both directions.

Escape hatch: none intentional. If genuinely needed, unstage STATUS.md,
commit the code, then commit STATUS.md separately. The point of the
lint is to make that split the path of least resistance.
"""
import subprocess
import sys

THRESHOLD_LINES = 20
INDEX_FILE = "STATUS.md"


def staged_numstat() -> list[tuple[int, int, str]]:
    """Return (added, removed, path) for each staged file. Binary files
    reported as ('-', '-', path) are yielded with zeros — they don't
    affect this lint."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--numstat"],
        capture_output=True,
        text=True,
        check=True,
    )
    out = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        added, removed, path = parts[0], parts[1], parts[2]
        try:
            a = int(added) if added != "-" else 0
            r = int(removed) if removed != "-" else 0
        except ValueError:
            continue
        out.append((a, r, path))
    return out


def main() -> int:
    entries = staged_numstat()

    status_change = 0
    rust_files: list[str] = []

    for added, removed, path in entries:
        if path == INDEX_FILE:
            status_change = added + removed
        elif path.endswith(".rs"):
            rust_files.append(path)

    if status_change <= THRESHOLD_LINES:
        return 0  # Small or no STATUS.md change; bundling is fine.

    if not rust_files:
        return 0  # Large STATUS.md change, but no code. Solo restructure is fine.

    # Violation: large STATUS.md change bundled with source code.
    print(
        f"ERROR: {INDEX_FILE} has {status_change} line(s) of diff "
        f"(threshold {THRESHOLD_LINES})",
        file=sys.stderr,
    )
    print(
        f"AND the commit also stages {len(rust_files)} Rust source file(s).",
        file=sys.stderr,
    )
    print(file=sys.stderr)
    print(
        f"{INDEX_FILE} is a load-bearing index file. Bundling a structural",
        file=sys.stderr,
    )
    print(
        "rewrite of it with code changes produces un-bisectable commits",
        file=sys.stderr,
    )
    print(
        "and guarantees merge conflicts when parallel sessions both touch",
        file=sys.stderr,
    )
    print("it concurrently.", file=sys.stderr)
    print(file=sys.stderr)
    print(
        f"Small Post-Change Review Step 8 row updates (≤ {THRESHOLD_LINES} lines)",
        file=sys.stderr,
    )
    print(
        "pass this lint — bundle those with code as normal.",
        file=sys.stderr,
    )
    print(file=sys.stderr)
    print("Staged Rust files (up to 10 shown):", file=sys.stderr)
    for f in rust_files[:10]:
        print(f"  {f}", file=sys.stderr)
    if len(rust_files) > 10:
        print(f"  ... and {len(rust_files) - 10} more", file=sys.stderr)
    print(file=sys.stderr)
    print("Fix: split into two commits.", file=sys.stderr)
    print(f"  git restore --staged {INDEX_FILE}   # unstage {INDEX_FILE}", file=sys.stderr)
    print("  git commit                           # code commit", file=sys.stderr)
    print(f"  git add {INDEX_FILE} && git commit  # {INDEX_FILE} commit", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
