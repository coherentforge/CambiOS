#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Pre-edit audit for a single file: prints its HEAD commit, working-tree
status, and full uncommitted diff. Run before the first Edit on any
file per session (especially under parallel-thread development).

Context: file-scoped `git add <file>` does not protect against
*within-file* multi-authorship. Two sessions can both touch the same
file; when one stages `git add Makefile`, every hunk currently in the
working tree — theirs and the parallel session's — gets swept into the
commit. The failure is not noticed at staging time; it's noticed at
`git diff --cached` review time, if then.

Fourth recurrence of the working-tree-sweep family, after:
  - `git commit -a` rule (2026-04-16)
  - commit-body-from-memory rule (2026-04-20)
  - `check-banned-paths` lint (2026-04-21)
  - `check-index-isolation` lint (2026-04-21)

Per CLAUDE.md's Prompt-Shaping Changelog convention — ship tooling on
recurrence rather than tightening prose — this script is the mechanism.
It doesn't block anything; it surfaces state so the caller (Claude or
a human) can distinguish "mine" (proceed) from "parallel session"
(stop, ask the user to commit first).

Usage:
  python3 tools/claude-preflight.py <path>
  make claude-preflight FILE=<path>

Exit codes:
  0 — always (informational; NOTICE footer signals dirty state)
  1 — usage error

The script is informational, not a gate: running `make claude-preflight`
never fails. If you want to script on clean/dirty, grep stdout for
"NOTICE:" or shell out to `git diff --exit-code -- <path>` directly.

Output format on exit 2:
  === preflight: <path> ===
  --- HEAD ---
  <hash> <subject> (<age>)
  --- status ---
  <git status --short output>
  [--- staged ---]
  [<git diff --cached output>]
  [--- unstaged ---]
  [<git diff output>]
  NOTICE: uncommitted changes present …

The NOTICE footer is the editorial prompt: mine → proceed; parallel-
session → stop.
"""
import subprocess
import sys


def run(cmd: list[str]) -> tuple[int, str]:
    """Run cmd, return (exitcode, stdout). stderr is discarded — git's
    "fatal: ambiguous argument" noise on untracked paths is expected
    and handled by the caller."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: claude-preflight.py <path>", file=sys.stderr)
        return 1

    path = sys.argv[1]

    print(f"=== preflight: {path} ===")

    # HEAD commit that last touched the file, if any.
    print("--- HEAD ---")
    rc, head_log = run(["git", "log", "-1", "--format=%h %s (%cr)", "--", path])
    if rc == 0 and head_log.strip():
        print(head_log.rstrip())
    else:
        print("(untracked or never committed)")

    # Working-tree status for the file.
    print()
    print("--- status ---")
    _, status_out = run(["git", "status", "--short", "--", path])
    if not status_out.strip():
        print("(clean)")
        return 0
    print(status_out.rstrip())

    # Staged + unstaged diffs.
    _, staged = run(["git", "diff", "--cached", "--", path])
    _, unstaged = run(["git", "diff", "--", path])

    if staged.strip():
        print()
        print("--- staged ---")
        print(staged.rstrip())
    if unstaged.strip():
        print()
        print("--- unstaged ---")
        print(unstaged.rstrip())

    print()
    print(f"NOTICE: {path} has uncommitted changes.")
    print("  - Mine (this session): proceed.")
    print("  - Parallel session / unknown origin: STOP. Ask the user to")
    print("    commit those first, or pick a different file/approach.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
