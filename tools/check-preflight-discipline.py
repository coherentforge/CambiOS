#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Reject Claude-authored commits that stage a file which was already
dirty at the start of the current Claude session AND was never
preflighted by this session.

Closes the gap that produced the 6th working-tree-sweep recurrence:
H1 (`tools/check-claude-staged-files.py`) verifies file-list
correspondence but not per-hunk authorship. When session A edits a
file that session B already had uncommitted changes in, A's
`git add <file>` sweeps B's hunks. A's commit body claims A
authored everything in the staged diff.

The gate. For each staged file:
  - If the file appears in the session's `initial_dirty_files`
    (snapshot taken on the first preflight call this session),
  - AND the file does not appear in the session's `preflighted`
    set,
  → REJECT. The commit is almost certainly sweeping uncommitted
    work the session never inspected.

Gradual rollout: this gate only fires when both
  (a) `CLAUDE_PREFLIGHT_SESSION` is set in the committer's env, AND
  (b) a state file exists for that session.

If either is missing, emit a one-line warning to stderr and exit 0.
That keeps Jason's manual commits and any pre-adoption Claude
sessions unblocked. Once adoption is universal, remove the
warn-but-pass branches and treat unset session as a hard error.

Bypass: `git commit --no-verify` (discouraged).

Sequence in `.githooks/commit-msg`:
  1. tools/check-claude-staged-files.py — H1 (Staged files: block)
  2. tools/check-preflight-discipline.py — this script

Either one's failure rejects the commit.
"""
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: check-preflight-discipline.py <commit-msg-file>",
            file=sys.stderr,
        )
        return 2

    msg = Path(sys.argv[1]).read_text()

    # Strip git's `# …` comment lines so they don't pollute trailer
    # detection.
    msg = "\n".join(
        line for line in msg.splitlines() if not line.lstrip().startswith("#")
    )

    if "Co-Authored-By: Claude" not in msg:
        # Manual Jason commit — gate does not apply.
        return 0

    session = os.environ.get("CLAUDE_PREFLIGHT_SESSION")
    if not session:
        print(
            "NOTICE: CLAUDE_PREFLIGHT_SESSION unset; skipping preflight-"
            "discipline check.",
            file=sys.stderr,
        )
        print(
            "  Set CLAUDE_PREFLIGHT_SESSION to a unique-per-session id "
            "(e.g., uuidgen) to enable enforcement.",
            file=sys.stderr,
        )
        return 0

    repo = Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
    )
    state_path = repo / ".git" / "claude-preflight" / f"{session}.json"
    if not state_path.exists():
        print(
            f"NOTICE: no preflight state for session {session}; skipping "
            "discipline check.",
            file=sys.stderr,
        )
        print(
            "  Run `make claude-preflight FILE=<path>` before editing a "
            "file with uncommitted changes.",
            file=sys.stderr,
        )
        return 0

    try:
        state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(
            f"NOTICE: could not read preflight state ({e}); skipping check.",
            file=sys.stderr,
        )
        return 0

    initial_dirty: set[str] = set(state.get("initial_dirty_files", []))
    preflighted: set[str] = set(state.get("preflighted", {}).keys())

    staged_raw = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only"], text=True
    ).strip()
    staged: set[str] = set(staged_raw.splitlines()) if staged_raw else set()

    violations = sorted((staged & initial_dirty) - preflighted)
    if not violations:
        return 0

    print(
        "ERROR: claude-preflight discipline violation.", file=sys.stderr
    )
    print("", file=sys.stderr)
    print(
        "  These files were dirty at the start of this Claude session,",
        file=sys.stderr,
    )
    print(
        "  are now staged, and were never preflighted by this session:",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    for f in violations:
        print(f"    {f}", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "  Almost-certain cause: this session edited a file that already",
        file=sys.stderr,
    )
    print(
        "  had uncommitted changes from a parallel Claude session, and",
        file=sys.stderr,
    )
    print(
        "  `git add` swept those changes into the staged diff. The",
        file=sys.stderr,
    )
    print(
        "  resulting commit would attribute the parallel session's hunks",
        file=sys.stderr,
    )
    print(
        "  to this commit's author — the 6th-recurrence shape "
        "(commit 4d4a4ab).",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("  To recover:", file=sys.stderr)
    print(
        "    1. `git reset` to unstage everything.", file=sys.stderr
    )
    print(
        "    2. `git diff <file>` and identify which hunks are this",
        file=sys.stderr,
    )
    print(
        "       session's vs. the parallel session's.", file=sys.stderr
    )
    print(
        "    3. Either coordinate with the parallel session to commit",
        file=sys.stderr,
    )
    print(
        "       theirs first, or use `git add -p` to stage only this",
        file=sys.stderr,
    )
    print(
        "       session's hunks before re-trying the commit.",
        file=sys.stderr,
    )
    print(
        "    4. After staging, run `make claude-preflight FILE=<path>`",
        file=sys.stderr,
    )
    print(
        "       so the session records that the file was inspected.",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print(
        "  Bypass: `git commit --no-verify` (discouraged; the gate is",
        file=sys.stderr,
    )
    print(
        "  meant to be tripped, not silenced).",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
