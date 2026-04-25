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

# Sticky behavior (2026-04-25, post-6th recurrence)

If the env var `CLAUDE_PREFLIGHT_SESSION` is set, this script ALSO
records each invocation in a per-session state file under
`.git/claude-preflight/<session_id>.json`. The first call in a session
snapshots `git status --porcelain` (tracked files only) into
`initial_dirty_files`; subsequent calls add to `preflighted`.

The companion `tools/check-preflight-discipline.py` runs in the
commit-msg phase and rejects Claude-authored commits whose staged set
contains any file from `initial_dirty_files` that was never
preflighted by the current session — the exact shape of the 6th
recurrence (`4d4a4ab` swept session A's uncommitted F2/F3 hunks into
session B's STOMP fix because A skipped preflight on a dirty file).

Without the env var, the script's behavior is unchanged: informational
NOTICE only, exit 0. Gradual rollout: hooks warn-but-pass when
CLAUDE_PREFLIGHT_SESSION is unset, so Jason's manual commits and
sessions that haven't adopted the env var yet are not blocked.

Usage:
  python3 tools/claude-preflight.py <path>
  make claude-preflight FILE=<path>
  CLAUDE_PREFLIGHT_SESSION=<id> make claude-preflight FILE=<path>

Exit codes:
  0 — always (informational; NOTICE footer signals dirty state)
  1 — usage error

Output format on dirty file:
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
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> tuple[int, str]:
    """Run cmd, return (exitcode, stdout). stderr is discarded — git's
    "fatal: ambiguous argument" noise on untracked paths is expected
    and handled by the caller."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout


def repo_root() -> Path:
    rc, out = run(["git", "rev-parse", "--show-toplevel"])
    if rc != 0:
        raise RuntimeError("not inside a git working tree")
    return Path(out.strip())


def session_state_path(session_id: str) -> Path:
    return repo_root() / ".git" / "claude-preflight" / f"{session_id}.json"


def init_session_state(session_id: str) -> dict:
    """First preflight in a session: snapshot HEAD + tracked-file dirty
    set so the commit-msg gate can later reject sweeps. Untracked (`??`)
    files are excluded — they have no HEAD baseline and are not the
    sweep shape we're guarding against."""
    rc_head, head = run(["git", "rev-parse", "HEAD"])
    head = head.strip() if rc_head == 0 else ""

    _, status_out = run(["git", "status", "--porcelain"])
    initial_dirty: list[str] = []
    for line in status_out.splitlines():
        if len(line) < 4:
            continue
        code = line[:2]
        if code == "??":
            continue
        # `git status --porcelain` format: XY <space> path. Path may
        # contain a rename arrow ("orig -> new"); take the post-arrow
        # form when present so the file we'll diff later matches.
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        initial_dirty.append(path)

    return {
        "session_id": session_id,
        "session_start_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "head_at_start": head,
        "initial_dirty_files": sorted(set(initial_dirty)),
        "preflighted": {},
    }


def record_preflight(session_id: str, file_path: str) -> None:
    """Append `file_path` to the session's `preflighted` set. Initializes
    the state file on first call. Best-effort: any IO error is logged
    to stderr and swallowed — a broken state file MUST NOT prevent
    Claude from running preflight, since that would block all editing."""
    try:
        state_path = session_state_path(session_id)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        if state_path.exists():
            state = json.loads(state_path.read_text())
        else:
            state = init_session_state(session_id)
        state.setdefault("preflighted", {})[file_path] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        state_path.write_text(json.dumps(state, indent=2) + "\n")
    except Exception as e:
        print(
            f"NOTICE: could not record preflight for session {session_id}: {e}",
            file=sys.stderr,
        )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: claude-preflight.py <path>", file=sys.stderr)
        return 1

    path = sys.argv[1]

    # Record this preflight for the current session, if one is declared.
    # Backward-compatible: when CLAUDE_PREFLIGHT_SESSION is unset, this
    # is a no-op and the script behaves exactly as before.
    session = os.environ.get("CLAUDE_PREFLIGHT_SESSION")
    if session:
        record_preflight(session, path)

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
