#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Pre-push gate: reject pushes containing Claude-authored commits whose
modified files were never observed in a Claude session's edit log.

Plan item (b) from ~/.claude/plans/threat-model-implementation.md.
Defense-in-depth on top of (a) sticky preflight (commit `e8957e2`):
(a) catches sweeps at commit time, (b) catches anything that slipped
through (a) — including bypass-via-`--no-verify` — at push time,
before the bad attribution leaves the local clone.

# How it works

Git invokes a pre-push hook with the line(s) of "<local_ref>
<local_oid> <remote_ref> <remote_oid>" on stdin. For each push
range, this script:

  1. Lists the commits being pushed (`git rev-list <remote>..<local>`).
  2. For each commit with a `Co-Authored-By: Claude` trailer:
     a. Pulls the modified file list (`git diff-tree --no-commit-id
        --name-only -r <commit>`).
     b. Loads the union of every recorded edit log under
        `.git/claude-edit-log/*.jsonl`.
     c. Rejects if any committed file is not in the union — that
        file was never observed being edited by Claude in any
        session, so the commit is almost certainly sweeping a
        parallel session's hunks.

The "union of all sessions" check is intentionally loose: it
accepts a commit whose files were touched by *some* Claude
session, not necessarily *this* session. The single-session check
already happens at commit time via (a) sticky preflight, so by
the time we reach here the commit-to-session correspondence has
been verified once. The pre-push gate is the catch-anything
backstop.

# Gradual rollout

If no edit logs exist (CLAUDE_PREFLIGHT_SESSION never set, or
the PostToolUse hook isn't installed yet), this gate emits a
single NOTICE and exits 0. That keeps Jason's manual pushes and
pre-adoption Claude sessions unblocked. Once adoption is
universal, tighten the no-log branch to a hard error.

# Bypass

`git push --no-verify` (discouraged; the gate is meant to be
tripped, not silenced).

# Why a separate script + hook (not folded into commit-msg)

A pre-push gate fires *after* commits exist locally — so it
catches commits that bypassed the commit-msg phase via
`--no-verify`. A commit-msg gate cannot catch its own bypass;
a pre-push gate can. Together (a) and (b) form a defense in
depth where bypassing one still leaves the other in place.
"""
import json
import os
import subprocess
import sys
from pathlib import Path


# Sentinel oids git uses for "branch creation" (no remote yet) and
# "branch deletion" (no local). On creation we have no remote_oid
# baseline; fall back to inspecting the full new branch range.
ZERO_OID = "0" * 40


def repo_root() -> Path:
    return Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
    )


def load_edit_log_union(repo: Path) -> set[str]:
    """Return the set of repo-relative paths recorded across ALL
    `.git/claude-edit-log/*.jsonl` files. Robust against malformed
    lines (skip and continue)."""
    log_dir = repo / ".git" / "claude-edit-log"
    if not log_dir.is_dir():
        return set()

    union: set[str] = set()
    for path in log_dir.glob("*.jsonl"):
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    file_path = rec.get("file")
                    if isinstance(file_path, str):
                        union.add(file_path)
        except OSError:
            continue
    return union


def commit_is_claude(commit: str) -> bool:
    msg = subprocess.check_output(
        ["git", "log", "-1", "--format=%B", commit], text=True
    )
    return "Co-Authored-By: Claude" in msg


def commit_files(commit: str) -> list[str]:
    out = subprocess.check_output(
        ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
        text=True,
    ).strip()
    return out.splitlines() if out else []


def commits_in_range(local_oid: str, remote_oid: str) -> list[str]:
    """Walk commits being pushed. On branch creation (remote == zero
    oid), inspect the entire new branch — but only commits not yet
    reachable from any other already-pushed ref, so we don't drown
    in unrelated history."""
    if remote_oid == ZERO_OID:
        rev_args = ["git", "rev-list", local_oid, "--not", "--remotes"]
    elif local_oid == ZERO_OID:
        # Branch deletion — nothing being pushed forward to inspect.
        return []
    else:
        rev_args = ["git", "rev-list", f"{remote_oid}..{local_oid}"]
    out = subprocess.check_output(rev_args, text=True).strip()
    return out.splitlines() if out else []


def main() -> int:
    repo = repo_root()
    edit_union = load_edit_log_union(repo)

    # Read the pre-push protocol stdin: lines of
    #   <local_ref> <local_oid> <remote_ref> <remote_oid>
    push_lines = sys.stdin.read().splitlines()

    violations: list[tuple[str, str, list[str]]] = []
    saw_any_claude_commit = False

    for line in push_lines:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local_ref, local_oid, _remote_ref, remote_oid = parts[:4]
        if local_oid == ZERO_OID:
            continue  # branch deletion — nothing to inspect

        for commit in commits_in_range(local_oid, remote_oid):
            try:
                if not commit_is_claude(commit):
                    continue
            except subprocess.CalledProcessError:
                continue
            saw_any_claude_commit = True

            try:
                files = commit_files(commit)
            except subprocess.CalledProcessError:
                continue

            missing = [f for f in files if f not in edit_union]
            if missing:
                violations.append((commit, local_ref, missing))

    if not saw_any_claude_commit:
        return 0  # nothing Claude-authored in this push

    if not edit_union:
        # Claude commits being pushed but no edit log recorded — the
        # PostToolUse hook isn't installed yet, or the session never
        # set CLAUDE_PREFLIGHT_SESSION. Warn and pass.
        print(
            "NOTICE: pre-push edit-window check found Claude-authored",
            file=sys.stderr,
        )
        print(
            "  commits but no .git/claude-edit-log/*.jsonl entries.",
            file=sys.stderr,
        )
        print(
            "  Configure the PostToolUse hook in .claude/settings.local.json",
            file=sys.stderr,
        )
        print(
            "  and set CLAUDE_PREFLIGHT_SESSION per Claude session to enable",
            file=sys.stderr,
        )
        print(
            "  this gate. See ~/.claude/plans/threat-model-implementation.md.",
            file=sys.stderr,
        )
        return 0

    if not violations:
        return 0

    print("ERROR: pre-push edit-window violation.", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "  These Claude-authored commits modify files that no Claude",
        file=sys.stderr,
    )
    print(
        "  session ever touched via Edit / Write / NotebookEdit:",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    for commit, local_ref, missing in violations:
        subj = subprocess.check_output(
            ["git", "log", "-1", "--format=%h %s", commit], text=True
        ).strip()
        print(f"  {subj} (on {local_ref})", file=sys.stderr)
        for f in missing:
            print(f"      {f}", file=sys.stderr)
        print("", file=sys.stderr)
    print(
        "  Almost-certain cause: a parallel Claude session's uncommitted",
        file=sys.stderr,
    )
    print(
        "  hunks were swept into one of these commits. The local commit",
        file=sys.stderr,
    )
    print(
        "  is wrong; rewriting before push is far cheaper than rewriting",
        file=sys.stderr,
    )
    print("  after.", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "  To recover: `git rebase -i <base>`, drop or amend the offending",
        file=sys.stderr,
    )
    print(
        "  commit so its file list matches what your session actually",
        file=sys.stderr,
    )
    print(
        "  edited. Coordinate with the parallel session if needed.",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print(
        "  Bypass: `git push --no-verify` (discouraged).",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
