#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
PostToolUse hook payload sink for Claude Code.

Records every Edit/Write/NotebookEdit that Claude performs in a
session, so the pre-push gate (`tools/check-edit-window.py`) can
later verify that every file in a Claude-authored commit was
actually touched by some Claude session — catching sweeps that
slipped past the commit-msg gate (sticky preflight).

This is plan item (b) from ~/.claude/plans/threat-model-implementation.md.
Companion to (a) sticky preflight (commit `e8957e2`); together they
form the two-tier defense against the working-tree-sweep family
that produced the 6th recurrence (`4d4a4ab`).

# How Claude Code calls this

When configured as a PostToolUse hook with matcher `Edit|Write|
NotebookEdit`, Claude Code invokes this script after each matching
tool use, passing the tool-use payload as JSON on stdin. The
payload's `tool_input.file_path` (or `tool_input.notebook_path`
for NotebookEdit) is the file Claude touched.

Configure via the `update-config` skill or directly in
`.claude/settings.local.json`:

  {
    "hooks": {
      "PostToolUse": [
        {
          "matcher": "Edit|Write|NotebookEdit",
          "hooks": [
            {
              "type": "command",
              "command": "python3 tools/log-claude-edit.py"
            }
          ]
        }
      ]
    }
  }

# What gets recorded

`.git/claude-edit-log/<session_id>.jsonl`, one JSONL line per
tool use:

  {"ts": "<iso>", "tool": "Edit", "file": "<repo-relative path>"}

Same `<session_id>` as `tools/claude-preflight.py` uses, sourced
from `CLAUDE_PREFLIGHT_SESSION`. Without the env var, this is a
silent no-op (gradual rollout matches (a)).

# Failure mode

Any error — missing payload, malformed JSON, write failure — is
logged to stderr and swallowed. A broken edit log MUST NOT block
Claude's tool use; the worst case is the pre-push gate has less
information to work with, which the gate handles via warn-but-pass.

# Bypass

To stop logging, unset CLAUDE_PREFLIGHT_SESSION or remove the
hook from settings. To bypass the eventual pre-push check, run
`git push --no-verify` (discouraged).
"""
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path | None:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return Path(out.strip())
    except subprocess.CalledProcessError:
        return None


def main() -> int:
    session = os.environ.get("CLAUDE_PREFLIGHT_SESSION")
    if not session:
        return 0  # gradual rollout — no env, no logging

    repo = repo_root()
    if repo is None:
        return 0  # not inside a git tree — nothing useful to log against

    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"NOTICE: log-claude-edit could not parse stdin: {e}", file=sys.stderr)
        return 0

    tool = payload.get("tool_name") or payload.get("tool", "")
    tool_input = payload.get("tool_input") or {}

    # Edit / Write use file_path; NotebookEdit uses notebook_path.
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not file_path:
        return 0  # nothing to log

    # Normalize to repo-relative path. Claude Code passes absolute
    # paths; pre-push checks compare against `git diff-tree` output
    # which is always repo-relative.
    abs_path = Path(file_path).resolve()
    try:
        rel_path = str(abs_path.relative_to(repo))
    except ValueError:
        # File outside the repo (rare; happens for /tmp scratch). Log
        # under the absolute path so we at least have a record, but
        # the pre-push check will never match it (intentional — only
        # in-repo files matter).
        rel_path = str(abs_path)

    log_dir = repo / ".git" / "claude-edit-log"
    log_path = log_dir / f"{session}.jsonl"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        line = json.dumps({
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": tool,
            "file": rel_path,
        })
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        print(f"NOTICE: log-claude-edit could not write {log_path}: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
