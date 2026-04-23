#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
#
# Reject Claude-authored commits whose "Staged files:" section does not
# match the actual staged files.
#
# Rationale: parallel Claude sessions have repeatedly swept each other's
# staged files into commits via `git commit -a` / `git add -A`. The
# body drifts from the diff. H1 closes the loop: every Claude commit
# MUST list its staged files, and mismatches fail the commit.
#
# Escalation ladder (see CLAUDE.md Prompt-Shaping Changelog):
#   1. Prose rule: "never git commit -a"
#   2. tools/check-banned-paths.py      (2026-04-21)
#   3. tools/claude-preflight.py        (2026-04-22)
#   4. c9e8e86 — 5th recurrence, auto-attribution swept foreign file
#   5. this lint                        (2026-04-23)
#
# Claude-authored is detected by the presence of "Co-Authored-By: Claude"
# anywhere in the commit message. Non-Claude commits pass through
# untouched; Jason's manual commits do not need a Staged files block.
#
# Parse rule: the first line matching /^\s*-?\s*Staged files/ (case-
# insensitive) begins the block. Following lines are paths iff they are
# (a) indented more than the header, (b) contain no internal whitespace,
# (c) non-empty. The block ends at the first line that fails those
# tests, or at the end of the message.
#
# Bypass: `git commit --no-verify` (discouraged; prefer to write the
# block correctly).

import re
import subprocess
import sys
from pathlib import Path


HEADER_RE = re.compile(r'^(?P<indent>\s*)-?\s*Staged files\b', re.IGNORECASE)


def extract_claimed_paths(msg):
    """Return (list-of-paths, found) where found is True iff the header
    line exists. An empty list with found=True is a valid zero-file
    declaration (though no Claude commit should actually stage zero
    files)."""
    lines = msg.splitlines()
    for i, line in enumerate(lines):
        m = HEADER_RE.match(line)
        if not m:
            continue
        header_indent = len(m.group('indent'))
        claimed = []
        for follow in lines[i + 1:]:
            rstripped = follow.rstrip()
            if not rstripped.strip():
                break
            leading = len(rstripped) - len(rstripped.lstrip())
            if leading <= header_indent:
                break
            token = rstripped.strip()
            if re.search(r'\s', token):
                # Prose continuation — end of block.
                break
            claimed.append(token)
        return claimed, True
    return [], False


def main():
    if len(sys.argv) < 2:
        print("usage: check-claude-staged-files.py <commit-msg-file>",
              file=sys.stderr)
        return 2

    msg = Path(sys.argv[1]).read_text()

    # Git writes comment lines (starting with #) into COMMIT_EDITMSG;
    # strip them so they don't pollute parsing.
    msg = "\n".join(
        line for line in msg.splitlines() if not line.lstrip().startswith("#")
    )

    if "Co-Authored-By: Claude" not in msg:
        return 0

    claimed, found_header = extract_claimed_paths(msg)
    if not found_header:
        print("ERROR: Claude-authored commit missing 'Staged files:' section.",
              file=sys.stderr)
        print("", file=sys.stderr)
        print("  Every Claude commit body must list its staged files in a",
              file=sys.stderr)
        print("  block like:", file=sys.stderr)
        print("", file=sys.stderr)
        print("    Staged files:", file=sys.stderr)
        print("      path/to/one.rs", file=sys.stderr)
        print("      path/to/two.rs", file=sys.stderr)
        print("", file=sys.stderr)
        print("  This catches working-tree sweeps where `git add -A` or",
              file=sys.stderr)
        print("  `git commit -a` pulled files in from a parallel session.",
              file=sys.stderr)
        print("", file=sys.stderr)
        print("  Bypass: git commit --no-verify (discouraged).",
              file=sys.stderr)
        return 1

    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        check=True,
    )
    actual_raw = result.stdout.strip()
    actual = actual_raw.splitlines() if actual_raw else []

    claimed_set = set(claimed)
    actual_set = set(actual)

    if claimed_set == actual_set:
        return 0

    missing_from_body = sorted(actual_set - claimed_set)
    extra_in_body = sorted(claimed_set - actual_set)

    print("ERROR: Staged files in commit body do not match "
          "`git diff --cached --name-only`.", file=sys.stderr)
    print("", file=sys.stderr)
    if missing_from_body:
        print("  Staged but not listed in commit body:", file=sys.stderr)
        for p in missing_from_body:
            print("    {}".format(p), file=sys.stderr)
    if extra_in_body:
        print("  Listed in body but not actually staged:", file=sys.stderr)
        for p in extra_in_body:
            print("    {}".format(p), file=sys.stderr)
    print("", file=sys.stderr)
    print("  If a file is in the diff unexpectedly, it was likely swept in",
          file=sys.stderr)
    print("  from a parallel session — reset the index and re-stage only",
          file=sys.stderr)
    print("  the files you own this session: `git reset` then",
          file=sys.stderr)
    print("  `git add <explicit file>...`.", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Bypass: git commit --no-verify (discouraged).",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
