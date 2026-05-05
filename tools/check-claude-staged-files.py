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
# Parse rule: the first line matching /^\s*-?\s*Staged files\s*:\s*$/
# (case-insensitive) begins the block. The trailing `:\s*$` means a
# bare prose mention like "...actually staged files. That shape..." no
# longer matches as the header — the line must be exactly the header,
# not a phrase containing "staged files". Following lines are paths
# iff they are (a) indented more than the header, (b) non-empty, (c)
# after stripping any leading Markdown bullet (`- ` or `* `) the
# remainder contains no internal whitespace. The block ends at the
# first line that fails those tests, or at the end of the message.
#
# The bullet-strip means both forms parse identically:
#     Staged files:           Staged files:
#       Makefile                - Makefile
#       tools/foo.py            - tools/foo.py
# Bare-indented was the original form; bullet form was added because
# Markdown convention reaches for `- ` and the bullet doesn't change
# what `git diff --cached --name-only` correspondence means.
#
# Bypass: `git commit --no-verify` (discouraged; prefer to write the
# block correctly).

import re
import subprocess
import sys
from pathlib import Path


HEADER_RE = re.compile(r'^(?P<indent>\s*)-?\s*Staged files\s*:\s*$', re.IGNORECASE)


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
            # Strip Markdown bullet prefix so `- foo` and `foo` parse
            # identically. Prose continuation (e.g. `- This change`)
            # still ends the block because the post-strip token retains
            # internal whitespace.
            if token.startswith(('- ', '* ')):
                token = token[2:].lstrip()
            if not token or re.search(r'\s', token):
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
        print("      - path/to/one.rs", file=sys.stderr)
        print("      - path/to/two.rs", file=sys.stderr)
        print("", file=sys.stderr)
        print("  (Bullets `- ` / `* ` are optional; bare paths also work.)",
              file=sys.stderr)
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
    if not claimed_set and actual_set:
        # Zero-parsed-paths shape: header found, but no path lines were
        # accepted. Almost always the column-zero pitfall — `- path` at
        # the same indent as `Staged files:` parses as zero paths.
        print("  Common cause: `Staged files:` path lines must be indented",
              file=sys.stderr)
        print("  past the header. The bullet `-` is part of the path token,",
              file=sys.stderr)
        print("  not the header column — `- path` at column 0 parses as zero",
              file=sys.stderr)
        print("  paths. Indent two spaces, e.g. `  - path/to/file`.",
              file=sys.stderr)
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
