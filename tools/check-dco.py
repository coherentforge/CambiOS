#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""
check-dco: every commit carries a Developer Certificate of Origin sign-off.

The sign-off is the line `git commit -s` adds:

    Signed-off-by: Name <email>

By adding it the committer certifies the Developer Certificate of Origin
(https://developercertificate.org): that they wrote the change or
otherwise have the right to submit it under the project's license. The
sign-off belongs to the person submitting the change, also when an agent
wrote it.

Two ways to run it:

    check-dco.py <commit-message-file>      the commit-msg hook
    check-dco.py --range <base>..<head>     every commit in a range (CI)

Merge commits in a range are skipped: they carry no change of their own.

Exit status:
  0  every commit checked is signed off
  1  a commit is not signed off
  2  usage error, or git could not list the range
"""

import re
import subprocess
import sys
from pathlib import Path

SIGN_OFF = re.compile(r"^Signed-off-by:\s*\S.*<[^<>\s]+@[^<>\s]+>\s*$", re.MULTILINE)

ADVICE = (
    "  Add it with `git commit -s` (or `git commit --amend -s` for the\n"
    "  last commit). The line certifies the Developer Certificate of\n"
    "  Origin, https://developercertificate.org; see CONTRIBUTING.md."
)


def strip_comments(message):
    """Drop the `#` comment lines git puts in a message being edited."""
    return "\n".join(l for l in message.splitlines() if not l.startswith("#"))


def check_file(path):
    message = strip_comments(Path(path).read_text(encoding="utf-8", errors="replace"))
    if SIGN_OFF.search(message):
        return 0
    print("ERROR: commit message has no `Signed-off-by:` line.", file=sys.stderr)
    print(ADVICE, file=sys.stderr)
    return 1


def check_range(rev_range):
    try:
        out = subprocess.run(
            ["git", "log", "--no-merges", "--format=%H%x00%B%x01", rev_range],
            check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"check-dco: `git log {rev_range}` failed: {getattr(e, 'stderr', e)}", file=sys.stderr)
        return 2
    unsigned = []
    count = 0
    for record in out.split("\x01"):
        record = record.strip("\n")
        if not record:
            continue
        sha, _, body = record.partition("\x00")
        count += 1
        if not SIGN_OFF.search(body):
            unsigned.append((sha, body.splitlines()[0] if body else ""))
    print(f"check-dco: {count} commit(s) in {rev_range}, {len(unsigned)} without a sign-off")
    if unsigned:
        print("ERROR: these commits have no `Signed-off-by:` line:", file=sys.stderr)
        for sha, subject in unsigned:
            print(f"  {sha[:12]}  {subject[:80]}", file=sys.stderr)
        print(ADVICE, file=sys.stderr)
        return 1
    return 0


def main(argv):
    if len(argv) == 2 and argv[0] == "--range":
        return check_range(argv[1])
    if len(argv) == 1 and not argv[0].startswith("-"):
        return check_file(argv[0])
    print("usage: check-dco.py <commit-message-file> | --range <base>..<head>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
