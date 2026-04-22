#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Reject any working-tree state that contains a path listed in
tools/banned-paths.txt.

Context: Git's index and the on-disk working tree can diverge. A `git rm
--cached` removes a file from the index but leaves it on disk; a
conflict-resolved merge can resurrect a previously-deleted file without
any visible commit; a cross-clone cherry-pick can leave working-tree
debris behind. In each case the divergence goes unnoticed until a later
`git status` surfaces the file as untracked — by which point no one
remembers which operation restored it.

The 2026-04-19 afc4b11 commit intentionally deleted user/hello-riscv64.S
and user/user-riscv64.ld (R-4 scaffolding superseded by R-6's signed
boot-module path). Two days later both files were still present in the
working tree as untracked. The deletion worked in git; the disk state
never got the memo. Per CLAUDE.md's Prompt-Shaping Changelog rule, a
third recurrence of the same-class pattern (two prior: git commit -a,
commit-body-from-memory) escalates from prose to a mechanism. This lint
is that mechanism.

Rule: if any path in tools/banned-paths.txt exists in the working tree
(tracked or untracked), fail. Paths are matched as exact strings relative
to the repo root.

How to use:
  - Ship a deletion commit for a file that must not come back. Before
    merging the deletion, append the path to tools/banned-paths.txt.
  - On any future clone / rebase / merge that resurrects the file, the
    pre-commit hook (or `make check-banned-paths`) fires and names the
    offender.

Fix on trip: `rm <path>` to sync disk with git. If the file legitimately
needs to come back, remove it from tools/banned-paths.txt in the same
commit that re-adds it — an explicit, reviewable un-ban.
"""
import os
import sys
from pathlib import Path

BANNED_LIST = Path(__file__).parent / "banned-paths.txt"


def read_banned_paths() -> list[str]:
    if not BANNED_LIST.is_file():
        return []
    out = []
    for raw in BANNED_LIST.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def main() -> int:
    repo_root = Path(os.getcwd())
    banned = read_banned_paths()
    if not banned:
        return 0

    offenders = [p for p in banned if (repo_root / p).exists()]
    if not offenders:
        return 0

    print("ERROR: banned path(s) present in working tree:", file=sys.stderr)
    for p in offenders:
        print(f"  {p}", file=sys.stderr)
    print(file=sys.stderr)
    print(
        "These paths are listed in tools/banned-paths.txt — files that were",
        file=sys.stderr,
    )
    print(
        "deleted from git and must not reappear on disk. Their presence means",
        file=sys.stderr,
    )
    print(
        "a merge, rebase, cross-clone sync, or incomplete `git rm` resurrected",
        file=sys.stderr,
    )
    print("the working-tree copy.", file=sys.stderr)
    print(file=sys.stderr)
    print("Fix: delete the offending file(s).", file=sys.stderr)
    for p in offenders:
        print(f"  rm {p}", file=sys.stderr)
    print(file=sys.stderr)
    print(
        "If the file legitimately needs to come back, remove its entry from",
        file=sys.stderr,
    )
    print(
        "tools/banned-paths.txt in the same commit that re-adds it.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
