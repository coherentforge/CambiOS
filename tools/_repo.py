# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""
Which files belong to the repository.

A lint that walks the filesystem scans whatever happens to be on disk:
build output, a virtualenv, a neighbour's scratch files. A lint that
names directories misses the directory added after it was written. The
lints that import this module scan what git says the repository holds,
so a new crate is in scope the moment its first file exists.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def repo_files():
    """Absolute paths of every file that belongs to the repository:
    tracked, or untracked and not ignored. Returns None when git cannot
    say; the caller stops instead of walking the filesystem, because a
    filesystem walk is what let gitignored files into a baseline."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT, check=True, capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return {ROOT / rel for rel in out.decode("utf-8").split("\0") if rel}


def rust_sources(files, skip_top=()):
    """The repository's `.rs` files that exist on disk, sorted, leaving
    out those under the named top-level directories."""
    picked = []
    for p in files:
        if p.suffix != ".rs" or not p.is_file():
            continue
        if p.relative_to(ROOT).parts[0] in skip_top:
            continue
        picked.append(p)
    return sorted(picked)
