# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""
The build lists, read from the Makefile.

The Makefile's "Build lists" section is the one place that names the
architectures, the user crates per architecture, and the proof crates.
Lints import this module instead of keeping their own copies; it asks
make for the values (`make print-<VAR>`), so a lint can never disagree
with the build about what the lists contain.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ListError(Exception):
    """make could not report a list (not a repository checkout, or the
    Makefile failed to parse). Callers stop; they do not guess."""


def make_vars(*names):
    """Values of Makefile variables, each split into words."""
    try:
        out = subprocess.run(
            ["make", "--no-print-directory", "-s"] + [f"print-{n}" for n in names],
            cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        raise ListError(f"`make print-...` failed: {detail.strip()}") from e
    lines = out.split("\n")
    if len(lines) < len(names):
        raise ListError(f"`make print-...` returned {len(lines)} lines for {len(names)} variables")
    return {n: lines[i].split() for i, n in enumerate(names)}


def arches():
    return make_vars("ARCHES")["ARCHES"]


def per_arch(prefix, arch_list):
    """{arch: words} for PREFIX_<arch> variables."""
    got = make_vars(*[f"{prefix}_{a}" for a in arch_list])
    return {a: got[f"{prefix}_{a}"] for a in arch_list}


def proof_crates():
    return make_vars("PROOF_CRATES")["PROOF_CRATES"]
