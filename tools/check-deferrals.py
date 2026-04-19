#!/usr/bin/env python3
# Copyright (C) 2024-2026 Jason Ricca. All rights reserved.
"""
check-deferrals: enforce CLAUDE.md Development Convention 9.

Every "figure it out later" — TODO, placeholder, "eventually," etc. —
must carry an observable revisit trigger. This lint scans kernel
source + design docs for deferral tokens and flags any that don't
have a recognized trigger nearby.

Deferral tokens (high-signal, case-insensitive):
  TODO, FIXME, XXX, HACK, eventually, placeholder, TBD, for now,
  figure out (later), defer(red|ral)

Trigger markers (must appear within 3 lines of the deferral):
  "Revisit when:", "Replace when:", "Phase {R-,}N[.N]*",
  "ADR-NNN" (linked or plain), "post-v1", "post-R-N", "pre-R-N",
  "commit <7+ hex>"

Baseline exemptions live in tools/check-deferrals-baseline.txt —
one record per line in "path:line:token" form. The goal is to not
*grow* the baseline, not to clear it overnight.

Exit status:
  0 — no new deferrals without triggers
  1 — new violations found (or baseline is stale)
  2 — repo root not found or baseline unreadable

Scope: scans docs/**/*.md, CLAUDE.md, STATUS.md, src/**/*.rs,
user/**/*.rs. Skips target/, fuzz/target/, .git/, /tmp vendored
deps, and this script's own baseline file.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = ROOT / "tools" / "check-deferrals-baseline.txt"

# Order matters: longer/more-specific tokens first so they win on overlap.
DEFERRAL_PATTERNS = [
    ("figure-out-later", re.compile(r"\bfigure\s+(?:it|this|that|them|out)\s+(?:out\s+)?later\b", re.IGNORECASE)),
    ("figure-out",       re.compile(r"\bfigure\s+out\b", re.IGNORECASE)),
    ("for-now",          re.compile(r"\bfor\s+now\b", re.IGNORECASE)),
    ("eventually",       re.compile(r"\beventually\b", re.IGNORECASE)),
    ("placeholder",      re.compile(r"\bplaceholder\b", re.IGNORECASE)),
    ("TBD",              re.compile(r"\bTBD\b")),
    ("TODO",             re.compile(r"\bTODO\b")),
    ("FIXME",            re.compile(r"\bFIXME\b")),
    ("XXX",              re.compile(r"\bXXX\b")),
    ("HACK",             re.compile(r"\bHACK\b")),
    ("deferred",         re.compile(r"\bdeferr(?:ed|al|als)\b", re.IGNORECASE)),
]

# Trigger markers — presence within ±3 lines of a deferral satisfies Convention 9.
TRIGGER_PATTERNS = [
    re.compile(r"Revisit when:", re.IGNORECASE),
    re.compile(r"Replace when:", re.IGNORECASE),
    re.compile(r"Watch for:", re.IGNORECASE),
    re.compile(r"\bPhase\s+(?:R-)?\d+(?:\.[0-9a-z]+)*\b"),
    re.compile(r"\bADR-\d{3}\b"),
    re.compile(r"\b(?:post|pre)-(?:v1|R-\d+)\b"),
    re.compile(r"\bcommit\s+[0-9a-f]{7,}\b", re.IGNORECASE),
    re.compile(r"\bR-\d+(?:\.[a-z])?\b"),  # bare phase anchor, e.g. "R-6"
]

# Files/dirs to skip entirely.
SKIP_DIR_NAMES = {
    ".git", "target", "fuzz", "node_modules", "iso_root",
    "limine",  # vendored binary drop under /tmp, but safe-guard anyway
}
SKIP_PATHS = {
    BASELINE_PATH,
    Path(__file__),
    ROOT / "docs" / "adr" / "INDEX.md",  # auto-generated
}

# File globs in scope.
SCAN_GLOBS = [
    ("docs", "**/*.md"),
    ("src", "**/*.rs"),
    ("user", "**/*.rs"),
    ("tools", "**/*.py"),
]
SCAN_TOPLEVEL = ["CLAUDE.md", "STATUS.md"]

CONTEXT_WINDOW = 3


def should_skip(path: Path) -> bool:
    if path in SKIP_PATHS:
        return True
    for part in path.parts:
        if part in SKIP_DIR_NAMES:
            return True
    return False


def iter_scan_paths():
    for top, pattern in SCAN_GLOBS:
        base = ROOT / top
        if not base.is_dir():
            continue
        for p in base.glob(pattern):
            if not should_skip(p):
                yield p
    for name in SCAN_TOPLEVEL:
        p = ROOT / name
        if p.is_file() and not should_skip(p):
            yield p


def has_trigger_near(lines, idx, window=CONTEXT_WINDOW):
    lo = max(0, idx - window)
    hi = min(len(lines), idx + window + 1)
    chunk = "\n".join(lines[lo:hi])
    return any(pat.search(chunk) for pat in TRIGGER_PATTERNS)


def find_deferrals(path: Path):
    """Yield (lineno, token_name, line_text) for each flagged deferral."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        # Skip lines that are defining the rule itself (CLAUDE.md Convention 9
        # prose mentions every token by name).
        if "Convention 9" in line or "check-deferrals" in line:
            continue
        # Skip lines inside CLAUDE.md's Changelog where we discuss patterns.
        for token_name, pat in DEFERRAL_PATTERNS:
            if pat.search(line):
                if not has_trigger_near(lines, idx):
                    yield (idx + 1, token_name, line.rstrip())
                break  # one report per line even if multiple tokens match


def load_baseline():
    if not BASELINE_PATH.is_file():
        return set()
    entries = set()
    for raw in BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 3)
        if len(parts) < 3:
            continue
        path, lineno, token = parts[0], parts[1], parts[2]
        entries.add((path, lineno, token))
    return entries


def write_baseline(hits):
    """Write every current flagged record to the baseline file. Caller is
    the user running --update-baseline; normal runs never do this."""
    lines = [
        "# Auto-generated by `make update-deferrals-baseline`.",
        "# Do not hand-edit unless you understand Convention 9.",
        "# Format: path:line:token-name (see tools/check-deferrals.py).",
        "",
    ]
    for rel, lineno, token, _line in sorted(hits):
        lines.append(f"{rel}:{lineno}:{token}")
    BASELINE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    if not ROOT.is_dir():
        print(f"repo root not found: {ROOT}", file=sys.stderr)
        return 2

    update_mode = "--update-baseline" in sys.argv

    baseline = load_baseline()
    new_violations = []
    all_hits = []

    for path in sorted(iter_scan_paths()):
        rel = path.relative_to(ROOT).as_posix()
        for lineno, token, line in find_deferrals(path):
            key = (rel, str(lineno), token)
            all_hits.append((rel, lineno, token, line))
            if key not in baseline:
                new_violations.append((rel, lineno, token, line))

    if update_mode:
        write_baseline(all_hits)
        print(f"check-deferrals: baseline written with {len(all_hits)} entries "
              f"→ {BASELINE_PATH.relative_to(ROOT)}")
        return 0

    print(f"check-deferrals: scanned; {len(all_hits)} total flagged, "
          f"{len(baseline)} baseline, {len(new_violations)} new")

    if new_violations:
        print(f"\ncheck-deferrals found {len(new_violations)} new "
              f"deferral(s) without a trigger:", file=sys.stderr)
        for rel, lineno, token, line in new_violations:
            print(f"  {rel}:{lineno}: [{token}]", file=sys.stderr)
            print(f"    > {line[:140]}", file=sys.stderr)
        print(
            "\nIf these are intentional and carry a trigger I didn't detect, "
            "either:",
            file=sys.stderr,
        )
        print("  (a) add a `Revisit when:` / `Replace when:` line within 3 lines, or", file=sys.stderr)
        print("  (b) name the trigger concretely (ADR-NNN, Phase R-N, post-v1, etc.), or", file=sys.stderr)
        print("  (c) exempt by appending to tools/check-deferrals-baseline.txt:", file=sys.stderr)
        for rel, lineno, token, _ in new_violations[:5]:
            print(f"       {rel}:{lineno}:{token}", file=sys.stderr)
        if len(new_violations) > 5:
            print(f"       ... and {len(new_violations) - 5} more", file=sys.stderr)
        return 1

    print("check-deferrals OK: no new violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
