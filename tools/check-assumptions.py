#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
check-assumptions: enforce CLAUDE.md Development Convention 8.

Every fixed numeric `const` in kernel code must carry a category tag
(SCAFFOLDING / ARCHITECTURAL / HARDWARE / TUNING) in a nearby doc
comment. Unconscious bounds — values picked because something fit —
are how production-ready software accrues weakness while it's still
cheap to fix.

This lint scans `src/**/*.rs` (kernel only; user-space is held to a
lighter standard) for `const NAME: <numeric> = …` declarations and
flags any whose preceding 10 lines don't name one of the four
categories.

Numeric types in scope:
  u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize

Baseline exemptions live in `tools/check-assumptions-baseline.txt` —
one record per line in `path:line:NAME` form. The goal is to not
*grow* the baseline, not to clear it overnight.

Exit status:
  0 — no new untagged bounds
  1 — new violations found
  2 — repo root not found or baseline unreadable

Scope: scans src/**/*.rs; skips test modules (`mod tests`,
`#[cfg(test)]`), target/, .git/, and this script's own baseline file.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = ROOT / "tools" / "check-assumptions-baseline.txt"

NUMERIC_TYPES = (
    r"(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize)"
)

# Match: [visibility] const NAME: <numeric> = ...
# Visibility forms: none | pub | pub(crate) | pub(super)
CONST_PATTERN = re.compile(
    rf"^\s*(?:pub(?:\s*\([^)]+\))?\s+)?const\s+"
    rf"([A-Z_][A-Z0-9_]*)\s*:\s*{NUMERIC_TYPES}\s*="
)

# Category tags — one must appear within CONTEXT_WINDOW lines above the const.
TAG_PATTERNS = [
    re.compile(r"\bSCAFFOLDING\b"),
    re.compile(r"\bARCHITECTURAL\b"),
    re.compile(r"\bHARDWARE\b"),
    re.compile(r"\bTUNING\b"),
]

SKIP_DIR_NAMES = {".git", "target", "fuzz", "node_modules"}
SKIP_PATHS = {
    BASELINE_PATH,
    Path(__file__),
}

CONTEXT_WINDOW = 10


def should_skip(path: Path) -> bool:
    if path in SKIP_PATHS:
        return True
    for part in path.parts:
        if part in SKIP_DIR_NAMES:
            return True
    return False


def iter_scan_paths():
    base = ROOT / "src"
    if not base.is_dir():
        return
    for p in base.glob("**/*.rs"):
        if not should_skip(p):
            yield p


def in_test_context(lines, idx):
    """Return True if line idx is inside a `mod tests {...}` or
    `#[cfg(test)] mod foo {...}` block. Walks backward tracking brace
    depth so we don't false-positive on consts below a closed test mod.
    """
    # Walk every line from the top to idx, maintaining a stack of
    # (start_line, kind) for each open block. A block is "test" if it
    # matches `mod\s+tests\b` or is preceded by `#[cfg(test)]`. When a
    # closing brace pops the test block, we exit test context.
    depth = 0
    in_test = False
    test_depth = None
    prev_was_cfg_test = False
    for i, line in enumerate(lines[:idx + 1]):
        opens = line.count("{")
        closes = line.count("}")
        is_mod_tests = bool(re.search(r"\bmod\s+\w+\s*\{", line)) and (
            re.search(r"\bmod\s+tests\b", line) or prev_was_cfg_test
        )
        if is_mod_tests and not in_test:
            in_test = True
            test_depth = depth + 1  # we're about to enter
        depth += opens - closes
        if in_test and test_depth is not None and depth < test_depth:
            in_test = False
            test_depth = None
        # Update prev_was_cfg_test for next iteration.
        stripped = line.strip()
        if "#[cfg(test)]" in stripped or "#[cfg(any(test" in stripped:
            prev_was_cfg_test = True
        elif stripped and not stripped.startswith("//"):
            prev_was_cfg_test = False
    return in_test


def has_tag_above(lines, idx, window=CONTEXT_WINDOW):
    lo = max(0, idx - window)
    chunk = "\n".join(lines[lo:idx])
    return any(pat.search(chunk) for pat in TAG_PATTERNS)


def find_untagged(path: Path):
    """Yield (lineno, name, line_text) for each untagged bound."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        m = CONST_PATTERN.match(line)
        if not m:
            continue
        if in_test_context(lines, idx):
            continue
        if has_tag_above(lines, idx):
            continue
        yield (idx + 1, m.group(1), line.rstrip())


def load_baseline():
    if not BASELINE_PATH.is_file():
        return set()
    entries = set()
    for raw in BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        path, lineno, name = parts[0], parts[1], parts[2]
        entries.add((path, lineno, name))
    return entries


def write_baseline(hits):
    """Rewrite the baseline from the current flagged set. Only the
    `--update-baseline` mode calls this; normal runs never do."""
    lines = [
        "# Auto-generated by `make update-assumptions-baseline`.",
        "# Do not hand-edit unless you understand Convention 8.",
        "# Format: path:line:CONST_NAME (see tools/check-assumptions.py).",
        "",
    ]
    for rel, lineno, name, _line in sorted(hits):
        lines.append(f"{rel}:{lineno}:{name}")
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
        for lineno, name, line in find_untagged(path):
            key = (rel, str(lineno), name)
            all_hits.append((rel, lineno, name, line))
            if key not in baseline:
                new_violations.append((rel, lineno, name, line))

    if update_mode:
        write_baseline(all_hits)
        print(
            f"check-assumptions: baseline written with {len(all_hits)} entries "
            f"→ {BASELINE_PATH.relative_to(ROOT)}"
        )
        return 0

    print(
        f"check-assumptions: scanned; {len(all_hits)} total flagged, "
        f"{len(baseline)} baseline, {len(new_violations)} new"
    )

    if new_violations:
        print(
            f"\ncheck-assumptions found {len(new_violations)} new untagged "
            f"numeric const(s):",
            file=sys.stderr,
        )
        for rel, lineno, name, line in new_violations:
            print(f"  {rel}:{lineno}: {name}", file=sys.stderr)
            print(f"    > {line[:140]}", file=sys.stderr)
        print(
            "\nEvery numeric `const` in kernel code must carry one of the four "
            "Convention 8 tags in a doc comment above it:",
            file=sys.stderr,
        )
        print("  SCAFFOLDING   — verification ergonomics, expected to grow", file=sys.stderr)
        print("  ARCHITECTURAL — real invariant, won't change", file=sys.stderr)
        print("  HARDWARE      — ABI/spec fact", file=sys.stderr)
        print("  TUNING        — workload-dependent", file=sys.stderr)
        print("\nFix by either:", file=sys.stderr)
        print("  (a) adding a doc comment with one of the four tags, or", file=sys.stderr)
        print("  (b) appending to tools/check-assumptions-baseline.txt:", file=sys.stderr)
        for rel, lineno, name, _ in new_violations[:5]:
            print(f"       {rel}:{lineno}:{name}", file=sys.stderr)
        if len(new_violations) > 5:
            print(f"       ... and {len(new_violations) - 5} more", file=sys.stderr)
        return 1

    print("check-assumptions OK: no new violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
