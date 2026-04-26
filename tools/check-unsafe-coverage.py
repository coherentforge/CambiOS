#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca

"""
check-unsafe-coverage: enforce CLAUDE.md Development Convention 1 —
"every unsafe block MUST have a // SAFETY: comment".

Scans all kernel `.rs` files for `unsafe { ... }` blocks and flags
each one whose preceding comment block does not contain `SAFETY:`.

Comment-block-aware: walks backward from the `unsafe {` line through
contiguous comment lines (line comments `//`, `///`, `//!`, plus
block-comment continuation `*` and `*/`). Stops at the first blank
line or non-comment line. The `SAFETY:` token may appear anywhere
in that block, OR inline on the same line as `unsafe {` (e.g.
`/* SAFETY: ... */ unsafe { foo() }`).

Skips:
  - `unsafe fn`, `unsafe impl`, `unsafe trait` (E2 decides whether
    those are in scope; today they are not).
  - `#[cfg(test)]` / `mod tests` blocks (brace-depth walker).
  - `unsafe` keyword that appears inside a line comment.
  - Verification proof crates (`verification/*-proofs/`) — their
    stub modules are out-of-tree.

Baseline exemptions live in `tools/check-unsafe-coverage-baseline.txt`
— one record per line in `path:line` form. Don't-grow-the-baseline
gate; new violations fail the commit.

Exit status:
  0 — no new sites
  1 — new sites flagged
  2 — repo root not found or baseline unreadable
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = ROOT / "tools" / "check-unsafe-coverage-baseline.txt"

# Scan all kernel `.rs` files. Verification proof crates ship stub
# modules, not kernel code; user-space crates have their own discipline.
SCAN_DIRS = ["src"]

# Pattern: an `unsafe` keyword followed (after optional whitespace) by
# `{`. Excludes `unsafe fn`, `unsafe impl`, `unsafe trait`.
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
UNSAFE_DECL = re.compile(r"\bunsafe\s+(fn|impl|trait)\b")
LINE_COMMENT_HEAD = re.compile(r"^\s*(///?!?|//!?)")
BLOCK_COMMENT_LINE = re.compile(r"^\s*(/\*|\*/?\s|\*$|\*\s)")
BLOCK_COMMENT_OPEN = re.compile(r"/\*")
SAFETY_MARKER = re.compile(r"\bSAFETY\b\s*:")


def strip_line_comment(line: str) -> str:
    """Drop the `//` line-comment tail. Block comments (`/* ... */`)
    that close on the same line are kept; conservative since they are
    rare in the kernel and may legitimately wrap an `unsafe { ... }`."""
    out = []
    i = 0
    in_str = False
    while i < len(line):
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        if not in_str and c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def line_opens_unsafe_block(line: str) -> bool:
    code = strip_line_comment(line)
    if not UNSAFE_BLOCK.search(code):
        return False
    if UNSAFE_DECL.search(code):
        # `unsafe fn ... { unsafe { ... } }` would have BOTH on the
        # same line; that is unusual enough to ignore for now and
        # revisit if it shows up in a real file.
        return False
    return True


def is_comment_or_blank(line: str) -> str:
    """Classify a line as 'comment', 'blank', or 'code'."""
    stripped = line.strip()
    if not stripped:
        return "blank"
    if LINE_COMMENT_HEAD.match(line) or BLOCK_COMMENT_LINE.match(line):
        return "comment"
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return "comment"
    return "code"


def has_inline_safety(line: str) -> bool:
    """`unsafe { ... }` on a line that ALSO carries `// SAFETY: …` or
    `/* SAFETY: … */` counts as covered."""
    return bool(SAFETY_MARKER.search(line))


def is_attribute_line(line: str) -> bool:
    """True iff the line is a Rust outer attribute like
    `#[cfg(target_arch = "x86_64")]` or `#[allow(unused)]`.
    Such attributes annotate the next item; they do not break the
    SAFETY-comment-to-unsafe contiguity."""
    stripped = line.strip()
    return stripped.startswith("#[") or stripped.startswith("#![")


def is_assignment_continuation(line: str) -> bool:
    """True iff the line LOOKS like the start of an assignment whose
    RHS continues on the following line(s). Common Rust idiom:
        // SAFETY: ...
        let foo: Bar =
            unsafe { ... };
    The `let foo: Bar =` line is code, but it is part of the same
    statement as the unsafe block; the SAFETY above the `let` covers
    the unsafe."""
    code = strip_line_comment(line).rstrip()
    if not code:
        return False
    # Trailing `=` (assignment) or `=>` (match arm) introduces a
    # continuation. We deliberately don't accept `,` or `(` — those
    # are too permissive and would allow the walker to skip past
    # arbitrary code in let/match expressions.
    return code.endswith("=") or code.endswith("=>")


def safety_in_preceding_comment_block(lines, idx) -> bool:
    """Walk backward looking for a `SAFETY:` annotation that covers
    this `unsafe { ... }` block.

    Walks past:
      - Comment lines (search for `SAFETY:`).
      - Other `unsafe { ... };` lines that have no SAFETY of their own
        (cluster behavior — a SAFETY comment above a sequence of
        adjacent unsafe-block reads covers the whole cluster).
      - Assignment-continuation lines (`let foo: Bar =` then the
        unsafe expression on the next line).
      - Outer attribute lines (`#[cfg(...)]`, `#[allow(...)]`) — they
        annotate the unsafe block / item below and do not break the
        SAFETY-comment-to-unsafe contiguity.

    Stops at:
      - The first blank line.
      - The first code line that is NOT one of the above.
    """
    j = idx - 1
    while j >= 0:
        line = lines[j]
        kind = is_comment_or_blank(line)
        if kind == "comment":
            if SAFETY_MARKER.search(line):
                return True
            j -= 1
            continue
        if kind == "blank":
            return False
        # `code` — but allow adjacent unsafe-block lines (cluster),
        # assignment-continuation lines (multi-line let/match RHS),
        # and outer attribute lines (`#[cfg(...)]`).
        if line_opens_unsafe_block(line):
            if has_inline_safety(line):
                return True
            j -= 1
            continue
        if is_assignment_continuation(line):
            j -= 1
            continue
        if is_attribute_line(line):
            j -= 1
            continue
        return False
    return False


def in_test_context(lines, idx) -> bool:
    """True iff `idx` is inside a `#[cfg(test)]` mod or `mod tests`
    block. Brace-depth walker over a 600-line lookback window."""
    window_start = max(0, idx - 600)
    in_test_mod = False
    brace_depth = 0
    for k in range(window_start, idx):
        line = lines[k]
        if re.search(r"#\[cfg\(test\)\]", line) or re.search(r"\bmod\s+tests\b", line):
            in_test_mod = True
        if in_test_mod:
            brace_depth += line.count("{") - line.count("}")
    return in_test_mod and brace_depth > 0


def find_violations(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if not line_opens_unsafe_block(line):
            continue
        if has_inline_safety(line):
            continue
        if safety_in_preceding_comment_block(lines, idx):
            continue
        if in_test_context(lines, idx):
            continue
        yield (idx + 1, line.rstrip())


def iter_scan_paths():
    for rel in SCAN_DIRS:
        d = ROOT / rel
        if not d.is_dir():
            continue
        for path in sorted(d.glob("**/*.rs")):
            yield path


def load_baseline():
    if not BASELINE_PATH.is_file():
        return set()
    entries = set()
    for raw in BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        entries.add((parts[0], parts[1]))
    return entries


def write_baseline(hits):
    header = [
        "# Auto-generated by `make update-unsafe-coverage-baseline`.",
        "# Format: path:line (see tools/check-unsafe-coverage.py).",
        "#",
        "# Goal: shrink to zero. Each entry is an `unsafe { ... }` block",
        "# that lacks an inline `// SAFETY:` comment in its preceding",
        "# comment block. The lint blocks NEW violations; clearing this",
        "# baseline is the work of CLAUDE.md prompt-shaping changelog",
        "# entry 'E1' (Tier 1 step E1, prancy-manatee plan).",
        "",
    ]
    lines = header + [f"{rel}:{lineno}" for rel, lineno, _line in sorted(hits)]
    BASELINE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    if not ROOT.is_dir():
        print(f"repo root not found: {ROOT}", file=sys.stderr)
        return 2

    update_mode = "--update-baseline" in sys.argv

    baseline = load_baseline()
    new_violations = []
    all_hits = []

    for path in iter_scan_paths():
        rel = path.relative_to(ROOT).as_posix()
        for lineno, line in find_violations(path):
            key = (rel, str(lineno))
            all_hits.append((rel, lineno, line))
            if key not in baseline:
                new_violations.append((rel, lineno, line))

    if update_mode:
        write_baseline(all_hits)
        print(
            f"check-unsafe-coverage: baseline written with {len(all_hits)} entries "
            f"→ {BASELINE_PATH.relative_to(ROOT)}"
        )
        return 0

    print(
        f"check-unsafe-coverage: scanned; {len(all_hits)} total flagged, "
        f"{len(baseline)} baseline, {len(new_violations)} new"
    )

    if new_violations:
        print(
            f"\ncheck-unsafe-coverage found {len(new_violations)} new "
            f"`unsafe {{ ... }}` block(s) without `// SAFETY:` "
            f"in the preceding comment:",
            file=sys.stderr,
        )
        for rel, lineno, line in new_violations:
            print(f"  {rel}:{lineno}", file=sys.stderr)
            print(f"    > {line.strip()[:140]}", file=sys.stderr)
        print(
            "\nCLAUDE.md Development Convention 1: every `unsafe` block must "
            "have a `// SAFETY:` comment explaining why the operation is sound.",
            file=sys.stderr,
        )
        print("\nFix by one of:", file=sys.stderr)
        print(
            "  (a) add a `// SAFETY: <one-line rationale>` comment immediately",
            file=sys.stderr,
        )
        print("      above the `unsafe {` line — preferred.", file=sys.stderr)
        print(
            "  (b) if the unsafe is genuinely covered by a SAFETY block",
            file=sys.stderr,
        )
        print(
            "      separated by blank lines or interleaved code, restructure",
            file=sys.stderr,
        )
        print("      so the comment is contiguous with the block.", file=sys.stderr)
        print(
            "  (c) append to tools/check-unsafe-coverage-baseline.txt to",
            file=sys.stderr,
        )
        print("      acknowledge a regression:", file=sys.stderr)
        for rel, lineno, _ in new_violations[:5]:
            print(f"       {rel}:{lineno}", file=sys.stderr)
        return 1

    print("check-unsafe-coverage OK: no new sites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
