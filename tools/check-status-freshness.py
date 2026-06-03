#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Pre-commit advisory: surface STATUS.md drift before it compounds.

Two independent advisory checks, both exit-0 (warn-but-pass), in the
same don't-grow-the-baseline family as the other tools/check-*.py gates.

1. DATE drift — `last_synced_to_code:` more than THRESHOLD_DAYS old.
   (Original behavior, unchanged. Rationale: the 2026-04-22 -> 2026-05-04
   12-day drift window that had to be recovered in one large catch-up sync.)

2. NUMBER drift — STATUS.md's prose counts no longer match the source.
   This is the gap that let the file sit at "561 host unit tests /
   47 harnesses" while the code was already at 892 / 48: a sync bumped
   the *date* but never re-derived the *numbers*, and a date-only check
   passed silently. The date moving is not evidence the counts moved.

   - Kani harness count is derived CHEAPLY (count active `#[kani::proof]`
     under verification/, no compile) and compared to every *total*
     stated in STATUS.md prose. Safe to run on every commit.
   - The unit-test count cannot be derived without compiling, so by
     default this only checks that the stated test numbers agree with
     EACH OTHER (catches a partial update — one mention fixed, another
     missed). With `--full` it runs `make stats` and compares against the
     live count; that path compiles, so it is for CI / manual runs, NOT
     the pre-commit hook.

Posture unchanged: advisory, exit 0. Only config-level errors (STATUS.md
missing, unparseable date) exit 1. Tighten to a hard block by flipping
the relevant return once the warn cycle proves it changes behavior.

Usage:
  python3 tools/check-status-freshness.py          # date + cheap number checks (pre-commit)
  python3 tools/check-status-freshness.py --full    # also re-derive the test count via `make stats`
  make check-status-freshness                       # no-arg form
  make check-status-freshness-full                  # --full form
"""
import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

THRESHOLD_DAYS = 7
STATUS_FILE = Path("STATUS.md")
VERIFICATION_DIR = Path("verification")

DATE_RE = re.compile(
    r"last_synced_to_code:\s*(\d{4}-\d{2}-\d{2})(?:\s*\(([^)]*)\))?"
)
# Total-harness mentions only. Per-crate notes in the Recent-landings
# narrative ("(5 harnesses)", "12 harnesses on src/ipc/...") are
# deliberately NOT matched — only the "N harnesses across M proof crates"
# and "N passing harnesses" totals are checked against the derived count.
HARNESS_TOTAL_RES = (
    re.compile(r"(\d+)\s+harnesses across \d+ proof crates"),
    re.compile(r"(\d+)\s+passing harnesses"),
)
TEST_COUNT_RES = (
    re.compile(r"(\d+)\s+host unit tests"),
    re.compile(r"Total:\s*\*\*(\d+)\*\*"),
)
MAKE_STATS_TESTS_RE = re.compile(r"Tests \(lib\):\s*(\d+)")

_WARNINGS = 0


def warn(msg: str) -> None:
    global _WARNINGS
    _WARNINGS += 1
    print(f"check-status-freshness: WARN: {msg}", file=sys.stderr)


def check_date(text: str) -> int:
    """Date-drift check. Returns 1 only on config error; else 0 (advisory)."""
    match = DATE_RE.search(text)
    if not match:
        print(
            "check-status-freshness: ERROR: `last_synced_to_code: "
            f"YYYY-MM-DD` line not found in {STATUS_FILE} frontmatter",
            file=sys.stderr,
        )
        return 1
    raw_date, annotation = match.group(1), match.group(2)
    try:
        synced = datetime.date.fromisoformat(raw_date)
    except ValueError:
        print(
            "check-status-freshness: ERROR: cannot parse "
            f"`last_synced_to_code: {raw_date}` as a date",
            file=sys.stderr,
        )
        return 1
    drift = (datetime.date.today() - synced).days
    if drift > THRESHOLD_DAYS:
        annot = f" ({annotation})" if annotation else ""
        warn(
            f"STATUS.md last_synced_to_code is {synced.isoformat()}{annot} "
            f"— {drift} days behind today (threshold {THRESHOLD_DAYS}). "
            "Consider a Recent-landings entry, a subsystem-row update, or a "
            "date bump before this commit lands."
        )
    return 0


def count_kani_harnesses():
    """Active `#[kani::proof]` count under verification/. Cheap; no compile.
    Returns None if the directory is absent (wrong cwd)."""
    if not VERIFICATION_DIR.is_dir():
        return None
    count = 0
    for path in VERIFICATION_DIR.rglob("*.rs"):
        if "target" in path.parts:
            continue
        for line in path.read_text(errors="ignore").splitlines():
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            if "#[kani::proof]" in stripped:
                count += 1
    return count


def stated_counts(text: str, patterns) -> list:
    found = []
    for rx in patterns:
        found.extend(int(m) for m in rx.findall(text))
    return found


def check_numbers(text: str, full: bool) -> int:
    """Advisory number-drift checks. Returns the count of genuine drift
    mismatches (operational warnings — missing dir, unparseable `make stats`
    — do not count, so they never trip --strict / CI)."""
    drift = 0

    # --- Kani harnesses: cheap, every run ---
    derived = count_kani_harnesses()
    stated_h = stated_counts(text, HARNESS_TOTAL_RES)
    if derived is None:
        warn("verification/ not found — skipping Kani harness check "
             "(run from repo root).")
    elif stated_h:
        bad = sorted({n for n in stated_h if n != derived})
        if bad:
            drift += 1
            warn(
                f"Kani harness drift: source has {derived} active "
                f"`#[kani::proof]` harnesses, STATUS.md prose states "
                f"{', '.join(map(str, bad))}. Update the harness totals."
            )

    # --- Unit tests: intra-prose consistency always; live compare on --full ---
    stated_t = stated_counts(text, TEST_COUNT_RES)
    if stated_t and len(set(stated_t)) > 1:
        drift += 1
        warn(
            "STATUS.md states inconsistent unit-test counts "
            f"({', '.join(map(str, sorted(set(stated_t))))}) — the prose "
            "disagrees with itself, a partial update."
        )
    if full and stated_t:
        try:
            out = subprocess.run(
                ["make", "stats"], capture_output=True, text=True,
                timeout=900, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            warn(f"--full: could not run `make stats` ({exc}).")
            return drift
        match = MAKE_STATS_TESTS_RE.search(out)
        if not match:
            warn("--full: could not parse Tests(lib) from `make stats`.")
            return drift
        live = int(match.group(1))
        bad = sorted({n for n in stated_t if n != live})
        if bad:
            drift += 1
            warn(
                f"Unit-test drift: `make stats` reports {live} lib tests, "
                f"STATUS.md states {', '.join(map(str, bad))}. Update the "
                "test totals."
            )
    return drift


def main() -> int:
    parser = argparse.ArgumentParser(
        description="STATUS.md freshness advisory (date + number drift)."
    )
    parser.add_argument(
        "--full", action="store_true",
        help="also re-derive the unit-test count via `make stats` "
             "(compiles; for CI / manual use, not the pre-commit hook)",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="exit 1 on objective number drift (Kani/test count mismatch). "
             "The date heuristic stays advisory. For CI enforcement.",
    )
    args = parser.parse_args()

    if not STATUS_FILE.exists():
        print(
            f"check-status-freshness: ERROR: {STATUS_FILE} not found "
            "(run from repository root)",
            file=sys.stderr,
        )
        return 1

    text = STATUS_FILE.read_text()
    rc = check_date(text)
    if rc != 0:
        return rc
    drift = check_numbers(text, full=args.full)

    if args.strict and drift:
        print(
            f"check-status-freshness: FAIL (--strict): {drift} number-drift "
            "issue(s) above must be fixed before this lands.",
            file=sys.stderr,
        )
        return 1

    if _WARNINGS:
        print(
            "Advisory only — not blocking. Per-landing increments are cheaper "
            "than the catch-up sync that recovers from prolonged drift.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
