#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Pre-commit advisory: surface STATUS.md drift before it compounds.

Two independent advisory checks, both exit-0 (warn-but-pass) by default, in
the same don't-grow-the-baseline family as the other tools/check-*.py gates.

1. DATE drift — `last_synced_to_code:` more than THRESHOLD_DAYS old.
   Rationale: the 2026-04-22 -> 2026-05-04 12-day drift window that had to
   be recovered in one large catch-up sync. The date moving is not, on its
   own, evidence the content moved.

2. KANI-HARNESS number drift — STATUS.md's stated harness totals no longer
   match the source. Derived CHEAPLY (count active `#[kani::proof]` under
   verification/, no compile) and compared to every *total* stated in the
   prose. Safe to run on every commit.

   The unit-test COUNT is deliberately NOT checked. STATUS.md no longer pins
   a test total in prose — it points at `make stats` instead — because that
   number can only be derived by compiling, and a hardcoded copy drifted CI
   red every time the suite grew (892 -> 903 was the last instance). With no
   pinned number there is nothing to compare and nothing to drift, so the
   `--full`/`make stats` path that used to verify it is gone entirely.

Posture: advisory, exit 0. `--strict` makes objective Kani-harness drift
exit 1 (for CI); the date heuristic always stays advisory. Only config-level
errors (STATUS.md missing, unparseable date) exit 1 unconditionally.

Usage:
  python3 tools/check-status-freshness.py            # date + Kani-harness checks
  python3 tools/check-status-freshness.py --strict   # Kani-harness drift FAILs (CI)
  make check-status-freshness                         # no-arg form
"""
import argparse
import datetime
import re
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


def check_numbers(text: str) -> int:
    """Advisory number-drift check (Kani harnesses). Returns the count of
    genuine drift mismatches; operational warnings (missing verification/ dir)
    do not count, so they never trip --strict / CI."""
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

    # The unit-test count is intentionally NOT checked. STATUS.md no longer
    # pins a total in prose (it points at `make stats`), so there is nothing
    # to drift against and nothing that would need a compile to verify.
    return drift


def main() -> int:
    parser = argparse.ArgumentParser(
        description="STATUS.md freshness advisory (date + Kani-harness drift)."
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="exit 1 on objective Kani-harness drift (source vs prose). "
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
    drift = check_numbers(text)

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
