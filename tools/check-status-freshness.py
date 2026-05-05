#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
Pre-commit advisory: warn when STATUS.md's `last_synced_to_code:` is
stale by more than THRESHOLD_DAYS.

Context: STATUS.md is the load-bearing answer to "is X done yet?"
The Post-Change Review §8 checklist asks every commit to update
the relevant subsystem row + bump `last_synced_to_code:` when it
moves. In practice that did not fire on most of the 110 commits
between 2026-04-22 and 2026-05-04, producing a 12-day drift window
where major architectural decisions (ADR-025/026/027, multi-Principal
vault Phase 1C, ADR-022 wall-clock implementation, two new proof
crates) were unrepresented in the index. The catch-up sync had to
recover that drift in one large doc commit instead of incremental
updates per landing.

This lint surfaces drift before it compounds. Same shape as the
existing don't-grow-the-baseline gates: noisy enough to read, not
bossy enough to block.

# Behavior

- Locate `last_synced_to_code: YYYY-MM-DD` in STATUS.md's frontmatter
  (the HTML comment block at the top).
- Compute drift = today - that_date in days.
- If drift > THRESHOLD_DAYS, print one stderr line naming the
  drift and the trailing parenthetical (the human-readable
  description from the date marker). Exit 0 — advisory.
- Otherwise exit 0 silently.

Pre-CI / pre-HN posture: this is informational, not blocking.
Tightening to a hard block becomes worth it when the warn cycle
proves it does not change behavior — at that point swap exit 0
for exit 1 here. Convention 9 cadence: prose first (the warning
message), then mechanism on first failure-to-respond.

# Threshold

7 days. Calibrated against the cause: a working week of accumulated
landings without sync is the point where catch-up cost (reading 7
days of git log to reconstruct what's missing) starts to exceed the
incremental cost (1-3 lines per commit). N=14 would tolerate one
slow week silently; N=7 catches that case while still permitting
weekend-only quiet stretches without noise.

# Edge cases

- STATUS.md missing or `last_synced_to_code:` line not found:
  exit 1 (config-level error, not advisory).
- Date unparseable (typo, wrong format): exit 1.
- Date in the future: drift = 0, silent pass. The human knows
  what they're doing; reverse drift is not what this lint catches.

Usage:
  python3 tools/check-status-freshness.py
  make check-status-freshness     # same, via Makefile

Bypass:
  None needed — advisory only. If desired, pipe stderr to /dev/null
  in CI noise contexts.
"""
import datetime
import re
import sys
from pathlib import Path

THRESHOLD_DAYS = 7
STATUS_FILE = Path("STATUS.md")
DATE_RE = re.compile(
    r"last_synced_to_code:\s*(\d{4}-\d{2}-\d{2})(?:\s*\(([^)]*)\))?"
)


def main() -> int:
    if not STATUS_FILE.exists():
        print(
            f"check-status-freshness: ERROR: {STATUS_FILE} not found "
            f"(run from repository root)",
            file=sys.stderr,
        )
        return 1

    text = STATUS_FILE.read_text()
    match = DATE_RE.search(text)
    if not match:
        print(
            f"check-status-freshness: ERROR: `last_synced_to_code: "
            f"YYYY-MM-DD` line not found in {STATUS_FILE} frontmatter",
            file=sys.stderr,
        )
        return 1

    raw_date, annotation = match.group(1), match.group(2)
    try:
        synced = datetime.date.fromisoformat(raw_date)
    except ValueError:
        print(
            f"check-status-freshness: ERROR: cannot parse "
            f"`last_synced_to_code: {raw_date}` as a date",
            file=sys.stderr,
        )
        return 1

    today = datetime.date.today()
    drift = (today - synced).days

    if drift <= THRESHOLD_DAYS:
        return 0  # Fresh enough; silent pass.

    annot = f" ({annotation})" if annotation else ""
    print(
        f"check-status-freshness: WARN: STATUS.md last_synced_to_code "
        f"is {synced.isoformat()}{annot} — {drift} days behind today "
        f"({today.isoformat()}, threshold {THRESHOLD_DAYS}).",
        file=sys.stderr,
    )
    print(
        "Consider whether recent commits warrant a Recent-landings "
        "entry, a subsystem-table row update, or a date bump before "
        "this commit lands. Per-landing increments are cheaper than "
        "the catch-up sync that recovers from prolonged drift.",
        file=sys.stderr,
    )
    print(
        "Advisory only — this commit is not blocked. The lint hardens "
        "to exit 1 once the warn cycle proves it does not change "
        "behavior; see tools/check-status-freshness.py for the trigger.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
