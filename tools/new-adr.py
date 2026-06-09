#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
new-adr: allocate the next ADR number and scaffold its file.

The next number is the single thing nobody should eyeball. This derives it
from the actual docs/adr/*.md files (max existing + 1), so it can never drift
from reality, and writes a stub with the canonical header. The duplicate-number
guard in check-adrs.py is the backstop if a number is ever chosen by hand.

Usage:
  python3 tools/new-adr.py "Native App Framework: runtime, IPC stdlib, toolkit"
  make new-adr TITLE="Native App Framework"

Exit status:
  0 — stub created
  1 — bad usage, or target file already exists
  2 — ADR directory missing
"""

import datetime
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADR_DIR = ROOT / "docs" / "adr"
ADR_FILE_RE = re.compile(r"^(\d{3})-.*\.md$")

TEMPLATE = """# ADR-{num}: {title}

- **Status:** Proposed
- **Date:** {date}
- **Depends on:** N/A
- **Related:** N/A
- **Supersedes:** N/A

## Context

<why this decision is needed — the problem, what prompted it>

## Decision

<the decision>

## Consequences

<trade-offs: what this enables, what it costs, what it forecloses>
"""


def slugify(title: str) -> str:
    s = title.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


def next_num() -> int:
    highest = 0
    for path in ADR_DIR.glob("*.md"):
        m = ADR_FILE_RE.match(path.name)
        if m:
            highest = max(highest, int(m.group(1)))
    return highest + 1


def main(argv) -> int:
    if not ADR_DIR.is_dir():
        print(f"new-adr: {ADR_DIR} not found", file=sys.stderr)
        return 2
    title = " ".join(argv).strip()
    if not title:
        print('usage: new-adr.py "Title of the decision"', file=sys.stderr)
        return 1
    # A ":" subtitle is fine in the header but not the filename slug.
    slug = slugify(title.split(":")[0])
    if not slug:
        print("new-adr: title produced an empty slug", file=sys.stderr)
        return 1

    num = next_num()
    num3 = f"{num:03d}"
    path = ADR_DIR / f"{num3}-{slug}.md"
    if path.exists():
        print(f"new-adr: {path.name} already exists — refusing to overwrite", file=sys.stderr)
        return 1

    date = datetime.date.today().isoformat()
    path.write_text(TEMPLATE.format(num=num3, title=title, date=date), encoding="utf-8")
    print(f"created {path.relative_to(ROOT)}")
    print("next: fill in the body, then `make check-adrs` to validate + refresh INDEX.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
