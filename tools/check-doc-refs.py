#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca
"""
check-doc-refs: verify source line-references in docs resolve to live code.

Anti-hallucination / anti-drift lint. A doc that cites `src/foo.rs:NN` is a
claim that can rot (the line moves) or be fabricated (an agent invents a line).
CI verifies code compiles; it does NOT verify a doc's prose. This closes that
gap for the highest-value case: the ASSUMPTIONS.md numeric-bound catalog, whose
rows point at the const that defines each bound. HD-01 (the MAX_VMAS ref drifting
from :33 to :35) is the canonical defect this catches.

For each markdown table row in the scanned doc(s):
  - every `[label](relpath#LNN)` ref must resolve to an existing file with >= NN
    lines (catches dangling / over-range / fabricated refs);
  - if the row names a backtick-quoted SYMBOL (first inline-code token) and the
    ref points at a source file, that SYMBOL must appear within +-1 line of NN
    (catches drift:
    the cited line no longer holds the symbol it claims to).

Don't-grow-the-baseline gate: existing acceptable mismatches live in
tools/check-doc-refs-baseline.txt; only NEW findings fail. Refresh the baseline
with `make update-doc-refs-baseline` after a legitimate change.

Scope: ASSUMPTIONS.md today (extend SCAN_DOCS as other catalogs gain line-refs).

Exit status:
  0 — no new findings
  1 — new findings beyond baseline
  2 — a scanned doc is missing
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = Path(__file__).resolve().parent / "check-doc-refs-baseline.txt"

# Docs that carry source line-refs worth verifying. Extend as needed.
SCAN_DOCS = [ROOT / "docs" / "ASSUMPTIONS.md"]

PROX_WINDOW = 1  # symbol must appear within +-this many lines of the cited line

# [label](relpath) with optional #LNN anchor; relpath points at a repo file.
LINK_RE = re.compile(r"\[[^\]]+\]\((\.\.?/[^)#]+?)(?:#L(\d+))?\)")
# first inline-code token in a row, e.g. `MAX_VMAS` -> MAX_VMAS
BACKTICK_RE = re.compile(r"`([^`]+)`")


def symbol_of(row: str):
    """First backtick token, reduced to a bare identifier (drop ' (per ...)' etc.)."""
    m = BACKTICK_RE.search(row)
    if not m:
        return None
    tok = m.group(1).strip()
    # keep the leading identifier-ish chunk: MAX_VMAS, HEAP_SIZE, Option<...> -> MAX_VMAS
    idm = re.match(r"[A-Za-z_][A-Za-z0-9_]*", tok)
    return idm.group(0) if idm else None


def scan_doc(doc: Path):
    """Return list of finding strings for one doc."""
    findings = []
    if not doc.exists():
        return None  # signals missing
    lines = doc.read_text(encoding="utf-8").splitlines()
    for i, row in enumerate(lines, 1):
        if not row.lstrip().startswith("|"):
            continue
        sym = symbol_of(row)
        for relpath, lineno in LINK_RE.findall(row):
            target = (doc.parent / relpath).resolve()
            rel = relpath.split("/")[-1]
            if not target.exists():
                findings.append(f"{doc.name}:{i}: ref -> {relpath} (file not found)")
                continue
            if not lineno:
                continue
            ln = int(lineno)
            try:
                tgt_lines = target.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                findings.append(f"{doc.name}:{i}: ref -> {relpath} (unreadable)")
                continue
            if ln > len(tgt_lines):
                findings.append(
                    f"{doc.name}:{i}: ref -> {rel}#L{ln} (out of range; file has {len(tgt_lines)} lines)"
                )
                continue
            # symbol-proximity (only for source files where the row names a symbol)
            if sym and target.suffix in (".rs", ".S", ".ld", ".toml"):
                lo = max(1, ln - PROX_WINDOW)
                hi = min(len(tgt_lines), ln + PROX_WINDOW)
                window = "\n".join(tgt_lines[lo - 1 : hi])
                if sym not in window:
                    findings.append(
                        f"{doc.name}:{i}: `{sym}` ref -> {rel}#L{ln} "
                        f"(symbol not within +-{PROX_WINDOW} of cited line; drifted?)"
                    )
    return findings


def load_baseline():
    if not BASELINE.exists():
        return set()
    return {
        ln.strip()
        for ln in BASELINE.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    }


def main(argv) -> int:
    write_baseline = "--update-baseline" in argv
    all_findings = []
    for doc in SCAN_DOCS:
        res = scan_doc(doc)
        if res is None:
            print(f"check-doc-refs: {doc} not found", file=sys.stderr)
            return 2
        all_findings.extend(res)

    if write_baseline:
        BASELINE.write_text(
            "# check-doc-refs baseline — known-acceptable doc->source ref mismatches.\n"
            "# Regenerate with `make update-doc-refs-baseline`. New entries beyond this set fail the gate.\n"
            + "".join(f"{f}\n" for f in sorted(all_findings)),
            encoding="utf-8",
        )
        print(f"check-doc-refs: baseline written with {len(all_findings)} entries")
        return 0

    baseline = load_baseline()
    new = [f for f in all_findings if f not in baseline]
    print(
        f"check-doc-refs: scanned; {len(all_findings)} total findings, "
        f"{len(baseline)} baseline, {len(new)} new"
    )
    if new:
        print("check-doc-refs: NEW findings (doc ref drifted or fabricated):", file=sys.stderr)
        for f in new:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("check-doc-refs OK: no new findings")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
