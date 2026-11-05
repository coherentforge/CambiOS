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
tools/check-doc-refs-baseline.txt; only NEW findings fail. The baseline is
expected to be empty: a drifted ref is repaired, not recorded.

Repair: `python3 tools/check-doc-refs.py --fix` re-anchors every drifted ref
whose symbol has exactly one definition in the cited file (`const` / `static` /
`struct` / `enum` / `type` / `fn` / `union` / `trait NAME`, ignoring a twin
under `#[cfg(kani)]`, `#[cfg(test)]` or `#[cfg(fuzzing)]`). Both the link label
(`path:NN`) and the anchor (`#LNN`) are rewritten. A ref it cannot resolve to
one definition is left alone and still fails the gate: a renamed or deleted
symbol needs a person. Run it after any change that moves a cited constant.

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


# A definition of SYMBOL, as opposed to a use of it.
DEF_KEYWORDS = r"(?:const|static|struct|enum|type|fn|union|trait)"
# A definition under one of these cfgs is a proof/test/fuzz twin of the
# production one (e.g. the `cfg(kani)` shrink of a table bound).
TWIN_CFG_RE = re.compile(r"#\[cfg\((?:kani|test|fuzzing)\)\]")
TWIN_LOOKBACK = 3  # lines above a definition searched for a twin cfg


def definition_line(tgt_lines, sym: str):
    """1-based line of SYMBOL's single production definition, or None when
    there is none or more than one (ambiguous: left for a person)."""
    def_re = re.compile(r"\b" + DEF_KEYWORDS + r"\s+" + re.escape(sym) + r"\b")
    hits = [i for i, text in enumerate(tgt_lines, 1) if def_re.search(text)]
    production = [
        i for i in hits
        if not any(
            TWIN_CFG_RE.search(tgt_lines[j - 1])
            for j in range(max(1, i - TWIN_LOOKBACK), i)
        )
    ]
    pick = production if production else hits
    return pick[0] if len(pick) == 1 else None


def fix_doc(doc: Path) -> int:
    """Re-anchor drifted line refs in place. Returns the number rewritten."""
    lines = doc.read_text(encoding="utf-8").splitlines(keepends=True)
    fixed = 0
    for i, row in enumerate(lines):
        if not row.lstrip().startswith("|"):
            continue
        sym = symbol_of(row)
        if not sym:
            continue
        for relpath, lineno in LINK_RE.findall(row):
            if not lineno:
                continue
            target = (doc.parent / relpath).resolve()
            if not target.exists() or target.suffix not in (".rs", ".S", ".ld", ".toml"):
                continue
            try:
                tgt_lines = target.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            ln = int(lineno)
            if ln <= len(tgt_lines):
                lo = max(1, ln - PROX_WINDOW)
                hi = min(len(tgt_lines), ln + PROX_WINDOW)
                if sym in "\n".join(tgt_lines[lo - 1 : hi]):
                    continue  # ref is good
            new_ln = definition_line(tgt_lines, sym)
            if new_ln is None or new_ln == ln:
                continue
            # Rewrite the anchor and, when the label repeats the line
            # (`[src/x.rs:NN](../src/x.rs#LNN)`), the label too.
            old_anchor = f"({relpath}#L{ln})"
            new_anchor = f"({relpath}#L{new_ln})"
            label_path = relpath.lstrip("./")
            row = row.replace(f"[{label_path}:{ln}]{old_anchor}", f"[{label_path}:{new_ln}]{new_anchor}")
            row = row.replace(old_anchor, new_anchor)
            fixed += 1
        lines[i] = row
    if fixed:
        doc.write_text("".join(lines), encoding="utf-8")
    return fixed


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
    if "--fix" in argv:
        for doc in SCAN_DOCS:
            if doc.exists():
                n = fix_doc(doc)
                print(f"check-doc-refs: re-anchored {n} ref(s) in {doc.name}")
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
        print("Repair drifted refs with `python3 tools/check-doc-refs.py --fix`; "
              "a ref it leaves behind names a symbol that no longer has one "
              "definition in the cited file.", file=sys.stderr)
        return 1
    print("check-doc-refs OK: no new findings")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
