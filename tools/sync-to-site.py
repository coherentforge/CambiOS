#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sync mirrored docs from the kernel repo to the cambios-site repo.

Phase 1 scope: ADRs only. Reads tools/sync-to-site.toml for the slug map and
the cross-doc reference maps, walks docs/adr/ in the kernel, transforms each
(adds Hugo frontmatter, rewrites internal links to site URLs, falls back to
GitHub blob URLs for kernel docs the site doesn't host), writes the site
copy. Idempotent: re-running on a synced state is a no-op.

Usage:
    python3 tools/sync-to-site.py [--site-dir PATH] [--check] [--only adr]

Environment:
    CAMBIOS_SITE_DIR overrides the default site path from sync-to-site.toml.

Exit codes:
    0  no changes applied (or none needed in --check mode)
    1  changes applied, or changes pending in --check mode
    2  configuration / I/O error
"""
import argparse
import os
import re
import sys
from pathlib import Path

try:
    import tomllib  # py3.11+
except ImportError:
    import tomli as tomllib  # type: ignore

KERNEL_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(__file__).resolve().parent / "sync-to-site.toml"


def load_config() -> dict:
    if not CONFIG_PATH.is_file():
        sys.exit(f"ERROR: config not found at {CONFIG_PATH}")
    with CONFIG_PATH.open("rb") as f:
        return tomllib.load(f)


def resolve_site_dir(args, config) -> Path:
    if args.site_dir:
        return Path(args.site_dir).resolve()
    env = os.environ.get("CAMBIOS_SITE_DIR")
    if env:
        return Path(env).resolve()
    default = config["paths"]["default_site_dir"]
    return (KERNEL_ROOT / default).resolve()


def parse_adr_header(text: str, slug_for_error: str) -> dict:
    """Extract title, status, date from a kernel ADR's first ~10 lines."""
    lines = text.split("\n")
    m = re.match(r"^# ADR-(\d{3}): (.+)$", lines[0])
    if not m:
        sys.exit(f"ERROR: {slug_for_error}: first line must match '# ADR-NNN: <title>': {lines[0]!r}")
    adr_num, title = m.group(1), m.group(2)

    head = "\n".join(lines[:10])
    m_status = re.search(r"(?m)^- \*\*Status:\*\* (.+)$", head)
    m_date = re.search(r"(?m)^- \*\*Date:\*\* (.+)$", head)
    if not m_status or not m_date:
        sys.exit(f"ERROR: {slug_for_error}: missing Status or Date bullet in first 10 lines")

    return {
        "adr_num": adr_num,
        "title": title,
        "status": m_status.group(1).strip(),
        "date": m_date.group(1).strip(),
    }


def rewrite_links(text: str, slug_map: dict, doc_map: dict, root_map: dict, github_url: str) -> str:
    """Rewrite kernel-relative .md links to site URLs (or GitHub fallbacks)."""
    # 1) ADR-to-ADR: ](NNN-kernel-slug.md) or ](NNN-kernel-slug.md#anchor)
    def adr_link(m):
        slug, anchor = m.group(1), m.group(2) or ""
        site_slug = slug_map.get(slug)
        return f"](/adr/{site_slug}/{anchor})" if site_slug else m.group(0)
    text = re.sub(r"\]\((\d{3}-[a-z0-9-]+)\.md(#[^\)]+)?\)", adr_link, text)

    # 2) Sibling docs: ](../FOO.md) -> /docs/foo/ if mapped, else GitHub.
    def sibling_doc(m):
        fname, anchor = m.group(1), m.group(2) or ""
        if fname in doc_map:
            return f"]({doc_map[fname]}{anchor})"
        return f"]({github_url}/docs/{fname}{anchor})"
    text = re.sub(r"\]\(\.\./([A-Za-z][A-Za-z0-9_.-]*\.md)(#[^\)]+)?\)", sibling_doc, text)

    # 3) Repo-root docs: ](../../FOO.md) -> /docs/foo/ if mapped, else GitHub.
    def root_doc(m):
        fname, anchor = m.group(1), m.group(2) or ""
        if fname in root_map:
            return f"]({root_map[fname]}{anchor})"
        return f"]({github_url}/{fname}{anchor})"
    text = re.sub(r"\]\(\.\./\.\./([A-Za-z][A-Za-z0-9_.-]*\.md)(#[^\)]+)?\)", root_doc, text)

    # 4) Source/file links from ADR: ](../../src/...) etc -> GitHub blob.
    text = re.sub(
        r"\]\(\.\./\.\./([a-zA-Z0-9_./#:-]+)\)",
        lambda m: f"]({github_url}/{m.group(1)})",
        text,
    )

    # 5) Sibling subdir links: ](../identity/...) etc -> GitHub.
    text = re.sub(
        r"\]\(\.\./([a-z][a-zA-Z0-9_./#:-]*)\)",
        lambda m: f"]({github_url}/docs/{m.group(1)})",
        text,
    )
    return text


def convert_adr(kernel_path: Path, slug_map, doc_map, root_map, github_url) -> str:
    src = kernel_path.read_text()
    header = parse_adr_header(src, kernel_path.stem)
    body = "\n".join(src.split("\n")[1:])  # drop the H1
    body = rewrite_links(body, slug_map, doc_map, root_map, github_url)

    safe_title = header["title"].replace('"', '\\"')
    fm = (
        "---\n"
        f'title: "{safe_title}"\n'
        f'adr_num: "{header["adr_num"]}"\n'
        f'status: "{header["status"]}"\n'
        f'date_proposed: "{header["date"]}"\n'
        f'weight: {int(header["adr_num"])}\n'
        "---\n"
    )
    return fm + body


def sync_adrs(kernel_root: Path, site_dir: Path, config: dict, check: bool) -> int:
    """Walk kernel docs/adr/, sync each to site content/adr/. Return change count."""
    slug_map = config["slug_map"]
    doc_map = config["doc_map"]
    root_map = config["root_doc_map"]
    github_url = config["paths"]["github_blob_url"]

    kernel_adr_dir = kernel_root / "docs" / "adr"
    site_adr_dir = site_dir / "content" / "adr"
    if not site_adr_dir.is_dir():
        sys.exit(f"ERROR: site ADR dir not found: {site_adr_dir}")

    changes = 0
    for kernel_path in sorted(kernel_adr_dir.glob("[0-9][0-9][0-9]-*.md")):
        kernel_slug = kernel_path.stem
        site_slug = slug_map.get(kernel_slug)
        if site_slug is None:
            print(f"WARN: no slug_map entry for {kernel_slug}; skipping. Add it to sync-to-site.toml.")
            continue
        site_path = site_adr_dir / f"{site_slug}.md"
        new_content = convert_adr(kernel_path, slug_map, doc_map, root_map, github_url)
        old_content = site_path.read_text() if site_path.exists() else ""
        if old_content == new_content:
            continue
        changes += 1
        rel = site_path.relative_to(site_dir)
        if check:
            action = "would update" if site_path.exists() else "would create"
        else:
            action = "updated" if site_path.exists() else "created"
            site_path.write_text(new_content)
        print(f"{action}: {rel}")
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-dir", help="Site repo path (overrides CAMBIOS_SITE_DIR)")
    parser.add_argument("--check", action="store_true", help="Dry-run; print plan, write nothing")
    parser.add_argument("--only", choices=["adr"], help="Restrict to one kind (default: all)")
    args = parser.parse_args()

    config = load_config()
    site_dir = resolve_site_dir(args, config)
    print(f"site dir: {site_dir}")

    total = 0
    if args.only in (None, "adr"):
        total += sync_adrs(KERNEL_ROOT, site_dir, config, args.check)

    verb = "would be applied" if args.check else "applied"
    print(f"\n{total} change(s) {verb}.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
