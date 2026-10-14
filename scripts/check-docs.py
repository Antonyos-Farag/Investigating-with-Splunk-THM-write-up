#!/usr/bin/env python3
"""
Documentation checks for the write-up.

Verifies, without any third-party dependencies:

1. every local link and anchor in README.md resolves;
2. the table of contents matches the actual headings, in order, with no orphans;
3. no `images/` references have crept back in;
4. code fences are balanced and no line is left with trailing whitespace;
5. the question sections keep their required structure.

Usage:  python3 scripts/check-docs.py [path/to/README.md]
Exit:   0 clean, 1 problems found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

REQUIRED_BLOCKS = ("**Objective**", "**Approach**", "**SPL**", "**Answer**")


def slug(heading: str) -> str:
    """GitHub's anchor algorithm: lowercase, drop everything but alphanumerics,
    spaces and hyphens, then swap spaces for hyphens."""
    text = heading.strip().lower()
    text = re.sub(r"`", "", text)
    text = re.sub(r"[^a-z0-9 -]", "", text)
    return text.replace(" ", "-")


def strip_fences(lines: list[str]) -> list[tuple[int, str]]:
    """Return (line_no, text) for lines outside fenced code blocks."""
    out, open_fence = [], None
    for i, line in enumerate(lines, 1):
        m = re.match(r"^\s*(```+|~~~+)", line)
        if m:
            marker = m.group(1)[0] * 3
            if open_fence is None:
                open_fence = marker
            elif open_fence == marker:
                open_fence = None
            continue
        out.append((i, line))
    return out, open_fence


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else README
    if not path.is_file():
        print(f"FAIL  {path} not found")
        return 1

    raw = path.read_text(encoding="utf-8")
    lines = raw.split("\n")
    prose, unclosed = strip_fences(lines)

    problems: list[str] = []
    if unclosed is not None:
        problems.append("unbalanced code fence (a ``` block is never closed)")
    if raw.count("```") % 2:
        problems.append("odd number of ``` fences")

    # --- headings, anchors -------------------------------------------------
    hdls = [re.match(r"^(#{1,6})\s*(.*)$", t) for n, t in prose]
    hdls = [m for m in hdls if m]
    levels = [len(m.group(1)) for m in hdls]
    headings = [m.group(2).strip() for m in hdls]
    slugs, seen = [], {}
    for h in headings:
        s = slug(h)
        seen[s] = seen.get(s, 0) + 1
        slugs.append(f"{s}-{seen[s] - 1}" if seen[s] > 1 else s)
    anchors = set(slugs)

    # --- links -------------------------------------------------------------
    toc_links: list[tuple[str, int]] = []
    for n, t in prose:
        for text, target in re.findall(r"\[([^\]]+)\]\(([^)\s]+)\)", t):
            if target.startswith("#"):
                toc_links.append((target, n))
                if target[1:] not in anchors:
                    problems.append(f"line {n}: anchor {target} matches no heading")
            elif re.match(r"^[a-z]+://", target):
                continue  # remote link — not checked offline
            else:
                if not (path.parent / target.split("#")[0]).exists():
                    problems.append(f"line {n}: local link {target} does not exist")

    # --- table of contents coverage --------------------------------------
    toc = re.findall(r"^\s*- \[[^\]]+\]\((#[^)]+)\)", raw, re.M)
    major = [s for s, h, lv in zip(slugs, headings, levels) if lv == 2 and h != "Table of contents"]
    toc_major = [t[1:] for t in toc if not t.startswith("#q")]
    if toc_major != major:
        problems.append(
            "table of contents out of sync with the H2 sections\n"
            f"    toc:     {', '.join(toc_major) or '(empty)'}\n"
            f"    heading: {', '.join(major) or '(empty)'}"
        )
    for q in sorted({s for s in slugs if re.match(r"^q\d", s)}):
        if f"#{q}" not in toc:
            problems.append(f"question section {q} is missing from the table of contents")

    # --- repo conventions --------------------------------------------------
    if "images/" in raw:
        problems.append("`images/` referenced, but the repository holds no screenshots")
    for n, t in prose:
        if t.rstrip() != t and t.strip():
            problems.append(f"line {n}: trailing whitespace")

    # --- question structure ------------------------------------------------
    parts = re.split(r"^### (Q\d[^\n]*)$", raw, flags=re.M)
    titles, bodies = parts[1::2], parts[2::2]
    # Each question ends at the next heading of any level, so text from later
    # sections can never satisfy a question's required blocks.
    bodies = [re.split(r"^#{2,3}\s", b, flags=re.M)[0] for b in bodies]
    for title, body in zip(titles, bodies):
        for block in REQUIRED_BLOCKS:
            if block not in body:
                problems.append(f"{title.strip()}: missing {block}")
    if len(titles) != 9:
        problems.append(f"expected 9 question sections, found {len(blocks)}")

    if problems:
        print(f"FAIL  {len(problems)} problem(s) in {path.name}:")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(
        f"OK    {path.name}: {len(headings)} headings, {len(anchors)} anchors, "
        f"{len(toc_links)} in-page links, 9 question sections — all resolved."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
