#!/usr/bin/env python3
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Checks relative links and anchors in Markdown files.

Usage: scripts/check-md-links.py FILE.md [FILE.md ...]

For every [text](target) and <a href="target"> in the given files, outside
code blocks and inline code: the target file must exist in the repository,
and a #fragment must match a heading (GitHub's slug rules, duplicates
numbered) or an explicit id/name anchor in the target Markdown file.
External links (http:, https:, mailto:, ...) are not checked. Exits 1 if
any link is broken.
"""
import html
import pathlib
import re
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent


def strip_code(text):
    """Blank out fenced code blocks and inline code, keeping line numbers."""
    out, fence = [], None
    for line in text.splitlines():
        m = re.match(r"^\s*(```+|~~~+)", line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            out.append("")
            continue
        if m:
            fence = m.group(1)
            out.append("")
            continue
        out.append(re.sub(r"`[^`]*`", "``", line))
    return out


def slug(heading):
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


_anchors = {}


def anchors(path):
    if path not in _anchors:
        found, seen, fence = set(), {}, None
        for line in path.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\s*(```+|~~~+)", line)
            if fence:
                if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                    fence = None
                continue
            if m:
                fence = m.group(1)
                continue
            h = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
            if h:
                s = slug(h.group(1))
                n = seen.get(s, 0)
                seen[s] = n + 1
                found.add(s if n == 0 else f"{s}-{n}")
            for a in re.findall(r'<a\s+(?:id|name)="([^"]+)"', line):
                found.add(a)
        _anchors[path] = found
    return _anchors[path]


LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)|href=\"([^\"]+)\"")


def check(md):
    errors = []
    for no, line in enumerate(strip_code(md.read_text(encoding="utf-8")), 1):
        for m in LINK.finditer(line):
            url = m.group(1) or m.group(2)
            if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I) or url.startswith("//"):
                continue
            target, _, frag = url.partition("#")
            frag = urllib.parse.unquote(frag)
            path = (md.parent / urllib.parse.unquote(target)).resolve() if target else md
            if not path.exists():
                errors.append(f"{md.relative_to(ROOT)}:{no}: missing file: {url}")
                continue
            if frag and path.suffix == ".md" and frag not in anchors(path):
                errors.append(f"{md.relative_to(ROOT)}:{no}: missing anchor: {url}")
    return errors


def main(args):
    if not args:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    errors = []
    for a in args:
        errors += check(pathlib.Path(a).resolve())
    for e in errors:
        print(e)
    print(f"{len(args)} files, {len(errors)} broken links", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
