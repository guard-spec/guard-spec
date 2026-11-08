#!/usr/bin/env python3
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Turns Trivy JSON reports into the body of a GitHub issue.

    python3 scripts/vuln-report.py TITLE REPORT.json [REPORT.json ...] > body.md

Prints Markdown with one table row per vulnerability (package, installed and
fixed version, severity) and exits 0 when there are none, 1 when there are.
Used by the daily scan of released images (.github/workflows/vuln-scan.yml).
"""
import json
import sys

MAX_ROWS = 300  # keeps the issue body under GitHub's 65,536 characters
ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def rows(path):
    with open(path, encoding="utf-8") as f:
        report = json.load(f)
    name = report.get("ArtifactName", path)
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            yield (
                ORDER.get(v.get("Severity", "UNKNOWN"), 4),
                name,
                result.get("Target", ""),
                v.get("VulnerabilityID", ""),
                v.get("PkgName", ""),
                v.get("InstalledVersion", ""),
                v.get("FixedVersion", "") or "no fix yet",
                v.get("Severity", "UNKNOWN"),
            )


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    title, paths = argv[1], argv[2:]
    found = sorted({r for p in paths for r in rows(p)})
    print(f"## {title}\n")
    if not found:
        print("No known vulnerabilities.")
        return 0
    fixable = sum(1 for r in found if r[6] != "no fix yet")
    print(f"{len(found)} known vulnerabilities, {fixable} with a fixed version. "
          "Fix them with a patch release (SECURITY.md: Critical within 48 hours, High within 7 days), "
          "or record why one does not apply in `.vex/guard-spec.openvex.json`.\n")
    print("| Image | Target | ID | Package | Installed | Fixed | Severity |")
    print("|---|---|---|---|---|---|---|")
    for _, image, target, vid, pkg, inst, fixed, sev in found[:MAX_ROWS]:
        print(f"| {image} | {target} | {vid} | {pkg} | {inst} | {fixed} | {sev} |")
    if len(found) > MAX_ROWS:
        print(f"\n{len(found) - MAX_ROWS} more of the lowest severities left out; the workflow run has the full reports.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
