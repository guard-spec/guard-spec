# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Import triaged red-team reports (GitHub issues) into a staging file.

    uv run --no-project python train/import_issues.py --from-json export.json
    uv run --no-project python train/import_issues.py --repo guard-spec/guard-spec

Reads issues made with the "Bypass" and "False positive" issue forms
(.github/ISSUE_TEMPLATE/) that a maintainer labelled `triage:train` or
`triage:holdout` (docs/red-team.md), either from the GitHub API or from a
local JSON export (the API's issue objects, or `gh issue list --json
number,title,body,labels,author,url`). The API token, if any, comes from
GITHUB_TOKEN or GH_TOKEN and is only sent in the request header; it is never
written anywhere.

Writes to --out (default train/runs/community, gitignored):

    community_train.jsonl    rows for the training split
    community_val.jsonl      rows for the validation split (group hash, as in data/build_data.py)
    community_holdout.jsonl  hold-out rows: never trained, selected or calibrated on
    import_report.json       accepted and refused issues with the reason, reporters to credit

Rows follow the train/data schema (train/DATA_CARD.md): id, text, labels,
lang, variant, source ("community:issue#N"), license, group.

A report is refused when it is not triaged, has no consent line, is in a
language the classifier data does not cover, looks like it contains personal
data or secrets (simple regexes, PII_PATTERNS), or duplicates a text already
in train/data (exact or normalised) or in eval/ (fingerprint, normalised text
or character 5-gram Jaccard above 0.8: the leakage guard of
data/build_data.py). eval/ is only read for that check.

Split: reports that name each other in "Related report" (minimal pairs) share
one group, `community.<lowest issue number>`, so a pair never straddles a
split. A group with any `triage:holdout` issue goes to the hold-out; the
others are split by the hash of the group (12% to val), as in build_data.py.

Standard library only, so it needs neither the training environment nor the
network for --from-json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path

TRAIN_ROOT = Path(__file__).resolve().parent
REPO_ROOT = TRAIN_ROOT.parent
sys.path.insert(0, str(TRAIN_ROOT / "data"))

from common import ATTACK_LABELS, normalize_for_fingerprint, shingles  # noqa: E402

DEFAULT_REPO = "guard-spec/guard-spec"
DEFAULT_OUT = TRAIN_ROOT / "runs" / "community"
LICENSE = "Apache-2.0"
VAL_PCT = 12  # data/build_data.py
JACCARD_MAX = 0.8  # data/build_data.py
MAX_CHARS = 4000

SPLIT_LABELS = {"triage:train": "train", "triage:holdout": "holdout"}
REFUSE_LABELS = {"triage:duplicate", "triage:rejected", "triage:security"}
KIND_LABELS = {"bypass": "bypass", "false-positive": "false_positive"}

LANGUAGES = {
    "English": ("en", "orig"),
    "Vietnamese (with diacritics)": ("vi", "orig"),
    "Vietnamese (without diacritics)": ("vi", "no_diacritics"),
    "Vietnamese (teencode)": ("vi", "teencode"),
}

ATTACK_TYPES = {
    "Direct injection": "direct_injection",
    "Jailbreak": "jailbreak",
    "Prompt extraction": "prompt_extraction",
    "Data exfiltration": "data_exfiltration",
    "Indirect injection": "indirect_injection",
    "Tool poisoning": "tool_poisoning",
    "Obfuscation": "obfuscation",
}

# Where the text appeared → the label it adds to an attack.
WHERE_LABELS = {
    "RAG document": "indirect_injection",
    "Tool result": "indirect_injection",
    "MCP tool description": "tool_poisoning",
}

# ---------------------------------------------------------------------------
# Personal data and secrets
# ---------------------------------------------------------------------------

# Reserved for documentation (RFC 2606 / 6761): placeholders, not personal data.
_PLACEHOLDER_DOMAIN = re.compile(r"(^|\.)(example\.(com|org|net)|example|test|invalid|localhost)$", re.I)
_EMAIL = re.compile(r"[\w.+-]+@((?:[\w-]+\.)+[A-Za-z]{2,})")
_CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("phone number", re.compile(r"(?<![\w+])(?:\+|00)[1-9]\d{0,2}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4}(?!\w)")),
    ("Vietnamese phone number", re.compile(r"(?<!\d)0[35789]\d(?:[ .]?\d{3}[ .]?\d{4}|\d{7})(?!\d)")),
    ("national ID number", re.compile(r"(?<!\d)0\d{11}(?!\d)")),
    ("US social security number", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b")),
    ("API key", re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|"
                           r"github_pat_\w{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|gs_[A-Za-z0-9]{24,})")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JSON web token", re.compile(r"\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}")),
]


def pii_findings(text: str) -> list[str]:
    """Names of the kinds of personal data or secrets that text seems to contain."""
    found = []
    for m in _EMAIL.finditer(text):
        if not _PLACEHOLDER_DOMAIN.search(m.group(1)):
            found.append("e-mail address")
            break
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits) and len(set(digits)) > 1:
            found.append("payment card number")
            break
    found += [name for name, rx in PII_PATTERNS if rx.search(text)]
    return found


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------

def label_names(issue: dict) -> set[str]:
    out = set()
    for lab in issue.get("labels") or []:
        out.add(lab if isinstance(lab, str) else lab.get("name", ""))
    return out - {""}


def author(issue: dict) -> str | None:
    u = issue.get("user") or issue.get("author") or {}
    return u.get("login") if isinstance(u, dict) else None


_FENCE = re.compile(r"^```[\w-]*\n(.*?)\n?```$", re.S)


def parse_form(body: str) -> dict[str, str]:
    """The sections of an issue form body: `### Label` → value (code fences and "_No response_" removed)."""
    sections: dict[str, str] = {}
    current, lines = None, []
    for ln in (body or "").replace("\r\n", "\n").split("\n"):
        if ln.startswith("### "):
            if current is not None:
                sections[current] = "\n".join(lines)
            current, lines = ln[4:].strip(), []
        elif current is not None:
            lines.append(ln)
    if current is not None:
        sections[current] = "\n".join(lines)
    out = {}
    for k, v in sections.items():
        v = v.strip()
        m = _FENCE.match(v)
        if m:
            v = m.group(1)
        out[k] = "" if v == "_No response_" else v
    return out


def checked(section: str, needle: str) -> bool:
    return any(re.match(r"^- \[[xX]\]", ln.strip()) and needle in ln for ln in section.split("\n"))


def related_issues(value: str) -> list[int]:
    return [int(n) for n in re.findall(r"#?(\d+)", value or "")]


class Refused(Exception):
    pass


def issue_kind(issue: dict, labels: set[str]) -> str:
    kinds = {KIND_LABELS[x] for x in labels if x in KIND_LABELS}
    if not kinds:
        title = (issue.get("title") or "").lower()
        if title.startswith("bypass"):
            kinds.add("bypass")
        elif title.startswith("false positive"):
            kinds.add("false_positive")
    if len(kinds) != 1:
        raise Refused("kind unclear: label it either bypass or false-positive")
    return kinds.pop()


def row_labels(kind: str, form: dict[str, str], labels: set[str]) -> list[str]:
    if kind == "false_positive":
        return ["benign"]
    out = {x.split(":", 1)[1] for x in labels if x.startswith("attack:")}
    unknown = out - set(ATTACK_LABELS)
    if unknown:
        raise Refused(f"unknown attack label(s): {', '.join(sorted(unknown))}")
    if not out:
        typ = form.get("Attack type", "")
        out |= {v for k, v in ATTACK_TYPES.items() if typ.startswith(k)}
        where_label = WHERE_LABELS.get(form.get("Where it appeared", ""))
        if where_label:
            out.add(where_label)
    # LABELING.md: obfuscation is a form label and always comes with the label of what the text does.
    if not out - {"obfuscation"}:
        out.add("direct_injection")
    return sorted(out)


def parse_issue(issue: dict) -> dict:
    """One triaged issue → a candidate row with its triage decision; raises Refused."""
    labels = label_names(issue)
    if "pull_request" in issue:
        raise Refused("a pull request, not an issue")
    if labels & REFUSE_LABELS:
        raise Refused(f"labelled {', '.join(sorted(labels & REFUSE_LABELS))}")
    splits = {SPLIT_LABELS[x] for x in labels if x in SPLIT_LABELS}
    if "needs-triage" in labels:
        raise Refused("not triaged yet (still labelled needs-triage)")
    if not splits:
        raise Refused("not triaged (no triage:train or triage:holdout label)")
    kind = issue_kind(issue, labels)
    form = parse_form(issue.get("body") or "")
    consent = form.get("Confirmation", "")
    if not checked(consent, "Apache-2.0"):
        raise Refused("no consent to the Apache-2.0 dataset")
    if not checked(consent, "synthetic or anonymised"):
        raise Refused("not confirmed as synthetic or anonymised")
    text = unicodedata.normalize("NFC", form.get("Prompt", "")).strip()
    if len(text) < 3:
        raise Refused("no prompt text")
    if len(text) > MAX_CHARS:
        raise Refused(f"prompt longer than {MAX_CHARS} characters: trim it in triage")
    lang = LANGUAGES.get(form.get("Language", ""))
    if lang is None:
        raise Refused(f"language {form.get('Language') or 'missing'!r}: the classifier data covers English and Vietnamese only")
    pii = pii_findings(text)
    if pii:
        raise Refused(f"looks like personal data or a secret ({', '.join(pii)}): ask the reporter for a synthetic version")
    return {
        "number": int(issue["number"]),
        "text": text,
        "labels": row_labels(kind, form, labels),
        "lang": lang[0],
        "variant": lang[1],
        "holdout": "holdout" in splits,
        "related": related_issues(form.get("Related report", "")),
        "author": author(issue),
    }


# ---------------------------------------------------------------------------
# Deduplication against train/ and eval/
# ---------------------------------------------------------------------------

class Corpus:
    """Texts already in train/data and eval/: exact, normalised, fingerprints and 5-gram shingles of eval."""

    def __init__(self, train_dir: Path, eval_dir: Path):
        self.train_exact: set[str] = set()
        self.train_norm: set[str] = set()
        for p in sorted(train_dir.rglob("*.jsonl")):
            for t in _texts(p):
                self.train_exact.add(t)
                self.train_norm.add(normalize_for_fingerprint(t))
        self.eval_norm: set[str] = set()
        self.eval_shingles: list[set[str]] = []
        for p in sorted((eval_dir / "data").glob("*.jsonl")):
            for t in _texts(p):
                self.eval_norm.add(normalize_for_fingerprint(t))
                self.eval_shingles.append(shingles(t))
        fp = eval_dir / "fingerprints.txt"
        self.eval_fps = set()
        if fp.exists():
            self.eval_fps = {ln.strip() for ln in fp.read_text(encoding="utf-8").splitlines()
                             if ln.strip() and not ln.startswith("#")}

    def duplicate(self, text: str) -> str | None:
        norm = normalize_for_fingerprint(text)
        if hashlib.sha256(norm.encode("utf-8")).hexdigest() in self.eval_fps or norm in self.eval_norm:
            return "already in eval/ (normalised text or fingerprint); eval/ is never used for training"
        if text in self.train_exact:
            return "duplicate of a train/data row (exact)"
        if norm in self.train_norm:
            return "duplicate of a train/data row (normalised)"
        s = shingles(text)
        best = max((len(s & e) / max(len(s | e), 1) for e in self.eval_shingles), default=0.0)
        if best > JACCARD_MAX:
            return f"near-duplicate of an eval/ row (5-gram Jaccard {best:.2f} > {JACCARD_MAX})"
        return None


def _texts(path: Path) -> Iterable[str]:
    with open(path, encoding="utf-8") as f:
        for ln in f:
            if ln.strip():
                t = json.loads(ln).get("text")
                if isinstance(t, str):
                    yield t


# ---------------------------------------------------------------------------
# Pair-aware split
# ---------------------------------------------------------------------------

def assign_groups(cands: list[dict]) -> dict[int, str]:
    """Issue number → group: reports linked through "Related report" share `community.<lowest number>`."""
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for c in cands:
        find(c["number"])
        for r in c["related"]:
            a, b = find(c["number"]), find(r)
            if a != b:
                parent[max(a, b)] = min(a, b)
    return {c["number"]: f"community.{find(c['number'])}" for c in cands}


def split_of(group: str) -> str:
    h = int(hashlib.sha256(f"split:{group}".encode()).hexdigest(), 16) % 100
    return "val" if h < VAL_PCT else "train"


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def stage(issues: list[dict], corpus: Corpus) -> tuple[dict[str, list[dict]], dict]:
    accepted, refused = [], []
    seen: dict[str, dict] = {}
    for issue in sorted(issues, key=lambda i: int(i.get("number", 0))):
        n = int(issue.get("number", 0))
        try:
            c = parse_issue(issue)
            dup = corpus.duplicate(c["text"])
            if dup:
                raise Refused(dup)
            norm = normalize_for_fingerprint(c["text"])
            if norm in seen:
                first = seen[norm]
                if ("benign" in first["labels"]) != ("benign" in c["labels"]):
                    first["conflict"] = True
                    raise Refused(f"same text as #{first['number']} with the opposite label")
                raise Refused(f"duplicate of #{first['number']}")
            seen[norm] = c
            accepted.append(c)
        except Refused as e:
            refused.append({"issue": n, "reason": str(e)})
    for c in [c for c in accepted if c.get("conflict")]:
        refused.append({"issue": c["number"], "reason": "a later report has the same text with the opposite label"})
    accepted = [c for c in accepted if not c.get("conflict")]

    groups = assign_groups(accepted)
    holdout_groups = {groups[c["number"]] for c in accepted if c["holdout"]}
    out: dict[str, list[dict]] = {"train": [], "val": [], "holdout": []}
    report_rows = []
    for c in accepted:
        g = groups[c["number"]]
        split = "holdout" if g in holdout_groups else split_of(g)
        row = {
            "id": f"{c['lang']}-{hashlib.sha256(c['text'].encode('utf-8')).hexdigest()[:12]}",
            "text": c["text"],
            "labels": c["labels"],
            "lang": c["lang"],
            "variant": c["variant"],
            "source": f"community:issue#{c['number']}",
            "license": LICENSE,
            "group": g,
        }
        out[split].append(row)
        report_rows.append({"issue": c["number"], "id": row["id"], "split": split, "group": g, "labels": c["labels"]})
    for rows in out.values():
        rows.sort(key=lambda r: (r["lang"], r["group"], r["variant"], r["text"]))
    credits = sorted({(c["number"], c["author"]) for c in accepted if c["author"]})
    report = {
        "accepted": sorted(report_rows, key=lambda r: r["issue"]),
        "refused": sorted(refused, key=lambda r: r["issue"]),
        "credits": [{"issue": n, "reporter": a} for n, a in credits],
        "counts": {k: len(v) for k, v in out.items()} | {"refused": len(refused)},
    }
    return out, report


def write(out_dir: Path, rows: dict[str, list[dict]], report: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for split, rs in rows.items():
        with open(out_dir / f"community_{split}.jsonl", "w", encoding="utf-8") as f:
            for r in rs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    (out_dir / "import_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_json(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "items" in data:
        data = data["items"]
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a list of issues")
    return data


Opener = Callable[[urllib.request.Request], "urllib.response.addinfourl"]


def fetch_issues(repo: str, labels: Iterable[str], token: str | None = None,
                 opener: Opener | None = None, api: str = "https://api.github.com") -> list[dict]:
    """Issues of repo with any of labels (open and closed), via the REST API. token is only sent as a header."""
    opener = opener or urllib.request.urlopen
    found: dict[int, dict] = {}
    for label in labels:
        page = 1
        while True:
            q = urllib.parse.urlencode({"labels": label, "state": "all", "per_page": 100, "page": page})
            req = urllib.request.Request(f"{api}/repos/{repo}/issues?{q}", headers={
                "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "guard-spec-import-issues"})
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            with opener(req) as resp:
                batch = json.loads(resp.read().decode("utf-8"))
            for issue in batch:
                if "pull_request" not in issue:
                    found[int(issue["number"])] = issue
            if len(batch) < 100:
                break
            page += 1
    return [found[n] for n in sorted(found)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-json", type=Path, help="local JSON export of issues")
    src.add_argument("--repo", help=f"GitHub repository to read, e.g. {DEFAULT_REPO} (token: GITHUB_TOKEN or GH_TOKEN, optional)")
    ap.add_argument("--label", action="append", help="triage labels to import (default: triage:train and triage:holdout)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory (default: train/runs/community)")
    ap.add_argument("--train-dir", type=Path, default=TRAIN_ROOT / "data", help=argparse.SUPPRESS)
    ap.add_argument("--eval-dir", type=Path, default=REPO_ROOT / "eval", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.from_json:
        issues = load_json(args.from_json)
    else:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None
        issues = fetch_issues(args.repo, args.label or sorted(SPLIT_LABELS), token)
    rows, report = stage(issues, Corpus(args.train_dir, args.eval_dir))
    write(args.out, rows, report)
    c = report["counts"]
    print(f"{len(issues)} issues: train {c['train']}, val {c['val']}, holdout {c['holdout']}, refused {c['refused']} -> {args.out}")
    for r in report["refused"]:
        print(f"  #{r['issue']}: {r['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
