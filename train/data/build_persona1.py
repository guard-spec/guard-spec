# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Build `persona1`: benign persona and system prompts, and in-the-wild jailbreaks, for RF-f9d52639.

Splits, fixed before any score (train/reports/persona1_preregistration.md):

  dev/      prompts.chat rows of half of its "act" names, enterprise prompts of every other role (EN and VI),
            and community role-play prompts from TrustAIRLab's "regular" set that short1 did not take.
  holdout/  prompts.chat rows of the other names, enterprise prompts of the other roles, TrustAIRLab
            jailbreaks that short1 did not take, and JailbreakBench artifacts (PAIR, JBC, random search),
            label-audited before scoring.

Written as `cmd/eval` data (`<split>/direct/{en,vi}.jsonl`, scored with `-path direct`). Rows that overlap an
earlier training, evaluation or benchmark row, or any `short1` row, are dropped (hash and shingle overlap only;
short1 is never scored).

    uv run --frozen python data/build_persona1.py --raw <raw dir> --tw <short1 raw dir> --out <out dir>
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_short1 import ATTACK_MARKERS, build_prior, mostly_latin, norm, shingles  # noqa: E402
from persona1_templates import persona_templates  # noqa: E402

SEED = 20261117
REV = {
    "prompts_chat": "5137e6dc22bf915a19f1c013149da8f07c978e2e",  # fka/prompts.chat (HF), CC0-1.0
    "tw": "a10aab8eff1c73165a442d4464dce192bd28b9c5",  # TrustAIRLab/in-the-wild-jailbreak-prompts, MIT (as short1)
    "jbb": "see raw/revisions.txt",  # JailbreakBench/artifacts (GitHub), MIT: PAIR, JBC, prompt_with_random_search
}
JBB_METHODS = ("PAIR", "JBC", "prompt_with_random_search")
MIN_CHARS, MAX_CHARS = 20, 6000
PRIOR_CONTAIN = 0.5
NEAR_DUP = 0.7
CAP = {("tw_jailbreak", "holdout"): 400, ("tw_roleplay", "dev"): 300, ("prompts_chat", "dev"): 500,
       ("prompts_chat", "holdout"): 500}  # every holdout row of prompts.chat is label-audited
ROLEPLAY = re.compile(r"(?i)\b(act as|you are (a|an|the|my)\b|pretend (to be|you are)|role ?play|from now on you|"
                      r"i want you to act|take on the role|stay in character|persona)\b")


def h12(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()[:12]


def order_key(t: str) -> str:
    return hashlib.sha256(f"{SEED}:{t}".encode()).hexdigest()


def half(key: str) -> str:
    return "holdout" if int(order_key("split:" + key)[:8], 16) % 2 else "dev"


def load(raw: Path, tw: Path) -> list[dict]:
    rows = []
    csv.field_size_limit(1 << 30)
    with open(raw / "prompts_chat.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r.get("type") == "IMAGE":
                continue
            rows.append({"text": r["prompt"], "label": "benign", "lang": "en", "stratum": "prompts_chat",
                         "split": half(r["act"]), "source": f"fka/prompts.chat:{r.get('type', '')}"})
    for r in pq.read_table(tw / "tw_jailbreak.parquet").to_pylist():
        if r["jailbreak"] and mostly_latin(r["prompt"] or ""):
            rows.append({"text": r["prompt"], "label": "attack", "lang": "en", "stratum": "tw_jailbreak",
                         "split": "holdout", "source": f"TrustAIRLab/in-the-wild-jailbreak-prompts:jailbreak:{r['platform']}"})
    for r in pq.read_table(tw / "tw_regular.parquet").to_pylist():
        t = r["prompt"] or ""
        if not r["jailbreak"] and mostly_latin(t) and ROLEPLAY.search(t):
            rows.append({"text": t, "label": "benign", "lang": "en", "stratum": "tw_roleplay", "split": "dev",
                         "source": f"TrustAIRLab/in-the-wild-jailbreak-prompts:regular:{r['platform']}"})
    for m in JBB_METHODS:
        for f in sorted((raw / "jbb" / "attack-artifacts" / m).glob("*/*.json")):
            for j in json.load(open(f, encoding="utf-8")).get("jailbreaks", []):
                if j.get("prompt"):
                    rows.append({"text": j["prompt"], "label": "attack", "lang": "en", "stratum": "jbb_" + m.lower(),
                                 "split": "holdout", "source": f"JailbreakBench/artifacts:{m}:{f.stem}:{j.get('category', '')}"})
    return rows + persona_templates(SEED)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, type=Path)
    ap.add_argument("--tw", required=True, type=Path, help="short1's raw dir (TrustAIRLab parquet files)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--data", type=Path, default=Path("~/WorkingSpace/AI_R_D/guardspec-data").expanduser())
    ap.add_argument("--cache", type=Path, default=Path("~/.cache/guardspec-short1").expanduser())
    ap.add_argument("--short1", type=Path,
                    default=Path("~/WorkingSpace/AI_R_D/guardspec-data/v8/v8e/short1/out").expanduser())
    a = ap.parse_args()

    exact, prior, files = build_prior(a.repo, a.data, a.cache)
    n = 0
    for p in sorted(a.short1.glob("*/*.jsonl")):
        for line in open(p, encoding="utf-8"):
            t = json.loads(line).get("text")
            if t:
                exact.add(norm(t)); prior.update(shingles(t)); n += 1
    files["<short1, hashed only>"] = n

    rows = load(a.raw, a.tw)
    rep = {"seed": SEED, "revisions": REV, "prior_files": files, "strata": {}}
    order = {"holdout": 0, "dev": 1}
    rows.sort(key=lambda r: (order[r["split"]], r["stratum"], order_key(r["text"])))
    kept_exact: set[str] = set()
    kept_sh: dict[str, list[set[int]]] = {"holdout": [], "dev": []}
    counts: dict[tuple[str, str], int] = {}
    out: dict[str, dict[str, list[dict]]] = {s: {"en": [], "vi": []} for s in order}
    for r in rows:
        key = (r["stratum"], r["split"])
        c = rep["strata"].setdefault(f"{r['stratum']}/{r['split']}", {"candidates": 0})
        c["candidates"] += 1

        def drop(why):
            c[why] = c.get(why, 0) + 1
        t = (r["text"] or "").strip()
        if not (MIN_CHARS <= len(t) <= MAX_CHARS):
            drop("length"); continue
        if r["label"] == "benign" and not r["stratum"].startswith("enterprise") and ATTACK_MARKERS.search(t):
            drop("attack_marker"); continue
        nt = norm(t)
        if nt in exact:
            drop("prior_exact"); continue
        sh = shingles(t)
        if len(sh & prior) / len(sh) >= PRIOR_CONTAIN:
            drop("prior_overlap"); continue
        if key in CAP and counts.get(key, 0) >= CAP[key]:
            drop("cap"); continue
        if nt in kept_exact:
            drop("exact_dup"); continue
        # Template rows of one role share wording by design (the split is by role), so they are not near-duplicates.
        pools = [] if r["stratum"].startswith("enterprise") else kept_sh["holdout"] + (kept_sh["dev"] if r["split"] == "dev" else [])
        if any(len(sh & k) / len(sh | k) >= NEAR_DUP for k in pools):
            drop("near_dup"); continue
        kept_exact.add(nt); kept_sh[r["split"]].append(sh)
        counts[key] = counts.get(key, 0) + 1
        c["kept"] = c.get("kept", 0) + 1
        cat = "jailbreak" if r["label"] == "attack" else "benign"
        out[r["split"]][r["lang"]].append({"id": f"persona1-{r['stratum']}-{h12(t)}", "text": t, "label": r["label"],
                                           "category": cat, "lang": r["lang"], "variant": "orig",
                                           "source": r["source"], "stratum": r["stratum"]})
    sums = {}
    for split, by_lang in out.items():
        d = a.out / split / "direct"
        d.mkdir(parents=True, exist_ok=True)
        for lang, rs in by_lang.items():
            if not rs:
                continue
            rs.sort(key=lambda x: x["id"])
            p = d / f"{lang}.jsonl"
            with open(p, "w", encoding="utf-8") as fh:
                for x in rs:
                    fh.write(json.dumps(x, ensure_ascii=False) + "\n")
            sums[f"{split}/direct/{lang}.jsonl"] = hashlib.sha256(p.read_bytes()).hexdigest()
    rep["outputs_sha256"] = sums
    rep["totals"] = {f"{s}/{lang}/{st}": sum(1 for x in rs if x["stratum"] == st)
                     for s, by in out.items() for lang, rs in by.items() for st in sorted({x["stratum"] for x in rs})}
    (a.out / "build_report.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n")
    (a.out / "SHA256SUMS").write_text("".join(f"{h}  {p}\n" for p, h in sorted(sums.items())))
    print(json.dumps(rep["totals"], indent=1))


if __name__ == "__main__":
    main()
