# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""Build `short1`, the fresh short-prompt holdout of v8e (RF-b15702bf, train/reports/v8e_short_preregistration.md).

Every rule here is fixed by the pre-registration. The script reads only public sources pinned below, drops rows
that overlap any earlier training, validation, evaluation or benchmark row, samples with a fixed seed and writes
two `cmd/eval` data directories:

  <out>/direct/{en,vi}.jsonl   user messages (`cmd/eval -path direct`)
  <out>/tool/en.jsonl          email bodies (`cmd/eval -path tool`)

plus <out>/build_report.json (counts after each filter) and <out>/SHA256SUMS. No model is loaded.

    uv run --frozen python data/build_short1.py --raw <raw dir> --out <out dir>
"""
from __future__ import annotations

import argparse
import csv
import glob
import gzip
import hashlib
import json
import os
import re
import unicodedata
from pathlib import Path

import pyarrow.parquet as pq

SEED = 20261115
REV = {
    "tw": "a10aab8eff1c73165a442d4464dce192bd28b9c5",  # TrustAIRLab/in-the-wild-jailbreak-prompts, MIT
    "llmail": "1063bdf01ec8762b812d5e06ee768a06faa5a6f7",  # microsoft/llmail-inject-challenge, MIT
    "wildchat": "7d6490e462285cf85d91eabea0f9a954fbddcd1f",  # allenai/WildChat-1M, ODC-BY
    "hs3": "f6d145777bcbde96137596340fab89793acd1031",  # nvidia/HelpSteer3, CC-BY-4.0
}
RAW_FILES = {
    "tw_jailbreak.parquet": "TrustAIRLab/in-the-wild-jailbreak-prompts jailbreak_2023_12_25/train-00000-of-00001.parquet",
    "tw_regular.parquet": "TrustAIRLab/in-the-wild-jailbreak-prompts regular_2023_12_25/train-00000-of-00001.parquet",
    "llmail_phase2.json": "microsoft/llmail-inject-challenge data/labelled_unique_submissions_phase2.json",
    "llmail_fp_emails.json": "microsoft/llmail-inject-challenge data/emails_for_fp_tests.json",
    "wildchat_00.parquet": "allenai/WildChat-1M data/train-00000-of-00014.parquet",
    "wildchat_01.parquet": "allenai/WildChat-1M data/train-00001-of-00014.parquet",
    "hs3_pref_train.jsonl.gz": "nvidia/HelpSteer3 preference/train.jsonl.gz",
    "hs3_pref_val.jsonl.gz": "nvidia/HelpSteer3 preference/validation.jsonl.gz",
}
# Sample sizes per stratum (an upper bound: a stratum with fewer rows after the filters keeps them all).
SIZES = {
    "tw_jailbreak": 500,
    "tw_regular": 500,
    "wildchat_en": 500,
    "wildchat_vi": 300,
    "hs3_vi": 300,
    "llmail_attack": 400,
    "llmail_benign": 300,
}
MIN_CHARS, MAX_CHARS = 20, 6000
SHINGLE = 8  # words per shingle for the overlap checks
PRIOR_CONTAIN = 0.5  # a candidate whose shingles are >= 50% in the prior index is dropped
NEAR_DUP = 0.7  # within the holdout: Jaccard of shingle sets >= 0.7 keeps the earlier row only

# Benign candidates that carry these markers are dropped (WildChat and the "regular" prompts contain some
# jailbreak and injection attempts). Fixed before any score; counts go to build_report.json.
ATTACK_MARKERS = re.compile(
    r"\b(ignore|disregard|forget) (all |any |the |your )?(previous|prior|above|earlier|preceding) (instructions|prompts|rules|directions)"
    r"|\bDAN\b|do anything now|developer mode|jailbr(ea|o)k|\bAIM\b|unfiltered|no (ethical|moral) (guidelines|restrictions)"
    r"|without (any )?(restrictions|filters|censorship)|system prompt|you are no longer|stay in character"
    r"|bỏ qua (mọi|tất cả|các)? ?(hướng dẫn|chỉ dẫn|lệnh)|quên (đi )?(mọi|tất cả|các)? ?(hướng dẫn|chỉ dẫn)",
    re.IGNORECASE,
)


def norm(t: str) -> str:
    t = unicodedata.normalize("NFKC", t).lower()
    return re.sub(r"\s+", " ", t).strip()


def shingles(t: str) -> set[int]:
    w = norm(t).split(" ")
    if len(w) < SHINGLE:
        return {hash(" ".join(w))}
    return {hash(" ".join(w[i:i + SHINGLE])) for i in range(len(w) - SHINGLE + 1)}


def order_key(t: str) -> str:
    return hashlib.sha256(f"{SEED}:{t}".encode()).hexdigest()


def mostly_latin(t: str) -> bool:
    letters = [c for c in t if c.isalpha()]
    return bool(letters) and sum(1 for c in letters if ord(c) < 0x250) / len(letters) >= 0.9


# --- prior index -------------------------------------------------------------------------------------------

def prior_files(repo: Path, data: Path) -> list[Path]:
    pats = [
        str(repo / "eval/data/*.jsonl"),
        str(repo / "train/data/*.jsonl"),
        str(repo / "train/data/realistic/*.jsonl"),
        str(data / "processed/*.jsonl"),
        str(data / "v5/work/data-v3b/*.jsonl"), str(data / "v5/work/data-v4A/*.jsonl"), str(data / "v5/out-full/*.jsonl"),
        str(data / "v5r2/work/data-v3b/*.jsonl"), str(data / "v5r2/work/data-v4A/*.jsonl"), str(data / "v5r2/out-full/*.jsonl"),
        str(data / "v6/out-full/*.jsonl"),
        str(data / "v7/data/*.jsonl"), str(data / "v7/data/mine/*.jsonl"),
        str(data / "v8/data/*.jsonl"), str(data / "v8/data-rerun/*.jsonl"),
    ]
    return sorted({Path(p) for pat in pats for p in glob.glob(pat)})


def public_bench_texts(cache: Path) -> list[str]:
    """The test splits bench/run.py scores (deepset, jackhhao, Gandalf, SPML), at their pinned revisions."""
    from huggingface_hub import hf_hub_download
    out = []
    specs = [
        ("deepset/prompt-injections", "4f61ecb038e9c3fb77e21034b22511b523772cdd", "data/test-00000-of-00001-701d16158af87368.parquet", "text"),
        ("jackhhao/jailbreak-classification", "2f2ceeb39658696fd3f462403562b6eea5306287", "balanced/jailbreak_dataset_test_balanced.csv", "prompt"),
        ("jackhhao/jailbreak-classification", "2f2ceeb39658696fd3f462403562b6eea5306287", "balanced/jailbreak_dataset_train_balanced.csv", "prompt"),
        ("Lakera/gandalf_ignore_instructions", "04737b65e90a6794ec227012e4a255a7def6344b", "data/test-00000-of-00001-bc92128b9288a6d1.parquet", "text"),
        ("reshabhs/SPML_Chatbot_Prompt_Injection", "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5", "spml_prompt_injection.csv", "User Prompt"),
    ]
    for repo, rev, fn, col in specs:
        p = hf_hub_download(repo, fn, repo_type="dataset", revision=rev, cache_dir=str(cache))
        if fn.endswith(".parquet"):
            out += [r[col] for r in pq.read_table(p).to_pylist() if r.get(col)]
        else:
            with open(p, encoding="utf-8", newline="") as f:
                out += [r[col] for r in csv.DictReader(f) if r.get(col)]
    return out


def build_prior(repo: Path, data: Path, cache: Path) -> tuple[set[str], set[int], dict]:
    exact, sh, files = set(), set(), {}
    def add(t):
        if isinstance(t, str) and t.strip():
            exact.add(norm(t))
            sh.update(shingles(t))
    for f in prior_files(repo, data):
        n = 0
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                add(r.get("text")); n += 1
        files[str(f).replace(str(data), "<data>").replace(str(repo), "<repo>")] = n
    pb = public_bench_texts(cache)
    for t in pb:
        add(t)
    files["<public bench test splits + jackhhao train>"] = len(pb)
    return exact, sh, files


# --- sources -----------------------------------------------------------------------------------------------

def first_user_turn(conv) -> str | None:
    for m in conv or []:
        if m.get("role") == "user":
            return m.get("content")
    return None


def load_sources(raw: Path) -> dict[str, list[dict]]:
    s: dict[str, list[dict]] = {k: [] for k in SIZES}
    for f, key in (("tw_jailbreak.parquet", "tw_jailbreak"), ("tw_regular.parquet", "tw_regular")):
        for r in pq.read_table(raw / f).to_pylist():
            want = key == "tw_jailbreak"
            if bool(r["jailbreak"]) != want:
                continue
            s[key].append({"text": r["prompt"], "lang": "en", "src": f"TrustAIRLab/in-the-wild-jailbreak-prompts:{f[3:-8]}_2023_12_25:{r['platform']}"})
    for f in ("wildchat_00.parquet", "wildchat_01.parquet"):
        t = pq.read_table(raw / f, columns=["conversation", "language", "toxic", "redacted"]).to_pylist()
        for r in t:
            if r["toxic"] or r["redacted"]:
                continue
            lang = {"English": "en", "Vietnamese": "vi"}.get(r["language"])
            if lang is None or (lang == "en" and f != "wildchat_00.parquet"):
                continue  # English from shard 00 only; Vietnamese from shards 00 and 01
            u = first_user_turn(r["conversation"])
            if u:
                s[f"wildchat_{lang}"].append({"text": u, "lang": lang, "src": f"allenai/WildChat-1M:{f[:-8]}"})
    for f in ("hs3_pref_train.jsonl.gz", "hs3_pref_val.jsonl.gz"):
        for line in gzip.open(raw / f, "rt", encoding="utf-8"):
            r = json.loads(line)
            if r.get("language") != "vietnamese":
                continue
            u = first_user_turn(r.get("context"))
            if u:
                s["hs3_vi"].append({"text": u, "lang": "vi", "src": "nvidia/HelpSteer3:preference"})
    for text, lab in json.load(open(raw / "llmail_phase2.json", encoding="utf-8")).items():
        if str(lab.get("attack_attempt")) == "True" and lab.get("reason") == "api_triggered":
            s["llmail_attack"].append({"text": text, "lang": "en", "src": "microsoft/llmail-inject-challenge:phase2:api_triggered"})
    for text in json.load(open(raw / "llmail_fp_emails.json", encoding="utf-8")):
        s["llmail_benign"].append({"text": text, "lang": "en", "src": "microsoft/llmail-inject-challenge:emails_for_fp_tests"})
    return s


LABEL = {"tw_jailbreak": ("attack", "jailbreak"), "llmail_attack": ("attack", "indirect_injection")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--data", type=Path, default=Path("~/WorkingSpace/AI_R_D/guardspec-data").expanduser())
    ap.add_argument("--cache", type=Path, default=Path("~/.cache/guardspec-short1").expanduser())
    a = ap.parse_args()

    sums = {}
    for f in RAW_FILES:
        sums[f] = hashlib.sha256((a.raw / f).read_bytes()).hexdigest()
    exact, prior, files = build_prior(a.repo, a.data, a.cache)
    src = load_sources(a.raw)
    rep = {"seed": SEED, "revisions": REV, "raw_sha256": sums, "prior_files": files, "strata": {}}
    kept_sh: list[set[int]] = []
    kept_exact: set[str] = set()
    rows = {"direct": {"en": [], "vi": []}, "tool": {"en": []}}

    for key in SIZES:  # fixed order: earlier strata win near-duplicates
        c = {"candidates": len(src[key])}
        cand = []
        for r in src[key]:
            t = (r["text"] or "").strip()
            if not (MIN_CHARS <= len(t) <= MAX_CHARS):
                c["length"] = c.get("length", 0) + 1; continue
            if r["lang"] == "en" and key.startswith("tw_") and not mostly_latin(t):
                c["not_latin"] = c.get("not_latin", 0) + 1; continue
            label = LABEL.get(key, ("benign", "benign"))[0]
            if label == "benign" and ATTACK_MARKERS.search(t):
                c["attack_marker"] = c.get("attack_marker", 0) + 1; continue
            n = norm(t)
            if n in exact:
                c["prior_exact"] = c.get("prior_exact", 0) + 1; continue
            sh = shingles(t)
            if len(sh & prior) / len(sh) >= PRIOR_CONTAIN:
                c["prior_overlap"] = c.get("prior_overlap", 0) + 1; continue
            cand.append((order_key(t), t, sh, r))
        cand.sort(key=lambda x: x[0])
        picked = []
        for _, t, sh, r in cand:
            if len(picked) >= SIZES[key]:
                break
            n = norm(t)
            if n in kept_exact or any(len(sh & k) / len(sh | k) >= NEAR_DUP for k in kept_sh):
                c["near_dup"] = c.get("near_dup", 0) + 1; continue
            kept_exact.add(n); kept_sh.append(sh); picked.append((t, r))
        c["kept"] = len(picked)
        rep["strata"][key] = c
        label, cat = LABEL.get(key, ("benign", "benign"))
        path = "tool" if key.startswith("llmail") else "direct"
        for t, r in picked:
            rid = f"short1-{key}-{hashlib.sha256(t.encode()).hexdigest()[:12]}"
            rows[path][r["lang"]].append({"id": rid, "text": t, "label": label, "category": cat, "lang": r["lang"],
                                          "variant": "orig", "source": r["src"], "stratum": key})

    out_sums = {}
    for path, by_lang in rows.items():
        d = a.out / path
        d.mkdir(parents=True, exist_ok=True)
        for lang, rs in by_lang.items():
            p = d / f"{lang}.jsonl"
            with open(p, "w", encoding="utf-8") as fh:
                for r in rs:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            out_sums[f"{path}/{lang}.jsonl"] = hashlib.sha256(p.read_bytes()).hexdigest()
    rep["outputs_sha256"] = out_sums
    (a.out / "build_report.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n")
    (a.out / "SHA256SUMS").write_text("".join(f"{h}  {p}\n" for p, h in sorted(out_sums.items())))
    print(json.dumps(rep["strata"], indent=1))
    print(json.dumps(out_sums, indent=1))


if __name__ == "__main__":
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    main()
