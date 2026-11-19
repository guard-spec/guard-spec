# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""R8d (RF-e82b0347): the fresh holdouts split2 and long10 (train/reports/r8d_preregistration.md). persona3 (R8c) is
reused for C1 and is not rebuilt here.

No holdout row is scored by any model before it is pinned. Stages (OUT is --out, outside the repository, e.g.
guardspec-data/v9/r8d):

  split2          OUT/split2/split2.json: 60 payload-splitting attack conversations and 60 benign ones (EN, VI), the
                  benign ones with negated and quoted overrides, joins and sums, in the shape of
                  cmd/gateway/testdata/multiturn.json, from data/r8d_templates.py.
  long10-exclude  the units of the long10 sources (bench/long/corpus.yaml) that share a run of 50 classifier tokens
                  with a row of E's training or validation data, persona_neg_train, the v7 pool or R8c's L and S
                  (--train-extra), or of which 20% or more of the 50-token shingles occur in a document of another
                  bench/long profile (long9 included); with --write they go into bench/long/exclude.json.
  check           every split2 turn and joined conversation against the guarded texts of build_r8c_holdouts
                  (E's data, persona_neg_train, eval/, persona1, persona2, the exemplars, multiturn.json, the
                  payload_split dev set, train/data) plus persona3, split1 and the files given with --train-extra
                  (R8c's L and S, R8d's N and L+): exact, or half of the row's 8-word shingles; long10 (benign and
                  attack documents) against the training rows with 50-token runs. Writes OUT/holdout_check.json;
                  exit 1 on any overlap.
  sums            OUT/SHA256SUMS and OUT/holdouts_manifest.json.

The owner hold-outs are never read; E's files are read only to compare against.

    cd train && uv run --frozen python data/build_r8d_holdouts.py split2 --out $OUT
    cd train && BENCH_CACHE=... MODEL_DIR=... uv run --frozen python data/build_r8d_holdouts.py long10-exclude --out $OUT \\
        --train-extra $R8C/L/r8c_L_train.jsonl --train-extra $R8C/L/r8c_S_train.jsonl [--write]
    cd train && BENCH_CACHE=... MODEL_DIR=... uv run --frozen python data/build_r8d_holdouts.py check --out $OUT \\
        --r8c $R8C_HOLDOUTS --train-extra <L> --train-extra <S> --train-extra <N> --train-extra <L+>
    cd train && uv run --frozen python data/build_r8d_holdouts.py sums --out $OUT
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "bench" / "long"))

import build_r8c_holdouts as H  # noqa: E402
import r8d_templates as T  # noqa: E402

SEED = 20261120
OTHER_PROFILES = ("quick", "full", "long", "long5", "long6", "long7", "long8", "long9")


def stage_split2(a) -> int:
    convs = T.split2_conversations(SEED)
    doc = {"_comment": "split2, the payload-splitting holdout of R8d (RF-e82b0347), written for this round from "
                       "train/data/r8d_templates.py (not from split1, S, N, multiturn.json, the payload_split dev set, "
                       "eval/ or train/). attack: an instruction split over 2 to 4 user turns; benign: multi-turn "
                       "requests with negated or quoted overrides, joins and sums. Scored once, L2 only, on the "
                       "conversation window (turns joined with a space).",
           "conversations": convs}
    p = a.out / "split2" / "split2.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", "utf-8")
    c = collections.Counter(f"{x['lang']}:{x['kind']}:{x['pattern']}" for x in convs)
    H.log(json.dumps({"file": str(p), "sha256": H.sha256_file(p), "counts": dict(sorted(c.items()))}, indent=1))
    return 0


def split2_texts(out: Path) -> list[tuple[str, str]]:
    d = json.loads((out / "split2" / "split2.json").read_text("utf-8"))
    res = []
    for c in d["conversations"]:
        res += [(f"{c['id']}:turn{i}", t) for i, t in enumerate(c["turns"])]
        res.append((f"{c['id']}:joined", " ".join(c["turns"])))
    return res


def stage_long10_exclude(a) -> int:
    import yaml
    import build
    from bench_guard import ShingleIndex

    cfg = yaml.safe_load((REPO / "bench/long/corpus.yaml").read_text("utf-8"))
    names = cfg["profiles"]["long10"]["sources"]
    tok = H.bench_tok()
    ix, n = H.training_index(tok, a.data, a.train_extra)
    H.log(f"training index: {ix.docs} rows/documents, {ix.shingles:,} shingles")
    other = ShingleIndex(tok)
    for prof in OTHER_PROFILES:
        for d in H.read_jsonl(H.bench_dir() / prof / "docs.jsonl"):
            if d["kind"] in ("benign", "host"):
                other.add(d["text"], f"{prof}:{d['id']}")
    H.log(f"bench index: {other.docs} documents, {other.shingles:,} shingles")
    rep = {"training_rows": n, "bench_docs": other.docs, "sources": {}}
    excl = {}
    for name in names:
        units = build.load_source(name, cfg["sources"][name], H.bench_dir() / "src", cfg["sources"])
        drop = []
        for i, u in enumerate(units):
            if ix.check(u)[1]:
                drop.append((i, "training"))
            elif H.shingle_share(other, tok, u) >= H.BENCH_NEAR_DUP:
                drop.append((i, "bench_near_dup"))
        excl[name] = [i for i, _ in drop]
        rep["sources"][name] = {"units": len(units), "excluded": len(drop),
                                "by_reason": dict(collections.Counter(r for _, r in drop))}
        H.log(f"  {name}: {len(units)} units, {len(drop)} excluded {rep['sources'][name]['by_reason']}")
    (a.out / "long10").mkdir(parents=True, exist_ok=True)
    (a.out / "long10" / "exclude_report.json").write_text(json.dumps(rep, indent=1) + "\n", "utf-8")
    if a.write:
        p = REPO / "bench/long/exclude.json"
        ex = json.loads(p.read_text("utf-8"))
        for name, idx in excl.items():
            if idx:
                ex["sources"][name] = idx
            else:
                ex["sources"].pop(name, None)
        note = ("R8d (2026-11-19, RF-e82b0347): the sources of the `long10` profile (the R8d holdout) were checked the "
                "same way against arm E's training and validation rows (v4-A, v6, v8e), R8b's persona_neg_train, the v7 "
                "training pool documents and R8c's L and S rows, and with R5's near-duplicate rule (20% of the 50-token "
                "shingles in a benign or host document of quick, full, long, long5, long6, long7, long8 or long9). Their "
                "units are listed under their own names. R8d's L+ and N rows come from other sources and are checked "
                "against the built long10 documents by data/build_r8d.py check.")
        if note not in ex["_comment"]:
            ex["_comment"].append(note)
        p.write_text(json.dumps(ex, indent=1, ensure_ascii=False) + "\n", "utf-8")
        H.log(f"wrote {p}")
    return 0


def holdout_files(out: Path) -> dict[str, Path]:
    return {"split2": out / "split2/split2.json", "long10/benign": out / "long10/benign/docs.jsonl",
            "long10/attack": out / "long10/attack/docs.jsonl"}


def stage_check(a) -> int:
    src = H.guarded_sources(a.data, a.train_extra)
    for lang in ("en", "vi"):
        src[f"persona3:{lang}"] = [r["text"] for r in H.read_jsonl(a.r8c / "persona3/holdout/direct" / f"{lang}.jsonl")]
    src["split1"] = [t for _, t in H.split1_texts(a.r8c)]
    guard = H.Guard(src)
    rep: dict = {"guard_sources": guard.counts, "overlap_rule": f"exact, or >= {H.OVERLAP} of the 8-word shingles",
                 "files": {}}
    bad = 0
    hits = []
    items = split2_texts(a.out)
    for i, t in items:
        h = guard.hit(t)
        if h:
            hits.append({"id": i, "kind": h[0], "share": h[1], "source": h[2]})
    rep["files"]["split2"] = {"rows": len(items), "overlaps": hits}
    bad += len(hits)
    tok = H.bench_tok()
    ix, n = H.training_index(tok, a.data, a.train_extra)
    for key in ("long10/benign", "long10/attack"):
        docs = H.read_jsonl(holdout_files(a.out)[key])
        got = []
        for d in docs:
            if d["kind"] == "control":
                continue
            h = ix.check(d["text"])[1]
            if h:
                got.append({"id": d["id"], "with": h[:3]})
        rep["files"][key] = {"docs": len(docs), "overlaps": got, "training_rows": n}
        bad += len(got)
    rep["result"] = "clean" if bad == 0 else f"OVERLAP ({bad})"
    (a.out / "holdout_check.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    H.log(json.dumps({k: v for k, v in rep.items() if k != "guard_sources"}, indent=1, ensure_ascii=False)[:4000])
    return 0 if bad == 0 else 1


def stage_sums(a) -> int:
    man, lines = {}, []
    for key, p in holdout_files(a.out).items():
        s = H.sha256_file(p)
        if p.suffix == ".json":
            d = json.loads(p.read_text("utf-8"))
            cnt = dict(collections.Counter(f"{c['lang']}:{c['kind']}" for c in d["conversations"]))
        else:
            cnt = dict(collections.Counter(f"{r.get('lang')}:{r.get('kind')}" for r in H.read_jsonl(p)))
        man[key] = {"path": str(p.relative_to(a.out)), "sha256": s, "counts": dict(sorted(cnt.items()))}
        lines.append(f"{s}  {p.relative_to(a.out)}")
    (a.out / "SHA256SUMS").write_text("\n".join(lines) + "\n", "utf-8")
    (a.out / "holdouts_manifest.json").write_text(json.dumps(man, indent=1) + "\n", "utf-8")
    H.log(json.dumps(man, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["split2", "long10-exclude", "check", "sums"])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--r8c", type=Path, default=Path.home() / "WorkingSpace/AI_R_D/guardspec-data/v9/r8c/out",
                    help="the R8c holdout directory (persona3/, split1/)")
    ap.add_argument("--data", type=Path, default=Path.home() / "WorkingSpace/AI_R_D/guardspec-data")
    ap.add_argument("--write", action="store_true", help="long10-exclude: update bench/long/exclude.json")
    ap.add_argument("--train-extra", action="append", default=[], help="further training files (L, S, N, L+)")
    a = ap.parse_args()
    return {"split2": stage_split2, "long10-exclude": stage_long10_exclude, "check": stage_check,
            "sums": stage_sums}[a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
