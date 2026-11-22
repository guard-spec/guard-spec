# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""R8e (RF-943afc53): the fresh holdouts vi1, tp1 and long11 (train/reports/r8e_preregistration.md). They are built
and pinned before any R8e score.

Stages (OUT is --out, outside the repository, e.g. guardspec-data/v9/r8e/out):

  vi1             candidates of the Vietnamese benign holdout, `cmd/eval` rows with a `stratum`:
                  - community: the first user turn of every Vietnamese conversation of
                    lmarena-ai/arena-human-preference-140k (user prompts CC-BY-4.0; the pinned files of R8c), minus
                    persona3's arena_vi rows, minus near-duplicates, minus rows overlapping a guarded text;
                  - orig, no_diacritics, teencode: Vietnamese business and IT messages from data/r8e_templates.py.
                  Writes OUT/vi1/candidates.jsonl and OUT/vi1/audit_sheet.jsonl (community rows, for the labellers).
  vi1-audit       --labels FILE ({id: benign|attack|ambiguous}): the community rows labelled benign and every templated
                  row go to OUT/vi1/holdout/vi.jsonl; OUT/vi1/audit.json records labels and counts.
  tp1             OUT/tp1/holdout/{en,vi}.jsonl: tool and MCP descriptions, 150 attacks and 150 benign
                  (data/r8e_templates.py tp1_rows), each row checked against the guarded texts.
  long11-payloads OUT/long11/payloads.jsonl: the 12 tool-poisoning payloads written for long11
                  (embed_long.py --extra-payloads).
  long11-exclude  as build_r8d_holdouts long10-exclude, for the long11 sources, against E's data, persona_neg_train,
                  the v7 pool and the R8c/R8d training files (--train-extra), and against every other profile's
                  documents (long9 and long10 included).
  check           every vi1 and tp1 row against the guarded texts of build_r8c_holdouts (E's data, persona_neg_train,
                  eval/, persona1, persona2, the exemplars, multiturn.json, the payload_split dev set, train/data)
                  plus persona3, split1, split2 and the --train-extra files (L, S, L+, N and R8e's T+, O+, N+, L++);
                  long11 (benign and attack documents) against the training rows with 50-token runs. Writes
                  OUT/holdout_check.json; exit 1 on any overlap.
  sums            OUT/SHA256SUMS and OUT/holdouts_manifest.json.

The owner hold-outs are never read; E's files are read only to compare against.

    cd train && uv run --frozen python data/build_r8e_holdouts.py vi1 --out $OUT --arena <arena dir>
    cd train && uv run --frozen python data/build_r8e_holdouts.py vi1-audit --out $OUT --labels <labels.json>
    cd train && uv run --frozen python data/build_r8e_holdouts.py tp1 --out $OUT
    cd train && uv run --frozen python data/build_r8e_holdouts.py long11-payloads --out $OUT
    cd train && BENCH_CACHE=... MODEL_DIR=... uv run --frozen python data/build_r8e_holdouts.py long11-exclude --out $OUT \\
        --train-extra <L> --train-extra <S> --train-extra <L+> --train-extra <N> [--write]
    cd train && BENCH_CACHE=... MODEL_DIR=... uv run --frozen python data/build_r8e_holdouts.py check --out $OUT \\
        --train-extra <every R8c, R8d and R8e training file>
    cd train && uv run --frozen python data/build_r8e_holdouts.py sums --out $OUT
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

from build_short1 import shingles  # noqa: E402
import build_r8c_holdouts as H  # noqa: E402
import build_r8d_holdouts as D  # noqa: E402
import r8e_templates as T  # noqa: E402

SEED = 20261122
NEAR_DUP = 0.7
DATA = Path.home() / "WorkingSpace/AI_R_D/guardspec-data"


def guard(a) -> "H.Guard":
    src = H.guarded_sources(a.data, a.train_extra)
    for lang in ("en", "vi"):
        src[f"persona3:{lang}"] = [r["text"] for r in H.read_jsonl(a.r8c / "persona3/holdout/direct" / f"{lang}.jsonl")]
    src["split1"] = [t for _, t in H.split1_texts(a.r8c)]
    src["split2"] = [t for _, t in D.split2_texts(a.r8d)]
    return H.Guard(src)


def stage_vi1(a) -> int:
    g = guard(a)
    persona3_vi = {H.norm(r["text"]) for r in H.read_jsonl(a.r8c / "persona3/holdout/direct/vi.jsonl")}
    prompts, shas = H.arena_prompts(a.arena)
    rep: dict = {"seed": SEED, "arena_sha256": shas, "community": collections.Counter()}
    cands, kept_sh = [], []
    for lang, t in sorted(((l, t) for l, t in prompts if l == "vi"), key=lambda x: H.order_key(x[1])):
        c = rep["community"]
        c["vi_unique"] += 1
        if not H.MIN_CHARS <= len(t) <= H.MAX_CHARS:
            c["dropped_length"] += 1
            continue
        if H.norm(t) in persona3_vi:
            c["dropped_persona3"] += 1
            continue
        if g.hit(t):
            c["dropped_overlap"] += 1
            continue
        sh = shingles(t)
        if any(len(sh & s) / max(1, len(sh | s)) >= NEAR_DUP for s in kept_sh):
            c["dropped_near_duplicate"] += 1
            continue
        kept_sh.append(sh)
        cands.append({"id": f"vi1-community-{H.h12(t)}", "text": t, "label": "benign", "category": "benign", "lang": "vi",
                      "variant": "orig", "source": "lmarena-ai/arena-human-preference-140k@6322995ab34d",
                      "license": "CC-BY-4.0", "stratum": "community"})
    rep["community"]["candidates"] = len(cands)
    tmpl = []
    for r in T.vi1_template_rows(SEED, a.templated):
        if g.hit(r["text"]):
            rep["community"]["template_dropped_overlap"] += 1
            continue
        tmpl.append(dict(r, id=f"vi1-{r['variant']}-{H.h12(r['text'])}", source="guard-spec:r8e-templates:vi1",
                         license="Apache-2.0", stratum=r["variant"]))
    rows = sorted(cands + tmpl, key=lambda r: r["id"])
    d = a.out / "vi1"
    H.write_jsonl(d / "candidates.jsonl", rows)
    H.write_jsonl(d / "audit_sheet.jsonl", [{"id": r["id"], "text": r["text"]} for r in sorted(cands, key=lambda r: r["id"])])
    rep["candidates"] = dict(collections.Counter(r["stratum"] for r in rows))
    rep["community"] = dict(rep["community"])
    (d / "build_report.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    H.log(json.dumps(rep, indent=1, ensure_ascii=False))
    return 0


def stage_vi1_audit(a) -> int:
    labels = json.loads(Path(a.labels).read_text("utf-8"))
    labels = labels.get("labels", labels)
    d = a.out / "vi1"
    rows = H.read_jsonl(d / "candidates.jsonl")
    rep = {"method": a.method, "labels": {}, "counts": collections.Counter()}
    keep = []
    for r in rows:
        if r["stratum"] == "community":
            lab = labels.get(r["id"])
            if lab is None:
                raise SystemExit(f"{r['id']}: no audit label")
            rep["labels"][r["id"]] = lab
            rep["counts"][f"community:{lab}"] += 1
            if lab != "benign":
                continue
        keep.append(r)
        rep["counts"][f"kept:{r['stratum']}"] += 1
    rep["counts"] = dict(sorted(rep["counts"].items()))
    rep["sha256"] = H.write_jsonl(d / "holdout" / "vi.jsonl", keep)
    (d / "audit.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    H.log(json.dumps({k: v for k, v in rep.items() if k != "labels"}, indent=1, ensure_ascii=False))
    return 0


def stage_tp1(a) -> int:
    g = guard(a)
    rows, dropped = [], 0
    for r in T.tp1_rows(SEED):
        if g.hit(r["text"]):
            dropped += 1
            continue
        rows.append({"id": f"tp1-{r['label']}-{r['lang']}-{H.h12(r['text'])}", "text": r["text"], "label": r["label"],
                     "category": r["category"], "lang": r["lang"], "variant": r["variant"],
                     "source": "guard-spec:r8e-templates:tp1", "license": "Apache-2.0", "labels": r["labels"]})
    sums = {}
    for lang in ("en", "vi"):
        rs = sorted((r for r in rows if r["lang"] == lang), key=lambda r: r["id"])
        sums[lang] = H.write_jsonl(a.out / "tp1/holdout" / f"{lang}.jsonl", rs)
    c = collections.Counter(f"{r['lang']}:{r['label']}:{r['variant']}" for r in rows)
    H.log(json.dumps({"rows": len(rows), "dropped_overlap": dropped, "counts": dict(sorted(c.items())), "sha256": sums}, indent=1))
    return 0


def stage_long11_payloads(a) -> int:
    g = guard(a)
    rows = []
    for k, (cat, text) in enumerate(T.LONG11_PAYLOADS):
        if g.hit(text):
            raise SystemExit(f"long11 payload {k} overlaps a guarded text")
        rows.append({"id": f"l11tp-{H.h12(text)}", "text": text, "lang": "en", "category": "tool_poisoning",
                     "labels": sorted({cat, "tool_poisoning"}), "source": "guard-spec:r8e-templates:long11",
                     "license": "Apache-2.0"})
    sha = H.write_jsonl(a.out / "long11" / "payloads.jsonl", rows)
    H.log(f"{len(rows)} payloads, sha256 {sha}")
    return 0


def stage_long11_exclude(a) -> int:
    """build_r8d_holdouts' exclusion for the long11 sources (long9 and long10 among the other profiles)."""
    import yaml
    import build
    from bench_guard import ShingleIndex

    cfg = yaml.safe_load((REPO / "bench/long/corpus.yaml").read_text("utf-8"))
    names = cfg["profiles"]["long11"]["sources"]
    tok = H.bench_tok()
    ix, n = H.training_index(tok, a.data, a.train_extra)
    H.log(f"training index: {ix.docs} rows/documents, {ix.shingles:,} shingles")
    other = ShingleIndex(tok)
    for prof in D.OTHER_PROFILES + ("long10",):
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
    (a.out / "long11").mkdir(parents=True, exist_ok=True)
    (a.out / "long11" / "exclude_report.json").write_text(json.dumps(rep, indent=1) + "\n", "utf-8")
    if a.write:
        p = REPO / "bench/long/exclude.json"
        ex = json.loads(p.read_text("utf-8"))
        for name, idx in excl.items():
            if idx:
                ex["sources"][name] = idx
            else:
                ex["sources"].pop(name, None)
        note = ("R8e (2026-11-22, RF-943afc53): the sources of the `long11` profile (the R8e holdout) were checked the "
                "same way against arm E's training and validation rows (v4-A, v6, v8e), R8b's persona_neg_train, the v7 "
                "training pool documents and R8c's and R8d's L, S, L+ and N rows, and with R5's near-duplicate rule (20% "
                "of the 50-token shingles in a benign or host document of quick, full, long, long5 to long10). Their units "
                "are listed under their own names. R8e's T+, O+, N+ and L++ rows are checked against the built long11 "
                "documents by data/build_r8e.py check.")
        if note not in ex["_comment"]:
            ex["_comment"].append(note)
        p.write_text(json.dumps(ex, indent=1, ensure_ascii=False) + "\n", "utf-8")
        H.log(f"wrote {p}")
    return 0


def holdout_files(out: Path) -> dict[str, Path]:
    return {"vi1": out / "vi1/holdout/vi.jsonl", "tp1/en": out / "tp1/holdout/en.jsonl", "tp1/vi": out / "tp1/holdout/vi.jsonl",
            "long11/payloads": out / "long11/payloads.jsonl", "long11/benign": out / "long11/benign/docs.jsonl",
            "long11/attack": out / "long11/attack/docs.jsonl"}


def stage_check(a) -> int:
    g = guard(a)
    rep: dict = {"guard_sources": g.counts, "overlap_rule": f"exact, or >= {H.OVERLAP} of the 8-word shingles", "files": {}}
    bad = 0
    fs = holdout_files(a.out)
    for key in ("vi1", "tp1/en", "tp1/vi", "long11/payloads"):
        rows = H.read_jsonl(fs[key])
        hits = [{"id": r["id"], "kind": h[0], "share": h[1], "source": h[2]} for r in rows if (h := g.hit(r["text"]))]
        rep["files"][key] = {"rows": len(rows), "overlaps": hits}
        bad += len(hits)
    tok = H.bench_tok()
    ix, n = H.training_index(tok, a.data, a.train_extra)
    for key in ("long11/benign", "long11/attack"):
        docs = H.read_jsonl(fs[key])
        got = [{"id": d["id"], "with": h[:3]} for d in docs if d["kind"] != "control" and (h := ix.check(d["text"])[1])]
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
        rs = H.read_jsonl(p)
        cnt = collections.Counter(f"{r.get('lang')}:{r.get('stratum') or r.get('label') or r.get('kind')}" for r in rs)
        man[key] = {"path": str(p.relative_to(a.out)), "sha256": s, "rows": len(rs), "counts": dict(sorted(cnt.items()))}
        lines.append(f"{s}  {p.relative_to(a.out)}")
    (a.out / "SHA256SUMS").write_text("\n".join(lines) + "\n", "utf-8")
    (a.out / "holdouts_manifest.json").write_text(json.dumps(man, indent=1) + "\n", "utf-8")
    H.log(json.dumps(man, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["vi1", "vi1-audit", "tp1", "long11-payloads", "long11-exclude", "check", "sums"])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--r8c", type=Path, default=DATA / "v9/r8c/out", help="the R8c holdout directory (persona3/, split1/)")
    ap.add_argument("--r8d", type=Path, default=DATA / "v9/r8d/out", help="the R8d holdout directory (split2/)")
    ap.add_argument("--data", type=Path, default=DATA)
    ap.add_argument("--arena", type=Path, default=DATA / "v9/r8c/raw/arena140k")
    ap.add_argument("--templated", type=int, default=300, help="vi1: templated rows")
    ap.add_argument("--labels")
    ap.add_argument("--method", default="")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--train-extra", action="append", default=[])
    a = ap.parse_args()
    return {"vi1": stage_vi1, "vi1-audit": stage_vi1_audit, "tp1": stage_tp1, "long11-payloads": stage_long11_payloads,
            "long11-exclude": stage_long11_exclude, "check": stage_check, "sums": stage_sums}[a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
