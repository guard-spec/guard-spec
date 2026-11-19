# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""R8d (RF-e82b0347) training additions of arm EPL2: `L+` (payload-carrying windows of long technical documentation)
and `N` (hard negatives of negated or quoted overrides), train/reports/r8d_preregistration.md.

Arm EPL2 trains on EPL's data (E's data, persona_neg_train.jsonl, r8c_L_train.jsonl, r8c_S_train.jsonl, all
unchanged) and the two files written here (`train.py --extra-train`):

  L+  for each sampled gateway window of the L+ pool (data/sources_r8d.yaml: new documentation sites, RFCs and README
      files, disjoint from every bench/long profile, long9 and long10 included, and from R8c's L), one window of the
      same host with a training payload embedded: build_v8's scheme and functions, as build_r8c's L, but only the
      attack row is written (no benign row), kind `r8d_attack`. With L's 1,500 benign and 1,496 attack rows, the long
      technical windows go from about 1 : 1 to about 1 : 1.7.
  N   benign rows of data/r8d_templates.py n_rows: negated overrides ("please don't ignore the previous instructions",
      "đừng bỏ qua hướng dẫn trước đó"), quoted or discussed attacks, and both split over turns joined with a space.

Stages (OUT = $GUARD_R8D_OUT, outside the repository; BENCH_CACHE as for bench/long). The pool and sanitize stages
are build_r8c's, run with this round's sources and output directory:

  pool      the L+ pool: OUT/pool/docs.jsonl, OUT/pool_report.json (units sharing a 50-token run with a bench/long
            document, an embedded-attack document or a hold-out row dropped or trimmed).
  sanitize  the gateway's sanitizer over the pool: OUT/pool/sanitized.jsonl.
  rows      OUT/r8d_Lplus_train.jsonl, OUT/r8d_N_train.jsonl, OUT/stats_r8d.json.
  check     as build_r8c check, over both files: 50-token runs against bench/long and the embedded-attack documents,
            12-token runs of short hold-out rows, and the 8-word rule in both directions against every hold-out row
            (persona1/2/3, split1, split2, multiturn.json, the payload_split dev set, eval/, the exemplars). Writes
            OUT/guard_r8d.json; exit 1 on any overlap.

    cd train && GUARD_R8D_OUT=... BENCH_CACHE=... MODEL_DIR=... GITHUB_TOKEN=... uv run --frozen python data/build_r8d.py pool \\
        --holdouts <R8c holdout dir> --r8d-holdouts <R8d holdout dir> --embedded '<R5, long6, long7, long8, long9, long10 attack>' ...
    ... data/build_r8d.py sanitize | rows | check (same options)

Seeded and byte-identical between runs. Nothing here reads a model.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import random
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
TRAIN = HERE.parent
REPO = TRAIN.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(TRAIN))
sys.path.insert(0, str(REPO / "bench" / "long"))

import build_r8c as R  # noqa: E402
import build_r8c_holdouts as H  # noqa: E402
import build_r8d_holdouts as D  # noqa: E402
import build_v8 as V8  # noqa: E402
import r8d_templates as T  # noqa: E402

GENRES = ("docs", "rfc", "readme")


def out_dir() -> Path:
    return Path(os.environ.get("GUARD_R8D_OUT") or sys.exit("set GUARD_R8D_OUT"))


def load_cfg() -> dict:
    return yaml.safe_load((HERE / "sources_r8d.yaml").read_text("utf-8"))


def h12(t: str) -> str:
    return hashlib.sha256(t.encode("utf-8")).hexdigest()[:12]


def use_r8d(a) -> None:
    """build_r8c's stages with this round's sources, genres and output directory; split2 joins the short hold-out
    rows (the 50/12-token guard and the 8-word rule in both directions)."""
    R.load_cfg, R.out_dir, R.GENRES = load_cfg, out_dir, GENRES
    out_dir().mkdir(parents=True, exist_ok=True)
    r8c_short = R.short_holdout_rows
    split2 = [{"id": i, "text": t} for i, t in D.split2_texts(a.r8d_holdouts)]
    R.short_holdout_rows = lambda hold: r8c_short(hold) + split2


def stage_rows(a) -> int:
    out = out_dir()
    cfg = load_cfg()
    seed = cfg["seed"]
    tok = V8.Tok()
    ix, gstats, short, holdouts, _ = R.guard(a, cfg)
    pool = {json.loads(ln)["id"]: json.loads(ln) for ln in open(out / "pool" / "docs.jsonl", encoding="utf-8")}
    clean = {}
    counts: collections.Counter = collections.Counter()
    for ln in open(out / "pool" / "sanitized.jsonl", encoding="utf-8"):
        d = json.loads(ln)
        if "text" in d:
            clean[d["id"]] = d["text"]
        else:
            counts["pool:rejected_by_sanitizer"] += 1

    def hit(t: str) -> bool:
        return bool(ix.check(t)[1] or short.check(t)[1])

    # host windows: a seeded sample per genre (spares for the guard and for hosts without a fitting payload)
    cand: dict[str, list] = collections.defaultdict(list)
    for did in sorted(clean):
        text = clean[did]
        for c0, c1 in R.window_spans(tok, text):
            if len(text[c0:c1].strip()) >= R.MIN_WINDOW_CHARS:
                cand[pool[did]["genre"]].append((did, c0, c1))
    rng = random.Random(f"{seed}:windows")
    hosts = []
    for genre in GENRES:
        items = cand[genre]
        want = int(cfg["windows"][genre])
        pick = sorted(rng.sample(items, min(len(items), want * 2)))
        for did, c0, c1 in pick:
            text = clean[did]
            w = text[c0:c1].strip()
            if hit(w):
                counts[f"host:guard_dropped:{genre}"] += 1
                continue
            s, e = len(text[:c0].encode("utf-8")), len(text[:c1].encode("utf-8"))
            src = pool[did]
            hosts.append({"id": f"en-r8dLh-{h12(w)}", "text": w, "labels": ["benign"], "lang": "en", "variant": "orig",
                          "source": src["source"], "license": src["license"], "group": f"r8d.{genre}.{did}",
                          "kind": "r8d_host", "set": "r8d", "origin": f"{did}:{s}-{e}", "host_kind": genre,
                          "want": want})
        counts[f"host:available:{genre}"] = len(items)

    pcfg = {"payloads": cfg["payloads"], "seed": seed}
    payloads = V8.load_payloads(pcfg, tok, ix, short, V8.held_texts(holdouts), V8.eval_fingerprints(), counts)
    wg, wc = R.word_guards(a)
    for lang in payloads:
        keep = [p for p in payloads[lang] if not wg.hit(p["text"]) and not wc.hit(p["text"])]
        counts[f"payload:skipped:holdout_word8:{lang}"] = len(payloads[lang]) - len(keep)
        counts[f"payload:usable:{lang}"] = len(keep)
        payloads[lang] = keep
    cursor = 0
    clean_b = {k: v.encode("utf-8") for k, v in clean.items()}
    Lp, seen, taken = [], set(), collections.Counter()
    for b in hosts:
        genre = b["host_kind"]
        if taken[genre] >= b["want"]:
            continue
        did, rng_s = b["origin"].rsplit(":", 1)
        s, e = (int(x) for x in rng_s.split("-"))
        position = V8.weighted_choice(random.Random(f"{seed}:host:{b['id']}"), cfg["placements"])
        made = None
        for attempt in range(8):
            p = payloads["en"][cursor % len(payloads["en"])]
            cursor += 1
            prng = random.Random(f"{seed}:embed:{b['id']}:{attempt}")
            if position == "straddle_window":
                res = V8.make_straddle(clean_b[did], s, e, p["text"], tok, prng)
            else:
                res = V8.make_one_window(position, b["text"], p["text"], "en", tok, prng, cfg)
            if res is None:
                counts[f"embed_failed:{position}"] += 1
                continue
            text, spans, _ = res
            if not V8.spans_hold(text, spans, p["text"]):
                counts[f"span_mismatch:{position}"] += 1
                continue
            r = V8.attack_row(b, genre, position, text, spans, p, tok)
            ws = tok.windows(r)
            if not any(w.why == "payload" for w in ws) or (position != "straddle_window" and len(ws) != 1):
                counts[f"window_mismatch:{position}"] += 1
                continue
            if hit(text) or text in seen:
                counts[f"guard_replaced:{position}"] += 1
                continue
            r.update({"id": f"en-r8dLa-{h12(text)}", "source": "guard-spec:r8d-embedded", "kind": "r8d_attack",
                      "set": "r8d"})
            r.pop("want", None)
            made = r
            break
        if made is None:
            counts[f"host_without_attack:{position}"] += 1
            continue
        seen.add(made["text"])
        taken[genre] += 1
        Lp.append(made)
    for g in GENRES:
        counts[f"attack:taken:{g}"] = taken[g]

    def reject(t: str) -> bool:
        if hit(t) or wg.hit(t) or wc.hit(t):
            counts["N:rejected_overlap"] += 1
            return True
        return False

    nc = cfg["negatives"]
    N = [{"id": f"{r['lang']}-r8dN-{h12(r['text'])}", "text": r["text"], "labels": ["benign"], "lang": r["lang"],
          "variant": "orig", "source": "guard-spec:r8d-negated-templates", "license": "Apache-2.0",
          "group": f"r8d.neg.{h12(r['text'])}", "kind": r["kind"], "set": "r8d", "turns": r["turns"]}
         for r in T.n_rows(seed, nc["rows"], nc["vi_share"], reject=reject)]
    files = {"r8d_Lplus_train": Lp, "r8d_N_train": N}
    stats = {"seed": seed, "inputs": {
        "pool_sha256": V8.sha256_file(out / "pool" / "docs.jsonl"),
        "sanitized_sha256": V8.sha256_file(out / "pool" / "sanitized.jsonl"),
        "payload_file_sha256": V8.sha256_file(TRAIN / cfg["payloads"]["file"]),
        "sources_r8d_sha256": V8.sha256_file(HERE / "sources_r8d.yaml"),
        "r8d_templates_sha256": V8.sha256_file(HERE / "r8d_templates.py"),
        "tokenizer": Path(tok.path).name, "tokenizer_sha256": V8.sha256_file(Path(tok.path))},
        "guard_index": gstats, "index_shingles": ix.shingles, "build": dict(sorted(counts.items()))}
    for name, rs in files.items():
        p = out / f"{name}.jsonl"
        H.write_jsonl(p, rs)
        stats[name] = describe(rs, tok) | {"sha256": V8.sha256_file(p)}
    (out / "stats_r8d.json").write_text(json.dumps(stats, indent=1, ensure_ascii=False) + "\n", "utf-8")
    R.log(json.dumps({k: stats[k] for k in files}, indent=1, ensure_ascii=False))
    return 0


def describe(rows: list[dict], tok) -> dict:
    win: collections.Counter = collections.Counter()
    for r in rows:
        for w in tok.windows(r):
            lab = "dropped" if w.labels is None else ("benign" if w.labels == ["benign"] else "attack")
            win[f"{r['kind']}:{lab}"] += 1
    att = [r for r in rows if r["kind"] == "r8d_attack"]
    return {
        "rows": len(rows),
        "by_kind_lang": dict(sorted(collections.Counter(f"{r['kind']}:{r['lang']}" for r in rows).items())),
        "by_kind_genre": dict(sorted(collections.Counter(f"{r['kind']}:{r.get('host_kind', '-')}" for r in rows).items())),
        "labels": dict(sorted(collections.Counter("+".join(r["labels"]) for r in rows).items())),
        "windows": dict(sorted(win.items())),
        "placement": dict(sorted(collections.Counter(r["position"] for r in att).items())),
        "payloads_used": len({r["payload_id"] for r in att}),
        "payload_uses_max": max(collections.Counter(r["payload_id"] for r in att).values(), default=0),
    }


def stage_check(a) -> int:
    out = out_dir()
    cfg = load_cfg()
    ix, gstats, short, _, _ = R.guard(a, cfg)
    wg, wc = R.word_guards(a)
    rep = {"k": 50, "short_k": 12, "index": gstats, "index_shingles": ix.shingles, "files": {}}
    ok = True
    for name in ("r8d_Lplus_train", "r8d_N_train"):
        p = out / f"{name}.jsonl"
        rows = H.read_jsonl(p)
        counts: collections.Counter = collections.Counter()
        examples: dict = {}
        kept = ix.filter_rows(rows, counts, p.name, examples)
        contained = [r["id"] for r in kept if short.check(r["text"])[1]]
        words = [r["id"] for r in rows if wg.hit(r["text"])]
        rev = [{"row": r["id"], "holdout_source": hh[0], "share": hh[1]} for r in rows if (hh := wc.hit(r["text"]))]
        rep["files"][name] = {"rows": len(rows), "rows_clean_50token": len(kept), "short_holdout_12token_overlap": contained,
                              "word8_overlap": words, "holdout_rows_contained": rev[:50], "counts": dict(counts),
                              "examples": examples, "sha256": V8.sha256_file(p)}
        ok = ok and len(kept) == len(rows) and not contained and not words and not rev
    rep["result"] = "clean" if ok else "OVERLAP"
    (out / "guard_r8d.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    R.log(json.dumps({k: v for k, v in rep.items() if k != "index"}, indent=1, ensure_ascii=False)[:5000])
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["pool", "sanitize", "rows", "check"])
    ap.add_argument("--holdouts", type=Path, required=True, help="the R8c holdout directory (persona3/, split1/)")
    ap.add_argument("--r8d-holdouts", type=Path, required=True, help="the R8d holdout directory (split2/)")
    ap.add_argument("--data", type=Path, default=Path.home() / "WorkingSpace/AI_R_D/guardspec-data")
    ap.add_argument("--embedded", action="append", default=[], help="embedded-attack documents (glob of docs.jsonl)")
    ap.add_argument("--holdout-rows", action="append", default=[], help="further hold-out row files (glob)")
    a = ap.parse_args()
    use_r8d(a)
    return {"pool": R.stage_pool, "sanitize": R.stage_sanitize, "rows": stage_rows, "check": stage_check}[a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
