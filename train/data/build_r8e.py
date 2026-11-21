# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""R8e (RF-943afc53) training additions of arm EPL3: T+, O+, N+ and L++ (data/sources_r8e.yaml,
train/reports/r8e_preregistration.md).

Arm EPL3 trains on EPL2's data (E's data, persona_neg_train, r8c_L_train, r8c_S_train, r8d_Lplus_train,
r8d_N_train, all unchanged) and the four files written here (`train.py --extra-train`):

  T+   r8e_Tplus_train.jsonl   tool and MCP descriptions, VI (orig, no_diacritics, teencode) and EN: attacks that copy
                               the conversation, the system prompt or secrets into a field; benign field mentions.
  O+   r8e_Oplus_train.jsonl   paraphrased overrides as attacks (no "ignore" / "bỏ qua").
  N+   r8e_Nplus_train.jsonl   benign quoted or discussed attacks (VI no_diacritics, teencode) and short questions.
  L++  r8e_Lpp_train.jsonl     attack windows of R8d's L+ pool (windows L+ did not use), each carrying an English
                               T+ or O+ attack: build_v8's scheme and functions, attack rows only.

Every row goes through build_r8c's guard (50-token runs against every bench/long profile up to long11, the
embedded-attack documents and the hold-out rows; 12-token runs of short hold-out rows; the 8-word rule in both
directions). The hold-out rows include vi1, tp1 and long11 (R8e's holdouts), split2, persona1/2/3 and split1.

Stages (OUT = $GUARD_R8E_OUT, outside the repository):

  rows   write the four files and OUT/stats_r8e.json.
  check  as build_r8d check over the four files; writes OUT/guard_r8e.json and exits 1 on any overlap.

    cd train && GUARD_R8E_OUT=... BENCH_CACHE=... MODEL_DIR=... uv run --frozen python data/build_r8e.py rows \\
        --holdouts <R8c holdout dir> --r8d-holdouts <R8d holdout dir> --r8e-holdouts <R8e holdout dir> \\
        --lp-dir <R8d L+ dir> --embedded '<R5, long6 .. long11 attack docs.jsonl>' ...
    ... data/build_r8e.py check (same options)

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
import r8e_templates as T  # noqa: E402

GENRES = ("docs", "rfc", "readme")
FILES = ("r8e_Tplus_train", "r8e_Oplus_train", "r8e_Nplus_train", "r8e_Lpp_train")


def out_dir() -> Path:
    return Path(os.environ.get("GUARD_R8E_OUT") or sys.exit("set GUARD_R8E_OUT"))


def load_cfg() -> dict:
    return yaml.safe_load((HERE / "sources_r8e.yaml").read_text("utf-8"))


def h12(t: str) -> str:
    return hashlib.sha256(t.encode("utf-8")).hexdigest()[:12]


def r8e_holdout_rows(hold: Path) -> list[dict]:
    rows = [{"id": r["id"], "text": r["text"]} for r in H.read_jsonl(hold / "vi1/holdout/vi.jsonl")]
    for lang in ("en", "vi"):
        rows += [{"id": r["id"], "text": r["text"]} for r in H.read_jsonl(hold / "tp1/holdout" / f"{lang}.jsonl")]
    rows += [{"id": r["id"], "text": r["text"]} for r in H.read_jsonl(hold / "long11/payloads.jsonl")]
    return rows


def use_r8e(a) -> None:
    """build_r8c's guard with this round's profiles and output directory; split2, vi1, tp1 and the long11 payloads
    join the short hold-out rows."""
    R.load_cfg, R.out_dir = load_cfg, out_dir
    out_dir().mkdir(parents=True, exist_ok=True)
    r8c_short = R.short_holdout_rows
    extra = [{"id": i, "text": t} for i, t in D.split2_texts(a.r8d_holdouts)] + r8e_holdout_rows(a.r8e_holdouts)
    R.short_holdout_rows = lambda hold: r8c_short(hold) + extra


def row(r: dict, tag: str, source: str) -> dict:
    return {"id": f"{r['lang']}-{tag}-{h12(r['text'])}", "text": r["text"], "labels": r["labels"], "lang": r["lang"],
            "variant": r["variant"], "source": source, "license": "Apache-2.0", "group": f"r8e.{tag}.{h12(r['text'])}",
            "kind": r["kind"], "set": "r8e"}


def stage_rows(a) -> int:
    out = out_dir()
    cfg = load_cfg()
    seed, n = cfg["seed"], cfg["counts"]
    tok = V8.Tok()
    ix, gstats, short, holdouts, _ = R.guard(a, cfg)
    wg, wc = R.word_guards(a)
    counts: collections.Counter = collections.Counter()

    def hit(t: str) -> bool:
        return bool(ix.check(t)[1] or short.check(t)[1])

    def reject(tag):
        def f(t: str) -> bool:
            if hit(t) or wg.hit(t) or wc.hit(t):
                counts[f"{tag}:rejected_overlap"] += 1
                return True
            return False
        return f

    src = "guard-spec:r8e-templates"
    Tp = [row(r, "r8eT", src) for r in T.t_rows(seed, n["tplus_attack"], n["tplus_benign"], reject("T+"))]
    Op = [row(r, "r8eO", src) for r in T.o_rows(seed + 1, n["oplus"], reject("O+"))]
    Np = [row(r, "r8eN", src) for r in T.n_rows(seed + 2, n["nplus"], reject("N+"))]

    # L++: new windows of R8d's L+ pool, each with an English T+ or O+ attack
    lp = Path(a.lp_dir)
    pins = cfg["lpp"]
    for f, key in (("pool/docs.jsonl", "pool_sha256"), ("pool/sanitized.jsonl", "sanitized_sha256"),
                   ("r8d_Lplus_train.jsonl", "lplus_sha256")):
        got = V8.sha256_file(lp / f)
        if got != pins[key]:
            raise SystemExit(f"{lp / f}: SHA-256 {got}, sources_r8e.yaml pins {pins[key]}")
    pool = {json.loads(ln)["id"]: json.loads(ln) for ln in open(lp / "pool/docs.jsonl", encoding="utf-8")}
    clean = {}
    for ln in open(lp / "pool/sanitized.jsonl", encoding="utf-8"):
        d = json.loads(ln)
        if "text" in d:
            clean[d["id"]] = d["text"]
    used = {r["host_id"] for r in H.read_jsonl(lp / "r8d_Lplus_train.jsonl")}
    payloads = [p for p in Tp + Op if p["lang"] == "en" and p["labels"] != ["benign"]]
    payloads = [dict(p, license="Apache-2.0") for p in payloads if tok.n(p["text"]) <= 170]
    random.Random(f"{seed}:lpp:payloads").shuffle(payloads)
    counts["lpp:payloads"] = len(payloads)
    cand: dict[str, list] = collections.defaultdict(list)
    for did in sorted(clean):
        text = clean[did]
        for c0, c1 in R.window_spans(tok, text):
            if len(text[c0:c1].strip()) >= R.MIN_WINDOW_CHARS:
                cand[pool[did]["genre"]].append((did, c0, c1))
    rng = random.Random(f"{seed}:lpp:windows")
    clean_b = {k: v.encode("utf-8") for k, v in clean.items()}
    Lpp, seen, cursor = [], set(), 0
    for genre in GENRES:
        want = int(pins["windows_per_genre"][genre])
        got = 0
        for did, c0, c1 in sorted(rng.sample(cand[genre], min(len(cand[genre]), want * 3))):
            if got >= want:
                break
            text = clean[did]
            w = text[c0:c1].strip()
            hid = f"en-r8dLh-{h12(w)}"  # the id L+ gives a host window: skip the ones L+ used
            if hid in used or hit(w):
                counts[f"lpp:host_skipped:{genre}"] += 1
                continue
            s, e = len(text[:c0].encode("utf-8")), len(text[:c1].encode("utf-8"))
            src_doc = pool[did]
            b = {"id": f"en-r8eLh-{h12(w)}", "text": w, "labels": ["benign"], "lang": "en", "variant": "orig",
                 "source": src_doc["source"], "license": src_doc["license"], "group": f"r8e.{genre}.{did}",
                 "kind": "r8e_host", "set": "r8e", "origin": f"{did}:{s}-{e}", "host_kind": genre}
            position = V8.weighted_choice(random.Random(f"{seed}:lpp:host:{b['id']}"), cfg["placements"])
            made = None
            for attempt in range(8):
                p = payloads[cursor % len(payloads)]
                cursor += 1
                prng = random.Random(f"{seed}:lpp:embed:{b['id']}:{attempt}")
                if position == "straddle_window":
                    res = V8.make_straddle(clean_b[did], s, e, p["text"], tok, prng)
                else:
                    res = V8.make_one_window(position, w, p["text"], "en", tok, prng, cfg)
                if res is None:
                    counts[f"lpp:embed_failed:{position}"] += 1
                    continue
                t2, spans, _ = res
                if not V8.spans_hold(t2, spans, p["text"]):
                    counts[f"lpp:span_mismatch:{position}"] += 1
                    continue
                r = V8.attack_row(b, genre, position, t2, spans, p, tok)
                ws = tok.windows(r)
                if not any(x.why == "payload" for x in ws) or (position != "straddle_window" and len(ws) != 1):
                    counts[f"lpp:window_mismatch:{position}"] += 1
                    continue
                if hit(t2) or t2 in seen:
                    counts[f"lpp:guard_replaced:{position}"] += 1
                    continue
                r.update({"id": f"en-r8eLa-{h12(t2)}", "source": "guard-spec:r8e-embedded", "kind": "r8e_lpp_attack",
                          "set": "r8e"})
                made = r
                break
            if made is None:
                counts[f"lpp:host_without_attack:{position}"] += 1
                continue
            seen.add(made["text"])
            Lpp.append(made)
            got += 1
        counts[f"lpp:taken:{genre}"] = got

    files = dict(zip(FILES, (Tp, Op, Np, Lpp)))
    stats = {"seed": seed, "inputs": {
        "sources_r8e_sha256": V8.sha256_file(HERE / "sources_r8e.yaml"),
        "r8e_templates_sha256": V8.sha256_file(HERE / "r8e_templates.py"),
        "lp_pool_sha256": pins["pool_sha256"], "lp_sanitized_sha256": pins["sanitized_sha256"],
        "tokenizer": Path(tok.path).name, "tokenizer_sha256": V8.sha256_file(Path(tok.path))},
        "guard_index": gstats, "index_shingles": ix.shingles, "build": dict(sorted(counts.items()))}
    for name, rs in files.items():
        p = out / f"{name}.jsonl"
        H.write_jsonl(p, rs)
        stats[name] = {"rows": len(rs), "sha256": V8.sha256_file(p),
                       "by_kind_lang_variant": dict(sorted(collections.Counter(
                           f"{r['kind']}:{r['lang']}:{r['variant']}" for r in rs).items())),
                       "labels": dict(sorted(collections.Counter("+".join(r["labels"]) for r in rs).items()))}
        if name == "r8e_Lpp_train":
            stats[name]["placement"] = dict(sorted(collections.Counter(r["position"] for r in rs).items()))
            stats[name]["genre"] = dict(sorted(collections.Counter(r["host_kind"] for r in rs).items()))
            stats[name]["payload_uses_max"] = max(collections.Counter(r["payload_id"] for r in rs).values(), default=0)
    (out / "stats_r8e.json").write_text(json.dumps(stats, indent=1, ensure_ascii=False) + "\n", "utf-8")
    R.log(json.dumps({k: stats[k] for k in files}, indent=1, ensure_ascii=False))
    return 0


def stage_check(a) -> int:
    out = out_dir()
    cfg = load_cfg()
    ix, gstats, short, _, _ = R.guard(a, cfg)
    wg, wc = R.word_guards(a)
    rep = {"k": 50, "short_k": 12, "index": gstats, "index_shingles": ix.shingles, "files": {}}
    ok = True
    for name in FILES:
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
    (out / "guard_r8e.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    R.log(json.dumps({k: v for k, v in rep.items() if k != "index"}, indent=1, ensure_ascii=False)[:5000])
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["rows", "check"])
    ap.add_argument("--holdouts", type=Path, required=True, help="the R8c holdout directory (persona3/, split1/)")
    ap.add_argument("--r8d-holdouts", type=Path, required=True, help="the R8d holdout directory (split2/)")
    ap.add_argument("--r8e-holdouts", type=Path, required=True, help="the R8e holdout directory (vi1/, tp1/, long11/)")
    ap.add_argument("--lp-dir", type=Path, help="R8d's L+ directory (pool/, r8d_Lplus_train.jsonl)")
    ap.add_argument("--data", type=Path, default=Path.home() / "WorkingSpace/AI_R_D/guardspec-data")
    ap.add_argument("--embedded", action="append", default=[], help="embedded-attack documents (glob of docs.jsonl)")
    ap.add_argument("--holdout-rows", action="append", default=[], help="further hold-out row files (glob)")
    a = ap.parse_args()
    use_r8e(a)
    if a.stage == "rows" and not a.lp_dir:
        ap.error("rows needs --lp-dir")
    return {"rows": stage_rows, "check": stage_check}[a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
