# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""R8c (RF-f9e76bb6) training additions of arm EPL: `L` (long technical windows, benign and embedded attack) and
`S` (payload splitting), train/reports/r8c_preregistration.md.

Arm EPL trains on E's data (data-v4A, out-full, v8e_train.jsonl, unchanged), R8b's persona_neg_train.jsonl and the
two files written here (`train.py --extra-train`):

  L  benign gateway windows (254 content tokens) of long technical documentation (documentation sites, RFCs,
     README files, man pages; data/sources_r8c.yaml, sources disjoint from every bench/long profile, long9
     included), kind `r8c_benign`, and for each of them one window of the same host with a training payload
     embedded, kind `r8c_attack`: exactly the build_v8 scheme (its placements, its embedding code, payloads of
     data/train.jsonl set A only, never eval/, a validation, hold-out or probe row), 1 : 1 by rows.
  S  payload-splitting attack texts and hard negatives (data/r8c_templates.py s_rows; the turns joined with a
     space, as the conversation window joins them), kinds `r8c_split_attack` and `r8c_split_benign`.

Stages (OUT = $GUARD_R8C_OUT, outside the repository; BENCH_CACHE as for bench/long):

  pool      load the sources (sha256 pins checked), drop or trim every unit that shares a run of 50 classifier
            tokens with a bench/long document (profiles of sources_r8c.yaml `guard`, long9 included), an
            embedded-attack document (--embedded) or a hold-out row, and write OUT/pool/docs.jsonl (documents of
            about 30k tokens per genre) and OUT/pool_report.json.
  sanitize  run the gateway's sanitizer (internal/sanitizer, through a temporary `go run` helper in the
            repository, removed afterwards) over the pool: OUT/pool/sanitized.jsonl. Windows are cut from the
            sanitized text, as the gateway sees it.
  rows      write OUT/r8c_L_train.jsonl, OUT/r8c_S_train.jsonl and OUT/stats_r8c.json (counts per kind, genre and
            placement, gateway windows per label, the SHA-256 of every input and output).
  check     bench_guard over both files (50-token runs; 12-token runs for short hold-out rows) and the 8-word
            shingle rule of build_r8c_holdouts (exact, or half of a hold-out row's shingles) between the hold-out
            rows (persona1/2/3, split1, multiturn.json, the payload_split dev set, eval/, the exemplars) and the
            new rows; writes OUT/guard_r8c.json and exits 1 on any overlap.

Hold-out rows of every stage: eval/ (every set), the repository's val_*_holdout files, persona1 (dev and
holdout), persona2, persona3, split1, multiturn.json, the payload_split dev set and the L3 exemplars
(--holdout-rows adds files). The owner hold-outs are not read here.

    cd train && GUARD_R8C_OUT=... BENCH_CACHE=... MODEL_DIR=... GITHUB_TOKEN=... uv run --frozen python data/build_r8c.py pool \\
        --holdouts <R8c holdout dir> --embedded '<R5 docs.jsonl>' --embedded '<long6 attack>' --embedded '<long7 attack>' \\
        --embedded '<long8 attack>' --embedded '<long9 attack>'
    ... data/build_r8c.py sanitize
    ... data/build_r8c.py rows (same options as pool)
    ... data/build_r8c.py check (same options)

Seeded and byte-identical between runs. Nothing here reads a model.
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
TRAIN = HERE.parent
REPO = TRAIN.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(TRAIN))
sys.path.insert(0, str(REPO / "bench" / "long"))

import build_r8c_holdouts as H  # noqa: E402
import build_v8 as V8  # noqa: E402
import r8c_templates as T  # noqa: E402
import windows as W  # noqa: E402

GENRES = ("docs", "rfc", "readme", "man")
MIN_WINDOW_CHARS = 200
SANITIZE_GO = '''package main

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

// Reads JSON lines {id, text} and writes {id, text} after the gateway's sanitizer ({id, rejected} when it
// rejects the text). Written by train/data/build_r8c.py sanitize, removed after the run.
func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<30)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for in.Scan() {
		var d struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(in.Bytes(), &d); err != nil {
			panic(err)
		}
		c, _, err := sanitizer.Sanitize(d.Text)
		if err != nil {
			_ = enc.Encode(map[string]string{"id": d.ID, "rejected": err.Error()})
			continue
		}
		_ = enc.Encode(map[string]string{"id": d.ID, "text": c})
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
'''


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def out_dir() -> Path:
    return Path(os.environ.get("GUARD_R8C_OUT") or sys.exit("set GUARD_R8C_OUT"))


def load_cfg() -> dict:
    return yaml.safe_load((HERE / "sources_r8c.yaml").read_text("utf-8"))


def h12(t: str) -> str:
    return hashlib.sha256(t.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------------------------------------
# Hold-outs and the guard

def short_holdout_rows(hold: Path) -> list[dict]:
    """split1 (turns and joined conversations), multiturn.json, the payload_split dev set and the exemplars, as
    rows {id, text}."""
    rows = [{"id": i, "text": t} for i, t in H.split1_texts(hold)]
    rows += [{"id": f"multiturn:{k}", "text": t} for k, t in enumerate(H.multiturn_texts())]
    rows += [{"id": f"payload_split:{k}", "text": t} for k, t in enumerate(H.payload_split_texts())]
    rows += [{"id": f"exemplar:{r.get('id', k)}", "text": r["text"]}
             for k, r in enumerate(H.read_jsonl(REPO / "internal/inference/ml/exemplars/default.jsonl"))]
    return rows


def holdout_paths(a) -> list[Path]:
    """Hold-out row files of the guard besides eval/ and val_*_holdout (build_v7.holdout_files adds those)."""
    data, hold = a.data, a.holdouts
    fs = sorted(glob.glob(str(data / "v9/persona1/out/*/direct/*.jsonl")))
    fs += sorted(glob.glob(str(data / "v9/r8b/persona2/holdout/direct/*.jsonl")))
    fs += sorted(glob.glob(str(hold / "persona3/holdout/direct/*.jsonl")))
    p = out_dir() / "guard_short_holdouts.jsonl"
    H.write_jsonl(p, short_holdout_rows(hold))
    return [Path(x) for x in fs] + [p] + [Path(x) for pat in a.holdout_rows for x in sorted(glob.glob(os.path.expanduser(pat)))]


def guard(a, cfg):
    import build  # bench/long/build.py
    import build_v7
    from bench_guard import tokenizer_fn

    bench = Path(os.environ.get("BENCH_CACHE") or REPO / "bench" / ".cache") / "long"
    build_v7.BENCH_PROFILES = list(cfg["guard"]["profiles"])
    tok = tokenizer_fn(build.find_tokenizer(None))
    holdouts = build_v7.holdout_files([str(p) for p in holdout_paths(a)])
    log(f"guard: {len(holdouts)} hold-out files; indexing bench/long {build_v7.BENCH_PROFILES} and {a.embedded}")
    ix, stats, short = build_v7.guard_index(tok, bench, a.embedded, holdouts)
    log(f"guard: {ix.docs} documents/rows, {ix.shingles:,} shingles; {short.docs} short hold-out rows")
    return ix, stats, short, holdouts, bench


class Contained:
    """The other direction of the 8-word rule, pair by pair: a guarded text of which half or more of the
    shingles occur in one given text (a hold-out row inside a longer training row)."""

    def __init__(self, sources: dict[str, list[str]]):
        self.rows: list[tuple[str, int]] = []
        self.inv: dict[int, list[int]] = collections.defaultdict(list)
        for name, texts in sources.items():
            for t in texts:
                sh = H.shingles(t) if t else set()
                if not sh:
                    continue
                j = len(self.rows)
                self.rows.append((name, len(sh)))
                for x in sh:
                    self.inv[x].append(j)

    def hit(self, text: str) -> tuple[str, float] | None:
        c: collections.Counter = collections.Counter()
        for x in H.shingles(text):
            for j in self.inv.get(x, ()):
                c[j] += 1
        for j, n in c.most_common():
            share = n / self.rows[j][1]
            if share >= H.OVERLAP:
                return self.rows[j][0], round(share, 3)
        return None


def guard_sources(a) -> dict[str, list[str]]:
    src: dict[str, list[str]] = {"short_holdouts": [r["text"] for r in short_holdout_rows(a.holdouts)]}
    for p in holdout_paths(a)[:-1]:
        src[f"holdout:{p.parent.parent.parent.name}/{p.parent.parent.name}/{p.name}"] = [r.get("text") or "" for r in H.read_jsonl(p)]
    for p in sorted(glob.glob(str(REPO / "eval" / "**" / "*.jsonl"), recursive=True)):
        src[f"eval:{Path(p).relative_to(REPO / 'eval')}"] = [r.get("text") or "" for r in H.read_jsonl(Path(p))]
    return src


def word_guards(a) -> tuple["H.Guard", Contained]:
    """The 8-word rule in both directions over the short hold-out rows, persona1/2/3 and eval/."""
    src = guard_sources(a)
    return H.Guard(src), Contained(src)


# ---------------------------------------------------------------------------------------------------------
# pool, sanitize

def stage_pool(a) -> int:
    import build
    from tokenizers import Tokenizer

    out = out_dir()
    cfg = load_cfg()
    corpus = yaml.safe_load((REPO / "bench/long/corpus.yaml").read_text("utf-8"))
    ix, gstats, short, holdouts, bench = guard(a, cfg)
    htok = Tokenizer.from_file(str(build.find_tokenizer(None)))
    htok.no_truncation()
    htok.no_padding()
    l9 = set(corpus["profiles"]["long9"]["sources"])
    rep: dict = {"guard_index": gstats, "holdout_files": [str(p) for p in holdouts], "sources": {}, "unpinned": {}}
    pools: dict[str, list] = {}
    for name, src in cfg["sources"].items():
        if name in corpus["sources"] or name in l9:
            raise SystemExit(f"{name}: also a bench/long source")
        units = build.load_source(name, src, bench / "src", corpus["sources"])
        got = build.sha256_text("\n\x1e\n".join(units))
        if src.get("sha256") and src["sha256"] != got:
            raise SystemExit(f"{name}: extracted text has SHA-256 {got}, sources_r8c.yaml pins {src['sha256']}")
        if not src.get("sha256"):
            rep["unpinned"][name] = got
        kept, dropped, trimmed = [], 0, 0

        def hit(t):
            return ix.check(t)[1] or short.check(t)[1]

        for u in units:
            if not hit(u):
                kept.append(u)
                continue
            paras = [b for b in u.split("\n\n") if b.strip()]
            good = [b for b in paras if not hit(b)]
            if good and sum(map(len, good)) >= 0.3 * len(u) and not hit("\n\n".join(good)):
                kept.append("\n\n".join(good))
                trimmed += 1
            else:
                dropped += 1
        rep["sources"][name] = {"units": len(units), "kept": len(kept), "trimmed": trimmed, "dropped": dropped, "sha256": got}
        log(f"  {name}: {len(units)} units, {trimmed} trimmed, {dropped} dropped by the guard")
        pools.setdefault(src["genre"], []).append((name, kept, src["license"]))
    docs = []
    for genre in GENRES:
        members = pools[genre]
        units = build.interleave([u for _, u, _ in members])
        srcs = build.interleave([[n] * len(u) for n, u, _ in members])
        lic = {n: l for n, _, l in members}
        k, cur, cur_src, cur_tok, total = 0, [], set(), 0, 0
        for u, s in zip(units, srcs):
            n = len(htok.encode(u).ids)
            cur.append(u)
            cur_src.add(s)
            cur_tok += n
            total += n
            if cur_tok >= cfg["pool"]["doc_tokens"]:
                docs.append(_pool_doc(genre, k, cur, cur_src, lic, cur_tok))
                k, cur, cur_src, cur_tok = k + 1, [], set(), 0
        if cur:
            docs.append(_pool_doc(genre, k, cur, cur_src, lic, cur_tok))
            k += 1
        rep.setdefault("pool", {})[genre] = {"docs": k, "tokens": total}
        log(f"  pool {genre}: {k} documents, {total:,} tokens")
    (out / "pool").mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(d, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for d in docs)
    (out / "pool" / "docs.jsonl").write_text(body, "utf-8")
    rep["pool_sha256"] = hashlib.sha256(body.encode()).hexdigest()
    (out / "pool_report.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(f"pool: {len(docs)} documents, sha256 {rep['pool_sha256']}")
    for n, s in rep["unpinned"].items():
        log(f"  not pinned in sources_r8c.yaml: sources.{n}.sha256: {s}")
    return 0


def _pool_doc(genre, k, units, srcs, lic, ntok):
    return {"id": f"r8cpool-{genre}-en-{k}", "kind": "benign", "lang": "en", "genre": genre, "text": "\n\n".join(units),
            "source": "+".join(sorted(srcs)), "license": "; ".join(f"{s}: {lic[s]}" for s in sorted(srcs)),
            "split": "dev", "tokens": ntok}


def stage_sanitize(a) -> int:
    out = out_dir()
    tmp = Path(tempfile.mkdtemp(prefix="_r8c_sanitize_", dir=REPO))  # inside the module: internal/ is importable
    try:
        (tmp / "main.go").write_text(SANITIZE_GO, "utf-8")
        with open(out / "pool" / "docs.jsonl", "rb") as fi, open(out / "pool" / "sanitized.jsonl", "wb") as fo:
            subprocess.run(["go", "run", f"./{tmp.name}"], cwd=REPO, stdin=fi, stdout=fo, check=True)
    finally:
        shutil.rmtree(tmp)
    n = sum(1 for _ in open(out / "pool" / "sanitized.jsonl", encoding="utf-8"))
    log(f"sanitized {n} documents: sha256 {V8.sha256_file(out / 'pool' / 'sanitized.jsonl')}")
    return 0


# ---------------------------------------------------------------------------------------------------------
# rows

def window_spans(tok: "V8.Tok", text: str) -> list[tuple[int, int]]:
    """Character spans of the gateway windows of a text (254 content tokens, a new window every 190)."""
    offs = tok.offsets(text)
    return [(offs[s][0], offs[e - 1][1]) for s, e in W.token_ranges(len(offs)) if e > s]


def stage_rows(a) -> int:
    out = out_dir()
    cfg = load_cfg()
    seed = cfg["seed"]
    tok = V8.Tok()
    ix, gstats, short, holdouts, _ = guard(a, cfg)
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

    # benign windows: a seeded sample per genre
    cand: dict[str, list] = collections.defaultdict(list)
    for did in sorted(clean):
        text = clean[did]
        for c0, c1 in window_spans(tok, text):
            w = text[c0:c1].strip()
            if len(w) >= MIN_WINDOW_CHARS:
                cand[pool[did]["genre"]].append((did, c0, c1))
    rng = random.Random(f"{seed}:windows")
    hosts = []
    for genre in GENRES:
        items = cand[genre]
        want = int(cfg["windows"][genre])
        pick = sorted(rng.sample(items, min(len(items), want * 2)))  # spares for the guard and duplicates
        got = 0
        for did, c0, c1 in pick:
            if got >= want:
                break
            text = clean[did]
            w = text[c0:c1].strip()
            if hit(w):
                counts[f"benign:guard_dropped:{genre}"] += 1
                continue
            s = len(text[:c0].encode("utf-8"))
            e = len(text[:c1].encode("utf-8"))
            src = pool[did]
            hosts.append({"id": f"en-r8cLb-{h12(w)}", "text": w, "labels": ["benign"], "lang": "en", "variant": "orig",
                          "source": src["source"], "license": src["license"], "group": f"r8c.{genre}.{did}",
                          "kind": "r8c_benign", "set": "r8c", "origin": f"{did}:{s}-{e}", "host_kind": genre})
            got += 1
        counts[f"benign:available:{genre}"] = len(items)
        counts[f"benign:taken:{genre}"] = got

    # attack windows: build_v8's scheme, one per host
    pcfg = {"payloads": cfg["payloads"], "seed": seed}
    payloads = V8.load_payloads(pcfg, tok, ix, short, V8.held_texts(holdouts), V8.eval_fingerprints(), counts)
    # The 8-word rule as well: the L3 exemplars are copies of data/train.jsonl rows, so a payload can be one.
    wg, wc = word_guards(a)
    for lang in payloads:
        keep = [p for p in payloads[lang] if not wg.hit(p["text"]) and not wc.hit(p["text"])]
        counts[f"payload:skipped:holdout_word8:{lang}"] = len(payloads[lang]) - len(keep)
        counts[f"payload:usable:{lang}"] = len(keep)
        payloads[lang] = keep
    cursor = {lang: 0 for lang in payloads}
    clean_b = {k: v.encode("utf-8") for k, v in clean.items()}
    rows = []
    for b in hosts:
        rows.append(b)
        did, rng_s = b["origin"].rsplit(":", 1)
        s, e = (int(x) for x in rng_s.split("-"))
        hrng = random.Random(f"{seed}:host:{b['id']}")
        position = V8.weighted_choice(hrng, cfg["placements"])
        made = None
        for attempt in range(8):
            pl = payloads["en"]
            p = pl[cursor["en"] % len(pl)]
            cursor["en"] += 1
            prng = random.Random(f"{seed}:embed:{b['id']}:{attempt}")
            if position == "straddle_window":
                res = V8.make_straddle(clean_b[did], s, e, p["text"], tok, prng)
            else:
                res = V8.make_one_window(position, b["text"], p["text"], "en", tok, prng, cfg)
            if res is None:
                counts[f"embed_failed:{position}"] += 1
                continue
            text, spans, _host = res
            if not V8.spans_hold(text, spans, p["text"]):
                counts[f"span_mismatch:{position}"] += 1
                continue
            r = V8.attack_row(b, b["host_kind"], position, text, spans, p, tok)
            ws = tok.windows(r)
            if not any(w.why == "payload" for w in ws) or (position != "straddle_window" and len(ws) != 1):
                counts[f"window_mismatch:{position}"] += 1
                continue
            if hit(text):
                counts[f"guard_replaced:{position}"] += 1
                continue
            r.update({"id": f"en-r8cLa-{h12(text)}", "source": "guard-spec:r8c-embedded", "kind": "r8c_attack",
                      "set": "r8c", "license": r["license"]})
            made = r
            break
        if made is None:
            counts[f"host_without_attack:{position}"] += 1
            continue
        rows.append(made)
    seen, L = set(), []
    for r in rows:
        if r["text"] in seen:
            counts[f"duplicate_text:{r['kind']}"] += 1
            continue
        seen.add(r["text"])
        L.append(r)

    # S

    def reject(t: str) -> bool:
        if hit(t) or wg.hit(t) or wc.hit(t):
            counts["S:rejected_overlap"] += 1
            return True
        return False

    sc = cfg["split"]
    S = []
    for r in T.s_rows(seed, sc["attack"], sc["benign"], sc["vi_share"], reject=reject):
        S.append({"id": f"{r['lang']}-r8cS-{h12(r['text'])}", "text": r["text"], "labels": r["labels"], "lang": r["lang"],
                  "variant": "orig", "source": "guard-spec:r8c-split-templates", "license": "Apache-2.0",
                  "group": f"r8c.split.{r['kind']}.{h12(r['text'])}", "kind": r["kind"], "set": "r8c",
                  "intent": r["intent"], "turns": r["turns"]})
    files = {"r8c_L_train": L, "r8c_S_train": S}
    stats = {"seed": seed, "inputs": {
        "pool_sha256": V8.sha256_file(out / "pool" / "docs.jsonl"),
        "sanitized_sha256": V8.sha256_file(out / "pool" / "sanitized.jsonl"),
        "payload_file_sha256": V8.sha256_file(TRAIN / cfg["payloads"]["file"]),
        "sources_r8c_sha256": V8.sha256_file(HERE / "sources_r8c.yaml"),
        "r8c_templates_sha256": V8.sha256_file(HERE / "r8c_templates.py"),
        "tokenizer": Path(tok.path).name, "tokenizer_sha256": V8.sha256_file(Path(tok.path))},
        "guard_index": gstats, "index_shingles": ix.shingles, "build": dict(sorted(counts.items()))}
    for name, rs in files.items():
        p = out / f"{name}.jsonl"
        H.write_jsonl(p, rs)
        stats[name] = describe(rs, tok) | {"sha256": V8.sha256_file(p)}
    (out / "stats_r8c.json").write_text(json.dumps(stats, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(json.dumps({k: stats[k] for k in files}, indent=1, ensure_ascii=False))
    return 0


def describe(rows: list[dict], tok) -> dict:
    win: collections.Counter = collections.Counter()
    for r in rows:
        for w in tok.windows(r):
            lab = "dropped" if w.labels is None else ("benign" if w.labels == ["benign"] else "attack")
            win[f"{r['kind']}:{lab}"] += 1
    att = [r for r in rows if r["kind"] == "r8c_attack"]
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


# ---------------------------------------------------------------------------------------------------------
# check

def stage_check(a) -> int:
    out = out_dir()
    cfg = load_cfg()
    ix, gstats, short, _, _ = guard(a, cfg)
    wg, wc = word_guards(a)
    rep = {"k": 50, "short_k": 12, "index": gstats, "index_shingles": ix.shingles, "files": {}}
    ok = True
    for name in ("r8c_L_train", "r8c_S_train"):
        p = out / f"{name}.jsonl"
        rows = H.read_jsonl(p)
        counts: collections.Counter = collections.Counter()
        examples: dict = {}
        kept = ix.filter_rows(rows, counts, p.name, examples)
        contained = [r["id"] for r in kept if short.check(r["text"])[1]]
        # 8-word rule, both directions: a new row mostly made of hold-out text, or a hold-out row mostly
        # contained in a new row
        words = [r["id"] for r in rows if wg.hit(r["text"])]
        rev = []
        for r in rows:
            hh = wc.hit(r["text"])
            if hh:
                rev.append({"row": r["id"], "holdout_source": hh[0], "share": hh[1]})
        rep["files"][name] = {"rows": len(rows), "rows_clean_50token": len(kept), "short_holdout_12token_overlap": contained,
                              "word8_overlap": words, "holdout_rows_contained": rev[:50], "counts": dict(counts),
                              "examples": examples, "sha256": V8.sha256_file(p)}
        ok = ok and len(kept) == len(rows) and not contained and not words and not rev
    rep["result"] = "clean" if ok else "OVERLAP"
    (out / "guard_r8c.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(json.dumps({k: v for k, v in rep.items() if k != "index"}, indent=1, ensure_ascii=False)[:5000])
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["pool", "sanitize", "rows", "check"])
    ap.add_argument("--holdouts", type=Path, help="the R8c holdout directory (persona3/, split1/)")
    ap.add_argument("--data", type=Path, default=Path.home() / "WorkingSpace/AI_R_D/guardspec-data")
    ap.add_argument("--embedded", action="append", default=[], help="embedded-attack documents (glob of docs.jsonl)")
    ap.add_argument("--holdout-rows", action="append", default=[], help="further hold-out row files (glob)")
    a = ap.parse_args()
    if a.stage != "sanitize" and not a.holdouts:
        ap.error("--holdouts is required")
    return {"pool": stage_pool, "sanitize": stage_sanitize, "rows": stage_rows, "check": stage_check}[a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
