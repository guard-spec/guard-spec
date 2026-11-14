# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""v8 training addition: the v7 long benign windows and as many attack windows of the same hosts (RF-3a9ce3f9 R7).

v7 (RF-895d3533 R6) added benign windows of long text only; the model learnt that prose around an
instruction is a benign signal (train/reports/v7_holdout.md). v8 keeps every v7 benign window and adds,
for each of them, one window of the same host text with a payload embedded (data/sources_v8.yaml):

    benign  the v7 row (kinds v7_long, v7_hardneg, v7_gen as `host_kind`), kind `v8_benign`, labels ["benign"]
    attack  a part of the same host (the window's own text, or for `straddle_window` the sanitized pool text
            from the window's start on) with a training payload at one of the placements of sources_v8.yaml,
            kind `v8_attack`, labels = the payload's labels + indirect_injection, with `spans` / `byte_spans`
            (train/windows.py labels each gateway window of the row from them)

so the addition is 1 : 1 by rows. The payloads are attack rows of data/train.jsonl (the training split,
v5/v6 payload set A); never eval/, a validation, hold-out or probe row. Every candidate row goes through
the guard of stage `check`; a candidate that shares a run is replaced by the same placement with the next
payload.

Stages (GUARD_V8_OUT is the output directory, outside the repository; GUARD_V7_DIR the v7 build):

    rows   write <out>/v8_train.jsonl (every benign and attack row), <out>/v8e_train.jsonl (arm E: every
           attack row and a seeded half of the benign rows) and <out>/stats_v8.json (counts per kind,
           language, placement and host genre, gateway windows per label, the benign : attack ratios,
           the payloads, the SHA-256 of every input and output).
    check  bench_guard over both files against every bench/long profile of sources_v8.yaml (long7
           included), the embedded-attack documents given with --embedded (R5, long6, long7) and every
           hold-out row; writes <out>/guard_v8.json and exits 1 if any row shares a run.

    cd train && GUARD_V8_OUT=... GUARD_V7_DIR=... BENCH_CACHE=... uv run --frozen python data/build_v8.py rows \\
        --embedded '<R5 attack docs.jsonl>' --embedded '<long6 attack>' --embedded '<long7 attack>' \\
        --holdout-rows '<extra hold-out files>' ...
    ... data/build_v8.py check (same options)

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

import windows as W  # noqa: E402  (train/windows.py, standard library only)
from common import fingerprint, normalize_for_fingerprint  # noqa: E402

CONTENT = W.MAX_LEN - 2  # 254 content tokens per gateway window
SLACK = 3                # tokens kept free when a payload and its host are fitted into one window
HOST_KINDS = ("v7_long", "v7_hardneg", "v7_gen")
ONE_WINDOW = ("mid", "split_adjacent", "split_within", "start", "end")
INDIRECT = "indirect_injection"


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sha12(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def load_cfg() -> dict:
    return yaml.safe_load((HERE / "sources_v8.yaml").read_text("utf-8"))


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested without a tokenizer)


def payload_set(group: str) -> str:
    """build_v5.payload_set: the v5/v6 split of the training payloads by group (A training, B/C validation
    and hold-out of those builds)."""
    h = int(hashlib.sha256(f"v5payload:{group}".encode()).hexdigest(), 16) % 100
    return "A" if h < 80 else ("B" if h < 90 else "C")


def weighted_choice(rng: random.Random, weights: dict[str, float], exclude=()) -> str:
    items = [(k, float(w)) for k, w in weights.items() if k not in exclude and float(w) > 0]
    total = sum(w for _, w in items)
    u = rng.random() * total
    acc = 0.0
    for k, w in items:
        acc += w
        if u < acc:
            return k
    return items[-1][0]


def split_halves(p: str) -> tuple[str, str] | None:
    """The payload cut at the space nearest its middle; None for a single word."""
    mid = len(p) // 2
    cands = [i for i, c in enumerate(p) if c == " " and 0 < i < len(p) - 1]
    if not cands:
        return None
    j = min(cands, key=lambda i: (abs(i - mid), i))
    a, b = p[:j].strip(), p[j:].strip()
    return (a, b) if a and b else None


def snap(s: str, i: int) -> int:
    """Move i back to the start of the word it is in (0 at most)."""
    i = max(0, min(i, len(s)))
    while i > 0 and not s[i - 1].isspace():
        i -= 1
    return i


def insert_at(host: str, i: int, piece: str) -> tuple[str, tuple[int, int]]:
    """Insert piece at character i, moved back to a word start, with a space on each side where the host
    has none; returns the text and the piece's character span."""
    i = snap(host, i)
    before = host[:i] + ("" if i == 0 or host[i - 1].isspace() else " ")
    after = ("" if i == len(host) or host[i].isspace() else " ") + host[i:]
    return before + piece + after, (len(before), len(before) + len(piece))


def embed(position: str, host: str, payload: str, rng: random.Random, bridges: list[str],
          gap_chars: tuple[int, int] | None = None) -> tuple[str, list[tuple[int, int]]] | None:
    """The host with the payload at a one-window placement; (text, character spans of the payload)."""
    if position == "start":
        sep = rng.choice(["\n\n", "\n", " "])
        return payload + sep + host, [(0, len(payload))]
    if position == "end":
        sep = rng.choice(["\n\n", "\n", " "])
        return host + sep + payload, [(len(host) + len(sep), len(host) + len(sep) + len(payload))]
    if position == "mid":
        n = len(host)
        text, sp = insert_at(host, rng.randint(n // 5, max(n // 5, (4 * n) // 5)), payload)
        return text, [sp]
    halves = split_halves(payload)
    if halves is None:
        return None
    a, b = halves
    if position == "split_adjacent":
        bridge = rng.choice(bridges)
        n = len(host)
        text, sp = insert_at(host, rng.randint(n // 10, max(n // 10, (9 * n) // 10)), f"{a} {bridge} {b}")
        s0 = sp[0]
        return text, [(s0, s0 + len(a)), (sp[1] - len(b), sp[1])]
    if position == "split_within":
        # gap_chars: the host characters between the halves (from the caller's token offsets)
        if gap_chars is None:
            return None
        p1, p2 = gap_chars
        if not 0 <= p1 < p2 <= len(host):
            return None
        t1, s2 = insert_at(host, p2, b)
        p1 = snap(t1, p1)
        if p1 >= s2[0] - 1:
            return None
        text, s1 = insert_at(t1, p1, a)
        shift = len(text) - len(t1)
        return text, [s1, (s2[0] + shift, s2[1] + shift)]
    raise ValueError(position)


def byte_spans(text: str, spans) -> list[list[int]]:
    return [list(x) for x in W.char_spans_to_bytes(text, spans)]


def spans_hold(text: str, spans, payload: str) -> bool:
    """Every word of the payload lies inside the spans, in order."""
    got = " ".join(text[a:b] for a, b in spans)
    pos = 0
    for w in payload.split():
        j = got.find(w, pos)
        if j < 0:
            return False
        pos = j + len(w)
    return bool(payload.split())


def half_of(rows: list[dict], fraction: float, seed) -> list[dict]:
    """A seeded `fraction` of the rows of each (host_kind, lang) stratum, in their original order."""
    by: dict[tuple, list[dict]] = collections.defaultdict(list)
    for r in rows:
        by[(r["host_kind"], r["lang"])].append(r)
    keep = set()
    for key in sorted(by):
        rs = sorted(by[key], key=lambda r: hashlib.sha256(f"{seed}:arm_e:{r['id']}".encode()).hexdigest())
        keep |= {r["id"] for r in rs[: round(fraction * len(rs))]}
    return [r for r in rows if r["id"] in keep]


# ---------------------------------------------------------------------------
# Tokenizer, guard, inputs


class Tok:
    """The base model's tokenizer.json (train/windows.GatewayTokenizer, what train.py cuts windows with)."""

    def __init__(self):
        cfg = yaml.safe_load((TRAIN / "config.yaml").read_text("utf-8"))
        from huggingface_hub import hf_hub_download

        self.path = hf_hub_download(cfg["base_model"], "tokenizer.json", revision=cfg["base_revision"])
        self.g = W.GatewayTokenizer(self.path)

    def offsets(self, text: str) -> list[tuple[int, int]]:
        """Character offsets of the content tokens."""
        return list(self.g.t.encode(text, add_special_tokens=False).offsets)

    def n(self, text: str) -> int:
        return len(self.g.t.encode(text, add_special_tokens=False).ids)

    def windows(self, row: dict) -> list[W.Window]:
        _, offs = self.g.encode_offsets(row["text"])
        return W.label_windows(row, offs)


def guard(args, cfg):
    import build  # bench/long/build.py
    import build_v7
    from bench_guard import tokenizer_fn

    bench = Path(os.environ.get("BENCH_CACHE") or REPO / "bench" / ".cache") / "long"
    build_v7.BENCH_PROFILES = list(cfg["guard"]["profiles"])
    tok = tokenizer_fn(build.find_tokenizer(None))
    holdouts = build_v7.holdout_files(args.holdout_rows)
    log(f"guard: {len(holdouts)} hold-out files; indexing bench/long {build_v7.BENCH_PROFILES} and {args.embedded}")
    ix, stats, short = build_v7.guard_index(tok, bench, args.embedded, holdouts)
    log(f"guard: {ix.docs} documents/rows, {ix.shingles:,} shingles; {short.docs} short hold-out rows")
    return ix, stats, short, holdouts


def v7_inputs(cfg) -> tuple[Path, list[dict], dict[str, bytes], dict]:
    v7 = Path(os.environ.get("GUARD_V7_DIR") or sys.exit("set GUARD_V7_DIR (the v7 build)"))
    files = {"v7_train_sha256": v7 / "v7_train.jsonl", "pool_sha256": v7 / "pool" / "docs.jsonl",
             "sanitized_sha256": v7 / "mine" / "sanitized.jsonl"}
    shas = {}
    for k, p in files.items():
        shas[k] = sha256_file(p)
        if shas[k] != cfg["v7"][k]:
            raise SystemExit(f"{p}: SHA-256 {shas[k]}, sources_v8.yaml pins {cfg['v7'][k]}")
    rows = [json.loads(ln) for ln in open(files["v7_train_sha256"], encoding="utf-8") if ln.strip()]
    clean = {}
    with open(files["sanitized_sha256"], encoding="utf-8") as f:
        for ln in f:
            d = json.loads(ln)
            clean[d["id"]] = d["text"].encode("utf-8")
    return v7, rows, clean, shas


def held_texts(holdouts: list[Path]) -> set[str]:
    """Normalized texts of every validation, hold-out and probe row (repository files and the given ones)."""
    out = set()
    fs = sorted(HERE.glob("val*.jsonl")) + sorted(HERE.glob("probe*.jsonl")) + list(holdouts)
    for p in fs:
        with open(p, encoding="utf-8") as f:
            for ln in f:
                if ln.strip():
                    out.add(normalize_for_fingerprint(json.loads(ln).get("text") or ""))
    return out


def eval_fingerprints() -> set[str]:
    fps = set()
    for p in (REPO / "eval" / "fingerprints.txt", REPO / "eval" / "codelog" / "fingerprints.txt",
              REPO / "eval" / "embedded" / "fingerprints.txt"):
        for ln in p.read_text("utf-8").splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                fps.add(ln)
    return fps


def load_payloads(cfg, tok: Tok, ix, short, held: set[str], fps: set[str], counts) -> dict[str, list[dict]]:
    pc = cfg["payloads"]
    out: dict[str, list[dict]] = {lang: [] for lang in pc["langs"]}
    with open(TRAIN / pc["file"], encoding="utf-8") as f:
        rows = [json.loads(ln) for ln in f if ln.strip()]
    for r in sorted(rows, key=lambda r: r["id"]):
        if r["labels"] == ["benign"] or r["lang"] not in out:
            continue
        counts["payload:attack_rows"] += 1
        t = r["text"]
        why = None
        if "owner" in r.get("source", ""):
            why = "owner_row"
        elif not pc["min_chars"] <= len(t) <= pc["max_chars"]:
            why = "length"
        elif payload_set(r["group"]) != pc["payload_set"]:
            why = "not_set_" + pc["payload_set"]
        elif fingerprint(t) in fps:
            why = "eval_fingerprint"
        elif normalize_for_fingerprint(t) in held:
            why = "in_val_holdout_probe"
        elif tok.n(t) > pc["max_tokens"]:
            why = "too_long"
        elif ix.check(t)[1] or short.check(t)[1]:
            why = "guard"
        if why:
            counts[f"payload:skipped:{why}"] += 1
            continue
        out[r["lang"]].append(r)
    for lang, lst in out.items():
        random.Random(f"{cfg['seed']}:payloads:{lang}").shuffle(lst)
        counts[f"payload:usable:{lang}"] = len(lst)
    return out


# ---------------------------------------------------------------------------
# Attack rows


def cut_tokens(text: str, offs, t0: int, t1: int) -> str:
    """The text of content tokens [t0, t1)."""
    if t1 <= t0:
        return ""
    return text[offs[t0][0]: offs[t1 - 1][1]]


def make_one_window(position, host_text, payload, lang, tok: Tok, rng: random.Random, cfg):
    """A one-window attack row's text and spans from a host window's text, or None."""
    ptoks = tok.n(payload)
    extra = 0
    if position == "split_adjacent":
        extra = 16  # bridge sentence
    offs = tok.offsets(host_text)
    budget = CONTENT - ptoks - extra - SLACK
    if budget < 24:
        return None
    for _ in range(4):
        h0 = rng.randint(0, max(0, len(offs) - budget))
        host = cut_tokens(host_text, offs, h0, min(len(offs), h0 + budget)).strip()
        gap = None
        if position == "split_within":
            hoffs = tok.offsets(host)
            if len(hoffs) < 40:
                return None
            g = rng.randint(15, min(60, len(hoffs) - 10))
            t1 = rng.randint(2, max(2, len(hoffs) - g - 2))
            gap = (hoffs[t1][0], hoffs[min(len(hoffs) - 1, t1 + g)][0])
        res = embed(position, host, payload, rng, cfg["bridges"][lang], gap)
        if res is None:
            return None
        text, spans = res
        n = tok.n(text)
        if n <= CONTENT:
            return text, spans, host
        budget -= n - CONTENT + 2
        if budget < 24:
            return None
    return None


def make_straddle(doc_bytes: bytes, s: int, e: int, payload, tok: Tok, rng: random.Random):
    """A two-window attack row: host text of the pool document from the window's start, the payload centred
    on the end of the first gateway window."""
    n_pay = tok.n(payload)
    want = CONTENT + rng.randint(60, 220)
    span = want * 16
    raw = doc_bytes[s: s + span].decode("utf-8", errors="ignore")
    offs = tok.offsets(raw)
    if len(offs) < want + 5:  # near the end of the document: the text before the window's end instead
        raw = doc_bytes[max(0, e - span): e].decode("utf-8", errors="ignore")
        offs = tok.offsets(raw)
        if len(offs) < want + 5:
            return None
        start = len(offs) - want
    else:
        start = 0
    # start and end on a token boundary; the leading token may be a word cut in half, as in the gateway's windows
    host = cut_tokens(raw, offs, start, start + want).strip()
    hoffs = tok.offsets(host)
    k = CONTENT - n_pay // 2
    if k <= 0 or k >= len(hoffs):
        return None
    text, sp = insert_at(host, hoffs[k][0], payload)
    return text, [sp], host


def attack_row(host_row, kind, position, text, spans, p, tok: Tok) -> dict:
    labels = sorted(set(p["labels"]) | {INDIRECT})
    row = {"id": f"{host_row['lang']}-v8a-{sha12(text)}", "text": text, "labels": labels, "lang": host_row["lang"],
           "variant": p["variant"], "source": "guard-spec:v8-embedded",
           "license": f"Apache-2.0; payload {p['license']}; host {host_row['license']}", "group": host_row["group"],
           "kind": "v8_attack", "set": "v8", "origin": host_row["origin"], "position": position,
           "spans": [list(x) for x in spans], "byte_spans": byte_spans(text, spans), "payload_id": p["id"],
           "payload_labels": p["labels"], "host_id": host_row["id"], "host_kind": kind, "tokens": tok.n(text)}
    return row


def benign_row(r: dict) -> dict:
    out = dict(r)
    out["id"] = f"{r['lang']}-v8b-{sha12(r['text'])}"
    out["host_kind"] = r["kind"]
    out["kind"] = "v8_benign"
    out["set"] = "v8"
    return out


def genre_of(r: dict) -> str:
    g = r.get("group", "")  # v7.<genre>.<doc> or v7.gen.<genre>
    parts = g.split(".")
    return f"gen_{parts[2]}" if len(parts) > 2 and parts[1] == "gen" else (parts[1] if len(parts) > 1 else "?")


def stage_rows(args) -> int:
    out = Path(os.environ.get("GUARD_V8_OUT") or sys.exit("set GUARD_V8_OUT"))
    out.mkdir(parents=True, exist_ok=True)
    cfg = load_cfg()
    v7dir, v7rows, clean, in_shas = v7_inputs(cfg)
    tok = Tok()
    ix, gstats, short, holdouts = guard(args, cfg)
    counts: collections.Counter = collections.Counter()
    payloads = load_payloads(cfg, tok, ix, short, held_texts(holdouts), eval_fingerprints(), counts)
    cursor = {lang: 0 for lang in payloads}

    def hit(t: str) -> bool:
        return bool(ix.check(t)[1] or short.check(t)[1])

    rows: list[dict] = []
    seed = cfg["seed"]
    for hr in v7rows:
        kind, lang = hr["kind"], hr["lang"]
        if kind not in HOST_KINDS:
            raise SystemExit(f"{hr['id']}: unknown v7 kind {kind}")
        b = benign_row(hr)
        rows.append(b)
        rng = random.Random(f"{seed}:host:{hr['id']}")
        doc = None
        if kind != "v7_gen":
            did, rng_s = hr["origin"].rsplit(":", 1)
            s, e = (int(x) for x in rng_s.split("-"))
            doc = (clean[did], s, e)
        position = weighted_choice(rng, cfg["placements"], exclude=("straddle_window",) if doc is None else ())
        made = None
        for attempt in range(8):
            pl = payloads[lang]
            p = pl[cursor[lang] % len(pl)]
            cursor[lang] += 1
            prng = random.Random(f"{seed}:embed:{hr['id']}:{attempt}")
            if position == "straddle_window":
                res = make_straddle(doc[0], doc[1], doc[2], p["text"], tok, prng)
            else:
                res = make_one_window(position, hr["text"], p["text"], lang, tok, prng, cfg)
            if res is None:
                counts[f"embed_failed:{position}"] += 1
                continue
            text, spans, _host = res
            if not spans_hold(text, spans, p["text"]):
                counts[f"span_mismatch:{position}"] += 1
                continue
            a = attack_row(b, kind, position, text, spans, p, tok)
            ws = tok.windows(a)
            if not any(w.why == "payload" for w in ws) or (position != "straddle_window" and len(ws) != 1):
                counts[f"window_mismatch:{position}"] += 1
                continue
            if hit(text):
                counts[f"guard_replaced:{position}"] += 1
                continue
            made = a
            break
        if made is None:
            counts[f"host_without_attack:{position}"] += 1
            continue
        rows.append(made)

    seen, uniq = set(), []
    for r in rows:
        if r["text"] in seen:
            counts[f"duplicate_text:{r['kind']}"] += 1
            continue
        seen.add(r["text"])
        uniq.append(r)
    rows = uniq
    keep = {r["id"] for r in half_of([r for r in rows if r["kind"] == "v8_benign"], cfg["arm_e"]["benign_fraction"], seed)}
    erows = [r for r in rows if r["kind"] == "v8_attack" or r["id"] in keep]
    stats = {"seed": seed, "inputs": {**in_shas, "payload_file_sha256": sha256_file(TRAIN / cfg["payloads"]["file"]),
                                      "sources_v8_sha256": sha256_file(HERE / "sources_v8.yaml"),
                                      "tokenizer": Path(tok.path).name, "tokenizer_sha256": sha256_file(Path(tok.path))},
             "guard_index": gstats, "index_shingles": ix.shingles, "build": dict(sorted(counts.items()))}
    for name, rs in (("v8_train", rows), ("v8e_train", erows)):
        p = out / f"{name}.jsonl"
        with open(p, "w", encoding="utf-8") as f:
            for r in rs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        stats[name] = describe(rs, tok) | {"sha256": sha256_file(p)}
    (out / "stats_v8.json").write_text(json.dumps(stats, indent=1, ensure_ascii=False, sort_keys=False) + "\n", "utf-8")
    log(json.dumps({k: stats[k] for k in ("v8_train", "v8e_train")}, indent=1, ensure_ascii=False))
    return 0


def describe(rows: list[dict], tok: Tok) -> dict:
    by_kind = collections.Counter(f"{r['kind']}:{r['lang']}" for r in rows)
    attacks = [r for r in rows if r["kind"] == "v8_attack"]
    benign = [r for r in rows if r["kind"] == "v8_benign"]
    win: collections.Counter = collections.Counter()
    for r in rows:
        for w in tok.windows(r):
            lab = "dropped" if w.labels is None else ("benign" if w.labels == ["benign"] else "attack")
            win[f"{r['kind']}:{lab}"] += 1
            win[f"all:{lab}"] += 1
    nb, na = len(benign), len(attacks)
    wb, wa = win["all:benign"], win["all:attack"]
    return {
        "rows": len(rows), "by_kind_lang": dict(sorted(by_kind.items())),
        "benign_attack_ratio_rows": f"{nb}:{na} = {nb / na:.4f}" if na else None,
        "windows": dict(sorted(win.items())),
        "benign_attack_ratio_windows": f"{wb}:{wa} = {wb / wa:.4f}" if wa else None,
        "placement": dict(sorted(collections.Counter(r["position"] for r in attacks).items())),
        "placement_by_lang": dict(sorted(collections.Counter(f"{r['position']}:{r['lang']}" for r in attacks).items())),
        "host_kind": dict(sorted(collections.Counter(f"{r['kind']}:{r['host_kind']}" for r in rows).items())),
        "host_genre": dict(sorted(collections.Counter(f"{r['kind']}:{genre_of(r)}:{r['lang']}" for r in rows).items())),
        "payloads_used": len({r["payload_id"] for r in attacks}),
        "payload_uses_max": max(collections.Counter(r["payload_id"] for r in attacks).values(), default=0),
        "payload_labels": dict(sorted(collections.Counter("+".join(r["payload_labels"]) for r in attacks).items())),
        "payload_variant": dict(sorted(collections.Counter(f"{r['variant']}:{r['lang']}" for r in attacks).items())),
        "attack_tokens_max": max((r["tokens"] for r in attacks), default=0),
    }


def stage_check(args) -> int:
    out = Path(os.environ.get("GUARD_V8_OUT") or sys.exit("set GUARD_V8_OUT"))
    cfg = load_cfg()
    ix, gstats, short, _ = guard(args, cfg)
    rep = {"k": 50, "index": gstats, "index_shingles": ix.shingles, "files": {}}
    ok = True
    for name in ("v8_train", "v8e_train"):
        p = out / f"{name}.jsonl"
        rows = [json.loads(ln) for ln in open(p, encoding="utf-8") if ln.strip()]
        counts: collections.Counter = collections.Counter()
        examples: dict = {}
        kept = ix.filter_rows(rows, counts, p.name, examples)
        contained = sum(1 for r in kept if short.check(r["text"])[1])
        rep["files"][name] = {"rows": len(rows), "rows_clean": len(kept), "short_holdout_12token_overlap": contained,
                              "counts": dict(counts), "examples": examples, "sha256": sha256_file(p)}
        ok = ok and len(kept) == len(rows) and contained == 0
    rep["result"] = "clean" if ok else "OVERLAP"
    (out / "guard_v8.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(json.dumps({k: v for k, v in rep.items() if k != "index"}, indent=1, ensure_ascii=False))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["rows", "check"])
    ap.add_argument("--embedded", action="append", default=[],
                    help="embedded-attack documents (glob of docs.jsonl): R5, long6 and long7")
    ap.add_argument("--holdout-rows", action="append", default=[], help="further hold-out row files (glob)")
    a = ap.parse_args()
    return {"rows": stage_rows, "check": stage_check}[a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
