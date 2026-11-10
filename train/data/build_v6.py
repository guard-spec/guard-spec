"""v6 training data (round 3, RF-895d3533): v5 + benign twins with prose fillers, security hard negatives, bench guard.

    cd train && GUARD_BUILD_OUT=<dir outside the repo> uv run --frozen python data/build_v6.py [--profile quick]

Reuses data/build_v5.py (sources, windows, hosts, embedding, leakage guard, balance; v5 itself is unchanged
and still reproducible) with data/sources_v6.yaml, data/gen_codelog_v5.py and data/gen_filler_v6.py, and
writes to $GUARD_BUILD_OUT (required, outside the repository):

    v6_train.jsonl          set A, training split
    v6_val.jsonl            set A, 12% of the groups (source file / generator unit / host), validation
    val_v6.jsonl            set B: other repositories, titles, works and templates (arm selection, calibration)
    val_v6_holdout.jsonl    set C: yet other ones; never used for selection or calibration
    stats.json              counts, twin pairing rate, both leakage reports, md5 of every output

What v6 adds to the v5 recipe (DATA_CARD.md "v6 data"):

  Benign twins. v5 learned "foreign prose inside a code or log host = attack" because its twins were the
  bare host. In v6 every embedded positive gets a twin with the same host, the same position and the same
  random choices (the generator's state is restored before the second embedding), the payload replaced by
  benign prose of similar length (0.6-1.5x the payload's tokens): a docstring, a comment block or a
  README / docs paragraph of the set's pinned repositories (EN), sentences of the set's Vietnamese
  public-domain prose (VI), or human-sounding log lines (gen_filler_v6, EN/VI). Twin rows: kind `twin`,
  labels ["benign"], `filler_kind`, `filler_origin`, `filler_spans` / `filler_byte_spans` (the filler's
  offsets; a benign row's spans are not read by train/windows.py), `pair` = the positive's id.

  Hard negatives about security. `secdoc_en`: documentation that explains prompt injection, jailbreaks
  and their defences (sources_v6.yaml; permissive licences only). `secprose_en` / `secprose_vi`:
  project-written explanatory paragraphs (gen_filler_v6). These kinds keep windows that mention prompt
  injection; a window dominated by instruction-like lines (`attack_dominated`) is skipped. `doc_en`
  (README / docs prose of the code repositories) and `human_log_en` / `human_log_vi` are ordinary hard
  negatives (the v5 ATTACK filter applies to them).

  bench/long guard. After the v5 leakage guard (fingerprints, 5-gram Jaccard, line copies, cross-set) every
  row is checked against the 50-token shingle index of the bench/long full profile (data/bench_guard.py):
  a row sharing one shingle with any bench document is dropped and counted (stats.json "bench_shingle").

Everything else is v5's: 254-token line-aligned windows, 12 embedding positions, payloads from
data/train.jsonl attacks only, benign share 78%, Vietnamese >= 40%, seeded and byte-identical between
runs. Downloads are cached in $GUARD_V6_CACHE (default train/.cache/v6, gitignored).
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

import yaml
from huggingface_hub import hf_hub_download

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_v5 as v5  # noqa: E402
import gen_codelog_v5 as gen  # noqa: E402
import gen_filler_v6 as fil  # noqa: E402
from bench_guard import ShingleIndex, load_bench  # noqa: E402
from common import fingerprint  # noqa: E402

DATA, TRAIN_ROOT, REPO = v5.DATA, v5.TRAIN_ROOT, v5.REPO
LICENSE_PROJECT = v5.LICENSE_PROJECT
MAX_TOK, POSITIONS, HOST_KINDS = v5.MAX_TOK, v5.POSITIONS, v5.HOST_KINDS
SEED = "v6:20261110:RF-895d3533"
v5.SEED = SEED  # build_v5.R() reads it: every random choice of this build is seeded by the v6 key
EPOCH_CAP = 64_000  # v5: 56,000; every positive now has a twin
log, R = v5.log, v5.R

# Hard-negative windows per (kind, set), full profile. v5's targets plus the v6 kinds.
EXTRA = {"A": {"doc_en": 600, "secdoc_en": 500, "secprose_en": 250, "secprose_vi": 450, "human_log_en": 300, "human_log_vi": 500},
         "B": {"doc_en": 70, "secdoc_en": 60, "secprose_en": 30, "secprose_vi": 50, "human_log_en": 35, "human_log_vi": 55}}
TARGETS = {s: dict(v5.TARGETS[s]) for s in ("A", "B", "C")}
TARGETS["A"].update(EXTRA["A"])
for s in ("B", "C"):
    TARGETS[s].update({k: round(v * 1.15) for k, v in EXTRA["B"].items()})
POSITIVES = dict(v5.POSITIVES)
PER_UNIT = dict(v5.PER_UNIT, doc_en=3, secdoc_en=40)  # a security source may be one large document (ATLAS.yaml)
SEC_KINDS = {"secdoc_en", "secprose_en", "secprose_vi"}
GENMOD = {**{k: gen for k in gen.GENERATORS}, **{k: fil for k in fil.GENERATORS}}

# Lines that are instructions to a model (not sentences about them): a security document window is
# skipped when two or more of its lines are such instructions, when one of them is longer than 40 words
# (a full prompt), or when more than a third of its lines are.
INSTR = re.compile(
    r"^[\W_]*(?:(?:please|now|from now on|ok|okay)[,:\s]+)?"
    r"(?:(?:ignore|disregard|forget|override|bỏ qua|phớt lờ|hãy bỏ qua|quên)\b.{0,40}\b(?:previous|prior|above|earlier|all|trước|mọi|tất cả)"
    r"|you are (?:now|dan|going to)\b|(?:act|pretend|respond|answer) as\b|(?:reveal|print|repeat|show|output) (?:your|the) (?:system prompt|hidden|secret|initial|instructions)"
    r"|(?:từ giờ|bây giờ|kể từ giờ) bạn (?:là|sẽ|hãy)|hãy (?:tiết lộ|in ra|lặp lại) (?:câu lệnh|chỉ dẫn|hướng dẫn) hệ thống)",
    re.I)


def attack_dominated(w: str) -> bool:
    lines = [ln for ln in w.split("\n") if ln.strip()]
    hits = [ln for ln in lines if INSTR.search(ln)]
    return len(hits) >= 2 or any(len(ln.split()) > 40 for ln in hits) or (len(hits) * 3 > len(lines))


def kind_lang(kind: str) -> str:
    return "vi" if kind.endswith("_vi") or kind in ("log_vi_repeat", "code_vi") else "en"


# ---------------------------------------------------------------------------
# Hard-negative windows (build_v5.make_windows with the v6 generators, kinds and skip rule)
# ---------------------------------------------------------------------------

def make_windows(tok, pools, tset, kind, n, counts, quota=None):
    out = []
    lang = kind_lang(kind)
    skip = attack_dominated if kind in SEC_KINDS else (lambda w: bool(v5.ATTACK.search(w)))
    if kind in GENMOD:
        g, i = GENMOD[kind], 0
        while len(out) < n and i < n * 4:
            text = g.unit(kind, tset, i)
            for w in v5.unit_windows(tok, text, R("gw", tset, kind, i), 1):
                if kind == "log_vi_repeat" and not v5.has_repeat(w):
                    continue
                if skip(w):
                    counts[f"skip_attack_like:{kind}"] += 1
                    continue
                out.append(v5.row_benign(w, kind, lang, tset, f"{g.__name__}:{kind}/{tset}/{i}", "guard-spec:v6-gen",
                                         LICENSE_PROJECT, f"v6.{tset}.gen.{kind}.{i}", tok))
            i += 1
        return out
    units, _ = v5.split_pool(pools.get((tset, kind), []), tset, kind)

    def take(us, n, got):
        for u in us:
            if len(got) >= n:
                break
            for w in v5.unit_windows(tok, u["text"], R("w", u["origin"]), PER_UNIT.get(kind, 2), from_top=kind == "diff"):
                if skip(w):
                    counts[f"skip_attack_like:{kind}"] += 1
                    continue
                got.append(v5.row_benign(w, kind, lang, tset, u["origin"], u["source"], u["license"], f"v6.{tset}.{u['origin']}", tok))
                if len(got) >= n:
                    break
        return got

    used = set()
    for name, q in sorted((quota or {}).items()):
        mine = [u for u in units if u["origin"].split(":", 1)[0] == name]
        got = take(mine, q, [])
        used |= {r["origin"] for r in got}
        counts[f"quota:{tset}/{kind}/{name}"] = len(got)
        if len(got) < q:
            counts[f"short:{tset}/{kind}/{name}"] = q - len(got)
        out += got
    n_rest = max(0, n - len(out))
    rest = take([u for u in units if u["origin"] not in used], n_rest, [])
    if len(rest) < n_rest:
        counts[f"short:{tset}/{kind}"] = n_rest - len(rest)
    return out + rest


# ---------------------------------------------------------------------------
# Benign fillers for the twins
# ---------------------------------------------------------------------------

DOCSTRING = re.compile(r'"""(.*?)"""|\'\'\'(.*?)\'\'\'', re.S)
COMMENT_LINE = {"code_go": r"//+", "code_rust": r"//[/!]?", "code_js": r"//+", "code_python": r"#", "shell": r"#", "config": r"#", "sql": r"--"}
SKIP_COMMENT = re.compile(r"copyright|licen[cs]e|spdx|all rights reserved|go:generate|\+build|nolint|noqa|#!|-\*-|todo\(|https?://", re.I)
MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
RST_ROLE = re.compile(r":[a-z:]+:`([^`]*)`")
SENT_EN = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")
SENT_VI = re.compile(r"(?<=[.!?;])\s+|\n+")


def wordy(s: str) -> bool:
    ws = s.split()
    return len(ws) >= 6 and sum(1 for w in ws if re.fullmatch(r"[A-Za-zÀ-ỹ][A-Za-zÀ-ỹ'’-]*[,.;:!?)]?", w)) >= 0.7 * len(ws)


def clean_prose(s: str) -> str:
    s = MD_LINK.sub(r"\1", s)
    s = RST_ROLE.sub(r"\1", s)
    s = re.sub(r"[`*_]{1,3}", "", s)
    return " ".join(s.split())


def paragraphs_of(text: str) -> list[str]:
    """Prose paragraphs of a Markdown / reStructuredText / plain-text document: no code fences, tables,
    headings, directives or list markup; each at least 6 words and 70% words."""
    out, fence = [], False
    for para in re.split(r"\n\s*\n", text):
        lines = para.split("\n")
        if any(ln.strip().startswith("```") for ln in lines):
            fence = not fence if sum(ln.strip().startswith("```") for ln in lines) % 2 else fence
            continue
        if fence:
            continue
        if any(ln.startswith(("    ", "\t", "|", "#", ".. ", ">", "=", "-", "*", "+", "<")) for ln in lines if ln.strip()):
            continue
        p = clean_prose(para)
        if wordy(p) and not v5.ATTACK.search(p):
            out.append(p)
    return out


def docstrings_of(text: str) -> list[str]:
    out = []
    for m in DOCSTRING.finditer(text):
        body = m.group(1) or m.group(2) or ""
        for para in re.split(r"\n\s*\n", body):
            if ">>>" in para or re.search(r"(?m)^\s*:\w+", para):
                continue
            p = clean_prose(para)
            if wordy(p) and not v5.ATTACK.search(p):
                out.append(p)
    return out


def comment_blocks_of(text: str, kind: str) -> list[str]:
    pat = re.compile(r"^\s*" + COMMENT_LINE[kind] + r"\s?(.*)$")
    out, buf = [], []

    def flush():
        if len(buf) >= 2:
            p = clean_prose(" ".join(buf))
            if wordy(p) and not v5.ATTACK.search(p):
                out.append(p)
        buf.clear()

    for ln in text.split("\n"):
        m = pat.match(ln)
        if m and m.group(1).strip() and not SKIP_COMMENT.search(m.group(1)):
            buf.append(m.group(1).strip())
        else:  # code, a blank comment line, or a licence / directive / URL line ends the block
            flush()
    flush()
    return out


class Fillers:
    """Benign prose banks of one set: snippets (lists of sentences with token counts) per language and kind."""

    MAX_UNITS = 900      # units scanned per kind (shuffled, seeded)
    MAX_SNIPPETS = 2500  # snippets kept per bank

    def __init__(self, tok, pools, tset, counts):
        self.tok, self.tset, self.counts = tok, tset, counts
        self.banks: dict[str, dict[str, list]] = {"en": {}, "vi": {}}
        t0 = time.time()
        en = {"docstring": [], "comment": [], "doc": []}
        for (s, kind), units in pools.items():
            if s != tset:
                continue
            us = sorted(units, key=lambda u: u["origin"])
            R("fillers", tset, kind).shuffle(us)
            for u in us[: self.MAX_UNITS]:
                if kind == "code_python":
                    self._add(en["docstring"], docstrings_of(u["text"]), u, SENT_EN)
                    self._add(en["comment"], comment_blocks_of(u["text"], kind), u, SENT_EN)
                elif kind in COMMENT_LINE:
                    self._add(en["comment"], comment_blocks_of(u["text"], kind), u, SENT_EN)
                elif kind == "doc_en":
                    self._add(en["doc"], paragraphs_of(u["text"]), u, SENT_EN)
                elif kind == "prose_vi":
                    self._add(self.banks["vi"].setdefault("prose_vi", []), [u["text"]], u, SENT_VI)
        for k, v in en.items():
            self.banks["en"][k] = v
        for lang in ("en", "vi"):
            bank = []
            for i in range(400):
                lines = fil.human_lines(lang, tset, i, 4)
                bank.append((f"gen_filler_v6:human_lines_{lang}/{tset}/{i}", "guard-spec:v6-gen", LICENSE_PROJECT,
                             [(ln, tok.n(ln)) for ln in lines], "\n"))
            self.banks[lang]["human_log"] = bank
        for lang in self.banks:
            for k, b in self.banks[lang].items():
                b.sort(key=lambda s: s[0])
                R("bank", tset, lang, k).shuffle(b)
                del b[self.MAX_SNIPPETS:]
                counts[f"fillers:{tset}/{lang}/{k}"] = len(b)
        log(f"  fillers {tset}: " + ", ".join(f"{lang}/{k} {len(b)}" for lang in self.banks for k, b in self.banks[lang].items())
            + f" ({time.time() - t0:.0f}s)")

    def _add(self, bank, paras, u, splitter):
        for j, p in enumerate(paras):
            sents = [s.strip() for s in splitter.split(p) if len(s.split()) >= 3]
            if sents:
                bank.append((f"{u['origin']}#{j}", u["source"], u["license"], [(s, self.tok.n(s)) for s in sents], " "))

    WEIGHTS = {"en": {"docstring": 3, "comment": 2, "doc": 3, "human_log": 2}, "vi": {"prose_vi": 3, "human_log": 2}}

    def get(self, lang, ntok, r, exclude_origin=None):
        """(text, kind, origin, source, license) of about ntok tokens (0.6-1.5x), or None."""
        kinds = [k for k in self.WEIGHTS[lang] if self.banks[lang].get(k)]
        if not kinds:
            return None
        weights = [self.WEIGHTS[lang][k] for k in kinds]
        best = None
        for _ in range(40):
            kind = r.choices(kinds, weights)[0]
            bank = self.banks[lang][kind]
            origin, source, lic, sents, sep = bank[r.randrange(len(bank))]
            if exclude_origin and origin.split("#")[0] == exclude_origin.split("#")[0]:
                continue
            j = r.randrange(len(sents))
            acc, tot = [], 0
            while j < len(sents) and tot < ntok * 0.8:
                if tot and tot + sents[j][1] > ntok * 1.35:
                    break
                acc.append(sents[j][0])
                tot += sents[j][1]
                j += 1
            if not acc:
                continue
            text = sep.join(acc)
            if 0.6 * ntok <= tot <= 1.5 * ntok:
                return text, kind, origin, source, lic
            if best is None or abs(tot - ntok) < abs(best[0] - ntok):
                best = (tot, text, kind, origin, source, lic)
        if best and 0.4 * ntok <= best[0] <= 2.0 * ntok:
            self.counts["filler_length_loose"] += 1
            return best[1:]
        return None


# ---------------------------------------------------------------------------
# Positives and their twins
# ---------------------------------------------------------------------------

def make_positives(tok, pools, tset, payloads, n_total, counts, fillers: Fillers):
    hosts = v5.Hosts(tok, pools, tset)
    rows = []
    for lang in ("en", "vi"):
        pl = [p for p in payloads if p["lang"] == lang and v5.payload_set(p) == tset]
        R("payloads", tset, lang).shuffle(pl)
        if not pl:
            continue
        n = n_total // 2
        made, i = 0, 0
        while made < n and i < n * 3:
            p = pl[i % len(pl)]
            position = POSITIONS[i % len(POSITIONS)]
            r = R("pos", tset, lang, i)
            rf = R("fill", tset, lang, i)
            i += 1
            ptoks = tok.n(p["text"])
            if ptoks > 170:
                counts["payload_too_long"] += 1
                continue
            filler = fillers.get(lang, ptoks, rf)
            if position == "log_message":
                state = r.getstate()
                res = v5.embed_log(lang, tset, i, p["text"], tok, r)
                if res is None:
                    counts[f"embed_failed:{position}"] += 1
                    continue
                host, text, spans, origin = res
                src, lic, hkind = "guard-spec:v6-gen", LICENSE_PROJECT, f"log_{lang}"
            else:
                hkind = r.choice(HOST_KINDS[lang][position])
                if position.startswith("straddle_window"):
                    ntok = r.randint(MAX_TOK + 60, MAX_TOK + 220)
                elif position == "straddle_chunk":
                    ntok = r.randint(700, 900) if lang == "en" else r.randint(800, 1000)
                else:
                    ntok = max(48, min(230, MAX_TOK - ptoks - r.randint(0, 60)))
                    if hkind == "diff":
                        ntok = max(ntok, 180)
                h = hosts.get(hkind, ntok, need_def=position == "docstring" and hkind == "code_python",
                              need_yaml=position == "yaml_value")
                if h is None:
                    counts[f"host_missing:{tset}/{hkind}"] += 1
                    continue
                host, origin, src, lic = h
                state = r.getstate()
                res = v5.embed(position, p["text"], lang, host, hkind, tok, r, tset)
                if res is None:
                    counts[f"embed_failed:{position}"] += 1
                    continue
                text, spans = res
            if text != unicodedata.normalize("NFC", text) or not v5.span_ok(position, p["text"], text, spans):
                counts[f"embed_span_mismatch:{position}"] += 1
                continue
            labels = sorted(set(p["labels"]) | {"indirect_injection"})
            group = f"v6.{tset}.host.{origin}"
            row = dict(text=text, labels=labels, lang=lang, variant=p["variant"], source="guard-spec:v6-embedded",
                       license=f"{LICENSE_PROJECT}; payload {p['license']}; host {lic}", group=group, kind="embedded",
                       set=tset, origin=origin, position=position, spans=[list(s) for s in spans],
                       payload_id=p["id"], payload_labels=p["labels"], host_kind=hkind, host_source=src,
                       tokens=tok.n(text))
            # The twin: the same host and position, the same random choices (state restored), the filler
            # in place of the payload.
            twin = None
            if filler is None or filler[2].split("#")[0] == origin:
                counts["twin_no_filler"] += 1
            else:
                ftext, fkind, forigin, fsrc, flic = filler
                r.setstate(state)
                if position == "log_message":
                    # The same generator lines (unit i) and insertion index; the excerpt may be trimmed
                    # by a different number of lines when the filler's line is longer than the payload's.
                    res2 = v5.embed_log(lang, tset, i, ftext, tok, r)
                    res2 = (res2[1], res2[2]) if res2 else None
                else:
                    res2 = v5.embed(position, ftext, lang, host, hkind, tok, r, tset)
                if res2 is None:
                    counts[f"twin_failed:{position}"] += 1
                else:
                    ttext, tspans = res2
                    if ttext != unicodedata.normalize("NFC", ttext) or not v5.span_ok(position, ftext, ttext, tspans):
                        counts[f"twin_span_mismatch:{position}"] += 1
                    else:
                        twin = v5.row_benign(ttext, "twin", lang, tset, origin, src, lic, group, tok)
                        twin.update(source="guard-spec:v6-twin", license=f"{LICENSE_PROJECT}; filler {flic}; host {lic}",
                                    position=position, host_kind=hkind, host_source=src, filler_kind=fkind, filler_origin=forigin,
                                    filler_source=fsrc, filler_spans=[list(s) for s in tspans], filler_tokens=tok.n(ftext),
                                    payload_tokens=ptoks)
                        twin["_pk"] = row["_pk"] = f"{tset}/{lang}/{i}"
                        counts[f"twins:{tset}/{lang}/{fkind}"] += 1
            if twin is not None:
                rows.append(twin)
            rows.append(row)
            made += 1
            counts[f"positives:{tset}/{lang}/{position}"] += 1
    return rows


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

FIELDS = ["id", "text", "labels", "lang", "variant", "source", "license", "group", "kind", "set", "tokens", "origin",
          "position", "spans", "byte_spans", "payload_id", "payload_labels", "host_kind", "host_source", "pair",
          "filler_kind", "filler_origin", "filler_source", "filler_spans", "filler_byte_spans", "filler_tokens", "payload_tokens"]


def write_jsonl(path: Path, rows) -> str:
    body = "".join(json.dumps({k: r[k] for k in FIELDS if k in r}, ensure_ascii=False) + "\n" for r in rows)
    path.write_text(body, encoding="utf-8")
    return hashlib.md5(body.encode("utf-8")).hexdigest()


def finalize(r):
    v5.finalize(r)
    if "filler_spans" in r:
        r["filler_byte_spans"] = [[len(r["text"][:a].encode("utf-8")), len(r["text"][:b].encode("utf-8"))] for a, b in r["filler_spans"]]


def summarize(rows):
    out = v5.summarize(rows)
    c = collections.Counter()
    for r in rows:
        if r["kind"] == "twin":
            c[f"twin_filler:{r.get('filler_kind')}:{r['lang']}"] += 1
            if r.get("pair"):
                c["twins_paired"] += 1
        if r["kind"] == "embedded" and r.get("pair"):
            c["positives_paired"] += 1
    out.update(sorted(c.items()))
    pos = out.get("kind:embedded:en", 0) + out.get("kind:embedded:vi", 0)
    out["twin_pairing_rate"] = round(c["positives_paired"] / pos, 4) if pos else 0.0
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--profile", choices=["full", "quick"], default="full")
    ap.add_argument("--payloads", default=os.environ.get("GUARD_V6_PAYLOADS") or str(DATA / "train.jsonl"),
                    help="training split whose attack rows are embedded (default data/train.jsonl)")
    ap.add_argument("--base-train", default=os.environ.get("GUARD_BASE_TRAIN") or str(DATA / "train.jsonl"),
                    help="the training file v6 is added to, for the epoch cap")
    ap.add_argument("--bench-docs", default=None, help="bench/long full-profile docs.jsonl (built when missing)")
    ap.add_argument("--stats-copy", default=None, help="also write stats.json here (e.g. data/stats_v6.json)")
    a = ap.parse_args(argv)
    t_start = time.time()
    out = os.environ.get("GUARD_BUILD_OUT")
    if not out:
        raise SystemExit("GUARD_BUILD_OUT (an output directory outside the repository) is required")
    out = Path(out).expanduser().resolve()
    if out == REPO or REPO in out.parents:
        raise SystemExit("GUARD_BUILD_OUT must be outside the repository: no third-party text is written into git")
    cache = v5.Cache(Path(os.environ.get("GUARD_V6_CACHE") or TRAIN_ROOT / ".cache" / "v6").expanduser().resolve())
    cfg = yaml.safe_load((DATA / "sources_v6.yaml").read_text("utf-8"))
    scale = 1.0 if a.profile == "full" else 0.25
    for name, src in cfg["sources"].items():
        bad = set(src.get("windows") or {}) - (set(src.get("select") or {}) & set(TARGETS[src["set"]]))
        if bad:
            raise SystemExit(f"{name}: `windows` kinds {sorted(bad)} are not selected kinds with a set {src['set']} target")
    counts = collections.Counter()
    pins: dict = {}

    tk = cfg["tokenizer"]
    tpath = Path(hf_hub_download(tk["repo"], tk["file"], revision=tk["revision"], cache_dir=str(cache.root / "hf")))
    if v5.file_sha256(tpath) != tk["sha256"]:
        raise SystemExit(f"tokenizer {tpath}: SHA-256 differs from sources_v6.yaml")
    tok = v5.Tok(tpath)

    bench_docs = Path(a.bench_docs) if a.bench_docs else \
        Path(os.environ.get("BENCH_CACHE") or REPO / "bench" / ".cache") / "long" / "full" / "docs.jsonl"
    if not bench_docs.exists():
        log(f"{bench_docs} missing: building the bench/long full profile")
        subprocess.run(["uv", "run", "--project", str(REPO / "bench"), "--frozen", "python", str(REPO / "bench" / "long" / "build.py"),
                        "--profile", "full"], check=True)
    bench_sha = v5.file_sha256(bench_docs)
    bench_cfg = yaml.safe_load((REPO / "bench" / "long" / "corpus.yaml").read_text("utf-8"))
    if bench_sha != bench_cfg["outputs"]["full"]:
        raise SystemExit(f"{bench_docs}: SHA-256 {bench_sha} is not the pinned full profile {bench_cfg['outputs']['full']}")

    t0 = time.time()
    pools = v5.load_sources(cfg, cache, pins)
    t_sources = time.time() - t0

    t0 = time.time()
    payloads = v5.load_payloads(Path(a.payloads), counts)
    counts["payload_candidates"] = len(payloads)
    log("building leakage references")
    guard = v5.Guard(tok, bench_docs, counts)
    payloads = v5.payload_guard(payloads, guard, counts)
    counts["payloads_kept"] = len(payloads)
    shingles = ShingleIndex(lambda s: tok.enc(s).ids)
    load_bench(shingles, bench_docs)
    shingles.check("")  # builds the sorted index now, so its size is known
    counts["bench_shingle:docs"] = shingles.docs
    counts["bench_shingle:shingles"] = shingles.shingles
    counts["bench_shingle:unique"] = shingles.unique
    log(f"  bench/long shingle index: {shingles.docs} documents, {shingles.unique} unique 50-token shingles")
    t_refs = time.time() - t0

    t0 = time.time()
    sets = {}
    for tset in ("A", "B", "C"):
        rows = []
        for kind, n in TARGETS[tset].items():
            quota = {name: max(1, round(src["windows"][kind] * scale)) for name, src in cfg["sources"].items()
                     if src["set"] == tset and kind in (src.get("windows") or {})}
            rows += make_windows(tok, pools, tset, kind, max(1, round(n * scale)), counts, quota)
        fillers = Fillers(tok, pools, tset, counts)
        rows += make_positives(tok, pools, tset, payloads, round(POSITIVES[tset] * scale), counts, fillers)
        counts[f"generated:{tset}"] = len(rows)
        sets[tset] = rows
        log(f"  set {tset}: {len(rows)} rows generated")
    t_gen = time.time() - t0

    t0 = time.time()
    shingle_examples: dict = {}
    for tset in sets:
        seen, uniq = set(), []
        for r in sets[tset]:
            fp = fingerprint(r["text"])
            if fp in seen:
                counts[f"dedupe_dropped:{tset}"] += 1
                continue
            seen.add(fp)
            uniq.append(r)
        sets[tset] = guard.filter(uniq, f"set_{tset}")
        log(f"  set {tset}: {len(sets[tset])} rows after the v5 leakage guard")
    v5.cross_set_guard(sets, guard, counts)
    for tset in sets:
        sets[tset] = shingles.filter_rows(sets[tset], counts, f"set_{tset}", shingle_examples)
        log(f"  set {tset}: {len(sets[tset])} rows after the bench/long shingle guard "
            f"({counts[f'bench_shingle:dropped:set_{tset}']} dropped)")
    t_guard = time.time() - t0

    for tset in sets:
        sets[tset] = v5.balance(sets[tset], tset, counts)
        for r in sets[tset]:
            finalize(r)
    for s in sets.values():
        by_key = collections.defaultdict(list)
        for r in s:
            if "_pk" in r:
                by_key[r.pop("_pk")].append(r)
        for rs in by_key.values():
            if len(rs) == 2:
                rs[0]["pair"], rs[1]["pair"] = rs[1]["id"], rs[0]["id"]
                counts["minimal_pairs"] += 1
            else:
                counts["pair_half_dropped_by_guard"] += 1

    split = {"v6_train": [], "v6_val": []}
    for r in sets["A"]:
        h = int(hashlib.sha256(f"split:{r['group']}".encode()).hexdigest(), 16) % 100
        split["v6_val" if h < v5.VAL_PCT else "v6_train"].append(r)
    split["val_v6"] = sets["B"]
    split["val_v6_holdout"] = sets["C"]

    base_rows = sum(1 for _ in open(a.base_train, encoding="utf-8")) if Path(a.base_train).exists() else 0
    epoch = base_rows + sum(v5.est_windows(r) for r in split["v6_train"])
    counts["epoch_estimate_rows"] = epoch
    counts["epoch_base_rows"] = base_rows
    if epoch > EPOCH_CAP:
        hn = [r for r in split["v6_train"] if r["labels"] == ["benign"] and r["kind"] != "twin"]
        excess = epoch - EPOCH_CAP
        hn.sort(key=lambda r: r["id"])
        R("epoch_cap").shuffle(hn)
        drop = {id(r) for r in hn[:excess]}
        split["v6_train"] = [r for r in split["v6_train"] if id(r) not in drop]
        counts["epoch_cap_dropped"] = len(drop)

    for name in split:
        split[name].sort(key=lambda r: (r["lang"], r["kind"], r["group"], r["id"]))
    out.mkdir(parents=True, exist_ok=True)
    md5 = {name: write_jsonl(out / f"{name}.jsonl", rs) for name, rs in split.items()}

    gm = {**gen.sample_md5(), **{f"v6:{k}": v for k, v in fil.sample_md5().items()}}
    stats = {
        "profile": a.profile,
        "md5": md5,
        "generators_md5": hashlib.md5(json.dumps(gm, sort_keys=True).encode()).hexdigest(),
        "splits": {name: summarize(rs) for name, rs in split.items()},
        "leakage": {"max_jaccard_kept": dict(sorted(guard.max.items())), "max_line_copy_kept": dict(sorted(guard.max_copy.items())),
                    "rule": "drop on fingerprint, 5-gram Jaccard > 0.8, or >= 50% of long lines copied (>= 3 lines)",
                    "dropped_examples": {k: v[:12] for k, v in sorted(guard.examples.items())}},
        "bench_shingle": {"rule": "drop a row sharing any 50-token shingle (classifier tokenizer) with a bench/long full-profile document",
                          "bench_sha256": bench_sha, "docs": shingles.docs, "shingles": shingles.shingles, "unique": shingles.unique,
                          "dropped": {k: v for k, v in sorted(counts.items()) if k.startswith("bench_shingle:dropped:")},
                          "dropped_examples": {k: v[:12] for k, v in sorted(shingle_examples.items())}},
        "sources": {name: {"set": src["set"], "license": src["license"], "pinned": src.get("tag") or src.get("to", "")[:12] or "urls",
                           "kinds": sorted(src.get("select") or {}) or [src["kind"]]} for name, src in cfg["sources"].items()},
        "counts": dict(sorted(counts.items())),
        "pins": dict(sorted(pins.items())),
        "bench_long_full_sha256": bench_sha,
        "payload_file_md5": hashlib.md5(Path(a.payloads).read_bytes()).hexdigest(),
        "seconds": {"sources": round(t_sources), "references": round(t_refs), "generate": round(t_gen), "guard": round(t_guard),
                    "total": round(time.time() - t_start)},
    }
    stats["seconds"]["total"] = round(time.time() - t_start)
    body = json.dumps(stats, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    (out / "stats.json").write_text(body, encoding="utf-8")
    if a.stats_copy:
        Path(a.stats_copy).write_text(body, encoding="utf-8")
    for name, rs in split.items():
        s = stats["splits"][name]
        log(f"{name}: {len(rs)} rows (benign {s.get('benign', 0)}, attack {s.get('attack', 0)}, vi {s.get('vi_share')}, "
            f"twin pairing {s.get('twin_pairing_rate')}), md5 {md5[name]}")
    unpinned = [n for n, s in cfg["sources"].items() if not s.get("content_sha256")]
    for n in unpinned:
        log(f"  not pinned in sources_v6.yaml: {n}: {json.dumps(pins.get(n))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
