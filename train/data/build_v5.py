"""v5 training data: code/config/log/long-prose hard negatives and embedded-attack positives (RF-437128e9).

    cd train && GUARD_BUILD_OUT=<dir outside the repo> uv run --frozen python data/build_v5.py [--profile quick]

Reads data/sources_v5.yaml (public sources pinned by tag/commit and SHA-256) and data/gen_codelog_v5.py
(seeded generators), and writes to $GUARD_BUILD_OUT (required, outside the repository):

    v5_train.jsonl          set A, training split
    v5_val.jsonl            set A, 12% of the groups (source file / generator unit / host), validation
    val_v5.jsonl            set B: other repositories, titles, works and templates (arm selection, calibration)
    val_v5_holdout.jsonl    set C: yet other ones; never used for selection or calibration
    stats.json              counts, leakage report (max 5-gram Jaccard per reference), md5 of every output

Rows (one JSON object per line) follow the DATA_CARD schema (id, text, labels, lang, variant, source,
license, group) plus:

    kind        hard-negative genre (code_go, config, log_vi, prose_en, ...) or `embedded` / `twin`
    set         A, B or C
    tokens      content tokens of `text` (base-model tokenizer, no special tokens)
    origin      repository path, commit, title or generator unit the text comes from
    position    (embedded) where the payload sits: start, end, random, comment, docstring, yaml_value,
                json_field, log_message, diff_plus, straddle_window, straddle_chunk, split_adjacent
    spans       (embedded) [[start, end], ...] character offsets of the payload in `text`
    byte_spans  (embedded) the same in UTF-8 bytes
    payload_id, payload_labels, host_id, pair (embedded/twin): the training row the payload comes from,
                its labels, the host it was put in, and the id of the minimal-pair twin

Benign windows have labels ["benign"]. An embedded row has the payload's labels plus
indirect_injection; the host text around the payload is benign, and cutting the row into model windows
(which windows get the payload labels) is left to the training step (T3), which reads `spans`.

Hard negatives are windows of at most 254 content tokens (the classifier's 256 minus two special
tokens) cut at line boundaries. Positives embed attack rows of data/train.jsonl only (never a
validation, hold-out, probe or eval row) into hosts from the same set's sources.

Leakage guard (stats.json "leakage"): a row is dropped when its normalized fingerprint is in
eval/fingerprints.txt or eval/codelog/fingerprints.txt or equals a reference text or window, when its
character 5-gram Jaccard with any reference is above 0.8, or when at least half of its long lines
(>= 24 normalized characters, at least 3 of them) occur verbatim in a reference (a copy detector for
slices that a fixed reference window cuts differently). References: eval/data, every eval/codelog row
and window, every window of the bench/long full profile, every file of this repository at every tag
and at HEAD, and every hold-out and probe split (train/data and, when set, GUARD_OWNER_HOLDOUT and
GUARD_OTPKYC_PROBE). Small references are compared exactly; large ones through MinHash LSH (64
permutations, 16 bands of 4) with an exact Jaccard check of every candidate pair. Sets B and C are also
checked against A (and C against B) the same way.

Downloads are cached in $GUARD_V5_CACHE (default train/.cache/v5, gitignored). Every random choice is
seeded; two runs give byte-identical outputs (md5 in stats.json).
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import math
import os
import random
import re
import subprocess
import sys
import tarfile
import time
import unicodedata
import urllib.parse
import urllib.request
from pathlib import Path

import numpy as np
import yaml
from huggingface_hub import hf_hub_download
from tokenizers import Tokenizer

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_codelog_v5 as gen  # noqa: E402
from common import fingerprint, normalize_for_fingerprint  # noqa: E402

DATA = Path(__file__).resolve().parent
TRAIN_ROOT = DATA.parent
REPO = TRAIN_ROOT.parent
EVAL = REPO / "eval"
UA = "GuardSpecTrain/0.5 (https://guardspec.io; classifier training data builder)"
LICENSE_PROJECT = "Apache-2.0"

MAX_TOK = 254            # 256-token model window minus [CLS]/[SEP]
L2_STEP = 190            # gateway window step (bench/long/build.py)
CHUNK_BYTES = 2048       # fused path chunk size
JACCARD_MAX = 0.8
LINE_COPY_MAX = 0.5
VAL_PCT = 12
BENIGN_SHARE = 0.78
VI_MIN_SHARE = 0.40
EPOCH_CAP = 56_000
SEED = "v5:20261109:RF-437128e9"

# Text that discusses or performs prompt injection is not a hard negative; such windows are skipped.
ATTACK = re.compile(
    r"ignore (all |the |any )?(previous|prior|above) (instructions?|prompts?|rules)|prompt[ _-]?inject|jailbreak|"
    r"system prompt|developer mode|exfiltrat|tool[_ ]poison|\bDAN\b|"
    r"(bỏ qua|phớt lờ|quên|bo qua) (mọi|tất cả|toàn bộ|các|moi|tat ca) (hướng dẫn|chỉ dẫn|chỉ thị|quy tắc|huong dan|chi thi)",
    re.I)

# Hard-negative windows per (kind, set) for the full profile; quick scales by 0.25. Hosts for positives
# come from other units of the same pool.
TARGETS = {
    "A": {"code_go": 800, "code_python": 800, "code_rust": 650, "code_js": 650, "config": 900, "sql": 350, "sql_gen": 120,
          "shell": 350, "terminal": 250, "diff": 650, "stacktrace_en": 450, "log_en": 550, "json_en": 200, "csv_en": 150,
          "prose_en": 800,
          "log_vi": 1600, "log_vi_repeat": 500, "json_vi": 450, "csv_vi": 350, "prose_vi": 1700, "code_vi": 400,
          "stacktrace_vi": 220},
    "B": {"code_go": 90, "code_python": 90, "code_rust": 70, "code_js": 70, "config": 100, "sql_gen": 50, "shell": 30,
          "terminal": 30, "diff": 70, "stacktrace_en": 50, "log_en": 60, "json_en": 25, "csv_en": 20, "prose_en": 90,
          "log_vi": 170, "log_vi_repeat": 55, "json_vi": 50, "csv_vi": 40, "prose_vi": 190, "code_vi": 45, "stacktrace_vi": 25},
}
TARGETS["B"] = {k: round(v * 1.15) for k, v in TARGETS["B"].items()}
TARGETS["C"] = dict(TARGETS["B"])
POSITIVES = {"A": 4000, "B": 500, "C": 500}
PER_UNIT = {"code_go": 2, "code_python": 2, "code_rust": 2, "code_js": 3, "config": 3, "sql": 3, "shell": 3, "diff": 1,
            "prose_en": 4, "prose_vi": 4}
HOST_SHARE = 0.18  # share of each source pool's units reserved for positive hosts

POSITIONS = ["start", "end", "random", "comment", "docstring", "yaml_value", "json_field", "log_message", "diff_plus",
             "straddle_window", "straddle_chunk", "split_adjacent"]

# Bridge sentences for split payloads, per set (bench/long uses its own, which are not used here).
BRIDGE = {
    "en": {"A": ["Section totals are listed in the appendix.", "The next batch starts at 06:00.", "Stock counts were checked twice."],
           "B": ["Balances are shown in thousands."], "C": ["Times are local to the depot."]},
    "vi": {"A": ["Tổng từng mục có trong phụ lục.", "Đợt tiếp theo bắt đầu lúc 6 giờ.", "Số lượng tồn kho đã được kiểm hai lần."],
           "B": ["Số dư tính theo đơn vị nghìn đồng."], "C": ["Giờ ghi theo giờ địa phương của kho."]},
}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def R(*parts) -> random.Random:
    h = hashlib.sha256("\x1f".join(str(p) for p in (SEED,) + parts).encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def bench_module():
    spec = importlib.util.spec_from_file_location("bench_long_build", REPO / "bench" / "long" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BL = bench_module()  # html_to_text, wikitext_to_text, paragraphs, tidy (the extractors bench/long uses)


# ---------------------------------------------------------------------------
# Downloads and extraction
# ---------------------------------------------------------------------------

class Cache:
    def __init__(self, root: Path):
        self.root = root

    def fetch(self, url: str) -> Path:
        p = self.root / "dl" / hashlib.sha256(url.encode()).hexdigest()
        if p.exists():
            return p
        log(f"  GET {url}")
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=600) as r, open(tmp, "wb") as f:
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                f.write(b)
        tmp.replace(p)
        return p


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def content_digest(files: list[tuple[str, str]]) -> str:
    return sha256_text("".join(f"{p}\0{sha256_text(t)}\n" for p, t in sorted(files)))


def classify(path: str, select: dict) -> str | None:
    for kind, pat in select.items():
        if re.search(pat, path):
            return kind
    return None


def extract_archive(name, src, cache: Cache, pins: dict) -> list[dict]:
    path = cache.fetch(src["url"])
    got = file_sha256(path)
    pins[name] = {"archive_sha256": got}
    if src.get("archive_sha256") and src["archive_sha256"] != got:
        log(f"  {name}: archive SHA-256 {got} differs from the pin {src['archive_sha256']} (content is checked next)")
    root = src.get("root", "")
    excl = re.compile(src.get("exclude") or "^$")
    files, lic = [], None
    with tarfile.open(path, "r:*") as tf:
        for m in tf:
            if not m.isfile():
                continue
            p = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if root:
                if not p.startswith(root):
                    continue
                p = p[len(root):]
            kind = None if excl.search(p) or m.size > 400_000 or m.size == 0 else classify(p, src["select"])
            if p != src["license_file"] and kind is None:
                continue
            raw = tf.extractfile(m).read()
            if p == src["license_file"]:
                lic = raw.decode("utf-8", "replace")
                if kind is None:
                    continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            text = text.replace("\r\n", "\n")
            if "\x00" in text or not text.strip():
                continue
            files.append((p, kind, text))
    if lic is None or src["license_match"] not in lic:
        raise SystemExit(f"{name}: licence file {src['license_file']} missing or without '{src['license_match']}'; refusing the source")
    digest = content_digest([(p, t) for p, _, t in files])
    pins[name]["content_sha256"] = digest
    if src.get("content_sha256") and src["content_sha256"] != digest:
        raise SystemExit(f"{name}: extracted content SHA-256 {digest}, sources_v5.yaml pins {src['content_sha256']}")
    return [dict(path=p, kind=k, text=t) for p, k, t in sorted(files)]


def git(*args, cwd=None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, encoding="utf-8",
                          errors="replace").stdout


def extract_gitlog(name, src, cache: Cache, pins: dict) -> list[dict]:
    d = cache.root / "git" / f"{name}.git"
    if not d.exists():
        log(f"  clone {src['url']}")
        d.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--bare", "--quiet", src["url"], str(d)], check=True)
    for c in (src["from"], src["to"]):
        subprocess.run(["git", "--git-dir", str(d), "cat-file", "-e", c + "^{commit}"], check=True)
    lic = git("--git-dir", str(d), "show", f"{src['to']}:{src['license_file']}")
    if src["license_match"] not in lic:
        raise SystemExit(f"{name}: licence file without '{src['license_match']}'")
    # No author names or e-mail addresses: the commit id and subject only.
    text = git("--git-dir", str(d), "log", "-p", "--no-merges", "--no-color", "--no-ext-diff", "--format=commit %H%n%n    %s%n",
               f"{src['from']}..{src['to']}")
    digest = sha256_text(text)
    pins[name] = {"content_sha256": digest}
    if src.get("content_sha256") and src["content_sha256"] != digest:
        raise SystemExit(f"{name}: git log SHA-256 {digest}, sources_v5.yaml pins {src['content_sha256']}")
    excl = re.compile(src.get("exclude") or "^$")
    units = []
    for commit in re.split(r"(?m)^(?=commit [0-9a-f]{40}$)", text):
        if not commit.startswith("commit "):
            continue
        head, _, body = commit.partition("\ndiff --git ")
        if not body:
            continue
        for k, sec in enumerate(("diff --git " + body).split("\ndiff --git ")):
            sec = sec if sec.startswith("diff --git ") else "diff --git " + sec
            fpath = sec.split("\n", 1)[0].split(" b/")[-1]
            if excl.search(fpath) or "Binary files" in sec[:400] or len(sec) > 60_000:
                continue
            units.append(dict(path=f"{head.split()[1][:12]}:{fpath}", kind="diff", text=head.rstrip() + "\n\n" + sec.rstrip() + "\n"))
    return units


def extract_html(name, src, cache: Cache, pins: dict) -> list[dict]:
    units = []
    for url in src["urls"]:
        raw = cache.fetch(url).read_bytes().decode("utf-8", errors="replace")
        title = re.search(r"title(\d+)", url).group(1)
        units += [dict(path=f"title{title}#{i}", kind="prose_en", text=u)
                  for i, u in enumerate(BL.paragraphs(BL.html_to_text(raw), 1500))]
    digest = sha256_text("\n\x1e\n".join(u["text"] for u in units))
    pins[name] = {"content_sha256": digest}
    if src.get("content_sha256") and src["content_sha256"] != digest:
        raise SystemExit(f"{name}: extracted text SHA-256 {digest}, sources_v5.yaml pins {src['content_sha256']}")
    return units


def extract_mediawiki(name, src, cache: Cache, pins: dict) -> list[dict]:
    units = []
    for revid in src["revisions"]:
        q = urllib.parse.urlencode({"action": "query", "format": "json", "prop": "revisions", "rvprop": "ids|content",
                                    "rvslots": "main", "revids": revid})
        d = json.loads(cache.fetch(f"{src['api']}?{q}").read_bytes())
        page = next(iter(d["query"]["pages"].values()))
        wt = page["revisions"][0]["slots"]["main"]["*"]
        if not any(re.search(r"\{\{\s*" + re.escape(t) + r"\s*[|}]", wt) for t in src["require_template"]):
            raise SystemExit(f"{name}: revision {revid} ({page['title']}) carries none of {src['require_template']}; refusing it")
        units += [dict(path=f"rev{revid}#{i}", kind="prose_vi", text=u)
                  for i, u in enumerate(BL.paragraphs(page["title"] + "\n\n" + BL.wikitext_to_text(wt), 1500))]
    digest = sha256_text("\n\x1e\n".join(u["text"] for u in units))
    pins[name] = {"content_sha256": digest}
    if src.get("content_sha256") and src["content_sha256"] != digest:
        raise SystemExit(f"{name}: extracted text SHA-256 {digest}, sources_v5.yaml pins {src['content_sha256']}")
    return units


EXTRACT = {"archive": extract_archive, "git-log": extract_gitlog, "http-html": extract_html, "mediawiki": extract_mediawiki}


def load_sources(cfg, cache: Cache, pins: dict) -> dict:
    """{(set, kind): [unit, ...]} with unit = {path, kind, text, source, license, attribution}."""
    pools = collections.defaultdict(list)
    for name, src in cfg["sources"].items():
        t0 = time.time()
        uc = cache.root / "units" / f"{name}.json"
        if uc.exists():
            saved = json.loads(uc.read_text("utf-8"))
            units, pins[name] = saved["units"], saved["pins"]
            ck = pins[name].get("content_sha256")
            if src.get("content_sha256") and src["content_sha256"] != ck:
                raise SystemExit(f"{name}: cached content SHA-256 {ck} differs from the pin; delete {uc}")
        else:
            log(f"source {name} ({src['kind']})")
            units = EXTRACT[src["kind"]](name, src, cache, pins)
            uc.parent.mkdir(parents=True, exist_ok=True)
            uc.write_text(json.dumps({"units": units, "pins": pins[name]}, ensure_ascii=False), "utf-8")
        for u in units:
            u.update(source=f"{name}@{src.get('tag') or src.get('to', '')[:12] or 'pinned'}", license=src["license"],
                     origin=f"{name}:{u['path']}")
            pools[(src["set"], u["kind"])].append(u)
        log(f"  {name}: {len(units)} units ({time.time() - t0:.1f}s)")
    return pools


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

class Tok:
    def __init__(self, path: Path):
        self.t = Tokenizer.from_file(str(path))
        self.t.no_truncation()
        self.t.no_padding()

    def n(self, s: str) -> int:
        return len(self.t.encode(s, add_special_tokens=False).ids)

    def enc(self, s: str):
        return self.t.encode(s, add_special_tokens=False)

    def cut(self, s: str, k: int) -> str:
        """The longest prefix of s with at most k tokens, cut after whitespace when possible."""
        e = self.enc(s)
        if len(e.ids) <= k:
            return s
        end = e.offsets[k - 1][1]  # one read of the offsets list
        j = s.rfind(" ", 0, end)
        return s[: j if j > end * 0.6 else end]


def target_len(r: random.Random) -> int:
    return MAX_TOK if r.random() < 0.7 else r.randint(48, MAX_TOK - 1)


def unit_windows(tok: Tok, text: str, r: random.Random, limit: int, from_top=False) -> list[str]:
    """Consecutive line-aligned windows of a unit (each <= MAX_TOK tokens), starting at a random line."""
    lines = text.split("\n")
    start = r.randrange(len(lines) - 20) if len(lines) > 40 and not from_top else 0
    lines = lines[start:]
    out, i = [], 0
    while i < len(lines) and len(out) < limit:
        tgt = target_len(r)
        buf, used = [], 0
        while i < len(lines):
            ln = lines[i]
            n = tok.n(ln) + 1
            if used + n > tgt and buf:
                break
            if n > tgt:  # one long line (prose paragraph, minified code): cut it at a token boundary
                head = tok.cut(ln, tgt - used)
                buf.append(head)
                rest = ln[len(head):].lstrip()
                lines[i] = rest
                if not rest:
                    i += 1
                used = tgt
                break
            buf.append(ln)
            used += n
            i += 1
        w = "\n".join(buf).strip("\n")
        while w and tok.n(w) > MAX_TOK:
            w = "\n".join(w.split("\n")[:-1]) if "\n" in w else tok.cut(w, MAX_TOK)
        if w.strip() and tok.n(w) >= 24:
            out.append(w)
    return out


def split_pool(units: list[dict], tset: str, kind: str):
    us = sorted(units, key=lambda u: u["origin"])
    R("pool", tset, kind).shuffle(us)
    k = max(1, int(len(us) * HOST_SHARE)) if len(us) > 4 else 0
    return us[k:], us[:k]  # windows, hosts


def make_windows(tok, pools, tset, kind, n, counts, quota=None):
    """n windows of the kind from the set's pool; `quota` ({source: windows}, sources_v5.yaml `windows`) of them
    come first from those sources' own units, so a small source is not drowned by a large pool, and the rest
    from the whole pool (the kind's total, and so the EN/VI balance, stays the same)."""
    out = []
    lang = "vi" if kind.endswith("_vi") or kind == "log_vi_repeat" or kind == "code_vi" else "en"
    if kind in gen.GENERATORS:
        i = 0
        while len(out) < n and i < n * 4:
            text = gen.unit(kind, tset, i)
            for w in unit_windows(tok, text, R("gw", tset, kind, i), 1):
                if kind == "log_vi_repeat" and not has_repeat(w):
                    continue
                out.append(row_benign(w, kind, lang, tset, f"gen_codelog_v5:{kind}/{tset}/{i}", "guard-spec:v5-gen",
                                      LICENSE_PROJECT, f"v5.{tset}.gen.{kind}.{i}", tok))
            i += 1
        return out
    units, _ = split_pool(pools.get((tset, kind), []), tset, kind)

    def take(us, n, got):
        for u in us:
            if len(got) >= n:
                break
            for w in unit_windows(tok, u["text"], R("w", u["origin"]), PER_UNIT.get(kind, 2), from_top=kind == "diff"):
                if ATTACK.search(w):
                    counts[f"skip_attack_like:{kind}"] += 1
                    continue
                got.append(row_benign(w, kind, lang, tset, u["origin"], u["source"], u["license"], f"v5.{tset}.{u['origin']}", tok))
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


def has_repeat(w: str) -> bool:
    ls = w.split("\n")
    return any(ls[i] == ls[i + 1] for i in range(len(ls) - 1))


def row_benign(text, kind, lang, tset, origin, source, license_, group, tok):
    return dict(text=text, labels=["benign"], lang=lang, variant="orig", source=source, license=license_, group=group,
                kind=kind, set=tset, origin=origin, tokens=tok.n(text))


# ---------------------------------------------------------------------------
# Positives: train-split attack rows embedded in hosts
# ---------------------------------------------------------------------------

def load_payloads(path: Path, counts) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            r = json.loads(ln)
            if r["labels"] == ["benign"] or r["lang"] not in ("en", "vi"):
                continue
            if not 30 <= len(r["text"]) <= 600:
                counts["payload_len_skipped"] += 1
                continue
            rows.append(r)
    rows.sort(key=lambda r: r["id"])
    return rows


def payload_set(r) -> str:
    h = int(hashlib.sha256(f"v5payload:{r['group']}".encode()).hexdigest(), 16) % 100
    return "A" if h < 80 else ("B" if h < 90 else "C")


def wrap(text: str, width: int = 78) -> list[str]:
    out = []
    for para in text.split("\n"):
        cur = ""
        for w in para.split(" "):
            if cur and len(cur) + 1 + len(w) > width:
                out.append(cur)
                cur = w
            else:
                cur = f"{cur} {w}" if cur else w
        out.append(cur)
    return out


def snap(s: str, i: int) -> int:
    i = max(0, min(i, len(s)))
    while i > 0 and not s[i - 1].isspace():
        i -= 1
    return i


def insert_at(host: str, i: int, piece: str, sep=" "):
    """Insert piece at character i (moved back to a word start); returns (text, (start, end)) of piece."""
    i = snap(host, i)
    before = host[:i] + ("" if i == 0 or host[i - 1].isspace() else sep)
    after = ("" if i == len(host) or host[i].isspace() else sep) + host[i:]
    return before + piece + after, (len(before), len(before) + len(piece))


def line_offsets(text):
    offs, o = [], 0
    for ln in text.split("\n"):
        offs.append(o)
        o += len(ln) + 1
    return offs


def insert_lines(host: str, line_idx: int, block: str):
    lines = host.split("\n")
    line_idx = max(0, min(line_idx, len(lines)))
    start = sum(len(ln) + 1 for ln in lines[:line_idx])
    text = "\n".join(lines[:line_idx] + block.split("\n") + lines[line_idx:])
    return text, start


COMMENT_PREFIX = {"code_python": "# ", "shell": "# ", "config": "# ", "code_go": "// ", "code_js": "// ", "code_rust": "// ",
                  "code_vi": "# ", "sql": "-- ", "sql_gen": "-- "}


def embed(position, payload, lang, host, hkind, tok, r, tset):
    """Returns (text, spans) with spans as character offsets, or None when the host does not fit."""
    if position == "start":
        sep = r.choice(["\n\n", "\n", " "])
        return payload + sep + host, [(0, len(payload))]
    if position == "end":
        sep = r.choice(["\n\n", "\n", " "])
        return host + sep + payload, [(len(host) + len(sep), len(host) + len(sep) + len(payload))]
    if position == "random":
        text, sp = insert_at(host, r.randrange(1, max(2, len(host))), payload)
        return text, [sp]
    if position == "comment":
        pre = COMMENT_PREFIX.get(hkind, "# ")
        lines = host.split("\n")
        k = r.randrange(1, max(2, len(lines)))
        indent = re.match(r"[ \t]*", lines[k] if k < len(lines) else "").group(0)
        block = "\n".join(indent + pre + ln for ln in wrap(payload))
        text, start = insert_lines(host, k, block)
        first = start + len(indent) + len(pre)
        return text, [(first, start + len(block))]
    if position == "docstring":
        lines = host.split("\n")
        defs = [i for i, ln in enumerate(lines) if re.match(r"\s*(async\s+)?def \w+\(.*\)\s*(->.*)?:\s*$", ln)]
        if defs:
            k = r.choice(defs)
            indent = re.match(r"[ \t]*", lines[k]).group(0) + "    "
            body = payload.replace('"""', "'''")
            block = f'{indent}"""{body}\n{indent}"""' if "\n" in body or len(body) > 70 else f'{indent}"""{body}"""'
            text, start = insert_lines(host, k + 1, block)
            s = start + len(indent) + 3
            return text, [(s, s + len(body))]
        body = payload.replace('"""', "'''")
        block = f'def _{r.choice(["helper", "check", "load", "sync"])}():\n    """{body}"""\n    return None\n'
        text, start = insert_lines(host, r.randrange(0, host.count("\n") + 1), block)
        s = start + block.index('"""') + 3
        return text, [(s, s + len(body))]
    if position == "yaml_value":
        lines = host.split("\n")
        keys = [i for i, ln in enumerate(lines) if re.match(r"\s*[\w.-]+:\s*\S", ln) and not ln.lstrip().startswith("#")]
        k = r.choice(keys) if keys else 0
        indent = re.match(r"[ \t-]*", lines[k] if lines else "").group(0).replace("-", " ")
        key = r.choice(["description", "summary", "note", "message", "help", "comment"])
        if "\n" in payload or len(payload) > 90:
            body = "\n".join(indent + "  " + ln for ln in wrap(payload, 70))
            block = f"{indent}{key}: |\n{body}"
            text, start = insert_lines(host, k + 1, block)
            s = start + len(f"{indent}{key}: |\n") + len(indent) + 2
            return text, [(s, start + len(block))]
        val = json.dumps(payload, ensure_ascii=False)
        block = f"{indent}{key}: {val}"
        text, start = insert_lines(host, k + 1, block)
        s = start + len(indent) + len(key) + 3
        return text, [(s, s + len(val) - 2)]
    if position == "json_field":
        val = json.dumps(payload, ensure_ascii=False)
        key = r.choice(["note", "comment", "description", "remark", "message", "ghi_chu" if lang == "vi" else "details"])
        lines = host.split("\n")
        cand = [i for i, ln in enumerate(lines) if re.match(r'\s*"[\w.@-]+":\s*[^\[{]', ln)]
        if cand:
            k = r.choice(cand)
            indent = re.match(r"\s*", lines[k]).group(0)
            block = f'{indent}"{key}": {val},'
            text, start = insert_lines(host, k, block)
            s = start + len(indent) + len(key) + 5
            return text, [(s, s + len(val) - 2)]
        j = host.find("{", r.randrange(0, max(1, len(host) // 2)))
        if j < 0:
            return None
        piece = f'"{key}": {val}, '
        text = host[: j + 1] + piece + host[j + 1:]
        s = j + 1 + len(key) + 5
        return text, [(s, s + len(val) - 2)]
    if position == "diff_plus":
        lines = host.split("\n")
        hunk = [i for i, ln in enumerate(lines) if ln[:1] in (" ", "+", "-") and not ln.startswith(("+++", "---")) and i > 0
                and any(lines[j].startswith("@@") for j in range(max(0, i - 40), i))]
        if not hunk:
            hunk = [i for i, ln in enumerate(lines) if ln.startswith("@@")]
        if not hunk:
            return None
        k = r.choice(hunk) + 1
        f = next((ln for ln in lines if ln.startswith("diff --git")), "")
        pre = "# " if re.search(r"\.(py|sh|ya?ml|toml|rb)$", f) else "// "
        block = "\n".join("+" + pre + ln for ln in wrap(payload))
        text, start = insert_lines(host, k, block)
        return text, [(start + 1 + len(pre), start + len(block))]
    if position == "log_message":
        return None  # built from the generator directly (embed_log)
    if position == "straddle_window":
        e = tok.enc(host)
        n = tok.n(payload)
        k = MAX_TOK - n // 2
        if len(e.ids) < k + 40:
            return None
        text, sp = insert_at(host, e.offsets[k][0], payload)
        return text, [sp]
    if position == "straddle_chunk":
        pb = len(payload.encode("utf-8"))
        b = CHUNK_BYTES - pb // 2
        acc, ci = 0, len(host)
        for idx, ch in enumerate(host):
            if acc >= b:
                ci = idx
                break
            acc += len(ch.encode("utf-8"))
        if ci >= len(host) - 20:
            return None
        text, sp = insert_at(host, ci, payload)
        return text, [sp]
    if position == "split_adjacent":
        mid = len(payload) // 2
        j = payload.rfind(" ", 0, mid)
        j = j if j > 0 else payload.find(" ", mid)
        if j <= 0:
            return None
        a, b = payload[:j].strip(), payload[j:].strip()
        bridge = r.choice(BRIDGE[lang][tset])
        piece = f"{a} {bridge} {b}"
        text, sp = insert_at(host, r.randrange(0, max(1, len(host) // 2)), piece)
        s0 = sp[0]
        return text, [(s0, s0 + len(a)), (s0 + len(a) + len(bridge) + 2, sp[1])]
    raise ValueError(position)


def embed_log(lang, tset, i, payload, tok, r):
    """A generator log excerpt (set's formats) whose line at a random place carries the payload as its message."""
    gr = gen.unit_rng(f"log_{lang}_host", tset, i)
    cat = (gen.LOG_VI if lang == "vi" else gen.LOG_EN)[tset]
    fmt = gr.choice(gen.LOG_FORMATS[tset])
    lines = [unicodedata.normalize("NFC", gen._log_line(gr, fmt, gen.fill(gr, gr.choice(cat), gen.WORDS[tset]), tset))
             for _ in range(gr.randint(6, 30))]
    one_line = payload.replace("\n", " ")
    pl = gen._log_line(gr, fmt, one_line, tset)
    k = r.randrange(0, len(lines) + 1)
    host = "\n".join(lines)
    while tok.n(host) > max(60, MAX_TOK - tok.n(pl) - 10) and len(lines) > 3:
        lines.pop()
        k = min(k, len(lines))
        host = "\n".join(lines)
    text, start = insert_lines(host, k, pl)
    j = pl.find(json.dumps(one_line, ensure_ascii=False)[1:-1]) if fmt == "ecs" else pl.find(one_line)
    if j < 0:
        return None
    val = json.dumps(one_line, ensure_ascii=False)[1:-1] if fmt == "ecs" else one_line
    return host, text, [(start + j, start + j + len(val))], f"gen_codelog_v5:log_{lang}_host/{tset}/{i}"


HOST_KINDS = {
    "en": {"start": ["prose_en", "log_en", "code_python", "code_go", "code_js", "code_rust", "config", "diff", "json_en", "stacktrace_en"],
           "end": ["prose_en", "log_en", "code_python", "code_go", "code_js", "config", "diff", "csv_en", "terminal"],
           "random": ["prose_en", "log_en", "code_python", "code_go", "code_rust", "config", "stacktrace_en"],
           "comment": ["code_python", "code_go", "code_js", "code_rust", "shell", "config", "sql"],
           "docstring": ["code_python"], "yaml_value": ["config"], "json_field": ["json_en"], "diff_plus": ["diff"],
           "straddle_window": ["prose_en", "log_en"], "straddle_chunk": ["prose_en", "log_en"],
           "split_adjacent": ["prose_en", "log_en"]},
    "vi": {"start": ["prose_vi", "log_vi", "json_vi", "code_vi", "csv_vi", "stacktrace_vi"],
           "end": ["prose_vi", "log_vi", "json_vi", "code_vi", "csv_vi"],
           "random": ["prose_vi", "log_vi", "code_vi", "stacktrace_vi"],
           "comment": ["code_vi", "code_python", "code_go", "code_js", "config"],
           "docstring": ["code_python", "code_vi"], "yaml_value": ["config"], "json_field": ["json_vi"], "diff_plus": ["diff"],
           "straddle_window": ["prose_vi", "log_vi"], "straddle_chunk": ["prose_vi", "log_vi"],
           "split_adjacent": ["prose_vi", "log_vi"]},
}


class Hosts:
    """Host texts for positives, from the units each pool reserved (never cut into hard-negative windows)."""

    def __init__(self, tok, pools, tset):
        self.tok, self.tset = tok, tset
        self.units = {}
        for (s, kind), us in pools.items():
            if s == tset:
                self.units[kind] = split_pool(us, s, kind)[1]
        self.pos = collections.Counter()

    def get(self, kind, ntok, need_def=False, need_yaml=False):
        """(text, origin, source, license) of about ntok tokens, or None."""
        if kind in gen.GENERATORS:
            # Units 1,000,000 + 100*k + j: never cut into hard-negative windows (those use small indices).
            base = 1_000_000 + 100 * self.pos[kind]
            self.pos[kind] += 1
            text, j = "", 0
            while self.tok.n(text) < ntok + 20 and j < 100:
                text += gen.unit(kind, self.tset, base + j)
                j += 1
            text = unicodedata.normalize("NFC", self._trim(text, ntok))
            return text, f"gen_codelog_v5:{kind}/{self.tset}/{base}", "guard-spec:v5-gen", LICENSE_PROJECT
        us = self.units.get(kind) or []
        if need_yaml:
            us = [u for u in us if re.search(r"\.ya?ml$", u["path"])]
        if need_def:
            us = [u for u in us if re.search(r"(?m)^\s*def \w+\(", u["text"])]
        if kind == "diff":
            us = [u for u in us if "\n@@ " in u["text"]]
        if not us:
            return None
        k = self.pos[(kind, need_def, need_yaml)] % len(us)
        u = us[k]
        self.pos[(kind, need_def, need_yaml)] += 1
        lines = u["text"].split("\n")
        if kind.startswith("prose") and self.tok.n(u["text"]) < ntok * 1.3:
            # Long hosts (straddle positions): the following units of the same source, in order.
            text, j = u["text"], k + 1
            while self.tok.n(text) < ntok * 1.3 and j < len(us) and j < k + 12:
                if us[j]["origin"].split("#")[0] == u["origin"].split("#")[0]:
                    text += "\n\n" + us[j]["text"]
                j += 1
            lines = text.split("\n")
        r = R("host", u["origin"], self.pos[(kind, need_def, need_yaml)])
        if need_def:
            defs = [i for i, ln in enumerate(lines) if re.match(r"\s*def \w+\(", ln)]
            st = max(0, r.choice(defs) - r.randint(0, 6))
        elif kind == "diff" or len(lines) <= 30:
            st = 0
        else:
            st = r.randrange(len(lines) - 20)
        text = self._trim("\n".join(lines[st:]), ntok)
        if self.tok.n(text) < ntok * 0.6 and st:
            text = self._trim(u["text"], ntok)
        if ATTACK.search(text):
            return None
        return unicodedata.normalize("NFC", text), u["origin"], u["source"], u["license"]

    def _trim(self, text, ntok):
        lines, out, used = text.split("\n"), [], 0
        for ln in lines:
            n = self.tok.n(ln) + 1
            if used + n > ntok and out:
                break
            if n > ntok:
                out.append(self.tok.cut(ln, max(16, ntok - used)))
                break
            out.append(ln)
            used += n
        return "\n".join(out).strip("\n")


def span_ok(position, payload, text, spans) -> bool:
    """Every word of the payload lies inside the spans, in order (JSON/YAML-quoted values are unescaped first)."""
    got = " ".join(text[a:b] for a, b in spans)
    if position in ("json_field", "yaml_value", "log_message") and len(spans) == 1 and not got.startswith(" "):
        try:
            un = json.loads('"' + got + '"')
            if position != "log_message" or _words_in(payload, un, position):
                got = un
        except ValueError:
            pass
    return _words_in(payload, got, position)


def _words_in(payload, got, position) -> bool:
    pos = 0
    for w in payload.split():
        if position == "docstring":
            w = w.replace('"""', "'''")
        j = got.find(w, pos)
        if j < 0:
            return False
        pos = j + len(w)
    return bool(payload.split())


def make_positives(tok, pools, tset, payloads, n_total, counts):
    hosts = Hosts(tok, pools, tset)
    rows = []
    for lang in ("en", "vi"):
        pl = [p for p in payloads if p["lang"] == lang and payload_set(p) == tset]
        R("payloads", tset, lang).shuffle(pl)
        if not pl:
            continue
        n = n_total // 2
        made, i = 0, 0
        while made < n and i < n * 3:
            p = pl[i % len(pl)]
            position = POSITIONS[i % len(POSITIONS)]
            r = R("pos", tset, lang, i)
            i += 1
            ptoks = tok.n(p["text"])
            if ptoks > 170:
                counts["payload_too_long"] += 1
                continue
            if position == "log_message":
                res = embed_log(lang, tset, i, p["text"], tok, r)
                if res is None:
                    counts[f"embed_failed:{position}"] += 1
                    continue
                host, text, spans, origin = res
                src, lic, hkind = "guard-spec:v5-gen", LICENSE_PROJECT, f"log_{lang}"
            else:
                hkind = r.choice(HOST_KINDS[lang][position])
                if position.startswith("straddle_window"):
                    ntok = r.randint(MAX_TOK + 60, MAX_TOK + 220)
                elif position == "straddle_chunk":
                    ntok = r.randint(700, 900) if lang == "en" else r.randint(800, 1000)
                else:
                    ntok = max(48, min(230, MAX_TOK - ptoks - r.randint(0, 60)))
                    if hkind == "diff":  # commit and index lines are token-heavy; keep at least one hunk
                        ntok = max(ntok, 180)
                h = hosts.get(hkind, ntok, need_def=position == "docstring" and hkind == "code_python",
                              need_yaml=position == "yaml_value")
                if h is None:
                    counts[f"host_missing:{tset}/{hkind}"] += 1
                    continue
                host, origin, src, lic = h
                res = embed(position, p["text"], lang, host, hkind, tok, r, tset)
                if res is None:
                    counts[f"embed_failed:{position}"] += 1
                    continue
                text, spans = res
            if text != unicodedata.normalize("NFC", text) or not span_ok(position, p["text"], text, spans):
                counts[f"embed_span_mismatch:{position}"] += 1
                continue
            labels = sorted(set(p["labels"]) | {"indirect_injection"})
            group = f"v5.{tset}.host.{origin}"
            row = dict(text=text, labels=labels, lang=lang, variant=p["variant"], source="guard-spec:v5-embedded",
                       license=f"{LICENSE_PROJECT}; payload {p['license']}; host {lic}", group=group, kind="embedded",
                       set=tset, origin=origin, position=position, spans=[list(s) for s in spans],
                       payload_id=p["id"], payload_labels=p["labels"], host_kind=hkind, host_source=src,
                       tokens=tok.n(text))
            if r.random() < 0.5:  # minimal pair: the same host without the payload
                twin = row_benign(host, "twin", lang, tset, origin, src, lic, group, tok)
                twin["host_kind"] = hkind
                twin["_pk"] = row["_pk"] = f"{tset}/{lang}/{i}"
                rows.append(twin)
            rows.append(row)
            made += 1
            counts[f"positives:{tset}/{lang}/{position}"] += 1
    return rows


# ---------------------------------------------------------------------------
# Leakage guard
# ---------------------------------------------------------------------------

_P = np.array([pow(1_000_003, 4 - j, 1 << 64) for j in range(5)], dtype=np.uint64)


def shingle_hashes(text: str) -> np.ndarray:
    """Sorted unique 64-bit hashes of the character 5-grams of the normalized text (common.shingles)."""
    t = normalize_for_fingerprint(text)
    a = np.frombuffer(t.encode("utf-32-le"), dtype=np.uint32).astype(np.uint64)
    if len(a) < 5:
        a = np.concatenate([a, np.zeros(5 - len(a), dtype=np.uint64)])
    with np.errstate(over="ignore"):
        h = np.zeros(len(a) - 4, dtype=np.uint64)
        for j in range(5):
            h = h + a[j: len(a) - 4 + j] * _P[j]
        h ^= h >> np.uint64(29)
        h *= np.uint64(0xBF58476D1CE4E5B9)
        h ^= h >> np.uint64(32)
    return np.unique(h)


def small_set(h: np.ndarray) -> np.ndarray:
    """32-bit copy of a shingle set for the stored references (collisions are negligible at window size)."""
    return np.unique((h >> np.uint64(32)).astype(np.uint32))


K_PERM, BANDS = 64, 16
_rs = np.random.RandomState(437128)
_A = _rs.randint(1, 2 ** 62, size=K_PERM, dtype=np.int64).astype(np.uint64) * np.uint64(2) + np.uint64(1)
_B = _rs.randint(0, 2 ** 62, size=K_PERM, dtype=np.int64).astype(np.uint64)


def minhash(h: np.ndarray) -> np.ndarray:
    with np.errstate(over="ignore"):
        return (h[None, :] * _A[:, None] + _B[:, None]).min(axis=1)


def norm_lines(text: str) -> list[str]:
    return [x for x in (" ".join(ln.lower().split()) for ln in text.split("\n")) if len(x) >= 24]


class RefIndex:
    """A large reference collection: MinHash LSH buckets (16 bands x 4 rows), shingle sets, fingerprints of
    whole texts and windows, and the set of long normalized lines (copy detector)."""

    def __init__(self, name):
        self.name = name
        self.sh: list[np.ndarray] = []
        self.label: list[str] = []
        self.buckets = [collections.defaultdict(list) for _ in range(BANDS)]
        self.fps: set[str] = set()
        self.lines: set[str] = set()

    def add(self, text: str, label: str):
        h = shingle_hashes(text)
        sig = minhash(h)
        j = len(self.sh)
        self.sh.append(small_set(h))
        self.label.append(label)
        rows = K_PERM // BANDS
        for b in range(BANDS):
            self.buckets[b][sig[b * rows:(b + 1) * rows].tobytes()].append(j)
        self.fps.add(fingerprint(text))
        self.lines.update(norm_lines(text))

    def query(self, text: str, h: np.ndarray):
        """(max exact Jaccard over the LSH candidates, its label, share of long lines copied, fingerprint hit)."""
        sig = minhash(h)
        hs = small_set(h)
        rows = K_PERM // BANDS
        cand = set()
        for b in range(BANDS):
            cand.update(self.buckets[b].get(sig[b * rows:(b + 1) * rows].tobytes(), ()))
        best, lab = 0.0, ""
        for j in sorted(cand):
            o = self.sh[j]
            inter = len(np.intersect1d(hs, o, assume_unique=True))
            jac = inter / (len(hs) + len(o) - inter)
            if jac > best:
                best, lab = jac, self.label[j]
        ls = norm_lines(text)
        copy = (sum(1 for x in ls if x in self.lines) / len(ls)) if len(ls) >= 3 else 0.0
        return best, lab, copy, fingerprint(text) in self.fps


def token_windows(tok, text, step=L2_STEP, width=MAX_TOK):
    """The gateway's model windows of a text: width content tokens every step tokens."""
    e = tok.enc(text)
    n = len(e.ids)
    if n <= width:
        return [text]
    offs = e.offsets  # a property that copies the whole list: read it once
    out = []
    for s in range(0, n, step):
        en = min(n, s + width)
        out.append(text[offs[s][0]: offs[en - 1][1]])
        if en == n:
            break
    return out


def repo_files() -> list[tuple[str, str]]:
    """(label, text) of every text file of this repository at every tag and at HEAD (unique blobs). Training
    data files (*.jsonl) are compared row by row instead (eval/, hold-outs), and the payloads come from them."""
    refs = sorted(git("-C", str(REPO), "tag").split()) + ["HEAD"]
    blobs = {}
    for ref in refs:
        for ln in git("-C", str(REPO), "ls-tree", "-r", ref).splitlines():
            meta, path = ln.split("\t", 1)
            _, typ, sha = meta.split()
            if typ == "blob" and not path.endswith((".jsonl", ".onnx", ".png", ".jpg", ".ico", ".woff2", ".gz", ".svg")):
                blobs.setdefault(sha, f"{ref}:{path}")
    shas = sorted(blobs)
    p = subprocess.run(["git", "-C", str(REPO), "cat-file", "--batch"], input=("\n".join(shas) + "\n").encode(),
                       capture_output=True, check=True)
    out, buf, i = [], p.stdout, 0
    for sha in shas:
        nl = buf.index(b"\n", i)
        size = int(buf[i:nl].split()[2])
        data = buf[nl + 1: nl + 1 + size]
        i = nl + 1 + size + 1
        if size > 2_000_000 or b"\x00" in data[:8000]:
            continue
        try:
            out.append((blobs[sha], data.decode("utf-8")))
        except UnicodeDecodeError:
            continue
    return out


def read_jsonl(p: Path) -> list[dict]:
    with open(p, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def holdout_texts() -> dict[str, list[str]]:
    out = {}
    for name in ("val_v3_holdout", "val_realistic_holdout", "val_v4_holdout", "probe_v4"):
        p = DATA / f"{name}.jsonl"
        if p.exists():
            out[name] = [r["text"] for r in read_jsonl(p)]
    for var, name in (("GUARD_OWNER_HOLDOUT", "user_holdout"), ("GUARD_OTPKYC_PROBE", "otpkyc_probe")):
        v = os.environ.get(var)
        if v and Path(v).expanduser().exists():
            out[name] = [r["text"] for r in read_jsonl(Path(v).expanduser())]
    return out


class Exact:
    """Exact 5-gram Jaccard (64-bit hashed shingles) of texts against named groups of small references."""

    def __init__(self, groups: dict[str, list[str]]):
        from scipy import sparse
        self.sparse = sparse
        self.vocab: dict[int, int] = {}
        self.names, self.cols, idx, ptr = [], [], [], [0]
        for name, refs in groups.items():
            c0 = len(ptr) - 1
            for t in refs:
                ids = []
                for x in shingle_hashes(t).tolist():
                    j = self.vocab.get(x)
                    if j is None:
                        j = self.vocab[x] = len(self.vocab)
                    ids.append(j)
                idx += ids
                ptr.append(len(idx))
            self.names.append(name)
            self.cols.append((c0, len(ptr) - 1))
        self.E = sparse.csr_matrix((np.ones(len(idx), dtype=np.float32), np.array(idx, dtype=np.int64), np.array(ptr)),
                                   shape=(len(ptr) - 1, len(self.vocab))).T.tocsr()
        self.e_size = np.diff(np.array(ptr)).astype(np.float32)

    def max_per_group(self, hashes: list[np.ndarray]) -> dict[str, np.ndarray]:
        out = {n: np.zeros(len(hashes), dtype=np.float32) for n in self.names}
        for s in range(0, len(hashes), 1000):
            chunk = hashes[s:s + 1000]
            tsz, idx, ptr = [], [], [0]
            for h in chunk:
                tsz.append(len(h))
                v = self.vocab
                idx += sorted({v[x] for x in h.tolist() if x in v})
                ptr.append(len(idx))
            T = self.sparse.csr_matrix((np.ones(len(idx), dtype=np.float32), np.array(idx, dtype=np.int64), np.array(ptr)),
                                       shape=(len(chunk), len(self.vocab)))
            inter = (T @ self.E).toarray()
            jac = inter / np.maximum(np.array(tsz, dtype=np.float32)[:, None] + self.e_size[None, :] - inter, 1)
            for n, (c0, c1) in zip(self.names, self.cols):
                if c1 > c0:
                    out[n][s:s + len(chunk)] = jac[:, c0:c1].max(axis=1)
        return out


class Guard:
    def __init__(self, tok, bench_docs: Path, counts):
        t0 = time.time()
        self.counts = counts
        self.fps = set()
        for f in (EVAL / "fingerprints.txt", EVAL / "codelog" / "fingerprints.txt"):
            self.fps |= {ln.strip() for ln in f.read_text("utf-8").splitlines() if ln.strip() and not ln.startswith("#")}
        small = {"eval": [r["text"] for lang in ("en", "vi") for r in read_jsonl(EVAL / "data" / f"{lang}.jsonl")]}
        codelog = [r["text"] for r in read_jsonl(EVAL / "codelog" / "codelog.jsonl")]
        small["eval_codelog_rows"] = codelog
        small.update(holdout_texts())
        self.small_names = list(small)
        self.exact = Exact(small)
        for name, refs in small.items():
            counts[f"guard:refs:{name}"] = len(refs)
            self.fps |= {fingerprint(t) for t in refs}
        self.large = {}
        ix = RefIndex("eval_codelog_windows")
        for i, t in enumerate(codelog):
            for w in token_windows(tok, t):
                ix.add(w, f"codelog#{i}")
        self.large[ix.name] = ix
        ix = RefIndex("bench_long_full")
        n = 0
        with open(bench_docs, encoding="utf-8") as f:
            for ln in f:
                d = json.loads(ln)
                ix.fps.add(fingerprint(d["text"]))
                for w in token_windows(tok, d["text"]):
                    ix.add(w, d["id"])
                    n += 1
        self.large[ix.name] = ix
        counts["guard:refs:bench_long_full_windows"] = n
        ix = RefIndex("repo_all_tags")
        files = repo_files()
        n = 0
        for lab, t in files:
            ix.fps.add(fingerprint(t))
            for w in token_windows(tok, t):
                ix.add(w, lab)
                n += 1
        self.large[ix.name] = ix
        counts["guard:refs:repo_files"] = len(files)
        counts["guard:refs:repo_windows"] = n
        self.max = {}
        self.max_copy = {}
        self.examples = collections.defaultdict(list)
        log(f"  leakage references ready in {time.time() - t0:.0f}s: bench {counts['guard:refs:bench_long_full_windows']} windows, "
            f"repo {len(files)} files / {n} windows, {sum(len(v) for v in small.values())} small reference rows")

    def filter(self, rows, tag):
        """Drop leaking rows; record the highest kept Jaccard and line-copy share per reference."""
        hashes = [shingle_hashes(r["text"]) for r in rows]
        keep = [fingerprint(r["text"]) not in self.fps for r in rows]
        self.counts[f"leak_fingerprint:{tag}"] = keep.count(False)
        best = self.exact.max_per_group(hashes)
        for name in self.small_names:
            for i, j in enumerate(best[name]):
                if j > JACCARD_MAX and keep[i]:
                    keep[i] = False
                    self.counts[f"leak_jaccard:{tag}:{name}"] += 1
        for name in self.small_names:
            self.max[f"{tag}|{name}"] = round(max((float(j) for i, j in enumerate(best[name]) if keep[i]), default=0.0), 4)
        for name, ix in self.large.items():
            mx, mc = 0.0, 0.0
            for i, r in enumerate(rows):
                if not keep[i]:
                    continue
                j, ref, copy, fp = ix.query(r["text"], hashes[i])
                if fp or j > JACCARD_MAX or copy >= LINE_COPY_MAX:
                    keep[i] = False
                    why = "fingerprint" if fp else ("jaccard" if j > JACCARD_MAX else "line_copy")
                    self.counts[f"leak_{why}:{tag}:{name}"] += 1
                    self.examples[f"{tag}|{name}"].append(f"{why} {j:.2f}/{copy:.2f}: {r.get('origin')} ~ {ref}")
                    continue
                mx, mc = max(mx, j), max(mc, copy)
            self.max[f"{tag}|{name}"] = round(mx, 4)
            self.max_copy[f"{tag}|{name}"] = round(mc, 4)
        return [r for r, k in zip(rows, keep) if k]


def payload_guard(payloads, guard: Guard, counts):
    """Payload rows (data/train.jsonl attacks) against eval and every hold-out/probe: dropped above 0.8 or on a
    fingerprint. They must also be training rows only: none may appear in a validation, hold-out or probe split."""
    texts = [p["text"] for p in payloads]
    keep = [fingerprint(t) not in guard.fps for t in texts]
    counts["payload_leak_fingerprint"] = keep.count(False)
    best = guard.exact.max_per_group([shingle_hashes(t) for t in texts])
    for name in guard.small_names:
        for i, j in enumerate(best[name]):
            if j > JACCARD_MAX and keep[i]:
                keep[i] = False
                counts[f"payload_leak_jaccard:{name}"] += 1
        guard.max[f"payloads|{name}"] = round(max((float(j) for i, j in enumerate(best[name]) if keep[i]), default=0.0), 4)
    held = set()
    for p in sorted(DATA.glob("val*.jsonl")) + sorted(DATA.glob("probe*.jsonl")):
        held |= {normalize_for_fingerprint(r["text"]) for r in read_jsonl(p)}
    for i, t in enumerate(texts):
        if keep[i] and normalize_for_fingerprint(t) in held:
            keep[i] = False
            counts["payload_in_val_or_holdout"] += 1
    return [p for p, k in zip(payloads, keep) if k]


def cross_set_guard(sets: dict, guard: Guard, counts):
    """B against A, C against A and B: drop near-duplicates (licence headers, shared boilerplate, reused payloads
    in similar hosts) so that the validation and hold-out sets stay independent of training."""
    for later, earlier in (("B", ["A"]), ("C", ["A", "B"])):
        name = "".join(earlier)
        ix = RefIndex(f"set_{name}")
        for s in earlier:
            for r in sets[s]:
                ix.add(r["text"], r["group"])
        keep, mx, mc = [], 0.0, 0.0
        for r in sets[later]:
            j, ref, copy, fp = ix.query(r["text"], shingle_hashes(r["text"]))
            if fp or j > JACCARD_MAX or copy >= LINE_COPY_MAX:
                counts[f"cross_set_dropped:{later}_vs_{name}"] += 1
                guard.examples[f"set_{later}|vs_set_{name}"].append(f"{j:.2f}/{copy:.2f}: {r.get('origin')} ~ {ref}")
                continue
            mx, mc = max(mx, j), max(mc, copy)
            keep.append(r)
        sets[later] = keep
        guard.max[f"set_{later}|vs_set_{name}"] = round(mx, 4)
        guard.max_copy[f"set_{later}|vs_set_{name}"] = round(mc, 4)


# ---------------------------------------------------------------------------
# Balance, split, write
# ---------------------------------------------------------------------------

def est_windows(r) -> int:
    t = r["tokens"]
    return 1 if t <= MAX_TOK else 1 + math.ceil((t - MAX_TOK) / L2_STEP)


def balance(rows, tset, counts):
    """Benign share ~BENIGN_SHARE and Vietnamese >= VI_MIN_SHARE of the set, by subsampling hard negatives."""
    pos = [r for r in rows if r["labels"] != ["benign"]]
    twins = [r for r in rows if r["kind"] == "twin"]
    hn = [r for r in rows if r["labels"] == ["benign"] and r["kind"] != "twin"]
    benign_target = round(len(pos) * BENIGN_SHARE / (1 - BENIGN_SHARE))
    total = benign_target + len(pos)
    vi_have = sum(r["lang"] == "vi" for r in pos + twins)
    hn_target = max(0, benign_target - len(twins))
    by_lang = {lang: [r for r in hn if r["lang"] == lang] for lang in ("en", "vi")}
    vi_hn = min(len(by_lang["vi"]), max(math.ceil(VI_MIN_SHARE * total) - vi_have,
                                        round(hn_target * len(by_lang["vi"]) / max(1, len(hn)))))
    en_hn = min(len(by_lang["en"]), hn_target - vi_hn)
    keep = []
    for lang, n in (("en", en_hn), ("vi", vi_hn)):
        rs = by_lang[lang]
        if n >= len(rs):
            keep += rs
            continue
        # Proportional per kind, random within a kind.
        kinds = collections.defaultdict(list)
        for r in rs:
            kinds[r["kind"]].append(r)
        frac = n / len(rs)
        for k in sorted(kinds):
            g = sorted(kinds[k], key=lambda r: r["text"])
            R("balance", tset, lang, k).shuffle(g)
            keep += g[: round(len(g) * frac)]
        counts[f"balance:{tset}/{lang}:hardneg_dropped"] = len(rs) - sum(1 for r in keep if r["lang"] == lang)
    return keep + twins + pos


def write_jsonl(path: Path, rows) -> str:
    fields = ["id", "text", "labels", "lang", "variant", "source", "license", "group", "kind", "set", "tokens", "origin",
              "position", "spans", "byte_spans", "payload_id", "payload_labels", "host_kind", "host_source", "pair"]
    body = "".join(json.dumps({k: r[k] for k in fields if k in r}, ensure_ascii=False) + "\n" for r in rows)
    path.write_text(body, encoding="utf-8")
    return hashlib.md5(body.encode("utf-8")).hexdigest()


def finalize(r):
    r["text"] = unicodedata.normalize("NFC", r["text"])
    r["id"] = f"{r['lang']}-{sha256_text(r['text'])[:12]}"
    if "spans" in r:
        r["byte_spans"] = [[len(r["text"][:a].encode("utf-8")), len(r["text"][:b].encode("utf-8"))] for a, b in r["spans"]]


def summarize(rows):
    c = collections.Counter()
    for r in rows:
        cls = "attack" if r["labels"] != ["benign"] else "benign"
        c["rows"] += 1
        c[f"{cls}"] += 1
        c[f"lang:{r['lang']}"] += 1
        c[f"{cls}:{r['lang']}"] += 1
        c[f"kind:{r['kind']}:{r['lang']}"] += 1
        if "position" in r:
            c[f"position:{r['position']}:{r['lang']}"] += 1
        for lb in r["labels"]:
            c[f"label:{lb}"] += 1
        c["tokens"] += r["tokens"]
        c["est_windows"] += est_windows(r)
    out = dict(sorted(c.items()))
    if c["rows"]:
        out["benign_share"] = round(c["benign"] / c["rows"], 4)
        out["vi_share"] = round(c["lang:vi"] / c["rows"], 4)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--profile", choices=["full", "quick"], default="full")
    ap.add_argument("--payloads", default=os.environ.get("GUARD_V5_PAYLOADS") or str(DATA / "train.jsonl"),
                    help="training split whose attack rows are embedded (default data/train.jsonl)")
    ap.add_argument("--base-train", default=os.environ.get("GUARD_BASE_TRAIN") or str(DATA / "train.jsonl"),
                    help="the training file v5 is added to, for the epoch cap")
    ap.add_argument("--bench-docs", default=None, help="bench/long full-profile docs.jsonl (built when missing)")
    ap.add_argument("--stats-copy", default=None, help="also write stats.json here (e.g. data/stats_v5.json)")
    a = ap.parse_args(argv)
    t_start = time.time()
    out = os.environ.get("GUARD_BUILD_OUT")
    if not out:
        raise SystemExit("GUARD_BUILD_OUT (an output directory outside the repository) is required")
    out = Path(out).expanduser().resolve()
    if out == REPO or REPO in out.parents:
        raise SystemExit("GUARD_BUILD_OUT must be outside the repository: no third-party text is written into git")
    cache = Cache(Path(os.environ.get("GUARD_V5_CACHE") or TRAIN_ROOT / ".cache" / "v5").expanduser().resolve())
    cfg = yaml.safe_load((DATA / "sources_v5.yaml").read_text("utf-8"))
    scale = 1.0 if a.profile == "full" else 0.25
    for name, src in cfg["sources"].items():
        bad = set(src.get("windows") or {}) - (set(src.get("select") or {}) & set(TARGETS[src["set"]]))
        if bad:
            raise SystemExit(f"{name}: `windows` kinds {sorted(bad)} are not selected kinds with a set {src['set']} target")
    counts = collections.Counter()
    pins: dict = {}

    tk = cfg["tokenizer"]
    tpath = Path(hf_hub_download(tk["repo"], tk["file"], revision=tk["revision"], cache_dir=str(cache.root / "hf")))
    if file_sha256(tpath) != tk["sha256"]:
        raise SystemExit(f"tokenizer {tpath}: SHA-256 differs from sources_v5.yaml")
    tok = Tok(tpath)

    bench_docs = Path(a.bench_docs) if a.bench_docs else \
        Path(os.environ.get("BENCH_CACHE") or REPO / "bench" / ".cache") / "long" / "full" / "docs.jsonl"
    if not bench_docs.exists():
        log(f"{bench_docs} missing: building the bench/long full profile")
        subprocess.run(["uv", "run", "--project", str(REPO / "bench"), "--frozen", "python", str(REPO / "bench" / "long" / "build.py"),
                        "--profile", "full"], check=True)
    bench_sha = file_sha256(bench_docs)
    bench_cfg = yaml.safe_load((REPO / "bench" / "long" / "corpus.yaml").read_text("utf-8"))
    if bench_sha != bench_cfg["outputs"]["full"]:
        raise SystemExit(f"{bench_docs}: SHA-256 {bench_sha} is not the pinned full profile {bench_cfg['outputs']['full']}")

    t0 = time.time()
    pools = load_sources(cfg, cache, pins)
    t_sources = time.time() - t0

    t0 = time.time()
    payloads = load_payloads(Path(a.payloads), counts)
    counts["payload_candidates"] = len(payloads)
    log("building leakage references")
    guard = Guard(tok, bench_docs, counts)
    payloads = payload_guard(payloads, guard, counts)
    counts["payloads_kept"] = len(payloads)
    t_refs = time.time() - t0

    t0 = time.time()
    sets = {}
    for tset in ("A", "B", "C"):
        rows = []
        for kind, n in TARGETS[tset].items():
            quota = {name: max(1, round(src["windows"][kind] * scale)) for name, src in cfg["sources"].items()
                     if src["set"] == tset and kind in (src.get("windows") or {})}
            rows += make_windows(tok, pools, tset, kind, max(1, round(n * scale)), counts, quota)
        rows += make_positives(tok, pools, tset, payloads, round(POSITIVES[tset] * scale), counts)
        counts[f"generated:{tset}"] = len(rows)
        sets[tset] = rows
        log(f"  set {tset}: {len(rows)} rows generated")
    t_gen = time.time() - t0

    t0 = time.time()
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
        log(f"  set {tset}: {len(sets[tset])} rows after the leakage guard")
    cross_set_guard(sets, guard, counts)
    # A twin whose positive was dropped (or the reverse) stays a valid row; only the pair link is cleared.
    t_guard = time.time() - t0

    for tset in sets:
        sets[tset] = balance(sets[tset], tset, counts)
        for r in sets[tset]:
            finalize(r)
    # Minimal pairs: the positive and its twin (the host without the payload) point at each other's id.
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

    split = {"v5_train": [], "v5_val": []}
    for r in sets["A"]:
        h = int(hashlib.sha256(f"split:{r['group']}".encode()).hexdigest(), 16) % 100
        split["v5_val" if h < VAL_PCT else "v5_train"].append(r)
    split["val_v5"] = sets["B"]
    split["val_v5_holdout"] = sets["C"]

    base_rows = sum(1 for _ in open(a.base_train, encoding="utf-8")) if Path(a.base_train).exists() else 0
    epoch = base_rows + sum(est_windows(r) for r in split["v5_train"])
    counts["epoch_estimate_rows"] = epoch
    counts["epoch_base_rows"] = base_rows
    if epoch > EPOCH_CAP:
        hn = [r for r in split["v5_train"] if r["labels"] == ["benign"] and r["kind"] != "twin"]
        excess = epoch - EPOCH_CAP
        hn.sort(key=lambda r: r["id"])
        R("epoch_cap").shuffle(hn)
        drop = {id(r) for r in hn[:excess]}
        split["v5_train"] = [r for r in split["v5_train"] if id(r) not in drop]
        counts["epoch_cap_dropped"] = len(drop)

    for name in split:
        split[name].sort(key=lambda r: (r["lang"], r["kind"], r["group"], r["id"]))
    out.mkdir(parents=True, exist_ok=True)
    md5 = {name: write_jsonl(out / f"{name}.jsonl", rs) for name, rs in split.items()}

    gm = gen.sample_md5()
    stats = {
        "profile": a.profile,
        "md5": md5,
        "gen_codelog_v5_md5": hashlib.md5(json.dumps(gm, sort_keys=True).encode()).hexdigest(),
        "splits": {name: summarize(rs) for name, rs in split.items()},
        "leakage": {"max_jaccard_kept": dict(sorted(guard.max.items())), "max_line_copy_kept": dict(sorted(guard.max_copy.items())),
                    "rule": "drop on fingerprint, 5-gram Jaccard > 0.8, or >= 50% of long lines copied (>= 3 lines)",
                    "dropped_examples": {k: v[:12] for k, v in sorted(guard.examples.items())}},
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
        log(f"{name}: {len(rs)} rows, md5 {md5[name]}")
    unpinned = [n for n, s in cfg["sources"].items() if not s.get("content_sha256")]
    for n in unpinned:
        log(f"  not pinned in sources_v5.yaml: {n}: {json.dumps(pins.get(n))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
