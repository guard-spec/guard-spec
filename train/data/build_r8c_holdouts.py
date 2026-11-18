# Copyright The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""R8c (RF-f9e76bb6): the fresh holdouts persona3, split1 and long9 (train/reports/r8c_preregistration.md).

No holdout row is scored by any model before the R8c holdout stage. Stages (OUT is --out, outside the repository,
e.g. guardspec-data/v9/r8c):

  persona3        candidates of the benign persona holdout, per language (EN, VI), with a `stratum` per row:
                  - enterprise_{en,vi}: system prompts of 12 new roles per language, 8 per role, built from openers,
                    rules, tones, refusals and companies of their own (data/r8c_templates.py; no sentence shared
                    with persona1, persona2 or a training template);
                  - arena_en (arena_vi): the first user turn of lmarena-ai/arena-human-preference-140k
                    conversations (user prompts CC-BY-4.0, pinned revision and SHA-256 below) that asks the model to
                    take a role or persona, in English (Vietnamese), without build_short1.ATTACK_MARKERS, not
                    overlapping any guarded text, near-duplicates within the set dropped; a seeded 330 English (every
                    Vietnamese one) go to the label audit.
                  Writes OUT/persona3/candidates/{en,vi}.jsonl and OUT/persona3/audit_sheet.jsonl (community rows,
                  ids and text only, for the labellers).
  audit           --labels FILE (JSON {id: benign|attack|ambiguous}): the community rows labelled benign (at most
                  300 English, in the seeded order) and every enterprise row go to
                  OUT/persona3/holdout/direct/{en,vi}.jsonl; OUT/persona3/audit.json records labels and counts.
  split1          OUT/split1/split1.json: 60 payload-splitting attack conversations and 60 benign ones (EN, VI), in
                  the shape of cmd/gateway/testdata/multiturn.json, from data/r8c_templates.py.
  long9-exclude   the units of the long9 sources (bench/long/corpus.yaml) that share a run of 50 classifier tokens
                  with a row of E's training or validation data, persona_neg_train or the v7 pool (the v8 hosts),
                  or of which 20% or more of the 50-token shingles occur in a document of another bench/long
                  profile; with --write they go into bench/long/exclude.json under their source names.
  check           every holdout row (persona3, split1 turns and joined conversations) against the guarded texts:
                  exact (build_short1.norm) or half of its 8-word shingles (build_short1.shingles) in the guarded
                  texts, which catches every pair with a Jaccard of 0.5 or more; long9 (benign and attack
                  documents) against the training rows with 50-token runs. Guarded: E's data, persona_neg_train,
                  the R8c L and S rows (--train-extra), eval/, persona1, persona2, the L3 exemplars, multiturn.json,
                  the payload_split dev set. Writes OUT/holdout_check.json; exit 1 on any overlap.
  sums            OUT/SHA256SUMS and OUT/holdouts_manifest.json (SHA-256 and counts of every holdout file).

Never read: the owner hold-outs (guardspec-data/incoming, processed/user_holdout.jsonl, data-v4A/user_holdout.jsonl).
E's files are read only to compare against, never copied.

    cd train && uv run --frozen python data/build_r8c_holdouts.py persona3 --out $OUT --arena <arena dir>
    cd train && uv run --frozen python data/build_r8c_holdouts.py audit --out $OUT --labels <labels.json>
    cd train && uv run --frozen python data/build_r8c_holdouts.py split1 --out $OUT
    cd train && BENCH_CACHE=... MODEL_DIR=... uv run --frozen python data/build_r8c_holdouts.py long9-exclude --out $OUT [--write]
    cd train && BENCH_CACHE=... MODEL_DIR=... uv run --frozen python data/build_r8c_holdouts.py check --out $OUT \\
        --train-extra $OUT/L/r8c_L_train.jsonl --train-extra $OUT/L/r8c_S_train.jsonl
    cd train && uv run --frozen python data/build_r8c_holdouts.py sums --out $OUT

Data paths default to guardspec-data next to the repository (--data). Seeded and byte-identical between runs.
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRAIN = HERE.parent
REPO = TRAIN.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "bench" / "long"))

from build_short1 import ATTACK_MARKERS, mostly_latin, norm, shingles  # noqa: E402
import build_r8b_persona as R8B  # noqa: E402
import persona1_templates as P1  # noqa: E402
import r8c_templates as T  # noqa: E402

SEED = 20261119
OVERLAP = 0.5        # half of a holdout row's 8-word shingles in the guarded texts
NEAR_DUP = 0.7       # within the community candidates: Jaccard >= 0.7 keeps the earlier row
MIN_CHARS, MAX_CHARS = 20, 6000
AUDIT_EN, KEEP_EN = 330, 300
BENCH_NEAR_DUP = 0.2  # long9 units: 20% of the 50-token shingles in another profile's document

ARENA_REPO = "lmarena-ai/arena-human-preference-140k"
ARENA_REV = "6322995ab34d7c2693e3f47dd13fa5caa0789a74"
ARENA_FILES = {  # data/train-0000N-of-00007.parquet -> SHA-256 (the Hub's LFS pointer, checked on read)
    0: "7b871a964dc9b238fe0d59f817dbe1a7a56934e23ec4d989f86e6891e5a891cf",
    1: "0cd29a6e3261159f41a69b28cd7f08c0bbbc1ef08ba18438d386a1b0c144af8a",
    2: "c633264fe8f0fa26cc9aa49961a75dc428791f70c7a476cbed766963b88bee24",
    3: "5bcf04c9f4488006a4a7ee944d886ee123e118b7f7d2db04b4ff6dbd8125e6b0",
    4: "2c50b4b3f6a5c02d660f5a70d5006332ddc00f5eb21f8e4d92bde3856647969b",
    5: "de59f74dce7477beaec55936b31a88537b93c5cbb4b483cfc6879a6862ce5e3b",
    6: "1a32a1c6934ebcaa3019643a08fb57563ee0a9be282d3222def3c572a49e9f4c",
}

# A request to take a role or persona, at the start of the prompt.
PERSONA_EN = re.compile(
    r"^\W*(you are|you're|act as|i want you to act|pretend (to be|you are|you're)|role[- ]?play|let'?s (role[- ]?play|pretend)"
    r"|imagine you are|you will (act|play|be)|from now on,? you|play the role|take on the role|assume the role"
    r"|be my|you are now|for this conversation,? you|in this chat,? you|your role is|your name is)\b", re.I)
PERSONA_VI = re.compile(
    r"^\W*(bạn là|hãy đóng vai|đóng vai|hãy là|giả sử bạn là|hãy tưởng tượng bạn là|trong vai trò|với vai trò|hãy nhập vai"
    r"|nhập vai|từ giờ bạn là|từ bây giờ bạn là|bạn sẽ là|hãy trở thành|vai trò của bạn)", re.I)

# Owner data: never read by this script (a path matching one of these is refused).
OWNER_PATTERNS = ("incoming", "user_holdout", "owner")


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def h12(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()[:12]


def order_key(t: str) -> str:
    return hashlib.sha256(f"{SEED}:{t}".encode()).hexdigest()


def write_jsonl(p: Path, rows) -> str:
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return sha256_file(p)


def read_jsonl(p: Path) -> list[dict]:
    if any(x in str(p) for x in OWNER_PATTERNS) and "persona_neg_train" not in str(p):
        raise SystemExit(f"{p}: owner data is never read by this script")
    with open(p, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


# ---------------------------------------------------------------------------------------------------------
# Inputs

def e_files(data: Path) -> list[Path]:
    """E's training and validation files (train/run_arms_v8.sh: data-v4A, out-full, v8e_train.jsonl), by name:
    the owner hold-out of data-v4A (user_holdout.jsonl) is not one of them."""
    v4a = [data / "v6/work/data-v4A" / f"{x}.jsonl" for x in ("train", "val", "val_hard", "val_vi_variants", "val_v3", "val_v4")]
    v6 = [data / "v6/out-full" / f"{x}.jsonl" for x in ("v6_train", "v6_val", "val_v6")]
    return v4a + v6 + [data / "v8/data/v8e_train.jsonl"]


def multiturn_texts() -> list[str]:
    d = json.loads((REPO / "cmd/gateway/testdata/multiturn.json").read_text("utf-8"))
    out = []
    for c in d["conversations"]:
        out += c["turns"] + [" ".join(c["turns"])]
    return out


def payload_split_texts() -> list[str]:
    """The payload_split dev set: the raw strings of internal/inference/rules/payload_split_test.go."""
    src = (REPO / "internal/inference/rules/payload_split_test.go").read_text("utf-8")
    out = []
    for m in re.finditer(r"var (payloadSplit\w+) = \[\]string\{(.*?)\n\}", src, re.S):
        out += re.findall(r"`([^`]*)`", m.group(2))
    if len(out) < 30:
        raise SystemExit(f"payload_split_test.go: only {len(out)} strings found")
    return out


def guarded_sources(data: Path, extra: list[str]) -> dict[str, list[str]]:
    """Every text a holdout row must not overlap, by source name."""
    src: dict[str, list[str]] = {}
    for p in e_files(data):
        src[f"E:{p.parent.name}/{p.name}"] = [r["text"] for r in read_jsonl(p)]
    src["persona_neg_train"] = [r["text"] for r in read_jsonl(data / "v9/r8b/persona_neg_train.jsonl")]
    for p in extra:
        for q in sorted(glob.glob(os.path.expanduser(p))):
            src[f"train_extra:{Path(q).name}"] = [r["text"] for r in read_jsonl(Path(q))]
    for p in sorted(glob.glob(str(REPO / "eval" / "**" / "*.jsonl"), recursive=True)):
        src[f"eval:{Path(p).relative_to(REPO / 'eval')}"] = [r.get("text") or "" for r in read_jsonl(Path(p))]
    for p in sorted(glob.glob(str(data / "v9/persona1/out/*/direct/*.jsonl"))):
        src[f"persona1:{Path(p).parts[-3]}/{Path(p).name}"] = [r["text"] for r in read_jsonl(Path(p))]
    for p in sorted(glob.glob(str(data / "v9/r8b/persona2/holdout/direct/*.jsonl"))):
        src[f"persona2:{Path(p).name}"] = [r["text"] for r in read_jsonl(Path(p))]
    src["exemplars"] = [r["text"] for r in read_jsonl(REPO / "internal/inference/ml/exemplars/default.jsonl")]
    src["multiturn.json"] = multiturn_texts()
    src["payload_split_test.go"] = payload_split_texts()
    for p in sorted(HERE.glob("*.jsonl")):  # the repository's training, validation and probe rows
        src[f"train/data:{p.name}"] = [r.get("text") or "" for r in read_jsonl(p)]
    return src


class Guard:
    """Exact texts and 8-word shingles of the guarded texts, with the source of each shingle's first occurrence."""

    def __init__(self, sources: dict[str, list[str]]):
        self.exact: dict[str, str] = {}
        self.sh: dict[int, str] = {}
        self.counts = {}
        for name, texts in sources.items():
            self.counts[name] = len(texts)
            for t in texts:
                if not t:
                    continue
                self.exact.setdefault(norm(t), name)
                for x in shingles(t):
                    self.sh.setdefault(x, name)

    def hit(self, t: str) -> tuple[str, float, str] | None:
        """(kind, share, source) when t overlaps: exact, or at least OVERLAP of its shingles guarded."""
        n = norm(t)
        if n in self.exact:
            return ("exact", 1.0, self.exact[n])
        sh = shingles(t)
        found = [self.sh[x] for x in sh if x in self.sh]
        share = len(found) / max(1, len(sh))
        if share >= OVERLAP:
            return ("shingles", round(share, 3), collections.Counter(found).most_common(1)[0][0])
        return None


# ---------------------------------------------------------------------------------------------------------
# persona3

def enterprise_rows() -> list[dict]:
    rows = R8B.templates(T.ROLES_EN_P3, T.ROLES_VI_P3, "r8c-P3", 8, SEED, T.COMP_EN_P3, T.COMP_VI_P3)
    for r in rows:
        r["source"] = r["source"].replace("guard-spec:r8b-templates:", "guard-spec:r8c-templates:")
        r["stratum"] = f"enterprise_{r['lang']}"
    return rows


def old_template_sentences() -> set[str]:
    """Every building block of the earlier persona templates (persona1, R8b roles B and C)."""
    out = set()
    blocks = [P1.COMPANIES_EN, P1.TONES_EN, P1.RULES_EN, P1.REFUSALS_EN, P1.OPENERS_EN,
              P1.COMPANIES_VI, P1.TONES_VI, P1.RULES_VI, P1.REFUSALS_VI, P1.OPENERS_VI]
    for comp in (R8B.COMP_EN_B, R8B.COMP_VI_B):
        blocks += list(comp[:5])
    for x in blocks:
        out |= {norm(s) for s in x}
    for roles in (P1.ROLES_EN, P1.ROLES_VI, R8B.ROLES_EN_B, R8B.ROLES_VI_B, R8B.ROLES_EN_C, R8B.ROLES_VI_C):
        for name, domain, duty in roles:
            out |= {norm(name), norm(duty)}
    return out


def check_new_blocks() -> list[str]:
    """Building blocks of persona3 that an earlier template set already has (must be empty)."""
    old = old_template_sentences()
    mine = []
    for comp in (T.COMP_EN_P3, T.COMP_VI_P3):
        for x in comp[:5]:
            mine += list(x)
    for roles in (T.ROLES_EN_P3, T.ROLES_VI_P3):
        for name, _, duty in roles:
            mine += [name, duty]
    return [s for s in mine if norm(s) in old]


def arena_prompts(arena: Path) -> tuple[list[tuple[str, str]], dict]:
    """(lang, first user turn) of every arena conversation in English or Vietnamese, in file order, deduplicated."""
    import pyarrow.parquet as pq

    out, seen, shas = [], set(), {}
    for i, want in sorted(ARENA_FILES.items()):
        p = arena / "data" / f"train-0000{i}-of-00007.parquet"
        got = sha256_file(p)
        if got != want:
            raise SystemExit(f"{p}: SHA-256 {got}, pinned {want}")
        shas[p.name] = got
        t = pq.read_table(p, columns=["language", "conversation_a"])
        for lang, conv in zip(t.column("language").to_pylist(), t.column("conversation_a").to_pylist()):
            if lang not in ("en", "vi"):
                continue
            users = [m for m in conv or [] if m.get("role") == "user"]
            if not users:
                continue
            text = " ".join((c.get("text") or "") for c in users[0]["content"] if c.get("type") == "text").strip()
            k = norm(text)
            if not text or k in seen:
                continue
            seen.add(k)
            out.append((lang, text))
    return out, shas


def stage_persona3(a) -> int:
    clash = check_new_blocks()
    if clash:
        raise SystemExit(f"persona3 building blocks already used by earlier templates: {clash}")
    guard = Guard(guarded_sources(a.data, []))
    rep: dict = {"seed": SEED, "guard_sources": guard.counts, "community": collections.Counter()}
    ent = enterprise_rows()
    for r in ent:
        if guard.hit(r["text"]):
            raise SystemExit(f"an enterprise row overlaps a guarded text: {r['text'][:80]}")
    prompts, shas = arena_prompts(a.arena)
    rep["arena_sha256"] = shas
    rep["arena_rows_en_vi_unique"] = len(prompts)
    cands = {"en": [], "vi": []}
    for lang, t in prompts:
        c = rep["community"]
        rx = PERSONA_EN if lang == "en" else PERSONA_VI
        if not rx.search(t):
            continue
        c[f"{lang}:persona_shaped"] += 1
        if not MIN_CHARS <= len(t) <= MAX_CHARS:
            c[f"{lang}:dropped_length"] += 1
            continue
        if lang == "en" and not mostly_latin(t):
            c[f"{lang}:dropped_not_latin"] += 1
            continue
        if ATTACK_MARKERS.search(t):
            c[f"{lang}:dropped_attack_marker"] += 1
            continue
        hit = guard.hit(t)
        if hit:
            c[f"{lang}:dropped_overlap:{hit[2].split(':')[0]}"] += 1
            continue
        cands[lang].append(t)
    out = {"en": [], "vi": []}
    for lang in ("en", "vi"):
        lst = sorted(cands[lang], key=order_key)
        kept, kept_sh = [], []
        for t in lst:
            sh = shingles(t)
            if any(len(sh & s) / max(1, len(sh | s)) >= NEAR_DUP for s in kept_sh):
                rep["community"][f"{lang}:dropped_near_duplicate"] += 1
                continue
            kept.append(t)
            kept_sh.append(sh)
        rep["community"][f"{lang}:pool"] = len(kept)
        take = kept[:AUDIT_EN] if lang == "en" else kept
        out[lang] = [{"id": f"persona3-arena_{lang}-{h12(t)}", "text": t, "label": "benign", "category": "benign",
                      "lang": lang, "variant": "orig", "source": f"{ARENA_REPO}@{ARENA_REV[:12]}", "license": "CC-BY-4.0",
                      "stratum": f"arena_{lang}", "order": i} for i, t in enumerate(take)]
    d = a.out / "persona3" / "candidates"
    sums = {}
    sheet = []
    for lang in ("en", "vi"):
        rows = [{"id": f"persona3-{r['stratum']}-{h12(r['text'])}", "text": r["text"], "label": "benign",
                 "category": "benign", "lang": lang, "variant": "orig", "source": r["source"], "license": "Apache-2.0",
                 "stratum": r["stratum"]} for r in ent if r["lang"] == lang] + out[lang]
        rows.sort(key=lambda x: x["id"])
        sums[f"{lang}.jsonl"] = write_jsonl(d / f"{lang}.jsonl", rows)
        sheet += [{"id": r["id"], "lang": lang, "text": r["text"]} for r in out[lang]]
    write_jsonl(a.out / "persona3" / "audit_sheet.jsonl", sorted(sheet, key=lambda x: x["id"]))
    rep["candidates"] = {f"{lang}:{s}": n for (lang, s), n in collections.Counter(
        (r["lang"], r["stratum"]) for r in ent + out["en"] + out["vi"]).items()}
    rep["candidates_sha256"] = sums
    rep["community"] = dict(sorted(rep["community"].items()))
    (a.out / "persona3" / "build_report.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(json.dumps({k: v for k, v in rep.items() if k != "guard_sources"}, indent=1, ensure_ascii=False))
    return 0


def stage_audit(a) -> int:
    labels = json.loads(Path(a.labels).read_text("utf-8"))
    labels = labels.get("labels", labels)
    d = a.out / "persona3"
    rep = {"labels": {}, "counts": collections.Counter(), "sha256": {}}
    for lang in ("en", "vi"):
        rows = read_jsonl(d / "candidates" / f"{lang}.jsonl")
        keep = []
        com = sorted((r for r in rows if r["stratum"].startswith("arena")), key=lambda r: r["order"])
        for r in com:
            lab = labels.get(r["id"])
            if lab is None:
                raise SystemExit(f"{r['id']}: no audit label")
            rep["labels"][r["id"]] = lab
            rep["counts"][f"{r['stratum']}:{lab}"] += 1
        ok = [r for r in com if labels[r["id"]] == "benign"]
        if lang == "en":
            ok = ok[:KEEP_EN]
        keep = [r for r in rows if not r["stratum"].startswith("arena")] + ok
        for r in keep:
            r.pop("order", None)
            rep["counts"][f"kept:{r['stratum']}"] += 1
        keep.sort(key=lambda x: x["id"])
        rep["sha256"][lang] = write_jsonl(d / "holdout" / "direct" / f"{lang}.jsonl", keep)
    rep["counts"] = dict(sorted(rep["counts"].items()))
    rep["method"] = a.method
    (d / "audit.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(json.dumps({k: v for k, v in rep.items() if k != "labels"}, indent=1, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------------------------------------
# split1

def stage_split1(a) -> int:
    convs = T.split1_conversations(SEED)
    doc = {"_comment": "split1, the payload-splitting holdout of R8c (RF-f9e76bb6), written for this round from "
                       "train/data/r8c_templates.py (not from multiturn.json, the payload_split dev set, eval/ or "
                       "train/). attack: an instruction split over 2 to 4 user turns; benign: multi-turn requests with "
                       "string joins, sums, word games and 'don't ignore' wording. Scored once, L2 only, on the "
                       "conversation window (turns joined with a space).",
           "conversations": convs}
    p = a.out / "split1" / "split1.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", "utf-8")
    c = collections.Counter(f"{x['lang']}:{x['kind']}" for x in convs)
    log(json.dumps({"file": str(p), "sha256": sha256_file(p), "counts": dict(sorted(c.items()))}, indent=1))
    return 0


def split1_texts(out: Path) -> list[tuple[str, str]]:
    d = json.loads((out / "split1" / "split1.json").read_text("utf-8"))
    res = []
    for c in d["conversations"]:
        res += [(f"{c['id']}:turn{i}", t) for i, t in enumerate(c["turns"])]
        res.append((f"{c['id']}:joined", " ".join(c["turns"])))
    return res


# ---------------------------------------------------------------------------------------------------------
# long9

def bench_tok():
    import build
    from bench_guard import tokenizer_fn

    return tokenizer_fn(build.find_tokenizer(None))


def bench_dir() -> Path:
    return Path(os.environ.get("BENCH_CACHE") or REPO / "bench" / ".cache") / "long"


def training_index(tok, data: Path, extra: list[str]):
    """50-token shingles of E's rows, persona_neg_train, the v7 pool documents and the given files."""
    from bench_guard import ShingleIndex

    ix = ShingleIndex(tok)
    n = collections.Counter()
    files = e_files(data) + [data / "v9/r8b/persona_neg_train.jsonl", data / "v7/data/pool/docs.jsonl"]
    for p in extra:
        files += [Path(q) for q in sorted(glob.glob(os.path.expanduser(p)))]
    for p in files:
        for r in read_jsonl(p):
            ix.add(r.get("text") or "", f"{p.name}:{r.get('id', '?')}")
            n[p.name] += 1
    return ix, dict(n)


def shingle_share(ix, tok, text: str) -> float:
    import numpy as np
    from bench_guard import shingle_hashes

    if ix._hashes is None and ix._map is None:
        ix._build()
    h = shingle_hashes(tok(text))
    if len(h) == 0 or len(ix._hashes) == 0:
        return 0.0
    pos = np.searchsorted(ix._hashes, h)
    pos[pos >= len(ix._hashes)] = 0
    return float((ix._hashes[pos] == h).mean())


def stage_long9_exclude(a) -> int:
    import yaml
    import build
    from bench_guard import ShingleIndex

    cfg = yaml.safe_load((REPO / "bench/long/corpus.yaml").read_text("utf-8"))
    names = cfg["profiles"]["long9"]["sources"]
    tok = bench_tok()
    ix, n = training_index(tok, a.data, [])
    log(f"training index: {ix.docs} rows/documents, {ix.shingles:,} shingles")
    other = ShingleIndex(tok)
    for prof in ("quick", "full", "long", "long5", "long6", "long7", "long8"):
        for d in read_jsonl(bench_dir() / prof / "docs.jsonl"):
            if d["kind"] in ("benign", "host"):
                other.add(d["text"], f"{prof}:{d['id']}")
    log(f"bench index: {other.docs} documents, {other.shingles:,} shingles")
    rep = {"training_rows": n, "bench_docs": other.docs, "sources": {}}
    excl = {}
    for name in names:
        src = cfg["sources"][name]
        units = build.load_source(name, src, bench_dir() / "src", cfg["sources"])
        drop = []
        for i, u in enumerate(units):
            if ix.check(u)[1]:
                drop.append((i, "training"))
            elif shingle_share(other, tok, u) >= BENCH_NEAR_DUP:
                drop.append((i, "bench_near_dup"))
        excl[name] = [i for i, _ in drop]
        rep["sources"][name] = {"units": len(units), "excluded": len(drop),
                                "by_reason": dict(collections.Counter(r for _, r in drop))}
        log(f"  {name}: {len(units)} units, {len(drop)} excluded {rep['sources'][name]['by_reason']}")
    (a.out / "long9").mkdir(parents=True, exist_ok=True)
    (a.out / "long9" / "exclude_report.json").write_text(json.dumps(rep, indent=1) + "\n", "utf-8")
    if a.write:
        p = REPO / "bench/long/exclude.json"
        ex = json.loads(p.read_text("utf-8"))
        for name, idx in excl.items():
            if idx:
                ex["sources"][name] = idx
            else:
                ex["sources"].pop(name, None)
        note = ("R8c (2026-11-19, RF-f9e76bb6): the sources of the `long9` profile (the R8c holdout) were checked the "
                "same way against arm E's training and validation rows (v4-A, v6, v8e), R8b's persona_neg_train and the "
                "v7 training pool documents, and with R5's near-duplicate rule (20% of the 50-token shingles in a "
                "benign or host document of quick, full, long, long5, long6, long7 or long8). Their units are listed "
                "under their own names. The R8c training rows (L, S) come from other sources and are checked against "
                "the built long9 documents by data/build_r8c.py check.")
        if note not in ex["_comment"]:
            ex["_comment"].append(note)
        p.write_text(json.dumps(ex, indent=1, ensure_ascii=False) + "\n", "utf-8")
        log(f"wrote {p}")
    return 0


# ---------------------------------------------------------------------------------------------------------
# check, sums

def holdout_files(out: Path) -> dict[str, Path]:
    fs = {f"persona3/{lang}": out / "persona3/holdout/direct" / f"{lang}.jsonl" for lang in ("en", "vi")}
    fs["split1"] = out / "split1/split1.json"
    fs["long9/benign"] = out / "long9/benign/docs.jsonl"
    fs["long9/attack"] = out / "long9/attack/docs.jsonl"
    return fs


def stage_check(a) -> int:
    guard = Guard(guarded_sources(a.data, a.train_extra))
    rep: dict = {"guard_sources": guard.counts, "overlap_rule": f"exact, or >= {OVERLAP} of the 8-word shingles",
                 "files": {}}
    bad = 0
    fs = holdout_files(a.out)
    items = []
    for lang in ("en", "vi"):
        items += [(f"persona3/{lang}", r["id"], r["text"]) for r in read_jsonl(fs[f"persona3/{lang}"])]
    items += [("split1", i, t) for i, t in split1_texts(a.out)]
    per: dict = collections.defaultdict(lambda: {"rows": 0, "overlaps": []})
    for f, i, t in items:
        per[f]["rows"] += 1
        h = guard.hit(t)
        if h:
            per[f]["overlaps"].append({"id": i, "kind": h[0], "share": h[1], "source": h[2]})
            bad += 1
    rep["files"].update(per)
    # within persona3 and split1: no row repeats another holdout file's row
    # long9 against the training rows (50-token runs)
    tok = bench_tok()
    ix, n = training_index(tok, a.data, a.train_extra)
    for key in ("long9/benign", "long9/attack"):
        docs = read_jsonl(fs[key])
        hits = []
        for d in docs:
            if d["kind"] == "control":
                continue  # the payload alone: an eval/ dev-half row, checked by eval/'s own rules
            got = ix.check(d["text"])[1]
            if got:
                hits.append({"id": d["id"], "with": got[:3]})
        rep["files"][key] = {"docs": len(docs), "overlaps": hits, "training_rows": n}
        bad += len(hits)
    rep["result"] = "clean" if bad == 0 else f"OVERLAP ({bad})"
    (a.out / "holdout_check.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(json.dumps({k: v for k, v in rep.items() if k != "guard_sources"}, indent=1, ensure_ascii=False)[:4000])
    return 0 if bad == 0 else 1


def stage_sums(a) -> int:
    man = {}
    lines = []
    for key, p in holdout_files(a.out).items():
        s = sha256_file(p)
        if p.suffix == ".json":
            d = json.loads(p.read_text("utf-8"))
            cnt = dict(collections.Counter(f"{c['lang']}:{c['kind']}" for c in d["conversations"]))
        else:
            rs = read_jsonl(p)
            cnt = dict(collections.Counter(f"{r.get('lang')}:{r.get('stratum') or r.get('kind')}" for r in rs))
        man[key] = {"path": str(p.relative_to(a.out)), "sha256": s, "counts": dict(sorted(cnt.items()))}
        lines.append(f"{s}  {p.relative_to(a.out)}")
    (a.out / "SHA256SUMS").write_text("\n".join(lines) + "\n", "utf-8")
    (a.out / "holdouts_manifest.json").write_text(json.dumps(man, indent=1) + "\n", "utf-8")
    log(json.dumps(man, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["persona3", "audit", "split1", "long9-exclude", "check", "sums"])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--data", type=Path, default=REPO.parent / "guardspec-data" if (REPO.parent / "guardspec-data").exists()
                    else Path.home() / "WorkingSpace/AI_R_D/guardspec-data")
    ap.add_argument("--arena", type=Path, help="persona3: local directory of the arena-140k files (data/*.parquet)")
    ap.add_argument("--labels", help="audit: JSON {id: benign|attack|ambiguous}")
    ap.add_argument("--method", default="", help="audit: how the labels were made (recorded in audit.json)")
    ap.add_argument("--write", action="store_true", help="long9-exclude: update bench/long/exclude.json")
    ap.add_argument("--train-extra", action="append", default=[], help="check: further training files (L, S)")
    a = ap.parse_args()
    return {"persona3": stage_persona3, "audit": stage_audit, "split1": stage_split1,
            "long9-exclude": stage_long9_exclude, "check": stage_check, "sums": stage_sums}[a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
