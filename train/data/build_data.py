"""Deterministic builder for the Guard Spec classifier training data (task N6).

    cd train && uv run python data/build_data.py

Downloads four small, pinned, permissively licensed Hugging Face datasets
into train/.cache (gitignored), mixes them with project-written rows from
gen_en.py and gen_vi.py, removes every row that leaks from the eval set, and
writes:

    train/data/train.jsonl   training split
    train/data/val.jsonl     validation / calibration split
    train/data/stats.json    counts per label, language, source; leakage report

Leakage guard (eval/README.md): a row is dropped when the sha256 of its
normalized text is in eval/fingerprints.txt, or when its character 5-gram
Jaccard similarity with any eval text (same normalization) is above 0.8.
The eval set is read only for this filter; nothing is trained or tuned on it.

Every random choice is seeded from common.SEED plus a section name.
"""

from __future__ import annotations

import collections
import csv
import gzip
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
from huggingface_hub import hf_hub_download
from scipy import sparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_en  # noqa: E402
import gen_vi  # noqa: E402
from common import (LABELS, fingerprint, leet, normalize_for_fingerprint, rng, shingles,  # noqa: E402
                    strip_diacritics, teencode_vi)

DATA = Path(__file__).resolve().parent
TRAIN_ROOT = DATA.parent
REPO = TRAIN_ROOT.parent
CACHE = TRAIN_ROOT / ".cache" / "hf"
EVAL = REPO / "eval"

VAL_PCT = 12
JACCARD_MAX = 0.8

# ---------------------------------------------------------------------------
# Sources (licenses verified on the dataset cards at these revisions)
# ---------------------------------------------------------------------------

DEEPSET = dict(key="deepset/prompt-injections", license="Apache-2.0",
               revision="4f61ecb038e9c3fb77e21034b22511b523772cdd",
               file="data/train-00000-of-00001-9564e8b05b4757ab.parquet")
GANDALF = dict(key="Lakera/gandalf_ignore_instructions", license="MIT",
               revision="04737b65e90a6794ec227012e4a255a7def6344b",
               file="data/train-00000-of-00001-ded53be747ff55cd.parquet")
JAILBREAK = dict(key="jackhhao/jailbreak-classification", license="Apache-2.0",
                 revision="2f2ceeb39658696fd3f462403562b6eea5306287",
                 file="balanced/jailbreak_dataset_train_balanced.csv")
OASST2 = dict(key="OpenAssistant/oasst2", license="Apache-2.0",
              revision="179dd21fc55192153d94adb0e0ce8f69e222bf75",
              file="2023-11-05_oasst2_prompts.messages.jsonl.gz")
PROJECT, PROJECT_LICENSE = "guard-spec", "Apache-2.0"

OASST_EN_N = 3200


def fetch(src) -> Path:
    return Path(hf_hub_download(src["key"], src["file"], repo_type="dataset", revision=src["revision"],
                                cache_dir=str(CACHE)))


# ---------------------------------------------------------------------------
# Labeling heuristics for source rows (documented in train/LABELING.md)
# ---------------------------------------------------------------------------

NON_ENGLISH = re.compile(r"[äöüßÄÖÜЀ-ӿ]")
NON_ENGLISH_WORDS = {
    "ich", "sie", "und", "der", "das", "ist", "nicht", "wie", "mit", "zu", "auf", "mir", "dich", "du", "wir",
    "ein", "eine", "dem", "sich", "gibt", "welche", "auch", "oder", "aber", "bitte", "jetzt", "alle", "alles",
    "frage", "schreibe", "antworte", "geld", "viel", "deutschland", "europa", "wieviele", "einem", "vergiss",
    "yo", "tu", "dices", "todo", "que", "dije", "olvide", "si", "eres", "por", "para", "como", "una",
    "warum", "macht", "gute", "aus", "worum", "geht", "es", "bei", "passiert", "wer", "wird",
    "ihr", "uns", "kann", "kannst", "sind", "habe", "hast", "mich", "zum", "zur", "vom", "fur", "uber",
    "wohnungsmarkt", "mieten", "nach", "noch", "schon", "sehr", "gut", "heute", "zaboravi", "sve", "instrukcije",
}


def is_english(text: str) -> bool:
    if NON_ENGLISH.search(text):
        return False
    return not (set(re.findall(r"[a-zA-Z]+", text.lower())) & NON_ENGLISH_WORDS)


RE_OVERRIDE = re.compile(r"\b(ignor\w*|disregard\w*|forget\w*|forgot|overrid\w*|bypass\w*|skip|stop following|"
                         r"cancel\w*|defy|new (task|instruction|programming)s?|from now on|instead|no longer)\b", re.I)
RE_JAILBREAK = re.compile(r"\b(act as|acting as|pretend|role ?play|(now )?you are (now )?(a|an|the|my) |now you are|"
                          r"you are no longer|dan\b|developer mode|no (restrictions|limits|filters|rules)|unfiltered|"
                          r"uncensored|hypothetical|stay in character|simulate|amnesia|theoretical world)", re.I)
RE_EXTRACT = re.compile(r"\b(password|passcode|pass ?phrase|secret|embeddings|the word you|forbidden word)\b|"
                        r"\b(reveal|repeat|write) (it|anything|everything)\b|"
                        r"\b(reveal|repeat|print|show|tell|give|spell|rewrite|write|share|output|list|quote|clarify|"
                        r"respond with|what (are|were|is|was))\b.{0,40}\b(instructions?|prompts?|rules|guidelines|directions|"
                        r"system message|first (sentence|statement|line))\b", re.I)
RE_EXFIL = re.compile(r"\b(send|email|forward|upload|post)\b.*\b(history|conversation|data|keys?|credentials|emails?)\b|"
                      r"!\[[^\]]*\]\(http", re.I)
# Obfuscation is a property of the *form* of the input (see LABELING.md), not of words like "backwards".
RE_OBFUSC = re.compile(r"[\u200b-\u200d\u2060\U000e0000-\U000e007f]|(?:\b\w\s){6,}|[A-Za-z0-9+/]{24,}={0,2}")
RE_LEET_WORD = re.compile(r"\b\w*[a-z][0134579][a-z]\w*\b", re.I)


def categorize_source(text: str) -> list[str]:
    t = text.replace("prompt injection", "")
    labels = []
    if RE_JAILBREAK.search(t):
        labels.append("jailbreak")
    if RE_EXTRACT.search(t):
        labels.append("prompt_extraction")
    if RE_EXFIL.search(t):
        labels.append("data_exfiltration")
    if is_obfuscated(t):
        labels.append("obfuscation")
    if RE_OVERRIDE.search(t) or not labels:
        labels.append("direct_injection")
    return sorted(set(labels))


def is_obfuscated(t: str) -> bool:
    return bool(RE_OBFUSC.search(t)) or len(RE_LEET_WORD.findall(t)) >= 3


RE_OASST_DROP = re.compile(
    r"(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all|your)\b.{0,30}\b(instructions?|rules|prompts?|guidelines)|"
    r"\bDAN\b|jailbr(?!.{0,40}(phone|iphone|ios|android|switch|console|ps\d|kindle))|developer mode|"
    r"no (restrictions|filters|limits|rules)|system prompt|stay in character|uncensored|unfiltered|"
    r"pretend (you are|to be) (an? )?(ai|chatbot|evil)", re.I)


# ---------------------------------------------------------------------------
# Row collection
# ---------------------------------------------------------------------------

class Collector:
    def __init__(self):
        self.rows: list[dict] = []

    def add(self, text, labels, lang, variant, source, license_, group):
        text = unicodedata.normalize("NFC", text).strip()
        if not text:
            return
        labels = sorted(set(labels))
        assert all(lb in LABELS for lb in labels), labels
        assert ("benign" in labels) == (labels == ["benign"]), labels
        self.rows.append(dict(text=text, labels=labels, lang=lang, variant=variant, source=source,
                              license=license_, group=group))


def load_sources(c: Collector, counts):
    # deepset train ---------------------------------------------------------------
    for i, r in enumerate(pq.read_table(fetch(DEEPSET)).to_pylist()):
        text = r["text"].strip()
        if not is_english(text):
            counts["deepset_non_english_skipped"] += 1
            continue
        labels = categorize_source(text) if r["label"] == 1 else ["benign"]
        c.add(text, labels, "en", "orig", DEEPSET["key"] + ":train", DEEPSET["license"], f"deepset.{i}")
    # gandalf train (all attacks) ----------------------------------------------------
    for i, r in enumerate(pq.read_table(fetch(GANDALF)).to_pylist()):
        text = r["text"].strip()
        if not is_english(text):
            counts["gandalf_non_english_skipped"] += 1
            continue
        c.add(text, categorize_source(text), "en", "orig", GANDALF["key"] + ":train", GANDALF["license"], f"gandalf.{i}")
    # jailbreak-classification train ------------------------------------------------
    with open(fetch(JAILBREAK), encoding="utf-8", newline="") as f:
        for i, r in enumerate(csv.DictReader(f)):
            text = r["prompt"].strip()
            if not text or not is_english(text):
                counts["jailbreak_cls_skipped"] += 1
                continue
            labels = ["jailbreak"] if r["type"] == "jailbreak" else ["benign"]
            if labels == ["jailbreak"] and is_obfuscated(text):
                labels.append("obfuscation")
            c.add(text, labels, "en", "orig", JAILBREAK["key"] + ":train", JAILBREAK["license"], f"jbcls.{i}")
    # oasst2 prompts: English sample + all Vietnamese, benign --------------------------
    en, vi = [], []
    with gzip.open(fetch(OASST2), "rt", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            if d.get("deleted") or d.get("review_result") is False or d.get("role") != "prompter":
                continue
            text = (d.get("text") or "").strip()
            if not (12 <= len(text) <= 1500):
                continue
            tox = (d.get("detoxify") or {}).get("toxicity") or 0
            if tox > 0.5:
                counts["oasst_toxic_skipped"] += 1
                continue
            if RE_OASST_DROP.search(text):
                counts["oasst_attacklike_skipped"] += 1
                continue
            if d.get("lang") == "en":
                en.append((d["message_id"], text))
            elif d.get("lang") == "vi":
                vi.append((d["message_id"], text))
    en.sort()
    rng("oasst.en").shuffle(en)
    for mid, text in en[:OASST_EN_N]:
        c.add(text, ["benign"], "en", "orig", OASST2["key"] + ":prompts", OASST2["license"], f"oasst.{mid}")
    return vi


def add_vi_variants(c, bases, section, source=PROJECT, license_=PROJECT_LICENSE, teen=0.5, leet_frac=0.25):
    r_t, r_l = rng(section + ".teen"), rng(section + ".leet")
    for b in bases:
        text, labels, g = b["text"], b["labels"], b["group"]
        c.add(text, labels, "vi", "orig", source, license_, g)
        if strip_diacritics(text) != text:
            c.add(strip_diacritics(text), labels, "vi", "no_diacritics", source, license_, g)
        if r_t.random() < teen:
            c.add(teencode_vi(text, g), labels, "vi", "teencode", source, license_, g)
        if r_l.random() < leet_frac:
            lab = labels if labels == ["benign"] else labels + ["obfuscation"]
            c.add(leet(text, g), lab, "vi", "leet", source, license_, g)


def build(c: Collector, counts):
    vi_oasst = load_sources(c, counts)

    # English project rows ------------------------------------------------------------
    en_attack = (gen_en.direct() + gen_en.jailbreak() + gen_en.extraction() + gen_en.exfil() + gen_en.indirect() +
                 gen_en.tool_poisoning())
    r_l = rng("en.leet")
    for b in en_attack:
        c.add(b["text"], b["labels"], "en", b["variant"], PROJECT, PROJECT_LICENSE, b["group"])
        if r_l.random() < 0.12:
            c.add(leet(b["text"], b["group"]), b["labels"] + ["obfuscation"], "en", "leet", PROJECT, PROJECT_LICENSE, b["group"])
    for b in gen_en.obfuscation():
        c.add(b["text"], b["labels"], "en", b["variant"], PROJECT, PROJECT_LICENSE, b["group"])
    r_l = rng("en.benign.leet")
    for b in gen_en.hard_benign():
        c.add(b["text"], b["labels"], "en", b["variant"], PROJECT, PROJECT_LICENSE, b["group"])
        if r_l.random() < 0.04:
            c.add(leet(b["text"], b["group"]), ["benign"], "en", "leet", PROJECT, PROJECT_LICENSE, b["group"])

    # Vietnamese project rows --------------------------------------------------------------
    vi_attack = (gen_vi.direct() + gen_vi.jailbreak() + gen_vi.extraction() + gen_vi.exfil() + gen_vi.indirect() +
                 gen_vi.tool_poisoning())
    add_vi_variants(c, vi_attack, "vi.attack", teen=0.5, leet_frac=0.25)
    for b in gen_vi.obfuscation():
        c.add(b["text"], b["labels"], "vi", "orig", PROJECT, PROJECT_LICENSE, b["group"])
    add_vi_variants(c, gen_vi.hard_benign(), "vi.benign", teen=0.45, leet_frac=0.10)
    oasst_bases = [dict(text=t, labels=["benign"], group=f"oasst.{mid}") for mid, t in sorted(vi_oasst)]
    add_vi_variants(c, oasst_bases, "vi.oasst", source=OASST2["key"] + ":prompts", license_=OASST2["license"],
                    teen=0.3, leet_frac=0.0)


# ---------------------------------------------------------------------------
# Leakage guard and dedupe
# ---------------------------------------------------------------------------

def load_eval():
    fps = {ln.strip() for ln in (EVAL / "fingerprints.txt").read_text(encoding="utf-8").splitlines()
           if ln.strip() and not ln.startswith("#")}
    texts = []
    for lang in ("en", "vi"):
        with open(EVAL / "data" / f"{lang}.jsonl", encoding="utf-8") as f:
            texts += [json.loads(ln)["text"] for ln in f]
    return fps, texts


def _shingle_matrix(texts, vocab, grow):
    indptr, idx = [0], []
    for t in texts:
        ids = set()
        for s in shingles(t):
            j = vocab.get(s)
            if j is None and grow:
                j = vocab[s] = len(vocab)
            if j is not None:
                ids.add(j)
        idx += sorted(ids)
        indptr.append(len(idx))
    return idx, indptr


def max_jaccard(train_texts, eval_texts):
    vocab: dict[str, int] = {}
    e_idx, e_ptr = _shingle_matrix(eval_texts, vocab, grow=True)
    E = sparse.csr_matrix((np.ones(len(e_idx), dtype=np.float32), e_idx, e_ptr), shape=(len(eval_texts), len(vocab)))
    e_size = np.diff(e_ptr).astype(np.float32)
    t_size = np.array([len(shingles(t)) for t in train_texts], dtype=np.float32)
    t_idx, t_ptr = _shingle_matrix(train_texts, vocab, grow=False)
    T = sparse.csr_matrix((np.ones(len(t_idx), dtype=np.float32), t_idx, t_ptr), shape=(len(train_texts), E.shape[1]))
    best = np.zeros(len(train_texts), dtype=np.float32)
    for start in range(0, len(train_texts), 2000):
        inter = (T[start:start + 2000] @ E.T).toarray()
        union = t_size[start:start + 2000, None] + e_size[None, :] - inter
        best[start:start + 2000] = (inter / np.maximum(union, 1)).max(axis=1)
    return best


def leakage_filter(rows, counts):
    fps, eval_texts = load_eval()
    kept = []
    for r in rows:
        if fingerprint(r["text"]) in fps:
            counts[f"leak_fingerprint:{r['source'].split(':')[0]}"] += 1
            counts["leak_fingerprint_total"] += 1
        else:
            kept.append(r)
    jac = max_jaccard([r["text"] for r in kept], eval_texts)
    out = []
    for r, j in zip(kept, jac):
        if j > JACCARD_MAX:
            counts[f"leak_jaccard:{r['source'].split(':')[0]}"] += 1
            counts["leak_jaccard_total"] += 1
        else:
            out.append(r)
    return out


def dedupe(rows, counts):
    by_text = collections.defaultdict(list)
    for r in rows:
        by_text[r["text"]].append(r)
    out = []
    for text, rs in by_text.items():
        benign = {("benign" in r["labels"]) for r in rs}
        if len(benign) > 1:
            counts["dedupe_conflicting_label_dropped"] += len(rs)
            continue
        counts["dedupe_exact_dropped"] += len(rs) - 1
        first = rs[0]
        first["labels"] = sorted(set().union(*[r["labels"] for r in rs]))
        out.append(first)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    counts = collections.Counter()
    c = Collector()
    build(c, counts)
    counts["generated"] = len(c.rows)
    rows = dedupe(c.rows, counts)
    rows = leakage_filter(rows, counts)
    # Restore a deterministic order and assign ids.
    rows.sort(key=lambda r: (r["lang"], r["group"], r["variant"], r["text"]))
    for r in rows:
        r["id"] = f"{r['lang']}-{hashlib.sha256(r['text'].encode('utf-8')).hexdigest()[:12]}"
    split = {"train": [], "val": []}
    for r in rows:
        h = int(hashlib.sha256(f"split:{r['group']}".encode()).hexdigest(), 16) % 100
        split["val" if h < VAL_PCT else "train"].append(r)
    for name, rs in split.items():
        with open(DATA / f"{name}.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for r in rs:
                f.write(json.dumps({k: r[k] for k in ("id", "text", "labels", "lang", "variant", "source", "license", "group")},
                                   ensure_ascii=False) + "\n")

    stats = {"counts": dict(sorted(counts.items())), "splits": {}}
    for name, rs in split.items():
        per = collections.Counter()
        for r in rs:
            per[f"{r['lang']}/rows"] += 1
            for lb in r["labels"]:
                per[f"{r['lang']}/{lb}"] += 1
            per[f"{r['lang']}/variant:{r['variant']}"] += 1
            per[f"source:{r['source'].split(':')[0]}"] += 1
        stats["splits"][name] = dict(sorted(per.items()))
        stats["splits"][name]["rows"] = len(rs)
    (DATA / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
