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
import os
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
import gen_hardneg  # noqa: E402
import gen_holdout_v3  # noqa: E402
import gen_v3  # noqa: E402
import gen_vi  # noqa: E402
import gen_vi_v2  # noqa: E402
from common import (LABELS, fingerprint, leet, normalize_for_fingerprint, rng, shingles,  # noqa: E402
                    strip_diacritics, teencode_v2, teencode_vi)

DATA = Path(__file__).resolve().parent
TRAIN_ROOT = DATA.parent
REPO = TRAIN_ROOT.parent
CACHE = TRAIN_ROOT / ".cache" / "hf"
EVAL = REPO / "eval"
EXEMPLARS = REPO / "internal" / "inference" / "ml" / "exemplars" / "default.jsonl"

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
# v3: real English prompts (first user turn), CC-BY-4.0 with attribution in DATA_LICENSES.md.
HELPSTEER2 = dict(key="nvidia/HelpSteer2", license="CC-BY-4.0",
                  revision="990b2711a36180dd19d9c94b8627844866f8982a", file="train.jsonl.gz")
PROJECT, PROJECT_LICENSE = "guard-spec", "Apache-2.0"
# v3: realistic EN/VI rows written row by row by an AI model for this project (data/realistic/README.md),
# Apache-2.0. GUARD_V3_REALISTIC=0 keeps its rows out of the training split only (the "without" arm of the
# v3 comparison); the 12% of its scenarios that the group hash sends to `val` stay there in both arms;
# the hold-out file is always built as `val_realistic_holdout` and never used for selection or calibration.
REALISTIC_SOURCE = PROJECT + ":realistic-fable"
REALISTIC_TRAIN = DATA / "realistic" / "realistic_train.jsonl"
REALISTIC_HOLDOUT = DATA / "realistic" / "realistic_holdout.jsonl"
USE_REALISTIC = os.environ.get("GUARD_V3_REALISTIC", "1") != "0"

OASST_EN_N = 3800  # v1: 3200. v2 takes more so that English `orig` reaches TARGET_RATIO without dropping attacks.
# v2: benign-to-attack ratio that every (language, variant) cell of the training split is brought to
# (balance_variants). v2 used 1.5 everywhere. v3 raises it to 2.0 for English, which gained hard
# negatives (gen_v3) and real prompts (HelpSteer2), and to 1.75 for Vietnamese, the most its
# no-diacritics and teencode cells can reach without dropping attacks; every variant of a language
# keeps the same ratio, so the surface form still carries no label signal.
TARGET_RATIO = {"en": 2.0, "vi": 1.75}
HELPSTEER_N = 2500
# Jailbreak-like role-play to drop from HelpSteer2 prompts (they are labelled benign by us).
RE_HS_DROP = re.compile(r"\b(no|without( any)?) (moral|ethic|filter|restriction|limit|guideline|rule|censor)\w*|"
                        r"\bbad AI\b|\bevil\b|\bDAN\b|jailbr|developer mode|\bunfiltered\b|\buncensored\b|"
                        r"ignore (all|any|your|previous|prior)\b.{0,30}\b(instructions?|rules|guidelines|prompts?)", re.I)


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
    load_helpsteer(c, counts)
    return vi


def load_helpsteer(c: Collector, counts):
    """v3: first user turn of nvidia/HelpSteer2 train prompts (real ShareGPT-style requests: role-play,
    technical and business writing). Benign; jailbreak-like role-play and non-English rows are dropped."""
    seen, keep = set(), []
    with gzip.open(fetch(HELPSTEER2), "rt", encoding="utf-8") as f:
        for line in f:
            text = json.loads(line)["prompt"].split("<extra_id_1>")[0].strip()
            if text in seen:
                continue
            seen.add(text)
            if not (12 <= len(text) <= 1500) or not is_english(text):
                counts["helpsteer_len_or_lang_skipped"] += 1
                continue
            if RE_HS_DROP.search(text) or RE_OASST_DROP.search(text):
                counts["helpsteer_attacklike_skipped"] += 1
                continue
            keep.append(text)
    keep.sort()
    rng("helpsteer").shuffle(keep)
    for text in keep[:HELPSTEER_N]:
        g = "hs2." + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        c.add(text, ["benign"], "en", "orig", HELPSTEER2["key"] + ":train", HELPSTEER2["license"], g)


# v1: identical variant rates for benign and attack rows, so that "no diacritics", "teencode",
# "leet" or "partly stripped diacritics" carry no information about the label.
VI_TEEN, VI_LEET, VI_PARTIAL, EN_LEET = 0.5, 0.2, 0.35, 0.08
# v2: a second teencode copy with the randomized v2 spelling (common.teencode_v2, table A), same rate
# for benign and attack bases.
VI_TEEN2 = 0.5


def partial_diacritics(text: str, key: str) -> str:
    """Strip diacritics on some lines only (e.g. a document whose header kept its accents)."""
    r = rng(f"partial:{key}")
    lines = text.split("\n")
    keep = r.randrange(len(lines))
    return "\n".join(ln if i == keep or r.random() < 0.3 else strip_diacritics(ln) for i, ln in enumerate(lines))


def add_vi_variants(c, bases, section, source=PROJECT, license_=PROJECT_LICENSE, teen=VI_TEEN, leet_frac=VI_LEET,
                    teen2=VI_TEEN2):
    r_t, r_l, r_p = rng(section + ".teen"), rng(section + ".leet"), rng(section + ".partial")
    r_t2 = rng(section + ".teen2")
    for b in bases:
        text, labels, g = b["text"], b["labels"], b["group"]
        c.add(text, labels, "vi", "orig", source, license_, g)
        if "\n" in text and r_p.random() < VI_PARTIAL:
            pt = partial_diacritics(text, g)
            if pt != text and pt != strip_diacritics(text):
                c.add(pt, labels, "vi", "partial_diacritics", source, license_, g)
        if strip_diacritics(text) != text:
            c.add(strip_diacritics(text), labels, "vi", "no_diacritics", source, license_, g)
        if r_t.random() < teen:
            c.add(teencode_vi(text, g), labels, "vi", "teencode", source, license_, g)
        if r_t2.random() < teen2:
            c.add(teencode_v2(text, g, "A"), labels, "vi", "teencode", source, license_, g)
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
        if r_l.random() < EN_LEET:
            c.add(leet(b["text"], b["group"]), b["labels"] + ["obfuscation"], "en", "leet", PROJECT, PROJECT_LICENSE, b["group"])
    for b in gen_en.obfuscation():
        c.add(b["text"], b["labels"], "en", b["variant"], PROJECT, PROJECT_LICENSE, b["group"])
    r_l = rng("en.benign.leet")
    for b in gen_en.hard_benign():
        c.add(b["text"], b["labels"], "en", b["variant"], PROJECT, PROJECT_LICENSE, b["group"])
        if r_l.random() < EN_LEET:
            c.add(leet(b["text"], b["group"]), ["benign"], "en", "leet", PROJECT, PROJECT_LICENSE, b["group"])

    # Vietnamese project rows --------------------------------------------------------------
    vi_attack = (gen_vi.direct() + gen_vi.jailbreak() + gen_vi.extraction() + gen_vi.exfil() + gen_vi.indirect() +
                 gen_vi.tool_poisoning())
    add_vi_variants(c, vi_attack, "vi.attack")
    for b in gen_vi.obfuscation():
        c.add(b["text"], b["labels"], "vi", "orig", PROJECT, PROJECT_LICENSE, b["group"])
    add_vi_variants(c, gen_vi.hard_benign(), "vi.benign")
    oasst_bases = [dict(text=t, labels=["benign"], group=f"oasst.{mid}") for mid, t in sorted(vi_oasst)]
    # v2: every oasst2 Vietnamese prompt also gets a v2 teencode copy, and single sentences of
    # multi-sentence prompts become extra bases (same group, so they land in the same split).
    oasst_bases += oasst_sentences(oasst_bases)
    add_vi_variants(c, oasst_bases, "vi.oasst", source=OASST2["key"] + ":prompts", license_=OASST2["license"],
                    leet_frac=0.0, teen2=1.0)
    add_hardneg(c, "train")
    add_vi_variants(c, gen_vi_v2.generate("train"), "v2.vi.train", source=PROJECT + ":v2")
    add_v3(c, gen_v3.generate("train"), "train", PROJECT + ":v3")
    add_realistic(c, REALISTIC_TRAIN, counts)


VARIANTS = {"orig", "no_diacritics", "teencode", "leet", "partial_diacritics"}


def add_realistic(c, path, counts):
    """v3: realistic rows as written (their no-diacritics and teencode rows are their own texts, so no
    transforms are added). The schema is checked; group ids are kept, so the train/val split by group
    hash keeps each scenario on one side."""
    with open(path, encoding="utf-8") as f:
        for ln in f:
            r = json.loads(ln)
            assert set(r) >= {"id", "text", "labels", "lang", "variant", "source", "license", "group"}, r.keys()
            assert r["lang"] in ("en", "vi") and r["variant"] in VARIANTS, r
            assert r["source"] == REALISTIC_SOURCE and r["license"] == "Apache-2.0", r
            c.add(r["text"], r["labels"], r["lang"], r["variant"], r["source"], r["license"], r["group"])
            counts[f"realistic:{path.stem}"] += 1


def add_v3(c, rows, split, src):
    """v3 generator rows (gen_v3 sets A/B, gen_holdout_v3 set C). Training: English rows get leet copies
    at EN_LEET and Vietnamese rows the usual variants. Validation splits: every Vietnamese base gets an
    orig, a no-diacritics and a teencode (table B, held-out spellings) copy; English rows stay orig."""
    en = [b for b in rows if b["lang"] == "en"]
    vi = [b for b in rows if b["lang"] == "vi"]
    r_l = rng(f"v3.en.leet.{split}")
    for b in en:
        c.add(b["text"], b["labels"], "en", "orig", src, PROJECT_LICENSE, b["group"])
        if split == "train" and r_l.random() < EN_LEET:
            lab = b["labels"] if b["labels"] == ["benign"] else b["labels"] + ["obfuscation"]
            c.add(leet(b["text"], b["group"]), lab, "en", "leet", src, PROJECT_LICENSE, b["group"])
    if split == "train":
        add_vi_variants(c, vi, f"v3.vi.{split}", source=src)
        return
    for b in vi:
        g = b["group"]
        c.add(b["text"], b["labels"], "vi", "orig", src, PROJECT_LICENSE, g)
        c.add(strip_diacritics(b["text"]), b["labels"], "vi", "no_diacritics", src, PROJECT_LICENSE, g)
        c.add(teencode_v2(b["text"], f"{g}.v3", "B"), b["labels"], "vi", "teencode", src, PROJECT_LICENSE, g)


RE_SENT = re.compile(r"(?<=[.!?])\s+")


def oasst_sentences(bases, max_per=2):
    out = []
    for b in bases:
        sents = [s.strip() for s in RE_SENT.split(b["text"]) if 20 <= len(s.strip()) <= 300]
        if len(sents) < 2:
            continue
        out += [dict(text=s, labels=["benign"], group=b["group"]) for s in sents[:max_per]]
    return out


def drop_priority(x):
    """v3: which benign rows balance_variants drops first. 0: rows from general-purpose sources
    (oasst2, HelpSteer2, jailbreak-classification, deepset); 1: project template rows; hard negatives
    (v1 `hardneg`, v2, v3 generators) are never dropped."""
    src = x["source"]
    if src in (PROJECT + ":hardneg", PROJECT + ":v2", PROJECT + ":v3", REALISTIC_SOURCE):
        return 2
    return 1 if src == PROJECT else 0


def balance_variants(rows, target, counts, section="balance"):
    """Bring every (lang, variant) cell to benign:attack == target[lang] (v2; v3: per language).

    Attack rows are never dropped. A cell with too many benign rows loses benign rows at random,
    general-purpose source rows first (v3, `drop_priority`); minimal-pair rows are kept, so the pairs
    stay intact, and so are the L3 exemplar rows of internal/inference/ml/exemplars, which must stay
    training rows. A cell with too few gets benign transforms of the same language's `orig` benign
    rows of the split (leet, no diacritics, v2 teencode, partly stripped diacritics), which keep their
    base row's group.
    """
    r = rng(section)
    keep_ids = {json.loads(ln)["id"] for ln in EXEMPLARS.read_text(encoding="utf-8").splitlines() if ln.strip()}
    cells = collections.defaultdict(lambda: ([], []))
    for x in rows:
        cells[(x["lang"], x["variant"])][x["labels"] != ["benign"]].append(x)
    texts = {x["text"] for x in rows}
    drop, added = set(), []
    transforms = {
        "leet": lambda t, g: leet(t, g + ".bal"),
        "no_diacritics": lambda t, g: strip_diacritics(t),
        "teencode": lambda t, g: teencode_v2(t, g + ".bal", "A"),
        "partial_diacritics": lambda t, g: partial_diacritics(t, g + ".bal") if "\n" in t else t,
    }
    for (lang, variant), (ben, atk) in sorted(cells.items()):
        want = round(target[lang] * len(atk))
        if len(ben) > want:
            pool = sorted((x for x in ben if ".pair." not in x["group"] and x["id"] not in keep_ids
                           and drop_priority(x) < 2), key=lambda x: x["text"])
            r.shuffle(pool)
            pool.sort(key=drop_priority)  # stable: random order within a priority class
            k = min(len(ben) - want, len(pool))
            drop.update(id(x) for x in pool[:k])
            counts[f"balance:{lang}/{variant}:benign_dropped"] += k
        elif len(ben) < want:
            fn = transforms.get(variant)
            n = 0
            if fn is not None:
                src = sorted(cells[(lang, "orig")][0], key=lambda x: x["text"])
                r.shuffle(src)
                for x in src:
                    if n >= want - len(ben):
                        break
                    t = unicodedata.normalize("NFC", fn(x["text"], x["group"])).strip()
                    if t == x["text"] or t in texts:
                        continue
                    texts.add(t)
                    added.append(dict(x, text=t, variant=variant))
                    n += 1
            counts[f"balance:{lang}/{variant}:benign_added"] += n
            counts[f"balance:{lang}/{variant}:benign_short"] += want - len(ben) - n
    return [x for x in rows if id(x) not in drop], added


def add_hardneg(c, split):
    """v1 generators (gen_hardneg). Template set A for training, B for the hard validation split."""
    src = PROJECT + (":hardneg" if split == "train" else ":hardneg-val")
    rows = gen_hardneg.generate(split)
    r_l = rng(f"hn.en.leet.{split}")
    for b in rows:
        if b["lang"] == "en":
            c.add(b["text"], b["labels"], "en", "orig", src, PROJECT_LICENSE, b["group"])
            if r_l.random() < EN_LEET:
                lab = b["labels"] if b["labels"] == ["benign"] else b["labels"] + ["obfuscation"]
                c.add(leet(b["text"], b["group"]), lab, "en", "leet", src, PROJECT_LICENSE, b["group"])
    add_vi_variants(c, [b for b in rows if b["lang"] == "vi"], f"hn.vi.{split}", source=src)


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


MAX_JACCARD = {}  # v3: highest kept 5-gram Jaccard with any eval text, per tag (stats.json)


def leakage_filter(rows, counts, tag=None):
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
    if tag is not None:
        for r, j in zip(kept, jac):
            if j <= JACCARD_MAX:
                for key in (tag, f"{tag}|{r['source']}"):
                    MAX_JACCARD[key] = round(max(MAX_JACCARD.get(key, 0.0), float(j)), 4)
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
    rows = leakage_filter(rows, counts, tag="train+val")
    # Restore a deterministic order and assign ids.
    rows.sort(key=lambda r: (r["lang"], r["group"], r["variant"], r["text"]))
    for r in rows:
        r["id"] = f"{r['lang']}-{hashlib.sha256(r['text'].encode('utf-8')).hexdigest()[:12]}"
    split = {"train": [], "val": [], "val_hard": [], "val_vi_variants": []}
    for r in rows:
        h = int(hashlib.sha256(f"split:{r['group']}".encode()).hexdigest(), 16) % 100
        split["val" if h < VAL_PCT else "train"].append(r)
    if not USE_REALISTIC:
        n0 = len(split["train"])
        split["train"] = [r for r in split["train"] if r["source"] != REALISTIC_SOURCE]
        counts["realistic_left_out_of_train"] = n0 - len(split["train"])
    # v2: every (language, variant) cell of the training split gets the same benign:attack ratio.
    # Rows added here are transforms of training rows; they get the leakage check below.
    kept, added = balance_variants(split["train"], TARGET_RATIO, counts)
    split["train"] = kept + leakage_filter(added, counts, tag="train+val")
    split["train"].sort(key=lambda r: (r["lang"], r["group"], r["variant"], r["text"]))
    for r in split["train"]:
        r["id"] = f"{r['lang']}-{hashlib.sha256(r['text'].encode('utf-8')).hexdigest()[:12]}"

    # Hard validation split: v1 generators with template set B, never used for training.
    hv = Collector()
    add_hardneg(hv, "val")
    hcounts = collections.Counter()
    hrows = leakage_filter(dedupe(hv.rows, hcounts), hcounts, tag="val_hard")
    train_texts = {r["text"] for r in rows}
    hrows = [r for r in hrows if r["text"] not in train_texts]
    for k, v in hcounts.items():
        counts[f"val_hard:{k}"] += v
    hrows.sort(key=lambda r: (r["lang"], r["group"], r["variant"], r["text"]))
    for r in hrows:
        r["id"] = f"{r['lang']}-{hashlib.sha256(r['text'].encode('utf-8')).hexdigest()[:12]}"
    split["val_hard"] = hrows

    # v2: Vietnamese variant validation split from gen_vi_v2 template set B. Every base gets an
    # orig, a no-diacritics and two teencode copies; teencode uses table B, whose extra spellings
    # training never sees. Used for early stopping and calibration together with val and val_hard.
    vv = Collector()
    src = PROJECT + ":v2-val"
    for b in gen_vi_v2.generate("val"):
        g = b["group"]
        vv.add(b["text"], b["labels"], "vi", "orig", src, PROJECT_LICENSE, g)
        vv.add(strip_diacritics(b["text"]), b["labels"], "vi", "no_diacritics", src, PROJECT_LICENSE, g)
        for k in range(2):
            vv.add(teencode_v2(b["text"], f"{g}.{k}", "B"), b["labels"], "vi", "teencode", src, PROJECT_LICENSE, g)
    vcounts = collections.Counter()
    vrows = leakage_filter(dedupe(vv.rows, vcounts), vcounts, tag="val_vi_variants")
    seen = train_texts | {r["text"] for r in split["train"]} | {r["text"] for r in hrows}
    vrows = [r for r in vrows if r["text"] not in seen]
    for k, v in vcounts.items():
        counts[f"val_vi_variants:{k}"] += v
    vrows.sort(key=lambda r: (r["lang"], r["group"], r["variant"], r["text"]))
    for r in vrows:
        r["id"] = f"{r['lang']}-{hashlib.sha256(r['text'].encode('utf-8')).hexdigest()[:12]}"
    split["val_vi_variants"] = vrows

    # v3: `val_v3` (gen_v3 template set B; selection and calibration, with the splits above) and
    # `val_v3_holdout` (gen_holdout_v3 template set C; scored once at the end, never used for
    # selection or calibration).
    seen = seen | {r["text"] for r in vrows}
    for name, gen_rows, src in (("val_v3", gen_v3.generate("val"), PROJECT + ":v3-val"),
                                ("val_v3_holdout", gen_holdout_v3.generate(), PROJECT + ":v3-holdout")):
        xc = Collector()
        add_v3(xc, gen_rows, "val", src)
        xcounts = collections.Counter()
        xrows = leakage_filter(dedupe(xc.rows, xcounts), xcounts, tag=name)
        xrows = [r for r in xrows if r["text"] not in seen]
        seen = seen | {r["text"] for r in xrows}
        for k, v in xcounts.items():
            counts[f"{name}:{k}"] += v
        xrows.sort(key=lambda r: (r["lang"], r["group"], r["variant"], r["text"]))
        for r in xrows:
            r["id"] = f"{r['lang']}-{hashlib.sha256(r['text'].encode('utf-8')).hexdigest()[:12]}"
        split[name] = xrows
    # v3: realistic hold-out (data/realistic, disjoint scenarios and organisations), as written.
    xc = Collector()
    add_realistic(xc, REALISTIC_HOLDOUT, counts)
    xcounts = collections.Counter()
    xrows = leakage_filter(dedupe(xc.rows, xcounts), xcounts, tag="val_realistic_holdout")
    xrows = [r for r in xrows if r["text"] not in seen]
    for k, v in xcounts.items():
        counts[f"val_realistic_holdout:{k}"] += v
    xrows.sort(key=lambda r: (r["lang"], r["group"], r["variant"], r["text"]))
    for r in xrows:
        r["id"] = f"{r['lang']}-{hashlib.sha256(r['text'].encode('utf-8')).hexdigest()[:12]}"
    split["val_realistic_holdout"] = xrows
    # Independence of the hold-outs from everything used for training, selection and calibration
    # (the realistic training file counts as used even when GUARD_V3_REALISTIC=0).
    used = [r["text"] for name in ("train", "val", "val_hard", "val_vi_variants", "val_v3") for r in split[name]]
    used += [json.loads(ln)["text"] for ln in REALISTIC_TRAIN.read_text(encoding="utf-8").splitlines() if ln.strip()]
    for name in ("val_v3_holdout", "val_realistic_holdout"):
        hj = max_jaccard([r["text"] for r in split[name]], used)
        MAX_JACCARD[f"{name}_vs_train_and_val"] = round(float(hj.max()), 4)
        counts[f"{name}_rows_jaccard_gt_0.8_vs_train_and_val"] = int((hj > JACCARD_MAX).sum())
    for name, rs in split.items():
        with open(DATA / f"{name}.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for r in rs:
                f.write(json.dumps({k: r[k] for k in ("id", "text", "labels", "lang", "variant", "source", "license", "group")},
                                   ensure_ascii=False) + "\n")

    stats = {"counts": dict(sorted(counts.items())), "max_jaccard_vs_eval": dict(sorted(MAX_JACCARD.items())),
             "splits": {}}
    for name, rs in split.items():
        per = collections.Counter()
        for r in rs:
            per[f"{r['lang']}/rows"] += 1
            for lb in r["labels"]:
                per[f"{r['lang']}/{lb}"] += 1
            per[f"{r['lang']}/variant:{r['variant']}"] += 1
            per[f"source:{r['source'].split(':')[0]}"] += 1
            per[f"source_full:{r['source']}"] += 1
            if r["labels"] == ["benign"]:
                per[f"{r['lang']}/benign/variant:{r['variant']}"] += 1
        stats["splits"][name] = dict(sorted(per.items()))
        stats["splits"][name]["rows"] = len(rs)
    (DATA / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
