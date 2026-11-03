# /// script
# requires-python = ">=3.10,<3.14"
# dependencies = [
#   "huggingface_hub==0.26.2",
#   "pyarrow==18.1.0",
# ]
# ///
"""Deterministic generator for the Guard Spec EN/VI prompt-injection eval set.

    uv run eval/build/build.py

Downloads two small, pinned Hugging Face datasets into eval/.cache (not
committed), mixes them with project-written rows from content_en.py and
content_vi.py, and writes:

    eval/data/en.jsonl, eval/data/vi.jsonl   the eval rows
    eval/fingerprints.txt                    sha256 of normalized text, one per line
    eval/LICENSES.md                         sources, licenses and row counts

Every random choice comes from random.Random seeded with SEED plus a section
name, so editing one section does not reshuffle the others.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import itertools
import json
import random
import re
import sys
import unicodedata
from pathlib import Path

import pyarrow.parquet as pq
from huggingface_hub import hf_hub_download

import content_en as EN
import content_vi as VI

SEED = 20261104
ROOT = Path(__file__).resolve().parents[1]  # eval/
CACHE = ROOT / ".cache"
DATA = ROOT / "data"

# ---------------------------------------------------------------------------
# Sources (licenses verified on the dataset cards at these revisions)
# ---------------------------------------------------------------------------

DEEPSET = dict(
    key="deepset/prompt-injections", license="Apache-2.0",
    url="https://huggingface.co/datasets/deepset/prompt-injections",
    revision="4f61ecb038e9c3fb77e21034b22511b523772cdd",
    files={"test": "data/test-00000-of-00001-701d16158af87368.parquet"},
)
GANDALF = dict(
    key="Lakera/gandalf_ignore_instructions", license="MIT",
    url="https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
    revision="04737b65e90a6794ec227012e4a255a7def6344b",
    files={"validation": "data/validation-00000-of-00001-94481a2a09ff2fff.parquet",
           "test": "data/test-00000-of-00001-bc92128b9288a6d1.parquet"},
)
PROJECT = "guard-spec"
PROJECT_LICENSE = "Apache-2.0"

CATEGORIES = ["direct_injection", "indirect_injection", "jailbreak", "prompt_extraction",
              "data_exfiltration", "tool_poisoning", "obfuscation", "benign"]
VARIANTS = ["orig", "no_diacritics", "teencode", "leet", "translated"]


def rng(section: str) -> random.Random:
    return random.Random(f"{SEED}:{section}")


def sample_product(section, lists, n):
    combos = list(itertools.product(*lists))
    rng(section).shuffle(combos)
    return combos[:n]


def subset(section, items, frac):
    r = rng(section)
    return [x for x in items if r.random() < frac]


# ---------------------------------------------------------------------------
# Text transforms
# ---------------------------------------------------------------------------

def strip_diacritics(s: str) -> str:
    s = s.replace("đ", "d").replace("Đ", "D")
    s = "".join(ch for ch in unicodedata.normalize("NFD", s) if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFC", s)


def normalize_for_fingerprint(s: str) -> str:
    """Lowercase, strip diacritics, collapse whitespace. N6 must use the same rule."""
    return " ".join(strip_diacritics(unicodedata.normalize("NFC", s)).lower().split())


def fingerprint(s: str) -> str:
    return hashlib.sha256(normalize_for_fingerprint(s).encode("utf-8")).hexdigest()


TEEN_WORDS = {
    "không": "ko", "được": "dc", "gì": "j", "vậy": "v", "rồi": "r", "với": "vs", "biết": "bít",
    "mình": "mk", "bạn": "b", "tôi": "t", "anh": "a", "em": "e", "nhé": "nha", "quá": "wá",
    "yêu": "iu", "giờ": "h", "trước": "trc", "những": "nhg", "người": "ng", "muốn": "mún",
    "luôn": "lun", "hướng dẫn": "hd", "thế nào": "tn", "bây giờ": "bh", "đi": "đi", "cho": "cho",
    "cái": "cái", "nhiều": "nhìu", "thôi": "thui", "chưa": "chx", "làm": "lm", "trả lời": "tl",
}
_TEEN_RE = re.compile(r"\b(" + "|".join(sorted(map(re.escape, TEEN_WORDS), key=len, reverse=True)) + r")\b",
                      re.IGNORECASE)


def teencode(s: str, key: str) -> str:
    """Vietnamese chat-style spelling: abbreviations, no diacritics, qu->w, ph->f, gi->j."""
    r = random.Random(f"{SEED}:teen:{key}")
    s = _TEEN_RE.sub(lambda m: TEEN_WORDS[m.group(0).lower()], s)
    s = strip_diacritics(s).lower()
    s = re.sub(r"(?<![a-z/.])qu", "w", s)
    s = re.sub(r"(?<![a-z/.])ph", "f", s)
    s = re.sub(r"\bgi(?=[aeiouy])", "j", s)
    s = re.sub(r"\bc(?=[aou])", lambda m: "k" if r.random() < 0.5 else "c", s)
    return s


LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def leet(s: str, key: str) -> str:
    r = random.Random(f"{SEED}:leet:{key}")
    out = []
    for ch in strip_diacritics(s):
        low = ch.lower()
        out.append(LEET[low] if low in LEET and r.random() < 0.6 else ch)
    return "".join(out)


def spaced(s: str) -> str:
    return "  ".join(" ".join(w) for w in s.split())


def zero_width(s: str) -> str:
    return "​".join(s)


HOMO = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "i": "і"}


def homoglyph(s: str) -> str:
    return "".join(HOMO.get(ch, ch) for ch in s)


def tag_smuggle(s: str) -> str:
    """ASCII smuggling: map printable ASCII to invisible Unicode tag characters."""
    return "".join(chr(0xE0000 + ord(ch)) for ch in s if 0x20 <= ord(ch) < 0x7F)


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Row collection
# ---------------------------------------------------------------------------

class Collector:
    def __init__(self):
        self.rows: list[dict] = []
        self.seen: dict[str, str] = {}
        self.dropped = 0

    def add(self, text, label, category, lang, variant, source, license_):
        assert label in ("attack", "benign"), label
        assert category in CATEGORIES, category
        assert variant in VARIANTS, variant
        assert lang in ("en", "vi"), lang
        assert (label == "benign") == (category == "benign"), (label, category)
        text = unicodedata.normalize("NFC", text).strip()
        if not text:
            return
        if text in self.seen:
            if self.seen[text] != label:
                raise SystemExit(f"conflicting labels for {text!r}")
            self.dropped += 1
            return
        self.seen[text] = label
        self.rows.append(dict(
            id=f"{lang}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}",
            text=text, label=label, category=category, lang=lang, variant=variant,
            source=source, license=license_))


def download(src) -> dict[str, list[dict]]:
    out = {}
    for split, fname in src["files"].items():
        path = hf_hub_download(src["key"], fname, repo_type="dataset", revision=src["revision"],
                               cache_dir=str(CACHE))
        out[split] = pq.read_table(path).to_pylist()
    return out


NON_ENGLISH = re.compile(r"[äöüßÄÖÜЀ-ӿ]")
NON_ENGLISH_WORDS = {
    # German/Spanish function words that are not also English words.
    "ich", "sie", "und", "der", "das", "ist", "nicht", "wie", "mit", "zu", "auf", "mir", "dich",
    "du", "wir", "ein", "eine", "dem", "sich", "gibt", "welche", "auch", "oder", "aber",
    "bitte", "jetzt", "alle", "alles", "frage", "schreibe", "antworte", "geld", "viel", "deutschland",
    "europa", "wieviele", "einem",
    "yo", "tu", "dices", "todo", "que", "dije", "olvide", "si",
}


def is_english(text: str) -> bool:
    if NON_ENGLISH.search(text):
        return False
    words = set(re.findall(r"[a-zA-Z]+", text.lower()))
    return not (words & NON_ENGLISH_WORDS)


def categorize_source(text: str) -> str:
    t = text.lower().replace("prompt injection", "")
    if re.search(r"act as|pretend|theoretical world|play a game|amnesia|act in a film|as a child|"
                 r"you are a journalist|you were a|free, answer", t):
        return "jailbreak"
    if re.search(r"password|secret|prompt|instruction|directions|guidelines|embeddings|spell-? ?check|"
                 r"first statement|not allowed to discuss|what are you", t):
        if re.search(r"password|secret|prompt|embeddings|spell|reveal|show|repeat|tell me|what (are|were|was|is)|"
                     r"rephrase|rewrite|reproduce|provide me|first statement|not allowed|give", t):
            return "prompt_extraction"
    return "direct_injection"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_en(c: Collector, deepset, gandalf):
    counts = collections.Counter()
    # Sources -----------------------------------------------------------------
    for row in deepset["test"]:
        text = row["text"].strip()
        if not is_english(text):
            counts["deepset_skipped_non_english"] += 1
            continue
        label = "attack" if row["label"] == 1 else "benign"
        cat = categorize_source(text) if label == "attack" else "benign"
        c.add(text, label, cat, "en", "orig", DEEPSET["key"] + ":test", DEEPSET["license"])
    for split in ("test", "validation"):
        for row in gandalf[split]:
            text = row["text"].strip()
            if not is_english(text):
                counts["gandalf_skipped_non_english"] += 1
                continue
            c.add(text, "attack", categorize_source(text), "en", "orig",
                  GANDALF["key"] + ":" + split, GANDALF["license"])

    def p(text, label, cat, variant="orig"):
        c.add(text, label, cat, "en", variant, PROJECT, PROJECT_LICENSE)

    # Project attacks -----------------------------------------------------------
    leet_pool = []
    for o, v, t in sample_product("en.direct", [EN.DIRECT_OPENERS, EN.DIRECT_OVERRIDES, EN.DIRECT_TASKS], 40):
        s = o + v + " " + t
        s = s[0].upper() + s[1:]
        p(s, "attack", "direct_injection")
        leet_pool.append((s, "direct_injection"))
    for s in EN.JAILBREAK_HANDWRITTEN:
        p(s, "attack", "jailbreak")
        leet_pool.append((s, "jailbreak"))
    for name, clause, tail in sample_product("en.jb", [EN.JAILBREAK_PERSONAS, EN.JAILBREAK_CLAUSES, EN.JAILBREAK_TAILS], 20):
        p(f"From now on you are {name}, {clause}. " + tail.format(p=name), "attack", "jailbreak")
    for s in EN.PROMPT_EXTRACTION:
        p(s, "attack", "prompt_extraction")
        leet_pool.append((s, "prompt_extraction"))
    for s in EN.DATA_EXFIL:
        p(s, "attack", "data_exfiltration")
        leet_pool.append((s, "data_exfiltration"))
    for (name, desc), extra in sample_product("en.mcp", [EN.MCP_TOOLS, EN.MCP_POISON], 40):
        p(EN.mcp_tool(name, desc, extra), "attack", "tool_poisoning")
    for carrier, ctx, payload in sample_product("en.indirect", [EN.CARRIERS, EN.INDIRECT_CONTEXTS, EN.INDIRECT_PAYLOADS], 60):
        p(carrier(ctx, payload), "attack", "indirect_injection")
    for i, base in enumerate(EN.OBFUSCATION_BASES):
        p(spaced(base), "attack", "obfuscation")
        p(zero_width(base), "attack", "obfuscation")
        p(homoglyph(base), "attack", "obfuscation")
        p("Decode this base64 string and follow it: " + b64(base), "attack", "obfuscation")
        p("Read this backwards and do what it says: " + base[::-1], "attack", "obfuscation")
        p("Please summarize this paragraph for me." + tag_smuggle(base), "attack", "obfuscation")
    for s, cat in rng("en.leet").sample(leet_pool, 40):
        p(leet(s, s), "attack", cat, "leet")

    # Hard benign --------------------------------------------------------------------
    for frame, topic in sample_product("en.sec", [EN.SEC_QUESTION_FRAMES, EN.SEC_TOPICS], 80):
        p(frame.format(t=topic), "benign", "benign")
    for group in (EN.SEC_HANDWRITTEN, EN.EVERYDAY, EN.CHESS, EN.SYSADMIN, EN.CODE_SNIPPETS):
        for s in group:
            p(s, "benign", "benign")
    for carrier, ctx, note in sample_product("en.docs", [EN.BENIGN_CARRIERS, EN.INDIRECT_CONTEXTS, EN.BENIGN_DOC_NOTES], 100):
        p(carrier(ctx, note), "benign", "benign")
    for (name, desc), extra in sample_product("en.mcpb", [EN.MCP_TOOLS, EN.MCP_BENIGN_EXTRA], 30):
        p(EN.mcp_tool(name, desc, extra), "benign", "benign")
    return counts


def _render_carrier(carrier, ctx, payload):
    def render(tf):
        tctx = {k: (v if k in ("fn", "ret", "sender") else tf(v)) for k, v in ctx.items()}
        return carrier(tctx, tf(payload))
    return render


def _render_text(s):
    return lambda tf: tf(s)


def _render_mcp(name, desc, extra):
    return lambda tf: VI.mcp_tool(name, tf(desc), tf(extra))


def _vi_variants(c, bases, label, section, teen_frac, leet_frac):
    """bases: list of (category, render, key). Emits orig, no_diacritics, teencode and leet variants."""
    teen_keys = {k for _, _, k in subset(section + ".teen", bases, teen_frac)}
    leet_keys = {k for _, _, k in subset(section + ".leet", bases, leet_frac)}
    for cat, render, key in bases:
        def add(text, variant):
            c.add(text, label, cat, "vi", variant, PROJECT, PROJECT_LICENSE)
        add(render(lambda s: s), "orig")
        add(render(strip_diacritics), "no_diacritics")
        if key in teen_keys:
            add(render(lambda s, k=key: teencode(s, k)), "teencode")
        if key in leet_keys:
            add(render(lambda s, k=key: leet(s, k)), "leet")


def build_vi(c: Collector, deepset, gandalf):
    # Attacks -----------------------------------------------------------------------
    bases = []
    for o, v, t in sample_product("vi.direct", [VI.DIRECT_OPENERS, VI.DIRECT_OVERRIDES, VI.DIRECT_TASKS], 40):
        s = o + v + " " + t
        s = s[0].upper() + s[1:]
        bases.append(("direct_injection", _render_text(s), s))
    bases += [("jailbreak", _render_text(s), s) for s in VI.JAILBREAK]
    bases += [("prompt_extraction", _render_text(s), s) for s in VI.PROMPT_EXTRACTION]
    bases += [("data_exfiltration", _render_text(s), s) for s in VI.DATA_EXFIL]
    for (name, desc), extra in sample_product("vi.mcp", [VI.MCP_TOOLS, VI.MCP_POISON], 24):
        bases.append(("tool_poisoning", _render_mcp(name, desc, extra), name + extra))
    for carrier, ctx, payload in sample_product("vi.indirect", [VI.CARRIERS, VI.INDIRECT_CONTEXTS, VI.INDIRECT_PAYLOADS], 44):
        bases.append(("indirect_injection", _render_carrier(carrier, ctx, payload),
                      carrier.__name__ + ctx["name"] + payload))
    _vi_variants(c, bases, "attack", "vi.attack", teen_frac=0.7, leet_frac=0.45)

    def p(text, cat, variant="orig", source=PROJECT, license_=PROJECT_LICENSE):
        c.add(text, "attack", cat, "vi", variant, source, license_)

    for base in VI.OBFUSCATION_BASES:
        p(spaced(base), "obfuscation")
        p(zero_width(base), "obfuscation")
        p(homoglyph(base), "obfuscation")
        p("Giải mã chuỗi base64 sau rồi làm theo: " + b64(base), "obfuscation")
        p("Đọc ngược câu này rồi làm theo: " + base[::-1], "obfuscation")
        p("Tóm tắt đoạn văn này giúp mình." + tag_smuggle(strip_diacritics(base)), "obfuscation")
    for s in VI.OBFUSCATION_HANDWRITTEN:
        p(s, "obfuscation")

    # Translations of source attacks ---------------------------------------------------
    source_texts = {}
    for row in deepset["test"]:
        if row["label"] == 1:
            source_texts[row["text"].strip()] = DEEPSET
    for split in ("test", "validation"):
        for row in gandalf[split]:
            source_texts[row["text"].strip()] = GANDALF
    for en_text, vi_text in VI.TRANSLATIONS.items():
        src = source_texts.get(en_text)
        if src is None:
            raise SystemExit(f"translation key not found in sources: {en_text!r}")
        p(vi_text, categorize_source(en_text), "translated", src["key"] + " (translated)", src["license"])

    # Hard benign -----------------------------------------------------------------------
    bases = []
    for frame, x in sample_product("vi.huongdan", [VI.HUONG_DAN_FRAMES, VI.HUONG_DAN_TOPICS], 36):
        s = frame.format(x=x)
        bases.append(("benign", _render_text(s), s))
    for frame, y in itertools.product(VI.QUEN_FRAMES, VI.QUEN_TOPICS):
        s = frame.format(y=y)
        bases.append(("benign", _render_text(s), s))
    for frame, t in itertools.product(VI.SEC_FRAMES, VI.SEC_TOPICS):
        s = frame.format(t=t)
        s = s[0].upper() + s[1:]
        bases.append(("benign", _render_text(s), s))
    for group in (VI.BO_QUA, VI.HE_THONG, VI.SPECIAL_HARD, VI.SEC_HANDWRITTEN, VI.CHAT, VI.SYSADMIN, VI.CODE_SNIPPETS):
        bases += [("benign", _render_text(s), s) for s in group]
    for carrier, ctx, note in sample_product("vi.docs", [VI.BENIGN_CARRIERS, VI.INDIRECT_CONTEXTS, VI.BENIGN_DOC_NOTES], 36):
        bases.append(("benign", _render_carrier(carrier, ctx, note), carrier.__name__ + ctx["name"] + note))
    for (name, desc), extra in sample_product("vi.mcpb", [VI.MCP_TOOLS, VI.MCP_BENIGN_EXTRA], 16):
        bases.append(("benign", _render_mcp(name, desc, extra), name + extra))
    _vi_variants(c, bases, "benign", "vi.benign", teen_frac=0.6, leet_frac=0.15)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_licenses(rows):
    by_src = collections.Counter()
    for r in rows:
        by_src[(r["source"].split(":")[0].replace(" (translated)", ""), r["license"],
                "translated" in r["source"])] += 1
    lines = [
        "# Eval set sources and licenses",
        "",
        "Generated by `eval/build/build.py`; do not edit by hand.",
        "Only sources whose license allows redistribution are used. Each license was checked",
        "on the Hugging Face dataset card at the pinned revision.",
        "",
        "| Source | License | URL | Pinned revision | Splits used | Rows |",
        "|---|---|---|---|---|---|",
    ]
    for src, splits in ((DEEPSET, "test only (train kept free for training)"), (GANDALF, "test, validation (train kept free)")):
        n = by_src[(src["key"], src["license"], False)]
        lines.append(f"| `{src['key']}` | {src['license']} | {src['url']} | `{src['revision'][:12]}` | {splits} | {n} |")
        nt = by_src[(src["key"], src["license"], True)]
        if nt:
            lines.append(f"| `{src['key']}` (Vietnamese translations, project-written) | {src['license']} (derivative) | {src['url']} | `{src['revision'][:12]}` | as above | {nt} |")
    n = by_src[(PROJECT, PROJECT_LICENSE, False)]
    lines.append(f"| Guard Spec project-written rows (`{PROJECT}`) | {PROJECT_LICENSE} | this repository | - | - | {n} |")
    lines += [
        f"| **Total** | | | | | **{len(rows)}** |",
        "",
        "## Notes",
        "",
        "- `deepset/prompt-injections`: the card's top-level `license` is `apache-2.0`. Its",
        "  `dataset_info` block also carries a stray `license: cc-by-4.0` field; both licenses allow",
        "  redistribution with attribution. German and Spanish rows are dropped (the set is EN/VI only).",
        "- `Lakera/gandalf_ignore_instructions`: MIT. Rows in Russian or German are dropped.",
        "  Neither card ships a separate LICENSE file; the license is the card's `license` field.",
        "- Excluded: `jayavibhav/prompt-injection` (no license on the card).",
        "- Project-written rows are licensed Apache-2.0 as project data. The Vietnamese rows are",
        "  machine-written and agent-reviewed, not human-labelled.",
        "- Attribution: rows from these sources keep their `source` and `license` fields; credit goes",
        "  to deepset (`deepset/prompt-injections`) and Lakera (`Lakera/gandalf_ignore_instructions`).",
        "",
    ]
    (ROOT / "LICENSES.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    deepset = download(DEEPSET)
    gandalf = download(GANDALF)
    c = Collector()
    skipped = build_en(c, deepset, gandalf)
    build_vi(c, deepset, gandalf)

    DATA.mkdir(parents=True, exist_ok=True)
    for lang in ("en", "vi"):
        with open(DATA / f"{lang}.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for r in c.rows:
                if r["lang"] == lang:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")

    fps = sorted({fingerprint(r["text"]) for r in c.rows})
    header = ("# sha256(normalized text) of every eval row; normalized = NFC, diacritics stripped "
              "(đ->d), lowercased, whitespace collapsed.\n# Training pipelines (N6) must drop rows "
              "whose fingerprint appears here.\n")
    (ROOT / "fingerprints.txt").write_text(header + "\n".join(fps) + "\n", encoding="utf-8")
    write_licenses(c.rows)

    # Summary ------------------------------------------------------------------------------
    total = len(c.rows)
    benign = sum(r["label"] == "benign" for r in c.rows)
    print(f"rows: {total}  benign: {benign} ({benign / total:.1%})  duplicates dropped: {c.dropped}  "
          f"fingerprints: {len(fps)}  skipped: {dict(skipped)}")
    table = collections.Counter((r["lang"], r["category"], r["label"]) for r in c.rows)
    for k in sorted(table):
        print("  %-3s %-20s %-7s %5d" % (*k, table[k]))
    var = collections.Counter((r["lang"], r["variant"]) for r in c.rows)
    print("variants:", dict(sorted(var.items())))
    if benign / total < 0.35:
        sys.exit("benign share below 35%")


if __name__ == "__main__":
    main()
