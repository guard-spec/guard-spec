"""Shared helpers for the Guard Spec classifier training-data generator.

The normalization (`normalize_for_fingerprint`) is identical to
eval/build/build.py, so fingerprints line up with eval/fingerprints.txt.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import itertools
import random
import re
import unicodedata

SEED = 20261105  # different from the eval seed on purpose

LABELS = ["benign", "direct_injection", "indirect_injection", "jailbreak", "prompt_extraction",
          "data_exfiltration", "tool_poisoning", "obfuscation"]
ATTACK_LABELS = LABELS[1:]


def rng(section: str) -> random.Random:
    return random.Random(f"{SEED}:{section}")


def sample_product(section, lists, n):
    combos = list(itertools.product(*lists))
    rng(section).shuffle(combos)
    return combos[:n]


def pick(r: random.Random, items):
    return items[r.randrange(len(items))]


# ---------------------------------------------------------------------------
# Normalization (must match eval/build/build.py)
# ---------------------------------------------------------------------------

def strip_diacritics(s: str) -> str:
    s = s.replace("đ", "d").replace("Đ", "D")
    s = "".join(ch for ch in unicodedata.normalize("NFD", s) if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFC", s)


def normalize_for_fingerprint(s: str) -> str:
    return " ".join(strip_diacritics(unicodedata.normalize("NFC", s)).lower().split())


def fingerprint(s: str) -> str:
    return hashlib.sha256(normalize_for_fingerprint(s).encode("utf-8")).hexdigest()


def shingles(s: str, k: int = 5) -> set[str]:
    t = normalize_for_fingerprint(s)
    if len(t) <= k:
        return {t}
    return {t[i:i + k] for i in range(len(t) - k + 1)}


# ---------------------------------------------------------------------------
# Surface transforms
# ---------------------------------------------------------------------------

# Vietnamese chat spelling. Written for training; the eval set uses its own table.
VI_TEEN = {
    "không": "hông", "được": "đc", "gì": "gì", "vậy": "z", "rồi": "ròi", "với": "vớii", "biết": "bít",
    "mình": "mik", "bạn": "bn", "cũng": "cx", "mới": "ms", "nói": "ns", "làm": "lm", "trước": "trc",
    "thế nào": "ntn", "như thế nào": "ntn", "nhắn tin": "ib", "nhé": "nhaa", "ạ": "ạk", "ừ": "uk",
    "anh": "a", "em": "e", "chị": "c", "tất cả": "tc", "hướng dẫn": "hd", "mật khẩu": "mk",
    "chỉ thị": "ct", "quy tắc": "qt", "trả lời": "rep", "đi": "đyy", "thôi": "thuii", "quá": "qá",
    "được không": "đc hum", "người dùng": "ng dùng", "hệ thống": "ht",
}
_VI_TEEN_RE = re.compile(r"\b(" + "|".join(sorted(map(re.escape, VI_TEEN), key=len, reverse=True)) + r")\b",
                         re.IGNORECASE)


def teencode_vi(s: str, key: str) -> str:
    r = random.Random(f"{SEED}:teen:{key}")
    s = _VI_TEEN_RE.sub(lambda m: VI_TEEN[m.group(0).lower()] if r.random() < 0.85 else m.group(0), s)
    s = strip_diacritics(s).lower() if r.random() < 0.8 else s.lower()
    s = re.sub(r"(?<![a-z/.@_])qu", "w", s)
    s = re.sub(r"(?<![a-z/.@_])ph", "f", s)
    s = re.sub(r"\bd(?=[aeiouy])", lambda m: "z" if r.random() < 0.35 else "d", s)
    s = re.sub(r"\bnh(?=[aeiouy])", lambda m: "nh", s)
    s = re.sub(r"\bc(?=[aou])", lambda m: "k" if r.random() < 0.4 else "c", s)
    s = re.sub(r"\bkh", lambda m: "kh" if r.random() < 0.6 else "k", s)
    return s


# v2 teencode: several spellings per word, chosen at random, so that no single abbreviation (v1 mapped
# "mật khẩu" -> "mk", "quy tắc" -> "qt", "hệ thống" -> "ht" and those showed up mostly in attacks) is tied to
# a label. Table "A" is used for training and training-time augmentation; table "B" adds spellings that
# training never sees and is used only for the val_vi_variants split, to measure transfer to unseen
# chat spelling. Written from general knowledge of Vietnamese chat writing, not from eval/.
_TEEN2_COMMON = {
    "không": ["ko", "k", "hông", "hok", "kh", "khum", "hk"],
    "được": ["đc", "dc", "dk", "đk", "đươc"],
    "gì": ["j", "gì", "ji", "gi"],
    "vậy": ["z", "v", "dz", "zậy", "vại"],
    "rồi": ["r", "ròi", "rùi", "rầu"],
    "với": ["vs", "vớii", "zới"],
    "biết": ["bít", "bik", "bt", "biet"],
    "mình": ["mk", "mik", "mh", "mìn"],
    "bạn": ["b", "bn", "pạn", "bạnn"],
    "cũng": ["cx", "cg", "cũg"],
    "mới": ["ms", "mớii"],
    "nói": ["ns", "nóii"],
    "làm": ["lm", "lèm"],
    "trước": ["trc", "trướk"],
    "thế nào": ["ntn", "thế lào", "tn"],
    "như thế nào": ["ntn"],
    "nhắn tin": ["ib", "nt", "inbox"],
    "tin nhắn": ["tn", "tin nhắn", "ib"],
    "nhé": ["nha", "nhaa", "nhe", "nhoa", "nhá"],
    "nha": ["nhaa", "nhoa", "nhaaa"],
    "ạ": ["ạk", "ak", "ạ ạ", "a"],
    "anh": ["a", "ah", "anhh"],
    "em": ["e", "emm"],
    "chị": ["c", "chị", "chụy"],
    "tất cả": ["tc", "tất cả", "hết"],
    "hướng dẫn": ["hd", "hdan", "hướng dẫn", "hdẫn"],
    "mật khẩu": ["mk", "pass", "pw", "mat khau", "mkhau"],
    "quy tắc": ["qtac", "qt", "luật"],
    "chỉ thị": ["ct", "chỉ thị"],
    "quản trị": ["qtri", "qt", "admin", "quản trị"],
    "quản trị viên": ["admin", "qtv", "ad"],
    "hệ thống": ["ht", "hthong", "hệ thốg", "system"],
    "trả lời": ["rep", "tl", "trả lời", "rep lại"],
    "người": ["ng", "ngừi", "người"],
    "người dùng": ["ng dùng", "user", "ngdung"],
    "đi": ["đyy", "đii", "di"],
    "thôi": ["thui", "thoai", "thoii"],
    "quá": ["wá", "qá", "wa"],
    "điện thoại": ["đt", "dt", "đthoại"],
    "facebook": ["fb", "phây", "face"],
    "bây giờ": ["bh", "bjo", "bây h"],
    "giờ": ["h", "jờ", "giờ"],
    "yêu": ["iu", "yeu"],
    "thích": ["thik", "thick", "thjk"],
    "chồng": ["ck", "chồg"],
    "vợ": ["vk", "vợ"],
    "cảm ơn": ["cmon", "tks", "thanks", "cám ơn", "camon"],
    "xin lỗi": ["sr", "sorry", "xl", "xin lũi"],
    "bao nhiêu": ["bn", "bnhiu", "bao nhiu"],
    "hôm nay": ["hnay", "hum nay", "hôm nai"],
    "ngày mai": ["mai", "nmai", "ngày mơi"],
    "nhiều": ["nhìu", "nhiu"],
    "chưa": ["chx", "chưa", "chua"],
    "luôn": ["lun", "luôn"],
    "muốn": ["mún", "muốn"],
    "nữa": ["nx", "nữa"],
    "lệnh": ["lệnh", "lenh", "command"],
    "có": ["cs", "có", "co"],
    "đúng": ["đúg", "dung", "chuẩn"],
    "học": ["họk", "hok", "học"],
    "trời ơi": ["trời ơii", "troi oi", "trùi ui"],
    "ơi": ["ơii", "ui", "oii"],
    "thật": ["thiệt", "thật"],
    "gửi": ["gửi", "gui", "send"],
    "quên": ["quên", "wên", "quen"],
    "bỏ qua": ["bỏ qa", "bỏ wa", "skip", "bỏ qua"],
}
# Spellings held out of training (table B only; none of them is in _TEEN2_COMMON).
_TEEN2_HELDOUT = {
    "không": ["hem", "hum", "hônk"], "được": ["đượt", "dượt"], "biết": ["bjk", "bjt"], "vậy": ["zị", "dị"],
    "rồi": ["gùi", "rùii"], "mình": ["mềnh", "mừn"], "gì": ["zì", "chi"], "với": ["vứi", "voy"],
    "thôi": ["thoy", "thuj"], "nhé": ["nhoé", "nhó"], "bạn": ["bợn", "pợn"], "quá": ["wóa", "quớ"],
    "mật khẩu": ["pas", "mậtk"], "hệ thống": ["hthốg", "h.thống"], "hướng dẫn": ["h/d", "hưỡng dẫn"],
    "cảm ơn": ["thank", "cảm ưn"], "hôm nay": ["hum nai", "hnai"], "người": ["ngừ", "nguoj"],
}
_TEEN2 = {"A": _TEEN2_COMMON,
          "B": {k: v + _TEEN2_HELDOUT.get(k, []) for k, v in _TEEN2_COMMON.items()}}
assert not any(set(v) & set(_TEEN2_COMMON[k]) for k, v in _TEEN2_HELDOUT.items())
_TEEN2_RE = re.compile(r"(?<!\w)(" + "|".join(sorted(map(re.escape, _TEEN2_COMMON), key=len, reverse=True)) + r")(?!\w)",
                       re.IGNORECASE)
_TEEN2_TAILS = {"A": [" :))", " =))", " hihi", " haha", " :v", "!!", " ^^", " nhaa"],
                "B": [" :)))", " =)))", " hjhj", " kkk", " :3", "!!!", " ^_^", " hehe"]}


def teencode_v2(s: str, key: str, table: str = "A") -> str:
    """Randomized chat spelling. Same procedure for benign and attack text; `table` is A (train) or B (val)."""
    r = random.Random(f"{SEED}:teen2:{table}:{key}")
    tab = _TEEN2[table]
    p_word = r.uniform(0.45, 0.95)
    s = _TEEN2_RE.sub(lambda m: r.choice(tab[m.group(0).lower()]) if r.random() < p_word else m.group(0), s)
    mode = r.random()
    if mode < 0.65:
        s = strip_diacritics(s).lower()
    elif mode < 0.85:
        s = s.lower()
    if r.random() < 0.7:
        s = re.sub(r"(?<![a-z/.@_:])qu", "w", s)
    if r.random() < 0.6:
        s = re.sub(r"(?<![a-z/.@_:])ph", "f", s)
    if r.random() < 0.4:
        s = re.sub(r"(?<![a-z/.@_:])gi(?=[aeiouy])", "j", s)
    s = re.sub(r"(?<![\w/.@_:])d(?=[aeiouy])", lambda m: "z" if r.random() < 0.3 else "d", s)
    s = re.sub(r"(?<![\w/.@_:])c(?=[aou])", lambda m: "k" if r.random() < 0.3 else "c", s)
    s = re.sub(r"ch\b", lambda m: "k" if r.random() < 0.25 else "ch", s)
    if r.random() < 0.3:
        s = re.sub(r"[.]$", "", s.rstrip()) + r.choice(_TEEN2_TAILS[table])
    return s


LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "g": "9", "b": "8", "l": "1"}


def leet(s: str, key: str, p: float = 0.55, strip=True) -> str:
    r = random.Random(f"{SEED}:leet:{key}")
    src = strip_diacritics(s) if strip else s
    return "".join(LEET[ch.lower()] if ch.lower() in LEET and r.random() < p else ch for ch in src)


def spaced(s: str, sep=" ") -> str:
    return "   ".join(sep.join(w) for w in s.split())


def dotted(s: str) -> str:
    return " ".join(".".join(w) for w in s.split())


def zero_width(s: str, ch="​") -> str:
    return ch.join(s)


HOMO = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "i": "і", "x": "х", "y": "у", "s": "ѕ"}


def homoglyph(s: str, key: str) -> str:
    r = random.Random(f"{SEED}:homo:{key}")
    return "".join(HOMO[ch] if ch in HOMO and r.random() < 0.7 else ch for ch in s)


def fullwidth(s: str) -> str:
    return "".join(chr(ord(ch) + 0xFEE0) if "!" <= ch <= "~" else ch for ch in s)


def tag_smuggle(s: str) -> str:
    return "".join(chr(0xE0000 + ord(ch)) for ch in s if 0x20 <= ord(ch) < 0x7F)


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def rot13(s: str) -> str:
    return codecs.encode(s, "rot13")


def hexenc(s: str) -> str:
    return s.encode("utf-8").hex()


def split_words(s: str, key: str) -> str:
    """Break words with hyphens or asterisks: ig-nore, pr*mpt."""
    r = random.Random(f"{SEED}:split:{key}")
    out = []
    for w in s.split():
        if len(w) > 4 and r.random() < 0.6:
            i = r.randrange(2, len(w) - 1)
            w = w[:i] + r.choice(["-", "*", ".", "_"]) + w[i:]
        out.append(w)
    return " ".join(out)


def mixed_case(s: str, key: str) -> str:
    r = random.Random(f"{SEED}:case:{key}")
    return "".join(ch.upper() if r.random() < 0.5 else ch.lower() for ch in s)
