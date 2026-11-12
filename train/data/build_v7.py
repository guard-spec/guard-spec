# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
"""v7 training addition: benign long-text windows, English and Vietnamese (RF-895d3533 R6).

Implements the data part of train/reports/v7_preregistration.md. Sources: data/sources_v7.yaml (pinned
public sources, loaded with bench/long/build.py's load_source, and project-written generated text). No
owner data is read for the training text; the owner hold-outs are read locally only to check that no
training text overlaps them.

Stages (GUARD_V7_OUT is the output directory, outside the repository):

    pool   load every source (sha256 pins checked), drop every unit that shares a run of 50 classifier
           tokens with a bench/long document (profiles quick, full, long, long5, long6 and the R5 / long6
           embedded-attack documents) or a hold-out row, and write the mining pool as documents of about
           30k tokens: <out>/pool/docs.jsonl (cmd/benchlong -corpus <out>/pool).
    rows   from the pool, the v6 mining run's window dump (cmd/benchlong -long on -dump, scores only) and
           the sanitized pool text (the dump's spans are offsets in the sanitized text), write
           <out>/v7_train.jsonl: every mined window (kind v7_hardneg: v6 fused score >= 0.5 or calibrated
           L2 >= 0.3, capped per language), a seeded random sample of the other windows per genre and
           language (kind v7_long), and the generated units (kind v7_gen); labels ["benign"].
    check  bench_guard over the final rows against the same bench documents and hold-out rows; writes
           <out>/guard_v7.json and exits 1 if any row shares a 50-token run.

    cd train && GUARD_V7_OUT=... BENCH_CACHE=... uv run --frozen python data/build_v7.py pool
    ... data/build_v7.py rows --dump <dump prefix> --sanitized <sanitized.jsonl>
    ... data/build_v7.py check

Nothing here reads a model; mining is cmd/benchlong with the v6 package on the laptop's CPU.
"""

from __future__ import annotations

import argparse
import collections
import glob
import gzip
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
sys.path.insert(0, str(REPO / "bench" / "long"))

from bench_guard import ShingleIndex, tokenizer_fn  # noqa: E402

POOL_DOC_TOKENS = 30_000
# Tokens of each genre x language taken into the mining pool (in source order; None: all of it).
POOL_TOKENS = {
    ("wiki", "en"): 2_500_000, ("prose", "en"): 4_000_000, ("docs", "en"): None, ("rfc", "en"): None,
    ("legal", "en"): 1_500_000, ("code", "en"): 1_500_000,
    ("wiki", "vi"): 5_000_000, ("prose", "vi"): None, ("docs", "vi"): None,
}
BENCH_PROFILES = ["quick", "full", "long", "long5", "long6"]


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def paths():
    out = Path(os.environ.get("GUARD_V7_OUT") or sys.exit("set GUARD_V7_OUT"))
    bench = Path(os.environ.get("BENCH_CACHE") or REPO / "bench" / ".cache") / "long"
    return out, bench


def holdout_files(extra: list[str]) -> list[Path]:
    """Hold-out rows no training text may overlap: eval/ (every set), the repository's val_*_holdout files,
    and the ones given (the v6 hold-out stage's splits, the owner hold-outs; read locally only)."""
    fs = sorted(Path(p) for p in glob.glob(str(REPO / "eval" / "**" / "*.jsonl"), recursive=True))
    fs += sorted(HERE.glob("val_*holdout*.jsonl"))
    for pat in extra:
        fs += sorted(Path(p) for p in glob.glob(os.path.expanduser(pat), recursive=True))
    return fs


SHORT_K = 12  # hold-out rows under 50 tokens: a run of 12 of their tokens counts as an overlap


def guard_index(tok, bench: Path, extra_docs: list[str], holdouts: list[Path]) -> tuple[ShingleIndex, dict, ShingleIndex]:
    """One shingle index over every bench/long document and every hold-out row of 50 tokens or more, and a
    12-token shingle index of the shorter hold-out rows."""
    ix = ShingleIndex(tok)
    short = ShingleIndex(tok, SHORT_K)
    stats: dict = collections.Counter()
    for prof in BENCH_PROFILES:
        p = bench / prof / "docs.jsonl"
        if not p.exists():
            raise SystemExit(f"missing {p} (build the profile first)")
        with open(p, encoding="utf-8") as f:
            for ln in f:
                d = json.loads(ln)
                ix.add(d["text"], f"{prof}:{d['id']}")
                stats[f"bench:{prof}"] += 1
    for pat in extra_docs:
        for p in sorted(glob.glob(os.path.expanduser(pat))):
            with open(p, encoding="utf-8") as f:
                for ln in f:
                    d = json.loads(ln)
                    ix.add(d["text"], f"embedded:{d['id']}")
                    stats["bench:embedded"] += 1
    for p in holdouts:
        with open(p, encoding="utf-8") as f:
            for ln in f:
                if not ln.strip():
                    continue
                r = json.loads(ln)
                t = r.get("text") or ""
                if ix.add(t, f"holdout:{p.name}:{r.get('id', '?')}") == 0:
                    short.add(t, f"holdout-short:{p.name}:{r.get('id', '?')}")
                stats[f"holdout:{p.name}"] += 1
    return ix, dict(stats), short


def load_cfg():
    cfg = yaml.safe_load((HERE / "sources_v7.yaml").read_text("utf-8"))
    corpus = yaml.safe_load((REPO / "bench" / "long" / "corpus.yaml").read_text("utf-8"))
    return cfg, corpus


# ---------------------------------------------------------------------------
# Generated text (project-written)

GEN = {
    ("fiction_roleplay", "en"): {
        "names": ["Mara", "Tobias", "Elena", "Jonah", "Priya", "Felix", "Ingrid", "Samuel", "Leona", "Hugo"],
        "roles": ["a pirate queen", "a travelling magician", "an old lighthouse keeper", "a rebel captain",
                  "a court jester", "a detective with no badge", "a dragon who could speak", "a ghost in the attic"],
        "s": [
            "In the third act {n} took on the role of {r}, and for once the director let her improvise.",
            "The rehearsal went on until midnight; {n} kept rewriting the lines of {r} in the margin of the script.",
            "On that stage there were no rules about who could speak first, and the children played without any restrictions on their imagination.",
            "\"Pretend you are {r},\" the teacher said, and the whole class giggled as {n} bowed to the audience.",
            "The novel follows {n}, who invents a second persona, {r}, to write letters she would never sign with her own name.",
            "For the summer camp game, every child had to act as {r} until the bell rang for dinner.",
            "{n} said the old map promised a valley without limits, where the river answered to no king.",
            "In the dream {n} could fly over the city, and nothing in the world could tell her where to stop.",
            "The players agreed that the game master could change the rules of the story whenever the plot needed it.",
            "Years later {n} still remembered the night she played {r} and forgot every line except the last one.",
            "The script asked the actor to break character only once, when the lights went out in the final scene.",
            "{n} laughed and said that in her stories the heroes never asked anyone for permission.",
            "The puppet show was about {r} who refused to follow the orders of a greedy mayor.",
            "When the curtain fell, the audience stood up, and {n} finally stepped out of the role.",
        ],
    },
    ("fiction_roleplay", "vi"): {
        "names": ["Mai", "Tuấn", "Lan", "Khoa", "Hạnh", "Bảo", "Ngọc", "Quân", "Thảo", "Phong"],
        "roles": ["một nữ hải tặc", "một ảo thuật gia lang thang", "người gác hải đăng già", "vị thuyền trưởng nổi loạn",
                  "chú hề trong cung", "một thám tử không có phù hiệu", "con rồng biết nói", "hồn ma trên gác mái"],
        "s": [
            "Trong hồi thứ ba, {n} nhập vai {r} và lần đầu tiên đạo diễn để cô tự do ứng biến.",
            "Buổi tập kéo dài đến nửa đêm; {n} cứ sửa lại lời thoại của {r} bên lề kịch bản.",
            "Trên sân khấu ấy không có luật nào về việc ai được nói trước, và bọn trẻ chơi mà không bị giới hạn trí tưởng tượng.",
            "\"Con hãy giả làm {r} nhé,\" cô giáo nói, cả lớp cười ồ khi {n} cúi chào khán giả.",
            "Cuốn tiểu thuyết kể về {n}, người tự tạo ra một nhân vật khác là {r} để viết những lá thư cô không dám ký tên thật.",
            "Trong trò chơi ở trại hè, mỗi đứa trẻ phải đóng vai {r} cho đến khi chuông báo giờ ăn tối.",
            "{n} kể rằng tấm bản đồ cũ hứa hẹn một thung lũng không có giới hạn, nơi dòng sông chẳng phục tùng vua nào.",
            "Trong giấc mơ, {n} bay qua thành phố và chẳng có gì trên đời bảo được cô phải dừng lại ở đâu.",
            "Những người chơi đồng ý rằng người dẫn truyện có thể đổi luật của câu chuyện bất cứ khi nào cốt truyện cần.",
            "Nhiều năm sau, {n} vẫn nhớ cái đêm cô đóng vai {r} và quên hết lời thoại, chỉ trừ câu cuối cùng.",
            "Kịch bản chỉ cho diễn viên thoát vai một lần, khi đèn tắt ở cảnh cuối.",
            "{n} cười và nói rằng trong truyện của cô, các anh hùng chẳng bao giờ xin phép ai cả.",
            "Vở múa rối kể về {r}, người không chịu làm theo lệnh của viên thị trưởng tham lam.",
            "Khi màn nhung khép lại, khán giả đứng dậy vỗ tay và {n} cuối cùng cũng bước ra khỏi vai diễn.",
        ],
    },
    ("tech_secrets", "en"): {
        "names": ["API_TOKEN", "DB_PASSWORD", "REGISTRY_TOKEN", "AWS_SECRET_ACCESS_KEY", "SMTP_PASSWORD", "WEBHOOK_SECRET"],
        "roles": ["https://example.com/releases/tool-v2.4.1-linux-amd64.tar.gz", "https://downloads.example.org/agent/install.sh",
                  "https://packages.example.net/cli/latest/cli.zip", "https://example.com/keys/release.asc"],
        "s": [
            "Store the value in an environment variable instead of the configuration file: `export {n}=<value>`.",
            "Never commit {n} to version control; add the file that holds it to `.gitignore` and keep it in a secret manager.",
            "Download the archive with `curl -fsSL -o tool.tar.gz {r}` and check its checksum before you extract it.",
            "If the token leaks, revoke it in the dashboard and create a new one; the old value stops working within a minute.",
            "Create the secret with `kubectl create secret generic app-credentials --from-literal={n}=changeme` and mount it read-only.",
            "The installer script is fetched from {r}; read it first, then run it with `sh install.sh --prefix /opt/tool`.",
            "Rotate {n} every 90 days and after any team member with access leaves the project.",
            "The CI job reads the password from a masked variable, so it never appears in the build log.",
            "Use `wget -q {r}` on hosts without curl, and verify the signature with `gpg --verify` before installing.",
            "Passwords in this example are placeholders; replace them with your own values before deploying.",
            "To reset the admin password, stop the service, run `tool admin reset-password`, and restart it.",
            "Secrets are encrypted at rest with the cluster key; only pods that mount them can read the plain text.",
        ],
    },
    ("tech_secrets", "vi"): {
        "names": ["API_TOKEN", "DB_PASSWORD", "REGISTRY_TOKEN", "AWS_SECRET_ACCESS_KEY", "SMTP_PASSWORD", "WEBHOOK_SECRET"],
        "roles": ["https://example.com/releases/tool-v2.4.1-linux-amd64.tar.gz", "https://downloads.example.org/agent/install.sh",
                  "https://packages.example.net/cli/latest/cli.zip", "https://example.com/keys/release.asc"],
        "s": [
            "Hãy lưu giá trị trong biến môi trường thay vì tệp cấu hình: `export {n}=<giá trị>`.",
            "Không bao giờ đưa {n} vào kho mã nguồn; thêm tệp chứa nó vào `.gitignore` và cất trong trình quản lý bí mật.",
            "Tải gói về bằng `curl -fsSL -o tool.tar.gz {r}` và kiểm tra mã băm trước khi giải nén.",
            "Nếu mã truy cập bị lộ, hãy thu hồi nó trên trang quản trị và tạo mã mới; mã cũ hết hiệu lực trong vòng một phút.",
            "Tạo secret bằng lệnh `kubectl create secret generic app-credentials --from-literal={n}=changeme` rồi gắn ở chế độ chỉ đọc.",
            "Tập lệnh cài đặt được tải từ {r}; hãy đọc trước rồi mới chạy `sh install.sh --prefix /opt/tool`.",
            "Đổi {n} sau mỗi 90 ngày và mỗi khi có thành viên từng được cấp quyền rời dự án.",
            "Tác vụ CI đọc mật khẩu từ một biến được che, nên nó không bao giờ hiện trong nhật ký build.",
            "Trên máy không có curl, dùng `wget -q {r}` và kiểm tra chữ ký bằng `gpg --verify` trước khi cài.",
            "Mật khẩu trong ví dụ này chỉ là giá trị mẫu; hãy thay bằng giá trị của bạn trước khi triển khai.",
            "Để đặt lại mật khẩu quản trị, dừng dịch vụ, chạy `tool admin reset-password` rồi khởi động lại.",
            "Secret được mã hóa khi lưu bằng khóa của cụm; chỉ pod nào gắn secret mới đọc được nội dung gốc.",
        ],
    },
    ("rfc_send", "en"): {
        "names": ["REGISTER", "HELLO", "SUBSCRIBE", "REPORT", "BIND", "NOTIFY"],
        "roles": ["192.0.2.17", "198.51.100.4", "2001:db8::25", "relay.example.net", "postmaster@example.com", "203.0.113.9"],
        "s": [
            "The client MUST send a {n} message to the address given in the server's referral before any other request.",
            "If no response arrives within 30 seconds, the sender SHOULD retransmit the {n} request to the next address in the list, for example {r}.",
            "A receiver that cannot parse the message MUST reply with an error and MUST NOT forward it to another address.",
            "Implementations MAY send the report to the address {r} configured by the operator; the format is defined in Section 4.",
            "The server sends its response to the source address and port of the request, unless the request carries a reply-to option.",
            "Messages addressed to {r} are delivered to the local mailbox of the administrator responsible for the domain.",
            "The keywords \"MUST\", \"SHOULD\" and \"MAY\" in this section are to be interpreted as described in BCP 14.",
            "Each {n} message carries a sequence number so that the receiver can detect duplicates and reordering.",
            "Security considerations: an attacker who can forge the source address can cause a server to send responses to a victim.",
            "The relay forwards the message to the next hop and records the address of the previous hop in a trace field.",
            "After a successful exchange, both peers send a final acknowledgement and close the session.",
            "The registry operator publishes the list of addresses to which notifications are sent.",
        ],
    },
    ("rfc_send", "vi"): {
        "names": ["REGISTER", "HELLO", "SUBSCRIBE", "REPORT", "BIND", "NOTIFY"],
        "roles": ["192.0.2.17", "198.51.100.4", "2001:db8::25", "relay.example.net", "postmaster@example.com", "203.0.113.9"],
        "s": [
            "Máy khách PHẢI gửi thông điệp {n} tới địa chỉ mà máy chủ chỉ định trước khi gửi bất kỳ yêu cầu nào khác.",
            "Nếu không nhận được phản hồi trong 30 giây, bên gửi NÊN gửi lại yêu cầu {n} tới địa chỉ kế tiếp trong danh sách, ví dụ {r}.",
            "Bên nhận không phân tích được thông điệp PHẢI trả lời bằng mã lỗi và KHÔNG ĐƯỢC chuyển tiếp nó tới địa chỉ khác.",
            "Phần mềm CÓ THỂ gửi báo cáo tới địa chỉ {r} do người vận hành cấu hình; định dạng được mô tả ở Mục 4.",
            "Máy chủ gửi phản hồi về địa chỉ và cổng nguồn của yêu cầu, trừ khi yêu cầu có tùy chọn địa chỉ trả lời.",
            "Thư gửi tới {r} được chuyển vào hộp thư của quản trị viên phụ trách tên miền.",
            "Các từ khóa \"PHẢI\", \"NÊN\" và \"CÓ THỂ\" trong mục này được hiểu như mô tả trong BCP 14.",
            "Mỗi thông điệp {n} mang một số thứ tự để bên nhận phát hiện bản trùng và thứ tự bị đảo.",
            "Vấn đề bảo mật: kẻ tấn công giả mạo được địa chỉ nguồn có thể khiến máy chủ gửi phản hồi tới nạn nhân.",
            "Bộ chuyển tiếp gửi thông điệp tới chặng kế tiếp và ghi địa chỉ của chặng trước vào trường truy vết.",
            "Sau khi trao đổi thành công, hai bên gửi xác nhận cuối cùng và đóng phiên.",
            "Đơn vị quản lý tên miền công bố danh sách các địa chỉ nhận thông báo.",
        ],
    },
}


def gen_unit(genre: str, lang: str, rng: random.Random) -> str:
    g = GEN[(genre, lang)]
    n, r = rng.choice(g["names"]), rng.choice(g["roles"])
    k = rng.randint(5, 8)
    sents = rng.sample(g["s"], k)
    return " ".join(s.format(n=n, r=r) for s in sents)


# ---------------------------------------------------------------------------
# Stages


def stage_pool(args) -> int:
    import build  # bench/long/build.py

    out, bench = paths()
    cfg, corpus = load_cfg()
    tpath = build.find_tokenizer(None)
    tok = tokenizer_fn(tpath)
    from tokenizers import Tokenizer
    htok = Tokenizer.from_file(str(tpath))
    htok.no_truncation()
    htok.no_padding()
    all_sources = dict(corpus["sources"]) | cfg["sources"]
    holdouts = holdout_files(args.holdout_rows)
    log(f"guard: {len(holdouts)} hold-out files; indexing bench/long {BENCH_PROFILES} and {args.embedded}")
    ix, gstats, short = guard_index(tok, bench, args.embedded, holdouts)
    log(f"guard: {ix.docs} documents/rows, {ix.shingles:,} shingles; {short.docs} short hold-out rows ({short.shingles:,} 12-token shingles)")

    report: dict = {"guard_index": gstats, "holdout_files": [str(p) for p in holdouts], "sources": {}, "unpinned": {}}
    pools: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for name, src in cfg["sources"].items():
        units = build.load_source(name, src, bench / "src", all_sources)
        got = build.sha256_text("\n\x1e\n".join(units))
        if src.get("sha256") and src["sha256"] != got:
            raise SystemExit(f"{name}: extracted text has SHA-256 {got}, sources_v7.yaml pins {src['sha256']}")
        if not src.get("sha256"):
            report["unpinned"][name] = got
        kept, dropped, trimmed = [], [], 0

        def hit(t):
            return ix.check(t)[1] or short.check(t)[1]

        for i, u in enumerate(units):
            hits = hit(u)
            if not hits:
                kept.append(u)
                continue
            # Keep the paragraphs that share no run with the index (RFC boilerplate, licence and template
            # text repeat across documents); the rows are checked again as a whole in the `check` stage.
            paras = [b for b in u.split("\n\n") if b.strip()]
            good = [b for b in paras if not hit(b)]
            if good and sum(map(len, good)) >= 0.3 * len(u) and not hit("\n\n".join(good)):
                kept.append("\n\n".join(good))
                trimmed += 1
            else:
                dropped.append([i, hits[:3]])
        report["sources"][name] = {"units": len(units), "dropped": len(dropped), "trimmed": trimmed, "kept": len(kept),
                                   "sha256": got, "dropped_examples": dropped[:10]}
        log(f"  {name}: {len(units)} units, {trimmed} trimmed to their clean paragraphs, {len(dropped)} dropped by the guard")
        pools.setdefault((src["genre"], src["lang"]), []).append((name, kept, src["license"]))

    docs = []
    pool_stats = {}
    for (genre, lang), members in sorted(pools.items()):
        units, srcs = build.interleave([u for _, u, _ in members]), build.interleave([[n] * len(u) for n, u, _ in members])
        lic = {n: l for n, _, l in members}
        cap = POOL_TOKENS.get((genre, lang))
        total, k, cur, cur_src, cur_tok = 0, 0, [], set(), 0
        for u, s in zip(units, srcs):
            if cap is not None and total >= cap:
                break
            n = len(htok.encode(u).ids)
            cur.append(u)
            cur_src.add(s)
            cur_tok += n
            total += n
            if cur_tok >= POOL_DOC_TOKENS:
                docs.append(_pool_doc(genre, lang, k, cur, cur_src, lic, cur_tok))
                k, cur, cur_src, cur_tok = k + 1, [], set(), 0
        if cur:
            docs.append(_pool_doc(genre, lang, k, cur, cur_src, lic, cur_tok))
            k += 1
        pool_stats[f"{genre}-{lang}"] = {"docs": k, "tokens": total}
        log(f"  pool {genre}-{lang}: {k} documents, {total:,} tokens")

    (out / "pool").mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(d, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for d in docs)
    (out / "pool" / "docs.jsonl").write_text(body, "utf-8")
    report["pool"] = pool_stats
    report["pool_sha256"] = hashlib.sha256(body.encode()).hexdigest()

    # Generated units, checked the same way.
    gcfg = cfg["generated"]
    gen_rows = []
    gdrop = 0
    for genre in gcfg["genres"]:
        for lang in gcfg["langs"]:
            rng = random.Random(f"{gcfg['seed']}:{genre}:{lang}")
            seen = set()
            while sum(1 for r in gen_rows if r["genre"] == genre and r["lang"] == lang) < gcfg["units_per_genre_lang"]:
                t = gen_unit(genre, lang, rng)
                if t in seen:
                    continue
                seen.add(t)
                _, hits = ix.check(t)
                if hits or short.check(t)[1]:
                    gdrop += 1
                    continue
                gen_rows.append({"genre": genre, "lang": lang, "text": t})
    with open(out / "generated.jsonl", "w", encoding="utf-8") as f:
        for r in gen_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    report["generated"] = {"units": len(gen_rows), "dropped_by_guard": gdrop}
    (out / "pool_report.json").write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(f"wrote {out / 'pool' / 'docs.jsonl'}: {len(docs)} documents, sha256 {report['pool_sha256']}")
    for n, s in report["unpinned"].items():
        log(f"  not pinned in sources_v7.yaml: sources.{n}.sha256: {s}")
    return 0


def _pool_doc(genre, lang, k, units, srcs, lic, ntok):
    return {"id": f"v7pool-{genre}-{lang}-{k}", "kind": "benign", "lang": lang, "genre": genre, "text": "\n\n".join(units),
            "source": "+".join(sorted(srcs)), "license": "; ".join(f"{s}: {lic[s]}" for s in sorted(srcs)),
            "split": "dev", "tokens": ntok}


def read_dump(prefix: str) -> dict[str, dict]:
    out = {}
    for f in sorted(glob.glob(prefix + "-*.jsonl.gz")):
        with gzip.open(f, "rt", encoding="utf-8") as fh:
            for ln in fh:
                d = json.loads(ln)
                out[d["id"]] = d
    if not out:
        raise SystemExit(f"no dump files {prefix}-*.jsonl.gz")
    return out


def stage_rows(args) -> int:
    out, _ = paths()
    cfg, _ = load_cfg()
    pool = {}
    with open(out / "pool" / "docs.jsonl", encoding="utf-8") as f:
        for ln in f:
            d = json.loads(ln)
            pool[d["id"]] = d
    clean = {}
    with open(args.sanitized, encoding="utf-8") as f:
        for ln in f:
            d = json.loads(ln)
            clean[d["id"]] = d["text"]
    dump = read_dump(args.dump)
    mine, samp = cfg["mine"], cfg["sample"]
    cand: dict[tuple[str, str], list] = collections.defaultdict(list)
    mined: dict[str, list] = collections.defaultdict(list)
    for did, d in pool.items():
        dd = dump.get(did)
        if dd is None or dd.get("rejected") or did not in clean:
            continue
        tb = clean[did].encode("utf-8")
        for w in dd.get("windows") or []:
            text = tb[w["s"]:w["e"]].decode("utf-8", errors="ignore").strip()
            if len(text) < 200:
                continue
            item = {"doc": did, "s": w["s"], "e": w["e"], "p": w["p"], "l2": w.get("l2", 0.0), "l1": w.get("l1", 0.0),
                    "text": text, "genre": d["genre"], "lang": d["lang"], "source": d["source"], "license": d["license"]}
            if w["p"] >= mine["fused_at_least"] or w.get("l2", 0.0) >= mine["l2_at_least"]:
                mined[d["lang"]].append(item)
            else:
                cand[(d["genre"], d["lang"])].append(item)
    rows = []
    stats: dict = {"mined_found": {k: len(v) for k, v in mined.items()}, "mined": {}, "sampled": {}, "generated": {}}
    for lang, items in sorted(mined.items()):
        items.sort(key=lambda x: (-max(x["p"], x["l2"]), x["doc"], x["s"]))
        keep = items[: mine["cap_per_lang"]]
        stats["mined"][lang] = collections.Counter(f"{x['genre']}" for x in keep)
        rows += [_row(x, "v7_hardneg") for x in keep]
    rng = random.Random(f"{samp['seed']}:sample")
    for key in sorted(cand):
        want = int(samp["windows"].get(f"{key[0]}-{key[1]}", 0))
        items = cand[key]
        pick = rng.sample(items, min(want, len(items)))
        stats["sampled"][f"{key[0]}-{key[1]}"] = {"available": len(items), "taken": len(pick)}
        rows += [_row(x, "v7_long") for x in sorted(pick, key=lambda x: (x["doc"], x["s"]))]
    with open(out / "generated.jsonl", encoding="utf-8") as f:
        for i, ln in enumerate(f):
            g = json.loads(ln)
            rows.append({"id": f"{g['lang']}-v7gen-{hashlib.sha256(g['text'].encode()).hexdigest()[:12]}", "text": g["text"],
                         "labels": ["benign"], "lang": g["lang"], "variant": "orig", "source": "guard-spec:v7-gen",
                         "license": "Apache-2.0", "group": f"v7.gen.{g['genre']}", "kind": "v7_gen", "set": "v7",
                         "origin": f"generated:{g['genre']}"})
            stats["generated"][f"{g['genre']}-{g['lang']}"] = stats["generated"].get(f"{g['genre']}-{g['lang']}", 0) + 1
    seen, uniq = set(), []
    for r in rows:
        if r["text"] in seen:
            continue
        seen.add(r["text"])
        uniq.append(r)
    stats["rows"] = len(uniq)
    stats["by_kind_lang"] = collections.Counter(f"{r['kind']}:{r['lang']}" for r in uniq)
    p = out / "v7_train.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for r in uniq:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    stats["v7_train_sha256"] = sha256_file(p)
    stats["inputs"] = {"pool_sha256": sha256_file(out / "pool" / "docs.jsonl"), "dump_files": sorted(glob.glob(args.dump + "-*.jsonl.gz")),
                       "dump_sha256": {Path(f).name: sha256_file(Path(f)) for f in sorted(glob.glob(args.dump + "-*.jsonl.gz"))},
                       "generated_sha256": sha256_file(out / "generated.jsonl")}
    (out / "stats_v7.json").write_text(json.dumps(stats, indent=1, ensure_ascii=False, default=dict) + "\n", "utf-8")
    log(json.dumps(stats, indent=1, ensure_ascii=False, default=dict))
    return 0


def _row(x, kind):
    h = hashlib.sha256(x["text"].encode()).hexdigest()[:12]
    return {"id": f"{x['lang']}-v7-{h}", "text": x["text"], "labels": ["benign"], "lang": x["lang"], "variant": "orig",
            "source": x["source"], "license": x["license"], "group": f"v7.{x['genre']}.{x['doc']}", "kind": kind, "set": "v7",
            "origin": f"{x['doc']}:{x['s']}-{x['e']}", "v6_fused": round(x["p"], 6), "v6_l2": round(x["l2"], 6)}


def stage_check(args) -> int:
    import build

    out, bench = paths()
    tok = tokenizer_fn(build.find_tokenizer(None))
    holdouts = holdout_files(args.holdout_rows)
    ix, gstats, short = guard_index(tok, bench, args.embedded, holdouts)
    counts: collections.Counter = collections.Counter()
    examples: dict = {}
    rows = [json.loads(ln) for ln in open(out / "v7_train.jsonl", encoding="utf-8") if ln.strip()]
    kept = ix.filter_rows(rows, counts, "v7_train.jsonl", examples)
    contained = sum(1 for r in kept if short.check(r["text"])[1])
    rep = {"k": 50, "index": gstats, "index_shingles": ix.shingles, "rows": len(rows), "rows_clean": len(kept),
           "short_holdout_12token_overlap": contained, "counts": dict(counts), "examples": examples,
           "v7_train_sha256": sha256_file(out / "v7_train.jsonl")}
    (out / "guard_v7.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", "utf-8")
    log(json.dumps({k: v for k, v in rep.items() if k != "index"}, indent=1, ensure_ascii=False))
    return 0 if len(kept) == len(rows) and contained == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stage", choices=["pool", "rows", "check"])
    ap.add_argument("--embedded", action="append", default=[],
                    help="further bench documents (glob of docs.jsonl), e.g. the R5 and long6 embedded-attack documents")
    ap.add_argument("--holdout-rows", action="append", default=[], help="further hold-out row files (glob)")
    ap.add_argument("--dump", help="rows: the mining run's -dump prefix")
    ap.add_argument("--sanitized", help="rows: JSONL {id, text} of the sanitized pool documents")
    a = ap.parse_args()
    return {"pool": stage_pool, "rows": stage_rows, "check": stage_check}[a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
