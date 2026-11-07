"""Public benchmark: Guard Spec versus other prompt-injection detectors.

    make benchmark                      # from the repository root
    uv run --project bench --frozen python bench/run.py [--promptguard] [--update-doc docs/benchmark.md]

Measurement only: nothing here tunes a threshold or a weight of Guard Spec.
Every detector runs with its own published default threshold; "TPR at
FPR <= 1%" picks a threshold per detector and dataset after the fact and is
labelled as such.

Steps:
  1. Datasets: eval/data (Guard Spec's published EN/VI set) and public
     Hugging Face datasets at pinned commits (DATASETS below), converted to
     the eval/ row schema in $BENCH_CACHE/data/<name>/rows.jsonl.
  2. Models: `go run ./cmd/models pull` (SHA-256 checked against
     models/manifest.yaml) into $BENCH_CACHE/models, unless MODEL_DIR is set.
  3. Guard Spec: cmd/eval (-tags onnx) per dataset and layer set, i.e. the
     gateway's input path (sanitizer, detector, fusion) and its /v1/scan
     decision, with -scores for per-row output.
  4. ProtectAI deberta-v3-base-prompt-injection-v2 (ONNX, fp32) in ONNX
     Runtime; LLM Guard's PromptInjection default is the same model at a
     different threshold, scored from the same outputs.
  5. Meta Llama Prompt Guard 2 (86M, 22M) with --promptguard only: gated
     on Hugging Face; needs the "promptguard" extra and the user's own
     HF_TOKEN in the environment (never stored or logged here).
  6. Metrics per detector x dataset x language, written to
     bench/results/results.{json,md} (and docs/benchmark.md with --update-doc).

Environment: BENCH_CACHE (default bench/.cache), MODEL_DIR (already pulled
Guard Spec models; default: pulled into $BENCH_CACHE/models, as is ProtectAI),
CGO_LDFLAGS / ONNXRUNTIME_LIB as for `make eval-ml` (the Makefile sets them).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "bench" / "results"
SEED = 20261107
SPML_PER_CLASS = 1000  # rows sampled per label from SPML (16k rows in all)
MIN_LANG_ROWS = 20  # smallest language group reported on its own

# ---------------------------------------------------------------------------
# Datasets. Licenses were checked on each card at the pinned revision.
# ---------------------------------------------------------------------------

DATASETS = [
    {
        "name": "guardspec-eval",
        "title": "Guard Spec eval set (eval/)",
        "repo": None,
        "license": "Apache-2.0 (project rows); Apache-2.0 / MIT for the deepset / Gandalf rows it includes",
        "split": "eval/data/en.jsonl, vi.jsonl",
        "note": "Published with this repository. L2, L3 and the fusion were never fitted on it; the L1 rules were "
        "refined on its dev half, so L1 numbers here are optimistic (eval/README.md).",
    },
    {
        "name": "deepset",
        "title": "deepset/prompt-injections",
        "repo": "deepset/prompt-injections",
        "revision": "4f61ecb038e9c3fb77e21034b22511b523772cdd",
        "license": "Apache-2.0",
        "file": "data/test-00000-of-00001-701d16158af87368.parquet",
        "split": "test",
        "note": "About half the rows are German or Spanish (lang 'other'). The English test rows are also in eval/; "
        "Guard Spec's classifier was trained on the train split.",
    },
    {
        "name": "jailbreak-classification",
        "title": "jackhhao/jailbreak-classification",
        "repo": "jackhhao/jailbreak-classification",
        "revision": "2f2ceeb39658696fd3f462403562b6eea5306287",
        "license": "Apache-2.0",
        "file": "balanced/jailbreak_dataset_test_balanced.csv",
        "split": "balanced test",
        "note": "Jailbreak (role-play) prompts versus benign prompts. Guard Spec's classifier was trained on the "
        "balanced train split; ProtectAI v2 lists this dataset among its training sources.",
    },
    {
        "name": "gandalf",
        "title": "Lakera/gandalf_ignore_instructions",
        "repo": "Lakera/gandalf_ignore_instructions",
        "revision": "04737b65e90a6794ec227012e4a255a7def6344b",
        "license": "MIT",
        "file": "data/test-00000-of-00001-bc92128b9288a6d1.parquet",
        "split": "test",
        "note": "Attacks only (no benign rows): only TPR is defined. The English test rows are also in eval/; "
        "Guard Spec's classifier was trained on the train split.",
    },
    {
        "name": "spml",
        "title": "reshabhs/SPML_Chatbot_Prompt_Injection",
        "repo": "reshabhs/SPML_Chatbot_Prompt_Injection",
        "revision": "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
        "license": "MIT",
        "file": "spml_prompt_injection.csv",
        "split": f"seeded sample, {SPML_PER_CLASS} per label",
        "note": "User prompts only. Labels depend on the chatbot's system prompt (a request that breaks that "
        "bot's rules is an attack), which an input detector does not see. No detector here lists it as "
        "training data.",
    },
]

# Excluded after checking (recorded in docs/benchmark.md):
EXCLUDED_DATASETS = [
    ("xTRam1/safe-guard-prompt-injection", "no license on the card at a3a877d608f3"),
    ("Lakera/mosscap_prompt_injection", "MIT, but unlabelled: every prompt sent to the game, attack or not"),
    ("jayavibhav/prompt-injection", "no license on the card"),
]

# German / Spanish / Russian markers (same rule as eval/build/build.py).
NON_ENGLISH = re.compile(r"[äöüßÄÖÜЀ-ӿñ¿¡]")
NON_ENGLISH_WORDS = {
    "ich", "sie", "und", "der", "das", "ist", "nicht", "wie", "mit", "zu", "auf", "mir", "dich",
    "du", "wir", "ein", "eine", "dem", "sich", "gibt", "welche", "auch", "oder", "aber",
    "bitte", "jetzt", "alle", "alles", "frage", "schreibe", "antworte", "geld", "viel", "deutschland",
    "europa", "wieviele", "einem",
    "yo", "tu", "dices", "todo", "que", "dije", "olvide", "si",
}


def lang_of(text: str) -> str:
    if NON_ENGLISH.search(text):
        return "other"
    words = set(re.findall(r"[a-zA-Z]+", text.lower()))
    return "other" if words & NON_ENGLISH_WORDS else "en"


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

GUARDSPEC_CONFIGS = [
    # name, cmd/eval arguments, models it loads
    ("Guard Spec L1", ["-detector", "fusion"], []),
    ("Guard Spec L1+L2", ["-layers", "l1,l2"], ["guardspec-classifier/v3b"]),
    ("Guard Spec L1+L2+L3", ["-layers", "l1,l2,l3"], ["guardspec-classifier/v3b", "multilingual-e5-small/614241f"]),
]
PROTECTAI = "protectai-deberta-v3-base-pi-v2/90c9989"
PROMPTGUARD = [
    ("Prompt Guard 2 86M", "meta-llama/Llama-Prompt-Guard-2-86M", "a8ded8e697ce7c355e395a0df51f94adb4a2fd27"),
    ("Prompt Guard 2 22M", "meta-llama/Llama-Prompt-Guard-2-22M", "11614a155199674a0a95e6602d6ab0417b790ed0"),
]
LLMGUARD_THRESHOLD = 0.92  # llm-guard 0.3.16 PromptInjection: flags round(score, 2) > 0.92


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def run(cmd, env=None, **kw):
    log("+", " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, check=True, env=env, cwd=REPO, **kw)


# ---------------------------------------------------------------------------
# Step 1: datasets
# ---------------------------------------------------------------------------


def row(name, i, text, label, lang, source, license_):
    return {
        "id": f"{name}-{i:05d}",
        "text": text,
        "label": label,
        "category": "",
        "lang": lang,
        "variant": "orig",
        "source": source,
        "license": license_,
    }


def load_public(ds, cache: Path) -> list[dict]:
    from huggingface_hub import hf_hub_download
    import pyarrow.parquet as pq

    path = hf_hub_download(ds["repo"], ds["file"], repo_type="dataset", revision=ds["revision"],
                           cache_dir=str(cache / "hf"))
    src = f"{ds['repo']}:{ds['split']}"
    out = []
    if ds["name"] == "deepset":
        for r in pq.read_table(path).to_pylist():
            t = r["text"].strip()
            out.append((t, "attack" if r["label"] == 1 else "benign"))
    elif ds["name"] == "gandalf":
        for r in pq.read_table(path).to_pylist():
            out.append((r["text"].strip(), "attack"))
    elif ds["name"] == "jailbreak-classification":
        with open(path, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                out.append((r["prompt"].strip(), "attack" if r["type"] == "jailbreak" else "benign"))
    elif ds["name"] == "spml":
        with open(path, encoding="utf-8", newline="") as f:
            rows = [(r["User Prompt"].strip(), "attack" if r["Prompt injection"] == "1" else "benign")
                    for r in csv.DictReader(f)]
        # Deterministic sample: distinct prompts, ordered by a seeded hash.
        seen, by_label = set(), {"attack": [], "benign": []}
        for t, lab in rows:
            if t and t not in seen:
                seen.add(t)
                by_label[lab].append(t)
        out = []
        for lab, ts in by_label.items():
            ts.sort(key=lambda t: hashlib.sha256(f"{SEED}:{t}".encode()).hexdigest())
            out += [(t, lab) for t in ts[:SPML_PER_CLASS]]
    else:
        raise ValueError(ds["name"])
    return [row(ds["name"], i, t, lab, lang_of(t), src, ds["license"]) for i, (t, lab) in enumerate(out) if t]


def prepare_datasets(cache: Path) -> dict[str, Path]:
    dirs = {}
    for ds in DATASETS:
        d = cache / "data" / ds["name"]
        d.mkdir(parents=True, exist_ok=True)
        if ds["repo"] is None:
            rows = []
            for f in sorted((REPO / "eval" / "data").glob("*.jsonl")):
                rows += [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
        else:
            rows = load_public(ds, cache)
        with open(d / "rows.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        dirs[ds["name"]] = d
        log(f"dataset {ds['name']}: {len(rows)} rows")
    return dirs


def read_rows(d: Path) -> list[dict]:
    return [json.loads(line) for line in (d / "rows.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Step 2-3: Guard Spec via cmd/eval
# ---------------------------------------------------------------------------


def ensure_models(cache: Path) -> tuple[Path, Path]:
    """Model roots (<root>/cache/<name>/<version>) for Guard Spec and for
    ProtectAI. `pull` skips files already present and checks every SHA-256."""
    root = cache / "models"
    want = ["protectai-deberta-v3-base-pi-v2@90c9989"]
    gs_root = Path(os.environ["MODEL_DIR"]) if os.environ.get("MODEL_DIR") else root
    if not os.environ.get("MODEL_DIR"):
        want += ["guardspec-classifier@v3b", "multilingual-e5-small@614241f"]
    run(["go", "run", "./cmd/models", "pull", "-dir", str(root / "cache"), *want])
    return gs_root, root


def model_bytes(model_dir: Path, rel: str) -> int:
    d = model_dir / "cache" / rel
    return sum(p.stat().st_size for p in d.glob("*.onnx"))


def run_guardspec(cache: Path, model_dir: Path, dirs: dict[str, Path], reuse: bool) -> dict:
    binary = cache / "bin" / "eval"
    binary.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CGO_ENABLED="1")
    run(["go", "build", "-tags", "onnx", "-o", str(binary), "./cmd/eval"], env=env)
    env.update(MODEL_DIR=str(model_dir), INFERENCE_INTRA_OP_THREADS="1")
    out = {}
    for name, args, models in GUARDSPEC_CONFIGS:
        per_ds = {}
        for ds, d in dirs.items():
            scores_path = cache / "scores" / f"{slug(name)}-{ds}.jsonl"
            scores_path.parent.mkdir(parents=True, exist_ok=True)
            if not (reuse and scores_path.exists()):
                run([str(binary), "-data", str(d), *args, "-scores", str(scores_path)], env=env,
                    stdout=subprocess.DEVNULL)
            per_ds[ds] = read_jsonl(scores_path)
        out[name] = {
            "rows": per_ds,
            "threshold": "gateway /v1/scan rule: score >= 0.85, sanitizer anomaly >= 0.6, or input rejected",
            "model_bytes": sum(model_bytes(model_dir, m) for m in models),
            "models": models or ["rules only (no model)"],
            "runtime": "Go, ONNX Runtime (int8 models), 1 intra-op thread per session",
        }
    return out


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


# ---------------------------------------------------------------------------
# Step 4-5: other detectors
# ---------------------------------------------------------------------------


def softmax(x):
    e = np.exp(x - x.max())
    return e / e.sum()


def time_rows(rows, score_fn, warmup=5):
    for r in rows[:warmup]:
        score_fn(r["text"])
    out = []
    for r in rows:
        t0 = time.perf_counter_ns()
        s = score_fn(r["text"])
        us = (time.perf_counter_ns() - t0) / 1e3
        out.append({"id": r["id"], "label": r["label"], "lang": r["lang"], "score": float(s), "latency_us": us})
    return out


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def run_protectai(cache: Path, model_dir: Path, dirs: dict[str, Path], reuse: bool) -> dict:
    import onnxruntime as ort
    from tokenizers import Tokenizer

    d = model_dir / "cache" / PROTECTAI
    cfg = json.loads((d / "config.json").read_text())
    inj = int({v: k for k, v in cfg["id2label"].items()}["INJECTION"])
    tok = Tokenizer.from_file(str(d / "tokenizer.json"))
    tok.enable_truncation(max_length=512)  # as the model card's pipeline and LLM Guard (match_type FULL)
    tok.no_padding()
    so = ort.SessionOptions()
    so.intra_op_num_threads, so.inter_op_num_threads = 1, 1
    so.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    sess = ort.InferenceSession(str(d / "model.onnx"), so, providers=["CPUExecutionProvider"])
    names = [i.name for i in sess.get_inputs()]

    def score(text):
        enc = tok.encode(text)
        feed = {"input_ids": np.array([enc.ids], dtype=np.int64),
                "attention_mask": np.array([enc.attention_mask], dtype=np.int64)}
        if "token_type_ids" in names:
            feed["token_type_ids"] = np.zeros_like(feed["input_ids"])
        logits = sess.run(None, {k: v for k, v in feed.items() if k in names})[0][0]
        return softmax(logits)[inj]

    per_ds = {}
    for ds, dd in dirs.items():
        path = cache / "scores" / f"protectai-v2-{ds}.jsonl"
        if reuse and path.exists():
            per_ds[ds] = read_jsonl(path)
        else:
            per_ds[ds] = time_rows(read_rows(dd), score)
            write_jsonl(path, per_ds[ds])
        for r in per_ds[ds]:
            r["blocked"] = r["score"] >= 0.5
        log(f"ProtectAI v2 {ds}: done")
    base = {
        "model_bytes": (d / "model.onnx").stat().st_size,
        "models": ["protectai/deberta-v3-base-prompt-injection-v2@90c9989 (onnx/model.onnx, fp32)"],
        "runtime": f"Python, ONNX Runtime {ort.__version__} (fp32), 1 intra-op thread",
    }
    llmguard = {ds: [dict(r, blocked=round(r["score"], 2) > LLMGUARD_THRESHOLD) for r in rows]
                for ds, rows in per_ds.items()}
    return {
        "ProtectAI v2": dict(base, rows=per_ds, threshold="INJECTION probability >= 0.5 (argmax, model card pipeline)"),
        "LLM Guard PromptInjection (default)": dict(
            base, rows=llmguard, same_scores_as="ProtectAI v2",
            threshold="llm-guard 0.3.16 defaults: same model, match_type FULL (first 512 tokens), "
            "flag when round(score, 2) > 0.92"),
    }


def run_promptguard(cache: Path, dirs: dict[str, Path]) -> tuple[dict, list[str]]:
    out, skipped = {}, []
    try:
        import torch
        from huggingface_hub import snapshot_download
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError:
        return out, ["Prompt Guard 2: the 'promptguard' extra is not installed (uv sync --extra promptguard)"]
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    for name, repo, rev in PROMPTGUARD:
        try:
            # huggingface_hub reads HF_TOKEN from the environment itself; this
            # script never reads, prints or stores it.
            path = snapshot_download(repo, revision=rev, cache_dir=str(cache / "hf"),
                                     allow_patterns=["*.json", "*.safetensors"])
        except Exception as e:  # gated: no token, or terms not accepted
            skipped.append(f"{name}: not downloadable without access ({type(e).__name__}); see docs/benchmark.md")
            continue
        tok = AutoTokenizer.from_pretrained(path)
        model = AutoModelForSequenceClassification.from_pretrained(path).eval()

        def score(text, tok=tok, model=model):
            with torch.inference_mode():
                enc = tok(text, return_tensors="pt", truncation=True, max_length=512)
                return torch.softmax(model(**enc).logits[0], -1)[1].item()

        per_ds = {ds: time_rows(read_rows(d), score) for ds, d in dirs.items()}
        for rows in per_ds.values():
            for r in rows:
                r["blocked"] = r["score"] >= 0.5
        out[name] = {
            "rows": per_ds,
            "threshold": "LABEL_1 (malicious) probability >= 0.5 (argmax)",
            "model_bytes": sum(p.stat().st_size for p in Path(path).glob("*.safetensors")),
            "models": [f"{repo}@{rev[:7]} (safetensors, fp32)"],
            "runtime": f"Python, PyTorch {torch.__version__} (fp32), 1 thread",
        }
    return out, skipped


# ---------------------------------------------------------------------------
# Step 6: metrics (same definitions as internal/evalset)
# ---------------------------------------------------------------------------


def roc_auc(pos, neg):
    if len(pos) == 0 or len(neg) == 0:
        return None
    s = np.concatenate([np.asarray(pos, dtype=float), np.asarray(neg, dtype=float)])
    order = s.argsort(kind="mergesort")
    ranks = np.empty(len(s))
    ss = s[order]
    i = 0
    while i < len(ss):  # average ranks over ties
        j = i
        while j < len(ss) and ss[j] == ss[i]:
            j += 1
        ranks[order[i:j]] = (i + 1 + j) / 2
        i = j
    n_p, n_n = len(pos), len(neg)
    return float((ranks[:n_p].sum() - n_p * (n_p + 1) / 2) / (n_p * n_n))


def threshold_at_fpr(neg, budget=0.01):
    s = sorted(neg)
    allowed = math.floor(budget * len(s) + 1e-9)
    for i in range(len(s) + 1):
        if 0 < i < len(s) and s[i] == s[i - 1]:
            continue
        if len(s) - i <= allowed:
            return -math.inf if i == 0 else math.nextafter(s[i - 1], math.inf)
    return math.inf


def auc_ci(pos, neg, n=1000):
    if not pos or not neg:
        return None
    rng = np.random.default_rng(SEED)
    p, q = np.asarray(pos), np.asarray(neg)
    vals = [roc_auc(rng.choice(p, len(p)), rng.choice(q, len(q))) for _ in range(n)]
    return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]


def pct(xs, p):
    if not xs:
        return None
    s = sorted(xs)
    return s[max(1, min(len(s), math.ceil(p / 100 * len(s)))) - 1]


def metrics(rows):
    pos = [r["score"] for r in rows if r["label"] == "attack"]
    neg = [r["score"] for r in rows if r["label"] == "benign"]
    bp = [r["blocked"] for r in rows if r["label"] == "attack"]
    bn = [r["blocked"] for r in rows if r["label"] == "benign"]
    m = {
        "n_attack": len(pos), "n_benign": len(neg),
        "roc_auc": roc_auc(pos, neg), "roc_auc_ci95": auc_ci(pos, neg),
        "tpr_default": sum(bp) / len(bp) if bp else None,
        "fpr_default": sum(bn) / len(bn) if bn else None,
        "tpr_at_fpr1": None, "fpr_at_fpr1": None,
        "latency_p50_ms": pct([r["latency_us"] / 1e3 for r in rows], 50),
        "latency_p95_ms": pct([r["latency_us"] / 1e3 for r in rows], 95),
    }
    if pos and neg:
        t = threshold_at_fpr(neg)
        m["tpr_at_fpr1"] = sum(s >= t for s in pos) / len(pos)
        m["fpr_at_fpr1"] = sum(s >= t for s in neg) / len(neg)
    return m


def all_metrics(detectors):
    out = {}
    for det, info in detectors.items():
        for ds, rows in info["rows"].items():
            # Languages get their own rows when at least two of them have
            # MIN_LANG_ROWS rows or more (all rows stay in "all").
            by_lang = {}
            for r in rows:
                by_lang.setdefault(r["lang"], []).append(r)
            big = {k: v for k, v in sorted(by_lang.items()) if len(v) >= MIN_LANG_ROWS}
            groups = {"all": rows}
            if len(big) > 1:
                groups.update(big)
            for g, rs in groups.items():
                out.setdefault(det, {}).setdefault(ds, {})[g] = metrics(rs)
    return out


# ---------------------------------------------------------------------------
# Environment and report
# ---------------------------------------------------------------------------


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def machine():
    cpu = ""
    if sys.platform == "darwin":
        cpu = sh(["sysctl", "-n", "machdep.cpu.brand_string"])
        mem = int(sh(["sysctl", "-n", "hw.memsize"]) or 0)
        os_name = f"macOS {platform.mac_ver()[0]} ({platform.machine()})"
    else:
        for line in sh(["lscpu"]).splitlines():
            if line.startswith("Model name:"):
                cpu = line.split(":", 1)[1].strip()
        mem = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"
        rel = Path("/etc/os-release")
        if rel.exists():
            m = re.search(r'^PRETTY_NAME="?([^"\n]*)', rel.read_text(), re.M)
            if m:
                os_name = f"{m.group(1)}, kernel {platform.release()} ({platform.machine()})"
    ort_go = re.search(r"^ORT_VERSION=(\S+)", (REPO / "build" / "onnx-deps.sh").read_text(), re.M)
    return {
        "date_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "commit": sh(["git", "rev-parse", "HEAD"]),
        "os": os_name,
        "cpu": cpu,
        "logical_cpus": os.cpu_count(),
        "ram_gb": round(mem / 2**30),
        "runner": os.environ.get("RUNNER_LABEL", "local"),
        "go": sh(["go", "env", "GOVERSION"]),
        "onnxruntime_go": ort_go.group(1) if ort_go else "",
        "python": platform.python_version(),
        "packages": {p: metadata.version(p) for p in
                     ("onnxruntime", "tokenizers", "huggingface_hub", "numpy", "pyarrow", "torch", "transformers")
                     if _installed(p)},
    }


def _installed(p):
    try:
        metadata.version(p)
        return True
    except metadata.PackageNotFoundError:
        return False


def fmt(x, digits=3):
    return "-" if x is None else f"{x:.{digits}f}"


def fmt_pct(x):
    return "-" if x is None else f"{100 * x:.1f}%"


def report_md(res):
    ds_by = {d["name"]: d for d in DATASETS}
    lines = []
    m = res["machine"]
    lines += [
        f"Run {m['date_utc']} UTC, commit `{m['commit'][:12]}`, {m['runner']}: {m['cpu']}, {m['logical_cpus']} logical "
        f"CPUs, {m['ram_gb']} GB RAM, {m['os']}. {m['go']}, ONNX Runtime {m['onnxruntime_go']} (Go) / "
        f"{m['packages'].get('onnxruntime', '-')} (Python), Python {m['python']}.",
        "",
        "### Datasets",
        "",
        "| Dataset | Revision | License | Split | Rows (attack / benign) | Languages |",
        "|---|---|---|---|---|---|",
    ]
    for name, info in res["datasets"].items():
        d = ds_by[name]
        rev = f"`{d['revision'][:12]}`" if d.get("revision") else "this commit"
        title = f"[`{d['repo']}`](https://huggingface.co/datasets/{d['repo']})" if d["repo"] else d["title"]
        langs = ", ".join(f"{k} {v}" for k, v in sorted(info["langs"].items()))
        lines.append(f"| {title} | {rev} | {d['license']} | {d['split']} | {info['rows']} "
                     f"({info['attack']} / {info['benign']}) | {langs} |")
    lines += ["", "### Detectors", "",
              "| Detector | Model files | Size on disk | Runtime | Default decision |", "|---|---|---:|---|---|"]
    for det, info in res["detectors"].items():
        size = f"{info['model_bytes'] / 1e6:.0f} MB" if info["model_bytes"] else "0 (rules)"
        lines.append(f"| {det} | {'; '.join(info['models'])} | {size} | {info['runtime']} | {info['threshold']} |")
    for s in res["skipped"]:
        lines.append(f"\nNot run: {s}.")
    for name in res["datasets"]:
        lines += ["", f"### {ds_by[name]['title']}", "", ds_by[name]["note"], "",
                  "| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | "
                  "TPR @ FPR ≤ 1% | p50 ms | p95 ms |",
                  "|---|---|---|---|---:|---:|---:|---:|---:|"]
        for det in res["detectors"]:
            groups = res["metrics"][det][name]
            for g in ["all"] + sorted(k for k in groups if k != "all"):
                x = groups[g]
                ci = x["roc_auc_ci95"]
                auc = fmt(x["roc_auc"]) + (f" [{ci[0]:.3f}, {ci[1]:.3f}]" if ci else "")
                same = res["detectors"][det].get("same_scores_as")
                lat = ("same model as ProtectAI v2", "") if same else (fmt(x["latency_p50_ms"], 2),
                                                                      fmt(x["latency_p95_ms"], 2))
                lines.append(f"| {det} | {g} | {x['n_attack']} / {x['n_benign']} | {auc} | {fmt_pct(x['tpr_default'])} "
                             f"| {fmt_pct(x['fpr_default'])} | {fmt_pct(x['tpr_at_fpr1'])} | {lat[0]} | {lat[1]} |")
    return "\n".join(lines) + "\n"


def update_doc(path: Path, md: str):
    text = path.read_text(encoding="utf-8")
    begin, end = "<!-- bench:begin -->", "<!-- bench:end -->"
    i, j = text.index(begin) + len(begin), text.index(end)
    path.write_text(text[:i] + "\n" + md + text[j:], encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--promptguard", action="store_true",
                    help="also run Meta Prompt Guard 2 (gated: needs access and HF_TOKEN in the environment)")
    ap.add_argument("--out", type=Path, default=RESULTS, help="results directory (default bench/results)")
    ap.add_argument("--update-doc", type=Path, help="replace the generated block of this markdown file")
    ap.add_argument("--reuse-scores", action="store_true",
                    help="reuse per-row scores already in $BENCH_CACHE/scores (re-render only; "
                    "latency then comes from the earlier run)")
    args = ap.parse_args()

    cache = Path(os.environ.get("BENCH_CACHE") or REPO / "bench" / ".cache").resolve()
    cache.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(cache).free / 2**30
    log(f"cache {cache} ({free:.1f} GB free)")
    if free < 6:
        sys.exit(f"less than 6 GB free in {cache}; set BENCH_CACHE to a larger disk")

    dirs = prepare_datasets(cache)
    gs_models, other_models = ensure_models(cache)
    detectors = run_guardspec(cache, gs_models, dirs, args.reuse_scores)
    detectors.update(run_protectai(cache, other_models, dirs, args.reuse_scores))
    skipped = []
    if args.promptguard:
        pg, skipped = run_promptguard(cache, dirs)
        detectors.update(pg)
    else:
        skipped.append("Meta Llama Prompt Guard 2 (86M, 22M): gated on Hugging Face (Llama 4 Community License); "
                       "run with --promptguard and your own HF_TOKEN after accepting the terms")

    datasets = {}
    for name, d in dirs.items():
        rows = read_rows(d)
        langs = {}
        for r in rows:
            langs[r["lang"]] = langs.get(r["lang"], 0) + 1
        datasets[name] = {"rows": len(rows), "attack": sum(r["label"] == "attack" for r in rows),
                          "benign": sum(r["label"] == "benign" for r in rows), "langs": langs}
    prev = args.out / "results.json"
    if args.reuse_scores and prev.exists():  # the scores (and latencies) are from that run
        mach = json.loads(prev.read_text(encoding="utf-8"))["machine"]
    else:
        mach = machine()
    res = {
        "machine": mach,
        "datasets": datasets,
        "dataset_sources": DATASETS,
        "excluded_datasets": EXCLUDED_DATASETS,
        "detectors": {k: {kk: vv for kk, vv in v.items() if kk != "rows"} for k, v in detectors.items()},
        "skipped": skipped,
        "metrics": all_metrics(detectors),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(res, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md = report_md(res)
    (args.out / "results.md").write_text(md, encoding="utf-8")
    if args.update_doc:
        update_doc(args.update_doc, md)
    print(md)


if __name__ == "__main__":
    main()
