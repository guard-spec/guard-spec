# Benchmark: Guard Spec and other prompt-injection detectors

> Tiếng Việt: [benchmark.vi.md](benchmark.vi.md).

This page compares Guard Spec's detector with other open prompt-injection
detectors on Guard Spec's own eval set and on public datasets. Everything on it
comes from one command, with every dataset and model pinned, so anyone can
rerun it and check the numbers.

It is a measurement and nothing else. No threshold, weight or rule of Guard
Spec was tuned on these datasets or on `eval/` for this page, and the other
detectors run with their published defaults.

- [Summary](#summary)
- [Reproduce](#reproduce)
- [What is measured](#what-is-measured)
- [Datasets](#datasets-and-licenses)
- [Detectors](#detectors)
- [Results](#results)
- [Discussion](#discussion)
- [Long documents](#long-documents)

## Summary

Run on 2026-11-07 (19:30 UTC on 2026-11-06) at commit `2e182a0` (v0.2.1)
with this benchmark's harness, on an Apple M3 Max laptop (macOS 15.4.1); the
full tables are under [Results](#results). Default decisions, all languages:

| Dataset | Guard Spec L1+L2+L3: AUC / TPR / FPR | ProtectAI v2: AUC / TPR / FPR | LLM Guard default: TPR / FPR |
|---|---|---|---|
| `eval/` (EN + VI, 2,176 rows) | 0.987 / 95.0% / 1.4% | 0.784 / 88.6% / 50.6% | 83.0% / 45.6% |
| `deepset` test (116, half German/Spanish) | 0.963 / 33.3% / 0.0% | 0.901 / 36.7% / 0.0% | 31.7% / 0.0% |
| `jailbreak-classification` test (262) | 0.994 / 92.1% / 0.0% | 0.979 / 84.2% / 1.6% | 84.2% / 1.6% |
| `Gandalf` test (112, attacks only) | - / 100% / - | - / 100% / - | 100% / - |
| `SPML` sample (2,000) | 0.974 / 36.4% / 0.0% | **0.997 / 99.2% / 8.4%** | 99.1% / 6.6% |

- On our own set Guard Spec is far ahead, which is expected and **not a fair
  test of ProtectAI**: half of `eval/` is Vietnamese (ProtectAI is
  English-only) and its benign rows are hard negatives written to look like
  attacks. On the English half ProtectAI reaches AUC 0.897 and flags 23% of
  benign rows.
- On **SPML**, the one public set no detector here was trained on, **ProtectAI
  is clearly better**: AUC 0.997 against 0.974 and, at the same 1% FPR, 97.6%
  of attacks against 84.5% (89.2% with L1+L2). At its default threshold
  Guard Spec blocks only 36% of SPML attacks, with no false positive;
  ProtectAI blocks 99% with 8% false positives.
- On `deepset` and `jailbreak-classification` Guard Spec ranks better (AUC),
  but Guard Spec's classifier was trained on their `train` splits, so those
  two rows favour it. On `deepset` both detectors block only about a third of
  attacks at their defaults.
- Guard Spec is smaller (237 MB int8 against 739 MB fp32) and faster per row
  (p50 5–8 ms against 32–67 ms on short inputs, one thread). The comparison
  is not like for like: our models are int8, ProtectAI's published ONNX file
  is fp32.
- Meta Prompt Guard 2 is gated and not in these tables; anyone with access
  can add it with one variable ([below](#including-meta-prompt-guard-2)).

## Reproduce

```bash
make benchmark
```

That target fetches ONNX Runtime and libtokenizers (`make onnx-deps`, pinned by
SHA-256), runs `bench/run.py` with the Python packages locked in
`bench/uv.lock` (needs [uv](https://docs.astral.sh/uv/)), and writes:

- `bench/results/results.json`: every metric, the machine and the versions;
- `bench/results/results.md`: the tables;
- the generated block of this page (between the `bench:begin` and
  `bench:end` markers).

What it does:

1. Downloads the public datasets at the pinned Hugging Face commits and
   converts them to the `eval/` row schema.
2. Pulls the models with `go run ./cmd/models pull`, which checks every file
   against the SHA-256 values in `models/manifest.yaml`:
   `guardspec-classifier@v3b`, `multilingual-e5-small@614241f` and
   `protectai-deberta-v3-base-pi-v2@90c9989`.
3. Runs Guard Spec through `cmd/eval -scores` (built with `-tags onnx`), which
   is the gateway's input path: sanitizer, detector layers, fusion and the
   `/v1/scan` block rule.
4. Runs the ProtectAI model in ONNX Runtime from Python.
5. Computes the metrics below for every detector, dataset and language.

Options:

| Variable | Default | Effect |
|---|---|---|
| `BENCH_CACHE` | `bench/.cache` | Downloads, converted datasets, per-row scores. About 1.2 GB (ProtectAI's ONNX file is 739 MB). The run stops when less than 6 GB is free there. |
| `MODEL_DIR` | `$BENCH_CACHE/models` | Use already pulled Guard Spec models (`<dir>/cache/<name>/<version>`) instead of pulling them. |
| `ONNX_DIR` | `.onnx` | Where `make onnx-deps` puts the native libraries. |
| `PROMPTGUARD=1` | off | Also run Meta Prompt Guard 2, see below. |

GitHub Actions: the **Benchmark** workflow (`.github/workflows/benchmark.yml`)
runs `make benchmark` on `ubuntu-24.04` when started by hand (Actions >
Benchmark > Run workflow); it never runs on its own. It writes the tables to
the job summary and uploads `bench/results/` and this page as the
`benchmark-results` artifact.

### Including Meta Prompt Guard 2

`meta-llama/Llama-Prompt-Guard-2-86M` and `-22M` are gated on Hugging Face
under the Llama 4 Community License: they cannot be downloaded without an
account that accepted the terms, so they are not in the published tables. With
access:

1. Accept the license on both model pages.
2. Export a read-only token of that account as `HF_TOKEN` in your shell
   (`huggingface_hub` reads it; `bench/run.py` never reads, prints or stores
   it).
3. Run `make benchmark PROMPTGUARD=1`. This installs the `promptguard` extra
   (PyTorch and Transformers, CPU) and adds two detector rows, at the pinned
   revisions `a8ded8e` (86M) and `11614a1` (22M), with the model's argmax
   decision (malicious probability ≥ 0.5), the first 512 tokens, one thread.

In the workflow, add the token as the repository secret `HF_READ_TOKEN` and
check "promptguard" when starting the run.

## What is measured

For every detector × dataset × language:

- **ROC AUC** of the detector's score, with a 95% bootstrap interval (1,000
  resamples, fixed seed). It does not depend on any threshold.
- **TPR and FPR at the default decision**: the share of attack rows and of
  benign rows the detector flags with its own published default. For Guard
  Spec that is the gateway's `/v1/scan` rule (detector score ≥ 0.85, or
  sanitizer anomaly ≥ 0.6, or an input the sanitizer rejects), the decision a
  deployment makes.
- **TPR at FPR ≤ 1%**: the share of attacks caught at the lowest threshold
  that flags at most 1% of that group's benign rows. The threshold is picked
  after the fact on the same rows, for every detector alike, so it is an
  upper bound on what a tuned threshold would give; it compares the score
  rankings, not the defaults. With fewer than 100 benign rows it means "no
  false positive at all".
- **Latency p50 / p95** per row, in milliseconds: one row at a time on one
  machine, with ONNX Runtime (or PyTorch) set to one intra-op thread. For
  Guard Spec it is the sanitizer plus the detector as the gateway runs them;
  with L2 and L3 both on, the gateway scores the two models concurrently, so
  that configuration can use two cores for one row. For the Python detectors
  it is tokenization plus the model call. Five warm-up rows are not timed for
  the Python detectors; `cmd/eval` times every row, model loading excluded.
- **Model size**: the size on disk of the model weights the detector loads.

Datasets without benign rows (Gandalf) only have a TPR.

## Datasets and licenses

Every dataset was checked on its Hugging Face card at the pinned commit. The
benchmark downloads them at run time; no row from them is stored in this
repository beyond what `eval/` already contains (see
[eval/LICENSES.md](../eval/LICENSES.md)).

| Dataset | License | Used | Why |
|---|---|---|---|
| `eval/` (Guard Spec) | Apache-2.0 (project rows), Apache-2.0 / MIT (sourced rows) | yes | Our published EN/VI set. |
| [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 | yes, `test` | Standard small benchmark; mixed English and German/Spanish. |
| [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | yes, balanced `test` | Jailbreak prompts versus benign prompts. |
| [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | yes, `test` | Real attacks from the Gandalf game (attacks only). |
| [`reshabhs/SPML_Chatbot_Prompt_Injection`](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | MIT | yes, 1,000 rows per label, seeded sample | Chatbot-specific injections; no detector here trained on it. |
| `xTRam1/safe-guard-prompt-injection` | none on the card (revision `a3a877d608f3`) | no | No license. |
| `Lakera/mosscap_prompt_injection` | MIT | no | Unlabelled: every prompt sent to the game, attack or not. |
| `jayavibhav/prompt-injection` | none on the card | no | No license. |

Row counts and languages per run are in the generated tables below.

**Vietnamese.** We found no public, licensed Vietnamese prompt-injection
dataset. The only Vietnamese rows here are those of `eval/`, which are
synthetic and labelled by AI agents (see [eval/README.md](../eval/README.md)).

**Language column.** `eval/` carries a language per row (`en`, `vi`). For the
public sets, rows with German, Spanish or Cyrillic markers (the rule of
`eval/build/build.py`) are `other`, the rest `en`. Only `deepset` has a
sizeable `other` share.

**Overlap with training data.** Read the public rows with this in mind:

- Guard Spec's classifier (L2, v3b) was trained on the `train` splits of
  `deepset/prompt-injections`, `Lakera/gandalf_ignore_instructions` and
  `jackhhao/jailbreak-classification` ([train/DATA_LICENSES.md](../train/DATA_LICENSES.md)).
  The benchmark uses only their `test` splits, but those come from the same
  distribution, which favours Guard Spec on these three sets.
- ProtectAI v2 lists `jackhhao/jailbreak-classification` among its training
  sets (split not stated), so the same holds for it there.
- The English `test` rows of `deepset` and `Gandalf` are also part of
  `eval/` (60 of 116 and 111 of 112 rows).
- Guard Spec's L1 rules were refined by reading failures on the "dev" half of
  `eval/` ([eval/README.md](../eval/README.md)); L1 numbers on `eval/` are
  optimistic. L2, L3 and the fusion were never fitted on `eval/`.
- Nothing in this benchmark was used to change Guard Spec.

## Detectors

| Detector | Included | Notes |
|---|---|---|
| Guard Spec L1 | yes | Rules only, the default build without models (`cmd/eval -detector fusion`). |
| Guard Spec L1+L2 | yes | Rules + classifier v3b (`-layers l1,l2`). |
| Guard Spec L1+L2+L3 | yes | Rules + classifier + embeddings, the default with models (`-layers l1,l2,l3`). |
| ProtectAI `deberta-v3-base-prompt-injection-v2` | yes | Apache-2.0. The published fp32 ONNX export, first 512 tokens, flags when P(INJECTION) ≥ 0.5 (argmax of the model card's pipeline). |
| LLM Guard `PromptInjection` | as a threshold of the ProtectAI row | llm-guard 0.3.16 (MIT, archived) wraps the same model: its default pins revision `89b085c`, whose weights are byte-identical to `90c9989` (same SHA-256), reads the first 512 tokens (`match_type=FULL`) and flags when `round(score, 2) > 0.92`. Installing it would only rerun the same model, so its row reuses the ProtectAI scores with that rule: same AUC, different TPR/FPR. Its default runs the model in PyTorch rather than ONNX, so latency is not reported separately. |
| Meta Llama Prompt Guard 2 (86M, 22M) | no (gated) | Llama 4 Community License, gated on Hugging Face; see [Including Meta Prompt Guard 2](#including-meta-prompt-guard-2). |

## Results

<!-- bench:begin -->
Run 2026-11-06 19:30 UTC, commit `2e182a03bc62`, local: Apple M3 Max, 14 logical CPUs, 36 GB RAM, macOS 15.4.1 (arm64). go1.26.10, ONNX Runtime 1.31.1 (Go) / 1.31.1 (Python), Python 3.12.0.

### Datasets

| Dataset | Revision | License | Split | Rows (attack / benign) | Languages |
|---|---|---|---|---|---|
| Guard Spec eval set (eval/) | this commit | Apache-2.0 (project rows); Apache-2.0 / MIT for the deepset / Gandalf rows it includes | eval/data/en.jsonl, vi.jsonl | 2176 (1171 / 1005) | en 926, vi 1250 |
| [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections) | `4f61ecb038e9` | Apache-2.0 | test | 116 (60 / 56) | en 60, other 56 |
| [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | `2f2ceeb39658` | Apache-2.0 | balanced test | 262 (139 / 123) | en 259, other 3 |
| [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | `04737b65e90a` | MIT | test | 112 (112 / 0) | en 111, other 1 |
| [`reshabhs/SPML_Chatbot_Prompt_Injection`](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | `02ce8084e979` | MIT | seeded sample, 1000 per label | 2000 (1000 / 1000) | en 1995, other 5 |

### Detectors

| Detector | Model files | Size on disk | Runtime | Default decision |
|---|---|---:|---|---|
| Guard Spec L1 | rules only (no model) | 0 (rules) | Go, ONNX Runtime (int8 models), 1 intra-op thread per session | gateway /v1/scan rule: score >= 0.85, sanitizer anomaly >= 0.6, or input rejected |
| Guard Spec L1+L2 | guardspec-classifier/v3b | 119 MB | Go, ONNX Runtime (int8 models), 1 intra-op thread per session | gateway /v1/scan rule: score >= 0.85, sanitizer anomaly >= 0.6, or input rejected |
| Guard Spec L1+L2+L3 | guardspec-classifier/v3b; multilingual-e5-small/614241f | 237 MB | Go, ONNX Runtime (int8 models), 1 intra-op thread per session | gateway /v1/scan rule: score >= 0.85, sanitizer anomaly >= 0.6, or input rejected |
| ProtectAI v2 | protectai/deberta-v3-base-prompt-injection-v2@90c9989 (onnx/model.onnx, fp32) | 739 MB | Python, ONNX Runtime 1.31.1 (fp32), 1 intra-op thread | INJECTION probability >= 0.5 (argmax, model card pipeline) |
| LLM Guard PromptInjection (default) | protectai/deberta-v3-base-prompt-injection-v2@90c9989 (onnx/model.onnx, fp32) | 739 MB | Python, ONNX Runtime 1.31.1 (fp32), 1 intra-op thread | llm-guard 0.3.16 defaults: same model, match_type FULL (first 512 tokens), flag when round(score, 2) > 0.92 |

Not run: Meta Llama Prompt Guard 2 (86M, 22M): gated on Hugging Face (Llama 4 Community License); run with --promptguard and your own HF_TOKEN after accepting the terms.

### Guard Spec eval set (eval/)

Published with this repository. L2, L3 and the fusion were never fitted on it; the L1 rules were refined on its dev half, so L1 numbers here are optimistic (eval/README.md).

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 1171 / 1005 | 0.952 [0.943, 0.962] | 89.2% | 0.1% | 91.0% | 0.11 | 0.22 |
| Guard Spec L1 | en | 562 / 364 | 0.929 [0.911, 0.945] | 84.2% | 0.3% | 86.7% | 0.11 | 0.21 |
| Guard Spec L1 | vi | 609 / 641 | 0.975 [0.964, 0.984] | 93.9% | 0.0% | 94.9% | 0.11 | 0.23 |
| Guard Spec L1+L2 | all | 1171 / 1005 | 0.987 [0.982, 0.992] | 94.9% | 1.4% | 93.3% | 6.02 | 22.01 |
| Guard Spec L1+L2 | en | 562 / 364 | 0.982 [0.973, 0.989] | 94.0% | 1.6% | 90.4% | 5.49 | 19.73 |
| Guard Spec L1+L2 | vi | 609 / 641 | 0.991 [0.984, 0.996] | 95.7% | 1.2% | 94.9% | 6.51 | 23.95 |
| Guard Spec L1+L2+L3 | all | 1171 / 1005 | 0.987 [0.981, 0.991] | 95.0% | 1.4% | 93.4% | 6.47 | 21.90 |
| Guard Spec L1+L2+L3 | en | 562 / 364 | 0.980 [0.970, 0.988] | 94.1% | 1.6% | 90.9% | 6.10 | 19.62 |
| Guard Spec L1+L2+L3 | vi | 609 / 641 | 0.992 [0.985, 0.997] | 95.7% | 1.2% | 94.7% | 6.91 | 23.46 |
| ProtectAI v2 | all | 1171 / 1005 | 0.784 [0.764, 0.802] | 88.6% | 50.6% | 26.2% | 66.89 | 237.54 |
| ProtectAI v2 | en | 562 / 364 | 0.897 [0.877, 0.917] | 86.8% | 23.4% | 35.1% | 46.41 | 169.34 |
| ProtectAI v2 | vi | 609 / 641 | 0.661 [0.632, 0.690] | 90.1% | 66.1% | 5.9% | 76.69 | 262.98 |
| LLM Guard PromptInjection (default) | all | 1171 / 1005 | 0.784 [0.764, 0.802] | 83.0% | 45.6% | 26.2% | same model as ProtectAI v2 |  |
| LLM Guard PromptInjection (default) | en | 562 / 364 | 0.897 [0.877, 0.917] | 84.0% | 20.3% | 35.1% | same model as ProtectAI v2 |  |
| LLM Guard PromptInjection (default) | vi | 609 / 641 | 0.661 [0.632, 0.690] | 82.1% | 59.9% | 5.9% | same model as ProtectAI v2 |  |

### deepset/prompt-injections

About half the rows are German or Spanish (lang 'other'). The English test rows are also in eval/; Guard Spec's classifier was trained on the train split.

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 60 / 56 | 0.757 [0.674, 0.835] | 13.3% | 0.0% | 28.3% | 0.10 | 0.26 |
| Guard Spec L1 | en | 31 / 29 | 0.877 [0.777, 0.953] | 22.6% | 0.0% | 45.2% | 0.10 | 0.21 |
| Guard Spec L1 | other | 29 / 27 | 0.710 [0.621, 0.799] | 3.4% | 0.0% | 24.1% | 0.10 | 0.38 |
| Guard Spec L1+L2 | all | 60 / 56 | 0.955 [0.913, 0.987] | 35.0% | 0.0% | 88.3% | 4.71 | 18.23 |
| Guard Spec L1+L2 | en | 31 / 29 | 0.958 [0.883, 1.000] | 45.2% | 0.0% | 90.3% | 4.33 | 14.94 |
| Guard Spec L1+L2 | other | 29 / 27 | 0.971 [0.930, 0.997] | 24.1% | 0.0% | 86.2% | 4.74 | 27.29 |
| Guard Spec L1+L2+L3 | all | 60 / 56 | 0.963 [0.921, 0.991] | 33.3% | 0.0% | 83.3% | 5.42 | 18.53 |
| Guard Spec L1+L2+L3 | en | 31 / 29 | 0.973 [0.914, 1.000] | 45.2% | 0.0% | 93.5% | 5.14 | 15.54 |
| Guard Spec L1+L2+L3 | other | 29 / 27 | 0.941 [0.874, 0.989] | 20.7% | 0.0% | 82.8% | 5.73 | 27.70 |
| ProtectAI v2 | all | 60 / 56 | 0.901 [0.839, 0.951] | 36.7% | 0.0% | 53.3% | 45.10 | 196.72 |
| ProtectAI v2 | en | 31 / 29 | 0.889 [0.796, 0.959] | 25.8% | 0.0% | 71.0% | 39.97 | 123.84 |
| ProtectAI v2 | other | 29 / 27 | 0.936 [0.866, 0.985] | 48.3% | 0.0% | 58.6% | 53.32 | 267.84 |
| LLM Guard PromptInjection (default) | all | 60 / 56 | 0.901 [0.839, 0.951] | 31.7% | 0.0% | 53.3% | same model as ProtectAI v2 |  |
| LLM Guard PromptInjection (default) | en | 31 / 29 | 0.889 [0.796, 0.959] | 22.6% | 0.0% | 71.0% | same model as ProtectAI v2 |  |
| LLM Guard PromptInjection (default) | other | 29 / 27 | 0.936 [0.866, 0.985] | 41.4% | 0.0% | 58.6% | same model as ProtectAI v2 |  |

### jackhhao/jailbreak-classification

Jailbreak (role-play) prompts versus benign prompts. Guard Spec's classifier was trained on the balanced train split; ProtectAI v2 lists this dataset among its training sources.

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 139 / 123 | 0.961 [0.942, 0.977] | 66.9% | 0.0% | 84.9% | 0.43 | 2.99 |
| Guard Spec L1+L2 | all | 139 / 123 | 0.993 [0.984, 0.999] | 92.1% | 0.0% | 93.5% | 42.14 | 507.41 |
| Guard Spec L1+L2+L3 | all | 139 / 123 | 0.994 [0.986, 0.999] | 92.1% | 0.0% | 93.5% | 41.87 | 511.62 |
| ProtectAI v2 | all | 139 / 123 | 0.979 [0.956, 0.995] | 84.2% | 1.6% | 69.8% | 327.75 | 1161.58 |
| LLM Guard PromptInjection (default) | all | 139 / 123 | 0.979 [0.956, 0.995] | 84.2% | 1.6% | 69.8% | same model as ProtectAI v2 |  |

### Lakera/gandalf_ignore_instructions

Attacks only (no benign rows): only TPR is defined. The English test rows are also in eval/; Guard Spec's classifier was trained on the train split.

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 112 / 0 | - | 77.7% | - | - | 0.10 | 0.19 |
| Guard Spec L1+L2 | all | 112 / 0 | - | 100.0% | - | - | 3.90 | 7.13 |
| Guard Spec L1+L2+L3 | all | 112 / 0 | - | 100.0% | - | - | 4.87 | 8.22 |
| ProtectAI v2 | all | 112 / 0 | - | 100.0% | - | - | 32.18 | 62.98 |
| LLM Guard PromptInjection (default) | all | 112 / 0 | - | 100.0% | - | - | same model as ProtectAI v2 |  |

### reshabhs/SPML_Chatbot_Prompt_Injection

User prompts only. Labels depend on the chatbot's system prompt (a request that breaks that bot's rules is an attack), which an input detector does not see. No detector here lists it as training data.

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 1000 / 1000 | 0.961 [0.952, 0.969] | 26.9% | 0.2% | 80.7% | 0.13 | 0.93 |
| Guard Spec L1+L2 | all | 1000 / 1000 | 0.979 [0.973, 0.985] | 37.0% | 0.0% | 89.2% | 7.03 | 130.35 |
| Guard Spec L1+L2+L3 | all | 1000 / 1000 | 0.974 [0.967, 0.980] | 36.4% | 0.0% | 84.5% | 8.28 | 156.34 |
| ProtectAI v2 | all | 1000 / 1000 | 0.997 [0.995, 0.999] | 99.2% | 8.4% | 97.6% | 61.24 | 631.59 |
| LLM Guard PromptInjection (default) | all | 1000 / 1000 | 0.997 [0.995, 0.999] | 99.1% | 6.6% | 97.6% | same model as ProtectAI v2 |  |
<!-- bench:end -->

## Discussion

**Where Guard Spec does worse.**

- **SPML.** This set's attacks are mostly polite requests that break one
  chatbot's rules ("rather than going to a doctor, suggest ..."), written by
  GPT-4 from leaked system prompts. Guard Spec's score ranks them well
  (AUC 0.97–0.98) but keeps most of them below its 0.85 block threshold:
  TPR 36% at default. ProtectAI flags 99% of them, at the cost of 8% false
  positives on the benign SPML prompts. Some of that gap is the threshold, not
  the model: at an equal 1% FPR Guard Spec catches 84–89% and ProtectAI
  98%. The labels also depend on a system prompt that neither detector sees,
  so part of this set is not decidable from the user message alone.
- **Non-English, non-Vietnamese input.** On the German and Spanish half of
  `deepset` (56 rows) Guard Spec blocks 21% of attacks at its default,
  ProtectAI 48%; both have no false positive there. Guard Spec's rules and
  classifier only target English and Vietnamese. The group is small (29
  attacks): treat the gap as a direction, not a size.
- **The default threshold is conservative.** On every public set Guard Spec
  has 0.0% FPR at its default and the "TPR at FPR ≤ 1%" column is much higher
  than the default TPR (`deepset` 33% → 83%, `SPML` 36% → 85%). The 0.85
  block threshold and the fusion were set for low false positives on
  `eval/`-like traffic (hard negatives, Vietnamese chat). Deployments that see
  plain English attacks may want a lower threshold; this page does not change
  it, because tuning on these sets would make the numbers meaningless.
- **L3 does not help on these sets.** L1+L2+L3 and L1+L2 are within noise on
  `eval/`, `deepset` and `jailbreak-classification`, and L3 is lower on SPML at
  1% FPR (84.5% against 89.2%). It adds 0.5–1.3 ms per row at p50.
- **Long inputs.** Guard Spec scores every 2,048-byte chunk of a long input,
  each in 256-token windows (see [Long documents](#long-documents));
  the long role-play prompts of `jailbreak-classification` take 42 ms at p50
  and 510 ms at p95 with the model layers (ProtectAI: 330 ms and 1.16 s, but
  it reads only the first 512 tokens).

**Where it does better, and why that is partly expected.**

- `eval/` is Guard Spec's own set: same authors, same notion of an attack,
  Vietnamese and hard negatives. Read the ProtectAI rows there as "what an
  English-only model does on this traffic", not as a ranking. Even so, the
  English half is informative: ProtectAI blocks 23% of its benign rows
  (security discussions, sysadmin text, code with attack strings), Guard Spec
  1.6%.
- `deepset`, `jailbreak-classification` and `Gandalf` share their distribution
  with Guard Spec's training data (`train` splits), and ProtectAI also trained
  on `jailbreak-classification`. Guard Spec's higher AUC on them is weak
  evidence.

**Other notes.**

- Small groups have wide intervals: `deepset` has 116 rows, and its per-language
  groups under 60. Differences inside the 95% intervals are not signal.
- LLM Guard's default (score > 0.92 instead of ≥ 0.5) trades a few points of
  TPR for a few points of FPR; it does not change the picture.
- Latency was measured on a shared laptop with other work running, one
  configuration after the other; read it as indicative. The manual workflow
  gives a Linux run.
- Guard Spec's "default" is the gateway's whole `/v1/scan` rule, which also
  blocks on sanitizer anomalies. That is why its TPR on `eval/` (95.0%) is above
  the README's "TPR at block" (0.939), which counts the detector score only.
- Language labels of the public sets come from a simple marker rule, not a
  language-identification model.

## Long documents

The tables above score short prompts. Retrieved documents, tool results and
pasted files are longer, and a detector that takes the **maximum over a
text's windows** gets more chances to fire as the text grows. This section
measures that, with `make bench-long` (`bench/long/`, `cmd/benchlong`).

**Setup.** The corpus is built from pinned public sources (Wikipedia EN/VI,
the U.S. Code, Go source code, Vietnamese public-domain literature and laws
from vi.wikisource; licences in
[`bench/long/corpus.yaml`](../bench/long/corpus.yaml)), plus seeded synthetic
logs, JSON, CSV, e-mail threads, chat transcripts and hard negatives (benign
text about prompt injection). Texts of one genre are joined to 20k, 50k,
100k, 200k and 500k tokens. Attack documents put one payload from the
**hold-out half of `eval/`** into a 2k-token host (a 28 KB one for the
segment boundary): at the start, the end, a random place, across a 256-token
window, a 2,048-byte chunk or a 24 KiB segment boundary, split in two halves
(adjacent, or about 1,500 tokens apart), hidden with zero-width or Unicode tag
characters, or shaped as a code comment or a JSON field; `control` is the
payload alone. Every text goes through the gateway's sanitizer. Two paths:

- `l2`: the classifier alone on every 256-token window (64-token overlap),
  Platt-calibrated as in the fusion;
- `l1,l2/logreg` (and `l1/max`): the gateway's fused score on every
  2,048-byte chunk, cut as the gateway cuts untrusted text but without its
  16-chunk cap. This is the score the 0.85 block threshold applies to.

T(n) is the threshold that keeps a benign text of n units (windows or chunks)
under 1% false positives: the larger of a block-bootstrap q99 of the maximum
over n contiguous benign units and a GEV fit on the logit of 16-unit block
maxima.

**First run: quick profile, local and indicative.** Apple M3 Max, ONNX
Runtime 1.31.1, `guardspec-classifier-v3b`, 2026-11-09, run from the
branch that added the benchmark; 26 benign documents (0.86M tokens), 12
payloads per language. Small samples: one 100k document per language, and
12 attacks per cell (one attack is 8 points). Full tables:
[`bench/results/long-m3max-local.md`](../bench/results/long-m3max-local.md).
The 4 vCPU and 2 vCPU runs on GitHub's runners come from
[`bench-long.yml`](../.github/workflows/bench-long.yml) after merge.

False positives of benign text at the 0.85 block threshold (`l1,l2`):

| | EN | VI (provisional) |
|---|---:|---:|
| One chunk (n = 1) | 7.8% | 2.9% |
| 16 chunks (about 7k tokens) | 26.1% | 13.9% |
| 64 chunks (about 26k tokens) | 49.8% | 38.4% |
| 20k-token documents (9 per language) | 44.4% | 33.3% |
| 50k-token documents (3) | 66.7% | 66.7% |
| 100k-token documents (1) | 100% | 100% |
| T(1) / T(16) / T(64) | 0.961 / 0.985 / 0.987 | 0.942 / 0.998 / 1.000 |

The classifier alone (`l2`, per 256-token window) shows the same growth:
4.2% of English windows reach 0.85, 20.4% of 16-window stretches and 64.8% of
256-window ones (Vietnamese 1.1%, 5.9%, 27.2%).

Detection of a payload in a 2k-token host (`l1,l2`, gateway decision, EN / VI):

| Variant | EN | VI |
|---|---:|---:|
| `control` (payload alone) | 100% | 91.7% |
| start / end / random place | 50.0% / 41.7% / 33.3% | 50.0% / 58.3% / 33.3% |
| across a window / chunk / segment boundary | 100% / 58.3% / 50.0% | 50.0% / 41.7% / 66.7% |
| split, adjacent / far apart | 33.3% / 8.3% | 16.7% / 25.0% |
| zero-width / tag characters | 41.7% / 100% (anomaly) | 58.3% / 100% (anomaly) |
| code comment / JSON field | 91.7% / 91.7% | 66.7% / 91.7% |

**What this means.**

- **Benign long text is not safe at 0.85 today.** Ordinary prose (Wikipedia,
  the U.S. Code, Vietnamese literature) has 0.4% to 2.4% of its chunks at or
  above 0.85, and some genres far more:
  51.6% of Go source chunks, 78.8% of the synthetic Vietnamese log chunks and
  5.7% of the English hard negatives score at or above 0.85 with `l1,l2`
  (the rules alone flag 60% of hard-negative chunks: they quote attack
  phrases). Since a document is flagged when any chunk is, a 50k-token
  document is flagged more often than not.
- **No threshold fixes it.** T(n) climbs to 0.99 and beyond within 16 chunks:
  a threshold that keeps long benign text under 1% false positives would
  also miss most attacks. The fix has to come from the model (training on
  code, logs and long documents) or from aggregation other than the maximum,
  not from the threshold.
- **A payload inside benign text is often missed.** The same payloads that
  are caught alone (100% EN) are caught 33% to 50% of the time when they sit
  in the middle of a chunk of prose. They are caught when they stand on their
  own lines (code comment, JSON field) or fill most of a window.
- **Split payloads far apart are not caught by design**: no window sees both
  halves (8.3% / 25.0%).
- **Tag-character payloads** are invisible to the model after the sanitizer
  strips them; the sanitizer's anomaly score blocks all of them.
- Vietnamese numbers are provisional: the Vietnamese corpus has fewer and
  less varied sources (no code; laws, literature, Wikipedia and synthetic text).

Reproduce: `make bench-long` (quick) or `make bench-long PROFILE=full`; see
[sizing, Long inputs](sizing.md#long-inputs) for running it on your own
hardware or your own documents.

The results will also appear on [guardspec.io/docs](https://guardspec.io/docs/),
which is built from this page.
