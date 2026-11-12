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
**dev half of `eval/`** (ids ending in hex 0–7; the `eval/` holdout half is
never used, see below) into a 2k-token host (a 28 KB one for the segment
boundary): at the start, the end, a random place, across a 256-token
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

**Dev and holdout slices.** Every document carries a `split` (`dev` or
`holdout`), the `eval/` convention: the last hex digit of a SHA-256 of the
document id, or of the payload id for attack and control documents so that all
variants of one payload fall in one slice (full profile: 38 / 34 benign, 384 /
384 attack documents; `long` profile: 66 / 62 benign). The report has the false-positive and detection tables
for both slices next to the totals (`doc_fpr_by_split`, `tpr_by_split`);
anything tuned on this benchmark reads the dev slice only. The training data
builders keep the corpus out of training: no 50-token shingle of any bench/long
document may appear in a v6 training row (`train/data/bench_guard.py`).

The payloads come from the **dev half of `eval/`** since 2026-11-11: a model
selected on the bench dev slice (the v6 gates) must never have seen
`eval/`-holdout wording, so that the `eval/` holdout half stays a clean final
measurement. The bench slice of an attack document is a second, independent
hash of the payload id, so bench dev and bench holdout still use disjoint
payloads (full profile: 32 per language, 32 dev / 32 holdout; quick: 12 per
language, 13 / 11). Before that date the payloads were the `eval/` holdout
half; the benign and host documents did not change, but the numbers published
below from earlier runs were measured on holdout payloads and are not directly
comparable with runs on the current corpus (`outputs` in
[`bench/long/corpus.yaml`](../bench/long/corpus.yaml) pins both).

**Baselines on the current corpus (full profile, dev / holdout).** Apple M3
Max (14 cores), ONNX Runtime 1.31.1, 2026-11-11, the working tree of the
payload change on top of `b381615`; full profile (912 documents, 9.4M tokens,
docs.jsonl `bfd045cc…`), `l1,l2` at the 0.85 block threshold, score pass only
(`-skip-latency -workers 4`, 26 minutes per model); `guardspec-classifier-v3b`
(the shipped default) and `guardspec-classifier-v5` with its own calibration
(Platt, logreg, L2 untrusted cap 0.88). Reference points for the v6 gates,
not tuning targets; nothing was tuned on them. Small cells: 1 to 7 benign
documents per size and slice, 15 / 17 EN and 17 / 15 VI payloads (dev /
holdout) times the variants of a group. The `>100k` bucket of the report
holds the Vietnamese 500k document.

Document false positives at 0.85 (`l1,l2`), dev / holdout (documents):

| Size | v3b EN | v3b VI | v5 EN | v5 VI |
|---|---:|---:|---:|---:|
| 20k | 40.0% / 50.0% (5 / 4) | 33.3% / 33.3% (6 / 3) | 20.0% / 25.0% | 50.0% / 66.7% |
| 50k | 28.6% / 50.0% (7 / 2) | 50.0% / 40.0% (4 / 5) | 28.6% / 50.0% | 50.0% / 40.0% |
| 100k | 33.3% / 50.0% (3 / 6) | 75.0% / 50.0% (4 / 4) | 33.3% / 16.7% | 75.0% / 25.0% |
| 200k | 40.0% / 25.0% (5 / 4) | 66.7% / 100% (3 / 4) | 20.0% / 25.0% | 66.7% / 75.0% |
| 500k | 100% / 100% (1 / 1) | – / 100% (0 / 1) | 0.0% / 100% | – / 100% |

Detection (gateway decision, `l1,l2`), dev / holdout, pooled over the variants
of a group:

| Payload | v3b EN | v3b VI | v5 EN | v5 VI |
|---|---:|---:|---:|---:|
| alone (`control`) | 100% / 88.2% | 88.2% / 100% | 93.3% / 88.2% | 94.1% / 100% |
| start / end / random place | 66.7% / 43.1% | 39.2% / 46.7% | 100% / 80.4% | 94.1% / 100% |
| across a window / chunk / segment boundary | 82.2% / 56.9% | 49.0% / 57.8% | 100% / 90.2% | 96.1% / 100% |
| split, adjacent / far apart | 23.3% / 23.5% | 17.6% / 26.7% | 96.7% / 70.6% | 88.2% / 90.0% |
| zero-width / tag characters | 86.7% / 67.6% | 67.6% / 73.3% | 100% / 94.1% | 100% / 96.7% |
| code comment / JSON field | 96.7% / 67.6% | 82.4% / 80.0% | 100% / 91.2% | 100% / 100% |
| embedded, all variants | 71.7% / 51.5% | 50.0% / 56.1% | 99.4% / 85.3% | 95.6% / 97.8% |

**The classifier's cap.** These baselines were measured before `cmd/benchlong`
applied the classifier's cap for untrusted content (`calibration.json`
`l2_untrusted_max`, which `cmd/eval -path tool` and the gateway apply to
documents and tool results): the v5 rows above are v5 *without* its cap. Since
the v6 work (task RF-895d3533) `cmd/benchlong -l2cap on` (the default) caps
every fused chunk as the gateway does and the report header records it
(`l2_cap`); `-l2cap off` reproduces the earlier behaviour. v3b has no cap, so
its rows are unchanged. v5 with the cap is in `train/MODEL_CARD.md` ("v6",
hold-outs).

**More documents at 100k and 200k tokens: the `long` profile.** The full
profile has one document per genre and size, so its 100k and 200k cells hold
3 to 6 documents: with none blocked, the Clopper-Pearson 95% upper bound of
the false-positive rate is still about 0.4 to 0.6 per cell (0.22 over the 15
dev documents of the v6 gate G6). The `long` profile
(`make bench-long PROFILE=long`, 2026-11-11, task RF-895d3533 R2b) adds 128
benign documents, 32 English and 33 / 31 Vietnamese per size (100k / 200k
tokens; 19.08M tokens in all, 66 dev / 62 holdout), and no attacks, from
sources whose text is disjoint from the quick/full ones (licences in
[`bench/long/corpus.yaml`](../bench/long/corpus.yaml)):

- English: Wikipedia (6 per size), the U.S. Code titles 5, 7, 10, 12, 15, 18
  and 29 (5), Go standard library and toolchain files interleaved with
  Kubernetes example manifests (4), the Kubernetes documentation (tasks,
  concepts, reference; 5), books, essays, speeches and other texts of the
  English Wikisource (5), 35 RFCs (4), the Apache access log sample of
  elastic/examples (2) and synthetic logs (1);
- Vietnamese: Wikipedia (11), laws and codes of the Vietnamese Wikisource (7),
  its literature, poetry, history and other texts (6), Vietnamese translations
  of the Kubernetes, React and Vue documentation (2 at 100k; too short for
  200k), and synthetic logs (2), JSON, CSV, e-mail threads, chat transcripts
  and hard negatives (1 each).

Every source is pinned (revision or commit, file or subtree SHA, SHA-256 of
the extracted text), the synthetic genres use their own seed, and
[`bench/long/exclude.json`](../bench/long/exclude.json) lists the source
units that share a run of 50 classifier tokens with a v6 training or
validation row (`train/data/bench_guard.py`, 22,461 rows): 2,467 units over
10 sources, mostly U.S. Code statutory notes and Vietnamese laws (the v6 data
draws on both), which the builder skips. The Python library reference was
dropped as a source for the same reason (the v6 data holds it). After the
exclusion the guard finds no overlap between the 128 documents and any v6
row. This is a measurement, not a selection: v6 (arm A) was chosen before,
and the holdout half is scored once per model.

Scored on the Apple M3 Max (14 cores), ONNX Runtime 1.31.1, 2026-11-11,
commit `2b805cc` (docs.jsonl `ccd7b905…`), `l1,l2` at the 0.85 block
threshold with each model's own calibration (`-l2cap on`: v5 and v6 with
their cap 0.88, v3b has none), score pass only (`-skip-latency -workers 4`,
ONNX Runtime's default threads): 38 to 42 minutes per model (v3b 2,288 s,
v5 2,426 s, v6 2,521 s; 7,900 / 7,400 / 7,100 tokens/s over 4 documents at a
time; 24,700 to 26,900 CPU-seconds). Blocked benign documents / documents,
with the rate and its Clopper-Pearson 95% upper bound:

| Split | Lang | Size | v3b | v5 (cap) | v6 (cap) |
|---|---|---|---:|---:|---:|
| dev | EN | 100k | 13 / 16 (81%, ≤ 95%) | 7 / 16 (44%, ≤ 67%) | 6 / 16 (38%, ≤ 61%) |
| dev | EN | 200k | 11 / 13 (85%, ≤ 97%) | 5 / 13 (38%, ≤ 65%) | 2 / 13 (15%, ≤ 41%) |
| dev | VI | 100k | 14 / 18 (78%, ≤ 92%) | 5 / 18 (28%, ≤ 50%) | 1 / 18 (6%, ≤ 24%) |
| dev | VI | 200k | 16 / 19 (84%, ≤ 96%) | 13 / 19 (68%, ≤ 85%) | 8 / 19 (42%, ≤ 63%) |
| holdout | EN | 100k | 11 / 16 (69%, ≤ 87%) | 5 / 16 (31%, ≤ 55%) | 3 / 16 (19%, ≤ 42%) |
| holdout | EN | 200k | 18 / 19 (95%, ≤ 100%) | 8 / 19 (42%, ≤ 63%) | 5 / 19 (26%, ≤ 48%) |
| holdout | VI | 100k | 11 / 15 (73%, ≤ 90%) | 8 / 15 (53%, ≤ 76%) | 3 / 15 (20%, ≤ 44%) |
| holdout | VI | 200k | 8 / 12 (67%, ≤ 88%) | 7 / 12 (58%, ≤ 82%) | 4 / 12 (33%, ≤ 61%) |
| dev | both | 100k + 200k | 54 / 66 (81.8%, ≤ 89.2%) | 30 / 66 (45.5%, ≤ 56.3%) | 17 / 66 (25.8%, ≤ 36.1%) |
| holdout | both | 100k + 200k | 48 / 62 (77.4%, ≤ 85.8%) | 28 / 62 (45.2%, ≤ 56.4%) | 15 / 62 (24.2%, ≤ 34.8%) |
| holdout | EN | 100k + 200k | 29 / 35 (82.9%) | 13 / 35 (37.1%) | 8 / 35 (22.9%, ≤ 37.5%) |
| holdout | VI | 100k + 200k | 19 / 27 (70.4%) | 15 / 27 (55.6%) | 7 / 27 (25.9%, ≤ 43.2%) |

- **What the larger sample says.** The v6 gate G6 saw 0 of 15 dev documents
  blocked (upper bound 0.22); on 66 dev and 62 holdout documents v6 blocks
  about one benign document in four at 100k to 200k tokens (all 128:
  25.0%, 95% interval 17.9% to 31.8%), the same on both slices and both
  languages. That is a third of v3b (80%) and about half of v5 (45%) on the
  same documents, and far from the 1% the gate asked for: the 0 / 15 was a
  small-sample result. The share of chunks at or above 0.85 drops from v3b's
  12% on English code and documentation, 10% on RFCs, 7% on Wikisource
  prose and 47% on synthetic Vietnamese logs to at most 0.4% in any genre
  for v6 (v5: 15.6% on the Vietnamese hard negatives, under 1% elsewhere);
  a document of 50 to 100 chunks is still blocked by its single worst
  chunk.
- **The sanitizer, not the model, decides some documents.** The gateway's
  sanitizer runs before scoring. It rejects both Vietnamese documentation
  documents at 100k ("input exceeds 8 layers of encoding": a React page whose
  JSX reads as nested tags to the HTML stripping, which does not settle in 8
  passes); they count as blocked in the report's gateway column, not in the
  model rates above (the two 100k VI cells hold 18 and 15 documents, one of
  each unscored). Its HTML stripping also shortens 11 English documents
  before the model sees them: Go code with Kubernetes manifests at 200k to
  138k and 141k tokens, Kubernetes documentation at 100k to 72k to 89k and
  at 200k to 122k to 154k (one to 25k), and one RFC document from 200k to
  1,177 tokens (an unclosed `<` swallows the rest). The cells use the
  document's nominal size. `cmd/benchlong` labels sizes by the corpus's own
  token count since this commit; the three runs above were labelled by the
  scored count and re-assembled by document (three documents were scored
  again alone to attribute one mixed cell: `long-docs-en-100000-4` is the
  one blocked by v5 and v6).
- The report files are kept with the training data outside the repository
  (`guardspec-data/v6/bench-long/long-{v3b,v5,v6}.{json,md}`). The timing
  of single long documents is in [sizing, Long inputs](sizing.md#long-inputs).

**The gateway's long path and a document-level rule (task RF-895d3533 R3).**
A document of 100k tokens reaches the gateway's long path (`MAX_SCAN_TOKENS`),
which scores 256-token windows (fused with L1, the cap and code corroboration),
not the 2,048-byte chunks above; `cmd/benchlong -long on` measures that path
as it runs (layer `long`). With it, v6 blocks 9 / 65 dev and 14 / 61 holdout
`long` documents (13.8% and 23.0%; the two rejected documents are not
counted). Payloads embedded in such documents (`bench/long/embed_long.py`:
the full profile's 32 dev and 32 holdout payloads in the seven placements of
the v6 gate G7, each in a long document of its own language and slice) are
caught as well as alone: 95.9% of 221 dev and 88.1% of 218 holdout documents,
against 93.8% and 90.6% for the payloads alone. Four document-level rules
were pre-registered and fitted on dev only
([`train/reports/r3_preregistration.md`](../train/reports/r3_preregistration.md)):
counting a window over 0.85 only when the rules (L1) corroborate it, a
threshold that grows with the number of windows (extreme-value fit), both, or
k windows over 0.85. None reached 1% without losing the embedded attacks: on
dev every benign window over 0.85 is one where an L1 rule fires (10 of 12 with
the classifier agreeing, 2 on an L1 floor alone), the blocked documents' worst
windows score 0.92 to 0.985, and the payloads' windows score in the same range
(median 0.986). The chosen rule (corroboration) blocks 13 / 61 holdout
documents (21.3%, 95% interval 11.9% to 33.7%) at an unchanged 88.1%
detection, so it is not used; `calibration.json` can carry such a rule
(`long_doc`) but no shipped model has one. Details in
[`train/MODEL_CARD.md`](../train/MODEL_CARD.md) (v6, R3).

**New long documents, tightened rules and a stricter decision (task RF-895d3533 R5).**
Because both halves of `long` had been scored, R5 built a new profile,
`long5` (150 benign documents of 100k and 200k tokens from sources and units
no other profile uses, 74 dev / 76 holdout; 80 new eval/ dev-half payloads,
alone and in the seven G7 placements), and pre-registered ten
combinations of two L1 rule sets (v6 as shipped, and R5's: Vietnamese
homographs such as "giàu"/"giấu", single adverbs of secrecy under the
corroboration bar, tighter hidden-note, refusal-suppression, password-trick
and decode rules) with five long-path decisions (today's, R3's L1
corroboration, an L1 floor counting only when L2 agrees, and two higher
corroboration bars)
([`train/reports/r5_preregistration.md`](../train/reports/r5_preregistration.md)).
The R5 rules leave eval/data and val_v3 unchanged. On dev no combination
blocked no benign document; the one blocking fewest (R5 rules, bar at a raw
rule weight 0.75) blocked 4 / 74 against 13 / 74 for v6 as it is. Scored once
on the holdout it blocks **5 / 76 documents (6.6%, 95% interval 2.2% to
14.7%)** against 11 / 76 (14.5%) for v6, and catches 86.3% of 227 embedded
payloads against 81.8% for the same payloads alone (v6 as it is: 89.9%). The
1% target is not met at either size, so the decision is not shipped; the R5
rules are kept. Details in [`train/MODEL_CARD.md`](../train/MODEL_CARD.md)
(v6, R5).

The quick profile was run the same day with both models (and the `l1,l2,l3`
set as well); its numbers agree with the full ones within the sample sizes.
The run reports are kept with the training data outside the repository; the
tables committed under `bench/results/` still come from the earlier corpus.

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

Reproduce: `make bench-long` (quick), `make bench-long PROFILE=full` or
`make bench-long PROFILE=long` (the 100k and 200k documents); see
[sizing, Long inputs](sizing.md#long-inputs) for running it on your own
hardware or your own documents.

The results will also appear on [guardspec.io/docs](https://guardspec.io/docs/),
which is built from this page.
