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
