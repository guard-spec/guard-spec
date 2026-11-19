---
license: apache-2.0
language: [en, vi]
pipeline_tag: text-classification
base_model: intfloat/multilingual-e5-small
library_name: onnx
tags:
  - prompt-injection
  - jailbreak
  - guardrail
  - llm-security
  - onnx
  - int8
  - multilingual
  - vietnamese
model-index:
  - name: guardspec-classifier-v8f
    results: []
---

<!--
Copyright 2026 The Guard Spec Authors
SPDX-License-Identifier: Apache-2.0
-->

# guardspec-classifier (v8f, shadow-mode candidate — not validated)

**Not the default and not recommended.** v8f is published only so that Guard Spec users can run it in **shadow mode**
next to the default (v8e): the gateway keeps deciding with v8e and records what v8f would have decided. It is one seed
(20261107) of R8c's arm EPL. The arm **did not meet** its pre-registered criteria: two of its three seeds each missed
one criterion. This seed met every criterion, but it was picked *after* the holdout was scored, so its holdout numbers
below are optimistic. Do not use v8f as your L2 model in production.

## Versions and branches

| branch | version | status |
|---|---|---|
| `main`, [`v8e`](https://huggingface.co/guard-spec/guardspec-classifier/tree/v8e) | **v8e** | **default** |
| [`v8f`](https://huggingface.co/guard-spec/guardspec-classifier/tree/v8f) | v8f | shadow-mode candidate, not validated (this card) |
| [`v3b`](https://huggingface.co/guard-spec/guardspec-classifier/tree/v3b) | v3b | earlier default, kept for rollback |

In Guard Spec (files checked against the SHA-256 in the gateway's manifest; a signed mirror is on the GitHub release
`model-guardspec-classifier-v8f`):

```sh
models pull guardspec-classifier@v8f
SHADOW_L2_MODEL=guardspec-classifier@v8f   # v8e keeps deciding; see docs/models.md, Shadow mode
```

## What v8f changes

v8f is v8e's recipe (R7 arm E: v6's data plus `v8e_train.jsonl`, 5 epochs, epoch chosen on the v6 validation files)
with three additions (`train/reports/r8c_preregistration.md`):
- **persona hard negatives:** 1,573 benign persona and role-play prompts (R8b);
- **L:** 1,500 benign windows of long technical documentation (docs, RFCs, READMEs, man pages), each paired with a
  window of the same host carrying a training payload;
- **S:** 400 payload-splitting attacks and 400 hard negatives, English and Vietnamese.

It is calibrated like v8e, on the same 12,785 validation rows, and carries v8e's `long_doc` and
`l2_untrusted_max` (0.88). INT8 only: there is no FP16 file.

## Evaluation (R8c, fresh holdouts, scored once; this seed was chosen afterwards)

All scores are INT8 on the CPU, through Guard Spec's gateway path, against v8e's three seeds (`train/reports/r8c_report.md`):

| | **v8f** (EPL seed 3) | v8e seed band | EPL arm (3 seeds) |
|---|---|---|---|
| persona3 benign blocked, EN (396) | **0.5%** | 1.5–2.3% | 0.5–0.8% |
| persona3 benign blocked, VI (117) | 0.9% | 0.9–3.4% | 0–0.9% |
| eval/data hold-out, TPR at FPR ≤ 1% | 0.940 | 0.915–0.960 | 0.937–0.945 |
| long9 benign long documents blocked (49) | **0** | 3–5 | 0–2 |
| long9 embedded attacks caught (168) | 86.3% | 86.9–88.7% | 83.9–86.3% |
| split1 payload-splitting attacks caught, L2 only (60) | **85.0%** | 63.3–71.7% | 85.0–93.3% |
| split1 benign conversations blocked, L2 only (60) | 1.7% | 5.0–6.7% | 1.7–6.7% |

## Files

| file | SHA-256 |
|---|---|
| `model_int8.onnx` | `79f26effb1b5595c38868735b6e7a474fa7be39a5288e77370e921e3ea1cc244` |
| `tokenizer.json` | `6879d3648d0329c894b1cbb0c89096430e24d3c7cf5d359d4ccc87ce585c4ae4` |
| `config.json` | `a74903e3d5f0f21799228d520b0b08aa2a2ac9c779bafd78c2d800f9e8a29d7a` |
| `thresholds.json` | `ca208f13ba2efe6565453d3f839be671c6e8dafe69ac1ba36d7b566802ed3138` |
| `calibration.json` | `665c646a38c95dbbe5d196b880a8db42d45b38fd12310dae56bbb32796178395` |

**ONNX inputs:** `input_ids` and `attention_mask` (int64, `[batch, seq]`). **Output:** `logits` (float32,
`[batch, 8]`) in the label order of `config.json`, as v8e.

## Limitations

- **Not validated.** The arm failed R8c, and this seed was selected after its holdout was scored. Treat the table
  above as optimistic; R8d (in progress) retrains the arm with fixes for the two misses and fresh holdouts.
- **Long-document attacks.** It catches somewhat fewer attacks embedded in long documents than v8e (86.3% against
  86.9–88.7%).
- Synthetic and agent-labelled data, 256-token windows, and no content moderation, as for v8e.
- Training data, licenses and attribution as for v8e plus the R8c sources (`train/data/sources_r8c.yaml`); the
  owner-supplied rows are used with consent and are not redistributed.
