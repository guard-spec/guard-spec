# Training data sources and licenses

Every source below allows redistribution and commercial use, so the
generated `train/data/*.jsonl` files and a model trained on them can be
published under Apache-2.0. The agent checked each license on the Hugging
Face card (front-matter `license:` field) at the pinned revision.

| Source | License | Pinned revision | Split / file used | Use | Rows after filtering (v1: train + val + val_hard) |
|---|---|---|---|---|---|
| [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 | `4f61ecb038e9` | `train` | EN attacks + benign | 291 |
| [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | `04737b65e90a` | `train` | EN attacks (prompt extraction / override) | 776 |
| [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | `2f2ceeb39658` | `balanced/jailbreak_dataset_train_balanced.csv` | EN jailbreaks + benign role-play / instructions | 1,016 |
| [`OpenAssistant/oasst2`](https://huggingface.co/datasets/OpenAssistant/oasst2) | Apache-2.0 | `179dd21fc551` | `2023-11-05_oasst2_prompts.messages.jsonl.gz` | Benign user prompts: a 3,200-row EN sample and every VI prompt (with variants) | 4,229 |
| Guard Spec project-written rows (`data/gen_en.py`, `data/gen_vi.py`, `data/gen_hardneg.py`) | Apache-2.0 | this repository | - | EN + VI attacks of every category, hard benign, minimal pairs | 14,779 |
| **v3**: [`nvidia/HelpSteer2`](https://huggingface.co/datasets/nvidia/HelpSteer2) | CC-BY-4.0 | `990b2711a361` | `train.jsonl.gz` (first user turn of each prompt) | EN benign: real role-play, technical and business requests | 2,500 sampled; 1,404 train + 303 val after balancing |
| **v3**: Guard Spec project-written rows (`data/gen_v3.py`, `data/gen_holdout_v3.py`) | Apache-2.0 | this repository | - | EN hard negatives (tasks with override verbs, sysadmin/security writing, meta and quoted attacks, role-play, logs), minimal pairs, VI admin/meta text; hold-out set C | see `data/stats.json` |
| **v3**: Guard Spec realistic rows (`data/realistic/`, source `guard-spec:realistic-fable`) | Apache-2.0 | this repository | `realistic_train.jsonl`, `realistic_holdout.jsonl` | EN + VI realistic attacks (authority impersonation, fake IT/compliance notices, indirect injection in emails, contracts, tickets, documents) and same-domain hard negatives | 2,412 train/val + 613 hold-out |

Row counts come from `data/stats.json`.

## Notes

- **deepset**: the card's top-level license is `apache-2.0`. Its
  `dataset_info` block also has a stray `cc-by-4.0` field; both allow
  redistribution with attribution. Only the `train` split is used. The
  `test` split is in the eval set.
- **Gandalf**: MIT. Only `train` is used. `test` and `validation` are in the
  eval set.
- **jailbreak-classification**: Apache-2.0 on the card. The card says its
  jailbreak prompts come from `verazuo/jailbreak_llms` (MIT) and its benign
  prompts from OpenOrca (MIT) and GPTeacher (MIT); all are compatible. Only
  the balanced `train` file is used.
- **oasst2**: Apache-2.0. Only `prompter` messages are used: not deleted, not
  rejected in review, 12–1,500 characters, detoxify toxicity ≤ 0.5, and not
  attack-like (see `RE_OASST_DROP`).
- **Considered and not used**:
  - `databricks/databricks-dolly-15k` (CC-BY-SA-3.0): share-alike terms would
    follow the data.
  - `tatsu-lab/alpaca`, `HuggingFaceH4/no_robots`: non-commercial licenses.
  - `jayavibhav/prompt-injection`: no license on its card.
- **HelpSteer2** (v3): CC-BY-4.0 on the card at the pinned revision; attribution: NVIDIA, "HelpSteer2"
  (Wang et al., 2024). Only the `prompt` field is used, cut at the first `<extra_id_1>` turn marker;
  12–1,500 characters, English, and not jailbreak-like (`RE_HS_DROP`, `RE_OASST_DROP`). Responses and
  ratings are not used. CC-BY-4.0 allows redistribution and commercial use with attribution, which
  this file and each row's `source`/`license` fields provide.
- **Realistic rows** (v3, `guard-spec:realistic-fable`): written row by row by an AI model for this
  project (no templates), at the owner's request, and released as project data under Apache-2.0.
  Provenance and checks are in `data/realistic/README.md`. Not reviewed by a native speaker.
- **Considered for v3 and not used**: `HuggingFaceH4/ultrachat_200k` (MIT) is synthetic dialogue and
  would add generic text, not the hard negatives v3 needed; prompt-injection datasets with unclear or
  missing licenses.
- **Project-written rows** are licensed Apache-2.0 as project data. The
  Vietnamese rows are machine-written and agent-labelled, not reviewed by a
  native speaker.
- **Attribution**: each row keeps its `source` and `license` fields. Credit
  goes to deepset, Lakera, jackhhao (and the upstream authors above) and the
  OpenAssistant contributors.
- **Base model**: `intfloat/multilingual-e5-small` (MIT, revision
  `614241f622f5`). See `MODEL_CARD.md`.
