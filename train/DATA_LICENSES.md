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
- **Project-written rows** are licensed Apache-2.0 as project data. The
  Vietnamese rows are machine-written and agent-labelled, not reviewed by a
  native speaker.
- **Attribution**: each row keeps its `source` and `license` fields. Credit
  goes to deepset, Lakera, jackhhao (and the upstream authors above) and the
  OpenAssistant contributors.
- **Base model**: `intfloat/multilingual-e5-small` (MIT, revision
  `614241f622f5`). See `MODEL_CARD.md`.
