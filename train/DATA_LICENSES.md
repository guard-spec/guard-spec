# Training data sources and licenses

Every public source below allows redistribution and commercial use, so the
generated `train/data/*.jsonl` files and a model trained on them can be
published under Apache-2.0. The two v3b rows at the end of the table are the
exception: they are not redistributed, and only weights trained on them are
published, with the owner's consent (see Notes). The agent checked each license on the Hugging
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
| **v3b**: owner-supplied synthetic EN/VI rows, batch 1 (`guard-spec:owner-supplied`) | supplied by the project owner; used with the owner's consent; **not redistributed** | none (outside this repository) | owner `user_train`, `user_holdout` | EN + VI prompt-injection attacks and benign rows, including banking OTP/KYC; translation pairs | 800: 580 training pool (517 train + 63 val) + 220 hold-out |
| **v3b**: OTP/eKYC rows (`guard-spec:otpkyc-fable`) | AI-written for this project; **not redistributed** | none (outside this repository) | `otpkyc_train`, `otpkyc_probe` | EN OTP/eKYC verification-bypass attacks, EN + VI benign banking text | 181 training pool (166 train + 15 val) + 120 benign probe |

Row counts come from `data/stats.json`, except the v3b rows, which `MODEL_CARD.md` (v3b) counts.

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
- **Owner-supplied rows** (v3b): 800 synthetic EN/VI rows (batch 1), written and supplied by the
  project owner: prompt-injection attacks and benign text, including banking OTP/KYC scenarios.
  On 2026-11-05 the owner consented to publishing model weights trained on them
  (`guardspec-classifier-v3b`, Apache-2.0). The rows themselves are **not redistributed**: they are
  not in this repository, in the eval set, in the published model repository or in any release
  artifact; `data/build_data.py` reads them from a path at build time into a gitignored directory
  (`DATA_CARD.md`, "v3b"). Do not quote them in documentation, issues or reports; describe them
  only in aggregate (counts and metrics).
- **OTP/eKYC rows** (v3b, `guard-spec:otpkyc-fable`): written by an AI model for this project;
  several slices were stopped by safety systems and not retried. Kept outside the repository like
  the owner rows; only the trained weights are published.
- **Published v3b weights** (`train/hf/README.md`): Apache-2.0. Every public source above allows
  this; HelpSteer2 (CC-BY-4.0) is attributed in the model card.
- **Project-written rows** are licensed Apache-2.0 as project data. The
  Vietnamese rows are machine-written and agent-labelled, not reviewed by a
  native speaker.
- **Attribution**: each row keeps its `source` and `license` fields. Credit
  goes to deepset, Lakera, jackhhao (and the upstream authors above) and the
  OpenAssistant contributors.
- **Base model**: `intfloat/multilingual-e5-small` (MIT, revision
  `614241f622f5`). See `MODEL_CARD.md`.

## v5: code, configuration, logs and long prose (RF-437128e9)

`data/build_v5.py` reads the sources in `data/sources_v5.yaml` (URL, tag, commit, archive and content
SHA-256, licence and attribution of each), downloads them into a gitignored cache and writes the windows
to `$GUARD_BUILD_OUT`, outside the repository. **No third-party text is committed**; only the builder,
`sources_v5.yaml`, `data/gen_codelog_v5.py` and the summary `data/stats_v5.json` are. The licence of each
repository is checked at the pinned tag (the licence file must contain the expected text, or the source
is refused); vi.wikisource pages must carry `{{PVCC-CPVN}}` or `{{PD-old}}` at the pinned revision.

| Source | Licence | Pinned | Used for | Set |
|---|---|---|---|---|
| [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes) | Apache-2.0 | `v1.31.0` (`9edcffc`) | Go, YAML/Dockerfile configs, shell (no `vendor/`, `third_party/`, generated code) | A |
| [python/cpython](https://github.com/python/cpython) `Lib/` | PSF-2.0 | `v3.12.7` (`0b05ead`) | Python (no tests), CI/tool configs, shell | A |
| Rust standard library (`rust-src` 1.81.0 component, `library/`) | MIT OR Apache-2.0 | 1.81.0 (`eeb90cd`) | Rust, `Cargo.toml` (no `stdarch`, `backtrace`, `portable-simd`, tests) | A |
| [Node.js](https://nodejs.org) `lib/` | MIT | `v20.17.0` (`efbec04`) | JavaScript (no `deps/`, `tools/`, `lib/internal/deps/`) | A |
| PostgreSQL `src/test/regress/sql` | PostgreSQL | 16.4 (`REL_16_4`) | SQL | A |
| [sigstore/cosign](https://github.com/sigstore/cosign) | Apache-2.0 | `v2.4.1` (`9a4cfe1`) | Go (`cmd/`, `pkg/`, `internal/`), CI/release YAML, shell (no tests, `test/`, `testdata/`, docs, specs) | A |
| [ory/hydra](https://github.com/ory/hydra) | Apache-2.0 | `v2.2.0` (`57096be`) | Go, SQL migrations (`persistence/sql/migrations`, `src`), quickstart/CI YAML, Dockerfiles, shell (no generated `internal/httpclient`, `migratest`, tests, `cypress/`, docs) | A |
| [oauth2-proxy/oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) | MIT | `v7.7.1` (`6fb0201`) | Go, docker-compose/YAML/`.cfg` configs, Dockerfile, shell (no tests, `testdata/`, docs, `static/`) | A |
| [ollama/ollama](https://github.com/ollama/ollama) | MIT | `v0.3.12` (`e9e9bdb`) | Go server, API client, OpenAI-compatible layer, env config, CI YAML, Dockerfile, `scripts/` (no `llm/` (llama.cpp), prompt `template/`, examples, integration tests, docs) | A |
| [openai/openai-python](https://github.com/openai/openai-python) | Apache-2.0 | `v1.51.0` (`b7d9ce7`) | Python client runtime, helpers and CLI (no generated `resources/`, `types/`; no tests, examples), CI YAML, scripts | A |
| [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) | Apache-2.0 | `v1.5.0` (`01886c8`) | Python (secret-detection plugins and filters; no tests, `test_data/`, `testing/`), CI/pre-commit YAML | A |
| [psf/requests](https://github.com/psf/requests) history | Apache-2.0 | `v2.28.0..v2.32.3` | unified diffs (`git log -p`, commit id and subject only) | A |
| [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) history | Unlicense OR MIT (used under MIT) | `13.0.0..14.1.0` | unified diffs | A |
| U.S. Code titles 7 and 15 (GovInfo, 2023) | Public domain (17 U.S.C. 105) | URLs + content SHA-256 | English long prose | A |
| vi.wikisource: 14 laws (PVCC-CPVN) and 8 pre-1900 works (PD-old) | Public domain | revision ids | Vietnamese long prose | A |
| [prometheus/prometheus](https://github.com/prometheus/prometheus) | Apache-2.0 | `v2.54.1` | Go, configs, shell (no `vendor/`, `web/ui`) | B |
| [django/django](https://github.com/django/django) | BSD-3-Clause | `5.1.1` | Python (no `static/`, `locale/`, tests, migrations), configs | B |
| [tokio-rs/tokio](https://github.com/tokio-rs/tokio) | MIT | `tokio-1.40.0` | Rust, configs | B |
| [expressjs/express](https://github.com/expressjs/express) + history | MIT | `4.21.0`, `4.19.2..4.21.0` | JavaScript, configs, diffs | B |
| U.S. Code titles 1, 4, 9, 36 | Public domain | | English long prose | B |
| vi.wikisource: 4 laws, 3 works | Public domain | revision ids | Vietnamese long prose | B |
| [etcd-io/etcd](https://github.com/etcd-io/etcd) | Apache-2.0 | `v3.5.16` | Go, configs, shell | C |
| [pallets/flask](https://github.com/pallets/flask) + history | BSD-3-Clause | `3.0.3`, `2.3.0..3.0.3` | Python, configs, diffs | C |
| [serde-rs/serde](https://github.com/serde-rs/serde) | MIT OR Apache-2.0 | `v1.0.210` | Rust, configs | C |
| [axios/axios](https://github.com/axios/axios) | MIT | `v1.7.7` | JavaScript (no `dist/`), configs | C |
| U.S. Code titles 3 and 13 | Public domain | | English long prose | C |
| vi.wikisource: 4 laws, 4 works | Public domain | revision ids | Vietnamese long prose | C |
| `data/gen_codelog_v5.py` (project-written generators, template sets A/B/C) | Apache-2.0 | this repository | logs EN/VI (incl. repeated lines), stack traces, JSON/CSV EN/VI, SQL, terminal output, Vietnamese-commented code | A/B/C |
| Payloads: attack rows of `data/train.jsonl` (the sources above in this file) | as each row | this repository | embedded positives | A/B/C |

**Not used** (source level): the Go standard library (`golang/go`, bench/long), Wikipedia in any
language (CC-BY-SA share-alike; bench/long), the vi.wikisource revisions bench/long uses and every
other version of those laws or works, U.S. Code titles 11, 17 and 35 (bench/long), this repository at
any commit (eval/codelog is built from it), and the message catalogs and seeds of `eval/codelog/build.py`
and `bench/long/build.py`. Vendored directories inside the repositories above are excluded because their
licences differ. CC-BY-SA, GPL and unlicensed sources were not considered.

Rows per split and source kind are in `data/stats_v5.json` (full profile: 22,518 rows, see
`DATA_CARD.md`, v5). The built files stay outside the repository: they hold third-party text under the
licences above (all permissive or public domain) and are not redistributed by this project.

**Attribution**: each row keeps `source` (`<source>@<tag>`), `license` and `origin` (repository path,
commit, title or revision); the authors are listed in `sources_v5.yaml`. Commit logs are reduced to the
commit id and subject (no author names or e-mail addresses).
