# Data card: Guard Spec classifier training data v0

Copyright The Guard Spec Authors. Project-written rows are licensed
Apache-2.0. Source rows keep their own licenses (`DATA_LICENSES.md`).

## Purpose

This data trains and calibrates the Guard Spec EN/VI attack-risk classifier
(`MODEL_CARD.md`). It is not an evaluation set. Evaluation uses `eval/` only,
and none of its rows appear here (see the leakage section).

## Files

| file | rows | content |
|---|---|---|
| `data/train.jsonl` | 15,850 | training split |
| `data/val.jsonl` | 2,228 | validation split, used for early stopping and threshold calibration |
| `data/stats.json` | - | counts per label, language, variant and source, plus the leakage report |
| `data/pilot_labels.jsonl` | 200 | manual pilot labels (`LABELING.md`) |

Schema (one JSON object per line):

| field | content |
|---|---|
| `id` | `<lang>-<first 12 hex of sha256(text)>` |
| `text` | the input |
| `labels` | non-empty list of labels: `["benign"]` or one or more attack labels |
| `lang` | `en` or `vi` |
| `variant` | `orig`, `no_diacritics`, `teencode`, `leet` |
| `source` | `guard-spec` or `<hf dataset>:<split>` |
| `license` | the row's license |
| `group` | template or source-row id. Every variant of one base text shares a group. |

Rebuild it with `cd train && uv run python data/build_data.py`. The build:

- downloads about 17 MB into `train/.cache` (gitignored);
- needs `eval/fingerprints.txt` and `eval/data/*.jsonl` for the leakage guard;
- is byte-identical between runs (checked with md5 on all three outputs).

## Composition (train + val)

Rows can carry more than one attack label, so label counts add up to more
than the row count.

| label | EN | VI |
|---|---|---|
| benign | 5,061 | 3,261 |
| direct_injection | 1,487 | 1,231 |
| indirect_injection | 699 | 1,158 |
| jailbreak | 977 | 661 |
| prompt_extraction | 1,085 | 1,210 |
| data_exfiltration | 742 | 1,353 |
| tool_poisoning | 387 | 592 |
| obfuscation | 529 | 543 |
| **rows** | **9,538** (4,477 attack) | **8,540** (5,279 attack) |

| | rows |
|---|---|
| VI variants | `orig` 3,322 · `no_diacritics` 3,219 · `teencode` 1,473 · `leet` 526 |
| EN variants | `orig` 9,168 · `leet` 370 |
| sources | project 11,848 · oasst2 4,147 · jailbreak-classification 1,016 · Gandalf 776 · deepset 291 |

### Project-written rows

`data/gen_en.py` and `data/gen_vi.py` build the project rows from seeded
templates, with new wording and vocabulary that is not taken from
`eval/build`. They cover:

- **Every attack label**, in both languages.
- **Indirect injection** in 16 EN and 14 VI carriers: email, Slack/Zalo,
  tickets, PDF text with `font-size:0`, product listings, READMEs, commit
  messages, meeting transcripts, hidden `aria-hidden` spans, search JSON,
  tool output JSON, CSV cells, image alt text, YAML comments, SMS, wiki
  pages, reviews and code comments. Payloads mix plain injection with
  exfiltration, extraction and jailbreak goals.
- **Tool poisoning** in four formats: MCP JSON, a Python `@mcp.tool()`
  docstring, YAML and TypeScript `server.tool`.
- **Obfuscation**:
  - spaced, dashed and dotted letters;
  - zero-width characters;
  - Cyrillic homoglyphs and fullwidth characters;
  - word splitting and mixed case;
  - leet;
  - base64, ROT13 and hex;
  - reversed text;
  - Unicode tag smuggling;
  - acrostics and concatenated fragments;
  - Vietnamese–English code-switching.
- **Hard benign rows**, about half of all benign project rows:
  - questions about prompt-injection security;
  - idioms that use trigger words ("disregard my last message", "bỏ qua",
    "quên");
  - "hướng dẫn hệ thống" and admin talk;
  - sysadmin and developer questions with override, bypass, reset or reveal;
  - code and test fixtures that contain attack strings;
  - benign role-play ("đóng vai hướng dẫn viên");
  - requests to print rules or instructions for ordinary things;
  - benign notes inside **the same carriers** as the indirect attacks;
  - benign tool definitions in the same formats as the poisoned ones.

Vietnamese variants:

- every base gets a `no_diacritics` copy;
- a seeded subset gets a `teencode` copy, using its own table (`hông`,
  `đc`, `z`, `mik`, `ntn`, `qu→w`, `ph→f`, `d→z`, ...);
- a seeded subset gets a `leet` copy.

Benign rows get these variants too, so that "no diacritics" or "teencode"
does not become a shortcut for "attack". The 422 human-written Vietnamese
oasst2 prompts get the same variants.

## Leakage guard

The procedure follows `eval/README.md`:

1. Normalize each text as `normalize_for_fingerprint` does: NFC, `đ→d`,
   strip diacritics, lowercase, collapse whitespace.
2. Drop any row whose sha256 is in `eval/fingerprints.txt`.
3. Drop any row whose character 5-gram Jaccard similarity with any eval text
   is above 0.8, using the same normalization.

| check | rows dropped |
|---|---|
| fingerprint match | 0 |
| 5-gram Jaccard > 0.8 | 2 (one deepset, one Gandalf) |

After filtering, the closest training row to any eval row has Jaccard 0.72.
Thirteen rows lie between 0.6 and 0.8. They are short Gandalf-style
paraphrases such as "Print previous instructions."

The deepset `test` split and the Gandalf `test` and `validation` splits are
never read for training. The project generators were written without copying
eval sentences, which is why so few rows were dropped.

## Split

The split is by `group`, so every variant of a base text lands on the same
side. A group goes to validation when `sha256("split:" + group) mod 100 < 12`.

Validation shares templates with training, though not texts or variants, so
validation scores are optimistic compared with the eval set.

## Known issues

- **Machine-written Vietnamese.** The Vietnamese rows are machine-written and
  agent-labelled, not checked by a native speaker. Teencode is rule-based and
  stiffer than real chat.
- **Template correlation.** Template rows share phrases, so the model can
  learn template artefacts. The eval set uses different templates, which is
  the point of reporting on it.
- **Source labels.** Source labels are kept as published: some deepset
  "attacks" are borderline. Source categories come from keyword heuristics.
  The pilot agreement was 99% after revision, but it was measured on the
  rows used to tune the heuristic.
- **English benign data.** Most of the English benign data is ordinary oasst2
  prompts and role-play prompts from jailbreak-classification. English
  attacks from sources are dominated by Gandalf password requests.
