# Red-team reports: bypasses and false positives

Guard Spec improves from texts it gets wrong. This page describes how to
report one, what maintainers do with a report, how a reported text becomes
training or hold-out data, and how the fix reaches a release.

There are two kinds of report:

| Kind | Meaning | Issue form |
|---|---|---|
| **Bypass** | an attack text that was allowed (or only logged) | [Bypass (prompt got through)](https://github.com/guard-spec/guard-spec/issues/new?template=bypass_report.yml) |
| **False positive** | a legitimate text that was blocked, routed or flagged | [False positive (benign blocked)](https://github.com/guard-spec/guard-spec/issues/new?template=false_positive_report.yml) |

## Before you report

- **No personal data, secrets or customer data.** Issues are public. Post a
  synthetic or anonymised text: replace names, e-mail addresses, phone
  numbers, account and ID numbers, API keys, internal host names and customer
  content with placeholders (`user@example.com`, `[NAME]`, `sk-REDACTED`).
  Keep the wording that makes the detector fail.
- **Severe bypasses are vulnerabilities.** If the text would let an attacker
  exfiltrate data, call tools or reach another tenant in a real deployment,
  or it is a general technique (an encoding, a sanitizer gap, a policy-engine
  flaw) that defeats every layer for a whole class of texts, report it
  privately as described in
  [SECURITY.md](../SECURITY.md#guardrail-bypasses-public-issue-or-private-report).
  It is triaged there, and its text joins the data only after the fix and the
  advisory are public.
- **Consent.** Both forms ask you to agree that the text may be added to the
  project's training or hold-out data and published under Apache-2.0. Without
  that line a report is still useful for a fix, but its text is not imported.

## How to report

**From the admin UI.** On the **Request log** page, use **Report** on a row,
or in the row's details. The dialog picks the kind from the decision (an
allowed or logged row is a bypass, a blocked or routed one a false positive;
you can change it), asks where the text appeared (user prompt, RAG document,
tool result, MCP tool description) and shows the fields it will send:

- decision, `injection_score` (fused over the layers that ran), label, the
  rule that decided, `anomaly_score` (L3), `toxicity_score`, the sanitizer
  flags and the model of the request;
- the gateway version and the detector layers, classifier and fusion from the
  Models page (`GET /v1/gateway/models`), when the control plane can reach
  the gateway.

The request log keeps no per-layer scores; `POST /guardrail/scan` returns
`scores.l1`, `l2` and `l3` if you want to add them. The request ID, hash,
route target and API key are never included.

The text of the request is included only when the organization stores
content ([Audit privacy](../README.md#audit-privacy)) **and** you tick
**Include the text** after the warning. The dialog then shows the last user
message (or the last tool result, for a RAG document or tool result) in an
editable box: anonymise it there. **Open GitHub issue** opens the form in a
new tab with these fields filled in; you review it, fill in the language,
attack type and expected outcome, and post it yourself. The control plane
sends nothing anywhere. If the prefilled link would be longer than GitHub
accepts (about 8,000 characters), the report is copied to the clipboard and
the empty form opens instead. Every role that can read the request log,
viewers included, can report.

**Without the admin UI.** Open the form directly and fill in the same
fields, from the audit row or a `POST /guardrail/scan` response.

**Minimal pairs.** A bypass and a benign text that differ in a few words are
the most useful reports. Put the other issue's number in **Related report**
so that both land in the same data split.

## What happens next

### Triage labels

The forms add `detection`, `bypass` or `false-positive`, and `needs-triage`.
A maintainer then removes `needs-triage` and adds one outcome:

| Label | Meaning |
|---|---|
| `triage:train` | accepted; the text goes to the training data (train or validation split) |
| `triage:holdout` | accepted; the text goes to the community hold-out, never trained on |
| `triage:duplicate` | the same text or the same technique is already reported; the issue is closed with a link to the first one |
| `triage:rejected` | not a detector error (expected behaviour, a configuration problem, an upstream model issue) or no usable text |
| `triage:security` | severe: moved to a private security advisory; the public issue is closed without details |

Optional labels during triage:

- `attack:<label>` sets the attack label of a bypass when the reporter's
  attack type is wrong or missing (`attack:direct_injection`,
  `attack:indirect_injection`, `attack:jailbreak`, `attack:prompt_extraction`,
  `attack:data_exfiltration`, `attack:tool_poisoning`, `attack:obfuscation`,
  the labels of [train/LABELING.md](../train/LABELING.md)).
- A maintainer may edit the issue to anonymise the text further; the
  importer reads the issue as it is at import time.

### Training or hold-out

A maintainer decides per report, before anyone trains on it:

- **Hold-out** when the report shows a new technique, a regression, or a
  pair at the decision boundary that a fix should be measured on. The
  community hold-out is scored once per candidate model, like
  `val_v3_holdout`, and is never used for training, model selection,
  thresholds or calibration.
- **Training** for the rest: variants of known techniques and ordinary false
  positives. The group hash sends about 12% of them to the validation split.
- When in doubt, hold-out. A text can move from hold-out to training in a
  later data version (and is then no longer used to measure); never the
  other way.

### Import and deduplication

`train/import_issues.py` turns triaged issues into staging files in the
schema of `train/data` (`train/DATA_CARD.md`). It needs no training
environment:

```bash
# From GitHub (token optional, read from GITHUB_TOKEN or GH_TOKEN, never stored)
uv run --no-project python train/import_issues.py --repo guard-spec/guard-spec

# From a local export, e.g. gh issue list --label triage:train --state all \
#   --json number,title,body,labels,author,url > issues.json
uv run --no-project python train/import_issues.py --from-json issues.json

# Tests (fixtures only, no network)
uv run --no-project python -m unittest discover -s train/tests -v
```

It writes `community_train.jsonl`, `community_val.jsonl`,
`community_holdout.jsonl` and `import_report.json` to `train/runs/community/`
(gitignored, `--out` to change). Each row is

```json
{"id": "en-bfb33ffec3af", "text": "…", "labels": ["prompt_extraction"], "lang": "en", "variant": "orig",
 "source": "community:issue#101", "license": "Apache-2.0", "group": "community.101"}
```

An issue is refused, with the reason in `import_report.json`, when it:

- is not triaged (`needs-triage`, or no `triage:train` / `triage:holdout`),
  or is labelled `triage:duplicate`, `triage:rejected` or `triage:security`;
- lacks the consent or the "synthetic or anonymised" confirmation;
- is in a language the classifier data does not cover (English and
  Vietnamese: with diacritics, without diacritics, teencode);
- looks like it contains personal data or a secret: e-mail addresses (except
  `example.com`, `.example`, `.test` and other reserved domains), phone
  numbers, national ID and social security numbers, payment card numbers
  (Luhn-checked), IBANs, API keys and tokens, private keys. These are simple
  regular expressions: they catch mistakes, not every case, so triage still
  reads the text;
- duplicates a text in `train/data` (exact, or after the normalisation of
  `eval/fingerprints.txt`: Unicode NFC, diacritics stripped, lower case,
  whitespace collapsed) or in `eval/` (fingerprint, normalised text, or a
  character 5-gram Jaccard similarity above 0.8, the leakage guard of
  `train/data/build_data.py`);
- repeats a text of another report in the same import (with the opposite
  label, both are refused until triage decides).

### The pair-aware split

Reports linked through **Related report** (directly or in a chain) form one
group, `community.<lowest issue number>`. A whole group goes to the same
split, so the benign and the attack text of a minimal pair never end up on
both sides of training and measurement. A group with any `triage:holdout`
report goes to the hold-out; the others are split by the same hash as the
rest of the training data (`sha256("split:" + group)`, 12% to validation).

### `eval/` is never touched

Reported texts are never added to `eval/`, and nothing is tuned on it
([CONTRIBUTING.md](../CONTRIBUTING.md#the-one-rule-about-eval)). The importer
reads `eval/` only to drop texts that are already there or nearly so. A
change to `eval/` needs a new eval release with its own provenance, never a
community report.

### Into the training data

A maintainer reviews the staging files and the report, then commits the
accepted rows in a pull request under `train/data/community/`
(`community_train.jsonl`, `community_val.jsonl`, `community_holdout.jsonl`),
which makes them part of the dedupe set of later imports. `train/DATA_CARD.md`
lists their counts and the reporters. The first such pull request also
teaches `train/data/build_data.py` to read that directory (training and
validation rows into the pool with their groups, the hold-out as its own
split), with the same leakage guard as every other row; until then no
community row reaches a model.

## How fixes ship

1. **A rule or a model.** A narrow, high-precision pattern becomes an L1
   rule; anything broader waits for a classifier trained with the new rows.
   Rules are developed on the reports and on `train/data` validation splits,
   never on `eval/`, and the pull request says which data it used.
2. **Measured on the hold-out.** A candidate is scored once on the community
   hold-out and the other hold-out splits, then on `eval/` at the end, with
   the numbers in the pull request.
3. **Shadow mode.** A new classifier runs next to the active one
   (`SHADOW_L2_MODEL`, README
   [Shadow mode and model reload](../README.md#shadow-mode-and-model-reload)):
   operators see on the **Models** page where it would block or allow
   differently on their own traffic, without changing a decision.
4. **Default.** After a release with the candidate in shadow mode and no
   regressions reported, the model manifest recommends it and a later
   release makes it the default. The CHANGELOG names the reports it fixes.

A reporter can check a fix with the release that names their issue, or
earlier with `POST /guardrail/scan` on a gateway running the candidate.

## Credit

- The CHANGELOG entry of the release with the fix thanks the reporters by
  their GitHub name and issue number.
- `train/DATA_CARD.md` lists the reporters whose texts are in the data
  (`import_report.json` has the list for each import).
- Private reports are credited in the security advisory, as SECURITY.md
  describes.

Say in the issue if you prefer not to be named.
